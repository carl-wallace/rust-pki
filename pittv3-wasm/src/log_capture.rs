//! Captures the `log` crate's output so the browser build can show it and hand it over.
//!
//! certval and pittv3-lib say what they are doing through `log`: which source settled a revocation
//! status, why a candidate path was dropped, which URI was fetched. In the browser none of it
//! arrived anywhere. `dioxus::launch` installs a `tracing` subscriber, and `log` and `tracing` are
//! separate globals — with nothing bridging them, a `log::` call from the validation stack reached
//! no sink at all and the console stayed empty.
//!
//! The `log` global was unclaimed, so this takes it and does two things with every record: forwards
//! it to `tracing` for the console, and appends it to a bounded in-memory buffer the app can offer
//! as a download. One implementation rather than two, because the console half cannot be done with a
//! second `tracing` subscriber — dioxus owns that global, and only one may be installed.
//!
//! The desktop reaches the same end by a different road: log4rs with a `ChannelAppender` feeding the
//! GUI's log pane. log4rs is not in the wasm tree, so this is the equivalent written against `log`
//! directly.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{OnceLock, RwLock};

use log::{Level, LevelFilter, Log, Metadata, Record};
use web_time::Instant;

/// Lines retained. Past this the oldest go, so a tab left open through many runs costs a bounded
/// amount of memory rather than a growing one — the same reasoning as the relay's per-click byte
/// budget. At `Debug` over a large run this is minutes of output, not seconds.
const MAX_LINES: usize = 20_000;

static BUFFER: RwLock<VecDeque<String>> = RwLock::new(VecDeque::new());
/// Every line ever captured, including the ones the bound has since discarded. `BUFFER`'s indices
/// shift when it overflows, so a position in it does not keep its meaning; this count does, which is
/// what lets [`since`] name a moment rather than a slot.
static WRITTEN: AtomicUsize = AtomicUsize::new(0);
static START: OnceLock<Instant> = OnceLock::new();
static LOGGER: BufferLogger = BufferLogger;

struct BufferLogger;

impl Log for BufferLogger {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        // The level filter set through `set_level` already gates delivery; answering true here keeps
        // the two from disagreeing about what is enabled.
        true
    }

    fn log(&self, record: &Record<'_>) {
        let elapsed = START.get_or_init(Instant::now).elapsed().as_millis();
        let line = format!(
            "{:>8}ms {:<5} {} - {}",
            elapsed,
            record.level(),
            record.target(),
            record.args()
        );

        // The console half. Levels are mapped rather than collapsed so the browser's own filtering
        // still works on output that originated in `log`.
        match record.level() {
            Level::Error => dioxus::logger::tracing::error!("{line}"),
            Level::Warn => dioxus::logger::tracing::warn!("{line}"),
            Level::Info => dioxus::logger::tracing::info!("{line}"),
            Level::Debug => dioxus::logger::tracing::debug!("{line}"),
            Level::Trace => dioxus::logger::tracing::trace!("{line}"),
        }

        // The download half.
        append(line);
    }

    fn flush(&self) {}
}

/// Adds one line to the buffer, discarding the oldest when the bound is reached, and counts it.
fn append(line: String) {
    WRITTEN.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut buffer) = BUFFER.write() {
        if buffer.len() == MAX_LINES {
            buffer.pop_front();
        }
        buffer.push_back(line);
    }
}

/// Claims the `log` global and starts capturing at `level`.
///
/// Called once, from `main`. A second call is ignored rather than treated as an error: losing the
/// race is not a failure, and there is nothing a browser app could do about it anyway.
pub fn install(level: LevelFilter) {
    let _ = START.set(Instant::now());
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(level);
    }
}

/// Changes how much is captured from here on.
///
/// certval is deliberate about levels: `Info` is what a run did, `Debug` is every URI fetched and
/// every revocation determination attempted. Defaulting to `Debug` would bury the line being looked
/// for, so the level is a control rather than a constant.
pub fn set_level(level: LevelFilter) {
    log::set_max_level(level);
}

/// The captured lines, oldest first, as a single document.
pub fn contents() -> String {
    match BUFFER.read() {
        Ok(buffer) => {
            let mut out = String::new();
            for line in buffer.iter() {
                out.push_str(line);
                out.push('\n');
            }
            out
        }
        Err(_) => String::new(),
    }
}

/// How many lines are held, for a caller that wants to say so before offering the download.
pub fn len() -> usize {
    BUFFER.read().map(|b| b.len()).unwrap_or(0)
}

/// A moment in the log, to be handed back to [`since`].
///
/// A count of everything ever captured rather than a position in the buffer: the buffer discards its
/// oldest lines past a bound, so a position stops meaning what it meant, while a count does not.
pub fn mark() -> usize {
    WRITTEN.load(Ordering::Relaxed)
}

/// The lines captured since `mark`, as a single document.
///
/// For a view whose output *is* the log — an inspection reports what a store holds by logging it —
/// so it can show what its own run produced without clearing what came before it or claiming earlier
/// runs as its own.
///
/// A run long enough to overflow the buffer has had the start of its own output discarded; what
/// survives is returned, since the alternative is to report nothing for the longest runs, which are
/// the ones most worth reading.
pub fn since(mark: usize) -> String {
    match BUFFER.read() {
        Ok(buffer) => {
            let new = WRITTEN.load(Ordering::Relaxed).saturating_sub(mark);
            let from = buffer.len().saturating_sub(new);
            let mut out = String::new();
            for line in buffer.iter().skip(from) {
                out.push_str(line);
                out.push('\n');
            }
            out
        }
        Err(_) => String::new(),
    }
}

/// Discards what has been captured, so a run can be exported without the runs before it.
pub fn clear() {
    if let Ok(mut buffer) = BUFFER.write() {
        buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The buffer is one static shared by the whole process, and the harness runs tests on parallel
    /// threads, so a test that fills it and a test that reads it back would otherwise see each
    /// other's lines. Every test that touches the buffer takes this first.
    static SERIALIZE: Mutex<()> = Mutex::new(());

    #[test]
    fn oldest_lines_go_first_and_the_bound_holds() {
        let _serialized = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        for i in 0..(MAX_LINES + 10) {
            append(format!("line {i}"));
        }
        assert_eq!(MAX_LINES, len(), "the bound holds");
        let text = contents();
        assert!(
            !text.contains("line 0\n"),
            "the oldest line was dropped, not the newest"
        );
        assert!(
            text.contains(&format!("line {}", MAX_LINES + 9)),
            "the newest line is retained"
        );
        clear();
        assert_eq!(0, len());
    }

    #[test]
    fn since_reports_only_what_came_after_the_mark() {
        let _serialized = SERIALIZE.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        append("before".to_string());
        let start = mark();
        append("after one".to_string());
        append("after two".to_string());

        let text = since(start);
        assert!(!text.contains("before"), "{text}");
        assert!(
            text.contains("after one") && text.contains("after two"),
            "{text}"
        );
        assert_eq!(2, text.lines().count());

        // A run that overflows the buffer has had the start of its own output discarded. What is
        // still held is reported; reporting nothing would blank the longest runs.
        let overflowing = mark();
        for i in 0..(MAX_LINES + 10) {
            append(format!("flood {i}"));
        }
        let text = since(overflowing);
        assert_eq!(MAX_LINES, text.lines().count());
        assert!(
            text.contains(&format!("flood {}", MAX_LINES + 9)),
            "the end of the run should survive"
        );
        assert!(
            !text.contains("after two"),
            "lines from before the mark should not reappear"
        );
        clear();
    }
}
