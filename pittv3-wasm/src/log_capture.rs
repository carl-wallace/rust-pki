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
use std::sync::{OnceLock, RwLock};

use log::{Level, LevelFilter, Log, Metadata, Record};
use web_time::Instant;

/// Lines retained. Past this the oldest go, so a tab left open through many runs costs a bounded
/// amount of memory rather than a growing one — the same reasoning as the relay's per-click byte
/// budget. At `Debug` over a large run this is minutes of output, not seconds.
const MAX_LINES: usize = 20_000;

static BUFFER: RwLock<VecDeque<String>> = RwLock::new(VecDeque::new());
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
        if let Ok(mut buffer) = BUFFER.write() {
            if buffer.len() == MAX_LINES {
                buffer.pop_front();
            }
            buffer.push_back(line);
        }
    }

    fn flush(&self) {}
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

/// Discards what has been captured, so a run can be exported without the runs before it.
pub fn clear() {
    if let Ok(mut buffer) = BUFFER.write() {
        buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oldest_lines_go_first_and_the_bound_holds() {
        clear();
        for i in 0..(MAX_LINES + 10) {
            if let Ok(mut b) = BUFFER.write() {
                if b.len() == MAX_LINES {
                    b.pop_front();
                }
                b.push_back(format!("line {i}"));
            }
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
}
