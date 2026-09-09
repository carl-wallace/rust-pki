//! Remembering the window's size and position, and deciding when a remembered one is safe to use.
//!
//! Three things are recorded: the geometry, the scale factor it was measured at, and the *name of
//! the display it was on*. The name is what makes the external-monitor case answerable — asked
//! whether a display is attached, the system can say, where comparing coordinates can only guess.
//!
//! **The policy lives in [`decide`], which is a pure function over the saved state and the attached
//! displays.** That is deliberate. Applying geometry needs a live window and cannot be tested here,
//! but deciding *whether* to apply it is where the judgement is, and every case below is a test.
//!
//! What this module cannot do: target a Space. macOS exposes no public API for naming one, so a
//! window restored to the right display may still open on a different desktop. That is the
//! system's to decide.

use std::fs;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Geometry worth restoring, in physical pixels, with the context needed to judge it later.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WindowState {
    /// Left edge of the window frame.
    pub x: i32,
    /// Top edge of the window frame.
    pub y: i32,
    /// Width of the content area.
    pub width: u32,
    /// Height of the content area.
    pub height: u32,
    /// Physical pixels per logical pixel when the above were measured. Recorded rather than
    /// used: the geometry is applied in the units it was measured in, and this is here so a person
    /// reading the file can tell what the numbers mean.
    #[serde(default = "one")]
    pub scale: f64,
    /// Name of the display the window was on, when the system offered one.
    ///
    /// A hint, never an instruction. Names are not guaranteed unique or stable across reboots and
    /// dock changes, so a match is not proof the display is the same one — which is why it can only
    /// ever *skip* a restore, and why [`Outcome::Apply`] is still verified against the live window.
    #[serde(default)]
    pub monitor: Option<String>,
}

/// Scale factor assumed for a remembered geometry that does not record one.
fn one() -> f64 {
    1.0
}

/// A display as [`decide`] needs to see it: what it is called and how big it is, in physical pixels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Display {
    /// What the system calls it, if anything.
    pub name: Option<String>,
    /// Width in physical pixels.
    pub width: u32,
    /// Height in physical pixels.
    pub height: u32,
}

/// What to do with a remembered geometry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Apply it, then verify against the live window.
    Apply,
    /// Leave the window as built, for the stated reason.
    UseDefault(&'static str),
}

/// Whether a remembered geometry should be applied, given the displays now attached.
///
/// Two refusals, and they answer the two ways a remembered geometry goes stale:
///
/// - **The display it was on is gone.** Asked by name rather than worked out from coordinates. An
///   earlier version of this compared rectangles and got it wrong — macOS is natively bottom-left
///   origin and tao converts, so a hand-rolled intersection decided that good positions on an
///   attached display were off screen, then moved the window to the primary monitor: the very
///   failure the check existed to prevent.
/// - **It no longer fits.** A saved size larger than the display it would open on is refused
///   outright rather than clamped, so the application never invents a size nobody chose. This also
///   contains a bad value already on disk, which is not hypothetical: a units mistake once wrote a
///   3280x3200 window into this file, and a fits check would have refused it instead of opening
///   oversized and saving that in turn.
///
/// A refusal drops the position with the size. Restoring half of a remembered state is a third
/// behaviour to explain, and "use the default" is the rule that needs no explaining.
pub fn decide(saved: &WindowState, displays: &[Display]) -> Outcome {
    // Displays that could be the one it was on. With no name recorded -- a file written before the
    // field existed -- every display is a candidate, which is the same latitude the old file had.
    let candidates: Vec<&Display> = match &saved.monitor {
        Some(name) => displays
            .iter()
            .filter(|d| d.name.as_deref() == Some(name.as_str()))
            .collect(),
        None => displays.iter().collect(),
    };

    if candidates.is_empty() {
        return Outcome::UseDefault("the display it was on is not attached");
    }
    if !candidates
        .iter()
        .any(|d| saved.width <= d.width && saved.height <= d.height)
    {
        return Outcome::UseDefault("the remembered size is larger than that display");
    }
    Outcome::Apply
}

/// Where the geometry is kept: `window.json` beside the other state under `~/.pittv3`.
fn state_file() -> Option<String> {
    Some(
        pittv3_gui_lib::settings_store::app_home()?
            .join("window.json")
            .to_str()?
            .to_string(),
    )
}

/// The last geometry written, so a drag does not write the same bytes on every event.
static LAST_WRITTEN: Mutex<Option<WindowState>> = Mutex::new(None);

/// Reads the remembered geometry, treating a malformed file as absent.
pub fn load() -> Option<WindowState> {
    let text = fs::read_to_string(state_file()?).ok()?;
    serde_json::from_str(&text).ok()
}

/// Writes `state` unless it repeats the last write.
pub fn save(state: WindowState) {
    if let Ok(mut last) = LAST_WRITTEN.lock() {
        if last.as_ref() == Some(&state) {
            return;
        }
        *last = Some(state.clone());
    }
    let Some(path) = state_file() else {
        return;
    };
    if let Ok(text) = serde_json::to_string(&state) {
        let _ = fs::write(path, text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display(name: &str, width: u32, height: u32) -> Display {
        Display {
            name: Some(name.to_string()),
            width,
            height,
        }
    }

    fn saved_on(monitor: Option<&str>, width: u32, height: u32) -> WindowState {
        WindowState {
            x: 100,
            y: 100,
            width,
            height,
            scale: 2.0,
            monitor: monitor.map(str::to_string),
        }
    }

    const LAPTOP: &str = "Built-in Retina Display";
    const EXTERNAL: &str = "DELL U2720Q";

    #[test]
    fn the_display_it_was_on_is_still_attached() {
        let displays = [display(LAPTOP, 3024, 1964), display(EXTERNAL, 3840, 2160)];
        assert_eq!(
            decide(&saved_on(Some(EXTERNAL), 2400, 1600), &displays),
            Outcome::Apply
        );
    }

    /// The case this exists for: the external display is unplugged.
    #[test]
    fn a_departed_display_falls_back_to_the_default() {
        let displays = [display(LAPTOP, 3024, 1964)];
        assert!(matches!(
            decide(&saved_on(Some(EXTERNAL), 2400, 1600), &displays),
            Outcome::UseDefault(_)
        ));
    }

    /// A size larger than the display it would open on, which is what a bad value on disk looks
    /// like as well as a genuine change of monitor.
    #[test]
    fn a_size_too_large_for_the_display_falls_back() {
        let displays = [display(LAPTOP, 3024, 1964)];
        assert!(matches!(
            decide(&saved_on(Some(LAPTOP), 3280, 3200), &displays),
            Outcome::UseDefault(_)
        ));
    }

    /// Same window, two displays of different sizes: it fits the external and not the built-in, and
    /// the name is what decides which one is being asked about.
    #[test]
    fn fitting_is_judged_against_the_named_display() {
        let displays = [display(LAPTOP, 3024, 1964), display(EXTERNAL, 3840, 2160)];
        assert_eq!(
            decide(&saved_on(Some(EXTERNAL), 3800, 2100), &displays),
            Outcome::Apply
        );
        assert!(matches!(
            decide(&saved_on(Some(LAPTOP), 3800, 2100), &displays),
            Outcome::UseDefault(_)
        ));
    }

    /// A file written before the name was recorded: no display is named, so any that fits will do.
    #[test]
    fn a_file_without_a_display_name_is_judged_on_size_alone() {
        let displays = [display(LAPTOP, 3024, 1964)];
        assert_eq!(
            decide(&saved_on(None, 1640, 1600), &displays),
            Outcome::Apply
        );
        assert!(matches!(
            decide(&saved_on(None, 4000, 1600), &displays),
            Outcome::UseDefault(_)
        ));
    }
}
