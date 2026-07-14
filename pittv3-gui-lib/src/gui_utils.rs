//! Utilities shared by GUI frontends, i.e., persistence of arguments and extraction of typed
//! values from form events

use dioxus::prelude::*;

#[cfg(feature = "std")]
use std::fs;
#[cfg(feature = "std")]
use std::fs::{create_dir_all, File};

#[cfg(feature = "std")]
use home::home_dir;
#[cfg(feature = "std")]
use log::error;

#[cfg(feature = "std")]
use certval::{Error, Result};
#[cfg(feature = "std")]
use pittv3_lib::args::Pittv3Args;

/// Returns a [`Pittv3Args`] deserialized from the pittv3.cfg file in the .pittv3 folder beneath the
/// user's home directory, creating the .pittv3 folder if it does not exist. Returns an error if
/// there is no home directory, no saved configuration or the saved configuration cannot be parsed.
#[cfg(feature = "std")]
pub fn read_saved_args() -> Result<Pittv3Args> {
    if let Some(hd) = home_dir() {
        let app_home = hd.join(".pittv3");
        if !app_home.exists() {
            let _ = create_dir_all(app_home);
        }
        let app_cfg = hd.join(".pittv3").join("pittv3.cfg");
        if let Ok(f) = File::open(app_cfg) {
            if let Ok(a) = serde_json::from_reader(&f) {
                return Ok(a);
            } else {
                return Err(Error::Unrecognized);
            }
        }
    }
    Err(Error::Unrecognized)
}

/// Saves a JSON representation of `args` to the pittv3.cfg file in the .pittv3 folder beneath the
/// user's home directory.
#[cfg(feature = "std")]
pub fn save_args(args: &Pittv3Args) -> Result<()> {
    if let Some(hd) = home_dir() {
        let app_cfg = hd.join(".pittv3").join("pittv3.cfg");
        if let Ok(json_args) = serde_json::to_string(&args) {
            if let Err(e) = fs::write(app_cfg, json_args) {
                error!("Unable to write args to file: {e}");
                return Err(Error::Unrecognized);
            } else {
                return Ok(());
            }
        }
    }
    Err(Error::Unrecognized)
}

/// Returns the text value associated with `key` in the given form event, or None if the key is
/// absent, the value is not text or the value is empty.
pub fn string_or_none(ev: &Event<FormData>, key: &str) -> Option<String> {
    match ev.get_first(key) {
        Some(FormValue::Text(s)) => {
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        _ => None,
    }
}

/// Returns the value associated with `key` in the given form event as a usize, or None if the key
/// is absent or the value is empty or cannot be parsed as a usize.
pub fn usize_or_none(ev: &Event<FormData>, key: &str) -> Option<usize> {
    match string_or_none(ev, key) {
        Some(v) => v.parse::<usize>().ok(),
        None => None,
    }
}

/// Returns true if the value associated with `key` in the given form event indicates a checked
/// checkbox and false otherwise, i.e., where the key is absent or the value is "0", "false" or empty.
pub fn true_or_false(ev: &Event<FormData>, key: &str) -> bool {
    match ev.get_first(key) {
        Some(FormValue::Text(s)) => !s.is_empty() && s != "0" && s != "false",
        _ => false,
    }
}

#[cfg(feature = "gui_desktop")]
use core::fmt::{Debug, Formatter};
#[cfg(feature = "gui_desktop")]
use log::Record;
#[cfg(feature = "gui_desktop")]
use log4rs::append::Append;

/// No-op log4rs appender used by desktop GUI frontends to discard log output when no logging
/// configuration is available.
#[cfg(feature = "gui_desktop")]
pub struct SimpleLogger;

#[cfg(feature = "gui_desktop")]
impl Debug for SimpleLogger {
    fn fmt(&self, _f: &mut Formatter<'_>) -> core::fmt::Result {
        Ok(())
    }
}

#[cfg(feature = "gui_desktop")]
impl Append for SimpleLogger {
    fn append(&self, _record: &Record<'_>) -> anyhow::Result<()> {
        Ok(())
    }

    fn flush(&self) {}
}
