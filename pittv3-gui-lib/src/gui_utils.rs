//! Provides GUI interface to similar set of actions as offered by command line utility

#![allow(non_snake_case)]

use dioxus::prelude::*;

#[cfg(feature = "std")]
use certval::{Error, Result};
#[cfg(feature = "std")]
use pittv3_lib::args::Pittv3Args;

#[cfg(feature = "std")]
use home::home_dir;
#[cfg(feature = "std")]
use log::error;
#[cfg(feature = "std")]
use std::fs;
#[cfg(feature = "std")]
use std::fs::{create_dir_all, File};

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

#[cfg(feature = "std")]
pub fn string_or_none(ev: &Event<FormData>, key: &str) -> Option<String> {
    if let Some(v) = ev.values.get(key) {
        if v[0].is_empty() {
            None
        } else {
            Some(v[0].clone())
        }
    } else {
        None
    }
}

#[cfg(feature = "std")]
pub fn usize_or_none(ev: &Event<FormData>, key: &str) -> Option<usize> {
    match string_or_none(ev, key) {
        Some(v) => match v.parse::<usize>() {
            Ok(u) => Some(u),
            Err(_) => None,
        },
        None => None,
    }
}

pub fn true_or_false(ev: &Event<FormData>, key: &str) -> bool {
    if let Some(v) = ev.values.get(key) {
        "0" != v[0]
    } else {
        false
    }
}

#[cfg(feature = "gui_desktop")]
use core::fmt::{Debug, Formatter};
#[cfg(feature = "gui_desktop")]
use log4rs::append::Append;

#[cfg(feature = "gui_desktop")]
use log::Record;

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
