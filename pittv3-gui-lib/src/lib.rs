#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code, clippy::unwrap_used)]
//todo restore missing_docs
#![warn(rust_2018_idioms)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod gui_settings;
pub mod gui_utils;

extern crate alloc;

#[cfg(any(feature = "std", feature = "std_app"))]
extern crate std;
