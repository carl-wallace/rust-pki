#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

extern crate alloc;

pub mod args;
pub mod no_std_utils;
pub mod options_no_std;
pub mod options_std;
pub mod options_std_app;
pub mod pitt_log;
pub mod stats;
pub mod std_utils;

#[cfg(feature = "sha1_sig")]
pub mod sha1_sig;

pub use crate::args::Pittv3Args;
