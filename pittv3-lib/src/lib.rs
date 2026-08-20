#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

extern crate alloc;

pub mod args;
// Available in every build: it is the decode every entry point taking caller bytes has to do, and a
// build that cannot do it is one where a PEM file fails in a way that looks like something else.
pub mod der_or_pem;
#[cfg(feature = "std")]
pub mod graph_cache;
pub mod help;
pub mod no_std_utils;
pub mod options_no_std;
pub mod options_std;
pub mod options_std_app;
pub mod pitt_log;
pub mod report;
pub mod stats;
pub mod std_utils;
pub mod uri_check;

#[cfg(feature = "sha1_sig")]
pub mod sha1_sig;

pub use crate::args::Pittv3Args;
