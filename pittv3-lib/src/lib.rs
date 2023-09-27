#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code, clippy::unwrap_used)]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod args;

#[cfg(feature = "std")]
pub mod options_std;
#[cfg(feature = "std_app")]
pub mod pitt_log;
pub mod stats;
pub mod std_utils;

#[cfg(not(feature = "std"))]
pub mod no_std_utils;

#[cfg(not(feature = "std_app"))]
pub mod options_no_std;

#[cfg(all(feature = "std_app", not(feature = "std")))]
pub mod options_std_app;

extern crate alloc;

#[cfg(any(feature = "std", feature = "std_app"))]
extern crate std;
