#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
// unused_qualifications is not included below because the rsx macro expansion trips it
#![warn(missing_docs, rust_2018_idioms)]

pub mod gui_settings;
pub mod gui_utils;
