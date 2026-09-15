#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
// unused_qualifications is not included below because the rsx macro expansion trips it
#![warn(missing_docs, rust_2018_idioms)]

pub mod export;
pub mod gui_end_entity;
pub mod gui_help;
// The Inspect report, rendered. One component both frontends use: a store holds the same thing
// whichever application opened it.
pub mod gui_inspect;
pub mod gui_results;
pub mod gui_rows;
pub mod gui_settings;
pub mod gui_settings_model;
pub mod gui_shell;
pub mod gui_uri_check;
pub mod gui_utils;
pub mod retrieval;
pub mod settings_store;
pub mod store_provenance;
pub mod validate;

/// Shared stylesheet for GUI frontends; embed via a `style` element so each frontend ships one
/// consistent look without a filesystem or network dependency.
pub const PITTV3_CSS: &str = include_str!("../assets/pittv3.css");
