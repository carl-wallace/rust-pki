#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

pub mod config;
pub mod dto;
pub mod orchestrate;
pub mod routes;
pub mod settings;
pub mod stores;

pub use config::{RequestLimits, ServiceConfig, ServiceState};

/// `Cache-Control` for content served under a name that stays the same when the bytes behind it
/// change: keep a copy, but ask before using it.
///
/// Shared so the two surfaces that serve such content cannot drift apart — the static files, whose
/// header the binary sets, and the trust store artifacts, which the store handler sets for itself.
/// "no-cache" is "ask first", not "do not keep": the copy is still stored, and the question is
/// answered with a 304 rather than by re-sending a store that can run to several megabytes.
pub const CACHE_CONTROL_REVALIDATE: &str = "no-cache, must-revalidate";
