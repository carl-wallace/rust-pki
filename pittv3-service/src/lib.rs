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
