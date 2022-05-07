#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod asn1;
pub mod environment;
pub mod source;
pub mod util;
pub mod validator;

#[cfg(feature = "revocation")]
pub mod revocation;

#[cfg(feature = "std")]
pub mod builder;

extern crate alloc;

pub use crate::asn1::*;

// order of pub use statements below is intended to assure the list emitted by cargo doc on the main
// index.html page is in alphabetical order.
#[cfg(feature = "std")]
pub use crate::builder::*;

pub use crate::environment::*;

#[cfg(feature = "revocation")]
pub use crate::revocation::*;

pub use crate::{source::*, util::*, validator::*};
