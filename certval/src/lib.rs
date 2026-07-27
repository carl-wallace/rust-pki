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

// The module itself is always present because the environment traits reference the
// SubjectNameAndKey abstraction it hosts; the CRL/OCSP machinery within is feature-gated.
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

pub use crate::revocation::*;

#[cfg(feature = "pqc")]
pub use crate::util::{crypto_composite::*, crypto_pqc::*};

pub use crate::{source::*, util::*, validator::*};
