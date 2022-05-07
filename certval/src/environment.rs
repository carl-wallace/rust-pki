//! Callback and trait object switchboard to support certification path validation

pub mod pki_environment;
pub mod pki_environment_traits;

pub use crate::{environment::pki_environment::*, environment::pki_environment_traits::*};
