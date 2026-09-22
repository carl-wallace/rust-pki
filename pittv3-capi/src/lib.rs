#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// Deliberately `deny` rather than `forbid`, which is the one difference between this crate and its
// neighbors. `certval`, `pittv3-gui` and `pittv3-gui-lib` all `forbid(unsafe_code)`, and every Win32
// entry point in the `windows` crate is an `unsafe fn`; this crate exists so that the unsafe has
// somewhere to live that is not one of those three. `deny` plus an explicit `allow` on the single
// module that needs it keeps every other line here under the same rule the neighbors are under, and
// makes any second site that wants unsafe an edit someone has to justify.
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

extern crate alloc;

pub mod status;
pub mod types;

/// The Windows chain engine, wrapped. Absent on every other target.
#[cfg(windows)]
#[allow(unsafe_code)]
pub mod capi_verify;

pub use crate::status::*;
pub use crate::types::*;

#[cfg(windows)]
pub use crate::capi_verify::verify;

/// Builds and validates a certification path using the Windows chain engine.
///
/// This is the non-Windows definition, which always returns [`CapiVerifyError::Unsupported`]. It
/// exists so that a caller can name the function without a `cfg` of its own: the GUI's Validate
/// Using CAPI action is one call site, and a call site that has to be conditionally compiled tends
/// to acquire a conditionally compiled button, a conditionally compiled results pane and a
/// conditionally compiled test beside it.
///
/// See the Windows definition, in the `capi_verify` module, for what the real one does. Named
/// rather than linked: that module is `cfg(windows)`, so on this target there is nothing to link
/// to and an intra-doc link here fails the documentation build for every other platform.
#[cfg(not(windows))]
pub fn verify(
    _target_der: &[u8],
    _options: &CapiOptions,
) -> Result<CapiVerification, CapiVerifyError> {
    Err(CapiVerifyError::Unsupported)
}
