//! Sources of trust anchors, certificates and CRLs

pub mod cert_source;
pub mod ta_source;

// Adapters that read Microsoft CryptoAPI system stores into the two sources above. Gated on the
// target as well as the feature so that enabling `capi` in a workspace that also builds for other
// platforms is not an error there -- it simply contributes nothing.
#[cfg(all(windows, feature = "capi"))]
pub mod capi_source;

#[cfg(all(feature = "revocation", feature = "std"))]
pub mod crl_source;

// The status cache is gated on `revocation` alone. It shares the CRL sources' subject but not their
// requirements -- it holds determinations in a map and touches neither the filesystem nor the
// network -- so gating it on `std` would withhold it from callers that can use it, which is what
// happened while it lived in crl_source.
#[cfg(feature = "revocation")]
pub mod revocation_cache;

pub use crate::{source::cert_source::*, source::ta_source::*};

#[cfg(all(windows, feature = "capi"))]
pub use crate::source::capi_source::*;

#[cfg(all(feature = "revocation", feature = "std"))]
pub use crate::source::crl_source::*;

#[cfg(feature = "revocation")]
pub use crate::source::revocation_cache::*;
