//! Sources of trust anchors, certificates and CRLs

pub mod cert_source;
pub mod ta_source;

// Row views over the two sources above. Ungated and free of I/O: a row is a projection of state
// already held, so every build that can hold a source can present one.
pub mod rows;

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

// Ungated, unlike `crl_source` above and the status cache beside it. CRLs in a vector need neither
// the filesystem nor `revocation`'s processing code -- `CrlSource` is a plain trait, always present
// -- and the callers who cannot use `crl_source` are exactly the ones who need this, so a gate here
// would withhold it from them. A consumer taking certval with default features off still gets it.
pub mod memory_crl_source;

pub use crate::{source::cert_source::*, source::rows::*, source::ta_source::*};

#[cfg(all(windows, feature = "capi"))]
pub use crate::source::capi_source::*;

#[cfg(all(feature = "revocation", feature = "std"))]
pub use crate::source::crl_source::*;

#[cfg(feature = "revocation")]
pub use crate::source::revocation_cache::*;

pub use crate::source::memory_crl_source::*;
