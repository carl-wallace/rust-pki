//! Revocation status determination, including CRL and OCSP support
//!
//! The revocation module provides support for determining the revocation status of X.509 certificates.
//! Revocation support is available when the `revocation`, `revocation,std` or `remote` feature gates are used.
//! No revocation support is available when `default-features = false` or `std` feature gates are used.
//!
//! As shown in the example below, revocation status determination is performed after validating a certification path
//! via [`PkiEnvironment::validate_path`](crate::PkiEnvironment::validate_path).
//! For convenience, [`check_revocation`](crate::check_revocation()) implements the [`ValidatePath`](crate::ValidatePath) type.
//!
//! ```no_run
//! #[tokio::test]
//! #[cfg(feature = "remote")]
//! async fn revocation_example() {
//! use certval::environment::PkiEnvironment;
//! use certval::source::{ta_source::TaSource, cert_source::CertSource, crl_source::CrlSourceFolders};
//! use certval::{CertificationPathSettings, CertificationPath, CertificationPathResults, check_revocation, get_time_of_interest, parse_cert};
//!
//! let ta_source = TaSource::default();
//! // populate TA source
//!
//! let cert_source = CertSource::default();
//! // populate certificate source
//!
//! let crl_source = CrlSourceFolders::new("/some/path/crls");
//!
//! // Create and populate a PkiEnvironment object
//! let mut pe = PkiEnvironment::default();
//! pe.populate_5280_pki_environment();
//! pe.add_trust_anchor_source(Box::new(ta_source.clone()));
//! pe.add_certificate_source(Box::new(cert_source.clone()));
//! pe.add_crl_source(Box::new(crl_source.clone()));
//! pe.add_revocation_cache(Box::new(RevocationCache::new()));
//!
//! let der_encoded_cert = include_bytes!("../tests/examples/GoodCACert.crt");
//! let target_cert = parse_cert(der_encoded_cert.as_slice(), "GoodCACert.crt")?;
//!
//! // Create a path settings instance (typically this would be deserialized from JSON)
//! let cps = CertificationPathSettings::default();
//!
//! let mut paths: Vec<CertificationPath> = vec![];
//! let r = pe.get_paths_for_target(&pe, &target_cert, &mut paths, 0, get_time_of_interest(&cps));
//!
//! for path in &mut paths {
//!     let mut cpr = CertificationPathResults::new();
//!     let mut r = pe.validate_path(&pe, &cps, path, &mut cpr);
//!     if r.is_ok() {
//!         r = check_revocation(&pe, &cps, path, &mut cpr).await;
//!     }
//! }
//! }
//! ```
//!
//! Revocation processing will be influenced by values included in the [`CertificationPathSettings`](crate::CertificationPathSettings) object, including:
//!
//! - [`PS_CHECK_REVOCATION_STATUS`](crate::PS_CHECK_REVOCATION_STATUS)
//! - [`PS_CHECK_OCSP_FROM_AIA`](crate::PS_CHECK_OCSP_FROM_AIA)
//! - [`PS_CHECK_CRLS`](crate::PS_CHECK_CRLS)
//! - [`PS_CHECK_CRLDP_HTTP`](crate::PS_CHECK_CRLDP_HTTP)
//! - [`PS_CRL_GRACE_PERIODS_AS_LAST_RESORT`](crate::PS_CRL_GRACE_PERIODS_AS_LAST_RESORT)
//! - [`PS_CRL_TIMEOUT`](crate::PS_CRL_TIMEOUT)
//! - [`PS_OCSP_AIA_NONCE_SETTING`](crate::PS_OCSP_AIA_NONCE_SETTING)
//!
#[cfg(feature = "revocation")]
pub mod check_revocation;
pub mod subject_name_and_key;

#[cfg(feature = "revocation")]
pub mod crl;
#[cfg(feature = "revocation")]
pub mod ocsp_client;

#[cfg(feature = "revocation")]
pub use crate::check_revocation::*;
pub use crate::revocation::subject_name_and_key::*;

#[cfg(feature = "revocation")]
pub use crate::crl::*;

// Gated on `revocation`, which is what gates the module itself, rather than on `remote`. The
// OCSP code divides into processing a response and going to fetch one, and only the second needs
// `remote` — `send_ocsp_request` carries that gate itself. Re-exporting the whole module behind
// `remote` hid the first from every build that cannot fetch, which is exactly the build that has to
// be handed a response by its caller.
#[cfg(feature = "revocation")]
pub use crate::ocsp_client::*;
