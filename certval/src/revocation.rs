//! Revocation status determination, including CRL and OCSP support
//!
//! The revocation module provides support for determining the revocation status of X.509 certificates.
//! Revocation support is available when the `revocation`, `revocation,std` or `remote` feature gates are used.
//! No revocation support is available when `default-features = false` or `std` feature gates are used.
//!
//! As shown in the example below, revocation status determination is performed after validating a certification path
//! via [`validate_path`](../certval/pki_environment/struct.PkiEnvironment.html#method.validate_path).
//! For convenience, [`check_revocation`](../revocation/check_revocation/fn.check_revocation.html) implements the [`ValidatePath`](../certval/pki_environment_traits/type.ValidatePath.html) type.
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
//! Revocation processing will be influenced by values included in the [`CertificationPathSettings`](../validator/path_results/type.CertificationPathResults.html) object, including:
//!
//! - [`PS_CHECK_REVOCATION_STATUS`](../validator/path_settings/static.PS_CHECK_REVOCATION_STATUS.html)
//! - [`PS_CHECK_OCSP_FROM_AIA`](../validator/path_settings/static.PS_CHECK_OCSP_FROM_AIA.html)
//! - [`PS_CHECK_CRLS`](../certval/path_settings/static.PS_CHECK_CRLS.html)
//! - [`PS_CHECK_CRLDP_HTTP`](../validator/path_settings/static.PS_CHECK_CRLDP_HTTP.html)
//! - [`PS_CRL_GRACE_PERIODS_AS_LAST_RESORT`](../validator/path_settings/static.PS_CRL_GRACE_PERIODS_AS_LAST_RESORT.html)
//! - [`PS_CRL_TIMEOUT`](../certval/path_settings/static.PS_CRL_TIMEOUT.html)
//! - [`PS_OCSP_AIA_NONCE_SETTING`](../validator/path_settings/static.PS_OCSP_AIA_NONCE_SETTING.html)
//!
pub mod check_revocation;

#[cfg(feature = "revocation")]
pub mod crl;
#[cfg(feature = "revocation")]
pub mod ocsp_client;

pub use crate::check_revocation::*;

#[cfg(feature = "revocation")]
pub use crate::crl::*;

#[cfg(feature = "remote")]
pub use crate::ocsp_client::*;
