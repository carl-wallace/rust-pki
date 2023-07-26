//! The pki_environment_traits module features trait definitions and type definitions that are used
//! by [`PkiEnvironment`] to provide functionality that supports building and/or validating X.509
//! certification paths.

use alloc::{string::String, vec::Vec};

use der::asn1::ObjectIdentifier;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::crl::CertificateList;
use x509_cert::name::Name;

use crate::util::error::*;
use crate::{
    CertificationPath, CertificationPathResults, CertificationPathSettings, PDVCertificate,
    PDVTrustAnchorChoice, PkiEnvironment,
};

/// `ValidatePath` provides a function signature for implementations that perform certification path
/// validation or that provide functionality in support of certification path validation.
pub type ValidatePath = fn(
    &PkiEnvironment<'_>,
    &CertificationPathSettings,    // path settings to govern validation
    &mut CertificationPath,        // path to verify
    &mut CertificationPathResults, // path validation results
) -> Result<()>;

/// `CalculateHash` provides a function signature for implementations that perform hashing
pub type CalculateHash = fn(
    &PkiEnvironment<'_>,
    &AlgorithmIdentifierOwned, // hash alg
    &[u8],                     // buffer to hash
) -> Result<Vec<u8>>;

/// `VerifySignature` provides a function signature for implementations that perform signature verification
/// over a message digest.
pub type VerifySignatureDigest = fn(
    &PkiEnvironment<'_>,
    &[u8],                      // buffer to verify
    &[u8],                      // signature
    &AlgorithmIdentifierOwned,  // signature algorithm
    &SubjectPublicKeyInfoOwned, // public key
) -> Result<()>;

/// `VerifySignature` provides a function signature for implementations that perform signature verification
/// over a message digest.
pub type VerifySignatureMessage = fn(
    &PkiEnvironment<'_>,
    &[u8],                      // message to hash and verify
    &[u8],                      // signature
    &AlgorithmIdentifierOwned,  // signature algorithm
    &SubjectPublicKeyInfoOwned, // public key
) -> Result<()>;

/// `GetTrustAnchors` provides a function signature for implementations that return a list of trust anchors
pub type GetTrustAnchors = fn(&PkiEnvironment<'_>, &mut Vec<Vec<u8>>) -> Result<()>;

/// `OidLookup` implementations take an OID and returns either a friendly name for the OID or a
/// NotFound error. Where NotFound is returned by all OidLookup implementations, the
/// [`PkiEnvironment`] returns a dot notation version of the OID.
pub type OidLookup = fn(&ObjectIdentifier) -> Result<String>;

/// The [`TrustAnchorSource`] trait enables trait objects to provide access to trust anchors backed via
/// some means, i.e., hard-coded, file-based, system store accessed via FFI, etc.
pub trait TrustAnchorSource {
    /// get_trust_anchors returns a vector with references to available trust anchors.
    fn get_trust_anchors(&'_ self) -> Result<Vec<&PDVTrustAnchorChoice>>;

    /// get_trust_anchor returns a reference to a trust anchor corresponding to the presented SKID.
    fn get_trust_anchor_by_skid(&self, skid: &[u8]) -> Result<&PDVTrustAnchorChoice>;

    /// get_trust_anchor_by_hex_skid returns a reference to a trust anchor corresponding to the presented hexadecimal SKID.
    fn get_trust_anchor_by_hex_skid(&'_ self, hex_skid: &str) -> Result<&PDVTrustAnchorChoice>;

    /// get_trust_anchor_for_name returns a reference to a trust anchor corresponding to present name.
    fn get_trust_anchor_by_name(&'_ self, target: &'_ Name) -> Result<&PDVTrustAnchorChoice>;

    /// get_trust_anchor_for_target returns a reference to a trust anchor corresponding to AKID or name from presented target.
    fn get_trust_anchor_for_target(
        &'_ self,
        target: &'_ PDVCertificate,
    ) -> Result<&PDVTrustAnchorChoice>;

    /// get_encoded_trust_anchor returns a copy of the encoded buffer for the trust anchor corresponding
    /// to the given SKID.
    fn get_encoded_trust_anchor(&self, skid: &[u8]) -> Result<Vec<u8>>;

    /// get_encoded_trust_anchor returns a vector containing copies of the available encoded trust anchors.
    fn get_encoded_trust_anchors(&self) -> Result<Vec<Vec<u8>>>;

    /// is_trust_anchor returns true if presented ta object is a trust anchor
    fn is_trust_anchor(&self, ta: &PDVTrustAnchorChoice) -> Result<()>;

    /// is_trust_anchor returns true if presented certificate object is a trust anchor
    fn is_cert_a_trust_anchor(&self, ta: &PDVCertificate) -> Result<()>;
}

/// The [`CertificateSource`] trait enables trait objects to provide access to certificates backed via
/// some means, i.e., hard-coded, file-based, system store accessed via FFI, etc.
pub trait CertificateSource {
    /// get_certificates returns a vector with references to available certificates.
    fn get_certificates(&'_ self) -> Result<Vec<&PDVCertificate>>;

    /// get_certificates_for_skid returns a vector of references to certificates corresponding to the presented SKID.
    fn get_certificates_for_skid(&self, skid: &[u8]) -> Result<Vec<&PDVCertificate>>;

    /// get_certificates_for_skid returns a vector of references to certificates corresponding to the presented subject name.
    fn get_certificates_for_name(&self, name: &Name) -> Result<Vec<&PDVCertificate>>;

    /// get_certificates_for_skid returns a vector of references to buffers corresponding to the presented SKID.
    fn get_encoded_certificates_for_skid(&self, skid: &[u8]) -> Result<Vec<Vec<u8>>>;

    /// get_certificates_for_skid returns a vector of references to buffers corresponding to the presented subject name.
    fn get_encoded_certificates_for_name(&self, name: &Name) -> Result<Vec<Vec<u8>>>;

    /// get_encoded_certificates returns a vector containing copies of the available encoded certificates.
    fn get_encoded_certificates(&self) -> Result<Vec<Vec<u8>>>;
}

/// The `CertificationPathBuilderFormats` enum is used to support possible future support for alternative
/// formats when serializing partial certification paths. At present, only CBOR is supported.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CertificationPathBuilderFormats {
    /// Serialize using CBOR format
    Cbor,
}

/// The [`CertificationPathBuilder`] trait defines the interface for implementations that support building
/// certification paths.
pub trait CertificationPathBuilder {
    /// find_paths_for_target takes a target certificate and a source for trust anchors and returns
    /// a vector of CertificationPath objects.
    fn get_paths_for_target<'a>(
        &self,
        pe: &PkiEnvironment<'a>,
        target: &PDVCertificate,
        paths: &mut Vec<CertificationPath>,
        threshold: usize,
        time_of_interest: u64,
    ) -> Result<()>;
}

/// The [`CrlSource`] trait defines the interface for storing and retrieving CRLs in support of certification path validation.
pub trait CrlSource {
    /// Retrieves CRLs for given certificate from store
    fn get_crls(&self, cert: &PDVCertificate) -> Result<Vec<Vec<u8>>>;
    /// Adds a CRL to the store
    fn add_crl(&self, crl_buf: &[u8], crl: &CertificateList, uri: &str) -> Result<()>;
}

/// The [`CheckRemoteResource`] trait defines an interface for checking last modified and blocklist values when downloading remote item
pub trait CheckRemoteResource {
    /// Gets last modified map or empty map
    fn get_last_modified(&self, uri: &str) -> Option<String>;

    /// Save last modified map, if desired
    fn set_last_modified(&self, uri: &str, last_modified: &str);

    /// Gets blocklist or empty vector
    fn check_blocklist(&self, uri: &str) -> bool;

    /// Save blocklist, if desired
    fn add_to_blocklist(&self, uri: &str);
}

/// The [`RevocationStatusCache`] trait defines the interface for storing and retrieving cached revocation status determinations
/// in support of certification path validation.
pub trait RevocationStatusCache {
    /// Returns Ok(Valid) is status is known to be good at time of interest, Ok(Revoked) if
    /// certificate is known to be revoked and Err(RevocationStatusDetermined) otherwise.
    fn get_status(&self, cert: &PDVCertificate, time_of_interest: u64) -> PathValidationStatus;

    /// Sets status for certificate to one of Valid or Revoked and a next update value.
    fn add_status(&self, cert: &PDVCertificate, next_update: u64, status: PathValidationStatus);
}
// TODO add allowlist and blocklist as RevocationStatusCache implementations
