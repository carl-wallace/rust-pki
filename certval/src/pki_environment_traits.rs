//! Trait definitions and type definitions used by PkiEnvironment objects.

use crate::error::*;
use crate::CertificationPath;
use crate::{PDVCertificate, PDVTrustAnchorChoice, PkiEnvironment};
use alloc::vec::Vec;
use x509::Name;

/*
/// The `Credential` trait is used to provide access to cryptographic keying material within the
/// [`PkiEnvironment`] construction.
pub trait Credential {
    /// get_name returns a friendly name for a credential
    fn get_name(&self) -> Option<String>;
    /// get_ascii_hex_key_id returns the ASCII hexadecimal representation of the key identifier associated with a credential
    fn get_ascii_hex_key_id(&self) -> Option<String>;
    /// get_key_id returns the key identifier associated with a credential
    fn get_key_id(&self) -> Option<Vec<u8>>;
}
*/

/// The [`TrustAnchorSource`] trait enables trait objects to provide access to trust anchors backed via
/// some means, i.e., hard-coded, file-based, system store accessed via FFI, etc.
pub trait TrustAnchorSource {
    /// get_trust_anchors returns a vector with references to available trust anchors.
    fn get_trust_anchors(&'_ self) -> Result<Vec<&PDVTrustAnchorChoice<'_>>>;

    /// get_trust_anchor returns a reference to a trust anchor corresponding to the presented SKID.
    fn get_trust_anchor_by_skid(&self, skid: &[u8]) -> Result<&PDVTrustAnchorChoice<'_>>;

    /// get_trust_anchor_by_hex_skid returns a reference to a trust anchor corresponding to the presented hexadecimal SKID.
    fn get_trust_anchor_by_hex_skid(&'_ self, hex_skid: &str) -> Result<&PDVTrustAnchorChoice<'_>>;

    /// get_trust_anchor_for_name returns a reference to a trust anchor corresponding to present name.
    fn get_trust_anchor_by_name(
        &'_ self,
        pe: &PkiEnvironment<'_>,
        target: &'_ Name<'_>,
    ) -> Result<&PDVTrustAnchorChoice<'_>>;

    /// get_trust_anchor_for_target returns a reference to a trust anchor corresponding to AKID or name from presented target.
    fn get_trust_anchor_for_target(
        &'_ self,
        pe: &PkiEnvironment<'_>,
        target: &'_ PDVCertificate<'_>,
    ) -> Result<&PDVTrustAnchorChoice<'_>>;

    /// get_encoded_trust_anchor returns a copy of the encoded buffer for the trust anchor corresponding
    /// to the given SKID.
    fn get_encoded_trust_anchor(&self, skid: &[u8]) -> Result<Vec<u8>>;

    /// get_encoded_trust_anchor returns a vector containing copies of the available encoded trust anchors.
    fn get_encoded_trust_anchors(&self) -> Result<Vec<Vec<u8>>>;

    /// get_trust_anchors returns a complete list of all trust anchors available via a given source.
    fn is_trust_anchor(&self, ta: &PDVTrustAnchorChoice<'_>) -> Result<bool>;
}

/// The [`CertificateSource`] trait enables trait objects to provide access to certificates backed via
/// some means, i.e., hard-coded, file-based, system store accessed via FFI, etc.
pub trait CertificateSource {
    /// get_certificates returns a vector with references to available certificates.
    fn get_certificates(&'_ self) -> Result<Vec<&PDVCertificate<'_>>>;

    /// get_certificates_for_skid returns a vector of references to certificates corresponding to the presented SKID.
    fn get_certificates_for_skid(&self, skid: &[u8]) -> Result<Vec<&PDVCertificate<'_>>>;

    /// get_certificates_for_skid returns a vector of references to certificates corresponding to the presented subject name.
    fn get_certificates_for_name(
        &self,
        pe: &PkiEnvironment<'_>,
        name: &Name<'_>,
    ) -> Result<Vec<&PDVCertificate<'_>>>;

    /// get_certificates_for_skid returns a vector of references to buffers corresponding to the presented SKID.
    fn get_encoded_certificates_for_skid(&self, skid: &[u8]) -> Result<Vec<Vec<u8>>>;

    /// get_certificates_for_skid returns a vector of references to buffers corresponding to the presented subject name.
    fn get_encoded_certificates_for_name(
        &self,
        pe: &PkiEnvironment<'_>,
        name: &Name<'_>,
    ) -> Result<Vec<Vec<u8>>>;

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
    fn get_paths_for_target<'a, 'reference>(
        &'a self,
        pe: &'a PkiEnvironment<'a>,
        target: &'a PDVCertificate<'a>,
        paths: &'reference mut Vec<CertificationPath<'a>>,
        threshold: usize,
        time_of_interest: u64,
    ) -> Result<()>
    where
        'a: 'reference;
}
