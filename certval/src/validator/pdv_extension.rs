//! Wrappers around asn.1 encoder/decoder structures to support certification path processing

use alloc::collections::BTreeMap;

use crate::asn1::piv_naci_indicator::{PivNaciIndicator, PIV_NACI_INDICATOR};
use const_oid::db::rfc5912::{
    ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS, ID_CE_CERTIFICATE_POLICIES,
    ID_CE_CRL_DISTRIBUTION_POINTS, ID_CE_EXT_KEY_USAGE, ID_CE_INHIBIT_ANY_POLICY,
    ID_CE_ISSUER_ALT_NAME, ID_CE_KEY_USAGE, ID_CE_NAME_CONSTRAINTS, ID_CE_POLICY_CONSTRAINTS,
    ID_CE_POLICY_MAPPINGS, ID_CE_PRIVATE_KEY_USAGE_PERIOD, ID_CE_SUBJECT_ALT_NAME,
    ID_CE_SUBJECT_KEY_IDENTIFIER, ID_PE_AUTHORITY_INFO_ACCESS, ID_PE_SUBJECT_INFO_ACCESS,
};
use const_oid::db::rfc6960::ID_PKIX_OCSP_NOCHECK;
use der::{asn1::ObjectIdentifier, Decode};
use x509_cert::ext::{pkix::crl::CrlDistributionPoints, pkix::*};
use x509_ocsp::OcspNoCheck;

use crate::util::error::*;

/// The [`ExtensionProcessing`] trait provides a common means of extracting extensions from objects that
/// feature extensions, like Certificate, TrustAnchorChoice, etc. and that retain copies of the
/// decoded extension structures, like `PDVCertificate`, `PDVTrustAnchorChoice`, etc.
///
/// Extensions are primarily used during certification path development and validation. Prior to
/// performing these actions, the parse_extensions method should be used to parse the extensions
/// that will be used to build and validate certification paths. The decoded extensions will be
/// cached and accessed via the get_extension function.
pub trait ExtensionProcessing {
    /// `get_extension` takes an ObjectIdentifier that identifies an extension type and returns the
    /// previously parsed [`PDVExtension`] for it, or `None` if that extension has not been parsed.
    fn get_extension(&self, oid: &ObjectIdentifier) -> Result<Option<&PDVExtension>>;

    /// `parse_extension` takes an ObjectIdentifier that identifies an extension type, decodes that
    /// extension if it is present, caches the result and returns it.
    fn parse_extension(&mut self, oid: &ObjectIdentifier) -> Result<Option<&PDVExtension>>;

    /// `parse_extensions` takes a slice of ObjectIdentifiers and calls [`parse_extension`](Self::parse_extension)
    /// for each, caching whichever of those extensions are present. Errors are not reported: an
    /// extension that is absent or fails to decode is simply left out of the cache.
    fn parse_extensions(&mut self, oids: &[ObjectIdentifier]);
}

/// [`ParsedExtensions`] is a typedef of a BTreeMap map that associates [`PDVExtension`] objects with object
/// identifier values. This is used to avoid parsing extensions repeatedly when performing certification
/// path processing.
pub type ParsedExtensions = BTreeMap<ObjectIdentifier, PDVExtension>;

/// [`PDVExtension`] provides a wrapper for supported extension types. At present this does not support
/// the CRLReason, IssuingDistributionPoint, FreshestCRL and CRLDistributionPoints extensions.
#[derive(PartialEq, Clone, Eq)]
pub enum PDVExtension {
    /// Parsed BasicConstraints extension
    BasicConstraints(BasicConstraints),
    /// Parsed SubjectKeyIdentifier extension
    SubjectKeyIdentifier(SubjectKeyIdentifier),
    /// Parsed ExtendedKeyUsage extension
    ExtendedKeyUsage(ExtendedKeyUsage),
    /// Parsed AuthorityInfoAccessSyntax extension
    AuthorityInfoAccessSyntax(AuthorityInfoAccessSyntax),
    /// Parsed SubjectInfoAccessSyntax extension
    SubjectInfoAccessSyntax(SubjectInfoAccessSyntax),
    /// Parsed KeyUsage extension
    KeyUsage(KeyUsage),
    /// Parsed SubjectAltName extension
    SubjectAltName(SubjectAltName),
    /// Parsed IssuerAltName extension
    IssuerAltName(IssuerAltName),
    /// Parsed PrivateKeyUsagePeriod extension
    PrivateKeyUsagePeriod(PrivateKeyUsagePeriod),
    /// Parsed CRLNumber extension
    CrlNumber(CrlNumber),
    /// Parsed CRLReason extension
    CrlReason(CrlReason),
    /// Parsed NameConstraints extension
    NameConstraints(NameConstraints),
    /// Parsed CertificatePolicies extension
    CertificatePolicies(CertificatePolicies),
    /// Parsed PolicyMappings extension
    PolicyMappings(PolicyMappings),
    /// Parsed AuthorityKeyIdentifier extension
    AuthorityKeyIdentifier(AuthorityKeyIdentifier),
    /// Parsed PolicyConstraints extension
    PolicyConstraints(PolicyConstraints),
    /// Parsed InhibitAnyPolicy extension
    InhibitAnyPolicy(InhibitAnyPolicy),
    /// Parsed OcspNoCheck extension
    OcspNoCheck(OcspNoCheck),
    /// Parsed PivNaciIndicator extension
    PivNaciIndicator(PivNaciIndicator),
    /// Parsed IssuingDistributionPoint extension
    IssuingDistributionPoint(IssuingDistributionPoint),
    /// Parsed CRLDistributionPoints extension
    CrlDistributionPoints(CrlDistributionPoints),
    /// Parsed FreshestCRL extension
    FreshestCrl(FreshestCrl),
    /// Unparsed, unrecognized extension
    Unrecognized(),
}

/// `decode_extension` decodes the value of an extension identified by `oid` into the matching
/// [`PDVExtension`] variant. It returns `Ok(None)` for an OID it has no decoder for and an error
/// when the value does not decode. It is the one decoder behind both `parse_extension`
/// implementations and the check in `check_critical_extensions` that refuses a path whose
/// processed extensions do not decode.
pub(crate) fn decode_extension(
    oid: &ObjectIdentifier,
    value: &[u8],
) -> Result<Option<PDVExtension>> {
    macro_rules! decode {
        ($t:ident) => {
            PDVExtension::$t($t::from_der(value)?)
        };
    }

    let ext = match *oid {
        ID_CE_BASIC_CONSTRAINTS => decode!(BasicConstraints),
        ID_CE_SUBJECT_KEY_IDENTIFIER => decode!(SubjectKeyIdentifier),
        ID_CE_EXT_KEY_USAGE => decode!(ExtendedKeyUsage),
        ID_PE_AUTHORITY_INFO_ACCESS => decode!(AuthorityInfoAccessSyntax),
        ID_PE_SUBJECT_INFO_ACCESS => decode!(SubjectInfoAccessSyntax),
        ID_CE_KEY_USAGE => decode!(KeyUsage),
        ID_CE_SUBJECT_ALT_NAME => decode!(SubjectAltName),
        ID_CE_ISSUER_ALT_NAME => decode!(IssuerAltName),
        ID_CE_PRIVATE_KEY_USAGE_PERIOD => decode!(PrivateKeyUsagePeriod),
        ID_CE_NAME_CONSTRAINTS => decode!(NameConstraints),
        ID_CE_CRL_DISTRIBUTION_POINTS => decode!(CrlDistributionPoints),
        ID_CE_CERTIFICATE_POLICIES => decode!(CertificatePolicies),
        ID_CE_POLICY_MAPPINGS => decode!(PolicyMappings),
        ID_CE_AUTHORITY_KEY_IDENTIFIER => decode!(AuthorityKeyIdentifier),
        ID_CE_POLICY_CONSTRAINTS => decode!(PolicyConstraints),
        ID_CE_INHIBIT_ANY_POLICY => decode!(InhibitAnyPolicy),
        ID_PKIX_OCSP_NOCHECK => decode!(OcspNoCheck),
        PIV_NACI_INDICATOR => decode!(PivNaciIndicator),
        _ => return Ok(None),
    };
    Ok(Some(ext))
}
