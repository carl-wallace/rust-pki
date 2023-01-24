//! Wrappers around asn.1 encoder/decoder structures to support certification path processing

use alloc::collections::BTreeMap;

use crate::asn1::cryptographic_message_syntax2004::PivNaciIndicator;
use der::asn1::ObjectIdentifier;
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
    /// `get_extension` takes a static ObjectIdentifier that identifies and extension type and returns
    /// a previously parsed PDVExtension instance containing the decoded extension if the extension was present.
    fn get_extension(&self, oid: &'static ObjectIdentifier) -> Result<Option<&'_ PDVExtension>>;

    /// `parse_extension` takes a static ObjectIdentifier that identifies an extension type and returns
    /// a `PDVExtension` containing the a decoded extension if the extension was present.
    fn parse_extension(
        &'_ mut self,
        oid: &'static ObjectIdentifier,
    ) -> Result<Option<&'_ PDVExtension>>;

    /// `parse_extension` takes a static ObjectIdentifier that identifies and extension type and returns
    /// a `PDVExtension` containing the a decoded extension if the extension was present.
    fn parse_extensions(&'_ mut self, oids: &[&'static ObjectIdentifier]);
}

/// [`ParsedExtensions`] is a typedef of a BTreeMap map that associates [`PDVExtension`] objects with object
/// identifier values. This is used to avoid parsing extensions repeatedly when performing certification
/// path processing.
pub type ParsedExtensions<'a> = BTreeMap<&'a ObjectIdentifier, PDVExtension>;

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
