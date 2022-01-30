//! Wrappers around asn.1 encoder/decoder structures to support certification path processing

use crate::error::*;
use crate::pdv_utilities::get_str_from_atav;
use alloc::collections::BTreeMap;
use alloc::{string::String, vec::Vec};
use der::Decodable;
use der::Decoder;
use regex::Regex;
use x509::trust_anchor_format::TrustAnchorChoice;
use x509::*;

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
    fn get_extension(&self, oid: &'static ObjectIdentifier)
        -> Result<Option<&'_ PDVExtension<'_>>>;

    /// `parse_extension` takes a static ObjectIdentifier that identifies an extension type and returns
    /// a `PDVExtension` containing the a decoded extension if the extension was present.
    fn parse_extension(
        &'_ mut self,
        oid: &'static ObjectIdentifier,
    ) -> Result<Option<&'_ PDVExtension<'_>>>;

    /// `parse_extension` takes a static ObjectIdentifier that identifies and extension type and returns
    /// a `PDVExtension` containing the a decoded extension if the extension was present.
    fn parse_extensions(&'_ mut self, oids: &[&'static ObjectIdentifier]);
}

/// [`ParsedExtensions`] is a typedef of a BTreeMap map that associates [`PDVExtension`] objects with object
/// identifier values. This is used to avoid parsing extensions repeatedly when performing certification
/// path processing.
pub type ParsedExtensions<'a> = BTreeMap<&'a ObjectIdentifier, PDVExtension<'a>>;

/// [`Asn1Metadata`] is a typedef of a BTreeMap map that associates types represented by the [`Asn1MetadataTypes`]
/// enum objects with arbitrary string values. At present this is only used to convey filenames and
/// may be dropped in favor of a String filename member in place of current [`Asn1Metadata`] members..
pub type Asn1Metadata<'a> = BTreeMap<&'a str, Asn1MetadataTypes>;

/// [`MD_LOCATOR`] is used to set/get a String value to/from an [`Asn1Metadata`] object. The value
/// may represent a file name, URI or other locator for troubleshooting purposes.
pub static MD_LOCATOR: &str = "mdLocator";

/// [`PDVExtension`] provides a wrapper for supported extension types. At present this does not support
/// the CRLReason, IssuingDistributionPoint, FreshestCRL and CRLDistributionPoints extensions.
#[derive(PartialEq, Clone, Eq)]
pub enum PDVExtension<'a> {
    //TODO - add support for more extensions
    /// Parsed BasicConstraints extension
    BasicConstraints(BasicConstraints),
    /// Parsed SubjectKeyIdentifier extension
    SubjectKeyIdentifier(SubjectKeyIdentifier<'a>),
    /// Parsed ExtendedKeyUsage extension
    ExtendedKeyUsage(ExtendedKeyUsage<'a>),
    /// Parsed AuthorityInfoAccessSyntax extension
    AuthorityInfoAccessSyntax(AuthorityInfoAccessSyntax<'a>),
    /// Parsed SubjectInfoAccessSyntax extension
    SubjectInfoAccessSyntax(SubjectInfoAccessSyntax<'a>),
    /// Parsed KeyUsage extension
    KeyUsage(KeyUsage<'a>),
    /// Parsed SubjectAltName extension
    SubjectAltName(SubjectAltName<'a>),
    /// Parsed IssuerAltName extension
    IssuerAltName(IssuerAltName<'a>),
    /// Parsed PrivateKeyUsagePeriod extension
    PrivateKeyUsagePeriod(PrivateKeyUsagePeriod),
    /// Parsed CRLNumber extension
    CRLNumber(CRLNumber<'a>),
    //CRLReason(CRLReason),
    //IssuingDistributionPoint(IssuingDistributionPoint<'a>),
    /// Parsed NameConstraints extension
    NameConstraints(NameConstraints<'a>),
    /// Parsed CRLDistributionPoints extension
    //CRLDistributionPoints(CRLDistributionPoints<'a>),
    /// Parsed CertificatePolicies extension
    CertificatePolicies(CertificatePolicies<'a>),
    /// Parsed PolicyMappings extension
    PolicyMappings(PolicyMappings<'a>),
    /// Parsed AuthorityKeyIdentifier extension
    AuthorityKeyIdentifier(AuthorityKeyIdentifier<'a>),
    /// Parsed PolicyConstraints extension
    PolicyConstraints(PolicyConstraints),
    /// Parsed FreshestCRL extension
    //FreshestCRL(FreshestCRL<'a>),
    /// Parsed InhibitAnyPolicy extension
    InhibitAnyPolicy(InhibitAnyPolicy),
    /// Parsed OcspNoCheck extension
    OcspNoCheck(OcspNoCheck),
    /// Parsed PivNaciIndicator extension
    PivNaciIndicator(PivNaciIndicator),
    /// Unparsed, unrecognized extension
    Unrecognized(),
}

/// Small assortment of types that can be used to save metadata collected during certification path
/// processing. For example, saving whether or not a certificate is self-issued or self-signed.
#[derive(PartialEq, Clone, Eq)]
pub enum Asn1MetadataTypes {
    /// Used for metadata represented as a bool
    Bool(bool),
    /// Used for metadata represented as a u32
    Number(u32),
    /// Used for metadata represented as a String
    String(String),
    /// Used for metadata represented as a Vec<u8>
    Buffer(Vec<u8>),
}

/// [`PDVCertificate`] is used to aggregate a binary, DER-encoded Certificate, a parsed Certificate, optional metadata
/// and optional parsed extensions in support of certification path development and validation operations.
///
/// The parsed extensions are usually those listed in tne [`EXTS_OF_INTEREST`](../path_validator/constant.EXTS_OF_INTEREST.html).
#[derive(Clone, Eq, PartialEq)]
pub struct PDVCertificate<'a> {
    /// Binary, encoded Certificate object
    pub encoded_cert: &'a [u8],
    /// Decoded Certificate object
    pub decoded_cert: Certificate<'a>,
    /// Optional metadata about the trust anchor
    pub metadata: Option<Asn1Metadata<'a>>,
    /// Optional parsed extension from the Certificate
    pub parsed_extensions: ParsedExtensions<'a>,
}

impl<'a> ExtensionProcessing for PDVCertificate<'a> {
    /// `get_extension` takes a static ObjectIdentifier that identifies and extension type and returns
    /// a previously parsed [`PDVExtension`] instance containing the decoded extension if the extension was present.
    fn get_extension(
        &self,
        oid: &'static ObjectIdentifier,
    ) -> Result<Option<&'_ PDVExtension<'_>>> {
        if self.parsed_extensions.contains_key(oid) {
            return Ok(Some(self.parsed_extensions.get(oid).unwrap()));
        }
        Ok(None)
    }

    /// `parse_extension` takes a static ObjectIdentifier that identifies and extension type and returns
    /// a [`PDVExtension`] containing the a decoded extension if the extension was present.
    fn parse_extensions(&'_ mut self, oids: &[&'static ObjectIdentifier]) {
        for oid in oids {
            let _r = self.parse_extension(oid);
        }
    }

    fn parse_extension(
        &mut self,
        oid: &'static ObjectIdentifier,
    ) -> Result<Option<&PDVExtension<'a>>> {
        macro_rules! add_and_return {
            ($pe:ident, $v:ident, $oid:ident, $t:ident) => {
                if let Ok(r) = $t::from_der($v) {
                    let ext = PDVExtension::$t(r);
                    $pe.insert(oid, ext);
                    return Ok(Some(&$pe[oid]));
                }
                return Err(Error::EncodingError);
            };
        }

        let pe = &mut self.parsed_extensions;
        if pe.contains_key(oid) {
            return Ok(Some(pe.get(oid).unwrap()));
        }

        if let Some(exts) = self.decoded_cert.tbs_certificate.extensions.as_ref() {
            if let Some(i) = exts.iter().find(|&ext| ext.extn_id == *oid) {
                let v = i.extn_value;
                match *oid {
                    PKIX_CE_BASIC_CONSTRAINTS => {
                        add_and_return!(pe, v, PKIX_CE_BASIC_CONSTRAINTS, BasicConstraints);
                    }
                    PKIX_CE_SUBJECT_KEY_IDENTIFIER => {
                        add_and_return!(
                            pe,
                            v,
                            PKIX_CE_SUBJECT_KEY_IDENTIFIER,
                            SubjectKeyIdentifier
                        );
                    }
                    PKIX_CE_EXTKEYUSAGE => {
                        add_and_return!(pe, v, PKIX_CE_EXTKEYUSAGE, ExtendedKeyUsage);
                    }
                    PKIX_PE_AUTHORITYINFOACCESS => {
                        add_and_return!(
                            pe,
                            v,
                            PKIX_PE_AUTHORITYINFOACCESS,
                            AuthorityInfoAccessSyntax
                        );
                    }
                    PKIX_PE_SUBJECTINFOACCESS => {
                        add_and_return!(pe, v, PKIX_PE_SUBJECTINFOACCESS, SubjectInfoAccessSyntax);
                    }
                    PKIX_CE_KEY_USAGE => {
                        add_and_return!(pe, v, PKIX_CE_KEY_USAGE, KeyUsage);
                    }
                    PKIX_CE_SUBJECT_ALT_NAME => {
                        add_and_return!(pe, v, PKIX_CE_SUBJECT_ALT_NAME, SubjectAltName);
                    }
                    PKIX_CE_ISSUER_ALT_NAME => {
                        add_and_return!(pe, v, PKIX_CE_ISSUER_ALT_NAME, IssuerAltName);
                    }
                    PKIX_CE_PRIVATE_KEY_USAGE_PERIOD => {
                        add_and_return!(
                            pe,
                            v,
                            PKIX_CE_PRIVATE_KEY_USAGE_PERIOD,
                            PrivateKeyUsagePeriod
                        );
                    }
                    PKIX_CE_CRLNUMBER => {
                        add_and_return!(pe, v, PKIX_CE_CRLNUMBER, CRLNumber);
                    }
                    // PKIX_CE_CRLREASONS => {
                    //     add!(pe, v, PKIX_CE_CRLREASONS, CRLReason);
                    // }
                    // PKIX_CE_ISSUINGDISTRIBUTIONPOINT => {
                    //     add!(
                    //         pe,
                    //         v,
                    //         PKIX_CE_ISSUINGDISTRIBUTIONPOINT,
                    //         IssuingDistributionPoint
                    //     );
                    // }
                    PKIX_CE_NAME_CONSTRAINTS => {
                        add_and_return!(pe, v, PKIX_CE_NAME_CONSTRAINTS, NameConstraints);
                    }
                    // PKIX_CE_CRL_DISTRIBUTION_POINTS => {
                    //     add_and_return!(
                    //         pe,
                    //         v,
                    //         PKIX_CE_CRL_DISTRIBUTION_POINTS,
                    //         CRLDistributionPoints
                    //     );
                    // }
                    PKIX_CE_CERTIFICATE_POLICIES => {
                        add_and_return!(pe, v, PKIX_CE_CERTIFICATE_POLICIES, CertificatePolicies);
                    }
                    PKIX_CE_POLICY_MAPPINGS => {
                        add_and_return!(pe, v, PKIX_CE_POLICY_MAPPINGS, PolicyMappings);
                    }
                    PKIX_CE_AUTHORITY_KEY_IDENTIFIER => {
                        add_and_return!(
                            pe,
                            v,
                            PKIX_CE_AUTHORITY_KEY_IDENTIFIER,
                            AuthorityKeyIdentifier
                        );
                    }
                    PKIX_CE_POLICY_CONSTRAINTS => {
                        add_and_return!(pe, v, PKIX_CE_POLICY_CONSTRAINTS, PolicyConstraints);
                    }
                    // PKIX_CE_FRESHEST_CRL => {
                    //     add_and_return!(pe, v, PKIX_CE_FRESHEST_CRL, FreshestCRL);
                    // }
                    PKIX_CE_INHIBIT_ANY_POLICY => {
                        add_and_return!(pe, v, PKIX_CE_INHIBIT_ANY_POLICY, InhibitAnyPolicy);
                    }
                    PKIX_OCSP_NOCHECK => {
                        add_and_return!(pe, v, PKIX_OCSP_NOCHECK, OcspNoCheck);
                    }
                    PIV_NACI_INDICATOR => {
                        add_and_return!(pe, v, PIV_NACI_INDICATOR, PivNaciIndicator);
                    }
                    _ => {
                        return Err(Error::Unrecognized);
                    }
                }
            }
        }
        Ok(None)
    }
}

/// [`PDVTrustAnchorChoice`] is used to aggregate a binary TrustAnchorChoice, a parsed TrustAnchorChoice,
/// optional metadata and optional parsed extensions in support of certification path development and
/// validation operations.
#[derive(Clone, Eq, PartialEq)]
pub struct PDVTrustAnchorChoice<'a> {
    /// Binary, encoded TrustAnchorChoice object
    pub encoded_ta: &'a [u8],
    /// Decoded TrustAnchorChoice object
    pub decoded_ta: TrustAnchorChoice<'a>,
    /// Optional metadata about the trust anchor
    pub metadata: Option<Asn1Metadata<'a>>,
    /// Optional parsed extension from the TrustAnchorChoice
    pub parsed_extensions: ParsedExtensions<'a>,
}

impl ExtensionProcessing for PDVTrustAnchorChoice<'_> {
    /// `get_extension` takes a static ObjectIdentifier that identifies and extension type and returns
    /// a previously parsed PDVExtension instance containing the decoded extension if the extension was present.
    fn get_extension(
        &self,
        oid: &'static ObjectIdentifier,
    ) -> Result<Option<&'_ PDVExtension<'_>>> {
        if self.parsed_extensions.contains_key(oid) {
            return Ok(Some(self.parsed_extensions.get(oid).unwrap()));
        }
        Ok(None)
    }

    /// `parse_extension` takes a static ObjectIdentifier that identifies and extension type and returns
    /// a [`PDVExtension`] containing the a decoded extension if the extension was present.
    fn parse_extensions(&'_ mut self, oids: &[&'static ObjectIdentifier]) {
        for oid in oids {
            let _r = self.parse_extension(oid);
        }
    }

    fn parse_extension(
        &mut self,
        oid: &'static ObjectIdentifier,
    ) -> Result<Option<&PDVExtension<'_>>> {
        macro_rules! add_and_return {
            ($pe:ident, $v:ident, $oid:ident, $t:ident) => {
                if let Ok(r) = $t::from_der($v) {
                    let ext = PDVExtension::$t(r);
                    $pe.insert(oid, ext);
                    return Ok(Some(&$pe[oid]));
                }
                return Err(Error::EncodingError);
            };
        }

        let pe = &mut self.parsed_extensions;
        if pe.contains_key(oid) {
            return Ok(Some(pe.get(oid).unwrap()));
        }

        let exts = match &self.decoded_ta {
            TrustAnchorChoice::Certificate(c) => &c.tbs_certificate.extensions,
            TrustAnchorChoice::TaInfo(tai) => {
                if let Some(cp) = &tai.cert_path {
                    if *oid == PKIX_CE_NAME_CONSTRAINTS {
                        if let Some(nc) = &cp.name_constr {
                            let ext = PDVExtension::NameConstraints(nc.clone());
                            pe.insert(oid, ext);
                            return Ok(Some(&pe[oid]));
                        }
                    } else if *oid == PKIX_CE_CERTIFICATE_POLICIES {
                        if let Some(cp) = &cp.policy_set {
                            let ext = PDVExtension::CertificatePolicies(cp.clone());
                            pe.insert(oid, ext);
                            return Ok(Some(&pe[oid]));
                        }
                    }

                    if let Some(c) = &cp.certificate {
                        &c.tbs_certificate.extensions
                    } else {
                        &None
                    }
                } else {
                    &None
                }
            }
        };

        if let Some(exts) = exts.as_ref() {
            if let Some(i) = exts.iter().find(|&ext| ext.extn_id == *oid) {
                let v = i.extn_value;
                match *oid {
                    PKIX_CE_BASIC_CONSTRAINTS => {
                        add_and_return!(pe, v, PKIX_CE_BASIC_CONSTRAINTS, BasicConstraints);
                    }
                    PKIX_CE_SUBJECT_KEY_IDENTIFIER => {
                        add_and_return!(
                            pe,
                            v,
                            PKIX_CE_SUBJECT_KEY_IDENTIFIER,
                            SubjectKeyIdentifier
                        );
                    }
                    PKIX_CE_EXTKEYUSAGE => {
                        add_and_return!(pe, v, PKIX_CE_EXTKEYUSAGE, ExtendedKeyUsage);
                    }
                    PKIX_PE_AUTHORITYINFOACCESS => {
                        add_and_return!(
                            pe,
                            v,
                            PKIX_PE_AUTHORITYINFOACCESS,
                            AuthorityInfoAccessSyntax
                        );
                    }
                    PKIX_PE_SUBJECTINFOACCESS => {
                        add_and_return!(pe, v, PKIX_PE_SUBJECTINFOACCESS, SubjectInfoAccessSyntax);
                    }
                    PKIX_CE_KEY_USAGE => {
                        add_and_return!(pe, v, PKIX_CE_KEY_USAGE, KeyUsage);
                    }
                    PKIX_CE_SUBJECT_ALT_NAME => {
                        add_and_return!(pe, v, PKIX_CE_SUBJECT_ALT_NAME, SubjectAltName);
                    }
                    PKIX_CE_ISSUER_ALT_NAME => {
                        add_and_return!(pe, v, PKIX_CE_ISSUER_ALT_NAME, IssuerAltName);
                    }
                    PKIX_CE_PRIVATE_KEY_USAGE_PERIOD => {
                        add_and_return!(
                            pe,
                            v,
                            PKIX_CE_PRIVATE_KEY_USAGE_PERIOD,
                            PrivateKeyUsagePeriod
                        );
                    }
                    PKIX_CE_CRLNUMBER => {
                        add_and_return!(pe, v, PKIX_CE_CRLNUMBER, CRLNumber);
                    }
                    // PKIX_CE_CRLREASONS => {
                    //     add!(pe, v, PKIX_CE_CRLREASONS, CRLReason);
                    // }
                    // PKIX_CE_ISSUINGDISTRIBUTIONPOINT => {
                    //     add!(
                    //         pe,
                    //         v,
                    //         PKIX_CE_ISSUINGDISTRIBUTIONPOINT,
                    //         IssuingDistributionPoint
                    //     );
                    // }
                    PKIX_CE_NAME_CONSTRAINTS => {
                        add_and_return!(pe, v, PKIX_CE_NAME_CONSTRAINTS, NameConstraints);
                    }
                    // PKIX_CE_CRL_DISTRIBUTION_POINTS => {
                    //     add_and_return!(
                    //         pe,
                    //         v,
                    //         PKIX_CE_CRL_DISTRIBUTION_POINTS,
                    //         CRLDistributionPoints
                    //     );
                    // }
                    PKIX_CE_CERTIFICATE_POLICIES => {
                        add_and_return!(pe, v, PKIX_CE_CERTIFICATE_POLICIES, CertificatePolicies);
                    }
                    PKIX_CE_POLICY_MAPPINGS => {
                        add_and_return!(pe, v, PKIX_CE_POLICY_MAPPINGS, PolicyMappings);
                    }
                    PKIX_CE_AUTHORITY_KEY_IDENTIFIER => {
                        add_and_return!(
                            pe,
                            v,
                            PKIX_CE_AUTHORITY_KEY_IDENTIFIER,
                            AuthorityKeyIdentifier
                        );
                    }
                    PKIX_CE_POLICY_CONSTRAINTS => {
                        add_and_return!(pe, v, PKIX_CE_POLICY_CONSTRAINTS, PolicyConstraints);
                    }
                    // PKIX_CE_FRESHEST_CRL => {
                    //     add_and_return!(pe, v, PKIX_CE_FRESHEST_CRL, FreshestCRL);
                    // }
                    PKIX_CE_INHIBIT_ANY_POLICY => {
                        add_and_return!(pe, v, PKIX_CE_INHIBIT_ANY_POLICY, InhibitAnyPolicy);
                    }
                    PKIX_OCSP_NOCHECK => {
                        add_and_return!(pe, v, PKIX_OCSP_NOCHECK, OcspNoCheck);
                    }
                    PIV_NACI_INDICATOR => {
                        add_and_return!(pe, v, PIV_NACI_INDICATOR, PivNaciIndicator);
                    }
                    _ => {
                        return Err(Error::Unrecognized);
                    }
                }
            }
        }
        Ok(None)
    }
}

/// [`DeferDecodeCertificate`] used to parse only the top-level Certificate structure, without parsing the details of the
/// TBSCertificate, AlgorithmIdentifier or BIT STRING fields.
///
/// Deferred decoding is useful when verifying certificates to avoid re-encoding the TBSCertificate
/// (and potentially encountering problems with structures that were not DER-encoded prior to signing).
/// This is intended to be used in tandem with a [`PDVCertificate`] structure that contains a fully-decoded
/// Certificate structure.
pub struct DeferDecodeCertificate<'a> {
    /// tbsCertificate       TBSCertificate,
    pub tbs_certificate: &'a [u8],
    /// signatureAlgorithm   AlgorithmIdentifier,
    pub signature_algorithm: &'a [u8],
    /// signature            BIT STRING
    pub signature: &'a [u8],
}

impl<'a> Decodable<'a> for DeferDecodeCertificate<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<DeferDecodeCertificate<'a>> {
        decoder.sequence(|decoder| {
            let tbs_certificate = decoder.tlv_bytes()?;
            let signature_algorithm = decoder.tlv_bytes()?;
            let signature = decoder.tlv_bytes()?;
            Ok(Self {
                tbs_certificate,
                signature_algorithm,
                signature,
            })
        })
    }
}

/// [`compare_names`] compares two Name values returning true if they match and false otherwise.
pub fn compare_names<'a>(left: &'a Name<'a>, right: &'a Name<'a>) -> bool {
    // no match if not the same number of RDNs
    if left.len() != right.len() {
        return false;
    }

    for i in 0..left.len() {
        let lrdn = &left[i];
        let rrdn = &right[i];

        if lrdn.len() != rrdn.len() {
            return false;
        }

        if lrdn != rrdn {
            // only do the whitespace and case insensitve stuff is simpler compare fails
            for j in 0..lrdn.len() {
                let l = lrdn.get(j).unwrap();
                let r = rrdn.get(j).unwrap();

                if l.oid != r.oid {
                    return false;
                }

                let l_str = get_str_from_atav(l);
                if let Ok(l_str_val) = l_str {
                    let r_str = get_str_from_atav(r);
                    if let Ok(r_str_val) = r_str {
                        let re = Regex::new(r"\s+").unwrap();

                        // trimp leading and trailing whitespace
                        let l_val = l_str_val.trim();
                        let r_val = r_str_val.trim();

                        //collapse multiple whitespace instances into one and convert to lowercase
                        let l_str_val = re.replace_all(l_val, " ").to_lowercase();
                        let r_str_val = re.replace_all(r_val, " ").to_lowercase();
                        if l_str_val != r_str_val {
                            return false;
                        }
                    }
                }
            }
        }
    }
    true
}

/// [`get_trust_anchor_name`] returns the name of the trust anchor.
///
/// The name is as read from the either the subject field of a certificate if the Certificate option
/// is used or from the CertPathControls field within a TrustAnchorInfo if that option is used.
/// The TBSCertificate option is not supported and the Certificate field within TrustAnchorInfo is
/// not consulted, i.e., if one wished to use TrustAnchorInfo then the Name must be populated within
/// CertPathControls.
pub fn get_trust_anchor_name<'a>(ta: &'a TrustAnchorChoice<'a>) -> Result<&'a Name<'a>> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => {
            return Ok(&cert.tbs_certificate.subject);
        }
        TrustAnchorChoice::TaInfo(tai) => {
            if let Some(cert_path) = &tai.cert_path {
                return Ok(&cert_path.ta_name);
            }
        }
    }
    Err(Error::EncodingError)
}
