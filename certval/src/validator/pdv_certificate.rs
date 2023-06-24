//! Wrappers around asn.1 encoder/decoder structures to support certification path processing

use alloc::collections::BTreeMap;
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::asn1::piv_naci_indicator::PivNaciIndicator;
use der::{
    asn1::{BitStringRef, ObjectIdentifier},
    Decode,
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::{pkix::crl::CrlDistributionPoints, pkix::*};
use x509_cert::Certificate;

use crate::asn1::piv_naci_indicator::PIV_NACI_INDICATOR;
use const_oid::db::rfc5912::{
    ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS, ID_CE_CERTIFICATE_POLICIES,
    ID_CE_CRL_DISTRIBUTION_POINTS, ID_CE_EXT_KEY_USAGE, ID_CE_ISSUER_ALT_NAME, ID_CE_KEY_USAGE,
    ID_CE_NAME_CONSTRAINTS, ID_CE_POLICY_CONSTRAINTS, ID_CE_POLICY_MAPPINGS,
    ID_CE_PRIVATE_KEY_USAGE_PERIOD, ID_PE_AUTHORITY_INFO_ACCESS, ID_PE_SUBJECT_INFO_ACCESS,
};
use const_oid::db::rfc6960::ID_PKIX_OCSP_NOCHECK;
use x509_ocsp::OcspNoCheck;

use crate::pdv_extension::*;
use crate::util::error::*;
use crate::util::logging::*;
use crate::EXTS_OF_INTEREST;

/// [`Asn1Metadata`] is a typedef of a BTreeMap map that associates types represented by the [`Asn1MetadataTypes`]
/// enum objects with arbitrary string values. At present this is only used to convey filenames and
/// may be dropped in favor of a String filename member in place of current [`Asn1Metadata`] members..
pub type Asn1Metadata = BTreeMap<String, Asn1MetadataTypes>;

/// [`MD_LOCATOR`] is used to set/get a String value to/from an [`Asn1Metadata`] object. The value
/// may represent a file name, URI or other locator for troubleshooting purposes.
pub static MD_LOCATOR: &str = "mdLocator";

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
    /// Used for metadata represented as a `Vec<u8>`
    Buffer(Vec<u8>),
}

/// [`PDVCertificate`] is used to aggregate a binary, DER-encoded Certificate, a parsed Certificate, optional metadata
/// and optional parsed extensions in support of certification path development and validation operations.
///
/// The parsed extensions are usually those listed in tne [`EXTS_OF_INTEREST`](../path_validator/constant.EXTS_OF_INTEREST.html).
#[derive(Clone, Eq, PartialEq)]
pub struct PDVCertificate {
    /// Binary, encoded Certificate object
    pub encoded_cert: Vec<u8>,
    /// Decoded Certificate object
    pub decoded_cert: Certificate,
    /// Optional metadata about the trust anchor
    pub metadata: Option<Asn1Metadata>,
    /// Optional parsed extension from the Certificate
    pub parsed_extensions: ParsedExtensions,
}

impl ExtensionProcessing for PDVCertificate {
    /// `get_extension` takes a static ObjectIdentifier that identifies and extension type and returns
    /// a previously parsed [`PDVExtension`] instance containing the decoded extension if the extension was present.
    fn get_extension(&self, oid: &ObjectIdentifier) -> Result<Option<&'_ PDVExtension>> {
        if self.parsed_extensions.contains_key(oid) {
            if let Some(ext) = self.parsed_extensions.get(oid) {
                return Ok(Some(ext));
            }
        }
        Ok(None)
    }

    /// `parse_extension` takes a static ObjectIdentifier that identifies and extension type and returns
    /// a [`PDVExtension`] containing the a decoded extension if the extension was present.
    fn parse_extensions(&'_ mut self, oids: &[ObjectIdentifier]) {
        for oid in oids {
            let _r = self.parse_extension(oid);
        }
    }

    fn parse_extension(&mut self, oid: &ObjectIdentifier) -> Result<Option<&PDVExtension>> {
        macro_rules! add_and_return {
            ($pe:ident, $v:ident, $oid:ident, $t:ident) => {
                match $t::from_der($v) {
                    Ok(r) => {
                        let ext = PDVExtension::$t(r);
                        $pe.insert(*oid, ext);
                        return Ok(Some(&$pe[oid]));
                    }
                    Err(e) => {
                        return Err(Error::Asn1Error(e));
                    }
                }
            };
        }

        let pe = &mut self.parsed_extensions;
        if pe.contains_key(oid) {
            return Ok(pe.get(oid));
        }

        if let Some(exts) = self.decoded_cert.tbs_certificate.extensions.as_ref() {
            if let Some(i) = exts.iter().find(|&ext| ext.extn_id == *oid) {
                let v = i.extn_value.as_bytes();
                match *oid {
                    ID_CE_BASIC_CONSTRAINTS => {
                        add_and_return!(pe, v, ID_CE_BASIC_CONSTRAINTS, BasicConstraints);
                    }
                    ID_CE_SUBJECT_KEY_IDENTIFIER => {
                        add_and_return!(pe, v, ID_CE_SUBJECT_KEY_IDENTIFIER, SubjectKeyIdentifier);
                    }
                    ID_CE_EXT_KEY_USAGE => {
                        add_and_return!(pe, v, ID_CE_EXT_KEY_USAGE, ExtendedKeyUsage);
                    }
                    ID_PE_AUTHORITY_INFO_ACCESS => {
                        add_and_return!(
                            pe,
                            v,
                            ID_PE_AUTHORITY_INFO_ACCESS,
                            AuthorityInfoAccessSyntax
                        );
                    }
                    ID_PE_SUBJECT_INFO_ACCESS => {
                        add_and_return!(pe, v, ID_PE_SUBJECT_INFO_ACCESS, SubjectInfoAccessSyntax);
                    }
                    ID_CE_KEY_USAGE => {
                        add_and_return!(pe, v, ID_CE_KEY_USAGE, KeyUsage);
                    }
                    ID_CE_SUBJECT_ALT_NAME => {
                        add_and_return!(pe, v, ID_CE_SUBJECT_ALT_NAME, SubjectAltName);
                    }
                    ID_CE_ISSUER_ALT_NAME => {
                        add_and_return!(pe, v, ID_CE_ISSUER_ALT_NAME, IssuerAltName);
                    }
                    ID_CE_PRIVATE_KEY_USAGE_PERIOD => {
                        add_and_return!(
                            pe,
                            v,
                            ID_CE_PRIVATE_KEY_USAGE_PERIOD,
                            PrivateKeyUsagePeriod
                        );
                    }
                    ID_CE_NAME_CONSTRAINTS => {
                        add_and_return!(pe, v, ID_CE_NAME_CONSTRAINTS, NameConstraints);
                    }
                    ID_CE_CRL_DISTRIBUTION_POINTS => {
                        add_and_return!(
                            pe,
                            v,
                            ID_CE_CRL_DISTRIBUTION_POINTS,
                            CrlDistributionPoints
                        );
                    }
                    ID_CE_CERTIFICATE_POLICIES => {
                        add_and_return!(pe, v, ID_CE_CERTIFICATE_POLICIES, CertificatePolicies);
                    }
                    ID_CE_POLICY_MAPPINGS => {
                        add_and_return!(pe, v, ID_CE_POLICY_MAPPINGS, PolicyMappings);
                    }
                    ID_CE_AUTHORITY_KEY_IDENTIFIER => {
                        add_and_return!(
                            pe,
                            v,
                            ID_CE_AUTHORITY_KEY_IDENTIFIER,
                            AuthorityKeyIdentifier
                        );
                    }
                    ID_CE_POLICY_CONSTRAINTS => {
                        add_and_return!(pe, v, ID_CE_POLICY_CONSTRAINTS, PolicyConstraints);
                    }
                    ID_CE_INHIBIT_ANY_POLICY => {
                        add_and_return!(pe, v, ID_CE_INHIBIT_ANY_POLICY, InhibitAnyPolicy);
                    }
                    ID_PKIX_OCSP_NOCHECK => {
                        add_and_return!(pe, v, PKIX_OCSP_NOCHECK, OcspNoCheck);
                    }
                    PIV_NACI_INDICATOR => {
                        add_and_return!(pe, v, PIV_NACI_INDICATOR, PivNaciIndicator);
                    }
                    _ => {
                        // ignore unrecognized
                    }
                }
            }
        }
        Ok(None)
    }
}

/// [`DeferDecodeSigned`] used to parse only the top-level Certificate structure, without parsing the details of the
/// TBSCertificate, AlgorithmIdentifier or BIT STRING fields.
///
/// Deferred decoding is useful when verifying certificates to avoid re-encoding the TBSCertificate
/// (and potentially encountering problems with structures that were not DER-encoded prior to signing).
/// This is intended to be used in tandem with a [`PDVCertificate`] structure that contains a fully-decoded
/// Certificate structure.
pub struct DeferDecodeSigned<'a> {
    /// tbsCertificate       TBSCertificate,
    pub tbs_field: &'a [u8],
    /// signatureAlgorithm   AlgorithmIdentifier,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    /// signature            BIT STRING
    pub signature: BitStringRef<'a>,
}

impl ::der::FixedTag for DeferDecodeSigned<'_> {
    const TAG: ::der::Tag = ::der::Tag::Sequence;
}

impl<'a> ::der::DecodeValue<'a> for DeferDecodeSigned<'a> {
    fn decode_value<R: ::der::Reader<'a>>(
        reader: &mut R,
        header: ::der::Header,
    ) -> ::der::Result<Self> {
        use ::der::Reader as _;
        reader.read_nested(header.length, |reader| {
            let tbs_certificate = reader.tlv_bytes()?;
            let signature_algorithm = reader.decode()?;
            let signature = reader.decode()?;
            Ok(Self {
                tbs_field: tbs_certificate,
                signature_algorithm,
                signature,
            })
        })
    }
}

/// `parse_cert` takes a buffer containing a binary DER encoded certificate and returns
/// a [`PDVCertificate`](../certval/pdv_certificate/struct.PDVCertificate.html) containing the
/// parsed certificate if parsing was successful (and None upon failure).
pub fn parse_cert(buffer: &[u8], filename: &str) -> Option<PDVCertificate> {
    let r = Certificate::from_der(buffer);
    match r {
        Ok(cert) => {
            let mut md = Asn1Metadata::new();
            md.insert(
                MD_LOCATOR.to_string(),
                Asn1MetadataTypes::String(filename.to_string()),
            );
            let mut pdvcert = PDVCertificate {
                encoded_cert: buffer.to_vec(),
                decoded_cert: cert,
                metadata: Some(md),
                parsed_extensions: ParsedExtensions::new(),
            };
            pdvcert.parse_extensions(EXTS_OF_INTEREST);
            Some(pdvcert)
        }
        Err(e) => {
            log_message(
                &PeLogLevels::PeError,
                format!("Failed to parse certificate from {}: {}", filename, e).as_str(),
            );
            None
        }
    }
}
