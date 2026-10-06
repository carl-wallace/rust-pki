//! Wrappers around asn.1 encoder/decoder structures to support certification path processing

use crate::asn1::piv_naci_indicator::PivNaciIndicator;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use der::{asn1::ObjectIdentifier, Decode, Encode};
use log::error;
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    certificate::{CertificateInner, Profile, Raw},
    ext::{pkix::crl::CrlDistributionPoints, pkix::*},
};

use crate::asn1::piv_naci_indicator::PIV_NACI_INDICATOR;
use const_oid::db::rfc5912::{
    ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS, ID_CE_CERTIFICATE_POLICIES,
    ID_CE_CRL_DISTRIBUTION_POINTS, ID_CE_EXT_KEY_USAGE, ID_CE_ISSUER_ALT_NAME, ID_CE_KEY_USAGE,
    ID_CE_NAME_CONSTRAINTS, ID_CE_POLICY_CONSTRAINTS, ID_CE_POLICY_MAPPINGS,
    ID_CE_PRIVATE_KEY_USAGE_PERIOD, ID_PE_AUTHORITY_INFO_ACCESS, ID_PE_SUBJECT_INFO_ACCESS,
};
use const_oid::db::rfc6960::ID_PKIX_OCSP_NOCHECK;
use der::asn1::BitString;
use x509_ocsp::OcspNoCheck;

use crate::pdv_extension::*;
use crate::util::error::*;
use crate::EXTS_OF_INTEREST;

/// [`PDVCertificate`] is used to aggregate a binary, DER-encoded Certificate, a parsed Certificate, an
/// optional locator naming where it was read from, and optional parsed extensions, in support of
/// certification path development and validation operations.
///
/// The parsed extensions are usually those listed in tne [`EXTS_OF_INTEREST`].
#[derive(Clone, Eq, PartialEq)]
pub struct PDVCertificate {
    /// Binary, encoded Certificate object
    encoded_cert: Vec<u8>,
    /// Decoded Certificate object
    decoded_cert: CertificateInner<Raw>,
    /// Optional parsed extension from the Certificate
    parsed_extensions: ParsedExtensions,
    /// The source for the certificate
    locator: Option<String>,
}

impl PDVCertificate {
    fn new(cert: CertificateInner<Raw>) -> der::Result<Self> {
        let mut pdv_cert = PDVCertificate {
            encoded_cert: cert.to_der()?,
            decoded_cert: cert,
            parsed_extensions: Default::default(),
            locator: None,
        };
        pdv_cert.parse_extensions(EXTS_OF_INTEREST);
        Ok(pdv_cert)
    }

    /// Return the byte encoding of the Certificate object
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded_cert
    }

    /// Return the locator for the source of this certificate
    pub fn locator(&self) -> Option<&str> {
        self.locator.as_deref()
    }

    /// Return the decoded Certificate object.
    ///
    /// Prefer this over `as_ref()` at call sites: once a `PDVCertificate` is held behind a smart
    /// pointer (e.g. `Arc<PDVCertificate>`), `.as_ref()` resolves to the pointer's own `AsRef`
    /// rather than this `AsRef<CertificateInner<Raw>>` impl. This inherent method is unambiguous
    /// through `Deref`.
    pub fn decoded(&self) -> &CertificateInner<Raw> {
        &self.decoded_cert
    }
}

impl AsRef<CertificateInner<Raw>> for PDVCertificate {
    fn as_ref(&self) -> &CertificateInner<Raw> {
        &self.decoded_cert
    }
}

impl TryFrom<&[u8]> for PDVCertificate {
    type Error = der::Error;

    fn try_from(enc_cert: &[u8]) -> der::Result<Self> {
        let cert = CertificateInner::from_der(enc_cert)?;
        let mut pdv_cert = PDVCertificate {
            encoded_cert: enc_cert.to_vec(),
            decoded_cert: cert,
            parsed_extensions: Default::default(),
            locator: None,
        };
        pdv_cert.parse_extensions(EXTS_OF_INTEREST);
        Ok(pdv_cert)
    }
}

impl<P> TryFrom<CertificateInner<P>> for PDVCertificate
where
    P: Profile,
{
    type Error = der::Error;

    fn try_from(cert: CertificateInner<P>) -> der::Result<Self> {
        let enc_cert = cert.to_der()?;
        let cert = CertificateInner::from_der(&enc_cert)?;
        Self::new(cert)
    }
}

impl ExtensionProcessing for PDVCertificate {
    /// `get_extension` takes an ObjectIdentifier that identifies an extension type and returns the
    /// previously parsed [`PDVExtension`] for it, or `None` if that extension has not been parsed.
    fn get_extension(&self, oid: &ObjectIdentifier) -> Result<Option<&PDVExtension>> {
        if self.parsed_extensions.contains_key(oid) {
            if let Some(ext) = self.parsed_extensions.get(oid) {
                return Ok(Some(ext));
            }
        }
        Ok(None)
    }

    /// `parse_extensions` takes a slice of ObjectIdentifiers and calls
    /// [`parse_extension`](ExtensionProcessing::parse_extension) for each, caching whichever of those
    /// extensions are present. Errors are not reported: an extension that is absent or fails to
    /// decode is simply left out of the cache.
    fn parse_extensions(&mut self, oids: &[ObjectIdentifier]) {
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

        if let Some(exts) = self.decoded_cert.tbs_certificate().extensions().as_ref() {
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
pub struct DeferDecodeSigned {
    /// tbsCertificate       TBSCertificate,
    pub tbs_field: Vec<u8>,
    /// signatureAlgorithm   AlgorithmIdentifier,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    /// signature            BIT STRING
    pub signature: BitString,
}

impl ::der::FixedTag for DeferDecodeSigned {
    const TAG: ::der::Tag = ::der::Tag::Sequence;
}

impl<'a> ::der::DecodeValue<'a> for DeferDecodeSigned {
    type Error = der::Error;

    fn decode_value<R: ::der::Reader<'a>>(
        reader: &mut R,
        header: ::der::Header,
    ) -> ::der::Result<Self> {
        reader.read_nested(header.length(), |reader| {
            let tbs_certificate = reader.tlv_bytes()?;
            let signature_algorithm = reader.decode()?;
            let signature = reader.decode()?;
            Ok(Self {
                tbs_field: tbs_certificate.to_vec(),
                signature_algorithm,
                signature,
            })
        })
    }
}

/// `parse_cert` takes a buffer containing a binary DER encoded certificate and returns a
/// [`PDVCertificate`] containing the parsed certificate if parsing was successful.
pub fn parse_cert(buffer: &[u8], filename: &str) -> Result<PDVCertificate> {
    match PDVCertificate::try_from(buffer) {
        Ok(mut pdvcert) => {
            pdvcert.locator = Some(filename.to_string());
            Ok(pdvcert)
        }
        Err(e) => {
            error!("Failed to parse certificate from {filename}: {e}");
            Err(Error::Asn1Error(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_from_bytes_preserves_original_der() {
        let cert_bytes =
            include_bytes!("../../tests/examples/PKITS_data_p256/certs/GoodCACert.crt");
        let pdv_cert = PDVCertificate::try_from(cert_bytes.as_slice())
            .expect("PDVCertificate::try_from succeeds");
        assert_eq!(
            pdv_cert.as_bytes(),
            cert_bytes,
            "PDVCertificate must store the original DER bytes"
        );
        assert_eq!(pdv_cert.locator(), None);
    }

    #[test]
    fn test_parse_cert_sets_locator_and_preserves_bytes() {
        let cert_bytes =
            include_bytes!("../../tests/examples/PKITS_data_p256/certs/GoodCACert.crt");
        let filename = "GoodCACert.crt";
        let pdv_cert = parse_cert(cert_bytes, filename).expect("parse_cert succeeds");
        assert_eq!(
            pdv_cert.as_bytes(),
            cert_bytes,
            "parse_cert must store the original DER bytes"
        );
        assert_eq!(pdv_cert.locator(), Some(filename));
    }

    #[test]
    fn test_pdv_certificate_explicit_default_field_signature_verification() {
        use crate::{
            parse_cert, verify_signature_message_rust_crypto, DeferDecodeSigned, PkiEnvironment,
        };
        use der::Encode;
        use x509_cert::Certificate;

        let ca_bytes = include_bytes!("../../tests/examples/ecdsa_ca.der");
        let leaf_bytes = include_bytes!("../../tests/examples/ecdsa_explicit_default_leaf.der");

        // 1. Verify that CertificateInner::from_der parses the leaf certificate,
        // but cert.to_der() drops the explicit default `critical: false` extension field,
        // altering the byte representation relative to the input bytes.
        let parsed_cert = CertificateInner::<Raw>::from_der(leaf_bytes).expect("leaf cert parses");
        let reencoded = parsed_cert.to_der().expect("re-encoding succeeds");
        assert_ne!(
            reencoded, leaf_bytes,
            "cert.to_der() drops explicit default fields, producing a mismatch with original DER"
        );

        // 2. Demonstrate that with the old behavior (using cert.to_der()), signature verification FAILS
        // because tbsCertificate digest changed.
        let reencoded_defer = DeferDecodeSigned::from_der(&reencoded).expect("re-encoded parses");
        let ca_cert = Certificate::from_der(ca_bytes).expect("ca cert parses");

        let mut pe = PkiEnvironment::default();
        pe.clear_all_callbacks();
        pe.add_verify_signature_message_callback(verify_signature_message_rust_crypto);

        let old_verify_result = pe.verify_signature_message(
            &pe,
            &reencoded_defer.tbs_field,
            &reencoded_defer.signature,
            &reencoded_defer.signature_algorithm,
            ca_cert.tbs_certificate().subject_public_key_info(),
        );
        assert!(
            old_verify_result.is_err(),
            "Re-encoded cert bytes change tbsCertificate digest and MUST cause signature verification failure"
        );

        // 3. Verify that with the fix (PDVCertificate preserving raw input DER bytes),
        // pdv_cert.as_bytes() retains leaf_bytes exactly.
        let pdv_cert =
            parse_cert(leaf_bytes, "ecdsa_explicit_default_leaf.der").expect("parse_cert succeeds");
        assert_eq!(
            pdv_cert.as_bytes(),
            leaf_bytes,
            "PDVCertificate must preserve original DER bytes"
        );

        // 4. Verify that signature verification SUCCEEDS over the preserved raw bytes,
        // validating both original DER preservation and ECDSA BitString handling (unused-bits byte stripping).
        let raw_defer = DeferDecodeSigned::from_der(pdv_cert.as_bytes()).expect("raw defer parses");
        let fix_verify_result = pe.verify_signature_message(
            &pe,
            &raw_defer.tbs_field,
            &raw_defer.signature,
            &raw_defer.signature_algorithm,
            ca_cert.tbs_certificate().subject_public_key_info(),
        );
        assert!(
            fix_verify_result.is_ok(),
            "Signature verification MUST succeed when original DER bytes are preserved"
        );
    }
}
