//! Wrappers around asn.1 encoder/decoder structures to support certification path processing
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "webpki")] {
        use log::error;
        use sha1::{Digest, Sha1};
        use webpki_roots::TrustAnchor;
        use alloc::vec;
        use alloc::string::ToString;
        use der::{asn1::OctetString, Length};
        use spki::SubjectPublicKeyInfoOwned;
        use x509_cert::anchor::{CertPathControls, TrustAnchorInfo};
    }
}

use crate::EXTS_OF_INTEREST;
use alloc::vec::Vec;
use const_oid::db::rfc5912::{
    ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS, ID_CE_CERTIFICATE_POLICIES,
    ID_CE_CRL_DISTRIBUTION_POINTS, ID_CE_EXT_KEY_USAGE, ID_CE_ISSUER_ALT_NAME, ID_CE_KEY_USAGE,
    ID_CE_NAME_CONSTRAINTS, ID_CE_POLICY_CONSTRAINTS, ID_CE_POLICY_MAPPINGS,
    ID_CE_PRIVATE_KEY_USAGE_PERIOD, ID_PE_AUTHORITY_INFO_ACCESS, ID_PE_SUBJECT_INFO_ACCESS,
};
use const_oid::db::rfc6960::ID_PKIX_OCSP_NOCHECK;
use der::{asn1::ObjectIdentifier, Decode, Encode};
use x509_cert::anchor::TrustAnchorChoice;
use x509_cert::ext::pkix::NameConstraints;
use x509_cert::ext::{pkix::crl::CrlDistributionPoints, pkix::*};
use x509_cert::name::Name;
use x509_cert::Certificate;
use x509_ocsp::OcspNoCheck;

use crate::util::error::*;
use crate::validator::pdv_certificate::*;
use crate::validator::pdv_extension::*;

/// [`PDVTrustAnchorChoice`] is used to aggregate a binary TrustAnchorChoice, a parsed TrustAnchorChoice,
/// optional metadata and optional parsed extensions in support of certification path development and
/// validation operations.
#[derive(Clone, Eq, PartialEq)]
pub struct PDVTrustAnchorChoice {
    /// Binary, encoded TrustAnchorChoice object
    pub encoded_ta: Vec<u8>,
    /// Decoded TrustAnchorChoice object
    pub decoded_ta: TrustAnchorChoice,
    /// Optional metadata about the trust anchor
    pub metadata: Option<Asn1Metadata>,
    /// Optional parsed extension from the TrustAnchorChoice
    pub parsed_extensions: ParsedExtensions,
}

impl TryFrom<&[u8]> for PDVTrustAnchorChoice {
    type Error = der::Error;

    fn try_from(enc_cert: &[u8]) -> der::Result<Self> {
        let ta = TrustAnchorChoice::from_der(enc_cert)?;
        let mut pdv_ta = PDVTrustAnchorChoice {
            encoded_ta: enc_cert.to_vec(),
            decoded_ta: ta,
            metadata: None,
            parsed_extensions: Default::default(),
        };
        pdv_ta.parse_extensions(EXTS_OF_INTEREST);
        Ok(pdv_ta)
    }
}

impl TryFrom<TrustAnchorChoice> for PDVTrustAnchorChoice {
    type Error = der::Error;

    fn try_from(ta: TrustAnchorChoice) -> der::Result<Self> {
        let enc_ta = ta.to_der()?;
        let mut pdv_ta = PDVTrustAnchorChoice {
            encoded_ta: enc_ta.to_vec(),
            decoded_ta: ta,
            metadata: None,
            parsed_extensions: Default::default(),
        };
        pdv_ta.parse_extensions(EXTS_OF_INTEREST);
        Ok(pdv_ta)
    }
}

/// The webpki-roots TrustAnchor structure stores values with the outer SEQUENCE tag and length
/// removed (!). This means approximately nothing can parse it. This function restores the outer
/// SEQUENCE tag for Name values and returns a parsed Name.
#[cfg(feature = "webpki")]
fn partial_name_to_name(partial_name_bytes: &[u8]) -> der::Result<Name> {
    let l = Length::new(partial_name_bytes.len() as u16);
    let mut length_bytes = l.to_der()?;
    let mut enc_name = vec![0x30];
    enc_name.append(&mut length_bytes);
    enc_name.append(&mut partial_name_bytes.to_vec());
    Name::from_der(&enc_name)
}

/// The webpki-roots TrustAnchor structure stores values with the outer SEQUENCE tag and length
/// removed (!). This means approximately nothing can parse it. This function restores the outer
/// SEQUENCE tag for SubjectPublicKeyInfo values and returns a parsed SubjectPublicKeyInfoOwned.
#[cfg(feature = "webpki")]
fn partial_spki_to_spki(partial_spki_bytes: &[u8]) -> der::Result<SubjectPublicKeyInfoOwned> {
    let l = Length::new(partial_spki_bytes.len() as u16);
    let mut length_bytes = l.to_der()?;
    let mut enc_spki = vec![0x30];
    enc_spki.append(&mut length_bytes);
    enc_spki.append(&mut partial_spki_bytes.to_vec());
    SubjectPublicKeyInfoOwned::from_der(&enc_spki)
}

#[cfg(feature = "webpki")]
impl TryFrom<&TrustAnchor<'_>> for PDVTrustAnchorChoice {
    type Error = crate::Error;

    /// Takes a webpki-roots TrustAnchor and attempts to produce a PDVTrustAnchorChoice by first
    /// generating an [RFC5914](https://datatracker.ietf.org/doc/html/rfc5914) TrustAnchorInfo info
    /// structure containing the name, public key and, optionally, name constraints from the TrustAnchor.
    fn try_from(ta: &TrustAnchor<'_>) -> crate::Result<Self> {
        let n = partial_name_to_name(ta.subject)?;
        let spki = partial_spki_to_spki(ta.spki)?;
        let nc = match ta.name_constraints {
            Some(nc) => Some(NameConstraints::from_der(nc)?),
            None => None,
        };

        // TrustAnchorInfo (and the certval library) require a key identifier for trust anchors.
        // Since the webpki-roots structure omits this value, calculate one (which may be different
        // from what the TA includes in a SKID extension in its cert, but c'est la vie.
        let key_id = match spki.subject_public_key.as_bytes() {
            Some(b) => Sha1::digest(b),
            None => {
                error!("Failed to calculate key identifier for {}", n.to_string());
                return Err(Error::Unrecognized);
            }
        };

        // TrustAnchorInfo structures that are used for path validation MUST have a CertPathControls
        // member (because this is where the name is conveyed in that structure).
        let cp = CertPathControls {
            ta_name: n,
            certificate: None,
            policy_set: None,
            policy_flags: None,
            name_constr: nc,
            path_len_constraint: None,
        };
        let tai = TrustAnchorInfo {
            version: Default::default(),
            pub_key: spki,
            key_id: OctetString::new(key_id.to_vec())?,
            ta_title: None,
            cert_path: Some(cp),
            extensions: None,
            ta_title_lang_tag: None,
        };
        let tac = TrustAnchorChoice::TaInfo(tai);
        let enc_ta = tac.to_der()?;
        let mut pdv_ta = PDVTrustAnchorChoice {
            encoded_ta: enc_ta.to_vec(),
            decoded_ta: tac,
            metadata: None,
            parsed_extensions: Default::default(),
        };
        pdv_ta.parse_extensions(EXTS_OF_INTEREST);
        Ok(pdv_ta)
    }
}

impl TryFrom<Certificate> for PDVTrustAnchorChoice {
    type Error = der::Error;

    fn try_from(cert: Certificate) -> der::Result<Self> {
        let enc_cert = cert.to_der()?;
        let ta = TrustAnchorChoice::from_der(&enc_cert)?;
        Ok(PDVTrustAnchorChoice {
            encoded_ta: enc_cert.to_vec(),
            decoded_ta: ta,
            metadata: None,
            parsed_extensions: Default::default(),
        })
    }
}

impl ExtensionProcessing for PDVTrustAnchorChoice {
    /// `get_extension` takes a static ObjectIdentifier that identifies and extension type and returns
    /// a previously parsed PDVExtension instance containing the decoded extension if the extension was present.
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

        let exts = match &self.decoded_ta {
            TrustAnchorChoice::Certificate(c) => &c.tbs_certificate.extensions,
            TrustAnchorChoice::TaInfo(tai) => {
                if let Some(cp) = &tai.cert_path {
                    // TODO Support all TrustAnchorInfo overrides
                    // TrustAnchorInfo may override some extensions per RFC 5914.
                    // This includes the TAI fields policySet, policyFlags,
                    // nameConstr, pathLenConstraint, and ext.
                    // Seems we're currently only using nameConstr and policySet here.
                    if *oid == ID_CE_NAME_CONSTRAINTS {
                        if let Some(nc) = &cp.name_constr {
                            let ext = PDVExtension::NameConstraints(nc.clone());
                            pe.insert(*oid, ext);
                            return Ok(Some(&pe[oid]));
                        }
                    } else if *oid == ID_CE_CERTIFICATE_POLICIES {
                        if let Some(cp) = &cp.policy_set {
                            let ext = PDVExtension::CertificatePolicies(cp.clone());
                            pe.insert(*oid, ext);
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
            _ => {
                return Err(Error::Unrecognized);
            }
        };

        if let Some(exts) = exts.as_ref() {
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
                    _ => {
                        // ignore unrecognized
                    }
                }
            }
        }
        Ok(None)
    }
}

/// [`get_trust_anchor_name`] returns the name of the trust anchor.
///
/// The name is as read from the either the subject field of a certificate if the Certificate option
/// is used or from the CertPathControls field within a TrustAnchorInfo if that option is used.
/// The TBSCertificate option is not supported and the Certificate field within TrustAnchorInfo is
/// not consulted, i.e., if one wished to use TrustAnchorInfo then the Name must be populated within
/// CertPathControls.
pub fn get_trust_anchor_name(ta: &TrustAnchorChoice) -> Result<&Name> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => {
            return Ok(&cert.tbs_certificate.subject);
        }
        TrustAnchorChoice::TaInfo(tai) => {
            if let Some(cert_path) = &tai.cert_path {
                return Ok(&cert_path.ta_name);
            }
        }
        TrustAnchorChoice::TbsCertificate(cert) => {
            return Ok(&cert.subject);
        }
    }
    Err(Error::NotFound)
}
