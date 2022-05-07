//! Wrappers around asn.1 encoder/decoder structures to support certification path processing

use const_oid::db::rfc5912::{
    ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_BASIC_CONSTRAINTS, ID_CE_CERTIFICATE_POLICIES,
    ID_CE_CRL_DISTRIBUTION_POINTS, ID_CE_EXT_KEY_USAGE, ID_CE_ISSUER_ALT_NAME, ID_CE_KEY_USAGE,
    ID_CE_NAME_CONSTRAINTS, ID_CE_POLICY_CONSTRAINTS, ID_CE_POLICY_MAPPINGS,
    ID_CE_PRIVATE_KEY_USAGE_PERIOD, ID_PE_AUTHORITY_INFO_ACCESS, ID_PE_SUBJECT_INFO_ACCESS,
};
use const_oid::db::rfc6960::ID_PKIX_OCSP_NOCHECK;
use der::{asn1::ObjectIdentifier, Decode};
use x509_cert::anchor::TrustAnchorChoice;
use x509_cert::ext::{pkix::crl::CrlDistributionPoints, pkix::*};
use x509_cert::name::Name;
use x509_ocsp::OcspNoCheck;

use crate::util::error::*;
use crate::validator::pdv_certificate::*;
use crate::validator::pdv_extension::*;

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
            if let Some(ext) = self.parsed_extensions.get(oid) {
                return Ok(Some(ext));
            }
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
                match $t::from_der($v) {
                    Ok(r) => {
                        let ext = PDVExtension::$t(r);
                        $pe.insert(oid, ext);
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
                    if *oid == ID_CE_NAME_CONSTRAINTS {
                        if let Some(nc) = &cp.name_constr {
                            let ext = PDVExtension::NameConstraints(nc.clone());
                            pe.insert(oid, ext);
                            return Ok(Some(&pe[oid]));
                        }
                    } else if *oid == ID_CE_CERTIFICATE_POLICIES {
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
            _ => {
                return Err(Error::Unrecognized);
            }
        };

        if let Some(exts) = exts.as_ref() {
            if let Some(i) = exts.iter().find(|&ext| ext.extn_id == *oid) {
                let v = i.extn_value;
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
        TrustAnchorChoice::TbsCertificate(cert) => {
            return Ok(&cert.subject);
        }
    }
    Err(Error::NotFound)
}
