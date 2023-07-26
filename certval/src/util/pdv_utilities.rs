//! Utility functions that support certification path processing

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str::FromStr;

use log::{debug, error};

#[cfg(feature = "std")]
use lazy_static::lazy_static;

#[cfg(feature = "std")]
use regex::Regex;

use const_oid::db::rfc2256::STATE_OR_PROVINCE_NAME;
use const_oid::db::rfc3280::{EMAIL_ADDRESS, PSEUDONYM};
use const_oid::db::rfc4519::*;
use const_oid::db::rfc5912::*;
use der::asn1::{Ia5String, PrintableString, Utf8StringRef};
use der::{asn1::ObjectIdentifier, Decode, Encode, Tagged};
use spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::pkix::{
    constraints::{
        name::{GeneralSubtree, GeneralSubtrees},
        BasicConstraints, PolicyConstraints,
    },
    name::GeneralName,
    InhibitAnyPolicy,
};
use x509_cert::name::Name;
use x509_cert::name::RdnSequence;
use x509_cert::{
    anchor::{CertPolicies, TrustAnchorChoice},
    Certificate, TbsCertificate,
};

use crate::{
    environment::pki_environment::PkiEnvironment,
    name_constraints_set::UID,
    path_results::{get_processed_extensions, set_processed_extensions, CertificationPathResults},
    path_settings::PS_MAX_PATH_LENGTH_CONSTRAINT,
    pdv_certificate::*,
    pdv_extension::*,
    util::error::*,
    util::pdv_alg_oids::*,
};

/// `is_self_signed_with_buffer` returns true if the public key in the parsed certificate can be
/// used to verify the TBSCertificate field as parsed from the encoded certificate object.
pub fn is_self_signed_with_buffer(
    pe: &PkiEnvironment<'_>,
    cert: &Certificate,
    enc_cert: &[u8],
) -> bool {
    match DeferDecodeSigned::from_der(enc_cert) {
        Ok(defer_cert) => {
            let r = pe.verify_signature_message(
                pe,
                &defer_cert.tbs_field,
                cert.signature.raw_bytes(),
                &cert.tbs_certificate.signature,
                &cert.tbs_certificate.subject_public_key_info,
            );
            //TODO is it worth making metadata a RefCell to save the result of checks like this?
            //If not, ditch metadata and replace with String field for locator
            matches!(r, Ok(_e))
        }
        Err(e) => {
            error!(
                "Failed to defer decode certificate in is_self_signed with: {}",
                e
            );
            false
        }
    }
}

/// `is_self_signed` returns true if the public key in the certificate can be used to verify the
/// signature on the certificate.
pub fn is_self_signed(pe: &PkiEnvironment<'_>, cert: &PDVCertificate) -> bool {
    is_self_signed_with_buffer(pe, &cert.decoded_cert, cert.encoded_cert.as_slice())
}

/// `is_self_issued` returns true if the subject field in the certificate is the same as the issuer
/// field.
pub fn is_self_issued(cert: &Certificate) -> bool {
    compare_names(&cert.tbs_certificate.issuer, &cert.tbs_certificate.subject)
}

/// `collect_uris_from_aia_and_sia` collects unique URIs from AIA and SIA extensions from the presented
/// certificate and returns them via the `uris` parameter.
pub fn collect_uris_from_aia_and_sia(cert: &PDVCertificate, uris: &mut Vec<String>) {
    let aia_ext = cert.get_extension(&ID_PE_AUTHORITY_INFO_ACCESS);
    if let Ok(Some(PDVExtension::AuthorityInfoAccessSyntax(aia))) = aia_ext {
        for ad in &aia.0 {
            if ID_AD_CA_ISSUERS == ad.access_method {
                if let GeneralName::UniformResourceIdentifier(uri) = &ad.access_location {
                    let s = uri.to_string();
                    if !uris.contains(&s) && s.starts_with("http") {
                        uris.push(uri.to_string());
                    }
                }
            }
        }
    }
    let sia_ext = cert.get_extension(&ID_PE_SUBJECT_INFO_ACCESS);
    if let Ok(Some(PDVExtension::SubjectInfoAccessSyntax(sia))) = sia_ext {
        for ad in &sia.0 {
            if ID_AD_CA_REPOSITORY == ad.access_method {
                if let GeneralName::UniformResourceIdentifier(uri) = &ad.access_location {
                    let s = uri.to_string();
                    if !uris.contains(&s) && s.starts_with("http") {
                        uris.push(uri.to_string());
                    }
                }
            }
        }
    }
}

/// `valid_at_time` evaluates the not_before and not_after fields of the given TBSCertificate instance
/// and provides an indication of validity relative to presented time of interest.
///
/// It returns the number of seconds left to live if the certificate is valid at the given time or
/// an error indicating which field failed if the certificate is not valid. The not_before field is
/// evaluated first.
///
/// To stifle logging output upon error, pass true for the stifle_log parameter.
pub fn valid_at_time(target: &TbsCertificate, toi: u64, stifle_log: bool) -> Result<u64> {
    if 0 == toi {
        // zero is used to disable validity check
        return Ok(0);
    }

    let nb = target.validity.not_before.to_unix_duration().as_secs();
    if nb > toi {
        if !stifle_log {
            log_error_for_name(&target.subject, "certificate is not yet valid, i.e., not_before is prior to the configured time of interest");
        }
        return Err(Error::PathValidation(
            PathValidationStatus::InvalidNotBeforeDate,
        ));
    }

    let na = target.validity.not_after.to_unix_duration().as_secs();
    if na < toi {
        if !stifle_log {
            log_error_for_name(
                &target.subject,
                format!(
                    "certificate is expired relative to the configured time of interest: {}",
                    target.validity.not_after
                )
                .as_str(),
            );
        }
        Err(Error::PathValidation(
            PathValidationStatus::InvalidNotAfterDate,
        ))
    } else {
        Ok(na - toi)
    }
}

/// `add_processed_extension` takes a [`CertificationPathResults`] and retrieves (or adds then retrieves)
/// an entry for [`PR_PROCESSED_EXTENSIONS`] to which the oid is added if not already present.
pub(crate) fn add_processed_extension(cpr: &mut CertificationPathResults, oid: ObjectIdentifier) {
    let mut oids = get_processed_extensions(cpr);
    if !oids.contains(&oid) {
        oids.insert(oid);
        set_processed_extensions(cpr, oids);
    }
}

/// `get_inhibit_any_policy_from_trust_anchor` returns true if the trust anchor inhibits the use of any policy
/// during certification path processing.
///
/// True is returned if inhibit any policy is found in an extension in TA certificate for certificate CHOICE
/// or the value from CertPathControls.PolicyFlags for TrustAnchorInfo CHOICE. Otherwise, false is returned.
pub(crate) fn get_inhibit_any_policy_from_trust_anchor(ta: &TrustAnchorChoice) -> Result<bool> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => {
            if let Some(extensions) = &cert.tbs_certificate.extensions {
                let i = extensions.iter();
                for ext in i {
                    if ID_CE_INHIBIT_ANY_POLICY == ext.extn_id {
                        let iap_result = InhibitAnyPolicy::from_der(ext.extn_value.as_bytes());
                        if let Ok(_iap) = iap_result {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        TrustAnchorChoice::TaInfo(tai) => {
            if let Some(cert_path) = &tai.cert_path {
                if let Some(pf) = cert_path.policy_flags {
                    if pf.contains(CertPolicies::InhibitAnyPolicy) {
                        return Ok(true);
                    }
                }
            }
        }
        _ => {
            return Err(Error::Unrecognized);
        }
    }
    Ok(false)
}

/// `get_require_explicit_policy_from_trust_anchor` returns true if the trust anchor requires all paths
/// to be valid under at least one policy during certification path processing.
///
/// True is returned if a policy constraints extension in is present in a certificate CHOICE or the value
/// is set in CertPathControls.PolicyFlags for TrustAnchorInfo CHOICE. Otherwise, false is returned.
pub(crate) fn get_require_explicit_policy_from_trust_anchor(
    ta: &TrustAnchorChoice,
) -> Result<bool> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => {
            if let Some(extensions) = &cert.tbs_certificate.extensions {
                let i = extensions.iter();
                for ext in i {
                    if ID_CE_POLICY_CONSTRAINTS == ext.extn_id {
                        let pc_result = PolicyConstraints::from_der(ext.extn_value.as_bytes());
                        if let Ok(pc) = pc_result {
                            if let Some(_rep) = pc.require_explicit_policy {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }
        TrustAnchorChoice::TaInfo(tai) => {
            if let Some(cert_path) = &tai.cert_path {
                if let Some(pf) = cert_path.policy_flags {
                    if pf.contains(CertPolicies::RequireExplicitPolicy) {
                        return Ok(true);
                    }
                }
            }
        }
        _ => {
            return Err(Error::Unrecognized);
        }
    }
    Ok(false)
}

/// `get_inhibit_policy_mapping_from_trust_anchor` returns true if the trust anchor inhibits the use of policy
/// mapping during certification path processing.
///
/// True is returned if inhibit policy mapping is found in an extension in TA certificate for certificate CHOICE
/// or the value from CertPathControls.PolicyFlags for TrustAnchorInfo CHOICE. Otherwise, false is returned.
pub(crate) fn get_inhibit_policy_mapping_from_trust_anchor(ta: &TrustAnchorChoice) -> Result<bool> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => {
            if let Some(extensions) = &cert.tbs_certificate.extensions {
                let i = extensions.iter();
                for ext in i {
                    if ID_CE_POLICY_CONSTRAINTS == ext.extn_id {
                        let pc_result = PolicyConstraints::from_der(ext.extn_value.as_bytes());
                        if let Ok(pc) = pc_result {
                            if let Some(_ipm) = pc.inhibit_policy_mapping {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }
        TrustAnchorChoice::TaInfo(tai) => {
            if let Some(cert_path) = &tai.cert_path {
                if let Some(pf) = cert_path.policy_flags {
                    if pf.contains(CertPolicies::InhibitPolicyMapping) {
                        return Ok(true);
                    }
                }
            }
        }
        _ => {
            return Err(Error::Unrecognized);
        }
    }
    Ok(false)
}

/// `get_path_length_constraint_from_trust_anchor` returns the value from basic constraints extension in
/// TA certificate for certificate CHOICE, the value from CertPathControls for TrustAnchorInfo CHOICE or
/// [`PS_MAX_PATH_LENGTH_CONSTRAINT`] is no constraint is asserted.
pub(crate) fn get_path_length_constraint_from_trust_anchor(ta: &TrustAnchorChoice) -> Result<u8> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => {
            if let Some(extensions) = &cert.tbs_certificate.extensions {
                let i = extensions.iter();
                for ext in i {
                    if ID_CE_BASIC_CONSTRAINTS == ext.extn_id {
                        let bc_result = BasicConstraints::from_der(ext.extn_value.as_bytes());
                        if let Ok(bc) = bc_result {
                            if let Some(pl) = bc.path_len_constraint {
                                return Ok(pl);
                            }
                        }
                    }
                }
            }
        }
        TrustAnchorChoice::TaInfo(tai) => {
            if let Some(cert_path) = &tai.cert_path {
                if let Some(len) = cert_path.path_len_constraint {
                    return Ok(len as u8);
                }
            }
        }
        _ => {
            return Err(Error::Unrecognized);
        }
    }
    Ok(PS_MAX_PATH_LENGTH_CONSTRAINT)
}

#[allow(dead_code)]
pub(crate) const EMAIL_PATTERN: &str =
    "^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([-.]{1}[a-z0-9]+)*.[a-z]{2,6})";

// // Port pattern of unknown origin
// pub(crate) const PORT_PATTERN: &str = "(.*):(\\d+)?$";
//
// // URI regular expression pattern from RFC 2396 Appendix B
// pub(crate) const URI_PATTERN: &str = "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?";

// TODO implement to support name constraints for no-std
/// `descended_from_rfc822` returns true if new_name is equal to or descended from prev_name and false otherwise.
#[cfg(feature = "std")]
pub(crate) fn descended_from_host(prev_name: &Ia5String, cand: &str, is_uri: bool) -> bool {
    let base = prev_name.to_string();

    let mut filter = regex::escape(base.as_str());
    filter.push('$');
    let filter_re = Regex::new(filter.as_str());
    if let Ok(fe) = filter_re {
        if let Some(parts) = fe.captures(cand) {
            if cand.len() == base.len() {
                return true;
            }

            let match_start = if let Some(part) = parts.get(0) {
                part.start()
            } else {
                return false;
            };

            if !is_uri {
                let cand_next_to_last_char = if match_start != 0 {
                    cand.chars().nth(match_start - 1).unwrap_or(' ')
                } else {
                    ' '
                };
                if cand_next_to_last_char == '.' {
                    return true;
                }
            } else {
                let cand_last_char = if match_start != 0 {
                    cand.chars().nth(match_start).unwrap_or(' ')
                } else {
                    ' '
                };
                if cand_last_char == '.' {
                    return true;
                }
            }
        }
    }
    false
}

// TODO implement to support name constraints for no-std
/// `is_email` returns true if addr matches the regular expression defined by [`EMAIL_PATTERN`].
#[cfg(feature = "std")]
pub(crate) fn is_email(addr: &str) -> bool {
    lazy_static! {
        static ref EMAIL_RE: Regex = Regex::new(
            "^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([-.]{1}[a-z0-9]+)*.[a-z]{2,6})"
        )
        .unwrap();
    }

    if let Some(_parts) = EMAIL_RE.captures(addr) {
        return true;
    }

    false
}

// TODO implement to support name constraints for no-std
/// `descended_from_rfc822` returns true if new_name is equal to or descended from prev_name and false otherwise.
#[cfg(feature = "std")]
pub(crate) fn descended_from_rfc822(prev_name: &Ia5String, new_name: &Ia5String) -> bool {
    let cand = new_name.to_string();
    let base = prev_name.to_string();

    let mut filter = regex::escape(base.as_str());
    filter.push('$');
    let filter_re = Regex::new(filter.as_str());
    if let Ok(fe) = filter_re {
        if let Some(parts) = fe.captures(cand.as_str()) {
            if is_email(base.as_str()) && cand.len() == base.len() {
                return true;
            }

            let match_start = if let Some(part) = parts.get(0) {
                part.start()
            } else {
                return false;
            };

            let base_first_char = if let Some(part) = base.chars().next() {
                part
            } else {
                return false;
            };

            let cand_last_char = if match_start != 0 {
                cand.chars().nth(match_start - 1).unwrap_or(' ')
            } else {
                ' '
            };

            if base_first_char != '.' {
                if base_first_char == '@' {
                    return true;
                }

                if '@' == cand_last_char {
                    return true;
                }
            } else if '@' != cand_last_char {
                return true;
            }
        }
    }
    false
}

/// `descended_from_dn` returns true if new_name is equal to or descended from prev_name and false otherwise.
pub(crate) fn descended_from_dn(subtree: &Name, name: &Name, min: u32, max: Option<u32>) -> bool {
    //if descendant fewer rdns then it is not a descendant
    if subtree.0.len() > name.0.len() {
        return false;
    }

    let diff = (name.0.len() - subtree.0.len()) as u32;
    if diff < min {
        return false;
    }
    if let Some(max) = max {
        if diff > max {
            return false;
        }
    }

    for i in 0..subtree.0.len() {
        if subtree.0[i] != name.0[i] {
            let mut let_it_slide = false;

            // some folks can't manage to use the same character set in a name constraint and subject name
            // allow this practice to not break stuff
            let l = &subtree.0[i];
            let r = &name.0[i];
            if l.0.len() != r.0.len() {
                // diff number of attributes
                return false;
            }
            for j in 0..l.0.len() {
                let la = l.0.get(j);
                let ra = r.0.get(j);
                if la.is_none() || ra.is_none() {
                    // ought not occur
                    return false;
                }
                let lau = la.unwrap();
                let rau = ra.unwrap();
                if lau.oid != rau.oid {
                    // if the type of attribute, i.e., c, cn, o, is different, return false
                    return false;
                }
                let lav = &lau.value;
                let rav = &rau.value;
                //not checking tag on the any since that is where the issue is most likely
                if lav.value() == rav.value() {
                    if lav.tag() != rav.tag() {
                        debug!("Permitting a DN name constraint match despite different character sets");
                        let_it_slide = true;
                    }
                } else {
                    let llav = lau.to_string();
                    let rlav = rau.to_string();
                    if llav.to_lowercase() == rlav.to_lowercase() {
                        debug!( "Permitting a DN name constraint match despite different capitalization");
                        let_it_slide = true;
                    }
                }
            }

            if !let_it_slide {
                return false;
            }
        }
    }

    true
}

/// `has_rfc822` returns true if the given GeneralSubtrees contains at least one RFC822 name and false otherwise
pub(crate) fn has_rfc822(subtrees: &GeneralSubtrees) -> bool {
    for subtree in subtrees {
        if let GeneralName::Rfc822Name(_rfc) = &subtree.base {
            return true;
        }
    }
    false
}

/// `has_dns_name` returns true if the given GeneralSubtrees contains at least one DNS name and false otherwise
pub(crate) fn has_dns_name(subtrees: &GeneralSubtrees) -> bool {
    for subtree in subtrees {
        if let GeneralName::DnsName(_dns) = &subtree.base {
            return true;
        }
    }
    false
}

/// `has_dn` returns true if the given GeneralSubtrees contains at least one DN and false otherwise
pub(crate) fn has_dn(subtrees: &GeneralSubtrees) -> bool {
    for subtree in subtrees {
        if let GeneralName::DirectoryName(_dn) = &subtree.base {
            return true;
        }
    }
    false
}

/// `has_uri` returns true if the given GeneralSubtrees contains at least one URI and false otherwise
pub(crate) fn has_uri(subtrees: &GeneralSubtrees) -> bool {
    for subtree in subtrees {
        if let GeneralName::UniformResourceIdentifier(_uri) = &subtree.base {
            return true;
        }
    }
    false
}

/// get_hash_alg_from_sig_alg takes an ObjectIdentifier that notionally contains a signature algorithm,
/// i.e., PKIXALG_SHA256_WITH_RSA_ENCRYPTION or PKIXALG_ECDSA_WITH_SHA256, and returns the indicated hash
/// algorithm.
pub fn get_hash_alg_from_sig_alg(sig_alg: &ObjectIdentifier) -> Result<AlgorithmIdentifierOwned> {
    if PKIXALG_SHA256_WITH_RSA_ENCRYPTION == *sig_alg || PKIXALG_ECDSA_WITH_SHA256 == *sig_alg {
        return Ok(AlgorithmIdentifier {
            oid: PKIXALG_SHA256,
            parameters: None,
        });
    } else if PKIXALG_SHA384_WITH_RSA_ENCRYPTION == *sig_alg
        || PKIXALG_ECDSA_WITH_SHA384 == *sig_alg
    {
        return Ok(AlgorithmIdentifier {
            oid: PKIXALG_SHA384,
            parameters: None,
        });
    } else if PKIXALG_SHA224_WITH_RSA_ENCRYPTION == *sig_alg
        || PKIXALG_ECDSA_WITH_SHA224 == *sig_alg
    {
        return Ok(AlgorithmIdentifier {
            oid: PKIXALG_SHA224,
            parameters: None,
        });
    } else if PKIXALG_SHA512_WITH_RSA_ENCRYPTION == *sig_alg
        || PKIXALG_ECDSA_WITH_SHA512 == *sig_alg
    {
        return Ok(AlgorithmIdentifier {
            oid: PKIXALG_SHA512,
            parameters: None,
        });
    }
    Err(Error::Unrecognized)
}

pub(crate) fn log_error_for_name(name: &Name, msg: &str) {
    let name_str = name_to_string(name);
    error!(
        "Encountered error while processing certificate with subject {}: {}",
        name_str, msg
    );
}

pub(crate) fn log_error_for_ca(ca: &PDVCertificate, msg: &str) {
    log_error_for_name(&ca.decoded_cert.tbs_certificate.subject, msg);
}

/// log a message with subject name of the certificate appended
pub fn log_error_for_subject(ca: &Certificate, msg: &str) {
    log_error_for_name(&ca.tbs_certificate.subject, msg);
}

/// `oid_lookup` takes an ObjectIdentifier and returns a string with a friendly name for the OID or
/// Error::NotFound.
pub fn oid_lookup(oid: &ObjectIdentifier) -> Result<String> {
    if *oid == PKIXALG_SHA224_WITH_RSA_ENCRYPTION {
        return Ok("SHA224 with RSA Encryption".to_string());
    } else if *oid == PKIXALG_SHA256_WITH_RSA_ENCRYPTION {
        return Ok("SHA256 with RSA Encryption".to_string());
    } else if *oid == PKIXALG_SHA384_WITH_RSA_ENCRYPTION {
        return Ok("SHA384 with RSA Encryption".to_string());
    } else if *oid == PKIXALG_SHA512_WITH_RSA_ENCRYPTION {
        return Ok("SHA512 with RSA Encryption".to_string());
    } else if *oid == PKIXALG_RSA_ENCRYPTION {
        return Ok("RSA Encryption".to_string());
    } else if *oid == NAME {
        return Ok("name".to_string());
    } else if *oid == SURNAME {
        return Ok("sn".to_string());
    } else if *oid == GIVEN_NAME {
        return Ok("givenName".to_string());
    } else if *oid == INITIALS {
        return Ok("initials".to_string());
    } else if *oid == GENERATION_QUALIFIER {
        return Ok("generationQualifier".to_string());
    } else if *oid == COMMON_NAME {
        return Ok("cn".to_string());
    } else if *oid == LOCALITY_NAME {
        return Ok("l".to_string());
    } else if *oid == STATE_OR_PROVINCE_NAME {
        return Ok("st".to_string());
    } else if *oid == STREET {
        return Ok("street".to_string());
    } else if *oid == ORGANIZATIONAL_UNIT_NAME {
        return Ok("ou".to_string());
    } else if *oid == ORGANIZATION_NAME {
        return Ok("o".to_string());
    } else if *oid == TITLE {
        return Ok("title".to_string());
    } else if *oid == DN_QUALIFIER {
        return Ok("dnQualifier".to_string());
    } else if *oid == COUNTRY_NAME {
        return Ok("c".to_string());
    } else if *oid == SERIAL_NUMBER {
        return Ok("serialNumber".to_string());
    } else if *oid == PSEUDONYM {
        return Ok("pseudonym".to_string());
    } else if *oid == DOMAIN_COMPONENT {
        return Ok("dc".to_string());
    } else if *oid == EMAIL_ADDRESS {
        return Ok("emailAddress".to_string());
    } else if *oid == UID {
        return Ok("uid".to_string());
    }
    Err(Error::NotFound)
}

/// encode_dn_from_string takes a string representation of a distinguished name and returns the DER
/// encoding of that name.
pub fn encode_dn_from_string(string: &str) -> Result<Vec<u8>> {
    match RdnSequence::from_str(string) {
        Ok(rdn) => match rdn.to_der() {
            Ok(v) => Ok(v),
            Err(e) => Err(Error::Asn1Error(e)),
        },
        Err(e) => Err(Error::Asn1Error(e)),
    }
}

/// rdn_oid_lookup takes a string, notionally an attribute label from a distinguished name, and return
/// either an ObjectIdentifier that corresponds to that string or Error::Unrecognized.
pub fn rdn_oid_lookup(oid_str: &str) -> Result<ObjectIdentifier> {
    let lc_oid_str = oid_str.to_lowercase();
    if lc_oid_str == "name" {
        return Ok(NAME);
    } else if lc_oid_str == "sn" {
        return Ok(SURNAME);
    } else if lc_oid_str == "givenName" {
        return Ok(GIVEN_NAME);
    } else if lc_oid_str == "initials" {
        return Ok(INITIALS);
    } else if lc_oid_str == "generationQualifier" {
        return Ok(GENERATION_QUALIFIER);
    } else if lc_oid_str == "cn" {
        return Ok(COMMON_NAME);
    } else if lc_oid_str == "l" {
        return Ok(LOCALITY_NAME);
    } else if lc_oid_str == "st" {
        return Ok(STATE_OR_PROVINCE_NAME);
    } else if lc_oid_str == "street" {
        return Ok(STREET);
    } else if lc_oid_str == "ou" {
        return Ok(ORGANIZATIONAL_UNIT_NAME);
    } else if lc_oid_str == "o" {
        return Ok(ORGANIZATION_NAME);
    } else if lc_oid_str == "title" {
        return Ok(TITLE);
    } else if lc_oid_str == "dnQualifier" {
        return Ok(DN_QUALIFIER);
    } else if lc_oid_str == "c" {
        return Ok(COUNTRY_NAME);
    } else if lc_oid_str == "serialNumber" {
        return Ok(SERIAL_NUMBER);
    } else if lc_oid_str == "pseudonym" {
        return Ok(PSEUDONYM);
    } else if lc_oid_str == "dc" {
        return Ok(DOMAIN_COMPONENT);
    } else if lc_oid_str == "emailAddress" {
        return Ok(EMAIL_ADDRESS);
    } else if lc_oid_str == "uid" {
        return Ok(UID);
    } else if let Ok(oid) = ObjectIdentifier::from_str(lc_oid_str.as_str()) {
        return Ok(oid);
    }
    Err(Error::Unrecognized)
}

/// `name_to_string` returns a string representation of given Name value.
pub fn name_to_string(name: &Name) -> String {
    name.to_string()
}

/// get_value_from_rdn returns the value from AttributeTypeAndValue as a string for use in comparing
/// values where leading whitespace may be a factor
pub fn get_value_from_rdn(atav: &AttributeTypeAndValue) -> Result<String> {
    let val = match atav.value.tag() {
        der::Tag::PrintableString => atav
            .value
            .decode_as()
            .ok()
            .map(|s: PrintableString| s.to_string()),
        der::Tag::Utf8String => atav
            .value
            .decode_as()
            .ok()
            .map(|s: Utf8StringRef<'_>| s.to_string()),
        der::Tag::Ia5String => atav
            .value
            .decode_as()
            .ok()
            .map(|s: Ia5String| s.to_string()),
        _ => None,
    };

    let mut s = "".to_string();
    if let Some(val) = val {
        let mut iter = val.char_indices().peekable();
        while let Some((i, c)) = iter.next() {
            match c {
                '#' if i == 0 => s.push_str("\\#"),
                ' ' if i == 0 || iter.peek().is_none() => s.push_str("\\ "),
                '"' | '+' | ',' | ';' | '<' | '>' | '\\' => s.push_str(format!("\\{}", c).as_str()),
                '\x00'..='\x1f' | '\x7f' => s.push_str(format!("\\{:02x}", c as u8).as_str()),
                _ => s.push(c),
            }
        }
    } else {
        match atav.value.to_der() {
            Ok(val) => {
                s.push_str(format!("{}=#", atav.oid).as_str());
                for c in val {
                    s.push_str(format!("{:02x}", c).as_str());
                }
            }
            Err(e) => {
                return Err(Error::Asn1Error(e));
            }
        }
    }
    Ok(s)
}

/// [`compare_names`] compares two Name values returning true if they match and false otherwise.
pub fn compare_names(left: &Name, right: &Name) -> bool {
    // no match if not the same number of RDNs
    if left.0.len() != right.0.len() {
        return false;
    }

    for i in 0..left.0.len() {
        let lrdn = &left.0[i];
        let rrdn = &right.0[i];

        if lrdn.0.len() != rrdn.0.len() {
            return false;
        }

        if lrdn != rrdn {
            // only do the whitespace and case insensitve stuff is simpler compare fails (not full featured on no-std, hence tolerance for unused variables)
            #[allow(unused_variables)]
            for j in 0..lrdn.0.len() {
                let l = lrdn.0.get(j);
                let r = rrdn.0.get(j);

                if l.is_none() || r.is_none() {
                    if l.is_none() && r.is_none() {
                        continue;
                    } else {
                        return false;
                    }
                }
                let l = l.unwrap();
                let r = r.unwrap();

                if l.oid != r.oid {
                    return false;
                }

                let l_str_val = match get_value_from_rdn(l) {
                    Ok(val) => val.replace("\\ ", " "),
                    Err(e) => {
                        return false;
                    }
                };
                let r_str_val = match get_value_from_rdn(r) {
                    Ok(val) => val.replace("\\ ", " "),
                    Err(e) => {
                        return false;
                    }
                };

                let l_val = l_str_val.trim().to_lowercase();
                let r_val = r_str_val.trim().to_lowercase();

                if l_val != r_val {
                    #[cfg(feature = "std")]
                    {
                        let re = if let Ok(re) = Regex::new(r"\s+") {
                            re
                        } else {
                            return false;
                        };

                        //collapse multiple whitespace instances into one and convert to lowercase
                        let l_str_val = re.replace_all(l_val.as_str(), " ");
                        let r_str_val = re.replace_all(r_val.as_str(), " ");
                        if l_str_val != r_str_val {
                            return false;
                        }
                    }
                    #[cfg(not(feature = "std"))]
                    {
                        // TODO implement to support name comparison with whitespace issues for no-std
                        return false;
                    }
                }
            }
        }
    }
    true
}

/// Retrieves a string value from the first attribute of last RDN element in the presented Name.
pub fn get_leaf_rdn(name: &Name) -> String {
    let rdn = &name.0[name.0.len() - 1];
    rdn.to_string()
}

/// ta_valid_at_time checks the validity of the given trust anchor relative to the given time of interest.
pub fn ta_valid_at_time(ta: &TrustAnchorChoice, toi: u64, stifle_log: bool) -> Result<u64> {
    match ta {
        TrustAnchorChoice::Certificate(c) => {
            return valid_at_time(&c.tbs_certificate, toi, stifle_log);
        }
        TrustAnchorChoice::TaInfo(tai) => {
            if let Some(cp) = &tai.cert_path {
                if let Some(c) = &cp.certificate {
                    return valid_at_time(&c.tbs_certificate, toi, stifle_log);
                }
            }
        }
        _ => {}
    }
    Err(Error::Unrecognized)
}

pub(crate) fn general_subtree_to_string(gs: &GeneralSubtree) -> String {
    match &gs.base {
        GeneralName::DirectoryName(dn) => {
            format!("DirectoryName: {}", dn)
        }
        GeneralName::UniformResourceIdentifier(uri) => {
            format!("UniformResourceIdentifier: {}", uri)
        }
        GeneralName::DnsName(dns) => format!("DnsName: {}", dns),
        GeneralName::Rfc822Name(rfc822) => {
            format!("Rfc822Name: {}", rfc822)
        }
        GeneralName::OtherName(_on) => format!("OtherName: {:?}", gs.base),
        GeneralName::RegisteredId(_rid) => format!("RegisteredId: {:?}", gs.base),
        GeneralName::IpAddress(_ip) => format!("IpAddress: {:?}", gs.base),
        GeneralName::EdiPartyName(_ip) => format!("EdiPartyName: {:?}", gs.base),
    }
}

#[test]
fn bad_input_self_signed() {
    use crate::populate_5280_pki_environment;
    let der_encoded_ta = include_bytes!("../../tests/examples/TrustAnchorRootCertificate.crt");
    let ta_cert = Certificate::from_der(der_encoded_ta).unwrap();
    let junk = include_bytes!("../../tests/examples/caCertsIssuedTofbcag4.p7c");
    let mut pe = PkiEnvironment::default();
    populate_5280_pki_environment(&mut pe);
    assert!(!is_self_signed_with_buffer(&pe, &ta_cert, junk));
}

#[test]
fn ta_exts_read() {
    let der_encoded_ta =
        include_bytes!("../../tests/examples/PKITS_data_2048/certs/TrustAnchorRootCertificate.crt");
    let default = TrustAnchorChoice::from_der(der_encoded_ta).unwrap();
    assert!(!get_inhibit_any_policy_from_trust_anchor(&default).unwrap());
    assert!(!get_require_explicit_policy_from_trust_anchor(&default).unwrap());
    assert!(!get_inhibit_policy_mapping_from_trust_anchor(&default).unwrap());

    let der_encoded_ta =
        include_bytes!("../../tests/examples/PKITS_data_2048/certs/GoodsubCACert.crt");
    let default = TrustAnchorChoice::from_der(der_encoded_ta).unwrap();
    assert!(!get_inhibit_any_policy_from_trust_anchor(&default).unwrap());
    assert!(get_require_explicit_policy_from_trust_anchor(&default).unwrap());
    assert!(!get_inhibit_policy_mapping_from_trust_anchor(&default).unwrap());

    let der_encoded_ta =
        include_bytes!("../../tests/examples/PKITS_data_2048/certs/inhibitAnyPolicy0CACert.crt");
    let default = TrustAnchorChoice::from_der(der_encoded_ta).unwrap();
    assert!(get_inhibit_any_policy_from_trust_anchor(&default).unwrap());
    assert!(get_require_explicit_policy_from_trust_anchor(&default).unwrap());
    assert!(!get_inhibit_policy_mapping_from_trust_anchor(&default).unwrap());

    let der_encoded_ta = include_bytes!(
        "../../tests/examples/PKITS_data_2048/certs/inhibitPolicyMapping0CACert.crt"
    );
    let default = TrustAnchorChoice::from_der(der_encoded_ta).unwrap();
    assert!(!get_inhibit_any_policy_from_trust_anchor(&default).unwrap());
    assert!(get_require_explicit_policy_from_trust_anchor(&default).unwrap());
    assert!(get_inhibit_policy_mapping_from_trust_anchor(&default).unwrap());
}

#[test]
fn get_hash_alg_from_sig_alg_test() {
    let ai224 = AlgorithmIdentifier {
        oid: PKIXALG_SHA224,
        parameters: None,
    };
    let ai256 = AlgorithmIdentifier {
        oid: PKIXALG_SHA256,
        parameters: None,
    };
    let ai384 = AlgorithmIdentifier {
        oid: PKIXALG_SHA384,
        parameters: None,
    };
    let ai512 = AlgorithmIdentifier {
        oid: PKIXALG_SHA512,
        parameters: None,
    };
    assert_eq!(
        get_hash_alg_from_sig_alg(&PKIXALG_ECDSA_WITH_SHA224).unwrap(),
        ai224
    );
    assert_eq!(
        get_hash_alg_from_sig_alg(&PKIXALG_SHA224_WITH_RSA_ENCRYPTION).unwrap(),
        ai224
    );
    assert_eq!(
        get_hash_alg_from_sig_alg(&PKIXALG_ECDSA_WITH_SHA256).unwrap(),
        ai256
    );
    assert_eq!(
        get_hash_alg_from_sig_alg(&PKIXALG_SHA256_WITH_RSA_ENCRYPTION).unwrap(),
        ai256
    );
    assert_eq!(
        get_hash_alg_from_sig_alg(&PKIXALG_ECDSA_WITH_SHA384).unwrap(),
        ai384
    );
    assert_eq!(
        get_hash_alg_from_sig_alg(&PKIXALG_SHA384_WITH_RSA_ENCRYPTION).unwrap(),
        ai384
    );
    assert_eq!(
        get_hash_alg_from_sig_alg(&PKIXALG_ECDSA_WITH_SHA512).unwrap(),
        ai512
    );
    assert_eq!(
        get_hash_alg_from_sig_alg(&PKIXALG_SHA512_WITH_RSA_ENCRYPTION).unwrap(),
        ai512
    );
}
