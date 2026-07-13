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
    certificate::{CertificateInner, Raw, TbsCertificateInner},
};

use crate::{
    environment::pki_environment::PkiEnvironment, name_constraints_set::UID,
    path_settings::PS_MAX_PATH_LENGTH_CONSTRAINT, pdv_certificate::*, pdv_extension::*,
    util::error::*, util::pdv_alg_oids::*, TimeOfInterest,
};

/// `is_self_signed_with_buffer` returns true if the public key in the parsed certificate can be
/// used to verify the TBSCertificate field as parsed from the encoded certificate object.
pub fn is_self_signed_with_buffer(
    pe: &PkiEnvironment,
    cert: &CertificateInner<Raw>,
    enc_cert: &[u8],
) -> bool {
    match DeferDecodeSigned::from_der(enc_cert) {
        Ok(defer_cert) => pe
            .verify_signature_message(
                pe,
                &defer_cert.tbs_field,
                cert.signature().raw_bytes(),
                cert.tbs_certificate().signature(),
                cert.tbs_certificate().subject_public_key_info(),
            )
            .is_ok(),
        Err(e) => {
            error!("Failed to defer decode certificate in is_self_signed with: {e}");
            false
        }
    }
}

/// `is_self_signed` returns true if the public key in the certificate can be used to verify the
/// signature on the certificate.
pub fn is_self_signed(pe: &PkiEnvironment, cert: &PDVCertificate) -> bool {
    is_self_signed_with_buffer(pe, cert.as_ref(), cert.as_bytes())
}

/// `is_self_issued` returns true if the subject field in the certificate is the same as the issuer
/// field.
pub fn is_self_issued(cert: &CertificateInner<Raw>) -> bool {
    compare_names(
        cert.tbs_certificate().issuer(),
        cert.tbs_certificate().subject(),
    )
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
pub fn valid_at_time(
    target: &TbsCertificateInner<Raw>,
    toi: TimeOfInterest,
    stifle_log: bool,
) -> Result<u64> {
    if toi.is_disabled() {
        // zero is used to disable validity check
        return Ok(0);
    }

    let validity = target.validity();
    let nb = validity.not_before;
    if nb > toi {
        if !stifle_log {
            log_error_for_name(target.subject(), "certificate is not yet valid, i.e., not_before is prior to the configured time of interest");
        }
        return Err(Error::PathValidation(
            PathValidationStatus::InvalidNotBeforeDate,
        ));
    }

    let na = validity.not_after;
    if na < toi {
        if !stifle_log {
            log_error_for_name(
                target.subject(),
                format!(
                    "certificate is expired relative to the configured time of interest: {}",
                    validity.not_after
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

/// `get_inhibit_any_policy_from_trust_anchor` returns true if the trust anchor inhibits the use of any policy
/// during certification path processing.
///
/// True is returned if inhibit any policy is found in an extension in TA certificate for certificate CHOICE
/// or the value from CertPathControls.PolicyFlags for TrustAnchorInfo CHOICE. Otherwise, false is returned.
pub(crate) fn get_inhibit_any_policy_from_trust_anchor(
    ta: &TrustAnchorChoice<Raw>,
) -> Result<bool> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => {
            if let Some(extensions) = &cert.tbs_certificate().extensions() {
                for ext in extensions.as_slice() {
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
    ta: &TrustAnchorChoice<Raw>,
) -> Result<bool> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => {
            if let Some(extensions) = &cert.tbs_certificate().extensions() {
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
pub(crate) fn get_inhibit_policy_mapping_from_trust_anchor(
    ta: &TrustAnchorChoice<Raw>,
) -> Result<bool> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => {
            if let Some(extensions) = &cert.tbs_certificate().extensions() {
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
pub(crate) fn get_path_length_constraint_from_trust_anchor(
    ta: &TrustAnchorChoice<Raw>,
) -> Result<u8> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => {
            if let Some(extensions) = &cert.tbs_certificate().extensions() {
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
pub fn descended_from_host(prev_name: &Ia5String, cand: &str, is_uri: bool) -> bool {
    let base = prev_name.as_bytes();
    let cand = cand.as_bytes();
    if base.is_empty() || cand.len() < base.len() {
        return false;
    }

    // DNS names and URI hosts are case-insensitive (ASCII fold per RFC 4343).
    let match_start = cand.len() - base.len();
    if !cand[match_start..].eq_ignore_ascii_case(base) {
        return false;
    }

    if match_start == 0 {
        return true;
    }

    if !is_uri {
        // the matched base must sit on a label boundary
        b'.' == cand[match_start - 1]
    } else {
        // a URI constraint matches a proper suffix only when it is a domain
        // constraint, i.e., when the base begins with a period
        b'.' == cand[match_start]
    }
}

// TODO implement to support name constraints for no-std
/// `descended_from_rfc822` returns true if new_name falls within the constraint expressed by
/// prev_name. Per RFC 5280 4.2.1.10, the constraint is a mailbox (a particular mailbox), a host
/// (all mailboxes on that host) or a domain indicated by a leading period (all mailboxes on hosts
/// within that domain). Per RFC 5280 7.5, local parts are compared exactly and host parts are
/// compared case-insensitively.
#[cfg(feature = "std")]
pub(crate) fn descended_from_rfc822(prev_name: &Ia5String, new_name: &Ia5String) -> bool {
    descended_from_rfc822_str(prev_name.as_ref(), new_name.as_ref())
}

/// `descended_from_rfc822_str` is the string-valued core of [`descended_from_rfc822`]. It is shared
/// with UPN (otherName) name-constraint processing, whose values are structured as email addresses
/// but are not necessarily carried as IA5String. Pure string comparison, so it needs no std.
pub(crate) fn descended_from_rfc822_str(base: &str, cand: &str) -> bool {
    // A candidate rfc822Name must be a single well-formed mailbox. A malformed address such as
    // "a@b@example.com" is not within any permitted namespace even though it ends with a permitted
    // host, so reject anything that does not contain exactly one '@'.
    if cand.matches('@').count() != 1 {
        return false;
    }
    let (cand_local, cand_host) = match cand.split_once('@') {
        Some(parts) => parts,
        None => return false,
    };

    // a constraint with more than one '@' matches nothing
    if base.matches('@').count() > 1 {
        return false;
    }
    match base.split_once('@') {
        // mailbox constraint
        Some((base_local, base_host)) => {
            cand_local == base_local && cand_host.eq_ignore_ascii_case(base_host)
        }
        None => {
            let base_bytes = base.as_bytes();
            let cand_host_bytes = cand_host.as_bytes();
            if base_bytes.is_empty() {
                false
            } else if b'.' == base_bytes[0] {
                // domain constraint: the candidate host must lie within the domain
                cand_host_bytes.len() > base_bytes.len()
                    && cand_host_bytes[cand_host_bytes.len() - base_bytes.len()..]
                        .eq_ignore_ascii_case(base_bytes)
            } else {
                // host constraint: the candidate host must match exactly
                cand_host_bytes.eq_ignore_ascii_case(base_bytes)
            }
        }
    }
}

/// `emails_from_dn` returns the values of any PKCS#9 emailAddress attributes present in the given
/// distinguished name, as `Ia5String` values. Applying rfc822 name constraints to an emailAddress
/// attribute carried in the subject DN (in addition to rfc822Name SAN entries) is legacy RFC 3280
/// behavior, as OpenSSL does; it is not required by RFC 5280.
#[cfg(feature = "std")]
pub(crate) fn emails_from_dn(name: &Name) -> Vec<Ia5String> {
    let mut emails = Vec::new();
    for rdn in name.iter_rdn() {
        for atav in rdn.iter() {
            if atav.oid != EMAIL_ADDRESS {
                continue;
            }
            // PKCS#9 emailAddress is IA5String; some issuers use Utf8String ('@' is not in the
            // PrintableString set, so no other type can hold a valid rfc822 name). Don't fail on a
            // malformed email address in the RDN -- applying constraints to emailAddress-in-DN is
            // non-standard anyway, so an address that isn't a valid rfc822 name is simply skipped.
            let ia5 = match atav.value.tag() {
                der::Tag::Ia5String => atav.value.decode_as::<Ia5String>().ok(),
                der::Tag::Utf8String => atav
                    .value
                    .decode_as::<Utf8StringRef<'_>>()
                    .ok()
                    .and_then(|s| Ia5String::new(s.as_str()).ok()),
                _ => None,
            };
            if let Some(ia5) = ia5 {
                emails.push(ia5);
            }
        }
    }
    emails
}

/// `descended_from_dn` returns true if new_name is equal to or descended from prev_name and false otherwise.
pub(crate) fn descended_from_dn(subtree: &Name, name: &Name, min: u32, max: Option<u32>) -> bool {
    //if descendant fewer rdns then it is not a descendant
    if subtree.len() > name.len() {
        return false;
    }

    let diff = (name.len() - subtree.len()) as u32;
    if diff < min {
        return false;
    }
    if let Some(max) = max {
        if diff > max {
            return false;
        }
    }

    for (subtree_rdn, name_rdn) in subtree.iter_rdn().zip(name.iter_rdn()) {
        if subtree_rdn != name_rdn {
            // some folks can't manage to use the same character set in a name constraint and subject name
            // allow this practice to not break stuff
            if subtree_rdn.len() != name_rdn.len() {
                // diff number of attributes
                return false;
            }
            // every attribute in the RDN must match, either exactly or via one of the
            // tolerances below; a single mismatched attribute fails the whole RDN
            for (subtree_attr, name_attr) in subtree_rdn.iter().zip(name_rdn.iter()) {
                let lau = subtree_attr;
                let rau = name_attr;
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
                    }
                } else {
                    let llav = lau.to_string();
                    let rlav = rau.to_string();
                    if llav.to_lowercase() == rlav.to_lowercase() {
                        debug!( "Permitting a DN name constraint match despite different capitalization");
                    } else {
                        return false;
                    }
                }
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

/// `has_ip` returns true if the given GeneralSubtrees contains at least one IP address and false otherwise
pub(crate) fn has_ip(subtrees: &GeneralSubtrees) -> bool {
    for subtree in subtrees {
        if let GeneralName::IpAddress(_uri) = &subtree.base {
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
    error!("Encountered error while processing certificate with subject {name_str}: {msg}");
}

pub(crate) fn log_error_for_ca(ca: &PDVCertificate, msg: &str) {
    log_error_for_name(ca.as_ref().tbs_certificate().subject(), msg);
}

/// log a message with subject name of the certificate appended
pub fn log_error_for_subject(ca: &CertificateInner<Raw>, msg: &str) {
    log_error_for_name(ca.tbs_certificate().subject(), msg);
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
                '"' | '+' | ',' | ';' | '<' | '>' | '\\' => s.push_str(format!("\\{c}").as_str()),
                '\x00'..='\x1f' | '\x7f' => s.push_str(format!("\\{:02x}", c as u8).as_str()),
                _ => s.push(c),
            }
        }
    } else {
        match atav.value.to_der() {
            Ok(val) => {
                s.push_str(format!("{}=#", atav.oid).as_str());
                for c in val {
                    s.push_str(format!("{c:02x}").as_str());
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
    if left.len() != right.len() {
        return false;
    }

    for (lrdn, rrdn) in left.iter_rdn().zip(right.iter_rdn()) {
        if lrdn.len() != rrdn.len() {
            return false;
        }

        if lrdn != rrdn {
            // only do the whitespace and case insensitve stuff is simpler compare fails (not full featured on no-std, hence tolerance for unused variables)
            #[allow(unused_variables)]
            for (l, r) in lrdn.iter().zip(rrdn.iter()) {
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
                        lazy_static! {
                            static ref WHITESPACE_RE: Regex = Regex::new(r"\s+").unwrap();
                        }
                        //collapse multiple whitespace instances into one and convert to lowercase
                        let l_str_val = WHITESPACE_RE.replace_all(l_val.as_str(), " ");
                        let r_str_val = WHITESPACE_RE.replace_all(r_val.as_str(), " ");
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
    let rdn = &name.iter_rdn().last();
    rdn.map(|r| r.to_string()).unwrap_or_default()
}

/// ta_valid_at_time checks the validity of the given trust anchor relative to the given time of interest.
pub fn ta_valid_at_time(
    ta: &TrustAnchorChoice<Raw>,
    toi: TimeOfInterest,
    stifle_log: bool,
) -> Result<u64> {
    match ta {
        TrustAnchorChoice::Certificate(c) => {
            return valid_at_time(c.tbs_certificate(), toi, stifle_log);
        }
        TrustAnchorChoice::TaInfo(tai) => {
            if let Some(cp) = &tai.cert_path {
                if let Some(c) = &cp.certificate {
                    return valid_at_time(c.tbs_certificate(), toi, stifle_log);
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
            format!("DirectoryName: {dn}")
        }
        GeneralName::UniformResourceIdentifier(uri) => {
            format!("UniformResourceIdentifier: {uri}")
        }
        GeneralName::DnsName(dns) => format!("DnsName: {dns}"),
        GeneralName::Rfc822Name(rfc822) => {
            format!("Rfc822Name: {rfc822}")
        }
        GeneralName::OtherName(_on) => format!("OtherName: {:?}", gs.base),
        GeneralName::RegisteredId(_rid) => format!("RegisteredId: {:?}", gs.base),
        GeneralName::IpAddress(_ip) => format!("IpAddress: {:?}", gs.base),
        GeneralName::EdiPartyName(_ip) => format!("EdiPartyName: {:?}", gs.base),
    }
}

#[test]
fn bad_input_self_signed() {
    let der_encoded_ta = include_bytes!("../../tests/examples/TrustAnchorRootCertificate.crt");
    let ta_cert = CertificateInner::from_der(der_encoded_ta).unwrap();
    let junk = include_bytes!("../../tests/examples/caCertsIssuedTofbcag4.p7c");
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
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

// DNS name constraints match case-insensitively (RFC 1035 Section 2.3.3, RFC 4343). Positive
// (assert!) and negative (assert!(!...)) cases cover exact, sub-domain, and non-matching hosts.
#[cfg(feature = "std")]
#[test]
fn descended_from_host_case_insensitive() {
    let base = Ia5String::new("Example.COM").unwrap();
    assert!(descended_from_host(&base, "example.com", false)); // exact host, differing case
    assert!(descended_from_host(&base, "HOST.Example.com", false)); // sub-domain, differing case
    assert!(!descended_from_host(&base, "host.notexample.com", false)); // suffix trap, not descended
}

// Label-boundary behavior for host constraints: a DNS constraint covers the host and its
// sub-domains; a URI constraint covers only the exact host unless it begins with a period,
// in which case it covers sub-domains only.
#[cfg(feature = "std")]
#[test]
fn descended_from_host_boundaries() {
    let host = |s: &str| Ia5String::new(s).unwrap();
    // DNS form
    assert!(descended_from_host(
        &host("example.com"),
        "example.com",
        false
    ));
    assert!(descended_from_host(
        &host("example.com"),
        "sub.example.com",
        false
    ));
    assert!(!descended_from_host(
        &host("example.com"),
        "evil-example.com",
        false
    ));
    assert!(!descended_from_host(&host("example.com"), "com", false));
    // URI host form: exact only
    assert!(descended_from_host(
        &host("example.com"),
        "example.com",
        true
    ));
    assert!(!descended_from_host(
        &host("example.com"),
        "sub.example.com",
        true
    ));
    // URI domain form: sub-domains only
    assert!(descended_from_host(
        &host(".example.com"),
        "sub.example.com",
        true
    ));
    assert!(!descended_from_host(
        &host(".example.com"),
        "example.com",
        true
    ));
    // trailing periods (absolute FQDN form) never match; certificates presenting
    // such names or constraints are rejected during path validation instead
    assert!(!descended_from_host(
        &host("example.com"),
        "sub.example.com.",
        false
    ));
    assert!(!descended_from_host(
        &host("example.com."),
        "sub.example.com",
        false
    ));
}

// rfc822 host parts match case-insensitively while local parts match exactly (RFC 5280
// Section 7.5).
#[cfg(feature = "std")]
#[test]
fn descended_from_rfc822_case_sensitivity() {
    let ia5 = |s: &str| Ia5String::new(s).unwrap();
    // host constraint: all mailboxes on the host, any local-part case
    let host = ia5("Example.COM");
    assert!(descended_from_rfc822(&host, &ia5("user@example.com")));
    assert!(descended_from_rfc822(&host, &ia5("USER@EXAMPLE.COM")));
    assert!(!descended_from_rfc822(&host, &ia5("user@notexample.com")));
    assert!(!descended_from_rfc822(&host, &ia5("user@sub.example.com"))); // host form is exact
                                                                          // mailbox constraint: host case-insensitive, local part exact
    let mailbox = ia5("Admin@Example.COM");
    assert!(descended_from_rfc822(&mailbox, &ia5("Admin@example.com")));
    assert!(!descended_from_rfc822(&mailbox, &ia5("admin@example.com")));
    // domain constraint: mailboxes on hosts within the domain, not the bare domain host
    let domain = ia5(".Example.COM");
    assert!(descended_from_rfc822(&domain, &ia5("user@sub.example.com")));
    assert!(!descended_from_rfc822(&domain, &ia5("user@example.com")));
    // trailing periods (absolute FQDN form) never match; certificates presenting
    // such names or constraints are rejected during path validation instead
    assert!(!descended_from_rfc822(&host, &ia5("user@example.com.")));
    assert!(!descended_from_rfc822(
        &domain,
        &ia5("user@sub.example.com.")
    ));
}

// A mailbox constraint whose local part uses legal-but-uncommon characters must still match
// (formerly gated behind an email regex that rejected such local parts).
#[cfg(feature = "std")]
#[test]
fn descended_from_rfc822_special_local_parts() {
    let ia5 = |s: &str| Ia5String::new(s).unwrap();
    for addr in [
        "us-er@example.com",
        "user%x@example.com",
        "u!ser@example.com",
        "us~er@example.com",
    ] {
        assert!(descended_from_rfc822(&ia5(addr), &ia5(addr)));
    }
    assert!(!descended_from_rfc822(
        &ia5("us-er@example.com"),
        &ia5("user@example.com")
    ));
}

// A malformed rfc822 name (not a single mailbox) is within no permitted namespace, even when it
// ends with a permitted host.
#[cfg(feature = "std")]
#[test]
fn descended_from_rfc822_rejects_malformed() {
    let ia5 = |s: &str| Ia5String::new(s).unwrap();
    let host = ia5("example.com");
    assert!(!descended_from_rfc822(
        &host,
        &ia5("invalid@address@example.com")
    )); // two '@'
    assert!(!descended_from_rfc822(&host, &ia5("example.com"))); // no '@', not a mailbox
}

// descended_from_dn's char-set/case tolerance must compare the current subtree RDN's attributes,
// not the whole subtree name flattened: a non-leading RDN that differs only by case must still be
// recognized as descended.
#[cfg(feature = "std")]
#[test]
fn descended_from_dn_uses_current_rdn_attributes() {
    let subtree = Name::from_str("CN=Example,O=Org").unwrap();
    let name = Name::from_str("CN=example,O=Org").unwrap();
    assert!(descended_from_dn(&subtree, &name, 0, None));
}

// In a multivalued RDN every attribute must match, exactly or via the case/char-set
// tolerance; one attribute matching case-insensitively must not excuse a different
// attribute that does not match at all.
#[cfg(feature = "std")]
#[test]
fn descended_from_dn_multivalued_rdn_requires_all_attributes() {
    let subtree = Name::from_str("CN=Example+OU=Unit,O=Org").unwrap();
    let case_only = Name::from_str("CN=example+OU=Unit,O=Org").unwrap();
    let one_differs = Name::from_str("CN=example+OU=Other,O=Org").unwrap();
    assert!(descended_from_dn(&subtree, &case_only, 0, None));
    assert!(!descended_from_dn(&subtree, &one_differs, 0, None));
}
