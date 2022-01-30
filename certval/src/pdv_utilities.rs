//! Utility functions that support certification path processing

use crate::error::*;
use crate::path_settings::{
    get_processed_extensions, set_processed_extensions, CertificationPathResults,
    MSFT_USER_PRINCIPAL_NAME, PS_MAX_PATH_LENGTH_CONSTRAINT,
};
use crate::{
    pdv_alg_oids::*, pdv_certificate::*, pki_environment::PeLogLevels,
    pki_environment::PkiEnvironment, ta_source::buffer_to_hex,
};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use der::asn1::{Ia5String, ObjectIdentifier};
use der::Tagged;
use der::{Decodable, Encodable};
use lazy_static::lazy_static;
use regex::Regex;
use x509::{
    pkix_oids::*, trust_anchor_format::TrustAnchorChoice, AlgorithmIdentifier,
    AttributeTypeAndValue, BasicConstraints, Certificate, GeneralName, GeneralSubtrees,
    InhibitAnyPolicy, Name, PolicyConstraints, TBSCertificate,
};

/// `is_self_signed_with_buffer` returns true if the public key in the parsed certificate can be
/// used to verify the TBSCertificate field as parsed from the encoded certificate object.
pub fn is_self_signed_with_buffer(
    pe: &PkiEnvironment<'_>,
    cert: &Certificate<'_>,
    enc_cert: &[u8],
) -> bool {
    match DeferDecodeCertificate::from_der(enc_cert) {
        Ok(defer_cert) => {
            let r = pe.verify_signature_message(
                pe,
                defer_cert.tbs_certificate,
                cert.signature.raw_bytes(),
                &cert.tbs_certificate.signature,
                &cert.tbs_certificate.subject_public_key_info,
            );
            //TODO is it worth making metadata a RefCell to save the result of checks like this?
            //If not, ditch metadata and replace with String field for locator
            matches!(r, Ok(_e))
        }
        Err(e) => {
            pe.log_message(
                &PeLogLevels::PeError,
                format!(
                    "Failed to defer decode certificate in is_self_signed with: {}",
                    e
                )
                .as_str(),
            );
            false
        }
    }
}

/// `is_self_signed` returns true if the public key in the certificate can be used to verify the
/// signature on the certificate.
pub fn is_self_signed(pe: &PkiEnvironment<'_>, cert: &PDVCertificate<'_>) -> bool {
    is_self_signed_with_buffer(pe, &cert.decoded_cert, cert.encoded_cert)
}

/// `is_self_issued` returns true if the subject field in the certificate is the same as the issuer
/// field.
pub fn is_self_issued(cert: &Certificate<'_>) -> bool {
    compare_names(&cert.tbs_certificate.issuer, &cert.tbs_certificate.subject)
}

/// `collect_uris_from_aia_and_sia` collects unique URIs from AIA and SIA extensions from the presented
/// certificate and returns them via the `uris` parameter.
pub fn collect_uris_from_aia_and_sia(cert: &PDVCertificate<'_>, uris: &mut Vec<String>) {
    let aia_ext = cert.get_extension(&PKIX_PE_AUTHORITYINFOACCESS);
    if let Ok(Some(PDVExtension::AuthorityInfoAccessSyntax(aia))) = aia_ext {
        for ad in aia {
            if PKIX_AD_CA_ISSUERS == ad.access_method {
                if let GeneralName::UniformResourceIdentifier(uri) = &ad.access_location {
                    let s = uri.to_string();
                    if !uris.contains(&s) && s.starts_with("http") {
                        uris.push(uri.to_string());
                    }
                }
            }
        }
    }
    let sia_ext = cert.get_extension(&PKIX_PE_SUBJECTINFOACCESS);
    if let Ok(Some(PDVExtension::SubjectInfoAccessSyntax(sia))) = sia_ext {
        for ad in sia {
            if PKIX_AD_CA_REPOSITORY == ad.access_method {
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
    pe: &PkiEnvironment<'_>,
    target: &TBSCertificate<'_>,
    toi: u64,
    stifle_log: bool,
) -> Result<u64> {
    if 0 == toi {
        // zero is used to disable validity check
        return Ok(0);
    }

    let nb = target.validity.not_before.to_unix_duration().as_secs();
    if nb > toi {
        if !stifle_log {
            log_error_for_name(pe, &target.subject, "certificate is not yet valid, i.e., not_before is prior to the configured time of interest");
        }
        return Err(Error::InvalidNotBeforeDate);
    }

    let na = target.validity.not_after.to_unix_duration().as_secs();
    if na < toi {
        if !stifle_log {
            log_error_for_name(
                pe,
                &target.subject,
                format!(
                    "certificate is expired relative to the configured time of interest: {}",
                    target.validity.not_after
                )
                .as_str(),
            );
        }
        Err(Error::InvalidNotAfterDate)
    } else {
        Ok(na - toi)
    }
}

/// `add_processed_extension` takes a [`CertificationPathResults`] and retrieves (or adds then retrieves)
/// an entry for [`PR_PROCESSED_EXTENSIONS`] to which the oid is added if not already present.
pub(crate) fn add_processed_extension(
    cpr: &mut CertificationPathResults<'_>,
    oid: ObjectIdentifier,
) {
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
pub(crate) fn get_inhibit_any_policy_from_trust_anchor<'a>(
    ta: &'a TrustAnchorChoice<'a>,
) -> Result<bool> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => {
            if let Some(extensions) = &cert.tbs_certificate.extensions {
                let i = extensions.iter();
                for ext in i {
                    if PKIX_CE_INHIBIT_ANY_POLICY == ext.extn_id {
                        let iap_result = InhibitAnyPolicy::from_der(ext.extn_value);
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
                    let b = pf.raw_bytes();
                    if 0x20 == 0x20 & b[0] {
                        return Ok(true);
                    }
                }
            }
        }
    }
    Ok(false)
}

/// `get_require_explicit_policy_from_trust_anchor` returns true if the trust anchor requires all paths
/// to be valid under at least one policy during certification path processing.
///
/// True is returned if a policy constraints extension in is present in a certificate CHOICE or the value
/// is set in CertPathControls.PolicyFlags for TrustAnchorInfo CHOICE. Otherwise, false is returned.
pub(crate) fn get_require_explicit_policy_from_trust_anchor<'a>(
    ta: &'a TrustAnchorChoice<'a>,
) -> Result<bool> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => {
            if let Some(extensions) = &cert.tbs_certificate.extensions {
                let i = extensions.iter();
                for ext in i {
                    if PKIX_CE_POLICY_CONSTRAINTS == ext.extn_id {
                        let pc_result = PolicyConstraints::from_der(ext.extn_value);
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
                    let b = pf.raw_bytes();
                    if 0x40 == 0x40 & b[0] {
                        return Ok(true);
                    }
                }
            }
        }
    }
    Ok(false)
}

/// `get_inhibit_policy_mapping_from_trust_anchor` returns true if the trust anchor inhibits the use of policy
/// mapping during certification path processing.
///
/// True is returned if inhibit policy mapping is found in an extension in TA certificate for certificate CHOICE
/// or the value from CertPathControls.PolicyFlags for TrustAnchorInfo CHOICE. Otherwise, false is returned.
pub(crate) fn get_inhibit_policy_mapping_from_trust_anchor<'a>(
    ta: &'a TrustAnchorChoice<'a>,
) -> Result<bool> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => {
            if let Some(extensions) = &cert.tbs_certificate.extensions {
                let i = extensions.iter();
                for ext in i {
                    if PKIX_CE_POLICY_CONSTRAINTS == ext.extn_id {
                        let pc_result = PolicyConstraints::from_der(ext.extn_value);
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
                    let b = pf.raw_bytes();
                    if 0x80 == 0x80 & b[0] {
                        return Ok(true);
                    }
                }
            }
        }
    }
    Ok(false)
}

/// `get_path_length_constraint_from_trust_anchor` returns the value from basic constraints extension in
/// TA certificate for certificate CHOICE, the value from CertPathControls for TrustAnchorInfo CHOICE or
/// [`PS_MAX_PATH_LENGTH_CONSTRAINT`] is no constraint is asserted.
pub(crate) fn get_path_length_constraint_from_trust_anchor<'a>(
    ta: &'a TrustAnchorChoice<'a>,
) -> Result<u8> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => {
            if let Some(extensions) = &cert.tbs_certificate.extensions {
                let i = extensions.iter();
                for ext in i {
                    if PKIX_CE_BASIC_CONSTRAINTS == ext.extn_id {
                        let bc_result = BasicConstraints::from_der(ext.extn_value);
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
    }
    Ok(PS_MAX_PATH_LENGTH_CONSTRAINT)
}

/// `get_str_from_atav` takes an AttributeTypeAndValue and attempts to return the value as a PrintableString,
/// UTF8String or IA5String without regard for the character set that is specified for the given attribute.
/// If the value cannot be rendered as one of these three types, EncodingError is returned.
pub fn get_str_from_atav(atav: &AttributeTypeAndValue<'_>) -> Result<String> {
    // Since character sets are so loosely used, just try the usual suspects
    let s = atav.value.printable_string();
    if let Ok(s) = s {
        return Ok(s.to_string());
    }

    let s = atav.value.utf8_string();
    if let Ok(s) = s {
        return Ok(s.to_string());
    }

    let s = atav.value.ia5_string();
    if let Ok(s) = s {
        return Ok(s.to_string());
    }

    let s = buffer_to_hex(atav.value.to_vec().unwrap().as_slice());
    Ok(s)
}

/// `name_to_string` returns a string representation of given Name value.
pub fn name_to_string(pe: &PkiEnvironment<'_>, name: &Name<'_>) -> String {
    let mut s = vec![];
    for rdn_set in name.iter().rev() {
        let index = s.len();
        for i in 0..rdn_set.len() {
            let atav = rdn_set.get(i).unwrap();
            let attr = pe.oid_lookup(&atav.oid);
            let val = get_str_from_atav(atav);
            if let Ok(val) = val {
                if 0 == i {
                    s.push(format!("{}={}", attr, val));
                } else {
                    s[index] = format!("{}+{}={}", s[index], attr, val);
                }
            } else {
                s.push(format!("{}=<unparsed>", attr));
            }
        }
    }
    s.join(",")
}

/// Email pattern of unknown origin
pub(crate) const EMAIL_PATTERN : &str = "([\\w\\d!\"#$%&'*+-/=?@^_`{|}~]+)@([\\w\\d!\"#$%&'*+-/=?@^_`{|}~]+\\.)([\\w\\d!\"#$%&'*+-/=?@^_`{|}~]+)(\\.[\\w\\d!\"#$%&'*+-/=?@^_`{|}~]+)*";

// // Port pattern of unknown origin
// pub(crate) const PORT_PATTERN: &str = "(.*):(\\d+)?$";
//
// // URI regular expression pattern from RFC 2396 Appendix B
// pub(crate) const URI_PATTERN: &str = "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?";

/// `descended_from_rfc822` returns true if new_name is equal to or descended from prev_name and false otherwise.
pub(crate) fn descended_from_host<'a>(prev_name: &Ia5String<'a>, cand: &str, is_uri: bool) -> bool {
    let base = prev_name.to_string();

    let mut filter = regex::escape(base.as_str());
    filter.push('$');
    let filter_re = Regex::new(filter.as_str());
    if let Ok(fe) = filter_re {
        if let Some(parts) = fe.captures(cand) {
            if cand.len() == base.len() {
                return true;
            }

            let match_start = parts.get(0).unwrap().start();

            if !is_uri {
                let cand_next_to_last_char = if match_start != 0 {
                    cand.chars().nth(match_start - 1).unwrap()
                } else {
                    ' '
                };
                if cand_next_to_last_char == '.' {
                    return true;
                }
            } else {
                let cand_last_char = if match_start != 0 {
                    cand.chars().nth(match_start).unwrap()
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

/// `is_email` returns true if addr matches the regular expression defined by [`EMAIL_PATTERN`].
pub(crate) fn is_email(addr: &str) -> bool {
    lazy_static! {
        static ref EMAIL_RE: Regex = Regex::new(EMAIL_PATTERN).unwrap();
    }

    if let Some(_parts) = EMAIL_RE.captures(addr) {
        return true;
    }

    false
}

/// `descended_from_rfc822` returns true if new_name is equal to or descended from prev_name and false otherwise.
pub(crate) fn descended_from_rfc822<'a>(
    prev_name: &Ia5String<'a>,
    new_name: &Ia5String<'a>,
) -> bool {
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

            let match_start = parts.get(0).unwrap().start();
            let base_first_char = base.chars().next().unwrap();
            let cand_last_char = if match_start != 0 {
                cand.chars().nth(match_start - 1).unwrap()
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
pub(crate) fn descended_from_dn<'a>(
    pe: &PkiEnvironment<'_>,
    subtree: &Name<'a>,
    name: &Name<'a>,
    min: u32,
    max: Option<u32>,
) -> bool {
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

    //let lstr = name_to_string(pe, subtree);
    //let rstr = name_to_string(pe, name);

    for i in 0..subtree.len() {
        if subtree[i] != name[i] {
            let mut let_it_slide = false;

            // some folks can't manage to use the same character set in a name constraint and subject name
            // allow this practice to not break stuff
            let l = &subtree[i];
            let r = &name[i];
            if l.len() != r.len() {
                // diff number of attributes
                return false;
            }
            for j in 0..l.len() {
                let la = l.get(j);
                let ra = r.get(j);
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
                let lav = lau.value;
                let rav = rau.value;
                //not checking tag on the any since that is where the issue is most likely
                if lav.value() == rav.value() {
                    if lav.tag() != rav.tag() {
                        pe.log_message(&PeLogLevels::PeDebug, "Permitting a DN name constraint match despite different character sets");
                        let_it_slide = true;
                    }
                } else {
                    let llav = get_str_from_atav(lau);
                    let rlav = get_str_from_atav(rau);
                    if let Ok(llav) = llav {
                        if let Ok(rlav) = rlav {
                            if llav.to_lowercase() == rlav.to_lowercase() {
                                pe.log_message(&PeLogLevels::PeDebug, "Permitting a DN name constraint match despite different capitalization");
                                let_it_slide = true;
                            }
                        }
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

/// `has_upn` returns true if the given GeneralSubtrees contains at least one UPN and false otherwise
pub(crate) fn has_upn(subtrees: &GeneralSubtrees<'_>) -> bool {
    for subtree in subtrees {
        if let GeneralName::OtherName(on) = &subtree.base {
            if on.type_id != MSFT_USER_PRINCIPAL_NAME {
                return true;
            }
        }
    }
    false
}

/// `has_rfc822` returns true if the given GeneralSubtrees contains at least one RFC822 name and false otherwise
pub(crate) fn has_rfc822(subtrees: &GeneralSubtrees<'_>) -> bool {
    for subtree in subtrees {
        if let GeneralName::Rfc822Name(_rfc) = subtree.base {
            return true;
        }
    }
    false
}

/// `has_dns_name` returns true if the given GeneralSubtrees contains at least one DNS name and false otherwise
pub(crate) fn has_dns_name(subtrees: &GeneralSubtrees<'_>) -> bool {
    for subtree in subtrees {
        if let GeneralName::DnsName(_dns) = subtree.base {
            return true;
        }
    }
    false
}

/// `has_dn` returns true if the given GeneralSubtrees contains at least one DN and false otherwise
pub(crate) fn has_dn(subtrees: &GeneralSubtrees<'_>) -> bool {
    for subtree in subtrees {
        if let GeneralName::DirectoryName(_dn) = &subtree.base {
            return true;
        }
    }
    false
}

/// `has_uri` returns true if the given GeneralSubtrees contains at least one URI and false otherwise
pub(crate) fn has_uri(subtrees: &GeneralSubtrees<'_>) -> bool {
    for subtree in subtrees {
        if let GeneralName::UniformResourceIdentifier(_uri) = &subtree.base {
            return true;
        }
    }
    false
}

pub(crate) fn get_hash_alg_from_sig_alg(
    sig_alg: &ObjectIdentifier,
) -> Result<AlgorithmIdentifier<'_>> {
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

pub(crate) fn log_error_for_name(pe: &PkiEnvironment<'_>, name: &Name<'_>, msg: &str) {
    let name_str = name_to_string(pe, name);
    pe.log_message(
        &PeLogLevels::PeError,
        format!(
            "Encountered error while processing certificate with subject {}: {}",
            name_str, msg
        )
        .as_str(),
    );
}

pub(crate) fn log_error_for_ca(pe: &PkiEnvironment<'_>, ca: &PDVCertificate<'_>, msg: &str) {
    log_error_for_name(pe, &ca.decoded_cert.tbs_certificate.subject, msg);
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
    } else if *oid == PKIX_AT_NAME {
        return Ok("name".to_string());
    } else if *oid == PKIX_AT_SURNAME {
        return Ok("sn".to_string());
    } else if *oid == PKIX_AT_GIVENNAME {
        return Ok("givenName".to_string());
    } else if *oid == PKIX_AT_INITIALS {
        return Ok("initials".to_string());
    } else if *oid == PKIX_AT_GENERATION_QUALIFIER {
        return Ok("generationQualifier".to_string());
    } else if *oid == PKIX_AT_COMMON_NAME {
        return Ok("cn".to_string());
    } else if *oid == PKIX_AT_LOCALITY_NAME {
        return Ok("l".to_string());
    } else if *oid == PKIX_AT_STATEORPROVINCENAME {
        return Ok("st".to_string());
    } else if *oid == PKIX_AT_STREET {
        return Ok("street".to_string());
    } else if *oid == PKIX_AT_ORGANIZATIONALUNITNAME {
        return Ok("ou".to_string());
    } else if *oid == PKIX_AT_ORGANIZATIONNAME {
        return Ok("o".to_string());
    } else if *oid == PKIX_AT_TITLE {
        return Ok("title".to_string());
    } else if *oid == PKIX_AT_DNQUALIFIER {
        return Ok("dnQualifier".to_string());
    } else if *oid == PKIX_AT_COUNTRYNAME {
        return Ok("c".to_string());
    } else if *oid == PKIX_AT_SERIALNUMBER {
        return Ok("serialNumber".to_string());
    } else if *oid == PKIX_AT_PSEUDONYM {
        return Ok("pseudonym".to_string());
    } else if *oid == PKIX_DOMAINCOMPONENT {
        return Ok("dc".to_string());
    } else if *oid == PKIX_EMAILADDRESS {
        return Ok("emailAddress".to_string());
    }
    //TODO add more OIDs
    Err(Error::NotFound)
}
