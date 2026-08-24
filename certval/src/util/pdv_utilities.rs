//! Utility functions that support certification path processing

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str::FromStr;

use log::error;

use const_oid::db::rfc2256::STATE_OR_PROVINCE_NAME;
use const_oid::db::rfc3280::{EMAIL_ADDRESS, PSEUDONYM};
use const_oid::db::rfc4519::*;
use const_oid::db::rfc5912::*;
// Named so `oid_lookup` can report them rather than printing a dotted OID. Unconditional because
// naming an algorithm is not verifying it: a build without the `eddsa` or `pqc` verifier still
// reads certificates that use them, and a log that cannot name what it just read is the worse
// outcome.
use const_oid::db::fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
// All twelve parameter sets: the `s`/`f` suffix (small signature vs fast signing) and the hash
// family are the whole of what distinguishes them, so naming only some would be worse than naming
// none -- a reader would not know whether an unnamed OID was a variant or a different algorithm.
use cms::content_info::ContentInfo;
use const_oid::db::fips205::{
    ID_SLH_DSA_SHAKE_128_F, ID_SLH_DSA_SHAKE_128_S, ID_SLH_DSA_SHAKE_192_F, ID_SLH_DSA_SHAKE_192_S,
    ID_SLH_DSA_SHAKE_256_F, ID_SLH_DSA_SHAKE_256_S, ID_SLH_DSA_SHA_2_128_F, ID_SLH_DSA_SHA_2_128_S,
    ID_SLH_DSA_SHA_2_192_F, ID_SLH_DSA_SHA_2_192_S, ID_SLH_DSA_SHA_2_256_F, ID_SLH_DSA_SHA_2_256_S,
};
use const_oid::db::rfc8410::{ID_ED_25519, ID_ED_448};
use der::asn1::{Ia5String, PrintableString, Utf8StringRef};
use der::{asn1::ObjectIdentifier, Decode, Encode, Tagged};
use spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::pkix::{
    constraints::{
        name::{GeneralSubtree, GeneralSubtrees},
        BasicConstraints, PolicyConstraints,
    },
    name::{DistributionPointName, GeneralName},
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

/// `collect_crl_dp_uris` collects unique URIs from the full names of the CRL distribution points
/// extension of the presented certificate and returns them via the `uris` parameter.
///
/// Unlike [`collect_uris_from_aia_and_sia`], no scheme filtering is applied. CRL DPs routinely name
/// `ldap://` locations, and what a caller can reach is the caller's business: a client with an LDAP
/// implementation, or a relay fetching on a browser's behalf, can use one where a direct HTTP
/// fetcher cannot. certval's own CRL retrieval filters for itself, rejecting anything but HTTP with
/// [`Error::InvalidUriScheme`], which also keeps the URIs it declined visible in the log rather
/// than silently absent.
///
/// This is deliberately available in every build, revocation feature or not, for the same reason
/// [`collect_uris_from_aia_and_sia`] is: reading a URI out of an extension is parsing, not
/// fetching, and the callers that need it most are the ones that cannot fetch for themselves.
pub fn collect_crl_dp_uris(cert: &PDVCertificate, uris: &mut Vec<String>) {
    if let Ok(Some(PDVExtension::CrlDistributionPoints(crl_dps))) =
        cert.get_extension(&ID_CE_CRL_DISTRIBUTION_POINTS)
    {
        for crl_dp in &crl_dps.0 {
            if let Some(DistributionPointName::FullName(gns)) = &crl_dp.distribution_point {
                for gn in gns {
                    if let GeneralName::UniformResourceIdentifier(uri) = gn {
                        let s = uri.to_string();
                        if !uris.contains(&s) {
                            uris.push(s);
                        }
                    }
                }
            }
        }
    }
}

/// `collect_ocsp_uris` collects unique URIs from the `id-ad-ocsp` access descriptions of the
/// presented certificate's authority information access extension and returns them via the `uris`
/// parameter.
///
/// Scheme filtering and build availability are as described for [`collect_crl_dp_uris`].
///
/// Note that an OCSP URI alone is not enough to retrieve a response: unlike a CRL, which is a plain
/// GET, an OCSP request must be constructed for the specific certificate and posted. A caller
/// driving its own retrieval needs both this and a means of building that request.
pub fn collect_ocsp_uris(cert: &PDVCertificate, uris: &mut Vec<String>) {
    if let Ok(Some(PDVExtension::AuthorityInfoAccessSyntax(aias))) =
        cert.get_extension(&ID_PE_AUTHORITY_INFO_ACCESS)
    {
        for aia in &aias.0 {
            if ID_AD_OCSP == aia.access_method {
                if let GeneralName::UniformResourceIdentifier(uri) = &aia.access_location {
                    let s = uri.to_string();
                    if !uris.contains(&s) {
                        uris.push(s);
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

/// `descended_from_host` returns true if `cand` is equal to or descended from `prev_name` and false
/// otherwise. Not to be confused with `descended_from_rfc822`, which compares email addresses.
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

/// `descended_from_rfc822` returns true if new_name falls within the constraint expressed by
/// prev_name. Per RFC 5280 4.2.1.10, the constraint is a mailbox (a particular mailbox), a host
/// (all mailboxes on that host) or a domain indicated by a leading period (all mailboxes on hosts
/// within that domain). Per RFC 5280 7.5, local parts are compared exactly and host parts are
/// compared case-insensitively.
pub(crate) fn descended_from_rfc822(prev_name: &Ia5String, new_name: &Ia5String) -> bool {
    descended_from_rfc822_str(prev_name.as_ref(), new_name.as_ref())
}

/// `descended_from_rfc822_str` is the string-valued core of [`descended_from_rfc822`]. Pure string
/// comparison, so it needs no std.
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
            // every attribute in the RDN must match; a single mismatched attribute fails the whole
            // RDN. atav_values_equal applies the same tolerances (differing character set, case, and
            // insignificant whitespace) that compare_names uses for chaining, so a subject that
            // chains to an issuer cannot simultaneously escape that issuer's name constraints.
            for (subtree_attr, name_attr) in subtree_rdn.iter().zip(name_rdn.iter()) {
                if subtree_attr.oid != name_attr.oid {
                    // if the type of attribute, i.e., c, cn, o, is different, return false
                    return false;
                }
                if !atav_values_equal(subtree_attr, name_attr) {
                    return false;
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
    log_error_for_name(ca.decoded().tbs_certificate().subject(), msg);
}

/// log a message with subject name of the certificate appended
pub fn log_error_for_subject(ca: &CertificateInner<Raw>, msg: &str) {
    log_error_for_name(ca.tbs_certificate().subject(), msg);
}

/// `oid_lookup` takes an ObjectIdentifier and returns a friendly name for it, or [`Error::NotFound`]
/// when the OID is not one of those named here.
///
/// It names the signature and public-key algorithms that a path log or report would otherwise print
/// as a bare dotted OID.
///
/// EC was the gap that showed: `1.2.840.10045.2.1` and `1.2.840.10045.4.3.3` appeared 269 times
/// across a survey of 72 Web PKI certificates on 2026-08-20, directly above lines that named the
/// curve properly. EdDSA and ML-DSA are here for the same reason before anyone meets them — a
/// validator built for post-quantum algorithms should not print their OIDs raw.
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
    } else if *oid == PKIXALG_EC_PUBLIC_KEY {
        return Ok("EC Public Key".to_string());
    } else if *oid == PKIXALG_ECDSA_WITH_SHA224 {
        return Ok("ECDSA with SHA224".to_string());
    } else if *oid == PKIXALG_ECDSA_WITH_SHA256 {
        return Ok("ECDSA with SHA256".to_string());
    } else if *oid == PKIXALG_ECDSA_WITH_SHA384 {
        return Ok("ECDSA with SHA384".to_string());
    } else if *oid == PKIXALG_ECDSA_WITH_SHA512 {
        return Ok("ECDSA with SHA512".to_string());
    } else if *oid == ID_ED_25519 {
        return Ok("Ed25519".to_string());
    } else if *oid == ID_ED_448 {
        return Ok("Ed448".to_string());
    } else if *oid == ID_ML_DSA_44 {
        return Ok("ML-DSA-44".to_string());
    } else if *oid == ID_ML_DSA_65 {
        return Ok("ML-DSA-65".to_string());
    } else if *oid == ID_ML_DSA_87 {
        return Ok("ML-DSA-87".to_string());
    } else if *oid == ID_SLH_DSA_SHA_2_128_S {
        return Ok("SLH-DSA-SHA2-128s".to_string());
    } else if *oid == ID_SLH_DSA_SHA_2_128_F {
        return Ok("SLH-DSA-SHA2-128f".to_string());
    } else if *oid == ID_SLH_DSA_SHA_2_192_S {
        return Ok("SLH-DSA-SHA2-192s".to_string());
    } else if *oid == ID_SLH_DSA_SHA_2_192_F {
        return Ok("SLH-DSA-SHA2-192f".to_string());
    } else if *oid == ID_SLH_DSA_SHA_2_256_S {
        return Ok("SLH-DSA-SHA2-256s".to_string());
    } else if *oid == ID_SLH_DSA_SHA_2_256_F {
        return Ok("SLH-DSA-SHA2-256f".to_string());
    } else if *oid == ID_SLH_DSA_SHAKE_128_S {
        return Ok("SLH-DSA-SHAKE-128s".to_string());
    } else if *oid == ID_SLH_DSA_SHAKE_128_F {
        return Ok("SLH-DSA-SHAKE-128f".to_string());
    } else if *oid == ID_SLH_DSA_SHAKE_192_S {
        return Ok("SLH-DSA-SHAKE-192s".to_string());
    } else if *oid == ID_SLH_DSA_SHAKE_192_F {
        return Ok("SLH-DSA-SHAKE-192f".to_string());
    } else if *oid == ID_SLH_DSA_SHAKE_256_S {
        return Ok("SLH-DSA-SHAKE-256s".to_string());
    } else if *oid == ID_SLH_DSA_SHAKE_256_F {
        return Ok("SLH-DSA-SHAKE-256f".to_string());
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

/// Collapses each run of whitespace in `s` to a single ASCII space, e.g., "a  b\tc" -> "a b c". Used
/// by [`compare_names`] to disregard insignificant internal whitespace when comparing DN attribute
/// values; a no-std replacement for the former regex-based collapse.
fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !in_ws {
                out.push(' ');
                in_ws = true;
            }
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    out
}

/// Compares the values of two DN attributes for equality under the RFC 5280 §7.1 caseIgnoreMatch-style
/// rules shared by name chaining ([`compare_names`]) and name-constraint matching ([`descended_from_dn`]).
/// Two values are equal when their encoded value octets are identical or when they decode to strings that
/// are equal after unescaping a leading-space escape, trimming, case-folding, and collapsing internal
/// whitespace runs to a single space. This is hand-rolled so std and no-std behave identically. The caller
/// is responsible for checking that the attribute type OIDs match.
fn atav_values_equal(l: &AttributeTypeAndValue, r: &AttributeTypeAndValue) -> bool {
    if l.value.value() == r.value.value() {
        return true;
    }
    let normalize = |a: &AttributeTypeAndValue| -> Option<String> {
        let v = get_value_from_rdn(a).ok()?.replace("\\ ", " ");
        Some(collapse_whitespace(v.trim().to_lowercase().as_str()))
    };
    match (normalize(l), normalize(r)) {
        (Some(l), Some(r)) => l == r,
        _ => false,
    }
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
            // fall back to the whitespace/case-insensitive comparison only when the simpler compare fails
            for (l, r) in lrdn.iter().zip(rrdn.iter()) {
                if l.oid != r.oid {
                    return false;
                }
                if !atav_values_equal(l, r) {
                    return false;
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

/// ta_valid_at_time checks the validity of the given trust anchor relative to the given time of
/// interest.
///
/// Trust anchors need not assert a validity period: an RFC 5914 [`TrustAnchorInfo`] carrying no
/// certificate (a name and public key, as a webpki-roots anchor is expressed) has none to check.
/// That is not the same as failing the check, so the three outcomes are distinct:
///
/// - `Ok(Some(ttl))` — a validity period is present and covers `toi`, with the seconds remaining
/// - `Ok(None)` — the anchor asserts no validity period, so there is nothing to enforce
/// - `Err(Error::PathValidation(_))` — a validity period is present and `toi` falls outside it
///
/// [`TrustAnchorInfo`]: x509_cert::anchor::TrustAnchorInfo
pub fn ta_valid_at_time(
    ta: &TrustAnchorChoice<Raw>,
    toi: TimeOfInterest,
    stifle_log: bool,
) -> Result<Option<u64>> {
    match ta {
        TrustAnchorChoice::Certificate(c) => {
            valid_at_time(c.tbs_certificate(), toi, stifle_log).map(Some)
        }
        // The tbsCert alternative carries a validity like any certificate does
        TrustAnchorChoice::TbsCertificate(tbs) => valid_at_time(tbs, toi, stifle_log).map(Some),
        TrustAnchorChoice::TaInfo(tai) => match tai
            .cert_path
            .as_ref()
            .and_then(|cp| cp.certificate.as_ref())
        {
            Some(c) => valid_at_time(c.tbs_certificate(), toi, stifle_log).map(Some),
            None => Ok(None),
        },
    }
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

/// `decode_pem_to_der` accepts the bytes of a PEM- or DER-encoded object and returns DER. When the
/// input begins with `-----`, it is PEM-decoded: the strict RFC 7468 decoder is tried first, then a
/// lenient fallback for real-world PEM that OpenSSL accepts but strict RFC 7468 rejects (a trailing
/// blank line, or base64 wrapped at a width other than 64, as some DoD/FPKI tools emit) — drop the
/// encapsulation-boundary lines, strip all whitespace, and base64-decode the body. Any bytes past the
/// outer DER SEQUENCE are then trimmed (see `trim_to_outer_der_sequence`). Available in no_std.
///
/// This decodes a *single* object. A multi-object PEM (a concatenated bundle) is not supported here:
/// depending on byte alignment it yields only the first object or fails outright, so treat a bundle as
/// unsupported input. Use [`decode_pem_to_ders`] to load every object in a bundle.
pub fn decode_pem_to_der(bytes: &[u8]) -> Result<Vec<u8>> {
    use base64ct::{Base64, Encoding};

    let der = if bytes.first() == Some(&0x2D) {
        match pem_rfc7468::decode_vec(bytes) {
            Ok((_label, der)) => der,
            Err(_e) => {
                let text = String::from_utf8_lossy(bytes);
                let body: String = text
                    .lines()
                    .filter(|line| !line.contains("-----"))
                    .flat_map(str::chars)
                    .filter(|c| !c.is_whitespace())
                    .collect();
                match Base64::decode_vec(&body) {
                    Ok(der) => der,
                    Err(_e) => return Err(crate::Error::Unrecognized),
                }
            }
        }
    } else {
        bytes.to_vec()
    };

    Ok(trim_to_outer_der_sequence(der))
}

/// Extensions for an input whose caller fans a file out into every certificate it holds.
///
/// Membership is a property of the *caller*, not of the format: a site belongs here once it loops
/// over what [`decode_pem_to_ders`] returns, and moving a site between this and
/// [`SINGLE_CERT_EXTENSIONS`] is then a one-line change. Offering `p7c` where the caller takes one
/// certificate would advertise a file it will go on to reject.
pub const CERT_BUNDLE_EXTENSIONS: &[&str] = &["der", "crt", "cer", "p7c", "p7b", "pem"];

/// [`CERT_BUNDLE_EXTENSIONS`] plus `ta`, an RFC 5914 `TrustAnchorInfo` — how anchor constraints
/// travel, and meaningful only where trust anchors are being read.
pub const TA_BUNDLE_EXTENSIONS: &[&str] = &["der", "crt", "cer", "p7c", "p7b", "pem", "ta"];

/// Extensions for an input that must resolve to exactly one certificate — a validation target, its
/// issuer, an end entity. See [`CERT_BUNDLE_EXTENSIONS`] for why these are separate lists.
pub const SINGLE_CERT_EXTENSIONS: &[&str] = &["der", "crt", "cer", "pem"];

/// Returns the certificates carried by a degenerate certs-only PKCS#7 `SignedData`, or `None` when
/// `bytes` are not one.
///
/// This is the shape DoD PKE publishes cross-certificate bundles in (`.p7c`) and the shape an SIA
/// `caRepository` commonly serves. It is a container, not a certificate: a caller that only tries
/// `Certificate::from_der` sees well-formed DER that is not a certificate and silently gets nothing,
/// which is why the expansion belongs beside the PEM decoding rather than at each call site.
///
/// `None` rather than an empty vector distinguishes "not this format" from "this format, no
/// certificates in it", so a caller can fall through to its own single-object handling.
pub fn certs_from_signed_data(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let ci = ContentInfo::from_der(bytes).ok()?;
    let content = ci.content.to_der().ok()?;
    let sd = SignedDataDeferAll::from_der(content.as_slice()).ok()?;
    Some(sd.certificates?.0)
}

/// A `CertificateSet` whose members are kept as the DER they arrived in.
///
/// Re-encoding is not merely wasted work here: a certificate that was not strict DER on the wire
/// comes back out changed, and its signature then verifies against nothing. Capturing the bytes is
/// the same reason [`DeferDecodeSigned`] exists for a single certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateSetDefer(pub Vec<Vec<u8>>);

impl ::der::FixedTag for CertificateSetDefer {
    const TAG: ::der::Tag = ::der::Tag::Sequence;
}

impl<'a> ::der::DecodeValue<'a> for CertificateSetDefer {
    type Error = ::der::Error;

    fn decode_value<R: ::der::Reader<'a>>(
        reader: &mut R,
        header: ::der::Header,
    ) -> ::der::Result<Self> {
        reader.read_nested(header.length(), |reader| {
            let mut certs = Vec::new();
            while !reader.is_finished() {
                certs.push(reader.tlv_bytes()?.to_vec());
            }
            Ok(Self(certs))
        })
    }
}

impl ::der::EncodeValue for CertificateSetDefer {
    fn value_len(&self) -> ::der::Result<::der::Length> {
        let mut len = ::der::Length::ZERO;
        for cert in &self.0 {
            len = (len + ::der::Length::new(cert.len() as u32))?;
        }
        Ok(len)
    }

    fn encode_value(&self, writer: &mut impl ::der::Writer) -> ::der::Result<()> {
        for cert in &self.0 {
            writer.write(cert)?;
        }
        Ok(())
    }
}

/// `SignedData` with every field but `certificates` left undecoded.
///
/// A certs-only message is a container whose other fields are vestigial -- `encapContentInfo` has
/// absent content, `signerInfos` is empty -- and decoding them can only turn a bundle full of
/// perfectly good certificates into a parse failure. Only what is being asked for is interpreted.
#[derive(Clone, Debug, Eq, PartialEq, ::der::Sequence)]
struct SignedDataDeferAll {
    pub version: ::der::Any,
    pub digest_algorithms: ::der::Any,
    pub encap_content_info: ::der::Any,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub certificates: Option<CertificateSetDefer>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub crls: Option<CertificateSetDefer>,
    pub signer_infos: ::der::Any,
}

/// Decodes every object in a possibly multi-object PEM input, in file order, returning one DER buffer
/// per object. A bare-DER input (no `-----BEGIN` marker) yields a single-element vector. Each PEM block
/// is decoded through [`decode_pem_to_der`], so the same strict-then-lenient handling and outer-SEQUENCE
/// trimming apply per block. This is the loader for certificate and trust-anchor folders, where a
/// concatenated bundle (an OpenSSL fullchain, or a root-CA bundle) must contribute every object rather
/// than silently only its first; CRL loading stays single-object via [`decode_pem_to_der`]. A block
/// that fails to decode fails the whole call (the caller skips the file), matching the single-object
/// contract. Available in no_std.
pub fn decode_pem_to_ders(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let text = String::from_utf8_lossy(bytes);
    // No PEM armor anywhere: a certs-only PKCS#7 container fans out into its certificates, and
    // anything else defers to the single-object decoder (handles bare DER and passthrough).
    if !text.contains("-----BEGIN") {
        if let Some(certs) = certs_from_signed_data(bytes) {
            return Ok(certs);
        }
        return Ok(alloc::vec![decode_pem_to_der(bytes)?]);
    }

    let mut ders: Vec<Vec<u8>> = Vec::new();
    let mut block = String::new();
    let mut in_block = false;
    for line in text.lines() {
        if line.contains("-----BEGIN") {
            in_block = true;
            block.clear();
        }
        if in_block {
            block.push_str(line);
            block.push('\n');
            if line.contains("-----END") {
                in_block = false;
                let der = decode_pem_to_der(block.as_bytes())?;
                // A block may itself be a certs-only container (`-----BEGIN PKCS7-----`).
                match certs_from_signed_data(&der) {
                    Some(certs) => ders.extend(certs),
                    None => ders.push(der),
                }
                block.clear();
            }
        }
    }
    if ders.is_empty() {
        // a `-----BEGIN` marker was present but no complete block decoded
        return Err(Error::Unrecognized);
    }
    Ok(ders)
}

/// Truncates `der` to the encoded length of its outer DER SEQUENCE when the buffer carries spurious
/// trailing bytes. Returns `der` unchanged when it does not begin with a definite-length SEQUENCE or
/// the encoded length is not shorter than the buffer, so conforming DER is never altered.
pub(crate) fn trim_to_outer_der_sequence(mut der: Vec<u8>) -> Vec<u8> {
    // 0x30 = universal, constructed, SEQUENCE — the outer tag of a cert, CRL, or TrustAnchorChoice.
    if der.first() != Some(&0x30) || der.len() < 2 {
        return der;
    }
    let len_byte = der[1];
    let total = if len_byte < 0x80 {
        // short-form length
        2 + len_byte as usize
    } else if len_byte == 0x80 {
        // indefinite length is not valid DER; leave it for the decoder to reject
        return der;
    } else {
        // long-form: the low 7 bits give the number of subsequent big-endian length octets
        let num = (len_byte & 0x7f) as usize;
        if num == 0 || num > 4 || der.len() < 2 + num {
            return der;
        }
        let mut len = 0usize;
        for &octet in &der[2..2 + num] {
            len = (len << 8) | octet as usize;
        }
        2 + num + len
    };
    if total < der.len() {
        der.truncate(total);
    }
    der
}

#[test]
fn trim_to_outer_der_sequence_drops_trailing() {
    // SEQUENCE, length 3, content [01 02 03]; total encoded length = 5
    let exact = alloc::vec![0x30, 0x03, 0x01, 0x02, 0x03];
    assert_eq!(trim_to_outer_der_sequence(exact.clone()), exact);
    // spurious trailing bytes are dropped
    let mut with_trailing = exact.clone();
    with_trailing.extend_from_slice(&[0xff, 0x00, 0xaa]);
    assert_eq!(trim_to_outer_der_sequence(with_trailing), exact);
    // a non-SEQUENCE outer tag is left untouched
    let not_seq = alloc::vec![0x02, 0x01, 0x00, 0x99];
    assert_eq!(trim_to_outer_der_sequence(not_seq.clone()), not_seq);
    // a truncated length header is left for the decoder to reject
    let truncated = alloc::vec![0x30, 0x82, 0x01];
    assert_eq!(trim_to_outer_der_sequence(truncated.clone()), truncated);
}

#[test]
fn decode_pem_to_der_lenient_and_passthrough() {
    use base64ct::{Base64, Encoding};
    // arbitrary DER: SEQUENCE { INTEGER 42, INTEGER 43 }
    let der = alloc::vec![0x30, 0x06, 0x02, 0x01, 0x2a, 0x02, 0x01, 0x2b];
    // raw DER passes through unchanged
    assert_eq!(decode_pem_to_der(&der).unwrap(), der);
    let b64 = Base64::encode_string(&der);

    // strict RFC 7468 (single short line, LF, no trailing) round-trips
    let strict = format!("-----BEGIN X-----\n{b64}\n-----END X-----\n");
    assert_eq!(decode_pem_to_der(strict.as_bytes()).unwrap(), der);

    // real-world quirks the strict decoder rejects but the lenient fallback accepts:
    // CRLF line endings plus a trailing blank line
    let crlf_trailing = format!("-----BEGIN X-----\r\n{b64}\r\n-----END X-----\r\n\r\n");
    assert_eq!(decode_pem_to_der(crlf_trailing.as_bytes()).unwrap(), der);

    // base64 split across many short CRLF lines (a width other than 64)
    let wrapped = b64
        .as_bytes()
        .chunks(4)
        .map(|c| core::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\r\n");
    let odd_width = format!("-----BEGIN X-----\r\n{wrapped}\r\n-----END X-----\r\n");
    assert_eq!(decode_pem_to_der(odd_width.as_bytes()).unwrap(), der);
}

#[test]
fn certs_only_pkcs7_fans_out_into_its_certificates() {
    use x509_cert::Certificate;

    // A real DoD PKE cross-certificate bundle: a container, not a certificate. Before this it
    // reached the caller whole, parsed as neither, and contributed nothing.
    let p7c = include_bytes!("../../tests/examples/caCertsIssuedTofbcag4.p7c");
    let ders = decode_pem_to_ders(p7c).unwrap();
    assert_eq!(
        6,
        ders.len(),
        "every certificate in the bundle, not just the first"
    );
    for der in &ders {
        Certificate::from_der(der).expect("each buffer is a certificate in its own right");
    }

    // Not a container: unchanged, one buffer out.
    let cert = include_bytes!("../../tests/examples/TrustAnchorRootCertificate.crt");
    assert_eq!(1, decode_pem_to_ders(cert).unwrap().len());

    // The distinction certs_from_signed_data draws, which is what lets the caller fall through.
    assert!(certs_from_signed_data(p7c).is_some());
    assert!(certs_from_signed_data(cert).is_none());

    // The property the deferred decode exists for: each certificate is the DER that was in the
    // file, byte for byte, not a re-encoding of a parsed one. A re-encode of input that was not
    // strict DER would still parse here while no longer verifying against its signature.
    for der in &ders {
        assert!(
            p7c.windows(der.len()).any(|w| w == der.as_slice()),
            "certificate DER appears verbatim in the container"
        );
    }
}

#[test]
fn decode_pem_to_ders_splits_bundle() {
    use base64ct::{Base64, Encoding};
    // two distinct DER SEQUENCEs, each exactly its own encoded length (no trailing trim needed)
    let der1 = alloc::vec![0x30, 0x03, 0x01, 0x02, 0x03];
    let der2 = alloc::vec![0x30, 0x02, 0x0a, 0x0b];

    // a two-object PEM bundle contributes both objects, in order
    let bundle = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n\
         -----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        Base64::encode_string(&der1),
        Base64::encode_string(&der2),
    );
    assert_eq!(
        decode_pem_to_ders(bundle.as_bytes()).unwrap(),
        alloc::vec![der1.clone(), der2.clone()]
    );

    // a single PEM object yields a one-element vector
    let single = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        Base64::encode_string(&der1)
    );
    assert_eq!(
        decode_pem_to_ders(single.as_bytes()).unwrap(),
        alloc::vec![der1.clone()]
    );

    // bare DER (no armor) also yields a one-element vector
    assert_eq!(
        decode_pem_to_ders(&der1).unwrap(),
        alloc::vec![der1.clone()]
    );

    // a malformed block fails the whole call (caller skips the file)
    let malformed = "-----BEGIN CERTIFICATE-----\n!!!notbase64!!!\n-----END CERTIFICATE-----\n";
    assert!(decode_pem_to_ders(malformed.as_bytes()).is_err());
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

#[test]
fn collapse_whitespace_reduces_runs() {
    assert_eq!(collapse_whitespace("a  b\t c"), "a b c");
    assert_eq!(collapse_whitespace("x\n\ny"), "x y");
    assert_eq!(collapse_whitespace("nochange"), "nochange");
    assert_eq!(collapse_whitespace(""), "");
    // leading/trailing runs collapse too (callers pre-trim, but the helper is standalone)
    assert_eq!(collapse_whitespace("  a  "), " a ");
}

// Names that differ only by insignificant internal whitespace (and case) compare equal. This
// exercised the std-only regex path before; the hand-rolled collapse now covers std and no-std.
#[cfg(feature = "std")]
#[test]
fn compare_names_ignores_insignificant_internal_whitespace() {
    let a = Name::from_str("O=Test  Org,C=US").unwrap();
    let b = Name::from_str("O=test Org,C=US").unwrap();
    assert!(compare_names(&a, &b));

    // a genuine difference is still rejected
    let c = Name::from_str("O=Test Orgs,C=US").unwrap();
    assert!(!compare_names(&a, &c));
}

// Constraint matching must agree with chaining on insignificant internal whitespace, or an excluded
// subtree is evaded (chaining links the path, the constraint check does not fire) and a permitted
// subtree is falsely rejected. Both directions go through the shared atav_values_equal helper.
#[cfg(feature = "std")]
#[test]
fn descended_from_dn_ignores_insignificant_whitespace() {
    let subtree = Name::from_str("O=Acme Corp").unwrap();
    // subject differs only by a doubled internal space and case; must be treated as within subtree
    let subject = Name::from_str("O=acme  corp").unwrap();
    assert!(descended_from_dn(&subtree, &subject, 0, None));
    assert!(compare_names(&subtree, &subject));

    // a genuine difference is still outside the subtree
    let other = Name::from_str("O=Acme Corps").unwrap();
    assert!(!descended_from_dn(&subtree, &other, 0, None));
}

// A trust anchor that asserts no validity period is not an invalid trust anchor. The distinction is
// load-bearing in three places: path validation must not fail such a path, the folder loader must
// not skip such a file, and pittv3's --ta-cleanup deletes or moves what it rejects, so conflating
// the two would destroy exactly the anchors that carry only a name and a public key.
#[cfg(feature = "std")]
#[test]
fn ta_validity_distinguishes_absent_from_failed() {
    use der::{Decode, Encode};
    use x509_cert::anchor::TrustAnchorInfo;
    use x509_cert::certificate::CertificateInner;

    let der =
        include_bytes!("../../tests/examples/PKITS_data_2048/certs/TrustAnchorRootCertificate.crt");
    let ta = TrustAnchorChoice::<Raw>::from_der(der).unwrap();
    assert!(matches!(ta, TrustAnchorChoice::Certificate(_)));

    // a certificate anchor inside its validity reports the time it has left
    let toi = TimeOfInterest::from_unix_secs(1647264981).unwrap();
    assert!(matches!(ta_valid_at_time(&ta, toi, true), Ok(Some(_))));

    // and outside it, a validity failure -- not merely "no answer"
    let expired = TimeOfInterest::from_unix_secs(1930000000).unwrap();
    assert!(matches!(
        ta_valid_at_time(&ta, expired, true),
        Err(Error::PathValidation(
            PathValidationStatus::InvalidNotAfterDate
        ))
    ));

    // an RFC 5914 anchor carrying a key but no certificate has nothing to check, at any time
    let cert = CertificateInner::<Raw>::from_der(der).unwrap();
    let tai: TrustAnchorInfo<Raw> = TrustAnchorInfo {
        version: Default::default(),
        pub_key: cert.tbs_certificate().subject_public_key_info().clone(),
        key_id: der::asn1::OctetString::new(&[0x01, 0x02, 0x03][..]).unwrap(),
        ta_title: None,
        cert_path: None,
        extensions: None,
        ta_title_lang_tag: None,
    };
    let bytes = TrustAnchorChoice::TaInfo(tai).to_der().unwrap();
    let no_validity = TrustAnchorChoice::<Raw>::from_der(&bytes).unwrap();
    assert_eq!(Ok(None), ta_valid_at_time(&no_validity, toi, true));
    assert_eq!(Ok(None), ta_valid_at_time(&no_validity, expired, true));
}

/// The revocation URI collectors read the two extensions a caller needs to retrieve revocation data
/// for itself. Both accumulate into a caller-supplied vector and skip duplicates, so a caller can
/// sweep a whole certification path into one list without post-processing.
#[test]
fn revocation_uris_collected() {
    let der = include_bytes!("../../tests/examples/ocsp_dod/47.der");
    let cert = parse_cert(der, "47.der").unwrap();

    let mut crl_dps = alloc::vec![];
    collect_crl_dp_uris(&cert, &mut crl_dps);
    assert_eq!(
        crl_dps,
        alloc::vec![String::from("http://crl.disa.mil/crl/DODEMAILCA_63.crl")]
    );

    let mut ocsp = alloc::vec![];
    collect_ocsp_uris(&cert, &mut ocsp);
    assert_eq!(ocsp, alloc::vec![String::from("http://ocsp.disa.mil")]);

    // Accumulating the same certificate again adds nothing: sweeping a path whose certificates
    // share a responder must not queue the same fetch repeatedly.
    collect_crl_dp_uris(&cert, &mut crl_dps);
    collect_ocsp_uris(&cert, &mut ocsp);
    assert_eq!(1, crl_dps.len());
    assert_eq!(1, ocsp.len());
}

/// A certificate carrying neither extension contributes nothing rather than failing, so a caller
/// can run the collectors across every position in a path without checking first.
#[test]
fn revocation_uris_absent_is_not_an_error() {
    let der = include_bytes!("../../tests/examples/PKITS_data_2048/certs/GoodCACert.crt");
    let cert = parse_cert(der, "GoodCACert.crt").unwrap();

    let mut ocsp = alloc::vec![];
    collect_ocsp_uris(&cert, &mut ocsp);
    assert!(ocsp.is_empty());
}

/// Every algorithm this library can encounter should have a name, because the fallback is a dotted
/// OID in a log or a report. EC was the gap that showed in practice — `1.2.840.10045.2.1` appeared
/// 141 times in one survey — and the post-quantum sets are here so they never become the next one.
#[test]
fn algorithm_oids_resolve_to_names_rather_than_dotted_numbers() {
    use const_oid::db::fips204::ID_ML_DSA_65;
    use const_oid::db::fips205::{ID_SLH_DSA_SHAKE_256_F, ID_SLH_DSA_SHA_2_128_S};
    use const_oid::db::rfc8410::ID_ED_25519;

    for (oid, expected) in [
        (PKIXALG_EC_PUBLIC_KEY, "EC Public Key"),
        (PKIXALG_ECDSA_WITH_SHA384, "ECDSA with SHA384"),
        (PKIXALG_RSA_ENCRYPTION, "RSA Encryption"),
        (ID_ED_25519, "Ed25519"),
        (ID_ML_DSA_65, "ML-DSA-65"),
        (ID_SLH_DSA_SHA_2_128_S, "SLH-DSA-SHA2-128s"),
        (ID_SLH_DSA_SHAKE_256_F, "SLH-DSA-SHAKE-256f"),
    ] {
        assert_eq!(oid_lookup(&oid).unwrap(), expected, "naming {oid}");
    }

    // An OID with no name is reported as absent rather than guessed at, which is what lets the
    // caller fall back to the dotted form deliberately.
    assert!(oid_lookup(&ObjectIdentifier::new_unwrap("1.2.3.4.5")).is_err());
}
