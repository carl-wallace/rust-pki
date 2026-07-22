//! Functions related to certification path validation operations

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::vec;

use log::info;

use crate::{
    environment::pki_environment::*, get_subject_public_key_info_from_trust_anchor,
    hex_skid_from_ta, path_results::*, path_settings::*, pdv_certificate::*, pdv_extension::*,
    pdv_trust_anchor::get_trust_anchor_name, util::error::*, util::pdv_utilities::*,
    validator::pdv_trust_anchor::PDVTrustAnchorChoice, CertificationPath,
};
use const_oid::db::rfc5280::ANY_POLICY;
use const_oid::db::rfc5912::*;
use der::{asn1::ObjectIdentifier, Decode, Encode};
use x509_cert::anchor::TrustAnchorChoice;
use x509_cert::ext::pkix::constraints::name::GeneralSubtrees;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::KeyUsages;
use x509_cert::ext::Extensions;

use crate::validator::policy_graph::check_certificate_policies_graph;

/// `EXTS_OF_INTEREST` provides a list of extensions that will be automatically parsed when preparing
/// a [`PDVCertificate`] instance. These extensions are used during path development and validation and
/// are subsequently available via get_extension without re-parsing.
pub const EXTS_OF_INTEREST: &[ObjectIdentifier] = &[
    ID_CE_SUBJECT_KEY_IDENTIFIER,
    ID_CE_AUTHORITY_KEY_IDENTIFIER,
    ID_CE_BASIC_CONSTRAINTS,
    ID_CE_NAME_CONSTRAINTS,
    ID_CE_SUBJECT_ALT_NAME,
    ID_CE_EXT_KEY_USAGE,
    ID_CE_KEY_USAGE,
    ID_CE_POLICY_CONSTRAINTS,
    ID_CE_CERTIFICATE_POLICIES,
    ID_CE_POLICY_MAPPINGS,
    ID_CE_INHIBIT_ANY_POLICY,
    ID_PE_AUTHORITY_INFO_ACCESS,
    ID_PE_SUBJECT_INFO_ACCESS,
    ID_CE_CRL_REASONS,
    ID_CE_ISSUING_DISTRIBUTION_POINT,
    ID_CE_CRL_DISTRIBUTION_POINTS,
    ID_CE_FRESHEST_CRL,
];

//-----------------------------------------------------------------------------
// Top level functions for use via PkiEnvironment's validate_path member. These
// aggregate lower level checks.
//-----------------------------------------------------------------------------
/// `validate_path_rfc5280` aggregates various checks to perform certification path validation per
/// [RFC 5280 Section 6.1]. It is intended for use in the validate_path field of a [`PkiEnvironment`] structure.
///
/// - The [`PkiEnvironment`] parameter provides a variety of callback functions that support certification
///   path validation, for example, signature verification, digest generation, and logging.
/// - The [`CertificationPathSettings`] parameter defines values that govern path validation. This consists
///   of a mix of standard path validation inputs from [RFC 5280 Section 6.1.1] and non-standard inputs,
///   i.e., whether or not to validate extendedKeyUsage values across the path.
/// - The [`CertificationPath`] parameter provides the target certificate to validate along with a trust
///   anchor and, if necessary, intermediate CA certificates.
/// - The [`CertificationPathResults`] parameter is used to collect potentially useful information from the
///   certification path validation operation.
///
/// [RFC 5280 Section 6.1]: <https://datatracker.ietf.org/doc/html/rfc5280.html#section-6.1>
/// [RFC 5280 Section 6.1.1]: <https://datatracker.ietf.org/doc/html/rfc5280.html#section-6.1.1>
pub fn validate_path_rfc5280(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cp: &mut CertificationPath,
    cpr: &mut CertificationPathResults,
) -> Result<()> {
    //enforce_alg_and_key_size_constraints(pe, cps, cp, cpr)?;
    check_validity(pe, cps, cp, cpr)?;
    if cps.get_require_ta_store() {
        if pe.is_cert_a_trust_anchor(&cp.target).is_ok() {
            return Ok(());
        }
        if pe.is_trust_anchor(&cp.trust_anchor).is_err() {
            return Err(Error::PathValidation(
                PathValidationStatus::MissingTrustAnchor,
            ));
        }
    }

    // RFC 5937 trust-anchor constraint provenance. When constraint enforcement is in effect, the
    // constraints applied to this path derive from cp.trust_anchor. If the trust store holds the
    // anchor with this key identifier (the same identity used by the require_ta_store membership
    // check), that stored copy is authoritative: reject a presented anchor that shares the key but
    // carries different constraints than the store's copy (e.g. a relaxed TrustAnchorInfo substituted
    // for a constrained one). The SPKI comparison guards against a subjectKeyIdentifier collision
    // landing on a different key; a key identifier absent from the store carries no store opinion, so
    // the presented anchor stands. (get_trust_anchor_by_hex_skid returns the first source's match for
    // a SKID; distinct anchors that share a SKID across sources is a theoretical case better caught by
    // a store-level duplicate-SKID check than by complicating this lookup.)
    if cps.get_enforce_trust_anchor_constraints() {
        if let Ok(stored) = pe.get_trust_anchor_by_hex_skid(&hex_skid_from_ta(&cp.trust_anchor)) {
            let presented_spki =
                get_subject_public_key_info_from_trust_anchor(&cp.trust_anchor.decoded_ta);
            let stored_spki = get_subject_public_key_info_from_trust_anchor(&stored.decoded_ta);
            if presented_spki == stored_spki && stored.encoded_ta != cp.trust_anchor.encoded_ta {
                return Err(Error::PathValidation(
                    PathValidationStatus::TrustAnchorConstraintsMismatch,
                ));
            }
        }
    }

    check_basic_constraints(pe, cps, cp, cpr)?;
    check_names(pe, cps, cp, cpr)?;
    //check_country_codes(pe, cps, cp, cpr)?;
    // Certificate policy processing is always graph-based (RFC 9618); PS_USE_POLICY_GRAPH is
    // retained for backward compatibility but no longer selects an implementation.
    check_certificate_policies_graph(pe, cps, cp, cpr)?;
    check_key_usage(pe, cps, cp, cpr)?;
    check_extended_key_usage(pe, cps, cp, cpr)?;
    check_critical_extensions(pe, cps, cp, cpr)?;
    verify_signatures(pe, cps, cp, cpr)?;
    cpr.set_validation_status(PathValidationStatus::Valid);
    info!(
        "Successfully completed basic path validation checks for certificate issued to {}",
        name_to_string(cp.target.as_ref().tbs_certificate().subject())
    );
    Ok(())
}

//-----------------------------------------------------------------------------
// Functions that perform some small aspect of path validation
//-----------------------------------------------------------------------------
/// `check_basic_constraints` ensures all intermediate CA certificates feature a basicConstraints extension
/// with the cA field set to true and that the certificate path length does not violate length constraints.
///
/// It uses values from the [`PS_INITIAL_PATH_LENGTH_CONSTRAINT`] item in the [`CertificationPathSettings`]
/// and the path_len_constraint field of basicConstraints extensions.
pub fn check_basic_constraints(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cp: &mut CertificationPath,
    cpr: &mut CertificationPathResults,
) -> Result<()> {
    cpr.add_processed_extension(ID_CE_BASIC_CONSTRAINTS);

    // Seeds RFC 5280's max_path_length state variable. PS_INITIAL_PATH_LENGTH_CONSTRAINT defaults to
    // the PS_MAX_PATH_LENGTH_CONSTRAINT ceiling rather than to the path length as in RFC 5280 6.1.2,
    // so a path with more non-self-issued certificates than the ceiling is rejected below even absent
    // any certificate-asserted pathLenConstraint. That fixed ceiling is a deliberate resource bound.
    let mut path_len_constraint = cps.get_initial_path_length_constraint();

    for (pos, ca_cert) in cp.intermediates.iter().enumerate() {
        // (l)  If the certificate was not self-issued, verify that
        //       max_path_length is greater than zero and decrement
        //       max_path_length by 1.
        if !is_self_issued(ca_cert.as_ref()) {
            if path_len_constraint == 0 {
                log_error_for_ca(ca_cert, "path length constraint violation");
                cpr.set_validation_status(PathValidationStatus::InvalidPathLength);
                cpr.set_failure_index(pos as u32 + 1);
                return Err(Error::PathValidation(
                    PathValidationStatus::InvalidPathLength,
                ));
            }
            path_len_constraint -= 1;
        }

        // only support v3 (this is a no-op here because the decoder fails to parse non-V3 certs)
        // if any of the bad_ca_cert_version, bad_ee_cert_version, unsupported_ca_cert_version or
        // unsupported_ee_cert_version tests in tests/path_validator.rs fail this should be uncommented.
        // if ca_cert.as_ref().tbs_certificate.version != Version::V3 {
        //     log_error_for_ca(ca_cert, "unsupported x509 version");
        //     cpr.set_validation_status( PathValidationStatus::InvalidBasicConstraints);
        //     return Err(Error::PathValidation(
        //         PathValidationStatus::InvalidBasicConstraints,
        //     ));
        // }

        let pdv_ext: Option<&PDVExtension> = ca_cert.get_extension(&ID_CE_BASIC_CONSTRAINTS)?;
        let bc = match pdv_ext {
            Some(PDVExtension::BasicConstraints(bc)) => bc,
            _ => {
                log_error_for_ca(ca_cert, "missing basic constraints");
                cpr.set_validation_status(PathValidationStatus::MissingBasicConstraints);
                cpr.set_failure_index(pos as u32 + 1);
                return Err(Error::PathValidation(
                    PathValidationStatus::MissingBasicConstraints,
                ));
            }
        };

        // (k)  If certificate i is a version 3 certificate, verify that the
        //       basicConstraints extension is present and that cA is set to
        //       TRUE.  (If certificate i is a version 1 or version 2
        //       certificate, then the application MUST either verify that
        //       certificate i is a CA certificate through out-of-band means
        //       or reject the certificate.  Conforming implementations may
        //       choose to reject all version 1 and version 2 intermediate
        //       certificates.)
        if !bc.ca {
            log_error_for_ca(ca_cert, "invalid basic constraints");
            cpr.set_validation_status(PathValidationStatus::InvalidBasicConstraints);
            cpr.set_failure_index(pos as u32 + 1);
            return Err(Error::PathValidation(
                PathValidationStatus::InvalidBasicConstraints,
            ));
        }

        if let Some(pl) = bc.path_len_constraint {
            // (m)  If pathLenConstraint is present in the certificate and is
            //       less than max_path_length, set max_path_length to the value
            //       of pathLenConstraint.
            path_len_constraint = path_len_constraint.min(pl);
        }
    }

    if cps.get_forbid_self_signed_ee() {
        let pdv_ext: Option<&PDVExtension> = cp.target.get_extension(&ID_CE_BASIC_CONSTRAINTS)?;
        let is_ee = if let Some(PDVExtension::BasicConstraints(bc)) = pdv_ext {
            !bc.ca
        } else {
            true
        };

        if is_ee && (is_self_issued(cp.target.as_ref()) || is_self_signed(pe, &cp.target)) {
            log_error_for_ca(
                &cp.target,
                "End-identity certificate is self-signed or self-issued, but it is forbidden",
            );
            cpr.set_validation_status(PathValidationStatus::SelfSignedEndIdentity);
            cpr.set_failure_index(cp.intermediates.len() as u32 + 1);
            return Err(Error::PathValidation(
                PathValidationStatus::SelfSignedEndIdentity,
            ));
        }
    }

    Ok(())
}

/// `check_validity` evaluates the target certificate and intermediate certificates against the
/// `PS_TIME_OF_INTEREST` value read from the [`CertificationPathSettings`] parameter.
pub fn check_validity(
    _pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cp: &mut CertificationPath,
    cpr: &mut CertificationPathResults,
) -> Result<()> {
    // RFC 5280 states: (2)  The certificate validity period includes the current time.
    // get_time_of_interest_or_now will return now or a caller specified time of interest.
    let toi = cps.get_time_of_interest();
    if toi.is_disabled() {
        info!("check_validity invoked with no time of interest; validity check disabled",);
        return Ok(());
    }

    // failure_index uses the trust-anchor-first convention of PR_FAILURE_INDEX
    let mut is_valid = |time_check_res: Result<u64>, failure_index: u32| -> Result<()> {
        match time_check_res {
            Err(Error::PathValidation(pvs)) => {
                cpr.set_validation_status(pvs);
                cpr.set_failure_index(failure_index);
                Err(Error::PathValidation(pvs))
            }
            Err(e) => Err(e),
            Ok(_) => Ok(()),
        }
    };

    let target = &cp.target;
    let target_ttl = valid_at_time(target.as_ref().tbs_certificate(), toi, false);
    is_valid(target_ttl, cp.intermediates.len() as u32 + 1)?;

    for (pos, ca_cert) in cp.intermediates.iter().enumerate() {
        let ca_ttl = valid_at_time(ca_cert.as_ref().tbs_certificate(), toi, false);
        is_valid(ca_ttl, pos as u32 + 1)?;
    }

    if cps.get_enforce_trust_anchor_validity() {
        // Check TA validity if feature is on (it's on by default) but if the TA does not feature a
        // validity, i.e., if it's a TrustAnchorInfo without an embedded certificate (e.g. a
        // webpki-roots trust anchor, which carries only name + SPKI), there is no validity period
        // to enforce — carry on rather than failing the path. `ta_valid_at_time` signals this with
        // `Error::Unrecognized`; only a real `PathValidation` status is a validity failure.
        match ta_valid_at_time(&cp.trust_anchor.decoded_ta, toi, false) {
            Err(Error::Unrecognized) => {}
            ta_ttl => is_valid(ta_ttl, 0)?,
        }
    }

    Ok(())
}

/// `has_min_or_max` returns true if any subtree asserts a nonzero minimum or a maximum.
fn has_min_or_max(subtrees: &Option<GeneralSubtrees>) -> bool {
    subtrees
        .as_ref()
        .is_some_and(|s| s.iter().any(|gs| gs.minimum != 0 || gs.maximum.is_some()))
}

/// `general_name_has_trailing_dot` returns true for a dNSName, or the host portion of an
/// rfc822Name, that ends with a period. RFC 5280 4.2.1.6 requires the preferred name syntax of
/// RFC 1034 3.5 (as modified by RFC 1123 2.1), which does not admit the absolute (rooted) form.
fn general_name_has_trailing_dot(gn: &GeneralName) -> bool {
    match gn {
        GeneralName::DnsName(dns) => dns.as_str().ends_with('.'),
        GeneralName::Rfc822Name(rfc822) => rfc822.as_str().ends_with('.'),
        _ => false,
    }
}

/// `has_trailing_dot` returns true if any subtree base is a name for which
/// [`general_name_has_trailing_dot`] returns true.
fn has_trailing_dot(subtrees: &Option<GeneralSubtrees>) -> bool {
    subtrees
        .as_ref()
        .is_some_and(|s| s.iter().any(|gs| general_name_has_trailing_dot(&gs.base)))
}

/// Ceiling on the work performed matching one certificate's subjectAltName against the operative
/// name-constraints state. Matching visits every SAN entry against every accumulated constraint, so
/// the cost scales with the product of the two counts. A path of certificate authorities that each
/// contribute many constraints, terminating in a certificate bearing many SAN entries, could
/// otherwise drive that product arbitrarily high. Certificates exceeding the budget are rejected.
const MAX_NAME_CONSTRAINT_MATCH_WORK: usize = 1_048_576;

/// Returns true when matching a subjectAltName of `san_len` entries against `constraint_count`
/// accumulated name constraints would exceed [`MAX_NAME_CONSTRAINT_MATCH_WORK`]. The count of
/// operative constraints grows as excluded subtrees are unioned in at each certificate authority, so
/// callers must supply the current combined count rather than a value captured before processing the
/// path.
fn name_constraint_matching_budget_exceeded(constraint_count: usize, san_len: usize) -> bool {
    san_len > 0 && constraint_count > MAX_NAME_CONSTRAINT_MATCH_WORK / san_len
}

/// `check_names` ensures that subject and issuer names chain appropriately throughout the certification
/// path and that no names violate any operative name constraints.
///
/// At present, the following name forms are supported for name constraints enforcement:
/// - distinguished name
/// - RFC822 names
/// - DNS names
/// - Uniform resource identifiers
///
/// Additional name forms may be added in the future.
pub fn check_names(
    _pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cp: &mut CertificationPath,
    cpr: &mut CertificationPathResults,
) -> Result<()> {
    cpr.add_processed_extension(ID_CE_NAME_CONSTRAINTS);

    // Read input variables from path settings
    let mut pbufs = BTreeMap::new();
    let mut ebufs = BTreeMap::new();
    let initial_perm = cps.get_initial_permitted_subtrees_as_set(&mut pbufs)?;
    let initial_excl = cps.get_initial_excluded_subtrees_as_set(&mut ebufs)?;

    // for convenience, combine target into array with the intermediate CA certs
    let mut v = cp.intermediates.clone();
    v.push(cp.target.clone());
    let certs_in_cert_path = v.len();

    let mut permitted_subtrees = initial_perm.unwrap_or_default();
    let mut excluded_subtrees = initial_excl.unwrap_or_default();

    let mut working_issuer_name = get_trust_anchor_name(&cp.trust_anchor.decoded_ta)?.clone();

    // Iterate over the list of intermediate CA certificates plus target to check name chaining
    for (pos, ca_cert) in v.iter().enumerate() {
        if !compare_names(
            ca_cert.as_ref().tbs_certificate().issuer(),
            &working_issuer_name,
        ) {
            log_error_for_ca(ca_cert, "name chaining violation");
            cpr.set_validation_status(PathValidationStatus::NameChainingFailure);
            cpr.set_failure_index(pos as u32 + 1);
            return Err(Error::PathValidation(
                PathValidationStatus::NameChainingFailure,
            ));
        }

        if pos + 1 != certs_in_cert_path {
            working_issuer_name = ca_cert.as_ref().tbs_certificate().subject().clone();
        }
    }

    // Iterate over the list of intermediate CA certificates plus target to check name constraints
    for (pos, ca_cert) in v.iter().enumerate() {
        let self_issued = is_self_issued(ca_cert.as_ref());

        if (pos + 1) == certs_in_cert_path || !self_issued {
            if !permitted_subtrees
                .subject_within_permitted_subtrees(ca_cert.as_ref().tbs_certificate().subject())
            {
                log_error_for_ca(
                    ca_cert,
                    "permitted name constraints violation for subject name",
                );
                cpr.set_validation_status(PathValidationStatus::NameConstraintsViolation);
                cpr.set_failure_index(pos as u32 + 1);
                return Err(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                ));
            }

            if excluded_subtrees
                .subject_within_excluded_subtrees(ca_cert.as_ref().tbs_certificate().subject())
            {
                log_error_for_ca(
                    ca_cert,
                    "excluded name constraints violation for subject name",
                );
                cpr.set_validation_status(PathValidationStatus::NameConstraintsViolation);
                cpr.set_failure_index(pos as u32 + 1);
                return Err(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                ));
            }

            let pdv_ext: Option<&PDVExtension> = ca_cert.get_extension(&ID_CE_SUBJECT_ALT_NAME)?;
            let san = if let Some(PDVExtension::SubjectAltName(san)) = pdv_ext {
                cpr.add_processed_extension(ID_CE_SUBJECT_ALT_NAME);
                Some(san)
            } else {
                None
            };

            // Bound name-constraints matching for this certificate against the constraints
            // accumulated from the certificate authorities processed so far, read live rather
            // than from the initial (typically empty) subtree state.
            let constraint_count = permitted_subtrees.len() + excluded_subtrees.len();
            let san_len = san.map(|s| s.0.len()).unwrap_or(0);
            if name_constraint_matching_budget_exceeded(constraint_count, san_len) {
                cpr.set_failure_index(pos as u32 + 1);
                return Err(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                ));
            }

            // RFC 5280 4.2.1.6: dNSName and the host portion of rfc822Name use the preferred
            // name syntax, which does not admit a trailing period. Reject rather than risk a
            // name that other consumers regard as equal to a constrained name evading a
            // constraint via the absolute form.
            if let Some(san) = san {
                if san.0.iter().any(general_name_has_trailing_dot) {
                    log_error_for_ca(ca_cert, "trailing period in SAN dNSName or rfc822Name");
                    cpr.set_validation_status(PathValidationStatus::NameConstraintsViolation);
                    cpr.set_failure_index(pos as u32 + 1);
                    return Err(Error::PathValidation(
                        PathValidationStatus::NameConstraintsViolation,
                    ));
                }
            }

            if !permitted_subtrees.san_within_permitted_subtrees(&san) {
                log_error_for_ca(ca_cert, "permitted name constraints violation for SAN");
                cpr.set_validation_status(PathValidationStatus::NameConstraintsViolation);
                cpr.set_failure_index(pos as u32 + 1);
                return Err(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                ));
            }

            if excluded_subtrees.san_within_excluded_subtrees(&san) {
                log_error_for_ca(ca_cert, "excluded name constraints violation for SAN");
                cpr.set_validation_status(PathValidationStatus::NameConstraintsViolation);
                cpr.set_failure_index(pos as u32 + 1);
                return Err(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                ));
            }
        }

        if pos + 1 != certs_in_cert_path {
            let pdv_ext: Option<&PDVExtension> = ca_cert.get_extension(&ID_CE_NAME_CONSTRAINTS)?;
            if let Some(PDVExtension::NameConstraints(nc)) = pdv_ext {
                cpr.add_processed_extension(ID_CE_NAME_CONSTRAINTS);

                // RFC 5280 4.2.1.10: minimum MUST be zero and maximum MUST be absent; an
                // application encountering other values MUST process them or reject the
                // certificate.
                if has_min_or_max(&nc.permitted_subtrees) || has_min_or_max(&nc.excluded_subtrees) {
                    log_error_for_ca(ca_cert, "unsupported minimum/maximum in name constraints");
                    cpr.set_validation_status(PathValidationStatus::NameConstraintsViolation);
                    cpr.set_failure_index(pos as u32 + 1);
                    return Err(Error::PathValidation(
                        PathValidationStatus::NameConstraintsViolation,
                    ));
                }

                // Constraints are held to the same preferred name syntax as SAN values; a
                // trailing period would otherwise render a constraint unenforceable.
                if has_trailing_dot(&nc.permitted_subtrees)
                    || has_trailing_dot(&nc.excluded_subtrees)
                {
                    log_error_for_ca(ca_cert, "trailing period in name constraints");
                    cpr.set_validation_status(PathValidationStatus::NameConstraintsViolation);
                    cpr.set_failure_index(pos as u32 + 1);
                    return Err(Error::PathValidation(
                        PathValidationStatus::NameConstraintsViolation,
                    ));
                }

                if let Some(excl) = &nc.excluded_subtrees {
                    excluded_subtrees.calculate_union(excl);
                }
                if let Some(perm) = &nc.permitted_subtrees {
                    permitted_subtrees.calculate_intersection(perm);
                }

                // A permitted subtree set that intersects to empty for some name form does not fail
                // the path here: each certificate's subject and subjectAltName are checked against
                // the operative subtrees per name form (an empty form rejects only a certificate
                // that actually presents a name of that form), so a form no certificate uses is
                // vacuously satisfied.
            }
        }
    } // end for (pos, ca_cert_ref) in v.iter_mut().enumerate() {

    // Record the terminal name-constraints working sets so callers (e.g., a GUI) can display the
    // effective permitted/excluded subtrees that a conforming path was validated against. Written
    // only on successful completion: a name-constraints violation returns early above and is
    // conveyed by PR_VALIDATION_STATUS/PR_FAILURE_INDEX instead. The NameConstraintsSet preserves
    // the per-form null-vs-empty distinction (see PR_FINAL_PERMITTED_SUBTREES).
    cpr.set_final_permitted_subtrees(permitted_subtrees);
    cpr.set_final_excluded_subtrees(excluded_subtrees);

    Ok(())
}

/// `check_key_usage` ensures all intermediate CA certificates assert the keyCertSign bit and that the
/// target certificate asserts the bits from the `PS_KEY_USAGE` item in the [`CertificationPathSettings`],
/// if any.
pub fn check_key_usage(
    _pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cp: &mut CertificationPath,
    cpr: &mut CertificationPathResults,
) -> Result<()> {
    cpr.add_processed_extension(ID_CE_KEY_USAGE);
    for (pos, ca_cert) in cp.intermediates.iter().enumerate() {
        let pdv_ext: Option<&PDVExtension> = ca_cert.get_extension(&ID_CE_KEY_USAGE)?;
        let ku = match pdv_ext {
            Some(PDVExtension::KeyUsage(ku)) => ku,
            // RFC 5280 6.1.4(n) gates the keyCertSign check on the key usage extension being
            // present, so an intermediate lacking one is not a conformance failure; rejecting it is
            // a deliberate fail-closed choice, since a modern CA certificate always carries key
            // usage asserting keyCertSign.
            _ => {
                log_error_for_ca(ca_cert, "key usage extension is missing");
                cpr.set_validation_status(PathValidationStatus::InvalidKeyUsage);
                cpr.set_failure_index(pos as u32 + 1);
                return Err(Error::PathValidation(PathValidationStatus::InvalidKeyUsage));
            }
        };
        // (n)  If a key usage extension is present, verify that the
        //      keyCertSign bit is set.
        if !ku.0.contains(KeyUsages::KeyCertSign) {
            log_error_for_ca(ca_cert, "keyCertSign is not set in key usage extension");
            cpr.set_validation_status(PathValidationStatus::InvalidKeyUsage);
            cpr.set_failure_index(pos as u32 + 1);
            return Err(Error::PathValidation(PathValidationStatus::InvalidKeyUsage));
        }
    }

    let target_ku = cp.target.get_extension(&ID_CE_KEY_USAGE)?;
    if let Some(PDVExtension::KeyUsage(target_ku_bits)) = target_ku {
        if let Some(nku) = cps.get_target_key_usage() {
            // TODO TEST THIS
            for i in nku {
                if !target_ku_bits.0.contains(i) {
                    log_error_for_ca(&cp.target, "key usage violation for target certificate");
                    cpr.set_validation_status(PathValidationStatus::InvalidKeyUsage);
                    cpr.set_failure_index(cp.intermediates.len() as u32 + 1);
                    return Err(Error::PathValidation(PathValidationStatus::InvalidKeyUsage));
                }
            }
        }
    }

    Ok(())
}

/// `check_extended_key_usage` implements the (unpublished but popular) intersection of extended key
/// usage values across the certification path, beginning with the trust anchor and proceeding through
/// to the target certificate. It also affirms the target certificate matches at least one EKU expressed
/// in the `PS_EXTENDED_KEY_USAGE` element in the [`CertificationPathSettings`], if any.
pub fn check_extended_key_usage(
    _pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cp: &mut CertificationPath,
    cpr: &mut CertificationPathResults,
) -> Result<()> {
    cpr.add_processed_extension(ID_CE_EXT_KEY_USAGE);

    let target_ekus: Option<ObjectIdentifierSet> = cps.get_extended_key_usage_as_oid_set();
    let process_ekus_across_path = cps.get_extended_key_usage_path();

    // if we are neither checking across path nor vetting target values, just return
    if !process_ekus_across_path && target_ekus.is_none() {
        return Ok(());
    }

    if process_ekus_across_path {
        // check that intersection of all EKU extensions in the path is not empty
        let mut default_eku = vec![ANY_EXTENDED_KEY_USAGE];

        let ta_eku = cp.trust_anchor.get_extension(&ID_CE_EXT_KEY_USAGE)?;
        let ekus_from_ta = if let Some(PDVExtension::ExtendedKeyUsage(ekus)) = ta_eku {
            ekus.0.clone()
        } else {
            if let Some(target_ekus) = &target_ekus {
                default_eku.clear();
                default_eku.extend(target_ekus.iter());
            }

            default_eku
        };

        let mut ekus_from_path: BTreeSet<_> = ekus_from_ta.iter().copied().collect();

        let intermediates_and_target = cp.intermediates.iter().chain(core::iter::once(&cp.target));

        for (pos, ca_cert) in intermediates_and_target.enumerate() {
            let pdv_ext: Option<&PDVExtension> = ca_cert.get_extension(&ID_CE_EXT_KEY_USAGE)?;
            if let Some(PDVExtension::ExtendedKeyUsage(eku_from_ca)) = pdv_ext {
                let any_in_path = ekus_from_path.contains(&ANY_EXTENDED_KEY_USAGE);
                let any_in_ca = eku_from_ca.0.contains(&ANY_EXTENDED_KEY_USAGE);
                match (any_in_path, any_in_ca) {
                    (true, false) => {
                        // replace any with all from cert
                        ekus_from_path.remove(&ANY_EXTENDED_KEY_USAGE);
                        ekus_from_path.extend(eku_from_ca.0.iter());
                    }
                    (true, true) => {
                        // add all from cert
                        ekus_from_path.extend(eku_from_ca.0.iter());
                    }
                    _ => {
                        // drop any that are not in the cert
                        ekus_from_path.retain(|e| eku_from_ca.0.contains(e));
                    }
                }

                if ekus_from_path.is_empty() {
                    log_error_for_ca(ca_cert, "Extended key usage violation");
                    cpr.set_validation_status(PathValidationStatus::InvalidKeyUsage);
                    cpr.set_failure_index(pos as u32 + 1);
                    return Err(Error::PathValidation(PathValidationStatus::InvalidKeyUsage));
                }
            }
            // given lack of specification for this approach, is lack of an EKU extension an error
            // or a lack of constraints? treating it as the latter.
            // else {
            //     log_error_for_ca(
            //         pe,
            //         ca_cert,
            //         "Extended key usage violation when processing intermediate CA certificate",
            //     );
            //     cpr.set_validation_status(PathValidationStatus::InvalidKeyUsage);
            //     return Err(Error::InvalidKeyUsage);
            // }
        }
    }

    let ekus_from_config = match target_ekus {
        Some(e) => e,          // We need to check configured EKU list
        None => return Ok(()), // Otherwise we're done
    };

    // if the configured EKU list features any EKU, then we're done
    if ekus_from_config.contains(&ANY_EXTENDED_KEY_USAGE) {
        return Ok(());
    }

    // if the target cert does not have an EKU, then we're done
    let eku_from_target = &cp.target.get_extension(&ID_CE_EXT_KEY_USAGE)?;
    let eku_from_target = match eku_from_target {
        Some(PDVExtension::ExtendedKeyUsage(e)) => e,
        _ => return Ok(()),
    };

    // else, iterate over EKUs from the cert and make sure at least one matches config
    for eku in &eku_from_target.0 {
        if ekus_from_config.contains(eku) || *eku == ANY_EXTENDED_KEY_USAGE {
            return Ok(());
        }
    }

    // if no match, fail
    log_error_for_ca(
        &cp.target,
        "extended key usage violation when processing target certificate",
    );
    cpr.set_validation_status(PathValidationStatus::InvalidKeyUsage);
    cpr.set_failure_index(cp.intermediates.len() as u32 + 1);
    Err(Error::PathValidation(PathValidationStatus::InvalidKeyUsage))
}

/// `check_critical_extensions` affirms all critical extensions in the certificates that comprise a certification
/// path have been processed by inspecting the `PR_PROCESSED_EXTENSIONS` value from the
/// [`CertificationPathResults`] object.
///
/// Each function supporting path validation contributes to the `PR_PROCESSED_EXTENSIONS` in a
/// [`CertificationPathResults`] object to facilitate this check. This implementation assumes that
/// if an extension is processed for one certificate then it is processed for all.
pub fn check_critical_extensions(
    _pe: &PkiEnvironment,
    _cps: &CertificationPathSettings,
    cp: &mut CertificationPath,
    cpr: &mut CertificationPathResults,
) -> Result<()> {
    let processed_exts: ObjectIdentifierSet = cpr.get_processed_extensions();

    // failure_index uses the trust-anchor-first convention of PR_FAILURE_INDEX
    let mut ensure_criticals_processed = |cert: &PDVCertificate,
                                          err_str: &'static str,
                                          failure_index: u32|
     -> Result<()> {
        if let Some(exts) = &cert.as_ref().tbs_certificate().extensions() {
            let exts = exts.as_slice();
            for ext in exts {
                // A critical extension is satisfied only if its OID was processed AND it is the
                // sole instance of that OID. Extension processing is keyed by OID (processed_exts
                // is a set), so when a critical extension OID appears more than once only one
                // instance is processed; without the count check the duplicate instance would be
                // silently waved off as processed. RFC 5280 4.2 forbids the issuer from emitting
                // duplicate extensions, so such a certificate is malformed regardless.
                if ext.critical
                    && (!processed_exts.contains(&ext.extn_id)
                        || exts.iter().filter(|e| e.extn_id == ext.extn_id).count() > 1)
                {
                    log_error_for_ca(cert, format!("{}: {}", err_str, ext.extn_id).as_str());
                    cpr.set_validation_status(PathValidationStatus::UnprocessedCriticalExtension);
                    cpr.set_failure_index(failure_index);
                    return Err(Error::PathValidation(
                        PathValidationStatus::UnprocessedCriticalExtension,
                    ));
                }
            }
        }
        Ok(())
    };

    for (pos, ca_cert) in cp.intermediates.iter().enumerate() {
        ensure_criticals_processed(ca_cert, "unprocessed critical extension", pos as u32 + 1)?;
    }
    ensure_criticals_processed(
        &cp.target,
        "unprocessed critical extension in target certificate",
        cp.intermediates.len() as u32 + 1,
    )?;

    Ok(())
}

/// `enforce_trust_anchor_constraints` prepares and returns a [`CertificationPathSettings`] object
/// that includes constraints derived from the trust anchor from a given [`CertificationPath`] and the
/// operative [`CertificationPathSettings`].
///
/// When the `PS_ENFORCE_TRUST_ANCHOR_CONSTRAINTS` value in the operative [`CertificationPathSettings`]
/// is set to false, this function does nothing.
pub fn enforce_trust_anchor_constraints(
    cps: &CertificationPathSettings,
    ta: &PDVTrustAnchorChoice,
) -> Result<CertificationPathSettings> {
    if !cps.get_enforce_trust_anchor_constraints() {
        return Ok(cps.clone());
    }

    let mut mod_cps = cps.clone();

    let mut ebufs = BTreeMap::new();
    let mut pbufs = BTreeMap::new();

    //o  If no subject distinguished name is associated with the trust
    //anchor, path validation fails.  The name may appear in the subject
    //field of a Certificate or TBSCertificate structure or in the
    //taName field of CertPathControls in a TrustAnchorInfo structure.
    let _name = get_trust_anchor_name(&ta.decoded_ta)?;

    //o  If a basic constraints extension is associated with the trust
    //anchor and contains a pathLenConstraint value, set the
    //max_path_length state variable equal to the pathLenConstraint
    //value from the basic constraints extension.
    let pl = get_path_length_constraint_from_trust_anchor(&ta.decoded_ta)?;

    let old_val = mod_cps.get_initial_path_length_constraint();
    if old_val > pl {
        mod_cps.set_initial_path_length_constraint(pl);
    }

    //o  If name constraints are associated with the trust anchor, set the
    //initial-permitted-subtrees variable equal to the intersection of
    //the permitted subtrees from the trust anchor and the user-provided
    //initial-permitted-subtrees.  If one of these two inputs is not
    //provided, the initial-permitted-subtrees variable is set to the
    //value that is available.  If neither is provided, the initial-
    //permitted-subtrees variable is set to an infinite set.
    {
        let mut name_constraints = None;
        let pdv_ext = ta.get_extension(&ID_CE_NAME_CONSTRAINTS);
        if let Ok(pdv_ext) = pdv_ext {
            if let Some(nc) = pdv_ext {
                if let PDVExtension::NameConstraints(nc) = nc {
                    if let Some(permitted) = &nc.permitted_subtrees {
                        // RFC 5937: initial-permitted-subtrees is the INTERSECTION of the TA's
                        // permitted subtrees and the user-provided set (an absent user set defaults
                        // to the infinite set, so the intersection yields the TA's subtrees).
                        let mut initial_perm =
                            cps.get_initial_permitted_subtrees_with_default_as_set(&mut pbufs)?;
                        initial_perm.calculate_intersection(permitted);
                        mod_cps.set_initial_permitted_subtrees_from_set(&initial_perm)?;
                    }
                }
                name_constraints = pdv_ext;
            }
        }

        if let Some(PDVExtension::NameConstraints(nc)) = name_constraints {
            if let Some(excluded) = &nc.excluded_subtrees {
                let mut initial_excl =
                    cps.get_initial_excluded_subtrees_with_default_as_set(&mut ebufs)?;
                initial_excl.calculate_union(excluded);
                mod_cps.set_initial_excluded_subtrees_from_set(&initial_excl)?;
            }
        }
    }

    /*
    //o  If certificate policies are associated with the trust anchor, set
    //the user-initial-policy-set variable equal to the intersection of
    //the certificate policies associated with the trust anchor and the
    //user-provided user-initial-policy-set.  If one of these two inputs
    //is not provided, the user-initial-policy-set variable is set to
    //the value that is available.  If neither is provided, the
    //user-initial-policy-set variable is set to any-policy.
     */
    let user_policy_set: ObjectIdentifierSet = cps.get_initial_policy_set_as_oid_set();
    let mut ta_policy_set = ObjectIdentifierSet::new();
    let mut ta_accepts_any_policy = false;
    let pdv_ext = ta.get_extension(&ID_CE_CERTIFICATE_POLICIES)?;
    if let Some(PDVExtension::CertificatePolicies(cp)) = pdv_ext {
        for p in &cp.0 {
            if !ta_policy_set.contains(&p.policy_identifier) {
                ta_policy_set.insert(p.policy_identifier);
            }
            if p.policy_identifier == ANY_POLICY {
                ta_accepts_any_policy = true;
            }
        }
    }

    if !ta_policy_set.is_empty() && !user_policy_set.is_empty() {
        let mut new_policy_set = ObjectIdentifierSet::new();
        if ta_accepts_any_policy {
            // TA asserts anyPolicy, so the intersection with the user set is the user set;
            // the TA's ANY_POLICY (and any TA-specific policies it subsumes) are not added.
            new_policy_set = user_policy_set;
        } else {
            let user_accepts_any_policy = user_policy_set.contains(&ANY_POLICY);

            // intersect
            for p in ta_policy_set {
                if user_accepts_any_policy || user_policy_set.contains(&p) {
                    new_policy_set.insert(p);
                }
            }
        }
        mod_cps.set_initial_policy_set_from_oid_set(new_policy_set);
    } else if !ta_policy_set.is_empty() && user_policy_set.is_empty() {
        // use policies from TA
        mod_cps.set_initial_policy_set_from_oid_set(ta_policy_set);
    } else {
        //use user policy set (empty or not)
        mod_cps.set_initial_policy_set_from_oid_set(user_policy_set);
    }

    //o  If an inhibit any policy value of true is associated with the
    //trust anchor (either in a CertPathControls or in an
    //inhibitAnyPolicy extension) and the initial-any-policy-inhibit
    //value is false, set the initial-any-policy-inhibit value to true.
    let initial_inhibit_any_policy = cps.get_initial_inhibit_any_policy_indicator();
    let ta_inhibit_any_policy = get_inhibit_any_policy_from_trust_anchor(&ta.decoded_ta)?;
    if ta_inhibit_any_policy && !initial_inhibit_any_policy {
        mod_cps.set_initial_inhibit_any_policy_indicator(ta_inhibit_any_policy);
    }

    //o  If a require explicit policy value of true is associated with the
    //trust anchor (either in a CertPathControls or in a
    //PolicyConstraints extension) and the initial-explicit-policy value
    //is false, set the initial-explicit-policy value to true.
    let initial_require_explicit_policy = cps.get_initial_explicit_policy_indicator();
    let ta_require_explicit_policy = get_require_explicit_policy_from_trust_anchor(&ta.decoded_ta)?;
    if ta_require_explicit_policy && !initial_require_explicit_policy {
        mod_cps.set_initial_explicit_policy_indicator(ta_require_explicit_policy);
    }

    //o  If an inhibit policy mapping value of true is associated with the
    //trust anchor (either in a CertPathControls or in a
    //PolicyConstraints extension) and the initial-policy-mapping-
    //inhibit value is false, set the initial-policy-mapping-inhibit
    //value to true.
    let initial_inhibit_policy_mapping = cps.get_initial_policy_mapping_inhibit_indicator();
    let ta_inhibit_policy_mapping = get_inhibit_policy_mapping_from_trust_anchor(&ta.decoded_ta)?;
    if ta_inhibit_policy_mapping && !initial_inhibit_policy_mapping {
        mod_cps.set_initial_policy_mapping_inhibit_indicator(ta_inhibit_policy_mapping);
    }

    let pdv_ext = ta.get_extension(&ID_CE_KEY_USAGE)?;
    if let Some(PDVExtension::KeyUsage(ku)) = pdv_ext {
        if !ku.key_cert_sign() {
            return Err(Error::PathValidation(PathValidationStatus::InvalidKeyUsage));
        }
    }

    match &ta.decoded_ta {
        TrustAnchorChoice::Certificate(c) => {
            check_critical_extensions_from_ta(&c.tbs_certificate().extensions())?;
        }
        TrustAnchorChoice::TaInfo(tai) => {
            check_critical_extensions_from_ta(&tai.extensions.as_ref())?;
        }
        TrustAnchorChoice::TbsCertificate(tbs) => {
            check_critical_extensions_from_ta(&tbs.extensions())?;
        }
    }

    Ok(mod_cps)
}

fn check_critical_extensions_from_ta(exts: &Option<&Extensions>) -> Result<()> {
    // id-pe-cmsContentConstraints from RFC 6010; tolerated because CCC constrains CMS content
    // processing, not certification path validation (TAMP-era trust anchors commonly carry it
    // as a critical extension)
    const ID_PE_CMS_CONTENT_CONSTRAINTS: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.18");
    let recognized_oids = [
        ID_CE_BASIC_CONSTRAINTS,
        ID_CE_NAME_CONSTRAINTS,
        ID_CE_CERTIFICATE_POLICIES,
        ID_CE_POLICY_CONSTRAINTS,
        ID_CE_KEY_USAGE,
        ID_CE_INHIBIT_ANY_POLICY,
        ID_PE_CMS_CONTENT_CONSTRAINTS,
    ];
    if let Some(exts) = exts {
        for ext in exts.as_slice() {
            if ext.critical && !recognized_oids.contains(&ext.extn_id) {
                return Err(Error::Unrecognized);
            }
        }
    }
    Ok(())
}

/// `verify_signatures` verifies the certificate signatures of certificates found in a certification path.
pub fn verify_signatures(
    pe: &PkiEnvironment,
    _cps: &CertificationPathSettings,
    cp: &mut CertificationPath,
    cpr: &mut CertificationPathResults,
) -> Result<()> {
    let intermediates_and_target = cp.intermediates.iter().chain(core::iter::once(&cp.target));

    let mut working_spki =
        get_subject_public_key_info_from_trust_anchor(&cp.trust_anchor.decoded_ta).clone();

    for (pos, cur_cert) in intermediates_and_target.enumerate() {
        let defer_cert = DeferDecodeSigned::from_der(cur_cert.as_bytes());
        let defer_cert = match defer_cert {
            Ok(c) => c,
            Err(e) => {
                log_error_for_ca(
                    cur_cert,
                    format!("signature verification error: {e:?}").as_str(),
                );
                cpr.set_validation_status(PathValidationStatus::EncodingError);
                cpr.set_failure_index(pos as u32 + 1);
                return Err(Error::PathValidation(PathValidationStatus::EncodingError));
            }
        };

        if cur_cert.as_ref().tbs_certificate().signature()
            != cur_cert.as_ref().signature_algorithm()
        {
            log_error_for_ca(
                cur_cert,
                format!(
                    "signature algorithm mismatch: {:?} - {:?}",
                    cur_cert.as_ref().tbs_certificate().signature(),
                    cur_cert.as_ref().signature_algorithm()
                )
                .as_str(),
            );
            cpr.set_validation_status(PathValidationStatus::EncodingError);
            cpr.set_failure_index(pos as u32 + 1);
            return Err(Error::PathValidation(PathValidationStatus::EncodingError));
        }

        // Skip the (expensive) signature verification when a configured signature cache reports this
        // exact certificate-and-issuer-key pair as already verified, e.g. by the path builder. The
        // cheap structural checks above still run, and with no cache configured this is always false,
        // so the signature is verified as usual.
        let verified_from_cache = pe.has_signature_cache()
            && working_spki
                .to_der()
                .ok()
                .map(|spki_der| {
                    pe.is_signature_verified(
                        &signature_cache_hash(cur_cert.as_bytes()),
                        &signature_cache_hash(&spki_der),
                    )
                })
                .unwrap_or(false);

        if !verified_from_cache {
            let r = pe.verify_signature_message(
                pe,
                &defer_cert.tbs_field,
                cur_cert.as_ref().signature().raw_bytes(),
                cur_cert.as_ref().tbs_certificate().signature(),
                &working_spki,
            );
            if let Err(e) = r {
                log_error_for_ca(
                    cur_cert,
                    format!("signature verification error: {e:?}").as_str(),
                );
                cpr.set_validation_status(PathValidationStatus::SignatureVerificationFailure);
                cpr.set_failure_index(pos as u32 + 1);
                return Err(Error::PathValidation(
                    PathValidationStatus::SignatureVerificationFailure,
                ));
            }
        }

        working_spki = cur_cert
            .as_ref()
            .tbs_certificate()
            .subject_public_key_info()
            .clone();
    }
    Ok(())
}

/*
/// `enforce_alg_and_key_size_constraints` enforces algorithm and key size constraints, if any.
pub fn enforce_alg_and_key_size_constraints(
    _pe: &PkiEnvironment,
    _cps: &CertificationPathSettings,
    _cp: &mut CertificationPath,
    _cpr: &mut CertificationPathResults,
) -> Result<()> {
    //TODO - implement alg and key size constraints enforcement
    Ok(())
}

/// `check_country_codes` ensures the target certificate from a CertificationPath does not violate any
/// constraints defined in the `PS_PERM_COUNTRIES` and `PS_EXCL_COUNTRIES` values from the [`CertificationPathSettings`].
pub fn check_country_codes(
    _pe: &PkiEnvironment,
    _cps: &CertificationPathSettings,
    _cp: &mut CertificationPath,
    _cpr: &mut CertificationPathResults,
) -> Result<()> {
    //TODO - implement country code enforcement
    Ok(())
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    // A configured signature cache that reports a signature as verified causes verify_signatures to
    // skip the (expensive) verification. Using a target that is not signed by the trust anchor, the
    // check fails without a cache and passes once an always-verified cache is added.
    #[cfg(all(feature = "std", feature = "rsa"))]
    #[test]
    fn signature_cache_bypasses_verification() {
        use crate::environment::pki_environment_traits::SignatureVerificationCache;

        struct AlwaysVerified;
        impl SignatureVerificationCache for AlwaysVerified {
            fn is_verified(&self, _: &[u8], _: &[u8]) -> bool {
                true
            }
            fn add_verified(&self, _: &[u8], _: &[u8]) {}
        }

        let ta_der = include_bytes!("../../tests/examples/TrustAnchorRootCertificate.crt");
        let target_der = include_bytes!("../../tests/examples/ocsp_dod/ca63.der");

        let build_path = || {
            let mut ta = PDVTrustAnchorChoice::try_from(ta_der.as_slice()).unwrap();
            ta.parse_extensions(EXTS_OF_INTEREST);
            let target = PDVCertificate::try_from(target_der.as_slice()).unwrap();
            CertificationPath::new(ta, vec![], target)
        };

        let mut pe = PkiEnvironment::new();
        pe.populate_5280_pki_environment();
        let cps = CertificationPathSettings::new();

        // Without a cache, the mismatched signature is rejected.
        let mut cp = build_path();
        let mut cpr = CertificationPathResults::new();
        assert_eq!(
            verify_signatures(&pe, &cps, &mut cp, &mut cpr),
            Err(Error::PathValidation(
                PathValidationStatus::SignatureVerificationFailure
            ))
        );

        // With an always-verified cache, the signature check is skipped.
        pe.add_signature_cache(Box::new(AlwaysVerified));
        let mut cp = build_path();
        let mut cpr = CertificationPathResults::new();
        assert!(verify_signatures(&pe, &cps, &mut cp, &mut cpr).is_ok());
    }

    #[test]
    fn budget_predicate_boundary() {
        // No subjectAltName entries: nothing to match, so no bound applies regardless of the count.
        assert!(!name_constraint_matching_budget_exceeded(usize::MAX, 0));

        // A product exactly at the ceiling is allowed; one constraint beyond it is rejected.
        let ceiling = MAX_NAME_CONSTRAINT_MATCH_WORK / 1024;
        assert!(!name_constraint_matching_budget_exceeded(ceiling, 1024));
        assert!(name_constraint_matching_budget_exceeded(ceiling + 1, 1024));
    }

    // The budget guard must consume the constraint count that accrues as certificate authorities
    // union their excluded subtrees into the operative state, not a count captured from the initial
    // (typically empty) subtree state. A count read before accumulation is zero and never trips the
    // budget no matter how large the subjectAltName; the count read after accumulation does. dNSName
    // subtree accumulation is a std-only feature, so this test is gated accordingly.
    #[cfg(feature = "std")]
    #[test]
    fn budget_tracks_accumulated_constraints() {
        use crate::validator::name_constraints_set::NameConstraintsSet;
        use der::asn1::Ia5String;
        use x509_cert::ext::pkix::constraints::name::GeneralSubtree;

        // Builds `n` distinct excluded dNSName subtrees, as a certificate authority contributes when
        // it unions name constraints into the operative state.
        fn dns_subtrees(n: usize) -> GeneralSubtrees {
            (0..n)
                .map(|i| GeneralSubtree {
                    base: GeneralName::DnsName(Ia5String::new(&format!("x{i}.invalid")).unwrap()),
                    minimum: 0,
                    maximum: None,
                })
                .collect()
        }

        let san_len = 1024;

        // The initial state, as at the top of check_names for a path with no initial subtrees. A
        // count captured here is what the earlier (dead) guard used, and it bounds nothing.
        let permitted = NameConstraintsSet::default();
        let mut excluded = NameConstraintsSet::default();
        let stale_count = permitted.len() + excluded.len();
        assert_eq!(stale_count, 0);
        assert!(
            !name_constraint_matching_budget_exceeded(stale_count, san_len),
            "a count captured before accumulation cannot bound the matching work"
        );

        // A certificate authority unions in enough excluded subtrees to blow the budget.
        let needed = MAX_NAME_CONSTRAINT_MATCH_WORK / san_len + 1;
        excluded.calculate_union(&dns_subtrees(needed));

        // The count read live from the current state reflects the accumulation and trips the budget.
        let live_count = permitted.len() + excluded.len();
        assert!(live_count >= needed);
        assert!(
            name_constraint_matching_budget_exceeded(live_count, san_len),
            "the live count must trip the budget once constraints accumulate"
        );
    }
}
