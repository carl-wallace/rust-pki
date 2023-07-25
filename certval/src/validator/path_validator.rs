//! Functions related to certification path validation operations

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::vec;
use core::ops::Deref;

use flagset::FlagSet;

use log::info;

use crate::policy_tree::check_certificate_policies;
use crate::{
    environment::pki_environment::*, get_subject_public_key_info_from_trust_anchor,
    path_results::*, path_settings::*, pdv_certificate::*, pdv_extension::*,
    pdv_trust_anchor::get_trust_anchor_name, util::error::*, util::pdv_utilities::*,
    validator::pdv_trust_anchor::PDVTrustAnchorChoice, CertificationPath,
};
use const_oid::db::rfc5280::ANY_POLICY;
use const_oid::db::rfc5912::*;
use der::{asn1::ObjectIdentifier, Decode};
use x509_cert::ext::pkix::KeyUsages;

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
/// path validation, for example, signature verification, digest generation, and logging.
/// - The [`CertificationPathSettings`] parameter defines values that govern path validation. This consists
/// of a mix of standard path validation inputs from [RFC 5280 Section 6.1.1] and non-standard inputs,
/// i.e., whether or not to validate extendedKeyUsage values across the path.
/// - The [`CertificationPath`] parameter provides the target certificate to validate along with a trust
/// anchor and, if necessary, intermediate CA certificates.
/// - The [`CertificationPathResults`] parameter is used to collect potentially useful information from the
/// certification path validation operation.
///
/// [RFC 5280 Section 6.1]: <https://datatracker.ietf.org/doc/html/rfc5280.html#section-6.1>
/// [RFC 5280 Section 6.1.1]: <https://datatracker.ietf.org/doc/html/rfc5280.html#section-6.1.1>
pub fn validate_path_rfc5280(
    pe: &PkiEnvironment<'_>,
    cps: &CertificationPathSettings,
    cp: &mut CertificationPath<'_>,
    cpr: &mut CertificationPathResults<'_>,
) -> Result<()> {
    //enforce_alg_and_key_size_constraints(pe, cps, cp, cpr)?;
    check_validity(pe, cps, cp, cpr)?;
    if get_require_ta_store(cps) {
        if pe.is_cert_a_trust_anchor(cp.target).is_ok() {
            return Ok(());
        }
        if pe.is_trust_anchor(cp.trust_anchor).is_err() {
            return Err(Error::PathValidation(
                PathValidationStatus::MissingTrustAnchor,
            ));
        }
    }

    check_basic_constraints(pe, cps, cp, cpr)?;
    check_names(pe, cps, cp, cpr)?;
    //check_country_codes(pe, cps, cp, cpr)?;
    if get_use_policy_graph(cps) {
        check_certificate_policies_graph(pe, cps, cp, cpr)?;
    } else {
        check_certificate_policies(pe, cps, cp, cpr)?;
    }
    check_key_usage(pe, cps, cp, cpr)?;
    check_extended_key_usage(pe, cps, cp, cpr)?;
    check_critical_extensions(pe, cps, cp, cpr)?;
    verify_signatures(pe, cps, cp, cpr)?;
    set_validation_status(cpr, PathValidationStatus::Valid);
    info!(
        "Successfully completed basic path validation checks for certificate issued to {}",
        name_to_string(&cp.target.decoded_cert.tbs_certificate.subject)
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
    _pe: &PkiEnvironment<'_>,
    cps: &CertificationPathSettings,
    cp: &mut CertificationPath<'_>,
    cpr: &mut CertificationPathResults<'_>,
) -> Result<()> {
    add_processed_extension(cpr, ID_CE_BASIC_CONSTRAINTS);
    let mut path_len_constraint = get_initial_path_length_constraint(cps);

    for ca_cert in cp.intermediates.iter() {
        // (l)  If the certificate was not self-issued, verify that
        //       max_path_length is greater than zero and decrement
        //       max_path_length by 1.
        if !is_self_issued(&ca_cert.decoded_cert) {
            if path_len_constraint == 0 {
                log_error_for_ca(ca_cert, "path length constraint violation");
                set_validation_status(cpr, PathValidationStatus::InvalidPathLength);
                return Err(Error::PathValidation(
                    PathValidationStatus::InvalidPathLength,
                ));
            }
            path_len_constraint -= 1;
        }

        // only support v3 (this is a no-op here because the decoder fails to parse non-V3 certs)
        // if any of the bad_ca_cert_version, bad_ee_cert_version, unsupported_ca_cert_version or
        // unsupported_ee_cert_version tests in tests/path_validator.rs fail this should be uncommented.
        // if ca_cert.decoded_cert.tbs_certificate.version != Version::V3 {
        //     log_error_for_ca(ca_cert, "unsupported x509 version");
        //     set_validation_status(cpr, PathValidationStatus::InvalidBasicConstraints);
        //     return Err(Error::PathValidation(
        //         PathValidationStatus::InvalidBasicConstraints,
        //     ));
        // }

        let pdv_ext: Option<&PDVExtension> = ca_cert.get_extension(&ID_CE_BASIC_CONSTRAINTS)?;
        let bc = match pdv_ext {
            Some(PDVExtension::BasicConstraints(bc)) => bc,
            _ => {
                log_error_for_ca(ca_cert, "missing basic constraints");
                set_validation_status(cpr, PathValidationStatus::MissingBasicConstraints);
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
            set_validation_status(cpr, PathValidationStatus::InvalidBasicConstraints);
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

    Ok(())
}

/// `check_validity` evaluates the target certificate and intermediate certificates against the
/// `PS_TIME_OF_INTEREST` value read from the [`CertificationPathSettings`] parameter.
pub fn check_validity(
    _pe: &PkiEnvironment<'_>,
    cps: &CertificationPathSettings,
    cp: &mut CertificationPath<'_>,
    cpr: &mut CertificationPathResults<'_>,
) -> Result<()> {
    // RFC 5280 states: (2)  The certificate validity period includes the current time.
    // get_time_of_interest_or_now will return now or a caller specified time of interest.
    let toi = get_time_of_interest(cps);
    if 0 == toi {
        info!("check_validity invoked with no time of interest; validity check disabled",);
        return Ok(());
    }

    let mut is_valid = |time_check_res: Result<u64>| -> Result<()> {
        match time_check_res {
            Err(e @ Error::PathValidation(pvs)) => {
                set_validation_status(cpr, pvs);
                Err(e)
            }
            Err(e) => Err(e),
            Ok(_) => Ok(()),
        }
    };

    let target = &cp.target;
    let target_ttl = valid_at_time(&target.decoded_cert.tbs_certificate, toi, false);
    is_valid(target_ttl)?;

    for ca_cert in cp.intermediates.iter() {
        let ca_ttl = valid_at_time(&ca_cert.decoded_cert.tbs_certificate, toi, false);
        is_valid(ca_ttl)?;
    }

    if get_enforce_trust_anchor_validity(cps) {
        // Check TA validity if feature is on (it's on by default) but if the TA does not feature a
        // validity, i.e., if it's a TA Info without a certificate, just carry on.

        let ta_ttl = ta_valid_at_time(&cp.trust_anchor.decoded_ta, toi, false);
        is_valid(ta_ttl)?;
    }

    Ok(())
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
    _pe: &PkiEnvironment<'_>,
    cps: &CertificationPathSettings,
    cp: &mut CertificationPath<'_>,
    cpr: &mut CertificationPathResults<'_>,
) -> Result<()> {
    add_processed_extension(cpr, ID_CE_NAME_CONSTRAINTS);

    // Read input variables from path settings
    let mut pbufs = BTreeMap::new();
    let mut ebufs = BTreeMap::new();
    let initial_perm = match get_initial_permitted_subtrees_as_set(cps, &mut pbufs) {
        Ok(ip) => ip,
        Err(e) => return Err(e),
    };
    let initial_excl = match get_initial_excluded_subtrees_as_set(cps, &mut ebufs) {
        Ok(ie) => ie,
        Err(e) => return Err(e),
    };

    // for convenience, combine target into array with the intermediate CA certs
    let mut v = cp.intermediates.clone();
    v.push(cp.target);
    let certs_in_cert_path = v.len();

    let mut perm_names_set = initial_perm.is_some();
    let mut permitted_subtrees = initial_perm.unwrap_or_default();
    let mut excluded_subtrees = initial_excl.unwrap_or_default();

    let mut working_issuer_name = get_trust_anchor_name(&cp.trust_anchor.decoded_ta)?;

    // Iterate over the list of intermediate CA certificates plus target to check name chaining
    for (pos, ca_cert_ref) in v.iter().enumerate() {
        let ca_cert = ca_cert_ref.deref();

        if !compare_names(
            &ca_cert.decoded_cert.tbs_certificate.issuer,
            working_issuer_name,
        ) {
            log_error_for_ca(ca_cert, "name chaining violation");
            set_validation_status(cpr, PathValidationStatus::NameChainingFailure);
            return Err(Error::PathValidation(
                PathValidationStatus::NameChainingFailure,
            ));
        }

        if pos + 1 != certs_in_cert_path {
            working_issuer_name = &ca_cert.decoded_cert.tbs_certificate.subject;
        }
    }

    // Iterate over the list of intermediate CA certificates plus target to check name constraints
    for (pos, ca_cert_ref) in v.iter().enumerate() {
        let ca_cert = ca_cert_ref.deref();
        let self_issued = is_self_issued(&ca_cert.decoded_cert);

        if (pos + 1) == certs_in_cert_path || !self_issued {
            if !permitted_subtrees
                .subject_within_permitted_subtrees(&ca_cert.decoded_cert.tbs_certificate.subject)
            {
                log_error_for_ca(
                    ca_cert,
                    "permitted name constraints violation for subject name",
                );
                set_validation_status(cpr, PathValidationStatus::NameConstraintsViolation);
                return Err(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                ));
            }

            if excluded_subtrees
                .subject_within_excluded_subtrees(&ca_cert.decoded_cert.tbs_certificate.subject)
            {
                log_error_for_ca(
                    ca_cert,
                    "excluded name constraints violation for subject name",
                );
                set_validation_status(cpr, PathValidationStatus::NameConstraintsViolation);
                return Err(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                ));
            }

            let pdv_ext: Option<&PDVExtension> = ca_cert.get_extension(&ID_CE_SUBJECT_ALT_NAME)?;
            let san = if let Some(PDVExtension::SubjectAltName(san)) = pdv_ext {
                add_processed_extension(cpr, ID_CE_SUBJECT_ALT_NAME);
                Some(san)
            } else {
                None
            };

            if !permitted_subtrees.san_within_permitted_subtrees(&san) {
                log_error_for_ca(ca_cert, "permitted name constraints violation for SAN");
                set_validation_status(cpr, PathValidationStatus::NameConstraintsViolation);
                return Err(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                ));
            }

            if excluded_subtrees.san_within_excluded_subtrees(&san) {
                log_error_for_ca(ca_cert, "excluded name constraints violation for SAN");
                set_validation_status(cpr, PathValidationStatus::NameConstraintsViolation);
                return Err(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                ));
            }
        }

        if pos + 1 != certs_in_cert_path {
            let pdv_ext: Option<&PDVExtension> = ca_cert.get_extension(&ID_CE_NAME_CONSTRAINTS)?;
            if let Some(PDVExtension::NameConstraints(nc)) = pdv_ext {
                add_processed_extension(cpr, ID_CE_NAME_CONSTRAINTS);

                if let Some(excl) = &nc.excluded_subtrees {
                    excluded_subtrees.calculate_union(excl);
                }
                if let Some(perm) = &nc.permitted_subtrees {
                    permitted_subtrees.calculate_intersection(perm);
                }

                if perm_names_set && permitted_subtrees.are_any_empty() {
                    return Err(Error::PathValidation(
                        PathValidationStatus::NameConstraintsViolation,
                    ));
                } else if !perm_names_set && permitted_subtrees.are_any_empty() {
                    perm_names_set = true;
                }
            }
        }
    } // end for (pos, ca_cert_ref) in v.iter_mut().enumerate() {

    Ok(())
}

/// `check_key_usage` ensures all intermediate CA certificates assert the keyCertSign bit and that the
/// target certificate asserts the bits from the `PS_KEY_USAGE` item in the [`CertificationPathSettings`],
/// if any.
pub fn check_key_usage(
    _pe: &PkiEnvironment<'_>,
    cps: &CertificationPathSettings,
    cp: &mut CertificationPath<'_>,
    cpr: &mut CertificationPathResults<'_>,
) -> Result<()> {
    add_processed_extension(cpr, ID_CE_KEY_USAGE);
    for ca_cert in cp.intermediates.iter() {
        let pdv_ext: Option<&PDVExtension> = ca_cert.get_extension(&ID_CE_KEY_USAGE)?;
        let ku = match pdv_ext {
            Some(PDVExtension::KeyUsage(ku)) => ku,
            _ => {
                log_error_for_ca(ca_cert, "key usage extension is missing");
                set_validation_status(cpr, PathValidationStatus::InvalidKeyUsage);
                return Err(Error::PathValidation(PathValidationStatus::InvalidKeyUsage));
            }
        };
        // (n)  If a key usage extension is present, verify that the
        //      keyCertSign bit is set.
        if !ku.0.contains(KeyUsages::KeyCertSign) {
            log_error_for_ca(ca_cert, "keyCertSign is not set in key usage extension");
            set_validation_status(cpr, PathValidationStatus::InvalidKeyUsage);
            return Err(Error::PathValidation(PathValidationStatus::InvalidKeyUsage));
        }
    }

    let target_ku = cp.target.get_extension(&ID_CE_KEY_USAGE)?;
    if let Some(PDVExtension::KeyUsage(target_ku_bits)) = target_ku {
        if let Some(ku) = get_target_key_usage(cps) {
            let nku = match FlagSet::<KeyUsages>::new(ku) {
                Ok(ku) => ku,
                _ => {
                    return Err(Error::Unrecognized);
                }
            };

            // TODO TEST THIS
            for i in nku {
                if !target_ku_bits.0.contains(i) {
                    log_error_for_ca(cp.target, "key usage violation for target certificate");
                    set_validation_status(cpr, PathValidationStatus::InvalidKeyUsage);
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
    _pe: &PkiEnvironment<'_>,
    cps: &CertificationPathSettings,
    cp: &mut CertificationPath<'_>,
    cpr: &mut CertificationPathResults<'_>,
) -> Result<()> {
    add_processed_extension(cpr, ID_CE_EXT_KEY_USAGE);

    let target_ekus: Option<ObjectIdentifierSet> = get_extended_key_usage_as_oid_set(cps);
    let process_ekus_across_path = get_extended_key_usage_path(cps);

    // if we are neither checking across path nor vetting target values, just return
    if !process_ekus_across_path && target_ekus.is_none() {
        return Ok(());
    }

    if process_ekus_across_path {
        // check that intersection of all EKU extensions in the path is not empty
        let mut default_eku = vec![ANY_EXTENDED_KEY_USAGE];

        let ta_eku = cp.trust_anchor.get_extension(&ID_CE_EXT_KEY_USAGE)?;
        let ekus_from_ta = if let Some(PDVExtension::ExtendedKeyUsage(ekus)) = ta_eku {
            &ekus.0
        } else {
            if let Some(target_ekus) = &target_ekus {
                default_eku.clear();
                default_eku.extend(target_ekus.iter());
            }

            &default_eku
        };

        let mut ekus_from_path: BTreeSet<_> = ekus_from_ta.iter().collect();

        let intermediates_and_target = cp.intermediates.iter().chain(core::iter::once(&cp.target));

        for ca_cert_ref in intermediates_and_target {
            let ca_cert = ca_cert_ref.deref();
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
                    set_validation_status(cpr, PathValidationStatus::InvalidKeyUsage);
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
            //     set_validation_status(cpr, PathValidationStatus::InvalidKeyUsage);
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
        cp.target,
        "extended key usage violation when processing target certificate",
    );
    set_validation_status(cpr, PathValidationStatus::InvalidKeyUsage);
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
    _pe: &PkiEnvironment<'_>,
    _cps: &CertificationPathSettings,
    cp: &mut CertificationPath<'_>,
    cpr: &mut CertificationPathResults<'_>,
) -> Result<()> {
    let processed_exts: ObjectIdentifierSet = get_processed_extensions(cpr);

    let mut ensure_criticals_processed = |cert: &PDVCertificate,
                                          err_str: &'static str|
     -> Result<()> {
        if let Some(exts) = &cert.decoded_cert.tbs_certificate.extensions {
            for ext in exts {
                if ext.critical && !processed_exts.contains(&ext.extn_id) {
                    log_error_for_ca(cert, format!("{}: {}", err_str, ext.extn_id).as_str());
                    set_validation_status(cpr, PathValidationStatus::UnprocessedCriticalExtension);
                    return Err(Error::PathValidation(
                        PathValidationStatus::UnprocessedCriticalExtension,
                    ));
                }
            }
        }
        Ok(())
    };

    for ca_cert in &cp.intermediates {
        ensure_criticals_processed(ca_cert, "unprocessed critical extension")?;
    }
    ensure_criticals_processed(
        cp.target,
        "unprocessed critical extension in target certificate",
    )?;

    Ok(())
}

/// `enforce_trust_anchor_constraints` prepares and returns a [`CertificationPathSettings`] object
/// that includes constraints derived from the trust anchor from a given [`CertificationPath`] and the
/// operative [`CertificationPathSettings`].
///
/// When the `PS_ENFORCE_TRUST_ANCHOR_CONSTRAINTS` value in the operative [`CertificationPathSettings`]
/// is set to false, this function does nothing.
pub fn enforce_trust_anchor_constraints<'a>(
    cps: &'a CertificationPathSettings,
    ta: &'a PDVTrustAnchorChoice,
    mod_cps: &'a mut CertificationPathSettings,
) -> Result<&'a CertificationPathSettings> {
    if !get_enforce_trust_anchor_constraints(cps) {
        return Ok(cps);
    }

    *mod_cps = cps.clone();

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
    set_initial_path_length_constraint(mod_cps, pl);

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
                        let mut initial_perm =
                            match get_initial_permitted_subtrees_with_default_as_set(
                                cps, &mut pbufs,
                            ) {
                                Ok(ip) => ip,
                                Err(e) => return Err(e),
                            };
                        initial_perm.calculate_union(permitted);
                        set_initial_permitted_subtrees_from_set(mod_cps, &initial_perm);
                    }
                }
                name_constraints = pdv_ext;
            }
        }

        if let Some(PDVExtension::NameConstraints(nc)) = name_constraints {
            if let Some(excluded) = &nc.excluded_subtrees {
                let mut initial_excl =
                    match get_initial_excluded_subtrees_with_default_as_set(cps, &mut ebufs) {
                        Ok(ie) => ie,
                        Err(e) => return Err(e),
                    };
                initial_excl.calculate_union(excluded);
                set_initial_excluded_subtrees_from_set(mod_cps, &initial_excl);
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
    let user_policy_set: ObjectIdentifierSet = get_initial_policy_set_as_oid_set(cps);
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
            // union
            new_policy_set = user_policy_set;
            new_policy_set.append(&mut ta_policy_set);
        } else {
            let user_accepts_any_policy = user_policy_set.contains(&ANY_POLICY);

            // intersect
            for p in ta_policy_set {
                if user_accepts_any_policy || user_policy_set.contains(&p) {
                    new_policy_set.insert(p);
                }
            }
        }
        set_initial_policy_set_from_oid_set(mod_cps, new_policy_set);
    } else if !ta_policy_set.is_empty() && user_policy_set.is_empty() {
        // use policies from TA
        set_initial_policy_set_from_oid_set(mod_cps, ta_policy_set);
    } else {
        //use user policy set (empty or not)
        set_initial_policy_set_from_oid_set(mod_cps, user_policy_set);
    }

    //o  If an inhibit any policy value of true is associated with the
    //trust anchor (either in a CertPathControls or in an
    //inhibitAnyPolicy extension) and the initial-any-policy-inhibit
    //value is false, set the initial-any-policy-inhibit value to true.
    let initial_inhibit_any_policy = get_initial_inhibit_any_policy_indicator(cps);
    let ta_inhibit_any_policy = get_inhibit_any_policy_from_trust_anchor(&ta.decoded_ta)?;
    if ta_inhibit_any_policy && !initial_inhibit_any_policy {
        set_initial_inhibit_any_policy_indicator(mod_cps, ta_inhibit_any_policy);
    }

    //o  If a require explicit policy value of true is associated with the
    //trust anchor (either in a CertPathControls or in a
    //PolicyConstraints extension) and the initial-explicit-policy value
    //is false, set the initial-explicit-policy value to true.
    let initial_require_explicit_policy = get_initial_explicit_policy_indicator(cps);
    let ta_require_explicit_policy = get_require_explicit_policy_from_trust_anchor(&ta.decoded_ta)?;
    if ta_require_explicit_policy && !initial_require_explicit_policy {
        set_initial_explicit_policy_indicator(mod_cps, ta_require_explicit_policy);
    }

    //o  If an inhibit policy mapping value of true is associated with the
    //trust anchor (either in a CertPathControls or in a
    //PolicyConstraints extension) and the initial-policy-mapping-
    //inhibit value is false, set the initial-policy-mapping-inhibit
    //value to true.
    let initial_inhibit_policy_mapping = get_initial_policy_mapping_inhibit_indicator(cps);
    let ta_inhibit_policy_mapping = get_inhibit_policy_mapping_from_trust_anchor(&ta.decoded_ta)?;
    if ta_inhibit_policy_mapping && !initial_inhibit_policy_mapping {
        set_initial_policy_mapping_inhibit_indicator(mod_cps, ta_inhibit_policy_mapping);
    }

    Ok(mod_cps)
}

/// `verify_signatures` verifies the certificate signatures of certificates found in a certification path.
pub fn verify_signatures(
    pe: &PkiEnvironment<'_>,
    _cps: &CertificationPathSettings,
    cp: &mut CertificationPath<'_>,
    cpr: &mut CertificationPathResults<'_>,
) -> Result<()> {
    let intermediates_and_target = cp.intermediates.iter().chain(core::iter::once(&cp.target));

    let mut working_spki =
        get_subject_public_key_info_from_trust_anchor(&cp.trust_anchor.decoded_ta);

    for cur_cert_ref in intermediates_and_target {
        let cur_cert = cur_cert_ref.deref();

        let defer_cert = DeferDecodeSigned::from_der(cur_cert.encoded_cert.as_slice());
        let defer_cert = match defer_cert {
            Ok(c) => c,
            Err(e) => {
                log_error_for_ca(
                    cur_cert,
                    format!("signature verification error: {:?}", e).as_str(),
                );
                set_validation_status(cpr, PathValidationStatus::EncodingError);
                return Err(Error::PathValidation(PathValidationStatus::EncodingError));
            }
        };

        if cur_cert.decoded_cert.tbs_certificate.signature
            != cur_cert.decoded_cert.signature_algorithm
        {
            log_error_for_ca(
                cur_cert,
                format!(
                    "signature algorithm mismatch: {:?} - {:?}",
                    cur_cert.decoded_cert.tbs_certificate.signature,
                    cur_cert.decoded_cert.signature_algorithm
                )
                .as_str(),
            );
            set_validation_status(cpr, PathValidationStatus::EncodingError);
            return Err(Error::PathValidation(PathValidationStatus::EncodingError));
        }

        let r = pe.verify_signature_message(
            pe,
            defer_cert.tbs_field,
            cur_cert.decoded_cert.signature.raw_bytes(),
            &cur_cert.decoded_cert.tbs_certificate.signature,
            working_spki,
        );
        if let Err(e) = r {
            log_error_for_ca(
                cur_cert,
                format!("signature verification error: {:?}", e).as_str(),
            );
            set_validation_status(cpr, PathValidationStatus::SignatureVerificationFailure);
            return Err(Error::PathValidation(
                PathValidationStatus::SignatureVerificationFailure,
            ));
        }

        working_spki = &cur_cert
            .decoded_cert
            .tbs_certificate
            .subject_public_key_info;
    }
    Ok(())
}

/*
/// `enforce_alg_and_key_size_constraints` enforces algorithm and key size constraints, if any.
pub fn enforce_alg_and_key_size_constraints(
    _pe: &PkiEnvironment<'_>,
    _cps: &CertificationPathSettings,
    _cp: &mut CertificationPath<'_>,
    _cpr: &mut CertificationPathResults<'_>,
) -> Result<()> {
    //TODO - implement alg and key size constraints enforcement
    Ok(())
}

/// `check_country_codes` ensures the target certificate from a CertificationPath does not violate any
/// constraints defined in the `PS_PERM_COUNTRIES` and `PS_EXCL_COUNTRIES` values from the [`CertificationPathSettings`].
pub fn check_country_codes(
    _pe: &PkiEnvironment<'_>,
    _cps: &CertificationPathSettings,
    _cp: &mut CertificationPath<'_>,
    _cpr: &mut CertificationPathResults<'_>,
) -> Result<()> {
    //TODO - implement country code enforcement
    Ok(())
}
*/
