//! Structured results from certification path validation operations.
//!
//! The types in this module provide a serde-friendly representation of the results of validating
//! one or more target certificates so that non-CLI frontends (GUI, web server) can consume results
//! programmatically instead of scraping logs or files. All types are alloc-only and feature-free so
//! that every frontend can share them.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use certval::{
    get_certificate_from_trust_anchor, name_constraints_set_to_name_constraints_settings,
    name_to_string, source::ta_source::buffer_to_hex, CertificationPath, CertificationPathResults,
    Error, NameConstraintsSet, NameConstraintsSettings, PDVCertificate, PDVTrustAnchorChoice,
    PathValidationStatus,
};

/// Summary details for one certificate (or trust anchor) in a certification path.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertSummary {
    /// Subject name rendered as a string
    pub subject: String,
    /// Issuer name rendered as a string, absent for trust anchors expressed as TrustAnchorInfo
    /// without a wrapped certificate
    pub issuer: Option<String>,
    /// ASCII hex representation of the serial number, absent for trust anchors expressed as
    /// TrustAnchorInfo without a wrapped certificate
    pub serial: Option<String>,
    /// notBefore rendered as a string, absent when unavailable
    pub not_before: Option<String>,
    /// notAfter rendered as a string, absent when unavailable
    pub not_after: Option<String>,
}

impl CertSummary {
    /// Prepares a [`CertSummary`] from a parsed certificate
    pub fn from_cert(cert: &PDVCertificate) -> CertSummary {
        let tbs = cert.decoded().tbs_certificate();
        CertSummary {
            subject: name_to_string(tbs.subject()),
            issuer: Some(name_to_string(tbs.issuer())),
            serial: Some(buffer_to_hex(tbs.serial_number().as_bytes())),
            not_before: Some(tbs.validity().not_before.to_string()),
            not_after: Some(tbs.validity().not_after.to_string()),
        }
    }

    /// Prepares a [`CertSummary`] from a parsed trust anchor. Serial number and validity are only
    /// available when the trust anchor wraps a certificate.
    pub fn from_trust_anchor(ta: &PDVTrustAnchorChoice) -> CertSummary {
        if let Some(cert) = get_certificate_from_trust_anchor(&ta.decoded_ta) {
            let tbs = cert.tbs_certificate();
            return CertSummary {
                subject: name_to_string(tbs.subject()),
                issuer: Some(name_to_string(tbs.issuer())),
                serial: Some(buffer_to_hex(tbs.serial_number().as_bytes())),
                not_before: Some(tbs.validity().not_before.to_string()),
                not_after: Some(tbs.validity().not_after.to_string()),
            };
        }

        let subject = match certval::get_trust_anchor_name(&ta.decoded_ta) {
            Ok(name) => name_to_string(name),
            Err(_e) => String::new(),
        };
        CertSummary {
            subject,
            issuer: None,
            serial: None,
            not_before: None,
            not_after: None,
        }
    }
}

/// Mechanism used to determine the revocation status of one certificate in a certification path.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevocationMethod {
    /// Status determination skipped due to presence of the OCSP no-check extension
    OcspNoCheck,
    /// Status determined using a CRL
    Crl,
    /// Status determined using an OCSP response
    Ocsp,
    /// Status determined using a configured blocklist
    Blocklist,
    /// Status determined using a configured allowlist
    Allowlist,
    /// No mechanism yielded a status determination
    None,
}

/// Revocation status determined for one certificate in a certification path.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevocationStatus {
    /// The certificate was determined to be not revoked
    NotRevoked,
    /// The certificate was determined to be revoked
    Revoked,
    /// Revocation status could not be determined
    Undetermined,
    /// Revocation status determination was not required (e.g., OCSP no-check)
    NotChecked,
}

/// Revocation status outcome for one certificate in a certification path.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationOutcome {
    /// Index of the certificate within the certification path using trust-anchor-first indexing,
    /// i.e., 1 denotes the certificate issued by the trust anchor and intermediates.len() + 1
    /// denotes the target certificate (index 0, the trust anchor, has no outcome)
    pub cert_index: usize,
    /// Mechanism used to determine status
    pub method: RevocationMethod,
    /// Status determination
    pub status: RevocationStatus,
}

/// Final values of policy-related outputs from certification path validation.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyOutcome {
    /// String representations of the OIDs present in the final row of the valid policy graph
    pub final_valid_policies: Vec<String>,
    /// Final value of the explicit_policy state variable from RFC 5280 section 6.1
    pub final_explicit_policy: Option<u32>,
    /// Final value of the policy_mapping state variable from RFC 5280 section 6.1
    pub final_policy_mapping: Option<u32>,
    /// Final value of the inhibit_anyPolicy state variable from RFC 5280 section 6.1
    pub final_inhibit_any_policy: Option<u32>,
}

/// Terminal name-constraints state from certification path validation, i.e., the effective permitted
/// and excluded subtrees the path was validated against upon completion of RFC 5280 section 6.1
/// name-constraints processing. Each form uses the [`NameConstraintsSettings`] convention: `None`
/// means the form was unconstrained, `Some(vec![])` means the permitted set intersected to empty for
/// that form (nothing permitted), and `Some(values)` lists the operative subtrees.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NameConstraintsOutcome {
    /// Effective permitted subtrees per name form
    pub permitted: NameConstraintsSettings,
    /// Effective excluded subtrees per name form
    pub excluded: NameConstraintsSettings,
}

/// Results from validating one certification path for a target certificate.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct PathReport {
    /// Validation status recorded while processing the path, absent when processing failed before
    /// any status was recorded
    pub status: Option<PathValidationStatus>,
    /// Rendering of the error returned by path validation, absent when the path validated
    pub error: Option<String>,
    /// Certificates comprising the path in trust-anchor-first order, i.e., certs[0] is the trust
    /// anchor and certs[certs.len() - 1] is the target certificate
    pub certs: Vec<CertSummary>,
    /// Revocation status outcomes for the certificates in the path (empty when revocation checking
    /// was not performed)
    pub revocation: Vec<RevocationOutcome>,
    /// Index of the certificate at which validation failed using the same trust-anchor-first
    /// indexing as `certs`, absent when the path validated or the failure is not attributable to a
    /// single certificate
    pub failure_index: Option<usize>,
    /// At least one reason for failure when the path failed to validate (empty when the path
    /// validated)
    pub failure_reasons: Vec<String>,
    /// Final values of policy-related outputs, absent when policy processing did not complete
    pub policy: Option<PolicyOutcome>,
    /// Terminal permitted/excluded name-constraints state, absent when name-constraints processing
    /// did not complete (e.g., the path failed before name checking finished)
    pub name_constraints: Option<NameConstraintsOutcome>,
    /// Time expended building and validating the path in milliseconds
    pub duration_ms: u64,
}

impl PathReport {
    /// Prepares a [`PathReport`] from a validated (or invalidated) certification path and the
    /// corresponding results object. The `error` parameter conveys the result returned by
    /// validate_path/check_revocation.
    pub fn from_path_results(
        path: &CertificationPath,
        cpr: &CertificationPathResults,
        error: Option<&Error>,
        duration_ms: u64,
    ) -> PathReport {
        let mut certs = Vec::with_capacity(path.intermediates.len() + 2);
        certs.push(CertSummary::from_trust_anchor(&path.trust_anchor));
        for ca_cert in path.intermediates.iter() {
            certs.push(CertSummary::from_cert(ca_cert));
        }
        certs.push(CertSummary::from_cert(&path.target));

        let status = cpr.get_validation_status();
        let error_string = error.map(|e| format!("{e:?}"));
        let failure_index = cpr.get_failure_index().map(|i| i as usize);

        let mut failure_reasons = vec![];
        let path_failed = error.is_some();
        if path_failed {
            if let Some(status) = status {
                if status != PathValidationStatus::Valid {
                    failure_reasons.push(format!("{status:?}"));
                }
            }
            if let Some(error_string) = &error_string {
                let redundant = failure_reasons
                    .iter()
                    .any(|r| error_string.contains(r.as_str()));
                if !redundant {
                    failure_reasons.push(error_string.clone());
                }
            }
        }

        PathReport {
            status,
            error: if path_failed { error_string } else { None },
            certs,
            revocation: revocation_outcomes_from_cpr(cpr, path.intermediates.len() + 1),
            failure_index,
            failure_reasons,
            policy: policy_outcome_from_cpr(cpr),
            name_constraints: name_constraints_from_cpr(cpr),
            duration_ms,
        }
    }
}

/// Overall status determined for a target certificate across all certification paths processed.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TargetStatus {
    /// At least one certification path validated successfully
    Valid,
    /// At least one certification path passed all checks except that revocation status could not be
    /// determined for at least one certificate in the path
    ValidExceptRevocationUndetermined,
    /// The target certificate was determined to be revoked
    Revoked,
    /// Certification paths were found but none validated successfully
    Invalid,
    /// No certification paths could be found for the target
    NoPathsFound,
}

/// Results from validating all certification paths processed for one target certificate.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TargetReport {
    /// Name of the target, i.e., a filename or caller-assigned label
    pub name: String,
    /// Summary details for the target certificate, absent when the target could not be parsed
    pub target: Option<CertSummary>,
    /// Overall status for the target across all processed paths
    pub status: TargetStatus,
    /// Results for each certification path processed for the target
    pub paths: Vec<PathReport>,
}

impl TargetReport {
    /// Computes the overall [`TargetStatus`] for a set of path reports. `paths_found` indicates
    /// whether the path builder returned any candidate paths (a report may contain no entries even
    /// though paths were found, e.g., when trust anchor constraint enforcement fails).
    pub fn compute_status(paths: &[PathReport], paths_found: bool) -> TargetStatus {
        if !paths_found && paths.is_empty() {
            return TargetStatus::NoPathsFound;
        }
        let mut revoked = false;
        let mut revocation_undetermined = false;
        for path in paths {
            match path.status {
                Some(PathValidationStatus::Valid) => {
                    if path.error.is_none() {
                        return TargetStatus::Valid;
                    }
                }
                Some(PathValidationStatus::CertificateRevokedEndEntity) => {
                    revoked = true;
                }
                Some(PathValidationStatus::RevocationStatusNotDetermined) => {
                    revocation_undetermined = true;
                }
                Some(PathValidationStatus::RevocationStatusNotAvailable) => {
                    revocation_undetermined = true;
                }
                _ => {}
            }
        }
        if revoked {
            return TargetStatus::Revoked;
        }
        if revocation_undetermined {
            return TargetStatus::ValidExceptRevocationUndetermined;
        }
        TargetStatus::Invalid
    }
}

/// Aggregate counts across all targets processed during a validation run.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportTotals {
    /// Number of targets processed
    pub targets: usize,
    /// Number of certification paths found across all targets
    pub paths_found: usize,
    /// Number of certification paths that validated successfully
    pub valid_paths: usize,
    /// Number of certification paths that failed to validate
    pub invalid_paths: usize,
}

/// Results from a validation run covering one or more target certificates.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ValidationReport {
    /// Results for each target processed
    pub targets: Vec<TargetReport>,
    /// Aggregate counts across all targets
    pub totals: ReportTotals,
    /// Time of interest used for the run expressed as seconds since Unix epoch (0 when validity
    /// checking was disabled)
    pub time_of_interest: u64,
    /// Time expended on the run in milliseconds
    pub duration_ms: u64,
}

/// Events emitted while a validation run progresses, for consumption by interactive frontends.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ProgressEvent {
    /// Processing began for the indicated target
    TargetStarted {
        /// Index of the target within the run
        target_index: usize,
        /// Name of the target, i.e., a filename or caller-assigned label
        name: String,
    },
    /// The path builder returned candidate paths for the indicated target
    PathsFound {
        /// Index of the target within the run
        target_index: usize,
        /// Number of candidate paths returned
        count: usize,
    },
    /// Validation completed for one candidate path for the indicated target
    PathCompleted {
        /// Index of the target within the run
        target_index: usize,
        /// Index of the path within the set processed for the target
        path_index: usize,
        /// Whether the path validated successfully
        valid: bool,
    },
    /// Processing completed for the indicated target
    TargetCompleted {
        /// Index of the target within the run
        target_index: usize,
        /// Overall status for the target
        status: TargetStatus,
    },
}

/// Callback type used to convey [`ProgressEvent`] instances to interactive frontends.
pub type ProgressFn = dyn Fn(ProgressEvent) + Send + Sync;

/// Prepares [`RevocationOutcome`] instances from the per-position revocation results vectors in a
/// [`CertificationPathResults`]. The `num_certs` parameter conveys the number of certificates in
/// the path not counting the trust anchor, i.e., intermediates.len() + 1. Returns an empty vector
/// when revocation checking was not performed (i.e., the results vectors are absent).
pub fn revocation_outcomes_from_cpr(
    cpr: &CertificationPathResults,
    num_certs: usize,
) -> Vec<RevocationOutcome> {
    let nocheck = cpr.get_nocheck_usage();
    let blocklist = cpr.get_blocklist_usage();
    let allowlist = cpr.get_allowlist_usage();
    let ocsp_responses = cpr.get_ocsp_responses();
    let crls = cpr.get_crl();
    if nocheck.is_none()
        && blocklist.is_none()
        && allowlist.is_none()
        && ocsp_responses.is_none()
        && crls.is_none()
    {
        return vec![];
    }

    let status = cpr.get_validation_status();
    let failure_index = cpr.get_failure_index().map(|i| i as usize);
    let revoked_status = matches!(
        status,
        Some(PathValidationStatus::CertificateRevokedEndEntity)
            | Some(PathValidationStatus::CertificateRevokedIntermediateCa)
    );

    let flag_at = |v: &Option<Vec<bool>>, pos: usize| -> bool {
        v.as_ref()
            .map(|v| v.get(pos) == Some(&true))
            .unwrap_or(false)
    };
    let artifacts_at = |v: &Option<Vec<Vec<Vec<u8>>>>, pos: usize| -> bool {
        v.as_ref()
            .map(|v| v.get(pos).map(|b| !b.is_empty()).unwrap_or(false))
            .unwrap_or(false)
    };

    let mut outcomes = Vec::with_capacity(num_certs);
    for pos in 0..num_certs {
        let cert_index = pos + 1;
        let revoked_here = revoked_status && failure_index == Some(cert_index);

        let (method, determined_status) = if flag_at(&nocheck, pos) {
            (RevocationMethod::OcspNoCheck, RevocationStatus::NotChecked)
        } else if flag_at(&blocklist, pos) {
            (RevocationMethod::Blocklist, RevocationStatus::Revoked)
        } else if flag_at(&allowlist, pos) {
            (RevocationMethod::Allowlist, RevocationStatus::NotRevoked)
        } else if artifacts_at(&ocsp_responses, pos) {
            if revoked_here {
                (RevocationMethod::Ocsp, RevocationStatus::Revoked)
            } else {
                (RevocationMethod::Ocsp, RevocationStatus::NotRevoked)
            }
        } else if artifacts_at(&crls, pos) {
            if revoked_here {
                (RevocationMethod::Crl, RevocationStatus::Revoked)
            } else {
                (RevocationMethod::Crl, RevocationStatus::NotRevoked)
            }
        } else {
            (RevocationMethod::None, RevocationStatus::Undetermined)
        };

        outcomes.push(RevocationOutcome {
            cert_index,
            method,
            status: determined_status,
        });
    }
    outcomes
}

/// Prepares a [`PolicyOutcome`] from the policy-related values in a [`CertificationPathResults`].
/// Returns None when no policy-related values are present, i.e., when policy processing did not
/// complete.
pub fn policy_outcome_from_cpr(cpr: &CertificationPathResults) -> Option<PolicyOutcome> {
    let final_explicit_policy = cpr.get_final_explicit_policy();
    let final_policy_mapping = cpr.get_final_policy_mapping();
    let final_inhibit_any_policy = cpr.get_final_inhibit_any_policy();
    let graph = cpr.get_final_valid_policy_graph();
    if final_explicit_policy.is_none()
        && final_policy_mapping.is_none()
        && final_inhibit_any_policy.is_none()
        && graph.is_none()
    {
        return None;
    }

    let mut final_valid_policies = vec![];
    if let Some(graph) = graph {
        if let Some(last_row) = graph.last() {
            for node in last_row {
                let oid = node.valid_policy.to_string();
                if !final_valid_policies.contains(&oid) {
                    final_valid_policies.push(oid);
                }
            }
        }
    }

    Some(PolicyOutcome {
        final_valid_policies,
        final_explicit_policy,
        final_policy_mapping,
        final_inhibit_any_policy,
    })
}

/// Renders a terminal name-constraints working set as [`NameConstraintsSettings`], overlaying the
/// per-form null flags the string conversion drops: a null bucket (a permitted form that intersected
/// to empty) becomes `Some(vec![])` to distinguish "nothing permitted" from an unconstrained `None`.
fn name_constraints_settings_from_set(set: &NameConstraintsSet) -> NameConstraintsSettings {
    let mut s = name_constraints_set_to_name_constraints_settings(set).unwrap_or_default();
    if set.rfc822_name_null {
        s.rfc822_name = Some(vec![]);
    }
    if set.dns_name_null {
        s.dns_name = Some(vec![]);
    }
    if set.directory_name_null {
        s.directory_name = Some(vec![]);
    }
    if set.uniform_resource_identifier_null {
        s.uniform_resource_identifier = Some(vec![]);
    }
    if set.ip_address_null {
        s.ip_address = Some(vec![]);
    }
    s
}

/// Builds a [`NameConstraintsOutcome`] from the terminal permitted/excluded subtrees recorded in a
/// [`CertificationPathResults`]. Returns `None` when name-constraints processing did not record its
/// terminal state (e.g., the path failed before name checking completed).
pub fn name_constraints_from_cpr(cpr: &CertificationPathResults) -> Option<NameConstraintsOutcome> {
    let permitted = cpr.get_final_permitted_subtrees();
    let excluded = cpr.get_final_excluded_subtrees();
    if permitted.is_none() && excluded.is_none() {
        return None;
    }
    Some(NameConstraintsOutcome {
        permitted: permitted
            .map(|s| name_constraints_settings_from_set(&s))
            .unwrap_or_default(),
        excluded: excluded
            .map(|s| name_constraints_settings_from_set(&s))
            .unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_json_round_trip() {
        let report = ValidationReport {
            targets: vec![TargetReport {
                name: "target.der".to_string(),
                target: Some(CertSummary {
                    subject: "CN=Target".to_string(),
                    issuer: Some("CN=CA".to_string()),
                    serial: Some("01FF".to_string()),
                    not_before: Some("2026-01-01T00:00:00Z".to_string()),
                    not_after: Some("2027-01-01T00:00:00Z".to_string()),
                }),
                status: TargetStatus::Invalid,
                paths: vec![PathReport {
                    status: Some(PathValidationStatus::InvalidNotAfterDate),
                    error: Some("PathValidation(InvalidNotAfterDate)".to_string()),
                    certs: vec![
                        CertSummary {
                            subject: "CN=Root".to_string(),
                            ..Default::default()
                        },
                        CertSummary {
                            subject: "CN=Target".to_string(),
                            ..Default::default()
                        },
                    ],
                    revocation: vec![RevocationOutcome {
                        cert_index: 1,
                        method: RevocationMethod::Crl,
                        status: RevocationStatus::NotRevoked,
                    }],
                    failure_index: Some(1),
                    failure_reasons: vec!["InvalidNotAfterDate".to_string()],
                    policy: Some(PolicyOutcome {
                        final_valid_policies: vec!["2.5.29.32.0".to_string()],
                        final_explicit_policy: Some(0),
                        final_policy_mapping: Some(1),
                        final_inhibit_any_policy: Some(2),
                    }),
                    name_constraints: Some(NameConstraintsOutcome {
                        permitted: NameConstraintsSettings {
                            dns_name: Some(vec!["example.com".to_string()]),
                            ..Default::default()
                        },
                        excluded: NameConstraintsSettings {
                            directory_name: Some(vec![]),
                            ..Default::default()
                        },
                    }),
                    duration_ms: 12,
                }],
            }],
            totals: ReportTotals {
                targets: 1,
                paths_found: 1,
                valid_paths: 0,
                invalid_paths: 1,
            },
            time_of_interest: 1_770_000_000,
            duration_ms: 15,
        };

        let json = serde_json::to_string(&report).unwrap();
        let round_tripped: ValidationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(round_tripped.targets.len(), 1);
        let target = &round_tripped.targets[0];
        assert_eq!(target.status, TargetStatus::Invalid);
        assert_eq!(target.paths[0].failure_index, Some(1));
        assert_eq!(
            target.paths[0].status,
            Some(PathValidationStatus::InvalidNotAfterDate)
        );
        assert_eq!(target.paths[0].revocation[0].method, RevocationMethod::Crl);
        assert_eq!(
            target.paths[0]
                .policy
                .as_ref()
                .unwrap()
                .final_valid_policies,
            vec!["2.5.29.32.0".to_string()]
        );
        let nc = target.paths[0].name_constraints.as_ref().unwrap();
        assert_eq!(nc.permitted.dns_name, Some(vec!["example.com".to_string()]));
        // Some(vec![]) survives the round trip, preserving "nothing permitted" vs. unconstrained
        assert_eq!(nc.excluded.directory_name, Some(vec![]));
        assert_eq!(round_tripped.totals, report.totals);
    }

    #[test]
    fn revocation_outcomes_empty_without_results() {
        let cpr = CertificationPathResults::new();
        assert!(revocation_outcomes_from_cpr(&cpr, 3).is_empty());
    }

    #[test]
    fn revocation_outcomes_methods_and_statuses() {
        let mut cpr = CertificationPathResults::new();
        cpr.prepare_revocation_results(4).unwrap();

        // position 0: OCSP no-check; position 1: CRL; position 2: OCSP; position 3: nothing
        cpr.set_nocheck_for_item(0);
        cpr.add_crl(&[0x30, 0x00], 1);
        cpr.add_ocsp_response(vec![0x30, 0x00], 2);

        let outcomes = revocation_outcomes_from_cpr(&cpr, 4);
        assert_eq!(outcomes.len(), 4);

        assert_eq!(outcomes[0].cert_index, 1);
        assert_eq!(outcomes[0].method, RevocationMethod::OcspNoCheck);
        assert_eq!(outcomes[0].status, RevocationStatus::NotChecked);

        assert_eq!(outcomes[1].method, RevocationMethod::Crl);
        assert_eq!(outcomes[1].status, RevocationStatus::NotRevoked);

        assert_eq!(outcomes[2].method, RevocationMethod::Ocsp);
        assert_eq!(outcomes[2].status, RevocationStatus::NotRevoked);

        assert_eq!(outcomes[3].cert_index, 4);
        assert_eq!(outcomes[3].method, RevocationMethod::None);
        assert_eq!(outcomes[3].status, RevocationStatus::Undetermined);
    }

    #[test]
    fn revocation_outcomes_revoked_at_failure_index() {
        let mut cpr = CertificationPathResults::new();
        cpr.prepare_revocation_results(2).unwrap();
        cpr.add_crl(&[0x30, 0x00], 0);
        cpr.add_crl(&[0x30, 0x00], 1);
        cpr.set_validation_status(PathValidationStatus::CertificateRevokedEndEntity);
        cpr.set_failure_index(2);

        let outcomes = revocation_outcomes_from_cpr(&cpr, 2);
        assert_eq!(outcomes[0].status, RevocationStatus::NotRevoked);
        assert_eq!(outcomes[1].status, RevocationStatus::Revoked);
        assert_eq!(outcomes[1].method, RevocationMethod::Crl);
    }

    #[test]
    fn policy_outcome_absent_without_results() {
        let cpr = CertificationPathResults::new();
        assert!(policy_outcome_from_cpr(&cpr).is_none());
    }

    #[test]
    fn policy_outcome_from_finals() {
        let mut cpr = CertificationPathResults::new();
        cpr.set_final_explicit_policy(0);
        cpr.set_final_policy_mapping(1);
        cpr.set_final_inhibit_any_policy(2);

        let outcome = policy_outcome_from_cpr(&cpr).unwrap();
        assert_eq!(outcome.final_explicit_policy, Some(0));
        assert_eq!(outcome.final_policy_mapping, Some(1));
        assert_eq!(outcome.final_inhibit_any_policy, Some(2));
        assert!(outcome.final_valid_policies.is_empty());
    }

    #[test]
    fn target_status_rollup() {
        let valid = PathReport {
            status: Some(PathValidationStatus::Valid),
            ..Default::default()
        };
        let invalid = PathReport {
            status: Some(PathValidationStatus::NameChainingFailure),
            error: Some("PathValidation(NameChainingFailure)".to_string()),
            ..Default::default()
        };
        let undetermined = PathReport {
            status: Some(PathValidationStatus::RevocationStatusNotDetermined),
            error: Some("PathValidation(RevocationStatusNotDetermined)".to_string()),
            ..Default::default()
        };
        let revoked = PathReport {
            status: Some(PathValidationStatus::CertificateRevokedEndEntity),
            error: Some("PathValidation(CertificateRevokedEndEntity)".to_string()),
            ..Default::default()
        };

        assert_eq!(
            TargetReport::compute_status(&[], false),
            TargetStatus::NoPathsFound
        );
        assert_eq!(
            TargetReport::compute_status(&[invalid.clone(), valid.clone()], true),
            TargetStatus::Valid
        );
        assert_eq!(
            TargetReport::compute_status(core::slice::from_ref(&invalid), true),
            TargetStatus::Invalid
        );
        assert_eq!(
            TargetReport::compute_status(&[invalid.clone(), undetermined.clone()], true),
            TargetStatus::ValidExceptRevocationUndetermined
        );
        assert_eq!(
            TargetReport::compute_status(&[undetermined, revoked], true),
            TargetStatus::Revoked
        );
    }
}
