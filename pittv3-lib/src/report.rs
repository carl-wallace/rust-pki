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

use der::Encode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use certval::{
    get_certificate_from_trust_anchor, is_self_signed,
    name_constraints_set_to_name_constraints_settings, name_to_string,
    source::ta_source::buffer_to_hex, valid_at_time, CertificationPath, CertificationPathResults,
    Error, NameConstraintsSet, NameConstraintsSettings, PDVCertificate, PDVTrustAnchorChoice,
    PathValidationStatus, PkiEnvironment, RevocationSource, TimeOfInterest,
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
    /// Uppercase ASCII hex SHA-256 of the DER-encoded certificate, absent for a trust anchor
    /// expressed as name and public key without a wrapped certificate.
    ///
    /// The other fields describe a certificate; this one identifies it. Subject, issuer and serial
    /// are rendered for reading and are not a key: two certificates can share all three (a reissue
    /// under a rotated key, a cross-certificate), and none of them can get from a row of a report
    /// back to the bytes the row describes. A caller holding the run's artifacts — to offer a
    /// download, to name a file, to tell whether two reports describe the same certificate — needs
    /// something derived from the encoding, and the digest is the same value whether the
    /// certificate was seen as a trust anchor, an intermediate or a target.
    ///
    /// Taken over the certificate itself for a trust anchor that wraps one, rather than over the
    /// `TrustAnchorChoice` around it, so that one certificate has one identity no matter which role
    /// a path gave it.
    pub sha256: Option<String>,
}

/// Uppercase ASCII hex SHA-256 of `der`, the identity [`CertSummary::sha256`] carries.
pub fn sha256_hex(der: &[u8]) -> String {
    buffer_to_hex(Sha256::digest(der).to_vec().as_slice())
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
            sha256: Some(sha256_hex(cert.as_bytes())),
        }
    }

    /// Prepares a [`CertSummary`] from a parsed trust anchor. Serial number, validity and digest are
    /// only available when the trust anchor wraps a certificate.
    pub fn from_trust_anchor(ta: &PDVTrustAnchorChoice) -> CertSummary {
        if let Some(cert) = get_certificate_from_trust_anchor(&ta.decoded_ta) {
            let tbs = cert.tbs_certificate();
            return CertSummary {
                subject: name_to_string(tbs.subject()),
                issuer: Some(name_to_string(tbs.issuer())),
                serial: Some(buffer_to_hex(tbs.serial_number().as_bytes())),
                not_before: Some(tbs.validity().not_before.to_string()),
                not_after: Some(tbs.validity().not_after.to_string()),
                // Over the certificate rather than over `ta.encoded_ta`, which is the
                // TrustAnchorChoice wrapping it: the same certificate reached as an intermediate on
                // another path must produce the same digest, or the identity is a description of the
                // role instead of the material. A certificate that will not re-encode leaves this
                // absent rather than falling back to the wrapper's digest, since a wrong identity is
                // worse than none.
                sha256: cert.to_der().ok().map(|der| sha256_hex(&der)),
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
            sha256: None,
        }
    }
}

/// Mechanism used to determine the revocation status of one certificate in a certification path.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevocationMethod {
    /// Status determination skipped due to presence of the OCSP no-check extension
    OcspNoCheck,
    /// Status determined using a CRL, without a record of where the CRL came from
    Crl,
    /// Status determined using an OCSP response, without a record of where the response came from
    Ocsp,
    /// Status determined using a configured blocklist
    Blocklist,
    /// Status determined using a configured allowlist
    Allowlist,
    /// Status determined from a previously cached determination rather than from revocation data
    /// examined on this run
    Cache,
    /// Status determined using an OCSP response supplied alongside the path
    StapledOcsp,
    /// Status determined using a CRL supplied alongside the path
    StapledCrl,
    /// Status determined using a CRL already held, rather than one retrieved for this validation
    LocalCrl,
    /// Status determined using an OCSP response retrieved from an authority information access URI
    OcspFromAia,
    /// Status determined using a CRL retrieved from a distribution point
    RemoteCrlDp,
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
    /// Certificates comprising the path in trust-anchor-first order, i.e., `certs[0]` is the trust
    /// anchor and `certs[certs.len() - 1]` is the target certificate. When `no_anchor` is set there
    /// is no path and this holds the rejected target alone.
    pub certs: Vec<CertSummary>,
    /// Set when `certs[0]` is not a trust anchor: the target was rejected during path building, so
    /// no path — and therefore no anchor — exists.
    ///
    /// Only slot 0 can be an anchor, so only slot 0 is in question. It cannot be settled from the
    /// shape, because a lone certificate is also how a target that *is* an anchor appears, nor from
    /// the outcome, because that is a consequence rather than the fact. The producer asks
    /// [`PkiEnvironment::is_cert_a_trust_anchor`] and records the answer; a reader that instead
    /// assumed slot 0 is always an anchor labelled a rejected end entity as one.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub no_anchor: bool,
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
            // A path was built, so it begins with the anchor it was built to: `certs` was assembled
            // trust-anchor-first above.
            no_anchor: false,
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
    /// The input was admitted as a certificate and could not be read as one, so no target existed
    /// to build a path for. Distinct from [`NoPathsFound`](TargetStatus::NoPathsFound), which says
    /// the store held no issuer for a certificate that was read: nothing about the store or the
    /// settings bears on this outcome, and reporting it as an absence of paths sent users looking
    /// at trust material over a file that was never a certificate.
    ParseError,
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
    /// Why no certification path was found, when the status is
    /// [`NoPathsFound`](TargetStatus::NoPathsFound). Empty otherwise, and empty when the outcome
    /// could not be attributed (a diagnosis is best-effort, never a substitute for the status).
    /// See [`NoPathsContext`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub no_paths_hints: Vec<String>,
    /// Why the input yielded no target, when the status is
    /// [`ParseError`](TargetStatus::ParseError). Absent otherwise. The status says a certificate
    /// could not be read; this says what went wrong reading it, which is the whole of what a run
    /// can offer about a file it could not decode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What the path builder had to work with, used to explain a zero-path outcome.
///
/// "No paths found" is the one outcome that says nothing about the certificate: it reports the
/// absence of a result, and the cause is almost always in the run's inputs rather than in the
/// target. This type collects the few facts that separate the causes — whether any trust anchor is
/// loaded, whether any loaded certificate could even have issued the target, whether the target is
/// within its validity period at the time of interest — so that [`hints`](NoPathsContext::hints)
/// can say which one applies.
///
/// The facts come from the [`PkiEnvironment`] the run used, so the diagnosis reflects the material
/// actually in play rather than what the caller believes it configured. That distinction is the
/// point: the common cause is trust material a frontend accepted but never routed into path
/// building.
///
/// The hints are deliberately free of any frontend's vocabulary — no flags, no field names — so
/// the CLI, desktop and browser can all render them. A frontend that wants to name its own input
/// appends its own line to [`TargetReport::no_paths_hints`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NoPathsContext {
    /// Number of trust anchors available to the run
    pub trust_anchors: usize,
    /// Number of intermediate CA certificates available to the run
    pub intermediates: usize,
    /// The target's issuer name, rendered for display
    pub issuer_name: String,
    /// Whether a trust anchor matches the target's issuer name
    pub issuer_is_trust_anchor: bool,
    /// Number of available certificates whose subject matches the target's issuer name, i.e., the
    /// candidate issuers the builder had to work with
    pub issuer_certs: usize,
    /// Why the target is outside its validity period at the time of interest, when it is. Path
    /// building excludes such certificates, so this alone explains a zero-path outcome.
    pub target_invalid_at_toi: Option<String>,
    /// Whether the target signed itself, in which case its issuer is itself and the only thing that
    /// can anchor it is the trust store. Worth separating because the generic advice — find the
    /// issuer certificate, fetch it if need be — is advice that cannot possibly work here.
    pub target_self_signed: bool,
    /// Whether the frontend can chase AIA and SIA URIs to fetch missing issuers: `None` when it
    /// cannot (so suggesting it would be noise), `Some(false)` when it can but the run did not, and
    /// `Some(true)` when the run already did.
    pub dynamic_build: Option<bool>,
}

impl NoPathsContext {
    /// Collects the diagnosis inputs from the environment a run used. `toi` is the time of interest
    /// the run validated against, expressed as it is in the settings.
    pub fn collect(
        pe: &PkiEnvironment,
        target: &PDVCertificate,
        toi: TimeOfInterest,
        dynamic_build: Option<bool>,
    ) -> NoPathsContext {
        let issuer = target.decoded().tbs_certificate().issuer();
        NoPathsContext {
            trust_anchors: pe.get_trust_anchors().len(),
            intermediates: pe.get_intermediates().map(|i| i.len()).unwrap_or_default(),
            issuer_name: name_to_string(issuer),
            issuer_is_trust_anchor: pe.get_trust_anchor_by_name(issuer).is_ok(),
            issuer_certs: pe.get_cert_by_name(issuer).len(),
            // stifle_log: the caller has already logged the failure to find a path, and this is a
            // question about the target rather than a fresh error
            target_invalid_at_toi: valid_at_time(target.decoded().tbs_certificate(), toi, true)
                .err()
                .map(|e| format!("{e:?}")),
            target_self_signed: is_self_signed(pe, target),
            dynamic_build,
        }
    }

    /// Explains the zero-path outcome as one or more display-ready sentences, most specific first.
    ///
    /// Returns an empty vector when the facts do not distinguish a cause, which is why the caller
    /// treats this as an addition to the status rather than a replacement for it.
    pub fn hints(&self) -> Vec<String> {
        let mut hints = vec![];

        // Ordered as the builder fails: nothing to terminate at, then a target that cannot enter
        // path building at all, then the gap between the target and the material on hand.
        if 0 == self.trust_anchors {
            // Deliberately says only what is true of every frontend. Why a supplied anchor did not
            // survive loading depends on the source it came from, so the frontend that owns that
            // source appends the explanation; this layer cannot know it.
            hints.push(
                "No trust anchors are loaded, so no certification path can terminate.".to_string(),
            );
        }

        if let Some(reason) = &self.target_invalid_at_toi {
            hints.push(format!(
                "The target certificate is not valid at the time of interest ({reason}); \
                 certificates outside their validity period are excluded from path building."
            ));
        }

        // A missing issuer and a present-but-unusable issuer are different problems with different
        // remedies, and reporting a bare zero conflates them.
        // A self-signed target is its own issuer, so the whole issuer-hunting line of explanation
        // below is beside the point: there is no certificate to go and find, and no URI to find it
        // at. Either it is an anchor of this run or it cannot be validated at all.
        let material_missing = if 0 == self.trust_anchors {
            false
        } else if self.target_self_signed && !self.issuer_is_trust_anchor {
            hints.push(
                "The target is self-signed, so it is its own issuer: nothing can vouch for it but \
                 a trust anchor, and no loaded anchor matches it. Validate it by adding it to the \
                 trust store, or select a store that carries it."
                    .to_string(),
            );
            false
        } else if self.issuer_is_trust_anchor {
            hints.push(format!(
                "A trust anchor matches the target's issuer name ({}), so the missing link is not \
                 the issuer certificate: the anchor's key identifier or signature does not match \
                 the target, or the anchor is not valid at the time of interest.",
                self.issuer_name
            ));
            false
        } else if 0 == self.intermediates {
            hints.push(format!(
                "No intermediate CA certificates are loaded and no trust anchor has subject {}, \
                 the target's issuer.",
                self.issuer_name
            ));
            true
        } else if 0 == self.issuer_certs {
            hints.push(format!(
                "None of the {} loaded intermediate CA certificates has subject {}, the target's \
                 issuer.",
                self.intermediates, self.issuer_name
            ));
            true
        } else {
            hints.push(format!(
                "{} loaded certificate(s) have subject {}, the target's issuer, but no chain from \
                 any of them reaches a loaded trust anchor.",
                self.issuer_certs, self.issuer_name
            ));
            true
        };

        // Only worth raising when the gap is material the builder could have fetched.
        if material_missing {
            match self.dynamic_build {
                Some(false) => hints.push(
                    "Chasing AIA and SIA URIs is off; enabling it lets the builder fetch the \
                     missing certificates."
                        .to_string(),
                ),
                Some(true) => hints.push(
                    "Chasing AIA and SIA URIs was enabled and still produced no issuer, so the \
                     missing certificates are not reachable from the URIs on hand."
                        .to_string(),
                ),
                None => {}
            }
        }

        hints
    }
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
    /// Time expended on the run in milliseconds.
    ///
    /// What that covers depends on who built the report. A run with a beginning and an end — the
    /// CLI, and the service — records wall clock, so preparation and revocation retrieval are in
    /// it. [`ValidationReport::from_targets`] has no such run to time and sums what the paths
    /// report instead, which is the validating alone.
    pub duration_ms: u64,
    /// Set when the run could not be carried out (e.g. a required input was missing or an output
    /// could not be written). A frontend should surface this as a failure rather than an empty
    /// result. `None` on a report that ran to completion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ValidationReport {
    /// Builds a report describing a run that could not be carried out, carrying `message` for a
    /// frontend to display. Used in place of aborting the process so both the CLI and GUI can
    /// report the failure through their own channels.
    pub fn failed(message: impl Into<String>) -> Self {
        ValidationReport {
            error: Some(message.into()),
            ..Default::default()
        }
    }

    /// Aggregates per-target reports into a run-level report, deriving the totals from the path
    /// reports themselves.
    ///
    /// This is for a frontend whose targets accumulate across interactions rather than arriving
    /// from a single run: the totals have to be recomputed whenever the set changes, and there are
    /// no certval run statistics to read them from — unlike `options_std`, which
    /// accumulates the same counts from `paths_per_target` and friends as it goes.
    ///
    /// `duration_ms` is the sum of what the paths themselves report. There is no one run here to
    /// wall-clock — that is the same reason the totals have to be recomputed — but every path
    /// carries what it took, and their sum is the work this report accounts for. It is a smaller
    /// number than the wall clock a single run records, since preparation and retrieval are not in
    /// it, and it grows as targets accumulate, which is the behaviour a caller displaying it wants.
    /// Reporting zero instead was worse than either: a run showing `0 ms` beside paths that each
    /// report real durations reads as a broken clock rather than as an absent one.
    pub fn from_targets(targets: &[TargetReport], time_of_interest: u64) -> Self {
        let mut totals = ReportTotals {
            targets: targets.len(),
            ..Default::default()
        };
        let mut duration_ms = 0;
        for target in targets {
            totals.paths_found += target.paths.len();
            for path in &target.paths {
                duration_ms += path.duration_ms;
                if path.error.is_none() && path.status == Some(PathValidationStatus::Valid) {
                    totals.valid_paths += 1;
                } else {
                    totals.invalid_paths += 1;
                }
            }
        }
        ValidationReport {
            targets: targets.to_vec(),
            totals,
            time_of_interest,
            duration_ms,
            error: None,
        }
    }
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
    #[cfg(feature = "revocation")]
    let crls = cpr.get_crl();
    #[cfg(feature = "revocation")]
    let crls_none = crls.is_none();
    #[cfg(not(feature = "revocation"))]
    let crls_none = true;
    if nocheck.is_none()
        && blocklist.is_none()
        && allowlist.is_none()
        && ocsp_responses.is_none()
        && crls_none
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
    // CRL results are held as compact CrlInfo records (revocation-gated), so they need their own
    // presence check; without the revocation feature there are never any CRL artifacts.
    #[cfg(feature = "revocation")]
    let crl_artifact_at = |pos: usize| -> bool {
        crls.as_ref()
            .map(|v| v.get(pos).map(|b| !b.is_empty()).unwrap_or(false))
            .unwrap_or(false)
    };
    #[cfg(not(feature = "revocation"))]
    let crl_artifact_at = |_pos: usize| -> bool { false };

    // Which source settled each position, as the checker recorded it. Read in preference to the
    // artifacts because the artifacts cannot answer the question: a determination served from the
    // status cache examines no revocation data and so leaves nothing behind, and a stapled response
    // is indistinguishable from a retrieved one once both are just "an OCSP response in the
    // results". Absent for results produced before the checker recorded it, which is why the
    // artifact arms below remain as a fallback.
    let sources = cpr.get_revocation_source();
    let source_at = |pos: usize| -> Option<RevocationSource> {
        sources.as_ref().and_then(|v| v.get(pos).copied())
    };

    let mut outcomes = Vec::with_capacity(num_certs);
    for pos in 0..num_certs {
        let cert_index = pos + 1;
        let revoked_here = revoked_status && failure_index == Some(cert_index);

        // A settled position reports revoked only where the failure index says the revocation was
        // found; every other settled position is not revoked.
        let settled = |m: RevocationMethod| -> (RevocationMethod, RevocationStatus) {
            if revoked_here {
                (m, RevocationStatus::Revoked)
            } else {
                (m, RevocationStatus::NotRevoked)
            }
        };

        // Blocklist and allowlist are consulted before the source is read: they are not rungs of the
        // checker's ladder but decisions about whether a URI may be fetched at all, so nothing
        // records them as a source.
        let (method, determined_status) = if flag_at(&blocklist, pos) {
            (RevocationMethod::Blocklist, RevocationStatus::Revoked)
        } else if flag_at(&allowlist, pos) {
            (RevocationMethod::Allowlist, RevocationStatus::NotRevoked)
        } else {
            match source_at(pos) {
                Some(RevocationSource::NoCheckExtension) => {
                    (RevocationMethod::OcspNoCheck, RevocationStatus::NotChecked)
                }
                Some(RevocationSource::Cache) => settled(RevocationMethod::Cache),
                Some(RevocationSource::StapledOcsp) => settled(RevocationMethod::StapledOcsp),
                Some(RevocationSource::StapledCrl) => settled(RevocationMethod::StapledCrl),
                Some(RevocationSource::LocalCrl) => settled(RevocationMethod::LocalCrl),
                Some(RevocationSource::OcspFromAia) => settled(RevocationMethod::OcspFromAia),
                Some(RevocationSource::RemoteCrlDp) => settled(RevocationMethod::RemoteCrlDp),
                // Either nothing settled this position, or the results predate the checker
                // recording sources. Fall back to what the artifacts show, which distinguishes CRL
                // from OCSP but not where either came from.
                Some(RevocationSource::None) | None => {
                    if flag_at(&nocheck, pos) {
                        (RevocationMethod::OcspNoCheck, RevocationStatus::NotChecked)
                    } else if artifacts_at(&ocsp_responses, pos) {
                        settled(RevocationMethod::Ocsp)
                    } else if crl_artifact_at(pos) {
                        settled(RevocationMethod::Crl)
                    } else {
                        (RevocationMethod::None, RevocationStatus::Undetermined)
                    }
                }
            }
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

    /// Builds a minimal CrlInfo used to mark that a CRL contributed at a given path position. The
    /// content is irrelevant to these tests; only presence at the position matters.
    #[cfg(feature = "revocation")]
    fn crl_marker() -> certval::CrlInfo {
        certval::CrlInfo {
            type_info: certval::CrlType {
                scope: certval::CrlScope::Complete,
                coverage: certval::CrlCoverage::All,
                authority: certval::CrlAuthority::Direct,
                reasons: certval::CrlReasons::AllReasons,
            },
            this_update: 0,
            next_update: None,
            issuer_name: String::new(),
            issuer_name_blob: Vec::new(),
            sig_alg_blob: Vec::new(),
            exts_blob: None,
            idp_name: None,
            idp_blob: None,
            skid: None,
            filename: None,
            uri: None,
        }
    }

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
                    sha256: Some("A1B2C3".to_string()),
                }),
                status: TargetStatus::Invalid,
                paths: vec![PathReport {
                    status: Some(PathValidationStatus::InvalidNotAfterDate),
                    error: Some("PathValidation(InvalidNotAfterDate)".to_string()),
                    no_anchor: false,
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
                no_paths_hints: vec![],
                error: None,
            }],
            totals: ReportTotals {
                targets: 1,
                paths_found: 1,
                valid_paths: 0,
                invalid_paths: 1,
            },
            time_of_interest: 1_770_000_000,
            duration_ms: 15,
            error: None,
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

    /// A context with material on hand, i.e., the shape where the diagnosis has to discriminate
    fn ctx() -> NoPathsContext {
        NoPathsContext {
            trust_anchors: 3,
            intermediates: 40,
            issuer_name: "CN=Some CA".to_string(),
            issuer_is_trust_anchor: false,
            issuer_certs: 0,
            target_invalid_at_toi: None,
            target_self_signed: false,
            dynamic_build: Some(false),
        }
    }

    #[test]
    fn no_paths_hints_name_the_missing_piece() {
        // no anchors: nothing for a path to terminate at, and the issuer analysis is beside the
        // point until that is fixed
        let hints = NoPathsContext {
            trust_anchors: 0,
            intermediates: 0,
            ..ctx()
        }
        .hints();
        assert_eq!(hints.len(), 1);
        assert!(hints[0].contains("No trust anchors are loaded"));

        // anchors but an empty graph: the case a CA folder that was never compiled produces
        let hints = NoPathsContext {
            intermediates: 0,
            ..ctx()
        }
        .hints();
        assert!(hints[0].contains("No intermediate CA certificates are loaded"));
        assert!(hints[0].contains("CN=Some CA"));
        assert!(hints[1].contains("Chasing AIA and SIA URIs is off"));

        // a populated graph that does not happen to contain the issuer
        let hints = ctx().hints();
        assert!(hints[0].contains("None of the 40 loaded intermediate CA certificates"));

        // the issuer is present but nothing above it reaches an anchor, which is a different
        // problem from the issuer being absent
        let hints = NoPathsContext {
            issuer_certs: 2,
            ..ctx()
        }
        .hints();
        assert!(hints[0].contains("2 loaded certificate(s) have subject"));
        assert!(hints[0].contains("no chain from any of them reaches"));
    }

    #[test]
    fn no_paths_hints_distinguish_target_and_anchor_problems() {
        // an anchor issued the target, so no amount of extra material will help
        let hints = NoPathsContext {
            issuer_is_trust_anchor: true,
            ..ctx()
        }
        .hints();
        assert!(hints[0].contains("A trust anchor matches the target's issuer name"));
        // fetching is not proposed: the material is present, it just does not fit
        assert_eq!(hints.len(), 1);

        // a target outside its validity period never enters path building at all
        let hints = NoPathsContext {
            target_invalid_at_toi: Some("PathValidation(InvalidNotAfterDate)".to_string()),
            ..ctx()
        }
        .hints();
        assert!(hints[0].contains("not valid at the time of interest"));
        assert!(hints[0].contains("InvalidNotAfterDate"));
    }

    /// A root validated as a target has itself for an issuer, so the issuer-hunting explanation is
    /// advice that cannot work: there is no certificate to find and no URI to find it at. Real
    /// case — `DoDRootCA4.der` against a store that does not carry it was told that none of the 37
    /// loaded intermediates had its subject, and to switch on AIA chasing.
    #[test]
    fn a_self_signed_target_is_told_it_needs_an_anchor_not_an_issuer() {
        let hints = NoPathsContext {
            target_self_signed: true,
            ..ctx()
        }
        .hints();

        assert_eq!(hints.len(), 1, "{hints:?}");
        assert!(hints[0].contains("self-signed"));
        assert!(hints[0].contains("trust store"));
        // the two things that would be wrong to say here
        assert!(!hints[0].contains("intermediate CA certificates"));
        assert!(hints.iter().all(|h| !h.contains("Chasing AIA and SIA")));

        // an anchor that matches it is a different outcome, and keeps the existing explanation
        let hints = NoPathsContext {
            target_self_signed: true,
            issuer_is_trust_anchor: true,
            ..ctx()
        }
        .hints();
        assert!(hints[0].contains("A trust anchor matches the target's issuer name"));
    }

    #[test]
    fn no_paths_hints_respect_what_the_frontend_can_do() {
        // None: a frontend that cannot fetch is not told to fetch
        let hints = NoPathsContext {
            dynamic_build: None,
            ..ctx()
        }
        .hints();
        assert_eq!(hints.len(), 1);

        // already chasing: the remedy has been tried, so say that instead of suggesting it
        let hints = NoPathsContext {
            dynamic_build: Some(true),
            ..ctx()
        }
        .hints();
        assert!(hints[1].contains("was enabled and still produced no issuer"));
    }

    #[test]
    fn revocation_outcomes_empty_without_results() {
        let cpr = CertificationPathResults::new();
        assert!(revocation_outcomes_from_cpr(&cpr, 3).is_empty());
    }

    #[test]
    #[cfg(feature = "revocation")]
    fn revocation_outcomes_methods_and_statuses() {
        let mut cpr = CertificationPathResults::new();
        cpr.prepare_revocation_results(4).unwrap();

        // position 0: OCSP no-check; position 1: CRL; position 2: OCSP; position 3: nothing
        cpr.set_nocheck_for_item(0);
        cpr.add_crl(crl_marker(), 1);
        cpr.add_ocsp_response(vec![0x30, 0x00], 2);
        // No sources are recorded, so this also covers the fallback taken for results produced
        // before the checker recorded them: CRL and OCSP are still told apart, but not where either
        // came from.
        cpr.set_validation_status(PathValidationStatus::RevocationStatusNotDetermined);
        cpr.set_failure_index(4);

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

    /// The status cache settles a certificate without examining revocation data, so it leaves no
    /// artifact to infer from. The recorded source is the only thing that distinguishes it from a
    /// position nothing settled -- and reporting a settled certificate as undetermined would
    /// understate a result that was in fact determined.
    #[test]
    #[cfg(feature = "revocation")]
    fn revocation_outcomes_report_a_cached_determination_despite_no_artifact() {
        let mut cpr = CertificationPathResults::new();
        cpr.prepare_revocation_results(2).unwrap();
        cpr.add_crl(crl_marker(), 0);
        cpr.set_revocation_source_for_item(0, RevocationSource::LocalCrl);
        cpr.set_revocation_source_for_item(1, RevocationSource::Cache);

        let outcomes = revocation_outcomes_from_cpr(&cpr, 2);
        assert_eq!(outcomes[0].method, RevocationMethod::LocalCrl);
        assert_eq!(outcomes[0].status, RevocationStatus::NotRevoked);
        assert_eq!(outcomes[1].method, RevocationMethod::Cache);
        assert_eq!(outcomes[1].status, RevocationStatus::NotRevoked);
    }

    /// Each rung of the ladder reports as itself. The artifacts cannot express this: a stapled
    /// response and one fetched from an authority information access URI are both just "an OCSP
    /// response in the results", and the same holds for a held CRL against a retrieved one.
    #[test]
    #[cfg(feature = "revocation")]
    fn revocation_outcomes_distinguish_where_each_answer_came_from() {
        let mut cpr = CertificationPathResults::new();
        cpr.prepare_revocation_results(5).unwrap();
        cpr.set_revocation_source_for_item(0, RevocationSource::StapledOcsp);
        cpr.set_revocation_source_for_item(1, RevocationSource::StapledCrl);
        cpr.set_revocation_source_for_item(2, RevocationSource::OcspFromAia);
        cpr.set_revocation_source_for_item(3, RevocationSource::RemoteCrlDp);
        cpr.set_revocation_source_for_item(4, RevocationSource::NoCheckExtension);

        let outcomes = revocation_outcomes_from_cpr(&cpr, 5);
        assert_eq!(outcomes[0].method, RevocationMethod::StapledOcsp);
        assert_eq!(outcomes[1].method, RevocationMethod::StapledCrl);
        assert_eq!(outcomes[2].method, RevocationMethod::OcspFromAia);
        assert_eq!(outcomes[3].method, RevocationMethod::RemoteCrlDp);
        assert_eq!(outcomes[4].method, RevocationMethod::OcspNoCheck);
        assert_eq!(outcomes[4].status, RevocationStatus::NotChecked);
    }

    /// A position with neither a recorded source nor an artifact is undetermined, and says so.
    #[test]
    #[cfg(feature = "revocation")]
    fn revocation_outcomes_report_unsettled_positions_as_undetermined() {
        let mut cpr = CertificationPathResults::new();
        cpr.prepare_revocation_results(3).unwrap();
        cpr.add_crl(crl_marker(), 0);
        cpr.set_revocation_source_for_item(0, RevocationSource::LocalCrl);
        cpr.set_validation_status(PathValidationStatus::RevocationStatusNotDetermined);
        cpr.set_failure_index(2);

        let outcomes = revocation_outcomes_from_cpr(&cpr, 3);
        assert_eq!(outcomes[0].method, RevocationMethod::LocalCrl);
        assert_eq!(outcomes[1].method, RevocationMethod::None);
        assert_eq!(outcomes[1].status, RevocationStatus::Undetermined);
        assert_eq!(outcomes[2].method, RevocationMethod::None);
    }

    #[test]
    #[cfg(feature = "revocation")]
    fn revocation_outcomes_revoked_at_failure_index() {
        let mut cpr = CertificationPathResults::new();
        cpr.prepare_revocation_results(2).unwrap();
        cpr.add_crl(crl_marker(), 0);
        cpr.add_crl(crl_marker(), 1);
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

    /// A report assembled from accumulated targets has no run to wall-clock, but every path it
    /// carries reports what it took. Summing those is what keeps the header honest: the browser
    /// showed `0 ms` beside paths reporting 8 and 19 ms, which reads as a broken clock rather than
    /// an absent one. The sum also has to grow as targets accumulate, since that is precisely the
    /// case this constructor exists for.
    #[test]
    fn from_targets_sums_the_durations_the_paths_report() {
        let path = |ms| PathReport {
            status: Some(PathValidationStatus::Valid),
            duration_ms: ms,
            ..Default::default()
        };
        let target = |paths: Vec<PathReport>| TargetReport {
            name: "t".to_string(),
            target: None,
            status: TargetStatus::Valid,
            paths,
            no_paths_hints: vec![],
            error: None,
        };

        let one = target(vec![path(8), path(19)]);
        let report = ValidationReport::from_targets(core::slice::from_ref(&one), 0);
        assert_eq!(27, report.duration_ms);
        assert_eq!(2, report.totals.paths_found);

        // A second target accumulating into the same view adds its paths' time to the total.
        let two = target(vec![path(5)]);
        let report = ValidationReport::from_targets(&[one, two], 0);
        assert_eq!(32, report.duration_ms);

        // No paths is the one case where zero is the truth.
        assert_eq!(
            0,
            ValidationReport::from_targets(&[target(vec![])], 0).duration_ms
        );
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
