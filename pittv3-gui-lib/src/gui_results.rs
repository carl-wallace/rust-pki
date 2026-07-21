//! Renderer-agnostic components for displaying a
//! [`ValidationReport`](pittv3_lib::report::ValidationReport) produced by a validation run.
//!
//! These components are feature-free so that every GUI frontend (desktop WebView, web) can share
//! them; file system access and run orchestration remain with the frontends.

use dioxus::prelude::*;

use certval::TimeOfInterest;
use pittv3_lib::report::{
    PathReport, ProgressEvent, RevocationMethod, RevocationOutcome, RevocationStatus, TargetReport,
    TargetStatus, ValidationReport,
};

/// Events conveyed from a validation run to the UI. Frontends send these over a channel from
/// whatever context executes the run and consume them on the UI side to update signals.
#[derive(Clone, Debug, PartialEq)]
pub enum RunEvent {
    /// A progress event emitted while the run advances
    Progress(ProgressEvent),
    /// The run completed and produced a report
    Done(Box<ValidationReport>),
    /// The run failed before producing a report
    Failed(String),
}

/// Returns a CSS class and label for a target status badge
fn status_parts(status: TargetStatus) -> (&'static str, &'static str) {
    match status {
        TargetStatus::Valid => ("badge badge-valid", "Valid"),
        TargetStatus::ValidExceptRevocationUndetermined => (
            "badge badge-undetermined",
            "Valid (revocation undetermined)",
        ),
        TargetStatus::Revoked => ("badge badge-revoked", "Revoked"),
        TargetStatus::Invalid => ("badge badge-invalid", "Invalid"),
        TargetStatus::NoPathsFound => ("badge badge-nopaths", "No paths found"),
    }
}

/// Renders a time of interest as a human-readable string
fn human_toi(toi: u64) -> String {
    if toi == 0 {
        return "disabled".to_string();
    }
    match TimeOfInterest::from_unix_secs(toi) {
        Ok(t) => t.to_string(),
        Err(_e) => toi.to_string(),
    }
}

/// Status badge for a target certificate
#[component]
pub fn StatusBadge(status: TargetStatus) -> Element {
    let (class, label) = status_parts(status);
    rsx! {
        span { class, "{label}" }
    }
}

/// Badge conveying the revocation outcome for one certificate in a path
#[component]
pub fn RevocationBadge(outcome: RevocationOutcome) -> Element {
    let method = match outcome.method {
        RevocationMethod::OcspNoCheck => "OCSP no-check",
        RevocationMethod::Crl => "CRL",
        RevocationMethod::Ocsp => "OCSP",
        RevocationMethod::Blocklist => "blocklist",
        RevocationMethod::Allowlist => "allowlist",
        RevocationMethod::None => "none",
    };
    let (class, label) = match outcome.status {
        RevocationStatus::NotRevoked => ("badge badge-valid", "not revoked"),
        RevocationStatus::Revoked => ("badge badge-revoked", "revoked"),
        RevocationStatus::Undetermined => ("badge badge-undetermined", "undetermined"),
        RevocationStatus::NotChecked => ("badge badge-nopaths", "not checked"),
    };
    rsx! {
        span { class, title: "Method: {method}", "{label} ({method})" }
    }
}

/// Details for one certification path: certificate chain table (trust-anchor first), per-cert
/// revocation outcomes, failure information and policy outputs
#[component]
pub fn PathDetail(path: PathReport, path_index: usize) -> Element {
    let status_text = match (&path.status, &path.error) {
        (Some(status), _) => format!("{status:?}"),
        (None, Some(_e)) => "Not recorded".to_string(),
        (None, None) => "Not recorded".to_string(),
    };
    let failed = path.error.is_some();
    let cert_count = path.certs.len();
    rsx! {
        div { class: "path-detail",
            div { class: "path-head",
                strong { "Path {path_index + 1}" }
                span { class: "hint", " {cert_count} certificate(s), {path.duration_ms} ms" }
                span { class: if failed { "badge badge-invalid" } else { "badge badge-valid" },
                    "{status_text}"
                }
            }
            if let Some(error) = path.error.clone() {
                p { class: "path-error", "Error: {error}" }
            }
            if !path.failure_reasons.is_empty() {
                ul { class: "failure-reasons",
                    for reason in path.failure_reasons.iter() {
                        li { "{reason}" }
                    }
                }
            }
            table { class: "cert-table",
                thead {
                    tr {
                        th { "#" }
                        th { "Subject" }
                        th { "Serial" }
                        th { "Not Before" }
                        th { "Not After" }
                        th { "Revocation" }
                    }
                }
                tbody {
                    for (i , cert) in path.certs.iter().enumerate() {
                        tr {
                            class: if path.failure_index == Some(i) { "row-failure" } else { "" },
                            td {
                                if i == 0 {
                                    "TA"
                                } else {
                                    "{i}"
                                }
                            }
                            td { title: cert.issuer.clone().unwrap_or_default(), "{cert.subject}" }
                            td { class: "mono", {cert.serial.clone().unwrap_or_else(|| "—".to_string())} }
                            td { {cert.not_before.clone().unwrap_or_else(|| "—".to_string())} }
                            td { {cert.not_after.clone().unwrap_or_else(|| "—".to_string())} }
                            td {
                                if let Some(outcome) = path.revocation.iter().find(|o| o.cert_index == i) {
                                    RevocationBadge { outcome: outcome.clone() }
                                } else {
                                    "—"
                                }
                            }
                        }
                    }
                }
            }
            if let Some(policy) = path.policy.clone() {
                div { class: "policy-outcome",
                    strong { "Policy outputs: " }
                    if policy.final_valid_policies.is_empty() {
                        span { "no valid policies" }
                    } else {
                        span { class: "mono", {policy.final_valid_policies.join(", ")} }
                    }
                    span { class: "hint",
                        " (explicit_policy: {opt_u32(policy.final_explicit_policy)}, "
                        "policy_mapping: {opt_u32(policy.final_policy_mapping)}, "
                        "inhibit_anyPolicy: {opt_u32(policy.final_inhibit_any_policy)})"
                    }
                }
            }
        }
    }
}

/// Renders an optional u32 as a string, with an em dash for None
fn opt_u32(v: Option<u32>) -> String {
    match v {
        Some(v) => v.to_string(),
        None => "—".to_string(),
    }
}

/// Accordion card for one target certificate: status badge summary plus per-path details
#[component]
pub fn TargetCard(target: TargetReport, #[props(default)] open: bool) -> Element {
    let path_count = target.paths.len();
    let subject = target
        .target
        .as_ref()
        .map(|t| t.subject.clone())
        .unwrap_or_default();
    rsx! {
        details { class: "target-card", open,
            summary {
                StatusBadge { status: target.status }
                span { class: "target-name", " {target.name}" }
                if !subject.is_empty() {
                    span { class: "hint", " — {subject}" }
                }
                span { class: "hint", " ({path_count} path(s))" }
            }
            if target.paths.is_empty() {
                p { class: "hint",
                    "No certification paths were processed for this target."
                }
            }
            for (i , path) in target.paths.iter().enumerate() {
                PathDetail { path: path.clone(), path_index: i }
            }
        }
    }
}

/// Summary strip plus per-target accordion for an entire validation run
#[component]
pub fn ResultsView(report: ValidationReport) -> Element {
    let totals = &report.totals;
    let toi = human_toi(report.time_of_interest);
    let single_target = report.targets.len() == 1;
    rsx! {
        div { class: "results-view",
            div { class: "results-summary",
                span { "Targets: {totals.targets}" }
                span { "Paths found: {totals.paths_found}" }
                span { class: "summary-valid", "Valid: {totals.valid_paths}" }
                span { class: "summary-invalid", "Invalid: {totals.invalid_paths}" }
                span { class: "hint", "Time of interest: {toi}" }
                span { class: "hint", "{report.duration_ms} ms" }
            }
            if report.targets.is_empty() {
                p { class: "hint",
                    "No validation targets were processed (generation, cleanup, diagnostics and "
                    "tool actions do not produce validation results)."
                }
            }
            for target in report.targets.iter() {
                TargetCard { target: target.clone(), open: single_target }
            }
        }
    }
}

/// Compact progress line for a validation run in flight, fed by [`ProgressEvent`] instances
#[component]
pub fn ProgressLine(events: Vec<ProgressEvent>) -> Element {
    let completed = events
        .iter()
        .filter(|e| matches!(e, ProgressEvent::TargetCompleted { .. }))
        .count();
    let latest = events.iter().rev().find_map(|e| match e {
        ProgressEvent::TargetStarted { name, .. } => Some(name.clone()),
        _ => None,
    });
    rsx! {
        div { class: "progress-line",
            span { class: "spinner" }
            span { " Running… {completed} target(s) completed" }
            if let Some(latest) = latest {
                span { class: "hint", " — processing {latest}" }
            }
        }
    }
}
