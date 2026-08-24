//! Renderer-agnostic components for displaying a
//! [`ValidationReport`] produced by a validation run.
//!
//! These components are feature-free so that every GUI frontend (desktop WebView, web) can share
//! them; file system access and run orchestration remain with the frontends.

use dioxus::prelude::*;

use certval::{NameConstraintsSettings, TimeOfInterest};
use pittv3_lib::report::{
    PathReport, ProgressEvent, RevocationMethod, RevocationOutcome, RevocationStatus, TargetReport,
    TargetStatus, ValidationReport,
};

/// A line of validation output along with a CSS class used to render it, i.e., "ok", "err" or
/// "info".
///
/// This is the running commentary a frontend shows alongside a run — notes, warnings and the
/// per-step narration — and is distinct from [`ValidationReport`], which is the structured result
/// [`ResultsView`] renders. A line is for reading; the report is for inspecting, serializing and
/// downloading.
#[derive(Clone, Debug)]
pub struct ResultLine {
    /// CSS class: "ok", "err" or "info"
    pub class: &'static str,
    /// Text to display
    pub text: String,
}

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
        // Where the answer came from, not just what kind of answer it was. A response the run was
        // given and one it fetched from an AIA are both "OCSP" but say different things about what
        // the run did, and a cached determination examined nothing at all this time. Someone
        // judging a result should be able to see which of those happened.
        //
        // "supplied" rather than "stapled" because stapled is certval's word for the slot, not a
        // description of what happened: nobody stapled anything. The frontend put it there, having
        // read it from a file, retrieved it through a relay, or been handed it with the request --
        // and that slot is the only way a response reaches the checker at all.
        RevocationMethod::Cache => "cache",
        RevocationMethod::StapledOcsp => "OCSP (supplied)",
        RevocationMethod::StapledCrl => "CRL (supplied)",
        RevocationMethod::LocalCrl => "local CRL",
        RevocationMethod::OcspFromAia => "OCSP (AIA)",
        RevocationMethod::RemoteCrlDp => "CRL (DP)",
        RevocationMethod::None => "none",
    };
    let (class, label) = match outcome.status {
        RevocationStatus::NotRevoked => ("badge badge-valid", "not revoked"),
        RevocationStatus::Revoked => ("badge badge-revoked", "revoked"),
        RevocationStatus::Undetermined => ("badge badge-undetermined", "undetermined"),
        RevocationStatus::NotChecked => ("badge badge-nopaths", "not checked"),
    };
    // The method sits beside the badge rather than inside it. A badge is a pill, and a pill has to
    // stay on one line to keep its shape -- "not revoked (OCSP no-check)" in the narrow revocation
    // column of a table whose cells break anywhere did not, and wrapped into its own rounded
    // corners. Outside it, the status stays one line and the method is free to wrap beneath.
    //
    // A method of `None` is not shown at all: it says only that nothing determined the status,
    // which is what the badge beside it already says.
    let show_method = !matches!(outcome.method, RevocationMethod::None);
    rsx! {
        span { class: "rev-outcome",
            span { class, title: "Method: {method}", "{label}" }
            if show_method {
                span { class: "rev-method", "{method}" }
            }
        }
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
                                // Slot 0 is the trust anchor unless the producer says it is not;
                                // assuming it always was is how an expired end entity came to be
                                // labelled one.
                                if i == 0 && path.no_anchor {
                                    "EE"
                                } else if i == 0 {
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
            if let Some(nc) = path.name_constraints.clone() {
                {
                    let permitted = nc_rows(&nc.permitted);
                    let excluded = nc_rows(&nc.excluded);
                    rsx! {
                        div { class: "name-constraints-outcome",
                            strong { "Name constraints: " }
                            div { class: "nc-group",
                                span { class: "nc-label", "Permitted: " }
                                if permitted.is_empty() {
                                    span { class: "hint", "unconstrained" }
                                } else {
                                    for (label , text) in permitted.iter() {
                                        span { key: "{label}", class: "nc-form",
                                            "{label}: "
                                            span { class: "mono", "{text}" }
                                        }
                                    }
                                }
                            }
                            div { class: "nc-group",
                                span { class: "nc-label", "Excluded: " }
                                if excluded.is_empty() {
                                    span { class: "hint", "none" }
                                } else {
                                    for (label , text) in excluded.iter() {
                                        span { key: "{label}", class: "nc-form",
                                            "{label}: "
                                            span { class: "mono", "{text}" }
                                        }
                                    }
                                }
                            }
                        }
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

/// Flattens the set name forms of a [`NameConstraintsSettings`] into (label, value) rows for display,
/// one row per form that carries a constraint. A form set to `Some(vec![])` (a permitted set that
/// intersected to empty, i.e., nothing permitted) renders as `∅`; an unconstrained (`None`) form is
/// omitted entirely.
fn nc_rows(s: &NameConstraintsSettings) -> Vec<(&'static str, String)> {
    fn push_form(
        rows: &mut Vec<(&'static str, String)>,
        label: &'static str,
        field: &Option<Vec<String>>,
    ) {
        if let Some(vals) = field {
            let text = if vals.is_empty() {
                "∅".to_string()
            } else {
                vals.join(", ")
            };
            rows.push((label, text));
        }
    }
    let mut rows = vec![];
    push_form(&mut rows, "DNS", &s.dns_name);
    push_form(&mut rows, "Email", &s.rfc822_name);
    push_form(&mut rows, "Directory", &s.directory_name);
    push_form(&mut rows, "URI", &s.uniform_resource_identifier);
    push_form(&mut rows, "IP", &s.ip_address);
    push_form(&mut rows, "Other", &s.not_supported);
    rows
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
            // A zero-path outcome describes the run's inputs rather than the certificate, so the
            // reasons belong on the card itself: there is no path row for them to hang off.
            if !target.no_paths_hints.is_empty() {
                ul { class: "no-paths-hints",
                    for hint in target.no_paths_hints.iter() {
                        li { "{hint}" }
                    }
                }
            }
            for (i , path) in target.paths.iter().enumerate() {
                PathDetail { path: path.clone(), path_index: i }
            }
        }
    }
}

/// Counts the targets in each status, as (badge class, label, count) rows ordered as the statuses
/// are declared and omitting those that did not occur.
///
/// The run totals count *paths*, and a target with several paths, or with none, contributes a
/// different number to each — so the strip cannot answer "how many of my certificates were good?"
/// from them. Counting the target cards is the only place that answer exists.
fn target_status_counts(targets: &[TargetReport]) -> Vec<(&'static str, &'static str, usize)> {
    let statuses = [
        TargetStatus::Valid,
        TargetStatus::ValidExceptRevocationUndetermined,
        TargetStatus::Revoked,
        TargetStatus::Invalid,
        TargetStatus::NoPathsFound,
    ];
    statuses
        .iter()
        .filter_map(|status| {
            let count = targets.iter().filter(|t| t.status == *status).count();
            if 0 == count {
                return None;
            }
            let (class, label) = status_parts(*status);
            Some((class, label, count))
        })
        .collect()
}

/// Summary strip plus per-target accordion for an entire validation run
#[component]
pub fn ResultsView(report: ValidationReport) -> Element {
    let totals = &report.totals;
    let toi = human_toi(report.time_of_interest);
    let single_target = report.targets.len() == 1;
    let by_status = target_status_counts(&report.targets);
    rsx! {
        div { class: "results-view",
            div { class: "results-summary summary-targets",
                span { "Targets: {totals.targets}" }
                for (class , label , count) in by_status.iter() {
                    span { key: "{label}", class: "{class}", "{label}: {count}" }
                }
            }
            // Paths are counted separately from targets because they do not correspond: a target
            // can yield several paths or none at all.
            div { class: "results-summary",
                span { "Paths found: {totals.paths_found}" }
                span { class: "summary-valid", "Valid paths: {totals.valid_paths}" }
                span { class: "summary-invalid", "Invalid paths: {totals.invalid_paths}" }
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
