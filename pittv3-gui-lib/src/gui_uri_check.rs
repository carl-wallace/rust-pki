//! Rendering for a "Check URIs in certificate" report, shared by the frontends.
//!
//! Only the *results* are shared, deliberately. How a certificate is chosen differs in kind between
//! the frontends — the desktop names a file on disk, the browser is handed one by a file input and
//! has no path to read — and so does how the check reaches a repository, which is an HTTP client in
//! one and a relay in the other. Forcing a single dialog over those would mean inventing an
//! abstraction over the filesystem to share some chrome. What is genuinely the same is the grid: the
//! same columns, the same taxonomy, the same colours, so a result means one thing wherever it is
//! read.

use dioxus::prelude::*;

use pittv3_lib::uri_check::{UriCheckReport, UriStatus};

/// CSS class selecting the colour for a URI-check result, reusing the validation badge palette so a
/// green here means what a green means on a path.
pub fn uri_status_class(status: UriStatus) -> &'static str {
    match status {
        UriStatus::CorrectData => "badge-valid",
        UriStatus::IncorrectData
        | UriStatus::UnknownAccessMethod
        | UriStatus::ResponderCertPolicyError => "badge-invalid",
        UriStatus::NotAvailable | UriStatus::BlacklistedHost => "badge-revoked",
        UriStatus::Warning
        | UriStatus::WarningMissingAia
        | UriStatus::WarningMissingCrlDp
        | UriStatus::CrlNotCheckedNoIssuerCert => "badge-undetermined",
    }
}

/// The results of one URI check: what was checked, against which issuer, and a row per URI.
///
/// An empty result set is reported as such rather than left blank — a certificate naming no URIs is
/// a finding, not an absence of one, and the taxonomy has entries for exactly that case.
#[component]
pub fn UriCheckResults(report: UriCheckReport) -> Element {
    rsx! {
        div { class: "uri-results",
            p { class: "results-summary", "Target: {report.target.subject}" }
            if let Some(issuer) = &report.issuer {
                p { class: "results-summary",
                    if report.issuer_auto_discovered {
                        "Issuer (auto-discovered): {issuer.subject}"
                    } else {
                        "Issuer: {issuer.subject}"
                    }
                }
            }
            if let Some(err) = &report.error {
                p { class: "badge badge-invalid", "{err}" }
            } else if report.results.is_empty() {
                p { class: "hint", "No URIs found to check." }
            } else {
                table { class: "cert-table",
                    thead {
                        tr {
                            th { "URI" }
                            th { "Result" }
                            th { "Timing (ms)" }
                            th { "Extension" }
                        }
                    }
                    tbody {
                        for r in report.results.iter() {
                            tr {
                                td { "{r.uri}" }
                                td {
                                    span { class: "badge {uri_status_class(r.status)}",
                                        "{r.status.label()}"
                                    }
                                }
                                td { "{r.timing_ms}" }
                                td { "{r.extension.label()}" }
                            }
                        }
                    }
                }
            }
        }
    }
}
