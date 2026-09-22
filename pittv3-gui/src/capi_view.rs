//! Windows-only: the CAPI results pane.
//!
//! Renders a [`CapiRunResult`] in CAPI's own vocabulary. Nothing here maps a chain engine verdict
//! onto certval's — see `pittv3_capi::types` for why — so what a reader sees is what Windows said,
//! in the words Windows said it, laid out the way the rest of the application lays out a run.
//!
//! # Why this is not in `pittv3-gui-lib`
//!
//! The shared component crate is built by the browser frontend too, which has no chain engine to
//! show results from. A `CapiRunResult` cannot exist there, so the pane would be dead weight in
//! every wasm bundle and would drag `pittv3-capi` into a dependency graph that has no use for it.
//!
//! # Styling
//!
//! Existing classes wherever the application already has one — `target-card`, `cert-table`,
//! `badge badge-valid`, `results-summary`, `mono` — so the pane is recognizably the same
//! application rather than a second one bolted on. Only what CAPI needs and certval has no
//! counterpart for is new, and that lives in [`CAPI_CSS`] rather than in the shared stylesheet:
//! `pittv3.css` is shipped by both frontends, and a Windows-only pane has no business widening it.

use dioxus::prelude::*;

use pittv3_capi::{CapiChain, CapiElement, CapiVerification};

use crate::capi_run::{blame, CapiRunResult, CapiTargetOutcome, EffectiveTrust};

/// Styles for the parts of a CAPI verdict the application has no existing class for.
///
/// Kept deliberately small. Anything a certval result also has is drawn with the class the certval
/// results view already uses, so the two panes cannot drift apart visually while claiming to be two
/// views of one run.
pub const CAPI_CSS: &str = r#"
.capi-trust {
  display: flex;
  align-items: flex-start;
  gap: 0.6rem;
  padding: 0.5rem 0.7rem;
  border: 1px solid var(--border);
  border-radius: 6px;
  margin-bottom: 0.5rem;
}
.capi-trust-ok { border-color: #15803d; background: color-mix(in srgb, #15803d 8%, transparent); }
.capi-trust-info { border-color: #1d4ed8; background: color-mix(in srgb, #1d4ed8 8%, transparent); }
.capi-trust-warn { border-color: #b45309; background: color-mix(in srgb, #b45309 12%, transparent); }
.capi-trust-what { font-weight: 600; }
.capi-trust-how { color: var(--muted); margin-top: 0.1rem; }
.capi-chip {
  display: inline-block;
  padding: 0.05rem 0.35rem;
  border-radius: 4px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.72rem;
  margin: 0.08rem 0.12rem 0.08rem 0;
  white-space: nowrap;
}
.capi-chip-err { background: color-mix(in srgb, #b91c1c 16%, transparent); color: #8a1c14; }
.capi-chip-info { background: color-mix(in srgb, #6b7280 18%, transparent); }
.capi-chip-unknown { background: color-mix(in srgb, #b45309 22%, transparent); color: #7a4a08; }
@media (prefers-color-scheme: dark) {
  .capi-chip-err { color: #fca5a5; }
  .capi-chip-unknown { color: #fcd34d; }
}
.capi-policy {
  border-left: 3px solid #b91c1c;
  padding: 0.35rem 0.6rem;
  margin: 0.35rem 0;
  background: color-mix(in srgb, #b91c1c 8%, transparent);
}
.capi-chain-head {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.4rem;
  margin-top: 0.4rem;
}
.capi-order { color: var(--muted); font-size: 0.75rem; margin-left: auto; }
.capi-lower { margin-top: 0.4rem; }
.capi-lower > summary { color: var(--muted); cursor: pointer; }
"#;

/// The `CERT_TRUST_` every flag name carries, dropped for display.
///
/// The prefix is on all of them and distinguishes nothing; dropping it is what lets a row of flags
/// read as a row rather than as a wall. The log keeps the full names, because a line someone
/// pastes into a search engine or a bug report should carry the name Windows documents.
fn short_flag(name: &str) -> &str {
    name.strip_prefix("CERT_TRUST_").unwrap_or(name)
}

/// The badge class and word for one target's outcome.
///
/// Revoked is called out from merely invalid because it is the answer people come to this tool
/// for. Read off the flag table rather than a literal bit, so the one definition of the flag stays
/// the one definition.
fn target_badge(
    outcome: &Result<CapiVerification, pittv3_capi::CapiVerifyError>,
) -> (&'static str, &'static str) {
    match outcome {
        Err(_) => ("badge badge-unreadable", "No verdict"),
        Ok(v) if v.validated => ("badge badge-valid", "Valid"),
        Ok(v) => {
            let revoked = v.chains.iter().any(|c| {
                c.elements.iter().any(|e| {
                    e.trust_status
                        .error_names()
                        .contains(&"CERT_TRUST_IS_REVOKED")
                })
            });
            match revoked {
                true => ("badge badge-revoked", "Revoked"),
                false => ("badge badge-invalid", "Invalid"),
            }
        }
    }
}

/// The CAPI results pane.
#[component]
pub fn CapiResultsView(result: CapiRunResult) -> Element {
    let valid = result.valid();
    let invalid = result.invalid();
    let refused = result.refused();

    rsx! {
        style { dangerous_inner_html: CAPI_CSS }
        div { class: "inspect-report",
            TrustBanner { result: result.clone() }

            div { class: "results-summary",
                span { strong { "{result.targets.len()}" } " target(s)" }
                span { class: "summary-valid", "{valid} valid" }
                span { class: "summary-invalid", "{invalid} invalid" }
                if refused > 0 {
                    span { "{refused} with no verdict" }
                }
                if let Some(secs) = result.time_of_interest {
                    span {
                        "as at "
                        span { class: "mono",
                            {pittv3_capi::unix_secs_to_string(secs as i64).unwrap_or_else(|| secs.to_string())}
                        }
                    }
                }
                span {
                    if result.revocation_checked {
                        "revocation checked below the root"
                    } else {
                        "revocation not checked"
                    }
                }
            }

            if result.targets.is_empty() {
                p { class: "hint", "Nothing to validate: the end entity list held no certificates." }
            }

            for target in result.targets.iter() {
                TargetCard { target: target.clone() }
            }
        }
    }
}

/// Where this run's trust came from. The one fact every verdict below depends on, so it is a band
/// across the top rather than a line in the log.
///
/// The first line is the trust set and the state of the checkbox that chose it; the second is what
/// else the run put in front of the builder. Keeping those apart is what stops the banner reading
/// as one run of clauses: the checkbox belongs to the sentence about trust, and the supporting
/// certificates are a separate fact about a separate input.
#[component]
fn TrustBanner(result: CapiRunResult) -> Element {
    // Three of the four states are only ever reached with the checkbox on; `MachineStores` is the
    // one it produces when off. Derived rather than passed in, so the banner cannot disagree with
    // the run it is describing.
    let checkbox = match result.trust {
        EffectiveTrust::MachineStores => "checkbox off",
        _ => "checkbox on",
    };

    let class = match result.trust {
        EffectiveTrust::RunAnchors(_) => "capi-trust capi-trust-ok",
        EffectiveTrust::CapiStoresAreTheRunsTrust => "capi-trust capi-trust-info",
        EffectiveTrust::MachineStores => "capi-trust",
        EffectiveTrust::NoAnchorsToUse => "capi-trust capi-trust-warn",
    };

    // The second line: what else went into the mix, and -- for the two states that need it -- why
    // the trust set is what it is. Left empty when there is nothing to add, so a run with no
    // supporting material shows one line rather than one line and a stranded zero: "0 supporting
    // certificate(s)" reads as though something went missing, which for a Windows store selection
    // is exactly backwards.
    let mut detail = match result.trust {
        EffectiveTrust::CapiStoresAreTheRunsTrust => "The store selector names Windows \
             certificate stores, so the checkbox makes no difference here."
            .to_string(),
        EffectiveTrust::NoAnchorsToUse => {
            "No trust anchors were gathered from this run, so the \
             verdicts below are this machine's and are the same answer the checkbox off would give."
                .to_string()
        }
        _ => String::new(),
    };
    if result.supporting_count > 0 {
        if !detail.is_empty() {
            detail.push(' ');
        }
        detail.push_str(&format!(
            "{} supporting certificate(s) offered to the builder.",
            result.supporting_count
        ));
    }

    rsx! {
        div { class,
            div { style: "flex-grow: 1;",
                div { class: "capi-trust-what",
                    "Validated against {result.trust_summary()} ({checkbox})"
                }
                if !detail.is_empty() {
                    div { class: "capi-trust-how", "{detail}" }
                }
                // Only on the state that warns, and only when there were inputs to name: the
                // difference between "no store was selected" and "the store selected yielded
                // nothing" is the difference between two fixes.
                if result.fell_back() && !result.anchor_sources.is_empty() {
                    div { class: "capi-trust-how",
                        "Anchor inputs consulted, none of which yielded a certificate: "
                        span { class: "mono", "{result.anchor_sources.join(\", \")}" }
                    }
                }
                if result.fell_back() && result.anchor_sources.is_empty() {
                    div { class: "capi-trust-how",
                        "No anchor inputs were named — select a store, or add trust anchors on the Validate view, to compare like for like."
                    }
                }
            }
        }
    }
}

/// One target, its verdict and the chains the engine built for it.
#[component]
fn TargetCard(target: CapiTargetOutcome) -> Element {
    let (badge_class, badge_label) = target_badge(&target.outcome);

    rsx! {
        details { class: "target-card", open: true,
            summary {
                span { class: badge_class, "{badge_label}" }
                span { class: "target-name",
                    match &target.outcome {
                        Ok(v) => match &v.target {
                            Some(cert) => cert.subject.clone(),
                            // CAPI accepting bytes certval will not parse is a finding, not a gap
                            // to paper over with the file name.
                            None => "CAPI accepted bytes that certval would not parse".to_string(),
                        },
                        Err(_) => target.label.clone(),
                    }
                }
            }

            div { class: "mono hint", "{target.label}" }

            match &target.outcome {
                Err(e) => rsx! {
                    p { class: "path-error", "The chain engine gave no verdict: {e}" }
                },
                Ok(verification) => rsx! {
                    if let Some(err) = &verification.policy_error {
                        div { class: "capi-policy",
                            span { class: "mono", "{err.name().unwrap_or(\"policy error\")}" }
                            " "
                            span { class: "mono hint", {format!("0x{:08X}", err.0)} }
                            {blame(verification)}
                            div { {err.message().unwrap_or("No description for this code in this build.")} }
                        }
                    }

                    for chain in verification.chains.iter().filter(|c| !c.lower_quality) {
                        ChainTable { chain: chain.clone() }
                    }

                    {
                        let lower: Vec<CapiChain> = verification
                            .chains
                            .iter()
                            .filter(|c| c.lower_quality)
                            .cloned()
                            .collect();
                        (!lower.is_empty()).then(|| rsx! {
                            details { class: "capi-lower",
                                summary { "{lower.len()} lower-quality chain(s) the engine built and did not prefer" }
                                for chain in lower.iter() {
                                    ChainTable { chain: chain.clone() }
                                }
                            }
                        })
                    }
                },
            }
        }
    }
}

/// One chain: its own trust status, then a row per certificate.
#[component]
fn ChainTable(chain: CapiChain) -> Element {
    rsx! {
        div { class: "path-detail",
            div { class: "capi-chain-head",
                strong { "Chain {chain.index}" }
                span {
                    class: if chain.lower_quality { "badge badge-nopaths" } else { "badge badge-valid" },
                    if chain.lower_quality { "lower quality" } else { "preferred" }
                }
                span { class: "hint", "{chain.elements.len()} certificate(s)" }
                FlagChips { status: chain.trust_status, errors_only: true }
                // CAPI orders a chain from the target outward; certval orders one from the anchor
                // down. Stated rather than corrected -- reversing would line the two up on screen
                // at the cost of not reporting what the engine returned.
                span { class: "capi-order", "target \u{2192} root (CAPI order)" }
            }

            table { class: "cert-table",
                thead {
                    tr {
                        th { "#" }
                        th { "Certificate" }
                        th { "Element status" }
                        th { "Revocation" }
                    }
                }
                tbody {
                    for (i , element) in chain.elements.iter().enumerate() {
                        ElementRow { index: i, element: element.clone() }
                    }
                }
            }
        }
    }
}

/// One certificate within a chain.
#[component]
fn ElementRow(index: usize, element: CapiElement) -> Element {
    let failed = !element.trust_status.is_ok();
    rsx! {
        tr { class: if failed { "row-failure" } else { "" },
            td { "{index}" }
            td {
                match &element.cert {
                    Some(cert) => rsx! {
                        div { "{cert.subject}" }
                        if let Some(serial) = &cert.serial {
                            div { class: "mono hint", "serial {serial}" }
                        }
                    },
                    None => rsx! {
                        div { class: "hint", "not parseable by certval" }
                    },
                }
                FlagChips { status: element.trust_status, errors_only: false }
            }
            td {
                if element.trust_status.is_ok() {
                    "no errors"
                } else {
                    FlagChips { status: element.trust_status, errors_only: true }
                }
            }
            td {
                match &element.revocation {
                    None => rsx! { span { class: "hint", "not checked" } },
                    Some(rev) => rsx! {
                        span {
                            class: if rev.is_ok() { "badge badge-valid" } else { "badge badge-undetermined" },
                            if rev.is_ok() { "Good" } else { "Not determined" }
                        }
                        if !rev.is_ok() {
                            div { class: "hint", "{rev.describe()}" }
                        }
                        if let Some(crl) = &rev.crl {
                            if let Some(issuer) = &crl.issuer {
                                // Windows fills this from an OCSP response as well as from a CRL,
                                // so it is named for what it is rather than as a CRL issuer: a DoD
                                // run puts an OCSP responder's name here.
                                div { class: "hint", "source: {issuer}" }
                            }
                            if let Some(entry) = &crl.entry {
                                div { class: "hint",
                                    "revoked: serial "
                                    span { class: "mono", "{entry.serial}" }
                                    " on {entry.revocation_date.clone().unwrap_or_else(|| \"unknown date\".to_string())}"
                                }
                            }
                        }
                    },
                }
            }
        }
    }
}

/// A status's flags as chips.
///
/// `errors_only` draws the error mask; otherwise the information mask, which is how a reader tells
/// *why* the engine assembled the chain it did. Unnamed bits get a chip of their own rather than
/// being dropped, so a flag Windows adds after this build cannot read as a clean result.
#[component]
fn FlagChips(status: pittv3_capi::CapiTrustStatus, errors_only: bool) -> Element {
    let (names, unknown, class) = match errors_only {
        true => (
            status.error_names(),
            status.unknown_error_bits(),
            "capi-chip capi-chip-err",
        ),
        false => (
            status.info_names(),
            status.unknown_info_bits(),
            "capi-chip capi-chip-info",
        ),
    };

    rsx! {
        for name in names.iter() {
            span { class, title: "{name}", "{short_flag(name)}" }
        }
        if unknown != 0 {
            span {
                class: "capi-chip capi-chip-unknown",
                title: "A bit this build has no name for, reported rather than dropped.",
                {format!("unrecognized 0x{unknown:08X}")}
            }
        }
    }
}
