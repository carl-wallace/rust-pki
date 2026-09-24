//! Windows-only: the CAPI results pane.
//!
//! Renders a [`CapiRunResult`] laid out the way the rest of the application lays out a run.
//!
//! # Two vocabularies, and which one is shared
//!
//! Windows' own words are never translated. Every flag is reported under the name Windows documents
//! it by, the policy check's `HRESULT` under its own, and a chain in the order the engine returned
//! it. `pittv3_capi::types` says why and it still holds: `CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT`
//! has no `PathValidationStatus` to be, and inventing one would put a fabricated answer in a column
//! of a comparison.
//!
//! The summary badge is a different thing and is shared. It is not a translation of a condition but
//! a rollup of an *outcome* into the six [`TargetStatus`] values, and every CAPI outcome does land
//! in one of the six — the way certval's own `NameConstraintsViolation` lands in `Invalid` without
//! that being a loss. Two panes in one tab strip, describing one run, that give the same outcome
//! different words and different colours defeat the comparison this application exists to make: a
//! reader flipping between the tabs reads a difference in rendering as a difference in validation.
//! So the rollup is drawn with [`status_parts`], which is the certval pane's own definition, and the
//! flags that produced it sit underneath in Windows' words.
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

use pittv3_capi::{
    CapiChain, CapiElement, CapiError, CapiRevocationInfo, CapiVerification, CapiVerifyError,
};
use pittv3_gui_lib::gui_results::status_parts;
use pittv3_lib::report::TargetStatus;

use crate::capi_run::{
    blame, rollup, rollup_counts, rollup_label, says_revoked, CapiRunResult, CapiTargetOutcome,
    EffectiveTrust, PARTIAL_CHAIN,
};

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
/* Where the engine ranked a chain is not a verdict, so it is deliberately not badge-shaped: an
   outlined pill cannot be misread as the green that means valid or the red that means invalid
   beside it. */
.capi-rank {
  display: inline-block;
  padding: 0.05rem 0.45rem;
  border: 1px solid var(--border);
  border-radius: 999px;
  color: var(--muted);
  font-size: 0.75rem;
  white-space: nowrap;
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

/// The badge class and word for one rollup, including the refusals that have none.
///
/// The word comes from [`rollup_label`], the one definition both surfaces read, so a badge and the
/// log line for the same target cannot differ. Only the colour is this pane's to choose, and for a
/// refusal it is the neutral grey the application already uses for "nothing to report here" — not
/// `badge-unreadable`, which is a claim about the file and would say the wrong thing about a store
/// that would not open.
fn badge_parts(status: Option<TargetStatus>) -> (&'static str, &'static str) {
    let class = match status {
        Some(status) => status_parts(status).0,
        None => "badge badge-nopaths",
    };
    (class, rollup_label(status))
}

/// The badge class and word for one target's outcome.
fn target_badge(
    outcome: &Result<CapiVerification, CapiVerifyError>,
) -> (&'static str, &'static str) {
    badge_parts(rollup(outcome))
}

/// The badge class and word for one element's revocation outcome.
///
/// Three answers, not two. `dwRevocationResult` is zero for a clean check and an `HRESULT`
/// otherwise, and `CRYPT_E_REVOKED` is an `HRESULT` — so keying the badge off "is it zero" put a
/// revoked certificate under the amber word for "could not tell", inside a card whose own header
/// said Revoked. A matched CRL entry counts as well: the engine found the serial, whatever it went
/// on to return.
fn revocation_parts(rev: &CapiRevocationInfo) -> (&'static str, &'static str) {
    if rev.is_ok() {
        return ("badge badge-valid", "not revoked");
    }
    let found_in_crl = rev.crl.as_ref().is_some_and(|crl| crl.entry.is_some());
    match found_in_crl || says_revoked(&CapiError(rev.result)) {
        true => ("badge badge-revoked", "revoked"),
        false => ("badge badge-undetermined", "undetermined"),
    }
}

/// The OCSP OID, the one value Windows documents for `pszRevocationOid`.
const OCSP_OID: &str = "1.3.6.1.5.5.7.48.1";

/// How the status was reached, for the line beside the badge — the counterpart of the method the
/// certval pane prints there.
///
/// Only the OID Windows documents for this field is given a word; anything else is shown as the OID
/// rather than guessed at. The CRL structure is deliberately not used to infer one, because Windows
/// fills it from an OCSP response too, so its presence does not mean a CRL was read.
fn revocation_method(rev: &CapiRevocationInfo) -> Option<String> {
    match rev.oid.as_deref()? {
        OCSP_OID => Some("OCSP".to_string()),
        other => Some(other.to_string()),
    }
}

/// The CAPI results pane.
#[component]
pub fn CapiResultsView(result: CapiRunResult) -> Element {
    let by_status: Vec<(&str, &str, usize)> = rollup_counts(&result.targets)
        .into_iter()
        .map(|(status, count)| {
            let (class, label) = badge_parts(status);
            (class, label, count)
        })
        .collect();

    rsx! {
        style { dangerous_inner_html: CAPI_CSS }
        div { class: "inspect-report",
            TrustBanner { result: result.clone() }

            // Two strips, as the certval pane has: what the targets came to, then the terms the run
            // came to it on. The first is drawn from the same rollup the cards below are, so the
            // count and the card cannot say different things about one target.
            div { class: "results-summary summary-targets",
                span { "Targets: {result.targets.len()}" }
                for (class , label , count) in by_status.iter() {
                    span { key: "{label}", class: "{class}", "{label}: {count}" }
                }
            }

            div { class: "results-summary",
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
                TargetCard { target: target.clone(), revocation_checked: result.revocation_checked }
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
fn TargetCard(
    target: CapiTargetOutcome,
    /// The run's revocation scope, threaded down so a certificate with no outcome can say which
    /// kind of nothing it is. The certval pane's `TargetCard` carries the same for the same reason.
    revocation_checked: bool,
) -> Element {
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
                        ChainTable { chain: chain.clone(), revocation_checked }
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
                                    ChainTable { chain: chain.clone(), revocation_checked }
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
fn ChainTable(chain: CapiChain, revocation_checked: bool) -> Element {
    // The engine was asked for revocation below the root, so the last element of a chain that
    // reached one has no outcome by design rather than by omission. A partial chain ends somewhere
    // that is not a root, so nothing in it is exempt.
    let root_row = match revocation_checked && !chain.trust_status.has_named_error(PARTIAL_CHAIN) {
        true => chain.elements.len().checked_sub(1),
        false => None,
    };
    rsx! {
        div { class: "path-detail",
            div { class: "capi-chain-head",
                strong { "Chain {chain.index}" }
                // The chain's own verdict, on the palette the rest of the application uses for one.
                // Which errors they were is in the chips beside it.
                span {
                    class: if chain.trust_status.is_ok() { "badge badge-valid" } else { "badge badge-invalid" },
                    if chain.trust_status.is_ok() { "no errors" } else { "errors" }
                }
                // Where the engine ranked this chain, which is not a verdict: a preferred chain can
                // be thoroughly broken, and a green badge reading "preferred" said it was not.
                span { class: "capi-rank",
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
                        ElementRow {
                            index: i,
                            element: element.clone(),
                            is_root_row: root_row == Some(i),
                        }
                    }
                }
            }
        }
    }
}

/// One certificate within a chain.
#[component]
fn ElementRow(
    index: usize,
    element: CapiElement,
    /// Whether this is the root of a complete chain in a run that checked revocation below it, and
    /// so has no revocation outcome by design.
    is_root_row: bool,
) -> Element {
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
                    // The root of a complete chain was excluded from checking rather than missed, so
                    // it gets the dash the certval pane leaves on its trust anchor row. Anything
                    // else with no outcome was not looked at, which is a different fact and says so.
                    None if is_root_row => rsx! { "\u{2014}" },
                    None => rsx! {
                        span { class: "badge badge-nopaths", "not checked" }
                    },
                    Some(rev) => {
                        let (badge_class, badge_label) = revocation_parts(rev);
                        let method = revocation_method(rev);
                        rsx! {
                        // The method beside the badge rather than inside it, as the certval pane
                        // does it: a pill has to stay on one line to keep its shape.
                        span { class: "rev-outcome",
                            span { class: badge_class, "{badge_label}" }
                            if let Some(method) = method {
                                span { class: "rev-method", "{method}" }
                            }
                        }
                        // The engine's own sentence, for whatever it said beyond the three-way
                        // answer above.
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
                    }}
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capi_run::tests::faulted;
    use pittv3_capi::{CapiCrlEntry, CapiCrlInfo};

    const REVOKED_BIT: u32 = 0x0000_0004;
    const UNTRUSTED_ROOT: u32 = 0x0000_0020;
    const REVOCATION_UNKNOWN_BIT: u32 = 0x0000_0040;
    const PARTIAL_CHAIN_BIT: u32 = 0x0001_0000;

    const CRYPT_E_REVOKED: u32 = 0x8009_2010;
    const CRYPT_E_NO_REVOCATION_CHECK: u32 = 0x8009_2012;
    const CRYPT_E_REVOCATION_OFFLINE: u32 = 0x8009_2013;

    /// Every rollup is drawn with the certval pane's own class and word. That is the whole point:
    /// one outcome cannot wear two colours across the tab strip.
    #[test]
    fn badges_come_from_the_certval_table() {
        assert_eq!(
            target_badge(&Ok(faulted(0))),
            status_parts(TargetStatus::Valid)
        );
        assert_eq!(
            target_badge(&Ok(faulted(REVOCATION_UNKNOWN_BIT))),
            status_parts(TargetStatus::ValidExceptRevocationUndetermined)
        );
        assert_eq!(
            target_badge(&Ok(faulted(REVOKED_BIT))),
            status_parts(TargetStatus::Revoked)
        );
        assert_eq!(
            target_badge(&Ok(faulted(PARTIAL_CHAIN_BIT))),
            status_parts(TargetStatus::NoPathsFound)
        );
        assert_eq!(
            target_badge(&Ok(faulted(UNTRUSTED_ROOT))),
            status_parts(TargetStatus::Invalid)
        );
        assert_eq!(
            target_badge(&Err(CapiVerifyError::TargetNotParsed(0))),
            status_parts(TargetStatus::ParseError)
        );
    }

    /// A run failure is not a claim about the file, so it does not get the class that makes one.
    #[test]
    fn a_run_failure_is_not_badged_as_an_unreadable_file() {
        let (class, label) = target_badge(&Err(CapiVerifyError::StoreFailed(0)));
        assert_eq!((class, label), ("badge badge-nopaths", "No verdict"));
        assert_ne!(class, status_parts(TargetStatus::ParseError).0);
    }

    /// `dwRevocationResult` is an `HRESULT` and `CRYPT_E_REVOKED` is one, so testing it for zero
    /// put a revoked certificate under the amber word for "could not tell" — inside a card whose
    /// own header said Revoked.
    #[test]
    fn a_revoked_certificate_is_not_undetermined() {
        let revoked = CapiRevocationInfo {
            result: CRYPT_E_REVOKED,
            ..Default::default()
        };
        assert_eq!(
            revocation_parts(&revoked),
            ("badge badge-revoked", "revoked")
        );

        // A matched entry counts as well: the engine found the serial, whatever it went on to
        // return for the check as a whole.
        let matched = CapiRevocationInfo {
            result: CRYPT_E_NO_REVOCATION_CHECK,
            crl: Some(CapiCrlInfo {
                entry: Some(CapiCrlEntry {
                    serial: "0A".to_string(),
                    revocation_date: None,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            revocation_parts(&matched),
            ("badge badge-revoked", "revoked")
        );

        let offline = CapiRevocationInfo {
            result: CRYPT_E_REVOCATION_OFFLINE,
            ..Default::default()
        };
        assert_eq!(
            revocation_parts(&offline),
            ("badge badge-undetermined", "undetermined")
        );

        assert_eq!(
            revocation_parts(&CapiRevocationInfo::default()),
            ("badge badge-valid", "not revoked")
        );
    }

    /// The method is a word for the one OID Windows documents in this field and the OID itself for
    /// anything else, rather than being inferred from the CRL structure — which Windows fills from
    /// an OCSP response too.
    #[test]
    fn the_revocation_method_is_named_or_shown_raw() {
        let ocsp = CapiRevocationInfo {
            oid: Some(OCSP_OID.to_string()),
            ..Default::default()
        };
        assert_eq!(revocation_method(&ocsp).as_deref(), Some("OCSP"));

        let unnamed = CapiRevocationInfo {
            oid: Some("1.2.3.4".to_string()),
            ..Default::default()
        };
        assert_eq!(revocation_method(&unnamed).as_deref(), Some("1.2.3.4"));

        let crl_only = CapiRevocationInfo {
            crl: Some(CapiCrlInfo::default()),
            ..Default::default()
        };
        assert_eq!(revocation_method(&crl_only), None);
    }
}
