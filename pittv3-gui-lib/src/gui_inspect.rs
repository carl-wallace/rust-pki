//! The Inspect report, rendered.
//!
//! One component, shared by both frontends, because a store holds the same thing whichever
//! application opened it. What differs between them is how the report was produced — the desktop
//! and the command line assemble one from paths, the browser from uploaded bytes — and what
//! happens to an export once it exists. Neither difference reaches the presentation, which is why
//! the presentation is here rather than in either frontend.
//!
//! The two tables join on index: a [`PathRow`]'s `indices` are positions in the certificate table,
//! so selecting a certificate lists the paths through it and selecting a leaf CA lists the
//! certificates in each of its paths.

use dioxus::prelude::*;

use certval::{CertRow, PathRow};
use pittv3_lib::edit::StagedEdits;
use pittv3_lib::inspect::{
    anchors_as_csv, certs_as_csv, paths_as_csv, unix_secs_as_date, unusable_text, InspectReport,
};

/// A guard against a pathological store, not a display decision.
///
/// Set well north of anything real: the baked stores sum to roughly 2,800 rows, of which Web PKI is
/// 2,563 certificates and 2,429 leaf CAs, and the SIPR stores add about sixty more. Every one of
/// them renders whole. A store that reaches this is one nobody has seen, and stopping is better
/// than a webview that will not paint — so what was dropped is said beneath the table, since a
/// silent truncation reads as a smaller store.
const ROW_CAP: usize = 10_000;

/// Whether one certificate row answers to a search string.
///
/// A free function because the table and its export must agree on what "these rows" means: an
/// export that applied a second, slightly different rule would hand over a set the reader never
/// saw.
fn matches_cert(row: &CertRow, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if row.index.to_string() == needle || row.filename.to_lowercase().contains(needle) {
        return true;
    }
    match row.detail() {
        Some(d) => {
            d.subject.to_lowercase().contains(needle)
                || d.issuer.to_lowercase().contains(needle)
                || d.skid.to_lowercase().contains(needle)
        }
        None => false,
    }
}

/// Renders what a store holds.
///
/// `on_export` receives a suggested filename and the document itself. The frontend decides what
/// becomes of it: the desktop writes it into the download folder, the browser offers it as a
/// download. An export carries what the tables are showing, filter included, since the filter is
/// how a reader says which part of the store they mean.
#[component]
pub fn InspectReportView(
    report: InspectReport,
    /// What is marked for removal. Held by the frontend rather than here, because saving is the
    /// frontend's errand and it needs the marks to do it.
    edits: StagedEdits,
    on_export: EventHandler<(String, String)>,
    on_export_certs: EventHandler<Vec<usize>>,
    on_export_anchors: EventHandler<Vec<usize>>,
    on_toggle_cert: EventHandler<usize>,
    on_toggle_anchor: EventHandler<usize>,
    /// Mark everything the cleanup rule names — unparseable, outside the time of interest,
    /// self-signed, or not a CA.
    on_mark_unusable: EventHandler<()>,
    /// Discard every mark, leaving the store as it was read.
    on_clear_marks: EventHandler<()>,
    /// Write what is on screen, marks applied, as a new store.
    on_save: EventHandler<()>,
) -> Element {
    let mut filter = use_signal(String::new);
    let mut cert_selected = use_signal(|| None::<usize>);
    let mut leaf_selected = use_signal(|| None::<String>);

    // The report again, owned, so the export handlers have something that outlives a render: a
    // closure cannot borrow a prop. Written by the effect below rather than rebuilt every render,
    // so the clone is paid once per report and an export costs nothing until it is asked for.
    let mut held = use_signal(InspectReport::default);

    // A new report describes a different store, so a selection made against the last one addresses
    // a position that may now hold something else. Reacting to the report rather than using `key:`,
    // which does not fire when a prop changes in place.
    use_effect(use_reactive(&report, move |report| {
        held.set(report);
        cert_selected.set(None);
        leaf_selected.set(None);
    }));

    let needle = filter().trim().to_lowercase();
    let hit =
        |haystack: &str| -> bool { needle.is_empty() || haystack.to_lowercase().contains(&needle) };

    let certs: Vec<&CertRow> = report
        .certs
        .iter()
        .filter(|row| matches_cert(row, &needle))
        .collect();

    // One row per leaf CA, which is the master for the paths: a CA reached several ways is one row
    // with a count rather than several rows repeating its name. Keyed by the identifier the graph
    // itself is keyed by, so the order is the order the listings print.
    let mut leaf_map: std::collections::BTreeMap<String, (String, Vec<usize>, usize)> =
        std::collections::BTreeMap::new();
    for path in &report.paths {
        let entry = leaf_map
            .entry(path.leaf_ca_skid.clone())
            .or_insert_with(|| {
                (
                    path.leaf_ca_subject.clone(),
                    path.leaf_ca_indices.clone(),
                    0,
                )
            });
        entry.2 += 1;
    }
    let leaves: Vec<(String, String, Vec<usize>, usize)> = leaf_map
        .into_iter()
        .filter(|(skid, (subject, _, _))| hit(subject) || hit(skid))
        .map(|(skid, (subject, indices, count))| (skid, subject, indices, count))
        .collect();

    // A key certified by more than one parent is one row in the leaf table and one certificate per
    // certification in the table above, which is why the two do not count the same. Said rather
    // than left to the reader as arithmetic.
    let carried_by: usize = leaves.iter().map(|(_, _, indices, _)| indices.len()).sum();

    let selected_cert =
        cert_selected().and_then(|index| report.certs.iter().find(|c| c.index == index));
    let selected_leaf = leaf_selected();

    let shown_paths: Vec<&PathRow> = match &selected_leaf {
        Some(skid) => report
            .paths
            .iter()
            .filter(|p| &p.leaf_ca_skid == skid)
            .collect(),
        None => report.paths.iter().collect(),
    };

    // A path loses its meaning if any certificate in it goes, so marking one certificate shows what
    // else would go with it -- before anything is written.
    let doomed = |path: &PathRow| path.indices.iter().any(|i| edits.cert_removed(*i));

    // What the certificates button hands over: the rows the table is showing, which is what the
    // filter above them says the reader means.
    let shown_indices: Vec<usize> = certs.iter().map(|r| r.index).collect();
    let anchor_indices: Vec<usize> = report.anchors.iter().map(|a| a.index).collect();

    // Built when asked for rather than every render, and from what the table is showing: the
    // filter is how a reader says which part of the store they mean.
    let export_certs = move |_| {
        let report = held.read();
        let needle = filter().trim().to_lowercase();
        let rows: Vec<&CertRow> = report
            .certs
            .iter()
            .filter(|row| matches_cert(row, &needle))
            .collect();
        on_export.call(("certificates-summary.csv".to_string(), certs_as_csv(&rows)));
    };
    let export_paths = move |_| {
        let report = held.read();
        let rows: Vec<&PathRow> = report.paths.iter().collect();
        on_export.call(("partial-paths-summary.csv".to_string(), paths_as_csv(&rows)));
    };
    let export_anchors = move |_| {
        let report = held.read();
        on_export.call((
            "trust-anchors-summary.csv".to_string(),
            anchors_as_csv(&report.anchors),
        ));
    };

    rsx! {
        div { class: "inspect-report",

        p { class: "inspect-summary", "{report.summary()}" }

        div { class: "button-row",
            button {
                onclick: move |_| on_save.call(()),
                "Save as a new store"
            }
            // The rule the command line's cleanup applies, as a selection rather than a separate
            // errand: it marks, and nothing is written until you say so, which is what report-only
            // used to be for.
            button {
                onclick: move |_| on_mark_unusable.call(()),
                "Mark what a cleanup would remove"
            }
            if !edits.is_empty() {
                button {
                    onclick: move |_| on_clear_marks.call(()),
                    "Clear marks"
                }
            }
            span { class: "hint",
                "{edits.summary()}. Saving writes a new trust anchor store and certificate store; \
                 what was opened is left alone."
            }
        }

        div { class: "controls",
            label { r#for: "insp-filter", "Narrow to: " }
            input {
                id: "insp-filter",
                r#type: "text",
                value: "{filter}",
                placeholder: "name, key identifier or index",
                oninput: move |ev| filter.set(ev.value()),
            }
        }

        if let Some(found) = report.target_paths.as_ref() {
            details { class: "panel", open: true,
                summary { "Partial paths for the supplied target ({found.len()})" }
                if found.is_empty() {
                    p { class: "hint",
                        "No stored path reaches this target. Its issuer may not be in the store, \
                         or the time of interest may not cover it."
                    }
                }
                for path in found.iter() {
                    p { class: if doomed(path) { "path-row removed" } else { "path-row" },
                        "{path.ta_subject} → {path.leaf_ca_subject} "
                        span { class: "hint", "{path.indices:?}" }
                    }
                }
            }
        }

        details { class: "panel", open: true,
            summary { "All Certificates ({certs.len()})" }
            div { class: "button-row",
                button { onclick: export_certs, "Export certificates summary" }
                button {
                    onclick: move |_| on_export_certs.call(shown_indices.clone()),
                    "Export certificates"
                }
            }
            div { class: "table-scroll",
                table { class: "rows",
                    thead {
                        tr {
                            th { "Edit" }
                            th { "Index" }
                            th { "Subject" }
                            th { "Issuer" }
                            th { "Key identifier" }
                            th { "State" }
                        }
                    }
                    tbody {
                        for row in certs.iter().take(ROW_CAP) {
                            tr {
                                class: match (cert_selected() == Some(row.index), edits.cert_removed(row.index)) {
                                    (true, true) => "selected removed",
                                    (true, false) => "selected",
                                    (false, true) => "removed",
                                    (false, false) => "",
                                },
                                onclick: {
                                    let index = row.index;
                                    move |_| {
                                        let same = cert_selected() == Some(index);
                                        cert_selected.set(match same {
                                            true => None,
                                            false => Some(index),
                                        });
                                    }
                                },
                                // First rather than last: it is the only thing in the row you act
                                // on, and a wide store scrolls the far side of the table out of
                                // view.
                                td {
                                    button {
                                        onclick: {
                                            let index = row.index;
                                            move |ev: Event<MouseData>| {
                                                ev.stop_propagation();
                                                on_toggle_cert.call(index);
                                            }
                                        },
                                        if edits.cert_removed(row.index) { "Restore" } else { "Remove" }
                                    }
                                }
                                td { "{row.index}" }
                                td { class: "name",
                                    match row.detail() {
                                        Some(d) => d.subject.clone(),
                                        None => row.filename.clone(),
                                    }
                                }
                                td { class: "name",
                                    match row.detail() {
                                        Some(d) => d.issuer.clone(),
                                        None => String::new(),
                                    }
                                }
                                td { class: "mono",
                                    match row.detail() {
                                        Some(d) => d.skid.clone(),
                                        None => String::new(),
                                    }
                                }
                                td { "{unusable_text(row)}" }
                            }
                        }
                    }
                }
            }
            if certs.len() > ROW_CAP {
                p { class: "hint",
                    "Showing the first {ROW_CAP} of {certs.len()} — more rows than any known store \
                     holds. Narrow with the box above; an export carries all {certs.len()}."
                }
            }
        }

        if let Some(row) = selected_cert {
            div { class: "panel detail",
                h3 { "Certificate at index {row.index}" }
                p { class: "hint", "Read from {row.filename}" }
                if let Some(d) = row.detail() {
                    dl {
                        dt { "Subject" }
                        dd { "{d.subject_dn}" }
                        dt { "Issuer" }
                        dd { "{d.issuer_dn}" }
                        dt { "Key identifier" }
                        dd { class: "mono", "{d.skid}" }
                        dt { "Valid" }
                        dd { "{unix_secs_as_date(d.not_before)} to {unix_secs_as_date(d.not_after)}" }
                        dt { "Basic constraints" }
                        dd { if d.is_ca { "cA" } else { "not a CA" } }
                        if !d.aia_and_sia.is_empty() {
                            dt { "AIA and SIA" }
                            dd {
                                for uri in d.aia_and_sia.iter() {
                                    p { class: "mono", "{uri}" }
                                }
                            }
                        }
                        if !d.permitted.is_empty() {
                            dt { "Permitted subtrees" }
                            dd {
                                for gs in d.permitted.iter() {
                                    p { "{gs}" }
                                }
                            }
                        }
                        if !d.excluded.is_empty() {
                            dt { "Excluded subtrees" }
                            dd {
                                for gs in d.excluded.iter() {
                                    p { "{gs}" }
                                }
                            }
                        }
                    }
                } else {
                    p { "{unusable_text(row)}" }
                }
                div { class: "button-row",
                    button {
                        onclick: {
                            let index = row.index;
                            move |_| on_export_certs.call(vec![index])
                        },
                        "Export this certificate"
                    }
                }
                h4 { "Partial paths through this certificate" }
                if !report.paths.iter().any(|p| p.indices.contains(&row.index)) {
                    p { class: "hint", "None." }
                }
                for path in report.paths.iter().filter(|p| p.indices.contains(&row.index)) {
                    p { class: if doomed(path) { "path-row removed" } else { "path-row" },
                        "{path.ta_subject} → {path.leaf_ca_subject} "
                        span { class: "hint", "{path.indices:?}" }
                    }
                }
            }
        }

        details { class: "panel", open: true,
            summary {
                title: "One row per CA key rather than per certificate. A CA key certified by more than one parent is a single row here, and one certificate in the table above for each certification it received.",
                "Leaf CAs by Key ({leaves.len()})"
            }
            if carried_by > leaves.len() {
                p { class: "hint",
                    "{leaves.len()} key(s), carried by {carried_by} certificate(s): a CA key \
                     certified by more than one parent is one row here and one certificate above \
                     for each certification."
                }
            }
            div { class: "button-row",
                button { onclick: export_paths, "Export partial paths summary" }
            }
            div { class: "table-scroll",
                table { class: "rows",
                    thead {
                        tr {
                            th { "Leaf CA" }
                            th { "Key identifier" }
                            th { "Certificates" }
                            th { "Paths" }
                        }
                    }
                    tbody {
                        for (skid, subject, indices, count) in leaves.iter().take(ROW_CAP) {
                            tr {
                                class: if leaf_selected().as_deref() == Some(skid.as_str()) { "selected" } else { "" },
                                onclick: {
                                    let skid = skid.clone();
                                    move |_| {
                                        let same = leaf_selected().as_deref() == Some(skid.as_str());
                                        leaf_selected.set(match same {
                                            true => None,
                                            false => Some(skid.clone()),
                                        });
                                    }
                                },
                                td { class: "name", "{subject}" }
                                td { class: "mono", "{skid}" }
                                td { "{indices.len()}" }
                                td { "{count}" }
                            }
                        }
                    }
                }
            }
            if leaves.len() > ROW_CAP {
                p { class: "hint",
                    "Showing the first {ROW_CAP} of {leaves.len()} — more rows than any known store \
                     holds. Narrow with the box above; an export carries every path."
                }
            }
        }

        if let Some(skid) = selected_leaf.as_ref() {
            div { class: "panel detail",
                h3 { "Certificates carrying this key" }
                p { class: "hint",
                    "More than one means the same CA key was certified more than once. They differ \
                     by who issued them and when they are valid, not by the key they carry."
                }
                for row in report.certs.iter().filter(|c| {
                    c.detail().map(|d| &d.skid == skid).unwrap_or(false)
                }) {
                    p { class: "path-row",
                        "{row.index}: "
                        if let Some(d) = row.detail() {
                            "issued by {d.issuer}, valid {unix_secs_as_date(d.not_before)} to {unix_secs_as_date(d.not_after)}"
                        }
                    }
                }
                div { class: "button-row",
                    button {
                        onclick: {
                            let carrying: Vec<usize> = report
                                .certs
                                .iter()
                                .filter(|c| c.detail().map(|d| &d.skid == skid).unwrap_or(false))
                                .map(|c| c.index)
                                .collect();
                            move |_| on_export_certs.call(carrying.clone())
                        },
                        "Export these certificates"
                    }
                }
                h3 { "Partial paths to this CA ({shown_paths.len()})" }
                for path in shown_paths.iter() {
                    div { class: "path-detail",
                        p {
                            class: if doomed(path) { "path-row removed" } else { "path-row" },
                            "From {path.ta_subject}, {path.len()} certificate(s)"
                        }
                        ol {
                            for i in path.indices.iter() {
                                li {
                                    "{i}: "
                                    match report.certs.get(*i).and_then(|c| c.detail()) {
                                        Some(d) => d.subject.clone(),
                                        None => "not in the pool".to_string(),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        details { class: "panel",
            summary { "Trust Anchors ({report.anchors.len()})" }
            div { class: "button-row",
                button { onclick: export_anchors, "Export trust anchors summary" }
                button {
                    onclick: move |_| on_export_anchors.call(anchor_indices.clone()),
                    "Export trust anchors"
                }
            }
            div { class: "table-scroll",
                table { class: "rows",
                    thead {
                        tr {
                            th { "Edit" }
                            th { "Index" }
                            th { "Subject" }
                            th { "Key identifier" }
                            th { "Read from" }
                        }
                    }
                    tbody {
                        for anchor in report.anchors.iter() {
                            tr {
                                class: if edits.anchor_removed(anchor.index) { "removed" } else { "" },
                                td {
                                    button {
                                        onclick: {
                                            let index = anchor.index;
                                            move |_| on_toggle_anchor.call(index)
                                        },
                                        if edits.anchor_removed(anchor.index) { "Restore" } else { "Remove" }
                                    }
                                }
                                td { "{anchor.index}" }
                                td {
                                    match &anchor.subject {
                                        Some(s) => s.clone(),
                                        None => "No Name".to_string(),
                                    }
                                }
                                td { class: "mono", "{anchor.skid}" }
                                td { "{anchor.filename}" }
                            }
                        }
                    }
                }
            }
        }
        }
    }
}
