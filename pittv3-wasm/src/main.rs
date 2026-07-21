#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

mod validate;

use dioxus::prelude::*;
use web_time::{SystemTime, UNIX_EPOCH};

use certval::PathValidationStatus;
use pittv3_gui_lib::gui_results::ResultsView;
use pittv3_gui_lib::gui_shell::AppShell;
use pittv3_gui_lib::PITTV3_CSS;
use pittv3_lib::report::{ReportTotals, TargetReport, ValidationReport};

use crate::validate::{
    validate_batch, validate_hackathon_zip, NameConstraintInputs, ResultLine, ValidationSettings,
    SAMPLE_INVALID, SAMPLE_VALID, STORES,
};

/// Store selection value indicating no baked-in store, i.e., uploaded trust anchors only
const NO_STORE: usize = usize::MAX;

/// OID for anyPolicy, the default user-initial-policy-set value
const ANY_POLICY_OID: &str = "2.5.29.32.0";

/// Sidebar views in display order
const VIEW_LABELS: &[&str] = &[
    "Validate",
    "Settings",
    "Results",
    "Resources",
    "Hackathon",
    "Help",
];

/// Index of the Results view within [`VIEW_LABELS`]
const RESULTS_VIEW: usize = 2;

fn now_as_unix_epoch() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => 0,
    }
}

/// Parses a `datetime-local` value (local time) into Unix-epoch seconds. None on host builds.
#[cfg(target_family = "wasm")]
fn datetime_local_to_epoch(value: &str) -> Option<u64> {
    let ms = js_sys::Date::parse(value);
    if ms.is_nan() {
        None
    } else {
        Some((ms / 1000.0) as u64)
    }
}

#[cfg(not(target_family = "wasm"))]
fn datetime_local_to_epoch(_value: &str) -> Option<u64> {
    None
}

fn main() {
    dioxus::launch(App);
}

/// Percent-encodes `s` for inclusion in a data: URI, leaving RFC 3986 unreserved characters as is
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Fetches the bytes at a same-origin relative URL. Used to pull a store's CBOR on demand so it
/// ships alongside the wasm rather than baked into the binary.
#[cfg(target_family = "wasm")]
async fn fetch_bytes(url: &str) -> Result<Vec<u8>, String> {
    let resp = gloo_net::http::Request::get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.ok() {
        return Err(format!("HTTP {} for {url}", resp.status()));
    }
    resp.binary().await.map_err(|e| e.to_string())
}

/// Native builds (e.g. `cargo check`/`cargo test` on the host) do not run in a browser and have no
/// fetch; the app itself only ever executes as wasm.
#[cfg(not(target_family = "wasm"))]
async fn fetch_bytes(_url: &str) -> Result<Vec<u8>, String> {
    Err("network fetch is only available in the browser build".to_string())
}

/// Reads all files carried by a form event into (name, bytes) pairs
async fn read_files(ev: &FormEvent) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![];
    for f in ev.files() {
        if let Ok(bytes) = f.read_bytes().await {
            out.push((f.name(), bytes.to_vec()));
        }
    }
    out
}

/// Appends `files` to `sig`, skipping entries already present
fn extend_unique(mut sig: Signal<Vec<(String, Vec<u8>)>>, files: Vec<(String, Vec<u8>)>) {
    let mut list = sig.write();
    for f in files {
        if !list.contains(&f) {
            list.push(f);
        }
    }
}

/// Assembles a [`ValidationReport`] from the accumulated per-target reports. The report is built
/// on demand because targets accumulate across interactions rather than arriving from one run.
fn build_report(targets: &[TargetReport], toi: u64) -> ValidationReport {
    let mut totals = ReportTotals {
        targets: targets.len(),
        ..Default::default()
    };
    for target in targets {
        totals.paths_found += target.paths.len();
        for path in &target.paths {
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
        time_of_interest: toi,
        duration_ms: 0,
    }
}

#[component]
fn App() -> Element {
    let mut view = use_signal(|| 0usize);
    let mut mode = use_signal(|| 0usize);
    let mut toi = use_signal(|| now_as_unix_epoch().to_string());
    let mut validate_all = use_signal(|| true);
    let mut targets = use_signal(Vec::<TargetReport>::new);
    let mut notes = use_signal(Vec::<ResultLine>::new);
    let mut uploaded_tas = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut uploaded_cas = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut loaded_ees = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut loaded_zips = use_signal(Vec::<(String, Vec<u8>)>::new);
    // Fetched CBOR for the most recently used built-in store, cached as (store index, ta, ca) so
    // repeated validations with the same selection do not re-download it.
    let mut loaded_store = use_signal(|| None::<(usize, Vec<u8>, Vec<u8>)>);

    // RFC 5280 path validation inputs (defaults match CertificationPathSettings::default())
    let mut initial_explicit_policy = use_signal(|| false);
    let mut initial_policy_mapping_inhibit = use_signal(|| false);
    let mut initial_inhibit_any_policy = use_signal(|| false);
    let mut initial_policy_set = use_signal(|| ANY_POLICY_OID.to_string());
    let mut enforce_ta_constraints = use_signal(|| false);
    let mut enforce_ta_validity = use_signal(|| true);

    // RFC 5280 initial-permitted / initial-excluded subtrees, one entry per line per name form
    let mut perm_dns = use_signal(String::new);
    let mut perm_email = use_signal(String::new);
    let mut perm_dn = use_signal(String::new);
    let mut perm_uri = use_signal(String::new);
    let mut perm_ip = use_signal(String::new);
    let mut excl_dns = use_signal(String::new);
    let mut excl_email = use_signal(String::new);
    let mut excl_dn = use_signal(String::new);
    let mut excl_uri = use_signal(String::new);
    let mut excl_ip = use_signal(String::new);

    let current_settings = move || ValidationSettings {
        toi: toi().parse::<u64>().unwrap_or_else(|_| now_as_unix_epoch()),
        validate_all: validate_all(),
        initial_explicit_policy: initial_explicit_policy(),
        initial_policy_mapping_inhibit: initial_policy_mapping_inhibit(),
        initial_inhibit_any_policy: initial_inhibit_any_policy(),
        initial_policy_set: initial_policy_set(),
        enforce_trust_anchor_constraints: enforce_ta_constraints(),
        enforce_trust_anchor_validity: enforce_ta_validity(),
        permitted_subtrees: NameConstraintInputs {
            dns_name: perm_dns(),
            rfc822_name: perm_email(),
            directory_name: perm_dn(),
            uniform_resource_identifier: perm_uri(),
            ip_address: perm_ip(),
        },
        excluded_subtrees: NameConstraintInputs {
            dns_name: excl_dns(),
            rfc822_name: excl_email(),
            directory_name: excl_dn(),
            uniform_resource_identifier: excl_uri(),
            ip_address: excl_ip(),
        },
    };

    // Restores every setting to its initial default (time of interest reset to the current time).
    let reset_settings = move |_| {
        toi.set(now_as_unix_epoch().to_string());
        validate_all.set(true);
        initial_explicit_policy.set(false);
        initial_policy_mapping_inhibit.set(false);
        initial_inhibit_any_policy.set(false);
        initial_policy_set.set(ANY_POLICY_OID.to_string());
        enforce_ta_constraints.set(false);
        enforce_ta_validity.set(true);
        for mut s in [
            perm_dns, perm_email, perm_dn, perm_uri, perm_ip, excl_dns, excl_email, excl_dn,
            excl_uri, excl_ip,
        ] {
            s.set(String::new());
        }
    };

    // Ensures the selected built-in store's CBOR is available, fetching (and caching) it on first
    // use. Returns the owned (ta, ca) bytes, or None when no store is selected; an Err carries a
    // message to surface. Reads that touch signals are scoped so no guard is held across the await.
    let ensure_store = move || async move {
        let cur = mode();
        let Some(s) = STORES.get(cur) else {
            return Ok(None);
        };
        let cached = {
            let guard = loaded_store.read();
            match guard.as_ref() {
                Some((i, ta, ca)) if *i == cur => Some((ta.clone(), ca.clone())),
                _ => None,
            }
        };
        if let Some(bytes) = cached {
            return Ok(Some(bytes));
        }
        let ta = fetch_bytes(s.ta_url).await;
        // A store without a ca_url is trust-anchor-only; represent its CA side as empty bytes
        // (validate() treats an empty CA buffer as "no CA store").
        let ca = match s.ca_url {
            Some(url) => fetch_bytes(url).await,
            None => Ok(Vec::new()),
        };
        match (ta, ca) {
            (Ok(ta), Ok(ca)) => {
                loaded_store.set(Some((cur, ta.clone(), ca.clone())));
                Ok(Some((ta, ca)))
            }
            (ta, ca) => Err(format!(
                "Failed to fetch {} store: {}",
                s.label,
                ta.err().or(ca.err()).unwrap_or_default()
            )),
        }
    };

    // downloads the accumulated results as a JSON-serialized ValidationReport via a synthesized
    // anchor click
    let save_results = move |_| {
        let report = build_report(
            &targets.read(),
            toi().parse::<u64>().unwrap_or_else(|_| now_as_unix_epoch()),
        );
        let json = serde_json::to_string_pretty(&report).unwrap_or_default();
        let uri = format!(
            "data:application/json;charset=utf-8,{}",
            percent_encode(&json)
        );
        let js = format!(
            "const a = document.createElement('a'); a.href = \"{uri}\"; a.download = \"pittv3-results-{}.json\"; a.click();",
            now_as_unix_epoch()
        );
        let _ = dioxus::document::eval(&js);
    };

    // loads a certificate into the aggregated list; validation happens when the Validate button
    // is clicked
    let load_ee = move |name: String, bytes: Vec<u8>| {
        extend_unique(loaded_ees, vec![(name, bytes)]);
    };

    // validates the loaded self-contained hackathon artifacts_certs_r5.zip archive(s); lives on its
    // own tab, so it is a separate action from certificate validation
    let validate_zips = move |_| {
        // each Validate replaces the prior results rather than appending to them
        targets.write().clear();
        notes.write().clear();
        let vs = current_settings();
        for (name, bytes) in loaded_zips() {
            let (reports, lines) = validate_hackathon_zip(&name, bytes, &vs);
            notes.write().extend(lines);
            targets.write().extend(reports);
        }
        view.set(RESULTS_VIEW);
    };

    // validates everything loaded (certificates against the store/uploads, archives wholesale)
    // using the settings in effect at click time. Async because the selected store's CBOR is
    // fetched on demand; a fetch failure is surfaced as a note and aborts before validation.
    let validate_loaded = move || async move {
        // each Validate replaces the prior results rather than appending to them
        targets.write().clear();
        notes.write().clear();
        let store_bytes = match ensure_store().await {
            Ok(bytes) => bytes,
            Err(e) => {
                notes.write().push(ResultLine {
                    class: "err",
                    text: e,
                });
                view.set(RESULTS_VIEW);
                return;
            }
        };
        let vs = current_settings();
        let label = STORES.get(mode()).map(|s| s.label);
        let store = store_bytes
            .as_ref()
            .map(|(ta, ca)| (label.unwrap_or_default(), ta.as_slice(), ca.as_slice()));
        // Prepare the environment (and the single partial-path discovery pass) once, then validate
        // every loaded certificate against it — not once per certificate.
        let (reports, lines) =
            validate_batch(store, &uploaded_tas(), &uploaded_cas(), &loaded_ees(), &vs);
        notes.write().extend(lines);
        targets.write().extend(reports);
        view.set(RESULTS_VIEW);
    };

    rsx! {
        style { {PITTV3_CSS} }
        style { {include_str!("../assets/pittv3-wasm.css")} }
        div { class: "wrap",
            h1 { class: "app-title", "PKI Interoperability Test Tool v3 (PITTv3)" }
            p { class: "tagline",
                "Certification path validation in the browser — including ML-DSA and SLH-DSA (FIPS 204/205) — powered by "
                code { "certval" }
                " compiled to WebAssembly. Certificates never leave this page."
            }

            AppShell {
                items: VIEW_LABELS.to_vec(),
                selected: view(),
                on_select: move |i: usize| view.set(i),
                match view() {
                    0 => rsx! {
                        div { class: "controls",
                            label { r#for: "store", "Trust anchor / CA store: " }
                            select {
                                id: "store",
                                onchange: move |ev| {
                                    let v = ev.value();
                                    mode.set(v.parse::<usize>().unwrap_or(NO_STORE));
                                },
                                for (i, s) in STORES.iter().enumerate() {
                                    option { value: "{i}", selected: mode() == i, "{s.label}" }
                                }
                                option { value: "none", selected: mode() == NO_STORE, "None (uploaded trust anchors and CA certificates only)" }
                            }
                        }

                        details { class: "panel",
                            summary { "Additional trust anchors and intermediates (certificates or .cbor stores)" }
                            div { class: "controls custom",
                                label { "Trust anchor(s): " }
                                input {
                                    r#type: "file",
                                    multiple: true,
                                    accept: ".der,.crt,.cer,.pem,.ta,.cbor",
                                    onchange: move |ev| async move {
                                        let files = read_files(&ev).await;
                                        extend_unique(uploaded_tas, files);
                                    },
                                }
                                label { "Intermediate CA(s): " }
                                input {
                                    r#type: "file",
                                    multiple: true,
                                    accept: ".der,.crt,.cer,.pem,.cbor",
                                    onchange: move |ev| async move {
                                        let files = read_files(&ev).await;
                                        extend_unique(uploaded_cas, files);
                                    },
                                }
                                span { class: "hint",
                                    "{uploaded_tas().len()} trust anchor(s), {uploaded_cas().len()} intermediate(s) loaded "
                                    button {
                                        onclick: move |_| {
                                            uploaded_tas.write().clear();
                                            uploaded_cas.write().clear();
                                        },
                                        "Clear"
                                    }
                                }
                            }
                        }

                        div { class: "controls",
                            label { "End Entity Certificate(s): " }
                            input {
                                r#type: "file",
                                multiple: true,
                                accept: ".der,.crt,.cer,.pem",
                                onchange: move |ev| async move {
                                    for (name, bytes) in read_files(&ev).await {
                                        load_ee(name, bytes);
                                    }
                                },
                            }
                            label { "Sample Certificate: " }
                            span {
                                button {
                                    onclick: move |_| load_ee(SAMPLE_VALID.0.to_string(), SAMPLE_VALID.1.to_vec()),
                                    "Load valid sample (ML-DSA-44)"
                                }
                                button {
                                    onclick: move |_| load_ee(SAMPLE_INVALID.0.to_string(), SAMPLE_INVALID.1.to_vec()),
                                    "Load invalid sample (ML-DSA-44)"
                                }
                            }
                            span { class: "hint",
                                "{loaded_ees().len()} certificate(s) loaded "
                                button {
                                    onclick: move |_| loaded_ees.write().clear(),
                                    "Clear"
                                }
                            }
                        }

                        div { class: "controls center-row",
                            button {
                                class: "validate-button",
                                disabled: loaded_ees().is_empty(),
                                onclick: move |_| async move { validate_loaded().await },
                                "Validate loaded certificate(s) using current TA and CA stores and settings"
                            }
                        }
                    },
                    1 => rsx! {
                        fieldset {
                            legend { "General" }
                            div { class: "controls",
                                label { r#for: "toi", "Time of interest (Unix epoch): " }
                                span {
                                    input {
                                        id: "toi",
                                        r#type: "text",
                                        value: "{toi}",
                                        oninput: move |ev| toi.set(ev.value()),
                                    }
                                    button { onclick: move |_| toi.set(now_as_unix_epoch().to_string()), "Now" }
                                    // Uncontrolled on purpose: binding `value` to the epoch made this a
                                    // controlled input, and every re-render reset the field mid-edit
                                    // (worst in Edge/Chromium). Left uncontrolled it is a one-way "pick a
                                    // time -> set the epoch" control; the epoch field above is the display
                                    // and source of truth. onchange commits only a complete datetime.
                                    input {
                                        r#type: "datetime-local",
                                        onchange: move |ev| {
                                            if let Some(secs) = datetime_local_to_epoch(&ev.value()) {
                                                toi.set(secs.to_string());
                                            }
                                        },
                                    }
                                }

                                label { r#for: "validate-all", "Validate all paths: " }
                                input {
                                    id: "validate-all",
                                    r#type: "checkbox",
                                    checked: validate_all(),
                                    onchange: move |ev| validate_all.set(ev.checked()),
                                }
                            }
                        }
                        fieldset {
                            legend { "Path validation settings (RFC 5280 inputs)" }
                            div { class: "controls",
                                label { r#for: "initial-explicit-policy", "Require explicit policy: " }
                                input {
                                    id: "initial-explicit-policy",
                                    r#type: "checkbox",
                                    checked: initial_explicit_policy(),
                                    onchange: move |ev| initial_explicit_policy.set(ev.checked()),
                                }

                                label { r#for: "inhibit-policy-mapping", "Inhibit policy mapping: " }
                                input {
                                    id: "inhibit-policy-mapping",
                                    r#type: "checkbox",
                                    checked: initial_policy_mapping_inhibit(),
                                    onchange: move |ev| initial_policy_mapping_inhibit.set(ev.checked()),
                                }

                                label { r#for: "inhibit-any-policy", "Inhibit anyPolicy: " }
                                input {
                                    id: "inhibit-any-policy",
                                    r#type: "checkbox",
                                    checked: initial_inhibit_any_policy(),
                                    onchange: move |ev| initial_inhibit_any_policy.set(ev.checked()),
                                }

                                label { r#for: "initial-policy-set", "Initial policy set (OIDs): " }
                                input {
                                    id: "initial-policy-set",
                                    r#type: "text",
                                    value: "{initial_policy_set}",
                                    oninput: move |ev| initial_policy_set.set(ev.value()),
                                }

                                label { r#for: "enforce-ta-constraints", "Enforce trust anchor constraints: " }
                                input {
                                    id: "enforce-ta-constraints",
                                    r#type: "checkbox",
                                    checked: enforce_ta_constraints(),
                                    onchange: move |ev| enforce_ta_constraints.set(ev.checked()),
                                }

                                label { r#for: "enforce-ta-validity", "Enforce trust anchor validity: " }
                                input {
                                    id: "enforce-ta-validity",
                                    r#type: "checkbox",
                                    checked: enforce_ta_validity(),
                                    onchange: move |ev| enforce_ta_validity.set(ev.checked()),
                                }

                                span { class: "hint",
                                    "Separate policy OIDs with spaces or commas; {ANY_POLICY_OID} is anyPolicy."
                                }
                            }
                        }
                        fieldset {
                            legend { "Initial permitted subtrees" }
                            div { class: "controls",
                                label { "dNSName: " }
                                textarea { rows: "2", value: "{perm_dns}", oninput: move |ev| perm_dns.set(ev.value()) }
                                label { "rfc822Name (email): " }
                                textarea { rows: "2", value: "{perm_email}", oninput: move |ev| perm_email.set(ev.value()) }
                                label { "directoryName (DN): " }
                                textarea { rows: "2", value: "{perm_dn}", oninput: move |ev| perm_dn.set(ev.value()) }
                                label { "URI: " }
                                textarea { rows: "2", value: "{perm_uri}", oninput: move |ev| perm_uri.set(ev.value()) }
                                label { "iPAddress: " }
                                textarea { rows: "2", value: "{perm_ip}", oninput: move |ev| perm_ip.set(ev.value()) }
                                span { class: "hint",
                                    "One entry per line; an empty box imposes no initial permitted constraint for that name form."
                                }
                            }
                        }
                        fieldset {
                            legend { "Initial excluded subtrees" }
                            div { class: "controls",
                                label { "dNSName: " }
                                textarea { rows: "2", value: "{excl_dns}", oninput: move |ev| excl_dns.set(ev.value()) }
                                label { "rfc822Name (email): " }
                                textarea { rows: "2", value: "{excl_email}", oninput: move |ev| excl_email.set(ev.value()) }
                                label { "directoryName (DN): " }
                                textarea { rows: "2", value: "{excl_dn}", oninput: move |ev| excl_dn.set(ev.value()) }
                                label { "URI: " }
                                textarea { rows: "2", value: "{excl_uri}", oninput: move |ev| excl_uri.set(ev.value()) }
                                label { "iPAddress: " }
                                textarea { rows: "2", value: "{excl_ip}", oninput: move |ev| excl_ip.set(ev.value()) }
                                span { class: "hint", "One entry per line." }
                            }
                        }
                        div { class: "controls center-row",
                            button { onclick: reset_settings, "Reset to defaults" }
                        }
                    },
                    2 => rsx! {
                        div { class: "results",
                            div { class: "results-header",
                                h2 { "Results" }
                                span {
                                    button {
                                        disabled: targets.read().is_empty(),
                                        onclick: save_results,
                                        "Save"
                                    }
                                    button {
                                        onclick: move |_| {
                                            targets.write().clear();
                                            notes.write().clear();
                                        },
                                        "Clear"
                                    }
                                }
                            }
                            if targets.read().is_empty() && notes.read().is_empty() {
                                p { class: "hint",
                                    "No results yet: validate a certificate from the Validate view."
                                }
                            }
                            if !targets.read().is_empty() {
                                ResultsView {
                                    report: build_report(
                                        &targets.read(),
                                        toi().parse::<u64>().unwrap_or_else(|_| now_as_unix_epoch()),
                                    ),
                                }
                            }
                            if !notes.read().is_empty() {
                                details { class: "advanced",
                                    summary { "Notes ({notes.read().len()} line(s))" }
                                    div { class: "results-body",
                                        for line in notes.read().iter() {
                                            p { class: line.class, "{line.text}" }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    3 => rsx! {
                        div { class: "help-view",
                            h2 { "Store artifacts" }
                            p {
                                "The built-in stores are CBOR files served alongside this app. Download any of "
                                "them and re-upload them via the trust-anchor and intermediate-CA controls on the "
                                "Validate tab to mix and match \u{2014} e.g. Web PKI roots with a different "
                                "collection's intermediates, or your own trust anchors with a built-in CA store. "
                                "They are the same format the store dropdown loads and the same format produced by "
                                "offline store-generation tooling, so stores you build yourself upload the same way."
                            }
                            p { class: "hint",
                                "The Web PKI and U.S. DoD stores were prepared on 2026-07-21; the ML-DSA-44 "
                                "PKITS edition is static test data. Regenerate the real-world stores periodically "
                                "to refresh their trust material."
                            }
                            h3 { "Web PKI (Mozilla roots + CCADB intermediates)" }
                            ul {
                                li {
                                    a { href: "resources/webpki_ta.cbor", download: "webpki_ta.cbor", "webpki_ta.cbor" }
                                    " \u{2014} trust anchors (Mozilla roots)"
                                }
                                li {
                                    a { href: "resources/webpki_ca.cbor", download: "webpki_ca.cbor", "webpki_ca.cbor" }
                                    " \u{2014} intermediate CAs (CCADB)"
                                }
                            }
                            h3 { "U.S. DoD (NIPR)" }
                            ul {
                                li {
                                    a { href: "resources/dod_nipr_prod_ta.cbor", download: "dod_nipr_prod_ta.cbor", "dod_nipr_prod_ta.cbor" }
                                    " \u{2014} trust anchors (DoD roots)"
                                }
                                li {
                                    a { href: "resources/dod_nipr_prod_ca.cbor", download: "dod_nipr_prod_ca.cbor", "dod_nipr_prod_ca.cbor" }
                                    " \u{2014} intermediate CAs"
                                }
                            }
                            h3 { "ML-DSA-44 PKITS" }
                            ul {
                                li {
                                    a { href: "resources/pkits_ml_dsa_44_ta.cbor", download: "pkits_ml_dsa_44_ta.cbor", "pkits_ml_dsa_44_ta.cbor" }
                                    " \u{2014} trust anchors"
                                }
                                li {
                                    a { href: "resources/pkits_ml_dsa_44_ca.cbor", download: "pkits_ml_dsa_44_ca.cbor", "pkits_ml_dsa_44_ca.cbor" }
                                    " \u{2014} intermediate CAs with partial paths"
                                }
                            }
                            p {
                                "Trust-anchor stores (*_ta.cbor) hold roots; CA stores (*_ca.cbor) hold intermediate "
                                "CA certificates with precomputed partial certification paths."
                            }
                        }
                    },
                    4 => rsx! {
                        div { class: "controls",
                            label { "Hackathon artifacts zip: " }
                            input {
                                r#type: "file",
                                multiple: true,
                                accept: ".zip",
                                onchange: move |ev| async move {
                                    let files = read_files(&ev).await;
                                    extend_unique(loaded_zips, files);
                                },
                            }
                            span { class: "hint",
                                "{loaded_zips().len()} archive(s) loaded "
                                button { onclick: move |_| loaded_zips.write().clear(), "Clear" }
                            }
                        }
                        div { class: "controls center-row",
                            button {
                                class: "validate-button",
                                disabled: loaded_zips().is_empty(),
                                onclick: validate_zips,
                                "Validate archive"
                            }
                        }
                        div { class: "help-view",
                            ul {
                                li {
                                    "Validates an artifacts_certs_r5.zip from the "
                                    a {
                                        href: "https://github.com/IETF-Hackathon/pqc-certificates",
                                        target: "_blank",
                                        "IETF Hackathon PQC Certificate repository"
                                    }
                                    ": *_ta.der entries form the trust anchor store and *_ee.der entries are "
                                    "validated against it. The archive is self-contained \u{2014} the store and "
                                    "uploads on the Validate tab are not consulted."
                                }
                            }
                        }
                    },
                    _ => rsx! {
                        div { class: "help-view",
                            h2 { "Notes" }
                            ul {
                                li {
                                    "Uploaded trust anchors and intermediate CAs may be DER or PEM certificates, "
                                    "or a .cbor store file (the same format as the built-in stores \u{2014} see the "
                                    "Resources tab to download them). A .cbor upload merges all of its certificates "
                                    "into that side."
                                }
                                li {
                                    "Uploaded trust anchors and intermediate CA certificates are used together "
                                    "with the selected built-in store; select \"None\" to rely on uploads alone, "
                                    "which \u{2014} with .cbor uploads \u{2014} lets you freely mix any trust-anchor "
                                    "store with any CA store. Uploads accumulate across selections until cleared."
                                }
                                li {
                                    "Certificates to validate accumulate as they are selected; nothing runs "
                                    "until the Validate button is clicked, which validates every loaded "
                                    "certificate against the current store, uploads and settings."
                                }
                                li { "A time of interest of 0 disables validity period checks." }
                                li {
                                    "When \"Validate all paths\" is unchecked, processing stops at the first "
                                    "valid path; otherwise every discovered path is validated."
                                }
                                li {
                                    "Everything runs in the browser: there is no revocation checking (CRL/OCSP) "
                                    "and no AIA/SIA chasing. Use the desktop PITTv3 utility for validation that "
                                    "requires network access."
                                }
                                li {
                                    "Built-in stores: \"Web PKI\" holds the Mozilla trust anchors plus the CCADB "
                                    "intermediate CAs; \"U.S. DoD\" holds the NIPR DoD roots and "
                                    "intermediate CAs; \"ML-DSA-44 PKITS\" "
                                    "holds PKITS test artifacts re-signed with the indicated post-quantum algorithm. "
                                    "The full set of PKITS artifacts resigned with PQC algorithms can be found in the "
                                    a {
                                        href: "https://github.com/IETF-Hackathon/pqc-certificates",
                                        target: "_blank",
                                        "IETF Hackathon PQC Certificate repo"
                                    }
                                    "."
                                }
                                li {
                                    "The Hackathon tab validates provider artifacts_certs_r5.zip archives from "
                                    "the hackathon repo wholesale: the zip's own trust anchors are used and each "
                                    "end entity certificate is validated against them, honoring these settings. "
                                    "This is separate from certificate validation on the Validate tab."
                                }
                                li {
                                    "The Save button in the Results view downloads the accumulated results as "
                                    "a JSON report."
                                }
                                li {
                                    "PITTv3 is open source. The source \u{2014} including the certval path-validation "
                                    "library and this wasm frontend \u{2014} is available in the "
                                    a {
                                        href: "https://github.com/carl-wallace/rust-pki",
                                        target: "_blank",
                                        "rust-pki repository"
                                    }
                                    "."
                                }
                            }
                        }
                    },
                }
            }
        }
    }
}
