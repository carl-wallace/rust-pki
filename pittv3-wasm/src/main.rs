#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

mod validate;

use dioxus::prelude::*;
use web_time::{SystemTime, UNIX_EPOCH};

use crate::validate::{
    validate, validate_hackathon_zip, ResultLine, ValidationSettings, SAMPLE_INVALID, SAMPLE_VALID,
    STORES,
};

/// Store selection value indicating no baked-in store, i.e., uploaded trust anchors only
const NO_STORE: usize = usize::MAX;

/// OID for anyPolicy, the default user-initial-policy-set value
const ANY_POLICY_OID: &str = "2.5.29.32.0";

fn now_as_unix_epoch() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => 0,
    }
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

#[component]
fn App() -> Element {
    let mut mode = use_signal(|| 0usize);
    let mut toi = use_signal(|| now_as_unix_epoch().to_string());
    let mut validate_all = use_signal(|| true);
    let mut results = use_signal(Vec::<ResultLine>::new);
    let mut uploaded_tas = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut uploaded_cas = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut loaded_ees = use_signal(Vec::<(String, Vec<u8>)>::new);

    // RFC 5280 path validation inputs (defaults match CertificationPathSettings::default())
    let mut initial_explicit_policy = use_signal(|| false);
    let mut initial_policy_mapping_inhibit = use_signal(|| false);
    let mut initial_inhibit_any_policy = use_signal(|| false);
    let mut initial_policy_set = use_signal(|| ANY_POLICY_OID.to_string());
    let mut enforce_ta_constraints = use_signal(|| false);
    let mut enforce_ta_validity = use_signal(|| true);
    let mut enforce_alg_and_key_size = use_signal(|| false);

    let current_settings = move || ValidationSettings {
        toi: toi().parse::<u64>().unwrap_or_else(|_| now_as_unix_epoch()),
        validate_all: validate_all(),
        initial_explicit_policy: initial_explicit_policy(),
        initial_policy_mapping_inhibit: initial_policy_mapping_inhibit(),
        initial_inhibit_any_policy: initial_inhibit_any_policy(),
        initial_policy_set: initial_policy_set(),
        enforce_trust_anchor_constraints: enforce_ta_constraints(),
        enforce_trust_anchor_validity: enforce_ta_validity(),
        enforce_alg_and_key_size_constraints: enforce_alg_and_key_size(),
    };

    let mut run = move |name: String, bytes: Vec<u8>| {
        let vs = current_settings();
        let store = STORES.get(mode());
        let lines = validate(store, &uploaded_tas(), &uploaded_cas(), &name, &bytes, &vs);
        results.write().extend(lines);
    };

    // downloads the accumulated results as a plain text file via a synthesized anchor click
    let save_results = move |_| {
        let text = results
            .read()
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let uri = format!("data:text/plain;charset=utf-8,{}", percent_encode(&text));
        let js = format!(
            "const a = document.createElement('a'); a.href = \"{uri}\"; a.download = \"pittv3-results-{}.txt\"; a.click();",
            now_as_unix_epoch()
        );
        let _ = dioxus::document::eval(&js);
    };

    // loads a certificate into the aggregated list and validates it
    let mut load_and_run = move |name: String, bytes: Vec<u8>| {
        extend_unique(loaded_ees, vec![(name.clone(), bytes.clone())]);
        run(name, bytes);
    };

    // validates a self-contained hackathon artifacts_certs_r5.zip archive
    let mut run_zip = move |name: String, bytes: Vec<u8>| {
        let lines = validate_hackathon_zip(&name, bytes, &current_settings());
        results.write().extend(lines);
    };

    rsx! {
        style { {include_str!("../assets/pittv3-wasm.css")} }
        div { class: "wrap",
            h1 { "PITTv3" }
            p { class: "tagline",
                "Certification path validation in the browser — including ML-DSA and SLH-DSA (FIPS 204/205) — powered by "
                code { "certval" }
                " compiled to WebAssembly. Certificates never leave this page."
            }

            details { class: "panel notes",
                summary { "Notes" }
                ul {
                    li { "Uploaded files may be DER or PEM encoded." }
                    li {
                        "Uploaded trust anchors and intermediate CA certificates are used together "
                        "with the selected built-in store; select \"None\" to rely on uploads alone. "
                        "Uploads accumulate across selections until cleared."
                    }
                    li {
                        "Certificates to validate also accumulate; \"Validate all again\" re-runs "
                        "every loaded certificate after changing the store, uploads or settings."
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
                        "The built-in stores contain PKITS test artifacts re-signed using the "
                        "indicated post-quantum algorithms. The full set of PKITS artifacts "
                        "resigned with PQC algorithms can be found in the "
                        a {
                            href: "https://github.com/IETF-Hackathon/pqc-certificates",
                            target: "_blank",
                            "IETF Hackathon PQC Certificate repo"
                        }
                        "."
                    }
                    li {
                        "Provider artifacts_certs_r5.zip archives from the hackathon repo can be "
                        "validated wholesale: the zip's own trust anchors are used and each end "
                        "entity certificate is validated against them, honoring the settings above."
                    }
                }
            }

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
                    option { value: "none", selected: mode() == NO_STORE, "None (uploaded trust anchors only)" }
                }

                label { r#for: "toi", "Time of interest (Unix epoch): " }
                span {
                    input {
                        id: "toi",
                        r#type: "text",
                        value: "{toi}",
                        oninput: move |ev| toi.set(ev.value()),
                    }
                    button { onclick: move |_| toi.set(now_as_unix_epoch().to_string()), "Now" }
                }

                label { r#for: "validate-all", "Validate all paths: " }
                input {
                    id: "validate-all",
                    r#type: "checkbox",
                    checked: validate_all(),
                    onchange: move |ev| validate_all.set(ev.checked()),
                }
            }

            details { class: "panel",
                summary { "Additional trust anchors and intermediates" }
                div { class: "controls custom",
                    label { "Trust anchor(s): " }
                    input {
                        r#type: "file",
                        multiple: true,
                        accept: ".der,.crt,.cer,.pem,.ta",
                        onchange: move |ev| async move {
                            let files = read_files(&ev).await;
                            extend_unique(uploaded_tas, files);
                        },
                    }
                    label { "Intermediate CA(s): " }
                    input {
                        r#type: "file",
                        multiple: true,
                        accept: ".der,.crt,.cer,.pem",
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

            details { class: "panel",
                summary { "Path validation settings (RFC 5280 inputs)" }
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

                    label { r#for: "enforce-alg-key-size", "Enforce algorithm and key size constraints: " }
                    input {
                        id: "enforce-alg-key-size",
                        r#type: "checkbox",
                        checked: enforce_alg_and_key_size(),
                        onchange: move |ev| enforce_alg_and_key_size.set(ev.checked()),
                    }

                    span { class: "hint",
                        "Separate policy OIDs with spaces or commas; {ANY_POLICY_OID} is anyPolicy."
                    }
                }
            }

            div { class: "controls",
                label { "Certificate(s) to validate: " }
                input {
                    r#type: "file",
                    multiple: true,
                    accept: ".der,.crt,.cer,.pem",
                    onchange: move |ev| async move {
                        for (name, bytes) in read_files(&ev).await {
                            load_and_run(name, bytes);
                        }
                    },
                }
                span {
                    button {
                        onclick: move |_| load_and_run(SAMPLE_VALID.0.to_string(), SAMPLE_VALID.1.to_vec()),
                        "Try valid sample (ML-DSA-44)"
                    }
                    button {
                        onclick: move |_| load_and_run(SAMPLE_INVALID.0.to_string(), SAMPLE_INVALID.1.to_vec()),
                        "Try invalid sample (ML-DSA-44)"
                    }
                }
                span { class: "hint",
                    "{loaded_ees().len()} certificate(s) loaded "
                    button {
                        disabled: loaded_ees().is_empty(),
                        onclick: move |_| {
                            for (name, bytes) in loaded_ees() {
                                run(name, bytes);
                            }
                        },
                        "Validate all again"
                    }
                    button {
                        onclick: move |_| loaded_ees.write().clear(),
                        "Clear"
                    }
                }
            }

            div { class: "controls",
                label { "Hackathon artifacts zip: " }
                input {
                    r#type: "file",
                    multiple: true,
                    accept: ".zip",
                    onchange: move |ev| async move {
                        for (name, bytes) in read_files(&ev).await {
                            run_zip(name, bytes);
                        }
                    },
                }
                span { class: "hint",
                    "Validates an artifacts_certs_r5.zip from the IETF Hackathon PQC Certificate "
                    "repo: *_ta.der entries form the trust anchor store and *_ee.der entries are "
                    "validated against it. The archive is self-contained; the store and uploads "
                    "above are not consulted."
                }
            }

            div { class: "results",
                div { class: "results-header",
                    h2 { "Results" }
                    span {
                        button {
                            disabled: results.read().is_empty(),
                            onclick: save_results,
                            "Save"
                        }
                        button { onclick: move |_| results.write().clear(), "Clear" }
                    }
                }
                div { class: "results-body",
                    for line in results.read().iter() {
                        p { class: line.class, "{line.text}" }
                    }
                }
            }
        }
    }
}
