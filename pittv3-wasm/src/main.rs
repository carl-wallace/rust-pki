#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

mod validate;

use dioxus::prelude::*;
use web_time::{SystemTime, UNIX_EPOCH};

use crate::validate::{
    validate_against_store, validate_against_uploads, ResultLine, SAMPLE_INVALID, SAMPLE_VALID,
    STORES,
};

const CUSTOM_MODE: usize = usize::MAX;

fn now_as_unix_epoch() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => 0,
    }
}

fn main() {
    dioxus::launch(App);
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

#[component]
fn App() -> Element {
    let mut mode = use_signal(|| 0usize);
    let mut toi = use_signal(|| now_as_unix_epoch().to_string());
    let mut validate_all = use_signal(|| true);
    let mut results = use_signal(Vec::<ResultLine>::new);
    let mut uploaded_tas = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut uploaded_cas = use_signal(Vec::<(String, Vec<u8>)>::new);

    let mut run = move |name: String, bytes: Vec<u8>| {
        let toi_v = toi().parse::<u64>().unwrap_or_else(|_| now_as_unix_epoch());
        let lines = if mode() == CUSTOM_MODE {
            validate_against_uploads(
                &uploaded_tas(),
                &uploaded_cas(),
                &name,
                &bytes,
                toi_v,
                validate_all(),
            )
        } else {
            validate_against_store(&STORES[mode()], &name, &bytes, toi_v, validate_all())
        };
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

            div { class: "controls",
                label { r#for: "store", "Trust anchor / CA store: " }
                select {
                    id: "store",
                    onchange: move |ev| {
                        let v = ev.value();
                        mode.set(v.parse::<usize>().unwrap_or(CUSTOM_MODE));
                    },
                    for (i, s) in STORES.iter().enumerate() {
                        option { value: "{i}", selected: mode() == i, "{s.label}" }
                    }
                    option { value: "custom", selected: mode() == CUSTOM_MODE, "Custom (uploaded trust anchors)" }
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

            if mode() == CUSTOM_MODE {
                div { class: "controls custom",
                    label { "Trust anchor(s): " }
                    input {
                        r#type: "file",
                        multiple: true,
                        accept: ".der,.crt,.cer,.pem,.ta",
                        onchange: move |ev| async move {
                            let files = read_files(&ev).await;
                            uploaded_tas.write().extend(files);
                        },
                    }
                    label { "Intermediate CA(s) (optional): " }
                    input {
                        r#type: "file",
                        multiple: true,
                        accept: ".der,.crt,.cer,.pem",
                        onchange: move |ev| async move {
                            let files = read_files(&ev).await;
                            uploaded_cas.write().extend(files);
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
                label { "Certificate(s) to validate: " }
                input {
                    r#type: "file",
                    multiple: true,
                    accept: ".der,.crt,.cer,.pem",
                    onchange: move |ev| async move {
                        for (name, bytes) in read_files(&ev).await {
                            run(name, bytes);
                        }
                    },
                }
                span {
                    button {
                        onclick: move |_| run(SAMPLE_VALID.0.to_string(), SAMPLE_VALID.1.to_vec()),
                        "Try valid sample (ML-DSA-44)"
                    }
                    button {
                        onclick: move |_| run(SAMPLE_INVALID.0.to_string(), SAMPLE_INVALID.1.to_vec()),
                        "Try invalid sample (ML-DSA-44)"
                    }
                }
            }

            div { class: "results",
                div { class: "results-header",
                    h2 { "Results" }
                    button { onclick: move |_| results.write().clear(), "Clear" }
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
