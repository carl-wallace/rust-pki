//! Provides GUI interface to similar set of actions as offered by command line utility

#![cfg(feature = "gui")]
#![allow(non_snake_case)]

use core::fmt::{Debug, Formatter};
use dioxus::prelude::*;

use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::Append;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;

#[cfg(feature = "std")]
use crate::options_std;

#[cfg(not(feature = "std"))]
use crate::options_std_app;

use crate::args::Pittv3Args;
use crate::get_now_as_unix_epoch;
use certval::{Error, Result};
use home::home_dir;
use log::{debug, error};
use rfd::FileDialog;
use std::fs;
use std::fs::{create_dir_all, File};

fn read_saved_args() -> Result<Pittv3Args> {
    if let Some(hd) = home_dir() {
        let app_home = hd.join(".pittv3");
        if !app_home.exists() {
            let _ = create_dir_all(app_home);
        }
        let app_cfg = hd.join(".pittv3").join("pittv3.cfg");
        if let Ok(f) = File::open(&app_cfg) {
            if let Ok(a) = serde_json::from_reader(&f) {
                return Ok(a);
            } else {
                return Err(Error::Unrecognized);
            }
        }
    }
    return Err(Error::Unrecognized);
}
fn save_args(args: &Pittv3Args) -> Result<()> {
    if let Some(hd) = home_dir() {
        let app_cfg = hd.join(".pittv3").join("pittv3.cfg");
        if let Ok(json_args) = serde_json::to_string(&args) {
            if let Err(e) = fs::write(&app_cfg, json_args) {
                error!("Unable to write args to file: {e}");
                return Err(Error::Unrecognized);
            } else {
                return Ok(());
            }
        }
    }
    Err(Error::Unrecognized)
}

fn string_or_none(ev: &Event<FormData>, key: &str) -> Option<String> {
    if let Some(v) = ev.values.get(key) {
        if v[0].is_empty() {
            None
        } else {
            Some(v[0].clone())
        }
    } else {
        None
    }
}

fn usize_or_none(ev: &Event<FormData>, key: &str) -> Option<usize> {
    match string_or_none(ev, key) {
        Some(v) => match v.parse::<usize>() {
            Ok(u) => Some(u),
            Err(_) => None,
        },
        None => None,
    }
}

fn true_or_false(ev: &Event<FormData>, key: &str) -> bool {
    if let Some(v) = ev.values.get(key) {
        if "0" == v[0] {
            false
        } else {
            true
        }
    } else {
        false
    }
}

use log::Record;

struct SimpleLogger;

impl Debug for SimpleLogger {
    fn fmt(&self, _f: &mut Formatter<'_>) -> core::fmt::Result {
        Ok(())
    }
}

impl Append for SimpleLogger {
    fn append(&self, _record: &Record<'_>) -> anyhow::Result<()> {
        Ok(())
    }

    fn flush(&self) {}
}

pub(crate) fn App(cx: Scope<'_>) -> Element<'_> {
    // --webpki-tas -d pittv3/tests/examples/downloads_webpki/ -s pittv3/tests/examples/disable_revocation_checking.json -y -e pittv3/tests/examples/amazon_2023.der
    let sa = match read_saved_args() {
        Ok(sa) => sa,
        Err(_) => Pittv3Args::default(),
    };

    let ta_folder = sa.ta_folder.unwrap_or_default();
    let s_ta_folder = use_state(cx, || ta_folder);
    let webpki_tas = sa.webpki_tas;
    let cbor = sa.cbor.unwrap_or_default();
    let s_cbor = use_state(cx, || cbor);
    let time_of_interest = get_now_as_unix_epoch().to_string();
    let logging_config = sa.logging_config.unwrap_or_default();
    let s_logging_config = use_state(cx, || logging_config);
    let error_folder = sa.error_folder.unwrap_or_default();
    let s_error_folder = use_state(cx, || error_folder);
    let download_folder = sa.download_folder.unwrap_or_default();
    let s_download_folder = use_state(cx, || download_folder);
    let ca_folder = sa.ca_folder.unwrap_or_default();
    let s_ca_folder = use_state(cx, || ca_folder);
    let generate = sa.generate;
    let chase_aia_and_sia = sa.chase_aia_and_sia;
    let cbor_ta_store = sa.cbor_ta_store;
    let validate_all = sa.validate_all;
    let validate_self_signed = sa.validate_self_signed;
    let dynamic_build = sa.dynamic_build;
    let end_entity_file = sa.end_entity_file.unwrap_or_default();
    let s_end_entity_file = use_state(cx, || end_entity_file);
    let end_entity_folder = sa.end_entity_folder.unwrap_or_default();
    let s_end_entity_folder = use_state(cx, || end_entity_folder);
    let results_folder = sa.results_folder.unwrap_or_default();
    let s_results_folder = use_state(cx, || results_folder);
    let settings = sa.settings.unwrap_or_default();
    let crl_folder = sa.crl_folder.unwrap_or_default();
    let s_crl_folder = use_state(cx, || crl_folder);
    let cleanup = sa.cleanup;
    let ta_cleanup = sa.ta_cleanup;
    let report_only = sa.report_only;
    let list_partial_paths = sa.list_partial_paths;
    let list_buffers = sa.list_buffers;
    let list_aia_and_sia = sa.list_aia_and_sia;
    let list_name_constraints = sa.list_name_constraints;
    let list_trust_anchors = sa.list_trust_anchors;
    let dump_cert_at_index = if let Some(u) = sa.dump_cert_at_index {
        u.to_string()
    } else {
        "".to_string()
    };
    let list_partial_paths_for_target = sa.list_partial_paths_for_target.unwrap_or_default();
    let s_list_partial_paths_for_target = use_state(cx, || list_partial_paths_for_target);
    let list_partial_paths_for_leaf_ca = if let Some(u) = sa.list_partial_paths_for_leaf_ca {
        u.to_string()
    } else {
        "".to_string()
    };
    let mozilla_csv = sa.mozilla_csv.unwrap_or_default();
    let s_mozilla_csv = use_state(cx, || mozilla_csv);

    cx.render(rsx! {
        div {
            form {
                onsubmit: move |ev| {
                    println!("Submitted {:?}", ev.values);

                    let toi = if let Some(v) = ev.values.get("time_of_interest") {
                        if let Ok(toi) = v[0].to_string().parse::<u64>() {
                            toi
                        }
                        else {
                            get_now_as_unix_epoch()
                        }
                    } else {
                        get_now_as_unix_epoch()
                    };

                    async move {
                        let args = Pittv3Args{
                            ta_folder: string_or_none(&ev, "ta-folder"),
                            webpki_tas: true_or_false(&ev, "webpki-tas"),
                            cbor: string_or_none(&ev, "cbor"),
                            time_of_interest: toi,
                            logging_config: string_or_none(&ev, "logging-config"),
                            error_folder: string_or_none(&ev, "error-folder"),
                            download_folder: string_or_none(&ev, "download-folder"),
                            ca_folder: string_or_none(&ev, "ca-folder"),
                            generate: true_or_false(&ev, "generate"),
                            chase_aia_and_sia: true_or_false(&ev, "chase-aia-and-sia"),
                            cbor_ta_store: true_or_false(&ev, "cbor-ta-store"),
                            validate_all: true_or_false(&ev, "validate-all"),
                            validate_self_signed: true_or_false(&ev, "validate-self-signed"),
                            dynamic_build: true_or_false(&ev, "dynamic-build"),
                            end_entity_file: string_or_none(&ev, "end-entity-file"),
                            end_entity_folder: string_or_none(&ev, "end-entity-folder"),
                            results_folder: string_or_none(&ev, "results-folder"),
                            settings: string_or_none(&ev, "settings"),
                            crl_folder: string_or_none(&ev, "crl-folder"),
                            cleanup: true_or_false(&ev, "cleanup"),
                            ta_cleanup: true_or_false(&ev, "ta-cleanup"),
                            report_only: true_or_false(&ev, "report-only"),
                            list_partial_paths: true_or_false(&ev, "list-partial-paths"),
                            list_buffers: true_or_false(&ev, "list-buffers"),
                            list_aia_and_sia: true_or_false(&ev, "list-aia-and-sia"),
                            list_name_constraints: true_or_false(&ev, "list-name-constraints"),
                            list_trust_anchors: true_or_false(&ev, "list-trust-anchors"),
                            dump_cert_at_index: usize_or_none(&ev, "dump_cert_at_index"),
                            list_partial_paths_for_target: string_or_none(&ev, "list-partial-paths-for-target"),
                            list_partial_paths_for_leaf_ca: usize_or_none(&ev, "dump_cert_at_index"),
                            mozilla_csv: string_or_none(&ev, "mozilla-csv"),
                        };

                        let _ = save_args(&args);

                        let mut logging_configured = false;

                        if let Some(logging_config) = &args.logging_config {
                            match log4rs::config::load_config_file(logging_config, Default::default()) {
                                Ok(_c) => {
                                    logging_configured = true;
                                    let c = Config::builder().appender(Appender::builder().build("SimpleLogger", Box::new(SimpleLogger))).build(Root::builder().appender("SimpleLogger").build(LevelFilter::Info)).unwrap();
                                    if let Err(e) = log4rs::init_config(c) {
                                        println!(
                                            "ERROR: failed to configure logging using {} with {:?}. Continuing without logging.",
                                            logging_config, e
                                        );
                                    }
                                }
                                Err(e) => {
                                    println!(
                                        "ERROR: failed to load logging configuration from {} with {:?}. Continuing without logging.",
                                        logging_config, e
                                    );
                                }
                            }
                        }

                        if !logging_configured {
                            // if there's no config, prepare one using stdout
                            let stdout = ConsoleAppender::builder()
                                .encoder(Box::new(PatternEncoder::new("{m}{n}")))
                                .build();
                            match Config::builder()
                                .appender(Appender::builder().build("stdout", Box::new(stdout)))
                                .build(Root::builder().appender("stdout").build(LevelFilter::Info)) {
                                Ok(config) => {
                                        let handle = log4rs::init_config(config);
                                        if let Err(e) = handle {
                                            println!(
                                                "ERROR: failed to configure logging for stdout with {:?}. Continuing without logging.",
                                                e
                                            );
                                        }
                                    }
                                Err(e) => {
                                    println!("ERROR: failed to prepare default logging configuration with {:?}. Continuing without logging", e);
                                }
                            }
                        }

                        debug!("PITTv3 start");

                        #[cfg(feature = "std")]
                        options_std(&args).await;

                        #[cfg(not(feature = "std"))]
                        options_std_app(&args);

                        debug!("PITTv3 end");
                    }
                    // future.restart();
                },
                oninput: move |ev| println!("Input {:?}", ev.values),
                fieldset {
                    table {
                        tbody {
                            tr{
                                td{div{title: "Full path of folder containing binary DER-encoded trust anchors to use when generating CBOR file containing partial certification paths and when validating certification paths.", class: "visible", label {r#for: "ta-folder", "TA Folder: "}}}
                                td{input { r#type: "text", name: "ta-folder", value: "{s_ta_folder}", style: "width: 500px;"}}
                                button {
                                    r#type: "button",
                                    onclick: move |_| {
                                        let setter = s_ta_folder.setter();
                                        async move {
                                            let file = FileDialog::new()
                                                .set_directory(home_dir().unwrap_or("/".into()))
                                                .pick_folder();
                                            if let Some(file) = file {
                                                setter(file.into_os_string().into_string().unwrap());
                                            }
                                        }
                                    },
                                    "..."
                                }
                            }
                            tr{
                                td{label {r#for: "cbor", "CBOR: "}}
                                td{input { r#type: "text", name: "cbor", value: "{s_cbor}", style: "width: 500px;"}}
                                button {
                                    r#type: "button",
                                    onclick: move |_| {
                                        let setter = s_cbor.setter();
                                        async move {
                                            let file = FileDialog::new()
                                                .add_filter("PITTv3 CBOR-serialized PKI", &["cbor", "pki"])
                                                .set_directory(home_dir().unwrap_or("/".into()))
                                                .pick_file();
                                            if let Some(file) = file {
                                                setter(file.into_os_string().into_string().unwrap());
                                            }
                                        }
                                    },
                                    "..."
                                }
                            }
                            tr{
                                td{label {r#for: "time-of-interest", "Time of Interest: "}}
                                td{input { r#type: "text", name: "time-of-interest", value: "{time_of_interest}", style: "width: 500px;"}}
                            }
                            tr{
                                td{label {r#for: "logging-config", "Logging Configuration: "}}
                                td{input { r#type: "text", name: "logging-config", value: "{s_logging_config}", style: "width: 500px;"}}
                                button {
                                    r#type: "button",
                                    onclick: move |_| {
                                        let setter = s_logging_config.setter();
                                        async move {
                                            let file = FileDialog::new()
                                                .add_filter("log4rs Configuration", &["yaml"])
                                                .set_directory(home_dir().unwrap_or("/".into()))
                                                .pick_file();
                                            if let Some(file) = file {
                                                setter(file.into_os_string().into_string().unwrap());
                                            }
                                        }
                                    },
                                    "..."
                                }
                            }
                            tr{
                                td{label {r#for: "error-folder", "Error Folder: "}}
                                td{input { r#type: "text", name: "error-folder", value: "{s_error_folder}", style: "width: 500px;"}}
                                button {
                                    r#type: "button",
                                    onclick: move |_| {
                                        let setter = s_error_folder.setter();
                                        async move {
                                            let file = FileDialog::new()
                                                .set_directory(home_dir().unwrap_or("/".into()))
                                                .pick_folder();
                                            if let Some(file) = file {
                                                setter(file.into_os_string().into_string().unwrap());
                                            }
                                        }
                                    },
                                    "..."
                                }
                            }
                            tr{
                                td{label {r#for: "download-folder", "Download Folder: "}}
                                td{input { r#type: "text", name: "download-folder", value: "{s_download_folder}", style: "width: 500px;"}}
                                button {
                                    r#type: "button",
                                    onclick: move |_| {
                                        let setter = s_download_folder.setter();
                                        async move {
                                            let file = FileDialog::new()
                                                .set_directory(home_dir().unwrap_or("/".into()))
                                                .pick_folder();
                                            if let Some(file) = file {
                                                setter(file.into_os_string().into_string().unwrap());
                                            }
                                        }
                                    },
                                    "..."
                                }
                            }
                            tr{
                                td{label {r#for: "ca-folder", "CA Folder: "}}
                                td{input { r#type: "text", name: "ca-folder", value: "{s_ca_folder}", style: "width: 500px;"}}
                                button {
                                    r#type: "button",
                                    onclick: move |_| {
                                        let setter = s_ca_folder.setter();
                                        async move {
                                            let file = FileDialog::new()
                                                .set_directory(home_dir().unwrap_or("/".into()))
                                                .pick_folder();
                                            if let Some(file) = file {
                                                setter(file.into_os_string().into_string().unwrap());
                                            }
                                        }
                                    },
                                    "..."
                                }
                            }
                            tr{
                                td{label {r#for: "webpki-tas", "WebPKI TAs: "}}
                                td{input { r#type: "checkbox", name: "webpki-tas", checked: "{webpki_tas}", value: "{webpki_tas}" }}
                            }
                        }
                    }
                }
                fieldset {
                    table {
                        tbody {
                            tr{
                                td{
                                    td{label {r#for: "generate", "Generate:"}}
                                    td{ input { r#type: "checkbox", name: "generate", checked: "{generate}", value: "{generate}" }}
                                }
                                td{
                                    td{label {r#for: "chase-aia-and-sia", " Chase SIA and AIA:"}}
                                    td{ input { r#type: "checkbox", name: "chase-aia-and-sia", checked: "{chase_aia_and_sia}", value: "{chase_aia_and_sia}" }}
                                }
                                td{
                                    td{label {r#for: "cbor-ta-store", " CBOR TA store:"}}
                                    td{ input { r#type: "checkbox", name: "cbor-ta-store", checked: "{cbor_ta_store}", value: "{cbor_ta_store}" }}
                                }
                            }
                        }
                    }
                }
                fieldset {
                    table {
                        tbody {
                            tr{
                                td{label {r#for: "end-entity-file", "End Entity File: "}}
                                td{input { r#type: "text", name: "end-entity-file", value: "{s_end_entity_file}", style: "width: 500px;"}}
                                button {
                                    r#type: "button",
                                    onclick: move |_| {
                                        let setter = s_end_entity_file.setter();
                                        async move {
                                            let file = FileDialog::new()
                                                .add_filter("Certificate File", &["der", "crt"])
                                                .set_directory(home_dir().unwrap_or("/".into()))
                                                .pick_file();
                                            if let Some(file) = file {
                                                setter(file.into_os_string().into_string().unwrap());
                                            }
                                        }
                                    },
                                    "..."
                                }
                            }
                            tr{
                                td{label {r#for: "end-entity-folder", "End Entity Folder: "}}
                                td{input { r#type: "text", name: "end-entity-folder", value: "{s_end_entity_folder}", style: "width: 500px;"}}
                                button {
                                    r#type: "button",
                                    onclick: move |_| {
                                        let setter = s_end_entity_folder.setter();
                                        async move {
                                            let file = FileDialog::new()
                                                .set_directory(home_dir().unwrap_or("/".into()))
                                                .pick_folder();
                                            if let Some(file) = file {
                                                setter(file.into_os_string().into_string().unwrap());
                                            }
                                        }
                                    },
                                    "..."
                                }
                            }
                            tr{
                                td{label {r#for: "results-folder", "Results Folder: "}}
                                td{input { r#type: "text", name: "results-folder", value: "{s_results_folder}", style: "width: 500px;"}}
                                button {
                                    r#type: "button",
                                    onclick: move |_| {
                                        let setter = s_results_folder.setter();
                                        async move {
                                            let file = FileDialog::new()
                                                .set_directory(home_dir().unwrap_or("/".into()))
                                                .pick_folder();
                                            if let Some(file) = file {
                                                setter(file.into_os_string().into_string().unwrap());
                                            }
                                        }
                                    },
                                    "..."
                                }
                            }
                            tr{
                                td{label {r#for: "settings", "Settings: "}}
                                td{input { r#type: "text", name: "settings", value: "{settings}", style: "width: 500px;"}}
                            }
                            tr{
                                td{label {r#for: "crl-folder", "CRL Folder: "}}
                                td{input { r#type: "text", name: "crl-folder", value: "{s_crl_folder}", style: "width: 500px;"}}
                                button {
                                    r#type: "button",
                                    onclick: move |_| {
                                        let setter = s_crl_folder.setter();
                                        async move {
                                            let file = FileDialog::new()
                                                .set_directory(home_dir().unwrap_or("/".into()))
                                                .pick_folder();
                                            if let Some(file) = file {
                                                setter(file.into_os_string().into_string().unwrap());
                                            }
                                        }
                                    },
                                    "..."
                                }
                            }
                        }
                    }
                    table {
                        tbody {
                            tr {
                                td{
                                    td{label {r#for: "validate-all", "Validate All: "}}
                                    td{input { r#type: "checkbox", name: "validate-all", checked: "{validate_all}", value: "{validate_all}" }}
                                }
                                td{
                                    td{label {r#for: "validate-self-signed", "Validate Self-Signed: "}}
                                    td{input { r#type: "checkbox", name: "validate-self-signed", checked: "{validate_self_signed}", value: "{validate_self_signed}" }}
                                }
                                td{
                                    td{label {r#for: "dynamic-build", "Dynamic Build: "}}
                                    td{input { r#type: "checkbox", name: "dynamic-build", checked: "{dynamic_build}", value: "{dynamic_build}" }}
                                }
                            }
                        }
                    }
                }
                fieldset {
                    table {
                        tbody {
                            tr{
                                td{
                                    td{label {r#for: "cleanup", "Cleanup:"}}
                                    td{input { r#type: "checkbox", name: "cleanup", checked: "{cleanup}", value: "{cleanup}" }}
                                }
                                td{
                                    td{label {r#for: "ta-cleanup", " TA Cleanup:"}}
                                    td{input { r#type: "checkbox", name: "ta-cleanup", checked: "{ta_cleanup}", value: "{ta_cleanup}" }}
                                }
                                td{
                                    td{label {r#for: "report-only", " Report Only:"}}
                                    td{input { r#type: "checkbox", name: "report-only", checked: "{report_only}", value: "{report_only}" }}
                                }
                            }
                        }
                    }
                }
                fieldset {
                    table {
                        tbody {
                            tr{
                                td{
                                    td{label {r#for: "list-partial-paths", "List Partial Paths: "}}
                                    td{input { r#type: "checkbox", name: "list-partial-paths", checked: "{list_partial_paths}", value: "{list_partial_paths}" }}
                                }
                                td{
                                    td{label {r#for: "list-buffers", "List Buffers: "}}
                                    td{input { r#type: "checkbox", name: "list-buffers", checked: "{list_buffers}", value: "{list_buffers}" }}
                                }
                                td{
                                    td{label {r#for: "list-aia-and-sia", "List SIA and AIA: "}}
                                    td{input { r#type: "checkbox", name: "list-aia-and-sia", checked: "{list_aia_and_sia}", value: "{list_aia_and_sia}" }}
                                }
                            }
                            tr{
                                td{
                                    td{label {r#for: "list-name-constraints", "List Name Constraints: "}}
                                    td{input { r#type: "checkbox", name: "list-name-constraints", checked: "{list_name_constraints}", value: "{list_name_constraints}" }}
                                }
                                td{
                                    td{label {r#for: "list-trust-anchors", "List Trust Anchors: "}}
                                    td{input { r#type: "checkbox", name: "list-trust-anchors", checked: "{list_trust_anchors}", value: "{list_trust_anchors}" }}
                                }
                            }
                        }
                    }
                    table {
                        tbody {
                            tr{
                                td{label {r#for: "dump-certs-at-index", "Dump Certificate At Index: "}}
                                td{input { r#type: "text", name: "dump-certs-at-index", value: "{dump_cert_at_index}", style: "width: 500px;"}}
                            }
                            tr{
                                td{label {r#for: "list-partial-paths-for-target", "List Partial Paths for Target: "}}
                                td{input {r#type: "text", name: "list-partial-paths-for-target", value: "{s_list_partial_paths_for_target}", style: "width: 500px;"}}
                                button {
                                    r#type: "button",
                                    onclick: move |_| {
                                        let setter = s_list_partial_paths_for_target.setter();
                                        async move {
                                            let file = FileDialog::new()
                                                .add_filter("Certificate File", &["der", "crt"])
                                                .set_directory(home_dir().unwrap_or("/".into()))
                                                .pick_folder();
                                            if let Some(file) = file {
                                                setter(file.into_os_string().into_string().unwrap());
                                            }
                                        }
                                    },
                                    "..."
                                }
                            }
                            tr{
                                td{label {r#for: "list-partial-paths-for-leaf-ca", "List Partial Paths for Leaf CA: "}}
                                td{input {r#type: "text", name: "list-partial-paths-for-leaf-ca", value: "{list_partial_paths_for_leaf_ca}", style: "width: 500px;"}}
                            }
                        }
                    }
                }
                fieldset {
                    table {
                        tbody {
                            tr{
                                td{label {r#for: "mozilla-csv", "Mozilla CSV: "}}
                                td{input {r#type: "text", name: "mozilla-csv", value: "{s_mozilla_csv}", style: "width: 500px;"}}
                                button {
                                    r#type: "button",
                                    onclick: move |_| {
                                        let setter = s_mozilla_csv.setter();
                                        async move {
                                            let file = FileDialog::new()
                                                .add_filter("CSV file", &["csv"])
                                                .set_directory(home_dir().unwrap_or("/".into()))
                                                .pick_file();
                                            if let Some(file) = file {
                                                setter(file.into_os_string().into_string().unwrap());
                                            }
                                        }
                                    },
                                    "..."
                                }
                            }
                        }
                    }
                }
                div{
                    style: "text-align:center",
                    button { r#type: "submit", value: "Submit", "Run Command(s)" }
                }
            }
        }
    })
}
