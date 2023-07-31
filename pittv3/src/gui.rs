//! Provides GUI interface to similar set of actions as offered by command line utility

#![cfg(any(feature = "gui", doc))]

#![allow(non_snake_case)]
use dioxus::prelude::*;

use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;

#[cfg(feature = "std")]
use crate::options_std;

#[cfg(not(feature = "std"))]
use crate::options_std_app;

use crate::args::Pittv3Args;
use crate::get_now_as_unix_epoch;

pub(crate) fn App(cx: Scope<'_>) -> Element<'_> {
    // --webpki-tas -d pittv3/tests/examples/downloads_webpki/ -s pittv3/tests/examples/disable_revocation_checking.json -y -e pittv3/tests/examples/amazon_2023.der
    let ta_folder =  "";
    let webpki_tas =  true;
    let cbor =  "";
    let time_of_interest =  "";
    let logging_config =  "";
    let error_folder =  "";
    let download_folder =  "pittv3/tests/examples/downloads_webpki";
    let ca_folder =  "";
    let generate =  false;
    let chase_aia_and_sia =  false;
    let cbor_ta_store =  false;
    let validate_all =  false;
    let validate_self_signed =  false;
    let dynamic_build =  true;
    let end_entity_file =  "pittv3/tests/examples/amazon_2023.der";
    let end_entity_folder =  "";
    let results_folder =  "";
    let settings =  "pittv3/tests/examples/disable_revocation_checking.json";
    let crl_folder =  "";
    let cleanup =  false;
    let ta_cleanup =  false;
    let report_only =  false;
    let list_partial_paths =  false;
    let list_buffers =  false;
    let list_aia_and_sia =  false;
    let list_name_constraints =  false;
    let list_trust_anchors =  false;
    let dump_cert_at_index =  "";
    let list_partial_paths_for_target =  "";
    let list_partial_paths_for_leaf_ca =  "";
    let mozilla_csv =  "";

    cx.render(rsx! {
        div {
            form {
                onsubmit: move |ev| {
                    println!("Submitted {:?}", ev.values);

                    let toi = if time_of_interest.is_empty() {
                        get_now_as_unix_epoch()
                    } else {
                        if let Ok(toi) = dump_cert_at_index.to_string().parse::<u64>() {
                            toi
                        }
                        else {
                            get_now_as_unix_epoch()
                        }
                    };

                    async move {
                        let args = Pittv3Args{
                            ta_folder: if ta_folder.is_empty() {None} else {Some(ta_folder.to_string())},
                            webpki_tas,
                            cbor: if cbor.is_empty() {None} else {Some(cbor.to_string())},
                            time_of_interest: toi,
                            logging_config: if logging_config.is_empty() {None} else {Some(logging_config.to_string())},
                            error_folder: if error_folder.is_empty() {None} else {Some(error_folder.to_string())},
                            download_folder: if download_folder.is_empty() {None} else {Some(download_folder.to_string())},
                            ca_folder: if ca_folder.is_empty() {None} else {Some(ca_folder.to_string())},
                            generate,
                            chase_aia_and_sia,
                            cbor_ta_store,
                            validate_all,
                            validate_self_signed,
                            dynamic_build,
                            end_entity_file: if end_entity_file.is_empty() {None} else {Some(end_entity_file.to_string())},
                            end_entity_folder: if end_entity_folder.is_empty() {None} else {Some(end_entity_folder.to_string())},
                            results_folder: if results_folder.is_empty() {None} else {Some(results_folder.to_string())},
                            settings: if settings.is_empty() {None} else {Some(settings.to_string())},
                            crl_folder: if crl_folder.is_empty() {None} else {Some(crl_folder.to_string())},
                            cleanup,
                            ta_cleanup,
                            report_only,
                            list_partial_paths,
                            list_buffers,
                            list_aia_and_sia,
                            list_name_constraints,
                            list_trust_anchors,
                            dump_cert_at_index: if dump_cert_at_index.is_empty() {None} else {Some(dump_cert_at_index.to_string().parse::<usize>().unwrap())},
                            list_partial_paths_for_target: if list_partial_paths_for_target.is_empty() {None} else {Some(list_partial_paths_for_target.to_string())},
                            list_partial_paths_for_leaf_ca: if list_partial_paths_for_leaf_ca.is_empty() {None} else {Some(list_partial_paths_for_leaf_ca.to_string().parse::<usize>().unwrap())},
                            mozilla_csv: if mozilla_csv.is_empty() {None} else {Some(mozilla_csv.to_string())},
                        };

                        let mut logging_configured = false;

                        if let Some(logging_config) = &args.logging_config {
                            if let Err(e) = log4rs::init_file(logging_config, Default::default()) {
                                println!(
                                    "ERROR: failed to configure logging using {} with {:?}. Continuing without logging.",
                                    logging_config, e
                                );
                            } else {
                                logging_configured = true;
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

                        #[cfg(feature = "std")]
                        options_std(&args).await;

                        #[cfg(not(feature = "std"))]
                        options_std_app(&args);
                    }
                    // future.restart();
                },
                oninput: move |ev| println!("Input {:?}", ev.values),
                fieldset {
                    table {
                        tbody {
                            tr{td{label {r#for: "ta-folder", "TA Folder: "}} td{input { r#type: "text", name: "ta-folder", value: "{ta_folder}", style: "width: 500px;"}}}
                            tr{td{label {r#for: "cbor", "CBOR: "}} td{ input { r#type: "text", name: "cbor", value: "{cbor}", style: "width: 500px;"}}}
                            tr{td{label {r#for: "time-of-interest", "Time of Interest: "}} td{ input { r#type: "text", name: "time-of-interest", value: "{time_of_interest}", style: "width: 500px;"}}}
                            tr{td{label {r#for: "logging-config", "Logging Configuration: "}} td{ input { r#type: "text", name: "logging-config", value: "{logging_config}", style: "width: 500px;"}}}
                            tr{td{label {r#for: "error-folder", "Error Folder: "}} td{ input { r#type: "text", name: "error-folder", value: "{error_folder}", style: "width: 500px;"}}}
                            tr{td{label {r#for: "download-folder", "Download Folder: "}} td{ input { r#type: "text", name: "download-folder", value: "{download_folder}", style: "width: 500px;"}}}
                            tr{td{label {r#for: "ca-folder", "CA Folder: "}} td{ input { r#type: "text", name: "ca-folder", value: "{ca_folder}", style: "width: 500px;"}}}
                            tr{td{label {r#for: "webpki-tas", "WebPKI TAs: "}} td{ input { r#type: "checkbox", name: "webpki-tas", value: "{cbor_ta_store}" }}}
                        }
                    }
                }
                fieldset {
                    table {
                        tbody {
                            tr{td{label {r#for: "generate", "Generate: "}} td{ input { r#type: "checkbox", name: "generate", value: "{generate}" }}}
                            tr{td{label {r#for: "chase-aia-and-sia", "Chase SIA and AIA: "}} td{ input { r#type: "checkbox", name: "chase-aia-and-sia", value: "{chase_aia_and_sia}" }}}
                            tr{td{label {r#for: "cbor-ta-store", "CBOR TA store: "}} td{ input { r#type: "checkbox", name: "cbor-ta-store", value: "{webpki_tas}" }}}
                        }
                    }
                }
                fieldset {
                    table {
                        tbody {
                            tr{td{label {r#for: "end-entity-file", "End Entity File: "}} td{input { r#type: "text", name: "end-entity-file", value: "{end_entity_file}", style: "width: 500px;"}}}
                            tr{td{label {r#for: "end-entity-folder", "End Entity Folder: "}} td{input { r#type: "text", name: "end-entity-folder", value: "{end_entity_folder}", style: "width: 500px;"}}}
                            tr{td{label {r#for: "results-folder", "Results Folder: "}} td{input { r#type: "text", name: "results-folder", value: "{results_folder}", style: "width: 500px;"}}}
                            tr{td{label {r#for: "settings", "Settings: "}} td{input { r#type: "text", name: "settings", value: "{settings}", style: "width: 500px;"}}}
                            tr{td{label {r#for: "crl-folder", "CRL Folder: "}} td{input { r#type: "text", name: "crl-folder", value: "{crl_folder}", style: "width: 500px;"}}}
                            tr{td{label {r#for: "validate-all", "Validate All: "}} td{ input { r#type: "checkbox", name: "validate-all", value: "{validate_all}" }}}
                            tr{td{label {r#for: "validate-self-signed", "Validate Self-Signed: "}} td{ input { r#type: "checkbox", name: "validate-self-signed", value: "{validate_self_signed}" }}}
                            tr{td{label {r#for: "dynamic-build", "Dynamic Build: "}} td{ input { r#type: "checkbox", name: "dynamic-build", value: "{dynamic_build}" }}}
                        }
                    }
                }
                fieldset {
                    table {
                        tbody {
                            tr{td{label {r#for: "cleanup", "Cleanup: "}} td{ input { r#type: "checkbox", name: "cleanup", value: "{cleanup}" }}}
                            tr{td{label {r#for: "ta-cleanup", "TA Cleanup: "}} td{ input { r#type: "checkbox", name: "ta-cleanup", value: "{ta_cleanup}" }}}
                            tr{td{label {r#for: "report-only", "Report Only: "}} td{ input { r#type: "checkbox", name: "report-only", value: "{report_only}" }}}
                        }
                    }
                }
                fieldset {
                    table {
                        tbody {
                            tr{td{label {r#for: "list-partial-paths", "List Partial Paths: "}} td{ input { r#type: "checkbox", name: "list-partial-paths", value: "{list_partial_paths}" }}}
                            tr{td{label {r#for: "list-buffers", "List Buffers: "}} td{ input { r#type: "checkbox", name: "list-buffers", value: "{list_buffers}" }}}
                            tr{td{label {r#for: "list-aia-and-sia", "List SIA and AIA: "}} td{ input { r#type: "checkbox", name: "list-aia-and-sia", value: "{list_aia_and_sia}" }}}
                            tr{td{label {r#for: "list-name-constraints", "List Name Constraints: "}} td{ input { r#type: "checkbox", name: "list-name-constraints", value: "{list_name_constraints}" }}}
                            tr{td{label {r#for: "list-trust-anchors", "List Trust Anchors: "}} td{ input { r#type: "checkbox", name: "list-trust-anchors", value: "{list_trust_anchors}" }}}
                            tr{td{label {r#for: "list-partial-paths-for-target", "List Partial Paths for Target: "}} td{input { r#type: "text", name: "list-partial-paths-for-target", value: "{list_partial_paths_for_target}", style: "width: 500px;"}}}
                            tr{td{label {r#for: "list-partial-paths-for-leaf-ca", "List Partial Paths for Leaf CA: "}} td{input { r#type: "text", name: "list-partial-paths-for-leaf-ca", value: "{list_partial_paths_for_leaf_ca}", style: "width: 500px;"}}}
                        }
                    }
                }
                fieldset {
                    table {
                        tbody {
                            tr{td{label {r#for: "mozilla-csv", "Mozilla CSV: "}} td{input { r#type: "text", name: "mozilla-csv", value: "{mozilla_csv}", style: "width: 500px;"}}}
                        }
                    }
                }
                button { r#type: "submit", value: "Submit", "Submit the form" }
            }
        }
    })
}

