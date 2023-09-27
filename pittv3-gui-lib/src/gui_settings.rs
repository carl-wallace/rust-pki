#![allow(non_snake_case)]

use dioxus::prelude::*;

use alloc::string::String;

#[cfg(feature = "gui_desktop")]
use crate::gui_utils::*;
#[cfg(feature = "gui_desktop")]
use certval::*;
#[cfg(feature = "gui_desktop")]
use dioxus_desktop::use_window;
#[cfg(feature = "gui_desktop")]
use pkiprocmacros::setting_vars;
#[cfg(feature = "gui_desktop")]
use std::io::Write;

use log::error;

#[derive(Props, PartialEq)]
pub struct SettingsProps {
    pub x: String,
}

#[cfg(feature = "gui_desktop")]
pub fn edit_settings(cx: Scope<'_, SettingsProps>) -> Element<'_> {
    let p = &cx.props.x;
    let cps = read_settings(&Some(p.clone())).unwrap_or_default();
    let window = use_window(cx);

    println!("{:?}", p);
    println!("{:?}", cps);

    setting_vars!(initial_explicit_policy_indicator, cps, cx);
    // setting_vars!(initial_policy_mapping_inhibit_indicator, cps, cx);
    // setting_vars!(initial_inhibit_any_policy_indicator, cps, cx);
    // setting_vars!(initial_policy_set, cps, cx);
    // todo name constraints and toi
    setting_vars!(check_revocation_status, cps, cx);
    setting_vars!(retrieve_from_aia_sia_http, cps, cx);

    let s_close = use_state(cx, || false);

    cx.render(rsx! {
        div {
            form {
                onsubmit: move |ev| {
                    if !s_close.get() {
                        let mut cps = CertificationPathSettings::new();

                        set_initial_explicit_policy_indicator(&mut cps, true_or_false(&ev, "initial_explicit_policy_indicator"),);

                        set_check_revocation_status(&mut cps, true_or_false(&ev, "check_revocation_status"),);
                        set_retrieve_from_aia_sia_http(&mut cps, true_or_false(&ev, "retrieve_from_aia_sia_http"),);
                        match serde_json::to_string(&cps) {
                            Ok(json_ps) => {
                                match std::fs::File::create(p) {
                                    Ok(mut final_file) => {
                                        if let Err(e) = final_file.write_all(json_ps.as_bytes()) {
                                            error!("Failed to save receive settings: {e}");
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to create file to receive settings: {e}");
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to encode settings: {e}");
                            }
                        }
                    }
                    window.close();
                },
                fieldset {
                    // todo add more stuff to UI
                    // PS_INITIAL_EXPLICIT_POLICY_INDICATOR: bool
                    // PS_INITIAL_POLICY_MAPPING_INHIBIT_INDICATOR: bool
                    // PS_INITIAL_INHIBIT_ANY_POLICY_INDICATOR: bool
                    // PS_INITIAL_POLICY_SET: set of OIDs
                    // PS_INITIAL_PERMITTED_SUBTREES: NameConstraints
                    // PS_INITIAL_EXCLUDED_SUBTREES: NameConstraints
                    // PS_TIME_OF_INTEREST: u64

                    table {
                        tbody {
                            tr{
                                td{label {r#for: "require_explicit_policy", "Require Explicit Policy: "}}
                                td{input { r#type: "checkbox", name: "require_explicit_policy", checked: "{s_initial_explicit_policy_indicator}", value: "{s_initial_explicit_policy_indicator}" }}
                            }
                        }
                    }
                }
                // fieldset {
                //     // todo add more stuff to UI
                //     // PS_ENFORCE_TRUST_ANCHOR_CONSTRAINTS: bool
                //     // PS_ENFORCE_TRUST_ANCHOR_VALIDITY: bool
                //     // PS_KEY_USAGE: u16
                //     // PS_EXTENDED_KEY_USAGE: set of OIDs
                //     // PS_EXTENDED_KEY_USAGE_PATH: bool
                //
                //     // PS_INITIAL_PATH_LENGTH_CONSTRAINT: u8
                //     // PS_MAX_PATH_LENGTH_CONSTRAINT: u8
                //     // PS_CRL_TIMEOUT: u64
                //     // PS_ENFORCE_ALG_AND_KEY_SIZE_CONSTRAINTS: bool
                //     // PS_USE_VALIDATOR_FILTER_WHEN_BUILDING: bool
                //     // PS_CHECK_REVOCATION_STATUS: bool
                //     // PS_CHECK_OCSP_FROM_AIA: bool
                //     // PS_RETRIEVE_FROM_AIA_SIA_HTTP: bool
                //     // PS_RETRIEVE_FROM_AIA_SIA_LDAP: bool
                //     // PS_CHECK_CRLS: bool
                //     // PS_CHECK_CRLDP_HTTP: bool
                //     // PS_CHECK_CRLDP_LDAP: bool
                //     // PS_CRL_GRACE_PERIODS_AS_LAST_RESORT: bool
                //     // PS_IGNORE_EXPIRED: bool
                //     // PS_OCSP_AIA_NONCE_SETTING: i8
                //     // PS_CERTIFICATES: set of certs
                //     // PS_REQUIRE_COUNTRY_CODE_INDICATOR: bool
                //     // PS_PERM_COUNTRIES: vector of string
                //     // PS_EXCL_COUNTRIES: vector of string
                //     // PS_TRUST_ANCHOR_FOLDER: string
                //     // PS_CERTIFICATION_AUTHORITY_FOLDER: string
                //     // PS_DOWNLOAD_FOLDER: string
                //     // PS_LAST_MODIFIED_MAP_FILE: string
                //     // PS_URI_BLOCKLIST_FILE: string
                //     // PS_CBOR_TA_STORE: string
                //     // PS_REQUIRE_TA_STORE: bool
                //     // PS_USE_POLICY_GRAPH: bool
                //     table {
                //         tbody {
                //             tr{
                //                 td{label {r#for: "check_revocation_status", "Check Revocation Status: "}}
                //                 td{input { r#type: "checkbox", name: "check_revocation_status", checked: "{s_check_revocation_status}", value: "{s_check_revocation_status}" }}
                //             }
                //             tr{
                //                 td{label {r#for: "retrieve_from_aia_sia_http", "Retrieve from HTTP AIA and SIA: "}}
                //                 td{input { r#type: "checkbox", name: "retrieve_from_aia_sia_http", checked: "{s_retrieve_from_aia_sia_http}", value: "{s_retrieve_from_aia_sia_http}" }}
                //             }
                //         }
                //     }
                // }
                fieldset {
                    // todo add more stuff to UI

                    // PS_ENFORCE_TRUST_ANCHOR_CONSTRAINTS: bool
                    // PS_ENFORCE_TRUST_ANCHOR_VALIDITY: bool
                    // PS_KEY_USAGE: u16
                    // PS_EXTENDED_KEY_USAGE: set of OIDs
                    // PS_EXTENDED_KEY_USAGE_PATH: bool

                    // PS_INITIAL_PATH_LENGTH_CONSTRAINT: u8
                    // PS_MAX_PATH_LENGTH_CONSTRAINT: u8
                    // PS_CRL_TIMEOUT: u64
                    // PS_ENFORCE_ALG_AND_KEY_SIZE_CONSTRAINTS: bool
                    // PS_USE_VALIDATOR_FILTER_WHEN_BUILDING: bool
                    // PS_CHECK_REVOCATION_STATUS: bool
                    // PS_CHECK_OCSP_FROM_AIA: bool
                    // PS_RETRIEVE_FROM_AIA_SIA_HTTP: bool
                    // PS_RETRIEVE_FROM_AIA_SIA_LDAP: bool
                    // PS_CHECK_CRLS: bool
                    // PS_CHECK_CRLDP_HTTP: bool
                    // PS_CHECK_CRLDP_LDAP: bool
                    // PS_CRL_GRACE_PERIODS_AS_LAST_RESORT: bool
                    // PS_IGNORE_EXPIRED: bool
                    // PS_OCSP_AIA_NONCE_SETTING: i8
                    // PS_CERTIFICATES: set of certs
                    // PS_REQUIRE_COUNTRY_CODE_INDICATOR: bool
                    // PS_PERM_COUNTRIES: vector of string
                    // PS_EXCL_COUNTRIES: vector of string
                    // PS_TRUST_ANCHOR_FOLDER: string
                    // PS_CERTIFICATION_AUTHORITY_FOLDER: string
                    // PS_DOWNLOAD_FOLDER: string
                    // PS_LAST_MODIFIED_MAP_FILE: string
                    // PS_URI_BLOCKLIST_FILE: string
                    // PS_CBOR_TA_STORE: string
                    // PS_REQUIRE_TA_STORE: bool
                    // PS_USE_POLICY_GRAPH: bool
                    table {
                        tbody {
                            tr{
                                td{label {r#for: "check_revocation_status", "Check Revocation Status: "}}
                                td{input { r#type: "checkbox", name: "check_revocation_status", checked: "{s_check_revocation_status}", value: "{s_check_revocation_status}" }}
                            }
                            tr{
                                td{label {r#for: "retrieve_from_aia_sia_http", "Retrieve from HTTP AIA and SIA: "}}
                                td{input { r#type: "checkbox", name: "retrieve_from_aia_sia_http", checked: "{s_retrieve_from_aia_sia_http}", value: "{s_retrieve_from_aia_sia_http}" }}
                            }
                        }
                    }
                }
                div{
                    style: "text-align:center",
                    button { r#type: "submit", value: "Submit", "Save" }
                    button {
                        onclick: move |_| {
                            let setter = s_close.setter();
                            setter(true);
                            window.close()
                        }, "Close"
                    }
                }

            }
        }
    })
}
