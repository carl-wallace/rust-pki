//! Form for editing [`CertificationPathSettings`](certval::CertificationPathSettings) values that
//! are persisted as JSON

#[cfg(feature = "std")]
use dioxus::prelude::*;

#[cfg(feature = "std")]
use std::io::Write;

#[cfg(feature = "std")]
use log::error;

#[cfg(feature = "std")]
use certval::*;

/// Form for editing a JSON-encoded [`CertificationPathSettings`](certval::CertificationPathSettings)
/// instance at the location indicated by `path`. The Save button updates the file with values from
/// the form before invoking the `on_close` handler; the Close button invokes the `on_close` handler
/// without saving. Frontends supply renderer-specific behavior, like closing a window, via `on_close`.
#[cfg(feature = "std")]
#[component]
pub fn EditSettings(path: String, on_close: EventHandler<()>) -> Element {
    let initial_values = use_hook({
        let path = path.clone();
        move || {
            let cps = read_settings(&Some(path)).unwrap_or_default();
            (
                cps.get_initial_explicit_policy_indicator(),
                cps.get_check_revocation_status(),
                cps.get_retrieve_from_aia_sia_http(),
            )
        }
    });

    let mut s_initial_explicit_policy_indicator = use_signal(|| initial_values.0);
    let mut s_check_revocation_status = use_signal(|| initial_values.1);
    let mut s_retrieve_from_aia_sia_http = use_signal(|| initial_values.2);

    let save = move |_| {
        // start from the file contents so settings not surfaced in the form are preserved
        let mut cps = read_settings(&Some(path.clone())).unwrap_or_default();
        cps.set_initial_explicit_policy_indicator(s_initial_explicit_policy_indicator());
        cps.set_check_revocation_status(s_check_revocation_status());
        cps.set_retrieve_from_aia_sia_http(s_retrieve_from_aia_sia_http());
        match serde_json::to_string(&cps) {
            Ok(json_ps) => match std::fs::File::create(&path) {
                Ok(mut final_file) => {
                    if let Err(e) = final_file.write_all(json_ps.as_bytes()) {
                        error!("Failed to save settings: {e}");
                    }
                }
                Err(e) => {
                    error!("Failed to create file to receive settings: {e}");
                }
            },
            Err(e) => {
                error!("Failed to encode settings: {e}");
            }
        }
        on_close.call(());
    };

    rsx! {
        div {
            fieldset {
                // todo add more stuff to UI
                // PS_INITIAL_POLICY_MAPPING_INHIBIT_INDICATOR: bool
                // PS_INITIAL_INHIBIT_ANY_POLICY_INDICATOR: bool
                // PS_INITIAL_POLICY_SET: set of OIDs
                // PS_INITIAL_PERMITTED_SUBTREES: NameConstraints
                // PS_INITIAL_EXCLUDED_SUBTREES: NameConstraints
                // PS_TIME_OF_INTEREST: u64
                table {
                    tbody {
                        tr {
                            td { label { r#for: "require_explicit_policy", "Require Explicit Policy: " } }
                            td {
                                input {
                                    r#type: "checkbox",
                                    name: "require_explicit_policy",
                                    checked: s_initial_explicit_policy_indicator(),
                                    onchange: move |ev| s_initial_explicit_policy_indicator.set(ev.checked()),
                                }
                            }
                        }
                    }
                }
            }
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
                // PS_CHECK_OCSP_FROM_AIA: bool
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
                        tr {
                            td { label { r#for: "check_revocation_status", "Check Revocation Status: " } }
                            td {
                                input {
                                    r#type: "checkbox",
                                    name: "check_revocation_status",
                                    checked: s_check_revocation_status(),
                                    onchange: move |ev| s_check_revocation_status.set(ev.checked()),
                                }
                            }
                        }
                        tr {
                            td { label { r#for: "retrieve_from_aia_sia_http", "Retrieve from HTTP AIA and SIA: " } }
                            td {
                                input {
                                    r#type: "checkbox",
                                    name: "retrieve_from_aia_sia_http",
                                    checked: s_retrieve_from_aia_sia_http(),
                                    onchange: move |ev| s_retrieve_from_aia_sia_http.set(ev.checked()),
                                }
                            }
                        }
                    }
                }
            }
            div {
                style: "text-align:center",
                button { onclick: save, "Save" }
                button { onclick: move |_| on_close.call(()), "Close" }
            }
        }
    }
}
