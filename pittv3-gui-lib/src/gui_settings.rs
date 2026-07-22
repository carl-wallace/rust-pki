//! Tabbed form for editing [`CertificationPathSettings`](certval::CertificationPathSettings)
//! values via a [`SettingsModel`](crate::gui_settings_model::SettingsModel).
//!
//! [`EditSettings`] is renderer-agnostic and persistence-free: it receives an initial model and
//! reports the edited model through `on_save`, so desktop (file-backed) and web (server- or
//! localStorage-backed) frontends share the form. [`EditSettingsFile`] is the desktop wrapper that
//! keeps today's read/write-a-JSON-file behavior.
//!
//! Presentation is defaults-first: each field shows its effective value (the model value or the
//! certval default), editing a field records an override, and Reset to defaults discards all
//! overrides. The revocation tab presents a composed mode selection with the individual settings
//! under an advanced disclosure.

use dioxus::prelude::*;

use certval::{NameConstraintsSettings, OcspNonceSetting};
use x509_cert::ext::pkix::KeyUsages;

use crate::gui_settings_model::{RevocationMode, SettingsModel};

#[cfg(feature = "std")]
use certval::read_settings;
#[cfg(feature = "std")]
use log::error;
#[cfg(feature = "std")]
use std::io::Write;

/// Returns true if `s` is plausibly a dotted-decimal OID
fn looks_like_oid(s: &str) -> bool {
    s.contains('.') && s.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Splits a textarea value into trimmed, non-empty lines
fn lines_of(value: &str) -> Vec<String> {
    value
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Joins list values for display in a textarea, one per line
fn lines_join(values: &[String]) -> String {
    values.join("\n")
}

/// Table row with a labeled checkbox showing the effective value of a boolean setting; the hint
/// marks fields carrying an override versus the default
#[component]
fn BoolRow(
    label: &'static str,
    checked: bool,
    overridden: bool,
    onchange: EventHandler<bool>,
) -> Element {
    rsx! {
        tr {
            td { label { "{label}: " } }
            td {
                input {
                    r#type: "checkbox",
                    checked,
                    onchange: move |ev| onchange.call(ev.checked()),
                }
            }
            td {
                span { class: "hint",
                    if overridden {
                        "override"
                    } else {
                        "default"
                    }
                }
            }
        }
    }
}

/// Table row with a labeled numeric input; an empty value clears the override
#[component]
fn NumberRow(
    label: &'static str,
    value: Option<u64>,
    placeholder: String,
    onchange: EventHandler<Option<u64>>,
) -> Element {
    let display = value.map(|v| v.to_string()).unwrap_or_default();
    rsx! {
        tr {
            td { label { "{label}: " } }
            td {
                input {
                    r#type: "number",
                    min: "0",
                    value: display,
                    placeholder,
                    oninput: move |ev| {
                        let v = ev.value();
                        if v.trim().is_empty() {
                            onchange.call(None);
                        } else if let Ok(parsed) = v.trim().parse::<u64>() {
                            onchange.call(Some(parsed));
                        }
                    },
                }
            }
            td {
                span { class: "hint",
                    if value.is_some() {
                        "override"
                    } else {
                        "default"
                    }
                }
            }
        }
    }
}

/// Table row with a labeled text input; an empty value clears the override
#[component]
fn TextRow(
    label: &'static str,
    value: Option<String>,
    onchange: EventHandler<Option<String>>,
) -> Element {
    let overridden = value.is_some();
    rsx! {
        tr {
            td { label { "{label}: " } }
            td {
                input {
                    r#type: "text",
                    value: value.unwrap_or_default(),
                    oninput: move |ev| {
                        let v = ev.value();
                        if v.is_empty() {
                            onchange.call(None);
                        } else {
                            onchange.call(Some(v));
                        }
                    },
                }
            }
            td {
                span { class: "hint",
                    if overridden {
                        "override"
                    } else {
                        "default"
                    }
                }
            }
        }
    }
}

/// Editor for a list of dotted-decimal OIDs, one per line, with validation feedback
#[component]
fn OidListEditor(
    label: &'static str,
    value: Option<Vec<String>>,
    onchange: EventHandler<Option<Vec<String>>>,
) -> Element {
    let text = value.as_deref().map(lines_join).unwrap_or_default();
    let invalid: Vec<String> = value
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter(|o| !looks_like_oid(o))
        .cloned()
        .collect();
    rsx! {
        div { class: "list-editor",
            label { "{label} (one OID per line): " }
            textarea {
                rows: 3,
                value: text,
                oninput: move |ev| {
                    let lines = lines_of(&ev.value());
                    if lines.is_empty() {
                        onchange.call(None);
                    } else {
                        onchange.call(Some(lines));
                    }
                },
            }
            if !invalid.is_empty() {
                p { class: "field-error", "Not dotted-decimal OIDs: {invalid.join(\", \")}" }
            }
        }
    }
}

/// Editor for a list of strings, one per line
#[component]
fn StringListEditor(
    label: &'static str,
    value: Option<Vec<String>>,
    onchange: EventHandler<Option<Vec<String>>>,
) -> Element {
    let text = value.as_deref().map(lines_join).unwrap_or_default();
    rsx! {
        div { class: "list-editor",
            label { "{label} (one per line): " }
            textarea {
                rows: 3,
                value: text,
                oninput: move |ev| {
                    let lines = lines_of(&ev.value());
                    if lines.is_empty() {
                        onchange.call(None);
                    } else {
                        onchange.call(Some(lines));
                    }
                },
            }
        }
    }
}

/// The key usage bits presented by [`KeyUsageEditor`], in display order
const KEY_USAGE_BITS: &[(KeyUsages, &str)] = &[
    (KeyUsages::DigitalSignature, "digitalSignature"),
    (KeyUsages::NonRepudiation, "nonRepudiation"),
    (KeyUsages::KeyEncipherment, "keyEncipherment"),
    (KeyUsages::DataEncipherment, "dataEncipherment"),
    (KeyUsages::KeyAgreement, "keyAgreement"),
    (KeyUsages::KeyCertSign, "keyCertSign"),
    (KeyUsages::CRLSign, "cRLSign"),
    (KeyUsages::EncipherOnly, "encipherOnly"),
    (KeyUsages::DecipherOnly, "decipherOnly"),
];

/// Editor for the target key usage setting as a set of flag checkboxes; clearing every flag
/// clears the override
#[component]
fn KeyUsageEditor(
    value: Option<certval::KeyUsageSettings>,
    onchange: EventHandler<Option<certval::KeyUsageSettings>>,
) -> Element {
    let current = value.unwrap_or_default();
    rsx! {
        div { class: "ku-editor",
            label { "Target key usage: " }
            span { class: "hint",
                if value.is_some() {
                    "override"
                } else {
                    "default (not checked)"
                }
            }
            div { class: "ku-flags",
                for (flag , name) in KEY_USAGE_BITS.iter() {
                    label { class: "ku-flag",
                        input {
                            r#type: "checkbox",
                            checked: current.contains(*flag),
                            onchange: {
                                let flag = *flag;
                                move |ev: FormEvent| {
                                    let mut next = current;
                                    if ev.checked() {
                                        next |= flag;
                                    } else {
                                        next -= flag;
                                    }
                                    if next.is_empty() {
                                        onchange.call(None);
                                    } else {
                                        onchange.call(Some(next));
                                    }
                                }
                            },
                        }
                        "{name}"
                    }
                }
            }
        }
    }
}

/// Name forms presented by [`NameSubtreesEditor`], matching the name forms supported by
/// name-constraints processing
#[derive(Clone, Copy, PartialEq)]
enum NameForm {
    Rfc822,
    Dns,
    Dn,
    Uri,
    IpCidr,
}

const NAME_FORMS: &[(NameForm, &str)] = &[
    (NameForm::Rfc822, "RFC 822 names"),
    (NameForm::Dns, "DNS names"),
    (NameForm::Dn, "Directory names"),
    (NameForm::Uri, "URIs"),
    (NameForm::IpCidr, "IP addresses (CIDR)"),
];

fn subtrees_get(ncs: &NameConstraintsSettings, form: NameForm) -> Vec<String> {
    let v = match form {
        NameForm::Rfc822 => &ncs.rfc822_name,
        NameForm::Dns => &ncs.dns_name,
        NameForm::Dn => &ncs.directory_name,
        NameForm::Uri => &ncs.uniform_resource_identifier,
        NameForm::IpCidr => &ncs.ip_address,
    };
    v.clone().unwrap_or_default()
}

fn subtrees_set(ncs: &mut NameConstraintsSettings, form: NameForm, values: Vec<String>) {
    let slot = match form {
        NameForm::Rfc822 => &mut ncs.rfc822_name,
        NameForm::Dns => &mut ncs.dns_name,
        NameForm::Dn => &mut ncs.directory_name,
        NameForm::Uri => &mut ncs.uniform_resource_identifier,
        NameForm::IpCidr => &mut ncs.ip_address,
    };
    if values.is_empty() {
        *slot = None;
    } else {
        *slot = Some(values);
    }
}

fn subtrees_is_empty(ncs: &NameConstraintsSettings) -> bool {
    ncs.rfc822_name.is_none()
        && ncs.dns_name.is_none()
        && ncs.directory_name.is_none()
        && ncs.uniform_resource_identifier.is_none()
        && ncs.ip_address.is_none()
        && ncs.not_supported.is_none()
}

/// Editor for an initial permitted or excluded subtrees setting: one list per supported name form;
/// clearing every list clears the override
#[component]
fn NameSubtreesEditor(
    label: &'static str,
    value: Option<NameConstraintsSettings>,
    onchange: EventHandler<Option<NameConstraintsSettings>>,
) -> Element {
    let current = value.clone().unwrap_or_default();
    rsx! {
        details { class: "subtrees-editor",
            summary {
                "{label} "
                span { class: "hint",
                    if value.is_some() {
                        "(override)"
                    } else {
                        "(default: unconstrained)"
                    }
                }
            }
            for (form , form_label) in NAME_FORMS.iter() {
                div { class: "list-editor",
                    label { "{form_label} (one per line): " }
                    textarea {
                        rows: 2,
                        value: lines_join(&subtrees_get(&current, *form)),
                        oninput: {
                            let current = current.clone();
                            let form = *form;
                            move |ev: FormEvent| {
                                let mut next = current.clone();
                                subtrees_set(&mut next, form, lines_of(&ev.value()));
                                if subtrees_is_empty(&next) {
                                    onchange.call(None);
                                } else {
                                    onchange.call(Some(next));
                                }
                            }
                        },
                    }
                }
            }
        }
    }
}

/// Tabs presented by [`EditSettings`]
#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsTab {
    Policy,
    NameConstraints,
    TrustAndPath,
    Target,
    Revocation,
    Fetching,
    Countries,
    Folders,
}

const TABS: &[(SettingsTab, &str)] = &[
    (SettingsTab::Policy, "Policy"),
    (SettingsTab::NameConstraints, "Name constraints"),
    (SettingsTab::TrustAndPath, "Trust anchors & path"),
    (SettingsTab::Target, "Target"),
    (SettingsTab::Revocation, "Revocation"),
    (SettingsTab::Fetching, "Fetching"),
    (SettingsTab::Countries, "Countries"),
    (SettingsTab::Folders, "Folders & files"),
];

/// Renderer-agnostic settings editor over a [`SettingsModel`]. The `on_save` handler receives the
/// edited model; persistence (file, server, browser storage) is the frontend's concern. Set
/// `show_folders` to present the desktop-only folders/files tab.
#[component]
pub fn EditSettings(
    initial: SettingsModel,
    #[props(default)] show_folders: bool,
    on_save: EventHandler<SettingsModel>,
    on_close: EventHandler<()>,
) -> Element {
    let mut model = use_signal(|| initial.clone());
    let mut tab = use_signal(|| SettingsTab::Policy);

    let m = model();
    let mode = m.revocation_mode();

    rsx! {
        div { class: "settings-editor",
            div { class: "tab-bar",
                for (t , label) in TABS.iter() {
                    if *t != SettingsTab::Folders || show_folders {
                        button {
                            r#type: "button",
                            class: if tab() == *t { "tab tab-active" } else { "tab" },
                            onclick: {
                                let t = *t;
                                move |_| tab.set(t)
                            },
                            "{label}"
                        }
                    }
                }
            }
            p { class: "hint",
                "Fields marked \"default\" are not present in the settings and use certval "
                "defaults; editing a field records an override."
            }

            match tab() {
                SettingsTab::Policy => rsx! {
                    table {
                        tbody {
                            BoolRow {
                                label: "Require explicit policy",
                                checked: m.initial_explicit_policy_indicator.unwrap_or(false),
                                overridden: m.initial_explicit_policy_indicator.is_some(),
                                onchange: move |v| model.write().initial_explicit_policy_indicator = Some(v),
                            }
                            BoolRow {
                                label: "Inhibit policy mapping",
                                checked: m.initial_policy_mapping_inhibit_indicator.unwrap_or(false),
                                overridden: m.initial_policy_mapping_inhibit_indicator.is_some(),
                                onchange: move |v| model.write().initial_policy_mapping_inhibit_indicator = Some(v),
                            }
                            BoolRow {
                                label: "Inhibit anyPolicy",
                                checked: m.initial_inhibit_any_policy_indicator.unwrap_or(false),
                                overridden: m.initial_inhibit_any_policy_indicator.is_some(),
                                onchange: move |v| model.write().initial_inhibit_any_policy_indicator = Some(v),
                            }
                        }
                    }
                    OidListEditor {
                        label: "Initial policy set",
                        value: m.initial_policy_set.clone(),
                        onchange: move |v| model.write().initial_policy_set = v,
                    }
                },
                SettingsTab::NameConstraints => rsx! {
                    NameSubtreesEditor {
                        label: "Initial permitted subtrees",
                        value: m.initial_permitted_subtrees.clone(),
                        onchange: move |v| model.write().initial_permitted_subtrees = v,
                    }
                    NameSubtreesEditor {
                        label: "Initial excluded subtrees",
                        value: m.initial_excluded_subtrees.clone(),
                        onchange: move |v| model.write().initial_excluded_subtrees = v,
                    }
                },
                SettingsTab::TrustAndPath => rsx! {
                    table {
                        tbody {
                            BoolRow {
                                label: "Enforce trust anchor constraints (RFC 5937)",
                                checked: m.enforce_trust_anchor_constraints.unwrap_or(false),
                                overridden: m.enforce_trust_anchor_constraints.is_some(),
                                onchange: move |v| model.write().enforce_trust_anchor_constraints = Some(v),
                            }
                            BoolRow {
                                label: "Enforce trust anchor validity",
                                checked: m.enforce_trust_anchor_validity.unwrap_or(true),
                                overridden: m.enforce_trust_anchor_validity.is_some(),
                                onchange: move |v| model.write().enforce_trust_anchor_validity = Some(v),
                            }
                            BoolRow {
                                label: "Require trust anchor store membership",
                                checked: m.require_ta_store.unwrap_or(true),
                                overridden: m.require_ta_store.is_some(),
                                onchange: move |v| model.write().require_ta_store = Some(v),
                            }
                            BoolRow {
                                label: "Filter candidate paths while building",
                                checked: m.use_validator_filter_when_building.unwrap_or(true),
                                overridden: m.use_validator_filter_when_building.is_some(),
                                onchange: move |v| model.write().use_validator_filter_when_building = Some(v),
                            }
                            NumberRow {
                                label: "Initial path length constraint",
                                value: m.initial_path_length_constraint.map(|v| v as u64),
                                placeholder: "15",
                                onchange: move |v: Option<u64>| {
                                    model.write().initial_path_length_constraint = v.map(|v| v.min(255) as u8);
                                },
                            }
                        }
                    }
                },
                SettingsTab::Target => rsx! {
                    KeyUsageEditor {
                        value: m.target_key_usage,
                        onchange: move |v| model.write().target_key_usage = v,
                    }
                    OidListEditor {
                        label: "Extended key usage",
                        value: m.extended_key_usage.clone(),
                        onchange: move |v| model.write().extended_key_usage = v,
                    }
                    table {
                        tbody {
                            BoolRow {
                                label: "Enforce EKU across path",
                                checked: m.extended_key_usage_path.unwrap_or(false),
                                overridden: m.extended_key_usage_path.is_some(),
                                onchange: move |v| model.write().extended_key_usage_path = Some(v),
                            }
                            BoolRow {
                                label: "Forbid self-signed end entities",
                                checked: m.forbid_self_signed_ee.unwrap_or(false),
                                overridden: m.forbid_self_signed_ee.is_some(),
                                onchange: move |v| model.write().forbid_self_signed_ee = Some(v),
                            }
                            BoolRow {
                                label: "Enforce algorithm and key size constraints",
                                checked: m.enforce_alg_and_key_size_constraints.unwrap_or(false),
                                overridden: m.enforce_alg_and_key_size_constraints.is_some(),
                                onchange: move |v| model.write().enforce_alg_and_key_size_constraints = Some(v),
                            }
                            NumberRow {
                                label: "Time of interest (Unix epoch, 0 disables)",
                                value: m.time_of_interest,
                                placeholder: "run time",
                                onchange: move |v| model.write().time_of_interest = v,
                            }
                            BoolRow {
                                label: "Ignore expired certificates when building",
                                checked: m.ignore_expired.unwrap_or(false),
                                overridden: m.ignore_expired.is_some(),
                                onchange: move |v| model.write().ignore_expired = Some(v),
                            }
                        }
                    }
                },
                SettingsTab::Revocation => rsx! {
                    div { class: "radio-group",
                        strong { "Revocation mode: " }
                        for (value , label) in [
                            (RevocationMode::Disabled, "None"),
                            (RevocationMode::CrlOrOcsp, "CRL or OCSP"),
                            (RevocationMode::CrlOnly, "CRL only"),
                            (RevocationMode::OcspOnly, "OCSP only"),
                        ]
                        {
                            label { class: "radio",
                                input {
                                    r#type: "radio",
                                    name: "revocation-mode",
                                    checked: mode == value,
                                    onchange: move |_| model.write().set_revocation_mode(value),
                                }
                                "{label}"
                            }
                        }
                        if mode == RevocationMode::Custom {
                            span { class: "badge badge-undetermined", "Custom" }
                        }
                    }
                    div { class: "radio-group",
                        strong { "OCSP nonce: " }
                        for (value , label) in [
                            (OcspNonceSetting::DoNotSendNonce, "Do not send"),
                            (OcspNonceSetting::SendNonceTolerateMismatchAbsence, "Send, tolerate absence"),
                            (OcspNonceSetting::SendNonceRequireMatch, "Send, require match"),
                        ]
                        {
                            label { class: "radio",
                                input {
                                    r#type: "radio",
                                    name: "ocsp-nonce",
                                    checked: m.ocsp_aia_nonce_setting.unwrap_or(OcspNonceSetting::DoNotSendNonce) == value,
                                    onchange: move |_| model.write().ocsp_aia_nonce_setting = Some(value),
                                }
                                "{label}"
                            }
                        }
                    }
                    details { class: "advanced",
                        summary { "Advanced" }
                        table {
                            tbody {
                                BoolRow {
                                    label: "Check revocation status (master)",
                                    checked: m.check_revocation_status.unwrap_or(true),
                                    overridden: m.check_revocation_status.is_some(),
                                    onchange: move |v| model.write().check_revocation_status = Some(v),
                                }
                                BoolRow {
                                    label: "Check CRLs",
                                    checked: m.check_crls.unwrap_or(true),
                                    overridden: m.check_crls.is_some(),
                                    onchange: move |v| model.write().check_crls = Some(v),
                                }
                                BoolRow {
                                    label: "Check OCSP from AIA",
                                    checked: m.check_ocsp_from_aia.unwrap_or(true),
                                    overridden: m.check_ocsp_from_aia.is_some(),
                                    onchange: move |v| model.write().check_ocsp_from_aia = Some(v),
                                }
                                BoolRow {
                                    label: "Fetch CRLs from HTTP CRL DPs",
                                    checked: m.check_crldp_http.unwrap_or(true),
                                    overridden: m.check_crldp_http.is_some(),
                                    onchange: move |v| model.write().check_crldp_http = Some(v),
                                }
                                BoolRow {
                                    label: "Fetch CRLs from LDAP CRL DPs (no LDAP support)",
                                    checked: m.check_crldp_ldap.unwrap_or(false),
                                    overridden: m.check_crldp_ldap.is_some(),
                                    onchange: move |v| model.write().check_crldp_ldap = Some(v),
                                }
                                BoolRow {
                                    label: "Allow stale CRLs within grace periods",
                                    checked: m.crl_grace_periods_as_last_resort.unwrap_or(true),
                                    overridden: m.crl_grace_periods_as_last_resort.is_some(),
                                    onchange: move |v| model.write().crl_grace_periods_as_last_resort = Some(v),
                                }
                                NumberRow {
                                    label: "Revocation max age (seconds, 0 disables)",
                                    value: m.revocation_max_age_secs,
                                    placeholder: "0",
                                    onchange: move |v| model.write().revocation_max_age_secs = v,
                                }
                                NumberRow {
                                    label: "CRL timeout (seconds)",
                                    value: m.crl_timeout_secs,
                                    placeholder: "60",
                                    onchange: move |v| model.write().crl_timeout_secs = v,
                                }
                            }
                        }
                    }
                },
                SettingsTab::Fetching => rsx! {
                    table {
                        tbody {
                            BoolRow {
                                label: "Retrieve from HTTP AIA and SIA",
                                checked: m.retrieve_from_aia_sia_http.unwrap_or(true),
                                overridden: m.retrieve_from_aia_sia_http.is_some(),
                                onchange: move |v| model.write().retrieve_from_aia_sia_http = Some(v),
                            }
                            BoolRow {
                                label: "Retrieve from LDAP AIA and SIA (no LDAP support)",
                                checked: m.retrieve_from_aia_sia_ldap.unwrap_or(false),
                                overridden: m.retrieve_from_aia_sia_ldap.is_some(),
                                onchange: move |v| model.write().retrieve_from_aia_sia_ldap = Some(v),
                            }
                            NumberRow {
                                label: "Maximum AIA/SIA certificates",
                                value: m.max_aia_sia_certs,
                                placeholder: "2000",
                                onchange: move |v| model.write().max_aia_sia_certs = v,
                            }
                        }
                    }
                },
                SettingsTab::Countries => rsx! {
                    table {
                        tbody {
                            BoolRow {
                                label: "Require country code compliance",
                                checked: m.require_country_code_indicator.unwrap_or(false),
                                overridden: m.require_country_code_indicator.is_some(),
                                onchange: move |v| model.write().require_country_code_indicator = Some(v),
                            }
                        }
                    }
                    StringListEditor {
                        label: "Permitted countries",
                        value: m.perm_countries.clone(),
                        onchange: move |v| model.write().perm_countries = v,
                    }
                    StringListEditor {
                        label: "Excluded countries",
                        value: m.excl_countries.clone(),
                        onchange: move |v| model.write().excl_countries = v,
                    }
                },
                SettingsTab::Folders => rsx! {
                    table {
                        tbody {
                            TextRow {
                                label: "Trust anchor folder",
                                value: m.trust_anchor_folder.clone(),
                                onchange: move |v| model.write().trust_anchor_folder = v,
                            }
                            TextRow {
                                label: "CA folder",
                                value: m.certification_authority_folder.clone(),
                                onchange: move |v| model.write().certification_authority_folder = v,
                            }
                            TextRow {
                                label: "Download folder",
                                value: m.download_folder.clone(),
                                onchange: move |v| model.write().download_folder = v,
                            }
                            TextRow {
                                label: "Last-modified map file",
                                value: m.last_modified_map_file.clone(),
                                onchange: move |v| model.write().last_modified_map_file = v,
                            }
                            TextRow {
                                label: "URI blocklist file",
                                value: m.uri_blocklist_file.clone(),
                                onchange: move |v| model.write().uri_blocklist_file = v,
                            }
                            BoolRow {
                                label: "CBOR contains only trust anchors",
                                checked: m.cbor_ta_store.unwrap_or(false),
                                overridden: m.cbor_ta_store.is_some(),
                                onchange: move |v| model.write().cbor_ta_store = Some(v),
                            }
                        }
                    }
                },
            }

            div { class: "settings-actions",
                button {
                    r#type: "button",
                    onclick: move |_| on_save.call(model()),
                    "Save"
                }
                button {
                    r#type: "button",
                    onclick: move |_| model.set(SettingsModel::default()),
                    "Reset to defaults"
                }
                button { r#type: "button", onclick: move |_| on_close.call(()), "Close" }
            }
        }
    }
}

/// Desktop wrapper for [`EditSettings`] that reads the JSON settings file at `path` into the form
/// and writes the edited settings back on save, preserving settings the form does not cover.
#[cfg(feature = "std")]
#[component]
pub fn EditSettingsFile(path: String, on_close: EventHandler<()>) -> Element {
    let initial = use_hook({
        let path = path.clone();
        move || {
            let cps = read_settings(&Some(path)).unwrap_or_default();
            SettingsModel::from_cps(&cps)
        }
    });

    let save_path = path.clone();
    let on_save = move |edited: SettingsModel| {
        // start from the file contents so settings not surfaced in the form are preserved
        let mut cps = read_settings(&Some(save_path.clone())).unwrap_or_default();
        edited.apply(&mut cps);
        match serde_json::to_string(&cps) {
            Ok(json_ps) => match std::fs::File::create(&save_path) {
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
        EditSettings {
            initial,
            show_folders: true,
            on_save,
            on_close: move |_| on_close.call(()),
        }
    }
}
