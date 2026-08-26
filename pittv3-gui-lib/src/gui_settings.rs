//! Tabbed form for editing [`CertificationPathSettings`](certval::CertificationPathSettings)
//! values via a [`SettingsModel`].
//!
//! [`EditSettings`] is renderer-agnostic and persistence-free: it receives an initial model and
//! reports the edited model through `on_save`, so desktop (file-backed) and web (server- or
//! localStorage-backed) frontends share the form. `EditSettingsFile` (feature `std`) is the
//! keeps today's read/write-a-JSON-file behavior.
//!
//! Presentation is defaults-first: each field shows its effective value (the model value or the
//! certval default), editing a field records an override, and Reset to defaults discards all
//! overrides. The revocation tab presents a composed mode selection with the individual settings
//! under an advanced disclosure.
//!
//! Every frontend presents every tab, including settings it cannot act on: a browser has no
//! filesystem and, until a fetch relay exists, no way to retrieve CRLs or OCSP responses. Those
//! groups carry a notice saying so rather than being hidden, for two reasons. A user
//! who learned the form in one frontend finds the same tabs in the next, and the settings file is
//! shared across all of them (`pittv3 -s`, the desktop editor, the browser's import/export), so
//! authoring a value that only takes effect elsewhere is a legitimate thing to do. What each
//! frontend can actually act on is declared by [`Capabilities`].

use dioxus::prelude::*;

use certval::{NameConstraintsSettings, OcspNonceSetting};
use x509_cert::ext::pkix::KeyUsages;

use crate::gui_rows::{datetime_local_to_epoch, epoch_to_datetime_local, now_as_unix_epoch};
use crate::gui_settings_model::{RevocationMode, SettingsModel};

#[cfg(feature = "std")]
use crate::settings_store::{FileSettingsStore, SettingsStore};
#[cfg(feature = "std")]
use log::error;

/// What the hosting frontend can act on, so the form can present every setting while marking the
/// groups that cannot take effect where it is running.
///
/// This is deliberately a statement about the *environment*, not about a privacy tier or a
/// packaging choice: a browser gains `network` when a fetch relay is available to it, and the
/// hosted variant selecting a different mode is one of the things that can flip that bit. Keeping
/// the form's input in these terms means a tier selector becomes something that *sets*
/// capabilities rather than something the form has to know about.
///
/// [`Default`] is the most restrictive combination — a browser with no relay — so a frontend that
/// says nothing gets accurate notices rather than silently promising more than it can do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// Local filesystem paths are meaningful, so the folders and files settings can take effect
    pub filesystem: bool,
    /// Outbound requests are available, directly or through a relay, so CRLs, OCSP responses and
    /// AIA/SIA certificates can be retrieved
    pub network: bool,
    /// certval was built with revocation support, so revocation settings are honored at all
    pub revocation: bool,
}

impl Capabilities {
    /// Everything available: the desktop and CLI frontends, built with `std` and `remote`
    pub fn desktop() -> Self {
        Self {
            filesystem: true,
            network: true,
            revocation: true,
        }
    }

    /// A browser with no relay: no filesystem and no outbound requests, but certval *is* built
    /// with revocation support, so revocation data supplied alongside the certificates is
    /// processed and only the fetching is missing. That is why this is no longer [`Default`] —
    /// `revocation` is the one bit a browser has without a relay, and reporting it accurately is
    /// what makes the form show "cannot reach a responder" rather than "built without support".
    pub fn browser_local() -> Self {
        Self {
            filesystem: false,
            network: false,
            revocation: true,
        }
    }

    /// A browser working through a relay: still no filesystem, but outbound requests are available
    /// — made by the service on the page's behalf rather than by the page — so the settings that
    /// govern retrieval take effect and the notices that said otherwise should not appear.
    ///
    /// This is what a tier selector sets. It is the same shape as [`desktop`](Self::desktop) minus
    /// the filesystem, which is the honest description: what the browser lacks at that point is
    /// somewhere to read a folder of CRLs from, not a way to reach the network.
    pub fn browser_relayed() -> Self {
        Self {
            filesystem: false,
            network: true,
            revocation: true,
        }
    }
}

/// Explains that a group of settings is recorded but cannot take effect in this frontend. Rendered
/// above the group rather than in place of it — see the module documentation for why the fields
/// stay visible and editable.
#[component]
fn CapabilityNotice(message: String) -> Element {
    rsx! {
        p { class: "hint capability-notice", "{message}" }
    }
}

/// Table row for the time of interest: the epoch value, a Now button, and a human-readable picker
/// mirroring it. An empty value clears the override, which means "the time of the run".
#[component]
fn TimeOfInterestRow(value: Option<u64>, onchange: EventHandler<Option<u64>>) -> Element {
    let display = value.map(|v| v.to_string()).unwrap_or_default();
    // Empty while the value is absent or disabled (0), so the picker does not claim a time that is
    // not in effect.
    let picker = match value {
        Some(secs) if secs != 0 => epoch_to_datetime_local(secs),
        _ => String::new(),
    };
    rsx! {
        div { class: "label-cell",
            label { "Time of interest (Unix epoch, 0 disables): " }
        }
        div { class: "field",
            input {
                                r#type: "number",
                                min: "0",
                                value: display,
                                placeholder: "run time",
                                oninput: move |ev| {
                                    let v = ev.value();
                                    if v.trim().is_empty() {
                                        onchange.call(None);
                                    } else if let Ok(parsed) = v.trim().parse::<u64>() {
                                        onchange.call(Some(parsed));
                                    }
                                },
                            }
                            button {
                                r#type: "button",
                                onclick: move |_| onchange.call(Some(now_as_unix_epoch())),
                                "Now"
                            }
                            // onchange fires only on a complete datetime, so it never clobbers a mid-edit epoch
                            input {
                                r#type: "datetime-local",
                                step: "1",
                                value: picker,
                                onchange: move |ev| {
                                    if let Some(secs) = datetime_local_to_epoch(&ev.value()) {
                                        onchange.call(Some(secs));
                                    }
                                },
                            }
            span { class: "hint",
                                if value.is_some() {
                                    "override (UTC)"
                                } else {
                                    "default: the time of the run"
                                }
                            }
        }
    }
}

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
/// marks fields carrying an override versus the default.
///
/// `default_note` replaces the bare "default" hint for a field whose unset value does not resolve to
/// certval's default in this frontend. Without it the row would say "default" beside a value certval
/// would not have chosen, which is true of neither reading.
#[component]
fn BoolRow(
    label: &'static str,
    checked: bool,
    overridden: bool,
    #[props(default)] default_note: Option<&'static str>,
    onchange: EventHandler<bool>,
) -> Element {
    rsx! {
        div { class: "label-cell",
            label { "{label}: " }
        }
        div { class: "field",
            input {
                                r#type: "checkbox",
                                checked,
                                onchange: move |ev| onchange.call(ev.checked()),
                            }
            span { class: "hint",
                                if overridden {
                                    "override"
                                } else {
                                    {default_note.unwrap_or("default")}
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
        div { class: "label-cell",
            label { "{label}: " }
        }
        div { class: "field",
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

/// Table row with a labeled text input; an empty value clears the override
#[component]
fn SettingTextRow(
    label: &'static str,
    value: Option<String>,
    onchange: EventHandler<Option<String>>,
) -> Element {
    let overridden = value.is_some();
    rsx! {
        div { class: "label-cell",
            label { "{label}: " }
        }
        div { class: "field",
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
    Folders,
}

const TABS: &[(SettingsTab, &str)] = &[
    (SettingsTab::Policy, "Policy"),
    (SettingsTab::NameConstraints, "Name constraints"),
    (SettingsTab::TrustAndPath, "Trust anchors & path"),
    (SettingsTab::Target, "Target"),
    (SettingsTab::Revocation, "Revocation"),
    (SettingsTab::Fetching, "Fetching"),
    (SettingsTab::Folders, "Folders & files"),
];

/// Whether a tab has anything to offer the frontend showing it.
///
/// Folders and files name paths on a machine the browser has no way to reach, so it is left out
/// there rather than shown with a notice saying it does nothing: a tab that only ever explains its
/// own absence of effect costs a reader more than it tells them. The values are not discarded with
/// it — they stay in the model, so a settings file carrying paths still loads here, keeps them, and
/// hands them back intact to the CLI or the desktop app that can act on them.
fn tab_applies(tab: SettingsTab, caps: &Capabilities) -> bool {
    match tab {
        SettingsTab::Folders => caps.filesystem,
        _ => true,
    }
}

/// Renderer-agnostic settings editor over a [`SettingsModel`]. The `on_save` handler receives the
/// edited model; persistence (file, server, browser storage) is the frontend's concern. `caps`
/// declares what this frontend can act on, which drives the per-group notices; it defaults to the
/// most restrictive combination.
#[component]
pub fn EditSettings(
    initial: SettingsModel,
    #[props(default)] caps: Capabilities,
    /// What an *unset* `check_revocation_status` resolves to for the run this frontend will make.
    ///
    /// certval's default is true, but a frontend may resolve an unset value differently: the browser
    /// turns it on only when the run can obtain revocation data, by retrieving it or by being handed
    /// it. Stating the outcome here keeps the form honest without gui-lib re-implementing the rule --
    /// the frontend that owns the rule reports it, and this only displays it. `None` means certval's
    /// default applies, which is the case for the desktop and the CLI.
    #[props(default)]
    revocation_default: Option<bool>,
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
                for (t , label) in TABS.iter().filter(|(t, _)| tab_applies(*t, &caps)) {
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
            p { class: "hint",
                "Fields marked \"default\" are not present in the settings and use certval "
                "defaults; editing a field records an override."
            }

            match tab() {
                SettingsTab::Policy => rsx! {
                    div { class: "controls",
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
                    div { class: "controls",
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
                    div { class: "controls",
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
                        TimeOfInterestRow {
                            value: m.time_of_interest,
                            onchange: move |v| model.write().time_of_interest = v,
                        }
                        BoolRow {
                            label: "Ignore expired certificates when building",
                            checked: m.ignore_expired.unwrap_or(false),
                            overridden: m.ignore_expired.is_some(),
                            onchange: move |v| model.write().ignore_expired = Some(v),
                        }
                    }
                },
                SettingsTab::Revocation => rsx! {
                    // Two distinct reasons revocation can be inert, reported separately because
                    // the remedies differ: one is how certval was built, the other is whether
                    // anything can reach a responder from here.
                    if !caps.revocation {
                        CapabilityNotice {
                            message: "This frontend was built without revocation support, so these settings are \
                                      recorded in the settings file but not applied to a run here."
                                .to_string(),
                        }
                    } else if !caps.network {
                        CapabilityNotice {
                            message: "Retrieving CRLs and OCSP responses needs outbound network access, which is \
                                      not available here. Revocation data supplied with the certificates is still \
                                      honored; these settings otherwise apply only where the tool can fetch."
                                .to_string(),
                        }
                    }
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
                        div { class: "controls",
                            BoolRow {
                                label: "Check revocation status (master)",
                                checked: m.check_revocation_status
                                    .unwrap_or(revocation_default.unwrap_or(true)),
                                overridden: m.check_revocation_status.is_some(),
                                // Only when this frontend's unset value disagrees with certval's,
                                // so the ordinary case still reads plainly as "default".
                                default_note: match revocation_default {
                                    Some(false) => {
                                        Some("default — off for this run; tick to check anyway")
                                    }
                                    _ => None,
                                },
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
                },
                SettingsTab::Fetching => rsx! {
                    if !caps.network {
                        CapabilityNotice {
                            message: "Chasing AIA and SIA needs outbound network access, which is not available \
                                      here: certificate repositories are served over plain http and send no CORS \
                                      headers, so a browser cannot reach them without a relay. Paths are built \
                                      from the selected store and any uploaded certificates instead."
                                .to_string(),
                        }
                    }
                    div { class: "controls",
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
                },
                SettingsTab::Folders => rsx! {
                    div { class: "controls",
                        SettingTextRow {
                            label: "Trust anchor folder",
                            value: m.trust_anchor_folder.clone(),
                            onchange: move |v| model.write().trust_anchor_folder = v,
                        }
                        SettingTextRow {
                            label: "CA folder",
                            value: m.certification_authority_folder.clone(),
                            onchange: move |v| model.write().certification_authority_folder = v,
                        }
                        SettingTextRow {
                            label: "Download folder",
                            value: m.download_folder.clone(),
                            onchange: move |v| model.write().download_folder = v,
                        }
                        SettingTextRow {
                            label: "Last-modified map file",
                            value: m.last_modified_map_file.clone(),
                            onchange: move |v| model.write().last_modified_map_file = v,
                        }
                        SettingTextRow {
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
        move || SettingsModel::from_cps(&FileSettingsStore::new(path).load())
    });

    // A failed write is reported here rather than only logged. Saving closes the form, so a silent
    // failure looks exactly like a successful save until the settings are next read back.
    let mut save_error = use_signal(String::new);

    let save_path = path.clone();
    let on_save = move |edited: SettingsModel| {
        let store = FileSettingsStore::new(save_path.clone());
        // start from the stored contents so settings not surfaced in the form are preserved
        let mut cps = store.load();
        edited.apply(&mut cps);
        if let Err(e) = store.save(&cps) {
            error!("{e}");
            // leave the form open so the edits are not lost with the file they could not reach
            save_error.set(e);
            return;
        }
        save_error.set(String::new());
        on_close.call(());
    };

    rsx! {
        if !save_error().is_empty() {
            p { class: "capability-notice", "{save_error}" }
        }
        EditSettings {
            initial,
            caps: Capabilities::desktop(),
            on_save,
            on_close: move |_| on_close.call(()),
        }
    }
}
