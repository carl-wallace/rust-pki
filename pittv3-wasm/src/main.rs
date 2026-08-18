#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

mod validate;

use dioxus::prelude::*;
use web_time::{SystemTime, UNIX_EPOCH};

use certval::{CertificationPathSettings, TimeOfInterest};
use pittv3_gui_lib::gui_results::ResultsView;
use pittv3_gui_lib::gui_settings::{Capabilities, EditSettings};
use pittv3_gui_lib::gui_settings_model::SettingsModel;
use pittv3_gui_lib::gui_shell::AppShell;
use pittv3_gui_lib::settings_store::SettingsStore;
use pittv3_gui_lib::PITTV3_CSS;
use pittv3_lib::report::{TargetReport, ValidationReport};

use crate::validate::{
    prepare_validation, validate_hackathon_zip, validate_prepared, PreparedValidation, ResultLine,
    SAMPLE_INVALID, SAMPLE_VALID, STORES,
};

/// Store selection value indicating no baked-in store, i.e., uploaded trust anchors only
const NO_STORE: usize = usize::MAX;

/// localStorage key under which the settings are persisted across reloads, as the same
/// `CertificationPathSettings` JSON the CLI's `--settings` reads and the Download button writes
/// (used only by the wasm-gated storage helpers, hence unused on the host test build)
#[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
const SETTINGS_KEY: &str = "pittv3.settings";

/// localStorage key for the validate-all choice. Separate from [`SETTINGS_KEY`] because it is not a
/// `CertificationPathSettings` value — it selects how many paths a run explores, not what a path
/// must satisfy — and keeping it out preserves the settings key as an exact copy of the shared
/// interchange format.
#[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
const VALIDATE_ALL_KEY: &str = "pittv3.validate_all";

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

/// Reads a string from localStorage. None when storage is unavailable or the key is absent; native
/// builds (cargo check/test on the host) have no browser storage, and the app only runs as wasm.
#[cfg(target_family = "wasm")]
fn storage_get(key: &str) -> Option<String> {
    web_sys::window()?
        .local_storage()
        .ok()??
        .get_item(key)
        .ok()?
}

/// Writes a string to localStorage. Best-effort: storage may be unavailable or full.
#[cfg(target_family = "wasm")]
fn storage_set(key: &str, value: &str) -> Result<(), String> {
    let storage = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .ok_or_else(|| "Browser storage is unavailable".to_string())?;
    storage
        .set_item(key, value)
        .map_err(|_| "Browser storage is full or blocked".to_string())
}

#[cfg(not(target_family = "wasm"))]
fn storage_get(_key: &str) -> Option<String> {
    None
}

#[cfg(not(target_family = "wasm"))]
fn storage_set(_key: &str, _value: &str) -> Result<(), String> {
    Ok(())
}

/// The browser frontend's [`SettingsStore`]: localStorage holding the same
/// `CertificationPathSettings` JSON that the CLI reads, the desktop editor writes and this app's
/// own Download/Load controls exchange. Storing the interchange format rather than a private
/// encoding is what lets a settings file move between the frontends unchanged.
struct LocalStorageSettingsStore;

impl SettingsStore for LocalStorageSettingsStore {
    fn load(&self) -> CertificationPathSettings {
        storage_get(SETTINGS_KEY)
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    }

    fn save(&self, cps: &CertificationPathSettings) -> Result<(), String> {
        let json =
            serde_json::to_string(cps).map_err(|e| format!("Failed to encode settings: {e}"))?;
        storage_set(SETTINGS_KEY, &json)
    }
}

/// Reads the persisted validate-all choice, defaulting to true (explore every discovered path)
fn load_validate_all() -> bool {
    storage_get(VALIDATE_ALL_KEY)
        .map(|v| v == "true")
        .unwrap_or(true)
}

/// Builds the settings for a run from the edited model.
///
/// A model with no time of interest means "use the current time", and this is where that is
/// materialized. It matters because certval's default for an absent `PS_TIME_OF_INTEREST` is
/// `TimeOfInterest::disabled()` in a no-std build like this one but `TimeOfInterest::now()` under
/// std: leaving the value out would silently disable validity-period checking in the browser while
/// the very same settings file checked against the current time on the desktop. Filling it in at
/// run time keeps the two frontends in agreement and still leaves the stored file portable, since
/// the value is not written back to the model.
///
/// Revocation status checking is materialized the same way and for the same class of reason:
/// certval's default for an absent `PS_CHECK_REVOCATION_STATUS` is *true*, and nothing in the
/// browser can fetch a CRL or an OCSP response until a relay exists, so an unstated preference
/// means off here.
///
/// This is anticipatory rather than load-bearing today. The validation path this frontend uses
/// (`pittv3_gui_lib::validate`) has no `check_revocation` call site at all -- the one that reads
/// this setting lives in `pittv3_lib::no_std_utils`, which it does not go through -- so the
/// setting currently decides nothing. Certval is built with `revocation` so the processing code is
/// present for stapled data; wiring the call site is what makes this line matter, and the default
/// should already be right when that happens rather than flipping every existing user's results to
/// `RevocationStatusNotDetermined` on the day it lands. A user who sets it explicitly still gets
/// what they asked for -- the settings form says outright that these settings apply only where the
/// tool can fetch.
fn run_settings(model: &SettingsModel) -> CertificationPathSettings {
    let mut cps = CertificationPathSettings::default();
    model.apply(&mut cps);
    if model.time_of_interest.is_none() {
        if let Ok(toi) = TimeOfInterest::from_unix_secs(now_as_unix_epoch()) {
            cps.set_time_of_interest(toi);
        }
    }
    if model.check_revocation_status.is_none() {
        cps.set_check_revocation_status(false);
    }
    cps
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

/// True on touch devices (iPad/iPhone). iPadOS Safari reports as desktop macOS in its user agent,
/// so `navigator.maxTouchPoints` (0 on a real Mac/PC, >0 on iPad/iPhone) is the reliable signal.
/// Used to broaden the store inputs' `accept` filter only where it is needed: iOS grays out files
/// whose extension (.cbor/.ta) has no registered UTI unless a supertype (application/octet-stream)
/// is also offered, whereas on desktop that supertype would defeat the extension filter entirely.
#[cfg(target_family = "wasm")]
fn is_touch_device() -> bool {
    web_sys::window()
        .map(|w| w.navigator().max_touch_points() > 0)
        .unwrap_or(false)
}

#[cfg(not(target_family = "wasm"))]
fn is_touch_device() -> bool {
    false
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
    let mut view = use_signal(|| 0usize);
    let mut mode = use_signal(|| 0usize);

    // The settings are held as a single SettingsModel, edited through the shared EditSettings form
    // and persisted as CertificationPathSettings JSON. A stored time of interest is restored as-is;
    // its absence means "current time", which run_settings materializes per run, so a stale stored
    // time can never silently drive validation.
    let mut settings = use_signal(|| SettingsModel::from_cps(&LocalStorageSettingsStore.load()));
    // Bumped whenever the model is replaced wholesale (loading a settings file, Reset). EditSettings
    // seeds its own working copy from `initial` once per mount, so the form is keyed on this to
    // remount and pick the new values up.
    let mut form_gen = use_signal(|| 0usize);
    let mut validate_all = use_signal(load_validate_all);
    // Transient status line for the settings-file load/save controls (cleared on next action)
    let mut settings_status = use_signal(String::new);
    let mut targets = use_signal(Vec::<TargetReport>::new);
    let mut notes = use_signal(Vec::<ResultLine>::new);
    let mut uploaded_tas = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut uploaded_cas = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut loaded_ees = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut loaded_zips = use_signal(Vec::<(String, Vec<u8>)>::new);
    // The uploads panel's expanded state is deliberately NOT tracked here — see the store
    // dropdown's `onchange`, which pushes it open once when "None" is selected and otherwise
    // leaves the browser to own it.
    // True while a validation is running, to show a busy state (the parse/validation is synchronous
    // and can take a moment on a large store).
    let mut validating = use_signal(|| false);
    // Fetched CBOR for the most recently used built-in store, cached as (store index, ta, ca) so
    // repeated validations with the same selection do not re-download it.
    let mut loaded_store = use_signal(|| None::<(usize, Vec<u8>, Vec<u8>)>);
    // Cached prepared validation environment (parsed stores + discovered partial paths) and its
    // preparation notes. Reused across Validate clicks so re-validating with only the target
    // certificates changed skips the reparse and, above all, the partial-path discovery.
    let mut prepared_env = use_signal(|| None::<(PreparedValidation, Vec<ResultLine>)>);
    // Set whenever an input feeding the prepared environment (settings, store selection, uploaded
    // trust anchors or CA certificates) changes, so the next Validate rebuilds it. Starts true
    // because nothing is prepared yet.
    let mut env_dirty = use_signal(|| true);

    // Persist the settings whenever the model changes, and mark the prepared environment stale
    // (settings can affect partial-path discovery). Reading the model here subscribes this effect
    // to every field at once — the single-signal equivalent of the per-field reads this replaced.
    use_effect(move || {
        let mut cps = LocalStorageSettingsStore.load();
        settings().apply(&mut cps);
        if let Err(e) = LocalStorageSettingsStore.save(&cps) {
            settings_status.set(e);
        }
        env_dirty.set(true);
    });

    // Validate-all is persisted separately; it is not a CertificationPathSettings value.
    use_effect(move || {
        let _ = storage_set(
            VALIDATE_ALL_KEY,
            if validate_all() { "true" } else { "false" },
        );
    });

    // The store selection and uploaded trust anchors / CA certificates also feed the prepared
    // environment; reading them here subscribes this effect so any change marks it stale.
    use_effect(move || {
        let _ = mode();
        let _ = uploaded_tas.read();
        let _ = uploaded_cas.read();
        env_dirty.set(true);
    });

    // Replaces the whole model, remounting the form so it reseeds from the new values. Used by
    // Reset to defaults and by loading a settings file.
    let mut replace_settings = move |model: SettingsModel| {
        settings.set(model);
        form_gen += 1;
    };

    // The time a run validates against, for stamping reports: the chosen time of interest, or the
    // current time when none is set. Mirrors what run_settings materializes into the settings.
    let effective_toi = move || {
        settings()
            .time_of_interest
            .unwrap_or_else(now_as_unix_epoch)
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
        let report = ValidationReport::from_targets(&targets.read(), effective_toi());
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

    // downloads the current settings as a certval CertificationPathSettings JSON file — the same
    // format the PITTv3 CLI and desktop apps read — via a synthesized anchor click. A non-custom
    // time of interest is omitted so the file stays portable (the reader supplies its own current
    // time); an explicitly set one is written so it travels with the file.
    let save_settings_file = move |_| {
        // Written from the model, not from run_settings: a time of interest the user did not choose
        // stays absent so the file remains portable, and the reader supplies its own current time.
        let mut cps = LocalStorageSettingsStore.load();
        settings().apply(&mut cps);
        let json = serde_json::to_string_pretty(&cps).unwrap_or_default();
        let uri = format!(
            "data:application/json;charset=utf-8,{}",
            percent_encode(&json)
        );
        let js = format!(
            "const a = document.createElement('a'); a.href = \"{uri}\"; a.download = \"pittv3-settings-{}.json\"; a.click();",
            now_as_unix_epoch()
        );
        let _ = dioxus::document::eval(&js);
        settings_status.set("Settings downloaded".to_string());
    };

    // loads settings from a certval CertificationPathSettings JSON file (the same format the CLI's
    // --settings reads and the desktop editor writes), replacing the model wholesale. A setting
    // absent from the file takes its certval default, so the loaded state matches the file exactly.
    // Validate-all is not part of the format and is left unchanged.
    let load_settings_file = move |ev: FormEvent| async move {
        let Some((name, bytes)) = read_files(&ev).await.into_iter().next() else {
            return;
        };
        let text = match String::from_utf8(bytes) {
            Ok(t) => t,
            Err(_) => {
                settings_status.set(format!("{name} is not a valid UTF-8 settings file"));
                return;
            }
        };
        let cps: CertificationPathSettings = match serde_json::from_str(&text) {
            Ok(c) => c,
            Err(e) => {
                settings_status.set(format!("Failed to parse {name}: {e}"));
                return;
            }
        };
        replace_settings(SettingsModel::from_cps(&cps));
        settings_status.set(format!("Loaded settings from {name}"));
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
        let cps = run_settings(&settings());
        for (name, bytes) in loaded_zips() {
            let (reports, lines) = validate_hackathon_zip(&name, bytes, &cps, validate_all());
            notes.write().extend(lines);
            targets.write().extend(reports);
        }
        view.set(RESULTS_VIEW);
    };

    // validates everything loaded (certificates against the store/uploads) using the settings in
    // effect at click time. The prepared environment (parsed stores + discovered partial paths) is
    // rebuilt only when it is dirty — i.e., the settings, store selection or uploads changed since
    // the last run — and otherwise reused, so re-validating different targets is fast. Async because
    // the selected store's CBOR is fetched on demand (only when rebuilding); a fetch or preparation
    // failure is surfaced as a note and aborts before validation.
    let validate_loaded = move || async move {
        // each Validate replaces the prior results rather than appending to them
        targets.write().clear();
        notes.write().clear();
        validating.set(true);
        // Yield one frame so the busy state paints before the synchronous parse/validation blocks
        // the (single) thread; on a large store the first parse otherwise reads as a hang.
        #[cfg(target_family = "wasm")]
        gloo_timers::future::TimeoutFuture::new(16).await;

        let base_notes: Vec<ResultLine> = vec![];
        let cps = run_settings(&settings());

        // Rebuild the prepared environment only when it is stale (or absent); otherwise reuse the
        // cached one, skipping the store fetch, reparse and partial-path discovery.
        if env_dirty() || prepared_env.read().is_none() {
            let store_bytes = match ensure_store().await {
                Ok(bytes) => bytes,
                Err(e) => {
                    notes.write().push(ResultLine {
                        class: "err",
                        text: e,
                    });
                    validating.set(false);
                    view.set(RESULTS_VIEW);
                    return;
                }
            };
            let label = STORES.get(mode()).map(|s| s.label);
            let store = store_bytes
                .as_ref()
                .map(|(ta, ca)| (label.unwrap_or_default(), ta.as_slice(), ca.as_slice()));
            match prepare_validation(store, &uploaded_tas(), &uploaded_cas(), &cps) {
                Ok(prepared) => {
                    prepared_env.set(Some(prepared));
                    env_dirty.set(false);
                }
                Err(fatal) => {
                    notes.write().extend(base_notes);
                    notes.write().extend(fatal);
                    validating.set(false);
                    view.set(RESULTS_VIEW);
                    return;
                }
            }
        }

        // validate the loaded targets against the (now current) cached environment
        notes.write().extend(base_notes);
        let guard = prepared_env.read();
        let (prepared, prep_notes) = guard.as_ref().unwrap();
        notes.write().extend(prep_notes.iter().cloned());
        let (reports, lines) = validate_prepared(prepared, &cps, &loaded_ees(), validate_all());
        drop(guard);
        notes.write().extend(lines);
        targets.write().extend(reports);
        validating.set(false);
        view.set(RESULTS_VIEW);
    };

    // On touch devices (iPad/iPhone) the file picker grays out .cbor/.ta stores unless a generic
    // supertype is offered; on desktop that supertype would defeat the extension filter, so keep
    // the strict list there. See is_touch_device.
    let touch = is_touch_device();
    let ta_accept = if touch {
        ".der,.crt,.cer,.pem,.ta,.cbor,application/octet-stream"
    } else {
        ".der,.crt,.cer,.pem,.ta,.cbor"
    };
    let ca_accept = if touch {
        ".der,.crt,.cer,.pem,.cbor,application/octet-stream"
    } else {
        ".der,.crt,.cer,.pem,.cbor"
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
                                    let selected = v.parse::<usize>().unwrap_or(NO_STORE);
                                    mode.set(selected);
                                    // "None" means uploaded material is the only trust source, so
                                    // open the panel holding it rather than leaving the user to
                                    // discover they have to expand it. Pushed straight at the DOM
                                    // rather than bound to a signal: `open` is left uncontrolled so
                                    // the browser stays the single owner of the panel's state. A
                                    // controlled `open` has to be re-asserted on every render,
                                    // which fights the user's own toggling — and because the
                                    // `toggle` event fires for programmatic changes too, syncing it
                                    // back from `ontoggle` oscillates instead of settling.
                                    if selected == NO_STORE {
                                        let _ = dioxus::document::eval(
                                            "const d = document.getElementById('uploads-panel'); if (d) d.open = true;",
                                        );
                                    }
                                },
                                for (i, s) in STORES.iter().enumerate() {
                                    option { value: "{i}", selected: mode() == i, "{s.label}" }
                                }
                                option { value: "none", selected: mode() == NO_STORE, "None (uploaded trust anchors and CA certificates only)" }
                            }
                        }

                        details { class: "panel", id: "uploads-panel",
                            summary { "Additional trust anchors and intermediates (certificates or .cbor stores)" }
                            div { class: "controls custom",
                                label { "Trust anchor(s): " }
                                input {
                                    r#type: "file",
                                    multiple: true,
                                    accept: "{ta_accept}",
                                    onchange: move |ev| async move {
                                        let files = read_files(&ev).await;
                                        extend_unique(uploaded_tas, files);
                                    },
                                }
                                label { "Intermediate CA(s): " }
                                input {
                                    r#type: "file",
                                    multiple: true,
                                    accept: "{ca_accept}",
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

                        // Validate All sits beside the Validate button rather than in Settings: it
                        // chooses how much of a run to do, not what a path must satisfy, and it is
                        // not a CertificationPathSettings value. The desktop app surfaces it the
                        // same way, on its Validate view.
                        div { class: "controls center-row",
                            label { r#for: "validate-all", "Validate all paths: " }
                            input {
                                id: "validate-all",
                                r#type: "checkbox",
                                checked: validate_all(),
                                onchange: move |ev| validate_all.set(ev.checked()),
                            }
                            span { class: "hint",
                                "Off stops at the first valid path; on reports every path found."
                            }
                        }

                        div { class: "controls center-row",
                            button {
                                class: "validate-button",
                                disabled: loaded_ees().is_empty() || validating(),
                                onclick: move |_| async move { validate_loaded().await },
                                if validating() {
                                    "Validating\u{2026}"
                                } else {
                                    "Validate loaded certificate(s) using current TA and CA stores and settings"
                                }
                            }
                        }
                    },
                    1 => rsx! {
                        // The shared settings form, the same component the desktop app mounts. It
                        // presents every tab including the ones this frontend cannot act on, each
                        // carrying a notice saying so — see Capabilities. Keyed on form_gen so a
                        // wholesale model replacement (Reset, or loading a file) remounts it.
                        div { key: "{form_gen}",
                            EditSettings {
                                initial: settings(),
                                caps: Capabilities::browser_local(),
                                on_save: move |edited| {
                                    settings.set(edited);
                                    settings_status.set("Settings saved".to_string());
                                },
                                on_close: move |_| view.set(0),
                            }
                        }
                        fieldset {
                            legend { "Settings file" }
                            div { class: "controls",
                                label { "Save settings: " }
                                span {
                                    button { onclick: save_settings_file, "Download settings file" }
                                }
                                label { "Load settings: " }
                                input {
                                    r#type: "file",
                                    accept: ".json,application/json",
                                    onchange: load_settings_file,
                                }
                                span { class: "hint",
                                    "Files use the same JSON format as the PITTv3 CLI and desktop apps. "
                                    "Loading a file replaces every field above. The current settings are also "
                                    "cached in this browser's local storage; use Download to keep a copy."
                                }
                                if !settings_status().is_empty() {
                                    span { class: "hint", "{settings_status}" }
                                }
                            }
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
                                    report: ValidationReport::from_targets(
                                        &targets.read(),
                                        effective_toi(),
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

#[cfg(test)]
mod tests {
    use super::run_settings;
    use pittv3_gui_lib::gui_settings_model::SettingsModel;

    /// certval's default for an absent `PS_CHECK_REVOCATION_STATUS` is true, so the browser would
    /// otherwise carry a preference for a check it has no way to satisfy. The frontend's current
    /// validation path reads the setting nowhere, so this guards the intent rather than an active
    /// behavior: it is what keeps the day a `check_revocation` call site is wired from silently
    /// turning every existing user's results into `RevocationStatusNotDetermined`.
    #[test]
    fn revocation_checking_is_off_unless_asked_for() {
        let cps = run_settings(&SettingsModel::default());
        assert!(!cps.get_check_revocation_status());
    }

    /// An explicit preference is still honored -- the settings form states that these settings
    /// apply only where the tool can fetch, so a user who sets it gets what they asked for rather
    /// than a silently discarded setting.
    #[test]
    fn explicit_revocation_preference_is_honored() {
        let model = SettingsModel {
            check_revocation_status: Some(true),
            ..SettingsModel::default()
        };
        assert!(run_settings(&model).get_check_revocation_status());
    }
}
