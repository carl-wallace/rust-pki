#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

mod validate;

use dioxus::prelude::*;
use web_time::{SystemTime, UNIX_EPOCH};

use certval::{CertificationPathSettings, PathValidationStatus, PS_TIME_OF_INTEREST};
use pittv3_gui_lib::gui_results::ResultsView;
use pittv3_gui_lib::gui_settings_model::SettingsModel;
use pittv3_gui_lib::gui_shell::AppShell;
use pittv3_gui_lib::PITTV3_CSS;
use pittv3_lib::report::{ReportTotals, TargetReport, ValidationReport};

use crate::validate::{
    make_cps, prepare_validation, validate_hackathon_zip, validate_prepared, NameConstraintInputs,
    PreparedValidation, ResultLine, ValidationSettings, SAMPLE_INVALID, SAMPLE_VALID, STORES,
};

/// Store selection value indicating no baked-in store, i.e., uploaded trust anchors only
const NO_STORE: usize = usize::MAX;

/// OID for anyPolicy, the default user-initial-policy-set value
const ANY_POLICY_OID: &str = "2.5.29.32.0";

/// localStorage key under which the settings tab is persisted across reloads (used only by the
/// wasm-gated storage helpers, hence unused on the host test build)
#[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
const SETTINGS_KEY: &str = "pittv3.settings";

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

/// The settings tab's default state: the certval defaults plus the current time as the (non-custom)
/// time of interest. Used for a fresh visit and by Reset to defaults.
fn default_settings() -> ValidationSettings {
    ValidationSettings {
        toi: now_as_unix_epoch(),
        toi_custom: false,
        validate_all: true,
        initial_explicit_policy: false,
        initial_policy_mapping_inhibit: false,
        initial_inhibit_any_policy: false,
        initial_policy_set: ANY_POLICY_OID.to_string(),
        enforce_trust_anchor_constraints: false,
        enforce_trust_anchor_validity: true,
        permitted_subtrees: NameConstraintInputs::default(),
        excluded_subtrees: NameConstraintInputs::default(),
    }
}

/// Reads the persisted settings tab from localStorage, or None when absent, unreadable or invalid.
#[cfg(target_family = "wasm")]
fn load_persisted_settings() -> Option<ValidationSettings> {
    let storage = web_sys::window()?.local_storage().ok()??;
    let json = storage.get_item(SETTINGS_KEY).ok()??;
    serde_json::from_str(&json).ok()
}

/// Writes the settings tab to localStorage so it survives a reload. Best-effort: storage may be
/// unavailable or full, in which case persistence is silently skipped.
#[cfg(target_family = "wasm")]
fn persist_settings(vs: &ValidationSettings) {
    if let Ok(json) = serde_json::to_string(vs) {
        if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
            let _ = storage.set_item(SETTINGS_KEY, &json);
        }
    }
}

// Native builds (cargo check/test on the host) have no browser storage; the app only runs as wasm.
#[cfg(not(target_family = "wasm"))]
fn load_persisted_settings() -> Option<ValidationSettings> {
    None
}

#[cfg(not(target_family = "wasm"))]
fn persist_settings(_vs: &ValidationSettings) {}

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

/// Formats Unix-epoch seconds as a `datetime-local` value (`YYYY-MM-DDTHH:MM:SS`) in local time,
/// the inverse of [`datetime_local_to_epoch`]. Empty on host builds.
#[cfg(target_family = "wasm")]
fn epoch_to_datetime_local(secs: u64) -> String {
    // new_0() then set_time avoids needing a JsValue import just to build the Date from millis.
    let date = js_sys::Date::new_0();
    date.set_time(secs as f64 * 1000.0);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        date.get_full_year(),
        date.get_month() + 1, // getMonth is 0-based
        date.get_date(),
        date.get_hours(),
        date.get_minutes(),
        date.get_seconds(),
    )
}

#[cfg(not(target_family = "wasm"))]
fn epoch_to_datetime_local(_secs: u64) -> String {
    String::new()
}

/// The `datetime-local` value mirroring the time-of-interest epoch string, so the picker shows the
/// selected time and the user need not decode the number. Empty when the time is disabled (0) or
/// not yet a valid epoch (e.g. mid-edit in the epoch field).
fn toi_datetime_value(toi: &str) -> String {
    match toi.trim().parse::<u64>() {
        Ok(secs) if secs != 0 => epoch_to_datetime_local(secs),
        _ => String::new(),
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

    // Restore the settings tab from localStorage (or fall back to defaults) so a custom time of
    // interest and the RFC 5280 inputs survive a reload. Destructure once and seed each signal.
    let ValidationSettings {
        toi_custom: init_toi_custom,
        toi: init_toi,
        validate_all: init_validate_all,
        initial_explicit_policy: init_iep,
        initial_policy_mapping_inhibit: init_ipmi,
        initial_inhibit_any_policy: init_iiap,
        initial_policy_set: init_ips,
        enforce_trust_anchor_constraints: init_etac,
        enforce_trust_anchor_validity: init_etav,
        permitted_subtrees: init_perm,
        excluded_subtrees: init_excl,
    } = use_hook(|| load_persisted_settings().unwrap_or_else(default_settings));
    let NameConstraintInputs {
        dns_name: init_perm_dns,
        rfc822_name: init_perm_email,
        directory_name: init_perm_dn,
        uniform_resource_identifier: init_perm_uri,
        ip_address: init_perm_ip,
    } = init_perm;
    let NameConstraintInputs {
        dns_name: init_excl_dns,
        rfc822_name: init_excl_email,
        directory_name: init_excl_dn,
        uniform_resource_identifier: init_excl_uri,
        ip_address: init_excl_ip,
    } = init_excl;

    // A custom time of interest is restored as-is; otherwise it is (re)initialized to the current
    // time so a stale stored time cannot silently drive validation. `toi_custom` tracks which.
    let mut toi_custom = use_signal(move || init_toi_custom);
    let mut toi = use_signal(move || {
        if init_toi_custom {
            init_toi.to_string()
        } else {
            now_as_unix_epoch().to_string()
        }
    });
    let mut validate_all = use_signal(move || init_validate_all);
    // Transient status line for the settings-file load/save controls (cleared on next action)
    let mut settings_status = use_signal(String::new);
    let mut targets = use_signal(Vec::<TargetReport>::new);
    let mut notes = use_signal(Vec::<ResultLine>::new);
    let mut uploaded_tas = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut uploaded_cas = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut loaded_ees = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut loaded_zips = use_signal(Vec::<(String, Vec<u8>)>::new);
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

    // RFC 5280 path validation inputs (defaults match CertificationPathSettings::default())
    let mut initial_explicit_policy = use_signal(move || init_iep);
    let mut initial_policy_mapping_inhibit = use_signal(move || init_ipmi);
    let mut initial_inhibit_any_policy = use_signal(move || init_iiap);
    let mut initial_policy_set = use_signal(move || init_ips);
    let mut enforce_ta_constraints = use_signal(move || init_etac);
    let mut enforce_ta_validity = use_signal(move || init_etav);

    // RFC 5280 initial-permitted / initial-excluded subtrees, one entry per line per name form
    let mut perm_dns = use_signal(move || init_perm_dns);
    let mut perm_email = use_signal(move || init_perm_email);
    let mut perm_dn = use_signal(move || init_perm_dn);
    let mut perm_uri = use_signal(move || init_perm_uri);
    let mut perm_ip = use_signal(move || init_perm_ip);
    let mut excl_dns = use_signal(move || init_excl_dns);
    let mut excl_email = use_signal(move || init_excl_email);
    let mut excl_dn = use_signal(move || init_excl_dn);
    let mut excl_uri = use_signal(move || init_excl_uri);
    let mut excl_ip = use_signal(move || init_excl_ip);

    let current_settings = move || ValidationSettings {
        toi: toi().parse::<u64>().unwrap_or_else(|_| now_as_unix_epoch()),
        toi_custom: toi_custom(),
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

    // Persist the settings tab to localStorage whenever any of its inputs change, and mark the
    // prepared environment stale (settings can affect partial-path discovery). Reading every field
    // through current_settings() subscribes this effect to all of them, so any edit fires it.
    use_effect(move || {
        persist_settings(&current_settings());
        env_dirty.set(true);
    });

    // The store selection and uploaded trust anchors / CA certificates also feed the prepared
    // environment; reading them here subscribes this effect so any change marks it stale.
    use_effect(move || {
        let _ = mode();
        let _ = uploaded_tas.read();
        let _ = uploaded_cas.read();
        env_dirty.set(true);
    });

    // Restores every setting to its initial default (time of interest reset to the current time).
    let reset_settings = move |_| {
        toi.set(now_as_unix_epoch().to_string());
        toi_custom.set(false);
        validate_all.set(true);
        initial_explicit_policy.set(false);
        initial_policy_mapping_inhibit.set(false);
        initial_inhibit_any_policy.set(false);
        initial_policy_set.set(ANY_POLICY_OID.to_string());
        enforce_ta_constraints.set(false);
        enforce_ta_validity.set(true);
        settings_status.set(String::new());
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

    // downloads the current settings as a certval CertificationPathSettings JSON file — the same
    // format the PITTv3 CLI and desktop apps read — via a synthesized anchor click. A non-custom
    // time of interest is omitted so the file stays portable (the reader supplies its own current
    // time); an explicitly set one is written so it travels with the file.
    let save_settings_file = move |_| {
        let vs = current_settings();
        let mut discard = vec![];
        let mut cps = make_cps(&vs, &mut discard);
        if !vs.toi_custom {
            cps.0.remove(PS_TIME_OF_INTEREST);
        }
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

    // loads settings from a certval CertificationPathSettings JSON file (the CLI/desktop format),
    // replacing every field above. A setting absent from the file takes its certval default, so the
    // loaded state matches the file exactly. The time of interest is honored (and marked custom)
    // when present, or reset to the current time when absent; validate-all is not part of the format
    // and is left unchanged.
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
        let m = SettingsModel::from_cps(&cps);
        match m.time_of_interest {
            Some(secs) => {
                toi.set(secs.to_string());
                toi_custom.set(true);
            }
            None => {
                toi.set(now_as_unix_epoch().to_string());
                toi_custom.set(false);
            }
        }
        initial_explicit_policy.set(m.initial_explicit_policy_indicator.unwrap_or(false));
        initial_policy_mapping_inhibit
            .set(m.initial_policy_mapping_inhibit_indicator.unwrap_or(false));
        initial_inhibit_any_policy.set(m.initial_inhibit_any_policy_indicator.unwrap_or(false));
        initial_policy_set.set(
            m.initial_policy_set
                .map(|v| v.join(" "))
                .unwrap_or_else(|| ANY_POLICY_OID.to_string()),
        );
        enforce_ta_constraints.set(m.enforce_trust_anchor_constraints.unwrap_or(false));
        enforce_ta_validity.set(m.enforce_trust_anchor_validity.unwrap_or(true));
        // one entry per line per name form; the unsupported-forms bucket is not surfaced
        let perm = m.initial_permitted_subtrees.unwrap_or_default();
        perm_dns.set(perm.dns_name.map(|v| v.join("\n")).unwrap_or_default());
        perm_email.set(perm.rfc822_name.map(|v| v.join("\n")).unwrap_or_default());
        perm_dn.set(
            perm.directory_name
                .map(|v| v.join("\n"))
                .unwrap_or_default(),
        );
        perm_uri.set(
            perm.uniform_resource_identifier
                .map(|v| v.join("\n"))
                .unwrap_or_default(),
        );
        perm_ip.set(perm.ip_address.map(|v| v.join("\n")).unwrap_or_default());
        let excl = m.initial_excluded_subtrees.unwrap_or_default();
        excl_dns.set(excl.dns_name.map(|v| v.join("\n")).unwrap_or_default());
        excl_email.set(excl.rfc822_name.map(|v| v.join("\n")).unwrap_or_default());
        excl_dn.set(
            excl.directory_name
                .map(|v| v.join("\n"))
                .unwrap_or_default(),
        );
        excl_uri.set(
            excl.uniform_resource_identifier
                .map(|v| v.join("\n"))
                .unwrap_or_default(),
        );
        excl_ip.set(excl.ip_address.map(|v| v.join("\n")).unwrap_or_default());
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
        let vs = current_settings();
        for (name, bytes) in loaded_zips() {
            let (reports, lines) = validate_hackathon_zip(&name, bytes, &vs);
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

        let vs = current_settings();
        let mut base_notes = vec![];
        let cps = make_cps(&vs, &mut base_notes);

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
        let (reports, lines) = validate_prepared(prepared, &cps, &loaded_ees(), vs.validate_all);
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
                        fieldset {
                            legend { "Path validation settings (RFC 5280 / RFC 5937 inputs)" }
                            fieldset {
                                legend { "General" }
                                div { class: "controls",
                                    label { r#for: "toi", "Time of interest (Unix epoch): " }
                                    span {
                                        input {
                                            id: "toi",
                                            r#type: "text",
                                            value: "{toi}",
                                            oninput: move |ev| {
                                                toi.set(ev.value());
                                                toi_custom.set(true);
                                            },
                                        }
                                        button {
                                            onclick: move |_| {
                                                toi.set(now_as_unix_epoch().to_string());
                                                toi_custom.set(false);
                                            },
                                            "Now"
                                        }
                                        // Value mirrors the epoch field so the picker shows the selected
                                        // time (no need to decode the number). Controlled binding is safe
                                        // here because only onchange (a complete datetime) writes back:
                                        // editing the sub-fields triggers no re-render until commit, so the
                                        // value is not reset mid-edit. step=1 keeps second precision.
                                        input {
                                            r#type: "datetime-local",
                                            step: "1",
                                            value: toi_datetime_value(&toi()),
                                            onchange: move |ev| {
                                                if let Some(secs) = datetime_local_to_epoch(&ev.value()) {
                                                    toi.set(secs.to_string());
                                                    toi_custom.set(true);
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
                                }
                            }
                            fieldset {
                                legend { "Certificate Policy-related constraints" }
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

                                    span { class: "hint",
                                        "Separate policy OIDs with spaces or commas; {ANY_POLICY_OID} is anyPolicy."
                                    }
                                }
                            }
                            // Initial permitted/excluded subtrees are RFC 5280 name-constraint inputs,
                            // so they live inside the RFC 5280 group rather than as standalone boxes.
                            fieldset {
                                legend { "Initial permitted subtrees (name constraints)" }
                                div { class: "controls",
                                    label { "dNSName: " }
                                    textarea { rows: "2", value: "{perm_dns}", oninput: move |ev| perm_dns.set(ev.value()) }
                                    label { "rfc822Name (email): " }
                                    textarea { rows: "2", value: "{perm_email}", oninput: move |ev| perm_email.set(ev.value()) }
                                    label { "directoryName (DN): " }
                                    textarea { rows: "2", value: "{perm_dn}", oninput: move |ev| perm_dn.set(ev.value()) }
                                    label { "URI: " }
                                    textarea { rows: "2", value: "{perm_uri}", oninput: move |ev| perm_uri.set(ev.value()) }
                                    label { "iPAddress (CIDR): " }
                                    textarea { rows: "2", value: "{perm_ip}", oninput: move |ev| perm_ip.set(ev.value()) }
                                    span { class: "hint",
                                        "One entry per line; an empty box imposes no initial permitted constraint for that name form."
                                    }
                                }
                            }
                            fieldset {
                                legend { "Initial excluded subtrees (name constraints)" }
                                div { class: "controls",
                                    label { "dNSName: " }
                                    textarea { rows: "2", value: "{excl_dns}", oninput: move |ev| excl_dns.set(ev.value()) }
                                    label { "rfc822Name (email): " }
                                    textarea { rows: "2", value: "{excl_email}", oninput: move |ev| excl_email.set(ev.value()) }
                                    label { "directoryName (DN): " }
                                    textarea { rows: "2", value: "{excl_dn}", oninput: move |ev| excl_dn.set(ev.value()) }
                                    label { "URI: " }
                                    textarea { rows: "2", value: "{excl_uri}", oninput: move |ev| excl_uri.set(ev.value()) }
                                    label { "iPAddress (CIDR): " }
                                    textarea { rows: "2", value: "{excl_ip}", oninput: move |ev| excl_ip.set(ev.value()) }
                                    span { class: "hint", "One entry per line." }
                                }
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
