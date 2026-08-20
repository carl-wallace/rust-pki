#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

mod relay;
mod validate;

use std::sync::Arc;

use dioxus::prelude::*;
use web_time::{SystemTime, UNIX_EPOCH};

use certval::{CertificationPathSettings, PkiEnvironment, RevocationCache, TimeOfInterest};
use pittv3_gui_lib::gui_results::ResultsView;
use pittv3_gui_lib::gui_settings::{Capabilities, EditSettings};
use pittv3_gui_lib::gui_settings_model::SettingsModel;
use pittv3_gui_lib::gui_shell::AppShell;
use pittv3_gui_lib::gui_uri_check::UriCheckResults;
use pittv3_gui_lib::settings_store::SettingsStore;
use pittv3_gui_lib::PITTV3_CSS;
use pittv3_lib::report::{RevocationStatus, TargetReport, ValidationReport};
use pittv3_lib::uri_check::{check_uris_in_cert, UriCheckReport};

use pittv3_gui_lib::export::{path_entries, paths_text, zip_paths};
use pittv3_gui_lib::retrieval::{add_uploaded_crl, harvest_revocation_work, staple_uploaded_ocsp};

use crate::relay::{
    chase_certificates, retrieve_crls, retrieve_ocsp, FetchBudget, RelayFetcher, Tier,
};
use crate::validate::{
    merge_service_stores, prepare_validation, shipped_catalog, validate_hackathon_zip,
    validate_prepared, validate_prepared_retaining, PreparedValidation, ResultLine, RetainedPath,
    StoreDescriptor,
};

/// Store selection value indicating no baked-in store, i.e., uploaded trust anchors only
const NO_STORE: usize = usize::MAX;

/// Where the stores a `pittv3-service` holds are listed, relative to this application, which that
/// service serves from its own root. A deployment that is only static hosting answers this with a
/// 404 or with its index page, and the application carries on with the stores it ships -- so the
/// request is made unconditionally rather than behind a setting nobody would know to turn on.
const SERVICE_STORES_URL: &str = "api/stores";

/// Where a service says it is up, relative to this application. Answering this is what makes the
/// relayed tier selectable: the endpoint that would do the retrieving is served by the same binary,
/// so a service that answers here has a relay.
const SERVICE_HEALTH_URL: &str = "api/health";

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

/// localStorage key for whether the revocation status cache is used. A run option like
/// [`VALIDATE_ALL_KEY`] and kept out of the settings for the same reason: it decides how a run goes
/// about reaching an answer, not what a path has to satisfy, and certval has no such setting -- the
/// cache is something a frontend registers on the environment or does not.
#[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
const REV_CACHE_KEY: &str = "pittv3.use_rev_cache";

/// Sidebar views in display order
const VIEW_LABELS: &[&str] = &[
    "Validate",
    "Settings",
    "Results",
    "Store artifacts",
    "Check URIs",
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

/// Reads the persisted revocation-cache choice, defaulting to true (reuse determinations)
fn load_use_rev_cache() -> bool {
    storage_get(REV_CACHE_KEY)
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
/// certval's default for an absent `PS_CHECK_REVOCATION_STATUS` is *true*, and a browser cannot
/// always obtain a CRL or an OCSP response, so an unstated preference depends on whether this run
/// can get hold of any.
///
/// This line is load-bearing: `pittv3_gui_lib::validate` calls `check_revocation` for a path that
/// otherwise validates, and that check consults stapled revocation data and registered CRL sources
/// rather than fetching. There are **two** ways a run comes by such data — retrieving it through a
/// relay, or being handed it by the user — and `supplied_revocation_data` is the second. Keying the
/// default on the tier alone is what made the upload buttons inert: a [`Tier::Local`] run switched
/// checking off and then never consulted the CRL it had just been given. With neither, an unstated
/// preference still means off, or every run would come back `RevocationStatusNotDetermined` for
/// want of data the page cannot obtain. In
/// [`Tier::Relayed`] the data can be retrieved, and checking is the point of having chosen that
/// tier, so an unstated preference means on.
///
/// A stated preference is honored either way — the settings form says outright that these settings
/// apply only where the tool can fetch, and a user who asks for checking in the local tier gets
/// what they asked for, undetermined status included.
fn run_settings(
    model: &SettingsModel,
    tier: Tier,
    supplied_revocation_data: bool,
) -> CertificationPathSettings {
    let mut cps = CertificationPathSettings::default();
    model.apply(&mut cps);
    if model.time_of_interest.is_none() {
        if let Ok(toi) = TimeOfInterest::from_unix_secs(now_as_unix_epoch()) {
            cps.set_time_of_interest(toi);
        }
    }
    // The unstated default asks whether this run can obtain revocation data at all -- retrieving is
    // one way to obtain it, and being handed it by the user is the other. Keying this on the tier
    // alone predates the upload buttons and made them inert: a no-network run would switch checking
    // off and then never consult the CRL or OCSP response it had just been given.
    if model.check_revocation_status.is_none() {
        cps.set_check_revocation_status(tier.retrieves() || supplied_revocation_data);
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
    // Whether determinations reached for one path may answer for another. On, a certificate checked
    // once is not checked again, which is much faster and is what a user validating certificates
    // wants. Off, every path derives every status from revocation data of its own -- which is what a
    // user *exporting* a path wants, since a hop answered from cache carries a status and no
    // evidence to hand anyone.
    let mut use_rev_cache = use_signal(load_use_rev_cache);
    // Transient status line for the settings-file load/save controls (cleared on next action)
    let mut settings_status = use_signal(String::new);
    let mut targets = use_signal(Vec::<TargetReport>::new);
    let mut notes = use_signal(Vec::<ResultLine>::new);
    let mut uploaded_tas = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut uploaded_cas = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut loaded_ees = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut loaded_zips = use_signal(Vec::<(String, Vec<u8>)>::new);
    // Revocation data supplied by hand, for a run with no network to fetch it. Held here rather
    // than pushed straight into the prepared environment because that environment is rebuilt
    // whenever the trust material or settings change, and a rebuild would take the uploads with
    // it. These are folded in at Validate instead, so they survive every rebuild.
    let mut uploaded_crls = use_signal(Vec::<(String, Vec<u8>)>::new);
    let mut uploaded_ocsp = use_signal(Vec::<(String, Vec<u8>)>::new);
    // "Check URIs in certificate": a single certificate examined on its own, independent of path
    // processing, so it keeps its own inputs rather than borrowing the Validate view's.
    let mut uri_target = use_signal(|| None::<(String, Vec<u8>)>);
    let mut uri_issuer = use_signal(|| None::<(String, Vec<u8>)>);
    let mut uri_auto = use_signal(|| true);
    let mut uri_running = use_signal(|| false);
    let mut uri_report = use_signal(|| None::<UriCheckReport>);
    // Whether this run has revocation data of its own. Read when the settings for a run are built,
    // because it is one of the two ways a run can obtain any -- see `run_settings`.
    let have_revocation_uploads =
        move || !uploaded_crls().is_empty() || !uploaded_ocsp().is_empty();
    // The uploads panel's expanded state is deliberately NOT tracked here — see the store
    // dropdown's `onchange`, which pushes it open once when "None" is selected and otherwise
    // leaves the browser to own it.
    // True while a validation is running, to show a busy state (the parse/validation is synchronous
    // and can take a moment on a large store).
    let mut validating = use_signal(|| false);
    // Stores the selector offers: the ones published with this application, plus whatever a service
    // serving it holds. Only ever appended to, so an index already selected keeps naming the store
    // it named when the listing arrives.
    let mut catalog = use_signal(shipped_catalog);
    // Whether a service is serving this application, which is what makes the relayed tier
    // selectable. Determined once at startup; a statically hosted copy leaves it false and the
    // selector says why.
    let mut service_present = use_signal(|| false);
    // Which tier a run uses. Local until a service is found *and* the user asks for retrieval:
    // choosing to disclose the URIs a certificate names is the user's to make, not a default that
    // follows from a deployment happening to offer it.
    let mut tier = use_signal(Tier::default);
    // Certificates retrieved by following AIA and SIA URIs during this session. Held apart from the
    // uploads so that clearing uploads does not discard them and so the notes can say where a
    // certificate in the path came from; they feed preparation exactly as an upload does.
    let mut chased_cas = use_signal(Vec::<(String, Vec<u8>)>::new);
    // Fetched CBOR for the most recently used store, cached as (store id, ta, ca) so repeated
    // validations with the same selection do not re-download it. Keyed by identifier rather than by
    // position, since position is a property of the catalogue rather than of the store.
    let mut loaded_store = use_signal(|| None::<(String, Vec<u8>, Vec<u8>)>);
    // Cached prepared validation environment (parsed stores + discovered partial paths) and its
    // preparation notes. Reused across Validate clicks so re-validating with only the target
    // certificates changed skips the reparse and, above all, the partial-path discovery.
    let mut prepared_env = use_signal(|| None::<(PreparedValidation, Vec<ResultLine>)>);
    // Set whenever an input feeding the prepared environment (settings, store selection, uploaded
    // trust anchors or CA certificates) changes, so the next Validate rebuilds it. Starts true
    // because nothing is prepared yet.
    let mut env_dirty = use_signal(|| true);
    // Revocation determinations, kept deliberately outside the prepared environment so they survive
    // its rebuilds. Uploads and chased certificates make that environment stale, but they change
    // which paths exist rather than whether a certificate was revoked, so discarding determinations
    // alongside it would re-fetch revocation data a retrieval had already paid for. Settings changes
    // are the case that does invalidate them, and the effect that watches settings clears this.
    let rev_cache = use_signal(|| Arc::new(RevocationCache::new()));
    // Confirmation for the Clear button below. Clearing is invisible otherwise -- nothing on screen
    // changes -- so without a word back the only way to tell it happened is to run again and watch
    // the retrieval notes.
    let mut rev_cache_status = use_signal(String::new);
    // The paths this run validated, kept so their artifacts can be exported without validating
    // again. Retaining costs nothing to compute -- the paths and results exist for the duration of
    // the validation regardless -- and re-validating to produce an export would describe a
    // different run, since revocation data moves between one click and the next.
    let mut retained_paths = use_signal(Vec::<RetainedPath>::new);
    // Name the export takes: the archive's file name and the single folder inside it. Offered rather
    // than generated because a bundle is usually about to be handed to someone else, and "the DoD
    // email cert Armen reported" survives that trip where a timestamp does not. PITTv2 prompts for
    // the same thing.
    let mut export_name = use_signal(|| "PITTv3Results".to_string());

    // What asking a service for its stores produced, in a sentence, for the Resources view. A
    // statically hosted copy finding no service is the ordinary case and not a failure, but "the
    // dropdown is shorter than I expected" has to be answerable from inside the application: the
    // alternative is a silent path whose only symptom is a missing entry.
    let mut store_service_status = use_signal(String::new);

    // Ask the service serving this application what stores it holds, once, at startup.
    //
    // Every outcome is recorded rather than only the interesting ones, and the messages go through
    // `tracing` rather than the `log` crate deliberately: `dioxus::launch` installs a tracing
    // subscriber (dioxus-logger, on by default) and nothing bridges `log` into it, so a `log::`
    // call here reaches no sink at all and the browser console stays empty.
    use_future(move || async move {
        // Asked first, and separately from the store listing: a service with no stores at all still
        // has a relay, and that is what the tier selector turns on.
        //
        // The answer is inspected rather than merely counted as a success. A static host that
        // serves index.html for every path answers this with 200 as well, and treating that as a
        // service would offer a tier whose every retrieval then fails.
        let healthy = match fetch_bytes(SERVICE_HEALTH_URL).await {
            Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| v.get("status")?.as_str().map(str::to_string))
                .is_some_and(|s| s == "ok"),
            Err(e) => {
                dioxus::logger::tracing::info!("No service at {SERVICE_HEALTH_URL}: {e}");
                false
            }
        };
        service_present.set(healthy);

        let bytes = match fetch_bytes(SERVICE_STORES_URL).await {
            Ok(bytes) => bytes,
            Err(e) => {
                let m = format!("No service answered {SERVICE_STORES_URL} ({e}); offering the stores published with this app.");
                dioxus::logger::tracing::info!("{m}");
                store_service_status.set(m);
                return;
            }
        };
        let served = match serde_json::from_slice::<Vec<StoreDescriptor>>(&bytes) {
            Ok(served) => served,
            // A static host answering every path with index.html lands here rather than in the arm
            // above -- the request succeeded, the answer was simply not a store listing.
            Err(e) => {
                let m = format!("{SERVICE_STORES_URL} answered with something other than a store listing ({e}); offering the stores published with this app.");
                dioxus::logger::tracing::info!("{m}");
                store_service_status.set(m);
                return;
            }
        };
        // Merged in place rather than read-modify-write, so nothing can be lost between the read
        // and the set.
        let offered = served.len();
        let added = catalog.with_mut(|c| merge_service_stores(c, served));
        let m = format!(
            "The service offers {offered} store(s); {added} added, {} already published with this app.",
            offered - added
        );
        dioxus::logger::tracing::info!("{m}");
        store_service_status.set(m);
    });

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
        // Settings are what genuinely invalidates a cached determination, so this is where the cache
        // is dropped rather than in the effect watching uploads and chased certificates. A cached
        // answer expires against the time being asked about, so moving the time of interest backward
        // can bring an expired one back into range, and an answer vetted under one revocation policy
        // is not vetted under a stricter one. Cheaper to clear on any settings change than to work
        // out which fields could matter.
        rev_cache().clear();
    });

    // Validate-all is persisted separately; it is not a CertificationPathSettings value.
    use_effect(move || {
        let _ = storage_set(
            VALIDATE_ALL_KEY,
            if validate_all() { "true" } else { "false" },
        );
    });

    // Whether to use the cache is decided when the environment is prepared, because that is when the
    // cache is registered on it -- so changing this has to make the environment stale, or the choice
    // would not take effect until something else happened to force a rebuild. Clearing on the way is
    // deliberate: turning the cache off and on again must not bring back determinations reached
    // before it was turned off, which are exactly the ones the user was trying to stop reusing.
    use_effect(move || {
        let on = use_rev_cache();
        let _ = storage_set(REV_CACHE_KEY, if on { "true" } else { "false" });
        rev_cache().clear();
        env_dirty.set(true);
    });

    // The store selection and uploaded trust anchors / CA certificates also feed the prepared
    // environment; reading them here subscribes this effect so any change marks it stale.
    use_effect(move || {
        let _ = mode();
        let _ = uploaded_tas.read();
        let _ = uploaded_cas.read();
        // Certificates retrieved by chasing feed preparation exactly as an upload does, so the
        // environment is as stale after a retrieval as after an upload.
        let _ = chased_cas.read();
        // The tier decides what an unstated revocation preference means, and the settings feed
        // preparation, so changing it makes the prepared environment stale too.
        let _ = tier();
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

    // Ensures the selected store's CBOR is available, fetching (and caching) it on first use.
    // Returns the owned (ta, ca) bytes, or None when no store is selected; an Err carries a message
    // to surface. Reads that touch signals are scoped so no guard is held across the await, and the
    // entry itself is cloned out for the same reason.
    let ensure_store = move || async move {
        let Some(s) = catalog().get(mode()).cloned() else {
            return Ok(None);
        };
        let cached = {
            let guard = loaded_store.read();
            guard
                .as_ref()
                .filter(|(id, _, _)| id == &s.id)
                .map(|(_, ta, ca)| (ta.clone(), ca.clone()))
        };
        if let Some(bytes) = cached {
            return Ok(Some(bytes));
        }
        let ta = fetch_bytes(&s.ta_url).await;
        // A store without a ca_url is trust-anchor-only; represent its CA side as empty bytes
        // (validate() treats an empty CA buffer as "no CA store").
        let ca = match &s.ca_url {
            Some(url) => fetch_bytes(url).await,
            None => Ok(Vec::new()),
        };
        match (ta, ca) {
            (Ok(ta), Ok(ca)) => {
                loaded_store.set(Some((s.id.clone(), ta.clone(), ca.clone())));
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

    // Builds the per-path export entries once for whichever export was asked for, so the archive and
    // the log describe the same paths in the same order.
    let build_entries = move || -> Vec<Vec<(String, Vec<u8>)>> {
        let guard = prepared_env.read();
        let Some((prepared, _)) = guard.as_ref() else {
            return vec![];
        };
        retained_paths
            .read()
            .iter()
            .map(|r| path_entries(prepared.environment(), &r.path, Some(&r.cps), &r.cpr))
            .collect()
    };

    // downloads every validated path's artifacts as a zip: the certificates, the revocation data
    // consulted, the responder certificates that make an OCSP response checkable, and a manifest per
    // path. Paths are numbered from one under the export's name.
    let save_artifacts = move |_| {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        let entries = build_entries();
        if entries.is_empty() {
            notes.write().push(ResultLine {
                class: "err",
                text: "No validated paths are held from this run to export".to_string(),
            });
            return;
        }
        let name = export_name();
        match zip_paths(&name, &entries) {
            Ok(zipped) => {
                let js = format!(
                    "const a = document.createElement('a'); a.href = \"data:application/zip;base64,{}\"; a.download = \"{name}.zip\"; a.click();",
                    STANDARD.encode(&zipped)
                );
                let _ = dioxus::document::eval(&js);
            }
            Err(e) => notes.write().push(ResultLine {
                class: "err",
                text: format!("Failed to build the archive: {e}"),
            }),
        }
    };

    // downloads the manifests alone -- every path's account of itself, one after another, without the
    // material behind them
    let save_path_logs = move |_| {
        let entries = build_entries();
        let text = paths_text(&entries);
        if text.is_empty() {
            notes.write().push(ResultLine {
                class: "err",
                text: "No validated paths are held from this run to export".to_string(),
            });
            return;
        }
        let name = export_name();
        let uri = format!("data:text/plain;charset=utf-8,{}", percent_encode(&text));
        let js = format!(
            "const a = document.createElement('a'); a.href = \"{uri}\"; a.download = \"{name}.txt\"; a.click();"
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
        let cps = run_settings(&settings(), tier(), have_revocation_uploads());
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
    // Rebuilds the prepared environment from the current store selection, uploads and retrieved
    // certificates. Separated out because a retrieving run prepares more than once: what a chase
    // brings back is an input to preparation, so folding it in means preparing again.
    let rebuild_env = move |cps: CertificationPathSettings| async move {
        let store_bytes = ensure_store().await?;
        let label = catalog()
            .get(mode())
            .map(|s| s.label.clone())
            .unwrap_or_default();
        let store = store_bytes
            .as_ref()
            .map(|(ta, ca)| (label.as_str(), ta.as_slice(), ca.as_slice()));
        // Uploaded and retrieved intermediates go into one pool: certval builds paths through
        // whatever it holds, and where a certificate came from is a matter for the notes rather
        // than for path building.
        let mut cas = uploaded_cas();
        cas.extend(chased_cas());
        let cache = if use_rev_cache() {
            Some(rev_cache())
        } else {
            None
        };
        match prepare_validation(store, &uploaded_tas(), &cas, &cps, cache.as_ref()) {
            Ok(prepared) => {
                prepared_env.set(Some(prepared));
                env_dirty.set(false);
                Ok(())
            }
            Err(fatal) => Err(fatal
                .into_iter()
                .map(|l| l.text)
                .collect::<Vec<String>>()
                .join("; ")),
        }
    };

    let validate_loaded = move || async move {
        // each Validate replaces the prior results rather than appending to them
        targets.write().clear();
        notes.write().clear();
        validating.set(true);
        // Yield one frame so the busy state paints before the synchronous parse/validation blocks
        // the (single) thread; on a large store the first parse otherwise reads as a hang.
        #[cfg(target_family = "wasm")]
        gloo_timers::future::TimeoutFuture::new(16).await;

        let cps = run_settings(&settings(), tier(), have_revocation_uploads());

        // Rebuild the prepared environment only when it is stale (or absent); otherwise reuse the
        // cached one, skipping the store fetch, reparse and partial-path discovery.
        if env_dirty() || prepared_env.read().is_none() {
            if let Err(e) = rebuild_env(cps.clone()).await {
                notes.write().push(ResultLine {
                    class: "err",
                    text: e,
                });
                validating.set(false);
                view.set(RESULTS_VIEW);
                return;
            }
        }

        // The retrieval budget is per click rather than per step, so a chase that spent it does not
        // leave a revocation retrieval to discover the same limit again.
        let mut budget = FetchBudget::new();

        // Uploaded revocation data goes in before the tier is consulted, so it reaches BOTH tiers.
        // A no-network run has no other way to obtain any, and a retrieving run must not go
        // and fetch what it was already given -- the harvest below skips a certificate whose
        // status is already settled. Deliberately outside `tier().retrieves()`: that branch is
        // false in exactly the no-network case this exists for. Not gated on
        // check_revocation_status either: supplying a file is an explicit act, and a run that
        // ignores it should say so through the settings rather than by discarding it silently.
        if !uploaded_crls().is_empty() || !uploaded_ocsp().is_empty() {
            let guard = prepared_env.read();
            if let Some((prepared, _)) = guard.as_ref() {
                for (name, bytes) in uploaded_crls() {
                    match add_uploaded_crl(prepared, &bytes) {
                        true => notes.write().push(ResultLine {
                            class: "info",
                            text: format!("Added CRL from {name}"),
                        }),
                        false => notes.write().push(ResultLine {
                            class: "err",
                            text: format!("{name} is not a CRL"),
                        }),
                    }
                }
                for (name, bytes) in uploaded_ocsp() {
                    let outcome = staple_uploaded_ocsp(prepared, &cps, &loaded_ees(), &bytes);
                    if outcome.matched > 0 {
                        notes.write().push(ResultLine {
                            class: "info",
                            text: format!(
                                "Stapled OCSP response from {name} to {} certificate(s)",
                                outcome.matched
                            ),
                        });
                    }
                    for note in outcome.notes {
                        notes.write().push(ResultLine {
                            class: "err",
                            text: format!("{name}: {note}"),
                        });
                    }
                }
            }
        }

        // --- retrieve, when the tier permits it ---
        //
        // Ordered deliberately: certificates first, because a path that cannot be built has no
        // certificates whose revocation status could be asked about, and the CRL distribution
        // points worth retrieving are the ones named on the path that building found.
        if tier().retrieves() {
            // Chasing is worth doing only when path building came up short. Determining that means
            // validating first, and those results are discarded if a retrieval changes the answer
            // -- which is the same shape the service's own run uses.
            let built_a_path = {
                let guard = prepared_env.read();
                let (prepared, _) = guard.as_ref().unwrap();
                let (reports, _) = validate_prepared(prepared, &cps, &loaded_ees(), validate_all());
                reports.iter().any(|r| !r.paths.is_empty())
            };

            if !built_a_path {
                let mut seeds = loaded_ees();
                seeds.extend(uploaded_cas());
                seeds.extend(chased_cas());
                let (found, chase_notes) = chase_certificates(&seeds, &mut budget).await;
                notes.write().extend(chase_notes);
                if !found.is_empty() {
                    chased_cas.write().extend(found);
                    if let Err(e) = rebuild_env(cps.clone()).await {
                        notes.write().push(ResultLine {
                            class: "err",
                            text: e,
                        });
                        validating.set(false);
                        view.set(RESULTS_VIEW);
                        return;
                    }
                }
            }

            if cps.get_check_revocation_status() {
                // Harvested from the paths the environment builds now, so the distribution points
                // retrieved are the ones on the paths that will be validated. The source is cloned
                // out rather than borrowed because it is shared by clone and the retrieval that
                // follows is asynchronous -- a read guard cannot be held across it.
                let (work, crl_sink, ocsp_sink) = {
                    let guard = prepared_env.read();
                    let (prepared, _) = guard.as_ref().unwrap();
                    (
                        harvest_revocation_work(prepared, &cps, &loaded_ees()),
                        prepared.crl_source().clone(),
                        prepared.ocsp_responses().clone(),
                    )
                };
                // Said out loud, because silence here is indistinguishable from a retrieval that
                // found nothing to do -- and an empty work list is exactly how a PEM target failed
                // on 2026-08-20, reporting every position undetermined with no explanation.
                if work.is_empty() {
                    notes.write().push(ResultLine {
                        class: "info",
                        text: "No revocation data to retrieve for the paths built".to_string(),
                    });
                }
                // OCSP first, and a CRL only for what OCSP leaves undetermined. The reverse was
                // tried first, reasoning that one CRL covers every certificate its issuer published
                // it for while a responder answers about one. Measurement said otherwise on two
                // independent PKIs -- DoD's DODEMAILCA_63.crl is 9.5 MB and Amazon's r2m04.crl is
                // 2.24 MB, against OCSP responses of a few hundred bytes -- and certval consults
                // stapled OCSP before any registered CRL source, so with both in hand the OCSP
                // always decided and the CRL was fetched and ignored. That is most of a click's
                // budget spent on data that changes no outcome, and it is what the person waiting
                // for a first answer is waiting on.
                let mut retrieved_ocsp = 0;
                if !work.ocsp.is_empty() {
                    let (added, ocsp_notes) =
                        retrieve_ocsp(&work.ocsp, &ocsp_sink, &mut budget).await;
                    retrieved_ocsp = added;
                    notes.write().extend(ocsp_notes);
                }

                // Which positions OCSP settled. Knowing that takes a validation pass: the checker
                // writes its determinations into the registered cache, and harvest_revocation_work
                // skips a certificate whose status that cache already answers. The reports are
                // discarded -- the run validates again below, once the CRLs are in.
                //
                // With the revocation cache turned off nothing is recorded, the second harvest
                // returns what the first did, and this degrades to retrieving both. That is the old
                // behaviour rather than a failure, which is why it is not gated on the setting.
                // Whether anything is still unresolved, read from the validation's own reports
                // rather than from the revocation cache. Asking the cache would tie this to the
                // "reuse determinations" setting -- turn that off and every CRL gets fetched again,
                // which is a bandwidth decision quietly riding on a per-path-evidence one. The
                // reports say what was actually determined, whatever the cache is doing.
                let crl_dp = match retrieved_ocsp > 0 {
                    true => {
                        let guard = prepared_env.read();
                        let (prepared, _) = guard.as_ref().unwrap();
                        let (reports, _) =
                            validate_prepared(prepared, &cps, &loaded_ees(), validate_all());
                        // Conservative on purpose: a path with no outcomes recorded counts as
                        // unresolved, so this only skips on positive evidence that every position is
                        // settled. It can never turn a determinable path into an undetermined one.
                        let unresolved = reports.iter().any(|t| {
                            t.paths.iter().any(|p| {
                                p.revocation.is_empty()
                                    || p.revocation
                                        .iter()
                                        .any(|o| o.status == RevocationStatus::Undetermined)
                            })
                        });
                        match unresolved {
                            true => work.crl_dp.clone(),
                            false => {
                                notes.write().push(ResultLine {
                                    class: "info",
                                    text: format!(
                                        "skipped {} CRL retrieval(s): OCSP settled every certificate",
                                        work.crl_dp.len()
                                    ),
                                });
                                vec![]
                            }
                        }
                    }
                    false => work.crl_dp.clone(),
                };

                if !crl_dp.is_empty() {
                    let (_added, crl_notes) = retrieve_crls(&crl_dp, &crl_sink, &mut budget).await;
                    notes.write().extend(crl_notes);
                }
            }
        }

        // --- validate against the environment as it now stands ---
        let guard = prepared_env.read();
        let (prepared, prep_notes) = guard.as_ref().unwrap();
        notes.write().extend(prep_notes.iter().cloned());
        let (reports, lines, retained) =
            validate_prepared_retaining(prepared, &cps, &loaded_ees(), validate_all(), true);
        retained_paths.set(retained);
        drop(guard);
        notes.write().extend(lines);
        targets.write().extend(reports);
        validating.set(false);
        view.set(RESULTS_VIEW);
    };

    // Where the selected store's material came from, said in the selector rather than left to the
    // label: a store held by a service can be material that service was configured with, and a
    // person judging a validation result has no other way to know that.
    let store_hint = catalog()
        .get(mode())
        .map(|s| s.origin.hint())
        .unwrap_or_default();

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
                        // The tier governs the whole run, so it is stated before the trust material
                        // rather than tucked in beside it. Disabled rather than hidden when no
                        // service is present: that this frontend *can* retrieve, given one, is
                        // worth knowing even where it cannot.
                        div { class: "controls",
                            label { r#for: "tier", "Retrieval: " }
                            select {
                                id: "tier",
                                disabled: !service_present(),
                                onchange: move |ev| {
                                    tier.set(match ev.value().as_str() {
                                        "relayed" => Tier::Relayed,
                                        _ => Tier::Local,
                                    })
                                },
                                option {
                                    value: "local",
                                    selected: !tier().retrieves(),
                                    "{Tier::Local.label()}"
                                }
                                option {
                                    value: "relayed",
                                    selected: tier().retrieves(),
                                    "{Tier::Relayed.label()}"
                                }
                            }
                            span { class: "hint", "{tier().hint()}" }
                            if !service_present() {
                                span { class: "hint",
                                    "No PITTv3 service is serving this page, so there is nothing to \
                                     retrieve through. Everything runs in the browser."
                                }
                            }
                        }

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
                                for (i, s) in catalog().into_iter().enumerate() {
                                    option { value: "{i}", selected: mode() == i, "{s.label}" }
                                }
                                option { value: "none", selected: mode() == NO_STORE, "None (uploaded trust anchors and CA certificates only)" }
                            }
                            if !store_hint.is_empty() {
                                span { class: "hint", "This store is {store_hint}." }
                            }
                            // What asking a service for its stores produced. Shown here rather than
                            // on a tab of its own: it explains the contents of the selector directly
                            // above it, which is the only place it is actionable.
                            if !store_service_status().is_empty() {
                                span { class: "hint", "{store_service_status}" }
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

                        details { class: "panel", id: "revocation-panel",
                            summary { "Revocation data (CRLs and OCSP responses)" }
                            div { class: "controls custom",
                                label { "CRL(s): " }
                                // Unfiltered for the same reason as the OCSP input below: .crl is
                                // the common extension but nothing requires it, and add_uploaded_crl
                                // already answers "is not a CRL" from the bytes. Widening what can
                                // be selected cannot break a file that was selectable before.
                                input {
                                    r#type: "file",
                                    multiple: true,
                                    onchange: move |ev| async move {
                                        let files = read_files(&ev).await;
                                        extend_unique(uploaded_crls, files);
                                    },
                                }
                                label { "OCSP response(s): " }
                                // Deliberately unfiltered. An OCSP response has no settled file
                                // extension -- tools write .ors, .der, .resp, or none at all -- and
                                // an `accept` list greys out anything it failed to anticipate, so a
                                // wrong guess here blocks the file rather than merely failing to
                                // suggest it. The bytes are what decide: staple_uploaded_ocsp says
                                // "Not an OCSP response" for anything that is not one, which is a
                                // better gate than the name and cannot lock the user out.
                                input {
                                    r#type: "file",
                                    multiple: true,
                                    onchange: move |ev| async move {
                                        let files = read_files(&ev).await;
                                        extend_unique(uploaded_ocsp, files);
                                    },
                                }
                                span { class: "hint",
                                    "{uploaded_crls().len()} CRL(s), {uploaded_ocsp().len()} OCSP response(s) loaded "
                                    button {
                                        onclick: move |_| {
                                            uploaded_crls.write().clear();
                                            uploaded_ocsp.write().clear();
                                        },
                                        "Clear"
                                    }
                                }
                                span { class: "hint",
                                    "Supplied at Validate, so a run with no network can still determine \
                                     revocation status. An OCSP response is matched to the certificates \
                                     it answers about by its CertID, so it does not matter which one you \
                                     loaded it for. Any file may be chosen — what it contains decides, \
                                     not what it is called. CRLs may be DER or PEM."
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
                            label { r#for: "use-rev-cache", "Reuse revocation determinations: " }
                            input {
                                id: "use-rev-cache",
                                r#type: "checkbox",
                                checked: use_rev_cache(),
                                onchange: move |ev| use_rev_cache.set(ev.checked()),
                            }
                            // Clearing is its own action rather than a side effect of toggling the
                            // checkbox above. Turning the reuse setting off does clear the cache, but
                            // using that to clear it also changes how the run behaves -- which is a
                            // real trap: it silently gives up the CRL retrievals OCSP would otherwise
                            // have spared.
                            button {
                                onclick: move |_| {
                                    rev_cache().clear();
                                    rev_cache_status
                                        .set("Revocation determinations cleared.".to_string());
                                },
                                "Clear cached determinations"
                            }
                            span { class: "hint",
                                "On, a certificate checked on one path is not checked again on another. "
                                "Off, every path obtains its own revocation data — slower, but each path "
                                "then carries the evidence for its own result, which an export needs. "
                                "Clear discards what has been determined so far without changing either."
                            }
                            if !rev_cache_status().is_empty() {
                                span { class: "hint", "{rev_cache_status}" }
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
                                // The tier decides what this frontend can act on, so the form's
                                // per-capability notices follow the selector rather than being
                                // fixed at "a browser cannot reach the network".
                                caps: match tier().retrieves() {
                                    true => Capabilities::browser_relayed(),
                                    false => Capabilities::browser_local(),
                                },
                                // The same rule run_settings applies, reported rather than
                                // re-derived, so the form cannot show a tick beside a check the run
                                // will not make. Recomputed on every render, so selecting a tier or
                                // loading revocation data updates the row without a save.
                                revocation_default: Some(
                                    tier().retrieves() || have_revocation_uploads(),
                                ),
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
                                        title: "Download the structured report as JSON",
                                        "Save report"
                                    }
                                    button {
                                        disabled: retained_paths.read().is_empty(),
                                        onclick: save_path_logs,
                                        title: "Download every path's manifest as one text file",
                                        "Save path logs"
                                    }
                                    button {
                                        disabled: retained_paths.read().is_empty(),
                                        onclick: save_artifacts,
                                        title: "Download the certificates and revocation data behind every path, as a zip",
                                        "Save artifacts"
                                    }
                                    input {
                                        r#type: "text",
                                        class: "export-name",
                                        value: "{export_name}",
                                        title: "Name for the export: the archive and the folder inside it",
                                        oninput: move |e| export_name.set(e.value()),
                                    }
                                    button {
                                        onclick: move |_| {
                                            targets.write().clear();
                                            notes.write().clear();
                                            retained_paths.write().clear();
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
                                "A trust store is a pair of CBOR files. The trust-anchor half "
                                "(*_ta.cbor) holds roots. The CA half (*_ca.cbor) holds intermediate "
                                "CA certificates together with precomputed partial certification "
                                "paths \u{2014} the paths from each anchor down through the "
                                "intermediates, worked out in advance."
                            }
                            p {
                                "That precomputation is why the halves are worth carrying around. "
                                "Discovering partial paths is the expensive step of preparing an "
                                "environment; building a path against one already discovered is "
                                "cheap. A store is therefore not merely a bag of certificates, it is "
                                "a bag of certificates with the search already done."
                            }
                            h3 { "Where they come from" }
                            p {
                                "Three sources, all the same format, all interchangeable:"
                            }
                            ul {
                                li {
                                    strong { "Built into this app. " }
                                    "Selectable from the dropdown on the Validate tab without any "
                                    "network access."
                                }
                                li {
                                    strong { "Served by a PITTv3 service. " }
                                    "Where this app is served by one, the stores it holds appear in "
                                    "the same dropdown and are downloaded from it. The dropdown says "
                                    "which is which, and whether a store came from a trust store "
                                    "provider or was configured by whoever runs the service \u{2014} "
                                    "worth knowing, because a configured store may hold chased "
                                    "material rather than published trust material."
                                }
                                li {
                                    strong { "Exported from a run. " }
                                    "Export PKI Environment on the Results view writes the trust "
                                    "material a validation actually used, in this same format. That "
                                    "is the way to capture a store you assembled by uploading, or by "
                                    "letting a run chase for certificates it did not have."
                                }
                            }
                            h3 { "Using them" }
                            p {
                                "Upload either half through the trust-anchor and intermediate-CA "
                                "controls on the Validate tab. A .cbor upload merges all of its "
                                "certificates into that side, so stores mix freely: Web PKI roots "
                                "with another collection's intermediates, or your own trust anchors "
                                "with a built-in CA store. Select \"None\" as the store to rely on "
                                "uploads alone."
                            }
                            p {
                                "Offline store-generation tooling produces the same format, so a "
                                "store you build yourself uploads exactly like a built-in one, and a "
                                "store exported from a run can be handed to the CLI or the desktop "
                                "app unchanged."
                            }
                            h3 { "Freshness" }
                            p {
                                "The built-in stores are generated when this app is built, from the "
                                "trust store provider crates, rather than being refreshed by hand. "
                                "Their currency is therefore that of those crates at the time this "
                                "build was made \u{2014} which is why no date is given here: the "
                                "providers do not record when their material was collected, so any "
                                "date this page stated would be a claim it could not check."
                            }
                            p {
                                "A service's stores are baked in the same way and are no fresher for "
                                "being served: the ones it marks \u{201c}provider\u{201d} were "
                                "generated when that service was built. The exception is a store the "
                                "dropdown marks \u{201c}configured\u{201d}, which is read from a "
                                "directory the service was pointed at \u{2014} that one can be "
                                "replaced and the service restarted, with nothing rebuilt. Where "
                                "currency matters, that is the one to prefer."
                            }
                            p { class: "hint",
                                "The ML-DSA-44 PKITS edition is static test data and does not go "
                                "stale. Real-world trust material does, and a root program moves "
                                "without announcing itself here."
                            }
                        }
                    },
                    4 => rsx! {
                        div { class: "help-view",
                            h2 { "Check URIs in certificate" }
                            p {
                                "Fetches every HTTP URI a certificate names — authority information "
                                "access, subject information access, CRL distribution points and "
                                "freshest CRL — and reports each one on its own. This is a check of "
                                "the repositories, not of the certificate: it builds no path and "
                                "reaches no verdict about trust."
                            }
                            p { class: "hint",
                                "An issuer, supplied or auto-discovered from AIA, is what makes CRL "
                                "signature verification and OCSP possible; without one those rows "
                                "report that they could not be checked rather than failing."
                            }
                        }
                        if !tier().retrieves() {
                            div { class: "controls",
                                span { class: "hint",
                                    "This check retrieves from the repositories a certificate names, "
                                    "so it needs the service. Choose \"Retrieve through the service\" "
                                    "on the Validate tab."
                                }
                            }
                        }
                        div { class: "controls custom",
                            label { "Certificate: " }
                            input {
                                r#type: "file",
                                onchange: move |ev| async move {
                                    if let Some((name, bytes)) = read_files(&ev).await.into_iter().next() {
                                        uri_target.set(Some((name, bytes)));
                                        uri_report.set(None);
                                    }
                                },
                            }
                            label { "Issuer (optional): " }
                            input {
                                r#type: "file",
                                onchange: move |ev| async move {
                                    if let Some((name, bytes)) = read_files(&ev).await.into_iter().next() {
                                        uri_issuer.set(Some((name, bytes)));
                                    }
                                },
                            }
                            label { r#for: "uri-auto", "Auto-discover the issuer: " }
                            input {
                                id: "uri-auto",
                                r#type: "checkbox",
                                checked: uri_auto(),
                                onchange: move |ev| uri_auto.set(ev.checked()),
                            }
                            span { class: "hint",
                                match uri_target() {
                                    Some((name, _)) => format!("{name} loaded"),
                                    None => "no certificate chosen".to_string(),
                                }
                            }
                        }
                        div { class: "controls center-row",
                            button {
                                disabled: uri_running() || uri_target().is_none() || !tier().retrieves(),
                                onclick: move |_| async move {
                                    let Some((_, target)) = uri_target() else {
                                        return;
                                    };
                                    uri_running.set(true);
                                    uri_report.set(None);
                                    // Its own environment and settings: this check answers about a
                                    // certificate rather than about a path, so the trust material
                                    // selected on the Validate tab has no bearing on it.
                                    let mut cps = CertificationPathSettings::default();
                                    if let Ok(toi) = TimeOfInterest::from_unix_secs(now_as_unix_epoch()) {
                                        cps.set_time_of_interest(toi);
                                    }
                                    let mut pe = PkiEnvironment::default();
                                    pe.populate_5280_pki_environment();
                                    let issuer = uri_issuer();
                                    let report = check_uris_in_cert(
                                        &pe,
                                        &cps,
                                        &RelayFetcher::new(),
                                        &target,
                                        issuer.as_ref().map(|(_, b)| b.as_slice()),
                                        uri_auto(),
                                        &[],
                                    )
                                    .await;
                                    uri_report.set(Some(report));
                                    uri_running.set(false);
                                },
                                if uri_running() { "Checking\u{2026}" } else { "Check URIs" }
                            }
                            button {
                                onclick: move |_| {
                                    uri_report.set(None);
                                    uri_target.set(None);
                                    uri_issuer.set(None);
                                },
                                "Clear"
                            }
                        }
                        if let Some(report) = uri_report() {
                            UriCheckResults { report }
                        }
                    },
                    5 => rsx! {
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
                                    "or a .cbor store file (the same format as the built-in stores). Export PKI "
                                    "Environment on the Results view writes that same format, so a run's trust "
                                    "material can be saved and uploaded again. A .cbor upload merges all of its "
                                    "certificates into that side."
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
                                    "Path validation always runs in the browser; what changes with the "
                                    "Retrieval setting is whether anything is fetched to feed it. "
                                    "\"In this browser only\" fetches nothing: paths are built from the "
                                    "selected store and uploads, and revocation status is undetermined "
                                    "unless revocation data was supplied. \"Retrieve through the service\" "
                                    "has the PITTv3 service fetch on this page's behalf — issuer "
                                    "certificates from AIA and SIA URIs when no path can be built, and, for "
                                    "the certificates on the paths it builds, their CRLs and an OCSP response "
                                    "per certificate whose issuer runs a responder. The certificates being "
                                    "validated stay in this page; the URIs they name do not, and an OCSP "
                                    "request identifies the certificate being asked about even though the "
                                    "certificate itself is not sent."
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
                                    "Where this app is served by the PITTv3 service, the trust stores that "
                                    "service holds are offered in the same dropdown. A store it holds under a "
                                    "name this app already ships is the same material and is not listed twice. "
                                    "The line under the dropdown says where the selected store came from, which "
                                    "matters for a store a deployment supplied itself: its certificates may have "
                                    "been gathered by following AIA URIs rather than published by the PKI they "
                                    "claim to come from."
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
    use crate::relay::Tier;
    use pittv3_gui_lib::gui_settings::Capabilities;
    use pittv3_gui_lib::gui_settings_model::SettingsModel;

    /// certval's default for an absent `PS_CHECK_REVOCATION_STATUS` is true, so a browser that
    /// cannot retrieve would otherwise carry a preference for a check it has no way to satisfy.
    /// The shared validation path does read the setting, which is what makes this load-bearing
    /// rather than anticipatory: without it every local run would come back
    /// `RevocationStatusNotDetermined` for want of data the page cannot obtain.
    #[test]
    fn revocation_checking_is_off_unless_asked_for_in_the_local_tier() {
        let cps = run_settings(&SettingsModel::default(), Tier::Local, false);
        assert!(!cps.get_check_revocation_status());
    }

    /// Uploading a CRL or an OCSP response is the other way a run obtains revocation data, so it
    /// moves the same unstated default the relay tier moves. Without this the upload buttons are
    /// inert in exactly the tier they exist for: checking stays off and the stapled data is never
    /// consulted, which reads as `RevocationStatusNotDetermined` and looks like the staple failed.
    #[test]
    fn supplied_revocation_data_turns_checking_on_in_the_local_tier() {
        let cps = run_settings(&SettingsModel::default(), Tier::Local, true);
        assert!(cps.get_check_revocation_status());
    }

    /// With a relay the data can be retrieved, and checking is the reason to have chosen that tier,
    /// so the unstated preference reverses. This is the one setting whose default the tier moves.
    #[test]
    fn revocation_checking_is_on_unless_refused_in_the_relayed_tier() {
        let cps = run_settings(&SettingsModel::default(), Tier::Relayed, false);
        assert!(cps.get_check_revocation_status());
    }

    /// An explicit preference is honored in either tier -- the settings form states that these
    /// settings apply only where the tool can fetch, so a user who sets one gets what they asked
    /// for rather than a silently discarded setting.
    #[test]
    fn explicit_revocation_preference_is_honored() {
        let asked_for = SettingsModel {
            check_revocation_status: Some(true),
            ..SettingsModel::default()
        };
        assert!(run_settings(&asked_for, Tier::Local, false).get_check_revocation_status());

        let refused = SettingsModel {
            check_revocation_status: Some(false),
            ..SettingsModel::default()
        };
        assert!(!run_settings(&refused, Tier::Relayed, false).get_check_revocation_status());

        // An upload does not override a refusal: the user said no.
        assert!(!run_settings(&refused, Tier::Local, true).get_check_revocation_status());
    }

    /// The tier is what the settings form's per-capability notices key off, so the two have to move
    /// together: a relayed run must not be told it cannot reach the network.
    #[test]
    fn the_tier_decides_the_declared_capabilities() {
        assert!(!Capabilities::browser_local().network);
        assert!(Capabilities::browser_relayed().network);
        // Neither browser tier gains a filesystem, which is the honest difference from the desktop.
        assert!(!Capabilities::browser_relayed().filesystem);
        assert!(Capabilities::desktop().filesystem);
    }
}
