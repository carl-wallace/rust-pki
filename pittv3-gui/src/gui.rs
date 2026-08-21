//! Provides GUI interface to similar set of actions as offered by command line utility

use dioxus::desktop::use_window;
use dioxus::prelude::*;

use futures_util::StreamExt;
use home::home_dir;
use log::{debug, error, LevelFilter};
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use rfd::AsyncFileDialog;

use pittv3_gui_lib::gui_help::HelpView;
use pittv3_gui_lib::gui_results::{ResultsView, RunEvent};
use pittv3_gui_lib::gui_rows::{BrowseRow, CheckboxCell, TextRow, TimeRow};
use pittv3_gui_lib::gui_settings::EditSettingsFile;
use pittv3_gui_lib::gui_shell::AppShell;
use pittv3_gui_lib::gui_uri_check::UriCheckResults;
use pittv3_gui_lib::gui_utils::{
    clear_log_sink, read_saved_args, save_args, set_log_sink, ChannelAppender,
};
use pittv3_gui_lib::settings_store::{default_settings_path, expand_tilde};
use pittv3_gui_lib::PITTV3_CSS;
use pittv3_lib::args::{get_now_as_unix_epoch, Pittv3Args};
use pittv3_lib::graph_cache;
use pittv3_lib::options_std::options_std;
use pittv3_lib::report::ValidationReport;
use pittv3_lib::uri_check::{check_uris_from_bytes, UriCheckReport};

use crate::stores;

/// Presents a folder selection dialog and assigns the selection, if any, to `sig`
async fn pick_folder_into(mut sig: Signal<String>) {
    let folder = AsyncFileDialog::new()
        .set_directory(home_dir().unwrap_or("/".into()))
        .pick_folder()
        .await;
    if let Some(folder) = folder {
        sig.set(folder.path().to_string_lossy().to_string());
    }
}

/// Asks for a folder and writes the selected built-in store's material into it, reporting the
/// outcome through `status` either way — a dialog that closes with nothing said is the shape of
/// failure this app has already been bitten by once (see the tilde expansion in `settings_store`).
async fn export_store_into(index: usize, mut status: Signal<String>) {
    let folder = AsyncFileDialog::new()
        .set_directory(home_dir().unwrap_or("/".into()))
        .pick_folder()
        .await;
    let Some(folder) = folder else {
        return;
    };
    match stores::export(index, folder.path()) {
        Ok(e) => {
            let cas = if e.ca_store {
                format!(
                    ", the CA store and {} intermediate CA certificate(s)",
                    e.intermediates
                )
            } else {
                String::new()
            };
            status.set(format!(
                "Wrote {} trust anchor(s){cas} to {}",
                e.anchors, e.folder
            ));
        }
        Err(msg) => {
            error!("{msg}");
            status.set(format!("Export failed: {msg}"));
        }
    }
}

/// Writes the environment a run over the current inputs validates against, as the two files that
/// describe it: `ta.cbor`, every anchor the run assembled, and `ca.cbor`, the certificates it
/// searched together with the partial paths it found among them.
///
/// Two files because the anchors sit outside the graph: partial paths terminate at them, but they
/// live in a `TaSource` that never enters the `CertSource`, so a graph on its own describes paths
/// to certificates it does not carry. Both come from the run's cache under one key, so they are
/// necessarily each other's halves — and both are what the validation actually used rather than a
/// reconstruction, which is the point of exporting them at all. That does mean there has to have
/// been a run: nothing is cached for inputs nothing has been validated against yet.
async fn export_environment_into(args: Pittv3Args, mut status: Signal<String>) {
    let Some(fingerprint) = graph_cache::fingerprint_for_args(&args) else {
        status.set(
            "These inputs build no graph to export: a store used on its own already carries its \
             partial paths, and dynamic build changes the graph as it runs."
                .to_string(),
        );
        return;
    };
    let Some(graph) = graph_cache::cached(&fingerprint) else {
        status.set(
            "Nothing has been built for these inputs yet — run a validation first, then export."
                .to_string(),
        );
        return;
    };
    let anchors = graph_cache::cached_anchors(&fingerprint);

    let folder = AsyncFileDialog::new()
        .set_directory(home_dir().unwrap_or("/".into()))
        .pick_folder()
        .await;
    let Some(folder) = folder else {
        return;
    };

    let ca_path = folder.path().join("ca.cbor");
    if let Err(e) = std::fs::write(&ca_path, &graph) {
        error!("Failed to write {}: {e}", ca_path.display());
        status.set(format!("Export failed: {e}"));
        return;
    }
    // Anchors are cached whenever a run loaded any, so their absence means the run had none of its
    // own — webpki anchors, which certval builds rather than reads, are the case that reaches here.
    let Some(anchors) = anchors else {
        status.set(format!(
            "Wrote the graph to {}. No trust anchor file: this run's anchors are built by certval \
             rather than read from material that can be written out.",
            ca_path.display()
        ));
        return;
    };
    let ta_path = folder.path().join("ta.cbor");
    match std::fs::write(&ta_path, &anchors) {
        Ok(()) => status.set(format!(
            "Wrote ta.cbor and ca.cbor to {}",
            folder.path().to_string_lossy()
        )),
        Err(e) => {
            error!("Failed to write {}: {e}", ta_path.display());
            status.set(format!("Export failed: {e}"));
        }
    }
}

/// Presents a selection dialog that accepts either a file or a folder and assigns the selection,
/// if any, to `sig`. macOS only: `rfd` implements the combined dialog for that platform alone, so
/// other platforms offer the two dialogs as separate buttons instead (see [`PathRow`]).
#[cfg(target_os = "macos")]
async fn pick_file_or_folder_into(mut sig: Signal<String>) {
    let picked = AsyncFileDialog::new()
        .set_directory(home_dir().unwrap_or("/".into()))
        .pick_file_or_folder()
        .await;
    if let Some(picked) = picked {
        sig.set(picked.path().to_string_lossy().to_string());
    }
}

/// Presents a file selection dialog limited to files of the indicated type and assigns the
/// selection, if any, to `sig`
async fn pick_file_into(
    mut sig: Signal<String>,
    filter_name: &'static str,
    extensions: &'static [&'static str],
) {
    let file = AsyncFileDialog::new()
        .add_filter(filter_name, extensions)
        // A second, permissive filter the user can switch to. A named filter is a suggestion, but on
        // some platforms it is enforced -- and a file it fails to anticipate is then unselectable
        // rather than merely unsuggested. The same reasoning removed the `accept` list from the
        // browser's revocation inputs on 2026-08-20: what a file contains decides whether it is
        // usable, and every one of these readers already says so when handed something it cannot use.
        .add_filter("All Files", &["*"])
        .set_directory(home_dir().unwrap_or("/".into()))
        .pick_file()
        .await;
    if let Some(file) = file {
        sig.set(file.path().to_string_lossy().to_string());
    }
}

/// Serializes the validation report to pretty JSON and writes it to a user-chosen file.
async fn save_report(report: ValidationReport) {
    let file = AsyncFileDialog::new()
        .add_filter("JSON", &["json"])
        .set_file_name("pittv3-results.json")
        .save_file()
        .await;
    if let Some(file) = file {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                if let Err(e) = std::fs::write(file.path(), json) {
                    error!("Failed to write results file: {e}");
                }
            }
            Err(e) => error!("Failed to serialize results: {e}"),
        }
    }
}

/// Returns the value of `sig` if it is not empty and None otherwise
fn string_or_none(sig: Signal<String>) -> Option<String> {
    let s = sig();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Returns the value of `sig` as a path if it is not empty and None otherwise, resolving a leading
/// `~` against the home directory. Every path here can be typed as readily as it can be chosen
/// from a file dialog, and there is no shell behind a text box to expand the tilde first.
fn path_or_none(sig: Signal<String>) -> Option<String> {
    string_or_none(sig).map(|s| expand_tilde(&s))
}

/// Returns the value of `sig` as a usize, or None if the value is empty or cannot be parsed
fn usize_or_none(sig: Signal<String>) -> Option<usize> {
    match string_or_none(sig) {
        Some(v) => v.parse::<usize>().ok(),
        None => None,
    }
}

/// Table row with a labeled text input and a folder selection dialog. Thin wrapper over the shared
/// [`BrowseRow`] supplying the native picker, which is the only part of the row that is not
/// portable.
#[component]
fn FolderRow(
    label: String,
    name: String,
    sig: Signal<String>,
    #[props(default)] title: String,
) -> Element {
    rsx! {
        BrowseRow {
            label,
            name,
            sig,
            title,
            on_browse: move |_| {
                spawn(pick_folder_into(sig));
            },
        }
    }
}

/// Table row for an input that accepts either a folder of certificates or a single certificate
/// file, which is what the trust anchor and CA inputs take.
///
/// macOS can offer both in one dialog, so there the `...` button does; every other platform has to
/// choose a dialog kind up front, so the row carries a second button. The distinction is only about
/// how the path is chosen — a typed or pasted path of either kind works everywhere, because the run
/// decides from the path itself rather than from which button produced it.
#[component]
fn PathRow(
    label: String,
    name: String,
    sig: Signal<String>,
    #[props(default)] title: String,
) -> Element {
    #[cfg(target_os = "macos")]
    return rsx! {
        BrowseRow {
            label,
            name,
            sig,
            title,
            on_browse: move |_| {
                spawn(pick_file_or_folder_into(sig));
            },
        }
    };

    #[cfg(not(target_os = "macos"))]
    return rsx! {
        BrowseRow {
            label,
            name,
            sig,
            title,
            on_browse: move |_| {
                spawn(pick_folder_into(sig));
            },
            on_browse_alt: move |_| {
                spawn(pick_file_into(sig, "Certificate File", CERT_EXTENSIONS));
            },
            alt_label: "File...",
        }
    };
}

/// Extensions offered when picking a certificate file as a trust anchor or CA input. `ta` is an
/// RFC 5914 TrustAnchorInfo, which is how anchor constraints travel. Only the platforms that need a
/// separate file dialog filter by extension; the combined macOS dialog does not, since a folder has
/// no extension to match.
#[cfg(not(target_os = "macos"))]
const CERT_EXTENSIONS: &[&str] = &["der", "crt", "cer", "pem", "ta"];

/// Table row with a labeled text input and a file selection dialog limited to files of the
/// indicated type. Thin wrapper over the shared [`BrowseRow`], as with [`FolderRow`].
#[component]
fn FileRow(
    label: String,
    name: String,
    sig: Signal<String>,
    filter_name: &'static str,
    extensions: &'static [&'static str],
    #[props(default)] title: String,
) -> Element {
    rsx! {
        BrowseRow {
            label,
            name,
            sig,
            title,
            on_browse: move |_| {
                spawn(pick_file_into(sig, filter_name, extensions));
            },
        }
    }
}

/// PITTv1/PITTv2-style "Check URIs in certificate" modal dialog: pick a target certificate (and,
/// optionally, its issuer), optionally auto-discover the issuer from AIA, and see per-URI
/// reachability and correctness for the AIA, SIA, CRL DP and freshest-CRL extensions.
#[component]
fn UriCheckModal(open: Signal<bool>) -> Element {
    let mut open = open;
    let s_target = use_signal(String::new);
    let s_issuer = use_signal(String::new);
    let s_auto = use_signal(|| true);
    let mut s_running = use_signal(|| false);
    let mut s_report = use_signal(|| None::<UriCheckReport>);

    if !open() {
        return rsx! {};
    }

    let run_check = move |_| async move {
        let target = s_target();
        if target.is_empty() {
            return;
        }
        s_running.set(true);
        s_report.set(None);
        let issuer_path = s_issuer();
        let auto = s_auto();
        let report = match std::fs::read(&target) {
            Ok(target_der) => {
                let issuer_der = if issuer_path.is_empty() {
                    None
                } else {
                    match std::fs::read(&issuer_path) {
                        Ok(b) => Some(b),
                        Err(e) => {
                            s_report.set(Some(UriCheckReport::failed(format!(
                                "failed to read issuer certificate {issuer_path}: {e}"
                            ))));
                            s_running.set(false);
                            return;
                        }
                    }
                };
                check_uris_from_bytes(
                    &target_der,
                    issuer_der.as_deref(),
                    auto,
                    get_now_as_unix_epoch(),
                    &[],
                )
                .await
            }
            Err(e) => UriCheckReport::failed(format!("failed to read target certificate: {e}")),
        };
        s_report.set(Some(report));
        s_running.set(false);
    };

    rsx! {
        div { class: "modal-overlay",
            div { class: "modal",
                div { class: "modal-header",
                    h2 { "Check URIs in certificate" }
                    button {
                        r#type: "button",
                        class: "modal-close",
                        onclick: move |_| open.set(false),
                        "\u{00d7}"
                    }
                }
                p { class: "hint",
                    "Fetches the HTTP URIs in the certificate's AIA, SIA, CRL DP and freshest-CRL extensions and reports each one, independent of path processing. An issuer, supplied or auto-discovered, adds CRL signature verification and OCSP checks."
                }
                table {
                    tbody {
                        FileRow {
                            label: "Target certificate",
                            name: "uri-target",
                            sig: s_target,
                            filter_name: "Certificate File",
                            extensions: ["der", "cer", "crt", "pem"].as_slice(),
                        }
                        FileRow {
                            label: "Issuer certificate (optional)",
                            name: "uri-issuer",
                            sig: s_issuer,
                            filter_name: "Certificate File",
                            extensions: ["der", "cer", "crt", "pem"].as_slice(),
                        }
                        tr {
                            CheckboxCell {
                                label: "Attempt auto-discovery if issuer not specified",
                                name: "uri-auto",
                                sig: s_auto,
                            }
                            td { class: "grow" }
                        }
                    }
                }
                div { class: "modal-actions",
                    button {
                        r#type: "button",
                        disabled: s_running(),
                        onclick: run_check,
                        if s_running() { "Checking\u{2026}" } else { "Check URIs" }
                    }
                    button {
                        r#type: "button",
                        onclick: move |_| s_report.set(None),
                        "Clear Results"
                    }
                }
                if let Some(report) = s_report() {
                    UriCheckResults { report }
                }
            }
        }
    }
}

/// Hosts the [`EditSettingsFile`] form in a child window, closing the window when the form is done
#[component]
fn EditSettingsWindow(path: String) -> Element {
    let window = use_window();
    rsx! {
        style { {PITTV3_CSS} }
        EditSettingsFile { path, on_close: move |_| window.close() }
    }
}

/// Task views reachable from the sidebar
#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Validate,
    Generate,
    Cleanup,
    Diagnostics,
    Tools,
    Settings,
    Results,
    Help,
}

/// Sidebar views in display order.
///
/// The head of the list is the ordinary path through the app — validate something, read the
/// outcome, adjust what a run does — and everything after it is a tool for working on the material
/// rather than a step in that path. Results sat seventh, below every tool, which put the thing a
/// run navigates to on its own five entries away from the thing that produced it.
///
/// Nothing indexes this list positionally; the selected entry and the Results index are both found
/// by lookup, so the order is presentation only.
const VIEWS: &[(View, &str)] = &[
    (View::Validate, "Validate"),
    (View::Results, "Results"),
    (View::Settings, "Settings"),
    (View::Generate, "Generate"),
    (View::Cleanup, "Cleanup"),
    (View::Diagnostics, "Diagnostics"),
    (View::Tools, "Tools"),
    (View::Help, "Help"),
];

/// Table row offering the built-in trust stores, plus the custom entry that leaves the trust
/// anchor and CA inputs below in effect.
///
/// The stores are named by provider environment rather than by folder, which is what makes the
/// trust-bit-scoped Mozilla sets selectable at all: nothing in a root's DER says which purposes
/// CCADB records it for, so a folder of roots cannot express them.
#[component]
fn StoreRow(sig: Signal<usize>, status: Signal<String>) -> Element {
    let mut sig = sig;
    rsx! {
        tr {
            td { label { r#for: "store", "Trust Store: " } }
            td { class: "grow",
                select {
                    id: "store",
                    name: "store",
                    onchange: move |ev| {
                        if let Ok(i) = ev.value().parse::<usize>() {
                            sig.set(i);
                        }
                    },
                    // The selection is marked on the options rather than given as the select's
                    // value: switching views unmounts this row, and a select built afresh shows
                    // its first option whatever value the element carries. The signal keeps the
                    // real selection either way, so the mismatch is only visible — a run still
                    // uses the store last chosen.
                    option {
                        value: "{stores::CUSTOM}",
                        selected: sig() == stores::CUSTOM,
                        "{stores::CUSTOM_LABEL}"
                    }
                    for (i, s) in stores::STORES.iter().enumerate() {
                        option { value: "{i + 1}", selected: sig() == i + 1, "{s.label}" }
                    }
                }
            }
            // Offered for a built-in store alone: a custom selection is already files on disk, so
            // there would be nothing to write that the user does not have, and webpki's anchors
            // are built during a run rather than held here.
            td { class: "nowrap",
                if sig() != stores::CUSTOM && !stores::is_webpki(sig()) {
                    button {
                        r#type: "button",
                        title: "Write this store's trust anchors and CBOR stores into a folder",
                        onclick: move |_| {
                            spawn(export_store_into(sig(), status));
                        },
                        "Export..."
                    }
                }
            }
        }
    }
}

/// Outcome of the last store export, shown until another one replaces it. A row of its own rather
/// than part of [`StoreHint`], which describes the store itself and should not be rewritten by an
/// action taken against it.
#[component]
fn StoreStatusRow(status: Signal<String>) -> Element {
    if status().is_empty() {
        return rsx! {};
    }
    rsx! {
        tr {
            td { }
            td { class: "grow",
                div { class: "hint", "{status}" }
            }
            td { }
        }
    }
}

/// Heading for a run of rows within a fieldset, spanning the full width.
///
/// For what the rows have in common and the fields cannot each restate — that everything below is
/// *additional* to a store already supplying trust material, say. Stating that per field, or worse
/// per store, is the thing this exists to avoid.
#[component]
fn SubgroupRow(title: String) -> Element {
    rsx! {
        tr { class: "subgroup",
            td { class: "subgroup", colspan: "3", "{title}" }
        }
    }
}

/// Says what the selected built-in store is, and whether it carries intermediates as well as
/// anchors. Renders nothing for a custom selection.
///
/// It does **not** say what the fields beneath it do: that is the same sentence for every store, so
/// it belongs to the group heading rather than to each blurb. The intermediates sentence names the
/// CA CBOR field only when the store carries none, which is the same condition that puts that row
/// on the screen — a hint should not send the reader looking for a field the view is not showing.
#[component]
fn StoreHint(selection: usize) -> Element {
    if selection == stores::CUSTOM {
        return rsx! {};
    }
    let Some(store) = stores::STORES.get(selection - 1) else {
        return rsx! {};
    };
    let has_ca = stores::has_ca_store(selection);
    rsx! {
        tr {
            td { }
            td { class: "grow",
                // A block rather than a span: `.hint` carries a left padding, and on an inline box
                // that indents the first line alone, leaving the wrapped lines hanging to its left.
                div { class: "hint",
                    if has_ca {
                        "Trust anchors and intermediate CAs from {store.pki}. "
                    } else {
                        "Trust anchors from {store.pki}. Supply intermediates below or turn on dynamic build. "
                    }
                    "{store.note}"
                }
            }
            td { }
        }
    }
}

/// Run button shown at the foot of each action view
#[component]
fn RunButton(running: bool, onrun: EventHandler<()>) -> Element {
    rsx! {
        div { style: "text-align:center",
            button {
                r#type: "button",
                class: "run-button",
                disabled: running,
                onclick: move |_| onrun.call(()),
                if running {
                    "Running…"
                } else {
                    "Run Command(s)"
                }
            }
        }
    }
}

/// Top-level application: sidebar task navigation over views that mirror the options offered by
/// the pittv3 command line utility
#[component]
pub(crate) fn App() -> Element {
    let sa = use_hook(|| read_saved_args().unwrap_or_default());

    // A run against a built-in store saves the cache paths it wrote into the CBOR arguments. What
    // is restored from that is the selection; showing the cache paths back as if the user had
    // typed them would invite editing a file the next run overwrites.
    let saved_store = use_hook(|| stores::selection_for(&sa.ta_cbor, sa.webpki_tas));
    let from_store = saved_store != stores::CUSTOM;
    let saved_or_empty = |v: &Option<String>| {
        if from_store {
            String::new()
        } else {
            v.clone().unwrap_or_default()
        }
    };

    let s_ta_folder = use_signal(|| sa.ta_folder.clone().unwrap_or_default());
    let s_cbor = use_signal(|| saved_or_empty(&sa.cbor));
    let s_store = use_signal(|| saved_store);
    // Outcome of the last store export. Not persisted with the arguments: it describes something
    // that happened, not something the next run should do.
    let s_store_export = use_signal(String::new);
    // The same, for the graph export in the Advanced group
    let mut s_graph_export = use_signal(String::new);
    let s_ta_cbor = use_signal(|| saved_or_empty(&sa.ta_cbor));
    let s_time_of_interest = use_signal(|| get_now_as_unix_epoch().to_string());
    let s_logging_config = use_signal(|| sa.logging_config.clone().unwrap_or_default());
    let s_error_folder = use_signal(|| sa.error_folder.clone().unwrap_or_default());
    let s_download_folder = use_signal(|| sa.download_folder.clone().unwrap_or_default());
    let s_ca_folder = use_signal(|| sa.ca_folder.clone().unwrap_or_default());
    let s_generate = use_signal(|| sa.generate);
    let s_chase_aia_and_sia = use_signal(|| sa.chase_aia_and_sia);
    let s_cbor_ta_store = use_signal(|| sa.cbor_ta_store);
    let s_validate_all = use_signal(|| sa.validate_all);
    let s_validate_self_signed = use_signal(|| sa.validate_self_signed);
    let s_dynamic_build = use_signal(|| sa.dynamic_build);
    let s_end_entity_file = use_signal(|| sa.end_entity_file.clone().unwrap_or_default());
    let s_end_entity_folder = use_signal(|| sa.end_entity_folder.clone().unwrap_or_default());
    let s_results_folder = use_signal(|| sa.results_folder.clone().unwrap_or_default());
    // Effective settings file. Saved args win; otherwise the default in ~/.pittv3 so the app always
    // has settings, matching the browser frontend where localStorage always answers. The file need
    // not exist — read_settings treats a missing path as "all defaults".
    let mut s_settings = use_signal(|| {
        sa.settings
            .clone()
            .filter(|p| !p.is_empty())
            .or_else(default_settings_path)
            .unwrap_or_default()
    });
    let s_crl_folder = use_signal(|| sa.crl_folder.clone().unwrap_or_default());
    let s_cleanup = use_signal(|| sa.cleanup);
    let s_ta_cleanup = use_signal(|| sa.ta_cleanup);
    let s_report_only = use_signal(|| sa.report_only);
    let s_list_partial_paths = use_signal(|| sa.list_partial_paths);
    let s_list_buffers = use_signal(|| sa.list_buffers);
    let s_list_aia_and_sia = use_signal(|| sa.list_aia_and_sia);
    let s_list_name_constraints = use_signal(|| sa.list_name_constraints);
    let s_list_trust_anchors = use_signal(|| sa.list_trust_anchors);
    let s_dump_cert_at_index = use_signal(|| {
        sa.dump_cert_at_index
            .map(|u| u.to_string())
            .unwrap_or_default()
    });
    let s_list_partial_paths_for_target =
        use_signal(|| sa.list_partial_paths_for_target.clone().unwrap_or_default());
    let s_list_partial_paths_for_leaf_ca = use_signal(|| {
        sa.list_partial_paths_for_leaf_ca
            .map(|u| u.to_string())
            .unwrap_or_default()
    });
    let s_mozilla_csv = use_signal(|| sa.mozilla_csv.clone().unwrap_or_default());

    let window = use_window();

    // run state: the validation run executes on a worker thread so the WebView stays responsive;
    // results and log output flow back over channels and are applied to signals on the UI side only
    let mut s_view = use_signal(|| View::Validate);
    let mut s_running = use_signal(|| false);
    let mut s_report = use_signal(|| None::<ValidationReport>);
    let mut s_uri_dialog_open = use_signal(|| false);
    let mut s_log = use_signal(Vec::<String>::new);

    // The arguments the form currently describes. Shared by the run and by anything else that has
    // to reason about what a run *would* do — exporting the graph asks which graph this form keys
    // to, and an answer assembled a second way would be an answer to a different question.
    //
    // Resolves the store selection first: a built-in store supplies the trust anchors, and the
    // intermediates too where its environment carries them. An anchors-only environment leaves the
    // CA CBOR field in effect, so Mozilla's TLS or S/MIME anchor set can be paired with
    // intermediates of the user's choosing. The TA folder is never displaced, since anchors from a
    // store and a folder are combined.
    let current_args = move || -> Result<Pittv3Args, String> {
        let (store_ta_cbor, store_cbor) = stores::materialize(s_store())?;

        Ok(Pittv3Args {
            ta_folder: path_or_none(s_ta_folder),
            ta_cbor: store_ta_cbor.or_else(|| path_or_none(s_ta_cbor)),
            // Set by the store selector alone. As a checkbox this could be combined with any other
            // anchor set, which is the two-TaSource case load_trust_anchors merges its own inputs
            // to avoid; a single-select control cannot express it.
            webpki_tas: stores::is_webpki(s_store()),
            cbor: store_cbor.or_else(|| path_or_none(s_cbor)),
            time_of_interest: s_time_of_interest()
                .parse::<u64>()
                .unwrap_or_else(|_| get_now_as_unix_epoch()),
            logging_config: path_or_none(s_logging_config),
            error_folder: path_or_none(s_error_folder),
            download_folder: path_or_none(s_download_folder),
            ca_folder: path_or_none(s_ca_folder),
            generate: s_generate(),
            chase_aia_and_sia: s_chase_aia_and_sia(),
            cbor_ta_store: s_cbor_ta_store(),
            validate_all: s_validate_all(),
            validate_self_signed: s_validate_self_signed(),
            dynamic_build: s_dynamic_build(),
            end_entity_file: path_or_none(s_end_entity_file),
            end_entity_folder: path_or_none(s_end_entity_folder),
            results_folder: path_or_none(s_results_folder),
            settings: path_or_none(s_settings),
            crl_folder: path_or_none(s_crl_folder),
            keep_crl_entries_in_memory: false,
            cleanup: s_cleanup(),
            ta_cleanup: s_ta_cleanup(),
            report_only: s_report_only(),
            list_partial_paths: s_list_partial_paths(),
            list_buffers: s_list_buffers(),
            list_aia_and_sia: s_list_aia_and_sia(),
            list_name_constraints: s_list_name_constraints(),
            list_trust_anchors: s_list_trust_anchors(),
            dump_cert_at_index: usize_or_none(s_dump_cert_at_index),
            list_partial_paths_for_target: path_or_none(s_list_partial_paths_for_target),
            list_partial_paths_for_leaf_ca: usize_or_none(s_list_partial_paths_for_leaf_ca),
            mozilla_csv: path_or_none(s_mozilla_csv),
            check_uris: None,
            issuer: None,
            no_auto_discover: false,
        })
    };

    let run_command = move |_: ()| {
        if s_running() {
            return;
        }
        let args = match current_args() {
            Ok(args) => args,
            Err(msg) => {
                error!("{msg}");
                s_log.write().push(msg);
                s_view.set(View::Results);
                return;
            }
        };

        let _ = save_args(&args);

        let mut logging_configured = false;

        if let Some(logging_config) = &args.logging_config {
            if let Err(e) = log4rs::init_file(logging_config, Default::default()) {
                println!(
                    "ERROR: failed to configure logging using {logging_config} with {e:?}. Continuing without logging."
                );
            } else {
                logging_configured = true;
            }
        }

        if !logging_configured {
            // if there's no config, prepare one using stdout plus the channel appender that
            // streams run output into the Results view (log4rs initialization is one-shot per
            // process; subsequent attempts fail harmlessly and logging keeps its first shape)
            let stdout = ConsoleAppender::builder()
                .encoder(Box::new(PatternEncoder::new("{m}{n}")))
                .build();
            match Config::builder()
                .appender(Appender::builder().build("stdout", Box::new(stdout)))
                .appender(Appender::builder().build("channel", Box::new(ChannelAppender)))
                .build(
                    Root::builder()
                        .appender("stdout")
                        .appender("channel")
                        .build(LevelFilter::Info),
                ) {
                Ok(config) => {
                    let handle = log4rs::init_config(config);
                    if let Err(e) = handle {
                        println!(
                            "ERROR: failed to configure logging for stdout with {e:?}. Continuing without logging."
                        );
                    }
                }
                Err(e) => {
                    println!("ERROR: failed to prepare default logging configuration with {e:?}. Continuing without logging");
                }
            }
        }

        debug!("PITTv3 start");

        s_running.set(true);
        s_report.set(None);
        s_log.write().clear();
        s_view.set(View::Results);

        let (tx, mut rx) = futures_channel::mpsc::unbounded::<RunEvent>();
        let (log_tx, mut log_rx) = futures_channel::mpsc::unbounded::<String>();
        set_log_sink(log_tx);

        // execute the run on a worker thread with its own runtime; awaiting options_std on the
        // UI executor would block the WebView for the duration of the run
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.unbounded_send(RunEvent::Failed(format!(
                        "failed to start runtime for validation run: {e}"
                    )));
                    return;
                }
            };
            let report = rt.block_on(options_std(&args));
            debug!("PITTv3 end");
            // A report carrying an error means the run could not be carried out (e.g. a missing
            // required input). Surface it as a failure instead of an empty Results view.
            let event = match report.error.clone() {
                Some(msg) => RunEvent::Failed(msg),
                None => RunEvent::Done(Box::new(report)),
            };
            let _ = tx.unbounded_send(event);
        });

        // apply run events and log lines to signals from tasks on the UI executor (signals must
        // not be written from the worker thread)
        spawn(async move {
            while let Some(line) = log_rx.next().await {
                s_log.write().push(line);
            }
        });
        spawn(async move {
            while let Some(ev) = rx.next().await {
                match ev {
                    RunEvent::Progress(_p) => {}
                    RunEvent::Done(report) => {
                        clear_log_sink();
                        s_report.set(Some(*report));
                        s_running.set(false);
                    }
                    RunEvent::Failed(msg) => {
                        clear_log_sink();
                        error!("{msg}");
                        s_log.write().push(msg);
                        s_running.set(false);
                    }
                }
            }
        });
    };

    let selected = VIEWS.iter().position(|(v, _)| *v == s_view()).unwrap_or(0);
    let results_index = VIEWS
        .iter()
        .position(|(v, _)| *v == View::Results)
        .unwrap_or(0);

    rsx! {
        style { {PITTV3_CSS} }
        AppShell {
            items: VIEWS.iter().map(|(_, label)| *label).collect::<Vec<_>>(),
            selected,
            busy_item: if s_running() { Some(results_index) } else { None },
            on_select: move |i: usize| s_view.set(VIEWS[i].0),
            {
                match s_view() {
                    View::Validate => rsx! {
                        // Two boxes rather than one: the first is the PKI a run is judged against —
                        // certval's own PkiEnvironment, anchors and intermediates and revocation
                        // material — and the second is what is judged and how. "Validation" named
                        // the view rather than either of them.
                        fieldset {
                            legend { "PKI Environment" }
                            table {
                                tbody {
                                    StoreRow { sig: s_store, status: s_store_export }
                                    StoreHint { selection: s_store() }
                                    StoreStatusRow { status: s_store_export }
                                    // "Additional" only when a store is supplying material to add
                                    // to: for a custom selection these fields are the trust
                                    // material, not a supplement to it.
                                    if s_store() == stores::CUSTOM {
                                        SubgroupRow { title: "Trust Anchors and Certification Authorities" }
                                    } else {
                                        SubgroupRow { title: "Additional Trust Anchors and Certification Authorities" }
                                    }
                                    PathRow {
                                        label: "TA Folder or File",
                                        name: "ta-folder",
                                        sig: s_ta_folder,
                                    }
                                    // Shown only for a custom selection: a built-in store is itself
                                    // a trust anchor CBOR, and the run writes its path here.
                                    if s_store() == stores::CUSTOM {
                                        FileRow {
                                            label: "TA CBOR",
                                            name: "ta-cbor",
                                            sig: s_ta_cbor,
                                            filter_name: "PITTv3 CBOR-serialized trust anchor store",
                                            extensions: ["cbor", "pki", "ta"].as_slice(),
                                        }
                                    }
                                    if !stores::has_ca_store(s_store()) {
                                        FileRow {
                                            label: "CA CBOR",
                                            name: "cbor",
                                            sig: s_cbor,
                                            filter_name: "PITTv3 CBOR-serialized PKI",
                                            extensions: ["cbor", "pki"].as_slice(),
                                        }
                                    }
                                    // Intermediates as loose files, the counterpart of the CA CBOR
                                    // row: a run reads them into the graph it builds, so no store
                                    // has to be generated first. Shown whatever the store
                                    // selection, unlike CA CBOR, because a folder augments a
                                    // store's certificates rather than being displaced by them —
                                    // and hidden only while dynamic build is on, which reveals the
                                    // same field below as the folder fetched certificates are
                                    // written to.
                                    if !s_dynamic_build() {
                                        PathRow {
                                            label: "CA Folder or File",
                                            name: "ca-folder",
                                            sig: s_ca_folder,
                                        }
                                    }
                                    SubgroupRow { title: "Revocation" }
                                    FolderRow { label: "CRL Folder", name: "crl-folder", sig: s_crl_folder }
                                }
                            }
                        }
                        fieldset {
                            legend { "Target and Settings" }
                            table {
                                tbody {
                                    FileRow {
                                        label: "End Entity File",
                                        name: "end-entity-file",
                                        sig: s_end_entity_file,
                                        filter_name: "Certificate File",
                                        extensions: ["der", "crt"].as_slice(),
                                    }
                                    FolderRow { label: "End Entity Folder", name: "end-entity-folder", sig: s_end_entity_folder }
                                    tr {
                                        td { label { r#for: "settings", "Settings: " } }
                                        td { class: "grow",
                                            input {
                                                r#type: "text",
                                                name: "settings",
                                                value: "{s_settings}",
                                                oninput: move |ev| s_settings.set(ev.value()),
                                            }
                                        }
                                        td { class: "nowrap",
                                            button {
                                                r#type: "button",
                                                onclick: move |_| pick_file_into(s_settings, "PITTv3 Settings", &["json"]),
                                                "..."
                                            }
                                            button {
                                                r#type: "button",
                                                disabled: s_settings().is_empty(),
                                                onclick: move |_| {
                                                    let dom = VirtualDom::new_with_props(
                                                        EditSettingsWindow,
                                                        EditSettingsWindowProps { path: s_settings() },
                                                    );
                                                    window.new_window(dom, Default::default());
                                                },
                                                "Edit"
                                            }
                                        }
                                    }
                                    // A run honors this file, so name it rather than leaving the
                                    // user to infer it from a path field they never filled in.
                                    tr {
                                        td { }
                                        td { class: "grow",
                                            // Block, for the reason given on StoreHint: an inline
                                            // .hint indents its first line only. Both lines here
                                            // are short enough not to wrap today.
                                            div { class: "hint",
                                                if s_settings().is_empty() {
                                                    "This run will use certval defaults."
                                                } else {
                                                    "This run will use the settings above."
                                                }
                                            }
                                        }
                                        td { }
                                    }
                                }
                            }
                            table {
                                tbody {
                                    TimeRow { label: "Time of Interest", name: "time-of-interest", sig: s_time_of_interest }
                                }
                            }
                            table {
                                tbody {
                                    tr {
                                        CheckboxCell { label: "Validate All", name: "validate-all", sig: s_validate_all }
                                        CheckboxCell { label: "Dynamic Build", name: "dynamic-build", sig: s_dynamic_build }
                                        td { class: "grow" }
                                    }
                                }
                            }
                            // Dynamic build fetches missing intermediates at run time and needs a
                            // place to store them; either a download folder or a CA folder satisfies
                            // this, so the download folder is shown only while dynamic build is
                            // enabled and the CA folder moves here from its input row above, since
                            // it then serves both roles.
                            if s_dynamic_build() {
                                table {
                                    tbody {
                                        FolderRow { label: "Download Folder", name: "download-folder", sig: s_download_folder }
                                        FolderRow {
                                            label: "CA Folder",
                                            name: "ca-folder",
                                            sig: s_ca_folder,
                                            title: "Full path of folder containing binary DER-encoded intermediate CA certificates. These are added to the graph built for path validation, and the folder receives certificates fetched during dynamic building when no download folder is given.",
                                        }
                                    }
                                }
                                p { class: "hint",
                                    "Dynamic build stores fetched intermediates here. Provide a download folder or a CA folder."
                                }
                            }
                            details { class: "advanced",
                                summary { "Advanced" }
                                table {
                                    tbody {
                                        FolderRow { label: "Results Folder", name: "results-folder", sig: s_results_folder }
                                        FolderRow { label: "Error Folder", name: "error-folder", sig: s_error_folder }
                                        FileRow {
                                            label: "Logging Configuration",
                                            name: "logging-config",
                                            sig: s_logging_config,
                                            filter_name: "log4rs Configuration",
                                            extensions: ["yaml"].as_slice(),
                                        }
                                    }
                                }
                                table {
                                    tbody {
                                        tr {
                                            // "WebPKI TAs" was here. It is an anchor set, so it is
                                            // an entry in the store selector now — see StoreSource.
                                            CheckboxCell { label: "Validate Self-Signed", name: "validate-self-signed", sig: s_validate_self_signed }
                                            td { class: "grow" }
                                        }
                                        // The environment the last run over these inputs used,
                                        // which exists as files only because it is cached: nothing
                                        // else writes the assembled anchors and the merged graph
                                        // out as a pair.
                                        tr {
                                            td { }
                                            td { class: "grow",
                                                button {
                                                    r#type: "button",
                                                    title: "Write this run's trust anchors and its certificate graph to a folder, as ta.cbor and ca.cbor",
                                                    onclick: move |_| {
                                                        match current_args() {
                                                            Ok(args) => {
                                                                spawn(export_environment_into(args, s_graph_export));
                                                            }
                                                            Err(msg) => {
                                                                error!("{msg}");
                                                                s_graph_export.set(msg);
                                                            }
                                                        }
                                                    },
                                                    "Export PKI Environment..."
                                                }
                                            }
                                            td { }
                                        }
                                        if !s_graph_export().is_empty() {
                                            tr {
                                                td { }
                                                td { class: "grow",
                                                    div { class: "hint", "{s_graph_export}" }
                                                }
                                                td { }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        RunButton { running: s_running(), onrun: run_command }
                    },
                    View::Generate => rsx! {
                        fieldset {
                            legend { "Generation" }
                            table {
                                tbody {
                                    PathRow {
                                        label: "TA Folder or File",
                                        name: "ta-folder",
                                        sig: s_ta_folder,
                                    }
                                    PathRow {
                                        label: "CA Folder or File",
                                        name: "ca-folder",
                                        sig: s_ca_folder,
                                    }
                                    // The file the run writes — labelled as such, since it sits
                                    // among inputs and is otherwise indistinguishable from one.
                                    // Which store it holds follows the CBOR TA store checkbox
                                    // below, so it is named for the row it will be loaded into on
                                    // the Validate view. (Same "(output)" convention as the
                                    // Mozilla CSV view's CA Folder.)
                                    if s_cbor_ta_store() {
                                        FileRow {
                                            label: "TA CBOR (output)",
                                            name: "cbor",
                                            sig: s_cbor,
                                            filter_name: "PITTv3 CBOR-serialized trust anchor store",
                                            extensions: ["cbor", "pki", "ta"].as_slice(),
                                        }
                                    } else {
                                        FileRow {
                                            label: "CA CBOR (output)",
                                            name: "cbor",
                                            sig: s_cbor,
                                            filter_name: "PITTv3 CBOR-serialized PKI",
                                            extensions: ["cbor", "pki"].as_slice(),
                                        }
                                    }
                                    FolderRow { label: "Download Folder", name: "download-folder", sig: s_download_folder }
                                }
                            }
                            table {
                                tbody {
                                    TimeRow { label: "Time of Interest", name: "time-of-interest", sig: s_time_of_interest }
                                }
                            }
                            table {
                                tbody {
                                    tr {
                                        CheckboxCell { label: "Generate", name: "generate", sig: s_generate }
                                        CheckboxCell { label: "Chase SIA and AIA", name: "chase-aia-and-sia", sig: s_chase_aia_and_sia }
                                        CheckboxCell { label: "CBOR TA store", name: "cbor-ta-store", sig: s_cbor_ta_store }
                                        td { class: "grow" }
                                    }
                                }
                            }
                            p { class: "hint",
                                if s_cbor_ta_store() {
                                    "Generate writes a trust anchor store to the TA CBOR path above, read from the CA input; either input may be a single file."
                                } else {
                                    "Generate writes the store to the CA CBOR path above, built from the TA and CA inputs; either may be a single file. Check CBOR TA store for a trust anchor store instead."
                                }
                            }
                        }
                        RunButton { running: s_running(), onrun: run_command }
                    },
                    View::Cleanup => rsx! {
                        fieldset {
                            legend { "Cleanup" }
                            table {
                                tbody {
                                    FolderRow { label: "CA Folder", name: "ca-folder", sig: s_ca_folder }
                                    FolderRow { label: "TA Folder", name: "ta-folder", sig: s_ta_folder }
                                    FolderRow { label: "Error Folder", name: "error-folder", sig: s_error_folder }
                                }
                            }
                            table {
                                tbody {
                                    TimeRow { label: "Time of Interest", name: "time-of-interest", sig: s_time_of_interest }
                                }
                            }
                            table {
                                tbody {
                                    tr {
                                        CheckboxCell { label: "Cleanup", name: "cleanup", sig: s_cleanup }
                                        CheckboxCell { label: "TA Cleanup", name: "ta-cleanup", sig: s_ta_cleanup }
                                        CheckboxCell { label: "Report Only", name: "report-only", sig: s_report_only }
                                        td { class: "grow" }
                                    }
                                }
                            }
                        }
                        RunButton { running: s_running(), onrun: run_command }
                    },
                    View::Diagnostics => rsx! {
                        fieldset {
                            legend { "Diagnostics" }
                            table {
                                tbody {
                                    StoreRow { sig: s_store, status: s_store_export }
                                    StoreHint { selection: s_store() }
                                    StoreStatusRow { status: s_store_export }
                                    if !stores::has_ca_store(s_store()) {
                                        FileRow {
                                            label: "CA CBOR",
                                            name: "cbor",
                                            sig: s_cbor,
                                            filter_name: "PITTv3 CBOR-serialized PKI",
                                            extensions: ["cbor", "pki"].as_slice(),
                                        }
                                    }
                                    PathRow {
                                        label: "TA Folder or File",
                                        name: "ta-folder",
                                        sig: s_ta_folder,
                                    }
                                    if s_store() == stores::CUSTOM {
                                        FileRow {
                                            label: "TA CBOR",
                                            name: "ta-cbor",
                                            sig: s_ta_cbor,
                                            filter_name: "PITTv3 CBOR-serialized trust anchor store",
                                            extensions: ["cbor", "pki", "ta"].as_slice(),
                                        }
                                    }
                                    FolderRow { label: "Download Folder", name: "download-folder", sig: s_download_folder }
                                }
                            }
                            table {
                                tbody {
                                    TimeRow { label: "Time of Interest", name: "time-of-interest", sig: s_time_of_interest }
                                }
                            }
                            table {
                                tbody {
                                    tr {
                                        CheckboxCell { label: "List Partial Paths", name: "list-partial-paths", sig: s_list_partial_paths }
                                        CheckboxCell { label: "List Buffers", name: "list-buffers", sig: s_list_buffers }
                                        CheckboxCell { label: "List SIA and AIA", name: "list-aia-and-sia", sig: s_list_aia_and_sia }
                                        td { class: "grow" }
                                    }
                                    tr {
                                        CheckboxCell { label: "List Name Constraints", name: "list-name-constraints", sig: s_list_name_constraints }
                                        CheckboxCell { label: "List Trust Anchors", name: "list-trust-anchors", sig: s_list_trust_anchors }
                                        td { class: "grow" }
                                    }
                                }
                            }
                            table {
                                tbody {
                                    TextRow { label: "Dump Certificate At Index", name: "dump-cert-at-index", sig: s_dump_cert_at_index }
                                    FileRow {
                                        label: "List Partial Paths for Target",
                                        name: "list-partial-paths-for-target",
                                        sig: s_list_partial_paths_for_target,
                                        filter_name: "Certificate File",
                                        extensions: ["der", "crt"].as_slice(),
                                    }
                                    TextRow { label: "List Partial Paths for Leaf CA", name: "list-partial-paths-for-leaf-ca", sig: s_list_partial_paths_for_leaf_ca }
                                }
                            }
                        }
                        RunButton { running: s_running(), onrun: run_command }
                    },
                    View::Tools => rsx! {
                        fieldset {
                            legend { "Tools" }
                            table {
                                tbody {
                                    FileRow {
                                        label: "Mozilla CSV",
                                        name: "mozilla-csv",
                                        sig: s_mozilla_csv,
                                        filter_name: "CSV file",
                                        extensions: ["csv"].as_slice(),
                                    }
                                    FolderRow { label: "CA Folder (output)", name: "ca-folder", sig: s_ca_folder }
                                }
                            }
                            p { class: "hint",
                                "Parses the Mozilla intermediate CA CSV report and writes the certificates to the CA folder."
                            }
                        }
                        fieldset {
                            legend { "Check URIs in certificate" }
                            p { class: "hint",
                                "Fetches and evaluates the HTTP URIs (AIA, SIA, CRL DP, freshest CRL) carried in a certificate, independent of path processing."
                            }
                            div { class: "tool-actions",
                                button {
                                    r#type: "button",
                                    onclick: move |_| s_uri_dialog_open.set(true),
                                    "Check URIs in certificate\u{2026}"
                                }
                            }
                        }
                        RunButton { running: s_running(), onrun: run_command }
                    },
                    View::Settings => rsx! {
                        fieldset {
                            legend { "Settings" }
                            table {
                                tbody {
                                    tr {
                                        td { label { r#for: "settings", "Settings file: " } }
                                        td {
                                            input {
                                                r#type: "text",
                                                name: "settings",
                                                value: "{s_settings}",
                                                oninput: move |ev| s_settings.set(ev.value()),
                                            }
                                        }
                                        td {
                                            button {
                                                r#type: "button",
                                                onclick: move |_| pick_file_into(s_settings, "PITTv3 Settings", &["json"]),
                                                "..."
                                            }
                                        }
                                    }
                                }
                            }
                            // Always shown: settings are app state, not a document you must open
                            // first. The path above selects which file backs them and defaults to
                            // ~/.pittv3/settings.json, which is created on save if it does not
                            // exist. The empty case is only reachable with no home directory.
                            if s_settings().is_empty() {
                                p { class: "hint",
                                    "No home directory, so there is no default settings file. Choose or type the path of a JSON settings file to edit."
                                }
                            } else {
                                EditSettingsFile {
                                    path: s_settings(),
                                    on_close: move |_| s_view.set(View::Validate),
                                }
                            }
                        }
                    },
                    View::Results => rsx! {
                        fieldset {
                            legend { "Results" }
                            div { class: "results-header",
                                button {
                                    r#type: "button",
                                    disabled: s_report().is_none(),
                                    onclick: move |_| {
                                        if let Some(r) = s_report() {
                                            spawn(save_report(r));
                                        }
                                    },
                                    "Save"
                                }
                                button {
                                    r#type: "button",
                                    disabled: s_report().is_none() && s_log().is_empty(),
                                    onclick: move |_| {
                                        s_report.set(None);
                                        s_log.write().clear();
                                    },
                                    "Clear"
                                }
                            }
                            if s_running() {
                                div { class: "progress-line",
                                    span { class: "spinner" }
                                    span { " Running…" }
                                }
                            }
                            if let Some(report) = s_report() {
                                ResultsView { report }
                            }
                            if !s_running() && s_report().is_none() {
                                p { class: "hint", "No results yet: run a command to see results here." }
                            }
                            if !s_log().is_empty() {
                                details { class: "advanced", open: s_running(),
                                    summary { "Run log ({s_log().len()} line(s))" }
                                    div { class: "log-stream",
                                        for line in s_log().iter() {
                                            p { "{line}" }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    View::Help => rsx! {
                        fieldset {
                            legend { "Help" }
                            HelpView {}
                        }
                    },
                }
            }
        }
        UriCheckModal { open: s_uri_dialog_open }
    }
}
