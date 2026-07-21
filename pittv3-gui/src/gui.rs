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
use pittv3_gui_lib::gui_settings::EditSettingsFile;
use pittv3_gui_lib::gui_shell::AppShell;
use pittv3_gui_lib::gui_utils::{
    clear_log_sink, read_saved_args, save_args, set_log_sink, ChannelAppender,
};
use pittv3_gui_lib::PITTV3_CSS;
use pittv3_lib::args::{get_now_as_unix_epoch, Pittv3Args};
use pittv3_lib::options_std::options_std;
use pittv3_lib::report::ValidationReport;

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

/// Presents a file selection dialog limited to files of the indicated type and assigns the
/// selection, if any, to `sig`
async fn pick_file_into(
    mut sig: Signal<String>,
    filter_name: &'static str,
    extensions: &'static [&'static str],
) {
    let file = AsyncFileDialog::new()
        .add_filter(filter_name, extensions)
        .set_directory(home_dir().unwrap_or("/".into()))
        .pick_file()
        .await;
    if let Some(file) = file {
        sig.set(file.path().to_string_lossy().to_string());
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

/// Returns the value of `sig` as a usize, or None if the value is empty or cannot be parsed
fn usize_or_none(sig: Signal<String>) -> Option<usize> {
    match string_or_none(sig) {
        Some(v) => v.parse::<usize>().ok(),
        None => None,
    }
}

/// Renders seconds since Unix epoch as an RFC 3339 string, or an em dash if unparseable
fn human_time(epoch: &str) -> String {
    let dt = epoch
        .parse::<u64>()
        .ok()
        .and_then(|s| der::DateTime::from_unix_duration(core::time::Duration::from_secs(s)).ok());
    match dt {
        Some(dt) => dt.to_string(),
        None => "—".to_string(),
    }
}

/// Table row featuring the time of interest with a human-readable rendering and a Now button
#[component]
fn TimeRow(label: String, name: String, sig: Signal<String>) -> Element {
    rsx! {
        tr {
            td { label { r#for: name.clone(), "{label}: " } }
            td {
                input {
                    r#type: "text",
                    name,
                    value: "{sig}",
                    oninput: move |ev| sig.set(ev.value()),
                }
            }
            td {
                button {
                    r#type: "button",
                    onclick: move |_| sig.set(get_now_as_unix_epoch().to_string()),
                    "Now"
                }
                span { class: "hint", "{human_time(&sig())}" }
            }
        }
    }
}

/// Table row featuring a labeled text input with no accompanying selection dialog
#[component]
fn TextRow(label: String, name: String, sig: Signal<String>) -> Element {
    rsx! {
        tr {
            td { label { r#for: name.clone(), "{label}: " } }
            td {
                input {
                    r#type: "text",
                    name,
                    value: "{sig}",
                    oninput: move |ev| sig.set(ev.value()),
                }
            }
        }
    }
}

/// Table row featuring a labeled text input with a folder selection dialog
#[component]
fn FolderRow(
    label: String,
    name: String,
    sig: Signal<String>,
    #[props(default)] title: String,
) -> Element {
    rsx! {
        tr {
            td {
                div { title, class: "visible",
                    label { r#for: name.clone(), "{label}: " }
                }
            }
            td {
                input {
                    r#type: "text",
                    name,
                    value: "{sig}",
                    oninput: move |ev| sig.set(ev.value()),
                }
            }
            td {
                button { r#type: "button", onclick: move |_| pick_folder_into(sig), "..." }
            }
        }
    }
}

/// Table row featuring a labeled text input with a file selection dialog limited to files of the
/// indicated type
#[component]
fn FileRow(
    label: String,
    name: String,
    sig: Signal<String>,
    filter_name: &'static str,
    extensions: &'static [&'static str],
) -> Element {
    rsx! {
        tr {
            td { label { r#for: name.clone(), "{label}: " } }
            td {
                input {
                    r#type: "text",
                    name,
                    value: "{sig}",
                    oninput: move |ev| sig.set(ev.value()),
                }
            }
            td {
                button {
                    r#type: "button",
                    onclick: move |_| pick_file_into(sig, filter_name, extensions),
                    "..."
                }
            }
        }
    }
}

/// Labeled checkbox cell for use within a table row
#[component]
fn CheckboxCell(label: String, name: String, sig: Signal<bool>) -> Element {
    rsx! {
        td { label { r#for: name.clone(), "{label}: " } }
        td {
            input {
                r#type: "checkbox",
                name,
                checked: sig(),
                onchange: move |ev| sig.set(ev.checked()),
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

const VIEWS: &[(View, &str)] = &[
    (View::Validate, "Validate"),
    (View::Generate, "Generate"),
    (View::Cleanup, "Cleanup"),
    (View::Diagnostics, "Diagnostics"),
    (View::Tools, "Tools"),
    (View::Settings, "Settings"),
    (View::Results, "Results"),
    (View::Help, "Help"),
];

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

    let s_ta_folder = use_signal(|| sa.ta_folder.clone().unwrap_or_default());
    let s_webpki_tas = use_signal(|| sa.webpki_tas);
    let s_cbor = use_signal(|| sa.cbor.clone().unwrap_or_default());
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
    let mut s_settings = use_signal(|| sa.settings.clone().unwrap_or_default());
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
    let mut s_log = use_signal(Vec::<String>::new);

    let run_command = move |_: ()| {
        if s_running() {
            return;
        }
        let args = Pittv3Args {
            ta_folder: string_or_none(s_ta_folder),
            webpki_tas: s_webpki_tas(),
            cbor: string_or_none(s_cbor),
            time_of_interest: s_time_of_interest()
                .parse::<u64>()
                .unwrap_or_else(|_| get_now_as_unix_epoch()),
            logging_config: string_or_none(s_logging_config),
            error_folder: string_or_none(s_error_folder),
            download_folder: string_or_none(s_download_folder),
            ca_folder: string_or_none(s_ca_folder),
            generate: s_generate(),
            chase_aia_and_sia: s_chase_aia_and_sia(),
            cbor_ta_store: s_cbor_ta_store(),
            validate_all: s_validate_all(),
            validate_self_signed: s_validate_self_signed(),
            dynamic_build: s_dynamic_build(),
            end_entity_file: string_or_none(s_end_entity_file),
            end_entity_folder: string_or_none(s_end_entity_folder),
            results_folder: string_or_none(s_results_folder),
            settings: string_or_none(s_settings),
            crl_folder: string_or_none(s_crl_folder),
            cleanup: s_cleanup(),
            ta_cleanup: s_ta_cleanup(),
            report_only: s_report_only(),
            list_partial_paths: s_list_partial_paths(),
            list_buffers: s_list_buffers(),
            list_aia_and_sia: s_list_aia_and_sia(),
            list_name_constraints: s_list_name_constraints(),
            list_trust_anchors: s_list_trust_anchors(),
            dump_cert_at_index: usize_or_none(s_dump_cert_at_index),
            list_partial_paths_for_target: string_or_none(s_list_partial_paths_for_target),
            list_partial_paths_for_leaf_ca: usize_or_none(s_list_partial_paths_for_leaf_ca),
            mozilla_csv: string_or_none(s_mozilla_csv),
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
            let _ = tx.unbounded_send(RunEvent::Done(Box::new(report)));
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
                        fieldset {
                            legend { "Validation" }
                            table {
                                tbody {
                                    FolderRow {
                                        label: "TA Folder",
                                        name: "ta-folder",
                                        sig: s_ta_folder,
                                        title: "Full path of folder containing binary DER-encoded trust anchors to use when generating CBOR file containing partial certification paths and when validating certification paths.",
                                    }
                                    FileRow {
                                        label: "CBOR",
                                        name: "cbor",
                                        sig: s_cbor,
                                        filter_name: "PITTv3 CBOR-serialized PKI",
                                        extensions: ["cbor", "pki"].as_slice(),
                                    }
                                    FileRow {
                                        label: "End Entity File",
                                        name: "end-entity-file",
                                        sig: s_end_entity_file,
                                        filter_name: "Certificate File",
                                        extensions: ["der", "crt"].as_slice(),
                                    }
                                    FolderRow { label: "End Entity Folder", name: "end-entity-folder", sig: s_end_entity_folder }
                                    FolderRow { label: "CRL Folder", name: "crl-folder", sig: s_crl_folder }
                                    tr {
                                        td { label { r#for: "settings", "Settings: " } }
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
                                        td {
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
                                    TimeRow { label: "Time of Interest", name: "time-of-interest", sig: s_time_of_interest }
                                }
                            }
                            table {
                                tbody {
                                    tr {
                                        CheckboxCell { label: "Validate All", name: "validate-all", sig: s_validate_all }
                                        CheckboxCell { label: "Dynamic Build", name: "dynamic-build", sig: s_dynamic_build }
                                    }
                                }
                            }
                            details { class: "advanced",
                                summary { "Advanced" }
                                table {
                                    tbody {
                                        FolderRow { label: "Results Folder", name: "results-folder", sig: s_results_folder }
                                        FolderRow { label: "Error Folder", name: "error-folder", sig: s_error_folder }
                                        FolderRow { label: "Download Folder", name: "download-folder", sig: s_download_folder }
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
                                            CheckboxCell { label: "WebPKI TAs", name: "webpki-tas", sig: s_webpki_tas }
                                            CheckboxCell { label: "Validate Self-Signed", name: "validate-self-signed", sig: s_validate_self_signed }
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
                                    FolderRow { label: "TA Folder", name: "ta-folder", sig: s_ta_folder }
                                    FolderRow { label: "CA Folder", name: "ca-folder", sig: s_ca_folder }
                                    FileRow {
                                        label: "CBOR",
                                        name: "cbor",
                                        sig: s_cbor,
                                        filter_name: "PITTv3 CBOR-serialized PKI",
                                        extensions: ["cbor", "pki"].as_slice(),
                                    }
                                    FolderRow { label: "Download Folder", name: "download-folder", sig: s_download_folder }
                                    TimeRow { label: "Time of Interest", name: "time-of-interest", sig: s_time_of_interest }
                                }
                            }
                            table {
                                tbody {
                                    tr {
                                        CheckboxCell { label: "Generate", name: "generate", sig: s_generate }
                                        CheckboxCell { label: "Chase SIA and AIA", name: "chase-aia-and-sia", sig: s_chase_aia_and_sia }
                                        CheckboxCell { label: "CBOR TA store", name: "cbor-ta-store", sig: s_cbor_ta_store }
                                    }
                                }
                            }
                            p { class: "hint",
                                "Check Generate to (re)build the CBOR store from the TA and CA folders when running."
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
                                    TimeRow { label: "Time of Interest", name: "time-of-interest", sig: s_time_of_interest }
                                }
                            }
                            table {
                                tbody {
                                    tr {
                                        CheckboxCell { label: "Cleanup", name: "cleanup", sig: s_cleanup }
                                        CheckboxCell { label: "TA Cleanup", name: "ta-cleanup", sig: s_ta_cleanup }
                                        CheckboxCell { label: "Report Only", name: "report-only", sig: s_report_only }
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
                                    FileRow {
                                        label: "CBOR",
                                        name: "cbor",
                                        sig: s_cbor,
                                        filter_name: "PITTv3 CBOR-serialized PKI",
                                        extensions: ["cbor", "pki"].as_slice(),
                                    }
                                    FolderRow { label: "TA Folder", name: "ta-folder", sig: s_ta_folder }
                                    FolderRow { label: "Download Folder", name: "download-folder", sig: s_download_folder }
                                    TimeRow { label: "Time of Interest", name: "time-of-interest", sig: s_time_of_interest }
                                }
                            }
                            table {
                                tbody {
                                    tr {
                                        CheckboxCell { label: "List Partial Paths", name: "list-partial-paths", sig: s_list_partial_paths }
                                        CheckboxCell { label: "List Buffers", name: "list-buffers", sig: s_list_buffers }
                                        CheckboxCell { label: "List SIA and AIA", name: "list-aia-and-sia", sig: s_list_aia_and_sia }
                                    }
                                    tr {
                                        CheckboxCell { label: "List Name Constraints", name: "list-name-constraints", sig: s_list_name_constraints }
                                        CheckboxCell { label: "List Trust Anchors", name: "list-trust-anchors", sig: s_list_trust_anchors }
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
                            if s_settings().is_empty() {
                                p { class: "hint",
                                    "Choose (or type the path of) a JSON settings file to edit. A new file is created on save if it does not exist."
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
    }
}
