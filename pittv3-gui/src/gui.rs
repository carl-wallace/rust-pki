//! Provides GUI interface to similar set of actions as offered by command line utility

use dioxus::desktop::tao::dpi::{PhysicalPosition, PhysicalSize};
use dioxus::desktop::{use_window, use_wry_event_handler};
use dioxus::prelude::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use home::home_dir;
use log::{debug, error, LevelFilter};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use rfd::AsyncFileDialog;

use pittv3_lib::der_or_pem::SINGLE_CERT_EXTENSIONS;
// Only the platforms with a separate file dialog have a list to feed; see CERT_EXTENSIONS.
#[cfg(not(target_os = "macos"))]
use pittv3_lib::der_or_pem::TA_BUNDLE_EXTENSIONS;

use std::sync::Mutex;

use crate::save::{self, RetainedArtifacts};
use pittv3_gui_lib::export::{
    pool_includes_ca_store, pool_includes_ta_store, stamped_export_name, RunInputs,
    DEFAULT_EXPORT_NAME,
};
use pittv3_gui_lib::gui_end_entity::EndEntityGroup;
use pittv3_gui_lib::gui_help::HelpView;
use pittv3_gui_lib::gui_results::{ResultsView, RunEvent};
use pittv3_gui_lib::gui_rows::now_as_unix_epoch;
use pittv3_gui_lib::gui_rows::{
    BrowseRow, CheckboxCell, CheckboxRow, PathListRow, TextRow, TimeRow,
};
use pittv3_gui_lib::gui_settings::EditSettingsFile;
use pittv3_gui_lib::gui_shell::AppShell;
use pittv3_gui_lib::gui_uri_check::UriCheckResults;
use pittv3_gui_lib::gui_utils::{
    clear_log_sink, last_dialog_dir, read_saved_args, remember_dialog_dir, save_args, set_log_sink,
    ChannelAppender, DialogPurpose,
};
use pittv3_gui_lib::settings_store::{
    default_ca_folder, default_crl_folder, default_download_folder, default_error_folder,
    default_log_config_path, default_log_file, default_settings_path, expand_tilde,
    saved_or_default,
};
use pittv3_gui_lib::PITTV3_CSS;
use pittv3_lib::args::{get_now_as_unix_epoch, Pittv3Args};
use pittv3_lib::graph_cache;
use pittv3_lib::options_std::options_std_retaining;
use pittv3_lib::prepared_graph::PreparedGraph;
use pittv3_lib::report::ValidationReport;
use pittv3_lib::std_utils::{cleanup_certificate_folder, cleanup_crls, purge_folder};
use pittv3_lib::std_utils::{
    count_ca_inputs, count_end_entity_inputs, count_revocation_inputs, count_trust_anchor_inputs,
};
use pittv3_lib::uri_check::{check_uris_from_bytes, UriCheckReport};
use pittv3_lib::RevocationCache;

use crate::logging;
use crate::peek;
use crate::stores;
use crate::window_state;
use crate::window_state::Outcome;

/// Records where a dialog just went, from what it returned: a folder is itself the location, a file
/// is its parent.
fn remember_pick(purpose: DialogPurpose, path: &std::path::Path) {
    let dir = match path.is_dir() {
        true => Some(path),
        false => path.parent(),
    };
    if let Some(dir) = dir {
        remember_dialog_dir(purpose, dir);
    }
}

/// Presents a folder selection dialog and assigns the selection, if any, to `sig`
async fn pick_folder_into(mut sig: Signal<String>) {
    let folder = AsyncFileDialog::new()
        .set_directory(dialog_dir(DialogPurpose::Open))
        .pick_folder()
        .await;
    if let Some(folder) = folder {
        remember_pick(DialogPurpose::Open, folder.path());
        sig.set(folder.path().to_string_lossy().to_string());
    }
}

/// Asks for a folder and writes the selected built-in store's material into it, reporting the
/// outcome through `status` either way — a dialog that closes with nothing said is the shape of
/// failure this app has already been bitten by once (see the tilde expansion in `settings_store`).
async fn export_store_into(index: usize, mut status: Signal<String>) {
    let folder = AsyncFileDialog::new()
        .set_directory(dialog_dir(DialogPurpose::Save))
        .pick_folder()
        .await;
    let Some(folder) = folder else {
        return;
    };
    remember_pick(DialogPurpose::Save, folder.path());
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

/// Reads one of the CBOR files a run was pointed at, for the bundle's inputs half.
///
/// A missing or unreadable file is not an error worth failing a save over: the bundle is still
/// worth having without it, and the command line it carries names only the files that are actually
/// there. Silence here is the same silence as a run whose anchors certval builds rather than reads.
fn read_input_file(path: &Option<String>) -> Option<Vec<u8>> {
    std::fs::read(path.as_ref()?).ok()
}

/// Reads the run's pooled inputs so a store dropped into a pool can be found among them.
///
/// The singular CBOR arguments are not the only way a store reaches a run: the Validate view's
/// pools take one too, and both apps accept a `.cbor` store wherever they accept a certificate. A
/// bundle that looked only at the singular arguments therefore lost `ca.cbor` whenever the store
/// had been dropped on the pool -- which is exactly what loading one bundle into the desktop looks
/// like, so a bundle made from a bundle came out without the store it had just been given.
///
/// Entries that are folders or unreadable are skipped; the caller decides which of the readable
/// ones is a store, using the same test the validator uses.
fn read_pool(paths: &[String]) -> Vec<(String, Vec<u8>)> {
    paths
        .iter()
        .filter_map(|p| std::fs::read(p).ok().map(|b| (p.clone(), b)))
        .collect()
}

/// The targets a run was asked about, read from the arguments it was launched with.
///
/// Taken from the arguments rather than from the paths the run found, because a run that found none
/// still had targets and they are the certificates its bundle is about. Folders are expanded the way
/// the run expands them, so a bundle records the certificates rather than a directory name that
/// means nothing on another machine.
fn read_targets(args: &Pittv3Args) -> Vec<(String, Vec<u8>)> {
    use std::path::Path;
    let mut out = vec![];
    let push_file = |path: &Path, out: &mut Vec<(String, Vec<u8>)>| {
        if let Ok(bytes) = std::fs::read(path) {
            out.push((path.to_string_lossy().to_string(), bytes));
        }
    };
    let named = args
        .end_entity_file
        .iter()
        .chain(args.end_entity_folder.iter())
        .chain(args.ee_inputs.iter());
    for entry in named {
        let path = Path::new(entry);
        match path.is_dir() {
            true => {
                let Ok(dir) = std::fs::read_dir(path) else {
                    continue;
                };
                for file in dir.flatten().filter(|f| f.path().is_file()) {
                    push_file(&file.path(), &mut out);
                }
            }
            false => push_file(path, &mut out),
        }
    }
    out
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
        .set_directory(dialog_dir(DialogPurpose::Save))
        .pick_folder()
        .await;
    let Some(folder) = folder else {
        return;
    };

    remember_pick(DialogPurpose::Save, folder.path());
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
        .set_directory(dialog_dir(DialogPurpose::Open))
        .pick_file_or_folder()
        .await;
    if let Some(picked) = picked {
        remember_pick(DialogPurpose::Open, picked.path());
        sig.set(picked.path().to_string_lossy().to_string());
    }
}

/// Asks where to put an export and writes it there, reporting either outcome into the run log.
///
/// A save dialog rather than a fixed location: this is the user's own copy of what a run used, and
/// the desktop's other writes -- the peek folder, a materialized store -- go under the application
/// home precisely because nobody chose where they should live. Here somebody is choosing.
/// Confirms an action that cannot be undone by fetching the material again.
///
/// Cleanup is offered without one: what it removes is unusable or refetchable, and asking every
/// time is how a confirmation stops being read. Purge takes everything, including artifacts a
/// repository may no longer publish, so it asks.
async fn confirm_purge(folder: &str) -> bool {
    rfd::AsyncMessageDialog::new()
        .set_title("Empty folder")
        .set_description(format!(
            "Remove every file in {folder}?\n\nCertificates can generally be fetched again. A \
             superseded CRL usually cannot: a CA publishes the current one and nothing else, so \
             validating as of a time it covered will no longer be possible."
        ))
        .set_buttons(rfd::MessageButtons::YesNo)
        .show()
        .await
        == rfd::MessageDialogResult::Yes
}

/// Confirms deleting the settings file, which the same rule as [`confirm_purge`] says must ask:
/// certificates and CRLs can generally be fetched again, and a set of hand-tuned settings cannot.
///
/// Names the path rather than saying "the settings file" because the box beside this button may be
/// pointing at somebody else's -- a bundle carries `inputs/settings.json`, and reproducing a run
/// from one is exactly when this button is within reach.
async fn confirm_delete_settings(path: &str) -> bool {
    rfd::AsyncMessageDialog::new()
        .set_title("Delete settings file")
        .set_description(format!(
            "Delete {path}?\n\nThe form goes back to certval's defaults, and the next run uses them \
             too. Settings this form does not show are removed with the file. This cannot be undone."
        ))
        .set_buttons(rfd::MessageButtons::YesNo)
        .show()
        .await
        == rfd::MessageDialogResult::Yes
}

/// Whether it is all right to do something that discards the settings form's edits: either there
/// are none, or the user said so.
///
/// Naming the two ways out together keeps every caller the same shape. Repointing the settings path
/// discards edits exactly as navigating away does — the form re-reads the file it is now aimed at —
/// so the buttons that repoint it ask the same question the sidebar does.
async fn leave_settings_ok(dirty: bool) -> bool {
    !dirty || confirm_discard_settings().await
}

/// Confirms leaving the settings form with edits that have not been saved.
async fn confirm_discard_settings() -> bool {
    rfd::AsyncMessageDialog::new()
        .set_title("Unsaved settings")
        .set_description(
            "The settings form has changes that have not been saved.\n\nLeaving discards them.",
        )
        .set_buttons(rfd::MessageButtons::YesNo)
        .show()
        .await
        == rfd::MessageDialogResult::Yes
}

/// Where a file dialog should open: the folder that kind of dialog last used, falling back to the
/// user's home as it always did when nothing has been remembered yet.
fn dialog_dir(purpose: DialogPurpose) -> std::path::PathBuf {
    last_dialog_dir(purpose).unwrap_or_else(|| home_dir().unwrap_or("/".into()))
}

async fn write_export(
    suggested: String,
    extensions: &[&str],
    bytes: Vec<u8>,
    mut log: Signal<Vec<String>>,
) {
    let Some(handle) = AsyncFileDialog::new()
        .set_directory(dialog_dir(DialogPurpose::Save))
        .set_file_name(&suggested)
        .add_filter("export", extensions)
        .save_file()
        .await
    else {
        // A cancelled dialog is a decision, not a failure, and saying so would be noise.
        return;
    };
    let path = handle.path().to_path_buf();
    match std::fs::write(&path, &bytes) {
        Ok(()) => {
            // Remembered on success only, and only the folder: a failed write says nothing about
            // where the user meant to put things.
            if let Some(parent) = path.parent() {
                remember_dialog_dir(DialogPurpose::Save, parent);
            }
            log.write().push(format!(
                "Saved {} byte(s) to {}",
                bytes.len(),
                path.display()
            ))
        }
        Err(e) => log
            .write()
            .push(format!("Failed to write {}: {e}", path.display())),
    }
}

/// Appends `picked` to the pool in `sig`, dropping paths already in it. Selecting the same folder
/// twice is a slip rather than an instruction to read it twice, and a duplicate entry would show as
/// a second row the user then has to notice and remove.
fn extend_pool(mut sig: Signal<Vec<String>>, picked: Vec<String>) {
    let mut pool = sig.write();
    for path in picked {
        if !pool.contains(&path) {
            pool.push(path);
        }
    }
}

/// Presents a multi-select dialog accepting files and folders together and appends what was chosen
/// to the pool in `sig`. macOS only, as with [`pick_file_or_folder_into`]: `rfd` implements the
/// combined dialog for that platform alone.
#[cfg(target_os = "macos")]
async fn pick_files_or_folders_into(sig: Signal<Vec<String>>) {
    let picked = AsyncFileDialog::new()
        .set_directory(dialog_dir(DialogPurpose::Open))
        .pick_files_or_folders()
        .await;
    if let Some(picked) = picked {
        if let Some(first) = picked.first() {
            remember_pick(DialogPurpose::Open, first.path());
        }
        extend_pool(
            sig,
            picked
                .iter()
                .map(|f| f.path().to_string_lossy().to_string())
                .collect(),
        );
    }
}

/// Presents a multi-select folder dialog and appends the chosen folders to the pool in `sig`.
#[cfg(not(target_os = "macos"))]
async fn pick_folders_into(sig: Signal<Vec<String>>) {
    let picked = AsyncFileDialog::new()
        .set_directory(dialog_dir(DialogPurpose::Open))
        .pick_folders()
        .await;
    if let Some(picked) = picked {
        if let Some(first) = picked.first() {
            remember_pick(DialogPurpose::Open, first.path());
        }
        extend_pool(
            sig,
            picked
                .iter()
                .map(|f| f.path().to_string_lossy().to_string())
                .collect(),
        );
    }
}

/// Presents a multi-select file dialog and appends the chosen files to the pool in `sig`.
///
/// `extensions` names the kinds worth suggesting; as with [`pick_file_into`] a permissive filter
/// sits beside it, because a named filter is enforced on some platforms and would then make a file
/// it failed to anticipate unselectable rather than merely unsuggested.
#[cfg(not(target_os = "macos"))]
async fn pick_files_into(
    sig: Signal<Vec<String>>,
    filter_name: &'static str,
    extensions: &'static [&'static str],
) {
    let picked = AsyncFileDialog::new()
        .add_filter(filter_name, extensions)
        .add_filter("All Files", &["*"])
        .set_directory(dialog_dir(DialogPurpose::Open))
        .pick_files()
        .await;
    if let Some(picked) = picked {
        if let Some(first) = picked.first() {
            remember_pick(DialogPurpose::Open, first.path());
        }
        extend_pool(
            sig,
            picked
                .iter()
                .map(|f| f.path().to_string_lossy().to_string())
                .collect(),
        );
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
        .set_directory(dialog_dir(DialogPurpose::Open))
        .pick_file()
        .await;
    if let Some(file) = file {
        remember_pick(DialogPurpose::Open, file.path());
        sig.set(file.path().to_string_lossy().to_string());
    }
}

/// Serializes the validation report to pretty JSON and writes it to a user-chosen file.
async fn save_report(report: ValidationReport, name: String) {
    let file = AsyncFileDialog::new()
        .set_directory(dialog_dir(DialogPurpose::Save))
        .add_filter("JSON", &["json"])
        // The export name and the run's stamp, as the path logs and the archive already use. A
        // fixed name offered the same file for every run, so saving a second one overwrote the
        // first -- and a sequence of runs is exactly when reports are worth keeping side by side.
        .set_file_name(format!("{name}.json"))
        .save_file()
        .await;
    if let Some(file) = file {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => match std::fs::write(file.path(), json) {
                Err(e) => error!("Failed to write results file: {e}"),
                Ok(()) => {
                    if let Some(parent) = file.path().parent() {
                        remember_dialog_dir(DialogPurpose::Save, parent);
                    }
                }
            },
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

/// Returns the entries of a pool signal as the arguments carry them: tilde expanded as with
/// [`path_or_none`], and blank rows dropped, so an empty entry left over from a form saved by an
/// older build never reaches a run as an input naming nothing.
fn pool(sig: Signal<Vec<String>>) -> Vec<String> {
    sig()
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| expand_tilde(s.trim()))
        .collect()
}

/// Drops repeats from a pool, keeping the first occurrence, so a pool assembled from the singular
/// arguments a run saved before pools existed does not list the same path twice. `--ca-folder` and
/// a `--ca` entry naming that same folder is the ordinary way this happens, and the merge below
/// folds both into one list.
fn dedup_pool(v: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(v.len());
    for p in v {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// What the four input pools on the Validate view contribute, as against how many entries they
/// hold. A `.p7c` of cross-certificates is six certificates and a folder is however many are in it,
/// so an entry count answers a question nobody asked: the number worth showing is the number the
/// run will have. The browser frontend reports its uploads the same way.
///
/// Worked out by the loaders the run itself uses, which means reading every file named. That is
/// what keeps it off the UI thread: see [`spawn_pool_count`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct PoolCounts {
    trust_anchors: usize,
    ca_certificates: usize,
    crl_pool: RevocationCounts,
    ocsp_pool: RevocationCounts,
    end_entities: usize,
}

/// What one revocation pool contributes, counted by kind.
///
/// Per pool rather than per view because the two rows are two lists and each answers for itself.
/// Both counts are kept for both rows: the rows are named for what they are *for*, and a file is
/// sorted by what it holds, so a row can honestly hold the other kind. Reporting what is there
/// beats reporting what the label promised.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RevocationCounts {
    crls: usize,
    ocsp_responses: usize,
}

/// `n` followed by the noun, plural unless there is one of them.
fn plural(n: usize, noun: &str) -> String {
    match n {
        1 => format!("1 {noun}"),
        n => format!("{n} {noun}s"),
    }
}

/// The revocation pool's count, which is two counts: a CRL and an OCSP response are not the same
/// thing to a run, and the pool takes both because a file says for itself which it is.
///
/// A kind that contributed nothing is left out rather than shown as a zero — a pool of CRLs is the
/// ordinary case and "0 OCSP responses" beside it is noise. Both being empty is worth saying, since
/// the entries are there on the row and something has to account for them.
fn revocation_contents(counts: &RevocationCounts) -> String {
    let mut parts = vec![];
    if counts.crls > 0 {
        parts.push(plural(counts.crls, "CRL"));
    }
    if counts.ocsp_responses > 0 {
        parts.push(plural(counts.ocsp_responses, "OCSP response"));
    }
    match parts.is_empty() {
        true => "0 revocation artifacts".to_string(),
        false => parts.join(", "),
    }
}

/// Counts one pool by kind, using the loader the run itself uses so the answer is what the run will
/// see rather than what the file names suggest.
fn revocation_counts(paths: &[String]) -> RevocationCounts {
    let (crls, ocsp_responses) = count_revocation_inputs(paths.iter().map(String::as_str));
    RevocationCounts {
        crls,
        ocsp_responses,
    }
}

/// Which row a restored path belongs in.
///
/// Saved arguments carry one `rev_inputs` list -- the two rows concatenate into it, because that is
/// what the run takes -- so which row a path came from is not recorded and has to be recovered from
/// the bytes. A path counts as OCSP only when it yields responses and no CRLs: a folder holding
/// both is CRL material with a response in it, and moving it would take the CRLs with it.
fn is_ocsp_only(path: &str) -> bool {
    let (crls, ocsp_responses) = count_revocation_inputs(std::iter::once(path));
    ocsp_responses > 0 && crls == 0
}

/// The paths a count is about, as the worker thread needs them: owned, since it outlives the render
/// that read the signals, and carrying the time the material is judged at, which decides the answer
/// as surely as the paths do.
struct PoolInputs {
    ta: Vec<String>,
    ca: Vec<String>,
    crl: Vec<String>,
    ocsp: Vec<String>,
    ee: Vec<String>,
    time_of_interest: u64,
}

/// Counts what the four pools contribute, on a worker thread, and sends the result back tagged with
/// `generation`.
///
/// On a thread rather than in a memo because counting is the loading: a pool naming a folder of a
/// few thousand certificates, or a CBOR store of them, would otherwise stall the WebView on the
/// keystroke that named it — the same reason a run does not happen on the UI executor either.
///
/// The pause at the top is a debounce with the wait already paid for. Every edit to a pool, and
/// every keystroke in the time of interest field, asks for a fresh count; a thread that wakes to
/// find `latest` moved past its own generation has been superseded before it read anything, and
/// stops without touching the disk.
fn spawn_pool_count(
    inputs: PoolInputs,
    generation: usize,
    latest: Arc<AtomicUsize>,
    tx: futures_channel::mpsc::UnboundedSender<(usize, PoolCounts)>,
) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(250));
        if generation != latest.load(Ordering::SeqCst) {
            return;
        }
        let toi = inputs.time_of_interest;
        let counts = PoolCounts {
            trust_anchors: count_trust_anchor_inputs(inputs.ta.iter().map(String::as_str)),
            ca_certificates: count_ca_inputs(inputs.ca.iter().map(String::as_str), toi),
            crl_pool: revocation_counts(&inputs.crl),
            ocsp_pool: revocation_counts(&inputs.ocsp),
            end_entities: count_end_entity_inputs(inputs.ee.iter().map(String::as_str)),
        };
        let _ = tx.unbounded_send((generation, counts));
    });
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

/// Row for an input that accepts either a folder of certificates or a single certificate
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
            // Named rather than left as the bare "..." the single-dialog platforms show. Beside a
            // button that says File, an ellipsis reads as "more" rather than as the other kind.
            primary_label: "Folder\u{2026}",
            alt_label: "File\u{2026}",
        }
    };
}

/// Row for a pool of inputs that may each be a file or a folder — the trust anchor, CA and
/// end entity lists on the Validate view, and the revocation artifacts beside them.
///
/// Thin wrapper over the shared [`PathListRow`], supplying the native pickers. The platform split
/// is [`PathRow`]'s: macOS offers files and folders in one dialog, so one Add button does both;
/// everywhere else the two dialogs are separate and so are the buttons. Either way a typed path of
/// either kind works, because the run decides from the path rather than from which button produced
/// it.
#[component]
fn PoolRow(
    label: String,
    name: String,
    sig: Signal<Vec<String>>,
    filter_name: &'static str,
    extensions: &'static [&'static str],
    #[props(default)] title: String,
    #[props(default)] hint: String,
    /// What the entries contribute, from [`PoolCounts`]. Empty until the first count comes back,
    /// which is when the row falls back to reporting entries.
    #[props(default)]
    contents: String,
) -> Element {
    #[cfg(target_os = "macos")]
    {
        let _ = (filter_name, extensions);
        return rsx! {
            PathListRow {
                label,
                name,
                sig,
                title,
                hint,
                contents,
                on_add: move |_| {
                    spawn(pick_files_or_folders_into(sig));
                },
            }
        };
    }

    #[cfg(not(target_os = "macos"))]
    return rsx! {
        PathListRow {
            label,
            name,
            sig,
            title,
            hint,
            contents,
            on_add: move |_| {
                spawn(pick_files_into(sig, filter_name, extensions));
            },
            on_add_alt: move |_| {
                spawn(pick_folders_into(sig));
            },
            alt_label: "Folders\u{2026}",
        }
    };
}

/// Extensions offered when picking a certificate file as a trust anchor or CA input. Both fan a
/// file out into every certificate it holds, so this is the bundle list. Only the platforms that
/// need a separate file dialog filter by extension; the combined macOS dialog does not, since a
/// folder has no extension to match.
#[cfg(not(target_os = "macos"))]
const CERT_EXTENSIONS: &[&str] = TA_BUNDLE_EXTENSIONS;

/// Extensions suggested for the trust anchor and CA pools: the bundle list plus the CBOR stores
/// this app itself exports, which those pools read as readily as they read a certificate.
const TA_POOL_EXTENSIONS: &[&str] = &[
    "der", "crt", "cer", "p7c", "p7b", "pem", "ta", "cbor", "pki",
];

/// Extensions suggested for the revocation pool. Only a suggestion, and a thin one: `.crl` is
/// conventional but nothing requires it, and an OCSP response has no settled extension at all —
/// which is why a permissive filter sits beside this one and why the contents, not the name,
/// decide what an artifact is.
const REV_POOL_EXTENSIONS: &[&str] = &["crl", "ocspResp", "ors", "resp", "der"];

/// Row with a labeled text input and a file selection dialog limited to files of the
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
fn UriCheckView() -> Element {
    let s_target = use_signal(String::new);
    let s_issuer = use_signal(String::new);
    let s_auto = use_signal(|| true);
    let mut s_running = use_signal(|| false);
    let mut s_report = use_signal(|| None::<UriCheckReport>);

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
        p { class: "hint",
            "Fetches the HTTP URIs in the certificate's AIA, SIA, CRL DP and freshest-CRL extensions and reports each one, independent of path processing. This is a check of the repositories, not of the certificate: it builds no path and reaches no verdict about trust. An issuer, supplied or auto-discovered, is what makes CRL signature verification and OCSP possible; without one those rows report that they could not be checked rather than failing."
        }
        div { class: "controls",
            FileRow {
                label: "Target certificate",
                name: "uri-target",
                sig: s_target,
                filter_name: "Certificate File",
                extensions: SINGLE_CERT_EXTENSIONS,
            }
            FileRow {
                label: "Issuer certificate (optional)",
                name: "uri-issuer",
                sig: s_issuer,
                filter_name: "Certificate File",
                extensions: SINGLE_CERT_EXTENSIONS,
            }
            div { class: "visible label-cell",
                label { "Issuer discovery: " }
            }
            div { class: "field check-group",
                CheckboxCell {
                    label: "Attempt auto-discovery if issuer not specified",
                    name: "uri-auto",
                    sig: s_auto,
                }
            }
        }
        div { class: "tool-actions",
            button {
                r#type: "button",
                disabled: s_running() || s_target().is_empty(),
                onclick: run_check,
                if s_running() {
                    "Checking\u{2026}"
                } else if s_target().is_empty() {
                    "Choose a certificate to check"
                } else {
                    "Check URIs"
                }
            }
            button {
                r#type: "button",
                disabled: s_report().is_none(),
                onclick: move |_| s_report.set(None),
                "Clear Results"
            }
        }
        if let Some(report) = s_report() {
            UriCheckResults { report }
        }
    }
}

/// Task views reachable from the sidebar
#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Validate,
    Generate,
    Cleanup,
    Inspect,
    CheckUris,
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
    (View::CheckUris, "Check URIs"),
    (View::Generate, "Generate"),
    (View::Cleanup, "Cleanup"),
    (View::Inspect, "Inspect"),
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
        div { class: "label-cell",
            label { r#for: "store", "Trust anchor / CA store: " }
        }
        div { class: "field",
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
                // Entries this process cannot use are shown disabled rather than omitted. A
                // machine store is unusable only because the app is not elevated, and that is worth
                // saying: an entry that simply vanished would be indistinguishable from a build
                // without the feature. Keeping the list the same length also keeps these option
                // values stable, which the selection signal indexes by.
                for (i, s) in stores::STORES.iter().enumerate() {
                    option {
                        value: "{i + 1}",
                        selected: sig() == i + 1,
                        disabled: !stores::is_accessible(i + 1),
                        "{s.label}"
                    }
                }
            }
            // Offered for a built-in store alone: a custom selection is already files on disk, so
            // there would be nothing to write that the user does not have, and webpki's anchors
            // are built during a run rather than held here.
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

/// Outcome of the last store export, shown until another one replaces it. A row of its own rather
/// than part of [`StoreHint`], which describes the store itself and should not be rewritten by an
/// action taken against it.
#[component]
fn StoreStatusRow(status: Signal<String>) -> Element {
    if status().is_empty() {
        return rsx! {};
    }
    rsx! {
        span { class: "hint", "{status}" }
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
        span { class: "hint",
            if has_ca {
                "Trust anchors and intermediate CAs from {store.pki}. "
            } else {
                "Trust anchors from {store.pki}. Supply intermediates below or turn on dynamic build. "
            }
            "{store.note}"
        }
    }
}

/// Action shown at the foot of each view, named for what it will do.
///
/// It said "Run Command(s)" everywhere, which named the command line the view assembles rather than
/// the thing the view is for; the plural belonged to a form that stood in for several invocations.
/// Each caller now supplies the sentence, as the browser frontend does.
///
/// `idle` is for a view whose action is switched off: pressing "Generate the store" with Generate
/// unchecked, or the Inspect button with nothing selected, assembles a run that does nothing and
/// reports nothing, which reads as the app failing rather than as the form being incomplete. The
/// button says what is missing instead. `nothing_to_do` names the sentence; an empty one leaves the
/// button enabled, which is what every view that always has something to do passes.
#[component]
fn RunButton(
    running: bool,
    onrun: EventHandler<()>,
    label: String,
    #[props(default)] nothing_to_do: String,
) -> Element {
    let idle = !nothing_to_do.is_empty();
    rsx! {
        div { style: "text-align:center",
            button {
                r#type: "button",
                class: "run-button",
                disabled: running || idle,
                onclick: move |_| onrun.call(()),
                if running {
                    "Running…"
                } else if idle {
                    "{nothing_to_do}"
                } else {
                    "{label}"
                }
            }
        }
    }
}

/// Restores the window's size and position, and keeps `~/.pittv3/window.json` in step with it.
///
/// **The geometry is applied to the live window, not through `WindowBuilder`.** Two earlier
/// attempts went through the builder and both failed there: a size handed to it is resolved against
/// whatever scale factor the system picks while the window is being created, which is where a
/// remembered 1640x1600 came back as a default-sized window in one direction and a doubled one in
/// the other. A window that already exists has a settled scale factor and reports its own position,
/// so what was asked for and what happened can be compared.
///
/// The default therefore needs no code: `main` builds the window at its usual size, and this either
/// overrides that or leaves it alone. See [`window_state::decide`] for when it declines.
fn remember_window_geometry() {
    let window = use_window();

    let restore = window.clone();
    use_hook(move || {
        let window = restore;
        let Some(saved) = window_state::load() else {
            return;
        };
        let displays: Vec<window_state::Display> = window
            .available_monitors()
            .map(|m| {
                let size = m.size();
                window_state::Display {
                    name: m.name(),
                    width: size.width,
                    height: size.height,
                }
            })
            .collect();

        if let Outcome::UseDefault(_) = window_state::decide(&saved, &displays) {
            return;
        }

        window.set_inner_size(PhysicalSize::new(saved.width, saved.height));
        window.set_outer_position(PhysicalPosition::new(saved.x, saved.y));

        // Verified rather than assumed. `current_monitor` is `NSWindow.screen`, which is nil
        // exactly when the window is on no screen at all -- the one condition worth undoing for,
        // and a measurement of what happened rather than a prediction of what would.
        if window.current_monitor().is_none() {
            if let Some(primary) = window.primary_monitor() {
                let p = primary.position();
                window.set_outer_position(PhysicalPosition::new(p.x + 40, p.y + 40));
            }
        }
    });

    let desktop = window.clone();
    // The size as the window last reported it. Taken from the `Resized` payload rather than by
    // asking the window afterwards: querying `inner_size()` in the handler returned the size the
    // window was built at no matter how it had been dragged, so moves were recorded and resizes
    // were not. The event carries the new size; that is the value to trust.
    let last_size = std::rc::Rc::new(std::cell::Cell::new(desktop.inner_size()));
    use_wry_event_handler(move |event, _| {
        let dioxus::desktop::tao::event::Event::WindowEvent { event, .. } = event else {
            return;
        };
        use dioxus::desktop::tao::event::WindowEvent;
        match event {
            WindowEvent::Resized(size) => last_size.set(*size),
            WindowEvent::Moved(_) => {}
            _ => return,
        }
        let Ok(position) = desktop.outer_position() else {
            // Reported unsupported on some platforms. A size with no position is not worth keeping:
            // restoring it would leave the window wherever the system chose anyway.
            return;
        };
        let size = last_size.get();
        window_state::save(window_state::WindowState {
            x: position.x,
            y: position.y,
            width: size.width,
            height: size.height,
            scale: desktop.scale_factor(),
            monitor: desktop.current_monitor().and_then(|m| m.name()),
        });
    });
}

/// Top-level application: sidebar task navigation over views that mirror the options offered by
/// the pittv3 command line utility
#[component]
pub(crate) fn App() -> Element {
    remember_window_geometry();

    let sa = use_hook(|| read_saved_args().unwrap_or_default());

    // A run against a built-in store saves the cache paths it wrote into the CBOR arguments. What
    // is restored from that is the selection; showing the cache paths back as if the user had
    // typed them would invite editing a file the next run overwrites.
    #[cfg(all(windows, feature = "capi"))]
    let saved_capi = sa.capi_ta_stores.clone();
    #[cfg(not(all(windows, feature = "capi")))]
    let saved_capi: Vec<String> = vec![];
    // Restored alongside the anchor store because two entries name the same one and differ only in
    // whether they write.
    #[cfg(all(windows, feature = "capi"))]
    let saved_capi_rw = sa.capi_ca_store_rw.clone();
    #[cfg(not(all(windows, feature = "capi")))]
    let saved_capi_rw: Option<String> = None;
    let saved_store =
        use_hook(|| stores::selection_for(&sa.ta_cbor, sa.webpki_tas, &saved_capi, &saved_capi_rw));
    let from_store = saved_store != stores::CUSTOM;
    let saved_or_empty = |v: &Option<String>| {
        if from_store {
            String::new()
        } else {
            v.clone().unwrap_or_default()
        }
    };

    // The four input pools the Validate view edits. Seeded from the saved arguments, and — for the
    // trust anchor and CA pools — from the singular arguments a run saved before the pools existed,
    // so a form filled in by an older build comes back as the same inputs rather than as an empty
    // list. The store selection is the exception: it writes the cache paths it materialized into
    // `ta_cbor`/`cbor`, and folding those into a pool the user can edit would invite editing a file
    // the next run overwrites, which is what `saved_or_empty` already guards.
    let s_ta_inputs = use_signal(|| {
        let mut v = sa.ta_inputs.clone();
        if !from_store {
            v.extend(sa.ta_cbor.clone().filter(|p| !p.is_empty()));
        }
        v.extend(sa.ta_folder.clone().filter(|p| !p.is_empty()));
        dedup_pool(v)
    });
    let s_ca_inputs = use_signal(|| {
        let mut v = sa.ca_inputs.clone();
        if !from_store {
            v.extend(sa.cbor.clone().filter(|p| !p.is_empty()));
        }
        v.extend(sa.ca_folder.clone().filter(|p| !p.is_empty()));
        dedup_pool(v)
    });
    let s_ee_inputs = use_signal(|| {
        let mut v = sa.ee_inputs.clone();
        v.extend(sa.end_entity_file.clone().filter(|p| !p.is_empty()));
        v.extend(sa.end_entity_folder.clone().filter(|p| !p.is_empty()));
        dedup_pool(v)
    });
    // Two rows, so each kind can be cleared or pruned without touching the other, and one saved
    // list, because `rev_inputs` is what the run takes. Which row a saved path came from is
    // therefore not recorded and is recovered by reading the files.
    //
    // That read is the same work the counts do and is done the same way -- on a worker thread,
    // since a pool naming a folder of CRLs would otherwise stall the WebView on startup. So
    // everything starts in the CRL row and the OCSP entries move out when the read returns.
    // Correct at every instant rather than merely at the end: the rows concatenate into one
    // argument, so a run started before the sort lands takes exactly the same material, and each
    // row reports its contents by kind throughout, so the CRL row says what it is holding while it
    // is still holding both.
    let mut s_crl_inputs = use_signal(|| sa.rev_inputs.clone());
    let mut s_ocsp_inputs = use_signal(Vec::<String>::new);
    use_hook(|| {
        let saved = sa.rev_inputs.clone();
        if saved.is_empty() {
            return;
        }
        let (tx, mut rx) = futures_channel::mpsc::unbounded::<(Vec<String>, Vec<String>)>();
        std::thread::spawn(move || {
            let (ocsp, crl): (Vec<String>, Vec<String>) =
                saved.into_iter().partition(|p| is_ocsp_only(p));
            let _ = tx.unbounded_send((crl, ocsp));
        });
        // Written on the UI executor, like every other signal write off a worker thread. Applied
        // only if nothing was added meanwhile, so a file dropped in during the read is not lost to
        // a wholesale replacement.
        spawn(async move {
            if let Some((crl, ocsp)) = rx.next().await {
                if ocsp.is_empty() {
                    return;
                }
                let added = s_crl_inputs().len() != crl.len() + ocsp.len();
                if !added {
                    s_crl_inputs.set(crl);
                    s_ocsp_inputs.set(ocsp);
                }
            }
        });
    });
    // Not persisted with the arguments: a host is the way a target was *obtained*, and what the run
    // validates is the file that came back. Restoring the host would suggest the next run re-asks.
    let s_peek_host = use_signal(String::new);
    let mut s_peek_status = use_signal(String::new);
    let mut s_peeking = use_signal(|| false);

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

    // What those pools hold, kept current beside them. Recounted whenever a pool changes and
    // whenever the time of interest does, because loading drops material not valid at that time and
    // so the count is an answer as of a moment.
    //
    // Two generations of the same counter: `counts_seq` is bumped by the effect that asks for a
    // count and read by both the worker (before it starts, as a debounce) and the task that applies
    // the result (before it writes, so a slow count over a folder cannot overwrite a fast one over
    // the empty pool that replaced it).
    let mut s_pool_counts = use_signal(PoolCounts::default);
    let counts_seq = use_hook(|| Arc::new(AtomicUsize::new(0)));
    let counts_tx = use_hook(|| {
        let (tx, mut rx) = futures_channel::mpsc::unbounded::<(usize, PoolCounts)>();
        let seq = counts_seq.clone();
        // Signals are written here, on the UI executor, and never from the worker thread.
        spawn(async move {
            while let Some((generation, counts)) = rx.next().await {
                if generation == seq.load(Ordering::SeqCst) {
                    s_pool_counts.set(counts);
                }
            }
        });
        tx
    });
    use_effect({
        let counts_seq = counts_seq.clone();
        let counts_tx = counts_tx.clone();
        move || {
            let generation = counts_seq.fetch_add(1, Ordering::SeqCst) + 1;
            spawn_pool_count(
                PoolInputs {
                    ta: pool(s_ta_inputs),
                    ca: pool(s_ca_inputs),
                    crl: pool(s_crl_inputs),
                    ocsp: pool(s_ocsp_inputs),
                    ee: pool(s_ee_inputs),
                    time_of_interest: s_time_of_interest()
                        .parse::<u64>()
                        .unwrap_or_else(|_| get_now_as_unix_epoch()),
                },
                generation,
                counts_seq.clone(),
                counts_tx.clone(),
            );
        }
    });
    // Offered into the field like the folder defaults, so what governs logging is visible and can
    // be edited or cleared. The file it names is written from a template when the run needs it.
    let s_logging_config =
        use_signal(|| saved_or_default(sa.logging_config.clone(), default_log_config_path));
    let s_error_folder =
        use_signal(|| saved_or_default(sa.error_folder.clone(), default_error_folder));
    // Same shape as the settings file below: a saved value wins, otherwise a default under
    // ~/.pittv3 so a machine that has never been configured is not refused on its first run. The
    // default is put *into the field* rather than resolved behind it, so what the run will use is
    // visible and can be changed or cleared.
    let s_download_folder =
        use_signal(|| saved_or_default(sa.download_folder.clone(), default_download_folder));
    let s_ca_folder = use_signal(|| saved_or_default(sa.ca_folder.clone(), default_ca_folder));
    let s_generate = use_signal(|| sa.generate);
    let s_chase_aia_and_sia = use_signal(|| sa.chase_aia_and_sia);
    let s_cbor_ta_store = use_signal(|| sa.cbor_ta_store);
    let s_validate_all = use_signal(|| sa.validate_all);
    let s_check_uris = use_signal(|| sa.check_uris_when_validating);
    // Held in the browser's polarity, not the argument's. `Pittv3Args` carries the CLI's
    // `no_revocation_cache`, because a clap bool flag names a deviation from the default; a
    // checkbox names a state, and the browser already settled which state it shows. Inverting here
    // keeps the two apps' controls reading the same way round -- see the wasm app's
    // "Reuse revocation determinations".
    let s_reuse_rev_cache = use_signal(|| !sa.no_revocation_cache);
    // Owned here rather than made per run, so a certificate checked on one Validate is not checked
    // again on the next. `Arc<RevocationCache>` implements `RevocationStatusCache` for exactly this
    // -- the run registers a clone and the handle stays here to be cleared.
    let rev_cache = use_hook(|| Arc::new(RevocationCache::new()));
    // Owned here for the same reason and on the same terms: a run leaves the certificates it
    // prepared here, and the next run over the same material takes them rather than deserializing
    // the store and parsing and indexing every certificate again. Nothing has to invalidate it --
    // the key covers the inputs, the settings and the time of interest -- so the button that empties
    // it is about releasing the memory, not about being right.
    let prepared_graph = use_hook(|| Arc::new(PreparedGraph::new()));
    let rev_cache_for_toggle = rev_cache.clone();
    let mut s_rev_cache_status = use_signal(String::new);
    // Turning reuse off and on again must not bring back the determinations the user was trying to
    // stop reusing, so the toggle clears -- the browser's rule, and its reason. It fires once on
    // first render against an empty cache, which costs nothing.
    //
    // What the desktop cannot do that the browser does is clear on a settings change: settings here
    // live in a file that can change without the app being told, and a cached answer vetted under
    // one revocation policy is not vetted under a stricter one, nor valid again if the time of
    // interest moves backward. That is what the Clear button is for, and why its hint says so.
    use_effect(move || {
        let _ = s_reuse_rev_cache();
        rev_cache_for_toggle.clear();
    });
    let s_validate_self_signed = use_signal(|| sa.validate_self_signed);
    let s_dynamic_build = use_signal(|| sa.dynamic_build);
    // No control: the run always builds from what earlier runs downloaded. The toggle that used to
    // sit here was really "I do not trust what has piled up in that folder", and the Cleanup and
    // Purge buttons answer that directly -- the folder gets fixed instead of routed around. The CLI
    // keeps `--use-downloaded-cas` for a genuinely self-contained run.
    let s_use_downloaded_cas = use_signal(|| true);
    let mut s_folder_status = use_signal(String::new);
    let s_results_folder = use_signal(|| sa.results_folder.clone().unwrap_or_default());
    // Effective settings file. Saved args win; otherwise the default in ~/.pittv3 so the app always
    // has settings, matching the browser frontend where localStorage always answers. The file need
    // not exist — read_settings treats a missing path as "all defaults".
    let mut s_settings =
        use_signal(|| saved_or_default(sa.settings.clone(), default_settings_path));
    // Bumped to ask the settings form to read its file again when the path has not changed --
    // Revert to Saved, and Delete, which leaves nothing to read. The form seeds once per mount, so
    // it is keyed on this alongside the path.
    let mut s_settings_gen = use_signal(|| 0usize);
    // Whether the settings form holds edits the file has not seen. The form reports it because only
    // the form knows; it is held here because the sidebar that navigates away from the form is here.
    let mut s_settings_dirty = use_signal(|| false);
    let s_crl_folder = use_signal(|| saved_or_default(sa.crl_folder.clone(), default_crl_folder));
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

    // run state: the validation run executes on a worker thread so the WebView stays responsive;
    // results and log output flow back over channels and are applied to signals on the UI side only
    let mut s_view = use_signal(|| View::Validate);
    let mut s_running = use_signal(|| false);
    let mut s_report = use_signal(|| None::<ValidationReport>);
    // What the last run kept, so the results view can save the artifacts behind it without
    // validating a second time. Held outside the signal system because the run produces it on a
    // worker thread; see `save::RetainedArtifacts`.
    let retained: RetainedArtifacts = use_hook(|| Arc::new(Mutex::new(None)));
    // The moment the run began, which is what its saved artifacts are named after. Held so the
    // archive and the path log carry the same name: they are separate buttons, so stamping at each
    // save gave one run two names differing by however long the user took between clicks. `None`
    // until a run starts, which the save buttons are disabled for anyway.
    let mut s_run_stamp = use_signal(|| None::<u64>);
    // What the last run was launched with, kept for the bundle's inputs half. Held rather than
    // re-read at save time for the same reason the stamp is: the form goes on being editable after
    // a run, and a bundle that reports the form describes inputs its evidence was not produced
    // under. Set beside the stamp so the two cannot disagree about which run they describe.
    let mut s_run_inputs = use_signal(|| None::<(Pittv3Args, Option<String>)>);
    let mut s_export_name = use_signal(|| DEFAULT_EXPORT_NAME.to_string());
    // Whether the last run left anything to save. The artifacts live behind a mutex the worker
    // thread fills, which the rsx cannot observe, so the buttons key off this instead.
    let mut s_can_export = use_signal(|| false);
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
            // The Validate view's pools. Passed alongside the singular arguments rather than
            // instead of them, because those still have rows on Generate, Cleanup and Inspect
            // and are the same arguments; an input named twice is carried once, since `push`
            // deduplicates on both the anchor and the certificate side.
            ta_inputs: pool(s_ta_inputs),
            // Set by the store selector alone. As a checkbox this could be combined with any other
            // anchor set, which is the two-TaSource case load_trust_anchors merges its own inputs
            // to avoid; a single-select control cannot express it.
            webpki_tas: stores::is_webpki(s_store()),
            // Also set by the store selector alone, and for the same reason. Unlike the material a
            // provider entry writes out, these name live stores that a run reads at the moment it
            // starts, so a certificate installed since the selection was made is seen.
            #[cfg(all(windows, feature = "capi"))]
            capi_ta_stores: stores::capi_stores(s_store()).0,
            #[cfg(all(windows, feature = "capi"))]
            capi_ca_stores: stores::capi_stores(s_store()).1,
            // Set only by the writable entry in the selector, so a run writes to a Windows store
            // because that entry was chosen and not because dynamic build happened to be on.
            #[cfg(all(windows, feature = "capi"))]
            capi_ca_store_rw: stores::capi_stores(s_store()).2,
            cbor: store_cbor.or_else(|| path_or_none(s_cbor)),
            time_of_interest: s_time_of_interest()
                .parse::<u64>()
                .unwrap_or_else(|_| get_now_as_unix_epoch()),
            logging_config: path_or_none(s_logging_config),
            error_folder: path_or_none(s_error_folder),
            download_folder: path_or_none(s_download_folder),
            ca_folder: path_or_none(s_ca_folder),
            ca_inputs: pool(s_ca_inputs),
            generate: s_generate(),
            chase_aia_and_sia: s_chase_aia_and_sia(),
            cbor_ta_store: s_cbor_ta_store(),
            validate_all: s_validate_all(),
            check_uris_when_validating: s_check_uris(),
            validate_self_signed: s_validate_self_signed(),
            dynamic_build: s_dynamic_build(),
            use_downloaded_cas: s_use_downloaded_cas(),
            // No singular counterpart: unlike the trust anchor and CA arguments these had rows on
            // the Validate view alone, so the pool replaced them outright rather than joining them.
            // Sending both would validate a target named in each of them twice.
            end_entity_file: None,
            end_entity_folder: None,
            ee_inputs: pool(s_ee_inputs),
            results_folder: path_or_none(s_results_folder),
            settings: path_or_none(s_settings),
            crl_folder: path_or_none(s_crl_folder),
            // One argument, both rows: the split is how the material is offered, not how it is
            // consumed -- `load_revocation_inputs` sorts by content on the way in.
            rev_inputs: [pool(s_crl_inputs), pool(s_ocsp_inputs)].concat(),
            keep_crl_entries_in_memory: false,
            no_revocation_cache: !s_reuse_rev_cache(),
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

    // Takes what a host presents and files it across the pools it belongs in. Spawned rather than
    // awaited so the window stays live during a handshake against a host that is slow to answer.
    // Why the peek button is inert, answered before anything is attempted. The desktop reaches only
    // the two conditions that are about the form itself; the browser adds two more about whether a
    // service is there to make the handshake at all.
    let peek_blocked_because = move || -> Option<String> {
        if s_peeking() {
            return Some("A handshake is now running.".to_string());
        }
        if s_peek_host().trim().is_empty() {
            return Some("Enter a host to take the certificates from.".to_string());
        }
        None
    };

    let mut take_presented = move |_: ()| {
        if s_peeking() {
            return;
        }
        let host = s_peek_host().trim().to_string();
        if host.is_empty() {
            return;
        }
        s_peeking.set(true);
        s_peek_status.set(format!("Asking {host} for its certificates..."));
        spawn(async move {
            match peek::take_presented_certificates(&host).await {
                Ok(peeked) => {
                    s_peek_status.set(peeked.summary());
                    extend_pool(s_ee_inputs, vec![peeked.end_entity]);
                    extend_pool(s_ca_inputs, peeked.chain);
                    if let Some(response) = peeked.stapled_ocsp {
                        extend_pool(s_ocsp_inputs, vec![response]);
                    }
                }
                Err(msg) => {
                    error!("{msg}");
                    s_peek_status.set(msg);
                }
            }
            s_peeking.set(false);
        });
    };

    let run_command = {
        let retained = retained.clone();
        let rev_cache = rev_cache.clone();
        let prepared_graph = prepared_graph.clone();
        move |_: ()| {
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
                // Written only when absent, so an edited file is never replaced. Without a
                // destination to substitute there is nothing to write, and the load below fails
                // through to the built-in configuration.
                if let Some(log_file) = default_log_file() {
                    logging::ensure_config_file(logging_config, &log_file);
                }
                // `deserializers()` rather than `Default::default()`: the template names the
                // channel appender that feeds the Results view, and the default registry cannot
                // resolve it.
                if let Err(e) = log4rs::init_file(logging_config, logging::deserializers()) {
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

                // A file as well, because the other two do not survive the run: an application
                // launched from the Finder has no stdout to read, and the channel appender feeds a
                // view that is cleared by the next run. Rolling rather than plain -- 5 MB across
                // four files, so a session that logs heavily is bounded at 20 MB and needs no
                // maintenance action of its own. A log4rs file named in the settings replaces all
                // of this, which is what that setting is for.
                let file = default_log_file().and_then(|path| {
                    let roll = FixedWindowRoller::builder()
                        .build(&format!("{path}.{{}}"), 3)
                        .ok()?;
                    let policy = CompoundPolicy::new(
                        Box::new(SizeTrigger::new(5 * 1024 * 1024)),
                        Box::new(roll),
                    );
                    RollingFileAppender::builder()
                        .encoder(Box::new(PatternEncoder::new("{d} {l} {t} - {m}{n}")))
                        .build(&path, Box::new(policy))
                        .ok()
                });

                let mut builder = Config::builder()
                    .appender(Appender::builder().build("stdout", Box::new(stdout)))
                    .appender(Appender::builder().build("channel", Box::new(ChannelAppender)));
                let mut root = Root::builder().appender("stdout").appender("channel");
                if let Some(file) = file {
                    builder = builder.appender(Appender::builder().build("file", Box::new(file)));
                    root = root.appender("file");
                }
                match builder.build(root.build(LevelFilter::Info)) {
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
            // A fresh run replaces what the previous one kept, so the buttons never offer artifacts
            // belonging to a run that is no longer on screen.
            if let Ok(mut held) = retained.lock() {
                *held = None;
            }
            s_can_export.set(false);
            s_run_stamp.set(Some(now_as_unix_epoch()));
            s_run_inputs.set(Some((args.clone(), stores::env_for(s_store()))));
            let run_cache = rev_cache.clone();
            let run_prepared = prepared_graph.clone();
            let run_retained = retained.clone();
            let done_retained = retained.clone();

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
                // Retention is asked for here and nowhere else: the desktop offers the artifacts after
                // a run, so it keeps what the run built. The CLI passes false and pays nothing.
                let (report, run_artifacts) = rt.block_on(options_std_retaining(
                    &args,
                    true,
                    Some(&run_cache),
                    Some(&run_prepared),
                ));
                if let Ok(mut held) = run_retained.lock() {
                    *held = run_artifacts;
                }
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
                            // A run happened, so there is something to export -- a run that found
                            // no paths still has the inputs it was given and a run-level account of
                            // itself, which is the evidence that answers why it found nothing. The
                            // state that leaves nothing is no run at all.
                            s_can_export.set(
                                done_retained
                                    .lock()
                                    .map(|held| held.is_some())
                                    .unwrap_or(false),
                            );
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
        }
    };

    // Saves every retained path's artifacts as one zip -- the same archive the browser downloads,
    // written where the user says instead of into a download.
    let save_artifacts = {
        let retained = retained.clone();
        move |_: MouseEvent| {
            let retained = retained.clone();
            let name = stamped_export_name(
                &s_export_name(),
                s_run_stamp().unwrap_or_else(now_as_unix_epoch),
            );
            // The environment halves, from the run's cache where there is one and from the files
            // the run read where there is not.
            //
            // **The cache is not enough on its own, which is what the first bundles showed.**
            // `fingerprint_for_args` answers `None` for a store used by itself, because such a
            // store already carries its partial paths and nothing needs building -- so the most
            // ordinary run there is produced a bundle with no environment in it at all, and a
            // command line that would have found no trust anchors. The cache is preferred because
            // it holds what a built graph actually became; the files are the fallback and are the
            // same bytes for a store that was only read.
            let inputs = match s_run_inputs() {
                None => RunInputs::default(),
                Some((args, store)) => {
                    let fingerprint = graph_cache::fingerprint_for_args(&args);
                    RunInputs {
                        anchors: fingerprint
                            .as_deref()
                            .and_then(graph_cache::cached_anchors)
                            .or_else(|| read_input_file(&args.ta_cbor))
                            .or_else(|| pool_includes_ta_store(&read_pool(&args.ta_inputs))),
                        // The store as the run read it, always, so it stays comparable -- from
                        // the singular argument, or from whichever pooled input is itself a store.
                        graph: read_input_file(&args.cbor)
                            .or_else(|| pool_includes_ca_store(&read_pool(&args.ca_inputs))),
                        // And what the run made of it, when it built anything. Kept alongside
                        // rather than written over `ca.cbor`, which is what this did at first --
                        // a built graph saved under that name looks like a store snapshot and is
                        // not one, and nothing in the file says so.
                        built_graph: fingerprint.as_deref().and_then(graph_cache::cached),
                        // The targets the run was asked about. Supplied here because the run's own
                        // retained state records them per validated path, and a run that found no
                        // paths would otherwise carry no target at all -- which is the certificate
                        // such a bundle exists to explain.
                        end_entities: read_targets(&args),
                        validate_all: args.validate_all,
                        store,
                        ..Default::default()
                    }
                }
            };
            let run_ms = s_report().map(|r| r.duration_ms);
            spawn(async move {
                match save::artifacts_archive(&retained, &name, inputs, run_ms) {
                    Ok(None) => s_log
                        .write()
                        .push("No run is held to save. Validate something first.".to_string()),
                    Err(e) => s_log
                        .write()
                        .push(format!("Failed to build the archive: {e}")),
                    Ok(Some(bytes)) => {
                        write_export(format!("{name}.zip"), &["zip"], bytes, s_log).await
                    }
                }
            });
        }
    };

    // Saves the manifests alone: every path's account of itself, without the material behind them.
    let save_path_logs = {
        let retained = retained.clone();
        move |_: MouseEvent| {
            let retained = retained.clone();
            let name = stamped_export_name(
                &s_export_name(),
                s_run_stamp().unwrap_or_else(now_as_unix_epoch),
            );
            spawn(async move {
                // The run figure comes from the report on screen, which is the run these paths
                // were retained from.
                match save::path_logs_text(&retained, s_report().map(|r| r.duration_ms)) {
                    None => s_log
                        .write()
                        .push("No run is held to save. Validate something first.".to_string()),
                    Some(text) => {
                        write_export(format!("{name}.txt"), &["txt"], text.into_bytes(), s_log)
                            .await
                    }
                }
            });
        }
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
            // Leaving the settings form is the only way to discard its edits now that saving no
            // longer navigates away, so it is the one transition that asks. Selecting Settings
            // again while already there is not a departure and must not prompt.
            on_select: move |i: usize| {
                let to = VIEWS[i].0;
                let leaving_dirty =
                    s_view() == View::Settings && to != View::Settings && s_settings_dirty();
                match leaving_dirty {
                    true => {
                        spawn(async move {
                            if leave_settings_ok(true).await {
                                s_view.set(to);
                            }
                        });
                    }
                    false => s_view.set(to),
                }
            },
            {
                match s_view() {
                    View::Validate => {
                        // Named for what the run will do, and counting what it will judge: a
                        // folder in the pool is one entry and as many targets as it holds, so the
                        // number on the button comes from the same count as the row above rather
                        // than from the length of the pool.
                        let targets = s_pool_counts().end_entities;
                        let validate_label = match targets {
                            0 => "Validate using the current store and settings".to_string(),
                            1 => "Validate 1 certificate using the current store and settings"
                                .to_string(),
                            n => format!(
                                "Validate {n} certificates using the current store and settings"
                            ),
                        };
                        rsx! {
                            // Peer boxes rather than a nesting, matching the wasm frontend: the store,
                            // the material that supplements it, the revocation artifacts, the targets
                            // and the run's own settings are five things a run needs, not one inside
                            // another. The store had been unboxed content at the head of a "PKI
                            // Environment" group, which read as though the panels below belonged to it.
                            div { class: "panel",
                                div { class: "controls",
                                    StoreRow { sig: s_store, status: s_store_export }
                                    StoreHint { selection: s_store() }
                                    StoreStatusRow { status: s_store_export }
                                }
                            }
                            // Supplementary material, collapsed: a store selection above is a
                            // complete environment on its own, so these open the form only for
                            // the runs that add to it. Open by default for a custom selection,
                            // where they are not supplementary but the whole of the trust
                            // material and an empty panel would hide the fields a run needs.
                            //
                            // Also open whenever the pools hold anything, whatever the store is.
                            // Collapsed-and-occupied is the one state that misleads: the panel
                            // reads as "nothing here" while the run takes material the form is
                            // not showing, and an input left over from an earlier run is then
                            // invisible rather than merely tidied away.
                            details {
                                class: "panel",
                                open: s_store() == stores::CUSTOM
                                    || !s_ta_inputs().is_empty()
                                    || !s_ca_inputs().is_empty(),
                                summary {
                                    if s_store() == stores::CUSTOM {
                                        "Trust anchors and certification authorities"
                                    } else {
                                        "Additional trust anchors and certification authorities"
                                    }
                                }
                                div { class: "controls",
                                    // One list per kind rather than a box per shape. A trust
                                    // anchor set is assembled from whatever the material arrived
                                    // as, and every shape the old rows took apart — a folder, a
                                    // certificate, a bundle, a CBOR store — is decided from the
                                    // path and then from the bytes, so sorting them into separate
                                    // arguments was work the run can do instead.
                                    PoolRow {
                                        label: "Trust Anchors",
                                        name: "ta",
                                        sig: s_ta_inputs,
                                        filter_name: "Trust anchor, bundle or CBOR store",
                                        extensions: TA_POOL_EXTENSIONS,
                                        contents: plural(
                                            s_pool_counts().trust_anchors,
                                            "trust anchor",
                                        ),
                                    }
                                    // Shown whatever dynamic build is set to. This pool is `--ca`,
                                    // which `load_ca_inputs` folds into the graph on the first pass
                                    // regardless; the row that changes role under dynamic build is the
                                    // singular `--ca-folder` in the run settings, which then doubles as
                                    // the place fetched certificates are written. Hiding this one with
                                    // that one cost a working input its control.
                                    PoolRow {
                                        label: "Intermediate CA Certificates",
                                        name: "ca",
                                        sig: s_ca_inputs,
                                        filter_name: "CA certificate, bundle or CBOR store",
                                        extensions: TA_POOL_EXTENSIONS,
                                        contents: plural(
                                            s_pool_counts().ca_certificates,
                                            "certificate",
                                        ),
                                    }
                                }
                            }
                            // Revocation material is optional in the same way, and a run that
                            // supplies none is the common one -- so this one opens on content and
                            // not on the store selection, which says nothing about revocation.
                            // The CRL folder counts only when it is not the default, which is
                            // always set; see `is_chosen`.
                            details {
                                class: "panel",
                                open: !s_crl_inputs().is_empty() || !s_ocsp_inputs().is_empty(),
                                summary { "Revocation data (CRLs and OCSP responses)" }
                                div { class: "controls",
                                    // Read-only, unlike the CRL folder below it, which is an index:
                                    // that folder is written as well as read, and indexing deletes
                                    // any CRL not valid at the time of interest.
                                    // Two rows for one argument. They are not filtered apart --
                                    // an OCSP response has no settled extension, and an `accept`
                                    // list greys out whatever it failed to anticipate -- so both
                                    // offer the same files and each reports what it is actually
                                    // holding. What the split buys is being able to clear or prune
                                    // one kind without disturbing the other, which one list cannot
                                    // offer however it is counted.
                                    PoolRow {
                                        label: "CRLs",
                                        name: "rev",
                                        sig: s_crl_inputs,
                                        filter_name: "CRL",
                                        extensions: REV_POOL_EXTENSIONS,
                                        contents: revocation_contents(&s_pool_counts().crl_pool),
                                    }
                                    PoolRow {
                                        label: "OCSP Responses",
                                        name: "ocsp",
                                        sig: s_ocsp_inputs,
                                        filter_name: "OCSP response",
                                        extensions: REV_POOL_EXTENSIONS,
                                        contents: revocation_contents(&s_pool_counts().ocsp_pool),
                                    }
                                }
                            }
                            fieldset {
                                EndEntityGroup {
                                    certificates_row: rsx! {
                                        PoolRow {
                                            label: "End Entity Certificates",
                                            name: "ee",
                                            sig: s_ee_inputs,
                                            filter_name: "Certificate File",
                                            extensions: SINGLE_CERT_EXTENSIONS,
                                            contents: plural(
                                                s_pool_counts().end_entities,
                                                "certificate",
                                            ),
                                        }
                                    },
                                    peek_host: s_peek_host,
                                    on_peek: move |_| take_presented(()),
                                    // The desktop opens the socket itself: `pittv3-relay` makes the
                                    // handshake in process, so nothing about the host leaves the
                                    // machine on its way to being asked.
                                    peek_actor: "This app",
                                    peek_blocked_because: peek_blocked_because(),
                                    peek_status: s_peek_status(),
                                }
                            }
                            // How a run behaves, as against what it judges: the settings file it
                            // honors, the time it judges against, and the switches that change how
                            // paths are built. A peer of the boxes above, not a tail on the targets.
                            div { class: "panel",
                                // The settings file is named on the Settings view, which owns both
                                // the path and the form over it; a second copy of the path here was
                                // the same signal behind a second picker. What is kept is the one
                                // thing that view cannot say: with no file named, a run falls back
                                // to certval's own defaults, and nothing else on this page shows it.
                                if s_settings().is_empty() {
                                    div { class: "controls center-row",
                                        span { class: "hint",
                                            "No settings file, so this run will use certval defaults."
                                        }
                                    }
                                }
                                // Time of interest is not here: it is a certification path setting,
                                // the settings form already edits it, and `options_std` honors the
                                // setting over the argument -- so a field here would have been the
                                // one that loses. The download and CA folders are likewise already
                                // rows on the settings form's Folders tab, and a run now reads them
                                // from there when the arguments do not carry them.
                                // One grid, not three: `max-content` is measured per grid, so a
                                // checkbox in a grid of its own lands at whatever x its own label
                                // happens to need and none of them line up.
                                div { class: "controls",
                                    CheckboxRow {
                                        label: "Validate all paths",
                                        name: "validate-all",
                                        sig: s_validate_all,
                                        title: "Off stops at the first valid path; on reports every path found.",
                                    }
                                    CheckboxRow {
                                        label: "Check URIs when validating",
                                        name: "check-uris-when-validating",
                                        sig: s_check_uris,
                                        title: "Runs the URI checker over every certificate on each path and appends the results to that path's log. Each certificate is checked once per run. Retrieves from the repositories the certificates name, so it needs network access.",
                                    }
                                    CheckboxRow {
                                        label: "Dynamic Build",
                                        name: "dynamic-build",
                                        sig: s_dynamic_build,
                                        title: "Fetch missing intermediates by following AIA and SIA URIs. They are written to the download folder, or the CA folder when none is set; name one on the Settings view.",
                                    }

                                    // Label and hint are the browser's, verbatim: the same setting
                                    // reading two ways round in the two apps is the divergence, not
                                    // the wording. `arg_help` is not used here because it describes
                                    // the argument, which is the negative of what this box shows.
                                    // Kept in the main group rather than under Advanced because its
                                    // absence is silent -- a run that reuses determinations produces
                                    // a bundle short of evidence and says nothing about it.
                                    CheckboxRow {
                                        label: "Reuse revocation determinations",
                                        name: "no-revocation-cache",
                                        sig: s_reuse_rev_cache,
                                        title: "On, a certificate checked on one path is not checked again on another, including across runs. Off, every path obtains its own revocation data - slower, but each path then carries the evidence for its own result, which an export needs.",
                                    }
                                    // Clearing is its own action rather than a side effect of the
                                    // checkbox, which is the browser's arrangement and for its
                                    // reason: turning reuse off to clear also changes how the run
                                    // behaves, giving up the retrievals reuse would have spared.
                                    //
                                    // Emitted as grid children of the surrounding `.controls`, like
                                    // every other row: a nested div becomes one grid item, blows out
                                    // the `max-content` label column and pushes the rest off the
                                    // view. The explanation is the button's tooltip rather than
                                    // standing text, for the reason CheckboxRow's `title` documents.
                                    div { class: "visible label-cell",
                                        label { "Cached determinations: " }
                                    }
                                    div { class: "field",
                                        button {
                                            title: "Discards what has been determined so far without changing whether reuse is on. Use it after changing settings or the time of interest: a determination reached under the old ones is not re-checked against the new.",
                                            onclick: {
                                                let rev_cache = rev_cache.clone();
                                                move |_| {
                                                    rev_cache.clear();
                                                    s_rev_cache_status
                                                        .set(
                                                            "Revocation determinations cleared."
                                                                .to_string(),
                                                        );
                                                }
                                            },
                                            "Clear cached determinations"
                                        }
                                    }
                                    // Transient, not standing text: it appears only after a click.
                                    if !s_rev_cache_status().is_empty() {
                                        span { class: "hint", "{s_rev_cache_status}" }
                                    }
                                }
                                details { class: "advanced",
                                    summary { "Advanced" }
                                    div { class: "controls",
                                        div { class: "field check-group",
                                            // "WebPKI TAs" was here. It is an anchor set, so it is
                                            // an entry in the store selector now — see StoreSource.
                                            CheckboxCell { label: "Validate Self-Signed", name: "validate-self-signed", sig: s_validate_self_signed }
                                        }
                                        // The environment the last run over these inputs used,
                                        // which exists as files only because it is cached: nothing
                                        // else writes the assembled anchors and the merged graph
                                        // out as a pair.
                                        div { class: "field",
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
                                        if !s_graph_export().is_empty() {
                                            span { class: "hint", "{s_graph_export}" }
                                        }
                                    }
                                }
                            }
                            RunButton {
                                running: s_running(),
                                onrun: run_command,
                                label: validate_label,
                                // Gated on the pool being empty rather than on the target count
                                // being zero, which is the tempting test and the wrong one: the
                                // count is produced on a worker thread behind a debounce, so it
                                // reads zero for the first moments of every session and for as
                                // long as a large pool takes to read. Disabling on it would grey
                                // the button while the row above says the material is there.
                                // The pool is known immediately and is what the user acted on.
                                //
                                // A pool that holds only an empty folder therefore stays enabled,
                                // and the run says it found nothing to judge -- the honest answer
                                // to "validate what I pointed you at" when it turns out to hold
                                // nothing.
                                nothing_to_do: match s_ee_inputs().is_empty() {
                                    true => "Add a certificate to validate",
                                    false => "",
                                },
                            }
                        }
                    }
                    View::Generate => rsx! {
                        div { class: "controls",
                            PathRow {
                                label: "TA Folder or File",
                                name: "ta-folder",
                                sig: s_ta_folder,
                            }
                            FileRow {
                                label: "Mozilla CSV",
                                name: "mozilla-csv",
                                sig: s_mozilla_csv,
                                filter_name: "CSV file",
                                extensions: ["csv"].as_slice(),
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
                            TimeRow { label: "Time of Interest", name: "time-of-interest", sig: s_time_of_interest }
                            // Labelled like every other row. An unlabelled field lands in the
                            // grid's first column, which is the label column.
                            div { class: "visible label-cell",
                                label { "Actions: " }
                            }
                            // Both of these are consulted only while generating -- see
                            // `chase_aia_and_sia` and `cbor_ta_store` in `args.rs` -- so with
                            // Generate off they are settable controls that change nothing.
                            // Disabled rather than hidden, and the signals are left alone: the
                            // choice comes back with the control.
                            div { class: "field check-group",
                                CheckboxCell { label: "Generate", name: "generate", sig: s_generate }
                                CheckboxCell {
                                    label: "Chase SIA and AIA",
                                    name: "chase-aia-and-sia",
                                    sig: s_chase_aia_and_sia,
                                    disabled: !s_generate(),
                                }
                                CheckboxCell {
                                    label: "CBOR TA store",
                                    name: "cbor-ta-store",
                                    sig: s_cbor_ta_store,
                                    disabled: !s_generate(),
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
                        // Both output rows bind the same `s_cbor` signal, because `--generate`
                        // writes to `--cbor` whichever kind of store it is making. Flipping
                        // CBOR TA store therefore relabels the row and keeps the path, so a
                        // path picked for one kind is reused for the other without saying so.
                        // The row's own label cannot show that -- the label is what changed --
                        // which is why the file is named here instead.
                        if !s_cbor().is_empty() {
                            p { class: "hint",
                                if s_cbor_ta_store() {
                                    "Writes a trust anchor store to {s_cbor()}"
                                } else {
                                    "Writes a CA store with partial paths to {s_cbor()}"
                                }
                            }
                        }
                        RunButton {
                            running: s_running(),
                            onrun: run_command,
                            label: "Generate the store",
                            nothing_to_do: if s_generate() { "" } else { "Check Generate to build a store" },
                        }
                    },
                    View::Cleanup => rsx! {
                        // One grid for the whole view. Each `.controls` is a separate CSS grid
                        // that measures its own label column, so splitting the rows across three of
                        // them left three columns of different widths and no two labels lining up.
                        // The group box used to hide that; without it there is nothing to hide it.
                        div { class: "controls",
                            FolderRow { label: "CA Folder", name: "ca-folder", sig: s_ca_folder }
                            FolderRow { label: "TA Folder", name: "ta-folder", sig: s_ta_folder }
                            FolderRow { label: "Error Folder", name: "error-folder", sig: s_error_folder }
                            TimeRow { label: "Time of Interest", name: "time-of-interest", sig: s_time_of_interest }
                            // Labelled like every other row rather than floating in the grid's
                            // first column, which is where an unlabelled field lands.
                            div { class: "visible label-cell",
                                label { "Actions: " }
                            }
                            // Report Only modifies the two actions rather than being one, so it
                            // is unavailable while neither is chosen. Disabled rather than
                            // hidden, and the signal is left alone: the choice comes back with
                            // the control.
                            div { class: "field check-group",
                                CheckboxCell { label: "Cleanup", name: "cleanup", sig: s_cleanup }
                                CheckboxCell { label: "TA Cleanup", name: "ta-cleanup", sig: s_ta_cleanup }
                                CheckboxCell {
                                    label: "Report Only",
                                    name: "report-only",
                                    sig: s_report_only,
                                    disabled: !s_cleanup() && !s_ta_cleanup(),
                                }
                            }
                        }
                        // The only view that removes material, and it had nothing to say about
                        // what it removes or what decides. The time of interest is named
                        // because it is the criterion rather than a filter on the report: a
                        // wrong value here does not produce a wrong answer to run again, it
                        // moves certificates that were fine.
                        p { class: "hint",
                            if s_report_only() {
                                "Lists the certificates a run could not use — unparseable, not valid at the time of interest, self-signed, or not a CA — without touching anything. The time of interest is what decides."
                            } else if s_error_folder().is_empty() {
                                "Removes the certificates a run could not use: unparseable, not valid at the time of interest, self-signed, or not a CA. No Error Folder is set, so they are deleted rather than moved. The time of interest is what decides. Check Report Only to see what would go first."
                            } else {
                                "Removes the certificates a run could not use: unparseable, not valid at the time of interest, self-signed, or not a CA. They are moved to the Error Folder rather than deleted. The time of interest is what decides. Check Report Only to see what would go first."
                            }
                        }
                        RunButton {
                            running: s_running(),
                            onrun: run_command,
                            label: "Clean up the store",
                            // Both actions off is a legal run that removes nothing, which reads as
                            // "the folders were already clean" rather than as nothing being asked.
                            nothing_to_do: match !s_cleanup() && !s_ta_cleanup() {
                                true => "Choose Cleanup or TA Cleanup",
                                false => "",
                            },
                        }
                    },
                    View::Inspect => rsx! {
                        p { class: "hint",
                            "Reports what a store holds, without validating anything. The checkboxes list the store as a whole; the fields below them ask about one certificate or one CA, and each runs on its own when filled in."
                        }
                        div { class: "controls",
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
                            TimeRow { label: "Time of Interest", name: "time-of-interest", sig: s_time_of_interest }
                            // One group rather than the previous three-then-two, which was a wrap
                            // rather than a grouping: all five list the store as a whole, and
                            // splitting them implied a distinction that does not exist.
                            div { class: "visible label-cell",
                                label { "Items to list: " }
                            }
                            div { class: "field check-group",
                                CheckboxCell { label: "Partial Paths", name: "list-partial-paths", sig: s_list_partial_paths }
                                CheckboxCell { label: "Buffers", name: "list-buffers", sig: s_list_buffers }
                                CheckboxCell { label: "SIA and AIA", name: "list-aia-and-sia", sig: s_list_aia_and_sia }
                                CheckboxCell { label: "Name Constraints", name: "list-name-constraints", sig: s_list_name_constraints }
                                CheckboxCell { label: "Trust Anchors", name: "list-trust-anchors", sig: s_list_trust_anchors }
                            }
                            TextRow { label: "Dump Certificate At Index", name: "dump-cert-at-index", sig: s_dump_cert_at_index }
                            FileRow {
                                label: "List Partial Paths for Target",
                                name: "list-partial-paths-for-target",
                                sig: s_list_partial_paths_for_target,
                                filter_name: "Certificate File",
                                extensions: SINGLE_CERT_EXTENSIONS,
                            }
                            TextRow { label: "List Partial Paths for Leaf CA", name: "list-partial-paths-for-leaf-ca", sig: s_list_partial_paths_for_leaf_ca }
                        }
                        RunButton {
                            running: s_running(),
                            onrun: run_command,
                            label: "Inspect the store",
                            // Every control on this view is optional, so an untouched form is a
                            // legal run that lists nothing -- which reads as the store being empty
                            // rather than as nothing having been asked for.
                            nothing_to_do: if s_list_partial_paths() || s_list_buffers()
                                || s_list_aia_and_sia() || s_list_name_constraints()
                                || s_list_trust_anchors() || !s_dump_cert_at_index().is_empty()
                                || !s_list_partial_paths_for_target().is_empty()
                                || !s_list_partial_paths_for_leaf_ca().is_empty()
                            {
                                ""
                            } else {
                                "Choose something to list"
                            },
                        }
                    },
                    View::CheckUris => rsx! {
                        UriCheckView {}
                    },
                    View::Settings => rsx! {
                        // Always shown: settings are app state, not a document you must open
                        // first. The path below selects which file backs them and defaults to
                        // ~/.pittv3/settings.json, which is created on save if it does not
                        // exist. The empty case is only reachable with no home directory.
                        if s_settings().is_empty() {
                            p { class: "hint",
                                "No home directory, so there is no default settings file. Choose or type the path of a JSON settings file to edit."
                            }
                        } else {
                            EditSettingsFile {
                                path: s_settings(),
                                // The other reason to read the file again: the same one, on
                                // request (Revert to Saved) or because it is no longer there
                                // (Delete).
                                reload_token: s_settings_gen(),
                                // Folders the run writes to, and the actions that maintain
                                // them, beside the folders it reads from. They persist with the
                                // rest of the args rather than into the settings file, which
                                // stays the CLI's `-s` JSON.
                                extra_folder_rows: Some(rsx! {
                                    // Read and written both: indexing removes any CRL that is
                                    // not valid at the time of interest, which is why it sits
                                    // with the folders the run maintains rather than with the
                                    // revocation material a run is handed. The Cleanup and
                                    // Purge buttons below act on this path, and until it moved
                                    // here they acted on a folder nothing on this screen could
                                    // see, let alone change.
                                    FolderRow { label: "CRL Folder (index)", name: "crl-folder", sig: s_crl_folder }
                                    FolderRow { label: "Results Folder", name: "results-folder", sig: s_results_folder }
                                    FolderRow { label: "Error Folder", name: "error-folder", sig: s_error_folder }
                                    FileRow {
                                        label: "Logging Configuration",
                                        name: "logging-config",
                                        sig: s_logging_config,
                                        filter_name: "log4rs Configuration",
                                        extensions: ["yaml"].as_slice(),
                                    }
                                    // Named as a group because the distinction is the point:
                                    // everything here is material this application fetched or
                                    // computed, so losing it costs a refetch or a rebuild. The
                                    // Cleanup view acts on the CA and trust anchor folders, which
                                    // the user assembled and which may not be recoverable -- which
                                    // is why that view has an error folder and a dry run and these
                                    // buttons do not.
                                    div { class: "visible label-cell",
                                        label { "Caches and downloads: " }
                                    }
                                    div { class: "field" }
                                    div { class: "visible label-cell",
                                        label { "Downloaded certificates: " }
                                    }
                                    div { class: "field",
                                        button {
                                            title: "Removes certificates a run could not use: unparseable, not valid at the time of interest, self-signed, or not a CA. Moved to the error folder rather than deleted whenever one is set, which it is by default.",
                                            onclick: move |_| {
                                                let m = cleanup_certificate_folder(
                                                    &s_download_folder(),
                                                    &s_error_folder(),
                                                    s_time_of_interest().parse().unwrap_or(0),
                                                );
                                                s_folder_status
                                                    .set(format!("Removed {} downloaded certificate(s).", m.removed));
                                            },
                                            "Remove unusable"
                                        }
                                        button {
                                            title: "Removes every file in the download folder.",
                                            onclick: move |_| {
                                                spawn(async move {
                                                    let folder = s_download_folder();
                                                    if confirm_purge(&folder).await {
                                                        let m = purge_folder(&folder);
                                                        s_folder_status
                                                            .set(format!("Removed {} file(s) from the download folder.", m.removed));
                                                    }
                                                });
                                            },
                                            "Empty"
                                        }
                                    }
                                    div { class: "visible label-cell",
                                        label { "CRL index: " }
                                    }
                                    div { class: "field",
                                        button {
                                            title: "Removes CRLs that do not cover the time of interest, and any file that cannot be read as a CRL. A superseded CRL generally cannot be fetched again, so this forecloses validating as of a time it covered.",
                                            onclick: move |_| {
                                                let m = cleanup_crls(
                                                    &s_crl_folder(),
                                                    s_time_of_interest().parse().unwrap_or(0),
                                                );
                                                s_folder_status.set(format!("Removed {} CRL(s).", m.removed));
                                            },
                                            "Remove stale"
                                        }
                                        button {
                                            title: "Removes every file in the CRL folder, including the last-modified map that makes fetches conditional.",
                                            onclick: move |_| {
                                                spawn(async move {
                                                    let folder = s_crl_folder();
                                                    if confirm_purge(&folder).await {
                                                        let m = purge_folder(&folder);
                                                        s_folder_status
                                                            .set(format!("Removed {} file(s) from the CRL folder.", m.removed));
                                                    }
                                                });
                                            },
                                            "Empty"
                                        }
                                    }
                                    div { class: "visible label-cell",
                                        label { "Cached graphs: " }
                                    }
                                    div { class: "field",
                                        button {
                                            title: "Removes every cached graph. Nothing else removes one, and a run whose inputs, settings or time of interest differ from the last writes another, so the folder grows until it is emptied. Rebuilding one costs the partial-path search on the next run that needs it.",
                                            onclick: move |_| {
                                                spawn(async move {
                                                    let folder = graph_cache::cache_folder();
                                                    if folder.is_empty() {
                                                        s_folder_status
                                                            .set("No graph cache folder to empty.".to_string());
                                                    } else if confirm_purge(&folder).await {
                                                        let m = purge_folder(&folder);
                                                        s_folder_status
                                                            .set(format!("Removed {} cached graph file(s).", m.removed));
                                                    }
                                                });
                                            },
                                            "Empty"
                                        }
                                        // The in-memory counterpart, and the only one of these
                                        // buttons that frees memory rather than disk. Discarding
                                        // costs the next run a parse and nothing else: the graph
                                        // on disk is untouched.
                                        button {
                                            title: "Discards the parsed certificates this session is holding, which is tens of megabytes for a large store. The next run over the same material parses them again; no result changes either way.",
                                            onclick: {
                                                let prepared_graph = prepared_graph.clone();
                                                move |_| {
                                                    s_folder_status
                                                        .set(match prepared_graph.clear() {
                                                            Some(certs) => {
                                                                format!("Discarded {certs} parsed certificate(s).")
                                                            }
                                                            None => "Nothing has been prepared this session.".to_string(),
                                                        });
                                                }
                                            },
                                            "Discard In-Memory Graph"
                                        }
                                    }
                                    if !s_folder_status().is_empty() {
                                        span { class: "hint", "{s_folder_status}" }
                                    }
                                }),
                                on_reload: move |_| s_settings_gen += 1,
                                on_dirty_change: move |d| s_settings_dirty.set(d),
                            }
                        }
                        // The file the form above is backed by, and the actions that change
                        // which one that is or whether it exists at all. Below the form rather
                        // than above it, as in the browser: the tabs are what this view is for,
                        // and naming the store is housekeeping done once.
                        //
                        // Save, Revert to Saved and Reset to defaults are deliberately not in
                        // here. They act on whichever store backs the form -- localStorage in
                        // the browser, this file here -- so grouping them under a heading that
                        // says `file` would mislabel them in the other frontend.
                        fieldset {
                            legend { "Settings file" }
                            div { class: "controls",
                                div { class: "label-cell",
                                    label { r#for: "settings", "Settings file: " }
                                }
                                div { class: "field",
                                    input {
                                        r#type: "text",
                                        name: "settings",
                                        value: "{s_settings}",
                                        // Committed on exit, not per keystroke: this path drives a
                                        // file read and reseeds the form above, so a half-typed
                                        // path would read as "missing" and blank the form on the
                                        // way to a name that does exist. Same reason the datetime
                                        // row uses onchange. Committing once also makes the
                                        // unsaved-edits question askable, which it is not per
                                        // character.
                                        onchange: move |ev| {
                                            let typed = ev.value();
                                            spawn(async move {
                                                if leave_settings_ok(s_settings_dirty()).await {
                                                    s_settings.set(typed);
                                                    return;
                                                }
                                                // Declined, so the path does not move -- but the box
                                                // is still showing what was typed. Rewriting the
                                                // signal it is bound to is what puts it back.
                                                let unchanged = s_settings();
                                                s_settings.set(unchanged);
                                            });
                                        },
                                    }
                                    button {
                                        r#type: "button",
                                        onclick: move |_| {
                                            spawn(async move {
                                                if !leave_settings_ok(s_settings_dirty()).await {
                                                    return;
                                                }
                                                pick_file_into(s_settings, "PITTv3 Settings", &["json"]).await;
                                            });
                                        },
                                        "\u{2026}"
                                    }
                                    // Actions on the file itself, beside the box that names it and
                                    // not among the form's actions above: these change *which*
                                    // settings are being edited, or whether they exist at all,
                                    // where Save and Revert act on whichever file is named here.
                                    button {
                                        r#type: "button",
                                        onclick: move |_| {
                                            spawn(async move {
                                                if !leave_settings_ok(s_settings_dirty()).await {
                                                    return;
                                                }
                                                if let Some(p) = default_settings_path() {
                                                    s_settings.set(p);
                                                }
                                            });
                                        },
                                        "Default"
                                    }
                                    button {
                                        r#type: "button",
                                        onclick: move |_| {
                                            spawn(async move {
                                                let path = s_settings();
                                                if !confirm_delete_settings(&path).await {
                                                    return;
                                                }
                                                match std::fs::remove_file(&path) {
                                                    // The form re-reads on remount and a missing
                                                    // file loads as an empty settings map, which
                                                    // is the same thing as all defaults.
                                                    Ok(()) => s_settings_gen += 1,
                                                    Err(e) => error!("Failed to delete {path}: {e}"),
                                                }
                                            });
                                        },
                                        "Delete"
                                    }
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
                                            let name = stamped_export_name(
                                                &s_export_name(),
                                                s_run_stamp().unwrap_or_else(now_as_unix_epoch),
                                            );
                                            spawn(save_report(r, name));
                                        }
                                    },
                                    title: "Save the structured report as JSON",
                                    "Save report"
                                }
                                // The log is shown below and was the one thing here that could be
                                // read and not kept. Suffixed rather than sharing the report's
                                // stamped name, since the path logs already take `{name}.txt`.
                                button {
                                    r#type: "button",
                                    disabled: s_log().is_empty(),
                                    onclick: move |_| {
                                        let name = stamped_export_name(
                                            &s_export_name(),
                                            s_run_stamp().unwrap_or_else(now_as_unix_epoch),
                                        );
                                        let text = s_log().join("\n");
                                        spawn(write_export(
                                            format!("{name}-log.txt"),
                                            &["txt"],
                                            text.into_bytes(),
                                            s_log,
                                        ));
                                    },
                                    title: "Save what the validation stack logged, as text",
                                    "Save log"
                                }
                                // Saving what a run used is offered here, beside the report, rather
                                // than below the results: the decision is made after seeing them,
                                // which is the difference between this and a Results Folder. Same
                                // order and same archive as the browser.
                                button {
                                    r#type: "button",
                                    disabled: !s_can_export(),
                                    onclick: save_path_logs,
                                    title: "Save every path's manifest as one text file",
                                    "Save path logs"
                                }
                                button {
                                    r#type: "button",
                                    disabled: !s_can_export(),
                                    onclick: save_artifacts,
                                    title: "Save the certificates and revocation data behind every path, as a zip",
                                    "Save artifacts"
                                }
                                input {
                                    r#type: "text",
                                    class: "export-name",
                                    value: "{s_export_name}",
                                    title: "Name for the export: the archive and the folder inside it",
                                    oninput: move |e| s_export_name.set(e.value()),
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
                                p { class: "hint",
                                    "No results yet: run something from Validate, Generate, Cleanup or Inspect."
                                }
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
                        HelpView {
                            // Absolute: a desktop application has no origin to be relative to.
                            // https rather than http, which does not serve the manual.
                            manual_url: "https://pittv3.redhoundsoftware.com/pittv3-book/",
                            notes: rsx! {
                                ul {
                                    li {
                                        "Every input list takes a folder, a certificate, a PEM or "
                                        "PKCS#7 bundle, or a CBOR store. What an entry is comes "
                                        "from the path and then from its contents, so entries need "
                                        "not be sorted by kind."
                                    }
                                    li {
                                        "A store selected above the input lists is used together "
                                        "with them. Choose the custom entry to rely on the lists "
                                        "alone."
                                    }
                                    li {
                                        "A time of interest of 0 disables validity period checks."
                                    }
                                    li {
                                        "Cleanup moves certificates to the error folder rather than "
                                        "deleting them whenever one is named, which it is by "
                                        "default. Report Only says what would go without touching "
                                        "anything."
                                    }
                                    li {
                                        "Folders this application writes to live under ~/.pittv3, "
                                        "including the log at ~/.pittv3/logs/pittv3.log."
                                    }
                                }
                            },
                        }
                    },
                }
            }
        }
    }
}
