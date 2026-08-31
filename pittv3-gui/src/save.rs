//! Saving the artifacts a validation used, after the run rather than before it.
//!
//! A Results Folder is the other way to get this material, and it has to be named before a run
//! starts. These are for the person who has seen the outcome and only then wants what is behind it,
//! which is what the browser frontend has offered since it had no filesystem to write to.
//!
//! **The archive is the same one the browser produces.** Both call
//! [`pittv3_gui_lib::export::path_entries`] over the paths a run retained and
//! [`pittv3_gui_lib::export::zip_paths`] to package them, so a bundle from the desktop and one from
//! the browser are the same bytes for the same run. The desktop writes it where the user says
//! instead of triggering a download; that is the whole of the difference.
//!
//! Validating again to produce the archive is not an option: revocation data moves, and a responder
//! asked twice can answer differently, so the material has to come from the run being reported. That
//! is why the run keeps it — see [`pittv3_lib::retained::RetainedRun`].

use std::sync::{Arc, Mutex};

use pittv3_gui_lib::export::{path_entries, paths_text, zip_paths};
use pittv3_lib::retained::RetainedRun;

/// What the last run kept, shared between the worker thread that produced it and the UI that offers
/// to save it.
///
/// A mutex rather than a signal because the run happens on its own thread with its own runtime, and
/// signals may only be written from the UI executor. Nothing contends for it: the worker stores once
/// when the run finishes and the buttons read it afterwards.
pub(crate) type RetainedArtifacts = Arc<Mutex<Option<RetainedRun>>>;

/// Builds the per-path export entries once, so an archive and a log describe the same paths in the
/// same order.
///
/// Returns an empty vector when nothing is held, which is the case before the first run and after a
/// run that found no paths at all.
fn build_entries(artifacts: &RetainedArtifacts) -> Vec<Vec<(String, Vec<u8>)>> {
    let guard = match artifacts.lock() {
        Ok(guard) => guard,
        // A poisoned mutex means the worker panicked mid-run; the run is not reportable either way,
        // and refusing to export is better than exporting whatever was written before the panic.
        Err(_) => return vec![],
    };
    let Some(run) = guard.as_ref() else {
        return vec![];
    };
    run.paths
        .iter()
        .map(|r| path_entries(&run.environment, &r.path, Some(&r.cps), &r.cpr))
        .collect()
}

/// The zip of every retained path's artifacts: the certificates, the revocation data consulted, the
/// responder certificates that make an OCSP response checkable, and a manifest per path.
///
/// `Ok(None)` means there was nothing to save, which the caller reports as such rather than writing
/// an empty archive.
pub(crate) fn artifacts_archive(
    artifacts: &RetainedArtifacts,
    name: &str,
) -> Result<Option<Vec<u8>>, String> {
    let entries = build_entries(artifacts);
    if entries.is_empty() {
        return Ok(None);
    }
    zip_paths(name, &entries).map(Some)
}

/// The manifests alone -- every path's account of itself, one after another, without the material
/// behind them.
///
/// Taken from the same entries the archive is built from rather than rendered separately, so the two
/// cannot disagree about what the run found.
pub(crate) fn path_logs_text(artifacts: &RetainedArtifacts) -> Option<String> {
    let entries = build_entries(artifacts);
    let text = paths_text(&entries);
    match text.is_empty() {
        true => None,
        false => Some(text),
    }
}

/// The name an export takes when the user has not chosen one. The field is pre-populated with it,
/// as the browser's is, so the common case needs no typing and both frontends produce a bundle under
/// the same name for the same run.
pub(crate) const DEFAULT_EXPORT_NAME: &str = "PITTv3Results";

/// A filename stem for an export, from what the user typed or [`DEFAULT_EXPORT_NAME`] when the field
/// has been cleared.
///
/// Sanitized because the value names a file and a folder inside the archive: a separator here would
/// scatter the contents or, worse, land them somewhere other than where the save dialog said.
pub(crate) fn export_name(typed: &str) -> String {
    let trimmed = typed.trim();
    let cleaned: String = trimmed
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' => '_',
            c => c,
        })
        .collect();
    match cleaned.is_empty() {
        true => DEFAULT_EXPORT_NAME.to_string(),
        false => cleaned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cleared_name_falls_back_to_the_one_the_field_starts_with() {
        assert_eq!(export_name(""), DEFAULT_EXPORT_NAME);
        assert_eq!(export_name("   "), DEFAULT_EXPORT_NAME);
    }

    /// The name reaches a filesystem path and an archive entry, so a separator in it is not a name
    /// but an instruction about where things land.
    #[test]
    fn separators_are_not_carried_into_the_name() {
        assert_eq!(export_name("../etc/passwd"), ".._etc_passwd");
        assert_eq!(export_name("C:\\runs\\one"), "C__runs_one");
    }

    #[test]
    fn a_typed_name_is_kept_and_trimmed() {
        assert_eq!(export_name("  dod run 3 "), "dod run 3");
    }

    /// Nothing retained is not a failure -- it is the state before the first run, and after a run
    /// that found no paths.
    #[test]
    fn nothing_retained_yields_nothing_to_save() {
        let artifacts: RetainedArtifacts = Arc::new(Mutex::new(None));
        assert!(artifacts_archive(&artifacts, "run").unwrap().is_none());
        assert!(path_logs_text(&artifacts).is_none());
    }
}
