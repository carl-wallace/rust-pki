//! Saving the artifacts a validation used, after the run rather than before it.
//!
//! A Results Folder is the other way to get this material, and it has to be named before a run
//! starts. These are for the person who has seen the outcome and only then wants what is behind it,
//! which is what the browser frontend has offered since it had no filesystem to write to.
//!
//! **The archive is the same one the browser produces.** Both call
//! [`pittv3_gui_lib::export::path_entries`] over the paths a run retained and
//! [`pittv3_gui_lib::export::zip_bundle`] to package them, so a bundle from the desktop and one from
//! the browser are the same bytes for the same run. The desktop writes it where the user says
//! instead of triggering a download; that is the whole of the difference.
//!
//! The bundle has two halves. The paths half is what each path was judged from, which is what this
//! module has always assembled. The inputs half is what a replay needs -- the environment, the
//! settings, the end entity certificates and the command line that reproduces the run -- and it is
//! completed here from the run's own retained state rather than from the form, since the form goes
//! on being editable after a run and a bundle that misreports its inputs is worse than none.
//!
//! Validating again to produce the archive is not an option: revocation data moves, and a responder
//! asked twice can answer differently, so the material has to come from the run being reported. That
//! is why the run keeps it — see [`pittv3_lib::retained::RetainedRun`].

use std::sync::{Arc, Mutex};

use pittv3_gui_lib::export::{path_entries, paths_text, zip_bundle, RunInputs};
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
    entries_for(run)
}

/// The per-path entries of a run already held. Split from [`build_entries`] so the archive can take
/// the lock once and build both halves of the bundle from the same view of the run, rather than
/// locking twice and risking two halves that describe different states.
fn entries_for(run: &RetainedRun) -> Vec<Vec<(String, Vec<u8>)>> {
    run.paths
        .iter()
        .map(|r| {
            path_entries(
                &run.environment,
                &r.path,
                Some(&r.cps),
                &r.cpr,
                Some(r.duration_ms),
            )
        })
        .collect()
}

/// Completes the caller's inputs from what the run itself kept.
///
/// The frontend knows the environment halves, whether the run pursued every path and which store it
/// came from; only the run knows the settings it ended up using, the certificates it was asked
/// about and the moment it judged against. Filling the second set here rather than at the button is
/// what keeps a bundle describing the run instead of the form: everything the archive claims about
/// its own inputs comes from the same retained state the paths half is built from.
///
/// The time of interest is taken from the run's settings rather than from the arguments because the
/// settings are where it ended up -- an argument that was defaulted still had to settle on a value,
/// and that value is what a replay has to be given.
fn complete_inputs(run: &RetainedRun, mut inputs: RunInputs) -> RunInputs {
    inputs.settings = Some(run.cps.clone());
    inputs.time_of_interest = run.cps.get_time_of_interest().as_unix_secs();

    // One entry per target, not per path: several paths to one end entity are several paths to one
    // certificate, and a replay is handed the certificate.
    let mut seen = vec![];
    for path in &run.paths {
        if seen.contains(&path.target_name) {
            continue;
        }
        seen.push(path.target_name.clone());
        inputs.end_entities.push((
            path.target_name.clone(),
            path.path.target.as_bytes().to_vec(),
        ));
    }

    // Every intermediate every path went through, whatever it came from. A run reaches certificates
    // the store does not carry, and a bundle rebuilding the store alone does not rebuild the run.
    for path in &run.paths {
        inputs
            .anchors_used
            .push(path.path.trust_anchor.encoded_ta.clone());
        for ca in &path.path.intermediates {
            inputs.intermediates.push(ca.as_bytes().to_vec());
        }
    }
    inputs
}

/// The bundle: the inputs a replay needs, the material behind every retained path, and a run-level
/// file stating what the run as a whole did.
///
/// `inputs` carries what only the frontend knows -- the environment halves, whether every path was
/// pursued, which store it came from -- and the rest is completed from the run.
///
/// `Ok(None)` means there was nothing to save, which the caller reports as such rather than writing
/// an empty archive.
pub(crate) fn artifacts_archive(
    artifacts: &RetainedArtifacts,
    name: &str,
    inputs: RunInputs,
    run_ms: Option<u64>,
) -> Result<Option<Vec<u8>>, String> {
    let guard = match artifacts.lock() {
        Ok(guard) => guard,
        Err(_) => return Ok(None),
    };
    let Some(run) = guard.as_ref() else {
        return Ok(None);
    };
    let entries = entries_for(run);
    if entries.is_empty() {
        return Ok(None);
    }
    let inputs = complete_inputs(run, inputs);
    zip_bundle(name, &entries, &inputs, run_ms).map(Some)
}

/// The manifests alone -- every path's account of itself, one after another, without the material
/// behind them.
///
/// Taken from the same entries the archive is built from rather than rendered separately, so the two
/// cannot disagree about what the run found.
///
/// `run_ms` is the run-level figure from the report the results view is showing, which is the run
/// these artifacts came from. It closes the log because no manifest can state it: each says what its
/// own path took, and the difference between their sum and the run is the retrieval and the work
/// between them.
pub(crate) fn path_logs_text(artifacts: &RetainedArtifacts, run_ms: Option<u64>) -> Option<String> {
    let entries = build_entries(artifacts);
    let text = paths_text(&entries, run_ms);
    match text.is_empty() {
        true => None,
        false => Some(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nothing retained is not a failure -- it is the state before the first run, and after a run
    /// that found no paths.
    #[test]
    fn nothing_retained_yields_nothing_to_save() {
        let artifacts: RetainedArtifacts = Arc::new(Mutex::new(None));
        assert!(
            artifacts_archive(&artifacts, "run", RunInputs::default(), None)
                .unwrap()
                .is_none()
        );
        assert!(path_logs_text(&artifacts, None).is_none());
        // and a run figure does not conjure a log out of paths that are not held
        assert!(path_logs_text(&artifacts, Some(1234)).is_none());
        // nor does a set of inputs: a bundle with no paths in it is not a bundle, so an archive
        // is not written for inputs alone however complete they are
        let inputs = RunInputs {
            anchors: Some(b"anchors".to_vec()),
            graph: Some(b"graph".to_vec()),
            ..Default::default()
        };
        assert!(artifacts_archive(&artifacts, "run", inputs, Some(1234))
            .unwrap()
            .is_none());
    }
}
