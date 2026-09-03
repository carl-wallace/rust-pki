//! Integration tests for the graph a run prepares and a caller keeps in memory.
//!
//! What has to hold is the same thing the graph saved on disk has to satisfy — reuse is invisible in
//! the answer — plus the thing specific to keeping the *parsed* form: that a run really does stop
//! reading its inputs when it can be served from memory.
//!
//! **Its own test binary on purpose.** These tests point the graph cache somewhere harmless through
//! an environment variable, and environment variables belong to the process rather than to a test.
//! See the module comment on `graph_cache.rs`, which shares the hazard and the arrangement.
//!
//! Gated on `revocation` as well as `std` because `options_std_retaining` takes the revocation cache
//! as a parameter only when both are on, so the call below has a different shape without it. The
//! tests themselves check no revocation status; the settings turn it off.
#![cfg(all(feature = "std", feature = "revocation"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use certval::*;
use pittv3_lib::args::Pittv3Args;
use pittv3_lib::graph_cache;
use pittv3_lib::options_std::options_std_retaining;
use pittv3_lib::prepared_graph::PreparedGraph;
use pittv3_lib::report::{TargetStatus, ValidationReport};

/// Serializes the tests in this file, which each set the same environment variable. Poison ignored
/// so one failure reports itself rather than being masked by the other test failing to acquire.
static CACHE_ENV_LOCK: Mutex<()> = Mutex::new(());

/// A time at which the PKITS fixtures are valid
const TOI: u64 = 1648039783;

const FLAVOR: &str = "../certval/tests/examples/PKITS_data_p256/certs";

fn example(name: &str) -> PathBuf {
    Path::new(FLAVOR).join(name)
}

fn folder_with(dir: &Path, names: &[&str]) -> String {
    fs::create_dir_all(dir).unwrap();
    for name in names {
        fs::copy(example(name), dir.join(name)).unwrap();
    }
    dir.to_str().unwrap().to_string()
}

/// Settings that carry no time of interest, so the run takes it from the arguments.
fn settings_file(dir: &Path) -> String {
    let mut cps = CertificationPathSettings::new();
    cps.set_check_revocation_status(false);
    let path = dir.join("settings.json");
    fs::write(&path, serde_json::to_string(&cps).unwrap()).unwrap();
    path.to_str().unwrap().to_string()
}

fn args_for(dir: &Path, ta_folder: String, ca_folder: String, toi: u64) -> Pittv3Args {
    Pittv3Args {
        ta_folder: Some(ta_folder),
        ca_folder: Some(ca_folder),
        end_entity_file: Some(
            example("ValidCertificatePathTest1EE.crt")
                .to_str()
                .unwrap()
                .to_string(),
        ),
        settings: Some(settings_file(dir)),
        time_of_interest: toi,
        ..Default::default()
    }
}

fn validate(args: &Pittv3Args, prepared: Option<&PreparedGraph>) -> ValidationReport {
    let (report, _) = tokio_test::block_on(options_std_retaining(args, false, None, prepared));
    report
}

/// Overwrites a certificate with the same number of bytes of nonsense, then puts its timestamps
/// back.
///
/// The key is each input's path, size and modification time, so this leaves it identical while
/// making the file useless. A run that still finds the path afterwards did not read the file, which
/// is the only way to show reuse from the outside: a hit is otherwise indistinguishable from doing
/// the work again correctly.
fn corrupt_in_place(path: &Path) {
    let before = fs::metadata(path).unwrap();
    let times = fs::FileTimes::new()
        .set_accessed(before.accessed().unwrap())
        .set_modified(before.modified().unwrap());

    fs::write(path, vec![0xff; before.len() as usize]).unwrap();

    let file = fs::File::options().write(true).open(path).unwrap();
    file.set_times(times).unwrap();

    let after = fs::metadata(path).unwrap();
    assert_eq!(before.len(), after.len(), "the corruption changed the size");
    assert_eq!(
        before.modified().unwrap(),
        after.modified().unwrap(),
        "the modification time did not survive being put back, so the key moved and this test \
         cannot say anything about reuse"
    );
}

/// Points the graph cache at nothing, so only the caller's own prepared graph can answer.
///
/// # Safety
///
/// The lock the caller holds serializes every test in this binary that touches this variable.
unsafe fn disable_graph_cache() {
    unsafe { std::env::set_var("PITTV3_GRAPH_CACHE", "off") };
}

#[test]
fn a_prepared_graph_is_reused_without_reading_the_inputs_again() {
    let _guard = CACHE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: serialized by the lock above.
    unsafe { disable_graph_cache() };
    let dir = tempfile::tempdir().unwrap();

    let ta_folder = folder_with(&dir.path().join("ta"), &["TrustAnchorRootCertificate.crt"]);
    let ca_dir = dir.path().join("ca");
    let ca_folder = folder_with(&ca_dir, &["GoodCACert.crt"]);
    let args = args_for(dir.path(), ta_folder, ca_folder, TOI);

    let prepared = PreparedGraph::new();
    assert_eq!(
        None,
        prepared.certificates(),
        "nothing has been prepared yet"
    );

    let first = validate(&args, Some(&prepared));
    assert_eq!(TargetStatus::Valid, first.targets[0].status);
    assert_eq!(
        Some(1),
        prepared.certificates(),
        "the run should have left its prepared certificates behind"
    );

    // The intermediate is now unreadable, and keyed exactly as it was.
    corrupt_in_place(&ca_dir.join("GoodCACert.crt"));

    // A fresh PreparedGraph has to go to the folder, and the folder no longer has a usable CA in
    // it. This
    // is the control: without it, the run below passing would only show that validation works.
    let unprepared = validate(&args, Some(&PreparedGraph::new()));
    assert_ne!(
        TargetStatus::Valid,
        unprepared.targets[0].status,
        "the corrupted intermediate still produced a valid path, so the run below proves nothing"
    );

    // Same run, given what the first one prepared: the path is found, from certificates that exist
    // only in memory.
    let second = validate(&args, Some(&prepared));
    assert_eq!(TargetStatus::Valid, second.targets[0].status);
    assert_eq!(first.totals.paths_found, second.totals.paths_found);
    assert_eq!(first.totals.valid_paths, second.totals.valid_paths);
    assert_eq!(
        first.targets[0].paths[0].certs.len(),
        second.targets[0].paths[0].certs.len()
    );

    unsafe { std::env::remove_var("PITTV3_GRAPH_CACHE") };
}

/// One graph is kept, under the key of the PKI it was prepared from.
#[test]
fn what_is_kept_is_keyed_to_the_pki_it_came_from() {
    let _guard = CACHE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: serialized by the lock above.
    unsafe { disable_graph_cache() };
    let dir = tempfile::tempdir().unwrap();

    let ta_folder = folder_with(&dir.path().join("ta"), &["TrustAnchorRootCertificate.crt"]);
    let ca_folder = folder_with(&dir.path().join("ca"), &["GoodCACert.crt"]);
    let args = args_for(dir.path(), ta_folder.clone(), ca_folder, TOI);

    let prepared = PreparedGraph::new();
    assert_eq!(
        TargetStatus::Valid,
        validate(&args, Some(&prepared)).targets[0].status
    );

    // The settings the run keyed on, as read from the file. The time of interest is taken back out
    // before hashing, so it does not matter that these do not carry the one the run settled.
    let cps = read_settings(&args.settings).unwrap();
    let key = graph_cache::saved_graph_fingerprint(&args, &cps)
        .expect("every run that is not a generate run keys");
    assert!(
        prepared.get(&key).is_some(),
        "the run filed its graph under a key its own arguments do not reproduce"
    );
    assert!(prepared.get("not the key").is_none());

    // Selecting a different PKI replaces what is kept rather than accumulating beside it.
    let bigger = folder_with(
        &dir.path().join("ca2"),
        &["GoodCACert.crt", "BasicSelfIssuedNewKeyCACert.crt"],
    );
    let other = args_for(dir.path(), ta_folder, bigger, TOI);
    assert_eq!(
        TargetStatus::Valid,
        validate(&other, Some(&prepared)).targets[0].status
    );
    assert!(
        prepared.get(&key).is_none(),
        "one graph is supposed to be kept, not a map of them"
    );

    assert_eq!(Some(2), prepared.certificates());
    assert_eq!(Some(2), prepared.clear(), "clear reports what it discarded");
    assert_eq!(None, prepared.clear(), "and says so when there was nothing");

    unsafe { std::env::remove_var("PITTV3_GRAPH_CACHE") };
}
