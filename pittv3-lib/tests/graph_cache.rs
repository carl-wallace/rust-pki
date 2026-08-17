//! Integration tests for the cached partial-path graph.
//!
//! A run that augments its trust material searches the combined set for partial paths, which is the
//! expensive half of preparing a run. The result is cached and reused when nothing it was built
//! from has changed. What has to hold is that reuse is invisible in the answer.
//!
//! **Its own test binary on purpose.** The cache folder is chosen by an environment variable, and
//! environment variables belong to the process rather than to a test, so a test that sets one while
//! sibling tests run in parallel is measuring their writes as well as its own. That is exactly what
//! happened when this lived alongside the CA-folder tests: four graphs in a folder that should have
//! held one.
#![cfg(feature = "std")]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use certval::*;
use pittv3_lib::args::Pittv3Args;
use pittv3_lib::graph_cache;
use pittv3_lib::options_std::options_std;
use pittv3_lib::report::{TargetStatus, ValidationReport};

/// Serializes the tests in this file. They each point the cache at their own folder, but they do it
/// through an environment variable, and those belong to the process: two tests running at once
/// would share whichever folder was set last. Held for the whole of a test body, poison ignored so
/// one failure reports itself rather than being masked by the other test failing to acquire.
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

fn settings_file(dir: &Path) -> String {
    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(TOI).unwrap());
    cps.set_check_revocation_status(false);
    let path = dir.join("settings.json");
    fs::write(&path, serde_json::to_string(&cps).unwrap()).unwrap();
    path.to_str().unwrap().to_string()
}

fn validate(dir: &Path, ta_folder: Option<String>, ca_folder: Option<String>) -> ValidationReport {
    let args = args_for(dir, ta_folder, ca_folder);
    tokio_test::block_on(options_std(&args))
}

/// The arguments a run uses, so a test can ask what a caller outside the run would compute for them.
fn args_for(dir: &Path, ta_folder: Option<String>, ca_folder: Option<String>) -> Pittv3Args {
    Pittv3Args {
        ta_folder,
        ca_folder,
        end_entity_file: Some(
            example("ValidCertificatePathTest1EE.crt")
                .to_str()
                .unwrap()
                .to_string(),
        ),
        settings: Some(settings_file(dir)),
        time_of_interest: TOI,
        ..Default::default()
    }
}

/// The cached graphs, not counting the anchor file written beside each one.
fn cached_graphs(cache: &Path) -> Vec<PathBuf> {
    fs::read_dir(cache)
        .map(|entries| {
            entries
                .map(|e| e.unwrap().path())
                .filter(|p| !p.to_string_lossy().ends_with(".ta.cbor"))
                .collect()
        })
        .unwrap_or_default()
}

/// A caller outside a run has to arrive at the same key the run filed the graph under, or it can
/// never find it. The desktop's Export Graph is that caller, and it found nothing every time:
/// `options_std` adjusts the settings for the run — AIA/SIA retrieval off, anchor validity off for
/// webpki anchors — and the whole settings blob goes into the key, so a key taken after those
/// adjustments cannot be reproduced from the arguments alone. The run now keys off the settings as
/// read, before it touches them.
#[test]
fn a_caller_outside_the_run_computes_the_same_key() {
    let _guard = CACHE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("cache");
    // SAFETY: this test binary is single-threaded by construction; see the module comment.
    unsafe { std::env::set_var("PITTV3_GRAPH_CACHE", &cache) };

    let ta_folder = folder_with(&dir.path().join("ta"), &["TrustAnchorRootCertificate.crt"]);
    let ca_folder = folder_with(&dir.path().join("ca"), &["GoodCACert.crt"]);
    let args = args_for(dir.path(), Some(ta_folder), Some(ca_folder));

    let report = tokio_test::block_on(options_std(&args));
    assert_eq!(TargetStatus::Valid, report.targets[0].status);

    let fingerprint =
        graph_cache::fingerprint_for_args(&args).expect("these inputs do build a graph");
    assert!(
        graph_cache::cached(&fingerprint).is_some(),
        "the run's graph is not filed under the key an outside caller computes"
    );

    // The anchors are cached beside the graph, because they are not in it: partial paths end at
    // them, but they live in a TaSource the CertSource never sees. An export of the graph alone
    // would describe paths to certificates it does not carry.
    let anchors = graph_cache::cached_anchors(&fingerprint).expect("the anchors were not cached");
    let ta = TaSource::new_from_cbor(&anchors).expect("the cached anchors do not load");
    assert!(!ta.is_empty(), "the cached anchor store is empty");

    // And the graph really does lack them, which is the reason both halves are written
    let graph = CertSource::new_from_cbor(&graph_cache::cached(&fingerprint).unwrap()).unwrap();
    assert!(
        !graph
            .get_buffers()
            .iter()
            .any(|cf| ta.get_tas().iter().any(|anchor| anchor.bytes == cf.bytes)),
        "an anchor turned up in the graph; the two halves are supposed to be disjoint"
    );

    unsafe { std::env::remove_var("PITTV3_GRAPH_CACHE") };
}

#[test]
fn the_augmented_graph_is_cached_reused_and_rekeyed() {
    let _guard = CACHE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("cache");
    // SAFETY: the lock above serializes the tests that touch this variable; see CACHE_ENV_LOCK.
    unsafe { std::env::set_var("PITTV3_GRAPH_CACHE", &cache) };

    let ta_folder = folder_with(&dir.path().join("ta"), &["TrustAnchorRootCertificate.crt"]);
    let ca_folder = folder_with(&dir.path().join("ca"), &["GoodCACert.crt"]);

    let first = validate(dir.path(), Some(ta_folder.clone()), Some(ca_folder.clone()));
    assert_eq!(TargetStatus::Valid, first.targets[0].status);
    assert_eq!(
        1,
        cached_graphs(&cache).len(),
        "the run's graph should have been cached"
    );

    // Same inputs: served from the cache, and the answer is the one built the long way
    let second = validate(dir.path(), Some(ta_folder.clone()), Some(ca_folder));
    assert_eq!(first.targets[0].status, second.targets[0].status);
    assert_eq!(first.totals.paths_found, second.totals.paths_found);
    assert_eq!(first.totals.valid_paths, second.totals.valid_paths);
    assert_eq!(
        first.targets[0].paths[0].certs.len(),
        second.targets[0].paths[0].certs.len()
    );
    assert_eq!(
        1,
        cached_graphs(&cache).len(),
        "a hit should not write a second copy"
    );

    // Different CA material is a different graph, and must not be answered with the first one
    let bigger = folder_with(
        &dir.path().join("ca2"),
        &["GoodCACert.crt", "BasicSelfIssuedNewKeyCACert.crt"],
    );
    let third = validate(dir.path(), Some(ta_folder), Some(bigger));
    assert_eq!(TargetStatus::Valid, third.targets[0].status);
    assert_eq!(
        2,
        cached_graphs(&cache).len(),
        "a changed input set has to key differently"
    );

    unsafe { std::env::remove_var("PITTV3_GRAPH_CACHE") };
}
