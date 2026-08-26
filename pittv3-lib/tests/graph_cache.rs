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

/// Builds a CBOR store at `cbor` from the certificate `ca_input` names, the way a user producing
/// one to hand back to a later run would.
fn generate_store(dir: &Path, ca_input: &Path, cbor: &Path) {
    tokio_test::block_on(options_std(&Pittv3Args {
        ta_folder: Some(
            example("TrustAnchorRootCertificate.crt")
                .to_str()
                .unwrap()
                .to_string(),
        ),
        ca_folder: Some(ca_input.to_str().unwrap().to_string()),
        cbor: Some(cbor.to_str().unwrap().to_string()),
        generate: true,
        settings: Some(settings_file(dir)),
        time_of_interest: TOI,
        ..Default::default()
    }));
}

/// A store handed to the CA input is the entire set of CA certificates for that run, and it already
/// carries the partial paths through itself — which is the whole reason they were serialized. So it
/// is adopted as it stands rather than being reduced to its certificates and searched again, and
/// the first run costs what the ones after it cost. Carl's report was that "the first run is slower
/// than I would expect given the paths have already been calculated", and it was.
///
/// **The observable is that nothing is cached**, because nothing was built. This module's own
/// comment has always said only augmented graphs are cached; a store arriving through the CA row
/// rather than through `--cbor` was the case that did not honor it, and a cache entry appearing here
/// means the search ran.
///
/// The second half is the other arm of the same decision: a store merged with material it was not
/// searched against *is* augmentation, because a path spanning the two exists only once they are
/// searched together. That one must still search, and still cache.
#[test]
fn a_store_in_the_ca_row_is_adopted_with_its_paths_rather_than_searched_again() {
    let _guard = CACHE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("cache");
    // SAFETY: this test binary is single-threaded by construction; see the module comment.
    unsafe { std::env::set_var("PITTV3_GRAPH_CACHE", &cache) };

    let good_ca = dir.path().join("good-ca.cbor");
    generate_store(dir.path(), &example("GoodCACert.crt"), &good_ca);
    assert!(good_ca.is_file(), "the CA store was not generated");

    // The store carries the paths the adoption is for; without them there would be nothing to adopt
    // and skipping the search would leave the run with no graph.
    let store = pittv3_lib::std_utils::cbor_cert_store(good_ca.to_str().unwrap())
        .expect("the generated store does not read back through the reader the run uses");
    assert!(
        store.num_partial_paths() > 0,
        "the generated store carries no partial paths, so this test cannot mean what it says"
    );
    let certs_only = pittv3_lib::std_utils::cbor_cert_store_certs(good_ca.to_str().unwrap())
        .expect("the generated store does not read back as certificates");
    assert_eq!(
        store.num_buffers(),
        certs_only.len(),
        "the two readers disagree about how many certificates the store holds"
    );

    let ta_folder = folder_with(&dir.path().join("ta"), &["TrustAnchorRootCertificate.crt"]);
    let report = validate(
        dir.path(),
        Some(ta_folder.clone()),
        Some(good_ca.to_str().unwrap().to_string()),
    );
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
    assert_eq!(3, report.targets[0].paths[0].certs.len());
    assert!(
        cached_graphs(&cache).is_empty(),
        "a graph was cached, so the store's paths were discarded and the search ran anyway"
    );

    // Augmentation: a second store in the CA row alongside one already loaded through `--cbor`.
    // Now the two have never been searched together, so the search has to run -- and its result is
    // worth caching, which is what tells the two arms apart from outside.
    let sub_ca = dir.path().join("sub-ca.cbor");
    generate_store(dir.path(), &example("GoodsubCACert.crt"), &sub_ca);

    let report = tokio_test::block_on(options_std(&Pittv3Args {
        cbor: Some(sub_ca.to_str().unwrap().to_string()),
        ..args_for(
            dir.path(),
            Some(ta_folder),
            Some(good_ca.to_str().unwrap().to_string()),
        )
    }));
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
    assert_eq!(
        1,
        cached_graphs(&cache).len(),
        "an augmented graph was not cached, so the two stores were not searched together"
    );

    unsafe { std::env::remove_var("PITTV3_GRAPH_CACHE") };
}

/// The pools are part of the graph's identity. They were added after the key was written, and a key
/// that ignored them would hand a run driven by one pool the graph built for another — the failure
/// mode a cache has that a rebuild does not. Also pinned: a run whose only CA input is the pool is
/// cacheable at all, which the `ca_folder.is_none()` gate used to refuse.
#[test]
fn the_pools_are_part_of_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let ta = folder_with(&dir.path().join("ta"), &["TrustAnchorRootCertificate.crt"]);
    let ca = folder_with(&dir.path().join("ca"), &["GoodCACert.crt"]);
    let other = folder_with(&dir.path().join("other"), &["BadSignedCACert.crt"]);

    let pool_only = Pittv3Args {
        ca_inputs: vec![ca.clone()],
        ..args_for(dir.path(), Some(ta.clone()), None)
    };
    let key = graph_cache::fingerprint_for_args(&pool_only)
        .expect("a run whose CA input is the pool builds a graph worth caching");

    let different_pool = Pittv3Args {
        ca_inputs: vec![other.clone()],
        ..args_for(dir.path(), Some(ta.clone()), None)
    };
    assert_ne!(
        Some(key.clone()),
        graph_cache::fingerprint_for_args(&different_pool),
        "a different CA pool is a different graph"
    );

    let extra_entry = Pittv3Args {
        ca_inputs: vec![ca.clone(), other.clone()],
        ..args_for(dir.path(), Some(ta.clone()), None)
    };
    assert_ne!(
        Some(key.clone()),
        graph_cache::fingerprint_for_args(&extra_entry),
        "an added entry is a different graph"
    );

    let extra_anchor = Pittv3Args {
        ca_inputs: vec![ca],
        ta_inputs: vec![other],
        ..args_for(dir.path(), Some(ta), None)
    };
    assert_ne!(
        Some(key),
        graph_cache::fingerprint_for_args(&extra_anchor),
        "the partial paths end at the anchors, so the anchor pool keys too"
    );
}
