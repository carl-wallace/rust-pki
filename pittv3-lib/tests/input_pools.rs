//! Integration tests for the repeatable input arguments — `ta_inputs`, `ca_inputs`, `ee_inputs`.
//!
//! The singular arguments they generalize each hold one string, which is why a desktop form over
//! them offered one box per kind of thing and a browser frontend that accumulates uploads had no
//! counterpart at all. These tests pin what the pools have to do to stand in for those boxes: every
//! entry is read, entries of different shapes combine into one graph, and the pool works with the
//! singular arguments absent, present, or naming the same material.
#![cfg(feature = "std")]

use std::fs;
use std::path::{Path, PathBuf};

use certval::*;
use pittv3_lib::args::Pittv3Args;
use pittv3_lib::options_std::options_std;
use pittv3_lib::report::{TargetStatus, ValidationReport};
use pittv3_lib::std_utils::load_ca_inputs;

/// A time at which the PKITS fixtures are valid
const TOI: u64 = 1648039783;

const FLAVOR: &str = "../certval/tests/examples/PKITS_data_p256/certs";

/// The four intermediates of the PKITS "require explicit policy" chain, root-first. A path needing
/// several intermediates is what makes a multi-entry pool testable: split them across entries and
/// only a run that read every entry can complete the path.
const CHAIN: &[&str] = &[
    "requireExplicitPolicy10CACert.crt",
    "requireExplicitPolicy10subCACert.crt",
    "requireExplicitPolicy10subsubCACert.crt",
    "requireExplicitPolicy10subsubsubCACert.crt",
];

fn example(name: &str) -> PathBuf {
    Path::new(FLAVOR).join(name)
}

fn example_str(name: &str) -> String {
    example(name).to_str().unwrap().to_string()
}

/// Copies `names` into a fresh folder under `dir` and returns its path, standing in for a folder a
/// user points the tool at.
fn folder_with(dir: &Path, label: &str, names: &[&str]) -> String {
    let folder = dir.join(label);
    fs::create_dir_all(&folder).unwrap();
    for name in names {
        fs::copy(example(name), folder.join(name)).unwrap();
    }
    folder.to_str().unwrap().to_string()
}

/// Writes the settings file a run reads, holding the time of interest and turning revocation
/// checking off: these tests are about which certificates reach path building, and the PKITS
/// fixtures carry no revocation material to answer with.
fn settings_file(dir: &Path) -> String {
    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(TOI).unwrap());
    cps.set_check_revocation_status(false);
    let path = dir.join("settings.json");
    fs::write(&path, serde_json::to_string(&cps).unwrap()).unwrap();
    path.to_str().unwrap().to_string()
}

/// Runs `args` after filling in the settings and time of interest every test here shares.
fn run(dir: &Path, args: Pittv3Args) -> ValidationReport {
    tokio_test::block_on(options_std(&Pittv3Args {
        settings: Some(settings_file(dir)),
        time_of_interest: TOI,
        ..args
    }))
}

/// The trust anchor every fixture chains to, as a single file rather than a folder — PKITS ships no
/// folder holding only its root.
fn root() -> String {
    example_str("TrustAnchorRootCertificate.crt")
}

/// A run driven entirely by the pools, with none of the singular arguments set. This is the shape a
/// frontend that has replaced its file and folder boxes with one list produces, so it is the case
/// that has to work before any of the others matter.
#[test]
fn the_pools_alone_validate() {
    let dir = tempfile::tempdir().unwrap();

    let report = run(
        dir.path(),
        Pittv3Args {
            ta_inputs: vec![root()],
            ca_inputs: vec![example_str("GoodCACert.crt")],
            ee_inputs: vec![example_str("ValidCertificatePathTest1EE.crt")],
            ..Default::default()
        },
    );

    assert_eq!(None, report.error);
    assert_eq!(1, report.totals.targets);
    assert_eq!(1, report.totals.valid_paths);
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
    // trust anchor, intermediate, target
    assert_eq!(3, report.targets[0].paths[0].certs.len());
}

/// Every entry of the CA pool is read, and the certificates from all of them land in one graph so a
/// path can span them. Split four intermediates across four entries of three different shapes — a
/// folder, two single files, and a folder again — and the path exists only if each was read and
/// they were searched together.
#[test]
fn ca_pool_entries_combine_into_one_graph() {
    let dir = tempfile::tempdir().unwrap();

    let report = run(
        dir.path(),
        Pittv3Args {
            ta_inputs: vec![root()],
            ca_inputs: vec![
                folder_with(dir.path(), "first", &[CHAIN[0]]),
                example_str(CHAIN[1]),
                example_str(CHAIN[2]),
                folder_with(dir.path(), "last", &[CHAIN[3]]),
            ],
            ee_inputs: vec![example_str("ValidrequireExplicitPolicyTest1EE.crt")],
            ..Default::default()
        },
    );

    assert_eq!(None, report.error);
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
    // trust anchor, four intermediates, target
    assert_eq!(6, report.targets[0].paths[0].certs.len());
}

/// The control for the test above: hold one entry back and the path cannot be built. Without this,
/// a pool that quietly read only its first entry would still pass, because the fixtures would have
/// been reachable some other way.
#[test]
fn a_missing_ca_pool_entry_breaks_the_path() {
    let dir = tempfile::tempdir().unwrap();

    let report = run(
        dir.path(),
        Pittv3Args {
            ta_inputs: vec![root()],
            ca_inputs: CHAIN[..3].iter().map(|n| example_str(n)).collect(),
            ee_inputs: vec![example_str("ValidrequireExplicitPolicyTest1EE.crt")],
            ..Default::default()
        },
    );

    assert_eq!(0, report.totals.valid_paths);
}

/// The pool augments the singular argument rather than displacing it, on both sides. A run that
/// took only one of the two would be missing an intermediate and find nothing.
#[test]
fn the_pool_and_the_singular_arguments_are_used_together() {
    let dir = tempfile::tempdir().unwrap();

    let report = run(
        dir.path(),
        Pittv3Args {
            ta_folder: Some(root()),
            ca_folder: Some(folder_with(dir.path(), "half", &CHAIN[..2])),
            ca_inputs: CHAIN[2..].iter().map(|n| example_str(n)).collect(),
            end_entity_file: Some(example_str("ValidrequireExplicitPolicyTest1EE.crt")),
            ..Default::default()
        },
    );

    assert_eq!(None, report.error);
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
    assert_eq!(6, report.targets[0].paths[0].certs.len());
}

/// An entry of the end entity pool may name a certificate or a folder of them, and the two kinds mix
/// in one list. That is the difference from `end_entity_file` and `end_entity_folder`, which say
/// which kind they carry by which argument they are.
#[test]
fn the_end_entity_pool_takes_files_and_folders() {
    let dir = tempfile::tempdir().unwrap();
    let folder = folder_with(
        dir.path(),
        "targets",
        &[
            "ValidCertificatePathTest1EE.crt",
            "InvalidCASignatureTest2EE.crt",
        ],
    );

    let report = run(
        dir.path(),
        Pittv3Args {
            ta_inputs: vec![root()],
            ca_inputs: vec![
                example_str("GoodCACert.crt"),
                example_str("BadSignedCACert.crt"),
            ],
            ee_inputs: vec![folder, example_str("ValidrequireExplicitPolicyTest1EE.crt")],
            ..Default::default()
        },
    );

    assert_eq!(None, report.error);
    assert_eq!(
        3, report.totals.targets,
        "two targets from the folder and one named directly"
    );
}

/// Nothing to validate is still nothing to validate: a run with all three end entity arguments
/// absent returns an empty report rather than doing the work of building a graph first.
#[test]
fn no_targets_yields_an_empty_report() {
    let dir = tempfile::tempdir().unwrap();

    let report = run(
        dir.path(),
        Pittv3Args {
            ta_inputs: vec![root()],
            ca_inputs: vec![example_str("GoodCACert.crt")],
            ..Default::default()
        },
    );

    assert_eq!(0, report.totals.targets);
}

/// Builds a CBOR store over `names` by running a generate the way a user would, and returns the
/// file it was written to. Driven through `options_std` rather than assembled here because the
/// partial paths are the point of these two tests, and they exist only when the anchors the paths
/// end at are registered — which is what a generate run does and a hand-built `CertSource` does
/// not.
fn write_ca_store(dir: &Path, label: &str, names: &[&str]) -> String {
    let cbor = dir.join(label);
    let report = run(
        dir,
        Pittv3Args {
            ta_inputs: vec![root()],
            // A folder of its own: naming it `label` would put the source folder at the very path
            // the store is about to be written to.
            ca_folder: Some(folder_with(dir, &format!("{label}-source"), names)),
            cbor: Some(cbor.to_str().unwrap().to_string()),
            generate: true,
            ..Default::default()
        },
    );
    assert_eq!(None, report.error);
    cbor.to_str().unwrap().to_string()
}

/// A lone CBOR store is adopted with the partial paths it carries: those paths already describe
/// every path through it, so searching again would recompute what the store was serialized to
/// avoid.
#[test]
fn a_lone_store_keeps_its_partial_paths() {
    let dir = tempfile::tempdir().unwrap();
    let store = write_ca_store(dir.path(), "ca.cbor", CHAIN);

    let mut source = CertSource::new();
    let outcome = load_ca_inputs(
        &PkiEnvironment::default(),
        [store.as_str()],
        &mut source,
        TimeOfInterest::from_unix_secs(TOI).unwrap(),
    );

    assert_eq!(CHAIN.len(), outcome.certs);
    assert!(outcome.paths_adopted);
    assert!(source.num_partial_paths() > 0);
}

/// A store combined with anything else keeps only its certificates. A path spanning two sources
/// exists once they are searched together, so paths computed against the store alone would not
/// describe the union — and the caller is told to search by a false `paths_adopted`.
#[test]
fn a_store_beside_another_input_does_not_claim_the_graph() {
    let dir = tempfile::tempdir().unwrap();
    let store = write_ca_store(dir.path(), "ca.cbor", &CHAIN[..2]);
    let rest = example_str(CHAIN[2]);

    let toi = TimeOfInterest::from_unix_secs(TOI).unwrap();
    let pe = PkiEnvironment::default();

    // whichever order they arrive in
    for inputs in [
        [store.as_str(), rest.as_str()],
        [rest.as_str(), store.as_str()],
    ] {
        let mut source = CertSource::new();
        let outcome = load_ca_inputs(&pe, inputs, &mut source, toi);

        assert_eq!(3, outcome.certs, "{inputs:?}");
        assert!(!outcome.paths_adopted, "{inputs:?}");
    }
}

/// An unreadable CA entry is logged and skipped rather than failing the run: the others may still
/// carry what a path needs, and an intermediate that never arrives costs a path the run reports as
/// a path it did not find. The trust anchor pool makes the opposite choice, for the opposite
/// reason — see `load_trust_anchors.rs`.
#[test]
fn an_unreadable_ca_entry_does_not_lose_the_others() {
    let dir = tempfile::tempdir().unwrap();

    let report = run(
        dir.path(),
        Pittv3Args {
            ta_inputs: vec![root()],
            ca_inputs: vec!["does/not/exist".to_string(), example_str("GoodCACert.crt")],
            ee_inputs: vec![example_str("ValidCertificatePathTest1EE.crt")],
            ..Default::default()
        },
    );

    assert_eq!(None, report.error);
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
}
