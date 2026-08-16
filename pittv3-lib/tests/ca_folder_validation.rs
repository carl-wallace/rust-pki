//! Integration tests for using a CA folder as a validation input.
//!
//! A folder of intermediates used to reach path building only by way of a generated CBOR store, so
//! a run given trust anchors, intermediates and a target found no paths at all and said nothing
//! about why. These tests pin the behavior that closes that: the folder is read into the graph the
//! run builds, no store required, and a folder that yields nothing says so.
#![cfg(feature = "std")]

use std::fs;
use std::path::{Path, PathBuf};

use certval::*;
use pittv3_lib::args::Pittv3Args;
use pittv3_lib::options_std::options_std;
use pittv3_lib::report::{TargetStatus, ValidationReport};

/// A time at which the PKITS fixtures are valid
const TOI: u64 = 1648039783;

const FLAVOR: &str = "../certval/tests/examples/PKITS_data_p256/certs";

fn example(name: &str) -> PathBuf {
    Path::new(FLAVOR).join(name)
}

/// Copies `name` from the PKITS fixtures into `dir`, which stands in for the folder a user points
/// the tool at, and returns the folder as the string the arguments carry.
fn folder_with(dir: &Path, names: &[&str]) -> String {
    fs::create_dir_all(dir).unwrap();
    for name in names {
        fs::copy(example(name), dir.join(name)).unwrap();
    }
    dir.to_str().unwrap().to_string()
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

/// Runs a validation of the PKITS test 1 end entity certificate with the given trust anchor and CA
/// folders. No CBOR store is involved, which is the point.
fn validate(dir: &Path, ta_folder: Option<String>, ca_folder: Option<String>) -> ValidationReport {
    let args = Pittv3Args {
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
    };
    tokio_test::block_on(options_std(&args))
}

/// A trust anchor folder plus a CA folder is enough to validate: the intermediate is read into the
/// graph the run builds, so neither a store nor a generate step is needed.
#[test]
fn ca_folder_supplies_intermediates() {
    let dir = tempfile::tempdir().unwrap();
    let ta_folder = folder_with(&dir.path().join("ta"), &["TrustAnchorRootCertificate.crt"]);
    let ca_folder = folder_with(&dir.path().join("ca"), &["GoodCACert.crt"]);

    let report = validate(dir.path(), Some(ta_folder), Some(ca_folder));

    assert_eq!(None, report.error);
    assert_eq!(1, report.totals.targets);
    assert_eq!(1, report.totals.paths_found);
    assert_eq!(1, report.totals.valid_paths);
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
    // The path is trust anchor, intermediate, target
    assert_eq!(3, report.targets[0].paths[0].certs.len());
}

/// Both inputs also take a single file, so nothing has to be assembled into a directory first. The
/// fixtures are the reason this matters: PKITS ships no folder holding only its root, so validating
/// against it used to mean building one.
#[test]
fn trust_anchor_and_ca_can_be_single_files() {
    let dir = tempfile::tempdir().unwrap();

    let report = validate(
        dir.path(),
        Some(
            example("TrustAnchorRootCertificate.crt")
                .to_str()
                .unwrap()
                .to_string(),
        ),
        Some(example("GoodCACert.crt").to_str().unwrap().to_string()),
    );

    assert_eq!(None, report.error);
    assert_eq!(1, report.totals.valid_paths);
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
    assert_eq!(3, report.targets[0].paths[0].certs.len());
}

/// A file and a folder are interchangeable on either side, so the mixed forms have to work too —
/// this is the shape a GUI produces when one input was picked and the other typed.
#[test]
fn a_file_and_a_folder_mix() {
    let dir = tempfile::tempdir().unwrap();
    let ca_folder = folder_with(&dir.path().join("ca"), &["GoodCACert.crt"]);

    let report = validate(
        dir.path(),
        Some(
            example("TrustAnchorRootCertificate.crt")
                .to_str()
                .unwrap()
                .to_string(),
        ),
        Some(ca_folder),
    );

    assert_eq!(TargetStatus::Valid, report.targets[0].status);
}

/// The same run without the CA folder is the control: the intermediate is the only thing missing,
/// so the outcome must be no paths rather than a path found some other way.
#[test]
fn no_ca_folder_finds_no_path() {
    let dir = tempfile::tempdir().unwrap();
    let ta_folder = folder_with(&dir.path().join("ta"), &["TrustAnchorRootCertificate.crt"]);

    let report = validate(dir.path(), Some(ta_folder), None);

    assert_eq!(0, report.totals.paths_found);
    assert_eq!(TargetStatus::NoPathsFound, report.targets[0].status);
    // Nothing was supplied that could have been read, so the folder is not blamed
    assert!(
        !report.targets[0]
            .no_paths_hints
            .iter()
            .any(|h| h.contains("CA folder")),
        "hints: {:?}",
        report.targets[0].no_paths_hints
    );
}

/// A folder that is read and yields nothing looks exactly like no folder at all by the time path
/// building runs, so the zero-path diagnosis has to name it.
#[test]
fn empty_ca_folder_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let ta_folder = folder_with(&dir.path().join("ta"), &["TrustAnchorRootCertificate.crt"]);
    // A folder holding a file the reader skips: only .der, .cer and .crt are read
    let ca_dir = dir.path().join("ca");
    fs::create_dir_all(&ca_dir).unwrap();
    fs::write(ca_dir.join("notes.txt"), "not a certificate").unwrap();

    let report = validate(
        dir.path(),
        Some(ta_folder),
        Some(ca_dir.to_str().unwrap().to_string()),
    );

    assert_eq!(TargetStatus::NoPathsFound, report.targets[0].status);
    assert!(
        report.targets[0]
            .no_paths_hints
            .iter()
            .any(|h| h.contains("no certificate was read from it")),
        "hints: {:?}",
        report.targets[0].no_paths_hints
    );
}
