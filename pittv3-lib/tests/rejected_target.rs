//! Integration tests for the two ways an input yields no certification path without the store
//! having anything to do with it.
//!
//! A check that fails while the path is being built -- the target is not valid at the time of
//! interest, say -- is a rejection of the certificate, not an absence of candidate issuers. A file
//! that is not a certificate is not even that. Both were reported as "no paths found", which reads
//! like the store or the configuration is wrong when nothing about either is. These tests pin each
//! outcome to its own status, carrying its own reason.
#![cfg(feature = "std")]

use std::fs;
use std::path::{Path, PathBuf};

use certval::*;
use pittv3_lib::args::Pittv3Args;
use pittv3_lib::options_std::options_std;
use pittv3_lib::report::{TargetStatus, ValidationReport};

/// A time at which the PKITS fixtures are valid
const TOI: u64 = 1648039783;

/// Long after the PKITS fixtures expire
const TOI_AFTER_EXPIRY: u64 = 4102444800;

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

/// Writes the settings file a run reads. Revocation checking is off: these tests are about what the
/// path builder does with the target, and the fixtures carry no revocation material to answer with.
fn settings_file(dir: &Path, toi: u64) -> String {
    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(toi).unwrap());
    cps.set_check_revocation_status(false);
    let path = dir.join("settings.json");
    fs::write(&path, serde_json::to_string(&cps).unwrap()).unwrap();
    path.to_str().unwrap().to_string()
}

fn validate(dir: &Path, toi: u64) -> ValidationReport {
    let ta_folder = folder_with(&dir.join("ta"), &["TrustAnchorRootCertificate.crt"]);
    let ca_folder = folder_with(&dir.join("ca"), &["GoodCACert.crt"]);
    let args = Pittv3Args {
        ta_folder: Some(ta_folder),
        ca_folder: Some(ca_folder),
        end_entity_file: Some(
            example("ValidCertificatePathTest1EE.crt")
                .to_str()
                .unwrap()
                .to_string(),
        ),
        settings: Some(settings_file(dir, toi)),
        time_of_interest: toi,
        ..Default::default()
    };
    tokio_test::block_on(options_std(&args))
}

/// Runs a validation over a folder of targets rather than a single file, which is how a file that
/// is not a certificate reaches the run at all: the walk admits by extension.
fn validate_folder(dir: &Path, ee_folder: &Path) -> ValidationReport {
    let ta_folder = folder_with(&dir.join("ta"), &["TrustAnchorRootCertificate.crt"]);
    let ca_folder = folder_with(&dir.join("ca"), &["GoodCACert.crt"]);
    let args = Pittv3Args {
        ta_folder: Some(ta_folder),
        ca_folder: Some(ca_folder),
        end_entity_folder: Some(ee_folder.to_str().unwrap().to_string()),
        settings: Some(settings_file(dir, TOI)),
        time_of_interest: TOI,
        ..Default::default()
    };
    tokio_test::block_on(options_std(&args))
}

/// The control: the same inputs at a time the fixtures are valid produce a path.
#[test]
fn valid_at_time_of_interest_finds_a_path() {
    let dir = tempfile::tempdir().unwrap();
    let report = validate(dir.path(), TOI);
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
}

/// The same inputs at a time the target has expired: the certificate is rejected, so the report has
/// to say that rather than report the neutral absence of paths.
#[test]
fn expired_target_is_invalid_not_no_paths_found() {
    let dir = tempfile::tempdir().unwrap();
    let report = validate(dir.path(), TOI_AFTER_EXPIRY);

    let target = &report.targets[0];
    assert_eq!(TargetStatus::Invalid, target.status);
    // The reason rides on the target, because no path was built for it to hang off
    assert!(
        target
            .error
            .as_deref()
            .is_some_and(|e| e.contains("InvalidNotAfterDate")),
        "reason: {:?}",
        target.error
    );
    // Nothing about the store is at fault, so the store is not blamed
    assert!(
        target.no_paths_hints.is_empty(),
        "hints: {:?}",
        target.no_paths_hints
    );
    // No path was built, so none is reported and none is counted. Reporting the rejection as a
    // one-certificate path put an entry in the path list that was never a path, and every total
    // that counts that list then counted it.
    assert!(target.paths.is_empty(), "paths: {:?}", target.paths);
    assert_eq!(0, report.totals.paths_found);
    assert_eq!(0, report.totals.valid_paths);
    assert_eq!(0, report.totals.invalid_paths);
}

/// A file named like a certificate and holding something else. The PIV credentials that turned this
/// up ship CHUID data as `.crt`, which the walk admits and the parser then rejects; the run filed
/// them under no-paths-found, which reads as a complaint about the store for input that was never a
/// certificate at all.
#[test]
fn a_file_that_is_not_a_certificate_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let ee_dir = dir.path().join("ee");
    fs::create_dir_all(&ee_dir).unwrap();
    fs::copy(
        example("ValidCertificatePathTest1EE.crt"),
        ee_dir.join("ValidCertificatePathTest1EE.crt"),
    )
    .unwrap();
    // APPLICATION [13], primitive -- the outer tag PIV CHUID data carries, and not a SEQUENCE
    fs::write(
        ee_dir.join("chuid.crt"),
        [0x4d, 0x04, 0x01, 0x02, 0x03, 0x04],
    )
    .unwrap();

    let report = validate_folder(dir.path(), &ee_dir);

    // Both files are reported: one that is dropped silently leaves a user comparing the folder with
    // the run and nothing to reconcile the two counts with
    assert_eq!(2, report.targets.len());

    let certificate = report
        .targets
        .iter()
        .find(|t| t.name.ends_with("ValidCertificatePathTest1EE.crt"))
        .unwrap();
    assert_eq!(TargetStatus::Valid, certificate.status);
    assert_eq!(None, certificate.error);

    let not_a_certificate = report
        .targets
        .iter()
        .find(|t| t.name.ends_with("chuid.crt"))
        .unwrap();
    assert_eq!(TargetStatus::ParseError, not_a_certificate.status);
    // The status says a certificate could not be read; the error says what went wrong reading it
    assert!(
        not_a_certificate.error.is_some(),
        "no reason carried: {not_a_certificate:?}"
    );
    // Nothing about the store bears on it, so the store is not blamed and no path is claimed
    assert!(not_a_certificate.no_paths_hints.is_empty());
    assert!(not_a_certificate.paths.is_empty());
    assert_eq!(None, not_a_certificate.target);
}
