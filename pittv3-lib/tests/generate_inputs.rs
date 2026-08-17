//! Integration tests for the inputs a generate run accepts.
//!
//! Validation learned to take a single file wherever it takes a folder, but generation did not:
//! `build_graph` handed the CA input straight to the folder-walking functions, which return
//! `NotFound` for anything that is not a directory. So a store could be validated against with a
//! file for its CA input but not built from one, and the argument's own help text promised
//! otherwise. These tests pin both halves of the fix — a CA store and a trust anchor store, each
//! built from a named file — and then use what was built, since a store that cannot be validated
//! against has not really been generated.
#![cfg(feature = "std")]

use std::fs;
use std::path::Path;

use certval::*;
use pittv3_lib::args::Pittv3Args;
use pittv3_lib::options_std::options_std;
use pittv3_lib::report::{TargetStatus, ValidationReport};

/// A time at which the PKITS fixtures are valid
const TOI: u64 = 1648039783;

const FLAVOR: &str = "../certval/tests/examples/PKITS_data_p256/certs";

fn example(name: &str) -> String {
    Path::new(FLAVOR).join(name).to_str().unwrap().to_string()
}

/// Writes the settings file a run reads, holding the time of interest and turning revocation
/// checking off: these tests are about which certificates reach the graph, and the PKITS fixtures
/// carry no revocation material to answer with.
fn settings_file(dir: &Path) -> String {
    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(TOI).unwrap());
    cps.set_check_revocation_status(false);
    let path = dir.join("settings.json");
    fs::write(&path, serde_json::to_string(&cps).unwrap()).unwrap();
    path.to_str().unwrap().to_string()
}

fn run(args: Pittv3Args) -> ValidationReport {
    tokio_test::block_on(options_std(&args))
}

/// Generates a store at `cbor` from `ca_input`, which may name a file or a folder. `ta_store` picks
/// which kind: a trust anchor store or the usual store of intermediates and partial paths.
fn generate(dir: &Path, ca_input: &str, cbor: &Path, ta_store: bool) {
    run(Pittv3Args {
        ta_folder: Some(example("TrustAnchorRootCertificate.crt")),
        ca_folder: Some(ca_input.to_string()),
        cbor: Some(cbor.to_str().unwrap().to_string()),
        generate: true,
        cbor_ta_store: ta_store,
        settings: Some(settings_file(dir)),
        time_of_interest: TOI,
        ..Default::default()
    });
}

/// Validates the PKITS test 1 end entity certificate with whatever trust anchor and CA material the
/// caller supplies, so a generated store can be exercised the way a user would use it.
fn validate(
    dir: &Path,
    ta_folder: Option<String>,
    ta_cbor: Option<String>,
    ca_folder: Option<String>,
    cbor: Option<String>,
) -> ValidationReport {
    run(Pittv3Args {
        ta_folder,
        ta_cbor,
        ca_folder,
        cbor,
        end_entity_file: Some(example("ValidCertificatePathTest1EE.crt")),
        settings: Some(settings_file(dir)),
        time_of_interest: TOI,
        ..Default::default()
    })
}

/// A CA store built from one named certificate, then validated against. The generate step used to
/// fail here for want of a directory, leaving an empty CBOR file behind and no path to be found.
#[test]
fn generates_a_ca_store_from_a_single_file() {
    let dir = tempfile::tempdir().unwrap();
    let cbor = dir.path().join("ca.cbor");

    generate(dir.path(), &example("GoodCACert.crt"), &cbor, false);

    assert!(cbor.is_file());
    let report = validate(
        dir.path(),
        Some(example("TrustAnchorRootCertificate.crt")),
        None,
        None,
        Some(cbor.to_str().unwrap().to_string()),
    );

    assert_eq!(None, report.error);
    assert_eq!(1, report.totals.valid_paths);
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
    // The path is trust anchor, intermediate, target
    assert_eq!(3, report.targets[0].paths[0].certs.len());
}

/// A trust anchor store built from one named anchor, then used as the anchors for a run. Note the
/// anchors come from the CA input rather than the trust anchor input when `cbor_ta_store` is set —
/// that is the flag's contract, and it is the reason this file is worth having.
#[test]
fn generates_a_ta_store_from_a_single_file() {
    let dir = tempfile::tempdir().unwrap();
    let cbor = dir.path().join("ta.cbor");

    generate(
        dir.path(),
        &example("TrustAnchorRootCertificate.crt"),
        &cbor,
        true,
    );

    assert!(cbor.is_file());
    let report = validate(
        dir.path(),
        None,
        Some(cbor.to_str().unwrap().to_string()),
        Some(example("GoodCACert.crt")),
        None,
    );

    assert_eq!(None, report.error);
    assert_eq!(1, report.totals.valid_paths);
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
}

/// A CBOR store named in the trust anchor or CA input is read as one rather than skipped.
///
/// The app exports a store as `ta.cbor` and `ca.cbor`, and the obvious place to then put them is
/// the TA and CA inputs — which read certificates, so both files were silently ignored and the run
/// found nothing with no explanation. Both rows now merge a store's contents into the same source
/// the rest of the material goes into, which is also the only way to add a second store to a run:
/// the `ta_cbor` and `cbor` arguments hold one path each.
#[test]
fn ta_and_ca_inputs_accept_a_cbor_store() {
    let dir = tempfile::tempdir().unwrap();
    let ta_cbor = dir.path().join("ta.cbor");
    let ca_cbor = dir.path().join("ca.cbor");

    generate(
        dir.path(),
        &example("TrustAnchorRootCertificate.crt"),
        &ta_cbor,
        true,
    );
    generate(dir.path(), &example("GoodCACert.crt"), &ca_cbor, false);

    // Both stores handed to the certificate inputs, not to the CBOR arguments
    let report = validate(
        dir.path(),
        Some(ta_cbor.to_str().unwrap().to_string()),
        None,
        Some(ca_cbor.to_str().unwrap().to_string()),
        None,
    );

    assert_eq!(None, report.error);
    assert_eq!(1, report.totals.valid_paths);
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
    assert_eq!(3, report.targets[0].paths[0].certs.len());
}

/// A folder is still read as a folder, so the dispatch has not traded one input shape for the
/// other.
#[test]
fn generates_a_ca_store_from_a_folder() {
    let dir = tempfile::tempdir().unwrap();
    let ca_folder = dir.path().join("ca");
    fs::create_dir_all(&ca_folder).unwrap();
    fs::copy(example("GoodCACert.crt"), ca_folder.join("GoodCACert.crt")).unwrap();
    let cbor = dir.path().join("ca.cbor");

    generate(dir.path(), ca_folder.to_str().unwrap(), &cbor, false);

    assert!(cbor.is_file());
    let report = validate(
        dir.path(),
        Some(example("TrustAnchorRootCertificate.crt")),
        None,
        None,
        Some(cbor.to_str().unwrap().to_string()),
    );

    assert_eq!(TargetStatus::Valid, report.targets[0].status);
}
