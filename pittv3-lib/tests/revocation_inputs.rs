//! Integration tests for `rev_inputs` — supplying revocation artifacts a run should use.
//!
//! Until this existed the only way to hand pittv3 a CRL was `--crl-folder`, which is an *index*:
//! it is written as well as read, and indexing deletes any CRL not valid at the time of interest.
//! There was no way at all to hand it an OCSP response — `ValidateOpts::crls` and
//! `CertificationPath::ocsp_responses` were reachable only from in-memory callers, and the CLI set
//! neither. So a run against captured evidence, or on a machine with no route to a responder, could
//! not determine revocation status however much of the answer the user was holding.
//!
//! The fixtures are a captured path (trust anchor, intermediate, target) with both a CRL and an OCSP
//! response for each position, so the same path can be judged from either kind of artifact.
#![cfg(all(feature = "std", feature = "revocation", feature = "rsa"))]

use std::fs;
use std::path::{Path, PathBuf};

use certval::*;
use pittv3_lib::args::Pittv3Args;
use pittv3_lib::options_std::options_std;
use pittv3_lib::report::{TargetStatus, ValidationReport};
use pittv3_lib::std_utils::load_revocation_inputs;

/// The time the fixtures were captured and are valid at, matching `certval/tests/revocation.rs`.
/// The target expired 2022-08-02, so nothing here can be judged at the present time.
const TOI: u64 = 1646567209;

const CAPTURED: &str = "../certval/tests/examples/harvard.edu";

fn fixture(name: &str) -> String {
    Path::new(CAPTURED).join(name).to_str().unwrap().to_string()
}

/// Copies the named fixtures into a folder of their own, so a test can hand a run exactly the
/// artifacts it means to and no others.
fn folder_with(dir: &Path, label: &str, names: &[&str]) -> String {
    let folder = dir.join(label);
    fs::create_dir_all(&folder).unwrap();
    for name in names {
        fs::copy(fixture(name), folder.join(name)).unwrap();
    }
    folder.to_str().unwrap().to_string()
}

/// Settings with revocation checking on — the point of these tests — and every remote route off, so
/// what determines the status is the supplied artifact and nothing else. Without this the test would
/// pass or fail on whether a responder still answers about a certificate that expired in 2022.
fn settings_file(dir: &Path) -> String {
    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(TOI).unwrap());
    cps.set_check_revocation_status(true);
    cps.set_check_ocsp_from_aia(false);
    cps.set_check_crldp_http(false);
    cps.set_retrieve_from_aia_sia_http(false);
    let path = dir.join("settings.json");
    fs::write(&path, serde_json::to_string(&cps).unwrap()).unwrap();
    path.to_str().unwrap().to_string()
}

/// Validates the captured target against the captured anchor and intermediate, with whatever
/// revocation artifacts `rev_inputs` names.
fn validate(dir: &Path, rev_inputs: Vec<String>) -> ValidationReport {
    tokio_test::block_on(options_std(&Pittv3Args {
        ta_inputs: vec![fixture("0-ta.der")],
        ca_inputs: vec![fixture("1.der")],
        ee_inputs: vec![fixture("2-target.der")],
        rev_inputs,
        settings: Some(settings_file(dir)),
        time_of_interest: TOI,
        ..Default::default()
    }))
}

/// With no revocation artifact and no way to fetch one, the run cannot say — which is the baseline
/// the two tests below are measured against. Without it they would prove only that the path is
/// good, not that the artifact is what answered the revocation question.
#[test]
fn without_an_artifact_the_status_is_undetermined() {
    let dir = tempfile::tempdir().unwrap();

    let report = validate(dir.path(), vec![]);

    assert_eq!(None, report.error);
    assert_eq!(1, report.totals.paths_found);
    assert_ne!(
        TargetStatus::Valid,
        report.targets[0].status,
        "nothing answered the revocation question, so the run must not claim Valid"
    );
}

/// A CRL named on the arguments is stapled into the path and answers for it. The folder is not
/// touched: this is the read-only counterpart of `--crl-folder`, which would have deleted from it.
#[test]
fn supplied_crls_determine_status() {
    let dir = tempfile::tempdir().unwrap();
    let crls = folder_with(dir.path(), "crls", &["1-crl.crl", "2-crl.crl"]);

    let report = validate(dir.path(), vec![crls.clone()]);

    assert_eq!(None, report.error);
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
    assert_eq!(
        2,
        fs::read_dir(&crls).unwrap().count(),
        "an input folder is read, never pruned"
    );
}

/// An OCSP response named on the arguments is filed against the certificate its CertID answers
/// about and determines status for it. Nothing tells the run which position a response belongs to —
/// the response says so itself.
#[test]
fn supplied_ocsp_responses_determine_status() {
    let dir = tempfile::tempdir().unwrap();
    let responses = folder_with(dir.path(), "ocsp", &["1-ocsp.ocspResp", "2-ocsp.ocspResp"]);

    let report = validate(dir.path(), vec![responses]);

    assert_eq!(None, report.error);
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
}

/// Entries may also name single artifacts, and the two kinds mix in one pool. A run should not have
/// to be told which is which, because the user holding them was not told either.
#[test]
fn the_two_kinds_mix_in_one_pool() {
    let dir = tempfile::tempdir().unwrap();

    let report = validate(
        dir.path(),
        vec![fixture("1-crl.crl"), fixture("2-ocsp.ocspResp")],
    );

    assert_eq!(None, report.error);
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
}

/// What each artifact is comes from its bytes, not its name. The captured folder is the honest test
/// of that: it holds CRLs with a `.crl` extension, OCSP responses with an extension nothing else
/// uses, the three certificates of the path, and a text manifest. Only the first two kinds are
/// revocation artifacts, and nothing in the names would separate them reliably.
#[test]
fn a_mixed_folder_is_sorted_by_content() {
    let loaded = load_revocation_inputs([CAPTURED]);

    assert_eq!(2, loaded.crls.len(), "1-crl.crl and 2-crl.crl");
    assert_eq!(
        2,
        loaded.ocsp_responses.len(),
        "1-ocsp.ocspResp and 2-ocsp.ocspResp"
    );
}

/// An entry naming nothing readable is reported and skipped rather than failing the run, matching
/// the CA pool: what a run was handed is still worth using when part of it is a typo.
#[test]
fn an_unreadable_entry_does_not_lose_the_others() {
    let dir = tempfile::tempdir().unwrap();

    let report = validate(
        dir.path(),
        vec![
            "does/not/exist".to_string(),
            fixture("1-crl.crl"),
            fixture("2-crl.crl"),
        ],
    );

    assert_eq!(None, report.error);
    assert_eq!(TargetStatus::Valid, report.targets[0].status);
}

/// A response about some other certificate is stapled nowhere, and the path is judged as though it
/// had not been supplied. Silence would be wrong here in the other direction too: filing it against
/// a position it does not answer for would have the run report a status on the strength of evidence
/// about a different certificate.
#[test]
fn a_response_about_another_certificate_answers_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere: PathBuf =
        Path::new("../certval/tests/examples/amazon.com/2-ocsp.ocspResp").into();
    assert!(elsewhere.is_file(), "fixture moved");

    let report = validate(dir.path(), vec![elsewhere.to_str().unwrap().to_string()]);

    assert_eq!(None, report.error);
    assert_ne!(
        TargetStatus::Valid,
        report.targets[0].status,
        "a response about another certificate must not settle this one"
    );
}
