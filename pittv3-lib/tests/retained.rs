//! Integration tests for path retention: the paths a run keeps so its artifacts can be exported
//! afterwards, and the [`RetainedPath`] they are kept as.
//!
//! A results folder is asked for before a run; retention is the other case, chosen after the
//! outcome is known. These cover the entry point that offers it and the shape of what comes back.
#![cfg(feature = "std")]

use std::fs;
use std::path::Path;

use certval::*;
use pittv3_lib::retained::RetainedPath;
use pittv3_lib::std_utils::{validate_targets_retaining, ValidateOpts};

const TOI: u64 = 1648039783;

fn read_example(flavor: &str, name: &str) -> Vec<u8> {
    let p = Path::new("../certval/tests/examples")
        .join(flavor)
        .join(name);
    fs::read(&p).unwrap_or_else(|e| panic!("failed to read {}: {e}", p.display()))
}

/// Builds a PkiEnvironment with the PKITS trust anchor and Good CA from the indicated flavor
/// folder (certs are pushed directly, i.e., no filesystem-folder machinery).
fn build_pe(flavor: &str, cps: &CertificationPathSettings) -> PkiEnvironment {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    let mut ta_store = TaSource::new();
    ta_store.push(CertFile {
        filename: "TrustAnchorRootCertificate.crt".to_string(),
        bytes: read_example(flavor, "TrustAnchorRootCertificate.crt"),
    });
    ta_store.initialize().unwrap();
    pe.add_trust_anchor_source(Box::new(ta_store));

    let mut cert_source = CertSource::default();
    cert_source.push(CertFile {
        filename: "GoodCACert.crt".to_string(),
        bytes: read_example(flavor, "GoodCACert.crt"),
    });
    cert_source.initialize(cps).unwrap();
    cert_source.find_all_partial_paths(&pe, cps);
    pe.add_certificate_source(Box::new(cert_source));

    pe
}

fn base_settings() -> CertificationPathSettings {
    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(TOI).unwrap());
    cps
}

fn targets(flavor: &str) -> Vec<(String, Vec<u8>)> {
    vec![
        (
            "valid".to_string(),
            read_example(flavor, "ValidCertificatePathTest1EE.crt"),
        ),
        (
            "badsig".to_string(),
            read_example(flavor, "InvalidEESignatureTest3EE.crt"),
        ),
    ]
}

/// Retention is off unless the call site asks, and asking yields the paths the report describes --
/// including the one that failed, which is the case someone most wants the material for.
///
/// Named through `pittv3_lib::retained::RetainedPath` on purpose: the type moved here from
/// `pittv3-gui-lib` so that both producers can emit it, and a test that only inferred it from the
/// return type would keep compiling if the module or its visibility changed.
#[test]
fn retained_paths_are_kept_only_when_asked() {
    let flavor = "PKITS_data_p256/certs";
    let mut cps = base_settings();
    cps.set_check_revocation_status(false);
    let pe = build_pe(flavor, &cps);
    let targets = targets(flavor);

    // Declining to retain costs the caller nothing and yields nothing to export from.
    let (report, retained): (_, Vec<RetainedPath>) = tokio_test::block_on(
        validate_targets_retaining(&pe, &cps, &targets, &ValidateOpts::default(), None, false),
    );
    assert!(retained.is_empty());
    let paths_reported = report.totals.paths_found;
    assert!(paths_reported > 0, "the run found no paths to retain");

    // Retaining yields exactly the paths the report accounts for, failures included.
    let (report, retained): (_, Vec<RetainedPath>) = tokio_test::block_on(
        validate_targets_retaining(&pe, &cps, &targets, &ValidateOpts::default(), None, true),
    );
    assert_eq!(retained.len(), report.totals.paths_found);
    assert_eq!(retained.len(), paths_reported);
    assert!(retained.iter().any(|r| r.target_name == "valid"));
    assert!(
        retained.iter().any(|r| r.target_name == "badsig"),
        "a path that failed validation is still material worth exporting"
    );
}

/// What a retained path carries is what an export is assembled from: the path as validated, the
/// results recorded while validating it, and the settings *that path* was judged under rather than
/// the run's -- a manifest reporting the run's would name inputs the path was not validated
/// against.
#[test]
fn a_retained_path_carries_what_an_export_needs() {
    let flavor = "PKITS_data_p256/certs";
    let mut cps = base_settings();
    cps.set_check_revocation_status(false);
    let pe = build_pe(flavor, &cps);

    let (_report, retained): (_, Vec<RetainedPath>) =
        tokio_test::block_on(validate_targets_retaining(
            &pe,
            &cps,
            &targets(flavor),
            &ValidateOpts::default(),
            None,
            true,
        ));

    let valid: &RetainedPath = retained
        .iter()
        .find(|r| r.target_name == "valid")
        .expect("the valid target retained no path");

    // The path is the one the report describes: trust anchor, Good CA, target.
    assert_eq!(valid.path.intermediates.len(), 1);
    assert!(valid
        .path
        .target
        .decoded()
        .tbs_certificate()
        .subject()
        .to_string()
        .contains("Valid EE Certificate Test1"));

    // The settings travel with the path, and are the ones it was judged under.
    assert!(!valid.cps.0.is_empty());
    assert_eq!(valid.cps.get_time_of_interest().as_unix_secs(), TOI);

    // The results are populated, which is what a manifest renders from.
    assert!(!valid.cpr.0.is_empty());
}
