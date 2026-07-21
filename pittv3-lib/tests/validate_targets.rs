//! Integration tests for the in-memory validate_targets entry point and the structured
//! ValidationReport it returns, using PKITS artifacts from the certval test suite.
#![cfg(feature = "std")]

use std::fs;
use std::path::Path;
use std::sync::Mutex;

use certval::*;
use pittv3_lib::report::*;
use pittv3_lib::std_utils::{validate_targets, ValidateOpts};

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

#[test]
fn validate_targets_report_shapes() {
    let flavor = "PKITS_data_p256/certs";
    let mut cps = base_settings();
    cps.set_check_revocation_status(false);
    let pe = build_pe(flavor, &cps);

    let targets = vec![
        (
            "valid".to_string(),
            read_example(flavor, "ValidCertificatePathTest1EE.crt"),
        ),
        (
            "badsig".to_string(),
            read_example(flavor, "InvalidEESignatureTest3EE.crt"),
        ),
    ];

    let events: Mutex<Vec<ProgressEvent>> = Mutex::new(vec![]);
    let progress = |e: ProgressEvent| {
        events.lock().unwrap().push(e);
    };

    let report = tokio_test::block_on(validate_targets(
        &pe,
        &cps,
        &targets,
        &ValidateOpts::default(),
        Some(&progress),
    ));

    assert_eq!(report.targets.len(), 2);
    assert_eq!(report.totals.targets, 2);
    assert_eq!(report.totals.paths_found, 2);
    assert_eq!(report.totals.valid_paths, 1);
    assert_eq!(report.totals.invalid_paths, 1);
    assert_eq!(report.time_of_interest, TOI);

    let valid = &report.targets[0];
    assert_eq!(valid.name, "valid");
    assert_eq!(valid.status, TargetStatus::Valid);
    assert!(valid
        .target
        .as_ref()
        .unwrap()
        .subject
        .contains("Valid EE Certificate Test1"));
    let valid_path = &valid.paths[0];
    assert_eq!(valid_path.status, Some(PathValidationStatus::Valid));
    assert!(valid_path.error.is_none());
    assert_eq!(valid_path.certs.len(), 3);
    assert!(valid_path.certs[0].subject.contains("Trust Anchor"));
    assert!(valid_path.certs[1].subject.contains("Good CA"));
    assert!(valid_path.failure_index.is_none());
    assert!(valid_path.failure_reasons.is_empty());
    let policy = valid_path.policy.as_ref().unwrap();
    assert!(policy.final_explicit_policy.is_some());
    assert!(policy.final_policy_mapping.is_some());
    assert!(policy.final_inhibit_any_policy.is_some());
    assert!(!policy.final_valid_policies.is_empty());

    let badsig = &report.targets[1];
    assert_eq!(badsig.status, TargetStatus::Invalid);
    let badsig_path = &badsig.paths[0];
    assert_eq!(
        badsig_path.status,
        Some(PathValidationStatus::SignatureVerificationFailure)
    );
    // trust-anchor-first indexing: 0 = TA, 1 = Good CA, 2 = target
    assert_eq!(badsig_path.failure_index, Some(2));
    assert!(badsig_path
        .failure_reasons
        .iter()
        .any(|r| r.contains("SignatureVerificationFailure")));

    // progress events cover both targets from start to completion
    let events = events.into_inner().unwrap();
    let starts = events
        .iter()
        .filter(|e| matches!(e, ProgressEvent::TargetStarted { .. }))
        .count();
    let completions = events
        .iter()
        .filter(|e| matches!(e, ProgressEvent::TargetCompleted { .. }))
        .count();
    let paths_completed = events
        .iter()
        .filter(|e| matches!(e, ProgressEvent::PathCompleted { .. }))
        .count();
    assert_eq!(starts, 2);
    assert_eq!(completions, 2);
    assert_eq!(paths_completed, 2);

    // the full report survives a JSON round trip
    let json = serde_json::to_string(&report).unwrap();
    let round_tripped: ValidationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(round_tripped.targets[0].status, TargetStatus::Valid);
    assert_eq!(round_tripped.targets[1].paths[0].failure_index, Some(2));
}

#[cfg(feature = "revocation")]
#[test]
fn validate_targets_revocation_undetermined_rollup() {
    let flavor = "PKITS_data_p256/certs";
    let mut cps = base_settings();
    cps.set_check_revocation_status(true);
    let pe = build_pe(flavor, &cps);

    let targets = vec![(
        "valid".to_string(),
        read_example(flavor, "ValidCertificatePathTest1EE.crt"),
    )];

    // no revocation artifacts are available, so the path passes RFC 5280 checks but revocation
    // status cannot be determined -- the rollup reports that as its own outcome
    let report = tokio_test::block_on(validate_targets(
        &pe,
        &cps,
        &targets,
        &ValidateOpts::default(),
        None,
    ));

    let target = &report.targets[0];
    assert_eq!(
        target.status,
        TargetStatus::ValidExceptRevocationUndetermined
    );
    let path = &target.paths[0];
    assert_eq!(
        path.status,
        Some(PathValidationStatus::RevocationStatusNotDetermined)
    );
    assert_eq!(path.revocation.len(), 2);
    assert_eq!(path.revocation[0].cert_index, 1);
    assert_eq!(path.revocation[0].method, RevocationMethod::None);
    assert_eq!(path.revocation[0].status, RevocationStatus::Undetermined);
    assert_eq!(path.revocation[1].cert_index, 2);
    assert_eq!(path.revocation[1].status, RevocationStatus::Undetermined);
}

// The PKITS 2048 artifacts are RSA-signed, so the stapled-CRL tests require the rsa feature,
// e.g., cargo test -p pittv3_lib --features rsa
#[cfg(all(feature = "revocation", feature = "rsa"))]
#[test]
fn validate_targets_stapled_crls() {
    let flavor = "PKITS_data_2048/certs";
    let crl_flavor = "PKITS_data_2048/crls";
    let mut cps = base_settings();
    cps.set_check_revocation_status(true);
    let pe = build_pe(flavor, &cps);

    let crls = vec![
        read_example(crl_flavor, "TrustAnchorRootCRL.crl"),
        read_example(crl_flavor, "GoodCACRL.crl"),
    ];

    let targets = vec![
        (
            "valid".to_string(),
            read_example(flavor, "ValidCertificatePathTest1EE.crt"),
        ),
        (
            "revoked".to_string(),
            read_example(flavor, "InvalidRevokedEETest3EE.crt"),
        ),
    ];

    // without stapled CRLs revocation status cannot be determined
    let report = tokio_test::block_on(validate_targets(
        &pe,
        &cps,
        &targets,
        &ValidateOpts::default(),
        None,
    ));
    assert_eq!(
        report.targets[0].status,
        TargetStatus::ValidExceptRevocationUndetermined
    );

    // with stapled CRLs status is determined for every certificate in the path
    let opts = ValidateOpts {
        crls,
        ..Default::default()
    };
    let report = tokio_test::block_on(validate_targets(&pe, &cps, &targets, &opts, None));

    let valid = &report.targets[0];
    assert_eq!(valid.status, TargetStatus::Valid);
    let valid_path = &valid.paths[0];
    assert_eq!(valid_path.revocation.len(), 2);
    assert_eq!(valid_path.revocation[0].method, RevocationMethod::Crl);
    assert_eq!(
        valid_path.revocation[0].status,
        RevocationStatus::NotRevoked
    );
    assert_eq!(valid_path.revocation[1].method, RevocationMethod::Crl);
    assert_eq!(
        valid_path.revocation[1].status,
        RevocationStatus::NotRevoked
    );

    let revoked = &report.targets[1];
    assert_eq!(revoked.status, TargetStatus::Revoked);
    let revoked_path = &revoked.paths[0];
    assert_eq!(
        revoked_path.status,
        Some(PathValidationStatus::CertificateRevokedEndEntity)
    );
    assert_eq!(revoked_path.failure_index, Some(2));
    assert_eq!(revoked_path.revocation[1].method, RevocationMethod::Crl);
    assert_eq!(revoked_path.revocation[1].status, RevocationStatus::Revoked);
}
