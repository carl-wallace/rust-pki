//! Alternate certificates per draft-davidben-lamps-turducken-certs through the validation path the
//! desktop and browser frontends share.
//!
//! The outer certificates are PKITS end entity certificates re-signed by the stock RSA 2048 PKITS
//! CA with an ML-DSA-65 alternate embedded. The ML-DSA-65 trust anchor and CA have names and key
//! identifiers of their own, so each candidate has an issuer in only one of the two environments and
//! which candidate validates is decided by the trust anchors.

// RSA and ML-DSA verification are needed alongside `turducken`, since one environment is each
#![cfg(all(feature = "turducken", feature = "pqc", feature = "rsa"))]

use certval::CertificationPathSettings;
use pittv3_gui_lib::export::{path_entries, PATH_LOG_NAME};
use pittv3_gui_lib::gui_settings_model::SettingsModel;
use pittv3_gui_lib::validate::{prepare_validation, validate_prepared_retaining};
use pittv3_lib::report::{TargetReport, TargetStatus};

const RSA_TA: &[u8] = include_bytes!(
    "../../certval/tests/examples/PKITS_data_2048/certs/TrustAnchorRootCertificate.crt"
);
const RSA_CA: &[u8] =
    include_bytes!("../../certval/tests/examples/PKITS_data_2048/certs/GoodCACert.crt");
const ML_DSA_TA: &[u8] =
    include_bytes!("examples/turducken/ml_dsa_65_TrustAnchorRootCertificate.der");
const ML_DSA_CA: &[u8] = include_bytes!("examples/turducken/ml_dsa_65_GoodCACert.der");
const VALID: &[u8] = include_bytes!("examples/turducken/ValidCertificatePathTest1EE.der");
const BAD_SIGNATURE: &[u8] = include_bytes!("examples/turducken/InvalidEESignatureTest3EE.der");

/// PKITS settings: its time of interest, with revocation off since no CRLs are supplied
fn settings() -> CertificationPathSettings {
    let model = SettingsModel {
        time_of_interest: Some(1647264981),
        ..SettingsModel::default()
    };
    let mut cps = CertificationPathSettings::default();
    model.apply(&mut cps).expect("a valid time of interest");
    cps.set_check_revocation_status(false);
    cps
}

/// Validates `ee` against an environment holding only `ta` and `ca`, returning the report and each
/// path's log as an export renders it.
fn validate(ta: &[u8], ca: &[u8], ee: &[u8]) -> (TargetReport, Vec<String>) {
    let cps = settings();
    let tas = [("ta.der".to_string(), ta.to_vec())];
    let cas = [("ca.der".to_string(), ca.to_vec())];
    #[cfg(feature = "revocation")]
    let prepared = prepare_validation(None, &tas, &cas, &cps, None);
    #[cfg(not(feature = "revocation"))]
    let prepared = prepare_validation(None, &tas, &cas, &cps);
    let (prepared, _) = prepared.expect("an environment");
    let (mut reports, _, retained) = validate_prepared_retaining(
        &prepared,
        &cps,
        &[("ee.der".to_string(), ee.to_vec())],
        true,
        true,
    );
    let logs = retained
        .iter()
        .map(|r| {
            let entries = path_entries(
                prepared.environment(),
                &r.path,
                Some(&r.cps),
                &r.cpr,
                Some(r.duration_ms),
                None,
                r.candidate.as_deref(),
            );
            let (_, log) = entries
                .into_iter()
                .find(|(name, _)| name == PATH_LOG_NAME)
                .expect("a path log");
            String::from_utf8(log).expect("text")
        })
        .collect();
    assert_eq!(reports.len(), 1);
    (reports.remove(0), logs)
}

#[test]
fn the_outer_validates_with_rsa_anchors() {
    let (report, logs) = validate(RSA_TA, RSA_CA, VALID);
    assert_eq!(report.status, TargetStatus::Valid);
    let valid: Vec<_> = report.paths.iter().filter(|p| p.error.is_none()).collect();
    assert_eq!(valid.len(), 1);
    assert_eq!(valid[0].candidate, None, "built from the outer certificate");
    // The alternate's issuer is not in this environment, so no path is built for it
    assert!(report.paths.iter().all(|p| p.candidate.is_none()));
    assert!(logs.iter().all(|l| !l.contains("Built from")));
}

#[test]
fn the_alternate_validates_with_ml_dsa_anchors() {
    let (report, logs) = validate(ML_DSA_TA, ML_DSA_CA, VALID);
    assert_eq!(report.status, TargetStatus::Valid);
    let valid: Vec<_> = report.paths.iter().filter(|p| p.error.is_none()).collect();
    assert_eq!(valid.len(), 1);
    let candidate = valid[0]
        .candidate
        .as_deref()
        .expect("built from an alternate");
    assert!(
        candidate.starts_with("alternate 1 (id-ml-dsa-65 from "),
        "{candidate}"
    );
    // The outer's issuer is not in this environment, so no path is built for it
    assert!(report.paths.iter().all(|p| p.candidate.is_some()));
    // An export's path log says which candidate the target is
    assert_eq!(logs.len(), 1);
    assert!(
        logs[0].contains(&format!("\t\t* Built from: {candidate}\n")),
        "{}",
        logs[0]
    );
}

#[test]
fn a_bad_signature_fails_with_either_anchors() {
    for (ta, ca) in [(RSA_TA, RSA_CA), (ML_DSA_TA, ML_DSA_CA)] {
        let (report, _) = validate(ta, ca, BAD_SIGNATURE);
        assert_eq!(report.status, TargetStatus::Invalid);
    }
}

/// The Turducken Demo PKI, whose certificates name CRL distribution points
#[cfg(feature = "revocation")]
mod demo {
    pub const RSA_ROOT: &[u8] = include_bytes!("examples/turducken/demo-rsa-root.der");
    pub const RSA_CA: &[u8] = include_bytes!("examples/turducken/demo-rsa-ca.der");
    pub const ML_DSA_ROOT: &[u8] = include_bytes!("examples/turducken/demo-ml-dsa-65-root.der");
    pub const ML_DSA_CA: &[u8] = include_bytes!("examples/turducken/demo-ml-dsa-65-ca.der");
    pub const OUTER: &[u8] = include_bytes!("examples/turducken/demo-ee-outer.der");
    pub const BASE: &str = "https://downloads.redhoundsoftware.com/turducken/demo/";
}

/// Returns the CRL distribution points the browser would retrieve before validating the demo outer
/// certificate against an environment holding only `ta` and `ca`.
#[cfg(feature = "revocation")]
fn harvested_crl_dps(ta: &[u8], ca: &[u8]) -> Vec<String> {
    let model = SettingsModel {
        // inside the validity of every demo certificate
        time_of_interest: Some(1798761600),
        ..SettingsModel::default()
    };
    let mut cps = CertificationPathSettings::default();
    model.apply(&mut cps).expect("a valid time of interest");
    let tas = [("ta.der".to_string(), ta.to_vec())];
    let cas = [("ca.der".to_string(), ca.to_vec())];
    let (prepared, _) = prepare_validation(None, &tas, &cas, &cps, None).expect("an environment");
    let work = pittv3_gui_lib::retrieval::harvest_revocation_work(
        &prepared,
        &cps,
        &[("outer.der".to_string(), demo::OUTER.to_vec())],
    );
    let mut dps = work.crl_dp;
    dps.sort();
    dps
}

/// Revocation data is retrieved for the paths validation builds, so for the alternate's path when
/// only its PKI is present, and not for the outer certificate's PKI, which nothing builds to.
#[cfg(feature = "revocation")]
#[test]
fn revocation_retrieval_covers_the_candidate_that_has_a_path() {
    let url = |f: &str| format!("{}{f}", demo::BASE);
    assert_eq!(
        harvested_crl_dps(demo::ML_DSA_ROOT, demo::ML_DSA_CA),
        [
            url("turducken-demo-ml-dsa-65-ca.crl"),
            url("turducken-demo-ml-dsa-65-root.crl")
        ]
    );
    assert_eq!(
        harvested_crl_dps(demo::RSA_ROOT, demo::RSA_CA),
        [
            url("turducken-demo-rsa-ca.crl"),
            url("turducken-demo-rsa-root.crl")
        ]
    );
}
