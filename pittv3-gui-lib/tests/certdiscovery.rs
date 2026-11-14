//! Referenced certificates per draft-ietf-lamps-certdiscovery through the validation path the
//! desktop and browser frontends share.
//!
//! The certificates are the Certificate Discovery Demo PKI: an RSA hierarchy and an ML-DSA-65
//! hierarchy whose CA and end entity certificates reference their counterparts. The RSA CA includes
//! the ML-DSA-65 CA (byInclusion); the RSA end entity names the ML-DSA-65 end entity by URI, with a
//! certificate hash, and a second RSA end entity includes it. The ML-DSA-65 end entity carries no AIA,
//! so its issuer is in an environment only when it was taken out of the RSA CA.
//!
//! A referenced end entity certifies another key, so it is not a candidate for the end entity that
//! references it, as a turducken alternate is. A frontend takes an included one out, or retrieves
//! one named by URI, and validates it as a target of its own (Section 6).

// RSA and ML-DSA verification are needed alongside `certdiscovery`, since one hierarchy is each
#![cfg(all(feature = "certdiscovery", feature = "pqc", feature = "rsa"))]

use certval::CertificationPathSettings;
use pittv3_gui_lib::validate::{prepare_validation, validate_prepared, PreparedValidation};
use pittv3_lib::candidates::{
    accept_referenced, fold_referenced, included_referenced, referenced_uris,
};
use pittv3_lib::report::{TargetReport, TargetStatus};

const RSA_TA: &[u8] = include_bytes!("examples/certdiscovery/certdiscovery-demo-rsa-root.der");
const RSA_CA: &[u8] = include_bytes!("examples/certdiscovery/certdiscovery-demo-rsa-ca.der");
const ML_DSA_TA: &[u8] =
    include_bytes!("examples/certdiscovery/certdiscovery-demo-ml-dsa-65-root.der");
const ML_DSA_CA: &[u8] =
    include_bytes!("examples/certdiscovery/certdiscovery-demo-ml-dsa-65-ca.der");
const RSA_EE: &[u8] = include_bytes!("examples/certdiscovery/certdiscovery-demo-ee-rsa.der");
const RSA_EE_INCLUSION: &[u8] =
    include_bytes!("examples/certdiscovery/certdiscovery-demo-ee-rsa-inclusion.der");
const ML_DSA_EE: &[u8] =
    include_bytes!("examples/certdiscovery/certdiscovery-demo-ee-ml-dsa-65.der");

/// Where the RSA end entity says the ML-DSA-65 end entity is
const ML_DSA_EE_URI: &str =
    "https://downloads.redhoundsoftware.com/certdiscovery/demo/certdiscovery-demo-ee-ml-dsa-65.der";

/// The current time, which the demo certificates are valid at, with revocation off since no CRLs
/// are supplied
fn settings() -> CertificationPathSettings {
    let mut cps = CertificationPathSettings::default();
    cps.set_check_revocation_status(false);
    cps
}

fn prepare(ta: &[u8], cas: &[&[u8]]) -> PreparedValidation {
    let cps = settings();
    let tas = [("ta.der".to_string(), ta.to_vec())];
    let cas: Vec<(String, Vec<u8>)> = cas
        .iter()
        .enumerate()
        .map(|(i, ca)| (format!("ca{i}.der"), ca.to_vec()))
        .collect();
    #[cfg(feature = "revocation")]
    let prepared = prepare_validation(None, &tas, &cas, &cps, None);
    #[cfg(not(feature = "revocation"))]
    let prepared = prepare_validation(None, &tas, &cas, &cps);
    prepared.expect("an environment").0
}

fn validate(prepared: &PreparedValidation, ee: &[u8]) -> TargetReport {
    let (mut reports, _) = validate_prepared(
        prepared,
        &settings(),
        &[("ee.der".to_string(), ee.to_vec())],
        true,
    );
    assert_eq!(reports.len(), 1);
    reports.remove(0)
}

/// The candidate each valid path was built from: `None` for the input certificate itself
fn valid_candidates(report: &TargetReport) -> Vec<Option<String>> {
    report
        .paths
        .iter()
        .filter(|p| p.error.is_none())
        .map(|p| p.candidate.clone())
        .collect()
}

#[test]
fn included_end_entity_validates_on_its_own_through_the_folded_ca() {
    // Only the RSA CA is supplied: the ML-DSA-65 CA comes out of it
    let prepared = prepare(ML_DSA_TA, &[RSA_CA]);

    // The including end entity is not expanded by path building
    let report = validate(&prepared, RSA_EE_INCLUSION);
    assert_ne!(report.status, TargetStatus::Valid, "{report:?}");

    // Taken out of it, the included end entity validates as a target of its own
    let included = included_referenced(RSA_EE_INCLUSION);
    assert_eq!(included, [ML_DSA_EE.to_vec()]);
    let report = validate(&prepared, &included[0]);
    assert_eq!(report.status, TargetStatus::Valid, "{report:?}");
    assert_eq!(valid_candidates(&report), [None]);
}

#[test]
fn without_the_ca_fold_the_referenced_end_entity_has_no_issuer() {
    let prepared = prepare(ML_DSA_TA, &[]);
    let report = validate(&prepared, ML_DSA_EE);
    assert_ne!(report.status, TargetStatus::Valid, "{report:?}");

    // Supplying the ML-DSA-65 CA directly gives the same result as folding it out of the RSA CA
    let prepared = prepare(ML_DSA_TA, &[ML_DSA_CA]);
    let report = validate(&prepared, ML_DSA_EE);
    assert_eq!(report.status, TargetStatus::Valid, "{report:?}");
}

#[test]
fn only_end_entities_offer_included_targets() {
    // The RSA CA includes the ML-DSA-65 CA, which is folded into the CA certificates instead
    assert!(included_referenced(RSA_CA).is_empty());
    assert_eq!(
        fold_referenced(vec![RSA_CA.to_vec()]),
        [RSA_CA.to_vec(), ML_DSA_CA.to_vec()]
    );
    // The end entity naming its referenced certificate by URI includes none
    assert!(included_referenced(RSA_EE).is_empty());
}

#[test]
fn referenced_uris_are_sorted_by_whether_the_certificate_is_a_ca() {
    assert_eq!(referenced_uris(None, RSA_EE, false), [ML_DSA_EE_URI]);
    assert!(referenced_uris(None, RSA_EE, true).is_empty());
    let back = referenced_uris(None, ML_DSA_CA, true);
    assert_eq!(back.len(), 1, "{back:?}");
    assert!(
        back[0].ends_with("/certdiscovery-demo-rsa-ca.der"),
        "{back:?}"
    );
}

#[test]
fn retrieved_certificate_is_checked_against_its_descriptor() {
    let pool = [("ee.der".to_string(), RSA_EE.to_vec())];
    assert_eq!(accept_referenced(&pool, ML_DSA_EE_URI, ML_DSA_EE), Ok(()));
    // An RSA certificate served in its place matches neither the algorithms nor the hash
    let refused = accept_referenced(&pool, ML_DSA_EE_URI, RSA_EE_INCLUSION).unwrap_err();
    assert!(refused.contains("signature algorithm"), "{refused}");
    // A URI nothing in the pool names is not checked
    assert_eq!(
        accept_referenced(&pool, "https://example.test/other.der", RSA_EE_INCLUSION),
        Ok(())
    );
}

#[test]
fn the_trust_anchor_decides_which_target_validates() {
    let prepared = prepare(RSA_TA, &[RSA_CA]);
    let report = validate(&prepared, RSA_EE_INCLUSION);
    assert_eq!(report.status, TargetStatus::Valid, "{report:?}");
    let report = validate(&prepared, ML_DSA_EE);
    assert_ne!(report.status, TargetStatus::Valid, "{report:?}");
}
