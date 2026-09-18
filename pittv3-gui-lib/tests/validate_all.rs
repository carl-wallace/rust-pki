//! `validate_all` over the shared validation path: off stops at the first valid path, on reports
//! every one found.
//!
//! Gated on `rsa` because the only material with more than one route to an anchor is the Web PKI
//! store `pittv3-lib` bakes in, and without a verifier for its signatures no path validates -- the
//! loop would never stop early and the test would pass without exercising what it is for. The same
//! reasoning, and the same fixture, as `pittv3-lib/tests/path_dedupe.rs`, which pins the equivalent
//! behaviour one crate down; this is the browser's copy of that loop, which is the pair that
//! diverged on 2026-08-27.
#![cfg(feature = "rsa")]

use std::fs;
use std::path::Path;

use certval::*;
use pittv3_gui_lib::gui_results::ResultLine;
use pittv3_gui_lib::validate::{prepare_validation, validate_prepared, PreparedValidation};

/// 2022-06-01T00:00:00Z, inside the baked end entity's validity window, pinned for the reason
/// `path_dedupe` pins the same instant: a real end entity expires, and a test that reads "now"
/// stops testing what it was written for.
const TOI: u64 = 1_654_041_600;

/// The one baked end entity with more than one route to an anchor.
const MULTI_PATH_EE: &str = "twitter.com.der";

fn resource(name: &str) -> Vec<u8> {
    let p = Path::new("../pittv3-lib/resources").join(name);
    fs::read(&p).unwrap_or_else(|e| panic!("failed to read {}: {e}", p.display()))
}

fn settings() -> CertificationPathSettings {
    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(TOI).unwrap());
    // Off deliberately: this is about how many paths are reported, and a fetch would make the
    // count depend on what a responder says today.
    cps.set_check_revocation_status(false);
    cps
}

/// The multi-path target, taken out of the baked end entity store by name.
fn multi_path_target() -> (String, Vec<u8>) {
    let source = CertSource::new_from_cbor(resource("ee.cbor").as_slice())
        .expect("the baked end entity store must parse");
    source
        .get_buffers()
        .into_iter()
        .find(|cf| cf.filename.ends_with(MULTI_PATH_EE))
        .map(|cf| (cf.filename, cf.bytes))
        .unwrap_or_else(|| panic!("the embedded end entity store must hold {MULTI_PATH_EE}"))
}

fn prepared(cps: &CertificationPathSettings) -> PreparedValidation {
    let ta_cbor = resource("ta.cbor");
    let ca_cbor = resource("ca.cbor");

    #[cfg(feature = "revocation")]
    let result: core::result::Result<(PreparedValidation, Vec<ResultLine>), Vec<ResultLine>> =
        prepare_validation(Some(("webpki", &ta_cbor, &ca_cbor)), &[], &[], cps, None);
    #[cfg(not(feature = "revocation"))]
    let result: core::result::Result<(PreparedValidation, Vec<ResultLine>), Vec<ResultLine>> =
        prepare_validation(Some(("webpki", &ta_cbor, &ca_cbor)), &[], &[], cps);

    result
        .expect("the baked Web PKI store is a usable environment")
        .0
}

/// Off is the default a run uses unless asked for every path, and it is also the condition the
/// 2026-08-27 double-count needed: the loop stops at the first success, leaving later candidates
/// unreached.
#[test]
fn validate_all_off_stops_at_the_first_valid_path() {
    let cps = settings();
    let prepared = prepared(&cps);
    let (reports, _) = validate_prepared(&prepared, &cps, &[multi_path_target()], false);

    assert_eq!(reports.len(), 1);
    assert_eq!(
        reports[0].paths.len(),
        1,
        "one success ends the search: {:#?}",
        reports[0]
    );
}

/// On reports every path found, which is the whole of the difference -- and the target has to be
/// one with more than one route, or the two settings are indistinguishable and this proves nothing.
#[test]
fn validate_all_on_reports_every_path_found() {
    let cps = settings();
    let prepared = prepared(&cps);
    let target = multi_path_target();

    let ees = std::slice::from_ref(&target);
    let (all, _) = validate_prepared(&prepared, &cps, ees, true);
    let (first, _) = validate_prepared(&prepared, &cps, ees, false);

    assert!(
        all[0].paths.len() > first[0].paths.len(),
        "the fixture must have more than one route, or this test is vacuous: {} vs {}",
        all[0].paths.len(),
        first[0].paths.len()
    );
    assert_eq!(
        all[0].status, first[0].status,
        "reporting more paths must not change the verdict"
    );
}
