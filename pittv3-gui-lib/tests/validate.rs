//! Integration tests for the browser validation path: `prepare_validation`, `validate_prepared`
//! and `validate_prepared_retaining`.
//!
//! These are what the two GUI frontends run a validation through. `pittv3-lib`'s suite exercises
//! `std_utils::validate_targets`, a different function reached by a different caller, so the two
//! can diverge — which is what happened on 2026-08-27, when each of four defects was one copy doing
//! something the other did not.
//!
//! Material is the PKITS P-256 flavor from certval's test suite, pushed as bytes rather than read
//! through any filesystem machinery, because bytes are all a browser ever has. The `validate_all`
//! module at the end needs a target with two routes to an anchor, which only the baked Web PKI
//! store has; it lives here rather than in a second file so the pre-commit hook links one test
//! binary per configuration instead of two.

use std::fs;
use std::path::Path;

use certval::*;
use pittv3_gui_lib::gui_results::ResultLine;
use pittv3_gui_lib::validate::{
    prepare_validation, validate_prepared, validate_prepared_retaining, PreparedValidation,
};
use pittv3_lib::report::TargetStatus;

/// What both preparation helpers return: the prepared environment plus notes, or the fatal notes
/// that say why there is none.
type Prepared = core::result::Result<(PreparedValidation, Vec<ResultLine>), Vec<ResultLine>>;

/// A pool as a frontend hands one over: each entry is what the user called it and the bytes behind
/// it, which for a browser is all there ever is.
type Pool = Vec<(String, Vec<u8>)>;

/// 2022-03-23T12:49:43Z, the time the PKITS material is valid at and the same instant the lower
/// crate's tests use.
const TOI: u64 = 1_648_039_783;

fn pkits(name: &str) -> Vec<u8> {
    let p = Path::new("../certval/tests/examples/PKITS_data_p256/certs").join(name);
    fs::read(&p).unwrap_or_else(|e| panic!("failed to read {}: {e}", p.display()))
}

fn named(name: &str) -> (String, Vec<u8>) {
    (name.to_string(), pkits(name))
}

fn settings() -> CertificationPathSettings {
    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(TOI).unwrap());
    // Off deliberately: what is under test is path building and reporting, and leaving it on would
    // make every assertion here depend on revocation data this material has no source for.
    cps.set_check_revocation_status(false);
    cps
}

/// Calls `prepare_validation` across the `revocation` feature, which adds a cache parameter. The
/// tests want to run either way -- the browser builds without it and the desktop with it.
fn prepare(
    tas: &[(String, Vec<u8>)],
    cas: &[(String, Vec<u8>)],
    cps: &CertificationPathSettings,
) -> Prepared {
    #[cfg(feature = "revocation")]
    {
        prepare_validation(None, tas, cas, cps, None)
    }
    #[cfg(not(feature = "revocation"))]
    {
        prepare_validation(None, tas, cas, cps)
    }
}

/// The anchor and the one CA every positive case here needs.
fn good_material() -> (Pool, Pool) {
    (
        vec![named("TrustAnchorRootCertificate.crt")],
        vec![named("GoodCACert.crt")],
    )
}

#[test]
fn a_target_with_a_path_to_an_anchor_validates() {
    let (tas, cas) = good_material();
    let cps = settings();
    let (prepared, _) = prepare(&tas, &cas, &cps).expect("preparation must succeed");

    let (reports, _) = validate_prepared(
        &prepared,
        &cps,
        &[named("ValidCertificatePathTest1EE.crt")],
        false,
    );

    assert_eq!(reports.len(), 1);
    let report = &reports[0];
    assert_eq!(report.status, TargetStatus::Valid, "{report:#?}");
    assert_eq!(report.paths.len(), 1);
    assert!(report.target.is_some(), "a validated target has a summary");
    assert!(report.no_paths_hints.is_empty());
    assert!(report.error.is_none());
}

/// The anchor alone, with no intermediate to reach it by. Distinct from a target that cannot be
/// read at all, which is the case below.
#[test]
fn a_target_with_no_issuer_reports_no_paths_rather_than_failing() {
    let (tas, _) = good_material();
    let cps = settings();
    let (prepared, _) = prepare(&tas, &[], &cps).expect("an anchor alone is a usable environment");

    let (reports, _) = validate_prepared(
        &prepared,
        &cps,
        &[named("ValidCertificatePathTest1EE.crt")],
        false,
    );

    assert_eq!(reports.len(), 1);
    assert_eq!(
        reports[0].status,
        TargetStatus::NoPathsFound,
        "{:#?}",
        reports[0]
    );
    assert!(reports[0].paths.is_empty());
}

/// `NoPathsFound` says the store held no issuer; `ParseError` says the input was never a
/// certificate. Reporting the second as the first sent users to look at their trust material over a
/// file that could not be read, which is why they are separate statuses.
#[test]
fn an_input_that_is_not_a_certificate_is_a_parse_error_not_an_absence_of_paths() {
    let (tas, cas) = good_material();
    let cps = settings();
    let (prepared, _) = prepare(&tas, &cas, &cps).expect("preparation must succeed");

    let (reports, _) = validate_prepared(
        &prepared,
        &cps,
        &[(
            "not-a-cert.txt".to_string(),
            b"this is not a certificate".to_vec(),
        )],
        false,
    );

    assert_eq!(reports.len(), 1);
    assert_eq!(
        reports[0].status,
        TargetStatus::ParseError,
        "{:#?}",
        reports[0]
    );
    assert!(
        reports[0].error.is_some(),
        "a parse error says what went wrong"
    );
    assert!(
        reports[0].target.is_none(),
        "there is no target to summarize"
    );
}

/// The 2026-08-20 defect in one assertion: `validate_target` decoded PEM and the harvest did not,
/// so a PEM target validated while contributing nothing to retrieval. Both now go through
/// `der_or_pem`, and a PEM target has to reach the same verdict as the DER it encodes.
#[test]
fn a_pem_target_validates_exactly_as_its_der_does() {
    let (tas, cas) = good_material();
    let cps = settings();
    let (prepared, _) = prepare(&tas, &cas, &cps).expect("preparation must succeed");

    let der = pkits("ValidCertificatePathTest1EE.crt");
    let pem = pem_encode(&der);

    let (reports, _) = validate_prepared(
        &prepared,
        &cps,
        &[
            ("target.der".to_string(), der),
            ("target.pem".to_string(), pem),
        ],
        false,
    );

    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].status, TargetStatus::Valid, "{:#?}", reports[0]);
    assert_eq!(
        reports[0].status, reports[1].status,
        "PEM and DER of one certificate must reach one verdict"
    );
}

/// Wraps DER as PEM without adding a dependency: the frontends accept whatever a user pastes, and
/// what is under test is that the decoder reaches it.
fn pem_encode(der: &[u8]) -> Vec<u8> {
    use base64ct::{Base64, Encoding};
    let b64 = Base64::encode_string(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out.into_bytes()
}

/// An export has to account for the result on screen, so the path comes from the run that produced
/// it or not at all. `retain` is what decides whether it is kept, and asking for nothing has to
/// cost nothing.
#[test]
fn retaining_yields_the_validated_path_and_declining_yields_none() {
    let (tas, cas) = good_material();
    let cps = settings();
    let (prepared, _) = prepare(&tas, &cas, &cps).expect("preparation must succeed");
    let ees = [named("ValidCertificatePathTest1EE.crt")];

    let (kept_reports, _, kept) = validate_prepared_retaining(&prepared, &cps, &ees, false, true);
    assert_eq!(kept.len(), 1, "one validated path, one retained path");
    assert_eq!(kept[0].target_name, "ValidCertificatePathTest1EE.crt");
    assert_eq!(
        kept[0].path.intermediates.len(),
        1,
        "anchor, one CA, target"
    );

    let (dropped_reports, _, dropped) =
        validate_prepared_retaining(&prepared, &cps, &ees, false, false);
    assert!(dropped.is_empty(), "nothing is retained unless asked for");

    assert_eq!(
        kept_reports[0].status, dropped_reports[0].status,
        "retaining must not change the verdict"
    );
}

/// Preparing with no anchors cannot yield a usable environment, and says so fatally rather than
/// returning an environment that fails every target for a reason the user would have to infer.
#[test]
fn preparing_without_trust_anchors_is_fatal() {
    let cps = settings();
    let err = prepare(&[], &[named("GoodCACert.crt")], &cps)
        .err()
        .expect("no anchors is not a usable environment");
    assert!(!err.is_empty(), "a fatal outcome states why");
}

/// A preparation that was handed uploads keeps the graph and anchors it built, because the sources
/// are moved into the environment a line later and nothing can ask for them back. With no uploads
/// there is nothing to keep: the pool is the store as fetched, which already carries its paths, so
/// `None` is the honest answer rather than a saving.
#[test]
fn a_preparation_from_uploads_keeps_its_graph_and_anchors() {
    let (tas, cas) = good_material();
    let cps = settings();
    let (prepared, _) = prepare(&tas, &cas, &cps).expect("preparation must succeed");

    assert!(
        prepared.built_graph().is_some(),
        "uploads were discovered over, so the graph is worth keeping"
    );
    assert!(
        prepared.built_anchors().is_some(),
        "the anchors the graph's partial paths end at"
    );
}

/// Serializes the PKITS anchor and CA as the two CBOR halves a baked store is made of, so the
/// `store` parameter can be exercised without a fixture of its own. The committed Web PKI store in
/// `pittv3-lib/resources` would have served, but its signatures need `certval/rsa`, which this
/// crate does not forward -- and a store test that silently validated nothing would be worse than
/// none.
///
/// `discover` is what a store generator does before writing the CA half: the partial paths are
/// computed once, at generation, and shipped inside the CBOR. Both values are tested below, because
/// the difference is not cosmetic -- see `a_store_without_partial_paths_finds_none`.
fn store_cbor(discover: bool) -> (Vec<u8>, Vec<u8>) {
    let cps = settings();

    let mut ta_store = TaSource::new();
    ta_store.push(CertFile {
        filename: "TrustAnchorRootCertificate.crt".to_string(),
        bytes: pkits("TrustAnchorRootCertificate.crt"),
    });
    ta_store.initialize().unwrap();

    let mut cert_source = CertSource::new();
    cert_source.push(CertFile {
        filename: "GoodCACert.crt".to_string(),
        bytes: pkits("GoodCACert.crt"),
    });
    cert_source.initialize(&cps).unwrap();

    if discover {
        let mut pe = PkiEnvironment::default();
        pe.populate_5280_pki_environment();
        pe.add_trust_anchor_source(Box::new(ta_store.clone()));
        cert_source.find_all_partial_paths(&pe, &cps);
    }

    (
        ta_store
            .serialize(CertificationPathBuilderFormats::Cbor)
            .unwrap(),
        cert_source
            .serialize(CertificationPathBuilderFormats::Cbor)
            .unwrap(),
    )
}

fn prepare_with_store(ta_cbor: &[u8], ca_cbor: &[u8], cps: &CertificationPathSettings) -> Prepared {
    #[cfg(feature = "revocation")]
    {
        prepare_validation(Some(("pkits_p256", ta_cbor, ca_cbor)), &[], &[], cps, None)
    }
    #[cfg(not(feature = "revocation"))]
    {
        prepare_validation(Some(("pkits_p256", ta_cbor, ca_cbor)), &[], &[], cps)
    }
}

/// The browser's ordinary case: a store selected rather than material uploaded. Also pins the other
/// half of the invariant above -- with nothing uploaded there is no graph to keep, because the pool
/// is the store as fetched and already carries its partial paths.
#[test]
fn a_selected_store_validates_and_keeps_no_graph_of_its_own() {
    let (ta_cbor, ca_cbor) = store_cbor(true);
    let cps = settings();
    let (prepared, _) = prepare_with_store(&ta_cbor, &ca_cbor, &cps)
        .expect("a store alone is a usable environment");

    let (reports, _) = validate_prepared(
        &prepared,
        &cps,
        &[named("ValidCertificatePathTest1EE.crt")],
        false,
    );
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].status, TargetStatus::Valid, "{:#?}", reports[0]);

    assert!(
        prepared.built_graph().is_none(),
        "nothing was uploaded, so a graph here would duplicate the store's own"
    );
    assert!(prepared.built_anchors().is_none());
}

/// A store carries its partial paths or it is inert, and this is why: preparation discovers paths
/// only when something was uploaded, so a CA store whose CBOR holds buffers and no paths yields
/// `NoPathsFound` for a target its own certificates could reach. The same bytes validate once the
/// generator's discovery pass has run over them, which is the test above. Written as a test rather
/// than a comment because it was found by writing the fixture wrongly the first time.
#[test]
fn a_store_without_partial_paths_finds_none() {
    let (ta_cbor, ca_cbor) = store_cbor(false);
    let cps = settings();
    let (prepared, _) = prepare_with_store(&ta_cbor, &ca_cbor, &cps).expect("still a usable store");

    let (reports, _) = validate_prepared(
        &prepared,
        &cps,
        &[named("ValidCertificatePathTest1EE.crt")],
        false,
    );
    assert_eq!(
        reports[0].status,
        TargetStatus::NoPathsFound,
        "an undiscovered store is inert, not merely slower"
    );
}

/// `validate_all` over the same shared path, in a module rather than a second test target so
/// the pre-commit hook links one test binary per configuration instead of two.
///
/// Gated on `rsa` because the only material with more than one route to an anchor is the Web PKI
/// store `pittv3-lib` bakes in, and without a verifier for its signatures no path validates -- the
/// loop would never stop early and the test would pass without exercising what it is for. The same
/// reasoning, and the same fixture, as `pittv3-lib/tests/path_dedupe.rs`, which pins the equivalent
/// behaviour one crate down; this is the browser's copy of that loop, which is the pair that
/// diverged on 2026-08-27.
#[cfg(feature = "rsa")]
mod validate_all {
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
        let result: core::result::Result<
            (PreparedValidation, Vec<ResultLine>),
            Vec<ResultLine>,
        > = prepare_validation(Some(("webpki", &ta_cbor, &ca_cbor)), &[], &[], cps, None);
        #[cfg(not(feature = "revocation"))]
        let result: core::result::Result<
            (PreparedValidation, Vec<ResultLine>),
            Vec<ResultLine>,
        > = prepare_validation(Some(("webpki", &ta_cbor, &ca_cbor)), &[], &[], cps);

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
}
