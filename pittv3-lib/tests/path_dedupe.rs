//! A chain reported once is not reported again, across calls that share one [`PathValidationStats`].
//!
//! Dynamic path building validates a target more than once: each pass hands the builder a higher
//! threshold and revalidates what comes back, so the same chain is routinely offered again. The
//! totals and the result-folder indices are keyed on what was *reported*, so a chain counted twice
//! makes a run announce more paths than it found — which is how a desktop run reported ten paths
//! where the same material yielded five in the browser (fixed in `4cf9a933`).
//!
//! The condition the defect needed is an early exit: with `validate_all` off the validation loop
//! stops at the first success, so any candidate after it goes unreached. Recording a chain where it
//! was *validated* therefore missed exactly those, and they were counted again next time. Recording
//! where it is *offered* is what this pins.
//! Gated on `rsa` as well as `std`: without a verifier for the Web PKI's signatures no path
//! validates, the loop never stops early, and the test would pass without exercising what it is for.
//! `certval.yml` runs it as its own leg for that reason -- a default-feature test run skips it.
#![cfg(all(feature = "std", feature = "rsa"))]

use certval::*;
use ciborium::de::from_reader;
use pittv3_lib::stats::PathValidationStats;
use pittv3_lib::std_utils::{validate_cert_bytes, ValidateOpts};

/// Inside the baked end entity's validity window (2021-12-13 .. 2022-12-12), so the run judges the
/// material rather than the calendar. Pinned for the same reason the PKITS tests pin theirs: a real
/// end entity expires, and a test that reads "now" stops testing what it was written for.
const TOI: u64 = 1_654_041_600; // 2022-06-01T00:00:00Z

/// The one baked end entity with more than one route to an anchor, which is what the defect needed.
const MULTI_PATH_EE: &str = "twitter.com.der";

fn settings() -> CertificationPathSettings {
    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(TOI).unwrap());
    // No revocation: this is about counting chains, and a fetch would make the test depend on a
    // responder still answering for certificates this old.
    cps.set_check_revocation_status(false);
    cps
}

/// The Web PKI material the `options_no_std` and `options_std_app` entry points embed.
fn environment(cps: &CertificationPathSettings) -> PkiEnvironment {
    let mut cert_source =
        CertSource::new_from_cbor(include_bytes!("../resources/ca.cbor").as_slice()).unwrap();
    cert_source.initialize(cps).unwrap();
    let mut ta_store = TaSource::new_from_cbor(include_bytes!("../resources/ta.cbor")).unwrap();
    ta_store.initialize().unwrap();

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe.add_trust_anchor_source(Box::new(ta_store));
    pe.add_certificate_source(Box::new(cert_source));
    pe
}

fn multi_path_target() -> (String, Vec<u8>) {
    let bap: BuffersAndPaths =
        from_reader(include_bytes!("../resources/ee.cbor").as_slice()).unwrap();
    bap.buffers
        .iter()
        .find(|cf| cf.filename.ends_with(MULTI_PATH_EE))
        .map(|cf| (cf.filename.clone(), cf.bytes.clone()))
        .unwrap_or_else(|| panic!("the embedded end entity store must hold {MULTI_PATH_EE}"))
}

#[test]
fn a_chain_already_reported_is_not_counted_again() {
    let cps = settings();
    let pe = environment(&cps);
    // Stops at the first valid path, leaving the second candidate unreached -- the state the
    // defect needed, and the default a run uses unless asked for every path.
    let opts = ValidateOpts {
        validate_all: false,
        ..Default::default()
    };
    let (name, bytes) = multi_path_target();

    let mut stats = PathValidationStats::default();
    let mut uris = vec![];
    let _ = tokio_test::block_on(validate_cert_bytes(
        &pe, &cps, &name, &bytes, &mut stats, &opts, &mut uris, 0,
    ));

    assert!(
        stats.valid_paths_per_target > 0,
        "a path has to validate for the loop to stop early; without that this test proves nothing"
    );

    let first = stats.paths_per_target;
    assert!(
        first > 1,
        "the target must offer more than one candidate or the early exit has nothing to skip, got {first}"
    );

    // The same target again with the same stats, as the next dynamic-building pass does.
    let _ = tokio_test::block_on(validate_cert_bytes(
        &pe, &cps, &name, &bytes, &mut stats, &opts, &mut uris, 0,
    ));

    assert_eq!(
        stats.paths_per_target, first,
        "every chain was already reported, so the second call must add nothing"
    );
}
