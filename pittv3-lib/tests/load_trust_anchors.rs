//! Integration tests for `load_trust_anchors`, which resolves the `ta_cbor` and `ta_folder`
//! arguments into one trust anchor source.
//!
//! The interesting property is that the two inputs are interchangeable and combinable: a store
//! generated from a folder must anchor exactly what the folder does, and supplying both must not
//! produce a doubled anchor set — certval refuses to anchor on a key identifier that resolves to
//! more than one key, so a duplicated anchor would disable itself.
#![cfg(feature = "std")]

use std::fs;
use std::path::Path;

use certval::*;
use pittv3_lib::args::Pittv3Args;
use pittv3_lib::std_utils::load_trust_anchors;

/// Anchors are read with the validity check disabled so the fixtures below cannot expire out from
/// under the test; what is being exercised is where the anchors came from, not when they are good.
fn toi() -> TimeOfInterest {
    TimeOfInterest::from_unix_secs(0).unwrap()
}

/// A PKITS trust anchor folder from the certval test suite. Only its structure is used — nothing
/// here verifies a signature — so the ML-DSA edition serves without a post-quantum feature.
fn ta_folder() -> String {
    "../certval/tests/examples/pkits_ml_dsa_44/ta".to_string()
}

fn args_with(ta_cbor: Option<String>, ta_folder: Option<String>) -> Pittv3Args {
    Pittv3Args {
        ta_cbor,
        ta_folder,
        ..Default::default()
    }
}

/// Serializes the anchors in `ta_folder()` to a CBOR store, the way the trust store providers and
/// `--generate --cbor-ta-store` both write one, and returns the path it was written to.
fn write_ta_store(dir: &Path) -> String {
    let pe = PkiEnvironment::default();
    let mut store = CertSource::new();
    ta_folder_to_vec(&pe, &ta_folder(), &mut store, toi()).unwrap();
    store.initialize(&CertificationPathSettings::new()).unwrap();
    let cbor = store
        .serialize(CertificationPathBuilderFormats::Cbor)
        .unwrap();

    let path = dir.join("ta.cbor");
    fs::write(&path, cbor).unwrap();
    path.to_str().unwrap().to_string()
}

fn load(args: &Pittv3Args) -> Option<TaSource> {
    load_trust_anchors(&PkiEnvironment::default(), args, toi()).unwrap()
}

/// The DER of each anchor, sorted. Labels are deliberately excluded: a store carries the label its
/// generator chose and a folder carries a file name, so they differ by construction.
fn anchor_der(store: &TaSource) -> Vec<Vec<u8>> {
    let mut der: Vec<Vec<u8>> = store.get_tas().into_iter().map(|cf| cf.bytes).collect();
    der.sort();
    der
}

#[test]
fn absent_inputs_yield_no_store() {
    assert!(load(&args_with(None, None)).is_none());
}

#[test]
fn cbor_store_and_folder_anchor_the_same_set() {
    let dir = tempfile::tempdir().unwrap();
    let ta_cbor = write_ta_store(dir.path());

    let from_folder = load(&args_with(None, Some(ta_folder()))).expect("a folder was supplied");
    let from_cbor = load(&args_with(Some(ta_cbor), None)).expect("a store was supplied");

    assert!(
        !from_folder.is_empty(),
        "the fixture folder holds an anchor"
    );
    assert_eq!(anchor_der(&from_folder), anchor_der(&from_cbor));
}

#[test]
fn combining_a_store_and_a_folder_does_not_duplicate_anchors() {
    let dir = tempfile::tempdir().unwrap();
    let ta_cbor = write_ta_store(dir.path());

    let combined =
        load(&args_with(Some(ta_cbor), Some(ta_folder()))).expect("both inputs were supplied");
    let alone = load(&args_with(None, Some(ta_folder()))).expect("a folder was supplied");

    assert_eq!(
        anchor_der(&combined),
        anchor_der(&alone),
        "the same anchor arriving by both routes must be carried once"
    );
}

#[test]
fn an_unreadable_store_is_an_error_rather_than_an_empty_set() {
    let args = args_with(Some("does/not/exist.cbor".to_string()), None);
    assert!(load_trust_anchors(&PkiEnvironment::default(), &args, toi()).is_err());

    // A file that exists but is not a store is the likelier mistake, and the one that would
    // otherwise leave a run validating against no anchors at all.
    let dir = tempfile::tempdir().unwrap();
    let junk = dir.path().join("junk.cbor");
    fs::write(&junk, b"not a cbor store").unwrap();
    let args = args_with(Some(junk.to_str().unwrap().to_string()), None);
    assert!(load_trust_anchors(&PkiEnvironment::default(), &args, toi()).is_err());
}
