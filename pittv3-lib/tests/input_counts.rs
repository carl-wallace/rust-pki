//! Integration tests for the input-pool counting functions — what a frontend shows beside a pool.
//!
//! A pool's own length is the wrong number, and misleadingly so: one `.p7c` of cross-certificates is
//! six certificates, a folder is however many are in it, and a CBOR store is however many it
//! carries. A row reporting entries reads "1" for all three. Both frontends had this bug; these
//! tests pin the answer for the one that reports on *paths* rather than on bytes it already holds,
//! which is what makes the answer a matter of reading the disk.
//!
//! The counts come from the loaders the run uses, so what is really pinned here is that the number
//! shown before a run is the number the run will have.
#![cfg(feature = "std")]

use std::fs;
use std::path::{Path, PathBuf};

use certval::*;
use pittv3_lib::std_utils::{
    count_ca_inputs, count_end_entity_inputs, count_revocation_inputs, count_trust_anchor_inputs,
    load_ca_inputs,
};

/// A time at which the PKITS fixtures are valid
const TOI: u64 = 1648039783;

const FLAVOR: &str = "../certval/tests/examples/PKITS_data_p256/certs";

/// A `.p7c` of six cross-certificates issued to the Federal Bridge CA G4 — the shape that started
/// this: a single file every count based on files reports as one.
const BUNDLE: &str = "../certval/tests/examples/caCertsIssuedTofbcag4.p7c";

/// 2021-05-01, when all six certificates in [`BUNDLE`] are valid. Four of them expired in 2023 and a
/// fifth in 2024, which is the point of [`BUNDLE_LATER`] below rather than an obstacle here.
const BUNDLE_TOI: u64 = 1619827200;

/// 2026-01-01, by which one of the six is still valid. Fixed rather than "now" so the test asserts a
/// number instead of describing the calendar.
const BUNDLE_LATER: u64 = 1767225600;

/// The captured path from the revocation fixtures: two CRLs, two OCSP responses, three certificates
/// and a manifest, in one folder.
const CAPTURED: &str = "../certval/tests/examples/harvard.edu";

/// Four intermediates, enough that a folder counting as one entry is visibly the wrong answer.
const CHAIN: &[&str] = &[
    "requireExplicitPolicy10CACert.crt",
    "requireExplicitPolicy10subCACert.crt",
    "requireExplicitPolicy10subsubCACert.crt",
    "requireExplicitPolicy10subsubsubCACert.crt",
];

fn example(name: &str) -> PathBuf {
    Path::new(FLAVOR).join(name)
}

fn example_str(name: &str) -> String {
    example(name).to_str().unwrap().to_string()
}

/// Copies `names` into a fresh folder under `dir` and returns its path, standing in for a folder a
/// user points the tool at.
fn folder_with(dir: &Path, label: &str, names: &[&str]) -> String {
    let folder = dir.join(label);
    fs::create_dir_all(&folder).unwrap();
    for name in names {
        fs::copy(example(name), folder.join(name)).unwrap();
    }
    folder.to_str().unwrap().to_string()
}

/// The bug as it was reported: a bundle is counted as the certificates in it, not as the one file it
/// arrived in. Both pools fan a file out, so both are asserted against the same material.
#[test]
fn a_bundle_counts_as_the_certificates_in_it() {
    assert_eq!(6, count_ca_inputs([BUNDLE], BUNDLE_TOI));
    assert_eq!(6, count_trust_anchor_inputs([BUNDLE]));
}

/// A CA count is an answer as of a moment, because loading drops material not valid at the time of
/// interest. Same file, same pool, five of the six expired: one.
#[test]
fn a_ca_count_is_as_of_the_time_of_interest() {
    assert_eq!(1, count_ca_inputs([BUNDLE], BUNDLE_LATER));
}

/// A trust anchor count is *not*, and the asymmetry is the point: an anchor is trust in a key, and
/// whether an expired one may anchor a path is `PS_ENFORCE_TRUST_ANCHOR_VALIDITY`'s decision at
/// validation time. Loading anchors used to filter them here, so a folder of eleven anchors loaded
/// ten while the same folder uploaded to the browser app loaded eleven; the count has to follow the
/// loader, or the pool tells the user a number the run then contradicts. Five of these six are
/// expired at `BUNDLE_LATER` and all six still count.
#[test]
fn a_trust_anchor_count_is_not() {
    assert_eq!(1, count_ca_inputs([BUNDLE], BUNDLE_LATER));
    assert_eq!(6, count_trust_anchor_inputs([BUNDLE]));
}

/// A time certval will not take disables the check rather than standing in for it, so the material
/// is counted rather than nothing. Without this the fallback would be a silent zero, which reads as
/// "these inputs are empty" — the opposite of what happened. Only the CA side has a time to get
/// wrong now.
#[test]
fn an_impossible_time_leaves_validity_unchecked() {
    assert_eq!(6, count_ca_inputs([BUNDLE], u64::MAX));
}

/// A folder counts as what is in it, and entries of different shapes add up: the whole point of a
/// pool is that a set is assembled from material in whatever form it arrived.
#[test]
fn a_folder_counts_as_its_contents() {
    let dir = tempfile::tempdir().unwrap();
    let folder = folder_with(dir.path(), "chain", &CHAIN[..3]);

    assert_eq!(3, count_ca_inputs([folder.as_str()], TOI));
    assert_eq!(
        4,
        count_ca_inputs([folder.as_str(), example_str(CHAIN[3]).as_str()], TOI),
        "a folder of three and a file beside it"
    );
}

/// Repeats collapse, because the loaders deduplicate: a certificate named twice is carried once and
/// counting it twice would promise a run material it does not have. A per-entry sum would miss this.
#[test]
fn material_named_twice_counts_once() {
    let dir = tempfile::tempdir().unwrap();
    let folder = folder_with(dir.path(), "chain", CHAIN);
    let also = example_str(CHAIN[0]);

    assert_eq!(4, count_ca_inputs([folder.as_str(), also.as_str()], TOI));
    assert_eq!(
        4,
        count_trust_anchor_inputs([folder.as_str(), also.as_str()])
    );
}

/// A CBOR store counts as the certificates it carries. This is the shape where an entry count is
/// furthest from the truth — a store of a thousand certificates is one file — and it is a shape the
/// app itself writes, so a user gets one by exporting.
#[test]
fn a_store_counts_as_its_certificates() {
    let dir = tempfile::tempdir().unwrap();
    let chain: Vec<String> = CHAIN.iter().map(|n| example_str(n)).collect();
    let mut source = CertSource::new();
    load_ca_inputs(
        &PkiEnvironment::default(),
        chain.iter().map(String::as_str),
        &mut source,
        TimeOfInterest::from_unix_secs(TOI).unwrap(),
    );
    let store = dir.path().join("ca.cbor");
    fs::write(
        &store,
        source
            .serialize(CertificationPathBuilderFormats::Cbor)
            .unwrap(),
    )
    .unwrap();

    assert_eq!(CHAIN.len(), count_ca_inputs([store.to_str().unwrap()], TOI));
}

/// An entry that cannot be read contributes nothing and costs the others nothing. A count is shown
/// beside inputs a user is still assembling, so a typo among them must not blank the row — the run
/// is where an input that will not load has consequences, and it reports them there.
#[test]
fn an_unreadable_entry_counts_as_nothing() {
    let good = example_str(CHAIN[0]);

    assert_eq!(1, count_ca_inputs(["does/not/exist", good.as_str()], TOI));
    assert_eq!(
        1,
        count_trust_anchor_inputs(["does/not/exist", good.as_str()])
    );
}

/// The end entity pool counts *targets*, which is the same question asked of different material: a
/// folder is traversed for the certificates in it, so the number is what the run will judge and what
/// the Validate button promises.
#[test]
fn an_end_entity_folder_counts_as_its_targets() {
    let dir = tempfile::tempdir().unwrap();
    let folder = folder_with(dir.path(), "targets", &CHAIN[..2]);
    fs::write(Path::new(&folder).join("notes.txt"), "not a certificate").unwrap();

    assert_eq!(
        2,
        count_end_entity_inputs([folder.as_str()]),
        "the text file is not a target"
    );
    assert_eq!(
        3,
        count_end_entity_inputs([folder.as_str(), example_str(CHAIN[2]).as_str()])
    );
}

/// A file named twice is one target, matching the run: per-target statistics are keyed by file name,
/// so the second naming is the same target and is validated once.
#[test]
fn an_end_entity_named_twice_counts_once() {
    let one = example_str(CHAIN[0]);

    assert_eq!(1, count_end_entity_inputs([one.as_str(), one.as_str()]));
}

/// The revocation pool counts two things, because a CRL and an OCSP response are not the same thing
/// to a run. Which a file holds comes from its bytes, so a folder of mixed material sorts itself —
/// the certificates and the manifest in the captured folder are neither and count as neither.
#[test]
fn revocation_inputs_count_by_kind() {
    assert_eq!((2, 2), count_revocation_inputs([CAPTURED]));
}
