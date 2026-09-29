//! Integration tests for how a folder of targets is walked.
//!
//! The walk and the recursion around it came over from Boost, whose `directory_iterator` reads one
//! level, so a function that wanted a whole tree had to recurse itself. `walkdir` descends on its
//! own, and the recursion was carried across the port without being re-examined against it. What
//! that cost is not a constant: a directory reached by more than one route was walked once per
//! route, so a certificate four levels down was validated eight times, its path built eight times
//! and its no-paths diagnosis written eight times.
//!
//! `files_processed` is the counter that shows it, incremented once per call in
//! `validate_cert_file` before any path building, so it counts visits whatever the run then makes
//! of the certificate.
#![cfg(feature = "std")]

use std::fs;
use std::path::Path;

use certval::{CertificationPathSettings, PkiEnvironment};
use pittv3_lib::args::Pittv3Args;
use pittv3_lib::stats::PathValidationStatsGroup;
use pittv3_lib::std_utils::{validate_cert_folder_retaining, ValidateOpts};

/// A certificate is needed only because the walk admits by extension and the visit is counted after
/// the parse. Which certificate, and whether a path can be built for it, does not bear on the
/// count.
const TARGET: &[u8] = include_bytes!("../../certval/tests/examples/TrustAnchorRootCertificate.crt");

/// Walks `folder` the way a run does and reports what each file's visit count came to.
fn visits(folder: &str) -> PathValidationStatsGroup {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let cps = CertificationPathSettings::default();
    let opts = ValidateOpts::from_args(&Pittv3Args::default());
    let mut stats = PathValidationStatsGroup::new();
    let mut fresh_uris = vec![];

    tokio_test::block_on(validate_cert_folder_retaining(
        &pe,
        &cps,
        folder,
        &mut stats,
        &opts,
        &mut fresh_uris,
        0,
        None,
        None,
    ));
    stats
}

/// One certificate, four levels down, is one validation. Under the ported recursion it was eight,
/// because `a`, `a/b` and `a/b/c` were each walked again as directory entries of a walk that had
/// already descended into them.
#[test]
fn a_nested_target_is_validated_once() {
    let dir = tempfile::tempdir().unwrap();
    let deep = dir.path().join("a").join("b").join("c");
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("deep.der"), TARGET).unwrap();
    fs::write(dir.path().join("top.der"), TARGET).unwrap();

    let stats = visits(dir.path().to_str().unwrap());
    assert_eq!(2, stats.len(), "both certificates should be reached");
    for (filename, s) in &stats {
        let depth = Path::new(filename).components().count();
        assert_eq!(
            1, s.files_processed,
            "{filename} (depth {depth}) was validated {} times",
            s.files_processed
        );
    }
}

/// The shallow case, which was already right and has to stay right: a file beside the folder is
/// reached by the one walk and by nothing else.
#[test]
fn a_flat_folder_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("one.der"), TARGET).unwrap();
    fs::write(dir.path().join("two.der"), TARGET).unwrap();

    let stats = visits(dir.path().to_str().unwrap());
    assert_eq!(2, stats.len());
    assert!(stats.values().all(|s| s.files_processed == 1));
}

/// Depth is what multiplied, so the guard is a tree deep enough that the old behavior and the new
/// one cannot be confused by a small number: at six levels the ported recursion reached the file
/// thirty-two times.
#[test]
fn depth_does_not_multiply_visits() {
    let dir = tempfile::tempdir().unwrap();
    let mut deep = dir.path().to_path_buf();
    for level in 0..6 {
        deep = deep.join(format!("d{level}"));
    }
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("deepest.der"), TARGET).unwrap();

    let stats = visits(dir.path().to_str().unwrap());
    assert_eq!(1, stats.len());
    assert_eq!(1, stats.values().next().unwrap().files_processed);
}
