//! Tests for the single-file trust anchor and certificate readers, which exist so a caller can let
//! a user nominate one certificate instead of requiring a folder built around it.
#![cfg(feature = "std")]

use std::fs;

use certval::*;

/// The p256 PKITS fixtures are used throughout: reading a certificate needs no signature
/// verification, but excluding a self-signed one does, and ECDSA is available by default.
const CERTS: &str = "tests/examples/PKITS_data_p256/certs";

fn toi() -> TimeOfInterest {
    // 0 disables the validity check, so these tests cannot expire out from under the fixtures
    TimeOfInterest::from_unix_secs(0).unwrap()
}

fn pe() -> PkiEnvironment {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe
}

#[test]
fn cert_file_reads_one_certificate() {
    let mut certs = CertSource::new();
    let added =
        cert_file_to_vec(&pe(), &format!("{CERTS}/GoodCACert.crt"), &mut certs, toi()).unwrap();
    assert_eq!(1, added);
    assert_eq!(1, certs.len());
}

#[test]
fn ta_file_reads_one_anchor() {
    let mut tas = TaSource::new();
    let added = ta_file_to_vec(
        &pe(),
        &format!("{CERTS}/TrustAnchorRootCertificate.crt"),
        &mut tas,
        toi(),
    )
    .unwrap();
    assert_eq!(1, added);
}

/// The rules that govern a file reached by walking a folder govern a file named outright, so a
/// self-signed certificate is excluded from a certificate source either way. This is the one that
/// would catch the single-file path being written as a bare read.
#[test]
fn cert_file_excludes_a_self_signed_certificate() {
    let mut certs = CertSource::new();
    let added = cert_file_to_vec(
        &pe(),
        &format!("{CERTS}/TrustAnchorRootCertificate.crt"),
        &mut certs,
        toi(),
    )
    .unwrap();
    assert_eq!(0, added, "a self-signed certificate is not an intermediate");
}

/// A folder is not a file. The two entry points are separate so that a caller dispatching on the
/// path gets a clear answer from whichever one it chose, rather than an empty result.
#[test]
fn a_folder_is_not_a_file() {
    let mut certs = CertSource::new();
    assert!(matches!(
        cert_file_to_vec(&pe(), CERTS, &mut certs, toi()),
        Err(Error::NotFound)
    ));

    let mut tas = TaSource::new();
    assert!(matches!(
        ta_file_to_vec(&pe(), CERTS, &mut tas, toi()),
        Err(Error::NotFound)
    ));
}

/// A named file is read on its merits, while a folder walk filters by extension — the one
/// deliberate difference between the two paths. A user who picks a file in a dialog has said which
/// file they mean; a folder walk has only the name to go on.
#[test]
fn a_named_file_needs_no_recognized_extension() {
    let dir = tempfile::tempdir().unwrap();
    let odd = dir.path().join("intermediate.bin");
    fs::copy(format!("{CERTS}/GoodCACert.crt"), &odd).unwrap();

    let mut named = CertSource::new();
    let added = cert_file_to_vec(&pe(), odd.to_str().unwrap(), &mut named, toi()).unwrap();
    assert_eq!(1, added);

    let mut walked = CertSource::new();
    let added =
        cert_folder_to_vec(&pe(), dir.path().to_str().unwrap(), &mut walked, toi()).unwrap();
    assert_eq!(
        0, added,
        "a folder walk still passes over a file whose extension says nothing"
    );
}

/// Seconds since the Unix epoch, the clock `read_blocklist` compares an entry's expiry against.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn write_blocklist(contents: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("blocklist.json");
    fs::write(&file, contents).unwrap();
    let name = file.to_str().unwrap().to_string();
    (dir, name)
}

#[test]
fn blocklist_entry_that_has_not_expired_is_kept() {
    let later = now_secs() + 3600;
    let (_dir, file) = write_blocklist(&format!(r#"{{"http://example.test/ca.p7c":{later}}}"#));
    let blocklist = read_blocklist(&file);
    assert_eq!(1, blocklist.len());
    assert!(blocklist.contains_key("http://example.test/ca.p7c"));
}

/// The point of the expiry: a URI blocked by one timeout is tried again rather than removed from
/// every later run in that folder.
#[test]
fn blocklist_entry_that_has_expired_is_dropped() {
    let earlier = now_secs() - 3600;
    let (_dir, file) = write_blocklist(&format!(r#"{{"http://example.test/ca.p7c":{earlier}}}"#));
    let blocklist = read_blocklist(&file);
    assert!(blocklist.is_empty());
}

/// A file written before entries carried an expiry is a JSON array. Reading it as an empty
/// blocklist is what retries the URIs a prior version blocked for good.
#[test]
fn blocklist_written_without_expiries_is_read_as_empty() {
    let (_dir, file) = write_blocklist(r#"["http://example.test/ca.p7c"]"#);
    let blocklist = read_blocklist(&file);
    assert!(blocklist.is_empty());
}

#[test]
fn absent_blocklist_reads_as_empty() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("blocklist.json");
    let blocklist = read_blocklist(file.to_str().unwrap());
    assert!(blocklist.is_empty());
}
