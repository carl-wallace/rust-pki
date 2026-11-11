//! Revocation status when more than one CRL for a scope is on hand.
//!
//! The path is PKITS Trust Anchor -> Good CA -> ValidCertificatePathTest1EE (serial 01). Two issues
//! of the Good CA CRL are used:
//!
//! - A: PKITS GoodCACRL.crl, CRL number 1, thisUpdate 2010-01-01 08:30:00Z (1262334600). Does not
//!   list serial 01.
//! - B: crl_supersession/GoodCACRL2.crl, CRL number 2, thisUpdate 2011-01-01 08:30:00Z
//!   (1293870600). Lists serial 01 as revoked.
//!
//! Both have nextUpdate 2030-12-31 08:30:00Z. B is the newer issue, so whenever B covers the time of
//! interest and processes, the end entity is revoked, whichever order the CRLs are held in. When B
//! cannot be used, A answers and the end entity is valid.

#![cfg(all(feature = "revocation", feature = "std", feature = "rsa"))]

use std::sync::Arc;

use certval::*;
use der::Decode;
use x509_cert::{certificate::Raw, crl::CertificateList};

const TA: &[u8] = include_bytes!("examples/PKITS_data_2048/certs/TrustAnchorRootCertificate.crt");
const CA: &[u8] = include_bytes!("examples/PKITS_data_2048/certs/GoodCACert.crt");
const EE: &[u8] = include_bytes!("examples/PKITS_data_2048/certs/ValidCertificatePathTest1EE.crt");
const TA_CRL: &[u8] = include_bytes!("examples/PKITS_data_2048/crls/TrustAnchorRootCRL.crl");
const CRL_A: &[u8] = include_bytes!("examples/PKITS_data_2048/crls/GoodCACRL.crl");
const CRL_B: &[u8] = include_bytes!("examples/crl_supersession/GoodCACRL2.crl");

/// 2010-06-01 00:00:00Z: after A's thisUpdate, before B's.
const BETWEEN_A_AND_B: u64 = 1275350400;

const REVOKED: Result<()> = Err(Error::PathValidation(
    PathValidationStatus::CertificateRevokedEndEntity,
));

/// A, with thisUpdate moved to 2012-01-01 08:30:00Z so it claims to be the newest issue. The
/// signature no longer verifies.
fn forged_newest() -> Vec<u8> {
    let mut crl = CRL_A.to_vec();
    let this_update = b"100101083000Z";
    let pos = crl
        .windows(this_update.len())
        .position(|w| w == this_update)
        .unwrap();
    crl[pos..pos + this_update.len()].copy_from_slice(b"120101083000Z");
    crl
}

fn cert(der: &[u8]) -> PDVCertificate {
    let mut cert = PDVCertificate::try_from(der).unwrap();
    cert.parse_extensions(EXTS_OF_INTEREST);
    cert
}

fn cert_path() -> CertificationPath {
    let ta = PDVTrustAnchorChoice::try_from(TA).unwrap();
    CertificationPath::new(ta, vec![cert(CA)], cert(EE))
}

fn settings(toi: Option<u64>) -> CertificationPathSettings {
    let mut cps = CertificationPathSettings::new();
    cps.set_require_ta_store(false);
    cps.set_check_ocsp_from_aia(false);
    cps.set_check_crldp_http(false);
    if let Some(toi) = toi {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(toi).unwrap());
    }
    cps
}

fn environment() -> PkiEnvironment {
    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();
    pe
}

/// A source holding the trust anchor's CRL followed by `crls`, in that order.
fn memory_source(crls: &[&[u8]]) -> MemoryCrlSource {
    let source = MemoryCrlSource::new();
    assert!(source.add(TA_CRL));
    for crl in crls {
        assert!(source.add(crl));
    }
    source
}

/// A folder holding the trust anchor's CRL and `scanned`, indexed, with `added` then added in the
/// order given. A folder scan yields files in whatever order the file system lists them, so CRLs
/// that must follow others in index order go in `added`, which appends.
fn folder_source(
    scanned: &[&[u8]],
    added: &[&[u8]],
    keep_entries_in_memory: bool,
) -> (tempfile::TempDir, Arc<CrlSourceFolders>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ta.crl"), TA_CRL).unwrap();
    for (i, crl) in scanned.iter().enumerate() {
        std::fs::write(dir.path().join(format!("scanned{i}.crl")), crl).unwrap();
    }
    let source = Arc::new(CrlSourceFolders::with_options(
        dir.path().to_str().unwrap(),
        keep_entries_in_memory,
    ));
    source.index_crls(TimeOfInterest::now()).unwrap();
    for (i, crl) in added.iter().enumerate() {
        let decoded = CertificateList::<Raw>::from_der(crl).unwrap();
        source
            .add_crl(crl, &decoded, &format!("http://example.com/added{i}.crl"))
            .unwrap();
    }
    (dir, source)
}

fn check(pe: &PkiEnvironment, cps: &CertificationPathSettings) -> Result<()> {
    let cert_path = cert_path();
    let mut cpr = CertificationPathResults::new();
    pe.validate_path(pe, cps, &cert_path, &mut cpr).unwrap();
    check_revocation_local(pe, cps, &cert_path, &mut cpr)
}

fn check_memory(crls: &[&[u8]], toi: Option<u64>) -> Result<()> {
    let mut pe = environment();
    pe.add_crl_source(Box::new(memory_source(crls)));
    check(&pe, &settings(toi))
}

#[test]
fn a_alone_is_valid() {
    assert_eq!(Ok(()), check_memory(&[CRL_A], None));
}

#[test]
fn b_alone_is_revoked() {
    assert_eq!(REVOKED, check_memory(&[CRL_B], None));
}

#[test]
fn one_source_a_then_b_is_revoked() {
    assert_eq!(REVOKED, check_memory(&[CRL_A, CRL_B], None));
}

#[test]
fn one_source_b_then_a_is_revoked() {
    assert_eq!(REVOKED, check_memory(&[CRL_B, CRL_A], None));
}

#[test]
fn two_sources_a_registered_first_is_revoked() {
    let mut pe = environment();
    pe.add_crl_source(Box::new(memory_source(&[CRL_A])));
    pe.add_crl_source(Box::new(memory_source(&[CRL_B])));
    assert_eq!(REVOKED, check(&pe, &settings(None)));
}

#[test]
fn two_sources_b_registered_first_is_revoked() {
    let mut pe = environment();
    pe.add_crl_source(Box::new(memory_source(&[CRL_B])));
    pe.add_crl_source(Box::new(memory_source(&[CRL_A])));
    assert_eq!(REVOKED, check(&pe, &settings(None)));
}

#[test]
fn folder_a_then_b_is_revoked() {
    let (_dir, source) = folder_source(&[CRL_A], &[CRL_B], false);
    let mut pe = environment();
    pe.add_crl_source(Box::new(source));
    assert_eq!(REVOKED, check(&pe, &settings(None)));
}

#[test]
fn folder_b_then_a_is_revoked() {
    let (_dir, source) = folder_source(&[CRL_B], &[CRL_A], false);
    let mut pe = environment();
    pe.add_crl_source(Box::new(source));
    assert_eq!(REVOKED, check(&pe, &settings(None)));
}

#[test]
fn before_b_is_answered_from_a() {
    assert_eq!(Ok(()), check_memory(&[CRL_A, CRL_B], Some(BETWEEN_A_AND_B)));
    assert_eq!(Ok(()), check_memory(&[CRL_B, CRL_A], Some(BETWEEN_A_AND_B)));
}

#[test]
fn a_forged_newest_crl_falls_back_to_b() {
    let forged = forged_newest();
    assert_eq!(
        REVOKED,
        check_memory(&[forged.as_slice(), CRL_A, CRL_B], None)
    );
}

#[test]
fn warm_kept_cache_answers_revoked() {
    let (_dir, source) = folder_source(&[forged_newest().as_slice(), CRL_A], &[CRL_B], true);
    let mut pe = environment();
    pe.add_crl_source(Box::new(source.clone()));
    pe.add_revocation_cache(Box::new(source.clone()));
    let cps = settings(None);
    assert_eq!(REVOKED, check(&pe, &cps));

    // The kept CRL is B: not the forged one, which failed verification, and not A.
    let ca = cert(CA);
    let issuer: &dyn SubjectNameAndKey = ca.decoded();
    assert_eq!(
        PathValidationStatus::CertificateRevoked,
        source.get_status(&cert(EE), issuer, TimeOfInterest::now())
    );

    // With the CRL sources gone, the answer comes from the kept CRL.
    pe.clear_crl_sources();
    assert_eq!(REVOKED, check(&pe, &cps));
}

#[test]
fn warm_revocation_cache_answers_revoked() {
    let cache = Arc::new(RevocationCache::new());
    let mut pe = environment();
    pe.add_crl_source(Box::new(memory_source(&[CRL_A, CRL_B])));
    pe.add_revocation_cache(Box::new(cache.clone()));
    let cps = settings(None);
    assert_eq!(REVOKED, check(&pe, &cps));

    // With the CRL sources gone, the answer comes from the cache.
    pe.clear_crl_sources();
    assert_eq!(REVOKED, check(&pe, &cps));
}

// The folder source lists a CRL from its index without reading the file, so a newest CRL whose file
// is gone is still tried, fails to load, and the walk falls back to A.
#[test]
fn a_newest_crl_that_cannot_be_read_falls_back_to_a() {
    let (dir, source) = folder_source(&[CRL_A], &[CRL_B], false);
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if std::fs::read(&path).unwrap() == CRL_B {
            std::fs::remove_file(path).unwrap();
        }
    }
    let candidates = source.get_crl_candidates(&cert(EE)).unwrap();
    assert_eq!(2, candidates.len());
    assert!(candidates
        .iter()
        .all(|c| matches!(c.data, CrlCandidateData::Index(_))));

    let mut pe = environment();
    pe.add_crl_source(Box::new(source));
    assert_eq!(Ok(()), check(&pe, &settings(None)));
}
