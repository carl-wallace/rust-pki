//! Positive/negative coverage for UPN (Microsoft user principal name) name constraints.
//!
//! The fixtures in `examples/upn_nc` are the PKITS RFC822 nameConstraints certificates recast so
//! that the constraint (in each CA) and the name (in each EE) are carried as a UPN otherName
//! (OID 1.3.6.1.4.1.311.20.2.3) instead of an rfc822Name: the rfc822 value is rewritten as a UPN
//! otherName with the same string and disposition, the CA is re-signed by the trust anchor key and
//! the EE by its issuing CA key. A UPN is structured as an email address and certval applies rfc822
//! semantics to it, so expected results match the RFC822 originals:
//!
//! * CA1 permits `.testcertificates.gov` (sub-domains only)
//! * CA2 permits `testcertificates.gov` (host itself)
//! * CA3 excludes `testcertificates.gov`
#![cfg(all(feature = "std", feature = "rsa"))]

use certval::environment::pki_environment::PkiEnvironment;
use certval::path_settings::*;
use certval::validator::path_validator::*;
use certval::*;

/// Builds the TrustAnchor -> CA -> EE path from the fixture bytes and runs RFC 5280 validation.
fn validate(der_ca: &[u8], der_ee: &[u8]) -> certval::Result<()> {
    let der_ta = include_bytes!("examples/TrustAnchorRootCertificate.crt");

    let mut ta = PDVTrustAnchorChoice::try_from(der_ta.as_slice()).unwrap();
    ta.parse_extensions(EXTS_OF_INTEREST);

    let mut ta_source = TaSource::new();
    ta_source.push(CertFile {
        filename: "TrustAnchorRootCertificate.crt".to_string(),
        bytes: der_ta.to_vec(),
    });
    ta_source.initialize().unwrap();

    let mut ca = PDVCertificate::try_from(der_ca).unwrap();
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate::try_from(der_ee).unwrap();
    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();
    pe.add_trust_anchor_source(Box::new(ta_source));

    let mut cert_path = CertificationPath::new(ta, vec![ca], ee);
    let cps = CertificationPathSettings::new();
    let mut cpr = CertificationPathResults::new();
    pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr)
}

const CA1: &[u8] = include_bytes!("examples/upn_nc/nameConstraintsUPNCA1Cert.crt");
const CA2: &[u8] = include_bytes!("examples/upn_nc/nameConstraintsUPNCA2Cert.crt");
const CA3: &[u8] = include_bytes!("examples/upn_nc/nameConstraintsUPNCA3Cert.crt");

fn assert_valid(r: certval::Result<()>) {
    assert!(
        r.is_ok(),
        "expected UPN-constrained path to validate, got {r:?}"
    );
}

fn assert_nc_violation(r: certval::Result<()>) {
    assert_eq!(
        r.err(),
        Some(Error::PathValidation(
            PathValidationStatus::NameConstraintsViolation
        )),
        "expected a UPN name-constraints violation"
    );
}

// CA1 permits the domain .testcertificates.gov: a UPN on a sub-domain host is permitted.
#[test]
fn valid_upn_permitted_subdomain_test21() {
    assert_valid(validate(
        CA1,
        include_bytes!("examples/upn_nc/ValidUPNnameConstraintsTest21EE.crt"),
    ));
}

// CA1 permits only sub-domains: a UPN on the bare host testcertificates.gov is not permitted.
#[test]
fn invalid_upn_not_permitted_host_test22() {
    assert_nc_violation(validate(
        CA1,
        include_bytes!("examples/upn_nc/InvalidUPNnameConstraintsTest22EE.crt"),
    ));
}

// CA2 permits the host testcertificates.gov: a UPN on that exact host is permitted.
#[test]
fn valid_upn_permitted_host_test23() {
    assert_valid(validate(
        CA2,
        include_bytes!("examples/upn_nc/ValidUPNnameConstraintsTest23EE.crt"),
    ));
}

// CA2 permits only the host itself: a UPN on a sub-domain is not permitted.
#[test]
fn invalid_upn_not_permitted_subdomain_test24() {
    assert_nc_violation(validate(
        CA2,
        include_bytes!("examples/upn_nc/InvalidUPNnameConstraintsTest24EE.crt"),
    ));
}

// CA3 excludes testcertificates.gov: a UPN on a sub-domain host is outside the exclusion.
#[test]
fn valid_upn_outside_excluded_test25() {
    assert_valid(validate(
        CA3,
        include_bytes!("examples/upn_nc/ValidUPNnameConstraintsTest25EE.crt"),
    ));
}

// CA3 excludes testcertificates.gov: a UPN on that exact host is excluded.
#[test]
fn invalid_upn_excluded_host_test26() {
    assert_nc_violation(validate(
        CA3,
        include_bytes!("examples/upn_nc/InvalidUPNnameConstraintsTest26EE.crt"),
    ));
}
