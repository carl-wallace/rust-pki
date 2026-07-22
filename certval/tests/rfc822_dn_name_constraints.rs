//! Positive/negative coverage for rfc822 name constraints applied to a PKCS#9 emailAddress
//! attribute carried in the subject DN (RFC 5280 4.2.1.10 style, matching OpenSSL behavior).
//!
//! The fixtures in `examples/rfc822_dn_nc` are the PKITS RFC822 nameConstraints end-entity
//! certificates with the rfc822Name relocated from the subjectAltName extension into the subject
//! DN as an emailAddress attribute, re-signed by the original issuing CA key (see
//! `examples/rfc822_dn_nc/generate.py`). Because the address now lives only in the DN, acceptance
//! depends entirely on the emailAddress-in-DN name-constraints check; expected results therefore
//! match the SAN-based PKITS originals:
//!
//! * CA1 permits `.testcertificates.gov` (sub-domains only)
//! * CA2 permits `testcertificates.gov` (host itself)
//! * CA3 excludes `testcertificates.gov`
#![cfg(all(feature = "std", feature = "rsa"))]

use certval::environment::pki_environment::PkiEnvironment;
use certval::path_settings::*;
use certval::validator::path_validator::*;
use certval::*;

/// Builds the TrustAnchor -> CA -> EE path from the fixture bytes and runs RFC 5280 validation,
/// returning both the validation result and the results object so callers can inspect recorded
/// terminal state (e.g., name-constraints subtrees).
fn validate_with_cpr(
    der_ca: &[u8],
    der_ee: &[u8],
) -> (certval::Result<()>, CertificationPathResults) {
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
    let r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
    (r, cpr)
}

/// Builds the TrustAnchor -> CA -> EE path from the fixture bytes and runs RFC 5280 validation.
fn validate(der_ca: &[u8], der_ee: &[u8]) -> certval::Result<()> {
    validate_with_cpr(der_ca, der_ee).0
}

const CA1: &[u8] = include_bytes!("examples/rfc822_dn_nc/nameConstraintsRFC822CA1Cert.crt");
const CA2: &[u8] = include_bytes!("examples/rfc822_dn_nc/nameConstraintsRFC822CA2Cert.crt");
const CA3: &[u8] = include_bytes!("examples/rfc822_dn_nc/nameConstraintsRFC822CA3Cert.crt");

fn assert_nc_violation(r: certval::Result<()>) {
    assert_eq!(
        r.err(),
        Some(Error::PathValidation(
            PathValidationStatus::NameConstraintsViolation
        )),
        "expected a name-constraints violation for the emailAddress-in-DN"
    );
}

// --- Valid: emailAddress in DN falls within the permitted / outside the excluded subtree ---

#[test]
fn valid_rfc822_dn_permitted_subdomain_test21() {
    // CA1 permits `.testcertificates.gov`; mailserver.testcertificates.gov is a sub-domain.
    let ee = include_bytes!("examples/rfc822_dn_nc/ValidRFC822nameConstraintsDNTest21EE.crt");
    assert!(validate(CA1, ee).is_ok());
}

#[test]
fn valid_rfc822_dn_permitted_host_test23() {
    // CA2 permits the host `testcertificates.gov`; the address is at that exact host.
    let ee = include_bytes!("examples/rfc822_dn_nc/ValidRFC822nameConstraintsDNTest23EE.crt");
    assert!(validate(CA2, ee).is_ok());
}

#[test]
fn valid_rfc822_dn_outside_excluded_test25() {
    // CA3 excludes `testcertificates.gov`; a sub-domain address is not excluded.
    let ee = include_bytes!("examples/rfc822_dn_nc/ValidRFC822nameConstraintsDNTest25EE.crt");
    assert!(validate(CA3, ee).is_ok());
}

// --- Invalid: emailAddress in DN violates the rfc822 constraint ---

#[test]
fn invalid_rfc822_dn_not_permitted_host_test22() {
    // CA1 permits sub-domains only; the host `testcertificates.gov` itself is not permitted.
    let ee = include_bytes!("examples/rfc822_dn_nc/InvalidRFC822nameConstraintsDNTest22EE.crt");
    assert_nc_violation(validate(CA1, ee));
}

#[test]
fn invalid_rfc822_dn_not_permitted_subdomain_test24() {
    // CA2 permits the host only; a sub-domain address is outside the permitted subtree.
    let ee = include_bytes!("examples/rfc822_dn_nc/InvalidRFC822nameConstraintsDNTest24EE.crt");
    assert_nc_violation(validate(CA2, ee));
}

#[test]
fn invalid_rfc822_dn_excluded_host_test26() {
    // CA3 excludes `testcertificates.gov`; an address at that host is excluded.
    let ee = include_bytes!("examples/rfc822_dn_nc/InvalidRFC822nameConstraintsDNTest26EE.crt");
    assert_nc_violation(validate(CA3, ee));
}

// --- Terminal name-constraints state recorded in the results (PR_FINAL_{PERMITTED,EXCLUDED}_SUBTREES) ---

#[test]
fn terminal_permitted_subtrees_recorded_on_success() {
    // CA1 asserts a permitted rfc822 subtree (.testcertificates.gov) and no excluded subtree, so the
    // terminal permitted set carries it and the excluded set stays empty.
    let ee = include_bytes!("examples/rfc822_dn_nc/ValidRFC822nameConstraintsDNTest21EE.crt");
    let (r, cpr) = validate_with_cpr(CA1, ee);
    assert!(r.is_ok());

    let permitted = cpr
        .get_final_permitted_subtrees()
        .expect("permitted subtrees recorded on success");
    let permitted = name_constraints_set_to_name_constraints_settings(&permitted).unwrap();
    assert_eq!(
        permitted.rfc822_name,
        Some(vec![".testcertificates.gov".to_string()])
    );

    let excluded = cpr
        .get_final_excluded_subtrees()
        .expect("excluded subtrees recorded on success");
    assert!(!excluded.are_any_empty());
    assert!(excluded.rfc822_name.is_empty());
}

#[test]
fn terminal_excluded_subtrees_recorded_on_success() {
    // CA3 asserts an excluded rfc822 subtree (testcertificates.gov) and no permitted subtree, so the
    // terminal excluded set carries it and the permitted set stays empty.
    let ee = include_bytes!("examples/rfc822_dn_nc/ValidRFC822nameConstraintsDNTest25EE.crt");
    let (r, cpr) = validate_with_cpr(CA3, ee);
    assert!(r.is_ok());

    let excluded = cpr
        .get_final_excluded_subtrees()
        .expect("excluded subtrees recorded on success");
    let excluded = name_constraints_set_to_name_constraints_settings(&excluded).unwrap();
    assert_eq!(
        excluded.rfc822_name,
        Some(vec!["testcertificates.gov".to_string()])
    );

    let permitted = cpr
        .get_final_permitted_subtrees()
        .expect("permitted subtrees recorded on success");
    assert!(permitted.rfc822_name.is_empty());
}

#[test]
fn terminal_subtrees_absent_on_name_constraints_failure() {
    // A name-constraints violation returns early from check_names before the terminal state is
    // recorded, so neither index is present. The failure is conveyed by the validation status.
    let ee = include_bytes!("examples/rfc822_dn_nc/InvalidRFC822nameConstraintsDNTest26EE.crt");
    let (r, cpr) = validate_with_cpr(CA3, ee);
    assert_nc_violation(r);
    assert!(cpr.get_final_permitted_subtrees().is_none());
    assert!(cpr.get_final_excluded_subtrees().is_none());
}
