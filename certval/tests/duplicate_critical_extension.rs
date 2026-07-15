//! A certificate that carries the same critical extension twice must be rejected.
//!
//! RFC 5280 4.2 forbids an issuer from including more than one instance of a particular extension.
//! certval processes extensions by OID, so a second copy of a critical extension would otherwise be
//! silently treated as processed; `validate_path` must instead reject it as an unprocessed critical
//! extension.
//!
//! The fixture is the passing PKITS path TrustAnchorRoot -> nameConstraintsDN1CACert ->
//! ValidDNnameConstraintsTest1EE with the CA's critical nameConstraints extension duplicated and the
//! CA re-signed by the trust anchor key (see code_reviews/dup_critical_ext_generate.py). The control
//! case uses the unmodified CA so the only difference between pass and fail is the duplicate.
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

const EE: &[u8] =
    include_bytes!("examples/PKITS_data_2048/certs/ValidDNnameConstraintsTest1EE.crt");

// Control: the unmodified CA (a single critical nameConstraints extension) validates.
#[test]
fn valid_dn_name_constraints_control() {
    let ca = include_bytes!("examples/PKITS_data_2048/certs/nameConstraintsDN1CACert.crt");
    assert!(
        validate(ca, EE).is_ok(),
        "unmodified PKITS DN nameConstraints Test1 path should validate"
    );
}

// The same path but with the CA's critical nameConstraints extension duplicated is rejected as an
// unprocessed critical extension.
#[test]
fn duplicate_critical_extension_rejected() {
    let ca =
        include_bytes!("examples/dup_critical_ext/nameConstraintsDN1CADuplicateCriticalNcCert.crt");
    assert_eq!(
        validate(ca, EE).err(),
        Some(Error::PathValidation(
            PathValidationStatus::UnprocessedCriticalExtension
        )),
        "a duplicated critical extension must be rejected"
    );
}
