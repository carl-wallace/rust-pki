//use certval::asn1::cryptographic_message_syntax2004::*;

use certval::environment::pki_environment::PkiEnvironment;
use certval::path_settings::*;
use certval::validator::path_validator::*;
use certval::*;
use der::Decode;
use x509_cert::*;

use self::certificate::{CertificateInner, Raw};

#[test]
fn prehash_required() {
    let enc_ca_cert = include_bytes!("examples/prehash_ca.der");
    let ca_cert = Certificate::from_der(enc_ca_cert).unwrap();
    let enc_target_cert = include_bytes!("examples/prehash_target.der");
    match DeferDecodeSigned::from_der(enc_target_cert) {
        Ok(parts) => {
            let pe = PkiEnvironment::new();
            verify_signature_message_rust_crypto(
                &pe,
                &parts.tbs_field,
                parts.signature.raw_bytes(),
                &parts.signature_algorithm,
                &ca_cert.tbs_certificate().subject_public_key_info(),
            )
            .unwrap();
        }
        Err(_) => panic!(),
    }
}

#[cfg(feature = "rsa")]
#[test]
fn pkits_test1() {
    let der_encoded_ta = include_bytes!("examples/TrustAnchorRootCertificate.crt");
    let der_encoded_ca = include_bytes!("examples/GoodCACert.crt");
    let der_encoded_ee = include_bytes!("examples/ValidCertificatePathTest1EE.crt");

    let mut ta = PDVTrustAnchorChoice::try_from(der_encoded_ta.as_slice()).unwrap();
    ta.parse_extensions(EXTS_OF_INTEREST);

    let mut ta_source2 = TaSource::new();
    let der_encoded_ta2 = include_bytes!("examples/TrustAnchorRootCertificate.crt");
    ta_source2.push(CertFile {
        filename: "TrustAnchorRootCertificate.crt".to_string(),
        bytes: der_encoded_ta2.to_vec(),
    });
    ta_source2.initialize().unwrap();

    let mut ca = PDVCertificate::try_from(der_encoded_ca.as_slice()).unwrap();
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate::try_from(der_encoded_ee.as_slice()).unwrap();

    let chain = vec![ca];

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();
    pe.add_trust_anchor_source(Box::new(ta_source2.clone()));

    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut cert_path = CertificationPath::new(ta, chain, ee);

    let cps = CertificationPathSettings::new();
    let mut cpr = CertificationPathResults::new();

    let r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
    if r.is_err() {
        panic!("Failed to validate path");
    }
}

// if this test fails, the version check in check_basic_constraints should be uncommented
#[test]
fn bad_ca_cert_version() {
    let der_encoded_ca = include_bytes!("examples/bad_version_tests/GoodCACert.bad_version.crt");
    let ca_cert = Certificate::from_der(der_encoded_ca);
    if ca_cert.is_ok() {
        panic!("Successfully parsed CA cert with unsupported version where error was expected");
    }
}

// if this test fails, the version check in check_basic_constraints should be uncommented
#[test]
fn bad_ee_cert_version() {
    let der_encoded_ee =
        include_bytes!("examples/bad_version_tests/ValidCertificatePathTest1EE.bad_version.crt");
    let ee_cert = Certificate::from_der(der_encoded_ee);
    if ee_cert.is_ok() {
        panic!("Successfully parsed CA cert with unsupported version where error was expected");
    }
}

// if this test fails, the version check in check_basic_constraints should be uncommented
#[test]
fn unsupported_ca_cert_version() {
    let der_encoded_ca =
        include_bytes!("examples/bad_version_tests/GoodCACert.unsupported_version.crt");
    let ca_cert = Certificate::from_der(der_encoded_ca);
    if ca_cert.is_ok() {
        panic!("Successfully parsed CA cert with unsupported version where error was expected");
    }
}

// if this test fails, the version check in check_basic_constraints should be uncommented
#[test]
fn unsupported_ee_cert_version() {
    let der_encoded_ee = include_bytes!(
        "examples/bad_version_tests/ValidCertificatePathTest1EE.unsupported_version.crt"
    );
    let ee_cert = Certificate::from_der(der_encoded_ee);
    if ee_cert.is_ok() {
        panic!("Successfully parsed CA cert with unsupported version where error was expected");
    }
}

#[test]
fn is_trust_anchor_test() {
    let mut pe = PkiEnvironment::default();
    let ta_source = TaSource::default();
    pe.add_trust_anchor_source(Box::new(ta_source.clone()));

    let der_encoded_ta = include_bytes!("../tests/examples/TrustAnchorRootCertificate.crt");
    let ta = PDVTrustAnchorChoice::try_from(der_encoded_ta.as_slice()).unwrap();
    let r = pe.is_trust_anchor(&ta);
    assert!(r.is_err());
    assert_eq!(r.err(), Some(Error::NotFound));

    let cf = CertFile {
        bytes: der_encoded_ta.to_vec(),
        filename: "TrustAnchorRootCertificate.crt".to_string(),
    };

    let mut ta_store = TaSource::new();
    ta_store.push(cf.clone());
    ta_store.initialize().unwrap();

    pe.clear_all_callbacks();
    pe.add_trust_anchor_source(Box::new(ta_store.clone()));

    let ta = PDVTrustAnchorChoice::try_from(der_encoded_ta.as_slice()).unwrap();
    assert!(pe.is_trust_anchor(&ta).is_ok());
}

#[test]
fn denies_self_signed_ee() {
    let _ = pretty_env_logger::try_init();

    let time_of_interest: TimeOfInterest = TimeOfInterest::from_unix_secs(1707264000).unwrap();
    let mut pe = PkiEnvironment::default();
    let ta_source = TaSource::default();
    let cert_source = CertSource::default();
    pe.add_trust_anchor_source(Box::new(ta_source));
    pe.add_certificate_source(Box::new(cert_source));

    pe.populate_5280_pki_environment();

    let pem_encoded_cert = include_bytes!("../tests/examples/ee_alice_ss_test.pem");
    use der::DecodePem as _;
    let cert = CertificateInner::<Raw>::from_pem(pem_encoded_cert).unwrap();
    let cert = PDVCertificate::try_from(cert).unwrap();

    let mut cps = CertificationPathSettings::default();
    cps.set_forbid_self_signed_ee(true);
    cps.set_time_of_interest(time_of_interest);

    let mut paths = vec![];
    if let Err(e) = pe.get_paths_for_target(&cert, &mut paths, 0, cps.get_time_of_interest()) {
        assert!(e.is_certificate_expired_error());
    }

    if paths.is_empty() {
        return;
    }

    for path in &mut paths {
        let mut cpr = CertificationPathResults::new();
        if validate_path_rfc5280(&pe, &cps, path, &mut cpr).is_err() {
            return;
        }
    }

    panic!("EE cert was accepted");
}

#[cfg(feature = "std")]
#[test]
fn wire_certchain_works() {
    use der::{DecodePem, Encode};
    let _ = pretty_env_logger::try_init();

    let time_of_interest: TimeOfInterest = TimeOfInterest::from_unix_secs(1707405529).unwrap();

    let mut pe = certval::environment::PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(time_of_interest);

    // Make a TrustAnchor source
    let mut trust_anchors = TaSource::new();

    let root =
        x509_cert::Certificate::from_pem(include_bytes!("examples/wire_certchain/ta.pem")).unwrap();

    trust_anchors.push(certval::CertFile {
        filename: format!("TrustAnchor #1"),
        bytes: root.to_der().unwrap(),
    });

    trust_anchors.initialize().unwrap();
    pe.add_trust_anchor_source(Box::new(trust_anchors));

    // Make a Certificate source for intermediate CA certs
    let mut cert_source = CertSource::new();
    let cert = x509_cert::Certificate::from_pem(include_bytes!(
        "examples/wire_certchain/intermediate.pem"
    ))
    .unwrap();
    cert_source.push(certval::CertFile {
        filename: format!("Intermediate CA #1 [{}]", cert.tbs_certificate().subject()),
        bytes: cert.to_der().unwrap(),
    });

    cert_source.initialize(&cps).unwrap();
    cert_source.find_all_partial_paths(&pe, &cps);
    pe.add_certificate_source(Box::new(cert_source));

    cps.set_require_ta_store(true);
    cps.set_forbid_self_signed_ee(true);

    let mut end_identity_cert = PDVCertificate::try_from(
        CertificateInner::<Raw>::from_pem(include_bytes!("examples/wire_certchain/ee.pem"))
            .unwrap(),
    )
    .unwrap();
    end_identity_cert.parse_extensions(EXTS_OF_INTEREST);

    let mut paths = vec![];
    pe.get_paths_for_target(&end_identity_cert, &mut paths, 0, time_of_interest)
        .unwrap();

    assert!(!paths.is_empty(), "No paths detected");

    for path in &mut paths {
        let mut cpr = CertificationPathResults::new();
        let _ = validate_path_rfc5280(&pe, &cps, path, &mut cpr).unwrap();
        let validation_status = cpr.get_validation_status().unwrap();
        assert_eq!(validation_status, PathValidationStatus::Valid);
    }
}
