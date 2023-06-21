use certval::asn1::cryptographic_message_syntax2004::*;
use certval::environment::pki_environment::PkiEnvironment;
use certval::path_settings::*;
use certval::validator::path_validator::*;
use certval::*;
use der::Decode;
use x509_cert::anchor::TrustAnchorChoice;
use x509_cert::*;

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
                parts.tbs_field,
                parts.signature.raw_bytes(),
                &parts.signature_algorithm,
                &ca_cert.tbs_certificate.subject_public_key_info,
            )
            .unwrap();
        }
        Err(_) => panic!(),
    }
}

#[test]
fn signed_data_parse_test1() {
    use der::Encode;
    let der_encoded_sd = include_bytes!("examples/caCertsIssuedTofbcag4.p7c");
    let ci = ContentInfo2004::from_der(der_encoded_sd).unwrap();
    let content = ci.content.to_vec().unwrap();
    let _sd = SignedData::from_der(content.as_slice()).unwrap();
    //assert_eq!(1, sd.certificates.unwrap().len());

    let der_encoded_sd = include_bytes!("examples/DODJITCINTEROPERABILITYROOTCA2_IT.p7c");
    let ci = ContentInfo2004::from_der(der_encoded_sd).unwrap();
    let content = ci.content.to_vec().unwrap();
    let sd = SignedData::from_der(content.as_slice()).unwrap();
    assert_eq!(1, sd.certificates.unwrap().len());

    let der_encoded_sd = include_bytes!("examples/DODROOTCA3_IB.p7c");
    let ci = ContentInfo2004::from_der(der_encoded_sd).unwrap();
    let content = ci.content.to_vec().unwrap();
    let sd = SignedData::from_der(content.as_slice()).unwrap();
    assert_eq!(26, sd.certificates.unwrap().len());
}

#[test]
fn pkits_test1() {
    let der_encoded_ta = include_bytes!("examples/TrustAnchorRootCertificate.crt");
    let der_encoded_ca = include_bytes!("examples/GoodCACert.crt");
    let der_encoded_ee = include_bytes!("examples/ValidCertificatePathTest1EE.crt");

    let tac = TrustAnchorChoice::from_der(der_encoded_ta).unwrap();
    let mut ta = PDVTrustAnchorChoice {
        encoded_ta: der_encoded_ta.to_vec(),
        decoded_ta: tac,
        metadata: None,
        parsed_extensions: ParsedExtensions::new(),
    };
    ta.parse_extensions(EXTS_OF_INTEREST);

    let mut ta_source2 = TaSource::new();
    let der_encoded_ta2 = include_bytes!("examples/TrustAnchorRootCertificate.crt");
    ta_source2.buffers.push(CertFile {
        filename: "TrustAnchorRootCertificate.crt".to_string(),
        bytes: der_encoded_ta2.to_vec(),
    });

    populate_parsed_ta_vector(&ta_source2.buffers, &mut ta_source2.tas);
    ta_source2.index_tas();

    let ca_cert = Certificate::from_der(der_encoded_ca).unwrap();
    let ee_cert = Certificate::from_der(der_encoded_ee).unwrap();

    let mut ca = PDVCertificate {
        encoded_cert: der_encoded_ca.to_vec(),
        decoded_cert: ca_cert,
        metadata: None,
        parsed_extensions: ParsedExtensions::new(),
    };
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate {
        encoded_cert: der_encoded_ee.to_vec(),
        decoded_cert: ee_cert,
        metadata: None,
        parsed_extensions: ParsedExtensions::new(),
    };

    let chain = vec![&ca];

    let mut pe = PkiEnvironment::new();
    populate_5280_pki_environment(&mut pe);
    pe.add_trust_anchor_source(&ta_source2);

    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut cert_path = CertificationPath::new(&ta, chain, &ee);

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
    pe.add_trust_anchor_source(&ta_source);

    let der_encoded_ta = include_bytes!("../tests/examples/TrustAnchorRootCertificate.crt");
    let tac = TrustAnchorChoice::from_der(der_encoded_ta).unwrap();
    let ta = PDVTrustAnchorChoice {
        encoded_ta: der_encoded_ta.to_vec(),
        decoded_ta: tac,
        metadata: None,
        parsed_extensions: ParsedExtensions::new(),
    };
    let r = pe.is_trust_anchor(&ta);
    assert!(r.is_err());
    assert_eq!(r.err(), Some(Error::NotFound));

    let cf = CertFile {
        bytes: der_encoded_ta.to_vec(),
        filename: "TrustAnchorRootCertificate.crt".to_string(),
    };
    let v = vec![cf];
    let mut ta_store = TaSource::new();
    ta_store.buffers = v;
    ta_store.tas = vec![ta];
    ta_store.index_tas();

    pe.clear_all_callbacks();
    pe.add_trust_anchor_source(&ta_store);

    let tac2 = TrustAnchorChoice::from_der(der_encoded_ta).unwrap();
    let ta2 = PDVTrustAnchorChoice {
        encoded_ta: der_encoded_ta.to_vec(),
        decoded_ta: tac2,
        metadata: None,
        parsed_extensions: ParsedExtensions::new(),
    };
    assert!(pe.is_trust_anchor(&ta2).is_ok());
}
