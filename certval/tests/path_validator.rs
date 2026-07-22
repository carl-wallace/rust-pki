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
                ca_cert.tbs_certificate().subject_public_key_info(),
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

// Regression test for issue #79: get_trust_anchors must merge anchors from every registered
// source, not return only the first source's anchors.
#[test]
fn get_trust_anchors_merges_all_sources() {
    let mut pe = PkiEnvironment::default();

    let der_ta1 = include_bytes!("../tests/examples/TrustAnchorRootCertificate.crt");
    let mut src1 = TaSource::new();
    src1.push(CertFile {
        bytes: der_ta1.to_vec(),
        filename: "TrustAnchorRootCertificate.crt".to_string(),
    });
    src1.initialize().unwrap();

    let der_ta2 = include_bytes!("../tests/examples/GoodCACert.crt");
    let mut src2 = TaSource::new();
    src2.push(CertFile {
        bytes: der_ta2.to_vec(),
        filename: "GoodCACert.crt".to_string(),
    });
    src2.initialize().unwrap();

    // Each source individually exposes one anchor.
    assert_eq!(src1.get_trust_anchors().unwrap().len(), 1);
    assert_eq!(src2.get_trust_anchors().unwrap().len(), 1);

    pe.add_trust_anchor_source(Box::new(src1));
    pe.add_trust_anchor_source(Box::new(src2));

    // The environment must surface anchors from both sources (pre-#79 returned only the first).
    assert_eq!(
        pe.get_trust_anchors().len(),
        2,
        "get_trust_anchors should merge anchors from all registered sources"
    );
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

#[cfg(all(feature = "std", feature = "eddsa"))]
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
        filename: "TrustAnchor #1".to_string(),
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
        validate_path_rfc5280(&pe, &cps, path, &mut cpr).unwrap();
        let validation_status = cpr.get_validation_status().unwrap();
        assert_eq!(validation_status, PathValidationStatus::Valid);
    }
}

// RFC 5937 trust-anchor constraint provenance: when constraint enforcement is in effect and
// the trust store holds an anchor for the presented anchor's public key, the stored copy is
// authoritative. A presented anchor that matches the stored key AND constraints validates; one that
// shares the key but carries different constraints is rejected with TrustAnchorConstraintsMismatch.

/// Success path: the path's trust anchor is byte-identical to the store's copy, so enforcement lets
/// it through and the path validates (mirrors `pkits_test1` with enforcement enabled).
#[cfg(feature = "rsa")]
#[test]
fn enforce_ta_constraints_accepts_matching_store_anchor() {
    let der_encoded_ta = include_bytes!("examples/TrustAnchorRootCertificate.crt");
    let der_encoded_ca = include_bytes!("examples/GoodCACert.crt");
    let der_encoded_ee = include_bytes!("examples/ValidCertificatePathTest1EE.crt");

    let mut ta = PDVTrustAnchorChoice::try_from(der_encoded_ta.as_slice()).unwrap();
    ta.parse_extensions(EXTS_OF_INTEREST);

    let mut ta_source = TaSource::new();
    ta_source.push(CertFile {
        filename: "TrustAnchorRootCertificate.crt".to_string(),
        bytes: der_encoded_ta.to_vec(),
    });
    ta_source.initialize().unwrap();

    let mut ca = PDVCertificate::try_from(der_encoded_ca.as_slice()).unwrap();
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate::try_from(der_encoded_ee.as_slice()).unwrap();
    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();
    pe.add_trust_anchor_source(Box::new(ta_source.clone()));

    let mut cert_path = CertificationPath::new(ta, vec![ca], ee);

    let mut cps = CertificationPathSettings::new();
    cps.set_enforce_trust_anchor_constraints(true);
    let mut cpr = CertificationPathResults::new();

    let r = validate_path_rfc5280(&pe, &cps, &mut cert_path, &mut cpr);
    assert!(r.is_ok(), "expected success, got {r:?}");
}

/// Failure path: the store holds the root as a bare Certificate (no CertPathControls); the path
/// presents a TrustAnchorInfo with the SAME public key but different constraints. With enforcement
/// in effect the validator detects the mismatch. `require_ta_store` is left off so the constraint-
/// provenance check is exercised in isolation from the membership check.
#[cfg(feature = "rsa")]
#[test]
fn enforce_ta_constraints_rejects_same_key_different_constraints() {
    use der::asn1::OctetString;
    use x509_cert::anchor::{CertPathControls, TrustAnchorChoice, TrustAnchorInfo};

    let der_encoded_ta = include_bytes!("examples/TrustAnchorRootCertificate.crt");
    let der_encoded_ca = include_bytes!("examples/GoodCACert.crt");
    let der_encoded_ee = include_bytes!("examples/ValidCertificatePathTest1EE.crt");

    // Store holds the root cert in Certificate form (no TA constraints).
    let mut ta_source = TaSource::new();
    ta_source.push(CertFile {
        filename: "TrustAnchorRootCertificate.crt".to_string(),
        bytes: der_encoded_ta.to_vec(),
    });
    ta_source.initialize().unwrap();

    // Build a TrustAnchorInfo sharing the root's public key but carrying a different constraint set
    // (a path-length constraint the stored bare-cert anchor does not have).
    let root = Certificate::from_der(der_encoded_ta).unwrap();
    let cp: CertPathControls<Raw> = CertPathControls {
        ta_name: root.tbs_certificate().subject().clone(),
        certificate: None,
        policy_set: None,
        policy_flags: None,
        name_constr: None,
        path_len_constraint: Some(0),
    };
    // key_id = the SKID the store indexes TrustAnchorRootCertificate.crt under, so the O(1)
    // get_trust_anchor_by_hex_skid lookup in the validator resolves to the stored anchor (this is
    // also the realistic case: an anchor reuses the real SKID to be recognized).
    let root_skid: [u8; 20] = [
        0xE4, 0x7D, 0x5F, 0xD1, 0x5C, 0x95, 0x86, 0x08, 0x2C, 0x05, 0xAE, 0xBE, 0x75, 0xB6, 0x65,
        0xA7, 0xD9, 0x5D, 0xA8, 0x66,
    ];
    let tai: TrustAnchorInfo<Raw> = TrustAnchorInfo {
        version: Default::default(),
        pub_key: root.tbs_certificate().subject_public_key_info().clone(),
        key_id: OctetString::new(root_skid.to_vec()).unwrap(),
        ta_title: None,
        cert_path: Some(cp),
        extensions: None,
        ta_title_lang_tag: None,
    };
    let tac: TrustAnchorChoice<Raw> = TrustAnchorChoice::TaInfo(tai);
    let mut presented = PDVTrustAnchorChoice::try_from(tac).unwrap();
    presented.parse_extensions(EXTS_OF_INTEREST);

    let mut ca = PDVCertificate::try_from(der_encoded_ca.as_slice()).unwrap();
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate::try_from(der_encoded_ee.as_slice()).unwrap();
    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();
    pe.add_trust_anchor_source(Box::new(ta_source.clone()));

    let mut cert_path = CertificationPath::new(presented, vec![ca], ee);

    let mut cps = CertificationPathSettings::new();
    cps.set_enforce_trust_anchor_constraints(true);
    cps.set_require_ta_store(false);
    // The hand-built TrustAnchorInfo has no validity dates, so skip TA-validity enforcement; the
    // constraint-provenance check is what this test exercises.
    cps.set_enforce_trust_anchor_validity(false);
    let mut cpr = CertificationPathResults::new();

    let r = validate_path_rfc5280(&pe, &cps, &mut cert_path, &mut cpr);
    assert_eq!(
        r.err(),
        Some(Error::PathValidation(
            PathValidationStatus::TrustAnchorConstraintsMismatch
        )),
        "expected TrustAnchorConstraintsMismatch"
    );
}

// A subject key identifier shared by two trust anchors with different public keys is ambiguous:
// the PkiEnvironment poisons that SKID and refuses trust-anchor lookups keyed on it, so neither
// anchor can be used. A store without the collision resolves normally, and a same-key duplicate
// under the same SKID is benign and still resolves.
#[cfg(feature = "rsa")]
#[test]
fn colliding_skid_different_keys_is_refused() {
    use der::asn1::OctetString;
    use der::Encode;
    use x509_cert::anchor::{TrustAnchorChoice, TrustAnchorInfo};

    // This test deliberately induces a SKID collision, which the library correctly reports at ERROR.
    // Suppress log output for the duration so the induced error does not clutter otherwise-quiet test
    // output; no assertion depends on logging. Install the logger first (idempotent) so a sibling
    // test's parallel try_init cannot reset the max level back after this one lowers it.
    let _ = pretty_env_logger::try_init();
    let prev_log_level = log::max_level();
    log::set_max_level(log::LevelFilter::Off);

    let der_root = include_bytes!("examples/TrustAnchorRootCertificate.crt");
    let der_other = include_bytes!("examples/GoodCACert.crt");
    let root = Certificate::from_der(der_root).unwrap();
    let other = Certificate::from_der(der_other).unwrap();

    // The SKID TrustAnchorRootCertificate.crt is indexed under.
    let root_skid: [u8; 20] = [
        0xE4, 0x7D, 0x5F, 0xD1, 0x5C, 0x95, 0x86, 0x08, 0x2C, 0x05, 0xAE, 0xBE, 0x75, 0xB6, 0x65,
        0xA7, 0xD9, 0x5D, 0xA8, 0x66,
    ];
    let root_skid_hex = buffer_to_hex(&root_skid);

    // A TaInfo trust anchor reusing root_skid as its key_id, carrying the given public key, as a DER
    // buffer a TaSource can parse.
    let make_tainfo = |spki: spki::SubjectPublicKeyInfoOwned| -> Vec<u8> {
        let tai: TrustAnchorInfo<Raw> = TrustAnchorInfo {
            version: Default::default(),
            pub_key: spki,
            key_id: OctetString::new(root_skid.to_vec()).unwrap(),
            ta_title: None,
            cert_path: None,
            extensions: None,
            ta_title_lang_tag: None,
        };
        TrustAnchorChoice::TaInfo(tai).to_der().unwrap()
    };

    let mut src_root = TaSource::new();
    src_root.push(CertFile {
        filename: "root".to_string(),
        bytes: der_root.to_vec(),
    });
    src_root.initialize().unwrap();

    let mut root_ta = PDVTrustAnchorChoice::try_from(der_root.as_slice()).unwrap();
    root_ta.parse_extensions(EXTS_OF_INTEREST);

    // Baseline: no collision, so the root resolves by its SKID and is recognized as a trust anchor.
    {
        let mut pe = PkiEnvironment::new();
        pe.add_trust_anchor_source(Box::new(src_root.clone()));
        assert!(pe.get_trust_anchor_by_hex_skid(&root_skid_hex).is_ok());
        assert!(pe.is_trust_anchor(&root_ta).is_ok());
    }

    // Collision: a second anchor reuses the SKID with a different key -> the SKID is poisoned.
    let mut src_collide = TaSource::new();
    src_collide.push(CertFile {
        filename: "collide".to_string(),
        bytes: make_tainfo(other.tbs_certificate().subject_public_key_info().clone()),
    });
    src_collide.initialize().unwrap();
    assert_eq!(
        src_collide.get_trust_anchors().unwrap().len(),
        1,
        "the TaInfo buffer should have parsed into a trust anchor"
    );
    {
        let mut pe = PkiEnvironment::new();
        pe.add_trust_anchor_source(Box::new(src_root.clone()));
        pe.add_trust_anchor_source(Box::new(src_collide.clone()));
        assert!(
            pe.get_trust_anchor_by_hex_skid(&root_skid_hex).is_err(),
            "an ambiguous SKID must not resolve to a trust anchor"
        );
        assert!(
            pe.is_trust_anchor(&root_ta).is_err(),
            "a cert bearing the ambiguous SKID must not be accepted as a trust anchor"
        );
    }

    // Same key reused under the same SKID is a benign duplicate, not a collision -> still resolves.
    let mut src_dup = TaSource::new();
    src_dup.push(CertFile {
        filename: "dup".to_string(),
        bytes: make_tainfo(root.tbs_certificate().subject_public_key_info().clone()),
    });
    src_dup.initialize().unwrap();
    {
        let mut pe = PkiEnvironment::new();
        pe.add_trust_anchor_source(Box::new(src_root.clone()));
        pe.add_trust_anchor_source(Box::new(src_dup.clone()));
        assert!(
            pe.get_trust_anchor_by_hex_skid(&root_skid_hex).is_ok(),
            "a same-key duplicate SKID is benign and must still resolve"
        );
    }

    log::set_max_level(prev_log_level);
}
