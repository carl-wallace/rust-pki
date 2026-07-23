#![cfg(feature = "revocation")]

#[cfg(all(feature = "revocation", feature = "std", feature = "rsa"))]
#[tokio::test]
async fn stapled_crl_async() {
    use certval::environment::pki_environment::PkiEnvironment;
    use certval::path_settings::*;
    use certval::validator::path_validator::*;
    use certval::*;

    // Target expires UTCTime 02/08/2022 23:59:59 GMT
    // CA expires UTCTime 31/12/2030 23:59:59 GMT

    let der_encoded_ta = include_bytes!("examples/harvard.edu/0-ta.der");
    let der_encoded_ca = include_bytes!("examples/harvard.edu/1.der");
    let der_encoded_ca_crl = include_bytes!("examples/harvard.edu/1-crl.crl");
    let der_encoded_ee = include_bytes!("examples/harvard.edu/2-target.der");
    let der_encoded_ee_crl = include_bytes!("examples/harvard.edu/2-crl.crl");

    let ta = PDVTrustAnchorChoice::try_from(der_encoded_ta.as_slice()).unwrap();
    let mut ca = PDVCertificate::try_from(der_encoded_ca.as_slice()).unwrap();
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate::try_from(der_encoded_ee.as_slice()).unwrap();

    let chain = vec![ca];

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();
    let mut pe2 = PkiEnvironment::new();
    pe2.add_validate_path_callback(validate_path_rfc5280);

    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut cert_path = CertificationPath::new(ta, chain, ee);

    cert_path.crls[0] = Some(der_encoded_ca_crl.to_vec());
    cert_path.crls[1] = Some(der_encoded_ee_crl.to_vec());

    let mut cps = CertificationPathSettings::new();
    cps.set_check_ocsp_from_aia(false);
    cps.set_require_ta_store(false);
    let mut cpr = CertificationPathResults::new();

    {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1646567209).unwrap());
        let mut r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
        if r.is_err() {
            panic!("Failed to successfully validate path");
        }
        r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await;
        if r.is_err() {
            panic!("Failed to successfully check revocation using stapled OCSP responses");
        }
    }
    #[cfg(feature = "remote")]
    {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1646567209).unwrap());
        let mut r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
        if r.is_err() {
            panic!("Failed to successfully validate path");
        }
        r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await;
        if r.is_err() {
            panic!("Failed to successfully check revocation after failing over from stapled OCSP responses to dynamic");
        }
    }
    #[cfg(not(feature = "remote"))]
    {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1649245609).unwrap());
        let r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
        if r.is_err() {
            panic!("Failed to successfully validate path");
        }
        #[cfg(feature = "revocation")]
        {
            let r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await;
            if r.is_ok() {
                panic!("Failed to reject stale stapled CRLs");
            }
        }
    }
}

#[cfg(all(feature = "revocation", feature = "std", feature = "rsa"))]
#[tokio::test]
async fn stapled_mix_async() {
    use certval::environment::pki_environment::PkiEnvironment;
    use certval::path_settings::*;
    use certval::validator::path_validator::*;
    use certval::*;

    // Target expires UTCTime 02/08/2022 23:59:59 GMT
    // CA expires UTCTime 31/12/2030 23:59:59 GMT

    let der_encoded_ta = include_bytes!("examples/harvard.edu/0-ta.der");
    let der_encoded_ca = include_bytes!("examples/harvard.edu/1.der");
    let der_encoded_ca_ocsp = include_bytes!("examples/harvard.edu/1-ocsp.ocspResp");
    let der_encoded_ee = include_bytes!("examples/harvard.edu/2-target.der");
    let der_encoded_ee_crl = include_bytes!("examples/harvard.edu/2-crl.crl");

    let ta = PDVTrustAnchorChoice::try_from(der_encoded_ta.as_slice()).unwrap();

    let mut ca = PDVCertificate::try_from(der_encoded_ca.as_slice()).unwrap();
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate::try_from(der_encoded_ee.as_slice()).unwrap();

    let chain = vec![ca];

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();
    let mut pe2 = PkiEnvironment::new();
    pe2.add_validate_path_callback(validate_path_rfc5280);

    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut cert_path = CertificationPath::new(ta, chain, ee);

    cert_path.ocsp_responses[0] = Some(der_encoded_ca_ocsp.to_vec());
    cert_path.crls[1] = Some(der_encoded_ee_crl.to_vec());

    let mut cps = CertificationPathSettings::new();
    cps.set_require_ta_store(false);

    cps.set_check_ocsp_from_aia(false);
    cps.set_check_crldp_http(false);
    let mut cpr = CertificationPathResults::new();

    {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1646567209).unwrap());
        let mut r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
        if r.is_err() {
            panic!("Failed to successfully validate path");
        }
        r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await;
        if r.is_err() {
            panic!("Failed to successfully check revocation using stapled OCSP responses");
        }
    }
    #[cfg(feature = "remote")]
    {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1646567209).unwrap());
        let mut r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
        if r.is_err() {
            panic!("Failed to successfully validate path");
        }
        r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await;
        if r.is_err() {
            panic!("Failed to successfully check revocation after failing over from stapled OCSP responses to dynamic");
        }
    }
    #[cfg(not(feature = "remote"))]
    {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1649245609).unwrap());
        let r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
        if r.is_err() {
            panic!("Failed to successfully validate path");
        }
        #[cfg(feature = "revocation")]
        {
            let r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await;
            if r.is_ok() {
                panic!("Failed to reject stale stapled CRLs");
            }
        }
    }
}

#[cfg(all(feature = "revocation", feature = "std", feature = "rsa"))]
#[tokio::test]
async fn cached_crl_async() {
    use certval::environment::pki_environment::PkiEnvironment;
    use certval::path_settings::*;
    use certval::validator::path_validator::*;
    use certval::CrlSourceFolders;
    use certval::*;
    use std::path::PathBuf;

    // Target expires UTCTime 02/08/2022 23:59:59 GMT
    // CA expires UTCTime 31/12/2030 23:59:59 GMT

    let der_encoded_ta = include_bytes!("examples/makaan.com/0-ta.der");
    let der_encoded_ca = include_bytes!("examples/makaan.com/1.der");
    let der_encoded_ee = include_bytes!("examples/makaan.com/2-target.der");

    let ta = PDVTrustAnchorChoice::try_from(der_encoded_ta.as_slice()).unwrap();

    let mut ca = PDVCertificate::try_from(der_encoded_ca.as_slice()).unwrap();
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate::try_from(der_encoded_ee.as_slice()).unwrap();

    let chain = vec![ca];

    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests/examples/makaan.com/crls");
    let crl_source = CrlSourceFolders::new(d.as_path().to_str().unwrap());
    if crl_source
        .index_crls(TimeOfInterest::from_unix_secs(1647011592).unwrap())
        .is_err()
    {
        panic!("Failed to index CRLs")
    }

    let v = crl_source.get_crls(&ee).unwrap();
    assert_eq!(1, v.len());

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();
    pe.add_crl_source(Box::new(crl_source));
    pe.add_revocation_cache(Box::new(RevocationCache::new()));

    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut cert_path = CertificationPath::new(ta, chain, ee);

    let mut cps = CertificationPathSettings::new();
    cps.set_require_ta_store(false);
    cps.set_check_ocsp_from_aia(false);
    cps.set_check_crldp_http(false);
    let mut cpr = CertificationPathResults::new();

    {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1647011592).unwrap());
        let mut r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
        if r.is_err() {
            panic!("Failed to successfully validate path");
        }
        r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await;
        if r.is_err() {
            panic!("Failed to successfully check revocation using cached CRLs");
        }
    }

    pe.clear_crl_sources();

    let mut cpr = CertificationPathResults::new();

    {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1647011592).unwrap());
        let mut r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
        if r.is_err() {
            panic!("Failed to successfully validate path");
        }
        r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await;
        if r.is_err() {
            panic!("Failed to successfully check revocation using cached CRLs");
        }
    }
}

#[cfg(all(feature = "revocation", feature = "std", feature = "rsa"))]
#[tokio::test]
async fn cached_crl_revoked_async() {
    use certval::environment::pki_environment::PkiEnvironment;
    use certval::path_settings::*;
    use certval::validator::path_validator::*;
    use certval::CrlSourceFolders;
    use certval::*;
    use std::path::PathBuf;

    // Target expires UTCTime 02/08/2022 23:59:59 GMT
    // CA expires UTCTime 31/12/2030 23:59:59 GMT

    let der_encoded_ta = include_bytes!("examples/intel.com/0-ta.der");
    let der_encoded_ca = include_bytes!("examples/intel.com/1.der");
    let der_encoded_ee = include_bytes!("examples/intel.com/2-target.der");

    let ta = PDVTrustAnchorChoice::try_from(der_encoded_ta.as_slice()).unwrap();

    let mut ca = PDVCertificate::try_from(der_encoded_ca.as_slice()).unwrap();
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate::try_from(der_encoded_ee.as_slice()).unwrap();

    let chain = vec![ca];

    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests/examples/intel.com/crls");
    let crl_source = CrlSourceFolders::new(d.as_path().to_str().unwrap());
    if crl_source
        .index_crls(TimeOfInterest::from_unix_secs(1647011592).unwrap())
        .is_err()
    {
        panic!("Failed to index CRLs")
    }

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();
    pe.add_crl_source(Box::new(crl_source));
    pe.add_revocation_cache(Box::new(RevocationCache::new()));

    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut cert_path = CertificationPath::new(ta, chain, ee);

    let mut cps = CertificationPathSettings::new();
    cps.set_require_ta_store(false);
    cps.set_check_ocsp_from_aia(false);
    cps.set_check_crldp_http(false);
    let mut cpr = CertificationPathResults::new();

    {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1647011592).unwrap());
        let r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
        if r.is_err() {
            panic!("Failed to successfully validate path");
        }
        if let Err(e) = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await {
            if Error::PathValidation(PathValidationStatus::CertificateRevokedEndEntity) != e {
                panic!("Failed to yield revoked end entity result (failed with other error)");
            }
        } else {
            panic!("Failed to yield revoked end entity result");
        }
    }

    pe.clear_crl_sources();

    let mut cpr = CertificationPathResults::new();

    {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1647011592).unwrap());
        let r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
        if r.is_err() {
            panic!("Failed to successfully validate path");
        }
        if let Err(e) = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await {
            if Error::PathValidation(PathValidationStatus::CertificateRevokedEndEntity) != e {
                panic!("Failed to yield revoked end entity result (failed with other error)");
            }
        } else {
            panic!("Failed to yield revoked end entity result");
        }
    }
}

#[cfg(all(feature = "revocation", feature = "std", feature = "rsa"))]
#[tokio::test]
async fn cached_crl_revoked_remote_async() {
    use certval::environment::pki_environment::PkiEnvironment;
    use certval::path_settings::*;
    use certval::validator::path_validator::*;
    use certval::CrlSourceFolders;
    use certval::*;
    use std::path::PathBuf;

    // Target expires UTCTime 02/08/2022 23:59:59 GMT
    // CA expires UTCTime 31/12/2030 23:59:59 GMT

    let der_encoded_ta = include_bytes!("examples/intel.com/0-ta.der");
    let der_encoded_ca = include_bytes!("examples/intel.com/1.der");
    let der_encoded_ee = include_bytes!("examples/intel.com/2-target.der");

    let ta = PDVTrustAnchorChoice::try_from(der_encoded_ta.as_slice()).unwrap();

    let mut ca = PDVCertificate::try_from(der_encoded_ca.as_slice()).unwrap();
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate::try_from(der_encoded_ee.as_slice()).unwrap();

    let chain = vec![ca];

    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests/examples/intel.com/crls2");
    let crl_source = CrlSourceFolders::new(d.as_path().to_str().unwrap());
    if crl_source
        .index_crls(TimeOfInterest::from_unix_secs(1647011592).unwrap())
        .is_err()
    {
        panic!("Failed to index CRLs")
    }

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();
    pe.add_crl_source(Box::new(crl_source));
    pe.add_revocation_cache(Box::new(RevocationCache::new()));

    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut cert_path = CertificationPath::new(ta, chain, ee);

    let mut cps = CertificationPathSettings::new();
    cps.set_require_ta_store(false);
    cps.set_check_ocsp_from_aia(false);
    let mut cpr = CertificationPathResults::new();

    {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1647011592).unwrap());
        let r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
        if r.is_err() {
            panic!("Failed to successfully validate path");
        }

        if let Err(e) = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await {
            if Error::PathValidation(PathValidationStatus::CertificateRevokedEndEntity) != e {
                panic!("Failed to yield revoked end entity result (failed with other error)");
            }
        } else {
            panic!("Failed to yield revoked end entity result");
        }
    }

    pe.clear_crl_sources();

    let mut cpr = CertificationPathResults::new();

    {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1647011592).unwrap());
        let r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
        if r.is_err() {
            panic!("Failed to successfully validate path");
        }
        if let Err(e) = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await {
            if Error::PathValidation(PathValidationStatus::CertificateRevokedEndEntity) != e {
                panic!("Failed to yield revoked end entity result (failed with other error)");
            }
        } else {
            panic!("Failed to yield revoked end entity result");
        }
    }
}

#[cfg(all(feature = "revocation", feature = "std", feature = "rsa"))]
#[tokio::test]
async fn cached_crl_remote_async() {
    use certval::environment::pki_environment::PkiEnvironment;
    use certval::path_settings::*;
    use certval::validator::path_validator::*;
    use certval::CrlSourceFolders;
    use certval::*;
    use std::path::PathBuf;

    // Target expires UTCTime 02/08/2022 23:59:59 GMT
    // CA expires UTCTime 31/12/2030 23:59:59 GMT

    let der_encoded_ta = include_bytes!("examples/makaan.com/0-ta.der");
    let der_encoded_ca = include_bytes!("examples/makaan.com/1.der");
    let der_encoded_ee = include_bytes!("examples/makaan.com/2-target.der");

    let ta = PDVTrustAnchorChoice::try_from(der_encoded_ta.as_slice()).unwrap();

    let mut ca = PDVCertificate::try_from(der_encoded_ca.as_slice()).unwrap();
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate::try_from(der_encoded_ee.as_slice()).unwrap();

    let chain = vec![ca];

    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("tests/examples/makaan.com/crls2");
    let crl_source = CrlSourceFolders::new(d.as_path().to_str().unwrap());
    if crl_source
        .index_crls(TimeOfInterest::from_unix_secs(1647011592).unwrap())
        .is_err()
    {
        panic!("Failed to index CRLs")
    }

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();
    pe.add_crl_source(Box::new(crl_source));
    pe.add_revocation_cache(Box::new(RevocationCache::new()));

    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut cert_path = CertificationPath::new(ta, chain, ee);

    let mut cps = CertificationPathSettings::new();
    cps.set_require_ta_store(false);
    cps.set_check_ocsp_from_aia(false);
    let mut cpr = CertificationPathResults::new();

    {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1647011592).unwrap());
        let mut r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
        if r.is_err() {
            panic!("Failed to successfully validate path");
        }
        r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await;
        if r.is_err() {
            panic!("Failed to successfully check revocation using cached CRLs");
        }
    }

    pe.clear_crl_sources();

    let mut cpr = CertificationPathResults::new();

    {
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1647011592).unwrap());
        let mut r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
        if r.is_err() {
            panic!("Failed to successfully validate path");
        }
        r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await;
        if r.is_err() {
            panic!("Failed to successfully check revocation using cached CRLs");
        }
    }
}

// Live end-to-end OCSP nonce round-trip against the DoD responder (ocsp.disa.mil), which honors
// nonces. Ignored by default: it needs live network access and an unexpired DoD leaf. The offline
// counterpart (deterministic, always run) is `ocsp_offline_replay_delegated_responder_with_nonce`
// in src/revocation/ocsp_client.rs, which replays a response harvested from this same responder.
// When cert 47 (exp 2026-11-21) or the responder cert rotates, re-harvest examples/ocsp_dod/.
// Run with: cargo test -p certval --features rsa -- --ignored live_ocsp_nonce_disa
#[cfg(all(feature = "remote", feature = "rsa"))]
#[ignore = "requires live network to ocsp.disa.mil and an unexpired DoD leaf (cert 47)"]
#[tokio::test]
async fn live_ocsp_nonce_disa() {
    use certval::*;
    use der::Decode;
    use x509_cert::certificate::{CertificateInner, Raw};

    let _ = pretty_env_logger::try_init();

    let issuer =
        CertificateInner::<Raw>::from_der(include_bytes!("examples/ocsp_dod/ca63.der")).unwrap();
    let mut target =
        PDVCertificate::try_from(include_bytes!("examples/ocsp_dod/47.der").as_slice()).unwrap();
    target.parse_extensions(EXTS_OF_INTEREST);

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();

    let mut cps = CertificationPathSettings::new();
    // Require the responder to echo the nonce we send; DoD's responder honors nonces.
    cps.set_ocsp_aia_nonce_setting(OcspNonceSetting::SendNonceRequireMatch);

    let mut cpr = CertificationPathResults::new();
    cpr.prepare_revocation_results(1).unwrap();

    let r = send_ocsp_request(
        &pe,
        &cps,
        "http://ocsp.disa.mil",
        &target,
        &issuer,
        &mut cpr,
        0,
    )
    .await;
    assert!(
        r.is_ok(),
        "live DoD OCSP with SendNonceRequireMatch should succeed (nonce echoed), got {r:?}"
    );
}

// A trust anchor expressed as a name plus public key with no wrapped certificate (as webpki roots
// are) can serve as the CRL issuer during revocation checking. Before the SubjectNameAndKey trait,
// revocation hard-failed on such an anchor: get_certificate_from_trust_anchor returned None, so
// check_revocation returned Error::Unrecognized before checking anything. This mirrors
// stapled_crl_async but strips the trust anchor to name+SPKI form (same name and key).
#[cfg(all(feature = "revocation", feature = "std", feature = "rsa"))]
#[tokio::test]
async fn stapled_crl_name_and_spki_trust_anchor() {
    use certval::environment::pki_environment::PkiEnvironment;
    use certval::path_settings::*;
    use certval::*;
    use der::asn1::OctetString;
    use der::Decode;
    use x509_cert::anchor::{CertPathControls, TrustAnchorChoice, TrustAnchorInfo};
    use x509_cert::certificate::{Certificate, Raw};

    let der_encoded_ta = include_bytes!("examples/harvard.edu/0-ta.der");
    let der_encoded_ca = include_bytes!("examples/harvard.edu/1.der");
    let der_encoded_ca_crl = include_bytes!("examples/harvard.edu/1-crl.crl");
    let der_encoded_ee = include_bytes!("examples/harvard.edu/2-target.der");
    let der_encoded_ee_crl = include_bytes!("examples/harvard.edu/2-crl.crl");

    // Build a name+SPKI trust anchor from the real root: same name and public key, but no wrapped
    // certificate (cert_path.certificate = None), i.e. the shape a webpki root has.
    let root = Certificate::from_der(der_encoded_ta.as_slice()).unwrap();
    let cp: CertPathControls<Raw> = CertPathControls {
        ta_name: root.tbs_certificate().subject().clone(),
        certificate: None,
        policy_set: None,
        policy_flags: None,
        name_constr: None,
        path_len_constraint: None,
    };
    let tai: TrustAnchorInfo<Raw> = TrustAnchorInfo {
        version: Default::default(),
        pub_key: root.tbs_certificate().subject_public_key_info().clone(),
        key_id: OctetString::new(vec![0u8; 20]).unwrap(),
        ta_title: None,
        cert_path: Some(cp),
        extensions: None,
        ta_title_lang_tag: None,
    };
    let ta = PDVTrustAnchorChoice::try_from(TrustAnchorChoice::TaInfo(tai)).unwrap();
    // The condition that used to break revocation: this anchor has no embedded certificate.
    assert!(get_certificate_from_trust_anchor(&ta.decoded_ta).is_none());

    let mut ca = PDVCertificate::try_from(der_encoded_ca.as_slice()).unwrap();
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate::try_from(der_encoded_ee.as_slice()).unwrap();
    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();

    let mut cert_path = CertificationPath::new(ta, vec![ca], ee);
    // crls[0] (CA's CRL) is signed by the root -> verified using the name+SPKI trust anchor's key.
    cert_path.crls[0] = Some(der_encoded_ca_crl.to_vec());
    cert_path.crls[1] = Some(der_encoded_ee_crl.to_vec());

    let mut cps = CertificationPathSettings::new();
    cps.set_check_revocation_status(true);
    cps.set_check_ocsp_from_aia(false);
    cps.set_require_ta_store(false);
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1646567209).unwrap());

    let mut cpr = CertificationPathResults::new();
    let r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await;
    assert!(
        r.is_ok(),
        "revocation should succeed using stapled CRLs with a name+SPKI trust anchor as CRL issuer, got {r:?}"
    );
}

// Affirm that revocation checking honors the configuration knobs that limit it, and — crucially —
// fails closed (RevocationStatusNotDetermined) whenever a required status cannot be determined. All
// cases are deterministic: OCSP-from-AIA and CRL-DP HTTP fetching are pinned off, so no network is
// used and revocation status comes only from stapled CRLs (or nothing).
#[cfg(all(feature = "std", feature = "rsa"))]
mod revocation_config {
    use certval::*;

    const TA: &[u8] = include_bytes!("examples/harvard.edu/0-ta.der");
    const CA: &[u8] = include_bytes!("examples/harvard.edu/1.der");
    const CA_CRL: &[u8] = include_bytes!("examples/harvard.edu/1-crl.crl");
    const EE: &[u8] = include_bytes!("examples/harvard.edu/2-target.der");
    const EE_CRL: &[u8] = include_bytes!("examples/harvard.edu/2-crl.crl");
    // A time within the harvard.edu chain's validity window (the target expires Feb 2022).
    const TOI: u64 = 1646567209;

    fn make_pe() -> PkiEnvironment {
        let mut pe = PkiEnvironment::new();
        pe.populate_5280_pki_environment();
        pe
    }

    fn make_path() -> CertificationPath {
        let ta = PDVTrustAnchorChoice::try_from(TA).unwrap();
        let mut ca = PDVCertificate::try_from(CA).unwrap();
        ca.parse_extensions(EXTS_OF_INTEREST);
        let mut ee = PDVCertificate::try_from(EE).unwrap();
        ee.parse_extensions(EXTS_OF_INTEREST);
        CertificationPath::new(ta, vec![ca], ee)
    }

    fn base_cps() -> CertificationPathSettings {
        let mut cps = CertificationPathSettings::new();
        cps.set_require_ta_store(false);
        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(TOI).unwrap());
        // Deterministic: no network-driven revocation sources.
        cps.set_check_ocsp_from_aia(false);
        cps.set_check_crldp_http(false);
        cps
    }

    async fn run(
        cps: &CertificationPathSettings,
        staple: impl Fn(&mut CertificationPath),
    ) -> Result<()> {
        let pe = make_pe();
        let mut path = make_path();
        staple(&mut path);
        let mut cpr = CertificationPathResults::new();
        check_revocation(&pe, cps, &mut path, &mut cpr).await
    }

    fn staple_both(p: &mut CertificationPath) {
        p.crls[0] = Some(CA_CRL.to_vec());
        p.crls[1] = Some(EE_CRL.to_vec());
    }
    fn staple_ca_only(p: &mut CertificationPath) {
        p.crls[0] = Some(CA_CRL.to_vec());
    }
    fn staple_none(_p: &mut CertificationPath) {}

    fn is_not_determined(r: &Result<()>) -> bool {
        matches!(
            r,
            Err(Error::PathValidation(
                PathValidationStatus::RevocationStatusNotDetermined
            ))
        )
    }

    // Stapled CRLs cover every certificate -> status is determined -> Ok.
    #[tokio::test]
    async fn stapled_crls_determine_status() {
        let r = run(&base_cps(), staple_both).await;
        assert!(r.is_ok(), "stapled CRLs should determine status, got {r:?}");
    }

    // Revocation enabled with no source of any kind must fail closed.
    #[tokio::test]
    async fn no_revocation_info_fails_closed() {
        let r = run(&base_cps(), staple_none).await;
        assert!(is_not_determined(&r), "expected fail-closed, got {r:?}");
    }

    // The single top-level opt-out returns Ok without determining status.
    #[tokio::test]
    async fn revocation_disabled_returns_ok() {
        let mut cps = base_cps();
        cps.set_check_revocation_status(false);
        assert!(run(&cps, staple_none).await.is_ok());
    }

    // Disabling the CRL source type must NOT open the gate: with no other source, still fail closed.
    #[tokio::test]
    async fn check_crls_off_without_source_fails_closed() {
        let mut cps = base_cps();
        cps.set_check_crls(false);
        let r = run(&cps, staple_none).await;
        assert!(is_not_determined(&r), "expected fail-closed, got {r:?}");
    }

    // Stapled rev info is consumed before the check_crls gate, so it still determines status even
    // when check_crls is off.
    #[tokio::test]
    async fn stapled_crls_honored_even_with_check_crls_off() {
        let mut cps = base_cps();
        cps.set_check_crls(false);
        let r = run(&cps, staple_both).await;
        assert!(r.is_ok(), "stapled CRLs should be honored, got {r:?}");
    }

    // Determining some but not all certificates still fails closed.
    #[tokio::test]
    async fn partial_coverage_fails_closed() {
        let r = run(&base_cps(), staple_ca_only).await;
        assert!(is_not_determined(&r), "expected fail-closed, got {r:?}");
    }
}

// Stapled OCSP over a DigiCert-issued *.peg.a2z.com chain. Both responses are CA-signed: the
// responder id is the issuing key's SHA-1 and no responder certificate is embedded, so certval
// verifies each response against the issuer already present in the path. The time of interest is
// pinned inside the responses' early-March-2022 validity window (and the leaf's validity), keeping
// the check deterministic and offline.
#[cfg(all(feature = "revocation", feature = "std", feature = "rsa"))]
#[tokio::test]
async fn stapled_ocsp_async() {
    use certval::*;

    let der_encoded_ta = include_bytes!("examples/amazon.com/0-ta.der");
    let der_encoded_ca = include_bytes!("examples/amazon.com/1.der");
    let der_encoded_ca_ocsp = include_bytes!("examples/amazon.com/1-ocsp.ocspResp");
    let der_encoded_ee = include_bytes!("examples/amazon.com/2-target.der");
    let der_encoded_ee_ocsp = include_bytes!("examples/amazon.com/2-ocsp.ocspResp");

    let ta = PDVTrustAnchorChoice::try_from(der_encoded_ta.as_slice()).unwrap();
    let mut ca = PDVCertificate::try_from(der_encoded_ca.as_slice()).unwrap();
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate::try_from(der_encoded_ee.as_slice()).unwrap();
    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();

    let mut cert_path = CertificationPath::new(ta, vec![ca], ee);
    cert_path.ocsp_responses[0] = Some(der_encoded_ca_ocsp.to_vec());
    cert_path.ocsp_responses[1] = Some(der_encoded_ee_ocsp.to_vec());

    let mut cps = CertificationPathSettings::new();
    cps.set_require_ta_store(false);
    cps.set_check_crldp_http(false);
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1646567209).unwrap());
    let mut cpr = CertificationPathResults::new();

    let r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await;
    assert!(
        r.is_ok(),
        "revocation should succeed using stapled CA-signed OCSP responses, got {r:?}"
    );
}

// The no_std variant of `stapled_ocsp_async`, exercising the synchronous `check_revocation`.
#[cfg(all(feature = "revocation", not(feature = "std"), feature = "rsa"))]
#[test]
fn stapled_ocsp() {
    use certval::*;

    let der_encoded_ta = include_bytes!("examples/amazon.com/0-ta.der");
    let der_encoded_ca = include_bytes!("examples/amazon.com/1.der");
    let der_encoded_ca_ocsp = include_bytes!("examples/amazon.com/1-ocsp.ocspResp");
    let der_encoded_ee = include_bytes!("examples/amazon.com/2-target.der");
    let der_encoded_ee_ocsp = include_bytes!("examples/amazon.com/2-ocsp.ocspResp");

    let ta = PDVTrustAnchorChoice::try_from(der_encoded_ta.as_slice()).unwrap();
    let mut ca = PDVCertificate::try_from(der_encoded_ca.as_slice()).unwrap();
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate::try_from(der_encoded_ee.as_slice()).unwrap();
    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();

    let mut cert_path = CertificationPath::new(ta, vec![ca], ee);
    cert_path.ocsp_responses[0] = Some(der_encoded_ca_ocsp.to_vec());
    cert_path.ocsp_responses[1] = Some(der_encoded_ee_ocsp.to_vec());

    let mut cps = CertificationPathSettings::new();
    cps.set_require_ta_store(false);
    cps.set_check_crldp_http(false);
    cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1646567209).unwrap());
    let mut cpr = CertificationPathResults::new();

    let r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr);
    assert!(
        r.is_ok(),
        "revocation should succeed using stapled CA-signed OCSP responses, got {r:?}"
    );
}
