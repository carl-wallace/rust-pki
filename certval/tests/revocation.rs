#![cfg(feature = "revocation")]

//todo fix or replace
// #[cfg(not(feature = "std"))]
// #[test]
// fn stapled_ocsp() {
//     use certval::environment::pki_environment::PkiEnvironment;
//     use certval::path_settings::*;
//     use certval::validator::path_validator::*;
//     use certval::*;
//     use der::Decode;
//     use x509_cert::anchor::TrustAnchorChoice;
//     use x509_cert::*;
//
//     let der_encoded_ta = include_bytes!("examples/amazon.com/0-ta.der");
//     let der_encoded_ca = include_bytes!("examples/amazon.com/1.der");
//     let der_encoded_ca_ocsp = include_bytes!("examples/amazon.com/1-ocsp.ocspResp");
//     let der_encoded_ee = include_bytes!("examples/amazon.com/2-target.der");
//     let der_encoded_ee_ocsp = include_bytes!("examples/amazon.com/2-ocsp.ocspResp");
//
//     let tac = TrustAnchorChoice::from_der(der_encoded_ta).unwrap();
//     let ta = PDVTrustAnchorChoice {
//         encoded_ta: der_encoded_ta,
//         decoded_ta: tac,
//         metadata: None,
//         parsed_extensions: ParsedExtensions::new(),
//     };
//
//     let ca_cert = Certificate::from_der(der_encoded_ca).unwrap();
//     let ee_cert = Certificate::from_der(der_encoded_ee).unwrap();
//
//     let mut ca = PDVCertificate {
//         encoded_cert: der_encoded_ca,
//         decoded_cert: ca_cert,
//         metadata: None,
//         parsed_extensions: ParsedExtensions::new(),
//     };
//     ca.parse_extensions(EXTS_OF_INTEREST);
//     let mut ee = PDVCertificate {
//         encoded_cert: der_encoded_ee,
//         decoded_cert: ee_cert,
//         metadata: None,
//         parsed_extensions: ParsedExtensions::new(),
//     };
//
//     let chain = vec![ca];
//
//     let mut pe = PkiEnvironment::new();
//     populate_5280_pki_environment(&mut pe);
//     let mut pe2 = PkiEnvironment::new();
//     pe2.add_validate_path_callback(validate_path_rfc5280);
//
//     ee.parse_extensions(EXTS_OF_INTEREST);
//
//     let mut cert_path = CertificationPath::new(ta, chain, ee);
//
//     cert_path.ocsp_responses[0] = Some(der_encoded_ca_ocsp.to_vec());
//     cert_path.ocsp_responses[1] = Some(der_encoded_ee_ocsp.to_vec());
//
//     let mut cps = CertificationPathSettings::new();
//     set_require_ta_store(&mut cps, false);
//
//     let mut cpr = CertificationPathResults::new();
//
//     {
//         set_time_of_interest(&mut cps, 1646482828);
//         let r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
//         if r.is_err() {
//             panic!("Failed to successfully validate path");
//         }
//         #[cfg(feature = "revocation")]
//         {
//             let r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr);
//             if r.is_err() {
//                 panic!("Failed to successfully check revocation using stapled OCSP responses");
//             }
//         }
//     }
//     {
//         set_time_of_interest(&mut cps, 1647030025);
//         let r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
//         if r.is_err() {
//             panic!("Failed to successfully validate path");
//         }
//         #[cfg(feature = "revocation")]
//         {
//             let r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr);
//             if r.is_ok() {
//                 panic!("Failed to reject stale stapled OCSP responses");
//             }
//         }
//     }
// }

//todo fix or replace
// #[cfg(all(feature = "revocation", feature = "std"))]
// #[tokio::test]
// async fn stapled_ocsp_async() {
//     use certval::environment::pki_environment::PkiEnvironment;
//     use certval::path_settings::*;
//     use certval::validator::path_validator::*;
//     use certval::*;
//     use der::Decode;
//     use x509_cert::anchor::TrustAnchorChoice;
//     use x509_cert::*;
//
//     // Target expires UTCTime 19/09/2022 23:59:59 GMT
//     // CA expires UTCTime 01/08/2028 12:00:00 GMT
//
//     let der_encoded_ta = include_bytes!("examples/amazon.com/0-ta.der");
//     let der_encoded_ca = include_bytes!("examples/amazon.com/1.der");
//     let der_encoded_ca_ocsp = include_bytes!("examples/amazon.com/1-ocsp.ocspResp");
//     let der_encoded_ee = include_bytes!("examples/amazon.com/2-target.der");
//     let der_encoded_ee_ocsp = include_bytes!("examples/amazon.com/2-ocsp.ocspResp");
//
//     let tac = TrustAnchorChoice::from_der(der_encoded_ta).unwrap();
//     let ta = PDVTrustAnchorChoice {
//         encoded_ta: der_encoded_ta,
//         decoded_ta: tac,
//         metadata: None,
//         parsed_extensions: ParsedExtensions::new(),
//     };
//
//     let ca_cert = Certificate::from_der(der_encoded_ca).unwrap();
//     let ee_cert = Certificate::from_der(der_encoded_ee).unwrap();
//
//     let mut ca = PDVCertificate {
//         encoded_cert: der_encoded_ca,
//         decoded_cert: ca_cert,
//         metadata: None,
//         parsed_extensions: ParsedExtensions::new(),
//     };
//     ca.parse_extensions(EXTS_OF_INTEREST);
//     let mut ee = PDVCertificate {
//         encoded_cert: der_encoded_ee,
//         decoded_cert: ee_cert,
//         metadata: None,
//         parsed_extensions: ParsedExtensions::new(),
//     };
//
//     let chain = vec![ca];
//
//     let mut pe = PkiEnvironment::new();
//     populate_5280_pki_environment(&mut pe);
//     let mut pe2 = PkiEnvironment::new();
//     pe2.add_validate_path_callback(validate_path_rfc5280);
//
//     ee.parse_extensions(EXTS_OF_INTEREST);
//
//     let mut cert_path = CertificationPath::new(ta, chain, ee);
//
//     cert_path.ocsp_responses[0] = Some(der_encoded_ca_ocsp.to_vec());
//     cert_path.ocsp_responses[1] = Some(der_encoded_ee_ocsp.to_vec());
//
//     let mut cps = CertificationPathSettings::new();
//     set_require_ta_store(&mut cps, false);
//
//     let mut cpr = CertificationPathResults::new();
//
//     {
//         set_time_of_interest(&mut cps, 1646482828);
//         let mut r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
//         if r.is_err() {
//             panic!("Failed to successfully validate path");
//         }
//         r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await;
//         if r.is_err() {
//             panic!("Failed to successfully check revocation using stapled OCSP responses");
//         }
//     }
//     #[cfg(feature = "remote")]
//     {
//         use std::time::{SystemTime, UNIX_EPOCH};
//         let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
//         set_time_of_interest(&mut cps, before.as_secs());
//         let mut r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
//         if r.is_err() {
//             panic!("Failed to successfully validate path");
//         }
//         r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await;
//         if r.is_err() {
//             panic!("Failed to successfully check revocation after failing over from stapled OCSP responses to dynamic");
//         }
//     }
//     #[cfg(not(feature = "remote"))]
//     {
//         set_time_of_interest(&mut cps, 1647030025);
//         let r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
//         if r.is_err() {
//             panic!("Failed to successfully validate path");
//         }
//         #[cfg(feature = "revocation")]
//         {
//             let r = check_revocation(&pe, &cps, &mut cert_path, &mut cpr).await;
//             if r.is_ok() {
//                 panic!("Failed to reject stale stapled OCSP responses");
//             }
//         }
//     }
// }

#[cfg(all(feature = "revocation", feature = "std"))]
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
    populate_5280_pki_environment(&mut pe);
    let mut pe2 = PkiEnvironment::new();
    pe2.add_validate_path_callback(validate_path_rfc5280);

    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut cert_path = CertificationPath::new(ta, chain, ee);

    cert_path.crls[0] = Some(der_encoded_ca_crl.to_vec());
    cert_path.crls[1] = Some(der_encoded_ee_crl.to_vec());

    let mut cps = CertificationPathSettings::new();
    set_check_ocsp_from_aia(&mut cps, false);
    set_require_ta_store(&mut cps, false);
    let mut cpr = CertificationPathResults::new();

    {
        set_time_of_interest(&mut cps, 1646567209);
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
        set_time_of_interest(&mut cps, 1646567209);
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
        set_time_of_interest(&mut cps, 1649245609);
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

#[cfg(all(feature = "revocation", feature = "std"))]
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
    populate_5280_pki_environment(&mut pe);
    let mut pe2 = PkiEnvironment::new();
    pe2.add_validate_path_callback(validate_path_rfc5280);

    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut cert_path = CertificationPath::new(ta, chain, ee);

    cert_path.ocsp_responses[0] = Some(der_encoded_ca_ocsp.to_vec());
    cert_path.crls[1] = Some(der_encoded_ee_crl.to_vec());

    let mut cps = CertificationPathSettings::new();
    set_require_ta_store(&mut cps, false);

    set_check_ocsp_from_aia(&mut cps, false);
    set_check_crldp_http(&mut cps, false);
    let mut cpr = CertificationPathResults::new();

    {
        set_time_of_interest(&mut cps, 1646567209);
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
        set_time_of_interest(&mut cps, 1646567209);
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
        set_time_of_interest(&mut cps, 1649245609);
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

#[cfg(all(feature = "revocation", feature = "std"))]
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
    if crl_source.index_crls(1647011592).is_err() {
        panic!("Failed to index CRLs")
    }

    let v = crl_source.get_crls(&ee).unwrap();
    assert_eq!(1, v.len());

    let mut pe = PkiEnvironment::new();
    populate_5280_pki_environment(&mut pe);
    pe.add_crl_source(&crl_source);
    pe.add_revocation_cache(&crl_source);

    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut cert_path = CertificationPath::new(ta, chain, ee);

    let mut cps = CertificationPathSettings::new();
    set_require_ta_store(&mut cps, false);
    set_check_ocsp_from_aia(&mut cps, false);
    set_check_crldp_http(&mut cps, false);
    let mut cpr = CertificationPathResults::new();

    {
        set_time_of_interest(&mut cps, 1647011592);
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
        set_time_of_interest(&mut cps, 1647011592);
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

#[cfg(all(feature = "revocation", feature = "std"))]
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
    if crl_source.index_crls(1647011592).is_err() {
        panic!("Failed to index CRLs")
    }

    let mut pe = PkiEnvironment::new();
    populate_5280_pki_environment(&mut pe);
    pe.add_crl_source(&crl_source);
    pe.add_revocation_cache(&crl_source);

    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut cert_path = CertificationPath::new(ta, chain, ee);

    let mut cps = CertificationPathSettings::new();
    set_require_ta_store(&mut cps, false);
    set_check_ocsp_from_aia(&mut cps, false);
    set_check_crldp_http(&mut cps, false);
    let mut cpr = CertificationPathResults::new();

    {
        set_time_of_interest(&mut cps, 1647011592);
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
        set_time_of_interest(&mut cps, 1647011592);
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

#[cfg(all(feature = "revocation", feature = "std"))]
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
    if crl_source.index_crls(1647011592).is_err() {
        panic!("Failed to index CRLs")
    }

    let mut pe = PkiEnvironment::new();
    populate_5280_pki_environment(&mut pe);
    pe.add_crl_source(&crl_source);
    pe.add_revocation_cache(&crl_source);

    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut cert_path = CertificationPath::new(ta, chain, ee);

    let mut cps = CertificationPathSettings::new();
    set_require_ta_store(&mut cps, false);
    set_check_ocsp_from_aia(&mut cps, false);
    let mut cpr = CertificationPathResults::new();

    {
        set_time_of_interest(&mut cps, 1647011592);
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
        set_time_of_interest(&mut cps, 1647011592);
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

#[cfg(all(feature = "revocation", feature = "std"))]
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
    if crl_source.index_crls(1647011592).is_err() {
        panic!("Failed to index CRLs")
    }

    let mut pe = PkiEnvironment::new();
    populate_5280_pki_environment(&mut pe);
    pe.add_crl_source(&crl_source);
    pe.add_revocation_cache(&crl_source);

    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut cert_path = CertificationPath::new(ta, chain, ee);

    let mut cps = CertificationPathSettings::new();
    set_require_ta_store(&mut cps, false);
    set_check_ocsp_from_aia(&mut cps, false);
    let mut cpr = CertificationPathResults::new();

    {
        set_time_of_interest(&mut cps, 1647011592);
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
        set_time_of_interest(&mut cps, 1647011592);
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
