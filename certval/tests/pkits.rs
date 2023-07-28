//! Contains top-level code to run PKITS test cases

// Not all PKITS test cases are run in all scenarios. The following describes where and why test
// cases are omitted and.
//
// In all scenarios, the following tests are not run due to lack of support for the features exercised
// by the artifacts in the test case.
//  - 4.1.4 through 4.1.6 are not exercised because DSA is not supported
//  - 4.2.3 is not exercised because the ASN.1 decoder does not support value in the validity period
//  - Revocation checking is not performed for 4.4.19, 4.5.x, 4.6.15, 4.6.17, 4.9.6,
// 4.11.7, 4.12.7, 4.12.9 and 4.13.19 owing to lack of support for key rollover certificates or separate
// CA and CRL signing keys.
//  - 4.14.14 and 4.14.15 are not exerised because the ASN.1 decoder does not support negative serial numbers
//  - 4.13.29 is not supported due to lack of support for reading email addresses from subject DN.
//  - 4.14.4, 4.14.5, 4.14.7 and 4.14.11 through 4.14.35 are not exercised owning to lack of support
// for indirect CRLs and use of only some reasons.
//  - Section 4.15 is not run owing to lack of support for delta CRLs.
//
// For std, revocation,std and remote feature gates, PKITS 2048 is run in full (delta unsupported
// features described above)
//
// Where std is not available, the following test are not run:
//  - 4.3.3 and 4.3.11 are not exercised owing to lack of regex support or alternative at present
//  - 4.13.21, 4.13.23, 4.13.25, 4.13.27, 4.13.30, 4.13.32, 4.13.34, 4.13.36, 4.3.3, 4.3.11 are run
// but do not yield expected result owing to lack of support for DNS name constraints, URI name constraints
// and RFC822 name constraints when std is not available (due to lack of regex and url parsing support
// at present).
//
// Where revocation is not available and for p256, the following test are not run:
//  - 4.4.x, 4.14.2, 4.14.3, 4.14.6, 4.14.8 and 4.14.9 are not run owing to lack of revocation
// support (or in case of p256, lack of CRLs with designated names)
//  - 4.7.4 and 4.7.5 are not run owing to focus on CRL issuer certificate (and revocation not being performed).

use certval::source::cert_source::CertFile;
use certval::PDVCertificate;
use certval::*;

use alloc::collections::BTreeMap;

extern crate alloc;

use certval::source::ta_source::TaSource;

mod pkits_data;
use crate::pkits_data::*;

mod pkits_utils;
use crate::pkits_utils::*;

extern crate lazy_static;

#[derive(Clone)]
pub struct CertPool {
    pub certs: BTreeMap<String, Vec<u8>>,
}

// Only 2048 and 256 are supported in test so far owing to lack of 384 support in Rust and lack
// of suitable 4096 PKITS data set.
pub enum PkitsFlavor {
    PkitsRsa2048,
    // PkitsRsa4096,
    PkitsP256,
    // PkitsP384,
}

#[cfg(not(feature = "std"))]
#[test]
fn pkits_p256() {
    let mut pool = CertPool {
        certs: BTreeMap::new(),
    };

    let mut pkits_data_map = PkitsDataMap::new();
    load_pkits(&mut pkits_data_map);
    let mut ta_source2 = TaSource::new();
    {
        // all tests share common trust anchor so add it to the pool
        let der_encoded_ta = get_pkits_cert_bytes_p256("TrustAnchorRootCertificate.crt");
        if let Ok(der_encoded_ta) = der_encoded_ta {
            ta_source2.push(CertFile {
                filename: "TrustAnchorRootCertificate.crt".to_string(),
                bytes: der_encoded_ta,
            });
        }
    }

    ta_source2.initialize().unwrap();

    let mut pe = PkiEnvironment::new();
    populate_5280_pki_environment(&mut pe);
    pe.add_trust_anchor_source(Box::new(ta_source2.clone()));
    pkits_guts_sync(
        &mut pool,
        &pkits_data_map,
        &pe,
        PkitsFlavor::PkitsP256,
        true,
        false,
    );
}

#[cfg(feature = "std")]
#[tokio::test]
async fn pkits_p256() {
    let mut pool = CertPool {
        certs: BTreeMap::new(),
    };

    let mut pkits_data_map = PkitsDataMap::new();
    load_pkits(&mut pkits_data_map);
    let mut ta_source2 = TaSource::new();
    {
        // all tests share common trust anchor so add it to the pool
        let der_encoded_ta = get_pkits_cert_bytes_p256("TrustAnchorRootCertificate.crt");
        if let Ok(der_encoded_ta) = der_encoded_ta {
            ta_source2.push(CertFile {
                filename: "TrustAnchorRootCertificate.crt".to_string(),
                bytes: der_encoded_ta,
            });
        }
    }

    ta_source2.initialize().unwrap();

    let mut pe = PkiEnvironment::new();
    populate_5280_pki_environment(&mut pe);
    pe.add_trust_anchor_source(Box::new(ta_source2.clone()));
    pkits_guts(
        &mut pool,
        &pkits_data_map,
        &pe,
        PkitsFlavor::PkitsP256,
        true,
        false,
    )
    .await;
}

#[cfg(feature = "std")]
#[tokio::test]
async fn pkits_2048() {
    let mut pool = CertPool {
        certs: BTreeMap::new(),
    };
    let mut pkits_data_map = PkitsDataMap::new();
    load_pkits(&mut pkits_data_map);
    let mut ta_source2 = TaSource::new();
    {
        // all tests share common trust anchor so add it to the pool
        let der_encoded_ta = get_pkits_cert_bytes("TrustAnchorRootCertificate.crt");
        if let Ok(der_encoded_ta) = der_encoded_ta {
            ta_source2.push(CertFile {
                filename: "TrustAnchorRootCertificate.crt".to_string(),
                bytes: der_encoded_ta,
            });
        }
    }

    ta_source2.initialize().unwrap();

    #[cfg(feature = "revocation")]
    {
        let mut pe = PkiEnvironment::new();
        populate_5280_pki_environment(&mut pe);
        pe.add_trust_anchor_source(Box::new(ta_source2.clone()));
        pkits_guts(
            &mut pool,
            &pkits_data_map,
            &pe,
            PkitsFlavor::PkitsRsa2048,
            false,
            false,
        )
        .await;
        pe.clear_all_callbacks();
    }
    #[cfg(not(feature = "revocation"))]
    {
        let mut pe = PkiEnvironment::new();
        populate_5280_pki_environment(&mut pe);
        pe.add_trust_anchor_source(Box::new(ta_source2.clone()));
        pkits_guts(
            &mut pool,
            &pkits_data_map,
            &pe,
            PkitsFlavor::PkitsRsa2048,
            true,
            false,
        )
        .await;
        pe.clear_all_callbacks();
    }
}

#[cfg(not(feature = "std"))]
#[test]
fn pkits_2048() {
    let mut pool = CertPool {
        certs: BTreeMap::new(),
    };
    let mut pkits_data_map = PkitsDataMap::new();
    load_pkits(&mut pkits_data_map);
    let mut ta_source2 = TaSource::new();
    {
        // all tests share common trust anchor so add it to the pool
        let der_encoded_ta = get_pkits_cert_bytes("TrustAnchorRootCertificate.crt");
        if let Ok(der_encoded_ta) = der_encoded_ta {
            ta_source2.push(CertFile {
                filename: "TrustAnchorRootCertificate.crt".to_string(),
                bytes: der_encoded_ta,
            });
        }
    }

    ta_source2.initialize().unwrap();

    #[cfg(feature = "revocation")]
    {
        let mut pe = PkiEnvironment::new();
        populate_5280_pki_environment(&mut pe);
        pe.add_trust_anchor_source(Box::new(ta_source2.clone()));
        pkits_guts_sync(
            &mut pool,
            &pkits_data_map,
            &pe,
            PkitsFlavor::PkitsRsa2048,
            false,
            false,
        );
    }
    #[cfg(not(feature = "revocation"))]
    {
        let mut pe = PkiEnvironment::new();
        populate_5280_pki_environment(&mut pe);
        pe.add_trust_anchor_source(Box::new(ta_source2.clone()));
        pkits_guts_sync(
            &mut pool,
            &pkits_data_map,
            &pe,
            PkitsFlavor::PkitsRsa2048,
            true,
            false,
        );
    }
}

#[cfg(not(feature = "std"))]
#[test]
fn pkits_p256_graph() {
    let mut pool = CertPool {
        certs: BTreeMap::new(),
    };

    let mut pkits_data_map = PkitsDataMap::new();
    load_pkits(&mut pkits_data_map);
    let mut ta_source2 = TaSource::new();
    {
        // all tests share common trust anchor so add it to the pool
        let der_encoded_ta = get_pkits_cert_bytes_p256("TrustAnchorRootCertificate.crt");
        if let Ok(der_encoded_ta) = der_encoded_ta {
            ta_source2.push(CertFile {
                filename: "TrustAnchorRootCertificate.crt".to_string(),
                bytes: der_encoded_ta,
            });
        }
    }

    ta_source2.initialize().unwrap();

    let mut pe = PkiEnvironment::new();
    populate_5280_pki_environment(&mut pe);
    pe.add_trust_anchor_source(Box::new(ta_source2.clone()));
    pkits_guts_sync(
        &mut pool,
        &pkits_data_map,
        &pe,
        PkitsFlavor::PkitsP256,
        true,
        true,
    );
}

#[cfg(feature = "std")]
#[tokio::test]
async fn pkits_p256_graph() {
    let mut pool = CertPool {
        certs: BTreeMap::new(),
    };

    let mut pkits_data_map = PkitsDataMap::new();
    load_pkits(&mut pkits_data_map);
    let mut ta_source2 = TaSource::new();
    {
        // all tests share common trust anchor so add it to the pool
        let der_encoded_ta = get_pkits_cert_bytes_p256("TrustAnchorRootCertificate.crt");
        if let Ok(der_encoded_ta) = der_encoded_ta {
            ta_source2.push(CertFile {
                filename: "TrustAnchorRootCertificate.crt".to_string(),
                bytes: der_encoded_ta,
            });
        }
    }

    ta_source2.initialize().unwrap();

    let mut pe = PkiEnvironment::new();
    populate_5280_pki_environment(&mut pe);
    pe.add_trust_anchor_source(Box::new(ta_source2.clone()));
    pkits_guts(
        &mut pool,
        &pkits_data_map,
        &pe,
        PkitsFlavor::PkitsP256,
        true,
        true,
    )
    .await;
}

#[cfg(feature = "std")]
#[tokio::test]
async fn pkits_2048_graph() {
    let mut pool = CertPool {
        certs: BTreeMap::new(),
    };
    let mut pkits_data_map = PkitsDataMap::new();
    load_pkits(&mut pkits_data_map);
    let mut ta_source2 = TaSource::new();
    {
        // all tests share common trust anchor so add it to the pool
        let der_encoded_ta = get_pkits_cert_bytes("TrustAnchorRootCertificate.crt");
        if let Ok(der_encoded_ta) = der_encoded_ta {
            ta_source2.push(CertFile {
                filename: "TrustAnchorRootCertificate.crt".to_string(),
                bytes: der_encoded_ta,
            });
        }
    }

    ta_source2.initialize().unwrap();

    #[cfg(feature = "revocation")]
    {
        let mut pe = PkiEnvironment::new();
        populate_5280_pki_environment(&mut pe);
        pe.add_trust_anchor_source(Box::new(ta_source2.clone()));
        pkits_guts(
            &mut pool,
            &pkits_data_map,
            &pe,
            PkitsFlavor::PkitsRsa2048,
            false,
            true,
        )
        .await;
        pe.clear_all_callbacks();
    }
    #[cfg(not(feature = "revocation"))]
    {
        let mut pe = PkiEnvironment::new();
        populate_5280_pki_environment(&mut pe);
        pe.add_trust_anchor_source(Box::new(ta_source2.clone()));
        pkits_guts(
            &mut pool,
            &pkits_data_map,
            &pe,
            PkitsFlavor::PkitsRsa2048,
            true,
            true,
        )
        .await;
        pe.clear_all_callbacks();
    }
}

#[cfg(not(feature = "std"))]
#[test]
fn pkits_2048_graph() {
    let mut pool = CertPool {
        certs: BTreeMap::new(),
    };
    let mut pkits_data_map = PkitsDataMap::new();
    load_pkits(&mut pkits_data_map);
    let mut ta_source2 = TaSource::new();
    {
        // all tests share common trust anchor so add it to the pool
        let der_encoded_ta = get_pkits_cert_bytes("TrustAnchorRootCertificate.crt");
        if let Ok(der_encoded_ta) = der_encoded_ta {
            ta_source2.push(CertFile {
                filename: "TrustAnchorRootCertificate.crt".to_string(),
                bytes: der_encoded_ta,
            });
        }
    }

    ta_source2.initialize().unwrap();

    #[cfg(feature = "revocation")]
    {
        let mut pe = PkiEnvironment::new();
        populate_5280_pki_environment(&mut pe);
        pe.add_trust_anchor_source(Box::new(ta_source2.clone()));
        pkits_guts_sync(
            &mut pool,
            &pkits_data_map,
            &pe,
            PkitsFlavor::PkitsRsa2048,
            false,
            true,
        );
    }
    #[cfg(not(feature = "revocation"))]
    {
        let mut pe = PkiEnvironment::new();
        populate_5280_pki_environment(&mut pe);
        pe.add_trust_anchor_source(Box::new(ta_source2.clone()));
        pkits_guts_sync(
            &mut pool,
            &pkits_data_map,
            &pe,
            PkitsFlavor::PkitsRsa2048,
            true,
            true,
        );
    }
}

#[cfg(not(feature = "std"))]
pub fn pkits_guts_sync(
    mpool: &mut CertPool,
    pkits_data_map: &PkitsDataMap,
    pe: &PkiEnvironment,
    flavor: PkitsFlavor,
    skip_revocation: bool,
    policy_graph: bool,
) {
    // all tests share common trust anchor so add it to the pool
    let der_encoded_ta = match flavor {
        PkitsFlavor::PkitsRsa2048 => {
            { get_pkits_cert_bytes("TrustAnchorRootCertificate.crt") }.unwrap()
        }
        // PkitsFlavor::PkitsRsa4096 => {
        //     { get_pkits_cert_bytes_4096("TrustAnchorRootCertificate.crt") }.unwrap()
        // }
        PkitsFlavor::PkitsP256 => {
            { get_pkits_cert_bytes_p256("TrustAnchorRootCertificate.crt") }.unwrap()
        } // PkitsFlavor::PkitsP384 => {
          //     { get_pkits_cert_bytes_p384("TrustAnchorRootCertificate.crt") }.unwrap()
          // }
    };

    if !mpool.certs.contains_key("TrustAnchorRootCertificate.crt") {
        mpool
            .certs
            .insert("TrustAnchorRootCertificate.crt".to_string(), der_encoded_ta);
    }

    let mut verified_ta_as_target = false;

    // iterate over settings map to populate mpool
    for k in pkits_data_map.keys() {
        let pd = pkits_data_map.get(k).unwrap();

        for i in 0..pd.len() {
            let case = pd.get(i).unwrap();

            // load certs for this case into the pool
            let der_encoded_ee = match flavor {
                PkitsFlavor::PkitsRsa2048 => {
                    { get_pkits_cert_bytes(case.target_file_name) }.unwrap()
                }
                // PkitsFlavor::PkitsRsa4096 => {
                //     { get_pkits_cert_bytes_4096(case.target_file_name) }.unwrap()
                // }
                PkitsFlavor::PkitsP256 => {
                    { get_pkits_cert_bytes_p256(case.target_file_name) }.unwrap()
                } // PkitsFlavor::PkitsP384 => {
                  //     { get_pkits_cert_bytes_p384(case.target_file_name) }.unwrap()
                  // }
            };
            mpool
                .certs
                .insert(case.target_file_name.to_string(), der_encoded_ee);
            for ca_file in &case.intermediate_ca_file_names {
                let der_encoded_ca = match flavor {
                    PkitsFlavor::PkitsRsa2048 => { get_pkits_ca_cert_bytes(ca_file) }.unwrap(),
                    // PkitsFlavor::PkitsRsa4096 => { get_pkits_ca_cert_bytes_4096(ca_file) }.unwrap(),
                    PkitsFlavor::PkitsP256 => { get_pkits_ca_cert_bytes_p256(ca_file) }.unwrap(),
                    // PkitsFlavor::PkitsP384 => { get_pkits_ca_cert_bytes_p384(ca_file) }.unwrap(),
                };

                mpool.certs.insert(ca_file.to_string(), der_encoded_ca);
            }
        }
    }

    let pool: &CertPool = &*mpool;

    // iterate over settings map
    for k in pkits_data_map.keys() {
        let pd = pkits_data_map.get(k).unwrap();

        for i in 0..pd.len() {
            let case = pd.get(i).unwrap();

            let case_name = if let Some(alt_test_name) = case.alt_test_name {
                alt_test_name.to_string()
            } else {
                format!("{}.{}", *k, i + 1)
            };

            if skip_revocation
                && (case_name.starts_with("4.4.")
                    || [
                        "4.14.2", "4.14.3", "4.14.6", "4.14.8", "4.14.9", "4.7.4", "4.7.5",
                    ]
                    .contains(&case_name.as_str()))
            {
                // where skip_revocation is true (i.e., for EC) then continue
                continue;
            }

            println!("{}", case_name);
            let mut ta = PDVTrustAnchorChoice::try_from(
                pool.certs["TrustAnchorRootCertificate.crt"].as_slice(),
            )
            .unwrap();
            ta.parse_extensions(EXTS_OF_INTEREST);

            let mut ee =
                match PDVCertificate::try_from(pool.certs[case.target_file_name].as_slice()) {
                    Ok(ee_cert) => ee_cert,
                    Err(err) => {
                        let k = err.kind();
                        println!("{}: {}", k, err);
                        continue;
                    }
                };
            ee.parse_extensions(EXTS_OF_INTEREST);

            let mut chain = vec![];
            let mut chain2 = vec![];
            let mut cpool = vec![];

            {
                for ca_file in &case.intermediate_ca_file_names {
                    // let der_encoded_ca = get_pkits_ca_cert_bytes(ca_file).unwrap();
                    // pool.certs.push(der_encoded_ca);
                    let mut ca = PDVCertificate::try_from(pool.certs[*ca_file].as_slice()).unwrap();
                    ca.parse_extensions(EXTS_OF_INTEREST);

                    cpool.push(ca);
                }

                for i in 0..case.intermediate_ca_file_names.len() {
                    chain.push(cpool[i].clone());
                    chain2.push(cpool[i].clone());
                }

                let mut cert_path = CertificationPath::new(ta.clone(), chain, ee);

                #[allow(unused_variables, unused_mut)]
                let mut skip_revocation_check = skip_revocation;
                #[cfg(feature = "revocation")]
                {
                    // key rollover support or seperate cert and CRL signing keys for revocation checking is not yet implemented, skip those for now
                    let self_issued_tests = [
                        "4.11.7", "4.12.7", "4.12.9", "4.13.19", "4.5.1", "4.5.2", "4.5.3",
                        "4.5.4", "4.5.5", "4.5.6", "4.6.15", "4.6.17", "4.9.6", "4.4.19",
                    ];
                    if self_issued_tests.contains(&case_name.as_str()) {
                        skip_revocation_check = true;
                    }
                }

                let crl = get_pkits_crl_bytes("TrustAnchorRootCRL.crl").unwrap();
                cert_path.crls[0] = Some(crl);
                for (i, n) in case.intermediate_ca_file_names.iter().enumerate() {
                    if *n == "NameOrdering" {
                        let crl = get_pkits_crl_ca_bytes("NameOrder").unwrap();
                        cert_path.crls[i + 1] = Some(crl);
                    } else if *n == "PoliciesP123subsubCAP12P2" {
                        let crl = get_pkits_crl_ca_bytes("PoliciesP123subsubCAP12P1").unwrap();
                        cert_path.crls[i + 1] = Some(crl);
                    } else if n.contains("NoCRLCA") {
                    } else if n.contains("TwoCRLsCA") {
                        if case.alt_test_name.is_none() {
                            let crl = get_pkits_crl_ca_bytes("TwoCRLsCAGood").unwrap();
                            cert_path.crls[i + 1] = Some(crl);
                        } else {
                            let crl = get_pkits_crl_ca_bytes("TwoCRLsCABad").unwrap();
                            cert_path.crls[i + 1] = Some(crl);
                        }
                    } else if n.contains("SeparateCertificateandCRLKeys") {
                        let crl = get_pkits_crl_ca_bytes("SeparateCertificateandCRLKeys").unwrap();
                        cert_path.crls[i + 1] = Some(crl);
                    } else if n.contains("onlySomeReasonsCA1") {
                        //TODO add a case with the other CRL (onlySomeReasonsCA1otherreasonsCRL.crl)
                        let crl = get_pkits_crl_ca_bytes("onlySomeReasonsCA1compromise").unwrap();
                        cert_path.crls[i + 1] = Some(crl);
                    } else if !n.contains("Self") {
                        let crl = get_pkits_crl_ca_bytes(n).unwrap();
                        cert_path.crls[i + 1] = Some(crl);
                    } else {
                        //println!("{}", n);
                    }
                }

                if "4.4.1" == case_name {
                    println!("break");
                }

                let mut tmp_settings = case.settings.clone();
                set_use_policy_graph(&mut tmp_settings, policy_graph);

                let mut cpr = CertificationPathResults::new();
                #[cfg(not(feature = "revocation"))]
                let r = pe.validate_path(&pe, &tmp_settings, &mut cert_path, &mut cpr);

                #[cfg(feature = "revocation")]
                let mut r = pe.validate_path(&pe, &tmp_settings, &mut cert_path, &mut cpr);

                #[cfg(feature = "revocation")]
                if r.is_ok() && !skip_revocation_check {
                    r = check_revocation(pe, &tmp_settings, &mut cert_path, &mut cpr);
                }
                if (r.is_err() && case.expected_error.is_none())
                    || (r.is_ok() && case.expected_error.is_some())
                {
                    #[cfg(feature = "std")]
                    {
                        panic!("Unexpected result for {}", case_name);
                    }
                    #[cfg(not(feature = "std"))]
                    if ![
                        "4.13.21", "4.13.23", "4.13.25", "4.13.27", "4.13.30", "4.13.32",
                        "4.13.34", "4.13.36", "4.3.3", "4.3.11", "4.14.2", "4.14.3", "4.14.6",
                        "4.14.8", "4.14.9", "4.7.4", "4.7.5",
                    ]
                    .contains(&case_name.as_str())
                    {
                        panic!("Unexpected result for {}", case_name);
                    }
                }

                if !verified_ta_as_target {
                    let ta_as_cert =
                        parse_cert(&ta.encoded_ta.to_vec(), "TrustAnchorRootCertificate.crt")
                            .unwrap();

                    let mut cert_path2 =
                        CertificationPath::new(ta, CertificateChain::default(), ta_as_cert);
                    let mut cpr = CertificationPathResults::new();
                    #[cfg(not(feature = "revocation"))]
                    let r = pe.validate_path(&pe, &tmp_settings, &mut cert_path2, &mut cpr);

                    #[cfg(feature = "revocation")]
                    let mut r = pe.validate_path(&pe, &tmp_settings, &mut cert_path2, &mut cpr);
                    #[cfg(feature = "revocation")]
                    if r.is_ok() && !skip_revocation_check {
                        r = check_revocation(pe, &tmp_settings, &mut cert_path2, &mut cpr);
                    }
                    if (r.is_err() && case.expected_error.is_none())
                        || (r.is_ok() && case.expected_error.is_some())
                    {
                        panic!("Unexpected result for {}", case_name);
                    }
                    verified_ta_as_target = true;
                }

                if !skip_revocation {
                    // no tests defined for EC at present, so skip when revocation check is true (i.e., for EC)
                    let der_encoded_ta5914 =
                        get_pkits_ta5914_2048_bytes(case.ta5914_filename).unwrap();
                    let mut ta5914 =
                        PDVTrustAnchorChoice::try_from(der_encoded_ta5914.as_slice()).unwrap();
                    ta5914.parse_extensions(EXTS_OF_INTEREST);

                    // validate again with settings supplied by 5914 formatted TA
                    let mut cpr = CertificationPathResults::new();
                    let m = enforce_trust_anchor_constraints(&G_DEFAULT_SETTINGS_5914, &ta5914);
                    let mut cert_path2 =
                        CertificationPath::new(ta5914, chain2, cert_path.target.clone());
                    if let Ok(mod_cps) = m {
                        #[cfg(not(feature = "revocation"))]
                        let r = pe.validate_path(&pe, &mod_cps, &mut cert_path2, &mut cpr);

                        #[cfg(feature = "revocation")]
                        let mut r = pe.validate_path(&pe, &mod_cps, &mut cert_path2, &mut cpr);
                        #[cfg(feature = "revocation")]
                        if r.is_ok() && !skip_revocation_check {
                            r = check_revocation(pe, &tmp_settings, &mut cert_path, &mut cpr);
                        }
                        if (r.is_err() && case.expected_error.is_none())
                            || (r.is_ok() && case.expected_error.is_some())
                        {
                            #[cfg(not(feature = "std"))]
                            if ![
                                "4.13.21", "4.13.23", "4.13.25", "4.13.27", "4.13.30", "4.13.32",
                                "4.13.34", "4.13.36", "4.3.3", "4.3.11", "4.14.2", "4.14.3",
                                "4.14.6", "4.14.8", "4.14.9", "4.7.4", "4.7.5",
                            ]
                            .contains(&case_name.as_str())
                            {
                                println!("Unexpected result for {} with TA enforcement", case_name);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(feature = "std")]
pub async fn pkits_guts(
    mpool: &mut CertPool,
    pkits_data_map: &PkitsDataMap,
    pe: &PkiEnvironment,
    flavor: PkitsFlavor,
    skip_revocation: bool,
    policy_graph: bool,
) {
    // all tests share common trust anchor so add it to the pool
    let der_encoded_ta = match flavor {
        PkitsFlavor::PkitsRsa2048 => {
            { get_pkits_cert_bytes("TrustAnchorRootCertificate.crt") }.unwrap()
        }
        // PkitsFlavor::PkitsRsa4096 => {
        //     { get_pkits_cert_bytes_4096("TrustAnchorRootCertificate.crt") }.unwrap()
        // }
        PkitsFlavor::PkitsP256 => {
            { get_pkits_cert_bytes_p256("TrustAnchorRootCertificate.crt") }.unwrap()
        } // PkitsFlavor::PkitsP384 => {
          //     { get_pkits_cert_bytes_p384("TrustAnchorRootCertificate.crt") }.unwrap()
          // }
    };

    if !mpool.certs.contains_key("TrustAnchorRootCertificate.crt") {
        mpool
            .certs
            .insert("TrustAnchorRootCertificate.crt".to_string(), der_encoded_ta);
    }

    let mut verified_ta_as_target = false;

    // iterate over settings map to populate mpool
    for k in pkits_data_map.keys() {
        let pd = pkits_data_map.get(k).unwrap();

        for i in 0..pd.len() {
            let case = pd.get(i).unwrap();

            // load certs for this case into the pool
            let der_encoded_ee = match flavor {
                PkitsFlavor::PkitsRsa2048 => {
                    { get_pkits_cert_bytes(case.target_file_name) }.unwrap()
                }
                // PkitsFlavor::PkitsRsa4096 => {
                //     { get_pkits_cert_bytes_4096(case.target_file_name) }.unwrap()
                // }
                PkitsFlavor::PkitsP256 => {
                    { get_pkits_cert_bytes_p256(case.target_file_name) }.unwrap()
                } // PkitsFlavor::PkitsP384 => {
                  //     { get_pkits_cert_bytes_p384(case.target_file_name) }.unwrap()
                  // }
            };
            mpool
                .certs
                .insert(case.target_file_name.to_string(), der_encoded_ee);
            for ca_file in &case.intermediate_ca_file_names {
                let der_encoded_ca = match flavor {
                    PkitsFlavor::PkitsRsa2048 => { get_pkits_ca_cert_bytes(ca_file) }.unwrap(),
                    // PkitsFlavor::PkitsRsa4096 => { get_pkits_ca_cert_bytes_4096(ca_file) }.unwrap(),
                    PkitsFlavor::PkitsP256 => { get_pkits_ca_cert_bytes_p256(ca_file) }.unwrap(),
                    // PkitsFlavor::PkitsP384 => { get_pkits_ca_cert_bytes_p384(ca_file) }.unwrap(),
                };

                mpool.certs.insert(ca_file.to_string(), der_encoded_ca);
            }
        }
    }

    let pool: &CertPool = &*mpool;

    // iterate over settings map
    for k in pkits_data_map.keys() {
        let pd = pkits_data_map.get(k).unwrap();

        for i in 0..pd.len() {
            let case = pd.get(i).unwrap();

            let case_name = if let Some(alt_test_name) = case.alt_test_name {
                alt_test_name.to_string()
            } else {
                format!("{}.{}", *k, i + 1)
            };

            if skip_revocation
                && (case_name.starts_with("4.4.")
                    || [
                        "4.14.2", "4.14.3", "4.14.6", "4.14.8", "4.14.9", "4.7.4", "4.7.5",
                    ]
                    .contains(&case_name.as_str()))
            {
                // where skip_revocation is true (i.e., for EC) then continue
                continue;
            }

            println!("{}", case_name);
            let mut ta = PDVTrustAnchorChoice::try_from(
                pool.certs["TrustAnchorRootCertificate.crt"].as_slice(),
            )
            .unwrap();
            ta.parse_extensions(EXTS_OF_INTEREST);

            let mut ee =
                match PDVCertificate::try_from(pool.certs[case.target_file_name].as_slice()) {
                    Ok(ee_cert) => ee_cert,
                    Err(err) => {
                        let k = err.kind();
                        println!("{}: {}", k, err);
                        continue;
                    }
                };
            if "4.3.11" == case_name {
                println!("break");
            }
            ee.parse_extensions(EXTS_OF_INTEREST);

            let mut chain = vec![];
            let mut chain2 = vec![];
            let mut cpool = vec![];

            {
                for ca_file in &case.intermediate_ca_file_names {
                    // let der_encoded_ca = get_pkits_ca_cert_bytes(ca_file).unwrap();
                    // pool.certs.push(der_encoded_ca);
                    let mut ca = PDVCertificate::try_from(pool.certs[*ca_file].as_slice()).unwrap();
                    ca.parse_extensions(EXTS_OF_INTEREST);

                    cpool.push(ca);
                }

                for c in cpool.iter() {
                    chain.push(c.clone());
                    chain2.push(c.clone());
                }

                let mut cert_path = CertificationPath::new(ta.clone(), chain, ee);

                #[allow(unused_variables, unused_mut)]
                let mut skip_revocation_check = skip_revocation;
                #[cfg(feature = "revocation")]
                {
                    // key rollover support or seperate cert and CRL signing keys for revocation checking is not yet implemented, skip those for now
                    let self_issued_tests = [
                        "4.11.7", "4.12.7", "4.12.9", "4.13.19", "4.5.1", "4.5.2", "4.5.3",
                        "4.5.4", "4.5.5", "4.5.6", "4.6.15", "4.6.17", "4.9.6", "4.4.19",
                    ];
                    if self_issued_tests.contains(&case_name.as_str()) {
                        skip_revocation_check = true;
                    }
                }

                let crl = get_pkits_crl_bytes("TrustAnchorRootCRL.crl").unwrap();
                cert_path.crls[0] = Some(crl);
                for (i, n) in case.intermediate_ca_file_names.iter().enumerate() {
                    if *n == "NameOrdering" {
                        let crl = get_pkits_crl_ca_bytes("NameOrder").unwrap();
                        cert_path.crls[i + 1] = Some(crl);
                    } else if *n == "PoliciesP123subsubCAP12P2" {
                        let crl = get_pkits_crl_ca_bytes("PoliciesP123subsubCAP12P1").unwrap();
                        cert_path.crls[i + 1] = Some(crl);
                    } else if n.contains("NoCRLCA") {
                    } else if n.contains("TwoCRLsCA") {
                        if case.alt_test_name.is_none() {
                            let crl = get_pkits_crl_ca_bytes("TwoCRLsCAGood").unwrap();
                            cert_path.crls[i + 1] = Some(crl);
                        } else {
                            let crl = get_pkits_crl_ca_bytes("TwoCRLsCABad").unwrap();
                            cert_path.crls[i + 1] = Some(crl);
                        }
                    } else if n.contains("SeparateCertificateandCRLKeys") {
                        let crl = get_pkits_crl_ca_bytes("SeparateCertificateandCRLKeys").unwrap();
                        cert_path.crls[i + 1] = Some(crl);
                    } else if n.contains("onlySomeReasonsCA1") {
                        //TODO add a case with the other CRL (onlySomeReasonsCA1otherreasonsCRL.crl)
                        let crl = get_pkits_crl_ca_bytes("onlySomeReasonsCA1compromise").unwrap();
                        cert_path.crls[i + 1] = Some(crl);
                    } else if !n.contains("Self") {
                        let crl = get_pkits_crl_ca_bytes(n).unwrap();
                        cert_path.crls[i + 1] = Some(crl);
                    } else {
                        // TODO address need for multiple CRL signers due to self-issued
                    }
                }

                let mut tmp_settings = case.settings.clone();
                set_use_policy_graph(&mut tmp_settings, policy_graph);

                let mut cpr = CertificationPathResults::new();
                #[cfg(not(feature = "revocation"))]
                let r = pe.validate_path(&pe, &tmp_settings, &mut cert_path, &mut cpr);

                #[cfg(feature = "revocation")]
                let mut r = pe.validate_path(pe, &tmp_settings, &mut cert_path, &mut cpr);
                #[cfg(feature = "revocation")]
                if r.is_ok() && !skip_revocation_check {
                    r = check_revocation(pe, &tmp_settings, &mut cert_path, &mut cpr).await;
                }
                if (r.is_err() && case.expected_error.is_none())
                    || (r.is_ok() && case.expected_error.is_some())
                {
                    panic!("Unexpected result for {}", case_name);
                }

                if !verified_ta_as_target {
                    let ta_as_cert = parse_cert(
                        <&[u8]>::clone(&ta.encoded_ta.as_slice()),
                        "TrustAnchorRootCertificate.crt",
                    )
                    .unwrap();

                    let mut cert_path2 =
                        CertificationPath::new(ta, CertificateChain::default(), ta_as_cert);
                    let mut cpr = CertificationPathResults::new();
                    #[cfg(not(feature = "revocation"))]
                    let r = pe.validate_path(&pe, &tmp_settings, &mut cert_path2, &mut cpr);

                    #[cfg(feature = "revocation")]
                    let mut r = pe.validate_path(pe, &tmp_settings, &mut cert_path2, &mut cpr);
                    #[cfg(feature = "revocation")]
                    if r.is_ok() && !skip_revocation_check {
                        r = check_revocation(pe, &tmp_settings, &mut cert_path2, &mut cpr).await;
                    }
                    if (r.is_err() && case.expected_error.is_none())
                        || (r.is_ok() && case.expected_error.is_some())
                    {
                        panic!("Unexpected result for {}", case_name);
                    }
                    verified_ta_as_target = true;
                }

                if !skip_revocation {
                    // no tests defined for EC at present, so skip when revocation check is true (i.e., for EC)
                    let der_encoded_ta5914 =
                        get_pkits_ta5914_2048_bytes(case.ta5914_filename).unwrap();
                    let mut ta5914 =
                        PDVTrustAnchorChoice::try_from(der_encoded_ta5914.as_slice()).unwrap();
                    ta5914.parse_extensions(EXTS_OF_INTEREST);

                    // validate again with settings supplied by 5914 formatted TA
                    let mut cpr = CertificationPathResults::new();
                    let m = enforce_trust_anchor_constraints(&G_DEFAULT_SETTINGS_5914, &ta5914);
                    let mut cert_path2 =
                        CertificationPath::new(ta5914, chain2, cert_path.target.clone());
                    if let Ok(mod_cps) = &m {
                        #[cfg(not(feature = "revocation"))]
                        let r = pe.validate_path(&pe, &mod_cps, &mut cert_path2, &mut cpr);

                        #[cfg(feature = "revocation")]
                        let mut r = pe.validate_path(pe, mod_cps, &mut cert_path2, &mut cpr);
                        #[cfg(feature = "revocation")]
                        if r.is_ok() && !skip_revocation_check {
                            r = check_revocation(pe, &tmp_settings, &mut cert_path, &mut cpr).await;
                        }
                        if (r.is_err() && case.expected_error.is_none())
                            || (r.is_ok() && case.expected_error.is_some())
                        {
                            println!("Unexpected result for {} with TA enforcement", case_name);
                        }
                    }
                }
            }
        }
    }
}
