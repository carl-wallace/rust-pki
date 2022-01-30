use certval::cert_source::CertFile;
use certval::ta_source::*;
use certval::*;
use certval::{CertificationPathSettings, Error, PDVCertificate, Result};
use trust_anchor_format::*;
use x509::*;

use alloc::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
extern crate alloc;

use x509::der::Decodable;
use x509::der::{DecodeValue, Decoder};

use certval::ta_source::TaSource;
use std::time::{SystemTime, UNIX_EPOCH};

#[macro_use]
extern crate lazy_static;

#[derive(Clone)]
pub struct CertPool {
    pub certs: BTreeMap<String, Vec<u8>>,
}

// The PkitsDataMap structure is used to group tests by section number. The key into each is a
// string representing a section in the NIST PKITS doc. The corresponding vector accumulates
// PkitTestCase or CertificationPathSettings for each test case in the section identified by the key.
pub type PkitsDataMap<'a> = BTreeMap<&'a str, Vec<PkitsTestCase<'a>>>;

// Policy OIDs used by PKITS test cases
pub const PKITS_TEST_POLICY_1: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.101.3.2.1.48.1");
pub const PKITS_TEST_POLICY_2: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.101.3.2.1.48.2");
pub const PKITS_TEST_POLICY_3: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.101.3.2.1.48.3");
pub const PKITS_TEST_POLICY_4: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.101.3.2.1.48.4");
pub const PKITS_TEST_POLICY_5: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.101.3.2.1.48.5");
pub const PKITS_TEST_POLICY_6: ObjectIdentifier =
    ObjectIdentifier::new("2.16.840.1.101.3.2.1.48.6");

// Define static CertificationPathSettings objects and populate per PKITS test descriptions.
lazy_static! {
    static ref G_CERTS_FOLDER: String = {
        String::from(format!("{}{}", env!("CARGO_MANIFEST_DIR"),"/tests/examples/PKITS_data_2048/certs/"))
    };

    static ref G_CRLS_FOLDER: String = {
        String::from(format!("{}{}", env!("CARGO_MANIFEST_DIR"),"/tests/examples/PKITS_data_2048/crls/"))
    };

    static ref G_CERTS_FOLDER_4096: String = {
        String::from(format!("{}{}", env!("CARGO_MANIFEST_DIR"),"/tests/examples/PKITS_data_4096/certs/"))
    };

    static ref G_CRLS_FOLDER_4096: String = {
        String::from(format!("{}{}", env!("CARGO_MANIFEST_DIR"),"/tests/examples/PKITS_data_4096/crls/"))
    };

    static ref G_CERTS_FOLDER_P256: String = {
        String::from(format!("{}{}", env!("CARGO_MANIFEST_DIR"),"/tests/examples/PKITS_data_p256/certs/"))
    };

    static ref G_CRLS_FOLDER_P256: String = {
        String::from(format!("{}{}", env!("CARGO_MANIFEST_DIR"),"/tests/examples/PKITS_data_p256/crls/"))
    };

    static ref G_CERTS_FOLDER_P384: String = {
        String::from(format!("{}{}", env!("CARGO_MANIFEST_DIR"),"/tests/examples/PKITS_data_p384/certs/"))
    };

    static ref G_CRLS_FOLDER_P384: String = {
        String::from(format!("{}{}", env!("CARGO_MANIFEST_DIR"),"/tests/examples/PKITS_data_p384/crls/"))
    };

    static ref G_TA5914_FOLDER: String = {
        String::from(format!("{}{}", env!("CARGO_MANIFEST_DIR"),"/tests/examples/PKITS_data/5914_tas/"))
    };

    // default settings used by most test cases
    static ref G_DEFAULT_SETTINGS: CertificationPathSettings<'static> = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        cs
    };
    static ref G_DEFAULT_SETTINGS_TA: String = {
        String::from("default.ta")
    };

    // same as above but with TA constaint enforcement enabled (and TAs used to supply other settings)
    static ref G_DEFAULT_SETTINGS_5914: CertificationPathSettings<'static> = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        set_enforce_trust_anchor_constraints(&mut cs, true);
        cs
    };

    //these four sets of settings are defined in section 4.8.1
    static ref G_SETTINGS1: CertificationPathSettings<'static> = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        set_initial_explicit_policy_indicator(&mut cs, true);
        cs
    };
    static ref G_SETTINGS1_TA: String = {
        String::from("settings1.ta")
    };

    static ref G_SETTINGS2: CertificationPathSettings<'static> = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        set_initial_explicit_policy_indicator(&mut cs, true);
        let mut oids = ObjectIdentifierSet::new();
        oids.insert(PKITS_TEST_POLICY_1);
        set_initial_policy_set(&mut cs, oids);
        cs
    };
    static ref G_SETTINGS2_TA: String = {
        String::from("settings2.ta")
    };

    static ref G_SETTINGS3: CertificationPathSettings<'static> = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        set_initial_explicit_policy_indicator(&mut cs, true);
        let mut oids = ObjectIdentifierSet::new();
        oids.insert(PKITS_TEST_POLICY_2);
        set_initial_policy_set(&mut cs, oids);
        cs
    };
    static ref G_SETTINGS3_TA: String = {
        String::from("settings3.ta")
    };

    static ref G_SETTINGS4: CertificationPathSettings<'static> = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        set_initial_explicit_policy_indicator(&mut cs, true);
        let mut oids = ObjectIdentifierSet::new();
        oids.insert(PKITS_TEST_POLICY_1);
        oids.insert(PKITS_TEST_POLICY_2);
        set_initial_policy_set(&mut cs, oids);
        cs
    };
    static ref G_SETTINGS4_TA: String = {
        String::from("settings4.ta")
    };

    //from 4.8.6, 4.8.10, 4.8.13
    static ref G_SETTINGS5: CertificationPathSettings<'static> = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        let mut oids = ObjectIdentifierSet::new();
        oids.insert(PKITS_TEST_POLICY_1);
        set_initial_policy_set(&mut cs, oids);
        cs
    };
    static ref G_SETTINGS5_TA: String = {
        String::from("settings5.ta")
    };

    static ref G_SETTINGS6: CertificationPathSettings<'static> = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        let mut oids = ObjectIdentifierSet::new();
        oids.insert(PKITS_TEST_POLICY_2);
        set_initial_policy_set(&mut cs, oids);
        cs
    };
    static ref G_SETTINGS6_TA: String = {
        String::from("settings6.ta")
    };

    static ref G_SETTINGS7: CertificationPathSettings<'static> = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        let mut oids = ObjectIdentifierSet::new();
        oids.insert(PKITS_TEST_POLICY_3);
        set_initial_policy_set(&mut cs, oids);
        cs
    };
    static ref G_SETTINGS7_TA: String = {
        String::from("settings7.ta")
    };

    //from 4.10.1
    static ref G_SETTINGS8: CertificationPathSettings<'static> = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        set_initial_policy_mapping_inhibit_indicator(&mut cs, true);
        cs
    };
    static ref G_SETTINGS8_TA: String = {
        String::from("settings8.ta")
    };

    //from 4.10.5
    static ref G_SETTINGS9: CertificationPathSettings<'static> = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        let mut oids = ObjectIdentifierSet::new();
        oids.insert(PKITS_TEST_POLICY_6);
        set_initial_policy_set(&mut cs, oids);
        cs
    };
    static ref G_SETTINGS9_TA: String = {
        String::from("settings9.ta")
    };

    //from 4.12.3
    static ref G_SETTINGS10: CertificationPathSettings<'static> = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        set_initial_inhibit_any_policy_indicator(&mut cs, true);
        cs
    };
    static ref G_SETTINGS10_TA: String = {
        String::from("settings10.ta")
    };
}

pub fn get_file_as_byte_vec(filename: &Path) -> Result<Vec<u8>> {
    if let Ok(mut f) = File::open(&filename) {
        if let Ok(metadata) = std::fs::metadata(&filename) {
            let mut buffer = vec![0; metadata.len() as usize];
            if let Ok(()) = f.read_exact(&mut buffer) {
                return Ok(buffer);
            }
        }
    }
    Err(Error::Unrecognized)
}

pub struct PkitsTestCase<'a> {
    pub intermediate_ca_file_names: Vec<&'a str>,
    pub target_file_name: &'a str,
    pub settings: &'a CertificationPathSettings<'a>,
    pub ta5914_filename: &'a str,
    pub alt_test_name: Option<&'a str>,
    pub expected_error: Option<Error>,
}

pub fn get_pkits_cert_bytes(fname: &'_ str) -> Result<Vec<u8>> {
    let f = format!("{}{}", G_CERTS_FOLDER.as_str(), fname);
    get_file_as_byte_vec(Path::new(&f))
}
pub fn get_pkits_ca_cert_bytes(fname: &'_ str) -> Result<Vec<u8>> {
    let mut f = format!("{}{}{}", G_CERTS_FOLDER.as_str(), fname, "CACert.crt");
    if !Path::new(f.as_str()).exists() {
        f = format!("{}{}{}", G_CERTS_FOLDER.as_str(), fname, "Cert.crt");
    }
    get_file_as_byte_vec(Path::new(&f))
}
pub fn get_pkits_cert_bytes_p256(fname: &'_ str) -> Result<Vec<u8>> {
    let f = format!("{}{}", G_CERTS_FOLDER_P256.as_str(), fname);
    get_file_as_byte_vec(Path::new(&f))
}
pub fn get_pkits_ca_cert_bytes_p256(fname: &'_ str) -> Result<Vec<u8>> {
    let mut f = format!("{}{}{}", G_CERTS_FOLDER_P256.as_str(), fname, "CACert.crt");
    if !Path::new(f.as_str()).exists() {
        f = format!("{}{}{}", G_CERTS_FOLDER_P256.as_str(), fname, "Cert.crt");
    }
    get_file_as_byte_vec(Path::new(&f))
}

pub fn get_pkits_cert_bytes_p384(fname: &'_ str) -> Result<Vec<u8>> {
    let f = format!("{}{}", G_CERTS_FOLDER_P384.as_str(), fname);
    get_file_as_byte_vec(Path::new(&f))
}
pub fn get_pkits_ca_cert_bytes_p384(fname: &'_ str) -> Result<Vec<u8>> {
    let mut f = format!("{}{}{}", G_CERTS_FOLDER_P384.as_str(), fname, "CACert.crt");
    if !Path::new(f.as_str()).exists() {
        f = format!("{}{}{}", G_CERTS_FOLDER_P384.as_str(), fname, "Cert.crt");
    }
    get_file_as_byte_vec(Path::new(&f))
}
pub fn get_pkits_cert_bytes_4096(fname: &'_ str) -> Result<Vec<u8>> {
    let f = format!("{}{}", G_CERTS_FOLDER_4096.as_str(), fname);
    get_file_as_byte_vec(Path::new(&f))
}
pub fn get_pkits_ca_cert_bytes_4096(fname: &'_ str) -> Result<Vec<u8>> {
    let mut f = format!("{}{}{}", G_CERTS_FOLDER_4096.as_str(), fname, "CACert.crt");
    if !Path::new(f.as_str()).exists() {
        f = format!("{}{}{}", G_CERTS_FOLDER_4096.as_str(), fname, "Cert.crt");
    }
    get_file_as_byte_vec(Path::new(&f))
}

pub fn get_pkits_ta5914_bytes(fname: &'_ str) -> Result<Vec<u8>> {
    let f = format!("{}{}", G_TA5914_FOLDER.as_str(), fname);
    get_file_as_byte_vec(Path::new(&f))
}

pub fn load_pkits(pkits_data_map: &'_ mut PkitsDataMap) {
    //-----------------------------------------------------------------------------
    //Section 4.1 - signature verification - 6 tests
    //-----------------------------------------------------------------------------
    {
        let target_file_name = "ValidCertificatePathTest1EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.2")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.1.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidCASignatureTest2EE.crt";
        let intermediate_ca_file_names = vec!["BadSigned"];
        pkits_data_map
            .entry("4.2")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.1.1"),
                expected_error: Some(Error::SignatureVerificationFailure),
            });
    }

    // {
    //     let target_file_name = "ValidCertificatePathTest1EE.crt";
    //     let intermediate_ca_file_names = vec!["Good"];
    //     pkits_data_map.entry("4.1").or_insert_with(Vec::new).push(PkitsTestCase{target_file_name, intermediate_ca_file_names, alt_test_name: None, expected_error: None});
    //     pkits_settings_map.entry("4.1").or_insert_with(Vec::new).push(&G_DEFAULT_SETTINGS);
    // }
    // {
    //     let target_file_name = "InvalidCASignatureTest2EE.crt";
    //     let intermediate_ca_file_names = vec!["BadSigned"];
    //     pkits_data_map.entry("4.1").or_insert_with(Vec::new).push(PkitsTestCase{target_file_name, intermediate_ca_file_names, alt_test_name: None, expected_error: Some(Error::SignatureVerificationFailure)});
    //     pkits_settings_map.entry("4.1").or_insert_with(Vec::new).push(&G_DEFAULT_SETTINGS);
    // }
    // {
    //     let target_file_name = "InvalidEESignatureTest3EE.crt";
    //     let intermediate_ca_file_names = vec!["Good"];
    //     pkits_data_map.entry("4.1").or_insert_with(Vec::new).push(PkitsTestCase{target_file_name, intermediate_ca_file_names, alt_test_name: None, expected_error: Some(Error::SignatureVerificationFailure)});
    //     pkits_settings_map.entry("4.1").or_insert_with(Vec::new).push(&G_DEFAULT_SETTINGS);
    // }
    // {
    //     let target_file_name = "ValidDSASignaturesTest4EE.crt";
    //     let intermediate_ca_file_names = vec!["DSA"];
    //     pkits_data_map.entry("4.1").or_insert_with(Vec::new).push(PkitsTestCase{target_file_name, intermediate_ca_file_names, alt_test_name: None, expected_error: None});
    //     pkits_settings_map.entry("4.1").or_insert_with(Vec::new).push(&G_DEFAULT_SETTINGS);
    // }
    // {
    //     let target_file_name = "ValidDSAParameterInheritanceTest5EE.crt";
    //     let intermediate_ca_file_names = vec!["DSA", "DSAParametersInherited"];
    //     pkits_data_map.entry("4.1").or_insert_with(Vec::new).push(PkitsTestCase{target_file_name, intermediate_ca_file_names, alt_test_name: None, expected_error: None});
    //     pkits_settings_map.entry("4.1").or_insert_with(Vec::new).push(&G_DEFAULT_SETTINGS);
    // }
    // {
    //     let target_file_name = "InvalidDSASignatureTest6EE.crt";
    //     let intermediate_ca_file_names = vec!["DSA"];
    //     pkits_data_map.entry("4.1").or_insert_with(Vec::new).push(PkitsTestCase{target_file_name, intermediate_ca_file_names, alt_test_name: None, expected_error: Some(Error::SignatureVerificationFailure)});
    //     pkits_settings_map.entry("4.1").or_insert_with(Vec::new).push(&G_DEFAULT_SETTINGS);
    // }

    //-----------------------------------------------------------------------------
    //Section 4.2 - validity periods - 8 tests
    //-----------------------------------------------------------------------------
    {
        let target_file_name = "InvalidCAnotBeforeDateTest1EE.crt";
        let intermediate_ca_file_names = vec!["BadnotBeforeDate"];
        pkits_data_map
            .entry("4.2")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidNotBeforeDate),
            });
    }
    {
        let target_file_name = "InvalidEEnotBeforeDateTest2EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.2")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidNotBeforeDate),
            });
    }
    // {
    //     // This test is marked as should succeed in PKITS, but the formats library does not support pre-1970 (i.e., Unix epoch) certs. This is unimportant.
    //     let target_file_name = "Validpre2000UTCnotBeforeDateTest3EE.crt";
    //     let intermediate_ca_file_names = vec!["Good"];
    //     pkits_data_map
    //         .entry("4.2")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS, ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: None,
    //             expected_error: None,
    //         });
    // }
    {
        let target_file_name = "ValidGeneralizedTimenotBeforeDateTest4EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.2")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidCAnotAfterDateTest5EE.crt";
        let intermediate_ca_file_names = vec!["BadnotAfterDate"];
        pkits_data_map
            .entry("4.2")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidNotAfterDate),
            });
    }
    {
        let target_file_name = "InvalidEEnotAfterDateTest6EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.2")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidNotAfterDate),
            });
    }
    {
        let target_file_name = "Invalidpre2000UTCEEnotAfterDateTest7EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.2")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidNotAfterDate),
            });
    }
    {
        let target_file_name = "ValidGeneralizedTimenotAfterDateTest8EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.2")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }

    //-----------------------------------------------------------------------------
    //Section 4.3 - verifying name chaining - 10 tests
    //-----------------------------------------------------------------------------
    {
        let target_file_name = "InvalidNameChainingTest1EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.3")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::NameChainingFailure),
            });
    }
    {
        let target_file_name = "InvalidNameChainingTest1EE.crt";
        let intermediate_ca_file_names = vec!["NameOrdering"];
        pkits_data_map
            .entry("4.3")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::NameChainingFailure),
            });
    }
    {
        let target_file_name = "ValidNameChainingWhitespaceTest3EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.3")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidNameChainingWhitespaceTest4EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.3")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidNameChainingCapitalizationTest5EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.3")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidNameUIDsTest6EE.crt";
        let intermediate_ca_file_names = vec!["UID"];
        pkits_data_map
            .entry("4.3")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidRFC3280MandatoryAttributeTypesTest7EE.crt";
        let intermediate_ca_file_names = vec!["RFC3280MandatoryAttributeTypes"];
        pkits_data_map
            .entry("4.3")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidRFC3280OptionalAttributeTypesTest8EE.crt";
        let intermediate_ca_file_names = vec!["RFC3280OptionalAttributeTypes"];
        pkits_data_map
            .entry("4.3")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidUTF8StringEncodedNamesTest9EE.crt";
        let intermediate_ca_file_names = vec!["UTF8StringEncodedNames"];
        pkits_data_map
            .entry("4.3")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidRolloverfromPrintableStringtoUTF8StringTest10EE.crt";
        let intermediate_ca_file_names = vec!["RolloverfromPrintableStringtoUTF8String"];
        pkits_data_map
            .entry("4.3")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidUTF8StringCaseInsensitiveMatchTest11EE.crt";
        let intermediate_ca_file_names = vec!["UTF8StringCaseInsensitiveMatch"];
        pkits_data_map
            .entry("4.3")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }

    //-----------------------------------------------------------------------------
    //Section 4.4 - basic certificate revocation - 21 tests
    //-----------------------------------------------------------------------------
    // TODO - implement me

    //-----------------------------------------------------------------------------
    //Section 4.5 - verifying paths with self-issued certificates - 8 tests
    //-----------------------------------------------------------------------------
    {
        let target_file_name = "ValidBasicSelfIssuedOldWithNewTest1EE.crt";
        let intermediate_ca_file_names =
            vec!["BasicSelfIssuedNewKey", "BasicSelfIssuedNewKeyOldWithNew"];
        pkits_data_map
            .entry("4.5")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    // { //TODO - requires CRL processing to yield expected result
    //     let target_file_name = "InvalidBasicSelfIssuedOldWithNewTest2EE.crt";
    //     let intermediate_ca_file_names = vec!["BasicSelfIssuedNewKey", "BasicSelfIssuedNewKeyOldWithNew"];
    //     pkits_data_map
    //         .entry("4.5")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS, ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.5.2"),
    //             expected_error: None,
    //         });
    // }
    {
        let target_file_name = "ValidBasicSelfIssuedNewWithOldTest3EE.crt";
        let intermediate_ca_file_names =
            vec!["BasicSelfIssuedOldKey", "BasicSelfIssuedOldKeyNewWithOld"];
        pkits_data_map
            .entry("4.5")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.5.3"),
                expected_error: None,
            });
    }
    // { //TODO - requires CRL processing to yield expected result
    //     let target_file_name = "ValidBasicSelfIssuedNewWithOldTest4EE.crt";
    //     let intermediate_ca_file_names =
    //         vec!["BasicSelfIssuedOldKey", "BasicSelfIssuedOldKeyNewWithOld"];
    //     pkits_data_map
    //         .entry("4.5")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.5.4"),
    //             expected_error: None,
    //         });
    // }
    // { //TODO - requires CRL processing to yield expected result
    //     let target_file_name = "InvalidBasicSelfIssuedNewWithOldTest5EE.crt";
    //     let intermediate_ca_file_names = vec!["BasicSelfIssuedOldKey", "BasicSelfIssuedOldKeyNewWithOld"];
    //     pkits_data_map
    //         .entry("4.5")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS, ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.5.5"),
    //             expected_error: None,
    //         });
    // }
    {
        let target_file_name = "ValidBasicSelfIssuedCRLSigningKeyTest6EE.crt";
        let intermediate_ca_file_names = vec!["BasicSelfIssuedCRLSigningKey"];
        pkits_data_map
            .entry("4.5")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.5.6"),
                expected_error: None,
            });
    }

    //-----------------------------------------------------------------------------
    //Section 4.6 - verifying basic constraints - 17 tests
    //-----------------------------------------------------------------------------
    {
        let target_file_name = "InvalidMissingbasicConstraintsTest1EE.crt";
        let intermediate_ca_file_names = vec!["MissingbasicConstraints"];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::MissingBasicConstraints),
            });
    }
    {
        let target_file_name = "InvalidcAFalseTest2EE.crt";
        let intermediate_ca_file_names = vec!["basicConstraintsCriticalcAFalse"];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidBasicConstraints),
            });
    }
    {
        let target_file_name = "InvalidcAFalseTest3EE.crt";
        let intermediate_ca_file_names = vec!["basicConstraintsNotCriticalcAFalse"];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidBasicConstraints),
            });
    }
    {
        let target_file_name = "ValidbasicConstraintsNotCriticalTest4EE.crt";
        let intermediate_ca_file_names = vec!["basicConstraintsNotCritical"];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidpathLenConstraintTest5EE.crt";
        let intermediate_ca_file_names = vec!["pathLenConstraint0", "pathLenConstraint0sub"];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidPathLength),
            });
    }
    {
        let target_file_name = "InvalidpathLenConstraintTest6EE.crt";
        let intermediate_ca_file_names = vec![
            "pathLenConstraint0",
            "pathLenConstraint0sub",
            "pathLenConstraint0subCA2",
        ];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidPathLength),
            });
    }
    {
        let target_file_name = "ValidpathLenConstraintTest7EE.crt";
        let intermediate_ca_file_names = vec!["pathLenConstraint0"];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidpathLenConstraintTest8EE.crt";
        let intermediate_ca_file_names = vec!["pathLenConstraint0"];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidpathLenConstraintTest9EE.crt";
        let intermediate_ca_file_names = vec![
            "pathLenConstraint6",
            "pathLenConstraint6subCA0",
            "pathLenConstraint6subsubCA00",
        ];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidPathLength),
            });
    }
    {
        let target_file_name = "InvalidpathLenConstraintTest10EE.crt";
        let intermediate_ca_file_names = vec![
            "pathLenConstraint6",
            "pathLenConstraint6subCA0",
            "pathLenConstraint6subsubCA00",
        ];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidPathLength),
            });
    }
    {
        let target_file_name = "InvalidpathLenConstraintTest11EE.crt";
        let intermediate_ca_file_names = vec![
            "pathLenConstraint6",
            "pathLenConstraint6subCA1",
            "pathLenConstraint6subsubCA11",
            "pathLenConstraint6subsubsubCA11X",
        ];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidPathLength),
            });
    }
    {
        let target_file_name = "InvalidpathLenConstraintTest12EE.crt";
        let intermediate_ca_file_names = vec![
            "pathLenConstraint6",
            "pathLenConstraint6subCA1",
            "pathLenConstraint6subsubCA11",
            "pathLenConstraint6subsubsubCA11X",
        ];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidPathLength),
            });
    }
    {
        let target_file_name = "ValidpathLenConstraintTest13EE.crt";
        let intermediate_ca_file_names = vec![
            "pathLenConstraint6",
            "pathLenConstraint6subCA4",
            "pathLenConstraint6subsubCA41",
            "pathLenConstraint6subsubsubCA41X",
        ];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidpathLenConstraintTest14EE.crt";
        let intermediate_ca_file_names = vec![
            "pathLenConstraint6",
            "pathLenConstraint6subCA4",
            "pathLenConstraint6subsubCA41",
            "pathLenConstraint6subsubsubCA41X",
        ];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidSelfIssuedpathLenConstraintTest15EE.crt";
        let intermediate_ca_file_names = vec!["pathLenConstraint0", "pathLenConstraint0SelfIssued"];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidSelfIssuedpathLenConstraintTest16EE.crt";
        let intermediate_ca_file_names = vec![
            "pathLenConstraint0",
            "pathLenConstraint0SelfIssued",
            "pathLenConstraint0subCA2",
        ];
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidPathLength),
            });
    }
    {
        let intermediate_ca_file_names = vec![
            "pathLenConstraint1",
            "pathLenConstraint1SelfIssued",
            "pathLenConstraint1subCA",
            "pathLenConstraint1SelfIssuedsubCA",
        ];
        let target_file_name = "ValidSelfIssuedpathLenConstraintTest17EE.crt";
        pkits_data_map
            .entry("4.6")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }

    //-----------------------------------------------------------------------------
    //Section 4.7 - key usage - 5 tests
    //-----------------------------------------------------------------------------
    {
        let target_file_name = "InvalidkeyUsageCriticalkeyCertSignFalseTest1EE.crt";
        let intermediate_ca_file_names = vec!["keyUsageCriticalkeyCertSignFalse"];
        pkits_data_map
            .entry("4.7")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidKeyUsage),
            });
    }
    {
        let target_file_name = "InvalidkeyUsageNotCriticalkeyCertSignFalseTest2EE.crt";
        let intermediate_ca_file_names = vec!["keyUsageNotCriticalkeyCertSignFalse"];
        pkits_data_map
            .entry("4.7")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::InvalidKeyUsage),
            });
    }
    {
        let target_file_name = "ValidkeyUsageNotCriticalTest3EE.crt";
        let intermediate_ca_file_names = vec!["keyUsageNotCritical"];
        pkits_data_map
            .entry("4.7")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    //TODO uncomment when CRL processing lands

    // {
    //     let target_file_name = "InvalidkeyUsageCriticalcRLSignFalseTest4EE.crt";
    //     let intermediate_ca_file_names = vec!["keyUsageCriticalcRLSignFalse"];
    //     pkits_data_map
    //         .entry("4.7")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names, settings: &G_DEFAULT_SETTINGS, ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: None,
    //             expected_error: Some(Error::InvalidKeyUsage),
    //         });
    // }
    // {
    //     let target_file_name = "InvalidkeyUsageNotCriticalcRLSignFalseTest5EE.crt";
    //     let intermediate_ca_file_names = vec!["keyUsageNotCriticalcRLSignFalse"];
    //     pkits_data_map
    //         .entry("4.7")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names, settings: &G_DEFAULT_SETTINGS, ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: None,
    //             expected_error: Some(Error::InvalidKeyUsage),
    //         });
    // }

    //-----------------------------------------------------------------------------
    //Section 4.8 - certificate policies - 20 tests (plus subtests)
    //-----------------------------------------------------------------------------
    {
        let target_file_name = "ValidCertificatePathTest1EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS1,
                ta5914_filename: &G_SETTINGS1_TA,
                alt_test_name: Some("4.8.1.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidCertificatePathTest1EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS2,
                ta5914_filename: &G_SETTINGS2_TA,
                alt_test_name: Some("4.8.1.2"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidCertificatePathTest1EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS3,
                ta5914_filename: &G_SETTINGS3_TA,
                alt_test_name: Some("4.8.1.3"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "ValidCertificatePathTest1EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS4,
                ta5914_filename: &G_SETTINGS4_TA,
                alt_test_name: Some("4.8.1.4"),
                expected_error: None,
            });
    }
    {
        //4.8.2
        let target_file_name = "AllCertificatesNoPoliciesTest2EE.crt";
        let intermediate_ca_file_names = vec!["NoPolicies"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.8.2.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "AllCertificatesNoPoliciesTest2EE.crt";
        let intermediate_ca_file_names = vec!["NoPolicies"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS1,
                ta5914_filename: &G_SETTINGS1_TA,
                alt_test_name: Some("4.8.2.2"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.8.3
        let target_file_name = "DifferentPoliciesTest3EE.crt";
        let intermediate_ca_file_names = vec!["Good", "PoliciesP2sub"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.8.3.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "DifferentPoliciesTest3EE.crt";
        let intermediate_ca_file_names = vec!["Good", "PoliciesP2sub"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS1,
                ta5914_filename: &G_SETTINGS1_TA,
                alt_test_name: Some("4.8.3.2"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "DifferentPoliciesTest3EE.crt";
        let intermediate_ca_file_names = vec!["Good", "PoliciesP2sub"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS4,
                ta5914_filename: &G_SETTINGS4_TA,
                alt_test_name: Some("4.8.3.3"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.8.4
        let target_file_name = "DifferentPoliciesTest4EE.crt";
        let intermediate_ca_file_names = vec!["Good", "Goodsub"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.8.4"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.8.5
        let target_file_name = "DifferentPoliciesTest5EE.crt";
        let intermediate_ca_file_names = vec!["Good", "PoliciesP2subCA2"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.8.5"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.8.6
        let target_file_name = "OverlappingPoliciesTest6EE.crt";
        let intermediate_ca_file_names = vec![
            "PoliciesP1234",
            "PoliciesP1234subCAP123",
            "PoliciesP1234subsubCAP123P12",
        ];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.8.6.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "OverlappingPoliciesTest6EE.crt";
        let intermediate_ca_file_names = vec![
            "PoliciesP1234",
            "PoliciesP1234subCAP123",
            "PoliciesP1234subsubCAP123P12",
        ];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS5,
                ta5914_filename: &G_SETTINGS5_TA,
                alt_test_name: Some("4.8.6.2"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "OverlappingPoliciesTest6EE.crt";
        let intermediate_ca_file_names = vec![
            "PoliciesP1234",
            "PoliciesP1234subCAP123",
            "PoliciesP1234subsubCAP123P12",
        ];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS6,
                ta5914_filename: &G_SETTINGS6_TA,
                alt_test_name: Some("4.8.6.3"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.8.7
        let target_file_name = "DifferentPoliciesTest7EE.crt";
        let intermediate_ca_file_names = vec![
            "PoliciesP123",
            "PoliciesP123subCAP12",
            "PoliciesP123subsubCAP12P1",
        ];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.8.7"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.8.8
        let target_file_name = "DifferentPoliciesTest8EE.crt";
        let intermediate_ca_file_names = vec![
            "PoliciesP12",
            "PoliciesP12subCAP1",
            "PoliciesP12subsubCAP1P2",
        ];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.8.8"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.8.9
        let target_file_name = "DifferentPoliciesTest9EE.crt";
        let intermediate_ca_file_names = vec![
            "PoliciesP123",
            "PoliciesP123subCAP12",
            "PoliciesP123subsubCAP12P2",
            "PoliciesP123subsubsubCAP12P2P1",
        ];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.8.9"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.8.10
        let target_file_name = "AllCertificatesSamePoliciesTest10EE.crt";
        let intermediate_ca_file_names = vec!["PoliciesP12"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.8.10.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "AllCertificatesSamePoliciesTest10EE.crt";
        let intermediate_ca_file_names = vec!["PoliciesP12"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS5,
                ta5914_filename: &G_SETTINGS5_TA,
                alt_test_name: Some("4.8.10.2"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "AllCertificatesSamePoliciesTest10EE.crt";
        let intermediate_ca_file_names = vec!["PoliciesP12"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS5,
                ta5914_filename: &G_SETTINGS5_TA,
                alt_test_name: Some("4.8.10.3"),
                expected_error: None,
            });
    }
    {
        //4.8.11
        let target_file_name = "AllCertificatesanyPolicyTest11EE.crt";
        let intermediate_ca_file_names = vec!["anyPolicy"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.8.11.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "AllCertificatesanyPolicyTest11EE.crt";
        let intermediate_ca_file_names = vec!["anyPolicy"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS5,
                ta5914_filename: &G_SETTINGS5_TA,
                alt_test_name: Some("4.8.11.2"),
                expected_error: None,
            });
    }
    {
        //4.8.12
        let target_file_name = "DifferentPoliciesTest12EE.crt";
        let intermediate_ca_file_names = vec!["PoliciesP3"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.8.12"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.8.13
        let target_file_name = "AllCertificatesSamePoliciesTest13EE.crt";
        let intermediate_ca_file_names = vec!["PoliciesP123"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS5,
                ta5914_filename: &G_SETTINGS5_TA,
                alt_test_name: Some("4.8.13.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "AllCertificatesSamePoliciesTest13EE.crt";
        let intermediate_ca_file_names = vec!["PoliciesP123"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS6,
                ta5914_filename: &G_SETTINGS6_TA,
                alt_test_name: Some("4.8.13.2"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "AllCertificatesSamePoliciesTest13EE.crt";
        let intermediate_ca_file_names = vec!["PoliciesP123"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS7,
                ta5914_filename: &G_SETTINGS7_TA,
                alt_test_name: Some("4.8.13.3"),
                expected_error: None,
            });
    }
    {
        //4.8.14
        let target_file_name = "AnyPolicyTest14EE.crt";
        let intermediate_ca_file_names = vec!["anyPolicy"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS5,
                ta5914_filename: &G_SETTINGS5_TA,
                alt_test_name: Some("4.8.14.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "AnyPolicyTest14EE.crt";
        let intermediate_ca_file_names = vec!["anyPolicy"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS6,
                ta5914_filename: &G_SETTINGS6_TA,
                alt_test_name: Some("4.8.14.2"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.8.15
        let target_file_name = "UserNoticeQualifierTest15EE.crt";
        let intermediate_ca_file_names = vec![];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.8.15"),
                expected_error: None,
            });
    }
    {
        //4.8.16
        let target_file_name = "UserNoticeQualifierTest16EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.8.16"),
                expected_error: None,
            });
    }
    {
        //4.8.17
        let target_file_name = "UserNoticeQualifierTest17EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.8.17"),
                expected_error: None,
            });
    }
    {
        //4.8.18
        let target_file_name = "UserNoticeQualifierTest18EE.crt";
        let intermediate_ca_file_names = vec!["PoliciesP12"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS5,
                ta5914_filename: &G_SETTINGS5_TA,
                alt_test_name: Some("4.8.18.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "UserNoticeQualifierTest18EE.crt";
        let intermediate_ca_file_names = vec!["PoliciesP12"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS6,
                ta5914_filename: &G_SETTINGS6_TA,
                alt_test_name: Some("4.8.18.2"),
                expected_error: None,
            });
    }
    {
        //4.8.19
        let target_file_name = "UserNoticeQualifierTest19EE.crt";
        let intermediate_ca_file_names = vec![];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS6,
                ta5914_filename: &G_SETTINGS6_TA,
                alt_test_name: Some("4.8.19"),
                expected_error: None,
            });
    }
    {
        //4.8.20
        let target_file_name = "CPSPointerQualifierTest20EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.8.20.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "CPSPointerQualifierTest20EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.8")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS1,
                ta5914_filename: &G_SETTINGS1_TA,
                alt_test_name: Some("4.8.20.2"),
                expected_error: None,
            });
    }

    //-----------------------------------------------------------------------------
    //Section 4.9 - require explicit policy - 8 tests
    //-----------------------------------------------------------------------------
    {
        let target_file_name = "ValidrequireExplicitPolicyTest1EE.crt";
        let intermediate_ca_file_names = vec![
            "requireExplicitPolicy10",
            "requireExplicitPolicy10sub",
            "requireExplicitPolicy10subsub",
            "requireExplicitPolicy10subsubsub",
        ];
        pkits_data_map
            .entry("4.9")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidrequireExplicitPolicyTest2EE.crt";
        let intermediate_ca_file_names = vec![
            "requireExplicitPolicy5",
            "requireExplicitPolicy5sub",
            "requireExplicitPolicy5subsub",
            "requireExplicitPolicy5subsubsub",
        ];
        pkits_data_map
            .entry("4.9")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidrequireExplicitPolicyTest3EE.crt";
        let intermediate_ca_file_names = vec![
            "requireExplicitPolicy4",
            "requireExplicitPolicy4sub",
            "requireExplicitPolicy4subsub",
            "requireExplicitPolicy4subsubsub",
        ];
        pkits_data_map
            .entry("4.9")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "ValidrequireExplicitPolicyTest4EE.crt";
        let intermediate_ca_file_names = vec![
            "requireExplicitPolicy0",
            "requireExplicitPolicy0sub",
            "requireExplicitPolicy0subsub",
            "requireExplicitPolicy0subsubsub",
        ];
        pkits_data_map
            .entry("4.9")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidrequireExplicitPolicyTest5EE.crt";
        let intermediate_ca_file_names = vec![
            "requireExplicitPolicy7",
            "requireExplicitPolicy7subCARE2",
            "requireExplicitPolicy7subsubCARE2RE4",
            "requireExplicitPolicy7subsubsubCARE2RE4",
        ];
        pkits_data_map
            .entry("4.9")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "ValidSelfIssuedrequireExplicitPolicyTest6EE.crt";
        let intermediate_ca_file_names =
            vec!["requireExplicitPolicy2", "requireExplicitPolicy2SelfIssued"];
        pkits_data_map
            .entry("4.9")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidSelfIssuedrequireExplicitPolicyTest7EE.crt";
        let intermediate_ca_file_names = vec![
            "requireExplicitPolicy2",
            "requireExplicitPolicy2SelfIssued",
            "requireExplicitPolicy2sub",
        ];
        pkits_data_map
            .entry("4.9")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "InvalidSelfIssuedrequireExplicitPolicyTest8EE.crt";
        let intermediate_ca_file_names = vec![
            "requireExplicitPolicy2",
            "requireExplicitPolicy2SelfIssued",
            "requireExplicitPolicy2sub",
            "requireExplicitPolicy2SelfIssuedsub",
        ];
        pkits_data_map
            .entry("4.9")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::NullPolicySet),
            });
    }
    //-----------------------------------------------------------------------------
    //Section 4.10 - policy mapping - 14 tests
    //-----------------------------------------------------------------------------
    {
        //4.10.1
        let target_file_name = "ValidPolicyMappingTest1EE.crt";
        let intermediate_ca_file_names = vec!["Mapping1to2"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS5,
                ta5914_filename: &G_SETTINGS5_TA,
                alt_test_name: Some("4.10.1.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidPolicyMappingTest1EE.crt";
        let intermediate_ca_file_names = vec!["Mapping1to2"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS6,
                ta5914_filename: &G_SETTINGS6_TA,
                alt_test_name: Some("4.10.1.2"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "ValidPolicyMappingTest1EE.crt";
        let intermediate_ca_file_names = vec!["Mapping1to2"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS8,
                ta5914_filename: &G_SETTINGS8_TA,
                alt_test_name: Some("4.10.1.3"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.10.2
        let target_file_name = "InvalidPolicyMappingTest2EE.crt";
        let intermediate_ca_file_names = vec!["Mapping1to2"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.10.2.1"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "InvalidPolicyMappingTest2EE.crt";
        let intermediate_ca_file_names = vec!["Mapping1to2"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS8,
                ta5914_filename: &G_SETTINGS8_TA,
                alt_test_name: Some("4.10.2.2"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.10.3
        let target_file_name = "ValidPolicyMappingTest3EE.crt";
        let intermediate_ca_file_names = vec![
            "P12Mapping1to3",
            "P12Mapping1to3sub",
            "P12Mapping1to3subsub",
        ];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS5,
                ta5914_filename: &G_SETTINGS5_TA,
                alt_test_name: Some("4.10.3.1"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "ValidPolicyMappingTest3EE.crt";
        let intermediate_ca_file_names = vec![
            "P12Mapping1to3",
            "P12Mapping1to3sub",
            "P12Mapping1to3subsub",
        ];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS6,
                ta5914_filename: &G_SETTINGS6_TA,
                alt_test_name: Some("4.10.3.2"),
                expected_error: None,
            });
    }
    {
        //4.10.4
        let target_file_name = "InvalidPolicyMappingTest4EE.crt";
        let intermediate_ca_file_names = vec![
            "P12Mapping1to3",
            "P12Mapping1to3sub",
            "P12Mapping1to3subsub",
        ];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS5,
                ta5914_filename: &G_SETTINGS5_TA,
                alt_test_name: Some("4.10.4"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.10.5
        let target_file_name = "ValidPolicyMappingTest5EE.crt";
        let intermediate_ca_file_names = vec!["P1Mapping1to234", "P1Mapping1to234sub"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS5,
                ta5914_filename: &G_SETTINGS5_TA,
                alt_test_name: Some("4.10.5.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidPolicyMappingTest5EE.crt";
        let intermediate_ca_file_names = vec!["P1Mapping1to234", "P1Mapping1to234sub"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS9,
                ta5914_filename: &G_SETTINGS9_TA,
                alt_test_name: Some("4.10.5.2"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.10.6
        let target_file_name = "ValidPolicyMappingTest6EE.crt";
        let intermediate_ca_file_names = vec!["P1Mapping1to234", "P1Mapping1to234sub"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS5,
                ta5914_filename: &G_SETTINGS5_TA,
                alt_test_name: Some("4.10.6.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidPolicyMappingTest6EE.crt";
        let intermediate_ca_file_names = vec!["P1Mapping1to234", "P1Mapping1to234sub"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS9,
                ta5914_filename: &G_SETTINGS9_TA,
                alt_test_name: Some("4.10.6.2"),
                expected_error: Some(Error::NullPolicySet),
            });
    }

    {
        //4.10.7
        let target_file_name = "InvalidMappingFromanyPolicyTest7EE.crt";
        let intermediate_ca_file_names = vec!["MappingFromanyPolicy"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.10.7"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.10.8
        let target_file_name = "InvalidMappingToanyPolicyTest8EE.crt";
        let intermediate_ca_file_names = vec!["MappingToanyPolicy"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.10.8"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.10.9
        let target_file_name = "ValidPolicyMappingTest9EE.crt";
        let intermediate_ca_file_names = vec!["PanyPolicyMapping1to2"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.10.9"),
                expected_error: None,
            });
    }
    {
        //4.10.10
        let target_file_name = "InvalidPolicyMappingTest10EE.crt";
        let intermediate_ca_file_names = vec!["Good", "GoodsubCAPanyPolicyMapping1to2"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.10.10"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        //4.10.12
        let target_file_name = "ValidPolicyMappingTest12EE.crt";
        let intermediate_ca_file_names = vec!["P12Mapping1to3"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS5,
                ta5914_filename: &G_SETTINGS5_TA,
                alt_test_name: Some("4.10.12.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidPolicyMappingTest12EE.crt";
        let intermediate_ca_file_names = vec!["P12Mapping1to3"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS6,
                ta5914_filename: &G_SETTINGS6_TA,
                alt_test_name: Some("4.10.12.2"),
                expected_error: None,
            });
    }
    {
        //4.10.13
        let target_file_name = "ValidPolicyMappingTest13EE.crt";
        let intermediate_ca_file_names = vec!["P1anyPolicyMapping1to2"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.10.13"),
                expected_error: None,
            });
    }
    {
        //4.10.14
        let target_file_name = "ValidPolicyMappingTest14EE.crt";
        let intermediate_ca_file_names = vec!["P1anyPolicyMapping1to2"];
        pkits_data_map
            .entry("4.10")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.10.14"),
                expected_error: None,
            });
    }

    //-----------------------------------------------------------------------------
    //Section 4.11 - inhibit policy mapping - 11 tests
    //-----------------------------------------------------------------------------
    {
        //4.11
        let target_file_name = "InvalidinhibitPolicyMappingTest1EE.crt";
        let intermediate_ca_file_names = vec!["inhibitPolicyMapping0", "inhibitPolicyMapping0sub"];
        pkits_data_map
            .entry("4.11")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "ValidinhibitPolicyMappingTest2EE.crt";
        let intermediate_ca_file_names =
            vec!["inhibitPolicyMapping1P12", "inhibitPolicyMapping1P12sub"];
        pkits_data_map
            .entry("4.11")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidinhibitPolicyMappingTest3EE.crt";
        let intermediate_ca_file_names = vec![
            "inhibitPolicyMapping1P12",
            "inhibitPolicyMapping1P12sub",
            "inhibitPolicyMapping1P12subsub",
        ];
        pkits_data_map
            .entry("4.11")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "ValidinhibitPolicyMappingTest4EE.crt";
        let intermediate_ca_file_names = vec![
            "inhibitPolicyMapping1P12",
            "inhibitPolicyMapping1P12sub",
            "inhibitPolicyMapping1P12subsub",
        ];
        pkits_data_map
            .entry("4.11")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidinhibitPolicyMappingTest5EE.crt";
        let intermediate_ca_file_names = vec![
            "inhibitPolicyMapping5",
            "inhibitPolicyMapping5sub",
            "inhibitPolicyMapping5subsub",
            "inhibitPolicyMapping5subsubsub",
        ];
        pkits_data_map
            .entry("4.11")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "InvalidinhibitPolicyMappingTest6EE.crt";
        let intermediate_ca_file_names = vec![
            "inhibitPolicyMapping1P12",
            "inhibitPolicyMapping1P12subCAIPM5",
            "inhibitPolicyMapping1P12subsubCAIPM5",
        ];
        pkits_data_map
            .entry("4.11")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "ValidSelfIssuedinhibitPolicyMappingTest7EE.crt";
        let intermediate_ca_file_names = vec![
            "inhibitPolicyMapping1P1",
            "inhibitPolicyMapping1P1SelfIssued",
            "inhibitPolicyMapping1P1sub",
        ];
        pkits_data_map
            .entry("4.11")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidSelfIssuedinhibitPolicyMappingTest8EE.crt";
        let intermediate_ca_file_names = vec![
            "inhibitPolicyMapping1P1",
            "inhibitPolicyMapping1P1SelfIssued",
            "inhibitPolicyMapping1P1sub",
            "inhibitPolicyMapping1P1subsub",
        ];
        pkits_data_map
            .entry("4.11")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "InvalidSelfIssuedinhibitPolicyMappingTest9EE.crt";
        let intermediate_ca_file_names = vec![
            "inhibitPolicyMapping1P1",
            "inhibitPolicyMapping1P1SelfIssued",
            "inhibitPolicyMapping1P1sub",
            "inhibitPolicyMapping1P1subsub",
        ];
        pkits_data_map
            .entry("4.11")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "InvalidSelfIssuedinhibitPolicyMappingTest10EE.crt";
        let intermediate_ca_file_names = vec![
            "inhibitPolicyMapping1P1",
            "inhibitPolicyMapping1P1SelfIssued",
            "inhibitPolicyMapping1P1sub",
            "inhibitPolicyMapping1P1SelfIssuedsub",
        ];
        pkits_data_map
            .entry("4.11")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "InvalidSelfIssuedinhibitPolicyMappingTest11EE.crt";
        let intermediate_ca_file_names = vec![
            "inhibitPolicyMapping1P1",
            "inhibitPolicyMapping1P1SelfIssued",
            "inhibitPolicyMapping1P1sub",
            "inhibitPolicyMapping1P1SelfIssuedsub",
        ];
        pkits_data_map
            .entry("4.11")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::NullPolicySet),
            });
    }

    //-----------------------------------------------------------------------------
    //Section 4.12 - inhibit any policy - 10 tests
    //-----------------------------------------------------------------------------
    {
        let target_file_name = "InvalidinhibitAnyPolicyTest1EE.crt";
        let intermediate_ca_file_names = vec!["inhibitAnyPolicy0"];
        pkits_data_map
            .entry("4.12")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "ValidinhibitAnyPolicyTest2EE.crt";
        let intermediate_ca_file_names = vec!["inhibitAnyPolicy0"];
        pkits_data_map
            .entry("4.12")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "inhibitAnyPolicyTest3EE.crt";
        let intermediate_ca_file_names = vec!["inhibitAnyPolicy1", "inhibitAnyPolicy1subCA1"];
        pkits_data_map
            .entry("4.12")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.12.3.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "inhibitAnyPolicyTest3EE.crt";
        let intermediate_ca_file_names = vec!["inhibitAnyPolicy1", "inhibitAnyPolicy1subCA1"];
        pkits_data_map
            .entry("4.12")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_SETTINGS10,
                ta5914_filename: &G_SETTINGS10_TA,
                alt_test_name: Some("4.12.3.2"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "InvalidinhibitAnyPolicyTest4EE.crt";
        let intermediate_ca_file_names = vec!["inhibitAnyPolicy1", "inhibitAnyPolicy1subCA1"];
        pkits_data_map
            .entry("4.12")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.12.4"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "InvalidinhibitAnyPolicyTest5EE.crt";
        let intermediate_ca_file_names = vec![
            "inhibitAnyPolicy5",
            "inhibitAnyPolicy5sub",
            "inhibitAnyPolicy5subsub",
        ];
        pkits_data_map
            .entry("4.12")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.12.5"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "InvalidinhibitAnyPolicyTest6EE.crt";
        let intermediate_ca_file_names = vec!["inhibitAnyPolicy1", "inhibitAnyPolicy1subCAIAP5"];
        pkits_data_map
            .entry("4.12")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.12.6"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "ValidSelfIssuedinhibitAnyPolicyTest7EE.crt";
        let intermediate_ca_file_names = vec![
            "inhibitAnyPolicy1",
            "inhibitAnyPolicy1SelfIssued",
            "inhibitAnyPolicy1subCA2",
        ];
        pkits_data_map
            .entry("4.12")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.12.7"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidSelfIssuedinhibitAnyPolicyTest8EE.crt";
        let intermediate_ca_file_names = vec![
            "inhibitAnyPolicy1",
            "inhibitAnyPolicy1SelfIssued",
            "inhibitAnyPolicy1subCA2",
            "inhibitAnyPolicy1subsubCA2",
        ];
        pkits_data_map
            .entry("4.12")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.12.8"),
                expected_error: Some(Error::NullPolicySet),
            });
    }
    {
        let target_file_name = "ValidSelfIssuedinhibitAnyPolicyTest9EE.crt";
        let intermediate_ca_file_names = vec![
            "inhibitAnyPolicy1",
            "inhibitAnyPolicy1SelfIssued",
            "inhibitAnyPolicy1subCA2",
            "inhibitAnyPolicy1SelfIssuedsubCA2",
        ];
        pkits_data_map
            .entry("4.12")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.12.9"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidSelfIssuedinhibitAnyPolicyTest10EE.crt";
        let intermediate_ca_file_names = vec![
            "inhibitAnyPolicy1",
            "inhibitAnyPolicy1SelfIssued",
            "inhibitAnyPolicy1subCA2",
        ];
        pkits_data_map
            .entry("4.12")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.12.10"),
                expected_error: Some(Error::NullPolicySet),
            });
    }

    //-----------------------------------------------------------------------------
    //Section 4.16 - private certificate extensions - 2 tests
    //-----------------------------------------------------------------------------
    {
        let target_file_name = "ValidUnknownNotCriticalCertificateExtensionTest1EE.crt";
        let intermediate_ca_file_names = vec![];
        pkits_data_map
            .entry("4.16")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidUnknownCriticalCertificateExtensionTest2EE.crt";
        let intermediate_ca_file_names = vec![];
        pkits_data_map
            .entry("4.16")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::UnprocessedCriticalExtension),
            });
    }

    //-----------------------------------------------------------------------------
    //Section 4.13 - name constraints - 38 tests
    //-----------------------------------------------------------------------------
    {
        let target_file_name = "ValidDNnameConstraintsTest1EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN1"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.1"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidDNnameConstraintsTest2EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN1"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.2"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "InvalidDNnameConstraintsTest3EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN1"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.3"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "ValidDNnameConstraintsTest4EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN1"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.4"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidDNnameConstraintsTest5EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN2"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.5"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidDNnameConstraintsTest6EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN3"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.6"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidDNnameConstraintsTest7EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN3"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.7"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "InvalidDNnameConstraintsTest8EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN4"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.8"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "InvalidDNnameConstraintsTest9EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN4"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.9"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "InvalidDNnameConstraintsTest10EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN5"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.10"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "ValidDNnameConstraintsTest11EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN5"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.11"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidDNnameConstraintsTest12EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN1", "nameConstraintsDN1subCA1"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.12"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "InvalidDNnameConstraintsTest13EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN1", "nameConstraintsDN1subCA2"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.13"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "ValidDNnameConstraintsTest14EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN1", "nameConstraintsDN1subCA2"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.14"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidDNnameConstraintsTest15EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN3", "nameConstraintsDN3subCA1"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.15"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "InvalidDNnameConstraintsTest16EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN3", "nameConstraintsDN3subCA1"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.16"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "InvalidDNnameConstraintsTest17EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN3", "nameConstraintsDN3subCA2"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.17"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "ValidDNnameConstraintsTest18EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN3", "nameConstraintsDN3subCA2"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.18"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "ValidDNnameConstraintsTest19EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN1", "nameConstraintsDN1SelfIssued"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.19"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidDNnameConstraintsTest20EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN1", "nameConstraintsDN1SelfIssued"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.20"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }

    {
        let target_file_name = "ValidRFC822nameConstraintsTest21EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsRFC822CA1"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.21"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidRFC822nameConstraintsTest22EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsRFC822CA1"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.22"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "ValidRFC822nameConstraintsTest23EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsRFC822CA2"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.23"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidRFC822nameConstraintsTest24EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsRFC822CA2"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.24"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "ValidRFC822nameConstraintsTest25EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsRFC822CA3"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.25"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidRFC822nameConstraintsTest26EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsRFC822CA3"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.26"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "ValidDNandRFC822nameConstraintsTest27EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN1", "nameConstraintsDN1subCA3"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.27"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidDNandRFC822nameConstraintsTest28EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDN1", "nameConstraintsDN1subCA3"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.28"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    // {
    //     // Not supporting email addresses read from DNs
    //     let target_file_name = "InvalidDNandRFC822nameConstraintsTest29EE.crt";
    //     let intermediate_ca_file_names = vec!["nameConstraintsDN1", "nameConstraintsDN1subCA3"];
    //     pkits_data_map
    //         .entry("4.13")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.13.29"),
    //             expected_error: None,
    //         });
    // }
    {
        let target_file_name = "ValidDNSnameConstraintsTest30EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDNS1"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.30"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidDNSnameConstraintsTest31EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDNS1"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.31"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "ValidDNSnameConstraintsTest32EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDNS2"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.32"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidDNSnameConstraintsTest33EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDNS2"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.33"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "ValidURInameConstraintsTest34EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsURI1"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.34"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidURInameConstraintsTest35EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsURI1"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.35"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "ValidURInameConstraintsTest36EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsURI2"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.36"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidURInameConstraintsTest37EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsURI2"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.37"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
    {
        let target_file_name = "InvalidDNSnameConstraintsTest38EE.crt";
        let intermediate_ca_file_names = vec!["nameConstraintsDNS1"];
        pkits_data_map
            .entry("4.13")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.13.38"),
                expected_error: Some(Error::NameConstraintsViolation),
            });
    }
}

// Only 2048 and 256 are supported in test so far owing to lack of 384 support in Rust and lack
// of suitable 4096 PKITS data set.
pub enum PkitsFlavor {
    PkitsRsa2048,
    PkitsRsa4096,
    PkitsP256,
    PkitsP384,
}

#[test]
fn pkits_p256() {
    let mut pool = CertPool {
        certs: BTreeMap::new(),
    };

    let mut pkits_data_map = PkitsDataMap::new();
    load_pkits(&mut pkits_data_map);

    let mut pe = PkiEnvironment::new();
    populate_5280_pki_environment(&mut pe);
    pkits_guts(&mut pool, &pkits_data_map, &pe, PkitsFlavor::PkitsP256);
}

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
            ta_source2.buffers.push(CertFile {
                filename: "TrustAnchorRootCertificate.crt".to_string(),
                bytes: der_encoded_ta,
            });
        }
    }

    populate_parsed_ta_vector(&ta_source2.buffers, &mut ta_source2.tas);

    {
        let mut pe = PkiEnvironment::new();
        populate_5280_pki_environment(&mut pe);
        pe.add_trust_anchor_source(&ta_source2);
        pkits_guts(&mut pool, &pkits_data_map, &pe, PkitsFlavor::PkitsRsa2048);
    }
}

pub fn pkits_guts(
    mpool: &mut CertPool,
    pkits_data_map: &PkitsDataMap,
    pe: &PkiEnvironment,
    flavor: PkitsFlavor,
) {
    // all tests share common trust anchor so add it to the pool
    let der_encoded_ta = match flavor {
        PkitsFlavor::PkitsRsa2048 => {
            { get_pkits_cert_bytes("TrustAnchorRootCertificate.crt") }.unwrap()
        }
        PkitsFlavor::PkitsRsa4096 => {
            { get_pkits_cert_bytes_4096("TrustAnchorRootCertificate.crt") }.unwrap()
        }
        PkitsFlavor::PkitsP256 => {
            { get_pkits_cert_bytes_p256("TrustAnchorRootCertificate.crt") }.unwrap()
        }
        PkitsFlavor::PkitsP384 => {
            { get_pkits_cert_bytes_p384("TrustAnchorRootCertificate.crt") }.unwrap()
        }
    };

    if !mpool.certs.contains_key("TrustAnchorRootCertificate.crt") {
        mpool
            .certs
            .insert("TrustAnchorRootCertificate.crt".to_string(), der_encoded_ta);
    }

    let exts_of_interest = [
        &PKIX_CE_SUBJECT_KEY_IDENTIFIER,
        &PKIX_CE_AUTHORITY_KEY_IDENTIFIER,
        &PKIX_CE_BASIC_CONSTRAINTS,
        &PKIX_CE_NAME_CONSTRAINTS,
        &PKIX_CE_SUBJECT_ALT_NAME,
        &PKIX_CE_EXTKEYUSAGE,
        &PKIX_CE_KEY_USAGE,
        &PKIX_CE_POLICY_CONSTRAINTS,
        &PKIX_CE_CERTIFICATE_POLICIES,
        &PKIX_CE_POLICY_MAPPINGS,
        &PKIX_CE_INHIBIT_ANY_POLICY,
    ];

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
                PkitsFlavor::PkitsRsa4096 => {
                    { get_pkits_cert_bytes_4096(case.target_file_name) }.unwrap()
                }
                PkitsFlavor::PkitsP256 => {
                    { get_pkits_cert_bytes_p256(case.target_file_name) }.unwrap()
                }
                PkitsFlavor::PkitsP384 => {
                    { get_pkits_cert_bytes_p384(case.target_file_name) }.unwrap()
                }
            };
            mpool
                .certs
                .insert(case.target_file_name.to_string(), der_encoded_ee);
            for ca_file in &case.intermediate_ca_file_names {
                let der_encoded_ca = match flavor {
                    PkitsFlavor::PkitsRsa2048 => { get_pkits_ca_cert_bytes(ca_file) }.unwrap(),
                    PkitsFlavor::PkitsRsa4096 => { get_pkits_ca_cert_bytes_4096(ca_file) }.unwrap(),
                    PkitsFlavor::PkitsP256 => { get_pkits_ca_cert_bytes_p256(ca_file) }.unwrap(),
                    PkitsFlavor::PkitsP384 => { get_pkits_ca_cert_bytes_p384(ca_file) }.unwrap(),
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

            println!("{}", case_name);
            let mut decoder =
                Decoder::new(pool.certs["TrustAnchorRootCertificate.crt"].as_slice()).unwrap();
            let header = decoder.peek_header().unwrap();
            let tac = TrustAnchorChoice::decode_value(&mut decoder, header.length).unwrap();
            let ta = PDVTrustAnchorChoice {
                encoded_ta: pool.certs["TrustAnchorRootCertificate.crt"].as_slice(),
                decoded_ta: tac,
                metadata: None,
                parsed_extensions: ParsedExtensions::new(),
            };

            let r_ee_cert = Certificate::from_der(pool.certs[case.target_file_name].as_slice());
            let ee_cert = match r_ee_cert {
                Ok(ee_cert) => ee_cert,
                Err(err) => {
                    let k = err.kind();
                    println!("{}: {}", k, err);
                    continue;
                }
            };
            let mut ee = PDVCertificate {
                encoded_cert: pool.certs[case.target_file_name].as_slice(),
                decoded_cert: ee_cert,
                metadata: None,
                parsed_extensions: ParsedExtensions::new(),
            };
            ee.parse_extensions(&exts_of_interest);

            let mut chain = vec![];
            let mut cpool = vec![];

            {
                for ca_file in &case.intermediate_ca_file_names {
                    // let der_encoded_ca = get_pkits_ca_cert_bytes(ca_file).unwrap();
                    // pool.certs.push(der_encoded_ca);
                    let ca_cert = Certificate::from_der(pool.certs[*ca_file].as_slice()).unwrap();
                    let mut ca = PDVCertificate {
                        encoded_cert: pool.certs[*ca_file].as_slice(),
                        decoded_cert: ca_cert,
                        metadata: None,
                        parsed_extensions: ParsedExtensions::new(),
                    };
                    ca.parse_extensions(&exts_of_interest);

                    cpool.push(ca);
                }

                for i in 0..case.intermediate_ca_file_names.len() {
                    chain.push(&cpool[i]);
                }

                let mut cert_path = CertificationPath {
                    target: &ee,
                    intermediates: chain,
                    trust_anchor: &ta,
                };

                let mut cpr = CertificationPathResults::new();
                let r = pe.validate_path(&pe, case.settings, &mut cert_path, &mut cpr);
                if (r.is_err() && case.expected_error.is_none())
                    || (r.is_ok() && case.expected_error.is_some())
                {
                    println!("Unexpected result for {}", case_name);
                }

                // TODO fix or skip for EC
                // let der_encoded_ta5914 = get_pkits_ta5914_bytes(case.ta5914_filename).unwrap();
                // let mut decoder = Decoder::new(der_encoded_ta5914.as_slice()).unwrap();
                // let header = decoder.peek_header().unwrap();
                // let tac5914 = TrustAnchorChoice::decode_value(&mut decoder, header.length).unwrap();
                // let mut ta5914 = PDVTrustAnchorChoice {
                //     encoded_ta: der_encoded_ta5914.as_slice(),
                //     decoded_ta: tac5914,
                //     metadata: None,
                //     parsed_extensions: ParsedExtensions::new(),
                // };
                // ta5914
                //     .parse_extensions(&[&PKIX_CE_CERTIFICATE_POLICIES, &PKIX_CE_NAME_CONSTRAINTS]);
                //
                // // validate again with settings supplied by 5914 formatted TA
                // let mut cpr = CertificationPathResults::new();
                // let mut m = G_DEFAULT_SETTINGS_5914.clone();
                //
                // let m = enforce_trust_anchor_constraints(&G_DEFAULT_SETTINGS_5914, &ta5914, &mut m);
                // let mut cert_path2 = CertificationPath {
                //     target: cert_path.target,
                //     intermediates: cert_path.intermediates,
                //     trust_anchor: ta5914.clone(),
                // };
                // if let Ok(mod_cps) = m {
                //     let r = pe.validate_path(&pe, &mod_cps, &mut cert_path2, &mut cpr);
                //     if (r.is_err() && case.expected_error.is_none())
                //         || (r.is_ok() && case.expected_error.is_some())
                //     {
                //         println!("Unexpected result for {} with TA enforcement", case_name);
                //     }
                // }
            }
        }
    }
}
