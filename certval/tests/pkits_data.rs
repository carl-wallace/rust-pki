use certval::*;
use certval::{CertificationPathSettings, Error};
use der::asn1::ObjectIdentifier;

use lazy_static::lazy_static;

use alloc::collections::BTreeMap;
extern crate alloc;

use certval::PathValidationStatus::{CertificateRevoked, RevocationStatusNotDetermined};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct PkitsTestCase<'a> {
    pub intermediate_ca_file_names: Vec<&'a str>,
    pub target_file_name: &'a str,
    pub settings: &'a CertificationPathSettings,
    pub ta5914_filename: &'a str,
    pub alt_test_name: Option<&'a str>,
    pub expected_error: Option<Error>,
}

// The PkitsDataMap structure is used to group tests by section number. The key into each is a
// string representing a section in the NIST PKITS doc. The corresponding vector accumulates
// PkitTestCase or CertificationPathSettings for each test case in the section identified by the key.
pub type PkitsDataMap<'a> = BTreeMap<&'a str, Vec<PkitsTestCase<'a>>>;

// Policy OIDs used by PKITS test cases
pub const PKITS_TEST_POLICY_1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.1");
pub const PKITS_TEST_POLICY_2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.2");
pub const PKITS_TEST_POLICY_3: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.3");
#[allow(dead_code)]
pub const PKITS_TEST_POLICY_4: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.4");
#[allow(dead_code)]
pub const PKITS_TEST_POLICY_5: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.5");
pub const PKITS_TEST_POLICY_6: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.2.1.48.6");

#[cfg(feature = "std")]
#[test]
fn serialize_pkits_settings() {
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();

    let cps = G_SETTINGS1.clone();
    let json_ps = serde_json::to_string(&cps).unwrap();
    let results_path = temp_dir.path().join("settings1.txt");
    let mut f = File::create(results_path).unwrap();
    f.write_all(json_ps.as_bytes()).unwrap();

    let cps = G_SETTINGS2.clone();
    let json_ps = serde_json::to_string(&cps).unwrap();
    let results_path = temp_dir.path().join("settings2.txt");
    let mut f = File::create(results_path).unwrap();
    f.write_all(json_ps.as_bytes()).unwrap();

    let cps = G_SETTINGS3.clone();
    let json_ps = serde_json::to_string(&cps).unwrap();
    let results_path = temp_dir.path().join("settings3.txt");
    let mut f = File::create(results_path).unwrap();
    f.write_all(json_ps.as_bytes()).unwrap();

    let cps = G_SETTINGS4.clone();
    let json_ps = serde_json::to_string(&cps).unwrap();
    let results_path = temp_dir.path().join("settings4.txt");
    let mut f = File::create(results_path).unwrap();
    f.write_all(json_ps.as_bytes()).unwrap();

    let cps = G_SETTINGS5.clone();
    let json_ps = serde_json::to_string(&cps).unwrap();
    let results_path = temp_dir.path().join("settings5.txt");
    let mut f = File::create(results_path).unwrap();
    f.write_all(json_ps.as_bytes()).unwrap();

    let cps = G_SETTINGS6.clone();
    let json_ps = serde_json::to_string(&cps).unwrap();
    let results_path = temp_dir.path().join("settings6.txt");
    let mut f = File::create(results_path).unwrap();
    f.write_all(json_ps.as_bytes()).unwrap();

    let cps = G_SETTINGS7.clone();
    let json_ps = serde_json::to_string(&cps).unwrap();
    let results_path = temp_dir.path().join("settings7.txt");
    let mut f = File::create(results_path).unwrap();
    f.write_all(json_ps.as_bytes()).unwrap();

    let cps = G_SETTINGS8.clone();
    let json_ps = serde_json::to_string(&cps).unwrap();
    let results_path = temp_dir.path().join("settings8.txt");
    let mut f = File::create(results_path).unwrap();
    f.write_all(json_ps.as_bytes()).unwrap();

    let cps = G_SETTINGS9.clone();
    let json_ps = serde_json::to_string(&cps).unwrap();
    let results_path = temp_dir.path().join("settings9.txt");
    let mut f = File::create(results_path).unwrap();
    f.write_all(json_ps.as_bytes()).unwrap();

    let cps = G_SETTINGS10.clone();
    let json_ps = serde_json::to_string(&cps).unwrap();
    let results_path = temp_dir.path().join("settings10.txt");
    let mut f = File::create(results_path).unwrap();
    f.write_all(json_ps.as_bytes()).unwrap();
}

// Define static CertificationPathSettings objects and populate per PKITS test descriptions.
lazy_static! {
    // default settings used by most test cases
    pub static ref G_DEFAULT_SETTINGS: CertificationPathSettings = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        cs
    };
    pub static ref G_DEFAULT_SETTINGS_TA: String = {
        String::from("default.ta")
    };

    // same as above but with TA constaint enforcement enabled (and TAs used to supply other settings)
    pub static ref G_DEFAULT_SETTINGS_5914: CertificationPathSettings = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        set_enforce_trust_anchor_constraints(&mut cs, true);
        cs
    };

    //these four sets of settings are defined in section 4.8.1
    pub static ref G_SETTINGS1: CertificationPathSettings = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        set_initial_explicit_policy_indicator(&mut cs, true);
        cs
    };
    pub static ref G_SETTINGS1_TA: String = {
        String::from("settings1.ta")
    };

    pub static ref G_SETTINGS2: CertificationPathSettings = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        set_initial_explicit_policy_indicator(&mut cs, true);
        let mut oids = ObjectIdentifierSet::new();
        oids.insert(PKITS_TEST_POLICY_1);
        set_initial_policy_set_from_oid_set(&mut cs, oids);
        cs
    };
    pub static ref G_SETTINGS2_TA: String = {
        String::from("settings2.ta")
    };

    pub static ref G_SETTINGS3: CertificationPathSettings = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        set_initial_explicit_policy_indicator(&mut cs, true);
        let mut oids = ObjectIdentifierSet::new();
        oids.insert(PKITS_TEST_POLICY_2);
        set_initial_policy_set_from_oid_set(&mut cs, oids);
        cs
    };
    pub static ref G_SETTINGS3_TA: String = {
        String::from("settings3.ta")
    };

    pub static ref G_SETTINGS4: CertificationPathSettings = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        set_initial_explicit_policy_indicator(&mut cs, true);
        let mut oids = ObjectIdentifierSet::new();
        oids.insert(PKITS_TEST_POLICY_1);
        oids.insert(PKITS_TEST_POLICY_2);
        set_initial_policy_set_from_oid_set(&mut cs, oids);
        cs
    };
    pub static ref G_SETTINGS4_TA: String = {
        String::from("settings4.ta")
    };

    //from 4.8.6, 4.8.10, 4.8.13
    pub static ref G_SETTINGS5: CertificationPathSettings = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        let mut oids = ObjectIdentifierSet::new();
        oids.insert(PKITS_TEST_POLICY_1);
        set_initial_policy_set_from_oid_set(&mut cs, oids);
        cs
    };
    pub static ref G_SETTINGS5_TA: String = {
        String::from("settings5.ta")
    };

    pub static ref G_SETTINGS6: CertificationPathSettings = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        let mut oids = ObjectIdentifierSet::new();
        oids.insert(PKITS_TEST_POLICY_2);
        set_initial_policy_set_from_oid_set(&mut cs, oids);
        cs
    };
    pub static ref G_SETTINGS6_TA: String = {
        String::from("settings6.ta")
    };

    pub static ref G_SETTINGS7: CertificationPathSettings = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        let mut oids = ObjectIdentifierSet::new();
        oids.insert(PKITS_TEST_POLICY_3);
        set_initial_policy_set_from_oid_set(&mut cs, oids);
        cs
    };
    pub static ref G_SETTINGS7_TA: String = {
        String::from("settings7.ta")
    };

    //from 4.10.1
    pub static ref G_SETTINGS8: CertificationPathSettings = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        set_initial_policy_mapping_inhibit_indicator(&mut cs, true);
        cs
    };
    pub static ref G_SETTINGS8_TA: String = {
        String::from("settings8.ta")
    };

    //from 4.10.5
    pub static ref G_SETTINGS9: CertificationPathSettings = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        let mut oids = ObjectIdentifierSet::new();
        oids.insert(PKITS_TEST_POLICY_6);
        set_initial_policy_set_from_oid_set(&mut cs, oids);
        cs
    };
    pub static ref G_SETTINGS9_TA: String = {
        String::from("settings9.ta")
    };

    //from 4.12.3
    pub static ref G_SETTINGS10: CertificationPathSettings = {
        let mut cs = CertificationPathSettings::new();
        let t = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {n.as_secs()} else {0};
        set_time_of_interest(&mut cs, t);
        set_initial_inhibit_any_policy_indicator(&mut cs, true);
        cs
    };
    pub static ref G_SETTINGS10_TA: String = {
        String::from("settings10.ta")
    };
}

pub fn load_pkits(pkits_data_map: &'_ mut PkitsDataMap) {
    //-----------------------------------------------------------------------------
    //Section 4.1 - signature verification - 6 tests
    //-----------------------------------------------------------------------------
    {
        let target_file_name = "ValidCertificatePathTest1EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.1")
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
        let target_file_name = "InvalidCASignatureTest2EE.crt";
        let intermediate_ca_file_names = vec!["BadSigned"];
        pkits_data_map
            .entry("4.1")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::SignatureVerificationFailure,
                )),
            });
    }
    {
        let target_file_name = "InvalidEESignatureTest3EE.crt";
        let intermediate_ca_file_names = vec!["Good"];
        pkits_data_map
            .entry("4.1")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::SignatureVerificationFailure,
                )),
            });
    }

    // {
    //     let target_file_name = "ValidDSASignaturesTest4EE.crt";
    //     let intermediate_ca_file_names = vec!["DSA"];
    //     pkits_data_map.entry("4.1").or_insert_with(Vec::new).push(PkitsTestCase{target_file_name, intermediate_ca_file_names, alt_test_name: None, crls: vec![], expected_error: None});
    //     pkits_settings_map.entry("4.1").or_insert_with(Vec::new).push(&G_DEFAULT_SETTINGS);
    // }
    // {
    //     let target_file_name = "ValidDSAParameterInheritanceTest5EE.crt";
    //     let intermediate_ca_file_names = vec!["DSA", "DSAParametersInherited"];
    //     pkits_data_map.entry("4.1").or_insert_with(Vec::new).push(PkitsTestCase{target_file_name, intermediate_ca_file_names, alt_test_name: None, crls: vec![], expected_error: None});
    //     pkits_settings_map.entry("4.1").or_insert_with(Vec::new).push(&G_DEFAULT_SETTINGS);
    // }
    // {
    //     let target_file_name = "InvalidDSASignatureTest6EE.crt";
    //     let intermediate_ca_file_names = vec!["DSA"];
    //     pkits_data_map.entry("4.1").or_insert_with(Vec::new).push(PkitsTestCase{target_file_name, intermediate_ca_file_names, alt_test_name: None, crls: vec![], expected_error: Some(Error::PathValidation(PathValidationStatus::SignatureVerificationFailure)});
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::InvalidNotBeforeDate,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::InvalidNotBeforeDate,
                )),
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
    //             crls: vec![], expected_error: None,
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
                alt_test_name: Some("4.2.4"),
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
                alt_test_name: Some("4.2.5"),
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::InvalidNotAfterDate,
                )),
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
                alt_test_name: Some("4.2.6"),
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::InvalidNotAfterDate,
                )),
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
                alt_test_name: Some("4.2.7"),
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::InvalidNotAfterDate,
                )),
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
                alt_test_name: Some("4.2.8"),
                expected_error: None,
            });
    }

    //-----------------------------------------------------------------------------
    //Section 4.3 - verifying name chaining - 11 tests
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameChainingFailure,
                )),
            });
    }
    {
        let target_file_name = "InvalidNameChainingOrderTest2EE.crt";
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameChainingFailure,
                )),
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
                alt_test_name: Some("4.3.5"),
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
                alt_test_name: Some("4.3.6"),
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
                alt_test_name: Some("4.3.7"),
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
                alt_test_name: Some("4.3.8"),
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
                alt_test_name: Some("4.3.9"),
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
                alt_test_name: Some("4.3.10"),
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
                alt_test_name: Some("4.3.11"),
                expected_error: None,
            });
    }

    //-----------------------------------------------------------------------------
    //Section 4.4 - basic certificate revocation - 21 tests
    //-----------------------------------------------------------------------------
    {
        let intermediate_ca_file_names = vec!["NoCRLCA"];
        let target_file_name = "InvalidMissingCRLTest1EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
            });
    }
    {
        let intermediate_ca_file_names = vec!["GoodCA", "RevokedsubCA"];
        let target_file_name = "InvalidRevokedCATest2EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::PathValidation(CertificateRevoked)),
            });
    }
    {
        let intermediate_ca_file_names = vec!["GoodCA"];
        let target_file_name = "InvalidRevokedEETest3EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::PathValidation(CertificateRevoked)),
            });
    }
    {
        let intermediate_ca_file_names = vec!["BadCRLSignatureCA"];
        let target_file_name = "InvalidBadCRLSignatureTest4EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
            });
    }
    {
        let intermediate_ca_file_names = vec!["BadCRLIssuerName"];
        let target_file_name = "InvalidBadCRLIssuerNameTest5EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
            });
    }
    {
        let intermediate_ca_file_names = vec!["WrongCRLCA"];
        let target_file_name = "InvalidWrongCRLTest6EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
            });
    }
    {
        let intermediate_ca_file_names = vec!["TwoCRLsCA"];
        let target_file_name = "ValidTwoCRLsTest7EE.crt";
        pkits_data_map
            .entry("4.4")
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
        let intermediate_ca_file_names = vec!["UnknownCRLEntryExtensionCA"];
        let target_file_name = "InvalidUnknownCRLEntryExtensionTest8EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
            });
    }
    {
        let intermediate_ca_file_names = vec!["UnknownCRLExtensionCA"];
        let target_file_name = "InvalidUnknownCRLExtensionTest9EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
            });
    }
    {
        let intermediate_ca_file_names = vec!["UnknownCRLExtensionCA"];
        let target_file_name = "InvalidUnknownCRLExtensionTest10EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
            });
    }

    {
        let intermediate_ca_file_names = vec!["OldCRLnextUpdateCA"];
        let target_file_name = "InvalidOldCRLnextUpdateTest11EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
            });
    }
    {
        let intermediate_ca_file_names = vec!["pre2000CRLnextUpdateCA"];
        let target_file_name = "Invalidpre2000CRLnextUpdateTest12EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
            });
    }
    {
        let intermediate_ca_file_names = vec!["GeneralizedTimeCRLnextUpdateCA"];
        let target_file_name = "ValidGeneralizedTimeCRLnextUpdateTest13EE.crt";
        pkits_data_map
            .entry("4.4")
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
    // decoder is intolerant of negative serial numbers, skip
    // {
    //     let intermediate_ca_file_names = vec!["NegativeSerialNumberCA"];
    //     let target_file_name = "ValidNegativeSerialNumberTest14EE.crt";
    //     pkits_data_map
    //         .entry("4.4")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: None,
    //             expected_error: None,
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["NegativeSerialNumberCA"];
    //     let target_file_name = "InvalidNegativeSerialNumberTest15EE.crt";
    //     pkits_data_map
    //         .entry("4.4")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: None,
    //             expected_error: Some(Error::PathValidation(CertificateRevoked)),
    //         });
    // }
    {
        let intermediate_ca_file_names = vec!["LongSerialNumberCA"];
        let target_file_name = "ValidLongSerialNumberTest16EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.4.16"),
                expected_error: None,
            });
    }
    {
        let intermediate_ca_file_names = vec!["LongSerialNumberCA"];
        let target_file_name = "ValidLongSerialNumberTest17EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.4.17"),
                expected_error: None,
            });
    }
    {
        let intermediate_ca_file_names = vec!["LongSerialNumberCA"];
        let target_file_name = "InvalidLongSerialNumberTest18EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.4.18"),
                expected_error: Some(Error::PathValidation(CertificateRevoked)),
            });
    }
    {
        let intermediate_ca_file_names = vec!["SeparateCertificateandCRLKeysCertificateSigningCA"];
        let target_file_name = "ValidSeparateCertificateandCRLKeysTest19EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.4.19"),
                expected_error: None,
            });
    }
    {
        let intermediate_ca_file_names = vec!["SeparateCertificateandCRLKeysCertificateSigningCA"];
        let target_file_name = "InvalidSeparateCertificateandCRLKeysTest20EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.4.20"),
                expected_error: Some(Error::PathValidation(CertificateRevoked)),
            });
    }
    {
        let intermediate_ca_file_names =
            vec!["SeparateCertificateandCRLKeysCA2CertificateSigningCA"];
        let target_file_name = "InvalidSeparateCertificateandCRLKeysTest21EE.crt";
        pkits_data_map
            .entry("4.4")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.4.21"),
                expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
            });
    }
    {
        let intermediate_ca_file_names = vec!["TwoCRLsCA"];
        let target_file_name = "ValidTwoCRLsTest7EE.crt";
        pkits_data_map
            .entry("4.4.7")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.4.7-2"),
                expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
            });
    }

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
    {
        let target_file_name = "InvalidBasicSelfIssuedOldWithNewTest2EE.crt";
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
                alt_test_name: Some("4.5.2"),
                expected_error: None,
                // altered error owing to lack of support for separate CA and CRL signing keys
                // expected_error: Some(Error::PathValidation(
                //     PathValidationStatus::CertificateRevoked,
                // )),
            });
    }
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
    {
        let target_file_name = "ValidBasicSelfIssuedNewWithOldTest4EE.crt";
        let intermediate_ca_file_names = vec!["BasicSelfIssuedOldKey"];
        pkits_data_map
            .entry("4.5")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.5.4"),
                expected_error: None,
            });
    }
    {
        let target_file_name = "InvalidBasicSelfIssuedNewWithOldTest5EE.crt";
        let intermediate_ca_file_names = vec!["BasicSelfIssuedOldKey"];
        pkits_data_map
            .entry("4.5")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.5.5"),
                expected_error: None,
                // altered error owing to lack of support for separate CA and CRL signing keys
                // expected_error: Some(Error::PathValidation(
                //     PathValidationStatus::CertificateRevoked,
                // )),
            });
    }
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
    // 4.5.7 and 4.5.8 omitted due to lack of support for separate CA and CRL signing keys

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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::MissingBasicConstraints,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::InvalidBasicConstraints,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::InvalidBasicConstraints,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::InvalidPathLength,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::InvalidPathLength,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::InvalidPathLength,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::InvalidPathLength,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::InvalidPathLength,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::InvalidPathLength,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::InvalidPathLength,
                )),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::InvalidKeyUsage)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::InvalidKeyUsage)),
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
    {
        let target_file_name = "InvalidkeyUsageCriticalcRLSignFalseTest4EE.crt";
        let intermediate_ca_file_names = vec!["keyUsageCriticalcRLSignFalse"];
        pkits_data_map
            .entry("4.7")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::PathValidation(PathValidationStatus::InvalidKeyUsage)),
            });
    }
    {
        let target_file_name = "InvalidkeyUsageNotCriticalcRLSignFalseTest5EE.crt";
        let intermediate_ca_file_names = vec!["keyUsageNotCriticalcRLSignFalse"];
        pkits_data_map
            .entry("4.7")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: None,
                expected_error: Some(Error::PathValidation(PathValidationStatus::InvalidKeyUsage)),
            });
    }

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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(PathValidationStatus::NullPolicySet)),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
    //             crls: vec![], expected_error: None,
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::NameConstraintsViolation,
                )),
            });
    }

    //-----------------------------------------------------------------------------
    //Section 4.14 - distribution points - ? tests
    //-----------------------------------------------------------------------------

    {
        let intermediate_ca_file_names = vec!["distributionPoint1CA"];
        let target_file_name = "ValiddistributionPointTest1EE.crt";
        pkits_data_map
            .entry("4.14")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.14.1"),
                expected_error: None,
            });
    }
    {
        let intermediate_ca_file_names = vec!["distributionPoint1CA"];
        let target_file_name = "InvaliddistributionPointTest2EE.crt";
        pkits_data_map
            .entry("4.14")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.14.2"),
                expected_error: Some(Error::PathValidation(CertificateRevoked)),
            });
    }
    {
        let intermediate_ca_file_names = vec!["distributionPoint1CA"];
        let target_file_name = "InvaliddistributionPointTest3EE.crt";
        pkits_data_map
            .entry("4.14")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.14.3"),
                expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
            });
    }
    // not supporting name relative to issuer
    // {
    //     let intermediate_ca_file_names = vec!["distributionPoint1CA"];
    //     let target_file_name = "ValiddistributionPointTest4EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.4"),
    //             expected_error: None,
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["distributionPoint2CA"];
    //     let target_file_name = "ValiddistributionPointTest5EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.5"),
    //             expected_error: None,
    //         });
    // }
    {
        let intermediate_ca_file_names = vec!["distributionPoint2CA"];
        let target_file_name = "InvaliddistributionPointTest6EE.crt";
        pkits_data_map
            .entry("4.14")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.14.6"),
                expected_error: Some(Error::PathValidation(CertificateRevoked)),
            });
    }
    // {
    //     let intermediate_ca_file_names = vec!["distributionPoint2CA"];
    //     let target_file_name = "ValiddistributionPointTest7EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.7"),
    //             expected_error: None,
    //         });
    // }
    {
        let intermediate_ca_file_names = vec!["distributionPoint2CA"];
        let target_file_name = "InvaliddistributionPointTest8EE.crt";
        pkits_data_map
            .entry("4.14")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.14.8"),
                expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
            });
    }
    {
        let intermediate_ca_file_names = vec!["distributionPoint2CA"];
        let target_file_name = "InvaliddistributionPointTest9EE.crt";
        pkits_data_map
            .entry("4.14")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.14.9"),
                expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
            });
    }
    {
        let intermediate_ca_file_names = vec!["NoissuingDistributionPointCA"];
        let target_file_name = "ValidNoissuingDistributionPointTest10EE.crt";
        pkits_data_map
            .entry("4.14")
            .or_insert_with(Vec::new)
            .push(PkitsTestCase {
                target_file_name,
                intermediate_ca_file_names,
                settings: &G_DEFAULT_SETTINGS,
                ta5914_filename: &G_DEFAULT_SETTINGS_TA,
                alt_test_name: Some("4.14.10"),
                expected_error: None,
            });
    }

    // {
    //     let intermediate_ca_file_names = vec!["onlyContainsUserCertsCA"];
    //     let target_file_name = "InvalidonlyContainsUserCertsTest11EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.11"),
    //             expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["onlyContainsCACertsCA"];
    //     let target_file_name = "InvalidonlyContainsCACertsTest12EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.12"),
    //             expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["onlyContainsCACertsCA"];
    //     let target_file_name = "ValidonlyContainsCACertsTest13EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.13"),
    //             expected_error: None,
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["onlyContainsAttributeCertsCA"];
    //     let target_file_name = "InvalidonlyContainsAttributeCertsTest14EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.14"),
    //             expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["onlySomeReasonsCA1"];
    //     let target_file_name = "InvalidonlySomeReasonsTest15EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.15"),
    //             expected_error: Some(Error::PathValidation(CertificateRevoked)),
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["onlySomeReasonsCA1"];
    //     let target_file_name = "InvalidonlySomeReasonsTest16EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.16"),
    //             expected_error: None,
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["onlySomeReasonsCA2"];
    //     let target_file_name = "InvalidonlySomeReasonsTest17EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.17"),
    //             expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["onlySomeReasonsCA3"];
    //     let target_file_name = "ValidonlySomeReasonsTest18EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.18"),
    //             expected_error: None,
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["onlySomeReasonsCA4"];
    //     let target_file_name = "ValidonlySomeReasonsTest19EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.19"),
    //             expected_error: None,
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["onlySomeReasonsCA4"];
    //     let target_file_name = "InvalidonlySomeReasonsTest20EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.20"),
    //             expected_error: Some(Error::PathValidation(CertificateRevoked)),
    //         });
    // }
    //
    // {
    //     let intermediate_ca_file_names = vec!["onlySomeReasonsCA4"];
    //     let target_file_name = "InvalidonlySomeReasonsTest21EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.21"),
    //             expected_error: Some(Error::PathValidation(CertificateRevoked)),
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["indirectCRLCA1"];
    //     let target_file_name = "ValidIDPwithindirectCRLTest22EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.22"),
    //             expected_error: None,
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["indirectCRLCA1"];
    //     let target_file_name = "InvalidIDPwithindirectCRLTest23EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.23"),
    //             expected_error: None,
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["indirectCRLCA2"];
    //     let target_file_name = "ValidIDPwithindirectCRLTest24EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.24"),
    //             expected_error: None,
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["indirectCRLCA2"];
    //     let target_file_name = "ValidIDPwithindirectCRLTest25EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.25"),
    //             expected_error: None,
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["indirectCRLCA2"];
    //     let target_file_name = "InvalidIDPwithindirectCRLTest26EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.26"),
    //             expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["indirectCRLCA2"];
    //     let target_file_name = "InvalidcRLIssuerTest27EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.27"),
    //             expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["indirectCRLCA3"];
    //     let target_file_name = "ValidcRLIssuerTest28EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.28"),
    //             expected_error: None,
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["indirectCRLCA3"];
    //     let target_file_name = "ValidcRLIssuerTest29EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.29"),
    //             expected_error: None,
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["indirectCRLCA4"];
    //     let target_file_name = "ValidcRLIssuerTest30EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.30"),
    //             expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
    //         });
    // }
    //
    // {
    //     let intermediate_ca_file_names = vec!["indirectCRLCA6"];
    //     let target_file_name = "InvalidcRLIssuerTest31EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.31"),
    //             expected_error: Some(Error::PathValidation(CertificateRevoked)),
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["indirectCRLCA6"];
    //     let target_file_name = "InvalidcRLIssuerTest32EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.32"),
    //             expected_error: Some(Error::PathValidation(CertificateRevoked)),
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["indirectCRLCA6"];
    //     let target_file_name = "ValidcRLIssuerTest33EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.33"),
    //             expected_error: None,
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["indirectCRLCA5"];
    //     let target_file_name = "InvalidcRLIssuerTest34EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.34"),
    //             expected_error: Some(Error::PathValidation(CertificateRevoked)),
    //         });
    // }
    // {
    //     let intermediate_ca_file_names = vec!["indirectCRLCA5"];
    //     let target_file_name = "InvalidcRLIssuerTest35EE.crt";
    //     pkits_data_map
    //         .entry("4.14")
    //         .or_insert_with(Vec::new)
    //         .push(PkitsTestCase {
    //             target_file_name,
    //             intermediate_ca_file_names,
    //             settings: &G_DEFAULT_SETTINGS,
    //             ta5914_filename: &G_DEFAULT_SETTINGS_TA,
    //             alt_test_name: Some("4.14.35"),
    //             expected_error: Some(Error::PathValidation(RevocationStatusNotDetermined)),
    //         });
    // }

    //-----------------------------------------------------------------------------
    //Section 4.15 - delta CRLs - ? tests
    //-----------------------------------------------------------------------------

    // TODO implement me (if/when delta CRL support is added)

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
                expected_error: Some(Error::PathValidation(
                    PathValidationStatus::UnprocessedCriticalExtension,
                )),
            });
    }
}
