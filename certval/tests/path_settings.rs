#![cfg(feature = "std")]

use certval::path_settings::*;
use certval::CertificationPathSettings;
use const_oid::db::rfc5280::ANY_POLICY;
use x509_cert::ext::pkix::KeyUsages;

#[test]
fn path_settings_serialize_deserialize() {
    let ps = CertificationPathSettings::default();
    let json_ps = serde_json::to_string(&ps).unwrap();
    let ps_de = serde_json::from_slice(json_ps.as_bytes()).unwrap();
    assert_eq!(ps, ps_de);
}

#[test]
fn settings_serialization_test() {
    use const_oid::db::rfc5280::ID_KP_SERVER_AUTH;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut cps = CertificationPathSettings::new();
    set_initial_explicit_policy_indicator(&mut cps, true);
    set_initial_policy_mapping_inhibit_indicator(&mut cps, true);
    set_initial_inhibit_any_policy_indicator(&mut cps, true);
    let policies = vec![ANY_POLICY.to_string()];
    set_initial_policy_set(&mut cps, policies);
    let perm = certval::NameConstraintsSettings {
        directory_name: Some(vec!["C=US,O=Org,OU=Org Unit,CN=Joe".to_string()]),
        rfc822_name: Some(vec!["x@example.com".to_string()]),
        user_principal_name: Some(vec!["1234567890@mil".to_string()]),
        dns_name: Some(vec!["j.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://j.example.com".to_string()]),
    };
    set_initial_permitted_subtrees(&mut cps, perm);
    let excl = certval::NameConstraintsSettings {
        directory_name: Some(vec!["C=US,O=Org,OU=Org Unit,CN=Sue".to_string()]),
        rfc822_name: Some(vec!["y@example.com".to_string()]),
        user_principal_name: Some(vec!["0987654321@mil".to_string()]),
        dns_name: Some(vec!["s.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://s.example.com".to_string()]),
    };
    set_initial_excluded_subtrees(&mut cps, excl);
    let toi = if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {
        n.as_secs()
    } else {
        0
    };
    set_time_of_interest(&mut cps, toi);
    let ekus = vec![ID_KP_SERVER_AUTH.to_string()];
    set_extended_key_usage(&mut cps, ekus);
    set_extended_key_usage_path(&mut cps, false);
    set_enforce_alg_and_key_size_constraints(&mut cps, false);
    set_check_revocation_status(&mut cps, false);
    set_check_ocsp_from_aia(&mut cps, false);
    set_check_ocsp_from_aia(&mut cps, false);
    set_retrieve_from_aia_sia_http(&mut cps, false);
    set_retrieve_from_aia_sia_ldap(&mut cps, false);
    set_check_crls(&mut cps, false);
    set_check_crldp_http(&mut cps, false);
    set_check_crldp_ldap(&mut cps, false);
    set_crl_grace_periods_as_last_resort(&mut cps, false);
    set_ignore_expired(&mut cps, false);
    set_ocsp_aia_nonce_setting(&mut cps, OcspNonceSetting::DoNotSendNonce);
    set_require_country_code_indicator(&mut cps, false);
    let permcountries = vec!["AA".to_string()];
    set_perm_countries(&mut cps, permcountries);
    let exclcountries = vec!["BB".to_string()];
    set_perm_countries(&mut cps, exclcountries);
    let fs = KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment;
    set_target_key_usage(&mut cps, fs.bits());

    let ser = serde_json::to_string(&cps).unwrap();
    let deser: CertificationPathSettings = serde_json::from_slice(ser.as_bytes()).unwrap();
    assert_eq!(deser, cps);

    let ser2 = serde_json::to_string(&deser).unwrap();
    assert_eq!(ser, ser2);
}
