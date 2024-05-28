#![cfg(feature = "std")]

use certval::path_settings::*;
use certval::CertificationPathSettings;
use certval::TimeOfInterest;
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

    let mut cps = CertificationPathSettings::new();
    cps.set_initial_explicit_policy_indicator(true);
    cps.set_initial_policy_mapping_inhibit_indicator(true);
    cps.set_initial_inhibit_any_policy_indicator(true);
    let policies = vec![ANY_POLICY.to_string()];
    cps.set_initial_policy_set(policies);
    let perm = certval::NameConstraintsSettings {
        directory_name: Some(vec!["CN=Joe,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["x@example.com".to_string()]),
        user_principal_name: Some(vec!["1234567890@mil".to_string()]),
        dns_name: Some(vec!["j.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://j.example.com".to_string()]),
        ip_address: None,
        not_supported: None,
    };
    cps.set_initial_permitted_subtrees(perm);
    let excl = certval::NameConstraintsSettings {
        directory_name: Some(vec!["CN=Sue,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["y@example.com".to_string()]),
        user_principal_name: Some(vec!["0987654321@mil".to_string()]),
        dns_name: Some(vec!["s.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://s.example.com".to_string()]),
        ip_address: None,
        not_supported: None,
    };
    cps.set_initial_excluded_subtrees(excl);
    cps.set_time_of_interest(TimeOfInterest::now());
    let ekus = vec![ID_KP_SERVER_AUTH.to_string()];
    cps.set_extended_key_usage(ekus);
    cps.set_extended_key_usage_path(false);
    cps.set_enforce_alg_and_key_size_constraints(false);
    cps.set_check_revocation_status(false);
    cps.set_check_ocsp_from_aia(false);
    cps.set_check_ocsp_from_aia(false);
    cps.set_retrieve_from_aia_sia_http(false);
    cps.set_retrieve_from_aia_sia_ldap(false);
    cps.set_check_crls(false);
    cps.set_check_crldp_http(false);
    cps.set_check_crldp_ldap(false);
    cps.set_crl_grace_periods_as_last_resort(false);
    cps.set_ignore_expired(false);
    cps.set_ocsp_aia_nonce_setting(OcspNonceSetting::DoNotSendNonce);
    cps.set_require_country_code_indicator(false);
    let permcountries = vec!["AA".to_string()];
    cps.set_perm_countries(permcountries);
    let exclcountries = vec!["BB".to_string()];
    cps.set_perm_countries(exclcountries);
    let fs = KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment;
    cps.set_target_key_usage(fs);

    let ser = serde_json::to_string(&cps).unwrap();
    let deser: CertificationPathSettings = serde_json::from_slice(ser.as_bytes()).unwrap();
    assert_eq!(deser, cps);

    let ser2 = serde_json::to_string(&deser).unwrap();
    assert_eq!(ser, ser2);
}
