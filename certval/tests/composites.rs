#![cfg(feature = "pqc")]

use certval::PkiEnvironment;
use base64ct::{Base64, Encoding};
use certval::{is_self_signed, PDVCertificate};
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct TestCase {
    #[allow(non_snake_case)]
    pub tcId: String,
    pub x5c: String,
    pub sk: String,
    pub sk_pkcs8: String,
    pub s: String
}

#[derive(Deserialize)]
pub struct TestCases {
    pub m: String,
    pub tests: Vec<TestCase>
}

#[test]
fn draft_ietf_lamps_pq_composite_sigs_06_test_vectors() {
    let json = include_bytes!("../tests/examples/composite.json");
    let test_cases : TestCases = serde_json::from_str(str::from_utf8(json).unwrap()).unwrap();

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    for test_case in test_cases.tests.iter() {
        println!("{test_case:#?}");
        let der_cert = Base64::decode_vec(&test_case.x5c).unwrap();
        let cert = PDVCertificate::try_from(der_cert.as_slice()).unwrap();
        assert!(is_self_signed(&pe, &cert));
    }
}