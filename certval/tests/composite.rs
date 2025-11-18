#![cfg(feature = "pqc")]

use std::fs::File;
use certval::{buffer_to_hex, PDVCertificate};
use certval::{is_self_signed, is_self_signed_with_buffer, verify_signature_message_composite_rustcrypto};
use std::fs;
use base64ct::{Base64, Encoding};
use serde::Deserialize;
use certval::PkiEnvironment;
use std::io::Write;

// #[derive(Deserialize, Debug)]
// struct CompositeTestSuite {
//     pub m: String,
//     pub tests: Vec<CompositeTestCase>,
// }
// #[derive(Deserialize, Debug)]
// struct CompositeTestCase {
//     pub tcId: String,
//     pub x5c: String,
// }
//
// #[test]
// fn composite_json_parse() {
//     let json_data = fs::read_to_string("tests/examples/composite.json").unwrap();
//     let test_suite: CompositeTestSuite = serde_json::from_str(&json_data).unwrap();
//     let mut pe = PkiEnvironment::default();
//     pe.populate_5280_pki_environment();
//     for test_case in test_suite.tests.iter() {
//         let der_cert = Base64::decode_vec(&test_case.x5c).unwrap();
//         println!("{}: {}", test_case.tcId, buffer_to_hex(&der_cert));
//
//         // let mut file = File::create(format!("../{}.der", test_case.tcId)).unwrap();
//         // file.write_all(&der_cert).unwrap();
//         let cert = PDVCertificate::try_from(der_cert.as_slice()).unwrap();
//         if is_self_signed_with_buffer(&pe, &cert.as_ref(), &der_cert) {
//             println!("SUCCESS: {}", test_case.tcId);
//         } else {
//             if !test_case.tcId.contains("brainpool") || !test_case.x5c.contains("ed448") {
//                 println!("FAIL: {}", test_case.tcId);
//             } else {
//                 println!("SUCCESS: {}", test_case.tcId);
//             }
//         }
//     }
// }

#[test]
fn composite_test() {
    let paths = fs::read_dir("tests/examples/composites").unwrap();
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();

    for path in paths {
        let path = path.unwrap().path();
        let path_str = path.display().to_string();
        println!("Name: {}", path.display());
        let der_cert = fs::read(path).unwrap();
        let cert = PDVCertificate::try_from(der_cert.as_slice()).unwrap();
        if is_self_signed_with_buffer(&pe, &cert.as_ref(), &der_cert) {
            println!("SUCCESS: {path_str}");
        } else {
            if !path_str.contains("brainpool") || !path_str.contains("ed448") {
                println!("FAIL: {path_str}");
            } else {
                println!("SUCCESS: {path_str}");
            }
        }
    }
}