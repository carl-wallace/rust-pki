use certval::path_settings::*;
use certval::path_validator::*;
use certval::pki_environment::*;
use certval::PkiEnvironment;
use certval::*;
use pkcs7::cryptographic_message_syntax2004::*;
use x509::der::{Decodable, Encodable};
use x509::der::{DecodeValue, Decoder};
use x509::trust_anchor_format::TrustAnchorChoice;
use x509::*;

#[test]
fn signed_data_parse_test1() {
    let der_encoded_sd = include_bytes!("examples/caCertsIssuedTofbcag4.p7c");
    let ci = ContentInfo2004::from_der(der_encoded_sd).unwrap();
    let content = ci.content.unwrap().to_vec().unwrap();
    let _sd = SignedData::from_der(content.as_slice()).unwrap();
    //assert_eq!(1, sd.certificates.unwrap().len());

    let der_encoded_sd = include_bytes!("examples/DODJITCINTEROPERABILITYROOTCA2_IT.p7c");
    let ci = ContentInfo2004::from_der(der_encoded_sd).unwrap();
    let content = ci.content.unwrap().to_vec().unwrap();
    let sd = SignedData::from_der(content.as_slice()).unwrap();
    assert_eq!(1, sd.certificates.unwrap().len());

    let der_encoded_sd = include_bytes!("examples/DODROOTCA3_IB.p7c");
    let ci = ContentInfo2004::from_der(der_encoded_sd).unwrap();
    let content = ci.content.unwrap().to_vec().unwrap();
    let sd = SignedData::from_der(content.as_slice()).unwrap();
    assert_eq!(26, sd.certificates.unwrap().len());
}

#[test]
fn pkits_test1() {
    let der_encoded_ta = include_bytes!("examples/TrustAnchorRootCertificate.crt");
    let der_encoded_ca = include_bytes!("examples/GoodCACert.crt");
    let der_encoded_ee = include_bytes!("examples/ValidCertificatePathTest1EE.crt");

    let mut decoder = Decoder::new(der_encoded_ta).unwrap();
    let header = decoder.peek_header().unwrap();
    let tac = TrustAnchorChoice::decode_value(&mut decoder, header.length).unwrap();
    let ta = PDVTrustAnchorChoice {
        encoded_ta: der_encoded_ta,
        decoded_ta: tac,
        metadata: None,
        parsed_extensions: ParsedExtensions::new(),
    };

    let ca_cert = Certificate::from_der(der_encoded_ca).unwrap();
    let ee_cert = Certificate::from_der(der_encoded_ee).unwrap();

    let mut ca = PDVCertificate {
        encoded_cert: der_encoded_ca,
        decoded_cert: ca_cert,
        metadata: None,
        parsed_extensions: ParsedExtensions::new(),
    };
    ca.parse_extensions(EXTS_OF_INTEREST);
    let mut ee = PDVCertificate {
        encoded_cert: der_encoded_ee,
        decoded_cert: ee_cert,
        metadata: None,
        parsed_extensions: ParsedExtensions::new(),
    };

    let mut chain = vec![];
    chain.push(&ca);

    let mut pe = PkiEnvironment::new();
    populate_5280_pki_environment(&mut pe);
    let mut pe2 = PkiEnvironment::new();
    pe2.add_validate_path_callback(validate_path_rfc5280);

    ee.parse_extensions(EXTS_OF_INTEREST);

    let mut cert_path = CertificationPath {
        target: &ee,
        intermediates: chain,
        trust_anchor: &ta,
    };

    let cps = CertificationPathSettings::new();
    let mut cpr = CertificationPathResults::new();

    let r = pe.validate_path(&pe, &cps, &mut cert_path, &mut cpr);
    if r.is_err() {
        println!("Oh no");
    }
}
