//! Verify real FN-DSA (Falcon) self-signed trust anchors through the registered callback.
//!
//! The artifacts are self-signed CA certificates from the IETF hackathon pqc-certificates
//! project (BouncyCastle provider), covering both the round-4 (unpadded) Falcon OIDs
//! (`1.3.9999.3.6` / `.9`) and the round-5 (padded) OIDs (`1.3.9999.3.11` / `.14`).

#![cfg(feature = "pqc")]

use certval::environment::pki_environment::PkiEnvironment;
use certval::*;
use der::Decode;
use x509_cert::Certificate;

/// A self-signed cert verifies when its own SPKI validates the signature over its TBS.
fn assert_self_signed_verifies(der: &[u8]) {
    let cert = Certificate::from_der(der).unwrap();
    let parts = DeferDecodeSigned::from_der(der).unwrap();
    let spki = cert.tbs_certificate().subject_public_key_info();

    // Directly through the FN-DSA callback.
    let pe = PkiEnvironment::new();
    verify_signature_message_fndsa(
        &pe,
        &parts.tbs_field,
        parts.signature.raw_bytes(),
        &parts.signature_algorithm,
        spki,
    )
    .unwrap();

    // And through the full switchboard, proving the callback is registered by default.
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe.verify_signature_message(
        &pe,
        &parts.tbs_field,
        parts.signature.raw_bytes(),
        &parts.signature_algorithm,
        spki,
    )
    .unwrap();
}

#[test]
fn falcon_512_unpadded_oid() {
    assert_self_signed_verifies(include_bytes!(
        "examples/fndsa/falcon-512-1.3.9999.3.6_ta.der"
    ));
}

#[test]
fn falcon_1024_unpadded_oid() {
    assert_self_signed_verifies(include_bytes!(
        "examples/fndsa/falcon-1024-1.3.9999.3.9_ta.der"
    ));
}

#[test]
fn falcon_512_padded_oid() {
    assert_self_signed_verifies(include_bytes!(
        "examples/fndsa/falcon-512-1.3.9999.3.11_ta.der"
    ));
}

#[test]
fn falcon_1024_padded_oid() {
    assert_self_signed_verifies(include_bytes!(
        "examples/fndsa/falcon-1024-1.3.9999.3.14_ta.der"
    ));
}

/// A tampered TBS must not verify.
#[test]
fn falcon_512_rejects_tampered_message() {
    let der = include_bytes!("examples/fndsa/falcon-512-1.3.9999.3.6_ta.der");
    let cert = Certificate::from_der(der).unwrap();
    let parts = DeferDecodeSigned::from_der(der).unwrap();
    let mut tbs = parts.tbs_field.clone();
    // Flip a byte deep in the TBS so it stays DER-parseable-length but content-altered.
    let last = tbs.len() - 1;
    tbs[last] ^= 0x01;

    let pe = PkiEnvironment::new();
    assert!(verify_signature_message_fndsa(
        &pe,
        &tbs,
        parts.signature.raw_bytes(),
        &parts.signature_algorithm,
        cert.tbs_certificate().subject_public_key_info(),
    )
    .is_err());
}
