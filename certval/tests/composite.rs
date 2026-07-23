//! Executed tests for composite ML-DSA signature verification
//! ([`verify_signature_message_composite_rustcrypto`]).
//!
//! Each vector is a self-signed composite trust-anchor certificate: the message is the signed
//! `tbsCertificate`, the key is the certificate's own SubjectPublicKeyInfo, and the signature is the
//! certificate's composite signature. A valid signature must verify; corrupting EITHER the ML-DSA
//! component OR the traditional component must be rejected (this is the property that catches a
//! verifier that only checks one half), as must a truncated or empty signature.
//!
//! Fixtures are IETF LAMPS PQC-hackathon interop artifacts (pqc-certificates repo, `cryptonext`
//! provider, `artifacts_certs_r5`), covering every composite OID certval recognizes.

#![cfg(feature = "pqc")]

use certval::{verify_signature_message_composite_rustcrypto, DeferDecodeSigned, PkiEnvironment};
use der::Decode;
use x509_cert::certificate::{CertificateInner, Raw};

/// `(display_name, der_bytes)` for a fixture under `tests/examples/composite/`.
macro_rules! cert {
    ($f:expr) => {
        ($f, &include_bytes!(concat!("examples/composite/", $f))[..])
    };
}

/// Exercise the good / tamper-ML-DSA-half / tamper-traditional-half / truncated / empty vectors for
/// one self-signed composite certificate.
fn assert_composite_vectors(name: &str, der: &[u8]) {
    let defer =
        DeferDecodeSigned::from_der(der).unwrap_or_else(|e| panic!("{name}: defer decode: {e}"));
    let cert = CertificateInner::<Raw>::from_der(der)
        .unwrap_or_else(|e| panic!("{name}: cert decode: {e}"));
    let spki = cert.tbs_certificate().subject_public_key_info();
    let sig_alg = &defer.signature_algorithm;
    let sig = defer.signature.raw_bytes().to_vec();
    let msg = &defer.tbs_field;

    let mut pe = PkiEnvironment::new();
    pe.populate_5280_pki_environment();
    let verify =
        |s: &[u8]| verify_signature_message_composite_rustcrypto(&pe, msg, s, sig_alg, spki);

    assert!(
        verify(&sig).is_ok(),
        "{name}: a valid composite signature must verify"
    );

    // The ML-DSA component is first in the composite signature.
    let mut ml_dsa_tampered = sig.clone();
    ml_dsa_tampered[0] ^= 0x01;
    assert!(
        verify(&ml_dsa_tampered).is_err(),
        "{name}: a corrupted ML-DSA component must be rejected"
    );

    // The traditional component is last.
    let mut trad_tampered = sig.clone();
    let last = trad_tampered.len() - 1;
    trad_tampered[last] ^= 0x01;
    assert!(
        verify(&trad_tampered).is_err(),
        "{name}: a corrupted traditional component must be rejected"
    );

    assert!(
        verify(&sig[..sig.len() / 2]).is_err(),
        "{name}: a truncated composite signature must be rejected"
    );
    assert!(
        verify(&[]).is_err(),
        "{name}: an empty signature must be rejected"
    );
}

// ML-DSA + ECDSA (P-256/P-384/P-521) — traditional side needs no optional feature.
#[test]
fn composite_ecdsa_vectors() {
    for (name, der) in [
        cert!("id-MLDSA44-ECDSA-P256-SHA256-1.3.6.1.5.5.7.6.40_ta.der"),
        cert!("id-MLDSA65-ECDSA-P256-SHA512-1.3.6.1.5.5.7.6.45_ta.der"),
        cert!("id-MLDSA65-ECDSA-P384-SHA512-1.3.6.1.5.5.7.6.46_ta.der"),
        cert!("id-MLDSA87-ECDSA-P384-SHA512-1.3.6.1.5.5.7.6.49_ta.der"),
        cert!("id-MLDSA87-ECDSA-P521-SHA512-1.3.6.1.5.5.7.6.54_ta.der"),
    ] {
        assert_composite_vectors(name, der);
    }
}

// ML-DSA + RSA (PSS and PKCS#1 v1.5, 2048/3072/4096).
#[cfg(feature = "rsa")]
#[test]
fn composite_rsa_vectors() {
    for (name, der) in [
        cert!("id-MLDSA44-RSA2048-PSS-SHA256-1.3.6.1.5.5.7.6.37_ta.der"),
        cert!("id-MLDSA44-RSA2048-PKCS15-SHA256-1.3.6.1.5.5.7.6.38_ta.der"),
        cert!("id-MLDSA65-RSA3072-PSS-SHA512-1.3.6.1.5.5.7.6.41_ta.der"),
        cert!("id-MLDSA65-RSA3072-PKCS15-SHA512-1.3.6.1.5.5.7.6.42_ta.der"),
        cert!("id-MLDSA65-RSA4096-PSS-SHA512-1.3.6.1.5.5.7.6.43_ta.der"),
        cert!("id-MLDSA65-RSA4096-PKCS15-SHA512-1.3.6.1.5.5.7.6.44_ta.der"),
        cert!("id-MLDSA87-RSA3072-PSS-SHA512-1.3.6.1.5.5.7.6.52_ta.der"),
        cert!("id-MLDSA87-RSA4096-PSS-SHA512-1.3.6.1.5.5.7.6.53_ta.der"),
    ] {
        assert_composite_vectors(name, der);
    }
}

// ML-DSA + Ed25519.
#[cfg(feature = "eddsa")]
#[test]
fn composite_ed25519_vectors() {
    for (name, der) in [
        cert!("id-MLDSA44-Ed25519-SHA512-1.3.6.1.5.5.7.6.39_ta.der"),
        cert!("id-MLDSA65-Ed25519-SHA512-1.3.6.1.5.5.7.6.48_ta.der"),
    ] {
        assert_composite_vectors(name, der);
    }
}
