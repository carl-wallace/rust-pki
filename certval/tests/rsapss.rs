//! RSASSA-PSS certificate signature verification.
//!
//! The fixtures are a from the Web PKI certificates: `DigiCert QV G3 Qualified TLS
//! RSA4096 RSASSA-PSS 2025 CA1`, an intermediate signed with `id-RSASSA-PSS`,
//! and the `QuoVadis Root CA 2 G3` root that issued it. Both are Mozilla-included
//! material, taken from the CCADB "all intermediates" report.
#![cfg(all(feature = "std", feature = "rsa"))]

use certval::*;
use der::{Decode, Encode};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

const EE: &[u8] = include_bytes!("examples/rsapss/digicert_qv_tls_pss.der");
const ROOT: &[u8] = include_bytes!("examples/rsapss/quovadis_root_ca_2_g3.der");

/// Verify through `PkiEnvironment`, which is the path building and path
/// validation route.
fn verify_via_environment(signature: &[u8], alg: &AlgorithmIdentifierOwned) -> certval::Result<()> {
    let cert = Certificate::from_der(EE).unwrap();
    let issuer = Certificate::from_der(ROOT).unwrap();
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe.verify_signature_message(
        &pe,
        &cert.tbs_certificate().to_der().unwrap(),
        signature,
        alg,
        issuer.tbs_certificate().subject_public_key_info(),
    )
}

/// Verify through the RustCrypto callback directly, so that assertions about
/// *which* error comes back describe this implementation rather than whichever
/// callbacks the environment happens to have registered.
fn verify_via_callback(signature: &[u8], alg: &AlgorithmIdentifierOwned) -> certval::Result<()> {
    let cert = Certificate::from_der(EE).unwrap();
    let issuer = Certificate::from_der(ROOT).unwrap();
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    verify_signature_message_rust_crypto(
        &pe,
        &cert.tbs_certificate().to_der().unwrap(),
        signature,
        alg,
        issuer.tbs_certificate().subject_public_key_info(),
    )
}

fn signature() -> Vec<u8> {
    Certificate::from_der(EE)
        .unwrap()
        .signature()
        .as_bytes()
        .unwrap()
        .to_vec()
}

fn algorithm() -> AlgorithmIdentifierOwned {
    Certificate::from_der(EE)
        .unwrap()
        .signature_algorithm()
        .clone()
}

#[test]
fn rsassa_pss_signature_verifies() {
    verify_via_environment(&signature(), &algorithm())
        .expect("an RSASSA-PSS certificate signature must verify");
    verify_via_callback(&signature(), &algorithm())
        .expect("an RSASSA-PSS certificate signature must verify");
}

/// A bad signature must be reported as `SignatureVerificationFailure` and not as
/// `Unrecognized`: callers read the latter as "no support for this algorithm",
/// and path building responds to it by dropping the certificate rather than
/// rejecting it.
#[test]
fn a_tampered_rsassa_pss_signature_fails_verification() {
    let mut tampered = signature();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;

    assert!(matches!(
        verify_via_callback(&tampered, &algorithm()),
        Err(Error::PathValidation(
            PathValidationStatus::SignatureVerificationFailure
        ))
    ));
    assert!(verify_via_environment(&tampered, &algorithm()).is_err());
}

/// Signature length is attacker-controlled — it is whatever the certificate
/// carries — so a length that does not match the modulus must be reported rather
/// than panic.
#[test]
fn a_truncated_rsassa_pss_signature_does_not_panic() {
    for len in [0usize, 1, 17, 255, 511] {
        let r = verify_via_callback(&vec![0x00; len], &algorithm());
        assert!(
            matches!(
                r,
                Err(Error::PathValidation(
                    PathValidationStatus::SignatureVerificationFailure
                ))
            ),
            "a {len}-byte signature must be reported, not panic: {r:?}"
        );
    }
}

/// `id-RSASSA-PSS` carries the salt length and MGF in its parameters and nowhere
/// else, so an AlgorithmIdentifier without them cannot be verified. Silently
/// substituting RFC 8017's SHA-1 defaults would verify under parameters the
/// signer never stated.
#[test]
fn rsassa_pss_without_parameters_is_rejected() {
    let stripped = AlgorithmIdentifierOwned {
        oid: algorithm().oid,
        parameters: None,
    };
    assert!(matches!(
        verify_via_callback(&signature(), &stripped),
        Err(Error::PathValidation(PathValidationStatus::EncodingError))
    ));
}

/// `rsa::pss::VerifyingKey<D>` always masks with MGF1-D, so parameters naming a
/// different mask generation function must be refused rather than verified under
/// substituted ones.
#[test]
fn a_mismatched_mask_generation_function_is_rejected() {
    let params = pkcs1::RsaPssParams {
        hash: spki::AlgorithmIdentifierRef {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        },
        mask_gen: spki::AlgorithmIdentifier {
            oid: const_oid::db::rfc5912::ID_MGF_1,
            parameters: Some(spki::AlgorithmIdentifierRef {
                oid: const_oid::db::rfc5912::ID_SHA_512,
                parameters: None,
            }),
        },
        salt_len: 32,
        trailer_field: pkcs1::TrailerField::BC,
    };
    let encoded = params.to_der().unwrap();
    let alg = AlgorithmIdentifierOwned {
        oid: algorithm().oid,
        parameters: Some(der::Any::from_der(&encoded).unwrap()),
    };
    assert!(matches!(
        verify_via_callback(&signature(), &alg),
        Err(Error::Unrecognized)
    ));
}

/// `RSASSA-PSS-params` tags all four of its fields context-specific with DEFAULTs
/// (RFC 4055 section 3.1). This pins the tagging of the fixture's parameters
/// alongside the values decoded from them, so a decoder that expected bare
/// fields would fail here rather than somewhere further downstream.
#[test]
fn parameters_decode_with_their_context_specific_tags() {
    let cert = Certificate::from_der(EE).unwrap();
    let parameters = cert
        .signature_algorithm()
        .parameters
        .as_ref()
        .expect("the fixture carries RSASSA-PSS parameters");
    let encoded = parameters.to_der().unwrap();

    // SEQUENCE, then [0] constructed for hashAlgorithm.
    assert_eq!(encoded[0], 0x30);
    assert_eq!(encoded[2], 0xa0);

    let params = pkcs1::RsaPssParams::from_der(&encoded).expect("parameters must decode");
    assert_eq!(params.hash.oid, const_oid::db::rfc5912::ID_SHA_256);
    assert_eq!(params.mask_gen.oid, const_oid::db::rfc5912::ID_MGF_1);
    assert_eq!(
        params.mask_gen.parameters.map(|p| p.oid),
        Some(const_oid::db::rfc5912::ID_SHA_256)
    );
    assert_eq!(params.salt_len, 32);
}
