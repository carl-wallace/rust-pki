//! Exercises the four signature-verification registration interfaces.
//!
//! Sibling to `calculate_hash_interface.rs`, and the property under test is the same one: a bare
//! function, a value carrying state, and a shared reference-counted value can all be registered
//! through a single `add_*_callback` method. The stateful case is the one a hardware-backed
//! implementation needs, since neither a module handle nor a cache of imported key objects can live
//! in a function pointer, and for verification that cache is what keeps the per-signature cost down.
//!
//! One object registered in several roles is also covered, because a PKCS #11 provider that hashes
//! and verifies shares a session and an algorithm table across those roles and should not have to be
//! split into separate objects to be registered.

#![cfg(feature = "rsa")]

use certval::*;
use der::{Decode, Encode};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use x509_cert::Certificate;

/// An end entity certificate and the CA certificate that issued it. Any correctly-chaining pair
/// would do; these are reused from the PKITS corpus already present in the repository.
const EE: &[u8] = include_bytes!("examples/PKITS_data_2048/certs/ValidCertificatePathTest1EE.crt");
const CA: &[u8] = include_bytes!("examples/PKITS_data_2048/certs/GoodCACert.crt");

/// The pieces a verification callback is handed: the signed content, the signature over it, the
/// algorithm and the issuer's public key.
struct SignedCert {
    tbs: Vec<u8>,
    signature: Vec<u8>,
    alg: AlgorithmIdentifierOwned,
    issuer_spki: SubjectPublicKeyInfoOwned,
}

fn signed_cert() -> SignedCert {
    let ee = Certificate::from_der(EE).unwrap();
    let ca = Certificate::from_der(CA).unwrap();
    SignedCert {
        tbs: ee.tbs_certificate().to_der().unwrap(),
        signature: ee.signature().as_bytes().unwrap().to_vec(),
        alg: ee.signature_algorithm().clone(),
        issuer_spki: ca.tbs_certificate().subject_public_key_info().clone(),
    }
}

/// The digest interface takes the hash of the signed content rather than the content itself.
fn digest_of(pe: &PkiEnvironment, sc: &SignedCert) -> Vec<u8> {
    let hash_alg = AlgorithmIdentifierOwned {
        oid: PKIXALG_SHA256,
        parameters: None,
    };
    pe.calculate_hash(pe, &hash_alg, &sc.tbs).unwrap()
}

/// Stands in for a hardware-backed provider: it owns state (here call counters, in practice a
/// session and a cache of key objects keyed by SPKI) and so cannot be expressed as a function
/// pointer. It is registered in several roles at once, as a real provider would be.
#[derive(Default)]
struct CountingVerifier {
    digest_calls: AtomicUsize,
    message_calls: AtomicUsize,
}

impl VerifySignatureDigest for CountingVerifier {
    fn verify_signature_digest(
        &self,
        pe: &PkiEnvironment,
        hash_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> certval::Result<()> {
        self.digest_calls.fetch_add(1, Ordering::SeqCst);
        verify_signature_digest_rust_crypto(pe, hash_to_verify, signature, signature_alg, spki)
    }
}

impl VerifySignatureMessage for CountingVerifier {
    fn verify_signature_message(
        &self,
        pe: &PkiEnvironment,
        message_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> certval::Result<()> {
        self.message_calls.fetch_add(1, Ordering::SeqCst);
        verify_signature_message_rust_crypto(pe, message_to_verify, signature, signature_alg, spki)
    }
}

/// The context-bearing interfaces have no software implementation to delegate to outside the `pqc`
/// feature, so this one answers on its own and simply records that it was reached.
#[derive(Default)]
struct CountingCtxVerifier {
    digest_calls: AtomicUsize,
    message_calls: AtomicUsize,
    last_ctx: std::sync::Mutex<Option<Vec<u8>>>,
}

impl VerifySignatureDigestWithContext for CountingCtxVerifier {
    fn verify_signature_digest_with_context(
        &self,
        _pe: &PkiEnvironment,
        _hash_to_verify: &[u8],
        _signature: &[u8],
        _signature_alg: &AlgorithmIdentifierOwned,
        _spki: &SubjectPublicKeyInfoOwned,
        ctx: &Option<Vec<u8>>,
    ) -> certval::Result<()> {
        self.digest_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_ctx.lock().unwrap() = ctx.clone();
        Ok(())
    }
}

impl VerifySignatureMessageWithContext for CountingCtxVerifier {
    fn verify_signature_message_with_context(
        &self,
        _pe: &PkiEnvironment,
        _message_to_verify: &[u8],
        _signature: &[u8],
        _signature_alg: &AlgorithmIdentifierOwned,
        _spki: &SubjectPublicKeyInfoOwned,
        ctx: &Option<Vec<u8>>,
    ) -> certval::Result<()> {
        self.message_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_ctx.lock().unwrap() = ctx.clone();
        Ok(())
    }
}

/// Always declines, to exercise the fall-through to the next registered implementation.
struct DecliningVerifier;

impl VerifySignatureDigest for DecliningVerifier {
    fn verify_signature_digest(
        &self,
        _pe: &PkiEnvironment,
        _hash_to_verify: &[u8],
        _signature: &[u8],
        _signature_alg: &AlgorithmIdentifierOwned,
        _spki: &SubjectPublicKeyInfoOwned,
    ) -> certval::Result<()> {
        Err(Error::Unrecognized)
    }
}

impl VerifySignatureMessage for DecliningVerifier {
    fn verify_signature_message(
        &self,
        _pe: &PkiEnvironment,
        _message_to_verify: &[u8],
        _signature: &[u8],
        _signature_alg: &AlgorithmIdentifierOwned,
        _spki: &SubjectPublicKeyInfoOwned,
    ) -> certval::Result<()> {
        Err(Error::Unrecognized)
    }
}

/// Bare functions still register exactly as they did before the interfaces became traits. Every
/// existing caller in the workspace takes this form, so this is the compatibility assertion.
#[test]
fn bare_functions_register() {
    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    pe.add_calculate_hash_callback(calculate_hash_rust_crypto);
    pe.add_verify_signature_digest_callback(verify_signature_digest_rust_crypto);
    pe.add_verify_signature_message_callback(verify_signature_message_rust_crypto);

    let sc = signed_cert();
    let digest = digest_of(&pe, &sc);

    pe.verify_signature_digest(&pe, &digest, &sc.signature, &sc.alg, &sc.issuer_spki)
        .unwrap();
    pe.verify_signature_message(&pe, &sc.tbs, &sc.signature, &sc.alg, &sc.issuer_spki)
        .unwrap();
}

/// One stateful value registered for both verification roles, exercised through both. This is the
/// shape a PKCS #11 provider takes, and the reason the interfaces could not remain function
/// pointers.
#[test]
fn stateful_implementation_registers_in_several_roles_and_retains_state() {
    let verifier = Arc::new(CountingVerifier::default());

    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    pe.add_calculate_hash_callback(calculate_hash_rust_crypto);
    pe.add_verify_signature_digest_callback(verifier.clone());
    pe.add_verify_signature_message_callback(verifier.clone());

    let sc = signed_cert();
    let digest = digest_of(&pe, &sc);

    for _ in 0..3 {
        pe.verify_signature_digest(&pe, &digest, &sc.signature, &sc.alg, &sc.issuer_spki)
            .unwrap();
        pe.verify_signature_message(&pe, &sc.tbs, &sc.signature, &sc.alg, &sc.issuer_spki)
            .unwrap();
    }

    // Both registrations and the handle retained here are the same object.
    assert_eq!(verifier.digest_calls.load(Ordering::SeqCst), 3);
    assert_eq!(verifier.message_calls.load(Ordering::SeqCst), 3);
}

/// The same for the two context-bearing interfaces, including that the context reaches the callback.
#[test]
fn stateful_implementation_registers_for_context_interfaces() {
    let verifier = Arc::new(CountingCtxVerifier::default());

    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    pe.add_calculate_hash_callback(calculate_hash_rust_crypto);
    pe.add_verify_signature_digest_ctx_callback(verifier.clone());
    pe.add_verify_signature_message_ctx_callback(verifier.clone());

    let sc = signed_cert();
    let digest = digest_of(&pe, &sc);
    let ctx = Some(b"context".to_vec());

    pe.verify_signature_ctx_digest(&pe, &digest, &sc.signature, &sc.alg, &sc.issuer_spki, &ctx)
        .unwrap();
    assert_eq!(verifier.digest_calls.load(Ordering::SeqCst), 1);
    assert_eq!(*verifier.last_ctx.lock().unwrap(), ctx);

    pe.verify_signature_message_ctx(&pe, &sc.tbs, &sc.signature, &sc.alg, &sc.issuer_spki, &None)
        .unwrap();
    assert_eq!(verifier.message_calls.load(Ordering::SeqCst), 1);
    assert_eq!(*verifier.last_ctx.lock().unwrap(), None);
}

/// A declining implementation falls through to the next rather than failing the operation, which is
/// what lets a hardware implementation defer to software for algorithms its module does not offer.
#[test]
fn mixed_registration_falls_through_in_order() {
    let verifier = Arc::new(CountingVerifier::default());

    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    pe.add_calculate_hash_callback(calculate_hash_rust_crypto);
    pe.add_verify_signature_message_callback(DecliningVerifier);
    pe.add_verify_signature_message_callback(verifier.clone());
    pe.add_verify_signature_message_callback(verify_signature_message_rust_crypto);

    let sc = signed_cert();
    pe.verify_signature_message(&pe, &sc.tbs, &sc.signature, &sc.alg, &sc.issuer_spki)
        .unwrap();

    // The first implementation declined, so the second answered and the third was never reached.
    assert_eq!(verifier.message_calls.load(Ordering::SeqCst), 1);
}

/// A closure registers too, since the blanket implementation covers anything callable with the right
/// signature. This gives a captured-state option without declaring a type.
#[test]
fn closure_registers_and_captures_state() {
    let counter = Arc::new(AtomicUsize::new(0));
    let seen = counter.clone();

    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    pe.add_calculate_hash_callback(calculate_hash_rust_crypto);
    pe.add_verify_signature_message_callback(
        move |pe: &PkiEnvironment,
              msg: &[u8],
              sig: &[u8],
              alg: &AlgorithmIdentifierOwned,
              spki: &SubjectPublicKeyInfoOwned| {
            seen.fetch_add(1, Ordering::SeqCst);
            verify_signature_message_rust_crypto(pe, msg, sig, alg, spki)
        },
    );

    let sc = signed_cert();
    pe.verify_signature_message(&pe, &sc.tbs, &sc.signature, &sc.alg, &sc.issuer_spki)
        .unwrap();
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

/// Verification still fails when the signature does not match, so a declining-then-answering chain
/// cannot turn a bad signature into a good one.
#[test]
fn tampered_signature_is_rejected() {
    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    pe.add_calculate_hash_callback(calculate_hash_rust_crypto);
    pe.add_verify_signature_message_callback(DecliningVerifier);
    pe.add_verify_signature_message_callback(verify_signature_message_rust_crypto);

    let mut sc = signed_cert();
    sc.signature[0] ^= 0xff;

    assert!(pe
        .verify_signature_message(&pe, &sc.tbs, &sc.signature, &sc.alg, &sc.issuer_spki)
        .is_err());
}

/// An error is still reported once every implementation has declined.
#[test]
fn exhausted_callbacks_report_unrecognized() {
    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    pe.add_calculate_hash_callback(calculate_hash_rust_crypto);
    pe.add_verify_signature_digest_callback(DecliningVerifier);
    pe.add_verify_signature_message_callback(DecliningVerifier);

    let sc = signed_cert();
    let digest = digest_of(&pe, &sc);

    assert!(pe
        .verify_signature_digest(&pe, &digest, &sc.signature, &sc.alg, &sc.issuer_spki)
        .is_err());
    assert!(pe
        .verify_signature_message(&pe, &sc.tbs, &sc.signature, &sc.alg, &sc.issuer_spki)
        .is_err());
}
