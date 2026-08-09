//! Exercises the [`CalculateHash`] registration interface.
//!
//! The interesting property is not that hashing works, it is that three different shapes of
//! implementation can all be registered through one `add_calculate_hash_callback` call: a bare
//! function, a value carrying state, and a shared reference-counted value registered for more than
//! one role. The middle case is what a hardware-backed implementation needs, since a handle to a
//! module or a cache of key objects cannot live in a function pointer.

use certval::*;
use spki::AlgorithmIdentifierOwned;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: PKIXALG_SHA256,
        parameters: None,
    }
}

const ABC_SHA256: [u8; 32] =
    hex_literal::hex!("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");

/// Stands in for a hardware-backed implementation: it owns state (here a call counter, in practice
/// a module handle and a session pool) and is therefore not expressible as a function pointer.
struct CountingHasher {
    calls: AtomicUsize,
}

impl CountingHasher {
    fn new() -> Self {
        CountingHasher {
            calls: AtomicUsize::new(0),
        }
    }
}

impl CalculateHash for CountingHasher {
    fn calculate_hash(
        &self,
        pe: &PkiEnvironment,
        hash_alg: &AlgorithmIdentifierOwned,
        buffer_to_hash: &[u8],
    ) -> certval::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        calculate_hash_rust_crypto(pe, hash_alg, buffer_to_hash)
    }
}

/// Always declines, to exercise the fall-through to the next registered implementation.
struct DecliningHasher;

impl CalculateHash for DecliningHasher {
    fn calculate_hash(
        &self,
        _pe: &PkiEnvironment,
        _hash_alg: &AlgorithmIdentifierOwned,
        _buffer_to_hash: &[u8],
    ) -> certval::Result<Vec<u8>> {
        Err(Error::Unrecognized)
    }
}

/// A bare function still registers exactly as it did before the interface became a trait. Every
/// existing caller in the workspace takes this form, so this is the compatibility assertion.
#[test]
fn bare_function_registers() {
    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    pe.add_calculate_hash_callback(calculate_hash_rust_crypto);

    let result = pe.calculate_hash(&pe, &sha256(), b"abc").unwrap();
    assert_eq!(result, ABC_SHA256);
}

/// A value carrying state registers through the same method, and its state survives across calls.
#[test]
fn stateful_implementation_registers_and_retains_state() {
    let counter = Arc::new(CountingHasher::new());
    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    pe.add_calculate_hash_callback(counter.clone());

    for _ in 0..3 {
        let result = pe.calculate_hash(&pe, &sha256(), b"abc").unwrap();
        assert_eq!(result, ABC_SHA256);
    }

    // The registered implementation and the handle retained here are the same object.
    assert_eq!(counter.calls.load(Ordering::SeqCst), 3);
}

/// Both shapes coexist in one environment, and a declining implementation falls through to the next
/// rather than failing the operation.
#[test]
fn mixed_registration_falls_through_in_order() {
    let counter = Arc::new(CountingHasher::new());
    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    pe.add_calculate_hash_callback(DecliningHasher);
    pe.add_calculate_hash_callback(counter.clone());
    pe.add_calculate_hash_callback(calculate_hash_rust_crypto);

    let result = pe.calculate_hash(&pe, &sha256(), b"abc").unwrap();
    assert_eq!(result, ABC_SHA256);

    // The first implementation declined, so the second answered and the third was never reached.
    assert_eq!(counter.calls.load(Ordering::SeqCst), 1);
}

/// A closure registers too, since the blanket implementation covers anything callable with the
/// right signature. This gives a captured-state option without declaring a type.
#[test]
fn closure_registers_and_captures_state() {
    let counter = Arc::new(AtomicUsize::new(0));
    let seen = counter.clone();

    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    pe.add_calculate_hash_callback(
        move |pe: &PkiEnvironment, alg: &AlgorithmIdentifierOwned, buf: &[u8]| {
            seen.fetch_add(1, Ordering::SeqCst);
            calculate_hash_rust_crypto(pe, alg, buf)
        },
    );

    let result = pe.calculate_hash(&pe, &sha256(), b"abc").unwrap();
    assert_eq!(result, ABC_SHA256);
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

/// An unregistered algorithm still yields an error once every implementation has declined.
#[test]
fn exhausted_callbacks_report_unrecognized() {
    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    pe.add_calculate_hash_callback(DecliningHasher);

    assert!(pe.calculate_hash(&pe, &sha256(), b"abc").is_err());
}
