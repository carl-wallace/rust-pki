//! Provides support for FN-DSA (Falcon) signature verification.
//!
//! Falcon is not implemented by the RustCrypto project (see the note in the
//! [`fn-dsa`] crate: it exists because Thomas Pornin already published a Falcon
//! implementation), so this module wraps the verify-only [`fn-dsa-vrfy`] crate
//! rather than sitting alongside the ML-DSA/SLH-DSA support in [`crypto_pqc`](super::crypto_pqc).
//!
//! The hackathon/OQS Falcon OIDs (`1.3.9999.3.6`, `.9`, `.11`, `.14`) all identify
//! the NIST round-3 Falcon finalist, so verification uses the "original Falcon"
//! hashing (`SHAKE256(nonce || message)`) with no domain-separation context. The
//! unpublished FN-DSA draft may introduce a different pre-hash/domain-separation
//! scheme; only the frozen round-3 behavior these certificates were produced with
//! is implemented here.
//!
//! X.509 Falcon signatures carry the variable-length *compressed* signature
//! encoding, whereas `fn-dsa-vrfy` expects the fixed ("padded") length; this module
//! zero-pads the signature up to that fixed size before verifying (padded Falcon is
//! defined as the compressed signature followed by zero octets).
//!
//! [`fn-dsa`]: https://crates.io/crates/fn-dsa
//! [`fn-dsa-vrfy`]: https://crates.io/crates/fn-dsa-vrfy

#![cfg(feature = "pqc")]

use alloc::vec::Vec;

use log::error;

use fn_dsa_vrfy::{
    signature_size, VerifyingKey, VerifyingKey1024, VerifyingKey512, DOMAIN_NONE, FN_DSA_LOGN_1024,
    FN_DSA_LOGN_512, HASH_ID_ORIGINAL_FALCON,
};
use pqckeys::pqc_oids::{
    OQ_FALCON_1024, OQ_FALCON_512, OQ_FALCON_PADDED_1024, OQ_FALCON_PADDED_512,
};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use crate::{Error, PkiEnvironment};

/// Decode a Falcon verifying key of the given degree, normalize the signature to the fixed
/// length expected by `fn-dsa-vrfy`, and verify it against `message_to_verify`.
fn verify_falcon<VK: VerifyingKey>(
    logn: u32,
    message_to_verify: &[u8],
    spki_val: &[u8],
    signature: &[u8],
) -> crate::Result<()> {
    let vk = VK::decode(spki_val).ok_or(Error::PqcValidation)?;

    // X.509 Falcon signatures use the variable-length compressed encoding; fn-dsa-vrfy
    // requires exactly the fixed ("padded") size, so zero-pad a short signature. A
    // signature longer than the fixed size is malformed for this scheme.
    let target = signature_size(logn);
    let sig = match signature.len() {
        n if n == target => signature.to_vec(),
        n if n < target => {
            let mut s = Vec::with_capacity(target);
            s.extend_from_slice(signature);
            s.resize(target, 0);
            s
        }
        _ => {
            error!("FN-DSA (Falcon) signature exceeds the fixed size for the algorithm");
            return Err(Error::PqcValidation);
        }
    };

    if vk.verify(
        &sig,
        &DOMAIN_NONE,
        &HASH_ID_ORIGINAL_FALCON,
        message_to_verify,
    ) {
        Ok(())
    } else {
        error!("Failed to verify FN-DSA (Falcon) signature");
        Err(Error::Unrecognized)
    }
}

/// Verify FN-DSA (Falcon) signatures.
///
/// Returns [`Error::Unrecognized`] for algorithm identifiers this callback does not handle, so the
/// [`PkiEnvironment`] can fall through to the next `verify_signature_message` callback.
pub fn verify_signature_message_fndsa(
    _pe: &PkiEnvironment,
    message_to_verify: &[u8],                 // buffer to verify
    signature: &[u8],                         // signature
    signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
    spki: &SubjectPublicKeyInfoOwned,         // public key
) -> crate::Result<()> {
    let spki_val = spki.subject_public_key.raw_bytes();
    if OQ_FALCON_512 == signature_alg.oid || OQ_FALCON_PADDED_512 == signature_alg.oid {
        verify_falcon::<VerifyingKey512>(FN_DSA_LOGN_512, message_to_verify, spki_val, signature)
    } else if OQ_FALCON_1024 == signature_alg.oid || OQ_FALCON_PADDED_1024 == signature_alg.oid {
        verify_falcon::<VerifyingKey1024>(FN_DSA_LOGN_1024, message_to_verify, spki_val, signature)
    } else {
        Err(Error::Unrecognized)
    }
}
