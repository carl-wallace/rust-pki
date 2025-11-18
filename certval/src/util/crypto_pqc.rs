//! Provides support for ML-DSA and SLH-DSA signatures

#![cfg(feature = "pqc")]

use log::error;

use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use slh_dsa::signature::Verifier;

use crate::{Error, PkiEnvironment};
use const_oid::db::{
    fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87},
    fips205::*,
};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

macro_rules! pqverify_mldsa {
    ($pkt:ty, $message_to_verify:ident, $spki_val:ident, $signature:ident) => {{
        let vk_bytes = ml_dsa::EncodedVerifyingKey::<$pkt>::try_from($spki_val)
            .map_err(|_e| Error::PqcValidation)?;
        let vk = ml_dsa::VerifyingKey::<$pkt>::decode(&vk_bytes);

        let sig_bytes = ml_dsa::EncodedSignature::<$pkt>::try_from($signature)
            .map_err(|_e| Error::PqcValidation)?;
        let sig = ml_dsa::Signature::<$pkt>::decode(&sig_bytes);

        match sig.map(|sig| vk.verify_internal($message_to_verify, &sig)) {
            Some(_) => {
                return Ok(());
            }
            None => {
                return Err(Error::Unrecognized);
            }
        }
    }};
}

macro_rules! pqverify_slhdsa {
    ($pkt:ty, $message_to_verify:ident, $spki_val:ident, $signature:ident) => {{
        let vk = slh_dsa::VerifyingKey::<$pkt>::try_from($spki_val)
            .map_err(|_e| Error::PqcValidation)?;
        let sig: slh_dsa::Signature<$pkt> = $signature
            .to_vec()
            .as_slice()
            .try_into()
            .map_err(|_e| Error::PqcValidation)?;
        match vk.verify($message_to_verify, &sig) {
            Ok(_) => {
                return Ok(());
            }
            Err(e) => {
                error!("Failed to verify SLH DSA signature: {}", e);
                return Err(Error::Unrecognized);
            }
        }
    }};
}

/// Verify ML-DSA and SLH-DSA signatures.
pub fn verify_signature_message_rustcrypto(
    _pe: &PkiEnvironment,
    message_to_verify: &[u8],                 // buffer to verify
    signature: &[u8],                         // signature
    signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
    spki: &SubjectPublicKeyInfoOwned,         // public key
) -> crate::Result<()> {
    let spki_val = spki.subject_public_key.raw_bytes();
    if ID_ML_DSA_44 == signature_alg.oid {
        pqverify_mldsa!(MlDsa44, message_to_verify, spki_val, signature)
    } else if ID_ML_DSA_65 == signature_alg.oid {
        pqverify_mldsa!(MlDsa65, message_to_verify, spki_val, signature)
    } else if ID_ML_DSA_87 == signature_alg.oid {
        pqverify_mldsa!(MlDsa87, message_to_verify, spki_val, signature)
    } else if ID_SLH_DSA_SHA_2_128_F == signature_alg.oid {
        pqverify_slhdsa!(slh_dsa::Sha2_128f, message_to_verify, spki_val, signature)
    } else if ID_SLH_DSA_SHA_2_128_S == signature_alg.oid {
        pqverify_slhdsa!(slh_dsa::Sha2_128s, message_to_verify, spki_val, signature)
    } else if ID_SLH_DSA_SHA_2_192_F == signature_alg.oid {
        pqverify_slhdsa!(slh_dsa::Sha2_192f, message_to_verify, spki_val, signature)
    } else if ID_SLH_DSA_SHA_2_192_S == signature_alg.oid {
        pqverify_slhdsa!(slh_dsa::Sha2_192s, message_to_verify, spki_val, signature)
    } else if ID_SLH_DSA_SHA_2_256_F == signature_alg.oid {
        pqverify_slhdsa!(slh_dsa::Sha2_256f, message_to_verify, spki_val, signature)
    } else if ID_SLH_DSA_SHA_2_256_S == signature_alg.oid {
        pqverify_slhdsa!(slh_dsa::Sha2_256s, message_to_verify, spki_val, signature)
    } else if ID_SLH_DSA_SHAKE_128_F == signature_alg.oid {
        pqverify_slhdsa!(slh_dsa::Shake128f, message_to_verify, spki_val, signature)
    } else if ID_SLH_DSA_SHAKE_128_S == signature_alg.oid {
        pqverify_slhdsa!(slh_dsa::Shake128s, message_to_verify, spki_val, signature)
    } else if ID_SLH_DSA_SHAKE_192_F == signature_alg.oid {
        pqverify_slhdsa!(slh_dsa::Shake192f, message_to_verify, spki_val, signature)
    } else if ID_SLH_DSA_SHAKE_192_S == signature_alg.oid {
        pqverify_slhdsa!(slh_dsa::Shake192s, message_to_verify, spki_val, signature)
    } else if ID_SLH_DSA_SHAKE_256_F == signature_alg.oid {
        pqverify_slhdsa!(slh_dsa::Shake256f, message_to_verify, spki_val, signature)
    } else if ID_SLH_DSA_SHAKE_256_S == signature_alg.oid {
        pqverify_slhdsa!(slh_dsa::Shake256s, message_to_verify, spki_val, signature)
    }
    Err(Error::Unrecognized)
}
