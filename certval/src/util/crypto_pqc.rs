//! Provides support for ML-DSA and SLH-DSA signatures

#![cfg(feature = "pqc")]

use log::error;

use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use sha2::{Digest, Sha256, Sha512};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use slh_dsa::signature::Verifier;

use crate::{Error, PkiEnvironment};
use const_oid::db::{
    fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87, ID_HASH_ML_DSA_44_WITH_SHA_512,
              ID_HASH_ML_DSA_65_WITH_SHA_512, ID_HASH_ML_DSA_87_WITH_SHA_512},
    fips205::*,
};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

macro_rules! pqverify_mldsa {
    ($pkt:ty, $message_to_verify:ident, $spki_val:ident, $signature:ident, $ctx:ident) => {{
        let vk_bytes = ml_dsa::EncodedVerifyingKey::<$pkt>::try_from($spki_val)
            .map_err(|_e| Error::PqcValidation)?;
        let vk = ml_dsa::VerifyingKey::<$pkt>::decode(&vk_bytes);

        let sig_bytes = ml_dsa::EncodedSignature::<$pkt>::try_from($signature)
            .map_err(|_e| Error::PqcValidation)?;
        match ml_dsa::Signature::<$pkt>::decode(&sig_bytes) {
            Some(sig) => {
                if let Some(ctx) = $ctx {
                    match vk.verify_with_context($message_to_verify, ctx, &sig) {
                        true => return Ok(()),
                        false => {
                            error!("Failed to verify ML DSA signature with context");
                            return Err(Error::Unrecognized);
                        }
                    }
                } else {
                    match vk.verify($message_to_verify, &sig) {
                        Ok(_) => return Ok(()),
                        Err(e) => {
                            error!("Failed to verify ML DSA signature: {}", e);
                            return Err(Error::Unrecognized);
                        }
                    }
                };
            },
            None => {
                error!("Failed to decode signature");
                return Err(Error::Unrecognized);
            }
        }
    }};
}

macro_rules! pqverify_ph_mldsa {
    ($pkt:ty, $message_to_verify:ident, $spki_val:ident, $signature:ident) => {{
        let vk_bytes = ml_dsa::EncodedVerifyingKey::<$pkt>::try_from($spki_val)
            .map_err(|_e| Error::PqcValidation)?;
        let vk = ml_dsa::VerifyingKey::<$pkt>::decode(&vk_bytes);

        let sig_bytes = ml_dsa::EncodedSignature::<$pkt>::try_from($signature)
            .map_err(|_e| Error::PqcValidation)?;
        match ml_dsa::Signature::<$pkt>::decode(&sig_bytes) {
            Some(sig) => {
                let ph = Sha512::digest($message_to_verify);
                let one = [0x01];
                let ctx_len = [0x00];
                let oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
                let mut message_rep = vec![];
                message_rep.append(&mut one.to_vec());
                message_rep.append(&mut ctx_len.to_vec());
                message_rep.append(&mut oid.to_vec());
                message_rep.append(&mut ph.to_vec());

                match vk.verify_internal(&message_rep, &sig) {
                    true => return Ok(()),
                    false => {
                        error!("Failed to verify Hash ML DSA signature");
                        return Err(Error::Unrecognized);
                    }
                }
            },
            None => {
                error!("Failed to decode signature");
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

macro_rules! pqverify_ph_slhdsa {
    ($pkt:ty, $hash:ty, $oid:ident, $message_to_verify:ident, $spki_val:ident, $signature:ident) => {{
        let vk = slh_dsa::VerifyingKey::<$pkt>::try_from($spki_val)
            .map_err(|_e| Error::PqcValidation)?;
        let sig: slh_dsa::Signature<$pkt> = $signature
            .to_vec()
            .as_slice()
            .try_into()
            .map_err(|_e| Error::PqcValidation)?;
        let ph = <$hash>::digest($message_to_verify);
        let one = [0x01];
        let ctx_len = [0x00];
        let mut message_rep = vec![];
        message_rep.append(&mut one.to_vec());
        message_rep.append(&mut ctx_len.to_vec());
        message_rep.append(&mut $oid.to_vec());
        message_rep.append(&mut ph.to_vec());
        match vk.slh_verify_internal(&[&message_rep], &sig) {
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

macro_rules! pqverify_ph_slhdsa_shake {
    ($pkt:ty, $shake:ty, $hash_len:expr, $oid:ident, $message_to_verify:ident, $spki_val:ident, $signature:ident) => {{
        let vk = slh_dsa::VerifyingKey::<$pkt>::try_from($spki_val)
            .map_err(|_e| Error::PqcValidation)?;
        let sig: slh_dsa::Signature<$pkt> = $signature
            .to_vec()
            .as_slice()
            .try_into()
            .map_err(|_e| Error::PqcValidation)?;
        let mut hasher = <$shake>::default();
        hasher.update($message_to_verify);
        let mut reader = hasher.finalize_xof();
        let mut ph = [0u8; $hash_len];
        reader.read(&mut ph);
        let one = [0x01];
        let ctx_len = [0x00];
        let mut message_rep = vec![];
        message_rep.append(&mut one.to_vec());
        message_rep.append(&mut ctx_len.to_vec());
        message_rep.append(&mut $oid.to_vec());
        message_rep.append(&mut ph.to_vec());
        match vk.slh_verify_internal(&[&message_rep], &sig) {
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
    pe: &PkiEnvironment,
    message_to_verify: &[u8],                 // buffer to verify
    signature: &[u8],                         // signature
    signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
    spki: &SubjectPublicKeyInfoOwned,         // public key
) -> crate::Result<()> {
    verify_signature_message_ctx_rustcrypto(pe, message_to_verify, signature, signature_alg, spki, &None)
}

/// Verify ML-DSA and SLH-DSA signatures.
pub fn verify_signature_message_ctx_rustcrypto(
    _pe: &PkiEnvironment,
    message_to_verify: &[u8],                 // buffer to verify
    signature: &[u8],                         // signature
    signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
    spki: &SubjectPublicKeyInfoOwned,         // public key
    ctx: &Option<Vec<u8>>,
) -> crate::Result<()> {
    let spki_val = spki.subject_public_key.raw_bytes();
    if ID_ML_DSA_44 == signature_alg.oid {
        pqverify_mldsa!(MlDsa44, message_to_verify, spki_val, signature, ctx)
    } else if ID_ML_DSA_65 == signature_alg.oid {
        pqverify_mldsa!(MlDsa65, message_to_verify, spki_val, signature, ctx)
    } else if ID_ML_DSA_87 == signature_alg.oid {
        pqverify_mldsa!(MlDsa87, message_to_verify, spki_val, signature, ctx)
    } else if ID_HASH_ML_DSA_44_WITH_SHA_512 == signature_alg.oid {
        pqverify_ph_mldsa!(MlDsa44, message_to_verify, spki_val, signature)
    } else if ID_HASH_ML_DSA_65_WITH_SHA_512 == signature_alg.oid {
        pqverify_ph_mldsa!(MlDsa65, message_to_verify, spki_val, signature)
    } else if ID_HASH_ML_DSA_87_WITH_SHA_512 == signature_alg.oid {
        pqverify_ph_mldsa!(MlDsa87, message_to_verify, spki_val, signature)
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
    } else if ID_HASH_SLH_DSA_SHA_2_128_S_WITH_SHA_256 == signature_alg.oid {
        let sha256_oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        pqverify_ph_slhdsa!(slh_dsa::Sha2_128s, Sha256, sha256_oid, message_to_verify, spki_val, signature)
    } else if ID_HASH_SLH_DSA_SHA_2_128_F_WITH_SHA_256 == signature_alg.oid {
        let sha256_oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        pqverify_ph_slhdsa!(slh_dsa::Sha2_128f, Sha256, sha256_oid, message_to_verify, spki_val, signature)
    } else if ID_HASH_SLH_DSA_SHA_2_192_S_WITH_SHA_512 == signature_alg.oid {
        let sha512_oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
        pqverify_ph_slhdsa!(slh_dsa::Sha2_192s, Sha512, sha512_oid, message_to_verify, spki_val, signature)
    } else if ID_HASH_SLH_DSA_SHA_2_192_F_WITH_SHA_512 == signature_alg.oid {
        let sha512_oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
        pqverify_ph_slhdsa!(slh_dsa::Sha2_192f, Sha512, sha512_oid, message_to_verify, spki_val, signature)
    } else if ID_HASH_SLH_DSA_SHA_2_256_S_WITH_SHA_512 == signature_alg.oid {
        let sha512_oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
        pqverify_ph_slhdsa!(slh_dsa::Sha2_256s, Sha512, sha512_oid, message_to_verify, spki_val, signature)
    } else if ID_HASH_SLH_DSA_SHA_2_256_F_WITH_SHA_512 == signature_alg.oid {
        let sha512_oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
        pqverify_ph_slhdsa!(slh_dsa::Sha2_256f, Sha512, sha512_oid, message_to_verify, spki_val, signature)
    } else if ID_HASH_SLH_DSA_SHAKE_128_S_WITH_SHAKE_128 == signature_alg.oid {
        let shake128_oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B];
        pqverify_ph_slhdsa_shake!(slh_dsa::Shake128s, sha3::Shake128, 32, shake128_oid, message_to_verify, spki_val, signature)
    } else if ID_HASH_SLH_DSA_SHAKE_128_F_WITH_SHAKE_128 == signature_alg.oid {
        let shake128_oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B];
        pqverify_ph_slhdsa_shake!(slh_dsa::Shake128f, sha3::Shake128, 32, shake128_oid, message_to_verify, spki_val, signature)
    } else if ID_HASH_SLH_DSA_SHAKE_192_S_WITH_SHAKE_256 == signature_alg.oid {
        let shake256_oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C];
        pqverify_ph_slhdsa_shake!(slh_dsa::Shake192s, sha3::Shake256, 64, shake256_oid, message_to_verify, spki_val, signature)
    } else if ID_HASH_SLH_DSA_SHAKE_192_F_WITH_SHAKE_256 == signature_alg.oid {
        let shake256_oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C];
        pqverify_ph_slhdsa_shake!(slh_dsa::Shake192f, sha3::Shake256, 64, shake256_oid, message_to_verify, spki_val, signature)
    } else if ID_HASH_SLH_DSA_SHAKE_256_S_WITH_SHAKE_256 == signature_alg.oid {
        let shake256_oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C];
        pqverify_ph_slhdsa_shake!(slh_dsa::Shake256s, sha3::Shake256, 64, shake256_oid, message_to_verify, spki_val, signature)
    } else if ID_HASH_SLH_DSA_SHAKE_256_F_WITH_SHAKE_256 == signature_alg.oid {
        let shake256_oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C];
        pqverify_ph_slhdsa_shake!(slh_dsa::Shake256f, sha3::Shake256, 64, shake256_oid, message_to_verify, spki_val, signature)
    }
    Err(Error::Unrecognized)
}
