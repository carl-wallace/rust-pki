//! Provides support for composite ML-DSA signatures
//!
#![cfg(feature = "pqc")]

use crate::crypto::{is_ecdsa, is_eddsa, is_rsa};
use crate::{
    Error, PkiEnvironment, RsaPssParams, TrailerField, PKIXALG_ECDSA_WITH_SHA256,
    PKIXALG_ECDSA_WITH_SHA384, PKIXALG_ECDSA_WITH_SHA512, PKIXALG_SECP256R1, PKIXALG_SECP384R1,
    PKIXALG_SECP521R1, PKIXALG_SHA256_WITH_RSA_ENCRYPTION, PKIXALG_SHA384_WITH_RSA_ENCRYPTION,
};
use alloc::{vec, vec::Vec};
use const_oid::db::fips204::*;
use const_oid::db::rfc5912::{
    ID_EC_PUBLIC_KEY, ID_MGF_1, ID_RSASSA_PSS, ID_SHA_256, ID_SHA_384, RSA_ENCRYPTION,
};
#[cfg(feature = "eddsa")]
use const_oid::db::rfc8410::ID_ED_25519;
use const_oid::ObjectIdentifier;
use der::asn1::BitString;
use der::Decode;
use der::Encode;
use der::{Any, AnyRef};
use hex_literal::hex;
use lazy_static::lazy_static;
use log::error;
use pqckeys::pqc_oids::*;
use sha2::Digest;
use sha2::{Sha256, Sha512};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

/// Returns DER encoded RSA PSS parameters for use with 2048-bit RSA keys or other as per section
/// [7.3 of draft-ietf-lamps-pq-composite-sigs-06](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-06#section-7.3).
fn get_rss_params(for_4096: bool) -> crate::Result<Vec<u8>> {
    if !for_4096 {
        let mfg_param = AlgorithmIdentifierOwned {
            oid: ID_SHA_256,
            parameters: Some(Any::from(AnyRef::NULL)),
        };
        let der_mfg_param = mfg_param.to_der()?;
        let params = RsaPssParams {
            hash: AlgorithmIdentifierOwned {
                oid: ID_SHA_256,
                parameters: None,
            },
            mask_gen: AlgorithmIdentifierOwned {
                oid: ID_MGF_1,
                parameters: Some(Any::from_der(&der_mfg_param)?),
            },
            salt_len: 256,
            trailer_field: TrailerField::BC,
        };
        Ok(params.to_der()?)
    } else {
        let mfg_param = AlgorithmIdentifierOwned {
            oid: ID_SHA_384,
            parameters: Some(Any::from(AnyRef::NULL)),
        };
        let der_mfg_param = mfg_param.to_der()?;
        let params = RsaPssParams {
            hash: AlgorithmIdentifierOwned {
                oid: ID_SHA_384,
                parameters: None,
            },
            mask_gen: AlgorithmIdentifierOwned {
                oid: ID_MGF_1,
                parameters: Some(Any::from_der(&der_mfg_param)?),
            },
            salt_len: 384,
            trailer_field: TrailerField::BC,
        };
        Ok(params.to_der()?)
    }
}

/// Takes a composite OID and returns a pair of AlgorithmIdentifiers representing the two algorithms
/// represented by the composite OID.
fn is_composite(
    composite_oid: ObjectIdentifier,
) -> crate::Result<(AlgorithmIdentifierOwned, AlgorithmIdentifierOwned)> {
    use pqckeys::pqc_oids::*;
    if ID_MLDSA44_RSA2048_PSS_SHA256 == composite_oid {
        let pqc = AlgorithmIdentifierOwned {
            oid: ID_ML_DSA_44,
            parameters: None,
        };
        let der_params = get_rss_params(false)?;
        let trad = AlgorithmIdentifierOwned {
            oid: ID_RSASSA_PSS,
            parameters: Some(Any::from_der(&der_params)?),
        };
        Ok((pqc, trad))
    } else if ID_MLDSA44_RSA2048_PKCS15_SHA256 == composite_oid {
        let pqc = AlgorithmIdentifierOwned {
            oid: ID_ML_DSA_44,
            parameters: None,
        };
        let trad = AlgorithmIdentifierOwned {
            oid: PKIXALG_SHA256_WITH_RSA_ENCRYPTION,
            parameters: Some(Any::from(AnyRef::NULL)),
        };
        Ok((pqc, trad))
    } else if ID_MLDSA44_ED25519_SHA512 == composite_oid {
        #[cfg(feature = "eddsa")]
        {
            let pqc = AlgorithmIdentifierOwned {
                oid: ID_ML_DSA_44,
                parameters: None,
            };
            let trad = AlgorithmIdentifierOwned {
                oid: ID_ED_25519,
                parameters: None,
            };
            Ok((pqc, trad))
        }
        #[cfg(not(feature = "eddsa"))]
        {
            Err(Error::Unrecognized)
        }
    } else if ID_MLDSA44_ECDSA_P256_SHA256 == composite_oid {
        let pqc = AlgorithmIdentifierOwned {
            oid: ID_ML_DSA_44,
            parameters: None,
        };
        let trad_der = PKIXALG_SECP256R1.to_der()?;
        let trad = AlgorithmIdentifierOwned {
            oid: PKIXALG_ECDSA_WITH_SHA256,
            parameters: Some(Any::from_der(trad_der.as_slice())?),
        };
        Ok((pqc, trad))
    } else if ID_MLDSA65_RSA3072_PSS_SHA512 == composite_oid
        || ID_MLDSA65_RSA4096_PSS_SHA512 == composite_oid
    {
        let pqc = AlgorithmIdentifierOwned {
            oid: ID_ML_DSA_65,
            parameters: None,
        };
        let der_params = get_rss_params(ID_MLDSA65_RSA4096_PSS_SHA512 == composite_oid)?;
        let trad = AlgorithmIdentifierOwned {
            oid: ID_RSASSA_PSS,
            parameters: Some(Any::from_der(&der_params)?),
        };
        Ok((pqc, trad))
    } else if ID_MLDSA65_RSA3072_PKCS15_SHA512 == composite_oid {
        let pqc = AlgorithmIdentifierOwned {
            oid: ID_ML_DSA_65,
            parameters: None,
        };
        let trad = AlgorithmIdentifierOwned {
            oid: PKIXALG_SHA256_WITH_RSA_ENCRYPTION,
            parameters: Some(Any::from(AnyRef::NULL)),
        };
        Ok((pqc, trad))
    } else if ID_MLDSA65_RSA4096_PKCS15_SHA512 == composite_oid {
        let pqc = AlgorithmIdentifierOwned {
            oid: ID_ML_DSA_65,
            parameters: None,
        };
        let trad = AlgorithmIdentifierOwned {
            oid: PKIXALG_SHA384_WITH_RSA_ENCRYPTION,
            parameters: Some(Any::from(AnyRef::NULL)),
        };
        Ok((pqc, trad))
    } else if ID_MLDSA65_ECDSA_P256_SHA512 == composite_oid {
        let pqc = AlgorithmIdentifierOwned {
            oid: ID_ML_DSA_65,
            parameters: None,
        };
        let trad_der = PKIXALG_SECP256R1.to_der()?;
        let trad = AlgorithmIdentifierOwned {
            oid: PKIXALG_ECDSA_WITH_SHA256,
            parameters: Some(Any::from_der(trad_der.as_slice())?),
        };
        Ok((pqc, trad))
    } else if ID_MLDSA65_ECDSA_P384_SHA512 == composite_oid {
        let pqc = AlgorithmIdentifierOwned {
            oid: ID_ML_DSA_65,
            parameters: None,
        };
        let trad_der = PKIXALG_SECP384R1.to_der()?;
        let trad = AlgorithmIdentifierOwned {
            oid: PKIXALG_ECDSA_WITH_SHA384,
            parameters: Some(Any::from_der(trad_der.as_slice())?),
        };
        Ok((pqc, trad))
    } else if ID_MLDSA65_ED25519_SHA512 == composite_oid {
        #[cfg(feature = "eddsa")]
        {
            let pqc = AlgorithmIdentifierOwned {
                oid: ID_ML_DSA_65,
                parameters: None,
            };
            let trad = AlgorithmIdentifierOwned {
                oid: ID_ED_25519,
                parameters: None,
            };
            Ok((pqc, trad))
        }
        #[cfg(not(feature = "eddsa"))]
        {
            Err(Error::Unrecognized)
        }
    } else if ID_MLDSA87_ECDSA_P384_SHA512 == composite_oid {
        let pqc = AlgorithmIdentifierOwned {
            oid: ID_ML_DSA_87,
            parameters: None,
        };
        let trad_der = PKIXALG_SECP384R1.to_der()?;
        let trad = AlgorithmIdentifierOwned {
            oid: PKIXALG_ECDSA_WITH_SHA384,
            parameters: Some(Any::from_der(trad_der.as_slice())?),
        };
        Ok((pqc, trad))
    } else if ID_MLDSA87_ED448_SHAKE256 == composite_oid {
        // ML-DSA-87 + Ed448 is not supported (no eddsa/Ed448 wiring); treat as unrecognized
        // rather than panicking on an otherwise well-formed composite OID.
        Err(Error::Unrecognized)
    } else if ID_MLDSA87_RSA3072_PSS_SHA512 == composite_oid
        || ID_MLDSA87_RSA4096_PSS_SHA512 == composite_oid
    {
        let pqc = AlgorithmIdentifierOwned {
            oid: ID_ML_DSA_87,
            parameters: None,
        };
        let der_params = get_rss_params(ID_MLDSA87_RSA4096_PSS_SHA512 == composite_oid)?;
        let trad = AlgorithmIdentifierOwned {
            oid: ID_RSASSA_PSS,
            parameters: Some(Any::from_der(&der_params)?),
        };
        Ok((pqc, trad))
    } else if ID_MLDSA87_ECDSA_P521_SHA512 == composite_oid {
        let pqc = AlgorithmIdentifierOwned {
            oid: ID_ML_DSA_87,
            parameters: None,
        };
        let trad_der = PKIXALG_SECP521R1.to_der()?;
        let trad = AlgorithmIdentifierOwned {
            oid: PKIXALG_ECDSA_WITH_SHA512,
            parameters: Some(Any::from_der(trad_der.as_slice())?),
        };
        Ok((pqc, trad))
    } else {
        Err(Error::Unrecognized)
    }
}

/// Splits a composite signature based on the OID representing the PQC algorithm component of the
/// composite signature.
fn split_sig(pqc_oid: ObjectIdentifier, composite: &[u8]) -> crate::Result<(&[u8], &[u8])> {
    let split_at = if ID_ML_DSA_44 == pqc_oid {
        2420
    } else if ID_ML_DSA_65 == pqc_oid {
        3309
    } else if ID_ML_DSA_87 == pqc_oid {
        4627
    } else {
        error!("Unrecognized PQC OID passed to split_sig: {pqc_oid}");
        return Err(Error::Unrecognized);
    };
    // split_at would panic if the composite is shorter than the expected ML-DSA component,
    // so bound-check the caller-supplied bytes and return an error instead.
    composite.split_at_checked(split_at).ok_or_else(|| {
        error!("composite signature too short to split at {split_at} for PQC OID {pqc_oid}");
        Error::Unrecognized
    })
}

/// Returns a DER-encoded object identifier representing the named curve from the ECDSA component of
/// a composite algorithm.
fn get_curve(trad_oid: ObjectIdentifier) -> crate::Result<Vec<u8>> {
    if PKIXALG_ECDSA_WITH_SHA256 == trad_oid {
        Ok(PKIXALG_SECP256R1.to_der()?)
    } else if PKIXALG_ECDSA_WITH_SHA384 == trad_oid {
        Ok(PKIXALG_SECP384R1.to_der()?)
    } else if PKIXALG_ECDSA_WITH_SHA512 == trad_oid {
        Ok(PKIXALG_SECP521R1.to_der()?)
    } else {
        error!("Unrecognized OID passed to get_curve: {trad_oid}");
        Err(Error::Unrecognized)
    }
}

/// Splits a key based on the OID identifying the PQC component of a composite algorithm and returns
/// a pair of SubjectKeyIdentifiers representing the PQC and traditional keys.
fn split_key(
    pqc_oid: ObjectIdentifier,
    trad_oid: ObjectIdentifier,
    composite: &[u8],
) -> crate::Result<(SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoOwned)> {
    let split_at = if ID_ML_DSA_44 == pqc_oid {
        1312
    } else if ID_ML_DSA_65 == pqc_oid {
        1952
    } else if ID_ML_DSA_87 == pqc_oid {
        2592
    } else {
        error!("Unrecognized PQC OID passed to split_key: {pqc_oid}");
        return Err(Error::Unrecognized);
    };
    // Bound-check before split_at so a short composite key returns an error rather than panicking.
    let (pqc_key, trad_key) = match composite.split_at_checked(split_at) {
        Some(parts) => parts,
        None => {
            error!("composite key too short to split at {split_at} for PQC OID {pqc_oid}");
            return Err(Error::Unrecognized);
        }
    };

    let pqc_spki = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: pqc_oid,
            parameters: None,
        },
        subject_public_key: BitString::from_bytes(pqc_key)?,
    };
    let trad_spki = if is_ecdsa(&trad_oid) {
        let curve = get_curve(trad_oid)?;
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ID_EC_PUBLIC_KEY,
                parameters: Some(Any::from_der(curve.as_slice())?),
            },
            subject_public_key: BitString::from_bytes(trad_key)?,
        }
    } else if is_rsa(&trad_oid) || ID_RSASSA_PSS == trad_oid {
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: RSA_ENCRYPTION,
                parameters: Some(Any::from(AnyRef::NULL)),
            },
            subject_public_key: BitString::from_bytes(trad_key)?,
        }
    } else if is_eddsa(&trad_oid) {
        #[cfg(feature = "eddsa")]
        {
            SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: ID_ED_25519,
                    parameters: Some(Any::from(AnyRef::NULL)),
                },
                subject_public_key: BitString::from_bytes(trad_key)?,
            }
        }
        #[cfg(not(feature = "eddsa"))]
        {
            return Err(Error::Unrecognized);
        }
    } else {
        error!("Unrecognized traditional OID passed to split_key: {trad_oid}");
        return Err(Error::Unrecognized);
    };
    Ok((pqc_spki, trad_spki))
}

/// Hashes a given message using hash algorithm determined by a given composite OID.
fn hash_message(composite_oid: ObjectIdentifier, message: &[u8]) -> crate::Result<Vec<u8>> {
    if composite_oid == ID_MLDSA44_RSA2048_PKCS15_SHA256
        || composite_oid == ID_MLDSA44_RSA2048_PSS_SHA256
        || composite_oid == ID_MLDSA44_ECDSA_P256_SHA256
    {
        Ok(Sha256::digest(message).as_slice().to_vec())
    } else if composite_oid == ID_MLDSA87_ED448_SHAKE256 {
        // ML-DSA-87 + Ed448 (SHAKE256) is unsupported; return an error instead of panicking.
        Err(Error::Unrecognized)
    } else {
        Ok(Sha512::digest(message).as_slice().to_vec())
    }
}

lazy_static! {
    static ref PREFIX: [u8; 32] =
        hex!("436F6D706F73697465416C676F726974686D5369676E61747572657332303235");
}
/// Gets the domain separator for a given OID.
pub fn get_domain(oid: ObjectIdentifier) -> crate::Result<Vec<u8>> {
    if oid == ID_MLKEM768_RSA2048_SHA3_256 {
        Ok(DS_MLKEM768_RSA2048_SHA3_256.to_vec())
    } else if oid == ID_MLKEM768_RSA3072_SHA3_256 {
        Ok(DS_MLKEM768_RSA3072_SHA3_256.to_vec())
    } else if oid == ID_MLKEM768_RSA4096_SHA3_256 {
        Ok(DS_MLKEM768_RSA4096_SHA3_256.to_vec())
    } else if oid == ID_MLKEM768_X25519_SHA3_256 {
        Ok(DS_MLKEM768_X25519_SHA3_256.to_vec())
    } else if oid == ID_MLKEM768_ECDH_P256_SHA3_256 {
        Ok(DS_MLKEM768_ECDH_P256_SHA3_256.to_vec())
    } else if oid == ID_MLKEM768_ECDH_P384_SHA3_256 {
        Ok(DS_MLKEM768_ECDH_P384_SHA3_256.to_vec())
    } else if oid == ID_MLKEM768_ECDH_BRAINPOOL_P256R1_SHA3_256 {
        Ok(DS_MLKEM768_ECDH_BRAINPOOL_P256R1_SHA3_256.to_vec())
    } else if oid == ID_MLKEM1024_RSA3072_SHA3_256 {
        Ok(DS_MLKEM1024_RSA3072_SHA3_256.to_vec())
    } else if oid == ID_MLKEM1024_ECDH_P384_SHA3_256 {
        Ok(DS_MLKEM1024_ECDH_P384_SHA3_256.to_vec())
    } else if oid == ID_MLKEM1024_ECDH_BRAINPOOL_P384R1_SHA3_256 {
        Ok(DS_MLKEM1024_ECDH_BRAINPOOL_P384R1_SHA3_256.to_vec())
    } else if oid == ID_MLKEM1024_X448_SHA3_256 {
        Ok(DS_MLKEM1024_X448_SHA3_256.to_vec())
    } else if oid == ID_MLKEM1024_ECDH_P521_SHA3_256 {
        Ok(DS_MLKEM1024_ECDH_P521_SHA3_256.to_vec())
    } else if oid == ID_MLDSA44_RSA2048_PSS_SHA256 {
        Ok(DS_MLDSA44_RSA2048_PSS_SHA256.to_vec())
    } else if oid == ID_MLDSA44_RSA2048_PKCS15_SHA256 {
        Ok(DS_MLDSA44_RSA2048_PKCS15_SHA256.to_vec())
    } else if oid == ID_MLDSA44_ED25519_SHA512 {
        Ok(DS_MLDSA44_ED25519_SHA512.to_vec())
    } else if oid == ID_MLDSA44_ECDSA_P256_SHA256 {
        Ok(DS_MLDSA44_ECDSA_P256_SHA256.to_vec())
    } else if oid == ID_MLDSA65_RSA3072_PSS_SHA512 {
        Ok(DS_MLDSA65_RSA3072_PSS_SHA512.to_vec())
    } else if oid == ID_MLDSA65_RSA3072_PKCS15_SHA512 {
        Ok(DS_MLDSA65_RSA3072_PKCS15_SHA512.to_vec())
    } else if oid == ID_MLDSA65_RSA4096_PSS_SHA512 {
        Ok(DS_MLDSA65_RSA4096_PSS_SHA512.to_vec())
    } else if oid == ID_MLDSA65_RSA4096_PKCS15_SHA512 {
        Ok(DS_MLDSA65_RSA4096_PKCS15_SHA512.to_vec())
    } else if oid == ID_MLDSA65_ECDSA_P256_SHA512 {
        Ok(DS_MLDSA65_ECDSA_P256_SHA512.to_vec())
    } else if oid == ID_MLDSA65_ECDSA_P384_SHA512 {
        Ok(DS_MLDSA65_ECDSA_P384_SHA512.to_vec())
    } else if oid == ID_MLDSA65_ECDSA_BRAINPOOL_P256R1_SHA512 {
        Ok(DS_MLDSA65_ECDSA_BRAINPOOL_P256R1_SHA512.to_vec())
    } else if oid == ID_MLDSA65_ED25519_SHA512 {
        Ok(DS_MLDSA65_ED25519_SHA512.to_vec())
    } else if oid == ID_MLDSA87_ECDSA_P384_SHA512 {
        Ok(DS_MLDSA87_ECDSA_P384_SHA512.to_vec())
    } else if oid == ID_MLDSA87_ECDSA_BRAINPOOL_P384R1_SHA512 {
        Ok(DS_MLDSA87_ECDSA_BRAINPOOL_P384R1_SHA512.to_vec())
    } else if oid == ID_MLDSA87_ED448_SHAKE256 {
        Ok(DS_MLDSA87_ED448_SHAKE256.to_vec())
    } else if oid == ID_MLDSA87_RSA3072_PSS_SHA512 {
        Ok(DS_MLDSA87_RSA3072_PSS_SHA512.to_vec())
    } else if oid == ID_MLDSA87_RSA4096_PSS_SHA512 {
        Ok(DS_MLDSA87_RSA4096_PSS_SHA512.to_vec())
    } else if oid == ID_MLDSA87_ECDSA_P521_SHA512 {
        Ok(DS_MLDSA87_ECDSA_P521_SHA512.to_vec())
    } else {
        Err(crate::Error::Unrecognized)
    }
}

/// verify_signature_message_composite
pub fn verify_signature_message_composite_rustcrypto(
    pe: &PkiEnvironment,
    message_to_verify: &[u8],                 // buffer to verify
    signature: &[u8],                         // signature
    signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
    spki: &SubjectPublicKeyInfoOwned,         // public key
) -> crate::Result<()> {
    if let Ok((pqc, trad)) = is_composite(signature_alg.oid) {
        let (pqc_spki, trad_spki) =
            split_key(pqc.oid, trad.oid, spki.subject_public_key.raw_bytes())?;

        let label = get_domain(signature_alg.oid)?;
        let ctx_len = [0x00];
        let (pqc_sig, trad_sig) = split_sig(pqc.oid, signature)?;
        let hash = hash_message(signature_alg.oid, message_to_verify)?;

        // Prefix || Label || len(ctx) || ctx || PH( M )
        let mut message_rep = vec![];
        message_rep.append(&mut PREFIX.to_vec());
        message_rep.append(&mut label.to_vec());
        message_rep.append(&mut ctx_len.to_vec());
        message_rep.append(&mut hash.to_vec());

        pe.verify_signature_message_ctx(pe, &message_rep, pqc_sig, &pqc, &pqc_spki, &Some(label))?;
        pe.verify_signature_message(pe, &message_rep, trad_sig, &trad, &trad_spki)?;
        return Ok(());
    }
    Err(Error::Unrecognized)
}
