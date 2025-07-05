//! Provides implementations of crypto-related [`PkiEnvironment`] interfaces using libraries from the
//! [Rust Crypto](https://github.com/RustCrypto) project for support.

use alloc::vec::Vec;

use log::{debug, error};

use der::{asn1::ObjectIdentifier, AnyRef, Encode};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

#[cfg(feature = "pqc")]
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
#[cfg(feature = "pqc")]
use pqckeys::pqc_oids::*;
#[cfg(feature = "pqc")]
use slh_dsa::signature::Verifier;

#[cfg(feature = "pqc")]
use const_oid::db::{
    fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87},
    fips205::*,
};

use crate::util::error::{Error, PathValidationStatus, Result};
use crate::{environment::pki_environment::*, util::pdv_alg_oids::*};

/// get_padding_scheme takes an AlgorithmIdentifier containing a signature algorithm and returns
/// a corresponding PaddingScheme instance.
///
/// At present, only the PKCS1v15Sign passing scheme is supported, relative to the
/// [`PKIXALG_SHA224_WITH_RSA_ENCRYPTION`], [`PKIXALG_SHA256_WITH_RSA_ENCRYPTION`],
/// [`PKIXALG_SHA384_WITH_RSA_ENCRYPTION`] and [`PKIXALG_SHA512_WITH_RSA_ENCRYPTION`] algorithm identifiers.
#[cfg(feature = "rsa")]
pub fn get_padding_scheme(signature_alg: &AlgorithmIdentifierOwned) -> Result<rsa::Pkcs1v15Sign> {
    match signature_alg.oid {
        PKIXALG_SHA256_WITH_RSA_ENCRYPTION => Ok(rsa::Pkcs1v15Sign::new::<Sha256>()),
        PKIXALG_SHA384_WITH_RSA_ENCRYPTION => Ok(rsa::Pkcs1v15Sign::new::<Sha384>()),
        PKIXALG_SHA224_WITH_RSA_ENCRYPTION => Ok(rsa::Pkcs1v15Sign::new::<Sha224>()),
        PKIXALG_SHA512_WITH_RSA_ENCRYPTION => Ok(rsa::Pkcs1v15Sign::new::<Sha512>()),
        _ => Err(Error::Unrecognized),
    }
}

/// is_rsa returns true is the presented OID is one of [`PKIXALG_SHA224_WITH_RSA_ENCRYPTION`],
/// [`PKIXALG_SHA256_WITH_RSA_ENCRYPTION`], [`PKIXALG_SHA384_WITH_RSA_ENCRYPTION`] or
/// [`PKIXALG_SHA512_WITH_RSA_ENCRYPTION`] and false otherwise.
pub(crate) fn is_rsa(oid: &ObjectIdentifier) -> bool {
    *oid == PKIXALG_SHA256_WITH_RSA_ENCRYPTION
        || *oid == PKIXALG_SHA384_WITH_RSA_ENCRYPTION
        || *oid == PKIXALG_SHA224_WITH_RSA_ENCRYPTION
        || *oid == PKIXALG_SHA512_WITH_RSA_ENCRYPTION
}

/// is_ecdsa returns true is the presented OID is one of [`PKIXALG_ECDSA_WITH_SHA224`],
/// [`PKIXALG_ECDSA_WITH_SHA256`], [`PKIXALG_ECDSA_WITH_SHA384`] or [`PKIXALG_ECDSA_WITH_SHA512`] and false otherwise.
pub(crate) fn is_ecdsa(oid: &ObjectIdentifier) -> bool {
    *oid == PKIXALG_EC_PUBLIC_KEY
        || *oid == PKIXALG_ECDSA_WITH_SHA256
        || *oid == PKIXALG_ECDSA_WITH_SHA384
        || *oid == PKIXALG_ECDSA_WITH_SHA224
        || *oid == PKIXALG_ECDSA_WITH_SHA512
}

#[allow(unused_variables)]
pub(crate) fn is_eddsa(oid: &ObjectIdentifier) -> bool {
    #[cfg(feature = "eddsa")]
    {
        *oid == PKIXALG_ED25519
    }
    #[cfg(not(feature = "eddsa"))]
    {
        false
    }
}

/// calculate_hash_rust_crypto implements the [`CalculateHash`](../certval/pki_environment_traits/type.CalculateHash.html) interface for [`PkiEnvironment`] using
/// implementations from the Rust Crypto project.
///
/// It supports [`PKIXALG_SHA224`], [`PKIXALG_SHA256`], [`PKIXALG_SHA384`] and [`PKIXALG_SHA512`].
pub fn calculate_hash_rust_crypto(
    _pe: &PkiEnvironment,
    hash_alg: &AlgorithmIdentifierOwned,
    buffer_to_hash: &[u8],
) -> Result<Vec<u8>> {
    match hash_alg.oid {
        PKIXALG_SHA224 => {
            let digest = Sha224::digest(buffer_to_hash).to_vec();
            Ok(digest)
        }
        PKIXALG_SHA256 => {
            let digest = Sha256::digest(buffer_to_hash).to_vec();
            Ok(digest)
        }
        PKIXALG_SHA384 => {
            let digest = Sha384::digest(buffer_to_hash).to_vec();
            Ok(digest)
        }
        PKIXALG_SHA512 => {
            let digest = Sha512::digest(buffer_to_hash).to_vec();
            Ok(digest)
        }
        _ => Err(Error::Unrecognized),
    }
}

/// verify_signature_digest_rust_crypto implements the [`VerifySignatureDigest`](../certval/pki_environment_traits/type.VerifySignatureDigest.html) interface for [`PkiEnvironment`] using
/// implementations from the [Rust Crypto](https://github.com/RustCrypto) project.
///
/// Only RSA is supported by this function. To verify ECDSA signatures, use [`verify_signature_message_rust_crypto`].
#[allow(unused_variables)]
pub fn verify_signature_digest_rust_crypto(
    _pe: &PkiEnvironment,
    hash_to_verify: &[u8],                    // buffer to verify
    signature: &[u8],                         // signature
    signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
    spki: &SubjectPublicKeyInfoOwned,         // public key
) -> Result<()> {
    if let Ok(enc_spki) = spki.to_der() {
        #[cfg(feature = "rsa")]
        if is_rsa(&signature_alg.oid) {
            use rsa::pkcs8::DecodePublicKey as _;
            let rsa = rsa::RsaPublicKey::from_public_key_der(&enc_spki);
            if let Ok(rsa) = rsa {
                let ps = get_padding_scheme(signature_alg)?;
                let x = rsa.verify(ps, hash_to_verify, signature);
                match x {
                    Ok(x) => {
                        return Ok(x);
                    }
                    Err(_x) => {
                        return Err(Error::PathValidation(
                            PathValidationStatus::SignatureVerificationFailure,
                        ));
                    }
                }
            }
        }
    }
    Err(Error::Unrecognized)
}

fn get_named_curve_parameter(alg_id: &AlgorithmIdentifierOwned) -> Result<ObjectIdentifier> {
    if let Some(params) = &alg_id.parameters {
        let ar: AnyRef<'_> = params.into();
        if let Ok(oid) = ObjectIdentifier::try_from(ar) {
            return Ok(oid);
        }
    }
    Err(Error::PathValidation(PathValidationStatus::EncodingError))
}

/// verify_signature_digest_rust_crypto implements the [`VerifySignatureMessage`](../certval/pki_environment_traits/type.VerifySignatureMessage.html) interface for [`PkiEnvironment`] using
/// implementations from the [Rust Crypto](https://github.com/RustCrypto) project.
///
/// RSA, P256, and P384 signatures are supported at present.
#[allow(unused_variables)]
pub fn verify_signature_message_rust_crypto(
    pe: &PkiEnvironment,
    message_to_verify: &[u8],                 // buffer to verify
    signature: &[u8],                         // signature
    signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
    spki: &SubjectPublicKeyInfoOwned,         // public key
) -> Result<()> {
    if is_rsa(&signature_alg.oid) {
        #[cfg(feature = "rsa")]
        if let Ok(enc_spki) = spki.to_der() {
            use rsa::pkcs8::DecodePublicKey as _;
            let rsa = rsa::RsaPublicKey::from_public_key_der(&enc_spki);
            if let Ok(rsa) = rsa {
                let hash_alg = crate::util::get_hash_alg_from_sig_alg(&signature_alg.oid)?;
                let hash_to_verify = calculate_hash_rust_crypto(pe, &hash_alg, message_to_verify)?;
                let ps = get_padding_scheme(signature_alg)?;
                return rsa
                    .verify(ps, hash_to_verify.as_slice(), signature)
                    .map_err(|_err| {
                        Error::PathValidation(PathValidationStatus::SignatureVerificationFailure)
                    });
            }
        }
    } else if is_ecdsa(&signature_alg.oid) {
        let named_curve = get_named_curve_parameter(&spki.algorithm)?;

        let hash_to_verify = match signature_alg.oid {
            PKIXALG_ECDSA_WITH_SHA256 => Sha256::digest(message_to_verify).to_vec(),
            PKIXALG_ECDSA_WITH_SHA384 => Sha384::digest(message_to_verify).to_vec(),
            PKIXALG_ECDSA_WITH_SHA512 => Sha512::digest(message_to_verify).to_vec(),
            _ => {
                error!(
                    "Unrecognized or unsupported signature algorithm: {}",
                    signature_alg.oid
                );
                return Err(Error::Unrecognized);
            }
        };
        macro_rules! verify_with_ecdsa {
            ($crypto_root:ident) => {{
                use ecdsa::signature::hazmat::PrehashVerifier;
                use $crypto_root::ecdsa;
                let verifying_key =
                    ecdsa::VerifyingKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
                        .map_err(|_err| {
                            error!("Could not decode verifying key");
                            Error::PathValidation(PathValidationStatus::EncodingError)
                        })?;
                let s = ecdsa::Signature::from_der(signature).map_err(|_err| {
                    error!("Could not decode signature");
                    Error::PathValidation(PathValidationStatus::EncodingError)
                })?;
                verifying_key
                    .verify_prehash(&hash_to_verify, &s)
                    .map_err(|_err| {
                        Error::PathValidation(PathValidationStatus::SignatureVerificationFailure)
                    })
            }};
        }

        return match named_curve {
            PKIXALG_SECP256R1 => {
                verify_with_ecdsa!(p256)
            }
            PKIXALG_SECP384R1 => {
                verify_with_ecdsa!(p384)
            }
            PKIXALG_SECP521R1 => {
                verify_with_ecdsa!(p521)
            }
            _ => {
                error!("Unrecognized or unsupported named curve: {}", named_curve);
                Err(Error::Unrecognized)
            }
        };
    } else if is_eddsa(&signature_alg.oid) {
        #[cfg(feature = "eddsa")]
        {
            let Ok(verifying_key) =
                ed25519_dalek::VerifyingKey::try_from(spki.subject_public_key.raw_bytes())
            else {
                error!("Could not decode verifying key");
                return Err(Error::PathValidation(PathValidationStatus::EncodingError));
            };
            let Ok(s) = ed25519_dalek::Signature::from_slice(signature) else {
                error!("Could not decode signature");
                return Err(Error::PathValidation(PathValidationStatus::EncodingError));
            };
            verifying_key
                .verify_strict(message_to_verify, &s)
                .map_err(|_| {
                    Error::PathValidation(PathValidationStatus::SignatureVerificationFailure)
                })?;
            return Ok(());
        }
    }

    debug!("Unrecognized signature algorithm: {}", signature_alg.oid);
    Err(Error::Unrecognized)
}

#[cfg(feature = "pqc")]
macro_rules! pqverify_mldsa {
    ($pkt:ty, $message_to_verify:ident, $spki_val:ident, $signature:ident) => {{
        let vk_bytes = ml_dsa::EncodedVerifyingKey::<$pkt>::try_from($spki_val)
            .map_err(|_e| Error::PqcValidation)?;
        let vk = ml_dsa::VerifyingKey::<$pkt>::decode(&vk_bytes);

        let sig_bytes = ml_dsa::EncodedSignature::<$pkt>::try_from($signature)
            .map_err(|_e| Error::PqcValidation)?;
        let sig = ml_dsa::Signature::<$pkt>::decode(&sig_bytes);

        match sig.map(|sig| vk.verify_internal(&[$message_to_verify], &sig)) {
            Some(_) => {
                return Ok(());
            }
            None => {
                return Err(Error::Unrecognized);
            }
        }
    }};
}

#[cfg(feature = "pqc")]
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

#[cfg(feature = "pqc")]
/// Verify ML-DSA and SLH-DSA signatures.
pub fn verify_signature_message_pqcrypto(
    _pe: &PkiEnvironment,
    message_to_verify: &[u8],                 // buffer to verify
    signature: &[u8],                         // signature
    signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
    spki: &SubjectPublicKeyInfoOwned,         // public key
) -> Result<()> {
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

#[test]
fn test_calculate_hash() {
    use crate::PkiEnvironment;
    use hex_literal::hex;
    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    pe.add_calculate_hash_callback(calculate_hash_rust_crypto);

    let hash_algorithm = AlgorithmIdentifierOwned {
        oid: PKIXALG_SHA256,
        parameters: None,
    };
    let result = pe
        .calculate_hash(&pe, &hash_algorithm, "abc".as_bytes())
        .unwrap();
    assert_eq!(
        result,
        hex!("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")
    );
}

#[test]
#[cfg(feature = "rsa")]
fn test_verify_signature_digest() {
    use crate::{DeferDecodeSigned, PkiEnvironment};
    use der::Decode;
    use x509_cert::Certificate;
    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    pe.add_verify_signature_digest_callback(verify_signature_digest_rust_crypto);
    pe.add_calculate_hash_callback(calculate_hash_rust_crypto);

    let der_encoded_ta = include_bytes!("../../tests/examples/TrustAnchorRootCertificate.crt");
    match DeferDecodeSigned::from_der(der_encoded_ta) {
        Ok(defer_cert) => {
            let hash_algorithm = AlgorithmIdentifierOwned {
                oid: PKIXALG_SHA256,
                parameters: None,
            };
            let result = pe
                .calculate_hash(&pe, &hash_algorithm, &defer_cert.tbs_field)
                .unwrap();
            let cert = Certificate::from_der(der_encoded_ta).unwrap();

            let result = pe.verify_signature_digest(
                &pe,
                &result,
                defer_cert.signature.as_bytes().unwrap(),
                &defer_cert.signature_algorithm,
                &cert.tbs_certificate().subject_public_key_info(),
            );
            assert!(result.is_ok())
        }
        Err(_e) => {
            panic!("Failed to decode certificate")
        }
    }
}
