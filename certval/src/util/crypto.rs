//! Provides implementations of crypto-related [`PkiEnvironment`] interfaces using libraries from the
//! [Rust Crypto](https://github.com/RustCrypto) project for support.

use alloc::vec::Vec;

use log::{debug, error};

#[cfg(feature = "pqc")]
use der::Decode;
use der::{asn1::ObjectIdentifier, AnyRef, Encode};
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use crate::util::error::{Error, PathValidationStatus, Result};
use crate::{
    environment::pki_environment::*, util::pdv_alg_oids::*,
    util::pdv_utilities::get_hash_alg_from_sig_alg,
};

#[cfg(feature = "pqc")]
use pqckeys::composite::*;
#[cfg(feature = "pqc")]
use pqckeys::pqc_oids::*;
#[cfg(feature = "pqc")]
use pqcrypto_falcon::{falcon1024, falcon512};
#[cfg(feature = "pqc")]
use pqcrypto_sphincsplus::{
    sphincssha256128frobust, sphincssha256128fsimple, sphincssha256128srobust,
    sphincssha256128ssimple, sphincssha256192frobust, sphincssha256192fsimple,
    sphincssha256192srobust, sphincssha256192ssimple, sphincssha256256frobust,
    sphincssha256256fsimple, sphincssha256256srobust, sphincssha256256ssimple,
};
#[cfg(feature = "pqc")]
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as OtherPublicKey};

/// get_padding_scheme takes an AlgorithmIdentifier containing a signature algorithm and returns
/// a corresponding PaddingScheme instance.
///
/// At present, only the PKCS1v15Sign passing scheme is supported, relative to the
/// [`PKIXALG_SHA224_WITH_RSA_ENCRYPTION`], [`PKIXALG_SHA256_WITH_RSA_ENCRYPTION`],
/// [`PKIXALG_SHA384_WITH_RSA_ENCRYPTION`] and [`PKIXALG_SHA512_WITH_RSA_ENCRYPTION`] algorithm identifiers.
pub fn get_padding_scheme(signature_alg: &AlgorithmIdentifierOwned) -> Result<Pkcs1v15Sign> {
    match signature_alg.oid {
        PKIXALG_SHA256_WITH_RSA_ENCRYPTION => Ok(Pkcs1v15Sign::new::<Sha256>()),
        PKIXALG_SHA384_WITH_RSA_ENCRYPTION => Ok(Pkcs1v15Sign::new::<Sha384>()),
        PKIXALG_SHA224_WITH_RSA_ENCRYPTION => Ok(Pkcs1v15Sign::new::<Sha224>()),
        PKIXALG_SHA512_WITH_RSA_ENCRYPTION => Ok(Pkcs1v15Sign::new::<Sha512>()),
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
    *oid == PKIXALG_ECDSA_WITH_SHA256
        || *oid == PKIXALG_ECDSA_WITH_SHA384
        || *oid == PKIXALG_ECDSA_WITH_SHA224
        || *oid == PKIXALG_ECDSA_WITH_SHA512
}

#[cfg(feature = "pqc")]
pub(crate) fn is_diluthium2(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_DILITHIUM2 || *oid == OQ_DILITHIUM2
}

#[cfg(feature = "pqc")]
pub(crate) fn is_diluthium3(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_DILITHIUM3 || *oid == OQ_DILITHIUM3
}

#[cfg(feature = "pqc")]
pub(crate) fn is_diluthium5(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_DILITHIUM5 || *oid == OQ_DILITHIUM5
}

#[cfg(feature = "pqc")]
pub(crate) fn is_diluthium2aes(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_DILITHIUM_AES2 || *oid == OQ_DILITHIUM_AES2
}

#[cfg(feature = "pqc")]
pub(crate) fn is_diluthium3aes(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_DILITHIUM_AES3 || *oid == OQ_DILITHIUM_AES3
}

#[cfg(feature = "pqc")]
pub(crate) fn is_diluthium5aes(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_DILITHIUM_AES5 || *oid == OQ_DILITHIUM_AES5
}
#[cfg(feature = "pqc")]
pub(crate) fn is_falcon512(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_FALCON_512 || *oid == OQ_FALCON_512
}
#[cfg(feature = "pqc")]
pub(crate) fn is_falcon1024(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_FALCON_1024 || *oid == OQ_FALCON_1024
}
#[cfg(feature = "pqc")]
pub(crate) fn is_sphincsp_sha256_128f_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_128F_ROBUST || *oid == ENTU_SPHINCSP_SHA256_128F_ROBUST
}
#[cfg(feature = "pqc")]
pub(crate) fn is_sphincsp_sha256_128f_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_128F_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_128F_SIMPLE
}
#[cfg(feature = "pqc")]
pub(crate) fn is_sphincsp_sha256_128s_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_128S_ROBUST || *oid == ENTU_SPHINCSP_SHA256_128S_ROBUST
}
#[cfg(feature = "pqc")]
pub(crate) fn is_sphincsp_sha256_128s_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_128S_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_128S_SIMPLE
}
#[cfg(feature = "pqc")]
pub(crate) fn is_sphincsp_sha256_192f_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_192F_ROBUST || *oid == ENTU_SPHINCSP_SHA256_192F_ROBUST
}
#[cfg(feature = "pqc")]
pub(crate) fn is_sphincsp_sha256_192f_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_192F_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_192F_SIMPLE
}
#[cfg(feature = "pqc")]
pub(crate) fn is_sphincsp_sha256_192s_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_192S_ROBUST || *oid == ENTU_SPHINCSP_SHA256_192S_ROBUST
}
#[cfg(feature = "pqc")]
pub(crate) fn is_sphincsp_sha256_192s_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_192S_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_192S_SIMPLE
}
#[cfg(feature = "pqc")]
pub(crate) fn is_sphincsp_sha256_256f_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_256F_ROBUST || *oid == ENTU_SPHINCSP_SHA256_256F_ROBUST
}
#[cfg(feature = "pqc")]
pub(crate) fn is_sphincsp_sha256_256f_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_256F_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_256F_SIMPLE
}
#[cfg(feature = "pqc")]
pub(crate) fn is_sphincsp_sha256_256s_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_256S_ROBUST || *oid == ENTU_SPHINCSP_SHA256_256S_ROBUST
}
#[cfg(feature = "pqc")]
pub(crate) fn is_sphincsp_sha256_256s_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_256S_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_256S_SIMPLE
}

/// calculate_hash_rust_crypto implements the [`CalculateHash`](../certval/pki_environment_traits/type.CalculateHash.html) interface for [`PkiEnvironment`] using
/// implementations from the Rust Crypto project.
///
/// It supports [`PKIXALG_SHA224`], [`PKIXALG_SHA256`], [`PKIXALG_SHA384`] and [`PKIXALG_SHA512`].
pub fn calculate_hash_rust_crypto(
    _pe: &PkiEnvironment<'_>,
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
pub fn verify_signature_digest_rust_crypto(
    _pe: &PkiEnvironment<'_>,
    hash_to_verify: &[u8],                    // buffer to verify
    signature: &[u8],                         // signature
    signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
    spki: &SubjectPublicKeyInfoOwned,         // public key
) -> Result<()> {
    let enc_spki = spki.to_der();
    if let Ok(enc_spki) = enc_spki {
        if is_rsa(&signature_alg.oid) {
            let rsa = RsaPublicKey::from_public_key_der(&enc_spki);
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
        //todo unwrap
        let ar: AnyRef<'_> = params.try_into().unwrap();
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
pub fn verify_signature_message_rust_crypto(
    pe: &PkiEnvironment<'_>,
    message_to_verify: &[u8],                 // buffer to verify
    signature: &[u8],                         // signature
    signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
    spki: &SubjectPublicKeyInfoOwned,         // public key
) -> Result<()> {
    let enc_spki = spki.to_der();
    if is_rsa(&signature_alg.oid) {
        if let Ok(enc_spki) = enc_spki {
            let rsa = RsaPublicKey::from_public_key_der(&enc_spki);
            if let Ok(rsa) = rsa {
                let hash_alg = get_hash_alg_from_sig_alg(&signature_alg.oid)?;
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
                use ::ecdsa::signature::hazmat::PrehashVerifier;
                use ::$crypto_root::ecdsa;
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
            _ => {
                error!("Unrecognized or unsupported named curve: {}", named_curve);
                Err(Error::Unrecognized)
            }
        };
    }
    debug!("Unrecognized signature algorithm: {}", signature_alg.oid);
    Err(Error::Unrecognized)
}
#[cfg(feature = "pqc")]
fn is_explicit_composite(oid: ObjectIdentifier) -> bool {
    ENTU_DILITHIUM3_ECDSA_P256 == oid
}
#[cfg(feature = "pqc")]
fn is_generic_composite(oid: ObjectIdentifier) -> bool {
    ENTU_COMPOSITE_SIG == oid
}
#[cfg(feature = "pqc")]
fn is_composite(oid: ObjectIdentifier) -> bool {
    is_explicit_composite(oid) || is_generic_composite(oid)
}

#[cfg(feature = "pqc")]
/// verify_signature_message_composite_pqcrypto
pub fn verify_signature_message_composite_pqcrypto(
    _pe: &PkiEnvironment<'_>,
    message_to_verify: &[u8],                 // buffer to verify
    signature: &[u8],                         // signature
    signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
    spki: &SubjectPublicKeyInfoOwned,         // public key
) -> Result<()> {
    // only doing generic composite at present
    if is_composite(signature_alg.oid) {
        // Parse each composite value
        // Params is an AnyRef, so it needs to be encoded to access value
        let params_enc = if let Some(p) = &signature_alg.parameters {
            match p.to_der() {
                Ok(rv) => rv,
                Err(_e) => return Err(Error::Unrecognized),
            }
        } else {
            return Err(Error::Unrecognized);
        };

        let params = match CompositeParams::from_der(params_enc.as_slice()) {
            Ok(p) => p,
            Err(_e) => return Err(Error::Unrecognized),
        };

        let cs = match CompositeSignatureValue::from_der(signature) {
            Ok(cs) => cs,
            Err(_e) => return Err(Error::Unrecognized),
        };

        let cspki = match CompositePublicKey::from_der(spki.subject_public_key.raw_bytes()) {
            Ok(cspki) => cspki,
            Err(_e) => return Err(Error::Unrecognized),
        };

        // Make sure number of params and signatures is same and that there are at least that many
        // public key values
        if cs.len() != params.len() {
            return Err(Error::Unrecognized);
        }
        if cs.len() > cspki.len() {
            return Err(Error::Unrecognized);
        }

        // iterate over signatures
        for i in 0..cs.len() {
            let cur_sig = match cs[i].as_bytes() {
                Some(r) => r,
                None => return Err(Error::Unrecognized),
            };
            let cur_sig_alg = &params[i];
            let ecdsa_key = is_ecdsa(&cur_sig_alg.oid);
            let mut matched = false;

            // find the public key that matches
            for cur_spki in &cspki {
                if cur_sig_alg.oid == cur_spki.algorithm.oid
                    || (ecdsa_key && PKIXALG_EC_PUBLIC_KEY == cur_spki.algorithm.oid)
                {
                    if ecdsa_key {
                        verify_signature_message_rust_crypto(
                            _pe,
                            message_to_verify,
                            cur_sig,
                            cur_sig_alg,
                            cur_spki,
                        )?;
                        matched = true;
                        break;
                    } else {
                        verify_signature_message_pqcrypto(
                            _pe,
                            message_to_verify,
                            cur_sig,
                            cur_sig_alg,
                            cur_spki,
                        )?;
                        matched = true;
                        break;
                    }
                }
            }
            if !matched {
                return Err(Error::Unrecognized);
            }
        }
        return Ok(());
    }
    Err(Error::Unrecognized)
}
#[cfg(feature = "pqc")]
macro_rules! pqverify {
    ($pkt:ty, $dst:ty, $vdst:expr, $message_to_verify:ident, $spki_val:ident, $signature:ident) => {{
        let pk = <$pkt>::from_bytes($spki_val).unwrap();
        let sm = <$dst>::from_bytes($signature).unwrap();
        let verifiedmsg = $vdst(&sm, $message_to_verify, &pk);
        match verifiedmsg {
            Ok(_) => {
                return Ok(());
            }
            Err(_e) => {
                return Err(Error::PathValidation(
                    PathValidationStatus::SignatureVerificationFailure,
                ));
            }
        };
    }};
}

#[cfg(feature = "pqc")]
/// Write some stuff. TODO
pub fn verify_signature_message_pqcrypto(
    _pe: &PkiEnvironment<'_>,
    message_to_verify: &[u8],                 // buffer to verify
    signature: &[u8],                         // signature
    signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
    spki: &SubjectPublicKeyInfoOwned,         // public key
) -> Result<()> {
    // dropped as the OCTET STRING definition in the spec is not really operative (only the value
    // gets incorporated into the BIT STRING
    // let spki_os = match OctetString::from_der(spki.subject_public_key) {
    //     Ok(spki_os) => spki_os,
    //     Err(_e) => return Err(Error::Unrecognized),
    // };
    let spki_val = spki.subject_public_key.raw_bytes();
    if is_diluthium2(&signature_alg.oid) {
        pqverify!(
            pqcrypto_dilithium::dilithium2::PublicKey,
            pqcrypto_dilithium::dilithium2::DetachedSignature,
            pqcrypto_dilithium::dilithium2::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_diluthium3(&signature_alg.oid) {
        pqverify!(
            pqcrypto_dilithium::dilithium3::PublicKey,
            pqcrypto_dilithium::dilithium3::DetachedSignature,
            pqcrypto_dilithium::dilithium3::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_diluthium5(&signature_alg.oid) {
        pqverify!(
            pqcrypto_dilithium::dilithium5::PublicKey,
            pqcrypto_dilithium::dilithium5::DetachedSignature,
            pqcrypto_dilithium::dilithium5::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_diluthium2aes(&signature_alg.oid) {
        pqverify!(
            pqcrypto_dilithium::dilithium2aes::PublicKey,
            pqcrypto_dilithium::dilithium2aes::DetachedSignature,
            pqcrypto_dilithium::dilithium2aes::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_diluthium3aes(&signature_alg.oid) {
        pqverify!(
            pqcrypto_dilithium::dilithium3aes::PublicKey,
            pqcrypto_dilithium::dilithium3aes::DetachedSignature,
            pqcrypto_dilithium::dilithium3aes::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_diluthium5aes(&signature_alg.oid) {
        pqverify!(
            pqcrypto_dilithium::dilithium5aes::PublicKey,
            pqcrypto_dilithium::dilithium5aes::DetachedSignature,
            pqcrypto_dilithium::dilithium5aes::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_falcon512(&signature_alg.oid) {
        pqverify!(
            falcon512::PublicKey,
            falcon512::DetachedSignature,
            falcon512::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_falcon1024(&signature_alg.oid) {
        pqverify!(
            falcon1024::PublicKey,
            falcon1024::DetachedSignature,
            falcon1024::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_sphincsp_sha256_128f_robust(&signature_alg.oid) {
        pqverify!(
            sphincssha256128frobust::PublicKey,
            sphincssha256128frobust::DetachedSignature,
            sphincssha256128frobust::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_sphincsp_sha256_128f_simple(&signature_alg.oid) {
        pqverify!(
            sphincssha256128fsimple::PublicKey,
            sphincssha256128fsimple::DetachedSignature,
            sphincssha256128fsimple::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_sphincsp_sha256_128s_robust(&signature_alg.oid) {
        pqverify!(
            sphincssha256128srobust::PublicKey,
            sphincssha256128srobust::DetachedSignature,
            sphincssha256128srobust::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_sphincsp_sha256_128s_simple(&signature_alg.oid) {
        pqverify!(
            sphincssha256128ssimple::PublicKey,
            sphincssha256128ssimple::DetachedSignature,
            sphincssha256128ssimple::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_sphincsp_sha256_192f_robust(&signature_alg.oid) {
        pqverify!(
            sphincssha256192frobust::PublicKey,
            sphincssha256192frobust::DetachedSignature,
            sphincssha256192frobust::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_sphincsp_sha256_192f_simple(&signature_alg.oid) {
        pqverify!(
            sphincssha256192fsimple::PublicKey,
            sphincssha256192fsimple::DetachedSignature,
            sphincssha256192fsimple::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_sphincsp_sha256_192s_robust(&signature_alg.oid) {
        pqverify!(
            sphincssha256192srobust::PublicKey,
            sphincssha256192srobust::DetachedSignature,
            sphincssha256192srobust::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_sphincsp_sha256_192s_simple(&signature_alg.oid) {
        pqverify!(
            sphincssha256192ssimple::PublicKey,
            sphincssha256192ssimple::DetachedSignature,
            sphincssha256192ssimple::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_sphincsp_sha256_256f_robust(&signature_alg.oid) {
        pqverify!(
            sphincssha256256frobust::PublicKey,
            sphincssha256256frobust::DetachedSignature,
            sphincssha256256frobust::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_sphincsp_sha256_256f_simple(&signature_alg.oid) {
        pqverify!(
            sphincssha256256fsimple::PublicKey,
            sphincssha256256fsimple::DetachedSignature,
            sphincssha256256fsimple::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_sphincsp_sha256_256s_robust(&signature_alg.oid) {
        pqverify!(
            sphincssha256256srobust::PublicKey,
            sphincssha256256srobust::DetachedSignature,
            sphincssha256256srobust::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
    } else if is_sphincsp_sha256_256s_simple(&signature_alg.oid) {
        pqverify!(
            sphincssha256256ssimple::PublicKey,
            sphincssha256256ssimple::DetachedSignature,
            sphincssha256256ssimple::verify_detached_signature,
            message_to_verify,
            spki_val,
            signature
        )
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
                &cert.tbs_certificate.subject_public_key_info,
            );
            assert!(result.is_ok())
        }
        Err(_e) => {
            panic!("Failed to decode certificate")
        }
    }
}
