//! Provides implementations of crypto-related [`PkiEnvironment`] interfaces using libraries from the
//! [Rust Crypto](https://github.com/RustCrypto) project for support.

use alloc::{format, vec::Vec};

use der::{asn1::ObjectIdentifier, Encode};
use p256::ecdsa::{
    signature::Verifier as Verifier256, Signature as Signature256, VerifyingKey as VerifyingKey256,
};
use rsa::pkcs8::DecodePublicKey;
use rsa::{hash::Hash, PaddingScheme, PublicKey, RsaPublicKey};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use crate::util::error::{Error, PathValidationStatus, Result};
use crate::{
    environment::pki_environment::*, log_message, util::pdv_alg_oids::*,
    util::pdv_utilities::get_hash_alg_from_sig_alg, PeLogLevels,
};

/// get_padding_scheme takes an AlgorithmIdentifier containing a signature algorithm and returns
/// a corresponding PaddingScheme instance.
///
/// At present, only the PKCS1v15Sign passing scheme is supported, relative to the
/// [`PKIXALG_SHA224_WITH_RSA_ENCRYPTION`], [`PKIXALG_SHA256_WITH_RSA_ENCRYPTION`],
/// [`PKIXALG_SHA384_WITH_RSA_ENCRYPTION`] and [`PKIXALG_SHA512_WITH_RSA_ENCRYPTION`] algorithm identifiers.
pub fn get_padding_scheme(signature_alg: &AlgorithmIdentifier<'_>) -> Result<PaddingScheme> {
    match signature_alg.oid {
        PKIXALG_SHA256_WITH_RSA_ENCRYPTION => Ok(PaddingScheme::PKCS1v15Sign {
            hash: Some(Hash::SHA2_256),
        }),
        PKIXALG_SHA384_WITH_RSA_ENCRYPTION => Ok(PaddingScheme::PKCS1v15Sign {
            hash: Some(Hash::SHA2_384),
        }),
        PKIXALG_SHA224_WITH_RSA_ENCRYPTION => Ok(PaddingScheme::PKCS1v15Sign {
            hash: Some(Hash::SHA2_224),
        }),
        PKIXALG_SHA512_WITH_RSA_ENCRYPTION => Ok(PaddingScheme::PKCS1v15Sign {
            hash: Some(Hash::SHA2_512),
        }),
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

/// calculate_hash_rust_crypto implements the [`CalculateHash`](../certval/pki_environment_traits/type.CalculateHash.html) interface for [`PkiEnvironment`] using
/// implementations from the Rust Crypto project.
///
/// It supports [`PKIXALG_SHA224`], [`PKIXALG_SHA256`], [`PKIXALG_SHA384`] and [`PKIXALG_SHA512`].
pub fn calculate_hash_rust_crypto(
    _pe: &PkiEnvironment<'_>,
    hash_alg: &AlgorithmIdentifier<'_>,
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
    hash_to_verify: &[u8],                   // buffer to verify
    signature: &[u8],                        // signature
    signature_alg: &AlgorithmIdentifier<'_>, // signature algorithm
    spki: &SubjectPublicKeyInfo<'_>,         // public key
) -> Result<()> {
    let enc_spki = spki.to_vec();
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

fn get_named_curve_parameter(alg_id: &AlgorithmIdentifier<'_>) -> Result<ObjectIdentifier> {
    if let Some(params) = alg_id.parameters {
        if let Ok(oid) = params.oid() {
            return Ok(oid);
        }
    }
    Err(Error::PathValidation(PathValidationStatus::EncodingError))
}

/// verify_signature_digest_rust_crypto implements the [`VerifySignatureMessage`](../certval/pki_environment_traits/type.VerifySignatureMessage.html) interface for [`PkiEnvironment`] using
/// implementations from the [Rust Crypto](https://github.com/RustCrypto) project.
///
/// RSA signatures and P256 signatures are supported at present.
pub fn verify_signature_message_rust_crypto(
    pe: &PkiEnvironment<'_>,
    message_to_verify: &[u8],                // buffer to verify
    signature: &[u8],                        // signature
    signature_alg: &AlgorithmIdentifier<'_>, // signature algorithm
    spki: &SubjectPublicKeyInfo<'_>,         // public key
) -> Result<()> {
    let enc_spki = spki.to_vec();
    if is_rsa(&signature_alg.oid) {
        if let Ok(enc_spki) = enc_spki {
            let rsa = RsaPublicKey::from_public_key_der(&enc_spki);
            if let Ok(rsa) = rsa {
                let hash_alg = get_hash_alg_from_sig_alg(&signature_alg.oid)?;
                let hash_to_verify = calculate_hash_rust_crypto(pe, &hash_alg, message_to_verify)?;
                let ps = get_padding_scheme(signature_alg)?;
                let x = rsa.verify(ps, hash_to_verify.as_slice(), signature);
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
    } else if is_ecdsa(&signature_alg.oid) {
        let named_curve = get_named_curve_parameter(&spki.algorithm)?;

        match named_curve {
            PKIXALG_SECP256R1 => {
                let ecdsa = VerifyingKey256::from_sec1_bytes(spki.subject_public_key);
                if let Ok(ecdsa) = ecdsa {
                    let s = Signature256::from_der(signature);
                    if let Ok(s) = s {
                        let x = ecdsa.verify(message_to_verify, &s);
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
            // PKIXALG_SECP384R1 => {
            // let ecdsa = VerifyingKey384::from_sec1_bytes(spki.subject_public_key);
            // if let Ok(ecdsa) = ecdsa {
            //     let s = Signature384::from_der(signature);
            //     if let Ok(s) = s {
            //         let x = ecdsa.verify(message_to_verify, &s);
            //         match x {
            //             Ok(x) => {return Ok(x);},
            //             Err(_x) => {return Err(Error::SignatureVerificationFailure);}
            //         }
            //     }
            // }

            // }
            _ => {
                log_message(
                    &PeLogLevels::PeError,
                    format!("Unrecognized or unsupported named curve: {}", named_curve).as_str(),
                );
                return Err(Error::Unrecognized);
            }
        }
    }
    log_message(
        &PeLogLevels::PeError,
        format!("Unrecognized signature algorithm: {}", signature_alg.oid).as_str(),
    );
    Err(Error::Unrecognized)
}

#[test]
fn test_calculate_hash() {
    use crate::PkiEnvironment;
    use hex_literal::hex;
    let mut pe = PkiEnvironment::default();
    pe.clear_all_callbacks();
    pe.add_calculate_hash_callback(calculate_hash_rust_crypto);

    let hash_algorithm = AlgorithmIdentifier {
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
            let hash_algorithm = AlgorithmIdentifier {
                oid: PKIXALG_SHA256,
                parameters: None,
            };
            let result = pe
                .calculate_hash(&pe, &hash_algorithm, defer_cert.tbs_field)
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
