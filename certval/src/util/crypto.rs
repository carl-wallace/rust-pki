//! Provides implementations of crypto-related [`PkiEnvironment`] interfaces using libraries from the
//! [Rust Crypto](https://github.com/RustCrypto) project for support.

use crate::util::error::{Error, PathValidationStatus, Result};
use crate::{environment::pki_environment::*, util::pdv_alg_oids::*};
use alloc::vec::Vec;
use const_oid::db::rfc5912::ID_RSASSA_PSS;
use der::{asn1::ObjectIdentifier, AnyRef, Encode};
use log::{debug, error};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

#[cfg(feature = "eddsa")]
use const_oid::db::rfc8410::ID_ED_25519;

#[cfg(feature = "rsa")]
use {
    alloc::string::ToString,
    const_oid::db::rfc5912::{ID_MGF_1, ID_SHA_256, ID_SHA_384, ID_SHA_512},
    der::Decode,
    pkcs1::RsaPssParams,
};

#[cfg(feature = "rsa")]
use signature::Verifier;

/// get_padding_scheme takes an AlgorithmIdentifier containing a signature algorithm and returns
/// a corresponding PaddingScheme instance.
///
/// At present, only the PKCS1v15Sign padding scheme is supported, relative to the
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
        *oid == ID_ED_25519
    }
    #[cfg(not(feature = "eddsa"))]
    {
        false
    }
}

/// calculate_hash_rust_crypto implements the [`CalculateHash`](crate::CalculateHash) interface for [`PkiEnvironment`] using
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

/// verify_signature_digest_rust_crypto implements the [`VerifySignatureDigest`](crate::VerifySignatureDigest) interface for [`PkiEnvironment`] using
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

/// verify_signature_digest_rust_crypto implements the [`VerifySignatureMessage`](crate::VerifySignatureMessage) interface for [`PkiEnvironment`] using
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
    } else if ID_RSASSA_PSS == signature_alg.oid {
        #[cfg(feature = "rsa")]
        {
            use rsa::pkcs8::DecodePublicKey as _;

            // Unrecognized rather than an encoding error: a key this callback
            // cannot decode is a statement about this callback, and the
            // environment only moves on to the next one (an offloaded
            // implementation, say) on Unrecognized.
            let enc_spki = spki.to_der()?;
            let Ok(rsa) = rsa::RsaPublicKey::from_public_key_der(&enc_spki) else {
                error!("Could not decode an RSA verifying key for an RSASSA-PSS signature");
                return Err(Error::Unrecognized);
            };

            // RFC 4055 section 3.1 makes the parameters field mandatory for
            // id-RSASSA-PSS, and the salt length and MGF live only there, so an
            // absent one is not a case to paper over with defaults.
            let Some(parameters) = &signature_alg.parameters else {
                error!("RSASSA-PSS AlgorithmIdentifier carries no parameters");
                return Err(Error::PathValidation(PathValidationStatus::EncodingError));
            };
            let enc_params = parameters.to_der()?;
            let params = RsaPssParams::from_der(&enc_params).map_err(|e| {
                error!("Could not decode RSASSA-PSS parameters: {e:?}");
                Error::PathValidation(PathValidationStatus::EncodingError)
            })?;

            // rsa::pss::VerifyingKey<D> always masks with MGF1-D, so a signature
            // whose parameters name a different MGF would be verified under
            // parameters the signer did not state. Reject rather than silently
            // substitute.
            if ID_MGF_1 != params.mask_gen.oid
                || params.mask_gen.parameters.map(|p| p.oid) != Some(params.hash.oid)
            {
                error!(
                    "Unsupported RSASSA-PSS mask generation function {:?}; only MGF1 over the same hash as hashAlgorithm is supported",
                    params.mask_gen.oid.to_string()
                );
                return Err(Error::Unrecognized);
            }

            // The salt length is carried in the parameters and is not always the
            // digest length, so it has to be taken from there rather than left to
            // VerifyingKey::new's default.
            let salt_len = params.salt_len as usize;
            macro_rules! verify_pss {
                ($digest:ty) => {{
                    let key = rsa::pss::VerifyingKey::<$digest>::new_with_salt_len(rsa, salt_len);
                    // Signature length comes from the certificate under
                    // validation, so a length that does not match the modulus is
                    // a verification failure rather than a fault.
                    let sig = rsa::pss::Signature::try_from(signature).map_err(|_err| {
                        error!("Could not decode RSASSA-PSS signature");
                        Error::PathValidation(PathValidationStatus::SignatureVerificationFailure)
                    })?;
                    return key.verify(message_to_verify, &sig).map_err(|_err| {
                        Error::PathValidation(PathValidationStatus::SignatureVerificationFailure)
                    });
                }};
            }

            if ID_SHA_256 == params.hash.oid {
                verify_pss!(Sha256)
            } else if ID_SHA_384 == params.hash.oid {
                verify_pss!(Sha384)
            } else if ID_SHA_512 == params.hash.oid {
                verify_pss!(Sha512)
            } else {
                error!(
                    "Unrecognized hash algorithm in RSA PSS parameters {:?}",
                    params.hash.oid.to_string()
                );
                return Err(Error::Unrecognized);
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
                error!("Unrecognized or unsupported named curve: {named_curve}");
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
                cert.tbs_certificate().subject_public_key_info(),
            );
            assert!(result.is_ok())
        }
        Err(_e) => {
            panic!("Failed to decode certificate")
        }
    }
}
