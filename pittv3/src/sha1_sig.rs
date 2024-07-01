#![cfg(feature = "sha1_sig")]

use rsa::Pkcs1v15Sign;
use rsa::RsaPublicKey;
use certval::PathValidationStatus;
use sha1::{Digest, Sha1};
use const_oid::db::rfc5912::SHA_1_WITH_RSA_ENCRYPTION;
use der::Encode;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned, DecodePublicKey};
use certval::PkiEnvironment;

/// Provides verify_signature_message implementation that targets RSA w/SHA1 only (in support of
/// verifying certificates signed using RSA w/SHA1)
pub fn verify_signature_message_rust_crypto_sha1(
    _pe: &PkiEnvironment,
    message_to_verify: &[u8],                 // buffer to verify
    signature: &[u8],                         // signature
    signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
    spki: &SubjectPublicKeyInfoOwned,         // public key
) -> certval::Result<()> {
    if SHA_1_WITH_RSA_ENCRYPTION != signature_alg.oid {
        return Err(certval::Error::Unrecognized);
    }

    let enc_spki = match spki.to_der() {
        Ok(enc_spki) => enc_spki,
        Err(e) => {
            println!("cargo::warning=Failed to encode public key passed to verify_signature_message_rust_crypto_sha1: {e:?}");
            return Err(certval::Error::Asn1Error(e));
        }
    };

    let rsa = match RsaPublicKey::from_public_key_der(&enc_spki) {
        Ok(rsa) => rsa,
        Err(e) => {
            println!("cargo::warning=Failed to parse public key passed to verify_signature_message_rust_crypto_sha1 as an RSA public key: {e:?}");
            return Err(certval::Error::ParseError);
        }
    };

    let hash_to_verify = Sha1::digest(message_to_verify);
    let ps = Pkcs1v15Sign::new::<Sha1>();
    rsa.verify(ps, hash_to_verify.as_slice(), signature)
        .map_err(|_err| {
            certval::Error::PathValidation(PathValidationStatus::SignatureVerificationFailure)
        })
}