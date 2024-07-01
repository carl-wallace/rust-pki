#![cfg(feature = "sha1_sig")]

use certval::{PathValidationStatus, PkiEnvironment};
use const_oid::db::rfc5912::SHA_1_WITH_RSA_ENCRYPTION;
use der::referenced::OwnedToRef;
use rsa::{
    pkcs1v15::{Signature, VerifyingKey},
    signature::Verifier,
    RsaPublicKey,
};
use sha1::Sha1;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

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

    let rsa = match RsaPublicKey::try_from(spki.owned_to_ref()) {
        Ok(rsa) => rsa,
        Err(e) => {
            println!("cargo::warning=Failed to parse public key passed to verify_signature_message_rust_crypto_sha1 as an RSA public key: {e:?}");
            return Err(certval::Error::ParseError);
        }
    };

    let verifying_key = VerifyingKey::<Sha1>::new(rsa);
    verifying_key
        .verify(
            message_to_verify,
            &Signature::try_from(signature).map_err(|_| certval::Error::ParseError)?,
        )
        .map_err(|_err| {
            certval::Error::PathValidation(PathValidationStatus::SignatureVerificationFailure)
        })
}
