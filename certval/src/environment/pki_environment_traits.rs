//! The pki_environment_traits module features trait definitions and type definitions that are used
//! by [`PkiEnvironment`] to provide functionality that supports building and/or validating X.509
//! certification paths.

use alloc::{string::String, sync::Arc, vec::Vec};

use der::asn1::ObjectIdentifier;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::{certificate::Raw, crl::CertificateList, name::Name};

use crate::util::error::*;
use crate::{
    CertFile, CertificationPath, CertificationPathResults, CertificationPathSettings,
    PDVCertificate, PDVTrustAnchorChoice, PkiEnvironment, SubjectNameAndKey, TimeOfInterest,
};

/// `ValidatePath` provides a function signature for implementations that perform certification path
/// validation or that provide functionality in support of certification path validation.
pub type ValidatePath = fn(
    &PkiEnvironment,
    &CertificationPathSettings,    // path settings to govern validation
    &mut CertificationPath,        // path to verify
    &mut CertificationPathResults, // path validation results
) -> Result<()>;

/// `CalculateHash` provides an interface for implementations that perform hashing.
///
/// A blanket implementation covers every function with a matching signature, so a bare function
/// (like `calculate_hash_rust_crypto`) can still be handed to
/// [`PkiEnvironment::add_calculate_hash_callback`] directly. Implement the trait on a type when the
/// implementation needs to carry state that a function pointer cannot, e.g. a handle to a hardware
/// module.
pub trait CalculateHash {
    /// calculate_hash returns the hash of `buffer_to_hash` using the algorithm named by `hash_alg`.
    fn calculate_hash(
        &self,
        pe: &PkiEnvironment,
        hash_alg: &AlgorithmIdentifierOwned,
        buffer_to_hash: &[u8],
    ) -> Result<Vec<u8>>;
}

impl<F> CalculateHash for F
where
    F: Fn(&PkiEnvironment, &AlgorithmIdentifierOwned, &[u8]) -> Result<Vec<u8>>,
{
    fn calculate_hash(
        &self,
        pe: &PkiEnvironment,
        hash_alg: &AlgorithmIdentifierOwned,
        buffer_to_hash: &[u8],
    ) -> Result<Vec<u8>> {
        self(pe, hash_alg, buffer_to_hash)
    }
}

impl<T: CalculateHash + ?Sized> CalculateHash for Arc<T> {
    fn calculate_hash(
        &self,
        pe: &PkiEnvironment,
        hash_alg: &AlgorithmIdentifierOwned,
        buffer_to_hash: &[u8],
    ) -> Result<Vec<u8>> {
        (**self).calculate_hash(pe, hash_alg, buffer_to_hash)
    }
}

/// `VerifySignatureDigest` provides an interface for implementations that perform signature
/// verification over a message digest.
///
/// A blanket implementation covers every function with a matching signature, so a bare function
/// (like `verify_signature_digest_rust_crypto`) can still be handed to
/// [`PkiEnvironment::add_verify_signature_digest_callback`] directly. Implement the trait on a type
/// when the implementation needs to carry state that a function pointer cannot, e.g. a handle to a
/// hardware module along with a cache of the key objects it has already imported.
pub trait VerifySignatureDigest {
    /// verify_signature_digest verifies `signature` over `hash_to_verify` using the algorithm named
    /// by `signature_alg` and the public key conveyed in `spki`.
    fn verify_signature_digest(
        &self,
        pe: &PkiEnvironment,
        hash_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> Result<()>;
}

impl<F> VerifySignatureDigest for F
where
    F: Fn(
        &PkiEnvironment,
        &[u8],
        &[u8],
        &AlgorithmIdentifierOwned,
        &SubjectPublicKeyInfoOwned,
    ) -> Result<()>,
{
    fn verify_signature_digest(
        &self,
        pe: &PkiEnvironment,
        hash_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> Result<()> {
        self(pe, hash_to_verify, signature, signature_alg, spki)
    }
}

impl<T: VerifySignatureDigest + ?Sized> VerifySignatureDigest for Arc<T> {
    fn verify_signature_digest(
        &self,
        pe: &PkiEnvironment,
        hash_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> Result<()> {
        (**self).verify_signature_digest(pe, hash_to_verify, signature, signature_alg, spki)
    }
}

/// `VerifySignatureDigestWithContext` provides an interface for implementations that perform
/// signature verification over a message digest with an optional context provided.
///
/// See [`VerifySignatureDigest`] for the blanket implementation that keeps bare functions
/// registrable.
pub trait VerifySignatureDigestWithContext {
    /// verify_signature_digest_with_context verifies `signature` over `hash_to_verify` using the
    /// algorithm named by `signature_alg`, the public key conveyed in `spki` and the context in
    /// `ctx`.
    fn verify_signature_digest_with_context(
        &self,
        pe: &PkiEnvironment,
        hash_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
        ctx: &Option<Vec<u8>>,
    ) -> Result<()>;
}

impl<F> VerifySignatureDigestWithContext for F
where
    F: Fn(
        &PkiEnvironment,
        &[u8],
        &[u8],
        &AlgorithmIdentifierOwned,
        &SubjectPublicKeyInfoOwned,
        &Option<Vec<u8>>,
    ) -> Result<()>,
{
    fn verify_signature_digest_with_context(
        &self,
        pe: &PkiEnvironment,
        hash_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
        ctx: &Option<Vec<u8>>,
    ) -> Result<()> {
        self(pe, hash_to_verify, signature, signature_alg, spki, ctx)
    }
}

impl<T: VerifySignatureDigestWithContext + ?Sized> VerifySignatureDigestWithContext for Arc<T> {
    fn verify_signature_digest_with_context(
        &self,
        pe: &PkiEnvironment,
        hash_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
        ctx: &Option<Vec<u8>>,
    ) -> Result<()> {
        (**self).verify_signature_digest_with_context(
            pe,
            hash_to_verify,
            signature,
            signature_alg,
            spki,
            ctx,
        )
    }
}

/// `VerifySignatureMessage` provides an interface for implementations that perform signature
/// verification over a message, i.e., where the implementation hashes the message itself.
///
/// See [`VerifySignatureDigest`] for the blanket implementation that keeps bare functions
/// registrable.
pub trait VerifySignatureMessage {
    /// verify_signature_message verifies `signature` over `message_to_verify` using the algorithm
    /// named by `signature_alg` and the public key conveyed in `spki`.
    fn verify_signature_message(
        &self,
        pe: &PkiEnvironment,
        message_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> Result<()>;
}

impl<F> VerifySignatureMessage for F
where
    F: Fn(
        &PkiEnvironment,
        &[u8],
        &[u8],
        &AlgorithmIdentifierOwned,
        &SubjectPublicKeyInfoOwned,
    ) -> Result<()>,
{
    fn verify_signature_message(
        &self,
        pe: &PkiEnvironment,
        message_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> Result<()> {
        self(pe, message_to_verify, signature, signature_alg, spki)
    }
}

impl<T: VerifySignatureMessage + ?Sized> VerifySignatureMessage for Arc<T> {
    fn verify_signature_message(
        &self,
        pe: &PkiEnvironment,
        message_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> Result<()> {
        (**self).verify_signature_message(pe, message_to_verify, signature, signature_alg, spki)
    }
}

/// `VerifySignatureMessageWithContext` provides an interface for implementations that perform
/// signature verification over a message with an optional context provided.
///
/// See [`VerifySignatureDigest`] for the blanket implementation that keeps bare functions
/// registrable.
pub trait VerifySignatureMessageWithContext {
    /// verify_signature_message_with_context verifies `signature` over `message_to_verify` using
    /// the algorithm named by `signature_alg`, the public key conveyed in `spki` and the context in
    /// `ctx`.
    fn verify_signature_message_with_context(
        &self,
        pe: &PkiEnvironment,
        message_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
        ctx: &Option<Vec<u8>>,
    ) -> Result<()>;
}

impl<F> VerifySignatureMessageWithContext for F
where
    F: Fn(
        &PkiEnvironment,
        &[u8],
        &[u8],
        &AlgorithmIdentifierOwned,
        &SubjectPublicKeyInfoOwned,
        &Option<Vec<u8>>,
    ) -> Result<()>,
{
    fn verify_signature_message_with_context(
        &self,
        pe: &PkiEnvironment,
        message_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
        ctx: &Option<Vec<u8>>,
    ) -> Result<()> {
        self(pe, message_to_verify, signature, signature_alg, spki, ctx)
    }
}

impl<T: VerifySignatureMessageWithContext + ?Sized> VerifySignatureMessageWithContext for Arc<T> {
    fn verify_signature_message_with_context(
        &self,
        pe: &PkiEnvironment,
        message_to_verify: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
        ctx: &Option<Vec<u8>>,
    ) -> Result<()> {
        (**self).verify_signature_message_with_context(
            pe,
            message_to_verify,
            signature,
            signature_alg,
            spki,
            ctx,
        )
    }
}

/// `GetTrustAnchors` provides a function signature for implementations that return a list of trust anchors
pub type GetTrustAnchors = fn(&PkiEnvironment, &mut Vec<Vec<u8>>) -> Result<()>;

/// `OidLookup` implementations take an OID and returns either a friendly name for the OID or a
/// NotFound error. Where NotFound is returned by all OidLookup implementations, the
/// [`PkiEnvironment`] returns a dot notation version of the OID.
pub type OidLookup = fn(&ObjectIdentifier) -> Result<String>;

/// The [`TrustAnchorSource`] trait enables trait objects to provide access to trust anchors backed via
/// some means, i.e., hard-coded, file-based, system store accessed via FFI, etc.
pub trait TrustAnchorSource {
    /// get_trust_anchors returns a vector with references to available trust anchors.
    fn get_trust_anchors(&self) -> Result<Vec<&PDVTrustAnchorChoice>>;

    /// get_trust_anchor returns a reference to a trust anchor corresponding to the presented SKID.
    fn get_trust_anchor_by_skid(&self, skid: &[u8]) -> Result<&PDVTrustAnchorChoice>;

    /// get_trust_anchor_by_hex_skid returns a reference to a trust anchor corresponding to the presented hexadecimal SKID.
    fn get_trust_anchor_by_hex_skid(&self, hex_skid: &str) -> Result<&PDVTrustAnchorChoice>;

    /// get_trust_anchor_for_name returns a reference to a trust anchor corresponding to present name.
    fn get_trust_anchor_by_name(&self, target: &Name) -> Result<&PDVTrustAnchorChoice>;

    /// get_trust_anchor_for_target returns a reference to a trust anchor corresponding to AKID or name from presented target.
    fn get_trust_anchor_for_target(&self, target: &PDVCertificate)
        -> Result<&PDVTrustAnchorChoice>;

    /// get_encoded_trust_anchor returns a copy of the encoded buffer for the trust anchor corresponding
    /// to the given SKID.
    fn get_encoded_trust_anchor(&self, skid: &[u8]) -> Result<Vec<u8>>;

    /// get_encoded_trust_anchor returns a vector containing copies of the available encoded trust anchors.
    fn get_encoded_trust_anchors(&self) -> Result<Vec<Vec<u8>>>;

    /// is_trust_anchor returns true if presented ta object is a trust anchor
    fn is_trust_anchor(&self, ta: &PDVTrustAnchorChoice) -> Result<()>;

    /// is_trust_anchor returns true if presented certificate object is a trust anchor
    fn is_cert_a_trust_anchor(&self, ta: &PDVCertificate) -> Result<()>;
}

/// Vector-like methods for TA store or certificate store
pub trait CertVector {
    /// Returns true if cert is already present and false otherwise
    fn contains(&self, cert: &CertFile) -> bool;
    /// Adds cert to collection
    fn push(&mut self, cert: CertFile);
    /// Returns number of certs in collection
    fn len(&self) -> usize;
    /// Returns true if len is 0
    fn is_empty(&self) -> bool;
}

/// The [`CertificateSource`] trait enables trait objects to provide access to certificates backed via
/// some means, i.e., hard-coded, file-based, system store accessed via FFI, etc.
pub trait CertificateSource {
    /// get_certificates returns a vector with references to available certificates.
    fn get_certificates(&self) -> Result<Vec<&PDVCertificate>>;

    /// get_certificates_for_skid returns a vector of references to certificates corresponding to the presented SKID.
    fn get_certificates_for_skid(&self, skid: &[u8]) -> Result<Vec<&PDVCertificate>>;

    /// get_certificates_for_skid returns a vector of references to certificates corresponding to the presented subject name.
    fn get_certificates_for_name(&self, name: &Name) -> Result<Vec<&PDVCertificate>>;

    /// get_certificates_for_skid returns a vector of references to buffers corresponding to the presented SKID.
    fn get_encoded_certificates_for_skid(&self, skid: &[u8]) -> Result<Vec<Vec<u8>>>;

    /// get_certificates_for_skid returns a vector of references to buffers corresponding to the presented subject name.
    fn get_encoded_certificates_for_name(&self, name: &Name) -> Result<Vec<Vec<u8>>>;

    /// get_encoded_certificates returns a vector containing copies of the available encoded certificates.
    fn get_encoded_certificates(&self) -> Result<Vec<Vec<u8>>>;

    /// find_paths_for_target takes a target certificate and a source for trust anchors and returns
    /// a vector of CertificationPath objects.
    fn get_paths_for_target(
        &self,
        pe: &PkiEnvironment,
        target: &PDVCertificate,
        paths: &mut Vec<CertificationPath>,
        threshold: usize,
        time_of_interest: TimeOfInterest,
    ) -> Result<()>;
}

/// The `CertificationPathBuilderFormats` enum is used to support possible future support for alternative
/// formats when serializing partial certification paths. At present, only CBOR is supported.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CertificationPathBuilderFormats {
    /// Serialize using CBOR format
    Cbor,
}

/// The [`CrlSource`] trait defines the interface for storing and retrieving CRLs in support of certification path validation.
pub trait CrlSource {
    /// Lists all CRLs available
    fn get_all_crls(&self) -> Result<Vec<Vec<u8>>>;
    /// Retrieves CRLs for given certificate from store
    fn get_crls(&self, cert: &PDVCertificate) -> Result<Vec<Vec<u8>>>;
    /// Adds a CRL to the store
    fn add_crl(&self, crl_buf: &[u8], crl: &CertificateList<Raw>, uri: &str) -> Result<()>;

    /// Offered a CRL that the caller has already verified so a store may retain its revoked serial
    /// numbers in memory for fast subsequent revocation status determinations. The default
    /// implementation is a no-op; only stores that support in-memory retention override it. The
    /// caller MUST have verified the CRL signature against `verifier`'s key (the store cannot, and
    /// when loaded cold has no issuer to verify against), so this is invoked only from the
    /// post-verification path. Retained entries must be bound to `verifier`'s SPKI so that issuers
    /// sharing a subject name (e.g. across a key rollover) can never answer for one another's
    /// certificates.
    fn keep_verified_crl(
        &self,
        _crl_buf: &[u8],
        _crl: &CertificateList<Raw>,
        _verifier: &dyn SubjectNameAndKey,
        _toi: TimeOfInterest,
        _retain_expired: bool,
    ) -> Result<()> {
        Ok(())
    }
}

/// The [`CheckRemoteResource`] trait defines an interface for checking last modified and blocklist values when downloading remote item
pub trait CheckRemoteResource {
    /// Gets last modified map or empty map
    fn get_last_modified(&self, uri: &str) -> Option<String>;

    /// Save last modified map, if desired
    fn set_last_modified(&self, uri: &str, last_modified: &str);

    /// Gets blocklist or empty vector
    fn check_blocklist(&self, uri: &str) -> bool;

    /// Save blocklist, if desired
    fn add_to_blocklist(&self, uri: &str);
}

/// The [`RevocationStatusCache`] trait defines the interface for storing and retrieving cached revocation status determinations
/// in support of certification path validation.
pub trait RevocationStatusCache {
    /// Returns Valid if status is known to be good at time of interest, CertificateRevoked if
    /// certificate is known to be revoked and RevocationStatusNotDetermined otherwise. `issuer` is
    /// the subject that would verify revocation data for `cert` (its issuing CA or trust anchor);
    /// implementations must bind answers to the issuer's key, not just its name, so that issuers
    /// sharing a subject name (e.g. across a key rollover) can never answer for one another's
    /// certificates.
    fn get_status(
        &self,
        cert: &PDVCertificate,
        issuer: &dyn SubjectNameAndKey,
        time_of_interest: TimeOfInterest,
    ) -> PathValidationStatus;

    /// Sets status for certificate to one of Valid or Revoked and a next update value. `issuer` is
    /// the subject whose key verified the revocation data behind the determination and must key the
    /// cached entry alongside the certificate identity (see `get_status`).
    fn add_status(
        &self,
        cert: &PDVCertificate,
        issuer: &dyn SubjectNameAndKey,
        next_update: u64,
        status: PathValidationStatus,
    );
}
// TODO add allowlist and blocklist as RevocationStatusCache implementations

/// The [`SignatureVerificationCache`] trait defines an interface for caching successful certificate
/// signature verifications so a signature verified once (for example while building the partial-path
/// graph) need not be re-verified on every subsequent path validation. Entries are keyed by a hash
/// of the certificate and a hash of the issuer's subject public key, which together fully determine
/// the verification, so a positive result is always sound to trust. An absent entry means the
/// signature is verified as usual, so correctness never depends on the cache being present or
/// populated.
pub trait SignatureVerificationCache {
    /// Returns true if a signature over the certificate identified by `cert_hash` by the key
    /// identified by `issuer_spki_hash` has already been verified successfully.
    fn is_verified(&self, cert_hash: &[u8], issuer_spki_hash: &[u8]) -> bool;

    /// Records a successful signature verification.
    fn add_verified(&self, cert_hash: &[u8], issuer_spki_hash: &[u8]);
}
