//! PkiEnvironment aggregates a set of function pointers and trait objects that supply functionality
//! useful when building and/or validating a certification path, processing or generating a CMS
//! message, or performing other actions that benefit from certification path validation.
//!
//! The sample below illustrates preparation of a PkiEnvironment object for use in
//! building and validating certification paths.
//! ```
//! use certval::PkiEnvironment;
//! use certval::*;
//!
//! // the default PkiEnvironment uses `oid_lookup` to look up friendly names for OIDs
//! let mut pe = PkiEnvironment::default();
//!
//! // add basic hashing, signature verification and path validation capabilities
//! pe.populate_5280_pki_environment();
//!
//! let mut ta_source = TaSource::default();
//! // populate the ta_store.buffers and ta_store.tas fields then index the trust anchors. see the
//! // `populate_parsed_ta_vector` usage in `Pittv3` for file-system based sample.
//! ta_source.index_tas();
//!
//! let mut cert_source = CertSource::default();
//! // populate the cert_source.buffers and cert_source.certs fields then index the certificates,
//! // i.e., populate the name and spki maps.
//!
//! // add ta_source and cert_source to provide access to trust anchors and intermediate CA certificates
//! pe.add_trust_anchor_source(Box::new(ta_source.clone()));
//!  pe.add_certificate_source(Box::new(cert_source.clone()));
//! ```
//!
//! The aggregation of function pointers and trait objects allows for implementations of features to
//! vary. For example, one app may desire path validation without some PKIX features (like
//! certificate policy) processing and another may desire access to trust anchors via a system store
//! (via an FFI implementation) or much smaller sets of trust anchors for selected operations.
//!

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::{vec, vec::Vec};

use der::asn1::ObjectIdentifier;
use der::Encode;
use log::error;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::{certificate::Raw, crl::CertificateList, name::Name};

use crate::source::ta_source::{
    buffer_to_hex, get_subject_public_key_info_from_trust_anchor, hex_skid_from_cert,
    hex_skid_from_ta,
};
use crate::PathValidationStatus::RevocationStatusNotDetermined;
use crate::{
    environment::pki_environment_traits::*, path_settings::*, util::crypto::*, util::error::*,
    util::pdv_utilities::oid_lookup, validate_path_rfc5280, CertificationPath,
    CertificationPathResults, PDVCertificate, PDVTrustAnchorChoice, TimeOfInterest,
};

#[cfg(feature = "pqc")]
use crate::util::{
    crypto_composite::verify_signature_message_composite_rustcrypto,
    crypto_fndsa::verify_signature_message_fndsa,
    crypto_pqc::{verify_signature_message_ctx_rustcrypto, verify_signature_message_rustcrypto},
};

/// [`PkiEnvironment`] provides a switchboard of callback functions that allow support to vary on
/// different platforms or to allow support to be tailored for specific use cases.
pub struct PkiEnvironment {
    //--------------------------------------------------------------------------
    //Crypto interfaces
    //--------------------------------------------------------------------------
    /// List of functions that provide a message digest functionality
    calculate_hash_callbacks: Vec<CalculateHash>,

    /// List of functions that provide a signature verification functionality given a digest
    verify_signature_digest_callbacks: Vec<VerifySignatureDigest>,

    /// List of functions that provide a signature verification functionality given a message
    verify_signature_message_callbacks: Vec<VerifySignatureMessage>,

    /// List of functions that provide a signature verification functionality given a digest and optional context
    verify_signature_digest_ctx_callbacks: Vec<VerifySignatureDigestWithContext>,

    /// List of functions that provide a signature verification functionality given a message and optional context
    verify_signature_message_ctx_callbacks: Vec<VerifySignatureMessageWithContext>,

    //--------------------------------------------------------------------------
    //Certification path processing interfaces
    //--------------------------------------------------------------------------
    /// List of functions that provide certification path validation functionality
    validate_path_callbacks: Vec<ValidatePath>,

    //--------------------------------------------------------------------------
    //Storage and retrieval interfaces
    //--------------------------------------------------------------------------
    /// List of trait objects that provide access to trust anchors
    trust_anchor_sources: Vec<Box<dyn TrustAnchorSource + Send + Sync>>,

    /// Hex-encoded subject key identifiers that resolve to more than one distinct public key across
    /// the registered `trust_anchor_sources`. Such a SKID cannot unambiguously identify a trust
    /// anchor, so trust-anchor lookups keyed on it are refused (fail-closed). Recomputed whenever the
    /// set of trust anchor sources changes; see `add_trust_anchor_source`.
    poisoned_ta_skids: BTreeSet<String>,

    /// List of trait objects that provide access to certificates
    certificate_sources: Vec<Box<dyn CertificateSource + Send + Sync>>,

    /// List of trait objects that provide access to CRLs
    crl_sources: Vec<Box<dyn CrlSource + Send + Sync>>,

    /// List of trait objects that provide access to cached revocation status determinations
    revocation_cache: Vec<Box<dyn RevocationStatusCache + Send + Sync>>,

    /// List of trait objects that cache successful certificate signature verifications
    signature_cache: Vec<Box<dyn SignatureVerificationCache + Send + Sync>>,

    /// List of trait objects that provide access to blocklist and last modified info
    check_remote: Vec<Box<dyn CheckRemoteResource + Send + Sync>>,

    //--------------------------------------------------------------------------
    //Miscellaneous interfaces
    //--------------------------------------------------------------------------
    /// List of functions that provide OID lookup capabilities
    oid_lookups: Vec<OidLookup>,
}

impl Default for PkiEnvironment {
    /// PkiEnvironment::default returns a new [`PkiEnvironment`] with empty callback vectors for each
    /// type of callback except `oid_lookups`, which features the [`oid_lookup`] function.
    fn default() -> Self {
        PkiEnvironment {
            calculate_hash_callbacks: vec![],
            verify_signature_digest_callbacks: vec![],
            verify_signature_message_callbacks: vec![],
            verify_signature_digest_ctx_callbacks: vec![],
            verify_signature_message_ctx_callbacks: vec![],
            validate_path_callbacks: vec![],
            trust_anchor_sources: vec![],
            poisoned_ta_skids: BTreeSet::new(),
            certificate_sources: vec![],
            oid_lookups: vec![oid_lookup],
            crl_sources: vec![],
            revocation_cache: vec![],
            signature_cache: vec![],
            check_remote: vec![],
        }
    }
}

impl PkiEnvironment {
    /// PkiEnvironment::new returns a new [`PkiEnvironment`] with empty callback vectors for each type of callback
    pub fn new() -> PkiEnvironment {
        PkiEnvironment {
            calculate_hash_callbacks: vec![],
            verify_signature_digest_callbacks: vec![],
            verify_signature_message_callbacks: vec![],
            verify_signature_digest_ctx_callbacks: vec![],
            verify_signature_message_ctx_callbacks: vec![],
            validate_path_callbacks: vec![],
            trust_anchor_sources: vec![],
            poisoned_ta_skids: BTreeSet::new(),
            certificate_sources: vec![],
            oid_lookups: vec![],
            crl_sources: vec![],
            revocation_cache: vec![],
            signature_cache: vec![],
            check_remote: vec![],
        }
    }

    /// clear_all_callbacks clears the contents of all function pointer and trait object vectors
    /// associated with an instance of [`PkiEnvironment`].
    pub fn clear_all_callbacks(&mut self) {
        self.clear_crl_sources();
        self.clear_oid_lookups();
        self.clear_revocation_cache();
        self.clear_signature_cache();
        self.clear_certificate_sources();
        self.clear_calculate_hash_callbacks();
        self.clear_trust_anchor_sources();
        self.clear_validate_path_callbacks();
        self.clear_verify_signature_digest_callbacks();
        self.clear_verify_signature_message_callbacks();
        self.clear_verify_signature_digest_ctx_callbacks();
        self.clear_verify_signature_message_ctx_callbacks();
        self.clear_check_remote_callbacks();
    }

    /// add_validate_path_callback adds a [`ValidatePath`] callback to the list used by validate_path.
    pub fn add_validate_path_callback(&mut self, c: ValidatePath) {
        self.validate_path_callbacks.push(c);
    }

    /// clear_validate_path_callbacks clears the list of [`ValidatePath`] callbacks used by validate_path.
    pub fn clear_validate_path_callbacks(&mut self) {
        self.validate_path_callbacks.clear();
    }

    /// validate_path iterates over validate_path_callbacks until an authoritative answer is found
    /// or all options have been exhausted
    pub fn validate_path(
        &self,
        pe: &PkiEnvironment,
        cps: &CertificationPathSettings,
        cp: &mut CertificationPath,
        cpr: &mut CertificationPathResults,
    ) -> Result<()> {
        let mut err = None;
        for f in &self.validate_path_callbacks {
            match f(pe, cps, cp, cpr) {
                Ok(r) => {
                    return Ok(r);
                }
                Err(e) => {
                    err = Some(e);
                }
            }
        }
        if let Some(e) = err {
            return Err(e);
        }
        Err(Error::Unrecognized)
    }

    /// add_calculate_hash_callback adds a [`CalculateHash`] callback to the list used by calculate_hash.
    pub fn add_calculate_hash_callback(&mut self, c: CalculateHash) {
        self.calculate_hash_callbacks.push(c);
    }

    /// clear_calculate_hash_callbacks clears the list of [`CalculateHash`] callbacks used by calculate_hash.
    pub fn clear_calculate_hash_callbacks(&mut self) {
        self.calculate_hash_callbacks.clear();
    }

    /// calculate_hash iterates over calculate_hash_callbacks until an authoritative answer is found
    /// or all options have been exhausted
    pub fn calculate_hash(
        &self,
        pe: &PkiEnvironment,
        hash_alg: &AlgorithmIdentifierOwned,
        buffer_to_hash: &[u8],
    ) -> Result<Vec<u8>> {
        for f in &self.calculate_hash_callbacks {
            let r = f(pe, hash_alg, buffer_to_hash);
            if let Ok(r) = r {
                return Ok(r);
            }
        }
        Err(Error::Unrecognized)
    }

    /// add_verify_signature_digest_callback adds a [`VerifySignatureDigest`] callback to the list used by verify_signature_digest.
    pub fn add_verify_signature_digest_callback(&mut self, c: VerifySignatureDigest) {
        self.verify_signature_digest_callbacks.push(c);
    }

    /// clear_verify_signature_digest_callbacks clears the list of [`VerifySignatureDigest`] callbacks used by verify_signature_digest.
    pub fn clear_verify_signature_digest_callbacks(&mut self) {
        self.verify_signature_digest_callbacks.clear();
    }

    /// verify_signature_digest iterates over verify_signature_digest_callbacks until an authoritative answer is found
    /// or all options have been exhausted
    pub fn verify_signature_digest(
        &self,
        pe: &PkiEnvironment,
        hash_to_verify: &[u8],                    // buffer to verify
        signature: &[u8],                         // signature
        signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
        spki: &SubjectPublicKeyInfoOwned,         // public key
    ) -> Result<()> {
        for f in &self.verify_signature_digest_callbacks {
            if f(pe, hash_to_verify, signature, signature_alg, spki).is_ok() {
                return Ok(());
            }
        }
        Err(Error::Unrecognized)
    }

    /// add_verify_signature_digest_ctx_callback adds a [`VerifySignatureDigestWithContext`] callback to the list used by verify_signature_ctx_digest.
    pub fn add_verify_signature_digest_ctx_callback(
        &mut self,
        c: VerifySignatureDigestWithContext,
    ) {
        self.verify_signature_digest_ctx_callbacks.push(c);
    }

    /// clear_verify_signature_digest_ctx_callbacks clears the list of [`VerifySignatureDigestWithContext`] callbacks used by verify_signature_ctx_digest.
    pub fn clear_verify_signature_digest_ctx_callbacks(&mut self) {
        self.verify_signature_digest_ctx_callbacks.clear();
    }

    /// verify_signature_digest iterates over verify_signature_digest_callbacks until an authoritative answer is found
    /// or all options have been exhausted
    pub fn verify_signature_ctx_digest(
        &self,
        pe: &PkiEnvironment,
        hash_to_verify: &[u8],                    // buffer to verify
        signature: &[u8],                         // signature
        signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
        spki: &SubjectPublicKeyInfoOwned,         // public key
        ctx: &Option<Vec<u8>>,                    // context
    ) -> Result<()> {
        for f in &self.verify_signature_digest_ctx_callbacks {
            if f(pe, hash_to_verify, signature, signature_alg, spki, ctx).is_ok() {
                return Ok(());
            }
        }
        Err(Error::Unrecognized)
    }
    /// add_verify_signature_message_callback adds a [`VerifySignatureMessage`] callback to the list used by verify_signature_message.
    pub fn add_verify_signature_message_callback(&mut self, c: VerifySignatureMessage) {
        self.verify_signature_message_callbacks.push(c);
    }

    /// clear_verify_signature_message_callbacks clears the list of [`VerifySignatureMessage`] callbacks used by verify_signature_message.
    pub fn clear_verify_signature_message_callbacks(&mut self) {
        self.verify_signature_message_callbacks.clear();
    }

    /// verify_signature_message iterates over verify_signature_message_callbacks until an authoritative answer is found
    /// or all options have been exhausted
    pub fn verify_signature_message(
        &self,
        pe: &PkiEnvironment,
        message_to_verify: &[u8],                 // buffer to verify
        signature: &[u8],                         // signature
        signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
        spki: &SubjectPublicKeyInfoOwned,         // public key
    ) -> Result<()> {
        for f in &self.verify_signature_message_callbacks {
            let r = f(pe, message_to_verify, signature, signature_alg, spki);
            if let Ok(r) = r {
                return Ok(r);
            }
        }
        Err(Error::Unrecognized)
    }

    /// add_verify_signature_message_ctx_callback adds a [`VerifySignatureMessageWithContext`] callback to the list used by verify_signature_message_ctx.
    pub fn add_verify_signature_message_ctx_callback(
        &mut self,
        c: VerifySignatureMessageWithContext,
    ) {
        self.verify_signature_message_ctx_callbacks.push(c);
    }

    /// clear_verify_signature_message_ctx_callbacks clears the list of [`VerifySignatureMessageWithContext`] callbacks used by verify_signature_message_ctx.
    pub fn clear_verify_signature_message_ctx_callbacks(&mut self) {
        self.verify_signature_message_ctx_callbacks.clear();
    }

    /// verify_signature_ctx_message iterates over verify_signature_message_ctx_callbacks until an authoritative answer is found
    /// or all options have been exhausted
    pub fn verify_signature_message_ctx(
        &self,
        pe: &PkiEnvironment,
        message_to_verify: &[u8],                 // buffer to verify
        signature: &[u8],                         // signature
        signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
        spki: &SubjectPublicKeyInfoOwned,         // public key
        ctx: &Option<Vec<u8>>,                    // context
    ) -> Result<()> {
        for f in &self.verify_signature_message_ctx_callbacks {
            let r = f(pe, message_to_verify, signature, signature_alg, spki, ctx);
            if let Ok(r) = r {
                return Ok(r);
            }
        }
        Err(Error::Unrecognized)
    }

    /// add_trust_anchor_source adds a [`TrustAnchorSource`] object to the list used by get_trust_anchor.
    ///
    /// Adding a source re-evaluates subject key identifier collisions across all registered trust
    /// anchor sources (see `poisoned_ta_skids`). A source whose membership changes after it is added
    /// must be removed and re-added for the collision set to be recomputed; the environment does not
    /// observe a source mutating itself in place.
    pub fn add_trust_anchor_source(&mut self, c: Box<dyn TrustAnchorSource + Send + Sync>) {
        self.trust_anchor_sources.push(c);
        self.reindex_poisoned_ta_skids();
    }

    /// clear_trust_anchor_sources clears the list of [`TrustAnchorSource`] objects used by get_trust_anchor.
    pub fn clear_trust_anchor_sources(&mut self) {
        self.trust_anchor_sources.clear();
        self.reindex_poisoned_ta_skids();
    }

    /// Recomputes [`poisoned_ta_skids`] from the current trust anchor sources. A subject key
    /// identifier is poisoned when two trust anchors share it but carry different public keys, since
    /// the SKID can then no longer identify a unique anchor. Same-key duplicates are benign and are
    /// not poisoned. Runs whenever the set of sources changes; anchors are few, so the scan is cheap.
    fn reindex_poisoned_ta_skids(&mut self) {
        let mut first_spki: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut poisoned: BTreeSet<String> = BTreeSet::new();
        for ta in self.get_trust_anchors() {
            let hex_skid = hex_skid_from_ta(ta);
            if hex_skid.is_empty() || poisoned.contains(&hex_skid) {
                continue;
            }
            let spki_der =
                match get_subject_public_key_info_from_trust_anchor(&ta.decoded_ta).to_der() {
                    Ok(d) => d,
                    Err(_e) => continue,
                };
            match first_spki.get(&hex_skid) {
                Some(existing) if *existing != spki_der => {
                    error!("Trust anchor subject key identifier {hex_skid} resolves to more than one public key across registered sources; refusing to anchor on it");
                    first_spki.remove(&hex_skid);
                    poisoned.insert(hex_skid);
                }
                Some(_) => {} // same SKID, same key: benign duplicate
                None => {
                    first_spki.insert(hex_skid, spki_der);
                }
            }
        }
        self.poisoned_ta_skids = poisoned;
    }

    /// Returns true if `hex_skid` is ambiguous across the registered trust anchor sources, i.e., it
    /// maps to more than one public key. Trust-anchor lookups keyed on such a SKID are refused.
    fn ta_skid_poisoned(&self, hex_skid: &str) -> bool {
        self.poisoned_ta_skids.contains(hex_skid)
    }

    /// get_trust_anchor iterates over trust_anchor_sources until an authoritative answer is found
    /// or all options have been exhausted
    pub fn get_trust_anchor(&self, skid: &[u8]) -> Result<&PDVTrustAnchorChoice> {
        if self.ta_skid_poisoned(&buffer_to_hex(skid)) {
            return Err(Error::Unrecognized);
        }
        for f in &self.trust_anchor_sources {
            let r = f.get_trust_anchor_by_skid(skid);
            if let Ok(r) = r {
                return Ok(r);
            }
        }
        Err(Error::Unrecognized)
    }

    /// get_trust_anchors returns the trust anchors from every registered trust anchor source,
    /// merged into a single collection. Sources that yield no anchors are skipped (previously only
    /// the first source that returned successfully was consulted; see issue #79).
    pub fn get_trust_anchors(&self) -> Vec<&PDVTrustAnchorChoice> {
        self.trust_anchor_sources
            .iter()
            .filter_map(|src| src.get_trust_anchors().ok())
            .flatten()
            .collect()
    }

    /// get_trust_anchor_by_hex_skid returns a reference to a trust anchor corresponding to the presented hexadecimal SKID.
    pub fn get_trust_anchor_by_hex_skid(&self, hex_skid: &str) -> Result<&PDVTrustAnchorChoice> {
        if self.ta_skid_poisoned(hex_skid) {
            return Err(Error::Unrecognized);
        }
        for f in &self.trust_anchor_sources {
            let r = f.get_trust_anchor_by_hex_skid(hex_skid);
            if let Ok(r) = r {
                return Ok(r);
            }
        }
        Err(Error::Unrecognized)
    }

    /// get_trust_anchor_for_target takes a target certificate and returns a trust anchor that may
    /// be useful in verifying the certificate.
    pub fn get_trust_anchor_for_target(
        &self,
        target: &PDVCertificate,
    ) -> Result<&PDVTrustAnchorChoice> {
        for f in &self.trust_anchor_sources {
            if let Ok(r) = f.get_trust_anchor_for_target(target) {
                // Refuse a candidate whose SKID is ambiguous across sources rather than anchoring on
                // a guess; the collision may be why this source matched by name in the first place.
                if self.ta_skid_poisoned(&hex_skid_from_ta(r)) {
                    continue;
                }
                return Ok(r);
            }
        }
        Err(Error::Unrecognized)
    }

    /// Retrieves a trust anchor for a given Name
    pub fn get_trust_anchor_by_name(&'_ self, name: &Name) -> Result<&PDVTrustAnchorChoice> {
        for f in &self.trust_anchor_sources {
            if let Ok(r) = f.get_trust_anchor_by_name(name) {
                if self.ta_skid_poisoned(&hex_skid_from_ta(r)) {
                    continue;
                }
                return Ok(r);
            }
        }

        Err(Error::Unrecognized)
    }

    /// Retrieves a set of certificates from certificate sources (i.e. intermediate CAs) matching a certain name
    pub fn get_cert_by_name(&'_ self, name: &Name) -> Vec<&PDVCertificate> {
        self.certificate_sources.iter().fold(vec![], |mut acc, f| {
            if let Ok(mut r) = f.get_certificates_for_name(name) {
                acc.append(&mut r);
            }
            acc
        })
    }

    /// is_cert_a_trust_anchor takes a target certificate indication if cert is a trust anchor.
    pub fn is_cert_a_trust_anchor(&self, target: &PDVCertificate) -> Result<()> {
        // An ambiguous SKID cannot identify a unique anchor, so do not treat a cert bearing one as a
        // trust anchor even if a source matches it.
        if self.ta_skid_poisoned(&hex_skid_from_cert(target)) {
            return Err(Error::NotFound);
        }
        for f in &self.trust_anchor_sources {
            if f.is_cert_a_trust_anchor(target).is_ok() {
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// is_trust_anchor takes a [`PDVTrustAnchorChoice`] indication if cert is a trust anchor.
    pub fn is_trust_anchor(&self, target: &PDVTrustAnchorChoice) -> Result<()> {
        if self.ta_skid_poisoned(&hex_skid_from_ta(target)) {
            return Err(Error::NotFound);
        }
        for f in &self.trust_anchor_sources {
            if f.is_trust_anchor(target).is_ok() {
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// add_certificate_source adds a [`CertificateSource`] object to the list.
    pub fn add_certificate_source(&mut self, c: Box<dyn CertificateSource + Send + Sync>) {
        self.certificate_sources.push(c);
    }

    /// clear_certificate_sources clears the list of [`CertificateSource`] objects.
    pub fn clear_certificate_sources(&mut self) {
        self.certificate_sources.clear();
    }

    /// gives all the intermediate certificates
    pub fn get_intermediates(&self) -> Result<Vec<&PDVCertificate>> {
        for f in &self.certificate_sources {
            let r = f.get_certificates();
            if let Ok(r) = r {
                return Ok(r);
            }
        }
        Err(Error::Unrecognized)
    }

    /// Fetches all intermediate certs matching a particular skid
    pub fn get_intermediates_by_skid(&self, skid: &[u8]) -> Result<Vec<&PDVCertificate>> {
        for f in &self.certificate_sources {
            let r = f.get_certificates_for_skid(skid);
            if let Ok(r) = r {
                return Ok(r);
            }
        }
        Err(Error::Unrecognized)
    }

    /// add_crl_source adds a [`CrlSource`] object to the list.
    pub fn add_crl_source(&mut self, c: Box<dyn CrlSource + Send + Sync>) {
        self.crl_sources.push(c);
    }

    /// clear_crl_sources clears the list of [`CrlSource`] objects.
    pub fn clear_crl_sources(&mut self) {
        self.crl_sources.clear();
    }

    /// Retrieves all the CRLs made available by the various [`CrlSource`] objects
    pub fn get_all_crls(&self) -> Result<Vec<Vec<u8>>> {
        let mut retval = vec![];
        for f in &self.crl_sources {
            let Ok(mut crls) = f.get_all_crls() else {
                continue;
            };
            retval.append(&mut crls);
        }
        retval.dedup();
        Ok(retval)
    }

    /// Retrieves CRLs for given certificate from store
    pub fn get_crls(&self, cert: &PDVCertificate) -> Result<Vec<Vec<u8>>> {
        let mut retval = vec![];
        for f in &self.crl_sources {
            if let Ok(crls) = f.get_crls(cert) {
                for crl in crls {
                    retval.push(crl);
                }
            }
        }
        if !retval.is_empty() {
            return Ok(retval);
        }
        Err(Error::NotFound)
    }

    /// Adds a CRL to the store
    pub fn add_crl(&self, crl_buf: &[u8], crl: &CertificateList<Raw>, uri: &str) -> Result<()> {
        let mut at_least_one_success = false;
        for f in &self.crl_sources {
            if f.add_crl(crl_buf, crl, uri).is_ok() {
                at_least_one_success = true;
            }
        }
        if at_least_one_success {
            return Ok(());
        }
        Err(Error::NotFound)
    }

    /// add_revocation_cache adds a [`RevocationStatusCache`] object to the list.
    pub fn add_revocation_cache(&mut self, c: Box<dyn RevocationStatusCache + Send + Sync>) {
        self.revocation_cache.push(c);
    }

    /// clear_revocation_cache clears the list of [`CertificateSource`] objects.
    pub fn clear_revocation_cache(&mut self) {
        self.revocation_cache.clear();
    }

    /// add_signature_cache adds a [`SignatureVerificationCache`] object to the list. Adding one opts
    /// the environment into memoizing successful certificate signature verifications; with none
    /// added, signatures are verified on every path validation as usual.
    pub fn add_signature_cache(&mut self, c: Box<dyn SignatureVerificationCache + Send + Sync>) {
        self.signature_cache.push(c);
    }

    /// clear_signature_cache clears the list of [`SignatureVerificationCache`] objects.
    pub fn clear_signature_cache(&mut self) {
        self.signature_cache.clear();
    }

    /// has_signature_cache returns true if at least one [`SignatureVerificationCache`] is configured.
    /// Callers use this to avoid computing cache keys when memoization is not in use.
    pub fn has_signature_cache(&self) -> bool {
        !self.signature_cache.is_empty()
    }

    /// is_signature_verified returns true if any configured [`SignatureVerificationCache`] reports the
    /// signature over `cert_hash` by the key identified by `issuer_spki_hash` as already verified.
    pub fn is_signature_verified(&self, cert_hash: &[u8], issuer_spki_hash: &[u8]) -> bool {
        self.signature_cache
            .iter()
            .any(|c| c.is_verified(cert_hash, issuer_spki_hash))
    }

    /// add_verified_signature records a successful signature verification in each configured
    /// [`SignatureVerificationCache`]. It is a no-op when no cache has been added.
    pub fn add_verified_signature(&self, cert_hash: &[u8], issuer_spki_hash: &[u8]) {
        for c in &self.signature_cache {
            c.add_verified(cert_hash, issuer_spki_hash);
        }
    }

    /// Retrieves cached revocation status determination for given certificate from store
    pub fn get_status(
        &self,
        cert: &PDVCertificate,
        time_of_interest: TimeOfInterest,
    ) -> PathValidationStatus {
        for f in &self.revocation_cache {
            let status = f.get_status(cert, time_of_interest);
            if RevocationStatusNotDetermined != status {
                return status;
            }
        }
        RevocationStatusNotDetermined
    }

    /// Adds a cached revocation status determination to the store
    pub fn add_status(
        &self,
        cert: &PDVCertificate,
        next_update: u64,
        status: PathValidationStatus,
    ) {
        for f in &self.revocation_cache {
            f.add_status(cert, next_update, status);
        }
    }

    /// get_paths_for_target takes a target certificate and a source for trust anchors and returns
    /// a vector of [`CertificationPath`] objects.
    pub fn get_paths_for_target(
        &self,
        target: &PDVCertificate,
        paths: &mut Vec<CertificationPath>,
        threshold: usize,
        time_of_interest: TimeOfInterest,
    ) -> Result<()> {
        let mut some_valid = false;
        let mut last_error = Error::Unrecognized;
        for f in &self.certificate_sources {
            match f.get_paths_for_target(self, target, paths, threshold, time_of_interest) {
                Ok(_) => some_valid = true,
                Err(e) => {
                    last_error = e;
                }
            }
        }
        if some_valid {
            Ok(())
        } else {
            Err(last_error)
        }
    }

    /// add_oid_lookup adds a oid_lookup callback to the list used by get_trust_anchors.
    pub fn add_oid_lookup(&mut self, c: OidLookup) {
        self.oid_lookups.push(c);
    }

    /// clear_oid_lookups clears the list of oid_lookup callbacks used by oid_lookup.
    pub fn clear_oid_lookups(&mut self) {
        self.oid_lookups.clear();
    }

    /// oid_lookup takes an [`ObjectIdentifier`] and returns either a friendly name for the OID or the
    /// OID represented in dot notation.
    pub fn oid_lookup(&self, oid: &ObjectIdentifier) -> String {
        for f in &self.oid_lookups {
            let r = f(oid);
            if let Ok(r) = r {
                return r;
            }
        }
        oid.to_string()
    }

    /// add_check_remote adds a [`CheckRemoteResource`] object to the list.
    pub fn add_check_remote(&mut self, c: Box<dyn CheckRemoteResource + Send + Sync>) {
        self.check_remote.push(c);
    }

    /// clear_check_remote_callbacks clears the list of [`CheckRemoteResource`] objects.
    pub fn clear_check_remote_callbacks(&mut self) {
        self.check_remote.clear();
    }

    /// get_last_modified takes a URI and returns stored last modified value or None.
    pub fn get_last_modified(&self, uri: &str) -> Option<String> {
        for f in &self.check_remote {
            let r = f.get_last_modified(uri);
            if let Some(r) = r {
                return Some(r);
            }
        }
        None
    }
    /// Save last modified value, if desired
    pub fn set_last_modified(&self, uri: &str, last_modified: &str) {
        for f in &self.check_remote {
            f.set_last_modified(uri, last_modified);
        }
    }
    /// Gets blocklist takes a URI and returns true if it is on blocklist and false otherwise
    pub fn check_blocklist(&self, uri: &str) -> bool {
        for f in &self.check_remote {
            let r = f.check_blocklist(uri);
            if r {
                return true;
            }
        }
        false
    }
    /// Save blocklist, if desired
    pub fn add_to_blocklist(&self, uri: &str) {
        for f in &self.check_remote {
            f.add_to_blocklist(uri);
        }
    }

    /// `populate_5280_pki_environment` populates a default [`PkiEnvironment`] instance with a default set of callback
    /// functions specified.
    ///
    /// The following callbacks are added:
    /// - [`validate_path_rfc5280`]
    /// - [`calculate_hash_rust_crypto`]
    /// - [`verify_signature_digest_rust_crypto`]
    /// - [`verify_signature_message_rust_crypto`]
    ///
    /// This function assumes that [`oid_lookup`] is either present due to [`PkiEnvironment::default`] creation
    /// or that it has been deliberately removed or replaced by the caller but will add oid_lookup if
    /// OID lookup support is absent.
    pub fn populate_5280_pki_environment(&mut self) {
        self.add_validate_path_callback(validate_path_rfc5280);
        self.add_calculate_hash_callback(calculate_hash_rust_crypto);
        self.add_verify_signature_digest_callback(verify_signature_digest_rust_crypto);
        self.add_verify_signature_message_callback(verify_signature_message_rust_crypto);
        if self.oid_lookups.is_empty() {
            self.add_oid_lookup(oid_lookup);
        }

        #[cfg(feature = "pqc")]
        self.add_verify_signature_message_callback(verify_signature_message_rustcrypto);
        #[cfg(feature = "pqc")]
        self.add_verify_signature_message_ctx_callback(verify_signature_message_ctx_rustcrypto);
        #[cfg(feature = "pqc")]
        self.add_verify_signature_message_callback(verify_signature_message_composite_rustcrypto);
        #[cfg(feature = "pqc")]
        self.add_verify_signature_message_callback(verify_signature_message_fndsa);
    }
}

/// Computes the hash used to key a [`SignatureVerificationCache`] entry from a certificate DER or an
/// issuer subject-public-key-info DER. SHA-256 uniquely identifies the input for this purpose.
pub(crate) fn signature_cache_hash(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).to_vec()
}

/// A bounded, thread-safe [`SignatureVerificationCache`] backed by an in-memory set. Recording stops
/// once the cap is reached so a long-lived environment that validates many distinct certificates
/// cannot grow it without bound; the graph builder records certificate-authority edges first, so the
/// frequently reused entries are retained.
#[cfg(feature = "std")]
pub struct DefaultSignatureVerificationCache {
    verified: std::sync::RwLock<alloc::collections::BTreeSet<(Vec<u8>, Vec<u8>)>>,
    cap: usize,
}

#[cfg(feature = "std")]
impl DefaultSignatureVerificationCache {
    /// Default maximum number of cached verifications.
    pub const DEFAULT_CAP: usize = 8192;

    /// Creates a cache with the default cap ([`DefaultSignatureVerificationCache::DEFAULT_CAP`]).
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAP)
    }

    /// Creates a cache that stops recording new entries once `cap` have accumulated.
    pub fn with_capacity(cap: usize) -> Self {
        DefaultSignatureVerificationCache {
            verified: std::sync::RwLock::new(alloc::collections::BTreeSet::new()),
            cap,
        }
    }
}

#[cfg(feature = "std")]
impl Default for DefaultSignatureVerificationCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl SignatureVerificationCache for DefaultSignatureVerificationCache {
    fn is_verified(&self, cert_hash: &[u8], issuer_spki_hash: &[u8]) -> bool {
        match self.verified.read() {
            Ok(set) => set.contains(&(cert_hash.to_vec(), issuer_spki_hash.to_vec())),
            Err(_) => false,
        }
    }

    fn add_verified(&self, cert_hash: &[u8], issuer_spki_hash: &[u8]) {
        if let Ok(mut set) = self.verified.write() {
            if set.len() < self.cap {
                set.insert((cert_hash.to_vec(), issuer_spki_hash.to_vec()));
            }
        }
    }
}

/// Delegating implementation so a caller can retain a shared handle to a cache (for example to
/// inspect it) while also handing it to a [`PkiEnvironment`] via `add_signature_cache`.
#[cfg(feature = "std")]
impl<T: SignatureVerificationCache + ?Sized> SignatureVerificationCache for alloc::sync::Arc<T> {
    fn is_verified(&self, cert_hash: &[u8], issuer_spki_hash: &[u8]) -> bool {
        (**self).is_verified(cert_hash, issuer_spki_hash)
    }

    fn add_verified(&self, cert_hash: &[u8], issuer_spki_hash: &[u8]) {
        (**self).add_verified(cert_hash, issuer_spki_hash)
    }
}

#[cfg(all(test, feature = "std"))]
mod signature_cache_tests {
    use super::*;

    #[test]
    fn default_signature_cache_records_queries_and_caps() {
        let cache = DefaultSignatureVerificationCache::with_capacity(2);
        assert!(!cache.is_verified(b"cert-a", b"key-1"));

        cache.add_verified(b"cert-a", b"key-1");
        assert!(cache.is_verified(b"cert-a", b"key-1"));
        // The issuer key is part of the key, so the same certificate against a different key is
        // still unknown.
        assert!(!cache.is_verified(b"cert-a", b"key-2"));

        // Fill the cache to its cap; the second entry is recorded.
        cache.add_verified(b"cert-b", b"key-1");
        assert!(cache.is_verified(b"cert-b", b"key-1"));

        // At the cap, further entries are dropped, so they report as not verified.
        cache.add_verified(b"cert-c", b"key-1");
        assert!(!cache.is_verified(b"cert-c", b"key-1"));
    }
}
