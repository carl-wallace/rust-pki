//! PkiEnvironment aggregates a set of function pointers and trait objects that supply functionality
//! useful when building and/or validating a certification path, processing or generating a CMS
//! message, etc. The sample below illustrates preparation of a PkiEnvironment object for use in
//! building and validating certification paths. Note, the instantiation of PkiEnvironment before
//! indexing the TaSource and CertSources objects provides access to optional logging capabilities.
//! ```
//! use certval::PkiEnvironment;
//! use certval::*;
//!
//! // the default PkiEnvironment uses `oid_lookup` to look up friendly names for OIDs
//! let mut pe = PkiEnvironment::default();
//! // provide a logging callback that uses preferred logging mechanism. PITTv3 uses log4rs.
//! // pe.add_logger(log_message);
//!
//! let mut ta_source = TaSource::default();
//! // populate the ta_store.buffers and ta_store.tas fields then call ta_store.index_tas()
//! ta_source.index_tas(&pe);
//!
//! let mut cert_source = CertSource::default();
//! // populate the cert_source.buffers and cert_source.certs fields then call cert_source.index_certs()
//! cert_source.index_certs(&pe);
//!
//! // add ta_source and cert_source to provide access to trust anchors and intermediate CA certificates
//! pe.add_trust_anchor_source(&ta_source);
//! pe.add_certificate_source(&cert_source);
//!
//! // add hashing and signature verification capabilities
//! pe.add_calculate_hash_callback(calculate_hash_rust_crypto);
//! pe.add_verify_signature_digest_callback(verify_signature_digest_rust_crypto);
//! pe.add_verify_signature_message_callback(verify_signature_message_rust_crypto);
//!
//! // add certification path building and validation capabilities
//! pe.add_path_builder(&cert_source);
//! pe.add_validate_path_callback(validate_path_rfc5280);
//! ```
//!
//! The aggregation of function pointers and trait objects allows for various implementations. For
//! example, one app may desire path validation without some PKIX features (like certificate policy)
//! processing and another may desire access to trust anchors via a system store (via an FFI
//! implementation) or much smaller sets of trust anchors for selected operations.
//!

use crate::error::*;
use crate::pdv_utilities::oid_lookup;
use crate::{
    crypto::*, path_settings::*, pki_environment_traits::*, validate_path_rfc5280, PDVCertificate,
    PDVTrustAnchorChoice,
};
use alloc::string::String;
use alloc::string::ToString;
use alloc::{vec, vec::Vec};
use der::asn1::ObjectIdentifier;
use x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

/*
/// `GetCredentialList` provides a function signature for implementations that list available credentials
pub type GetCredentialList = fn(&PkiEnvironment<'_>, &dyn Credential) -> Result<()>;
*/

/// `ValidatePath` provides a function signature for implementations that perform certification path validation
pub type ValidatePath = fn(
    &PkiEnvironment<'_>,
    &CertificationPathSettings<'_>, // path settings to govern validation
    &mut CertificationPath<'_>,     // path to verify
    &mut CertificationPathResults<'_>, // path validation results
) -> Result<()>;

/// `CalculateHash` provides a function signature for implementations that perform hashing
pub type CalculateHash = fn(
    &PkiEnvironment<'_>,
    &AlgorithmIdentifier<'_>, // hash alg
    &[u8],                    // buffer to hash
) -> Result<Vec<u8>>;

/// `VerifySignature` provides a function signature for implementations that perform signature verification
/// over a message digest.
pub type VerifySignatureDigest = fn(
    &PkiEnvironment<'_>,
    &[u8],                     // buffer to verify
    &[u8],                     // signature
    &AlgorithmIdentifier<'_>,  // signature algorithm
    &SubjectPublicKeyInfo<'_>, // public key
) -> Result<()>;

/// `VerifySignature` provides a function signature for implementations that perform signature verification
/// over a message digest.
pub type VerifySignatureMessage = fn(
    &PkiEnvironment<'_>,
    &[u8],                     // message to hash and verify
    &[u8],                     // signature
    &AlgorithmIdentifier<'_>,  // signature algorithm
    &SubjectPublicKeyInfo<'_>, // public key
) -> Result<()>;

/// `GetTrustAnchors` provides a function signature for implementations that return a list of trust anchors
pub type GetTrustAnchors = fn(&PkiEnvironment<'_>, &mut Vec<Vec<u8>>) -> Result<()>;

/// `OidLookup` implementations take an OID and returns either a friendly name for the OID or a
/// NotFound error. Where NotFound is returned by all OidLookup implementations, the
/// [`PkiEnvironment`] returns a dot notation version of the OID.
pub type OidLookup = fn(&ObjectIdentifier) -> Result<String>;

/// Enum that describes level associated with a log message
#[derive(Debug, Eq, PartialEq)]
pub enum PeLogLevels {
    /// Common error logging level
    PeError,
    /// Common info logging level
    PeInfo,
    /// Common warn logging level
    PeWarn,
    /// Common debug logging level
    PeDebug,
}

/// `PeLogger` provides a function signature for logging implementations using various backends
pub type PeLogger = fn(level: &PeLogLevels, message: &str);

/// [`PkiEnvironment`] provides a switchboard of callback functions that allow support to vary on different
/// platforms or to allow support to be tailored for specific use cases.
pub struct PkiEnvironment<'a> {
    /*
    //--------------------------------------------------------------------------
    //Credential interfaces
    //--------------------------------------------------------------------------
    /// List of functions that provide a list of available credentials
    get_credential_list_callbacks: Vec<GetCredentialList>,
    */
    //--------------------------------------------------------------------------
    //Crypto interfaces
    //--------------------------------------------------------------------------
    /// List of functions that provide a message digest functionality
    calculate_hash_callbacks: Vec<CalculateHash>,

    /// List of functions that provide a siganture verification functionality given a digest
    verify_signature_digest_callbacks: Vec<VerifySignatureDigest>,

    /// List of functions that provide a siganture verification functionality given a message
    verify_signature_message_callbacks: Vec<VerifySignatureMessage>,

    //--------------------------------------------------------------------------
    //Certification path processing interfaces
    //--------------------------------------------------------------------------
    /// List of functions that provide a list of path validation implementations
    validate_path_callbacks: Vec<ValidatePath>,

    /// List of trait objects that build certification paths
    path_builders: Vec<&'a dyn CertificationPathBuilder>,

    //--------------------------------------------------------------------------
    //Storage and retrieval interfaces
    //--------------------------------------------------------------------------
    /// List of trait objects that provide access to trust anchors
    trust_anchor_sources: Vec<&'a dyn TrustAnchorSource>,

    /// List of trait objects that provide access to certificates
    certificate_sources: Vec<&'a dyn CertificateSource>,

    //--------------------------------------------------------------------------
    //Credential interfaces
    //--------------------------------------------------------------------------
    /// List of functions that provide OID lookup capabilities
    oid_lookups: Vec<OidLookup>,

    /// List of functions that provide logging support
    loggers: Vec<PeLogger>,
}

impl Default for PkiEnvironment<'_> {
    /// PkiEnvironment::default returns a new PkiEnvironment with empty callback vectors for each
    /// type of callback except `oid_lookups`, which features the [`oid_lookup`] function.
    fn default() -> Self {
        PkiEnvironment {
            //get_credential_list_callbacks: vec![],
            calculate_hash_callbacks: vec![],
            verify_signature_digest_callbacks: vec![],
            verify_signature_message_callbacks: vec![],
            validate_path_callbacks: vec![],
            trust_anchor_sources: vec![],
            certificate_sources: vec![],
            path_builders: vec![],
            oid_lookups: vec![oid_lookup],
            loggers: vec![],
        }
    }
}

impl<'a> PkiEnvironment<'a> {
    /// PkiEnvironment::new returns a new PkiEnvironment with empty callback vectors for each type of callback
    pub fn new() -> PkiEnvironment<'a> {
        PkiEnvironment {
            //get_credential_list_callbacks: vec![],
            calculate_hash_callbacks: vec![],
            verify_signature_digest_callbacks: vec![],
            verify_signature_message_callbacks: vec![],
            validate_path_callbacks: vec![],
            trust_anchor_sources: vec![],
            certificate_sources: vec![],
            path_builders: vec![],
            oid_lookups: vec![],
            loggers: vec![],
        }
    }

    /*
    /// add_credential_list_callback adds a GetCredentialList callback to the list used by get_credential_list.
    pub fn add_credential_list_callback(&mut self, c: GetCredentialList) {
        self.get_credential_list_callbacks.push(c);
    }

    /// clear_credential_list clears the list of GetCredentialList callbacks used by get_credential_list.
    pub fn clear_credential_list(&mut self) {
        self.get_credential_list_callbacks.clear();
    }

    /// get_credential_list iterates over get_credential_list_callbacks until an authoritative
    /// source for a credential is found or all options have been exhausted
    pub fn get_credential_list(
        &self,
        pe: &PkiEnvironment<'_>,
        cred: &dyn Credential,
    ) -> Result<()> {
        for f in &self.get_credential_list_callbacks {
            let r = f(pe, cred);
            if let Ok(r) = r {
                return Ok(r);
            }
        }
        Err(Error::Unrecognized)
    }
    */

    /// add_validate_path_callback adds a ValidatePath callback to the list used by validate_path.
    pub fn add_validate_path_callback(&mut self, c: ValidatePath) {
        self.validate_path_callbacks.push(c);
    }

    /// clear_validate_path_callbacks clears the list of ValidatePath callbacks used by validate_path.
    pub fn clear_validate_path_callbacks(&mut self) {
        self.validate_path_callbacks.clear();
    }

    /// validate_path iterates over validate_path_callbacks until an authoritative answer is found
    /// or all options have been exhausted
    pub fn validate_path(
        &self,
        pe: &PkiEnvironment<'_>,
        cps: &CertificationPathSettings<'_>,
        cp: &mut CertificationPath<'_>,
        cpr: &mut CertificationPathResults<'_>,
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

    /// add_validate_path_callback adds a ValidatePath callback to the list used by validate_path.
    pub fn add_calculate_hash_callback(&mut self, c: CalculateHash) {
        self.calculate_hash_callbacks.push(c);
    }

    /// clear_validate_path_callbacks clears the list of ValidatePath callbacks used by validate_path.
    pub fn clear_calculate_hash_callbacks(&mut self) {
        self.validate_path_callbacks.clear();
    }

    /// validate_path iterates over validate_path_callbacks until an authoritative answer is found
    /// or all options have been exhausted
    pub fn calculate_hash(
        &self,
        pe: &PkiEnvironment<'_>,
        hash_alg: &AlgorithmIdentifier<'_>,
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

    /// add_verify_signature_digest_callback adds a VerifySignatureDigest callback to the list used by verify_signature_digest.
    pub fn add_verify_signature_digest_callback(&mut self, c: VerifySignatureDigest) {
        self.verify_signature_digest_callbacks.push(c);
    }

    /// clear_verify_signature_digest_callbacks clears the list of VerifySignatureDigest callbacks used by verify_signature_digest.
    pub fn clear_verify_signature_digest_callbacks(&mut self) {
        self.verify_signature_digest_callbacks.clear();
    }

    /// verify_signature_digest iterates over verify_signature_digest_callbacks until an authoritative answer is found
    /// or all options have been exhausted
    pub fn verify_signature_digest(
        &self,
        pe: &PkiEnvironment<'_>,
        hash_to_verify: &[u8],                   // buffer to verify
        signature: &[u8],                        // signature
        signature_alg: &AlgorithmIdentifier<'_>, // signature algorithm
        spki: &SubjectPublicKeyInfo<'_>,         // public key
    ) -> Result<()> {
        for f in &self.verify_signature_digest_callbacks {
            let r = f(pe, hash_to_verify, signature, signature_alg, spki);
            if let Ok(r) = r {
                return Ok(r);
            }
        }
        Err(Error::Unrecognized)
    }

    /// add_verify_signature_message_callback adds a VerifySignatureMessage callback to the list used by verify_signature_message.
    pub fn add_verify_signature_message_callback(&mut self, c: VerifySignatureMessage) {
        self.verify_signature_message_callbacks.push(c);
    }

    /// clear_verify_signature_message_callbacks clears the list of VerifySignatureMessage callbacks used by verify_signature_message.
    pub fn clear_verify_signature_message_callbacks(&mut self) {
        self.verify_signature_message_callbacks.clear();
    }

    /// verify_signature_digest iterates over verify_signature_message_callbacks until an authoritative answer is found
    /// or all options have been exhausted
    pub fn verify_signature_message(
        &self,
        pe: &PkiEnvironment<'_>,
        message_to_verify: &[u8],                // buffer to verify
        signature: &[u8],                        // signature
        signature_alg: &AlgorithmIdentifier<'_>, // signature algorithm
        spki: &SubjectPublicKeyInfo<'_>,         // public key
    ) -> Result<()> {
        for f in &self.verify_signature_message_callbacks {
            let r = f(pe, message_to_verify, signature, signature_alg, spki);
            if let Ok(r) = r {
                return Ok(r);
            }
        }
        Err(Error::Unrecognized)
    }

    /// add_trust_anchor_source adds a TrustAnchorSource object to the list used by get_trust_anchor.
    pub fn add_trust_anchor_source(&mut self, c: &'a dyn TrustAnchorSource) {
        self.trust_anchor_sources.push(c);
    }

    /// clear_trust_anchor_sources clears the list of TrustAnchorSource objects used by get_trust_anchor.
    pub fn clear_trust_anchor_sources(&mut self) {
        self.trust_anchor_sources.clear();
    }

    /// get_trust_anchor iterates over trust_anchor_sources until an authoritative answer is found
    /// or all options have been exhausted
    pub fn get_trust_anchor(&self, skid: &[u8]) -> Result<&PDVTrustAnchorChoice<'_>> {
        for f in &self.trust_anchor_sources {
            let r = f.get_trust_anchor_by_skid(skid);
            if let Ok(r) = r {
                return Ok(r);
            }
        }
        Err(Error::Unrecognized)
    }

    /// get_trust_anchor_by_hex_skid returns a reference to a trust anchor corresponding to the presented hexadecimal SKID.
    pub fn get_trust_anchor_by_hex_skid(
        &'_ self,
        hex_skid: &str,
    ) -> Result<&PDVTrustAnchorChoice<'_>> {
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
        &'_ self,
        pe: &PkiEnvironment<'_>,
        target: &'_ PDVCertificate<'_>,
    ) -> Result<&PDVTrustAnchorChoice<'_>> {
        for f in &self.trust_anchor_sources {
            let r = f.get_trust_anchor_for_target(pe, target);
            if let Ok(r) = r {
                return Ok(r);
            }
        }
        Err(Error::Unrecognized)
    }

    /// add_trust_anchor_source adds a CertificateSource object to the list.
    pub fn add_certificate_source(&mut self, c: &'a dyn CertificateSource) {
        self.certificate_sources.push(c);
    }

    /// clear_get_trust_anchor_sources clears the list of CertificateSource objects.
    pub fn clear_certificate_sources(&mut self) {
        self.certificate_sources.clear();
    }

    /// add_trust_anchor_source adds a CertificateSource object to the list.
    pub fn add_path_builder(&mut self, c: &'a dyn CertificationPathBuilder) {
        self.path_builders.push(c);
    }

    /// clear_get_trust_anchor_sources clears the list of CertificateSource objects.
    pub fn clear_path_builders(&mut self) {
        self.path_builders.clear();
    }

    /// find_paths_for_target takes a target certificate and a source for trust anchors and returns
    /// a vector of CertificationPath objects.
    pub fn get_paths_for_target<'reference>(
        &'a self,
        pe: &'a PkiEnvironment<'a>,
        target: &'a PDVCertificate<'a>,
        paths: &'reference mut Vec<CertificationPath<'a>>,
        threshold: usize,
        time_of_interest: u64,
    ) -> Result<()>
    where
        'a: 'reference,
    {
        for f in &self.path_builders {
            let r = f.get_paths_for_target(pe, target, paths, threshold, time_of_interest);
            if let Ok(r) = r {
                return Ok(r);
            }
        }
        Err(Error::Unrecognized)
    }

    /// add_oid_lookup adds a oid_lookup callback to the list used by get_trust_anchors.
    pub fn add_oid_lookup(&mut self, c: OidLookup) {
        self.oid_lookups.push(c);
    }

    /// clear_oid_lookups clears the list of oid_lookup callbacks used by oid_lookup.
    pub fn clear_oid_lookups(&mut self) {
        self.oid_lookups.clear();
    }

    /// log_message passes a message to all available logging backends until one is found. if no
    /// match, dot notation version of OID is returned.
    pub fn oid_lookup(&self, oid: &ObjectIdentifier) -> String {
        for f in &self.oid_lookups {
            let r = f(oid);
            if let Ok(r) = r {
                return r;
            }
        }
        oid.to_string()
    }

    /// add_get_trust_anchors_callback adds a GetTrustAnchors callback to the list used by get_trust_anchors.
    pub fn add_logger(&mut self, c: PeLogger) {
        self.loggers.push(c);
    }

    /// clear_loggers clears the list of log_message callbacks used by log_message.
    pub fn clear_loggers(&mut self) {
        self.loggers.clear();
    }

    /// log_message passes a message to all available logging backends
    pub fn log_message(&self, level: &PeLogLevels, message: &str) {
        for f in &self.loggers {
            f(level, message);
        }
    }
}

/// `populate_5280_pki_environment` populates a default PkiEnvironment instance with a default set of callback
/// functions specified.
///
/// The following callbacks are added:
/// - [`validate_path_rfc5280`]
/// - [`calculate_hash_rust_crypto`]
/// - [`verify_signature_digest_rust_crypto`]
/// - [`verify_signature_message_rust_crypto`]
///
/// This function assumes that [`oid_lookup`] is either present due to PkiEnvironment::default creation
/// or that it has been deliberately removed or replaced by the caller.
pub fn populate_5280_pki_environment(pe: &mut PkiEnvironment<'_>) {
    pe.add_validate_path_callback(validate_path_rfc5280);
    pe.add_calculate_hash_callback(calculate_hash_rust_crypto);
    pe.add_verify_signature_digest_callback(verify_signature_digest_rust_crypto);
    pe.add_verify_signature_message_callback(verify_signature_message_rust_crypto);
}
