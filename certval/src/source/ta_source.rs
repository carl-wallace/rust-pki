//! Provides implementation of a manually populated in-memory TA store. The following snip, similar
//! to code in [`PITTv3`](../../pittv3/index.html), illustrates preparation and use of a [`TaSource`] object.
//!
//! ```
//! use certval::PkiEnvironment;
//! use certval::TaSource;
//!
//! // the default PkiEnvironment uses `oid_lookup` to look up friendly names for OIDs
//! let mut pe = PkiEnvironment::default();
//!
//! let mut ta_source = TaSource::default();
//! // populate the ta_store.buffers and ta_store.tas fields then index the trust anchors. see the
//! // `populate_parsed_ta_vector` usage in `Pittv3` for file-system based sample.
//! ta_source.index_tas();
//!
//! // add ta_source to provide access to trust anchors
//! pe.add_trust_anchor_source(Box::new(ta_source.clone()));
//! ```
//!
//! [`TaSource`] instances are used when preparing a serialized file containing intermediate CA
//! certificates and partial paths (see [`find_all_partial_paths`](../cert_source/struct.CertSource.html#method.find_all_partial_paths)) and when building
//! certification paths (see [`get_paths_for_target`](../cert_source/struct.CertSource.html#method.get_paths_for_target)).
//!

use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::{vec, vec::Vec};
use core::str;
use log::{error, info, warn};

use ciborium::from_reader;

#[cfg(feature = "webpki")]
use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(feature = "webpki")]
use alloc::format;

use subtle_encoding::hex;

use const_oid::db::rfc5912::{ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_SUBJECT_KEY_IDENTIFIER};
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::name::Name;
use x509_cert::{
    anchor::TrustAnchorChoice,
    certificate::{CertificateInner, Raw},
};

use crate::{
    environment::pki_environment_traits::TrustAnchorSource,
    pdv_extension::PDVExtension,
    pdv_extension::*,
    pdv_trust_anchor::get_trust_anchor_name,
    source::cert_source::CertFile,
    util::error::*,
    util::pdv_utilities::{get_leaf_rdn, name_to_string},
    BuffersAndPaths, CertVector, PDVCertificate, PDVTrustAnchorChoice,
};

/// `get_subject_public_key_info_from_trust_anchor` returns a reference to the subject public key
/// containing in a TrustAnchorChoice object:
/// - Certificate.tbs_certificate.subject_public_key_info
/// - TrustAnchorInfo.pub_key field.
///
/// The TBSCertificate option within TrustAnchorChoice is not supported.
pub fn get_subject_public_key_info_from_trust_anchor(
    ta: &TrustAnchorChoice<Raw>,
) -> &SubjectPublicKeyInfoOwned {
    match ta {
        TrustAnchorChoice::Certificate(cert) => cert.tbs_certificate().subject_public_key_info(),
        TrustAnchorChoice::TaInfo(tai) => &tai.pub_key,
        TrustAnchorChoice::TbsCertificate(tbs) => tbs.subject_public_key_info(),
    }
}

/// get_certificate_from_trust_anchor returns the certificate from the TrustAnchorChoice. This will
/// be either the Certificate choice itself or the TrustAnchorInfo.cert_path.certificate field.
pub fn get_certificate_from_trust_anchor(
    ta: &TrustAnchorChoice<Raw>,
) -> Option<&CertificateInner<Raw>> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => return Some(cert),
        TrustAnchorChoice::TaInfo(tai) => {
            if let Some(cp) = &tai.cert_path {
                if let Some(cert) = &cp.certificate {
                    return Some(cert);
                }
            }
        }
        _ => return None,
    }
    None
}

/// `buffer_to_hex` takes a byte array and returns a string featuring upper case ASCII hex characters (without
/// commas, spaces, or brackets).
/// ```
/// use certval::buffer_to_hex;
/// let buf :[u8; 3] = [1,2,3];
/// let bufhex = buffer_to_hex(&buf);
/// assert_eq!(bufhex, "010203");
/// ```
pub fn buffer_to_hex(buffer: &[u8]) -> String {
    let hex = hex::encode_upper(buffer);
    let r = str::from_utf8(hex.as_slice());
    if let Ok(s) = r {
        s.to_string()
    } else {
        "".to_string()
    }
}

/// `hex_skid_from_ta` takes a trust anchor object and returns a string features upper case ASCII hex characters (without
/// commas, spaces, or brackets).
///
/// The value represents one of the following:
/// - the value of the SubjectKeyIdentifier (SKID) extension in a Certificate option
/// - the value of a SHA256 hash of the SubjectPublicKeyInfoOwned from a Certificate option that lacks a SKID extension
/// - the value of the key ID field in a TrustAnchorChoice option.
///
/// The TBSCertificate option within TrustAnchorChoice is not supported.
pub fn hex_skid_from_ta(ta: &PDVTrustAnchorChoice) -> String {
    match &ta.decoded_ta {
        TrustAnchorChoice::Certificate(_cert) => {
            let skid = ta.get_extension(&ID_CE_SUBJECT_KEY_IDENTIFIER);
            let hex_skid = if let Ok(Some(PDVExtension::SubjectKeyIdentifier(skid))) = skid {
                buffer_to_hex(skid.0.as_bytes())
            } else {
                let working_spki = get_subject_public_key_info_from_trust_anchor(&ta.decoded_ta);
                // A public key BIT STRING is byte-aligned; a nonzero unused-bits count is
                // malformed, so decline to compute a key identifier rather than panic or digest a
                // non-byte-aligned value (empty string is the no-identifier sentinel here).
                match working_spki.subject_public_key.as_bytes() {
                    Some(b) => buffer_to_hex(Sha256::digest(b).to_vec().as_slice()),
                    None => String::new(),
                }
            };
            hex_skid
        }
        TrustAnchorChoice::TaInfo(tai) => buffer_to_hex(tai.key_id.as_bytes()),
        _ => {
            //TODO add support for TbsCertificate?
            "".to_string()
        }
    }
}

/// `hex_skid_from_ta` takes a certificate object and returns a string features upper case ASCII hex characters (without
/// commas, spaces, or brackets) representing either the value of the SKID extension or key ID field.
pub fn hex_skid_from_cert(cert: &PDVCertificate) -> String {
    let skid = cert.get_extension(&ID_CE_SUBJECT_KEY_IDENTIFIER);
    let hex_skid = if let Ok(Some(PDVExtension::SubjectKeyIdentifier(skid))) = skid {
        buffer_to_hex(skid.0.as_bytes())
    } else {
        let working_spki = &cert.decoded().tbs_certificate().subject_public_key_info();
        // A public key BIT STRING is byte-aligned; a nonzero unused-bits count is malformed, so
        // decline to compute a key identifier rather than panic or digest a non-byte-aligned value
        // (empty string is the no-identifier sentinel here).
        match working_spki.subject_public_key.as_bytes() {
            Some(b) => buffer_to_hex(Sha256::digest(b).to_vec().as_slice()),
            None => String::new(),
        }
    };
    hex_skid
}

/// `get_filename_from_ta_metadata` returns the string from the `MD_LOCATOR` in the metadata or an
/// empty string.
pub fn get_filename_from_ta_metadata(cert: &PDVTrustAnchorChoice) -> String {
    cert.locator().map(str::to_string).unwrap_or_default()
}

/// `TrustAnchorKeyId` is a String value containing the ASCII hex representation of public key from
/// a trust anchor.
///
/// The value is read from one of the following:
/// * the subjectKeyIdentifier extension in a TrustAnchorChoice::Certificate structure,
/// * the keyID field in a TrustAnchorChoice::TrustAnchorInfo structure
/// * the SHA256 digest of the  SubjectPublicKeyInfoOwned read from TrustAnchorChoice::Certificate or
///   TrustAnchorChoice::TrustAnchorInfo
pub type TrustAnchorKeyId = String;

#[derive(Clone)]
/// Structure containing caller-provided a vector of buffers and a vector of parsed trust anchors
/// that reference items in the buffers vector. Two internal maps are used to correlate names and
/// key IDs to values in the caller-supplied map.
pub struct TaSource {
    /// list of TAs prepared by the caller
    tas: Vec<PDVTrustAnchorChoice>,

    /// Contains list of buffers referenced by tas field
    buffers: Vec<CertFile>,

    /// Maps TA SKIDs to keys in the tas map
    skid_map: BTreeMap<String, usize>,

    /// Maps TA Names to keys in the tas map
    name_map: BTreeMap<String, usize>,
}

impl Default for TaSource {
    fn default() -> Self {
        Self::new()
    }
}

impl CertVector for TaSource {
    fn contains(&self, cert: &CertFile) -> bool {
        self.buffers.contains(cert)
    }
    fn push(&mut self, cert: CertFile) {
        if !self.buffers.contains(&cert) {
            self.buffers.push(cert)
        }
    }
    fn len(&self) -> usize {
        self.buffers.len()
    }
    fn is_empty(&self) -> bool {
        self.buffers.is_empty()
    }
}

impl TaSource {
    /// instantiates a new TaSource
    pub fn new() -> TaSource {
        TaSource {
            tas: Vec::new(),
            buffers: Vec::new(),
            skid_map: BTreeMap::new(),
            name_map: BTreeMap::new(),
        }
    }

    /// Create new instance from CBOR
    pub fn new_from_cbor(cbor: &[u8]) -> Result<Self> {
        // todo - change serialization?
        let bap: BuffersAndPaths = match from_reader(cbor) {
            Ok(cbor_data) => cbor_data,
            Err(_e) => return Err(Error::ParseError),
        };

        Ok(Self {
            tas: Vec::new(),
            buffers: bap.buffers,
            skid_map: BTreeMap::new(),
            name_map: BTreeMap::new(),
        })
    }

    /// Creates a new TaSource instance from the [TLS_SERVER_ROOTS](https://docs.rs/webpki-roots/0.25.1/webpki_roots/constant.TLS_SERVER_ROOTS.html)
    /// variable in [webpki-roots crate](https://crates.io/crates/webpki-roots). This conversion is best effort.
    /// Any trust anchors that cannot be converted are logged and the process continues.
    #[cfg(feature = "webpki")]
    pub fn new_from_webpki() -> Result<Self> {
        let mut buffers = vec![];
        for (i, ta) in TLS_SERVER_ROOTS.iter().enumerate() {
            let pdv_ta = match PDVTrustAnchorChoice::try_from(ta) {
                Ok(t) => t,
                Err(e) => {
                    error!("Failed to convert WebPKI TrustAnchor #{i}: {e}");
                    continue;
                }
            };
            let cf = CertFile {
                filename: format!("WebPKI TrustAnchor #{i}"),
                bytes: pdv_ta.encoded_ta.clone(),
            };
            buffers.push(cf);
        }
        let mut tas = Self {
            tas: Vec::new(),
            buffers,
            skid_map: BTreeMap::new(),
            name_map: BTreeMap::new(),
        };
        tas.initialize()?;
        Ok(tas)
    }

    /// Processes any buffers passed to the instance, i.e., via new_from_cbor
    pub fn initialize(&mut self) -> Result<()> {
        populate_parsed_ta_vector(&self.buffers, &mut self.tas);
        self.index_tas();
        Ok(())
    }

    /// Returns vector of TAs
    pub fn get_tas(&self) -> Vec<CertFile> {
        self.buffers.clone()
    }

    /// index_tas builds internally used maps based on key identifiers and names. It must be called
    /// after populating the `tas` and `buffers` fields and before use.
    pub fn index_tas(&mut self) {
        for (i, ta) in self.tas.iter().enumerate() {
            let hex_skid = hex_skid_from_ta(ta);
            // a TA whose key identifier cannot be computed (e.g. malformed public key) is left out
            // of the SKID index rather than bucketed under an empty key
            if !hex_skid.is_empty() {
                self.skid_map.insert(hex_skid, i);
            }

            if let Ok(name) = get_trust_anchor_name(&ta.decoded_ta) {
                let name_str = name_to_string(name);
                self.name_map.insert(name_str, i);
            };
        }
    }

    /// Log certificate details to PkiEnvironment's logging mechanism at debug level.
    pub fn log_tas(&self) {
        for (i, ta) in self.tas.iter().enumerate() {
            let hex_skid = hex_skid_from_ta(ta);
            let ta_filename = get_filename_from_ta_metadata(ta);
            if let Ok(name) = get_trust_anchor_name(&ta.decoded_ta) {
                let sub = get_leaf_rdn(name);
                info!("Index: {i:3}; SKID: {hex_skid}; Subject: {sub}; Filename: {ta_filename}");
            } else {
                info!("Index: {i:3}; SKID: {hex_skid}; Subject: No Name; Filename: {ta_filename}");
            }
        }
    }
}

impl TrustAnchorSource for TaSource {
    fn get_trust_anchor_for_target(
        &self,
        target: &PDVCertificate,
    ) -> Result<&PDVTrustAnchorChoice> {
        let mut akid_hex = None;
        let mut name_vec = vec![target.decoded().tbs_certificate().issuer()];
        let akid_ext = target.get_extension(&ID_CE_AUTHORITY_KEY_IDENTIFIER);
        if let Ok(Some(PDVExtension::AuthorityKeyIdentifier(akid))) = akid_ext {
            if let Some(kid) = &akid.key_identifier {
                akid_hex.replace(buffer_to_hex(kid.as_bytes()));
            } else if let Some(names) = &akid.authority_cert_issuer {
                for n in names {
                    if let GeneralName::DirectoryName(dn) = n {
                        name_vec.push(dn);
                    }
                }
            }
        }

        if let Some(akid_hex) = akid_hex {
            match self.get_trust_anchor_by_hex_skid(&akid_hex) {
                Ok(s) => return Ok(s),
                Err(_e) => {
                    warn!("Failed to find trust anchor by key identifier {akid_hex}");
                }
            }
        }

        for n in name_vec {
            let r = self.get_trust_anchor_by_name(n);

            if r.is_ok() {
                info!("Found trust anchor by name: {n}");
                return r;
            }
        }
        Err(Error::Unrecognized)
    }

    fn get_trust_anchor_by_skid(&self, skid: &[u8]) -> Result<&PDVTrustAnchorChoice> {
        let hex_skid = buffer_to_hex(skid);
        self.get_trust_anchor_by_hex_skid(hex_skid.as_str())
    }

    fn get_trust_anchor_by_hex_skid(&self, hex_skid: &str) -> Result<&PDVTrustAnchorChoice> {
        self.skid_map
            .get(hex_skid)
            .ok_or(Error::Unrecognized)
            .map(|idx| &self.tas[*idx])
    }

    fn get_trust_anchor_by_name(&self, name: &Name) -> Result<&PDVTrustAnchorChoice> {
        let name_str = name_to_string(name);
        self.name_map
            .get(&name_str)
            .ok_or(Error::Unrecognized)
            .map(|idx| &self.tas[*idx])
    }

    fn get_trust_anchors(&self) -> Result<Vec<&PDVTrustAnchorChoice>> {
        let mut v = vec![];
        for ta in &self.tas {
            v.push(ta);
        }

        Ok(v)
    }

    /// is_cert_a_trust_anchor returns true if presented certificate object is a trust anchor
    fn is_cert_a_trust_anchor(&self, ta: &PDVCertificate) -> Result<()> {
        let hex_skid = hex_skid_from_cert(ta);
        let stored = self.get_trust_anchor_by_hex_skid(hex_skid.as_str())?;
        // A subjectKeyIdentifier match is not sufficient: the SKID extension value
        // is chosen by the certificate creator. Confirm the presented certificate carries
        // the same public key as the stored anchor before accepting it.
        let presented_spki = ta.decoded().tbs_certificate().subject_public_key_info();
        let stored_spki = get_subject_public_key_info_from_trust_anchor(&stored.decoded_ta);
        if presented_spki == stored_spki {
            Ok(())
        } else {
            Err(Error::Unrecognized)
        }
    }

    fn is_trust_anchor(&self, ta: &PDVTrustAnchorChoice) -> Result<()> {
        let hex_skid = hex_skid_from_ta(ta);
        let stored = self.get_trust_anchor_by_hex_skid(hex_skid.as_str())?;
        // A subjectKeyIdentifier match is not sufficient: the SKID extension value is
        // chosen by the certificate/anchor creator. Confirm the presented anchor carries the same
        // SPKI as the stored anchor before accepting it as a member of the trust store.
        let presented_spki = get_subject_public_key_info_from_trust_anchor(&ta.decoded_ta);
        let stored_spki = get_subject_public_key_info_from_trust_anchor(&stored.decoded_ta);
        if presented_spki == stored_spki {
            Ok(())
        } else {
            Err(Error::Unrecognized)
        }
    }

    fn get_encoded_trust_anchor(&self, skid: &[u8]) -> Result<Vec<u8>> {
        let hex_skid = buffer_to_hex(skid);
        self.get_trust_anchor_by_hex_skid(hex_skid.as_str())
            .map(|ta| ta.encoded_ta.to_owned().to_vec())
    }

    fn get_encoded_trust_anchors(&self) -> Result<Vec<Vec<u8>>> {
        let mut v = vec![];
        for ta in &self.tas {
            v.push(ta.encoded_ta.to_owned().to_vec());
        }
        Ok(v)
    }
}

/// `populate_parsed_ta_vector` takes a vector of buffers that contain binary DER-encoded TrustAnchorChoice
/// objects and populates a vector with parsed TrustAnchorChoice structures that reference the
/// buffers stored in the map.
///
/// Unlike the [`CertSource::certs`](../cert_source/struct.CertSource.html)
/// field, the [`TaSource::tas`](`TaSource`) field does not contain
/// optionally present parsed structures (because there is not need to maintain correlation for trust
/// anchors because indices are not used).
fn populate_parsed_ta_vector(
    ta_buffer_vec: &[CertFile],
    parsed_ta_vec: &mut Vec<PDVTrustAnchorChoice>,
) {
    for cf in ta_buffer_vec {
        match PDVTrustAnchorChoice::create(cf.bytes.as_slice(), &cf.filename) {
            Ok(ta) => parsed_ta_vec.push(ta),
            Err(e) => error!("Failed to parse TrustAnchorChoice: {:?}", e),
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn get_trust_anchor_test() {
    use crate::{ta_folder_to_vec, PkiEnvironment};
    use hex_literal::hex;
    let mut ta_store = TaSource::new();
    let ta_store_folder = format!(
        "{}{}",
        env!("CARGO_MANIFEST_DIR"),
        "/tests/examples/ta_store_with_bad"
    );

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    ta_folder_to_vec(
        &pe,
        &ta_store_folder,
        &mut ta_store,
        crate::TimeOfInterest::disabled(),
    )
    .unwrap();
    ta_store.initialize().unwrap();
    pe.add_trust_anchor_source(Box::new(ta_store.clone()));
    let bad = hex!("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
    let good = hex!("6C8A94A277B180721D817A16AAF2DCCE66EE45C0");
    assert!(pe.get_trust_anchor(&bad).is_err());
    assert!(pe.get_trust_anchor(&good).is_ok());
}

// The webpki-roots table converts in full, including name-constrained roots (whose NameConstraints
// value is stored with the outer SEQUENCE tag stripped, like subject and SPKI).
#[cfg(feature = "webpki")]
#[test]
fn new_from_webpki_converts_all_roots() {
    let src = TaSource::new_from_webpki().unwrap();
    assert_eq!(src.buffers.len(), webpki_roots::TLS_SERVER_ROOTS.len());
}

// Malformed CBOR must be reported as an error rather than panicking, matching
// CertSource::new_from_cbor. Here 0x00 is well-formed CBOR (the integer 0) but not a serialized
// BuffersAndPaths, so deserialization fails.
#[test]
fn new_from_cbor_rejects_malformed_input() {
    assert_eq!(
        TaSource::new_from_cbor(&[0x00]).err(),
        Some(Error::ParseError)
    );
}
