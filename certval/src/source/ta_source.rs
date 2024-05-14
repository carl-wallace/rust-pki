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

#[cfg(feature = "std")]
use alloc::sync::Arc;
use ciborium::from_reader;
use core::cell::RefCell;
#[cfg(feature = "std")]
use std::sync::Mutex;

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
    pdv_certificate::*,
    pdv_extension::PDVExtension,
    pdv_extension::*,
    pdv_trust_anchor::get_trust_anchor_name,
    source::cert_source::CertFile,
    util::error::*,
    util::pdv_utilities::{get_leaf_rdn, name_to_string},
    BuffersAndPaths, CertVector, PDVCertificate, PDVTrustAnchorChoice, EXTS_OF_INTEREST,
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
        TrustAnchorChoice::Certificate(cert) => &cert.tbs_certificate.subject_public_key_info,
        TrustAnchorChoice::TaInfo(tai) => &tai.pub_key,
        TrustAnchorChoice::TbsCertificate(tbs) => &tbs.subject_public_key_info,
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
                //todo unwrap
                let digest =
                    Sha256::digest(working_spki.subject_public_key.as_bytes().unwrap()).to_vec();
                buffer_to_hex(digest.as_slice())
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
        let working_spki = &cert.decoded_cert.tbs_certificate.subject_public_key_info;
        //todo unwrap
        let digest = Sha256::digest(working_spki.subject_public_key.as_bytes().unwrap()).to_vec();
        buffer_to_hex(digest.as_slice())
    };
    hex_skid
}

/// `get_filename_from_ta_metadata` returns the string from the `MD_LOCATOR` in the metadata or an
/// empty string.
pub fn get_filename_from_ta_metadata(cert: &PDVTrustAnchorChoice) -> String {
    if let Some(md) = &cert.metadata {
        if let Asn1MetadataTypes::String(filename) = &md[MD_LOCATOR] {
            return filename.to_owned();
        }
    }
    "".to_string()
}

/// `TrustAnchorKeyId` is a String value containing the ASCII hex representation of public key from
/// a trust anchor.
///
/// The value is read from one of the following:
/// * the subjectKeyIdentifier extension in a TrustAnchorChoice::Certificate structure,
/// * the keyID field in a TrustAnchorChoice::TrustAnchorInfo structure
/// * the SHA256 digest of the  SubjectPublicKeyInfoOwned read from TrustAnchorChoice::Certificate or
/// TrustAnchorChoice::TrustAnchorInfo
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

    #[cfg(feature = "std")]
    /// Maps TA SKIDs to keys in the tas map
    skid_map: Arc<Mutex<RefCell<BTreeMap<String, usize>>>>,

    #[cfg(feature = "std")]
    /// Maps TA Names to keys in the tas map
    name_map: Arc<Mutex<RefCell<BTreeMap<String, usize>>>>,

    #[cfg(not(feature = "std"))]
    /// Maps TA SKIDs to keys in the tas map
    skid_map: RefCell<BTreeMap<String, usize>>,

    #[cfg(not(feature = "std"))]
    /// Maps TA Names to keys in the tas map
    name_map: RefCell<BTreeMap<String, usize>>,
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
            #[cfg(feature = "std")]
            skid_map: Arc::new(Mutex::new(RefCell::new(BTreeMap::new()))),
            #[cfg(not(feature = "std"))]
            skid_map: RefCell::new(BTreeMap::new()),
            #[cfg(feature = "std")]
            name_map: Arc::new(Mutex::new(RefCell::new(BTreeMap::new()))),
            #[cfg(not(feature = "std"))]
            name_map: RefCell::new(BTreeMap::new()),
        }
    }

    /// Create new instance from CBOR
    pub fn new_from_cbor(cbor: &[u8]) -> Result<Self> {
        // todo - change serialization?
        let bap: BuffersAndPaths = match from_reader(cbor) {
            Ok(cbor_data) => cbor_data,
            Err(e) => {
                panic!("Failed to parse embedded EE CBOR with: {}", e)
            }
        };

        Ok(Self {
            tas: Vec::new(),
            buffers: bap.buffers,
            #[cfg(feature = "std")]
            skid_map: Arc::new(Mutex::new(RefCell::new(BTreeMap::new()))),
            #[cfg(not(feature = "std"))]
            skid_map: RefCell::new(BTreeMap::new()),
            #[cfg(feature = "std")]
            name_map: Arc::new(Mutex::new(RefCell::new(BTreeMap::new()))),
            #[cfg(not(feature = "std"))]
            name_map: RefCell::new(BTreeMap::new()),
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
            #[cfg(feature = "std")]
            skid_map: Arc::new(Mutex::new(RefCell::new(BTreeMap::new()))),
            #[cfg(not(feature = "std"))]
            skid_map: RefCell::new(BTreeMap::new()),
            #[cfg(feature = "std")]
            name_map: Arc::new(Mutex::new(RefCell::new(BTreeMap::new()))),
            #[cfg(not(feature = "std"))]
            name_map: RefCell::new(BTreeMap::new()),
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
    pub fn index_tas(&self) {
        #[cfg(feature = "std")]
        let skid_map_guard = if let Ok(g) = self.skid_map.lock() {
            g
        } else {
            return;
        };
        #[cfg(feature = "std")]
        let mut skid_map = skid_map_guard.borrow_mut();

        #[cfg(not(feature = "std"))]
        let mut skid_map = self.skid_map.borrow_mut();

        #[cfg(feature = "std")]
        let name_map_guard = if let Ok(g) = self.name_map.lock() {
            g
        } else {
            return;
        };
        #[cfg(feature = "std")]
        let mut name_map = name_map_guard.borrow_mut();

        #[cfg(not(feature = "std"))]
        let mut name_map = self.name_map.borrow_mut();

        for (i, ta) in self.tas.iter().enumerate() {
            let hex_skid = hex_skid_from_ta(ta);
            skid_map.insert(hex_skid, i);

            if let Ok(name) = get_trust_anchor_name(&ta.decoded_ta) {
                let name_str = name_to_string(name);
                name_map.insert(name_str, i);
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
                info!(
                    "Index: {:3}; SKID: {}; Subject: {}; Filename: {}",
                    i, hex_skid, sub, ta_filename
                );
            } else {
                info!(
                    "Index: {:3}; SKID: {}; Subject: No Name; Filename: {}",
                    i, hex_skid, ta_filename
                );
            }
        }
    }
}

impl TrustAnchorSource for TaSource {
    fn get_trust_anchor_for_target(
        &'_ self,
        target: &'_ PDVCertificate,
    ) -> Result<&PDVTrustAnchorChoice> {
        let mut akid_hex = "".to_string();
        let mut name_vec = vec![&target.decoded_cert.tbs_certificate.issuer];
        let akid_ext = target.get_extension(&ID_CE_AUTHORITY_KEY_IDENTIFIER);
        if let Ok(Some(PDVExtension::AuthorityKeyIdentifier(akid))) = akid_ext {
            if let Some(kid) = &akid.key_identifier {
                akid_hex = buffer_to_hex(kid.as_bytes());
            } else if let Some(names) = &akid.authority_cert_issuer {
                for n in names {
                    if let GeneralName::DirectoryName(dn) = n {
                        name_vec.push(dn);
                    }
                }
            }
        }
        if !akid_hex.is_empty() {
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
                return r;
            }
        }
        Err(Error::Unrecognized)
    }

    fn get_trust_anchor_by_skid(&'_ self, skid: &[u8]) -> Result<&PDVTrustAnchorChoice> {
        #[cfg(feature = "std")]
        let skid_map_guard = if let Ok(g) = self.skid_map.lock() {
            g
        } else {
            return Err(Error::Unrecognized);
        };
        #[cfg(feature = "std")]
        let skid_map = skid_map_guard.borrow();

        #[cfg(not(feature = "std"))]
        let skid_map = &self.skid_map.borrow_mut();

        let hex_skid = buffer_to_hex(skid);
        if skid_map.contains_key(hex_skid.as_str()) {
            return Ok(&self.tas[skid_map[&hex_skid]]);
        }

        Err(Error::Unrecognized)
    }

    fn get_trust_anchor_by_hex_skid(&'_ self, hex_skid: &str) -> Result<&PDVTrustAnchorChoice> {
        #[cfg(feature = "std")]
        let skid_map_guard = if let Ok(g) = self.skid_map.lock() {
            g
        } else {
            return Err(Error::Unrecognized);
        };
        #[cfg(feature = "std")]
        let skid_map = skid_map_guard.borrow_mut();

        #[cfg(not(feature = "std"))]
        let skid_map = &self.skid_map.borrow_mut();
        if skid_map.contains_key(hex_skid) {
            return Ok(&self.tas[skid_map[hex_skid]]);
        }

        Err(Error::Unrecognized)
    }

    fn get_trust_anchor_by_name(&'_ self, name: &'_ Name) -> Result<&PDVTrustAnchorChoice> {
        #[cfg(feature = "std")]
        let name_map_guard = if let Ok(g) = self.name_map.lock() {
            g
        } else {
            return Err(Error::Unrecognized);
        };
        #[cfg(feature = "std")]
        let name_map = name_map_guard.borrow_mut();

        #[cfg(not(feature = "std"))]
        let name_map = &self.name_map.borrow_mut();
        let name_str = name_to_string(name);
        if name_map.contains_key(&name_str) {
            return Ok(&self.tas[name_map[&name_str]]);
        }

        Err(Error::Unrecognized)
    }

    fn get_trust_anchors(&'_ self) -> Result<Vec<&PDVTrustAnchorChoice>> {
        let mut v = vec![];
        for ta in &self.tas {
            v.push(ta);
        }

        Ok(v)
    }

    /// is_cert_a_trust_anchor returns true if presented certificate object is a trust anchor
    fn is_cert_a_trust_anchor(&self, ta: &PDVCertificate) -> Result<()> {
        #[cfg(feature = "std")]
        let skid_map_guard = if let Ok(g) = self.skid_map.lock() {
            g
        } else {
            return Err(Error::Unrecognized);
        };
        #[cfg(feature = "std")]
        let skid_map = skid_map_guard.borrow_mut();

        #[cfg(not(feature = "std"))]
        let skid_map = &self.skid_map.borrow_mut();
        let hex_skid = hex_skid_from_cert(ta);
        match skid_map.contains_key(hex_skid.as_str()) {
            true => Ok(()),
            false => Err(Error::NotFound),
        }
    }

    fn is_trust_anchor(&self, ta: &PDVTrustAnchorChoice) -> Result<()> {
        #[cfg(feature = "std")]
        let skid_map_guard = if let Ok(g) = self.skid_map.lock() {
            g
        } else {
            return Err(Error::Unrecognized);
        };
        #[cfg(feature = "std")]
        let skid_map = skid_map_guard.borrow_mut();

        #[cfg(not(feature = "std"))]
        let skid_map = &self.skid_map.borrow_mut();
        let hex_skid = hex_skid_from_ta(ta);
        match skid_map.contains_key(hex_skid.as_str()) {
            true => Ok(()),
            false => Err(Error::NotFound),
        }
    }

    fn get_encoded_trust_anchor(&self, skid: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "std")]
        let skid_map_guard = if let Ok(g) = self.skid_map.lock() {
            g
        } else {
            return Err(Error::Unrecognized);
        };
        #[cfg(feature = "std")]
        let skid_map = skid_map_guard.borrow_mut();

        #[cfg(not(feature = "std"))]
        let skid_map = &self.skid_map.borrow_mut();
        let hex_skid = buffer_to_hex(skid);
        if skid_map.contains_key(hex_skid.as_str()) {
            return Ok(self.tas[skid_map[&hex_skid]].encoded_ta.to_owned().to_vec());
        }

        Err(Error::Unrecognized)
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
        match PDVTrustAnchorChoice::try_from(cf.bytes.as_slice()) {
            Ok(mut ta) => {
                let mut md = Asn1Metadata::new();
                md.insert(
                    MD_LOCATOR.to_string(),
                    Asn1MetadataTypes::String(cf.filename.clone()),
                );
                ta.metadata = Some(md);
                if !parsed_ta_vec.contains(&ta) {
                    ta.parse_extensions(EXTS_OF_INTEREST);
                    parsed_ta_vec.push(ta);
                }
            }
            Err(e) => {
                error!("Failed to parse TrustAnchorChoice: {:?}", e);
            }
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
    ta_folder_to_vec(&pe, &ta_store_folder, &mut ta_store, 0).unwrap();
    ta_store.initialize().unwrap();
    pe.add_trust_anchor_source(Box::new(ta_store.clone()));
    let bad = hex!("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
    let good = hex!("6C8A94A277B180721D817A16AAF2DCCE66EE45C0");
    assert!(pe.get_trust_anchor(&bad).is_err());
    assert!(pe.get_trust_anchor(&good).is_ok());
}
