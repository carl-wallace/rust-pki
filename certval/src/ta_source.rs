//! Provides implementation of a manually populated in-memory TA store. The following snip, similar
//! to code in [`PITTv3`](../../pittv3/index.html), illustrates preparation and use of a [`TaSource`] object.
//!
//! ```
//! use certval::PkiEnvironment;
//! use certval::TaSource;
//!
//! // the default PkiEnvironment uses `oid_lookup` to look up friendly names for OIDs
//! let mut pe = PkiEnvironment::default();
//! // provide a logging callback that uses preferred logging mechanism. See `log_message` in
//! // `Pittv3` for log4rs-based sample.
//! // pe.add_logger(log_message);
//!
//! let mut ta_source = TaSource::default();
//! // populate the ta_source.buffers and ta_source.tas fields then call ta_source.index_tas(). See
//! // `populate_parsed_ta_vector` in `Pittv3` for file-system based sample.
//! ta_source.index_tas(&pe);
//!
//! // add ta_source to provide access to trust anchors
//! pe.add_trust_anchor_source(&ta_source);
//! ```
//!
//! [`TaSource`] instances are used when preparing a serialized file containing intermediate CA
//! certificates and partial paths (see [`find_all_partial_paths`](../cert_source/struct.CertSource.html#method.find_all_partial_paths)) and when building
//! certification paths (see [`get_paths_for_target`](../cert_source/struct.CertSource.html#method.get_paths_for_target)).
//!

use crate::cert_source::{get_leaf_rdn, CertFile};
use crate::error::*;
use crate::{
    pdv_certificate::PDVExtension, pdv_certificate::*, pdv_utilities::name_to_string,
    pki_environment_traits::TrustAnchorSource, ExtensionProcessing, PDVCertificate,
    PDVTrustAnchorChoice, PeLogLevels, PkiEnvironment, EXTS_OF_INTEREST,
};
use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::{vec, vec::Vec};
use core::cell::RefCell;
use core::str;
use der::{DecodeValue, Decoder};
use sha2::{Digest, Sha256};
use subtle_encoding::hex;
use x509::{
    trust_anchor_format::TrustAnchorChoice, GeneralName, Name, SubjectPublicKeyInfo,
    PKIX_CE_AUTHORITY_KEY_IDENTIFIER, PKIX_CE_SUBJECT_KEY_IDENTIFIER,
};

/// `get_subject_public_key_info_from_trust_anchor` returns a reference to the subject public key
/// containing in a TrustAnchorChoice object:
/// - Certificate.tbs_certificate.subject_public_key_info
/// - TrustAnchorInfo.pub_key field.
///
/// The TBSCertificate option within TrustAnchorChoice is not supported.
pub fn get_subject_public_key_info_from_trust_anchor<'a>(
    ta: &'a TrustAnchorChoice<'a>,
) -> &'a SubjectPublicKeyInfo<'a> {
    match ta {
        TrustAnchorChoice::Certificate(cert) => &cert.tbs_certificate.subject_public_key_info,
        TrustAnchorChoice::TaInfo(tai) => &tai.pub_key,
    }
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
/// - the value of a SHA256 hash of the SubjectPublicKeyInfo from a Certificate option that lacks a SKID extension
/// - the value of the key ID field in a TrustAnchorChoice option.
///
/// The TBSCertificate option within TrustAnchorChoice is not supported.
pub fn hex_skid_from_ta(ta: &PDVTrustAnchorChoice<'_>) -> String {
    match &ta.decoded_ta {
        TrustAnchorChoice::Certificate(_cert) => {
            let skid = ta.get_extension(&PKIX_CE_SUBJECT_KEY_IDENTIFIER);
            let hex_skid = if let Ok(Some(PDVExtension::SubjectKeyIdentifier(skid))) = skid {
                buffer_to_hex(skid.as_bytes())
            } else {
                let working_spki = get_subject_public_key_info_from_trust_anchor(&ta.decoded_ta);
                let digest = Sha256::digest(working_spki.subject_public_key).to_vec();
                buffer_to_hex(digest.as_slice())
            };
            hex_skid
        }
        TrustAnchorChoice::TaInfo(tai) => buffer_to_hex(tai.key_id.as_bytes()),
    }
}

/// `hex_skid_from_ta` takes a certificate object and returns a string features upper case ASCII hex characters (without
/// commas, spaces, or brackets) representing either the value of the SKID extension or key ID field.
pub fn hex_skid_from_cert(cert: &PDVCertificate<'_>) -> String {
    let skid = cert.get_extension(&PKIX_CE_SUBJECT_KEY_IDENTIFIER);
    let hex_skid = if let Ok(Some(PDVExtension::SubjectKeyIdentifier(skid))) = skid {
        buffer_to_hex(skid.as_bytes())
    } else {
        let working_spki = &cert.decoded_cert.tbs_certificate.subject_public_key_info;
        let digest = Sha256::digest(working_spki.subject_public_key).to_vec();
        buffer_to_hex(digest.as_slice())
    };
    hex_skid
}

/// `get_filename_from_ta_metadata` returns the string from the `MD_LOCATOR` in the metadata or an
/// empty string.
pub fn get_filename_from_ta_metadata(cert: &PDVTrustAnchorChoice<'_>) -> String {
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
/// * the SHA256 digest of the SubjectPublicKeyInfo read from TrustAnchorChoice::Certificate or
/// TrustAnchorChoice::TrustAnchorInfo
pub type TrustAnchorKeyId = String;

#[derive(Clone)]
/// Structure containing caller-provided a vector of buffers and a vector of parsed trust anchors
/// that reference items in the buffers vector. Two internal maps are used to correlate names and
/// key IDs to values in the caller-supplied map.
pub struct TaSource<'a> {
    /// list of TAs prepared by the caller
    pub tas: Vec<PDVTrustAnchorChoice<'a>>,

    /// Contains list of buffers referenced by tas field
    pub buffers: Vec<CertFile>,

    /// Maps TA SKIDs to keys in the tas map
    skid_map: RefCell<BTreeMap<TrustAnchorKeyId, usize>>,

    /// Maps TA Names to keys in the tas map
    name_map: RefCell<BTreeMap<String, usize>>,
}

impl<'a> Default for TaSource<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> TaSource<'a> {
    /// instantiates a new TaSource
    pub fn new() -> TaSource<'a> {
        TaSource {
            tas: Vec::new(),
            buffers: Vec::new(),
            skid_map: RefCell::new(BTreeMap::new()),
            name_map: RefCell::new(BTreeMap::new()),
        }
    }

    /// index_tas builds internally used maps based on key identifiers and names. It must be called
    /// after populating the `tas` and `buffers` fields and before use.
    pub fn index_tas(&self, pe: &PkiEnvironment<'_>) {
        for (i, ta) in self.tas.iter().enumerate() {
            let hex_skid = hex_skid_from_ta(ta);
            self.skid_map.borrow_mut().insert(hex_skid, i);

            if let Ok(name) = get_trust_anchor_name(&ta.decoded_ta) {
                let name_str = name_to_string(pe, name);
                self.name_map.borrow_mut().insert(name_str, i);
            };
        }
    }

    /// Log certificate details to PkiEnvironment's logging mechanism at debug level.
    pub fn log_tas(&self, pe: &PkiEnvironment<'_>) {
        for (i, ta) in self.tas.iter().enumerate() {
            let hex_skid = hex_skid_from_ta(ta);
            let ta_filename = get_filename_from_ta_metadata(ta);
            if let Ok(name) = get_trust_anchor_name(&ta.decoded_ta) {
                let sub = get_leaf_rdn(name);
                pe.log_message(
                    &PeLogLevels::PeInfo,
                    format!(
                        "Index: {:3}; SKID: {}; Subject: {}; Filename: {}",
                        i, hex_skid, sub, ta_filename
                    )
                    .as_str(),
                );
            } else {
                pe.log_message(
                    &PeLogLevels::PeInfo,
                    format!(
                        "Index: {:3}; SKID: {}; Subject: No Name; Filename: {}",
                        i, hex_skid, ta_filename
                    )
                    .as_str(),
                );
            }
        }
    }
}

impl TrustAnchorSource for TaSource<'_> {
    fn get_trust_anchor_for_target(
        &'_ self,
        pe: &PkiEnvironment<'_>,
        target: &'_ PDVCertificate<'_>,
    ) -> Result<&PDVTrustAnchorChoice<'_>> {
        let mut akid_hex = "".to_string();
        let mut name_vec = vec![&target.decoded_cert.tbs_certificate.issuer];
        let akid_ext = target.get_extension(&PKIX_CE_AUTHORITY_KEY_IDENTIFIER);
        if let Ok(Some(PDVExtension::AuthorityKeyIdentifier(akid))) = akid_ext {
            if let Some(kid) = akid.key_identifier {
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
            return self.get_trust_anchor_by_hex_skid(&akid_hex);
        } else {
            for n in name_vec {
                let r = self.get_trust_anchor_by_name(pe, n);
                if r.is_ok() {
                    return r;
                }
            }
        }
        Err(Error::Unrecognized)
    }

    fn get_trust_anchor_by_skid(&'_ self, skid: &[u8]) -> Result<&PDVTrustAnchorChoice<'_>> {
        let hex_skid = buffer_to_hex(skid);
        if self.skid_map.borrow().contains_key(hex_skid.as_str()) {
            return Ok(&self.tas[self.skid_map.borrow()[&hex_skid]]);
        }

        Err(Error::Unrecognized)
    }

    fn get_trust_anchor_by_hex_skid(&'_ self, hex_skid: &str) -> Result<&PDVTrustAnchorChoice<'_>> {
        if self.skid_map.borrow().contains_key(hex_skid) {
            return Ok(&self.tas[self.skid_map.borrow()[hex_skid]]);
        }

        Err(Error::Unrecognized)
    }

    fn get_trust_anchor_by_name(
        &'_ self,
        pe: &PkiEnvironment<'_>,
        name: &'_ Name<'_>,
    ) -> Result<&PDVTrustAnchorChoice<'_>> {
        let name_str = name_to_string(pe, name);
        if self.name_map.borrow().contains_key(&name_str) {
            return Ok(&self.tas[self.name_map.borrow()[&name_str]]);
        }

        Err(Error::Unrecognized)
    }

    fn get_trust_anchors(&'_ self) -> Result<Vec<&PDVTrustAnchorChoice<'_>>> {
        let mut v = vec![];
        for ta in &self.tas {
            v.push(ta);
        }

        Ok(v)
    }

    fn is_trust_anchor(&self, ta: &PDVTrustAnchorChoice<'_>) -> Result<bool> {
        let hex_skid = hex_skid_from_ta(ta);
        Ok(self.skid_map.borrow().contains_key(hex_skid.as_str()))
    }

    fn get_encoded_trust_anchor(&self, skid: &[u8]) -> Result<Vec<u8>> {
        let hex_skid = buffer_to_hex(skid);
        if self.skid_map.borrow().contains_key(hex_skid.as_str()) {
            return Ok(self.tas[self.skid_map.borrow()[&hex_skid]]
                .encoded_ta
                .to_owned()
                .to_vec());
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
pub fn populate_parsed_ta_vector<'a, 'reference>(
    ta_buffer_vec: &'a [CertFile],
    parsed_ta_vec: &'reference mut Vec<PDVTrustAnchorChoice<'a>>,
) {
    for cf in ta_buffer_vec {
        let mut decoder = Decoder::new(cf.bytes.as_slice()).unwrap();
        let header = decoder.peek_header().unwrap();
        if let Ok(tac) = TrustAnchorChoice::decode_value(&mut decoder, header.length) {
            let mut md = Asn1Metadata::new();
            md.insert(MD_LOCATOR, Asn1MetadataTypes::String(cf.filename.clone()));
            let mut ta = PDVTrustAnchorChoice {
                encoded_ta: cf.bytes.as_slice(),
                decoded_ta: tac,
                metadata: Some(md),
                parsed_extensions: ParsedExtensions::new(),
            };
            ta.parse_extensions(EXTS_OF_INTEREST);
            parsed_ta_vec.push(ta);
        }
    }
}
