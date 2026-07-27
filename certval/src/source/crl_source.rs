//! Provides a place to store CRLs for retrieval at a later time

use alloc::collections::BTreeMap;
use alloc::{vec, vec::Vec};
use core::ops::{Deref, DerefMut};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock, RwLockWriteGuard};

use log::{debug, error, info};

use walkdir::WalkDir;

use sha2::{Digest, Sha256};

use const_oid::db::rfc5912::{
    ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_CRL_DISTRIBUTION_POINTS, ID_CE_ISSUING_DISTRIBUTION_POINT,
};
use der::{Decode, Encode};
use x509_cert::{certificate::Raw, crl::CertificateList, ext::pkix::IssuingDistributionPoint};

use crate::pdv_extension::ExtensionProcessing;
use crate::PathValidationStatus::RevocationStatusNotDetermined;
use crate::{buffer_to_hex, CheckRemoteResource, PathValidationStatus, RevocationStatusCache};
use crate::{
    get_file_as_byte_vec_pem, name_to_string, CrlSource, Error, PDVCertificate, PDVExtension,
    Result, SubjectNameAndKey, TimeOfInterest,
};

#[cfg(feature = "revocation")]
use crate::revocation::crl::{
    build_kept_serials, check_crl_validity, crl_covers_cert, get_crl_info, CrlInfo, CrlScope,
};

struct StatusAndTime {
    status: PathValidationStatus, // Valid or Revoked
    time: u64,
}

/// This is the inner structure in [`CrlSourceFolders`].
/// it is held under a read-write lock and various maps should be kept consistent with the content
/// of the `crl_info`.
struct CrlSourceFoldersInner {
    crl_info: Vec<CrlInfo>,
    issuer_map: IssuerMap,
    skid_map: SkidMap,
    dp_map: DpMap,
    /// Revoked serials of verified full/direct CRLs, keyed by CRL scope (not by crl_info index, so
    /// it is independent of the append-only crl_info vector). Populated only via keep_verified_crl,
    /// which the post-verification CRL processing path invokes; never populated by a cold index.
    kept: BTreeMap<CrlKey, KeptCrl>,
}

/// CrlSourceFolders provides a simple CRL store that supports storing CRL retrieved from remote
/// resources for subsequent use. When constructed with `keep_entries_in_memory` set (see
/// [`CrlSourceFolders::with_options`]) it also implements [`RevocationStatusCache`]: after a CRL is
/// verified and processed once (via `keep_verified_crl` from the CRL processing path), the revoked
/// serial numbers of full/direct CRLs are retained in memory so subsequent certificates under the
/// same scope are answered without re-parsing or re-verifying the CRL. Kept entries are bound to
/// the key that verified the CRL and answer only on behalf of that same issuing key, so issuers
/// sharing a subject name (e.g. across a key rollover) can never answer for one another. As a
/// RevocationStatusCache it answers only from those kept CRLs and abstains otherwise; register a
/// [`RevocationCache`] alongside it to cache OCSP determinations and anything not covered by a
/// kept CRL.
#[readonly::make]
pub struct CrlSourceFolders {
    /// Folder where CRLs are stored
    #[readonly]
    pub crls_folder: String,

    /// When true, retain verified full/direct CRLs' revoked serials in memory (see the type doc).
    keep_entries_in_memory: bool,

    inner: RwLock<CrlSourceFoldersInner>,
}

/// Provided in-memory revocation status cache
#[readonly::make]
pub struct RevocationCache {
    cache_map: RwLock<CacheMap>,
}

/// Provides file-based remote URI status information (relative to a file folder, typically the CRLs
/// folder used by a CrlSourceFolders instance)
#[readonly::make]
pub struct RemoteStatus {
    /// Folder where remote status information is stored, i.e., last_modified_map.json. This is
    /// typically the same as the crls_folder used by a CrlSourceFolders instance
    #[readonly]
    pub lmm_folder: String,

    blocklist: RwLock<Blocklist>,
    last_modified_map: RwLock<LastModifiedMap>,
}

type IssuerMap = BTreeMap<String, Vec<usize>>;
type SkidMap = BTreeMap<Vec<u8>, Vec<usize>>;
type DpMap = BTreeMap<Vec<u8>, Vec<usize>>;
// Keyed by (issuer name, hex SHA-256 of issuer SPKI, serial). The SPKI hash binds a cached
// determination to the issuing key so issuers sharing a subject name cannot answer for one another.
type CacheMap = BTreeMap<(String, String, String), StatusAndTime>;
type LastModifiedMap = BTreeMap<String, String>;
type Blocklist = Vec<String>;

/// Scope key for kept CRL entries. Issuer-qualified so two issuers that share an idp name cannot
/// collide; the optional idp distinguishes distribution-point partitions within a single issuer.
/// The verifier SPKI binds the entries to the key that verified the CRL's signature: population
/// keys on the SPKI that did verify, lookup keys on the SPKI that would verify for the current
/// path, so issuers sharing a subject name (e.g. across a key rollover) occupy separate slots and
/// can never answer for one another's certificates.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CrlKey {
    issuer: String,
    idp: Option<String>,
    verifier_spki: Vec<u8>,
}

/// A kept CRL: the sorted revoked serial numbers plus the validity window through which they may be
/// used (mirroring check_crl_validity, the time of interest must fall within thisUpdate/nextUpdate).
/// Serial numbers are INTEGER value octets (canonical for a DER-decoded serial number). The
/// per-validation revocation max age was applied by the processing path that verified the CRL and is
/// not re-applied here; a validation configured with a stricter max age that shares this store gets
/// answers vetted under the policy in force at keep time.
struct KeptCrl {
    this_update: u64,
    next_update: u64,
    serials: Vec<Vec<u8>>,
}

#[cfg(feature = "revocation")]
fn crl_key(info: &CrlInfo, verifier_spki: &[u8]) -> CrlKey {
    CrlKey {
        issuer: info.issuer_name.clone(),
        idp: info.idp_name.clone(),
        verifier_spki: verifier_spki.to_vec(),
    }
}

impl CrlSourceFolders {
    /// Instantiates a new CrlSourceFolders instance that uses the indicated folder for storage and
    /// retrieval of CRLs.
    pub fn new(crls_folder: &str) -> Self {
        Self::with_options(crls_folder, false)
    }

    /// Instantiates a CrlSourceFolders instance that, when `keep_entries_in_memory` is true, retains
    /// the revoked serial numbers of each verified full/direct CRL in memory so subsequent
    /// certificates under the same scope are answered via the [`RevocationStatusCache`]
    /// implementation without re-parsing or re-verifying the CRL. Memory is traded for speed; a
    /// value of false yields the original file-backed behavior.
    pub fn with_options(crls_folder: &str, keep_entries_in_memory: bool) -> Self {
        CrlSourceFolders {
            crls_folder: crls_folder.to_string(),
            keep_entries_in_memory,
            inner: RwLock::new(CrlSourceFoldersInner {
                crl_info: vec![],
                issuer_map: BTreeMap::new(),
                dp_map: BTreeMap::new(),
                skid_map: BTreeMap::new(),
                kept: BTreeMap::new(),
            }),
        }
    }

    /// index_crls populates the internal name and IDP maps used to retrieve CRLs.
    pub fn index_crls(&self, toi: TimeOfInterest) -> Result<usize> {
        let mut inner = self.inner.write().map_err(|_| Error::Unrecognized)?;
        let inner = inner.deref_mut();
        index_crls_internal(
            self.crls_folder.as_str(),
            &mut inner.crl_info,
            &mut inner.issuer_map,
            &mut inner.dp_map,
            &mut inner.skid_map,
            toi,
        )
    }

    fn read_all_crls(&self) -> Result<Vec<Vec<u8>>> {
        let crl_info_guard = self.inner.read().map_err(|_| Error::LockGuardError)?;
        let crl_info = crl_info_guard.crl_info.as_slice();
        let mut retval = vec![];
        for ci in crl_info.iter() {
            let Some(filename) = &ci.filename else {
                continue;
            };

            if let Ok(crl_buf) = get_file_as_byte_vec_pem(Path::new(filename.as_str())) {
                retval.push(crl_buf);
            }
        }
        Ok(retval)
    }
}

impl CrlSourceFoldersInner {
    // A method on the inner struct (not on CrlSourceFolders) because it reads only inner's data and
    // operates through the read guard the caller already holds.
    fn read_crl_at_index(&self, index: usize) -> Option<Vec<u8>> {
        let ci = &self.crl_info[index];
        if let Some(filename) = &ci.filename {
            if let Ok(crl_buf) = get_file_as_byte_vec_pem(Path::new(filename.as_str())) {
                return Some(crl_buf);
            }
        }
        None
    }
}

impl RevocationCache {
    /// Create new RevocationCache instance
    pub fn new() -> Self {
        RevocationCache {
            cache_map: RwLock::new(Default::default()),
        }
    }
}

impl Default for RevocationCache {
    /// Create a new default RevocationCache instance
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteStatus {
    /// Create new RemoteStatus instance
    pub fn new(folder: &str) -> Self {
        RemoteStatus {
            lmm_folder: folder.to_string(),
            blocklist: RwLock::new(vec![]),
            last_modified_map: RwLock::new(Default::default()),
        }
    }
    fn load_lmm(&self, last_modified_map: &mut RwLockWriteGuard<'_, LastModifiedMap>) {
        let p = Path::new(&self.lmm_folder);
        let lmmp = p.join("last_modified_map.json");
        if let Some(lmmp) = lmmp.as_path().to_str() {
            last_modified_map.clear();
            let lmm = crate::file_utils::read_last_modified_map(lmmp);
            for k in lmm {
                if let std::collections::btree_map::Entry::Vacant(e) = last_modified_map.entry(k.0)
                {
                    e.insert(k.1);
                }
            }
        }
    }
    // fn load_blocklist(&self, blocklist: &mut RefMut<'_, Blocklist>) {
    //     let p = Path::new(&self.crls_folder);
    //     let blp = p.join("blocklist.json");
    //     if let Some(blp) = blp.as_path().to_str() {
    //         let bl = crate::uri_utils::read_blocklist(blp);
    //         blocklist.clear();
    //         for i in bl {
    //             if !blocklist.contains(&i) {
    //                 blocklist.push(i);
    //             }
    //         }
    //     }
    // }
}

impl CheckRemoteResource for RemoteStatus {
    /// get_last_modified takes a URI and returns stored last modified value or None.
    fn get_last_modified(&self, uri: &str) -> Option<String> {
        // Fast path: once the map has been loaded a shared read lock suffices.
        {
            let last_modified_map = self.last_modified_map.read().ok()?;
            if !last_modified_map.is_empty() {
                return last_modified_map.get(uri).cloned();
            }
        }
        // The map has not been loaded yet; take the write lock to populate it, then read.
        let mut last_modified_map = self.last_modified_map.write().ok()?;
        if last_modified_map.is_empty() {
            self.load_lmm(&mut last_modified_map);
        }
        last_modified_map.get(uri).cloned()
    }
    /// Save last modified value, if desired
    fn set_last_modified(&self, uri: &str, last_modified: &str) {
        // Update the in-memory map and serialize it (both in-memory operations) under the write
        // lock, but release the lock before writing to disk so the slow filesystem I/O does not
        // block other readers and writers.
        let json_lmm = {
            let mut last_modified_map = if let Ok(l) = self.last_modified_map.write() {
                l
            } else {
                return;
            };
            if last_modified_map.is_empty() {
                self.load_lmm(&mut last_modified_map);
            }
            if let std::collections::btree_map::Entry::Vacant(e) =
                last_modified_map.entry(uri.to_string())
            {
                e.insert(last_modified.to_string());
                serde_json::to_string(&last_modified_map.deref()).ok()
            } else {
                None
            }
        };

        if let Some(json_lmm) = json_lmm {
            let p = Path::new(&self.lmm_folder);
            let lmmp = p.join("last_modified_map.json");
            if fs::write(lmmp, json_lmm).is_err() {
                error!("Unable to write last modified map file",);
            }
        }
    }
    /// Gets blocklist takes a URI and returns true if it is on blocklist and false otherwise
    fn check_blocklist(&self, uri: &str) -> bool {
        let blocklist = if let Ok(blocklist) = self.blocklist.read() {
            blocklist
        } else {
            return false;
        };
        // if blocklist.is_empty() {
        //     self.load_blocklist(&mut blocklist);
        // }
        blocklist.contains(&uri.to_string())
    }
    /// Save blocklist, if desired
    fn add_to_blocklist(&self, uri: &str) {
        let mut blocklist = if let Ok(blocklist) = self.blocklist.write() {
            blocklist
        } else {
            return;
        };
        // if blocklist.is_empty() {
        //     self.load_blocklist(&mut blocklist);
        // }
        if !blocklist.contains(&uri.to_string()) {
            blocklist.push(uri.to_string());

            // TODO persist or in-memory? if persist, add time of addition
            // let json_blocklist = serde_json::to_string(&blocklist.deref());
            // let p = Path::new(&self.crls_folder);
            // let blp = p.join("blocklist.json");
            // if let Ok(json_blocklist) = &json_blocklist {
            //     if fs::write(&blp, json_blocklist).is_err() {
            //         log_message(&PeLogLevels::PeError, "Unable to write blocklist file");
            //     }
            // }
        }
    }
}

impl CrlSource for CrlSourceFolders {
    fn get_all_crls(&self) -> Result<Vec<Vec<u8>>> {
        self.read_all_crls()
    }

    fn add_crl(&self, crl_buf: &[u8], crl: &CertificateList<Raw>, uri: &str) -> Result<()> {
        let mut cur_crl_info = get_crl_info(crl)?;
        let digest = Sha256::digest(uri).to_vec();
        let hex = buffer_to_hex(digest.as_slice());
        if !hex.is_empty() {
            let filename = format!("{hex}.crl");
            let path = Path::new(self.crls_folder.as_str()).join(filename);
            if let Err(_e) = std::fs::write(&path, crl_buf) {
                return Err(Error::Unrecognized);
            }
            cur_crl_info.filename = path.to_str().map(|s| s.to_string());
            cur_crl_info.uri = Some(uri.to_string());

            let mut inner = self.inner.write().map_err(|_| Error::Unrecognized)?;
            let inner = inner.deref_mut();
            add_crl_info(
                &mut inner.crl_info,
                &mut inner.issuer_map,
                &mut inner.dp_map,
                &mut inner.skid_map,
                crl,
                cur_crl_info,
            );
        }
        Ok(())
    }

    fn get_crls(&self, cert: &PDVCertificate) -> Result<Vec<Vec<u8>>> {
        let inner = self.inner.read().map_err(|_| Error::Unrecognized)?;

        if let Some(dps) = get_dps_from_cert(cert) {
            for dp in dps {
                if inner.dp_map.contains_key(&dp) {
                    let indices = &inner.dp_map[&dp];
                    let mut retval = vec![];
                    for index in indices {
                        if let Some(crl_buf) = inner.read_crl_at_index(*index) {
                            retval.push(crl_buf);
                        }
                    }
                    return Ok(retval);
                }
            }
        }

        if let Ok(Some(PDVExtension::AuthorityKeyIdentifier(akid))) =
            cert.get_extension(&ID_CE_AUTHORITY_KEY_IDENTIFIER)
        {
            if let Some(kid) = &akid.key_identifier {
                if inner.skid_map.contains_key(kid.as_bytes()) {
                    let indices = &inner.skid_map[&kid.as_bytes().to_vec()];
                    let mut retval = vec![];
                    for index in indices {
                        if let Some(crl_buf) = inner.read_crl_at_index(*index) {
                            retval.push(crl_buf);
                        }
                    }
                    return Ok(retval);
                }
            }
        }

        let issuer_name = name_to_string(cert.decoded().tbs_certificate().issuer());
        if inner.issuer_map.contains_key(&issuer_name) {
            let indices = &inner.issuer_map[&issuer_name];
            let mut retval = vec![];
            for index in indices {
                if let Some(crl_buf) = inner.read_crl_at_index(*index) {
                    retval.push(crl_buf);
                }
            }
            return Ok(retval);
        }
        Err(Error::NotFound)
    }

    #[cfg_attr(not(feature = "revocation"), allow(unused_variables))]
    fn keep_verified_crl(
        &self,
        _crl_buf: &[u8],
        crl: &CertificateList<Raw>,
        verifier: &dyn SubjectNameAndKey,
    ) -> Result<()> {
        #[cfg(feature = "revocation")]
        {
            if !self.keep_entries_in_memory {
                return Ok(());
            }
            let info = match get_crl_info(crl) {
                Ok(info) => info,
                Err(_e) => return Ok(()),
            };
            // A CRL with no nextUpdate cannot be freshness-bounded, mirroring add_status which only
            // caches determinations that carry a nextUpdate.
            let next_update = match info.next_update {
                Some(nu) => nu,
                None => return Ok(()),
            };
            // The kept entries are bound to the key that verified the CRL; with no encodable SPKI
            // there is nothing sound to bind to, so decline to keep.
            let verifier_spki = match verifier.spki().to_der() {
                Ok(spki) => spki,
                Err(_e) => return Ok(()),
            };
            let serials = match build_kept_serials(crl, &info) {
                Some(serials) => serials,
                None => return Ok(()),
            };
            let key = crl_key(&info, &verifier_spki);
            let mut inner = self.inner.write().map_err(|_| Error::Unrecognized)?;
            // Latest-verified wins so a reissued CRL replaces stale serials for the same scope.
            // Replacement only ever compares CRLs verified by the same key, since the key is part
            // of the slot identity.
            let fresher = inner
                .kept
                .get(&key)
                .is_none_or(|k| next_update >= k.next_update);
            if fresher {
                inner.kept.insert(
                    key,
                    KeptCrl {
                        this_update: info.this_update,
                        next_update,
                        serials,
                    },
                );
            }
        }
        Ok(())
    }
}

#[cfg(feature = "revocation")]
impl CrlSourceFoldersInner {
    /// Candidate crl_info indices for a certificate, mirroring the distribution-point / SKID /
    /// issuer-name lookup precedence used by get_crls. Used by the RevocationStatusCache path.
    fn matching_indices(&self, cert: &PDVCertificate) -> Vec<usize> {
        if let Some(dps) = get_dps_from_cert(cert) {
            for dp in dps {
                if let Some(indices) = self.dp_map.get(&dp) {
                    return indices.clone();
                }
            }
        }
        if let Ok(Some(PDVExtension::AuthorityKeyIdentifier(akid))) =
            cert.get_extension(&ID_CE_AUTHORITY_KEY_IDENTIFIER)
        {
            if let Some(kid) = &akid.key_identifier {
                if let Some(indices) = self.skid_map.get(kid.as_bytes()) {
                    return indices.clone();
                }
            }
        }
        let issuer_name = name_to_string(cert.decoded().tbs_certificate().issuer());
        self.issuer_map
            .get(&issuer_name)
            .cloned()
            .unwrap_or_default()
    }
}

fn get_dps_from_cert(cert: &PDVCertificate) -> Option<Vec<Vec<u8>>> {
    match cert.get_extension(&ID_CE_CRL_DISTRIBUTION_POINTS) {
        Ok(Some(PDVExtension::CrlDistributionPoints(crl_dps))) => {
            let mut retval = vec![];
            for crl_dp in &crl_dps.0 {
                if let Some(dp) = &crl_dp.distribution_point {
                    if let Ok(enc_dp) = dp.to_der() {
                        retval.push(enc_dp);
                    }
                }
            }
            Some(retval)
        }
        _ => None,
    }
}

fn get_dp_from_crl(crl: &CertificateList<Raw>) -> Option<Vec<u8>> {
    if let Some(exts) = &crl.tbs_cert_list.crl_extensions {
        for ext in exts {
            if ext.extn_id == ID_CE_ISSUING_DISTRIBUTION_POINT {
                if let Ok(idp) = IssuingDistributionPoint::from_der(ext.extn_value.as_bytes()) {
                    if let Some(dp) = idp.distribution_point {
                        if let Ok(enc_dp) = dp.to_der() {
                            return Some(enc_dp);
                        }
                    }
                }
            }
        }
    }
    None
}

fn add_crl_info(
    crl_info: &mut Vec<CrlInfo>,
    issuer_map: &mut BTreeMap<String, Vec<usize>>,
    idp_map: &mut BTreeMap<Vec<u8>, Vec<usize>>,
    skid_map: &mut BTreeMap<Vec<u8>, Vec<usize>>,
    crl: &CertificateList<Raw>,
    cur_crl_info: CrlInfo,
) {
    if !crl_info.contains(&cur_crl_info) {
        let mut is_dp = false;

        let ti = cur_crl_info.type_info;
        crl_info.push(cur_crl_info.clone());
        let index = crl_info.len() - 1;

        // delta CRLs are not supported (no base+delta merge); leave them unindexed so a
        // lone delta is never served for processing as if it were a complete CRL
        if CrlScope::Delta == ti.scope || CrlScope::DeltaDp == ti.scope {
            return;
        }

        if let Some(dp) = get_dp_from_crl(crl) {
            // assuming that partitions are managed such that key rollover does not occur
            //  within a partition
            if idp_map.contains_key(&dp) {
                let mut v = idp_map[&dp].clone();
                v.push(index);
                idp_map.insert(dp, v);
            } else {
                idp_map.insert(dp, vec![index]);
            }
            is_dp = true;
        } else if let Some(akid) = &cur_crl_info.skid {
            if skid_map.contains_key(akid) {
                let mut v = skid_map[akid].clone();
                v.push(index);
                skid_map.insert(akid.clone(), v);
            } else {
                skid_map.insert(akid.clone(), vec![index]);
            }
        }

        if !is_dp && ti.scope == CrlScope::Complete {
            let issuer_name = name_to_string(&crl.tbs_cert_list.issuer);
            if issuer_map.contains_key(&issuer_name) {
                let mut v = issuer_map[&issuer_name].clone();
                v.push(index);
                issuer_map.insert(issuer_name, v);
            } else {
                issuer_map.insert(issuer_name, vec![index]);
            }
        }
    }
}

fn index_crls_internal(
    crls_folder: &str,
    crl_info: &mut Vec<CrlInfo>,
    issuer_map: &mut BTreeMap<String, Vec<usize>>,
    idp_map: &mut BTreeMap<Vec<u8>, Vec<usize>>,
    skid_map: &mut BTreeMap<Vec<u8>, Vec<usize>>,
    toi: TimeOfInterest,
) -> Result<usize> {
    let initial_count = crl_info.len();
    for entry in WalkDir::new(crls_folder) {
        match entry {
            Ok(e) => {
                let path = e.path();
                if e.file_type().is_dir() {
                    match path.to_str() {
                        Some(s) => {
                            if s != crls_folder {
                                debug!("Recursing {}", e.path().display());
                                let r = index_crls_internal(
                                    s, crl_info, issuer_map, idp_map, skid_map, toi,
                                );
                                if r.is_err() {
                                    continue;
                                }
                            }
                        }
                        None => {
                            continue;
                        }
                    }
                } else {
                    let file_exts = ["crl"];
                    if let Some(ext) = e.path().extension().and_then(OsStr::to_str) {
                        if !file_exts.contains(&ext) {
                            continue;
                        }
                    } else {
                        continue;
                    }

                    let crl_buf = get_file_as_byte_vec_pem(e.path())?;

                    let crl = match CertificateList::from_der(crl_buf.as_slice()) {
                        Ok(crl) => crl,
                        Err(e) => {
                            error!("Failed to parse CRL with {e}");
                            continue;
                        }
                    };
                    match get_crl_info(&crl) {
                        Ok(mut cur_crl_info) => {
                            if let Some(filename) = e.path().to_str() {
                                cur_crl_info.filename = Some(filename.to_string());
                            }

                            // Store indexing is lenient about an absent nextUpdate (Duration::MAX):
                            // the fail-closed staleness decision belongs to path validation, which
                            // reads the operator's PS_REVOCATION_MAX_AGE. Deleting a nextUpdate-less
                            // CRL here would discard one that a validation configured with a tolerance
                            // could still use. A CRL with an expired nextUpdate is still pruned below.
                            if check_crl_validity(toi, core::time::Duration::MAX, &crl).is_ok() {
                                add_crl_info(
                                    crl_info,
                                    issuer_map,
                                    idp_map,
                                    skid_map,
                                    &crl,
                                    cur_crl_info,
                                );
                            } else if fs::remove_file(e.path()).is_err() {
                                if let Some(filename) = e.path().to_str() {
                                    error!("Failed to delete stale CRL at {filename}");
                                }
                            }
                        }
                        Err(_) => {
                            continue;
                        }
                    }
                }
            }
            _ => {
                error!("Failed to unwrap directory entry while indexing CRLs");
                continue;
            }
        }
    }
    Ok(crl_info.len() - initial_count)
}

/// Hex SHA-256 of the issuer's DER-encoded SPKI, used to key cached determinations to the issuing
/// key. None when the SPKI cannot be encoded, in which case there is nothing sound to key on.
fn issuer_spki_hash_hex(issuer: &dyn SubjectNameAndKey) -> Option<String> {
    let spki = issuer.spki().to_der().ok()?;
    Some(buffer_to_hex(Sha256::digest(&spki).to_vec().as_slice()))
}

impl RevocationStatusCache for RevocationCache {
    fn get_status(
        &self,
        cert: &PDVCertificate,
        issuer: &dyn SubjectNameAndKey,
        time_of_interest: TimeOfInterest,
    ) -> PathValidationStatus {
        let name = name_to_string(cert.decoded().tbs_certificate().issuer());
        let issuer_key = match issuer_spki_hash_hex(issuer) {
            Some(hash) => hash,
            None => return RevocationStatusNotDetermined,
        };
        let serial = buffer_to_hex(cert.decoded().tbs_certificate().serial_number().as_bytes());

        let cache_map = if let Ok(c) = self.cache_map.read() {
            c
        } else {
            return RevocationStatusNotDetermined;
        };
        let key = (name, issuer_key, serial);
        if cache_map.contains_key(&key) {
            let status_and_time = &cache_map[&key];
            if status_and_time.time > time_of_interest.as_unix_secs() {
                info!("Serviced revocation status check for certificate with serial number {} issued by {} from cache", key.2, key.0);
                return status_and_time.status;
            }
        }

        RevocationStatusNotDetermined
    }
    fn add_status(
        &self,
        cert: &PDVCertificate,
        issuer: &dyn SubjectNameAndKey,
        next_update: u64,
        status: PathValidationStatus,
    ) {
        if status != PathValidationStatus::Valid
            && status != PathValidationStatus::CertificateRevoked
        {
            return;
        }

        let name = name_to_string(cert.decoded().tbs_certificate().issuer());
        let issuer_key = match issuer_spki_hash_hex(issuer) {
            Some(hash) => hash,
            None => return,
        };
        let serial = buffer_to_hex(cert.decoded().tbs_certificate().serial_number().as_bytes());
        let key = (name, issuer_key, serial);

        let mut cache_map = if let Ok(g) = self.cache_map.write() {
            g
        } else {
            return;
        };
        let status_and_time = StatusAndTime {
            status,
            time: next_update,
        };
        if cache_map.contains_key(&key) {
            let old_status_and_time = &cache_map[&key];
            if old_status_and_time.time < next_update {
                debug!("Updating entry in revocation status check for certificate with serial number {} issued by {} in cache", key.2, key.0);
                cache_map.insert(key, status_and_time);
            }
        } else {
            debug!("Adding entry to revocation status check for certificate with serial number {} issued by {} to cache", key.2, key.0);
            cache_map.insert(key, status_and_time);
        }
    }
}

impl RevocationStatusCache for CrlSourceFolders {
    /// Answers only from the in-memory kept CRLs (populated via keep_verified_crl); abstains with
    /// RevocationStatusNotDetermined otherwise. A per-certificate memo registered alongside (e.g. a
    /// [`RevocationCache`]) handles OCSP determinations and anything not covered by a kept CRL --
    /// PkiEnvironment::get_status consults each registered cache in turn and returns the first
    /// determination.
    #[cfg_attr(not(feature = "revocation"), allow(unused_variables))]
    fn get_status(
        &self,
        cert: &PDVCertificate,
        issuer: &dyn SubjectNameAndKey,
        time_of_interest: TimeOfInterest,
    ) -> PathValidationStatus {
        #[cfg(feature = "revocation")]
        {
            // The kept slot is keyed by the SPKI that verified the CRL; look it up with the SPKI
            // that would verify a CRL for this certificate (its issuer on the current path). A CRL
            // verified by a different key than the one that issued the certificate can therefore
            // never answer for it, no matter how its names line up — the miss falls through to full
            // processing, which settles matters with a signature check.
            let verifier_spki = match issuer.spki().to_der() {
                Ok(spki) => spki,
                Err(_e) => return RevocationStatusNotDetermined,
            };
            if let Ok(inner) = self.inner.read() {
                let serial = cert
                    .decoded()
                    .tbs_certificate()
                    .serial_number()
                    .as_bytes()
                    .to_vec();
                for idx in inner.matching_indices(cert) {
                    let info = match inner.crl_info.get(idx) {
                        Some(info) => info,
                        None => continue,
                    };
                    let kept = match inner.kept.get(&crl_key(info, &verifier_spki)) {
                        Some(kept) => kept,
                        None => continue,
                    };
                    // Freshness mirrors check_crl_validity in both directions: the time of interest
                    // must fall within the kept CRL's thisUpdate/nextUpdate window.
                    let toi_secs = time_of_interest.as_unix_secs();
                    if kept.this_update > toi_secs || kept.next_update <= toi_secs {
                        continue;
                    }
                    if crl_covers_cert(cert, info).is_err() {
                        continue;
                    }
                    return if kept.serials.binary_search(&serial).is_ok() {
                        PathValidationStatus::CertificateRevoked
                    } else {
                        PathValidationStatus::Valid
                    };
                }
            }
        }
        RevocationStatusNotDetermined
    }

    // Nothing to record: this store answers only from kept CRLs. Determinations are cached by a
    // separately-registered RevocationStatusCache (e.g. RevocationCache).
    fn add_status(
        &self,
        _cert: &PDVCertificate,
        _issuer: &dyn SubjectNameAndKey,
        _next_update: u64,
        _status: PathValidationStatus,
    ) {
    }
}

// A single CrlSourceFolders often needs to be registered in two roles at once: as a CrlSource
// (which populates the in-memory kept CRLs via keep_verified_crl) and as a RevocationStatusCache
// (which answers from them). Because the kept state is mutated at runtime, both roles must observe
// the same instance, so consumers share one via Arc and register a clone in each role. These
// delegating implementations let `Arc<CrlSourceFolders>` satisfy both traits.
impl CrlSource for Arc<CrlSourceFolders> {
    fn get_all_crls(&self) -> Result<Vec<Vec<u8>>> {
        (**self).get_all_crls()
    }
    fn get_crls(&self, cert: &PDVCertificate) -> Result<Vec<Vec<u8>>> {
        (**self).get_crls(cert)
    }
    fn add_crl(&self, crl_buf: &[u8], crl: &CertificateList<Raw>, uri: &str) -> Result<()> {
        (**self).add_crl(crl_buf, crl, uri)
    }
    fn keep_verified_crl(
        &self,
        crl_buf: &[u8],
        crl: &CertificateList<Raw>,
        verifier: &dyn SubjectNameAndKey,
    ) -> Result<()> {
        (**self).keep_verified_crl(crl_buf, crl, verifier)
    }
}

impl RevocationStatusCache for Arc<CrlSourceFolders> {
    fn get_status(
        &self,
        cert: &PDVCertificate,
        issuer: &dyn SubjectNameAndKey,
        time_of_interest: TimeOfInterest,
    ) -> PathValidationStatus {
        (**self).get_status(cert, issuer, time_of_interest)
    }
    fn add_status(
        &self,
        cert: &PDVCertificate,
        issuer: &dyn SubjectNameAndKey,
        next_update: u64,
        status: PathValidationStatus,
    ) {
        (**self).add_status(cert, issuer, next_update, status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CheckRemoteResource;

    // A stored last-modified value must be readable both in memory and, after the write released the
    // lock and persisted the map, from a fresh instance over the same folder.
    #[test]
    fn last_modified_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().to_str().unwrap();
        let uri = "http://example.test/crl";
        let value = "Mon, 01 Jan 2035 00:00:00 GMT";

        let rs = RemoteStatus::new(folder);
        rs.set_last_modified(uri, value);
        assert_eq!(rs.get_last_modified(uri), Some(value.to_string()));

        // A fresh instance loads the value written to disk, confirming the out-of-lock write persisted.
        let rs2 = RemoteStatus::new(folder);
        assert_eq!(rs2.get_last_modified(uri), Some(value.to_string()));
        assert_eq!(rs2.get_last_modified("http://example.test/other"), None);
    }
}
