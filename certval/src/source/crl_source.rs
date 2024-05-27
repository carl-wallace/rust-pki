//! Provides a place to store CRLs for retrieval at a later time

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::{vec, vec::Vec};
use core::cell::RefCell;
use core::cell::RefMut;
use core::ops::Deref;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

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
    Result,
};

#[cfg(feature = "revocation")]
use crate::revocation::crl::{check_crl_validity, get_crl_info, CrlInfo, CrlScope};

struct StatusAndTime {
    status: PathValidationStatus, // Valid or Revoked
    time: u64,
}

//TODO hygiene
/// CrlSourceFolders provides a simple CRL store that supports storing CRL retrieved from remote
/// resources for subsequent use.
#[derive(Clone)]
#[readonly::make]
pub struct CrlSourceFolders {
    /// Folder where CRLs are stored
    #[readonly]
    pub crls_folder: String,

    crl_info: Vec<CrlInfo>,
    issuer_map: IssuerMap,
    skid_map: SkidMap,
    dp_map: DpMap,
    // cache_map: Arc<Mutex<RefCell<CacheMap>>>,
    // blocklist: Arc<Mutex<RefCell<Blocklist>>>,
    // last_modified_map: Arc<Mutex<RefCell<LastModifiedMap>>>,
}

/// Provided in-memory revocation status cache
#[derive(Clone)]
#[readonly::make]
pub struct RevocationCache {
    cache_map: Arc<Mutex<RefCell<CacheMap>>>,
}

/// Provides file-based remote URI status information (relative to a file folder, typically the CRLs
/// folder used by a CrlSourceFolders instance)
#[derive(Clone)]
#[readonly::make]
pub struct RemoteStatus {
    /// Folder where remote status information is stored, i.e., last_modified_map.json. This is
    /// typically the same as the crls_folder used by a CrlSourceFolders instance
    #[readonly]
    pub lmm_folder: String,

    blocklist: Arc<Mutex<RefCell<Blocklist>>>,
    last_modified_map: Arc<Mutex<RefCell<LastModifiedMap>>>,
}

type IssuerMap = BTreeMap<String, Vec<usize>>;
type SkidMap = BTreeMap<Vec<u8>, Vec<usize>>;
type DpMap = BTreeMap<Vec<u8>, Vec<usize>>;
type CacheMap = BTreeMap<(String, String), StatusAndTime>;
type LastModifiedMap = BTreeMap<String, String>;
type Blocklist = Vec<String>;

impl CrlSourceFolders {
    /// Instantiates a new CrlSourceFolders instance that uses the indicated folder for storage and
    /// retrieval of CRLs.
    pub fn new(crls_folder: &str) -> Self {
        CrlSourceFolders {
            crls_folder: crls_folder.to_string(),
            crl_info: vec![],
            issuer_map: BTreeMap::new(),
            dp_map: BTreeMap::new(),
            skid_map: BTreeMap::new(),
        }
    }

    /// index_crls populates the internal name and IDP maps used to retrieve CRLs.
    pub fn index_crls(&mut self, toi: u64) -> Result<usize> {
        index_crls_internal(
            self.crls_folder.as_str(),
            &mut self.crl_info,
            &mut self.issuer_map,
            &mut self.dp_map,
            &mut self.skid_map,
            toi,
        )
    }

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
            cache_map: Arc::new(Mutex::new(RefCell::new(Default::default()))),
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
            blocklist: Arc::new(Mutex::new(RefCell::new(vec![]))),
            last_modified_map: Arc::new(Mutex::new(RefCell::new(Default::default()))),
        }
    }
    fn load_lmm(&self, last_modified_map: &mut RefMut<'_, LastModifiedMap>) {
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
        let last_modified_map_guard = if let Ok(g) = self.last_modified_map.lock() {
            g
        } else {
            return None;
        };
        let mut last_modified_map = last_modified_map_guard.deref().borrow_mut();
        if last_modified_map.is_empty() {
            self.load_lmm(&mut last_modified_map);
        }
        if last_modified_map.contains_key(uri) {
            Some(last_modified_map[uri].clone())
        } else {
            None
        }
    }
    /// Save last modified value, if desired
    fn set_last_modified(&self, uri: &str, last_modified: &str) {
        let last_modified_map_guard = if let Ok(g) = self.last_modified_map.lock() {
            g
        } else {
            return;
        };
        let mut last_modified_map = last_modified_map_guard.deref().borrow_mut();
        if last_modified_map.is_empty() {
            self.load_lmm(&mut last_modified_map);
        }
        if let std::collections::btree_map::Entry::Vacant(e) =
            last_modified_map.entry(uri.to_string())
        {
            e.insert(last_modified.to_string());

            let json_lmm = serde_json::to_string(&last_modified_map.deref());
            let p = Path::new(&self.lmm_folder);
            let lmmp = p.join("last_modified_map.json");
            if let Ok(json_lmm) = &json_lmm {
                if fs::write(lmmp, json_lmm).is_err() {
                    error!("Unable to write last modified map file",);
                }
            }
        }
    }
    /// Gets blocklist takes a URI and returns true if it is on blocklist and false otherwise
    fn check_blocklist(&self, uri: &str) -> bool {
        let blocklist_guard = if let Ok(g) = self.blocklist.lock() {
            g
        } else {
            return false;
        };
        let blocklist = blocklist_guard.deref().borrow_mut();
        // if blocklist.is_empty() {
        //     self.load_blocklist(&mut blocklist);
        // }
        blocklist.contains(&uri.to_string())
    }
    /// Save blocklist, if desired
    fn add_to_blocklist(&self, uri: &str) {
        let blocklist_guard = if let Ok(g) = self.blocklist.lock() {
            g
        } else {
            return;
        };
        let mut blocklist = blocklist_guard.deref().borrow_mut();
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
    fn add_crl(&mut self, crl_buf: &[u8], crl: &CertificateList<Raw>, uri: &str) -> Result<()> {
        let mut cur_crl_info = get_crl_info(crl)?;
        let digest = Sha256::digest(uri).to_vec();
        let hex = buffer_to_hex(digest.as_slice());
        if !hex.is_empty() {
            let filename = format!("{}.crl", hex);
            let path = Path::new(self.crls_folder.as_str()).join(filename);
            if let Err(_e) = std::fs::write(&path, crl_buf) {
                return Err(Error::Unrecognized);
            }
            cur_crl_info.filename = path.to_str().map(|s| s.to_string());

            add_crl_info(
                &mut self.crl_info,
                &mut self.issuer_map,
                &mut self.dp_map,
                &mut self.skid_map,
                crl,
                cur_crl_info,
            );
        }
        Ok(())
    }

    fn get_crls(&self, cert: &PDVCertificate) -> Result<Vec<Vec<u8>>> {
        if let Some(dps) = get_dps_from_cert(cert) {
            for dp in dps {
                if self.dp_map.contains_key(&dp) {
                    let indices = &self.dp_map[&dp];
                    let mut retval = vec![];
                    for index in indices {
                        if let Some(crl_buf) = self.read_crl_at_index(*index) {
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
                if self.skid_map.contains_key(&kid.as_bytes().to_vec()) {
                    let indices = &self.skid_map[&kid.as_bytes().to_vec()];
                    let mut retval = vec![];
                    for index in indices {
                        if let Some(crl_buf) = self.read_crl_at_index(*index) {
                            retval.push(crl_buf);
                        }
                    }
                    return Ok(retval);
                }
            }
        }

        let issuer_name = name_to_string(&cert.decoded_cert.tbs_certificate.issuer);
        if self.issuer_map.contains_key(&issuer_name) {
            let indices = &self.issuer_map[&issuer_name];
            let mut retval = vec![];
            for index in indices {
                if let Some(crl_buf) = self.read_crl_at_index(*index) {
                    retval.push(crl_buf);
                }
            }
            return Ok(retval);
        }
        Err(Error::NotFound)
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
    };
    None
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
    toi: u64,
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
                            error!("Failed to parse CRL with {}", e);
                            continue;
                        }
                    };
                    match get_crl_info(&crl) {
                        Ok(mut cur_crl_info) => {
                            if let Some(filename) = e.path().to_str() {
                                cur_crl_info.filename = Some(filename.to_string());
                            }

                            if check_crl_validity(toi, &crl).is_ok() {
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
                                    error!("Failed to delete stale CRL at {}", filename);
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

impl RevocationStatusCache for RevocationCache {
    fn get_status(&self, cert: &PDVCertificate, time_of_interest: u64) -> PathValidationStatus {
        let name = name_to_string(&cert.decoded_cert.tbs_certificate.issuer);
        let serial = buffer_to_hex(cert.decoded_cert.tbs_certificate.serial_number.as_bytes());

        let cache_map_guard = if let Ok(g) = self.cache_map.lock() {
            g
        } else {
            return RevocationStatusNotDetermined;
        };
        let cache_map = cache_map_guard.deref().borrow_mut();
        let key = (name, serial);
        if cache_map.contains_key(&key) {
            let status_and_time = &cache_map[&key];
            if status_and_time.time > time_of_interest {
                info!("Serviced revocation status check for certificate with serial number {} issued by {} from cache", key.1, key.0);
                return status_and_time.status;
            }
        }

        RevocationStatusNotDetermined
    }
    fn add_status(&self, cert: &PDVCertificate, next_update: u64, status: PathValidationStatus) {
        if status != PathValidationStatus::Valid
            && status != PathValidationStatus::CertificateRevoked
        {
            return;
        }

        let name = name_to_string(&cert.decoded_cert.tbs_certificate.issuer);
        let serial = buffer_to_hex(cert.decoded_cert.tbs_certificate.serial_number.as_bytes());
        let key = (name, serial);

        let cache_map_guard = if let Ok(g) = self.cache_map.lock() {
            g
        } else {
            return;
        };
        let mut cache_map = cache_map_guard.deref().borrow_mut();
        let status_and_time = StatusAndTime {
            status,
            time: next_update,
        };
        if cache_map.contains_key(&key) {
            let old_status_and_time = &cache_map[&key];
            if old_status_and_time.time < next_update {
                debug!("Updating entry in revocation status check for certificate with serial number {} issued by {} in cache", key.1, key.0);
                cache_map.insert(key, status_and_time);
            }
        } else {
            debug!("Adding entry to revocation status check for certificate with serial number {} issued by {} to cache", key.1, key.0);
            cache_map.insert(key, status_and_time);
        }
    }
}
