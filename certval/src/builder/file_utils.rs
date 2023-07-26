//! The file_utils module contains utility functions related to interactions with the filesystem.

use std::ffi::OsStr;
use std::path::Path;
use walkdir::WalkDir;

use log::{error, info};

use der::Decode;
use x509_cert::anchor::TrustAnchorChoice;
use x509_cert::Certificate;

use crate::source::cert_source::CertFile;
use crate::util::pdv_utilities::*;
use crate::*;

#[cfg(feature = "std")]
use serde_json::Result as SerdeResult;

#[cfg(feature = "std")]
use std::io::Read;

#[cfg(feature = "std")]
use alloc::collections::BTreeMap;

#[cfg(feature = "std")]
use std::fs::File;

/// `ta_folder_to_vec` is used to help process a folder containing DER-encoded trust anchor files
/// for use as a trust anchor source.
///
/// `ta_folder_to_vec` takes a string containing the full path of a folder containing binary DER
/// encoded [`Certificate`] or [`TrustAnchorChoice`] files, a mutable vector of [`CertFile`] objects and a time
/// of interest, expressed as seconds since Unix epoch. It recursively traverses the directory
/// populating the vector with items corresponding to files that could be processed as a TrustAnchorChoice
/// that is valid at the time of interest and returns the number of items added. Pass 0 for `time_of_interest`
/// to skip the validity check.
///
/// Only files with .der, .cer, .crt or .ta extensions are processed.
pub fn ta_folder_to_vec(
    pe: &PkiEnvironment,
    tas_dir: &str,
    tas_vec: &mut Vec<CertFile>,
    time_of_interest: u64,
) -> Result<usize> {
    cert_or_ta_folder_to_vec(pe, tas_dir, tas_vec, time_of_interest, true)
}

/// `cert_folder_to_vec` is used to help process a folder containing DER-encoded certificate files
/// for use as a certificate source.
///
/// `cert_folder_to_vec` takes a string containing the full path of a folder containing binary DER
/// encoded [`Certificate`] files, a mutable vector of [`CertFile`] objects and a time of interest, expressed
/// as seconds since Unix epoch. It recursively traverses the directory populating the vector with
/// items corresponding to files that could be processed as a [`Certificate`] that is valid at the time of
/// interest and returns the number of items added. Pass 0 for `time_of_interest` to skip the validity check.
///
/// Only files with .der, .cer, or .crt extensions are processed.
pub fn cert_folder_to_vec(
    pe: &PkiEnvironment,
    certs_dir: &str,
    certs_vec: &mut Vec<CertFile>,
    time_of_interest: u64,
) -> Result<usize> {
    cert_or_ta_folder_to_vec(pe, certs_dir, certs_vec, time_of_interest, false)
}

/// `cert_or_ta_folder_to_vec` is used by [`ta_folder_to_vec`] and [`cert_folder_to_vec`] to recursively traverse
/// a folder in search of [`Certificate`] or [`TrustAnchorChoice`] objects, as appropriate.
fn cert_or_ta_folder_to_vec(
    pe: &PkiEnvironment,
    certsdir: &str,
    certsvec: &mut Vec<CertFile>,
    time_of_interest: u64,
    collect_tas: bool,
) -> Result<usize> {
    if !Path::is_dir(Path::new(certsdir)) {
        error!("{} does not exist or is not a directory", certsdir);
        return Err(Error::NotFound);
    }

    let initial_count = certsvec.len();
    for entry in WalkDir::new(certsdir) {
        match entry {
            Ok(e) => {
                let path = e.path();
                if e.file_type().is_dir() {
                    if let Some(s) = path.to_str() {
                        if s != certsdir {
                            error!("Recursing {}", path.display());
                            let r = cert_or_ta_folder_to_vec(
                                pe,
                                s,
                                certsvec,
                                time_of_interest,
                                collect_tas,
                            );
                            if r.is_err() {
                                continue;
                            }
                        }
                    }
                    continue;
                } else {
                    let file_exts = if collect_tas {
                        vec!["der", "crt", "cer", "ta"]
                    } else {
                        vec!["der", "crt", "cer"]
                    };
                    if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                        if !file_exts.contains(&ext) {
                            continue;
                        }
                    } else {
                        continue;
                    }

                    let buffer = get_file_as_byte_vec_pem(path)?;

                    // make sure it parses before saving buffer
                    if collect_tas {
                        let r = TrustAnchorChoice::from_der(buffer.as_slice());
                        if let Ok(TrustAnchorChoice::Certificate(cert)) = r {
                            let r = valid_at_time(&cert.tbs_certificate, time_of_interest, true);
                            if let Err(_e) = r {
                                error!(
                                    "Ignored {} as not valid at indicated time of interest",
                                    path.to_str().unwrap_or("")
                                );
                                continue;
                            }
                        } else {
                            continue;
                        }
                    } else {
                        let r = Certificate::from_der(buffer.as_slice());
                        if let Ok(cert) = r {
                            let r = valid_at_time(&cert.tbs_certificate, time_of_interest, true);
                            if let Err(_e) = r {
                                error!(
                                    "Ignored {} as not valid at indicated time of interest",
                                    path.to_str().unwrap_or("")
                                );
                                continue;
                            }

                            if is_self_signed_with_buffer(pe, &cert, buffer.as_slice()) {
                                if let Some(s) = path.to_str() {
                                    info!("Ignoring {} as self-signed", s);
                                }
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }

                    let cf = CertFile {
                        filename: path.to_str().unwrap_or("").to_string(),
                        bytes: buffer,
                    };
                    if !certsvec.contains(&cf) {
                        certsvec.push(cf);
                    }
                }
            }
            _ => {
                error!("Failed to unwrap entry in certs_folder_to_certfile_vec");
                continue;
            }
        }
    }
    Ok(certsvec.len() - initial_count)
}

/// `read_last_modified_map` accepts a string containing the name of a file that notionally contains JSON data that
/// represents last modified information and returns a map of URIs to last modified times.
///
/// The map is expressed as a BTreeMap<String, String> with a URI as the key and last modified time
/// returned from that resource as the value.
///
/// A sample last modified map is shown below. Generally, these should be automatically prepared in folders
/// that receive downloaded files, not manually specified.
///
/// ```json
/// {"http://example.com/CRLs/SomeCRL.crl":"Tue, 01 Mar 2022 19:21:02 GMT",
/// "http://example.com/CRLs/SomeOtherCRL.crl":"Sat, 12 Mar 2022 14:52:24 GMT"}
/// ```
///
#[cfg(feature = "std")]
pub fn read_last_modified_map(fname: &str) -> BTreeMap<String, String> {
    if Path::exists(Path::new(fname)) {
        if let Ok(json) = get_file_as_byte_vec(Path::new(fname)) {
            let r: SerdeResult<BTreeMap<String, String>> = serde_json::from_slice(&json);
            if let Ok(lmm_data) = r {
                return lmm_data;
            }
        }
    }
    BTreeMap::new()
}

/// `read_blocklist` accepts a string containing the name of a file that notionally contains JSON data
/// that represents a blocklist and returns a vector of strings representing URIs that have been placed
/// on the blocklist.
///
/// A sample blocklist is shown below. Note, each entry is a full URI, not a hostname.
///
/// ```json
/// ["http://example.com/issuedby/IssuedByExampleCA.p7c",
/// "http://example.com/issuedby/IssuedToExampleCA.p7c"]
/// ```
#[cfg(feature = "std")]
pub fn read_blocklist(fname: &str) -> Vec<String> {
    if Path::exists(Path::new(fname)) {
        if let Ok(json) = get_file_as_byte_vec(Path::new(fname)) {
            let r: SerdeResult<Vec<String>> = serde_json::from_slice(&json);
            if let Ok(blocklist) = r {
                return blocklist;
            }
        }
    }
    vec![]
}

/// `get_file_as_byte_vec` takes a Path containing a file name and returns a vector of bytes containing
/// the contents of that file or an [Error::StdIoError].
#[cfg(feature = "std")]
pub fn get_file_as_byte_vec(filename: &Path) -> Result<Vec<u8>> {
    match File::open(filename) {
        Ok(mut f) => match std::fs::metadata(filename) {
            Ok(metadata) => {
                let mut buffer = vec![0; metadata.len() as usize];
                match f.read_exact(&mut buffer) {
                    Ok(_) => Ok(buffer),
                    Err(e) => Err(Error::StdIoError(e.kind())),
                }
            }
            Err(e) => Err(Error::StdIoError(e.kind())),
        },
        Err(e) => Err(Error::StdIoError(e.kind())),
    }
}

/// `get_file_as_byte_vec_pem` takes a Path containing a file name and returns a vector of bytes containing
/// the contents of that file or an [Error::StdIoError]. If the file is PEM encoded, it is decoded
/// prior to returning the vector of bytes. To read without PEM, use `get_file_as_byte_vec`.
#[cfg(feature = "std")]
pub fn get_file_as_byte_vec_pem(filename: &Path) -> Result<Vec<u8>> {
    let b = get_file_as_byte_vec(filename)?;
    if b[0] == 0x2D {
        match pem_rfc7468::decode_vec(b.as_slice()) {
            Ok(b) => {
                return Ok(b.1);
            }
            Err(e) => {
                error!("Failed to parse certificate from {:?}: {:?}", filename, e);
                return Err(Error::Unrecognized);
            }
        }
    }
    Ok(b)
}

#[test]
fn non_existent_dir() {
    let pe = PkiEnvironment::default();
    let mut certsvec = vec![];
    let toi = 0;
    let r = cert_or_ta_folder_to_vec(&pe, "tests/examples/nonexistent", &mut certsvec, toi, false);
    assert!(r.is_err());
    let r = r.err();
    assert_eq!(Some(Error::NotFound), r);
}

#[test]
fn with_expired() {
    let pe = PkiEnvironment::default();

    //disable validity check
    let mut certsvec = vec![];
    let toi = 0;
    let r = cert_or_ta_folder_to_vec(
        &pe,
        "tests/examples/cert_store_with_expired",
        &mut certsvec,
        toi,
        false,
    );
    assert!(r.is_ok());
    assert_eq!(5, r.unwrap());

    //enable validity check but vector is already full of what would otherwise be read
    let toi = 1647443375;
    let r = cert_or_ta_folder_to_vec(
        &pe,
        "tests/examples/cert_store_with_expired",
        &mut certsvec,
        toi,
        false,
    );
    assert!(r.is_ok());
    assert_eq!(0, r.unwrap());

    // validity check with empty vector results in one fewer certificate being harvested
    let mut certsvec = vec![];
    let toi = 1647443375;
    let r = cert_or_ta_folder_to_vec(
        &pe,
        "tests/examples/cert_store_with_expired",
        &mut certsvec,
        toi,
        false,
    );
    assert!(r.is_ok());
    assert_eq!(4, r.unwrap());
}
