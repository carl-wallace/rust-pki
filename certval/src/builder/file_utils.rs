//! The file_utils module contains utility functions related to interactions with the filesystem.

use std::ffi::OsStr;
use std::path::Path;
use walkdir::WalkDir;

use log::{error, info};

use der::Decode;
use x509_cert::anchor::TrustAnchorChoice;
use x509_cert::certificate::{CertificateInner, Raw};

use crate::source::cert_source::CertFile;
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
/// encoded [`Certificate`](x509_cert::certificate::Certificate) or [`TrustAnchorChoice`] files, a mutable vector of [`CertFile`] objects and a time
/// of interest, expressed as seconds since Unix epoch. It recursively traverses the directory
/// populating the vector with items corresponding to files that could be processed as a TrustAnchorChoice
/// that is valid at the time of interest and returns the number of items added. Pass 0 for `time_of_interest`
/// to skip the validity check.
///
/// Only files with .der, .cer, .crt or .ta extensions are processed.
pub fn ta_folder_to_vec(
    pe: &PkiEnvironment,
    tas_dir: &str,
    tas_vec: &mut dyn CertVector,
    time_of_interest: TimeOfInterest,
) -> Result<usize> {
    cert_or_ta_folder_to_vec(pe, tas_dir, tas_vec, time_of_interest, true)
}

/// `cert_folder_to_vec` is used to help process a folder containing DER-encoded certificate files
/// for use as a certificate source.
///
/// `cert_folder_to_vec` takes a string containing the full path of a folder containing binary DER
/// encoded [`Certificate`](x509_cert::certificate::Certificate) files, a mutable vector of [`CertFile`] objects and a time of interest, expressed
/// as seconds since Unix epoch. It recursively traverses the directory populating the vector with
/// items corresponding to files that could be processed as a [`Certificate`](x509_cert::certificate::Certificate) that is valid at the time of
/// interest and returns the number of items added. Pass 0 for `time_of_interest` to skip the validity check.
///
/// Only files with .der, .cer, or .crt extensions are processed.
pub fn cert_folder_to_vec(
    pe: &PkiEnvironment,
    certs_dir: &str,
    certs_vec: &mut dyn CertVector,
    time_of_interest: TimeOfInterest,
) -> Result<usize> {
    cert_or_ta_folder_to_vec(pe, certs_dir, certs_vec, time_of_interest, false)
}

/// `ta_file_to_vec` is used to help process a single file containing one or more DER- or PEM-encoded
/// trust anchors for use as a trust anchor source.
///
/// It is the single-file counterpart of [`ta_folder_to_vec`], for callers that let a user nominate
/// an anchor directly rather than a folder to search. The file may hold several concatenated PEM
/// objects, each of which is accepted or rejected on its own. Unlike the folder walk, the file name
/// is not required to carry a recognized extension: the caller named this file, so refusing to read
/// it on the strength of its name would be unhelpful. Objects that do not parse as a
/// [`TrustAnchorChoice`], or that are not valid at the time of interest, are dropped. Pass 0 for
/// `time_of_interest` to skip the validity check. Returns the number of items added.
#[cfg(feature = "std")]
pub fn ta_file_to_vec(
    pe: &PkiEnvironment,
    ta_file: &str,
    tas_vec: &mut dyn CertVector,
    time_of_interest: TimeOfInterest,
) -> Result<usize> {
    cert_or_ta_file_to_vec(pe, ta_file, tas_vec, time_of_interest, true)
}

/// `cert_file_to_vec` is used to help process a single file containing one or more DER- or PEM-encoded
/// certificates for use as a certificate source.
///
/// It is the single-file counterpart of [`cert_folder_to_vec`], for callers that let a user nominate
/// a certificate (or a PEM bundle such as a fullchain) directly rather than a folder to search. See
/// [`ta_file_to_vec`] for the shared rules; here objects are read as
/// [`Certificate`](x509_cert::certificate::Certificate) and self-signed
/// certificates are excluded, as they are when a folder is read. Returns the number of items added.
#[cfg(feature = "std")]
pub fn cert_file_to_vec(
    pe: &PkiEnvironment,
    cert_file: &str,
    certs_vec: &mut dyn CertVector,
    time_of_interest: TimeOfInterest,
) -> Result<usize> {
    cert_or_ta_file_to_vec(pe, cert_file, certs_vec, time_of_interest, false)
}

/// `cert_or_ta_file_to_vec` is used by [`ta_file_to_vec`] and [`cert_file_to_vec`] to read one file,
/// returning [`Error::NotFound`] when the path is not a file (including when it is a folder, which
/// the folder-taking functions handle instead).
#[cfg(feature = "std")]
fn cert_or_ta_file_to_vec(
    pe: &PkiEnvironment,
    filename: &str,
    certsvec: &mut dyn CertVector,
    time_of_interest: TimeOfInterest,
    collect_tas: bool,
) -> Result<usize> {
    let path = Path::new(filename);
    if !Path::is_file(path) {
        error!("{filename} does not exist or is not a file");
        return Err(Error::NotFound);
    }
    Ok(add_file_to_vec(
        pe,
        path,
        certsvec,
        time_of_interest,
        collect_tas,
        false,
    ))
}

/// `add_file_to_vec` reads one file into `certsvec` and returns the number of objects it added.
///
/// This is the per-file half of the folder walk, shared with the single-file entry points so that
/// one file is filtered by exactly the same rules whether it was reached by walking a folder or
/// named outright. `check_extension` is the one difference between those two cases: a folder walk
/// skips files whose extension does not suggest certificate material, while a named file is read on
/// its merits.
///
/// A file that cannot be read or decoded is skipped rather than reported: during a folder walk one
/// stray file must not empty the store (with `?` it did), and for a named file the count of zero
/// tells the caller as much as an error would. A file may hold several concatenated PEM objects (a
/// fullchain or root-CA bundle), so each object is accepted or rejected on its own.
#[cfg(feature = "std")]
fn add_file_to_vec(
    pe: &PkiEnvironment,
    path: &Path,
    certsvec: &mut dyn CertVector,
    time_of_interest: TimeOfInterest,
    collect_tas: bool,
    check_extension: bool,
) -> usize {
    let initial_count = certsvec.len();

    if check_extension {
        // This walk fans every file out through decode_pem_to_ders, so it takes the bundle list:
        // a p7c or a concatenated PEM contributes all of its certificates. Without the extensions
        // here they are skipped silently and only a directly named file works.
        let file_exts = if collect_tas {
            TA_BUNDLE_EXTENSIONS
        } else {
            CERT_BUNDLE_EXTENSIONS
        };
        match path.extension().and_then(OsStr::to_str) {
            Some(ext) => {
                if !file_exts.contains(&ext) {
                    return 0;
                }
            }
            None => return 0,
        }
    }

    let buffers = match get_file_as_der_certs_pem(path) {
        Ok(buffers) => buffers,
        Err(e) => {
            error!(
                "Ignoring {} as it could not be read or decoded: {e:?}",
                path.display()
            );
            return 0;
        }
    };

    for buffer in buffers {
        // make sure it parses before saving buffer; a rejected object skips only
        // itself, not the rest of a bundle.
        if collect_tas {
            // Every TrustAnchorChoice alternative is a trust anchor here, not only
            // the Certificate one: an RFC 5914 TrustAnchorInfo is how trust anchor
            // constraints are expressed, which is most of the reason to hold anchors
            // in this form at all, and .ta is an accepted extension for exactly that
            // material. An anchor asserting no validity period (Ok(None)) is kept --
            // there is nothing to check, which is not the same as failing a check.
            let ta = match TrustAnchorChoice::<Raw>::from_der(buffer.as_slice()) {
                Ok(ta) => ta,
                Err(_e) => continue,
            };
            if ta_valid_at_time(&ta, time_of_interest, true).is_err() {
                error!(
                    "Ignored an object in {} as not valid at indicated time of interest",
                    path.to_str().unwrap_or("")
                );
                continue;
            }
        } else {
            let r = CertificateInner::from_der(buffer.as_slice());
            if let Ok(cert) = r {
                let r = valid_at_time(cert.tbs_certificate(), time_of_interest, true);
                if let Err(_e) = r {
                    error!(
                        "Ignored an object in {} as not valid at indicated time of interest",
                        path.to_str().unwrap_or("")
                    );
                    continue;
                }

                if is_self_signed_with_buffer(pe, &cert, buffer.as_slice()) {
                    if let Some(s) = path.to_str() {
                        info!("Ignoring a self-signed object in {s}");
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

    certsvec.len() - initial_count
}

/// `cert_or_ta_folder_to_vec` is used by [`ta_folder_to_vec`] and [`cert_folder_to_vec`] to recursively traverse
/// a folder in search of [`Certificate`] or [`TrustAnchorChoice`] objects, as appropriate.
fn cert_or_ta_folder_to_vec(
    pe: &PkiEnvironment,
    certsdir: &str,
    certsvec: &mut dyn CertVector,
    time_of_interest: TimeOfInterest,
    collect_tas: bool,
) -> Result<usize> {
    if !Path::is_dir(Path::new(certsdir)) {
        error!("{certsdir} does not exist or is not a directory");
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
                    // Files reached by walking a folder are filtered by extension: the folder was
                    // nominated, not the file, so anything that does not look like certificate
                    // material is passed over rather than reported.
                    add_file_to_vec(pe, path, certsvec, time_of_interest, collect_tas, true);
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

/// Returns the file that records URI last-modified values: the [`PS_LAST_MODIFIED_MAP_FILE`] setting
/// when one names a file, and `last_modified_map.json` in `download_folder` otherwise.
///
/// The setting is documented as the way to name this file and the getter has always existed, but the
/// callers that fetch built the path from the download folder and never consulted it -- so a value
/// the settings form accepted, stored and redisplayed had no effect on a run. Resolving it in one
/// place keeps the precedence from being restated per call site.
#[cfg(feature = "std")]
pub fn last_modified_map_file(cps: &CertificationPathSettings, download_folder: &str) -> String {
    fetch_state_file(
        cps.get_last_modified_map_file(),
        download_folder,
        "last_modified_map.json",
    )
}

/// Returns the file listing URIs not worth retrying: the [`PS_URI_BLOCKLIST_FILE`] setting when one
/// names a file, and `blocklist.json` in `download_folder` otherwise. See
/// [`last_modified_map_file`] for why the resolution lives here.
#[cfg(feature = "std")]
pub fn uri_blocklist_file(cps: &CertificationPathSettings, download_folder: &str) -> String {
    fetch_state_file(
        cps.get_uri_blocklist_file(),
        download_folder,
        "blocklist.json",
    )
}

/// An empty configured value is treated as absent rather than as a request to use "": the settings
/// form writes an empty string when a field is cleared, and honoring that literally would send the
/// reader at a path that cannot exist.
#[cfg(feature = "std")]
fn fetch_state_file(
    configured: Option<String>,
    download_folder: &str,
    default_name: &str,
) -> String {
    if let Some(configured) = configured {
        if !configured.is_empty() {
            return configured;
        }
    }
    Path::new(download_folder)
        .join(default_name)
        .to_str()
        .unwrap_or_default()
        .to_string()
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
                    Err(e) => {
                        error!("Failed to read data from {filename:?}: {e}");
                        Err(Error::StdIoError(e.kind()))
                    }
                }
            }
            Err(e) => {
                error!("Failed to read metadata for {filename:?}: {e}");
                Err(Error::StdIoError(e.kind()))
            }
        },
        Err(e) => {
            error!("Failed to read {filename:?}: {e}");
            Err(Error::StdIoError(e.kind()))
        }
    }
}

/// `get_file_as_byte_vec_pem` takes a Path containing a file name and returns a vector of bytes containing
/// the contents of that file or an [Error::StdIoError]. If the file is PEM encoded, it is decoded
/// prior to returning the vector of bytes. To read without PEM support, use `get_file_as_byte_vec`.
///
/// This returns a *single* object. If the file holds a multi-object PEM bundle, only the first object
/// is returned (and, depending on byte alignment, some bundles fail to decode entirely) — see
/// [`decode_pem_to_der`]. This suits CRL files, which hold exactly one CRL; to load every object from a
/// certificate or trust-anchor bundle use [`get_file_as_der_certs_pem`].
#[cfg(feature = "std")]
pub fn get_file_as_byte_vec_pem(filename: &Path) -> Result<Vec<u8>> {
    let b = get_file_as_byte_vec(filename)?;
    // decode_pem_to_der (in pdv_utilities, no_std-capable) handles strict RFC 7468, a lenient
    // fallback for real-world PEM OpenSSL accepts but strict RFC 7468 rejects, and outer-SEQUENCE
    // trailing-byte trimming.
    decode_pem_to_der(&b).inspect_err(|e| {
        error!("Failed to PEM decode data from {filename:?}: {e:?}");
    })
}

/// `get_file_as_der_certs_pem` is the multi-object counterpart to [`get_file_as_byte_vec_pem`]: it
/// returns one DER buffer per object in the file (see [`decode_pem_to_ders`]), so a concatenated
/// certificate or trust-anchor bundle contributes every object rather than silently only its first.
/// A bare-DER file yields a single-element vector. CRL loading uses the single-object
/// [`get_file_as_byte_vec_pem`] because a CRL file holds exactly one CRL.
#[cfg(feature = "std")]
pub fn get_file_as_der_certs_pem(filename: &Path) -> Result<Vec<Vec<u8>>> {
    let b = get_file_as_byte_vec(filename)?;
    decode_pem_to_ders(&b).inspect_err(|e| {
        error!("Failed to PEM decode data from {filename:?}: {e:?}");
    })
}

// An RFC 5914 TrustAnchorInfo is a trust anchor, and is the form that carries trust anchor
// constraints, so a folder of .ta files must load as anchors. It previously loaded as nothing: only
// the Certificate alternative was accepted, and everything else was skipped without a word.
#[test]
fn loads_rfc5914_trust_anchors() {
    let pe = PkiEnvironment::default();
    let mut tasvec = TaSource::new();
    let toi = TimeOfInterest::from_unix_secs(1647264981).unwrap();
    let n = cert_or_ta_folder_to_vec(
        &pe,
        "tests/examples/PKITS_data_2048/5914_tas",
        &mut tasvec,
        toi,
        true,
    )
    .unwrap();
    assert!(n > 0);
    assert!(tasvec.initialize().is_ok());

    // the same folder read as certificates yields nothing, i.e., these are TaInfo objects rather
    // than certificates that happen to parse either way
    let mut certsvec = CertSource::default();
    let n = cert_or_ta_folder_to_vec(
        &pe,
        "tests/examples/PKITS_data_2048/5914_tas",
        &mut certsvec,
        toi,
        false,
    )
    .unwrap();
    assert_eq!(0, n);
}

#[test]
fn non_existent_dir() {
    let pe = PkiEnvironment::default();
    let mut certsvec = CertSource::default();
    let toi = TimeOfInterest::disabled();
    let r = cert_or_ta_folder_to_vec(&pe, "tests/examples/nonexistent", &mut certsvec, toi, false);
    assert!(r.is_err());
    let r = r.err();
    assert_eq!(Some(Error::NotFound), r);
}

#[test]
fn with_expired() {
    let pe = PkiEnvironment::default();

    //disable validity check
    let mut certsvec = CertSource::default();
    let toi = TimeOfInterest::disabled();
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
    let toi = TimeOfInterest::from_unix_secs(1647443375).unwrap();
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
    let mut certsvec = CertSource::default();
    let toi = TimeOfInterest::from_unix_secs(1647443375).unwrap();
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

// A concatenated PEM bundle (an OpenSSL fullchain or a CA bundle) must contribute every certificate,
// not just the first. Build a two-cert bundle from known non-self-signed fixtures and confirm the
// folder scan loads both.
#[test]
fn loads_all_certs_from_pem_bundle() {
    use base64ct::{Base64, Encoding};
    use std::io::Write;

    let to_pem = |der: &[u8]| -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            Base64::encode_string(der)
        )
    };

    let der1 =
        get_file_as_byte_vec(Path::new("tests/examples/cert_store_with_expired/178.der")).unwrap();
    let der2 =
        get_file_as_byte_vec(Path::new("tests/examples/cert_store_with_expired/45.der")).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let mut f = std::fs::File::create(dir.path().join("bundle.crt")).unwrap();
    f.write_all(to_pem(&der1).as_bytes()).unwrap();
    f.write_all(to_pem(&der2).as_bytes()).unwrap();
    drop(f);

    let pe = PkiEnvironment::default();
    let mut certsvec = CertSource::default();
    let toi = TimeOfInterest::disabled();
    let n = cert_or_ta_folder_to_vec(&pe, dir.path().to_str().unwrap(), &mut certsvec, toi, false)
        .unwrap();

    // both certificates from the single bundle file were loaded (content-keyed dedup)
    assert_eq!(2, n);
    assert!(certsvec.contains(&CertFile {
        filename: String::new(),
        bytes: der1,
    }));
    assert!(certsvec.contains(&CertFile {
        filename: String::new(),
        bytes: der2,
    }));
}
