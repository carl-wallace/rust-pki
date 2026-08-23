//! Builder support

use std::path::Path;

use crate::Result;

use log::error;

use crate::builder::file_utils::cert_file_to_vec;
use crate::builder::file_utils::cert_folder_to_vec;
use crate::builder::file_utils::ta_file_to_vec;
use crate::builder::file_utils::ta_folder_to_vec;
use crate::*;

#[cfg(feature = "remote")]
use crate::fetch_to_buffer;

#[cfg(feature = "remote")]
use std::fs;

/// `build_graph` reads certificates from the location named in the supplied
/// [`CertificationPathSettings`], finds all possible partial certification paths among them and
/// returns a buffer containing the CBOR-encoded result. Every input arrives through `cps`; there
/// are no folder or time-of-interest parameters.
///
/// - [`PS_CERTIFICATION_AUTHORITY_FOLDER`] names the CA input and is required. It may name a folder,
///   which is traversed recursively, or a single file, which is read on its merits, extension and
///   all, exactly as it is when one is nominated at validation time. A file may hold several
///   concatenated PEM objects.
/// - [`PS_CBOR_TA_STORE`] turns the run into trust anchor collection: the CA input is read as
///   [`TrustAnchorChoice`](x509_cert::anchor::TrustAnchorChoice) material and no partial paths are
///   found, so the result is a trust anchor store rather than a certificate store.
/// - [`PS_TIME_OF_INTEREST`] discards certificates that are not valid at the indicated time. A value
///   of zero skips the validity check.
/// - [`PS_RETRIEVE_FROM_AIA_SIA_HTTP`] (`remote` feature, and ignored while collecting trust
///   anchors) chases the AIA and SIA URIs of the certificates gathered so far, looping until a pass
///   adds no new certificate or the store reaches [`PS_MAX_AIA_SIA_CERTS`] — the ceiling that keeps a
///   responder serving a fresh certificate on every hop from running the loop forever. Fetched
///   artifacts land in [`PS_DOWNLOAD_FOLDER`], or in the CA folder when no download folder is set;
///   since a file cannot receive them, a run that chases with a file for its CA input must also set
///   a download folder. A `last_modified_map.json` and a `blocklist.json` in that folder carry fetch
///   state across runs.
///
/// Buffer labels in the returned store are reduced to basenames, so a generated store does not carry
/// the absolute paths of the machine that built it. [`BuffersAndPaths`] features additional
/// information regarding serialization of certificate buffers and partial paths.
pub async fn build_graph(pe: &PkiEnvironment, cps: &CertificationPathSettings) -> Result<Vec<u8>> {
    let ca_folder = if let Some(ca_folder) = cps.get_certification_authority_folder() {
        ca_folder
    } else {
        error!("ca_folder argument must be provided when generate is specified",);
        return Err(Error::NotFound);
    };

    // The CA input may name a single file as well as a folder, as it may at validation time. The
    // folder-taking functions return NotFound for anything that is not a directory, so the choice
    // is made here rather than left to them.
    let named_file = Path::new(&ca_folder).is_file();
    let collect_tas = cps.get_cbor_ta_store();

    #[cfg(feature = "remote")]
    let chasing = cps.get_retrieve_from_aia_sia_http() && !collect_tas;

    // Absent a download folder the CA folder receives what is fetched, which a file cannot do. Only
    // a run that chases has anything to write, so this is an error for those runs alone.
    #[cfg(feature = "remote")]
    if named_file && chasing && cps.get_download_folder().is_none() {
        error!("a download folder is required when AIA and SIA are chased and the CA input names a file rather than a folder");
        return Err(Error::NotFound);
    }

    #[cfg(feature = "remote")]
    let download_folder = if let Some(download_folder) = cps.get_download_folder() {
        download_folder
    } else {
        ca_folder.clone()
    };

    let toi = cps.get_time_of_interest();

    let mut cert_store = CertSource::new();
    let r = match (named_file, collect_tas) {
        (true, true) => ta_file_to_vec(pe, &ca_folder, &mut cert_store, toi),
        (true, false) => cert_file_to_vec(pe, &ca_folder, &mut cert_store, toi),
        (false, true) => ta_folder_to_vec(pe, &ca_folder, &mut cert_store, toi),
        (false, false) => cert_folder_to_vec(pe, &ca_folder, &mut cert_store, toi),
    };
    if let Err(e) = r {
        error!(
            "Failed to read certificates from {} with error {:?}",
            ca_folder, e
        );
    }

    #[cfg(feature = "remote")]
    if chasing {
        let mut uris = Vec::new();
        let mut certs_count = 0;
        let mut uris_count = 0;
        let max_certs = cps.get_max_aia_sia_certs();

        let p = Path::new(&download_folder);
        let blp = p.join("last_modified_map.json");
        let lmm_file = if let Some(bl) = blp.to_str() {
            bl.to_string()
        } else {
            "".to_string()
        };

        let blp = p.join("blocklist.json");
        let blocklist_file = if let Some(bl) = blp.to_str() {
            bl.to_string()
        } else {
            "".to_string()
        };

        loop {
            {
                let r = cert_store.initialize(cps);
                if let Err(e) = r {
                    error!("Failed to populate cert map: {e}");
                }

                // Collect AIA/SIA URIs from the certificates loaded so far (skipping the ones
                // already processed on prior loops). Previously this iterated an empty scratch
                // vector, so no URIs were ever gathered and dynamic building fetched nothing.
                collect_uris_from_aia_and_sia_for_graph_build(
                    cert_store.certs(),
                    &mut uris,
                    certs_count,
                );
            }

            let mut blocklist = read_blocklist(&blocklist_file);
            let mut lmm = read_last_modified_map(&lmm_file);
            let r = fetch_to_buffer(
                pe,
                &uris,
                &download_folder,
                &mut cert_store,
                uris_count,
                &mut lmm,
                &mut blocklist,
                toi,
                cps.get_max_aia_fetch_bytes(),
            )
            .await;
            if let Err(e) = r {
                error!("URI fetching failed with {e:?}");
            }
            let json_lmm = serde_json::to_string(&lmm);
            if !lmm_file.is_empty() {
                if let Ok(json_lmm) = &json_lmm {
                    if fs::write(&lmm_file, json_lmm).is_err() {
                        error!("Unable to write last modified map file",);
                    }
                }
            }

            let json_blocklist = serde_json::to_string(&blocklist);
            if !blocklist_file.is_empty() {
                if let Ok(json_blocklist) = &json_blocklist {
                    if fs::write(&blocklist_file, json_blocklist).is_err() {
                        error!("Unable to write blocklist file");
                    }
                }
            }

            if certs_count == cert_store.num_buffers() {
                break;
            }
            // Bound the AIA/SIA fetch loop: a responder that serves a fresh certificate on every hop
            // never lets the store converge. Stop collecting once the store reaches the configured
            // ceiling and build the graph from what has been gathered.
            if cert_store.num_buffers() as u64 >= max_certs {
                error!(
                    "AIA/SIA collection reached the configured maximum certificate count ({max_certs}); halting collection to bound resource use"
                );
                break;
            }
            certs_count = cert_store.num_buffers();
            uris_count = uris.len();
            error!("URI count: {uris_count}; Cert count: {certs_count}");
        }
    }

    let r = cert_store.initialize(cps);
    if let Err(e) = r {
        error!("Failed to populate parsed certificate vector with error {e:?}");
    }

    if cert_store.num_buffers() == 0 {
        error!("No certificates were read, so no partial paths were found and no CBOR certificate store will be generated"
            );
        return Err(Error::NotFound);
    }

    if !cps.get_cbor_ta_store() {
        cert_store.find_all_partial_paths(pe, cps);
    }

    // Reduce filename labels to basenames so the generated store does not carry the
    // generating machine's absolute paths (leak + non-deterministic output).
    cert_store.normalize_buffer_labels();

    let buffer = if let Ok(b) = cert_store.serialize(CertificationPathBuilderFormats::Cbor) {
        b
    } else {
        return Err(Error::Unrecognized);
    };
    Ok(buffer)
}

/// `read_cbor` accepts an optional string containing the name of a file that notionally containing
/// CBOR data and returns a vector containing bytes read from that file.
///
/// If the file cannot be read or is empty, an empty vector is returned. This function does not
/// attempt to parse the resulting bytes as CBOR.
pub fn read_cbor(filename: &Option<String>) -> Vec<u8> {
    if let Some(filename) = filename {
        let p = Path::new(filename.as_str());
        if Path::exists(p) {
            match get_file_as_byte_vec(p) {
                Ok(cbor_data) => {
                    return cbor_data;
                }
                Err(e) => {
                    error!(
                        "Failed to read CBOR data from {filename} with {e:?}. Continuing without it."
                    );
                }
            }
        }
    }
    vec![]
}

#[cfg(test)]
mod tests {
    use crate::builder::file_utils::ta_folder_to_vec;
    use crate::*;

    #[cfg(feature = "std")]
    #[tokio::test]
    async fn non_existent_dir() {
        let ta_store_folder = format!(
            "{}{}",
            env!("CARGO_MANIFEST_DIR"),
            "/tests/examples/ta_store_with_bad"
        );
        let ca_store_folder = format!(
            "{}{}",
            env!("CARGO_MANIFEST_DIR"),
            "/tests/examples/cert_store_with_expired"
        );
        let nonexistent = format!(
            "{}{}",
            env!("CARGO_MANIFEST_DIR"),
            "/tests/examples/nonexistent"
        );

        let mut pe = PkiEnvironment::default();
        pe.populate_5280_pki_environment();

        let mut ta_store = TaSource::new();
        ta_folder_to_vec(
            &pe,
            &ta_store_folder,
            &mut ta_store,
            TimeOfInterest::disabled(),
        )
        .unwrap();
        ta_store.initialize().unwrap();

        let mut cps = CertificationPathSettings::default();
        let r = build_graph(&pe, &cps).await;
        assert!(r.is_err());
        let r = r.err();
        assert_eq!(Some(Error::NotFound), r);

        let r = build_graph(&pe, &cps).await;
        assert!(r.is_err());
        let r = r.err();
        assert_eq!(Some(Error::NotFound), r);

        cps.set_certification_authority_folder(nonexistent.clone());
        let r = build_graph(&pe, &cps).await;
        assert!(r.is_err());
        let r = r.err();
        assert_eq!(Some(Error::NotFound), r);

        cps.set_time_of_interest(TimeOfInterest::from_unix_secs(1731505759).unwrap());

        cps.set_retrieve_from_aia_sia_http(false);
        cps.set_certification_authority_folder(ca_store_folder.clone());
        pe.add_trust_anchor_source(Box::new(ta_store.clone()));
        let cbor = build_graph(&pe, &cps).await;
        assert!(cbor.is_ok());
        let cert_source = match CertSource::new_from_cbor(cbor.unwrap().as_slice()) {
            Ok(cbor_data) => cbor_data,
            Err(e) => {
                panic!("Failed to parse CBOR file: {e}")
            }
        };
        assert_eq!(3, cert_source.len());

        // serialize as TA store (so no partial paths)
        cps.set_cbor_ta_store(true);
        cps.set_certification_authority_folder(ca_store_folder.clone());
        let cbor = build_graph(&pe, &cps).await;
        assert!(cbor.is_ok());
        let cert_source = match CertSource::new_from_cbor(cbor.unwrap().as_slice()) {
            Ok(cbor_data) => cbor_data,
            Err(e) => {
                panic!("Failed to parse CBOR file: {e}")
            }
        };
        assert_eq!(3, cert_source.len());
    }
}
