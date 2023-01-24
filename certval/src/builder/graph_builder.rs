//! Builder support

use std::path::Path;

use crate::Result;

use crate::builder::file_utils::cert_folder_to_vec;
use crate::builder::file_utils::ta_folder_to_vec;
use crate::source::cert_source::*;
use crate::PeLogLevels;
use crate::*;

#[cfg(feature = "remote")]
use crate::fetch_to_buffer;

#[cfg(feature = "remote")]
use std::fs;

/// `build_graph` takes a string containing the full path of a folder containing binary DER-encoded
/// trust anchor files, a string containing the full path of a folder containing binary
/// DER-encoded CA certificate files, and a time of interest expressed as seconds since Unix epoch
/// then attempts to find all possible partial certification paths.
///
/// It returns a buffer containing CBOR-encoded partial paths. [BuffersAndPaths] features additional
/// information regarding serialization of certificate buffers and partial paths.
///
/// The time of interest is used to ignore certificates that are expired at the indicated time (when
/// time of interest value is zero, the validity check is not performed).
pub async fn build_graph(
    pe: &PkiEnvironment<'_>,
    cps: &CertificationPathSettings,
) -> Result<Vec<u8>> {
    let ca_folder = if let Some(ca_folder) = get_certification_authority_folder(cps) {
        ca_folder
    } else {
        log_message(
            &PeLogLevels::PeError,
            "ca_folder argument must be provided when generate is specified",
        );
        return Err(Error::NotFound);
    };

    #[cfg(feature = "remote")]
    let download_folder = if let Some(download_folder) = get_download_folder(cps) {
        download_folder
    } else {
        ca_folder.clone()
    };

    let toi = get_time_of_interest(cps);

    let mut cert_store = CertSource::new();
    let r = if get_cbor_ta_store(cps) {
        ta_folder_to_vec(
            pe,
            &ca_folder,
            &mut cert_store.buffers_and_paths.buffers,
            toi,
        )
    } else {
        cert_folder_to_vec(
            pe,
            &ca_folder,
            &mut cert_store.buffers_and_paths.buffers,
            toi,
        )
    };
    if let Err(e) = r {
        log_message(
            &PeLogLevels::PeError,
            format!(
                "Failed to read certificates from {} with error {:?}",
                &ca_folder, e
            )
            .as_str(),
        );
    }

    #[cfg(feature = "remote")]
    if get_retrieve_from_aia_sia_http(cps) && !get_cbor_ta_store(cps) {
        let mut uris = Vec::new();
        let mut certs_count = 0;
        let mut uris_count = 0;

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
                let mut tmp_vec: Vec<Option<PDVCertificate<'_>>> = vec![];
                let r =
                    populate_parsed_cert_vector(&cert_store.buffers_and_paths, cps, &mut tmp_vec);
                if let Err(e) = r {
                    log_message(
                        &PeLogLevels::PeError,
                        format!("Failed to populate cert map: {}", e).as_str(),
                    );
                }

                collect_uris_from_aia_and_sia_for_graph_build(&tmp_vec, &mut uris, certs_count);
            }

            let mut blocklist = read_blocklist(&blocklist_file);
            let mut lmm = read_last_modified_map(&lmm_file);
            let r = fetch_to_buffer(
                pe,
                &uris,
                &download_folder,
                &mut cert_store.buffers_and_paths.buffers,
                uris_count,
                &mut lmm,
                &mut blocklist,
                toi,
            )
            .await;
            if let Err(e) = r {
                log_message(
                    &PeLogLevels::PeError,
                    format!("URI fetching failed with {:?}", e).as_str(),
                );
            }
            let json_lmm = serde_json::to_string(&lmm);
            if !lmm_file.is_empty() {
                if let Ok(json_lmm) = &json_lmm {
                    if fs::write(&lmm_file, json_lmm).is_err() {
                        log_message(
                            &PeLogLevels::PeError,
                            "Unable to write last modified map file",
                        );
                    }
                }
            }

            let json_blocklist = serde_json::to_string(&blocklist);
            if !blocklist_file.is_empty() {
                if let Ok(json_blocklist) = &json_blocklist {
                    if fs::write(&blocklist_file, json_blocklist).is_err() {
                        log_message(&PeLogLevels::PeError, "Unable to write blocklist file");
                    }
                }
            }

            if certs_count == cert_store.buffers_and_paths.buffers.len() {
                break;
            }
            certs_count = cert_store.buffers_and_paths.buffers.len();
            uris_count = uris.len();
            log_message(
                &PeLogLevels::PeError,
                format!("URI count: {}; Cert count: {}", uris_count, certs_count).as_str(),
            );
        }
    }

    let r = populate_parsed_cert_vector(&cert_store.buffers_and_paths, cps, &mut cert_store.certs);
    if let Err(e) = r {
        log_message(
            &PeLogLevels::PeError,
            format!(
                "Failed to populate parsed certificate vector with error {:?}",
                e
            )
            .as_str(),
        );
    }

    if cert_store.buffers_and_paths.buffers.is_empty() {
        log_message(
            &PeLogLevels::PeError,
            "No certificates were read, so no partial paths were found and no CBOR certificate store will be generated"
            );
        return Err(Error::NotFound);
    }

    if !get_cbor_ta_store(cps) {
        cert_store.find_all_partial_paths(pe, cps);
    }

    let buffer =
        if let Ok(b) = cert_store.serialize_partial_paths(CertificationPathBuilderFormats::Cbor) {
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
                    log_message(
                        &PeLogLevels::PeError,
                        format!(
                            "Failed to read CBOR data from {} with {:?}. Continuing without it.",
                            filename, e
                        )
                        .as_str(),
                    );
                }
            }
        }
    }
    vec![]
}

#[cfg(feature = "std")]
#[tokio::test]
async fn non_existent_dir() {
    use ciborium::de::from_reader;

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
    populate_5280_pki_environment(&mut pe);

    let mut ta_store = TaSource::new();
    ta_folder_to_vec(&pe, &ta_store_folder, &mut ta_store.buffers, 0).unwrap();
    populate_parsed_ta_vector(&ta_store.buffers, &mut ta_store.tas);
    ta_store.index_tas();
    // for (i, ta) in ta_store.tas.iter().enumerate() {
    //     let hex_skid = hex_skid_from_ta(ta);
    //     ta_store.skid_map.insert(hex_skid, i);
    //
    //     if let Ok(name) = get_trust_anchor_name(&ta.decoded_ta) {
    //         let name_str = name_to_string(name);
    //         ta_store.name_map.insert(name_str, i);
    //     };
    // }

    let mut cps = CertificationPathSettings::default();
    let r = build_graph(&pe, &cps).await;
    assert!(r.is_err());
    let r = r.err();
    assert_eq!(Some(Error::NotFound), r);

    let r = build_graph(&pe, &cps).await;
    assert!(r.is_err());
    let r = r.err();
    assert_eq!(Some(Error::NotFound), r);

    set_certification_authority_folder(&mut cps, nonexistent.clone());
    let r = build_graph(&pe, &cps).await;
    assert!(r.is_err());
    let r = r.err();
    assert_eq!(Some(Error::NotFound), r);

    set_retrieve_from_aia_sia_http(&mut cps, false);
    set_certification_authority_folder(&mut cps, ca_store_folder.clone());
    pe.add_trust_anchor_source(&ta_store);
    let cbor = build_graph(&pe, &cps).await;
    assert!(cbor.is_ok());
    let mut cert_source = CertSource::new();
    match from_reader(cbor.unwrap().as_slice()) {
        Ok(cbor_data) => {
            cert_source.buffers_and_paths = cbor_data;
        }
        Err(e) => {
            panic!("Failed to parse CBOR file: {}", e)
        }
    }
    assert_eq!(3, cert_source.buffers_and_paths.buffers.len());
    {
        let partial_paths_guard = if let Ok(g) = cert_source.buffers_and_paths.partial_paths.lock()
        {
            g
        } else {
            panic!()
        };
        assert_eq!(1, partial_paths_guard.borrow().len());
    }

    // serialize as TA store (so no partial paths)
    set_cbor_ta_store(&mut cps, true);
    set_certification_authority_folder(&mut cps, ca_store_folder.clone());
    let cbor = build_graph(&pe, &cps).await;
    assert!(cbor.is_ok());
    let mut cert_source = CertSource::new();
    match from_reader(cbor.unwrap().as_slice()) {
        Ok(cbor_data) => {
            cert_source.buffers_and_paths = cbor_data;
        }
        Err(e) => {
            panic!("Failed to parse CBOR file: {}", e)
        }
    }
    assert_eq!(3, cert_source.buffers_and_paths.buffers.len());
    {
        let partial_paths_guard = if let Ok(g) = cert_source.buffers_and_paths.partial_paths.lock()
        {
            g
        } else {
            panic!()
        };
        assert_eq!(0, partial_paths_guard.borrow().len());
    }
}
