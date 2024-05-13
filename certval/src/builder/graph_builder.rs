//! Builder support

use std::path::Path;

use crate::Result;

use log::error;

use crate::builder::file_utils::cert_folder_to_vec;
use crate::builder::file_utils::ta_folder_to_vec;
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
pub async fn build_graph(pe: &PkiEnvironment, cps: &CertificationPathSettings) -> Result<Vec<u8>> {
    let ca_folder = if let Some(ca_folder) = cps.get_certification_authority_folder() {
        ca_folder
    } else {
        error!("ca_folder argument must be provided when generate is specified",);
        return Err(Error::NotFound);
    };

    #[cfg(feature = "remote")]
    let download_folder = if let Some(download_folder) = cps.get_download_folder() {
        download_folder
    } else {
        ca_folder.clone()
    };

    let toi = cps.get_time_of_interest();

    let mut cert_store = CertSource::new();
    let r = if cps.get_cbor_ta_store() {
        ta_folder_to_vec(pe, &ca_folder, &mut cert_store, toi)
    } else {
        cert_folder_to_vec(pe, &ca_folder, &mut cert_store, toi)
    };
    if let Err(e) = r {
        error!(
            "Failed to read certificates from {} with error {:?}",
            &ca_folder, e
        );
    }

    #[cfg(feature = "remote")]
    if cps.get_retrieve_from_aia_sia_http() && !cps.get_cbor_ta_store() {
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
                let tmp_vec: Vec<Option<PDVCertificate>> = vec![];
                let r = cert_store.initialize(cps);
                if let Err(e) = r {
                    error!("Failed to populate cert map: {}", e);
                }

                collect_uris_from_aia_and_sia_for_graph_build(&tmp_vec, &mut uris, certs_count);
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
            )
            .await;
            if let Err(e) = r {
                error!("URI fetching failed with {:?}", e);
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
            certs_count = cert_store.num_buffers();
            uris_count = uris.len();
            error!("URI count: {}; Cert count: {}", uris_count, certs_count);
        }
    }

    let r = cert_store.initialize(cps);
    if let Err(e) = r {
        error!(
            "Failed to populate parsed certificate vector with error {:?}",
            e
        );
    }

    if cert_store.num_buffers() == 0 {
        error!("No certificates were read, so no partial paths were found and no CBOR certificate store will be generated"
            );
        return Err(Error::NotFound);
    }

    if !cps.get_cbor_ta_store() {
        cert_store.find_all_partial_paths(pe, cps);
    }

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
                        "Failed to read CBOR data from {} with {:?}. Continuing without it.",
                        filename, e
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
    ta_folder_to_vec(&pe, &ta_store_folder, &mut ta_store, 0).unwrap();
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

    cps.set_retrieve_from_aia_sia_http(false);
    cps.set_certification_authority_folder(ca_store_folder.clone());
    pe.add_trust_anchor_source(Box::new(ta_store.clone()));
    let cbor = build_graph(&pe, &cps).await;
    assert!(cbor.is_ok());
    let cert_source = match CertSource::new_from_cbor(cbor.unwrap().as_slice()) {
        Ok(cbor_data) => cbor_data,
        Err(e) => {
            panic!("Failed to parse CBOR file: {}", e)
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
            panic!("Failed to parse CBOR file: {}", e)
        }
    };
    assert_eq!(3, cert_source.len());
}
