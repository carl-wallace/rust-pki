//! Contains miscellaneous utility functions

use crate::pitt_file_utils::*;
use crate::pitt_uri_utils::fetch_to_buffer;
use crate::Pittv3Args;
use certval::cert_source::*;
use certval::pdv_utilities::collect_uris_from_aia_and_sia;
use certval::ta_source::TaSource;
use certval::PeLogLevels;
use certval::*;
use der::{Decodable, DecodeValue, Decoder};
use log::{debug, error, info, warn};
use serde_json::Result;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use x509::trust_anchor_format::TrustAnchorChoice;
use x509::{
    Certificate, GeneralName, PKIX_AD_CA_ISSUERS, PKIX_AD_CA_REPOSITORY,
    PKIX_PE_AUTHORITYINFOACCESS, PKIX_PE_SUBJECTINFOACCESS,
};

/// `log_message` provides a logging function that can be added to a
/// [`PkiEnvironment`](../certval/pki_environment/struct.PkiEnvironment.html) instance for use
/// throughout the certification path builder, validator and PITTv3 application.
pub fn log_message(level: &PeLogLevels, message: &str) {
    if &PeLogLevels::PeError == level {
        error!("{}", message);
    } else if &PeLogLevels::PeWarn == level {
        warn!("{}", message);
    } else if &PeLogLevels::PeInfo == level {
        info!("{}", message);
    } else {
        debug!("{}", message);
    }
}

/// `collect_uris_from_aia_and_sia_for_graph_build` accepts an array of optional certs and populates
/// an array of strings representing unique http and https URIs from AIA or SIA extensions found in
/// the certs.
///
/// The array features optional slots because buffers that don't parse when deserializing are set to
/// None to keep the indices in sync). A start index serves to avoid re-reviewing certificates when
/// processing URIs in a loop until no additional certificates are found.
pub fn collect_uris_from_aia_and_sia_for_graph_build(
    certs: &[Option<PDVCertificate>],
    uris: &mut Vec<String>,
    start_index: usize,
) {
    for c in certs.iter().skip(start_index).flatten() {
        collect_uris_from_aia_and_sia(c, uris);
    }
}

/// `collect_uris_from_aia_and_sia_from_ta` accepts a trust anchor and returns unique URIs retrieved
/// from AIA and/or SIA extensions, if present.
pub fn collect_uris_from_aia_and_sia_from_ta(cert: &PDVTrustAnchorChoice, uris: &mut Vec<String>) {
    let aia_ext = cert.get_extension(&PKIX_PE_AUTHORITYINFOACCESS);
    if let Ok(Some(PDVExtension::AuthorityInfoAccessSyntax(aia))) = aia_ext {
        for ad in aia {
            if PKIX_AD_CA_ISSUERS == ad.access_method {
                if let GeneralName::UniformResourceIdentifier(uri) = &ad.access_location {
                    let s = uri.to_string();
                    if !uris.contains(&s) && s.starts_with("http") {
                        uris.push(uri.to_string());
                    }
                }
            }
        }
    }
    let sia_ext = cert.get_extension(&PKIX_PE_SUBJECTINFOACCESS);
    if let Ok(Some(PDVExtension::SubjectInfoAccessSyntax(sia))) = sia_ext {
        for ad in sia {
            if PKIX_AD_CA_REPOSITORY == ad.access_method {
                if let GeneralName::UniformResourceIdentifier(uri) = &ad.access_location {
                    let s = uri.to_string();
                    if !uris.contains(&s) && s.starts_with("http") {
                        uris.push(uri.to_string());
                    }
                }
            }
        }
    }
}

/// `parse_cert` takes a buffer containing a binary DER encoded certificate and returns
/// a [`PDVCertificate`](../certval/pdv_certificate/struct.PDVCertificate.html) containing the
/// parsed certificate if parsing was successful (and None upon failure).
pub fn parse_cert<'a, 'b>(buffer: &'a [u8], filename: &'b str) -> Option<PDVCertificate<'a>> {
    let r = Certificate::from_der(buffer);
    match r {
        Ok(cert) => {
            let mut md = Asn1Metadata::new();
            md.insert(MD_LOCATOR, Asn1MetadataTypes::String(filename.to_string()));
            let mut pdvcert = PDVCertificate {
                encoded_cert: buffer,
                decoded_cert: cert,
                metadata: Some(md),
                parsed_extensions: ParsedExtensions::new(),
            };
            pdvcert.parse_extensions(EXTS_OF_INTEREST);
            Some(pdvcert)
        }
        Err(e) => {
            log_message(
                &PeLogLevels::PeError,
                format!("Failed to parse certificate from {}: {}", filename, e).as_str(),
            );
            None
        }
    }
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
                            "Failed to parse CBOR data from {} with {:?}. Continuing without it.",
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

/// `read_lmm` accepts a string containing the name of a file that notionally contains JSON data that
/// represents last modified information and returns a map of URIs to last modified times.
///
/// The map is expressed as a BTreeMap<String, String> with a URI as the key and last modified time
/// returned from that resource as the value.
pub fn read_lmm(fname: &str) -> BTreeMap<String, String> {
    if Path::exists(Path::new(fname)) {
        if let Ok(json) = get_file_as_byte_vec(Path::new(fname)) {
            let r: Result<BTreeMap<String, String>> = serde_json::from_slice(&json);
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
pub fn read_blocklist(fname: &str) -> Vec<String> {
    if Path::exists(Path::new(fname)) {
        if let Ok(json) = get_file_as_byte_vec(Path::new(fname)) {
            let r: Result<Vec<String>> = serde_json::from_slice(&json);
            if let Ok(blocklist) = r {
                return blocklist;
            }
        }
    }
    vec![]
}

/// `build_graph` takes a string containing the full path of a folder containing binary DER-encoded
/// trust anchor files, a string containing the full path of a folder containing binary
/// DER-encoded CA certificate files, and a time of interest expressed as seconds since Unix epoch
/// and attempts to find all possible partial certification paths.
///
/// The time of interest is used to ignore certificates that are expired at the indicated time (when time
/// of interest value is zero, the validity check is not performed).
pub async fn build_graph(
    pe: &PkiEnvironment<'_>,
    cps: &CertificationPathSettings<'_>,
    args: &Pittv3Args,
) -> Result<Vec<u8>> {
    let ta_folder = if let Some(ta_folder) = &args.ta_folder {
        ta_folder
    } else {
        // this and ca-folder should be checked by the caller
        panic!("ta_folder argument must be provided when generate is specified")
    };

    let ca_folder = if let Some(ca_folder) = &args.ca_folder {
        ca_folder
    } else {
        panic!("ca_folder argument must be provided when generate is specified")
    };

    let download_folder = if let Some(download_folder) = &args.download_folder {
        download_folder
    } else {
        ca_folder
    };

    let lmm_file = if let Some(lmm) = &args.last_modified_map {
        lmm
    } else {
        ""
    };

    let blocklist_file = if let Some(blocklist) = &args.blocklist {
        blocklist
    } else {
        ""
    };

    let mut ta_store = TaSource::new();
    let r = certs_folder_to_map(pe, ta_folder, &mut ta_store.buffers, args.time_of_interest);
    if let Err(e) = r {
        println!("{}", e);
    }
    for (i, cf) in ta_store.buffers.iter().enumerate() {
        let mut decoder = Decoder::new(ta_store.buffers[i].bytes.as_slice()).unwrap();
        let header = decoder.peek_header().unwrap();
        if let Ok(tac) = TrustAnchorChoice::decode_value(&mut decoder, header.length) {
            let mut md = Asn1Metadata::new();
            md.insert(MD_LOCATOR, Asn1MetadataTypes::String(cf.filename.clone()));
            let mut ta = PDVTrustAnchorChoice {
                encoded_ta: ta_store.buffers[i].bytes.as_slice(),
                decoded_ta: tac,
                metadata: Some(md),
                parsed_extensions: ParsedExtensions::new(),
            };
            ta.parse_extensions(EXTS_OF_INTEREST);
            ta_store.tas.push(ta);
        } else {
            println!("Failed to process trust anchor: {}", cf.filename);
        }
    }
    ta_store.index_tas(pe);

    //let mut certs_vec = Vec::new();
    let mut cert_store = CertSource::new();
    let r = certs_folder_to_certfile_vec(
        pe,
        ca_folder,
        &mut cert_store.buffers_and_paths.buffers,
        args.time_of_interest,
    );
    if let Err(e) = r {
        println!(
            "Failed to read certificates from {} with error {:?}",
            ca_folder, e
        );
    }

    if args.chase_aia_and_sia {
        let mut uris = Vec::new();
        let mut certs_count = 0;
        let mut uris_count = 0;
        loop {
            {
                let mut tmp_vec: Vec<Option<PDVCertificate<'_>>> = vec![];
                let r = populate_parsed_cert_vector(
                    pe,
                    &cert_store.buffers_and_paths,
                    cps,
                    &mut tmp_vec,
                );
                if let Err(e) = r {
                    println!("Failed to populate cert map: {}", e);
                }

                collect_uris_from_aia_and_sia_for_graph_build(&tmp_vec, &mut uris, certs_count);
            }

            let mut blocklist = read_blocklist(blocklist_file);
            let mut lmm = read_lmm(lmm_file);
            let r = fetch_to_buffer(
                pe,
                &uris,
                download_folder,
                &mut cert_store.buffers_and_paths.buffers,
                uris_count,
                &mut lmm,
                &mut blocklist,
                args.time_of_interest,
            )
            .await;
            if let Err(e) = r {
                println!("URI fetching failed with {:?}", e);
            }
            let json_lmm = serde_json::to_string(&lmm);
            if !lmm_file.is_empty() {
                if let Ok(json_lmm) = &json_lmm {
                    fs::write(lmm_file, json_lmm).expect("Unable to write last modified map file");
                }
            }

            let json_blocklist = serde_json::to_string(&blocklist);
            if !blocklist_file.is_empty() {
                if let Ok(json_blocklist) = &json_blocklist {
                    fs::write(blocklist_file, json_blocklist)
                        .expect("Unable to write blocklist file");
                }
            }

            // let r = certs_folder_to_certfile_vec(
            //     download_folder,
            //     &mut cert_store.buffers_and_paths.buffers,
            // );
            // if let Err(e) = r {
            //     println!("Processing URI folder failed with {:?}", e);
            // }
            if certs_count == cert_store.buffers_and_paths.buffers.len() {
                break;
            }
            certs_count = cert_store.buffers_and_paths.buffers.len();
            uris_count = uris.len();
            println!("URI count: {}; Cert count: {}", uris_count, certs_count);
        }
    }

    let r = populate_parsed_cert_vector(
        pe,
        &cert_store.buffers_and_paths,
        cps,
        &mut cert_store.certs,
    );
    if let Err(e) = r {
        println!(
            "Failed to populate parsed certificate vector with error {:?}",
            e
        );
    }

    cert_store.find_all_partial_paths(pe, &ta_store, cps);

    let buffer = cert_store
        .serialize_partial_paths(pe, CertificationPathBuilderFormats::Cbor)
        .unwrap();
    Ok(buffer)
}

/// Returns number of seconds since Unix epoch upon success and zero upon failure. This is used by
/// [`Pittv3Args`] to establish a default value for the time-of-interest option.
pub fn get_now_as_unix_epoch() -> u64 {
    if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {
        n.as_secs()
    } else {
        0
    }
}
