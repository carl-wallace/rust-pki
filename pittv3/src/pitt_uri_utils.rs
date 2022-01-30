//! Contains utility functions related to downloading artifacts from URIs
//!
use certval::cert_source::CertFile;
use certval::pdv_utilities::{is_self_signed_with_buffer, valid_at_time};
use certval::PeLogLevels::*;
use certval::{PeLogLevels, PkiEnvironment};
use der::{Decodable, Encodable};
use error_chain::error_chain;
use pkcs7::cryptographic_message_syntax2004::*;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use x509::Certificate;

error_chain! {
     foreign_links {
         Io(std::io::Error);
         HttpRequest(reqwest::Error);
     }
}

/// `save_certs_from_p7` takes a buffer that notionally contains a degenerate certs-only SignedData
/// message and returns buffers containing the resulting certificates via the `buffers` parameter,
/// discarding any duplicates.
///
/// A file containing the certificate is written to a location that uses the filename parameter as
/// a base to which an index is added before saving via [`save_cert`]. Certificates that are not
/// valid at the indicated time of interest are discarded as well.
fn save_certs_from_p7(
    pe: &PkiEnvironment,
    filename: &Path,
    bytes: &[u8],
    target: &str,
    buffers: &mut Vec<CertFile>,
    time_of_interest: u64,
) -> bool {
    let mut at_least_one_saved = false;
    let ci = ContentInfo2004::from_der(bytes);
    if let Ok(ci) = ci {
        if let Some(any) = ci.content {
            if let Ok(content) = any.to_vec() {
                let sd = SignedData::from_der(content.as_slice());
                match sd {
                    Ok(sd) => {
                        for (i, c) in sd.certificates.iter().enumerate() {
                            for a in c {
                                let f = format!("{}_{}.der", filename.to_str().unwrap(), i);
                                if let Ok(enccert) = a.to_vec() {
                                    if save_cert(
                                        pe,
                                        &PathBuf::from_str(&f).unwrap(),
                                        enccert.as_slice(),
                                        target,
                                        buffers,
                                        time_of_interest,
                                    ) {
                                        at_least_one_saved = true;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        pe.log_message(
                            &PeError,
                            format!("Failed to parse SignedData from {} with {:?}", target, e)
                                .as_str(),
                        );
                    }
                }
            }
        }
    }
    at_least_one_saved
}

/// `save_cert` takes a buffer that notionally contains a certificate. if the certificate can be parsed
/// and it is not present in `buffers`, then it is appended to `buffers` and written to `filename`. The
/// file write is best effort. If it fails, life goes on.
fn save_cert(
    pe: &PkiEnvironment,
    filename: &Path,
    bytes: &[u8],
    target: &str,
    buffers: &mut Vec<CertFile>,
    time_of_interest: u64,
) -> bool {
    let mut saved = false;
    let r = Certificate::from_der(bytes);
    match r {
        Ok(cert) => {
            if let Err(_e) = valid_at_time(pe, &cert.tbs_certificate, time_of_interest, true) {
                pe.log_message(
                    &PeLogLevels::PeDebug,
                    format!("Ignoring certificate downloaded from {} as not valid at indicated time of interest ({})", target, time_of_interest).as_str(),
                );
                return saved;
            }

            if is_self_signed_with_buffer(pe, &cert, bytes) {
                pe.log_message(
                    &PeLogLevels::PeDebug,
                    format!(
                        "Ignoring certificate downloaded from {} as self-signed",
                        target
                    )
                    .as_str(),
                );
                return saved;
            }

            let cf = CertFile {
                bytes: bytes.to_vec(),
                filename: target.to_string(),
            };
            if !buffers.contains(&cf) {
                buffers.push(cf);
                saved = true;

                match File::create(filename) {
                    Ok(mut dest) => {
                        let r = dest.write_all(bytes);
                        if let Err(e) = r {
                            pe.log_message(
                                &PeError,
                                format!("Failed to copy {} with {:?}", target, e).as_str(),
                            );
                        }
                    }
                    Err(e) => {
                        pe.log_message(
                            &PeLogLevels::PeError,
                            format!(
                                "Failed to save {} with error: {}",
                                filename.to_str().unwrap(),
                                e
                            )
                            .as_str(),
                        );
                    }
                }
            } else {
                pe.log_message(
                    &PeLogLevels::PeDebug,
                    format!(
                        "Ignoring certificate downloaded from {} as already available",
                        target
                    )
                    .as_str(),
                );
            }
        }
        Err(e) => {
            pe.log_message(
                &PeLogLevels::PeError,
                format!("Failed to parse certificate from {} with: {:?}", target, e).as_str(),
            );
        }
    }
    saved
}

/// fetch_to_buffer takes an array of URIs to process along with with a folder name and buffer array
/// to receive downloaded certificates.
///
/// Other parameters are used to limit actions taken by this function. The `start_index` indicates how
/// many URIs to skip in the `uris` parameter. The `last_mod_map` and `blocklist` limit interactions
/// with remote resources, potentially avoiding downloads for resource that have not changed since
/// previous download or avoiding connections to blocklisted resources. The `time_of_interest`` is used
/// to discard certificates that are not time valid at the time of interest.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_to_buffer(
    pe: &PkiEnvironment<'_>,
    uris: &[String],
    folder: &str,
    buffers: &mut Vec<CertFile>,
    start_index: usize,
    last_mod_map: &mut BTreeMap<String, String>,
    blocklist: &mut Vec<String>,
    time_of_interest: u64,
) -> Result<()> {
    // Downloaded artifacts are saved for future use, create a path object for that folder
    let path = Path::new(folder);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    // URIs may be piled up by the caller wiht the start_index used to ignore URIs that were
    // already processed.
    for target in uris.iter().skip(start_index) {
        // skip targets that have been placed on the blocklist (like URIs from an intranet)
        if blocklist.contains(target) {
            pe.log_message(
                &PeLogLevels::PeError,
                format!("Skipping due to blocklist: {}", target).as_str(),
            );
            continue;
        } else {
            pe.log_message(
                &PeLogLevels::PeInfo,
                format!("Downloading {}", target).as_str(),
            );
        }

        // Read saved last modified time, if any, for use in avoiding unnecessary download below
        let h = if last_mod_map.contains_key(target) {
            &last_mod_map[target]
        } else {
            ""
        };

        let response = if h.is_empty() {
            client.get(target).send().await
        } else {
            client
                .get(target)
                .header("If-Modified-Since", h)
                .send()
                .await
        };

        // read the content type (though this is such a mess may want to just try cert then try
        // PKCS7, or vice versa, instead of bothering)
        let mut content_type = String::new();
        match response {
            Ok(response) => {
                let fname_from_response = response
                    .url()
                    .path_segments()
                    .and_then(|segments| segments.last())
                    .and_then(|name| if name.is_empty() { None } else { Some(name) })
                    .unwrap_or("tmp.bin");

                // seen it before, skip it now
                if 304 == response.status() {
                    continue;
                }

                let last_mod = response.headers().get("Last-Modified");
                if let Some(last_mod) = last_mod {
                    if let Ok(s) = last_mod.to_str() {
                        last_mod_map.insert(target.to_string(), s.to_string());
                    }
                }

                let content_type_header = response.headers().get("Content-Type");
                if let Some(content_type_val) = content_type_header {
                    if let Ok(s) = content_type_val.to_str() {
                        content_type = s.to_string();
                    }
                }

                // some things "succeed" when handing us an HTML page with an error. skip those.
                if "text/html" == content_type {
                    continue;
                }

                let fname = path.join(fname_from_response);

                let content = &response.bytes().await;
                if let Ok(bytes) = content {
                    pe.log_message(
                        &PeLogLevels::PeDebug,
                        format!("Downloaded buffer {}", target).as_str(),
                    );

                    // save_certs_from_p7
                    if "application/pkcs7-mime" == content_type {
                        save_certs_from_p7(
                            pe,
                            &fname,
                            bytes.as_ref(),
                            target,
                            buffers,
                            time_of_interest,
                        );
                    } else if "application/x-x509-ca-cert" == content_type {
                        save_cert(
                            pe,
                            &fname,
                            bytes.as_ref(),
                            target,
                            buffers,
                            time_of_interest,
                        );
                    } else {
                        let r = Certificate::from_der(bytes.as_ref());
                        match r {
                            Ok(_) => {
                                save_cert(
                                    pe,
                                    &fname,
                                    bytes.as_ref(),
                                    target,
                                    buffers,
                                    time_of_interest,
                                );
                            }
                            Err(_) => {
                                save_certs_from_p7(
                                    pe,
                                    &fname,
                                    bytes.as_ref(),
                                    target,
                                    buffers,
                                    time_of_interest,
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                pe.log_message(
                    &PeLogLevels::PeError,
                    format!("Failed to process {} with {:?}", target, e).as_str(),
                );
                if !blocklist.contains(target) {
                    blocklist.push(target.clone());
                }
            }
        }
    }
    Ok(())
}
