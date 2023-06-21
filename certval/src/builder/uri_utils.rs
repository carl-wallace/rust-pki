//! Contains utility functions related to downloading artifacts from URIs
//!

use const_oid::db::rfc5912::{
    ID_AD_CA_ISSUERS, ID_AD_CA_REPOSITORY, ID_PE_AUTHORITY_INFO_ACCESS, ID_PE_SUBJECT_INFO_ACCESS,
};
use x509_cert::ext::pkix::name::GeneralName;

use crate::util::pdv_utilities::*;
use crate::*;

use cfg_if::cfg_if;
cfg_if! {
    if #[cfg(feature = "remote")] {
        use crate::{Error, PeLogLevels, PeLogLevels::*, PkiEnvironment, Result};
        use crate::source::cert_source::CertFile;
        use crate::util::logging::log_message;
        use crate::util::pdv_utilities::{is_self_signed_with_buffer, valid_at_time};
        use alloc::collections::BTreeMap;
        use der::{Decode, Encode};
        use x509_cert::Certificate;
        use std::fs::File;
        use std::io::Write;
        use std::path::{PathBuf, Path};
        use std::str::FromStr;
        use std::time::Duration;
    }
}

/// `save_certs_from_p7` takes a buffer that notionally contains a degenerate certs-only SignedData
/// message and returns buffers containing the resulting certificates via the `buffers` parameter,
/// discarding any duplicates.
///
/// A file containing the certificate is written to a location that uses the filename parameter as
/// a base to which an index is added before saving via [`save_cert`]. Certificates that are not
/// valid at the indicated time of interest are discarded as well.
#[cfg(feature = "remote")]
fn save_certs_from_p7(
    pe: &PkiEnvironment<'_>,
    filename: &Path,
    bytes: &[u8],
    target: &str,
    buffers: &mut Vec<CertFile>,
    time_of_interest: u64,
) -> bool {
    let mut at_least_one_saved = false;
    let filename = if let Some(fname) = filename.to_str() {
        fname
    } else {
        return false;
    };

    let ci = ContentInfo2004::from_der(bytes);
    if let Ok(ci) = ci {
        if let Ok(content) = ci.content.to_vec() {
            let sd = SignedData::from_der(content.as_slice());
            match sd {
                Ok(sd) => {
                    for (i, c) in sd.certificates.iter().enumerate() {
                        for a in c {
                            let f = format!("{}_{}.der", filename, i);
                            let pb = if let Ok(pb) = PathBuf::from_str(&f) {
                                pb
                            } else {
                                return false;
                            };
                            if let Ok(enccert) = a.to_vec() {
                                if save_cert(
                                    pe,
                                    &pb,
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
                    log_message(
                        &PeError,
                        format!("Failed to parse SignedData from {} with {:?}", target, e).as_str(),
                    );
                }
            }
        }
    }
    at_least_one_saved
}

/// `save_cert` takes a buffer that notionally contains a certificate. if the certificate can be parsed
/// and it is not present in `buffers`, then it is appended to `buffers` and written to `filename`. The
/// file write is best effort. If it fails, life goes on.
#[cfg(feature = "remote")]
fn save_cert(
    pe: &PkiEnvironment<'_>,
    filename: &Path,
    bytes: &[u8],
    target: &str,
    buffers: &mut Vec<CertFile>,
    time_of_interest: u64,
) -> bool {
    let mut saved = false;
    let filename = if let Some(fname) = filename.to_str() {
        fname
    } else {
        return false;
    };

    let r = Certificate::from_der(bytes);
    match r {
        Ok(cert) => {
            if let Err(_e) = valid_at_time(&cert.tbs_certificate, time_of_interest, true) {
                log_message(
                    &PeLogLevels::PeDebug,
                    format!("Ignoring certificate downloaded from {} as not valid at indicated time of interest ({})", target, time_of_interest).as_str(),
                );
                return saved;
            }

            if is_self_signed_with_buffer(pe, &cert, bytes) {
                log_message(
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
                            log_message(
                                &PeError,
                                format!("Failed to copy {} with {:?}", target, e).as_str(),
                            );
                        }
                    }
                    Err(e) => {
                        log_message(
                            &PeLogLevels::PeError,
                            format!("Failed to save {} with error: {}", filename, e).as_str(),
                        );
                    }
                }
            } else {
                log_message(
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
            log_message(
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
#[cfg(feature = "remote")]
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

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(_e) => return Err(Error::Unrecognized),
    };

    // URIs may be piled up by the caller wiht the start_index used to ignore URIs that were
    // already processed.
    for target in uris.iter().skip(start_index) {
        // skip targets that have been placed on the blocklist (like URIs from an intranet)
        if blocklist.contains(target) {
            log_message(
                &PeLogLevels::PeError,
                format!("Skipping due to blocklist: {}", target).as_str(),
            );
            continue;
        } else {
            log_message(
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
                    //TODO read buffer from folder
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
                    log_message(
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
                log_message(
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

/// `collect_uris_from_aia_and_sia_for_graph_build` accepts an array of optional certs and populates
/// an array of strings representing unique http and https URIs from AIA or SIA extensions found in
/// the certs.
///
/// The array features optional slots because buffers that don't parse when deserializing are set to
/// None to keep the indices in sync. A start index serves to avoid re-reviewing certificates when
/// processing URIs in a loop until no additional certificates are found.
pub fn collect_uris_from_aia_and_sia_for_graph_build<'a>(
    certs: &[Option<PDVCertificate>],
    uris: &mut Vec<String>,
    start_index: usize,
) {
    for c in certs.iter().skip(start_index).flatten() {
        collect_uris_from_aia_and_sia(c, uris);
    }
}

/// `collect_uris_from_aia_and_sia_from_ta` accepts a trust anchor and returns a vector of unique
/// http and https URIs retrieved from AIA and/or SIA extensions, if present.
pub fn collect_uris_from_aia_and_sia_from_ta<'a>(
    cert: &PDVTrustAnchorChoice,
    uris: &mut Vec<String>,
) {
    let aia_ext = cert.get_extension(&ID_PE_AUTHORITY_INFO_ACCESS);
    if let Ok(Some(PDVExtension::AuthorityInfoAccessSyntax(aia))) = aia_ext {
        for ad in &aia.0 {
            if ID_AD_CA_ISSUERS == ad.access_method {
                if let GeneralName::UniformResourceIdentifier(uri) = &ad.access_location {
                    let s = uri.to_string();
                    if !uris.contains(&s) && s.starts_with("http") {
                        uris.push(uri.to_string());
                    }
                }
            }
        }
    }
    let sia_ext = cert.get_extension(&ID_PE_SUBJECT_INFO_ACCESS);
    if let Ok(Some(PDVExtension::SubjectInfoAccessSyntax(sia))) = sia_ext {
        for ad in &sia.0 {
            if ID_AD_CA_REPOSITORY == ad.access_method {
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
