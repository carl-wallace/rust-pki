//! Contains utility functions related to downloading artifacts from URIs
//!

use const_oid::db::rfc5912::{
    ID_AD_CA_ISSUERS, ID_AD_CA_REPOSITORY, ID_PE_AUTHORITY_INFO_ACCESS, ID_PE_SUBJECT_INFO_ACCESS,
};
use x509_cert::ext::pkix::name::GeneralName;

use crate::*;

#[cfg(feature = "remote")]
use log::{debug, error, info};

#[cfg(feature = "remote")]
use cms::{content_info::ContentInfo, signed_data::SignedData};

use cfg_if::cfg_if;
cfg_if! {
    if #[cfg(feature = "remote")] {
        use crate::{Error, PkiEnvironment, Result};
        use crate::source::cert_source::CertFile;
        use crate::util::pdv_utilities::{
            is_self_signed_with_buffer, trim_to_outer_der_sequence, valid_at_time,
        };
        use alloc::collections::BTreeMap;
        use der::{Decode, Encode};
        use x509_cert::certificate::{CertificateInner,Raw};
        use std::fs::File;
        use std::io::Write;
        use std::path::{PathBuf, Path};
        use std::str::FromStr;
        use std::sync::OnceLock;
        use std::time::Duration;
    }
}

/// Returns a process-wide [`reqwest::Client`] shared across every artifact download (CRL, OCSP, and
/// AIA/SIA fetches). Building a fresh client per request throws away reqwest's connection pool,
/// forcing a new TCP+TLS handshake for every fetch on the enrollment hot path; a single pooled
/// client amortizes connection setup across requests. The shared client carries no default timeout
/// -- callers apply a per-request bound via [`reqwest::RequestBuilder::timeout`], since the CRL path
/// takes a caller-supplied timeout while OCSP/AIA use a fixed one.
///
/// Returns `None` (logged once) if the client could not be built -- e.g. the TLS backend failed to
/// initialize -- which callers translate into a network error.
#[cfg(feature = "remote")]
pub(crate) fn shared_http_client() -> Option<&'static reqwest::Client> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| match reqwest::Client::builder().build() {
            Ok(client) => Some(client),
            Err(e) => {
                error!("Failed to build the shared HTTP client: {e}");
                None
            }
        })
        .as_ref()
}

/// Reads a fetched HTTP response body into memory while enforcing `max_bytes` as it streams, so a
/// hostile or misconfigured responder cannot exhaust memory with an unbounded body. Reading the whole
/// body up front (reqwest's `bytes()`) allocates it in full before any size or parse check runs, so
/// the cap must be applied at ingest -- here, over the streamed chunks.
///
/// The `Content-Length` header is attacker-controlled and absent on chunked responses, so it serves
/// only as a fast-fail hint (a claimed length over the cap is rejected before any body is read); the
/// running byte count over the streamed chunks is the authoritative guard. `label` names the source
/// in log messages. Returns [`Error::LengthError`] if the body exceeds `max_bytes` and
/// [`Error::NetworkError`] on a transport error mid-stream.
#[cfg(feature = "remote")]
pub(crate) async fn read_capped_body(
    mut response: reqwest::Response,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>> {
    if let Some(len) = response.content_length() {
        if len > max_bytes {
            debug!("{label} reported a {len}-byte body exceeding the {max_bytes}-byte cap");
            return Err(Error::LengthError);
        }
    }

    let mut buf: Vec<u8> = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len() as u64 + chunk.len() as u64 > max_bytes {
                    debug!("{label} streamed a body exceeding the {max_bytes}-byte cap");
                    return Err(Error::LengthError);
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => {
                debug!("Failed to read body from {label} with {e}");
                return Err(Error::NetworkError);
            }
        }
    }
    Ok(buf)
}

/// Name of the map recording what each URI last wrote into a download folder.
///
/// Beside the artifacts rather than beside the last-modified map, because its entries are relative
/// to this folder and so travel with it.
#[cfg(feature = "remote")]
pub const FETCHED_ARTIFACTS_NAME: &str = "fetched_artifacts.json";

/// Reads the URI-to-artifact map from `path`, or an empty map when there is none to read.
///
/// **An absent or unreadable map degrades to today's behaviour and not to a wrong answer.** With no
/// entry for a URI the conditional request is simply not made, so the artifact is fetched again --
/// a redundant transfer at worst. That is also the migration path: every existing download folder
/// starts without one.
#[cfg(feature = "remote")]
fn read_fetched_artifacts(path: &Path) -> BTreeMap<String, Vec<String>> {
    let Ok(bytes) = std::fs::read(path) else {
        return BTreeMap::new();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

/// Writes the URI-to-artifact map, best effort.
///
/// A write that fails costs the next run a re-fetch, which is the same cost as never having written
/// it, so it is logged rather than surfaced.
#[cfg(feature = "remote")]
fn write_fetched_artifacts(path: &Path, artifacts: &BTreeMap<String, Vec<String>>) {
    match serde_json::to_vec_pretty(artifacts) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, json) {
                debug!("Failed to write {} with {e}", path.display());
            }
        }
        Err(e) => debug!("Failed to serialize the fetched-artifact map with {e:?}"),
    }
}

/// `save_certs_from_p7` takes a buffer that notionally contains a degenerate certs-only SignedData
/// message and returns buffers containing the resulting certificates via the `buffers` parameter,
/// discarding any duplicates.
///
/// A file containing the certificate is written to a location that uses the filename parameter as
/// a base to which an index is added before saving via [`save_cert`]. Certificates that are not
/// valid at the indicated time of interest are discarded as well.
///
/// `filename` is `None` when the caller named no folder to keep downloads in; see [`save_cert`].
/// The certificates still reach `buffers`.
#[cfg(feature = "remote")]
fn save_certs_from_p7(
    pe: &PkiEnvironment,
    filename: Option<&Path>,
    bytes: &[u8],
    target: &str,
    buffers: &mut dyn CertVector,
    time_of_interest: TimeOfInterest,
    written: &mut Vec<String>,
) -> bool {
    let mut at_least_one_saved = false;
    let filename = filename.and_then(|f| f.to_str());

    match ContentInfo::from_der(bytes) {
        Ok(ci) => {
            if let Ok(content) = ci.content.to_der() {
                let sd = SignedData::from_der(content.as_slice());
                match sd {
                    Ok(sd) => {
                        for c in sd.certificates.iter() {
                            for (i, a) in c.0.iter().enumerate() {
                                // One name per certificate in the message, or none at all when
                                // there is nowhere to write them. The index counts certificates
                                // within the set, not sets: `certificates` is an `Option`, so
                                // enumerating it yields at most one item and every certificate in a
                                // bundle was written to `_0`, each overwriting the last. The run
                                // that fetched them was unaffected -- they all reach `buffers` --
                                // so this cost only reuse, and only a later run noticed.
                                let pb = filename.map(|f| {
                                    #[allow(irrefutable_let_patterns)]
                                    let Ok(pb) = PathBuf::from_str(&format!("{f}_{i}.der"));
                                    pb
                                });
                                if let Ok(enccert) = a.to_der() {
                                    if save_cert(
                                        pe,
                                        pb.as_deref(),
                                        enccert.as_slice(),
                                        target,
                                        buffers,
                                        time_of_interest,
                                        written,
                                    ) {
                                        at_least_one_saved = true;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse SignedData from {target} with {e:?}");
                    }
                }
            }
        }
        Err(e) => {
            error!("Failed to parse ContentInfo from {target} with {e:?}");
        }
    }
    at_least_one_saved
}

/// `save_cert` takes a buffer that notionally contains a certificate. if the certificate can be parsed,
/// and it is not present in `buffers`, then it is appended to `buffers` and, when `filename` names
/// somewhere to put it, written there. The attempt to write a file is "best effort". If it fails,
/// life goes on.
///
/// `filename` is `None` when the caller named no folder to keep downloads in. The certificate still
/// reaches `buffers`, which is what the run builds paths from; only the copy on disk is skipped.
/// This is a distinct case from a write that fails, and has to be, because the path built from an
/// empty folder is a bare relative name that would drop files into the process's working directory.
#[cfg(feature = "remote")]
fn save_cert(
    pe: &PkiEnvironment,
    filename: Option<&Path>,
    bytes: &[u8],
    target: &str,
    buffers: &mut dyn CertVector,
    time_of_interest: TimeOfInterest,
    written: &mut Vec<String>,
) -> bool {
    let mut saved = false;
    let filename = filename.and_then(|f| f.to_str());

    let r = CertificateInner::from_der(bytes);
    match r {
        Ok(cert) => {
            if let Err(_e) = valid_at_time(cert.tbs_certificate(), time_of_interest, true) {
                debug!("Ignoring certificate downloaded from {target} as not valid at indicated time of interest ({time_of_interest})");
                return saved;
            }

            if is_self_signed_with_buffer(pe, &cert, bytes) {
                debug!("Ignoring certificate downloaded from {target} as self-signed");
                return saved;
            }

            // Store what the certificate actually is, not what arrived around it. A certificate
            // read from a file reaches the pool through decode_pem_to_der, which ends in this same
            // trim, so normalizing here keeps the two entry paths producing identical bytes for an
            // identical certificate -- and CertFile equality, which the deduplication just below and
            // the dynamic-building loop's "did the pool grow" test both rest on, is byte equality.
            let cf = CertFile {
                bytes: trim_to_outer_der_sequence(bytes.to_vec()),
                filename: target.to_string(),
            };
            if !buffers.contains(&cf) {
                buffers.push(cf);
                saved = true;

                if let Some(filename) = filename {
                    match File::create(filename) {
                        Ok(mut dest) => {
                            let r = dest.write_all(bytes);
                            match r {
                                // Recorded only on a write that succeeded: the map is a claim that
                                // the file is there, and a claim made about a failed write is the
                                // very thing this exists to stop.
                                Ok(()) => written.push(filename.to_string()),
                                Err(e) => error!("Failed to copy {target} with {e:?}"),
                            }
                        }
                        Err(e) => {
                            error!("Failed to save {filename} with error: {e}");
                        }
                    }
                }
            } else {
                debug!("Ignoring certificate downloaded from {target} as already available");
            }
        }
        Err(e) => {
            error!("Failed to parse certificate from {target} with: {e:?}");
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
    pe: &PkiEnvironment,
    uris: &[String],
    folder: &str,
    buffers: &mut dyn CertVector,
    start_index: usize,
    last_mod_map: &mut BTreeMap<String, String>,
    blocklist: &mut Vec<String>,
    time_of_interest: TimeOfInterest,
    max_bytes: u64,
) -> Result<()> {
    // Downloaded artifacts are saved for future use, create a path object for that folder. An empty
    // folder means the caller has nowhere to keep them -- a run writing fetched certificates to a
    // CAPI store rather than to disk, for one -- and is not the same as a folder that turns out to
    // be unwritable: joining a name onto an empty path yields a bare relative name, which would
    // scatter downloads through the process's working directory.
    let path = match folder.is_empty() {
        true => None,
        false => Some(Path::new(folder)),
    };

    // What each URI last produced in this folder, so a 304 can be answered from disk instead of
    // losing the artifact. Kept beside the artifacts rather than beside the last-modified map: the
    // names are relative to this folder, so moving or copying a download folder carries the record
    // with it instead of invalidating it.
    let artifacts_path = path.map(|p| p.join(FETCHED_ARTIFACTS_NAME));
    let mut artifacts: BTreeMap<String, Vec<String>> = artifacts_path
        .as_deref()
        .map(read_fetched_artifacts)
        .unwrap_or_default();

    let client = match shared_http_client() {
        Some(client) => client,
        None => return Err(Error::Unrecognized),
    };

    // URIs may be piled up by the caller wiht the start_index used to ignore URIs that were
    // already processed.
    for target in uris.iter().skip(start_index) {
        // skip targets that have been placed on the blocklist (like URIs from an intranet)
        if blocklist.contains(target) {
            error!("Skipping due to blocklist: {target}");
            continue;
        }

        // The files this URI produced last time, if they are all still there. A 304 is only worth
        // asking for when the answer can be honoured: the last-modified map on its own asserts that
        // a copy exists somewhere and nothing checks, so a folder that has been tidied or moved
        // leaves the next run told "unchanged" and coming away with nothing.
        //
        // Rather than re-requesting after an unhonourable 304, the conditional request is simply not
        // made -- the same outcome without a wasted round trip, and it cannot strand material.
        let readable: Vec<String> = match (path, artifacts.get(target)) {
            (Some(folder), Some(names)) => {
                let all_present = names.iter().all(|n| folder.join(n).is_file());
                match all_present {
                    true => names.clone(),
                    false => vec![],
                }
            }
            _ => vec![],
        };

        // Read saved last modified time, if any, for use in avoiding unnecessary download below
        let h = match readable.is_empty() {
            true => "",
            false => last_mod_map.get(target).map(|s| s.as_str()).unwrap_or(""),
        };

        // Announced after the last-modified map is consulted rather than before it, and as a check
        // rather than a download, because a URI the map knows is usually answered 304 with no bytes
        // moving. Saying "Downloading" ahead of the request made a run that transferred nothing read
        // as one re-fetching everything, and made the empty download folder that a 304 leaves behind
        // look like a second fault. Every URI reaching here now says what became of it: checked,
        // then fetched, unchanged, or skipped.
        if h.is_empty() {
            info!("Fetching {target}");
        } else {
            info!("Checking {target} (If-Modified-Since: {h})");
        }

        let response = if h.is_empty() {
            client
                .get(target)
                .timeout(Duration::from_secs(10))
                .send()
                .await
        } else {
            client
                .get(target)
                .header("If-Modified-Since", h)
                .timeout(Duration::from_secs(10))
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
                    .and_then(|mut segments| segments.next_back())
                    .filter(|&name| !name.is_empty())
                    .unwrap_or("tmp.bin");

                // Seen it before. Nothing was transferred, so the copies already on disk are what
                // this URI contributes to the run -- read back rather than skipped, which is what
                // made a warm cache quietly narrow the pool it was supposed to widen.
                if 304 == response.status() {
                    let mut back = 0;
                    for name in &readable {
                        let Some(folder) = path else { continue };
                        let Ok(bytes) = std::fs::read(folder.join(name)) else {
                            continue;
                        };
                        // Through the same gate a fresh download goes through, so a certificate that
                        // has since expired or that this run would refuse is refused here too. The
                        // file is already on disk, so nothing is written again.
                        let mut ignored = vec![];
                        if save_cert(
                            pe,
                            None,
                            bytes.as_slice(),
                            target,
                            buffers,
                            time_of_interest,
                            &mut ignored,
                        ) {
                            back += 1;
                        }
                    }
                    info!("Unchanged, {back} artifact(s) read from {folder}: {target}");
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
                    info!("Skipping an HTML response rather than an artifact: {target}");
                    continue;
                }

                let fname = path.map(|p| p.join(fname_from_response));

                match read_capped_body(response, max_bytes, target).await {
                    Ok(bytes) => {
                        info!("Fetched {} bytes from {target}", bytes.len());
                        // What this URI writes on this pass, recorded so a later 304 can be answered
                        // from the folder rather than losing the artifact.
                        let mut written: Vec<String> = vec![];

                        // save_certs_from_p7
                        if "application/pkcs7-mime" == content_type {
                            save_certs_from_p7(
                                pe,
                                fname.as_deref(),
                                bytes.as_ref(),
                                target,
                                buffers,
                                time_of_interest,
                                &mut written,
                            );
                        } else if "application/x-x509-ca-cert" == content_type {
                            save_cert(
                                pe,
                                fname.as_deref(),
                                bytes.as_ref(),
                                target,
                                buffers,
                                time_of_interest,
                                &mut written,
                            );
                        } else {
                            let r = CertificateInner::<Raw>::from_der(bytes.as_ref());
                            match r {
                                Ok(_) => {
                                    save_cert(
                                        pe,
                                        fname.as_deref(),
                                        bytes.as_ref(),
                                        target,
                                        buffers,
                                        time_of_interest,
                                        &mut written,
                                    );
                                }
                                Err(_) => {
                                    save_certs_from_p7(
                                        pe,
                                        fname.as_deref(),
                                        bytes.as_ref(),
                                        target,
                                        buffers,
                                        time_of_interest,
                                        &mut written,
                                    );
                                }
                            }
                        }

                        // Recorded relative to the folder, so the record survives the folder being
                        // moved or copied. A URI that wrote nothing this pass keeps whatever it
                        // claimed before rather than being cleared: the earlier files may still be
                        // there, and the presence check above is what decides whether they count.
                        let relative: Vec<String> = match path {
                            Some(folder) => written
                                .iter()
                                .filter_map(|w| {
                                    Path::new(w)
                                        .strip_prefix(folder)
                                        .ok()
                                        .and_then(|r| r.to_str())
                                        .map(|r| r.to_string())
                                })
                                .collect(),
                            None => vec![],
                        };
                        if !relative.is_empty() {
                            artifacts.insert(target.to_string(), relative);
                        }
                    }
                    Err(e) => {
                        error!("Failed to download {target} with {e:?}");
                    }
                }
            }
            Err(e) => {
                error!("Failed to process {target} with {e:?}");
                if !blocklist.contains(target) {
                    blocklist.push(target.clone());
                }
            }
        }
    }

    if let Some(p) = artifacts_path.as_deref() {
        write_fetched_artifacts(p, &artifacts);
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
pub fn collect_uris_from_aia_and_sia_for_graph_build(
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
pub fn collect_uris_from_aia_and_sia_from_ta(cert: &PDVTrustAnchorChoice, uris: &mut Vec<String>) {
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
