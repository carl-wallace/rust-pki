//! Certification path validation shared by the PITTv3 GUI frontends.
//!
//! Built on certval with no-default-features, so this compiles for `wasm32-unknown-unknown` as
//! well as the host: nothing here reaches the filesystem, the network, or the clock beyond
//! `web_time::Instant`. The frontend supplies the trust material as bytes it has already
//! obtained — fetched in the browser, read from disk on the desktop, or handed over by a server —
//! so the same validation path serves every frontend and no frontend forks it.

use std::io::{Cursor, Read};

use certval::*;
use pittv3_lib::report::{CertSummary, NoPathsContext, PathReport, TargetReport};
use web_time::Instant;

// Re-exported so callers taking the validation API from this module keep getting the line type it
// returns; the type itself lives beside the other UI-facing run output.
pub use crate::gui_results::ResultLine;

fn info(text: String) -> ResultLine {
    ResultLine {
        class: "info",
        text,
    }
}
fn ok(text: String) -> ResultLine {
    ResultLine { class: "ok", text }
}
fn err(text: String) -> ResultLine {
    ResultLine { class: "err", text }
}

/// Returns DER bytes given buffers that may be PEM or DER encoded. DER detection accepts
/// SEQUENCE (certificates and the certificate variant of TrustAnchorChoice) plus the context
/// tags that begin the tbsCert and taInfo variants of a DER-encoded RFC 5914 TrustAnchorChoice.
fn maybe_pem(bytes: &[u8]) -> Result<Vec<u8>> {
    if !bytes.is_empty() && matches!(bytes[0], 0x30 | 0xA1 | 0xA2) {
        Ok(bytes.to_vec())
    } else {
        match pem_rfc7468::decode_vec(bytes) {
            Ok(b) => Ok(b.1),
            Err(_e) => Err(Error::Unrecognized),
        }
    }
}

/// A [`PkiEnvironment`] prepared for validation: trust anchors and CA
/// certificates parsed and merged, and — when uploads are present — a partial-path discovery pass
/// completed. Preparing this is the expensive part of a run (parsing stores and, above all,
/// discovering partial paths), so the frontend caches it and reuses it across Validate clicks while
/// the trust anchors, CA certificates and settings are unchanged. Only the target certificates then
/// need differ, and re-validating them skips reparse and rediscovery entirely.
pub struct PreparedValidation {
    /// Fully populated environment with the trust-anchor and certificate sources registered
    pe: PkiEnvironment,
}

/// Prepares a validation environment from an optional baked-in store plus uploaded trust anchors and
/// intermediate CA certificates: one merged trust-anchor store, one merged CA store, and a single
/// partial-path discovery pass when uploads are present (baked stores ship with paths precomputed).
/// This is the heavy step; validate targets against the result with [`validate_prepared`]. Returns
/// the prepared environment plus informational notes, or fatal notes when preparation cannot yield a
/// usable environment (e.g., no trust anchors).
pub fn prepare_validation(
    store: Option<(&str, &[u8], &[u8])>,
    tas: &[(String, Vec<u8>)],
    cas: &[(String, Vec<u8>)],
    cps: &CertificationPathSettings,
    // certval's glob import shadows the 1-arg `Result` alias, so name the 2-arg form explicitly
) -> core::result::Result<(PreparedValidation, Vec<ResultLine>), Vec<ResultLine>> {
    let mut out = vec![];

    // --- trust anchors: baked store (if any) + uploaded TAs (certs or .cbor stores) ---
    let mut ta_store = match store {
        Some((_, ta_cbor, _)) => match TaSource::new_from_cbor(ta_cbor) {
            Ok(t) => t,
            Err(e) => return Err(vec![err(format!("Failed to parse TA store CBOR: {e:?}"))]),
        },
        None => TaSource::new(),
    };
    for (name, bytes) in tas {
        // A `.cbor` trust-anchor store (BuffersAndPaths) merges all of its anchors; new_from_cbor
        // rejects anything else, so a PEM/DER certificate falls through to the single-cert path.
        if let Ok(src) = TaSource::new_from_cbor(bytes) {
            for cf in src.get_tas() {
                ta_store.push(cf);
            }
            continue;
        }
        match maybe_pem(bytes) {
            Ok(der) => ta_store.push(CertFile {
                filename: name.clone(),
                bytes: der,
            }),
            Err(_) => out.push(err(format!(
                "Failed to parse uploaded trust anchor {name} as a PEM/DER certificate or a CBOR store"
            ))),
        }
    }
    if ta_store.is_empty() {
        return Err(vec![err(
            "No trust anchors are available. Select a built-in store or upload at least one trust anchor."
                .to_string(),
        )]);
    }
    if let Err(e) = ta_store.initialize() {
        return Err(vec![err(format!("Failed to initialize TA store: {e:?}"))]);
    }

    // --- one CA store: the baked store's certificates (with their precomputed partial paths) plus
    // any uploaded intermediates, all in a single pool so path discovery can link across them. An
    // empty CA buffer denotes a trust-anchor-only store (ca_url = None). ---
    let mut cert_source = match store {
        Some((_, _, ca_cbor)) if !ca_cbor.is_empty() => match CertSource::new_from_cbor(ca_cbor) {
            Ok(c) => c,
            Err(e) => return Err(vec![err(format!("Failed to parse CA store CBOR: {e:?}"))]),
        },
        _ => CertSource::new(),
    };
    for (name, bytes) in cas {
        // A `.cbor` CA store merges all of its buffers; otherwise treat as a single PEM/DER cert.
        if let Ok(src) = CertSource::new_from_cbor(bytes) {
            for cf in src.get_buffers() {
                cert_source.push(cf);
            }
            continue;
        }
        match maybe_pem(bytes) {
            Ok(der) => cert_source.push(CertFile {
                filename: name.clone(),
                bytes: der,
            }),
            Err(_) => out.push(err(format!(
                "Failed to parse uploaded CA certificate {name} as a PEM/DER certificate or a CBOR store"
            ))),
        }
    }
    if let Err(e) = cert_source.initialize(cps) {
        return Err(vec![err(format!("Failed to initialize CA store: {e:?}"))]);
    }

    match (store, tas.is_empty() && cas.is_empty()) {
        (Some((label, _, _)), true) => out.push(info(format!("Using {label} store"))),
        (Some((label, _, _)), false) => out.push(info(format!(
            "Using {label} store with {} uploaded trust anchor(s) and {} uploaded intermediate(s)",
            tas.len(),
            cas.len()
        ))),
        (None, _) => out.push(info(format!(
            "Using {} uploaded trust anchor(s) and {} uploaded intermediate(s)",
            tas.len(),
            cas.len()
        ))),
    }

    // --- prepare the environment ONCE ---
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe.add_trust_anchor_source(Box::new(ta_store));
    // The baked store ships with precomputed partial paths, so discovery runs only when uploads
    // change the merged set. It rebuilds the whole merged pool's paths — but ONCE, cached by the
    // caller across runs. The TA source must be registered first (discovery consults it).
    if !tas.is_empty() || !cas.is_empty() {
        cert_source.find_all_partial_paths(&pe, cps);
    }
    pe.add_certificate_source(Box::new(cert_source));

    Ok((PreparedValidation { pe }, out))
}

/// Validates every certificate in `ees` against an environment prepared by [`prepare_validation`].
/// This is the per-target work that reruns on each Validate click: it builds and validates the
/// path(s) for each target but does not rebuild the environment or rediscover partial paths. Returns
/// a report per target that reached path building, plus displayable notes.
pub fn validate_prepared(
    prepared: &PreparedValidation,
    cps: &CertificationPathSettings,
    ees: &[(String, Vec<u8>)],
    validate_all: bool,
) -> (Vec<TargetReport>, Vec<ResultLine>) {
    let mut out = vec![];
    let mut reports = vec![];
    for (name, bytes) in ees {
        let (report, lines) = validate_target(&prepared.pe, cps, name, bytes, validate_all);
        out.extend(lines);
        if let Some(r) = report {
            reports.push(r);
        }
    }
    (reports, out)
}

/// Reports a target for which the builder produced no candidate path, carrying the diagnosis of
/// why. The environment is queried here rather than at display time because it holds the trust
/// material the run actually used, which is the thing the answer turns on.
///
/// Chasing is reported as unavailable (`None`) rather than off: the browser build has no fetch path
/// for AIA and SIA, so proposing it would name an option this frontend does not have.
fn no_paths_report(
    pe: &PkiEnvironment,
    target: &PDVCertificate,
    toi: TimeOfInterest,
    ee_name: &str,
    target_summary: CertSummary,
) -> TargetReport {
    TargetReport {
        name: ee_name.to_string(),
        target: Some(target_summary),
        status: TargetReport::compute_status(&[], false),
        paths: vec![],
        no_paths_hints: NoPathsContext::collect(pe, target, toi, None).hints(),
    }
}

/// Builds and validates certification path(s) for a single target certificate against a fully
/// prepared [`PkiEnvironment`](certval::PkiEnvironment), returning a structured report for the
/// target (absent when the certificate could not be parsed) along with displayable notes
fn validate_target(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    ee_name: &str,
    ee: &[u8],
    validate_all: bool,
) -> (Option<TargetReport>, Vec<ResultLine>) {
    let mut out = vec![];
    let toi = cps.get_time_of_interest();

    let der = match maybe_pem(ee) {
        Ok(der) => der,
        Err(_) => {
            out.push(err(format!("Failed to parse {ee_name} as PEM or DER")));
            return (None, out);
        }
    };
    let target = match parse_cert(&der, ee_name) {
        Ok(t) => t,
        Err(e) => {
            out.push(err(format!("Failed to parse certificate {ee_name}: {e:?}")));
            return (None, out);
        }
    };
    let target_summary = CertSummary::from_cert(&target);

    // validate_path treats a target found in the TA store as trusted and returns success without
    // verifying its signature (and TA store membership requires only a subjectKeyIdentifier and
    // public key match, not an exact certificate match), so when the target is a trust anchor
    // check its signature here to keep bad signatures and unsupported algorithms from being
    // reported as valid
    if pe.is_cert_a_trust_anchor(&target).is_ok() {
        if is_self_signed(pe, &target) {
            out.push(ok(format!(
                "{ee_name} is a trust anchor and is self-signed"
            )));
        } else {
            out.push(err(format!(
                "{ee_name} matches a trust anchor by key but is not self-signed (bad signature or unsupported algorithm)"
            )));
        }
    }

    out.push(info(format!(
        "Building and validating path(s) for {} ({})",
        ee_name,
        target.decoded().tbs_certificate().subject()
    )));

    let mut paths: Vec<CertificationPath> = vec![];
    if let Err(e) = pe.get_paths_for_target(&target, &mut paths, 0, toi) {
        // A PathValidation error means a check failed while building the path (e.g. the target is
        // not valid at the time of interest) — a rejection of the certificate, not an absence of
        // candidate issuers. Report it as an invalid target carrying the reason rather than the
        // neutral "no paths found", which reads like a store/configuration problem. Other errors
        // (no candidate path exists) keep the no-paths-found outcome.
        if let Error::PathValidation(pvs) = &e {
            let reason = format!("{pvs:?}");
            out.push(err(format!(
                "{ee_name}: certificate rejected during path building — {reason}"
            )));
            let path = PathReport {
                status: Some(*pvs),
                error: Some(format!("{e:?}")),
                certs: vec![target_summary.clone()],
                failure_reasons: vec![reason],
                ..Default::default()
            };
            return (
                Some(TargetReport {
                    name: ee_name.to_string(),
                    target: Some(target_summary),
                    status: TargetReport::compute_status(std::slice::from_ref(&path), true),
                    paths: vec![path],
                    no_paths_hints: vec![],
                }),
                out,
            );
        }
        out.push(err(format!("Failed to find certification paths: {e:?}")));
        let report = no_paths_report(pe, &target, toi, ee_name, target_summary);
        out.extend(report.no_paths_hints.iter().map(|h| err(h.clone())));
        return (Some(report), out);
    }
    if paths.is_empty() {
        out.push(err("No certification paths found".to_string()));
        let report = no_paths_report(pe, &target, toi, ee_name, target_summary);
        out.extend(report.no_paths_hints.iter().map(|h| err(h.clone())));
        return (Some(report), out);
    }

    let mut valid = 0;
    let mut invalid = 0;
    let mut path_reports = vec![];
    for (i, path) in paths.iter_mut().enumerate() {
        let path_start = Instant::now();
        let mut cpr = CertificationPathResults::new();
        // fold RFC 5914 trust anchor constraints into the settings per RFC 5937; this is a no-op
        // clone when enforcement is disabled, and validate_path does not perform it itself
        let path_cps = match enforce_trust_anchor_constraints(cps, &path.trust_anchor) {
            Ok(c) => c,
            Err(e) => {
                invalid += 1;
                out.push(err(format!(
                    "Path {}: failed to apply trust anchor constraints: {e:?}",
                    i + 1
                )));
                path_reports.push(PathReport::from_path_results(
                    path,
                    &CertificationPathResults::new(),
                    Some(&e),
                    path_start.elapsed().as_millis() as u64,
                ));
                continue;
            }
        };
        let r = pe.validate_path(pe, &path_cps, path, &mut cpr);
        path_reports.push(PathReport::from_path_results(
            path,
            &cpr,
            r.as_ref().err(),
            path_start.elapsed().as_millis() as u64,
        ));
        let cert_count = path.intermediates.len() + 2;
        match r {
            Ok(_) => {
                valid += 1;
                out.push(ok(format!(
                    "Path {} ({} certificates): VALID",
                    i + 1,
                    cert_count
                )));
                if !validate_all {
                    break;
                }
            }
            Err(e) => {
                invalid += 1;
                out.push(err(format!(
                    "Path {} ({} certificates): INVALID with {e:?}",
                    i + 1,
                    cert_count
                )));
            }
        }
    }

    let summary = format!(
        "{} path(s) considered: {} valid, {} invalid",
        valid + invalid,
        valid,
        invalid
    );
    if valid > 0 {
        out.push(ok(summary));
    } else {
        out.push(err(summary));
    }

    let status = TargetReport::compute_status(&path_reports, true);
    (
        Some(TargetReport {
            name: ee_name.to_string(),
            target: Some(target_summary),
            status,
            paths: path_reports,
            no_paths_hints: vec![],
        }),
        out,
    )
}

/// Checks whether a certificate is self-signed, i.e., whether its signature verifies using its
/// own public key, as done for trust anchors from hackathon archives. This mirrors the hackathon
/// compatibility matrices and the CLI --validate-self-signed option, which check self-signed-ness
/// only. Full path validation is deliberately not used here: with the trust anchors loaded into
/// the TA store, validate_path treats a target found in the store as trusted and returns success
/// without verifying the signature, reporting certificates signed with unsupported algorithms as
/// valid.
fn validate_self_signed(pe: &PkiEnvironment, name: &str, der: &[u8]) -> Vec<ResultLine> {
    let mut out = vec![];
    let target = match parse_cert(der, name) {
        Ok(t) => t,
        Err(e) => {
            out.push(err(format!("Failed to parse certificate {name}: {e:?}")));
            return out;
        }
    };
    if is_self_signed(pe, &target) {
        out.push(ok(format!("{name} is self-signed")));
    } else {
        out.push(err(format!(
            "{name} is not self-signed (bad signature or unsupported algorithm)"
        )));
    }
    out
}

/// Validates the contents of an IETF Hackathon PQC certificates archive in the R5 format, i.e.,
/// artifacts_certs_r5.zip. Entries named `*_ta.der` form the trust anchor store and entries named
/// `*_ee.der` are validated against it; all other entries (private keys, KEM artifacts, etc.) are
/// ignored. The archive is self-contained: built-in stores and uploads are not consulted. Returns
/// a structured report per end entity certificate along with displayable notes (trust anchor
/// self-signed checks are reported as notes).
pub fn validate_hackathon_zip(
    zip_name: &str,
    bytes: Vec<u8>,
    cps: &CertificationPathSettings,
    validate_all: bool,
) -> (Vec<TargetReport>, Vec<ResultLine>) {
    let mut out = vec![];
    let mut reports = vec![];

    let mut archive = match zip::ZipArchive::new(Cursor::new(bytes)) {
        Ok(a) => a,
        Err(e) => {
            return (
                vec![],
                vec![err(format!("Failed to read {zip_name} as a zip file: {e}"))],
            )
        }
    };

    let mut tas: Vec<(String, Vec<u8>)> = vec![];
    let mut ees: Vec<(String, Vec<u8>)> = vec![];
    let mut ignored = 0usize;
    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(entry) => entry,
            Err(e) => {
                out.push(err(format!("Failed to read entry {i} in {zip_name}: {e}")));
                continue;
            }
        };
        if entry.is_dir() {
            continue;
        }
        // entries may sit under a top-level folder, e.g., artifacts_certs_r5/<name>_ta.der
        let name = match entry.name().rsplit('/').next() {
            Some(n) => n.to_string(),
            None => continue,
        };
        let is_ta = name.ends_with("_ta.der");
        let is_ee = name.ends_with("_ee.der");
        if !is_ta && !is_ee {
            ignored += 1;
            continue;
        }
        let mut buf = vec![];
        if let Err(e) = entry.read_to_end(&mut buf) {
            out.push(err(format!("Failed to decompress {name}: {e}")));
            continue;
        }
        if is_ta {
            tas.push((name, buf));
        } else {
            ees.push((name, buf));
        }
    }
    tas.sort();
    ees.sort();

    out.push(info(format!(
        "{zip_name}: {} trust anchor(s), {} end entity certificate(s), {} other entries ignored",
        tas.len(),
        ees.len(),
        ignored
    )));
    if tas.is_empty() {
        out.push(err(format!(
            "No *_ta.der entries found in {zip_name}; expected an archive in the artifacts_certs_r5.zip format"
        )));
        return (reports, out);
    }

    let mut ta_store = TaSource::new();
    for (name, der) in &tas {
        ta_store.push(CertFile {
            filename: name.clone(),
            bytes: der.clone(),
        });
    }

    if let Err(e) = ta_store.initialize() {
        out.push(err(format!("Failed to initialize TA store: {e:?}")));
        return (reports, out);
    }

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe.add_trust_anchor_source(Box::new(ta_store));
    // path building for TA-issued targets happens in the certificate source, so one must be
    // registered even though the R5 format carries no intermediate CA certificates
    let mut cert_source = CertSource::new();
    if let Err(e) = cert_source.initialize(cps) {
        out.push(err(format!("Failed to initialize CA store: {e:?}")));
        return (reports, out);
    }
    pe.add_certificate_source(Box::new(cert_source));

    // trust anchors are self-signed certificates per the R5 format, so each is checked for
    // self-signed-ness (signature verifies with the certificate's own key)
    for (name, der) in &tas {
        out.extend(validate_self_signed(&pe, name, der));
    }
    for (name, der) in &ees {
        let (report, lines) = validate_target(&pe, cps, name, der, validate_all);
        out.extend(lines);
        if let Some(report) = report {
            reports.push(report);
        }
    }
    (reports, out)
}
