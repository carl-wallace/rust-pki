//! Certification path validation shared by the PITTv3 GUI frontends.
//!
//! Built on certval with no-default-features, so this compiles for `wasm32-unknown-unknown` as
//! well as the host: nothing here reaches the filesystem, the network, or the clock beyond
//! `web_time::Instant`. The frontend supplies the trust material as bytes it has already
//! obtained — fetched in the browser, read from disk on the desktop, or handed over by a server —
//! so the same validation path serves every frontend and no frontend forks it.

use std::io::{Cursor, Read};
#[cfg(feature = "revocation")]
use std::sync::Arc;

use certval::*;
use pittv3_lib::report::{CertSummary, NoPathsContext, PathReport, TargetReport, TargetStatus};
use web_time::Instant;

use crate::retrieval::{MemoryCrlSource, OcspResponses};

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

/// Re-exported so the frontends keep the name they already use; the implementation lives one layer
/// down in [`pittv3_lib::der_or_pem`].
///
/// Two copies is how the 2026-08-20 bug got in: `validate_target` decoded PEM and the harvest did
/// not, so a PEM target validated normally and contributed nothing to retrieve. Having one is the
/// point — a caller cannot reach for the wrong one if there is only one.
pub use pittv3_lib::der_or_pem::{certs_in, maybe_pem};

/// A [`PkiEnvironment`] prepared for validation: trust anchors and CA
/// certificates parsed and merged, and — when uploads are present — a partial-path discovery pass
/// completed. Preparing this is the expensive part of a run (parsing stores and, above all,
/// discovering partial paths), so the frontend caches it and reuses it across Validate clicks while
/// the trust anchors, CA certificates and settings are unchanged. Only the target certificates then
/// need differ, and re-validating them skips reparse and rediscovery entirely.
pub struct PreparedValidation {
    /// Fully populated environment with the trust-anchor and certificate sources registered
    pe: PkiEnvironment,
    /// CRLs the frontend has retrieved for this run. Registered on `pe` as a clone sharing these
    /// contents, so a CRL added after preparation is consulted by the next validation without the
    /// environment being rebuilt — which matters because rebuilding it means rediscovering partial
    /// paths, the expensive step this type exists to avoid repeating.
    crls: MemoryCrlSource,
    /// OCSP responses the frontend has retrieved for this run. Not registered on `pe`, because
    /// certval has no OCSP source to register one with: a response reaches the checker only through
    /// a path's `ocsp_responses` slot, so [`validate_target`] fills those from here each time it
    /// builds a path.
    ocsp: OcspResponses,
}

impl PreparedValidation {
    /// The environment this run validates against, for a caller that needs to ask what the run
    /// holds — building paths to harvest revocation URIs from, say.
    pub fn environment(&self) -> &PkiEnvironment {
        &self.pe
    }

    /// The CRLs retrieved for this run. Adding to it is how a frontend supplies revocation data:
    /// the checker consults it through the environment, and nothing has to be rebuilt.
    pub fn crl_source(&self) -> &MemoryCrlSource {
        &self.crls
    }

    /// The OCSP responses retrieved for this run. Adding to it is how a frontend supplies one; the
    /// validation path puts it in front of the checker.
    pub fn ocsp_responses(&self) -> &OcspResponses {
        &self.ocsp
    }
}

/// Labels one certificate out of an upload. A single-certificate file keeps its own name; every
/// member of a bundle gets its index appended, so a report can say which one a path used.
///
/// Numbering from zero and only when the file held more than one matches how the relay labels the
/// members of a fetched bundle (`{uri}#{index}`), so uploaded and retrieved sources read alike --
/// and a bare name always means the file held exactly one certificate.
fn numbered(name: &str, i: usize, count: usize) -> String {
    if count > 1 {
        format!("{name}#{i}")
    } else {
        name.to_string()
    }
}

/// Prepares a validation environment from an optional baked-in store plus uploaded trust anchors and
/// intermediate CA certificates: one merged trust-anchor store, one merged CA store, and a single
/// partial-path discovery pass when uploads are present (baked stores ship with paths precomputed).
/// This is the heavy step; validate targets against the result with [`validate_prepared`]. Returns
/// the prepared environment plus informational notes, or fatal notes when preparation cannot yield a
/// usable environment (e.g., no trust anchors).
///
/// `rev_cache` is taken rather than created here so a caller can keep revocation determinations
/// across rebuilds. That matters because uploads and retrieved certificates make the environment
/// stale, and a cache built here would be discarded with it -- costing a re-fetch of revocation data
/// that a retrieval had already paid for. Determinations stay sound across such a rebuild: they are
/// keyed on the issuing key and bounded by the validity of the data behind them, and adding
/// certificates changes which paths exist rather than whether a certificate was revoked. A caller
/// that shares one owes it a `clear()` when the time of interest moves backward or the revocation
/// policy tightens; one that would rather not think about it can pass a fresh cache each time and get
/// the previous behavior. Passing `None` registers no cache at all, so every path determines every
/// status for itself -- slower, and what a caller wants when each path has to stand on its own
/// evidence rather than on an answer reached while validating another one.
pub fn prepare_validation(
    store: Option<(&str, &[u8], &[u8])>,
    tas: &[(String, Vec<u8>)],
    cas: &[(String, Vec<u8>)],
    cps: &CertificationPathSettings,
    #[cfg(feature = "revocation")] rev_cache: Option<&Arc<RevocationCache>>,
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
        // certs_in rather than maybe_pem: a `.p7c` of cross-certificates and a concatenated PEM
        // bundle each hold several anchors, and taking only the first (or the container itself)
        // fails quietly later rather than here.
        match certs_in(bytes) {
            Ok(ders) => {
                let count = ders.len();
                for (i, der) in ders.into_iter().enumerate() {
                    ta_store.push(CertFile {
                        filename: numbered(name, i, count),
                        bytes: der,
                    });
                }
            }
            Err(_) => out.push(err(format!(
                "Failed to parse uploaded trust anchor {name} as a PEM/DER certificate, a PKCS#7 certificate bundle, or a CBOR store"
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
        match certs_in(bytes) {
            Ok(ders) => {
                let count = ders.len();
                for (i, der) in ders.into_iter().enumerate() {
                    cert_source.push(CertFile {
                        filename: numbered(name, i, count),
                        bytes: der,
                    });
                }
            }
            Err(_) => out.push(err(format!(
                "Failed to parse uploaded CA certificate {name} as a PEM/DER certificate, a PKCS#7 certificate bundle, or a CBOR store"
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
    // The graph and the paths built over it re-present the same CA signatures many times;
    // caching them is sound because a hit means this exact signature already verified under
    // this exact key.
    pe.add_signature_cache(Box::new(DefaultSignatureVerificationCache::new()));
    pe.add_trust_anchor_source(Box::new(ta_store));
    // Registered empty and always, rather than only when the frontend has CRLs: the source is
    // shared by clone, so a frontend that retrieves one later adds it to the same contents this
    // environment already consults. An empty source answers with no candidates, which is what the
    // checker saw before it existed.
    let crls = MemoryCrlSource::new();
    pe.add_crl_source(Box::new(crls.clone()));
    // The revocation checker consults the status cache before anything else and writes back to it
    // whenever a CRL or an OCSP response determines a status. Both ends iterate the registered
    // caches, so with none registered the first check always answers "not determined" and every
    // determination is discarded -- the same certificate is re-derived on each run and, when the
    // frontend retrieves, re-fetched for. Only Valid and revoked verdicts are cached, and each is
    // served only until the nextUpdate of the data behind it, so an undetermined status never
    // suppresses a retry and a stale one is never reused. The cache belongs to this environment and
    // is discarded with it, which is what keeps it honest when the time of interest changes: that
    // is a settings change, and a settings change rebuilds the environment.
    #[cfg(feature = "revocation")]
    // `None` declines the cache outright, which is not the same as passing an empty one: with no
    // cache registered every path derives every certificate's status from revocation data of its
    // own, so each path accounts for itself. That matters for an export -- a path whose certificates
    // were answered from cache carries a status and no evidence, because the evidence was obtained
    // while validating a different path -- and it is the only way to make a run reach a responder
    // twice on purpose.
    if let Some(rev_cache) = rev_cache {
        pe.add_revocation_cache(Box::new(rev_cache.clone()));
    }
    // Nothing to register for OCSP -- certval has no source for it -- so this is simply carried
    // and consulted when a path is built. See validate_target.
    let ocsp = OcspResponses::new();
    // The baked store ships with precomputed partial paths, so discovery runs only when uploads
    // change the merged set. It rebuilds the whole merged pool's paths — but ONCE, cached by the
    // caller across runs. The TA source must be registered first (discovery consults it).
    if !tas.is_empty() || !cas.is_empty() {
        cert_source.find_all_partial_paths(&pe, cps);
    }
    pe.add_certificate_source(Box::new(cert_source));

    Ok((PreparedValidation { pe, crls, ocsp }, out))
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
    let (reports, out, _) = validate_prepared_retaining(prepared, cps, ees, validate_all, false);
    (reports, out)
}

// Re-exported rather than defined here: `pittv3_lib::std_utils` retains the same type, so an export
// written against it works with a run this crate prepared and validated or with one the lower crate
// carried out end to end. Kept in this module's namespace because that is where callers already
// reach for it.
pub use pittv3_lib::retained::RetainedPath;

/// As [`validate_prepared`], additionally returning each validated path when `retain` is set, so a
/// frontend can export the artifacts behind a result without validating a second time.
///
/// Validating again to produce an export would describe a *different* run: revocation data moves,
/// and a responder asked twice can answer twice. An export is worth having precisely because it
/// accounts for the result on screen, so the material has to come from that run or not at all.
pub fn validate_prepared_retaining(
    prepared: &PreparedValidation,
    cps: &CertificationPathSettings,
    ees: &[(String, Vec<u8>)],
    validate_all: bool,
    retain: bool,
) -> (Vec<TargetReport>, Vec<ResultLine>, Vec<RetainedPath>) {
    let mut out = vec![];
    let mut reports = vec![];
    let mut retained = vec![];
    for (name, bytes) in ees {
        let sink = retain.then_some(&mut retained);
        let (report, lines) = validate_target(
            &prepared.pe,
            cps,
            name,
            bytes,
            validate_all,
            &prepared.ocsp,
            sink,
        );
        out.extend(lines);
        if let Some(r) = report {
            reports.push(r);
        }
    }
    (reports, out, retained)
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
        error: None,
    }
}

/// Reports a target for which no certification path exists because of the target itself rather than
/// the material available to build with: the file was not a certificate, or the certificate was
/// refused before any path was built.
///
/// No path was built, so none is reported and none is counted. The reason rides on the target,
/// which is the only thing there is. Reporting it as a one-certificate path instead put an entry in
/// the path list that was never a path, and the totals -- which count that list -- counted it, so a
/// run over a folder of expired certificates reported paths it had never found.
///
/// A file that could not be read at all is reported rather than dropped: dropping it made a run
/// report fewer targets than the folder holds, leaving a user comparing the two counts nothing to
/// reconcile them with.
fn no_path_reason_report(
    ee_name: &str,
    target: Option<CertSummary>,
    status: TargetStatus,
    reason: String,
) -> TargetReport {
    TargetReport {
        name: ee_name.to_string(),
        target,
        status,
        paths: vec![],
        no_paths_hints: vec![],
        error: Some(reason),
    }
}

/// Fills `path`'s OCSP slots from the responses retrieved for this run.
///
/// certval indexes those slots by position -- the intermediates from the one the trust anchor
/// issued, then the target -- and identifies what a response is about by the certificate and its
/// issuer. This is the translation between the two, and it has to be redone for each path, since a
/// certificate can sit at a different position on each one and under a different issuer.
///
/// A slot already holding a response is left alone: a caller that stapled something itself meant it.
fn staple_ocsp(path: &mut CertificationPath, ocsp: &OcspResponses) {
    let found: Vec<Option<Vec<u8>>> = {
        let chain: Vec<&PDVCertificate> = path
            .intermediates
            .iter()
            .chain(core::iter::once(&path.target))
            .collect();
        chain
            .iter()
            .enumerate()
            .map(|(pos, cert)| {
                let issuer: &dyn SubjectNameAndKey = match pos {
                    0 => &path.trust_anchor.decoded_ta,
                    _ => chain[pos - 1].as_ref(),
                };
                ocsp.get(cert, issuer)
            })
            .collect()
    };

    for (slot, response) in path.ocsp_responses.iter_mut().zip(found) {
        if slot.is_none() && response.is_some() {
            *slot = response;
        }
    }
}

/// Builds and validates certification path(s) for a single target certificate against a fully
/// prepared [`PkiEnvironment`](certval::PkiEnvironment), returning a structured report for the
/// target (absent when the certificate could not be parsed) along with displayable notes.
///
/// Revocation status is determined for a path that otherwise validates, when the settings ask for
/// it, from data the caller has already supplied: revocation data stapled into the path and any
/// CRL source registered in the environment. Nothing is fetched here. A path whose status cannot be
/// determined from that data comes back as `RevocationStatusNotDetermined`, which the target rollup
/// reports as valid-except-revocation-undetermined rather than as an outright failure
fn validate_target(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    ee_name: &str,
    ee: &[u8],
    validate_all: bool,
    ocsp: &OcspResponses,
    mut retain: Option<&mut Vec<RetainedPath>>,
) -> (Option<TargetReport>, Vec<ResultLine>) {
    let mut out = vec![];
    let toi = cps.get_time_of_interest();

    let der = match maybe_pem(ee) {
        Ok(der) => der,
        Err(_) => {
            let reason = format!("Failed to parse {ee_name}: the file is not DER, PEM or base64");
            out.push(err(reason.clone()));
            return (
                Some(no_path_reason_report(
                    ee_name,
                    None,
                    TargetStatus::ParseError,
                    reason,
                )),
                out,
            );
        }
    };
    let target = match parse_cert(&der, ee_name) {
        Ok(t) => t,
        Err(e) => {
            let reason = format!("Failed to parse certificate {ee_name}: {e:?}");
            out.push(err(reason.clone()));
            return (
                Some(no_path_reason_report(
                    ee_name,
                    None,
                    TargetStatus::ParseError,
                    reason,
                )),
                out,
            );
        }
    };
    let target_summary = CertSummary::from_cert(&target);

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
            return (
                Some(no_path_reason_report(
                    ee_name,
                    Some(target_summary),
                    TargetStatus::Invalid,
                    reason,
                )),
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
        // Put any retrieved OCSP response where the checker looks for it. Its slots are indexed by
        // position in this path, while the responses are held by what they are about, so the two
        // are matched up here -- freshly, against whatever path building has just produced.
        if !ocsp.is_empty() {
            staple_ocsp(path, ocsp);
        }
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
        #[cfg(not(feature = "revocation"))]
        let r = pe.validate_path(pe, &path_cps, path, &mut cpr);
        #[cfg(feature = "revocation")]
        let mut r = pe.validate_path(pe, &path_cps, path, &mut cpr);

        // Revocation is checked only after the path itself validates, so a path that failed for
        // another reason reports that reason rather than a revocation status nothing was going to
        // determine. The data consulted is whatever the caller has already put in the path's
        // stapled slots plus any registered CRL source; this call fetches nothing, which is why it
        // belongs in a path that a browser can run.
        #[cfg(feature = "revocation")]
        if r.is_ok() && path_cps.get_check_revocation_status() {
            r = check_revocation_local(pe, &path_cps, path, &mut cpr);
        }

        path_reports.push(PathReport::from_path_results(
            path,
            &cpr,
            r.as_ref().err(),
            path_start.elapsed().as_millis() as u64,
        ));
        // Kept for a later export, with the settings this path was actually judged under rather than
        // the run's -- `path_cps` carries the RFC 5937 trust anchor constraints folded in above, and
        // a manifest reporting the run's settings would name inputs the path was not validated
        // against. Paths that failed are kept too: a failure is the case someone most wants the
        // material for.
        if let Some(retained) = retain.as_deref_mut() {
            retained.push(RetainedPath {
                target_name: ee_name.to_string(),
                path: path.clone(),
                cps: path_cps.clone(),
                cpr: cpr.clone(),
            });
        }
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
                // A revoked end entity is the same certificate on every candidate path, so the
                // first path to report it has settled the target and the rest cost a signature
                // check and a revocation lookup to reach the same answer. Stop for the same reason
                // and under the same condition as a successful path does above: the run has what it
                // came for, unless validate_all asked to see every path regardless.
                let revoked =
                    e == Error::PathValidation(PathValidationStatus::CertificateRevokedEndEntity);
                if revoked && !validate_all {
                    break;
                }
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
            error: None,
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
    // The graph and the paths built over it re-present the same CA signatures many times;
    // caching them is sound because a hit means this exact signature already verified under
    // this exact key.
    pe.add_signature_cache(Box::new(DefaultSignatureVerificationCache::new()));
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
        let (report, lines) = validate_target(
            &pe,
            cps,
            name,
            der,
            validate_all,
            &OcspResponses::new(),
            None,
        );
        out.extend(lines);
        if let Some(report) = report {
            reports.push(report);
        }
    }
    (reports, out)
}
