//! Contains utility functions related to certification path validation, CBOR file generation and
//! trust anchor/certificate folder cleanup.
#![cfg(feature = "std")]

extern crate alloc;

use alloc::string::String;
use log::{error, info};
use std::{ffi::OsStr, fs, path::Path, time::Instant};
use walkdir::WalkDir;

use const_oid::db::rfc5912::ID_CE_BASIC_CONSTRAINTS;
use der::Decode;
use x509_cert::anchor::TrustAnchorChoice;

use certval::util::pdv_utilities::*;
use certval::*;

use crate::pitt_log::*;
use crate::{
    args::Pittv3Args,
    report::{
        CertSummary, NoPathsContext, PathReport, ProgressEvent, ReportTotals, TargetReport,
        ValidationReport,
    },
    stats::{PVStats, PathValidationStats, PathValidationStatsGroup},
};

#[cfg(feature = "revocation")]
use certval::check_revocation;

/// Decodes a CBOR certificate store into the certificates it carries, as `(name, DER)` pairs.
///
/// The store is the serialized form of a [`CertSource`], so what comes back is what a run would
/// build paths from — one entry per buffer, in store order, carrying whatever name the store
/// recorded (often the file the certificate was generated from). Nothing here parses or validates:
/// a caller wanting to write the certificates out should not have to reason about the material.
///
/// Lives here rather than in a frontend so every frontend can offer it. `pittv3-gui`'s store export
/// is the first caller; the browser will want the same thing, and the CLI already exposes it as
/// `--list-buffers` with a download folder.
#[cfg(feature = "std")]
pub fn cbor_store_to_ders(cbor: &[u8]) -> core::result::Result<Vec<(String, Vec<u8>)>, String> {
    let cert_source = CertSource::new_from_cbor(cbor)
        .map_err(|e| format!("failed to parse the CBOR certificate store: {e:?}"))?;
    Ok(cert_source
        .get_buffers()
        .into_iter()
        .map(|cf| (cf.filename, cf.bytes))
        .collect())
}

/// Reads `path` as a CBOR trust anchor store and returns its anchors, or `None` when it is not one.
///
/// The trust anchor and CA inputs take certificates, and a store is not one — but the two are easy
/// to confuse, and this app invites the confusion by exporting a store as `ta.cbor` and `ca.cbor`.
/// Rather than refuse a file the tool itself wrote, the input reads it: anchors from a store named
/// here are merged into the same [`TaSource`] as the rest, exactly as `ta_cbor` is, so nominating
/// one is additive and a run can draw on a built-in store and an exported one at once. Called only
/// once a file has failed to yield certificates, so nothing about the ordinary path changes.
#[cfg(feature = "std")]
pub fn cbor_ta_store_anchors(path: &str) -> Option<Vec<CertFile>> {
    let bytes = get_file_as_byte_vec_pem(Path::new(path)).ok()?;
    TaSource::new_from_cbor(&bytes)
        .ok()
        .map(|from_cbor| from_cbor.get_tas())
}

/// Reads `path` as a CBOR certificate store and returns the certificates it carries, or `None` when
/// it is not one. The CA-side counterpart of [`cbor_ta_store_anchors`].
///
/// Only the certificates are taken, not the partial paths recorded alongside them: they are being
/// merged into a graph that is about to be built over the combined material, and paths computed
/// against the store alone would not describe it.
#[cfg(feature = "std")]
pub fn cbor_cert_store_certs(path: &str) -> Option<Vec<CertFile>> {
    cbor_cert_store(path).map(|from_cbor| from_cbor.get_buffers())
}

/// Reads the file at `path` as a CBOR certificate store, or `None` when it is not one.
///
/// Unlike [`cbor_cert_store_certs`] this keeps the partial paths the store carries, which is what a
/// caller wants when the store is the entire set of CA certificates for a run: those paths already
/// describe every path through it, so searching again would recompute an answer that was serialized
/// precisely so it would not have to be.
#[cfg(feature = "std")]
pub fn cbor_cert_store(path: &str) -> Option<CertSource> {
    let bytes = get_file_as_byte_vec_pem(Path::new(path)).ok()?;
    CertSource::new_from_cbor(&bytes).ok()
}

/// What a set of CA inputs contributed, reported by [`load_ca_inputs`].
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Default)]
pub struct CaInputs {
    /// Certificates the inputs added to the source.
    pub certs: usize,
    /// Whether the source now holds a graph that already describes every path through it, so
    /// searching for partial paths would recompute an answer that was serialized precisely so it
    /// would not have to be. True only when a single CBOR store carrying partial paths was the
    /// whole of the CA input.
    pub paths_adopted: bool,
}

/// Adds the CA certificates named by `paths` to `cert_source`, in the order given.
///
/// Each entry may name a folder of intermediates, a single certificate, a bundle holding several
/// (a fullchain PEM, a `.p7c`), or a CBOR certificate store; which it is comes from the path and
/// then, when a file yielded nothing, from the bytes. The CA-side counterpart of
/// [`push_trust_anchor_input`], and interchangeable for the same reason: the material arrives in
/// whatever shape its source published it in.
///
/// A CBOR store is treated one of two ways, and the distinction is what makes several inputs safe
/// to combine. When it is the only thing that contributed it is adopted as it stands, partial paths
/// included — that is what the `cbor` argument does with the same bytes. When anything else
/// contributed, before it or after it, only its certificates are taken: a path spanning two sources
/// exists only once they are searched together, so paths computed against the store alone would not
/// describe the union, and the caller is told to search by a false `paths_adopted`.
///
/// An input that cannot be read is logged and skipped rather than failing the run, since the others
/// may still carry what a path needs.
#[cfg(feature = "std")]
pub fn load_ca_inputs<'a>(
    pe: &PkiEnvironment,
    paths: impl IntoIterator<Item = &'a str>,
    cert_source: &mut CertSource,
    time_of_interest: TimeOfInterest,
) -> CaInputs {
    let start = cert_source.len();
    // Length at the moment a store was adopted whole. Anything added afterwards means its paths no
    // longer span the source, which is why this is compared rather than merely set.
    let mut adopted_at = None;

    for path in paths {
        let before = cert_source.len();
        let r = if Path::new(path).is_file() {
            cert_file_to_vec(pe, path, cert_source, time_of_interest)
        } else {
            cert_folder_to_vec(pe, path, cert_source, time_of_interest)
        };
        if let Err(e) = r {
            error!("Failed to read certificates from {path}: {e:?}");
        }

        let from_cbor_store = cert_source.len() == before && Path::new(path).is_file();
        if from_cbor_store {
            if 0 == before {
                if let Some(store) = cbor_cert_store(path) {
                    // Only claim the graph if the store actually carries paths. A store exported
                    // without them is certificates in a different container, and adopting it would
                    // otherwise leave the run with no graph at all.
                    if store.num_partial_paths() > 0 {
                        adopted_at = Some(store.len());
                    }
                    *cert_source = store;
                }
            } else if let Some(certs) = cbor_cert_store_certs(path) {
                for cf in certs {
                    cert_source.push(cf);
                }
            }
        }

        let contributed = cert_source.len() - before;
        if from_cbor_store && adopted_at.is_some() {
            info!(
                "Read {contributed} certificate(s) and {} partial path(s) from the CBOR store at {path}",
                cert_source.num_partial_paths()
            );
        } else if from_cbor_store {
            info!("Read {contributed} certificate(s) from the CBOR store at {path}");
        } else {
            info!("Read {contributed} certificate(s) from {path}");
        }
    }

    CaInputs {
        certs: cert_source.len() - start,
        paths_adopted: adopted_at == Some(cert_source.len()),
    }
}

/// Adds the trust anchors named by one input to `ta_store`, returning how many it contributed.
///
/// `path` may name a folder of anchors, a single certificate, a bundle holding several, or a CBOR
/// trust anchor store; which it is comes from the path and then, when a file yielded nothing, from
/// the bytes. That the four are interchangeable is the point: a trust anchor set is assembled from
/// whatever the material happened to arrive as, and the caller should not have to sort it first.
///
/// A single anchor is as reasonable a thing to nominate as a folder of them — the material often
/// arrives as one file — so naming a file is not a lesser case, and the alternative would be asking
/// the user to build a directory around one certificate.
///
/// An input that yields no anchor is not an error (see `TA_FOLDER_EMPTY` in `options_std`), only a
/// zero return. An input that cannot be *read*, though, is: `Err` carries a message naming it, and
/// the caller is expected to stop. That is the opposite of what [`load_ca_inputs`] does with the
/// same mistake, on purpose. A missing intermediate costs a path, which the run reports as a path
/// it did not find; a missing anchor costs trust, and a run against fewer anchors than the user
/// named does not look wrong — it looks like an answer.
#[cfg(feature = "std")]
pub fn push_trust_anchor_input(
    pe: &PkiEnvironment,
    path: &str,
    ta_store: &mut TaSource,
    time_of_interest: TimeOfInterest,
) -> core::result::Result<usize, String> {
    let named_file = Path::new(path).is_file();
    let before = ta_store.len();
    let r = if named_file {
        ta_file_to_vec(pe, path, ta_store, time_of_interest)
    } else {
        ta_folder_to_vec(pe, path, ta_store, time_of_interest)
    };
    if let Err(e) = r {
        return Err(format!(
            "failed to load trust anchors from {path} with error {e:?}"
        ));
    }

    // A file that yielded no anchor may be a CBOR trust anchor store rather than certificate
    // material — the shape this app's own store export writes. Read it as one and merge it in,
    // which is what `ta_cbor` does with the same bytes.
    if named_file && ta_store.len() == before {
        if let Some(anchors) = cbor_ta_store_anchors(path) {
            for cf in anchors {
                ta_store.push(cf);
            }
            info!(
                "Read {} trust anchor(s) from the CBOR store at {path}",
                ta_store.len() - before
            );
        }
    }

    Ok(ta_store.len() - before)
}

/// Builds the trust anchor store named by the `ta_cbor`, `ta_folder` and `ta_inputs` arguments, or
/// `None` when none of them was given.
///
/// Those inputs are the trust anchor counterparts of `cbor`, `ca_folder` and `ca_inputs`, and are
/// combined into one [`TaSource`] rather than being registered as several sources: certval refuses
/// to anchor on a key identifier that resolves to different keys across the sources registered on
/// an environment, so inputs that share an anchor must be deduplicated before any of them is added.
/// [`CertVector::push`] does that.
///
/// `ta_folder` and `ta_inputs` are read by [`push_trust_anchor_input`], so each of their entries may
/// be a folder, a certificate, a bundle or a CBOR store; `ta_cbor` is the one input that must be a
/// CBOR store, and says so when it is not.
///
/// The returned source is initialized and ready to hand to
/// [`PkiEnvironment::add_trust_anchor_source`]. `Err` carries a message naming the input that
/// failed, for a caller to surface; an input that yields no anchor is not an error here (see
/// `TA_FOLDER_EMPTY` in `options_std`), only an empty result.
#[cfg(feature = "std")]
pub fn load_trust_anchors(
    pe: &PkiEnvironment,
    args: &Pittv3Args,
    time_of_interest: TimeOfInterest,
) -> core::result::Result<Option<TaSource>, String> {
    if args.ta_cbor.is_none() && args.ta_folder.is_none() && args.ta_inputs.is_empty() {
        return Ok(None);
    }

    let mut ta_store = TaSource::new();

    if let Some(ta_cbor) = &args.ta_cbor {
        let cbor = read_cbor(&args.ta_cbor);
        if cbor.is_empty() {
            return Err(format!(
                "failed to read CBOR trust anchor store from {ta_cbor}"
            ));
        }
        // new_from_cbor yields a source holding the store's buffers; move them through push so an
        // anchor that also appears in the folder below is carried once.
        match TaSource::new_from_cbor(cbor.as_slice()) {
            Ok(from_cbor) => {
                for cf in from_cbor.get_tas() {
                    ta_store.push(cf);
                }
            }
            Err(e) => {
                return Err(format!(
                    "failed to parse CBOR trust anchor store at {ta_cbor}: {e:?}"
                ))
            }
        }
    }

    // The singular argument first, then the pool, so a log read top to bottom follows the order the
    // inputs were named in. Nothing depends on the order otherwise: `push` deduplicates, so an
    // anchor appearing in two inputs is carried once whichever was read first.
    for path in args.ta_folder.iter().chain(args.ta_inputs.iter()) {
        push_trust_anchor_input(pe, path, &mut ta_store, time_of_interest)?;
    }

    if let Err(e) = ta_store.initialize() {
        return Err(format!(
            "failed to initialize trust anchor source with error {e:?}"
        ));
    }

    Ok(Some(ta_store))
}

/// `ValidateOpts` conveys the options that govern processing of a single validation target,
/// decoupling the core validation logic from [`Pittv3Args`] so that non-CLI callers (GUI, web
/// server) need not fabricate a full argument structure (and never see filesystem paths unless
/// they choose to supply them).
#[derive(Clone, Debug, Default)]
pub struct ValidateOpts {
    /// Validate all available certification paths instead of stopping at the first valid path
    pub validate_all: bool,
    /// Collect URIs from AIA and SIA extensions of trust anchors and intermediate CA certificates
    /// encountered while processing paths (used to drive dynamic path building)
    pub dynamic_build: bool,
    /// Full path of folder to receive artifacts from processed certification paths, if desired
    pub results_folder: Option<String>,
    /// Full path of folder to receive artifacts from paths that fail validation, if desired
    pub error_folder: Option<String>,
    /// DER-encoded CRLs to staple into candidate certification paths prior to validation (matched
    /// to path positions by issuer name), enabling single-artifact revocation input
    pub crls: Vec<Vec<u8>>,
    /// DER-encoded OCSP responses to staple into candidate certification paths prior to validation,
    /// matched to path positions by the `CertID` each response answers about rather than by issuer
    /// name: a response names one certificate, where a CRL covers all of an issuer's
    pub ocsp_responses: Vec<Vec<u8>>,
}

impl ValidateOpts {
    /// Prepares a [`ValidateOpts`] from the corresponding [`Pittv3Args`] fields
    pub fn from_args(args: &Pittv3Args) -> ValidateOpts {
        ValidateOpts {
            validate_all: args.validate_all,
            #[cfg(feature = "remote")]
            dynamic_build: args.dynamic_build,
            #[cfg(not(feature = "remote"))]
            dynamic_build: false,
            results_folder: args.results_folder.clone(),
            error_folder: args.error_folder.clone(),
            // Left empty here and filled by the caller, because reading them is I/O and this is
            // called once per target: `options_std` reads the pool once and assigns it.
            crls: vec![],
            ocsp_responses: vec![],
        }
    }
}

/// Whether chasing AIA and SIA URIs is a remedy worth suggesting when path building comes up empty,
/// in the form [`NoPathsContext`] takes: `None` when the build cannot fetch at all, so proposing it
/// would send the user after an option that does not exist.
#[cfg(feature = "remote")]
fn dynamic_build_state(opts: &ValidateOpts) -> Option<bool> {
    Some(opts.dynamic_build)
}

/// Without the `remote` feature there is no fetching to enable, whatever the option says.
#[cfg(not(feature = "remote"))]
fn dynamic_build_state(_opts: &ValidateOpts) -> Option<bool> {
    None
}

/// Reads every DER- or PEM-encoded revocation artifact named by `paths` into memory, sorted into
/// the CRLs and the OCSP responses by what the bytes turn out to be.
///
/// Each entry may name a single artifact or a folder to traverse. Nothing is filtered by extension,
/// deliberately: an OCSP response has no settled one — tools write `.ors`, `.der`, `.resp`, or
/// nothing at all — so a name-based filter is a guess that silently drops the file it failed to
/// anticipate. Deciding from the bytes cannot fail that way, and a file that is neither is reported
/// and skipped.
///
/// This is read-only. It is the non-destructive counterpart of `crl_folder`, which is an *index*:
/// that folder is written as well as read, and indexing deletes any CRL not valid at the time of
/// interest. An artifact named here is used and left alone.
#[cfg(all(feature = "std", feature = "revocation"))]
pub fn load_revocation_inputs<'a>(paths: impl IntoIterator<Item = &'a str>) -> RevocationInputs {
    use x509_cert::certificate::Raw;
    use x509_cert::crl::CertificateList;

    let mut out = RevocationInputs::default();
    for path in paths {
        let p = Path::new(path);
        let files: Vec<std::path::PathBuf> = if p.is_file() {
            vec![p.to_path_buf()]
        } else {
            WalkDir::new(p)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| !e.file_type().is_dir())
                .map(|e| e.path().to_path_buf())
                .collect()
        };
        if files.is_empty() {
            error!("No revocation artifact was read from {path}");
            continue;
        }
        for file in files {
            let name = file.to_string_lossy().to_string();
            // PEM-aware, because a CRL is commonly distributed that way and the CRL folder reader
            // accepts both; an OCSP response is always DER, and passing DER through is a no-op.
            let Ok(bytes) = get_file_as_byte_vec_pem(&file) else {
                error!("Failed to read {name}");
                continue;
            };
            if CertificateList::<Raw>::from_der(bytes.as_slice()).is_ok() {
                out.crls.push(bytes);
                continue;
            }
            match crate::ocsp_match::answered_cert_ids(bytes.as_slice()) {
                Ok(_) => out.ocsp_responses.push(bytes),
                // The OCSP reader's message is the more specific of the two -- it distinguishes
                // "not an OCSP response" from a response that reports an error status or answers
                // about nothing -- so it is the one worth showing.
                Err(why) => error!("Ignoring {name}: it is not a CRL, and {why}"),
            }
        }
    }
    out
}

/// The revocation artifacts a run was handed, split by kind. Two vectors rather than one because
/// they are stapled by different rules: a CRL matches on issuer name, an OCSP response on the
/// `CertID` it answers about.
#[cfg(all(feature = "std", feature = "revocation"))]
#[derive(Clone, Debug, Default)]
pub struct RevocationInputs {
    /// DER-encoded CRLs.
    pub crls: Vec<Vec<u8>>,
    /// DER-encoded OCSP responses.
    pub ocsp_responses: Vec<Vec<u8>>,
}

#[cfg(all(feature = "std", feature = "revocation"))]
impl RevocationInputs {
    /// Whether nothing at all was read.
    pub fn is_empty(&self) -> bool {
        self.crls.is_empty() && self.ocsp_responses.is_empty()
    }
}

/// `staple_ocsp_responses` staples caller-provided DER-encoded OCSP responses into a candidate
/// certification path, filing each response against the positions whose certificate it answers
/// about. Positions that already carry a response are left alone.
///
/// The response says what it is about, so the caller does not have to: an OCSP `CertID` names the
/// certificate and its issuer, and [`ocsp_match`](crate::ocsp_match) builds the request certval
/// would have sent for each position and compares. One response can therefore answer for more than
/// one position, and a response that answers for none is stapled nowhere — the path is validated as
/// though it had not been supplied, which is what the caller would want: the response is about some
/// other certificate.
#[cfg(all(feature = "std", feature = "revocation"))]
fn staple_ocsp_responses(path: &mut CertificationPath, responses: &[Vec<u8>]) {
    use crate::ocsp_match::{answered_cert_ids, answers_about};

    if responses.is_empty() {
        return;
    }

    let mut parsed = vec![];
    for bytes in responses {
        match answered_cert_ids(bytes.as_slice()) {
            Ok(ids) => parsed.push((ids, bytes)),
            Err(why) => error!("Failed to read a provided OCSP response for stapling: {why}"),
        }
    }

    let num_certs = path.intermediates.len() + 1;
    let mut staples: Vec<(usize, Vec<u8>)> = vec![];
    for pos in 0..num_certs {
        if path
            .ocsp_responses
            .get(pos)
            .map(|r| r.is_some())
            .unwrap_or(true)
        {
            continue;
        }
        // Position 0 is issued by the trust anchor; every other position by the one before it.
        let cert = if pos < path.intermediates.len() {
            &path.intermediates[pos]
        } else {
            &path.target
        };
        let issuer: &dyn SubjectNameAndKey = if 0 == pos {
            &path.trust_anchor.decoded_ta
        } else {
            path.intermediates[pos - 1].as_ref()
        };
        for (ids, bytes) in &parsed {
            if answers_about(ids, cert, issuer) == Some(true) {
                staples.push((pos, (*bytes).clone()));
                break;
            }
        }
    }
    for (pos, bytes) in staples {
        path.ocsp_responses[pos] = Some(bytes);
    }
}

/// `staple_crls` staples caller-provided DER-encoded CRLs into a candidate certification path by
/// matching each CRL's issuer name to the issuer name of each certificate in the path. Positions
/// that already have a stapled CRL are left alone, as are CRLs that fail to parse (with a log
/// message). Stapled CRLs are consumed during revocation status determination.
#[cfg(feature = "std")]
fn staple_crls(path: &mut CertificationPath, crls: &[Vec<u8>]) {
    use x509_cert::certificate::Raw;
    use x509_cert::crl::CertificateList;

    if crls.is_empty() {
        return;
    }

    let mut parsed = vec![];
    for crl_bytes in crls {
        match CertificateList::<Raw>::from_der(crl_bytes.as_slice()) {
            Ok(crl) => parsed.push((crl, crl_bytes)),
            Err(e) => {
                error!("Failed to parse a provided CRL for stapling with {e}");
            }
        }
    }

    let num_certs = path.intermediates.len() + 1;
    let mut staples: Vec<(usize, Vec<u8>)> = vec![];
    for pos in 0..num_certs {
        if path.crls.get(pos).map(|c| c.is_some()).unwrap_or(true) {
            continue;
        }
        let issuer = if pos < path.intermediates.len() {
            path.intermediates[pos].decoded().tbs_certificate().issuer()
        } else {
            path.target.decoded().tbs_certificate().issuer()
        };
        for (crl, crl_bytes) in &parsed {
            if compare_names(&crl.tbs_cert_list.issuer, issuer) {
                staples.push((pos, (*crl_bytes).clone()));
                break;
            }
        }
    }
    for (pos, crl_bytes) in staples {
        path.crls[pos] = Some(crl_bytes);
    }
}

/// `validate_cert_file` attempts to validate the certificate read from the file indicated by
/// `cert_filename` using the resources available via the
/// [`PkiEnvironment`](certval::PkiEnvironment) parameter and the settings
/// available via [`CertificationPathSettings`](certval::CertificationPathSettings)
/// parameter.
///
/// This is a thin file-reading wrapper around [`validate_cert_bytes`]. `opts` is taken already
/// built rather than derived from [`Pittv3Args`] here, because it now carries the revocation
/// artifacts a run was handed and reading those per target would read the same files once for every
/// certificate validated.
#[cfg(feature = "std")]
pub(crate) async fn validate_cert_file(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cert_filename: &str,
    stats: &mut PathValidationStats,
    opts: &ValidateOpts,
    fresh_uris: &mut Vec<String>,
    threshold: usize,
) -> Result<()> {
    let target_bytes = get_file_as_byte_vec_pem(Path::new(&cert_filename))?;
    validate_cert_bytes(
        pe,
        cps,
        cert_filename,
        target_bytes.as_slice(),
        stats,
        opts,
        fresh_uris,
        threshold,
    )
    .await
}

/// `validate_cert_bytes` attempts to validate the certificate parsed from `target_bytes` using the
/// resources available via the [`PkiEnvironment`]
/// parameter and the settings available via
/// [`CertificationPathSettings`] parameter.
///
/// Where dynamic path building is used, path validation is governed by the `threshold` parameter,
/// i.e., only paths with at least one certificate at an index above the threshold will be validated.
/// The `opts` parameter contributes `results_folder`, `validate_all`, `error_folder` and `dynamic_build`.
/// Each path that is processed will be saved to the `results_folder`, if present in `opts`.
/// If `validate_all` is specified, validation will be attempted for all paths that were found by the builder.
/// If `error_folder` is specified, paths that fail validation will be logged there (in addition to the results_folder).
/// If `dynamic_build` is set, then URIs from the AIA and SIA extension of any trust anchor or
/// intermediate CA cert will be added to `fresh_uris`, if not already present. The caller may use these
/// URIs to fetch additional artifacts that may be used to build and validate additional certification paths.
/// The `stats` parameter is used to aggregate basic path processing statistics along with a
/// structured [`PathReport`] for each path processed.
#[cfg(feature = "std")]
#[allow(clippy::too_many_arguments)]
pub async fn validate_cert_bytes(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    name: &str,
    target_bytes: &[u8],
    stats: &mut PathValidationStats,
    opts: &ValidateOpts,
    fresh_uris: &mut Vec<String>,
    threshold: usize,
) -> Result<()> {
    let time_of_interest = cps.get_time_of_interest();
    let cert_filename = name;

    let target_cert = parse_cert(target_bytes, cert_filename)?;
    info!("Start building and validating path(s) for {cert_filename}");

    let start2 = Instant::now();
    stats.files_processed += 1;
    if stats.target_summary.is_none() {
        stats.target_summary = Some(CertSummary::from_cert(&target_cert));
    }

    // Diagnose a zero-path outcome here rather than where the report is assembled: this is where
    // the environment still holds the trust material, and where the target is parsed. Chasing is
    // reported as available-but-off from `opts` because this entry point performs no fetching
    // itself; the CLI's dynamic-building loop calls back in after each fetch, so the last pass
    // leaves the diagnosis that reflects everything that was retrieved.
    let diagnose = |pe: &PkiEnvironment| {
        NoPathsContext::collect(
            pe,
            &target_cert,
            time_of_interest,
            dynamic_build_state(opts),
        )
        .hints()
    };

    let mut paths: Vec<CertificationPath> = vec![];
    let r = pe.get_paths_for_target(&target_cert, &mut paths, threshold, time_of_interest);
    if let Err(e) = r {
        error!("Failed to find certification paths for target with error {e:?}");
        stats.no_paths_hints = diagnose(pe);
        return Err(Error::Unrecognized);
    }

    if paths.is_empty() {
        collect_uris_from_aia_and_sia(&target_cert, fresh_uris);
        info!("Failed to find any certification paths for target",);
        stats.no_paths_hints = diagnose(pe);
        return Err(Error::Unrecognized);
    }

    // A path was found, so any diagnosis from an earlier pass of the dynamic-building loop is stale
    stats.no_paths_hints.clear();

    for (i, path) in paths.iter_mut().enumerate() {
        info!(
            "Validating {} certificate path for {}",
            (path.intermediates.len() + 2),
            path.target.decoded().tbs_certificate().subject()
        );
        let path_start = Instant::now();
        staple_crls(path, &opts.crls);
        #[cfg(feature = "revocation")]
        staple_ocsp_responses(path, &opts.ocsp_responses);
        let mut cpr = CertificationPathResults::new();

        // fold RFC 5914 trust anchor constraints into the settings per RFC 5937; this is a no-op
        // clone when enforcement is disabled, and validate_path does not perform it itself
        let path_cps = match enforce_trust_anchor_constraints(cps, &path.trust_anchor) {
            Ok(path_cps) => path_cps,
            Err(e) => {
                error!("Failed to enforce trust anchor constraints for {cert_filename} with {e:?}");
                stats.invalid_paths_per_target += 1;
                stats.path_reports.push(PathReport::from_path_results(
                    path,
                    &CertificationPathResults::new(),
                    Some(&e),
                    (Instant::now() - path_start).as_millis() as u64,
                ));
                continue;
            }
        };

        #[cfg(not(feature = "revocation"))]
        let r = pe.validate_path(pe, &path_cps, path, &mut cpr);

        #[cfg(feature = "revocation")]
        let mut r = pe.validate_path(pe, &path_cps, path, &mut cpr);

        // Revocation checking rides the `revocation` feature, not `remote`: the async
        // `check_revocation` does local-CRL/cached/stapled checks and gates only the
        // network fetch on `remote` internally.
        #[cfg(feature = "revocation")]
        if r.is_ok() && path_cps.get_check_revocation_status() {
            r = check_revocation(pe, &path_cps, path, &mut cpr).await;
        }

        log_path(
            pe,
            &opts.results_folder,
            path,
            stats.paths_per_target + i,
            Some(&cpr),
            Some(&path_cps),
        );
        stats.path_reports.push(PathReport::from_path_results(
            path,
            &cpr,
            r.as_ref().err(),
            (Instant::now() - path_start).as_millis() as u64,
        ));
        stats.results.push(cpr);
        match r {
            Ok(_) => {
                stats.valid_paths_per_target += 1;

                info!("Successfully validated {cert_filename}");
                if !opts.validate_all {
                    break;
                }
            }
            Err(e) => {
                stats.invalid_paths_per_target += 1;

                log_path(pe, &opts.error_folder, path, i, None, None);
                if e == Error::PathValidation(PathValidationStatus::CertificateRevokedEndEntity) {
                    info!("Failed to validate {cert_filename} with {e:?}");
                    break;
                } else {
                    info!("Failed to validate {cert_filename} with {e:?}");
                }
            }
        }

        #[cfg(feature = "remote")]
        if opts.dynamic_build {
            // if we get here we are validating all possible paths with dynamic building. gather
            // up URIs from the trust anchor
            collect_uris_from_aia_and_sia_from_ta(&path.trust_anchor, fresh_uris);

            // This is possibly overkill as CA certs are processed during preparing of partial
            // paths following dynamic building. Without this, then URIs from certs in the
            // intially deserialized CBOR may not be followed.
            for c in path.intermediates.iter() {
                collect_uris_from_aia_and_sia(c, fresh_uris);
            }
        }
    }
    stats.paths_per_target += paths.len();

    let finish = Instant::now();
    let duration2 = finish - start2;
    info!(
        "{:?} to build and validate {} path(s) for {}",
        duration2,
        paths.len(),
        cert_filename
    );
    Ok(())
}

/// `validate_targets` builds and validates certification paths for a set of in-memory targets,
/// returning a structured [`ValidationReport`]. Each target is a (name, DER-encoded certificate)
/// pair; the name is a caller-assigned label (e.g., a filename) used in the report and log output.
///
/// This is the in-memory entry point for non-CLI frontends: no filesystem access occurs unless
/// `opts` supplies results/error folders, and no dynamic building loop is performed (URIs collected
/// while processing are discarded; callers wanting AIA/SIA chasing drive it themselves). CRLs
/// supplied via `opts.crls` are stapled into candidate paths by issuer name prior to validation.
///
/// Progress events are conveyed to the optional `progress` callback as each target is processed.
/// Path-level events are emitted after the paths for a target have been processed (i.e., events
/// stream between targets, not within a target).
#[cfg(feature = "std")]
pub async fn validate_targets(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    targets: &[(String, Vec<u8>)],
    opts: &ValidateOpts,
    progress: Option<&(dyn Fn(ProgressEvent) + Send + Sync + '_)>,
) -> ValidationReport {
    let start = Instant::now();
    let mut stats = PathValidationStatsGroup::new();
    let mut fresh_uris: Vec<String> = vec![];
    let mut target_reports: Vec<TargetReport> = vec![];
    let mut totals = ReportTotals::default();

    for (target_index, (name, der)) in targets.iter().enumerate() {
        if let Some(progress) = progress {
            progress(ProgressEvent::TargetStarted {
                target_index,
                name: name.clone(),
            });
        }

        stats.init_for_target(name);
        let stats_for_target = match stats.get_mut(name) {
            Some(stats_for_target) => stats_for_target,
            None => continue,
        };

        // snapshot counts so duplicate names contribute per-call deltas to the totals
        let prev_paths = stats_for_target.paths_per_target;
        let prev_valid = stats_for_target.valid_paths_per_target;
        let prev_invalid = stats_for_target.invalid_paths_per_target;

        let _ = validate_cert_bytes(
            pe,
            cps,
            name.as_str(),
            der.as_slice(),
            stats_for_target,
            opts,
            &mut fresh_uris,
            0,
        )
        .await;

        let paths_found = stats_for_target.paths_per_target - prev_paths;
        let path_reports = core::mem::take(&mut stats_for_target.path_reports);
        let status = TargetReport::compute_status(&path_reports, paths_found > 0);

        if let Some(progress) = progress {
            progress(ProgressEvent::PathsFound {
                target_index,
                count: paths_found,
            });
            for (path_index, path_report) in path_reports.iter().enumerate() {
                progress(ProgressEvent::PathCompleted {
                    target_index,
                    path_index,
                    valid: path_report.error.is_none()
                        && path_report.status == Some(PathValidationStatus::Valid),
                });
            }
            progress(ProgressEvent::TargetCompleted {
                target_index,
                status,
            });
        }

        let target_summary = match parse_cert(der.as_slice(), name.as_str()) {
            Ok(target_cert) => Some(CertSummary::from_cert(&target_cert)),
            Err(_e) => None,
        };
        let no_paths_hints = core::mem::take(&mut stats_for_target.no_paths_hints);

        totals.targets += 1;
        totals.paths_found += paths_found;
        totals.valid_paths += stats_for_target.valid_paths_per_target - prev_valid;
        totals.invalid_paths += stats_for_target.invalid_paths_per_target - prev_invalid;

        target_reports.push(TargetReport {
            name: name.clone(),
            target: target_summary,
            status,
            paths: path_reports,
            no_paths_hints,
        });
    }

    ValidationReport {
        targets: target_reports,
        totals,
        time_of_interest: cps.get_time_of_interest().as_unix_secs(),
        duration_ms: (Instant::now() - start).as_millis() as u64,
        error: None,
    }
}

/// validate_cert_folder recursively traverses the given `certs_folder` and invokes `validate_cert_file`
/// for each .der, .crt or .cer file that is found.
#[async_recursion::async_recursion]
#[cfg(feature = "std")]
pub async fn validate_cert_folder(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    certs_folder: &str,
    stats: &mut PathValidationStatsGroup,
    opts: &ValidateOpts,
    fresh_uris: &mut Vec<String>,
    threshold: usize,
) {
    for entry in WalkDir::new(certs_folder) {
        match entry {
            Ok(e) => {
                let path = e.path();
                if e.file_type().is_dir() {
                    if let Some(s) = path.to_str() {
                        if s != certs_folder {
                            validate_cert_folder(pe, cps, s, stats, opts, fresh_uris, threshold)
                                .await;
                        }
                    } else {
                        error!("Skipping file due to invalid Unicode in name",);
                    }
                } else {
                    let mut do_validate = false;
                    if let Some(filename) = path.to_str() {
                        if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                            if SINGLE_CERT_EXTENSIONS.contains(&ext) {
                                do_validate = true;
                            }
                        }

                        if do_validate {
                            stats.init_for_target(filename);
                            if let Some(stats_for_file) = stats.get_mut(filename) {
                                if opts.validate_all
                                    || (stats_for_file.valid_paths_per_target == 0
                                        && !stats_for_file.target_is_revoked)
                                {
                                    // validate when validating all or we don't have a definitive answer yet
                                    let _ = validate_cert_file(
                                        pe,
                                        cps,
                                        filename,
                                        stats_for_file,
                                        opts,
                                        fresh_uris,
                                        threshold,
                                    )
                                    .await;
                                }
                            }
                        } else {
                            info!("Skipping {filename}");
                        }
                    }
                }
            }
            _ => {
                error!("Failed to unwrap entry in {certs_folder}");
            }
        }
    }
}

/// generate takes a Pittv3Args structure containing at least `cbor`, `ca-folder` and a source of
/// trust anchors (`ta-cbor`, `ta-folder`, `ta-inputs` or `webpki-tas`) and then calls
/// [`build_graph`].
///
/// The CA material is the one folder `ca-folder` names, because [`build_graph`] reads it from a
/// single certification-authority-folder setting; the `ca-inputs` pool is a validation-time input
/// and is not consulted here.
/// Where dynamic building is in effect, the `download-folder` option will be used if present (else
/// ca-folder is used as destination for downloaded artifacts).
#[cfg(feature = "std")]
pub async fn generate(
    args: &Pittv3Args,
    cps: &mut CertificationPathSettings,
    pe: &mut PkiEnvironment,
) {
    let start = Instant::now();

    let no_anchors =
        args.ta_cbor.is_none() && args.ta_folder.is_none() && args.ta_inputs.is_empty();

    // Reported through the log rather than stdout: a GUI captures the log and never sees a
    // println, so a run that stopped here looked to a user like a run that did nothing at all.
    #[cfg(feature = "webpki")]
    if args.cbor.is_none() || (no_anchors && !args.webpki_tas) || args.ca_folder.is_none() {
        error!("The cbor and ca-folder options are required when generate is specified plus one of ta-cbor, ta-folder, ta-inputs or webpki-tas. Generation reads its CA certificates from the one folder ca-folder names, so a ca-inputs pool does not satisfy it.");
        return;
    }

    #[cfg(not(feature = "webpki"))]
    if args.cbor.is_none() || no_anchors || args.ca_folder.is_none() {
        error!("The cbor and ca-folder options are required when generate is specified plus one of ta-cbor, ta-folder or ta-inputs. Generation reads its CA certificates from the one folder ca-folder names, so a ca-inputs pool does not satisfy it.");
        return;
    }

    if let Some(ca_folder) = &args.ca_folder {
        cps.set_certification_authority_folder(ca_folder.to_string());
    }

    #[cfg(feature = "remote")]
    if let Some(download_folder) = &args.download_folder {
        cps.set_download_folder(download_folder.to_string());
    }

    cps.set_cbor_ta_store(args.cbor_ta_store);

    let graph = build_graph(pe, cps).await;
    match graph {
        Ok(graph) => {
            if let Some(cbor) = args.cbor.as_ref() {
                // Not expect(): an unwritable path is a typo, not a bug, and panicking here took
                // the run's worker thread with it. Naming the file it wrote also answers "where
                // did the store go", which the argument alone does not.
                match fs::write(cbor, graph.as_slice()) {
                    Ok(()) => info!("Wrote the generated store to {cbor}"),
                    Err(e) => error!("Failed to write the generated store to {cbor}: {e}"),
                }
            }
        }
        Err(e) => error!("Failed to generate the store: {e:?}"),
    }
    info!("Generation took {:?}", Instant::now() - start);
}

/// `cleanup_certs` attempts to remove files that cannot be used from the indicated `certs_folder`
/// subject to the `report_only` parameter.
///
/// Where `report_only` is true, files are not cleaned up but are simply logged. Where `report_only`
/// is false, files are cleaned up, which means deleted if `error_folder` is absent or moved if present.
///
/// Files are elected for cleanup for the following reasons:
/// - File cannot be parsed as a certificate
/// - Certificate is not valid at indicated time `t`
/// - Certificate is not a CA certificate
/// - Certificate is self-signed
#[cfg(feature = "std")]
pub fn cleanup_certs(
    pe: &PkiEnvironment,
    certs_folder: &str,
    error_folder: &str,
    report_only: bool,
    t: TimeOfInterest,
) {
    for entry in WalkDir::new(certs_folder) {
        match entry {
            Ok(e) => {
                let path = e.path();
                if e.file_type().is_dir() {
                    if let Some(s) = path.to_str() {
                        if s != certs_folder {
                            info!("Recursing {}", path.display());
                            cleanup_certs(pe, s, error_folder, report_only, t);
                        }
                    }
                } else {
                    let filename = path.to_str().unwrap_or("");
                    if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                        // Single, not bundle: this decides keep-or-delete per file, which has no
                        // meaning yet for a container holding several certificates.
                        if !SINGLE_CERT_EXTENSIONS.contains(&ext) {
                            // non-certificate extension
                            continue;
                        }
                    } else {
                        // no extension
                        continue;
                    }

                    let target = get_file_as_byte_vec_pem(path).unwrap_or_default();
                    if target.is_empty() {
                        error!("Failed to read target file at {filename}");
                        continue;
                    }

                    let mut delete_file = false;
                    match parse_cert(target.as_slice(), filename) {
                        Ok(tc) => {
                            if !t.is_disabled() {
                                let r = valid_at_time(tc.decoded().tbs_certificate(), t, true);
                                if let Err(_e) = r {
                                    delete_file = true;
                                    error!(
                                        "Not valid at indicated time of interest ({t}): {filename}"
                                    );
                                }
                            }

                            if is_self_signed(pe, &tc) {
                                delete_file = true;
                                error!("Self-signed: {filename}");
                            }

                            let bc = tc.get_extension(&ID_CE_BASIC_CONSTRAINTS);
                            if let Ok(Some(PDVExtension::BasicConstraints(bc))) = bc {
                                if !bc.ca {
                                    delete_file = true;
                                    error!("Not a CA per basicConstraints: {filename}");
                                }
                            } else {
                                delete_file = true;
                                error!("Missing basicConstraints: {filename}");
                            }
                        }
                        Err(_e) => {
                            //parse_cert writes out a log messaage
                            delete_file = true;
                        }
                    }

                    if !report_only && delete_file {
                        delete_or_move_file(error_folder, path, filename);
                    }
                }
            }
            Err(e) => {
                println!("Failed to unwrap entry: {e}");
            }
        } // end match entry {
    } // end for entry in WalkDir::new(certs_folder)
}

/// `cleanup_tas` attempts to remove files that cannot be used from the indicated `tas_folder`
/// subject to the `report_only` parameter.
///
/// Where `report_only` is true, files are not cleaned up but are simply logged. Where `report_only`
/// is false, files are cleaned up, which means deleted if `error_folder` is absent or moved if present.
///
/// Files are elected for cleanup for the following reasons:
/// - File cannot be parsed as a trust anchor
/// - Trust anchor is not valid at indicated time `t`
#[cfg(feature = "std")]
pub fn cleanup_tas(
    _pe: &PkiEnvironment,
    tas_folder: &str,
    error_folder: &str,
    report_only: bool,
    t: TimeOfInterest,
) {
    for entry in WalkDir::new(tas_folder) {
        match entry {
            Ok(e) => {
                let path = e.path();
                if e.file_type().is_dir() {
                    if let Some(s) = path.to_str() {
                        if s != tas_folder {
                            info!("Recursing {}", path.display());
                            cleanup_tas(_pe, s, error_folder, report_only, t);
                        }
                    }
                } else {
                    let filename = path.to_str().unwrap_or("");
                    if let Some(ext) = e.path().extension().and_then(OsStr::to_str) {
                        // Single, not bundle: as with cleanup_certs, the keep-or-delete decision
                        // is per file.
                        if !SINGLE_CERT_EXTENSIONS.contains(&ext) && "ta" != ext {
                            // non-certificate extension
                            continue;
                        }
                    } else {
                        // no extension
                        continue;
                    }

                    let target = get_file_as_byte_vec_pem(e.path()).unwrap_or_default();
                    if target.is_empty() {
                        error!("Failed to read target file at {filename}");
                        continue;
                    }

                    let mut delete_file = false;
                    match TrustAnchorChoice::from_der(target.as_slice()) {
                        Ok(ta) => {
                            // Only a failed validity check condemns the file. An anchor that asserts
                            // no validity period returns Ok(None) and must be kept: cleanup deletes
                            // or moves what it rejects, so treating "nothing to check" as "expired"
                            // would destroy every RFC 5914 anchor carrying only a name and key.
                            let r = ta_valid_at_time(&ta, t, true);
                            if r.is_err() {
                                delete_file = true;
                                error!("Not valid at indicated time of interest ({t}): {filename}");
                            }
                        }
                        Err(e) => {
                            error!("Failed to parse trust anchor at {filename} with {e}");
                            delete_file = true;
                        }
                    }

                    if !report_only && delete_file {
                        delete_or_move_file(error_folder, path, filename);
                    }
                }
            }
            Err(e) => {
                println!("Failed to unwrap entry: {e}");
            }
        } // end match entry {
    } // end for entry in WalkDir::new(certs_folder)
}

fn delete_or_move_file(error_folder: &str, path: &Path, filename: &str) {
    if error_folder.is_empty() {
        //delete file
        let r = fs::remove_file(path);
        if let Err(e) = r {
            println!("Failed to delete {filename} with {e:?}");
            error!("Failed to delete {filename} with {e:?}");
        }
    } else if let Some(new_filename) = Path::new(error_folder).join(path).file_name() {
        // move file
        let r = fs::rename(filename, new_filename);
        if let Err(e) = r {
            println!("Failed to delete {filename} with {e:?}");
            error!("Failed to delete {filename} with {e:?}");
        }
    }
}

/// `cleanup` implements the `cleanup` option using [`cleanup_certs`] for support.
#[cfg(feature = "std")]
pub fn cleanup(pe: &PkiEnvironment, args: &Pittv3Args) {
    let ca_folder = if let Some(ca_folder) = &args.ca_folder {
        ca_folder
    } else {
        println!("The ca-folder option must be specified when using the cleaup option");
        return;
    };

    let error_folder = if let Some(error_folder) = &args.error_folder {
        error_folder
    } else {
        ""
    };
    cleanup_certs(
        pe,
        ca_folder,
        error_folder,
        args.report_only,
        TimeOfInterest::from_unix_secs(args.time_of_interest).unwrap(),
    );
}

/// `ta_cleanup` implements the `ta-cleanup` option using [`cleanup_tas`] for support.
#[cfg(feature = "std")]
pub fn ta_cleanup(pe: &PkiEnvironment, args: &Pittv3Args) {
    let ta_folder = if let Some(ta_folder) = &args.ta_folder {
        ta_folder
    } else {
        println!("The ta-folder option must be specified when using the ta-cleaup option");
        return;
    };

    let error_folder = if let Some(error_folder) = &args.error_folder {
        error_folder
    } else {
        ""
    };
    cleanup_tas(
        pe,
        ta_folder,
        error_folder,
        args.report_only,
        TimeOfInterest::from_unix_secs(args.time_of_interest).unwrap(),
    );
}
