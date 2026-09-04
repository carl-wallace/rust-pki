//! Contains utility functions related to certification path validation, CBOR file generation and
//! trust anchor/certificate folder cleanup.
#![cfg(feature = "std")]

extern crate alloc;

use alloc::string::String;
#[cfg(all(windows, feature = "capi"))]
use core::str::FromStr;
use log::{debug, error, info};
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
        TargetStatus, ValidationReport,
    },
    retained::RetainedPath,
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

/// Parses `Location\Name` CAPI store specifications, naming the one that failed.
///
/// Rejects the whole set on the first bad entry rather than skipping it: a mistyped store name
/// would otherwise read as an empty store, and a run that silently proceeds with fewer anchors
/// than the user asked for is the failure mode worth avoiding here.
#[cfg(all(windows, feature = "capi"))]
pub fn parse_capi_stores(specs: &[String]) -> core::result::Result<Vec<CapiStore>, String> {
    let mut stores = Vec::with_capacity(specs.len());
    for spec in specs {
        match CapiStore::from_str(spec) {
            Ok(store) => stores.push(store),
            Err(e) => {
                return Err(format!(
                    "{spec} is not a usable CAPI store name ({e:?}). Expected a name like \
                     LocalMachine\\ROOT or CurrentUser\\CA, or a bare store name for a \
                     current-user store"
                ))
            }
        }
    }
    Ok(stores)
}

/// Reads intermediate CA certificates from CAPI stores into `cert_source`.
///
/// The counterpart of [`load_ca_inputs`] for stores rather than paths. Pushed into the same source
/// so the certificates take part in one graph, and deduplicated against it by
/// [`CertVector::push`].
#[cfg(all(windows, feature = "capi"))]
pub fn load_capi_ca_stores(
    specs: &[String],
    cert_source: &mut CertSource,
) -> core::result::Result<usize, String> {
    if specs.is_empty() {
        return Ok(0);
    }
    let stores = parse_capi_stores(specs)?;
    let before = cert_source.len();
    match certfiles_from_capi(&stores, &CapiReadOptions::default()) {
        Ok(certfiles) => {
            for cf in certfiles {
                cert_source.push(cf);
            }
            let added = cert_source.len() - before;
            info!(
                "Added {added} certificate(s) from CAPI store(s) {}",
                specs.join(", ")
            );
            Ok(added)
        }
        Err(e) => Err(format!(
            "failed to read certificates from CAPI store(s) {}: {e:?}",
            specs.join(", ")
        )),
    }
}

/// Builds the trust anchor store named by the `ta_cbor`, `ta_folder`, `ta_inputs` and
/// `capi_ta_stores` arguments, or `None` when none of them was given.
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
///
/// **Anchors are loaded whatever their validity period says.** A trust anchor is trust in a *key*,
/// and RFC 5280 path validation does not check the anchor's own validity; whether an expired one
/// may anchor a path is what `PS_ENFORCE_TRUST_ANCHOR_VALIDITY` decides, during validation, where
/// the user can turn it off. Filtering here instead would decide it for them and leave that setting
/// with nothing to act on — and it did, until 2026-09-03: a folder of eleven anchors loaded ten,
/// while the same folder uploaded to the browser app loaded eleven, because that side never had the
/// filter. The anchor a run declines to use is a validation result and reads as one; an anchor
/// dropped as the folder is read is indistinguishable from a path that was never there. Use
/// `--ta-cleanup`, which exists to remove expired anchors and says so, when that is what is wanted.
#[cfg(feature = "std")]
pub fn load_trust_anchors(
    pe: &PkiEnvironment,
    args: &Pittv3Args,
) -> core::result::Result<Option<TaSource>, String> {
    #[cfg(all(windows, feature = "capi"))]
    let no_capi = args.capi_ta_stores.is_empty();
    #[cfg(not(all(windows, feature = "capi")))]
    let no_capi = true;

    if args.ta_cbor.is_none() && args.ta_folder.is_none() && args.ta_inputs.is_empty() && no_capi {
        return Ok(None);
    }

    let mut ta_store = TaSource::new();

    // Folded into this store rather than registered as a source of its own, so that the stores are
    // one more input among the others rather than a second anchor set beside them: a machine root
    // the user has also placed in a folder is then carried once and logged once. Read before the
    // file-based inputs below, so a shared anchor keeps the provenance of the store it came from.
    #[cfg(all(windows, feature = "capi"))]
    if !args.capi_ta_stores.is_empty() {
        let stores = parse_capi_stores(&args.capi_ta_stores)?;
        match certfiles_from_capi(&stores, &CapiReadOptions::default()) {
            Ok(certfiles) => {
                for cf in certfiles {
                    ta_store.push(cf);
                }
            }
            Err(e) => {
                return Err(format!(
                    "failed to read trust anchors from CAPI store(s) {}: {e:?}",
                    args.capi_ta_stores.join(", ")
                ))
            }
        }
    }

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
        push_trust_anchor_input(pe, path, &mut ta_store, TimeOfInterest::disabled())?;
    }

    if let Err(e) = ta_store.initialize() {
        return Err(format!(
            "failed to initialize trust anchor source with error {e:?}"
        ));
    }

    Ok(Some(ta_store))
}

/// How many trust anchors the entries in a trust anchor input pool would contribute.
///
/// Answers the question the pool's own length cannot: an entry may be a folder, a bundle carrying
/// several anchors, or a CBOR store, so the number of entries and the number of anchors a run will
/// have are different numbers, and it is the second one a caller looks at the pool to learn.
///
/// The inputs are loaded exactly as [`load_trust_anchors`] loads them and the size of the result is
/// read off, so this is the number the run will use rather than an estimate of it -- including the
/// deduplication `push` performs, which a per-entry sum would miss.
///
/// An input that cannot be read contributes nothing rather than failing. This describes a set of
/// inputs while it is still being assembled; the run is where a trust anchor that will not load is
/// an error, and it says so there.
///
/// There is no time of interest here, and taking one would be the bug: [`load_trust_anchors`] loads
/// anchors without regard to their validity period, so a count taken *as of* a moment would differ
/// from the number the run goes on to use, and the pool would be telling the user something the run
/// then contradicts. The CA-side counterparts still take one because their loading still filters.
#[cfg(feature = "std")]
pub fn count_trust_anchor_inputs<'a>(paths: impl IntoIterator<Item = &'a str>) -> usize {
    let pe = PkiEnvironment::default();
    let mut ta_store = TaSource::new();
    for path in paths {
        if let Err(e) =
            push_trust_anchor_input(&pe, path, &mut ta_store, TimeOfInterest::disabled())
        {
            debug!("Counting no trust anchors from {path}: {e}");
        }
    }
    ta_store.len()
}

/// The time the counting functions judge validity against, from the epoch seconds a frontend holds.
///
/// A value certval will not take as a time disables the check rather than substituting one: the
/// alternative is counting against *some other* moment, and a count that quietly answers a
/// different question than it was asked is worse than one that checks nothing.
#[cfg(feature = "std")]
fn counting_time_of_interest(time_of_interest: u64) -> TimeOfInterest {
    match TimeOfInterest::from_unix_secs(time_of_interest) {
        Ok(toi) => toi,
        Err(_e) => TimeOfInterest::disabled(),
    }
}

/// How many certificates the entries in a CA input pool would contribute, the CA-side counterpart
/// of [`count_trust_anchor_inputs`] and built the same way, by running [`load_ca_inputs`] over a
/// store of its own.
///
/// A CBOR store named on its own is adopted whole, so what comes back for one is the store's own
/// size; combined with anything else only its certificates count, which is again what the run does
/// with the same inputs.
#[cfg(feature = "std")]
pub fn count_ca_inputs<'a>(
    paths: impl IntoIterator<Item = &'a str>,
    time_of_interest: u64,
) -> usize {
    let pe = PkiEnvironment::default();
    let mut cert_source = CertSource::new();
    load_ca_inputs(
        &pe,
        paths,
        &mut cert_source,
        counting_time_of_interest(time_of_interest),
    )
    .certs
}

/// How many targets the entries in an end entity input pool would yield.
///
/// A folder entry is traversed for the certificates in it, exactly as `validate_cert_folder` does
/// and by the same extension filter, so a folder counts as the targets it holds rather than as one.
/// A file entry counts as one target whatever it holds: unlike the trust anchor and CA inputs, an
/// end entity file is decoded as a single certificate and a bundle named here is not fanned out.
///
/// Repeats collapse, because the run keys its per-target statistics by file name and a file named
/// twice is validated once.
#[cfg(feature = "std")]
pub fn count_end_entity_inputs<'a>(paths: impl IntoIterator<Item = &'a str>) -> usize {
    let mut targets: Vec<String> = vec![];
    let mut count = |name: String| {
        if !targets.contains(&name) {
            targets.push(name);
        }
    };

    for path in paths {
        if !Path::new(path).is_dir() {
            count(path.to_string());
            continue;
        }
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_dir() {
                continue;
            }
            let ext = entry.path().extension().and_then(OsStr::to_str);
            let is_certificate = ext.is_some_and(|ext| SINGLE_CERT_EXTENSIONS.contains(&ext));
            let Some(name) = entry.path().to_str() else {
                continue;
            };
            if is_certificate {
                count(name.to_string());
            }
        }
    }
    targets.len()
}

/// How many CRLs and how many OCSP responses, in that order, the entries in a revocation input pool
/// would supply.
///
/// Reads the artifacts and discards them, since which kind a file holds is decided from its bytes
/// (see [`load_revocation_inputs`]) and there is no cheaper way to ask. A folder entry is traversed,
/// so it counts as what is in it.
#[cfg(all(feature = "std", feature = "revocation"))]
pub fn count_revocation_inputs<'a>(paths: impl IntoIterator<Item = &'a str>) -> (usize, usize) {
    let inputs = load_revocation_inputs(paths);
    (inputs.crls.len(), inputs.ocsp_responses.len())
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
#[allow(clippy::too_many_arguments)]
pub(crate) async fn validate_cert_file(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cert_filename: &str,
    stats: &mut PathValidationStats,
    opts: &ValidateOpts,
    fresh_uris: &mut Vec<String>,
    threshold: usize,
    retain: Option<&mut Vec<RetainedPath>>,
) -> Result<()> {
    // A file the walk admitted and the reader cannot deliver never becomes a target, so record why
    // here: nothing downstream sees this file again, and without it the entry reaches the report as
    // an unexplained absence of paths.
    let target_bytes = match get_file_as_byte_vec_pem(Path::new(&cert_filename)) {
        Ok(bytes) => bytes,
        Err(e) => {
            stats.no_path_reason = Some((TargetStatus::ParseError, format!("{e:?}")));
            return Err(e);
        }
    };
    validate_cert_bytes_retaining(
        pe,
        cps,
        cert_filename,
        target_bytes.as_slice(),
        stats,
        opts,
        fresh_uris,
        threshold,
        retain,
    )
    .await
}

/// Identifies a certification path by its certificates: the trust anchor, then the intermediates in
/// order, then the target, hashed together.
///
/// Order is part of the identity, so the same certificates arranged into a different chain hash
/// differently, and the anchor is included so that two routes over identical intermediates from
/// different anchors stay distinct.
#[cfg(feature = "std")]
fn chain_fingerprint(path: &CertificationPath) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(path.trust_anchor.encoded_ta.as_slice());
    for ca in path.intermediates.iter() {
        hasher.update(ca.as_bytes());
    }
    hasher.update(path.target.as_bytes());
    hasher.finalize().to_vec()
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
    validate_cert_bytes_retaining(
        pe,
        cps,
        name,
        target_bytes,
        stats,
        opts,
        fresh_uris,
        threshold,
        None,
    )
    .await
}

/// As [`validate_cert_bytes`], additionally pushing each validated path onto `retain` when one is
/// given, so a caller can export the artifacts behind a result without validating a second time.
///
/// Validating again to produce an export would describe a *different* run — revocation data moves,
/// and a responder asked twice may answer differently — so the material has to be kept from the run
/// being reported rather than reconstructed from it afterwards.
///
/// Retention is per call site rather than a setting: a results folder has to be asked for before a
/// run, and this exists for the person who only wants the material once they have seen the outcome.
/// A caller that means to export keeps the [`PkiEnvironment`] alive too — see
/// [`crate::retained::RetainedPath`] for why the CRLs are not held here.
#[allow(clippy::too_many_arguments)]
pub async fn validate_cert_bytes_retaining(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    name: &str,
    target_bytes: &[u8],
    stats: &mut PathValidationStats,
    opts: &ValidateOpts,
    fresh_uris: &mut Vec<String>,
    threshold: usize,
    mut retain: Option<&mut Vec<RetainedPath>>,
) -> Result<()> {
    let time_of_interest = cps.get_time_of_interest();
    let cert_filename = name;

    // An input reaches here because something claimed it was a certificate -- the walk admits a file
    // by its extension, and a caller naming bytes directly is making the same claim. When it is not
    // one, that is the whole of what happened to it: no path was sought, so no store and no setting
    // is implicated, and saying "no paths found" pointed users at trust material over a file that
    // was never a certificate.
    let target_cert = match parse_cert(target_bytes, cert_filename) {
        Ok(target_cert) => target_cert,
        Err(e) => {
            error!("Failed to parse a certificate from {cert_filename}: {e:?}");
            stats.no_path_reason = Some((TargetStatus::ParseError, format!("{e:?}")));
            return Err(e);
        }
    };
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
        // A PathValidation error means a check rejected the target itself while the path was being
        // built (e.g. it is not valid at the time of interest) -- a rejection of the certificate,
        // not an absence of candidate issuers. No path exists either way, so this contributes no
        // paths; what it contributes is the reason, which belongs on the target. Reporting it as
        // the neutral "no paths found" instead reads like a store or configuration problem when
        // nothing about either is wrong. Every other error keeps the no-paths-found outcome.
        if let Error::PathValidation(pvs) = &e {
            let reason = format!("{pvs:?}");
            error!("{cert_filename}: certificate rejected during path building - {reason}");
            stats.no_path_reason = Some((TargetStatus::Invalid, reason));
            return Err(e);
        }
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

    // `reported` indexes the result folders, so it advances only for paths actually written.
    // `suppressed` is subtracted from the total below. The two are deliberately different: a path
    // the deduplication drops was never a new path and must not be counted, while a path the builder
    // found and the loop never reached -- validation stops at the first success unless validate_all
    // is set -- WAS found, and subtracting it would collapse "Paths found" into "Valid paths found"
    // and hide that a second candidate existed.
    let mut reported = 0usize;
    let mut suppressed = 0usize;

    // Every path the builder returned is recorded here, before any of them is validated, rather
    // than as each one is reached.
    //
    // The dynamic-building loop calls back in once per pass and the builder can offer a path an
    // earlier pass already returned; having recorded it is what lets the repeat be skipped, which
    // is worth doing before validating rather than after, since a repeat costs a signature check
    // and a revocation round trip. Recording a path where it is validated misses every path the
    // loop never reaches -- it stops at the first success unless validate_all is set, and always at
    // a revoked end entity -- so those went unrecorded, were offered again on the next pass,
    // suppressed nothing, and were counted a second time. Over eight revoked targets one run
    // counted twenty paths twice that way, which is what made it report more paths found than the
    // same material yielded in the browser, whose totals come from the reports themselves.
    //
    // Logged at debug on every suppression on purpose. Deduplicating here is a backstop over
    // whatever the builder's own `threshold` did, so silence would hide the builder handing back
    // paths it was asked to withhold; a run that suppresses nothing says the threshold held.
    let mut to_validate = Vec::with_capacity(paths.len());
    for (i, path) in paths.iter().enumerate() {
        if stats.reported_chains.insert(chain_fingerprint(path)) {
            to_validate.push(i);
        } else {
            debug!(
                "Suppressing a certification path already reported for {cert_filename} (offered again with threshold {threshold})"
            );
            suppressed += 1;
        }
    }

    for i in to_validate {
        let path = &mut paths[i];
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
                // Counted like any other reported path: it was found, judged and recorded as
                // invalid, so leaving it out of the total would make the reports outnumber the paths.
                reported += 1;
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
            stats.paths_per_target + reported,
            Some(&cpr),
            Some(&path_cps),
        );
        reported += 1;
        stats.path_reports.push(PathReport::from_path_results(
            path,
            &cpr,
            r.as_ref().err(),
            (Instant::now() - path_start).as_millis() as u64,
        ));
        // Kept for a later export, with the settings this path was actually judged under rather than
        // the run's -- `path_cps` carries the RFC 5937 trust anchor constraints folded in above, and
        // a manifest reporting the run's settings would name inputs the path was not validated
        // against. Paths that failed are kept too: a failure is the case someone most wants the
        // material for. Cloned because `cpr` is moved into `stats` on the next line and the path
        // belongs to the built set.
        if let Some(retained) = retain.as_deref_mut() {
            retained.push(RetainedPath {
                target_name: name.to_string(),
                path: path.clone(),
                cps: path_cps.clone(),
                cpr: cpr.clone(),
            });
        }
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
                info!("Failed to validate {cert_filename} with {e:?}");
                // A revoked end entity is the same certificate on every candidate path, so the
                // first path to report it has settled the target and the rest cost a signature
                // check and a revocation lookup to reach the same answer. Stop for the same reason
                // and under the same condition as a successful path does: the run has what it came
                // for, unless validate_all asked to see every path regardless.
                let revoked =
                    e == Error::PathValidation(PathValidationStatus::CertificateRevokedEndEntity);
                if revoked && !opts.validate_all {
                    break;
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
    stats.paths_per_target += paths.len() - suppressed;

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
    let (report, _) = validate_targets_retaining(pe, cps, targets, opts, progress, false).await;
    report
}

/// As [`validate_targets`], additionally returning every validated path when `retain` is set, so a
/// frontend can export the artifacts behind a result without validating a second time.
///
/// Off by default and chosen at the call site: a GUI sets it because the decision to export is made
/// after seeing the results, while a batch run that will never export should not hold every path it
/// built. Nothing is computed either way — the paths and results exist for the duration of the run
/// regardless, and retaining them is declining to drop them — so the cost is holding them for the
/// life of the caller rather than per target.
///
/// A caller that means to export keeps the [`PkiEnvironment`] alive alongside the returned paths:
/// the CRLs behind a status are recovered from the sources registered on it, not held here.
pub async fn validate_targets_retaining(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    targets: &[(String, Vec<u8>)],
    opts: &ValidateOpts,
    progress: Option<&(dyn Fn(ProgressEvent) + Send + Sync + '_)>,
    retain: bool,
) -> (ValidationReport, Vec<RetainedPath>) {
    let mut retained: Vec<RetainedPath> = vec![];
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

        let _ = validate_cert_bytes_retaining(
            pe,
            cps,
            name.as_str(),
            der.as_slice(),
            stats_for_target,
            opts,
            &mut fresh_uris,
            0,
            retain.then_some(&mut retained),
        )
        .await;

        let paths_found = stats_for_target.paths_per_target - prev_paths;
        let path_reports = core::mem::take(&mut stats_for_target.path_reports);
        // A target that never yielded a path is reported as why rather than rolled up from path
        // results it has none of
        let (status, error) = match stats_for_target.no_path_reason.take() {
            Some((status, reason)) => (status, Some(reason)),
            None => (
                TargetReport::compute_status(&path_reports, paths_found > 0),
                None,
            ),
        };

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
            error,
        });
    }

    let report = ValidationReport {
        targets: target_reports,
        totals,
        time_of_interest: cps.get_time_of_interest().as_unix_secs(),
        duration_ms: (Instant::now() - start).as_millis() as u64,
        error: None,
    };
    (report, retained)
}

/// validate_cert_folder recursively traverses the given `certs_folder` and invokes `validate_cert_file`
/// for each .der, .crt or .cer file that is found.
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
    validate_cert_folder_retaining(
        pe,
        cps,
        certs_folder,
        stats,
        opts,
        fresh_uris,
        threshold,
        None,
    )
    .await
}

/// As [`validate_cert_folder`], additionally pushing each validated path onto `retain` when one is
/// given, so the artifacts behind a folder run can be exported without validating a second time.
///
/// The sink is reborrowed rather than moved on the way down: a folder holding folders recurses, and
/// each file in each of them contributes to the one collection the caller passed in.
#[async_recursion::async_recursion]
#[cfg(feature = "std")]
#[allow(clippy::too_many_arguments)]
pub async fn validate_cert_folder_retaining(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    certs_folder: &str,
    stats: &mut PathValidationStatsGroup,
    opts: &ValidateOpts,
    fresh_uris: &mut Vec<String>,
    threshold: usize,
    mut retain: Option<&mut Vec<RetainedPath>>,
) {
    for entry in WalkDir::new(certs_folder) {
        match entry {
            Ok(e) => {
                let path = e.path();
                if e.file_type().is_dir() {
                    if let Some(s) = path.to_str() {
                        if s != certs_folder {
                            validate_cert_folder_retaining(
                                pe,
                                cps,
                                s,
                                stats,
                                opts,
                                fresh_uris,
                                threshold,
                                retain.as_deref_mut(),
                            )
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
                                        retain.as_deref_mut(),
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

    // Honor the `cbor_ta_store` when set to true (to avoid clobbering a true from a settings file)
    if args.cbor_ta_store {
        cps.set_cbor_ta_store(true);
    }

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

/// Outcome of a folder maintenance action: how many files it removed, and how many it could not.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FolderMaintenance {
    /// Files removed
    pub removed: usize,
    /// Files that could not be removed, or could not be read to decide
    pub failed: usize,
}

/// Discards the last-modified map for `folder`, if there is one.
///
/// **Every function that removes downloaded artifacts must call this.** The map records, per URI,
/// the `Last-Modified` a previous fetch saw, and a run sends it back as `If-Modified-Since`; a 304
/// then means "you already have this" and the artifact is neither transferred nor added to the run
/// — `fetch_crl` returns `ResourceUnchanged` and the certificate path skips the URI. So the map is
/// a claim that a copy exists on disk. Remove the copy and leave the claim, and the next run is
/// told nothing has changed and comes away with nothing, from the network or the folder.
///
/// The whole map goes rather than the entries for what was removed: a saved certificate is named
/// from its URL's last path segment and a saved CRL from a hash of its content, so a file cannot be
/// mapped back to the URI that fetched it. Discarding all of it costs one conditional request per
/// URI on the next run, which is the right price for an action the user asked for.
#[cfg(feature = "std")]
pub fn forget_last_modified(folder: &str) -> bool {
    if folder.is_empty() {
        return false;
    }
    let lmm_file = last_modified_map_file(folder);
    if !Path::new(&lmm_file).exists() {
        return false;
    }
    match fs::remove_file(&lmm_file) {
        Ok(()) => {
            info!("Discarded the last-modified map at {lmm_file}");
            true
        }
        Err(e) => {
            error!("Failed to discard the last-modified map at {lmm_file}: {e}");
            false
        }
    }
}

/// Removes the CRLs in `folder` that do not cover `toi`, leaving the rest.
///
/// This is the predicate indexing used to apply on its own, on every run. It is a maintenance
/// action now rather than a side effect of reading, because whether a CRL is worth keeping is a
/// question about the folder and not about the run that happens to be reading it: a run at a past
/// time of interest would otherwise remove every CRL issued since, and a run at the present time
/// would remove the superseded ones a historical run needs.
///
/// A CRL with no nextUpdate is kept. It has no upper bound to be past, and how much age to tolerate
/// is the operator's call at validation time, not this function's.
///
/// Note what "stale" costs here: a superseded CRL generally cannot be fetched again, since a CA
/// publishes the current one and nothing else. Removing it forecloses validating anything as of a
/// time it covered.
#[cfg(feature = "std")]
pub fn cleanup_crls(folder: &str, toi_secs: u64) -> FolderMaintenance {
    use x509_cert::certificate::Raw;
    use x509_cert::crl::CertificateList;

    let mut outcome = FolderMaintenance::default();
    if toi_secs == 0 {
        info!("Not removing any CRL: no time of interest to judge one against");
        return outcome;
    }
    for entry in WalkDir::new(folder) {
        let Ok(e) = entry else {
            outcome.failed += 1;
            continue;
        };
        let path = e.path();
        if e.file_type().is_dir() || path.extension().and_then(OsStr::to_str) != Some("crl") {
            continue;
        }
        let bytes = get_file_as_byte_vec_pem(path).unwrap_or_default();
        let Ok(crl) = CertificateList::<Raw>::from_der(bytes.as_slice()) else {
            // Unreadable as a CRL is stale in the only sense that matters for an index of CRLs.
            match fs::remove_file(path) {
                Ok(()) => outcome.removed += 1,
                Err(_) => outcome.failed += 1,
            }
            continue;
        };
        let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
        let covers = match crl.tbs_cert_list.next_update {
            Some(nu) => this_update <= toi_secs && toi_secs < nu.to_unix_duration().as_secs(),
            None => true,
        };
        if !covers {
            match fs::remove_file(path) {
                Ok(()) => outcome.removed += 1,
                Err(e) => {
                    error!("Failed to remove {}: {e}", path.display());
                    outcome.failed += 1;
                }
            }
        }
    }
    if outcome.removed > 0 {
        forget_last_modified(folder);
    }
    info!(
        "Removed {} CRL(s) from {folder} that do not cover the time of interest ({} could not be removed)",
        outcome.removed, outcome.failed
    );
    outcome
}

/// Removes the certificates in `folder` that a run could not use: unparseable, not valid at
/// `toi_secs`, self-signed, or not a CA. Moved to `error_folder` instead of deleted when one is
/// given, which is what `--cleanup` does and for the same reason.
///
/// Wraps [`cleanup_certs`] so a frontend needs no `PkiEnvironment` of its own, and counts what
/// changed by comparing the folder before and after — `cleanup_certs` reports through the log
/// rather than returning, and a button needs something to say.
#[cfg(feature = "std")]
pub fn cleanup_certificate_folder(
    folder: &str,
    error_folder: &str,
    toi_secs: u64,
) -> FolderMaintenance {
    let count = || {
        WalkDir::new(folder)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !e.file_type().is_dir())
            .count()
    };
    let before = count();
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let toi =
        TimeOfInterest::from_unix_secs(toi_secs).unwrap_or_else(|_| TimeOfInterest::disabled());
    cleanup_certs(&pe, folder, error_folder, false, toi);
    let after = count();
    let removed = before.saturating_sub(after);
    if removed > 0 {
        forget_last_modified(folder);
    }
    FolderMaintenance { removed, failed: 0 }
}

/// Removes every file in `folder`, leaving the folder itself. Subfolders are traversed.
///
/// The blunt counterpart to the cleanup functions: those decide file by file, this one does not
/// decide at all. Kept separate for that reason — a caller offering both is offering two different
/// promises, and only one of them can be undone by fetching the material again.
#[cfg(feature = "std")]
pub fn purge_folder(folder: &str) -> FolderMaintenance {
    let mut outcome = FolderMaintenance::default();
    for entry in WalkDir::new(folder) {
        let Ok(e) = entry else {
            outcome.failed += 1;
            continue;
        };
        if e.file_type().is_dir() {
            continue;
        }
        match fs::remove_file(e.path()) {
            Ok(()) => outcome.removed += 1,
            Err(err) => {
                error!("Failed to remove {}: {err}", e.path().display());
                outcome.failed += 1;
            }
        }
    }
    // The map is a file in the folder, so the sweep above already took it. Named anyway so the
    // invariant is stated where it is relied on rather than left to the reader to notice.
    forget_last_modified(folder);
    info!(
        "Removed {} file(s) from {folder} ({} could not be removed)",
        outcome.removed, outcome.failed
    );
    outcome
}
