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
        CertSummary, PathReport, ProgressEvent, ReportTotals, TargetReport, ValidationReport,
    },
    stats::{PVStats, PathValidationStats, PathValidationStatsGroup},
};

#[cfg(feature = "revocation")]
use certval::check_revocation;

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
            crls: vec![],
        }
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
/// [`PkiEnvironment`](../certval/pki_environment/struct.PkiEnvironment.html) parameter and the settings
/// available via [`CertificationPathSettings`](../certval/path_settings/type.CertificationPathSettings.html)
/// parameter.
///
/// This is a thin file-reading wrapper around [`validate_cert_bytes`]. The `args` parameter
/// contributes `results_folder`, `validate_all`, `error_folder` and `dynamic_build`.
#[cfg(feature = "std")]
pub(crate) async fn validate_cert_file(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cert_filename: &str,
    stats: &mut PathValidationStats,
    args: &Pittv3Args,
    fresh_uris: &mut Vec<String>,
    threshold: usize,
) -> Result<()> {
    let target_bytes = get_file_as_byte_vec_pem(Path::new(&cert_filename))?;
    let opts = ValidateOpts::from_args(args);
    validate_cert_bytes(
        pe,
        cps,
        cert_filename,
        target_bytes.as_slice(),
        stats,
        &opts,
        fresh_uris,
        threshold,
    )
    .await
}

/// `validate_cert_bytes` attempts to validate the certificate parsed from `target_bytes` using the
/// resources available via the [`PkiEnvironment`](../certval/pki_environment/struct.PkiEnvironment.html)
/// parameter and the settings available via
/// [`CertificationPathSettings`](../certval/path_settings/type.CertificationPathSettings.html) parameter.
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

    let mut paths: Vec<CertificationPath> = vec![];
    let r = pe.get_paths_for_target(&target_cert, &mut paths, threshold, time_of_interest);
    if let Err(e) = r {
        println!("Failed to find certification paths for target with error {e:?}");
        error!("Failed to find certification paths for target with error {e:?}");
        return Err(Error::Unrecognized);
    }

    if paths.is_empty() {
        collect_uris_from_aia_and_sia(&target_cert, fresh_uris);
        info!("Failed to find any certification paths for target",);
        return Err(Error::Unrecognized);
    }

    for (i, path) in paths.iter_mut().enumerate() {
        info!(
            "Validating {} certificate path for {}",
            (path.intermediates.len() + 2),
            path.target.decoded().tbs_certificate().subject()
        );
        let path_start = Instant::now();
        staple_crls(path, &opts.crls);
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

        totals.targets += 1;
        totals.paths_found += paths_found;
        totals.valid_paths += stats_for_target.valid_paths_per_target - prev_valid;
        totals.invalid_paths += stats_for_target.invalid_paths_per_target - prev_invalid;

        target_reports.push(TargetReport {
            name: name.clone(),
            target: target_summary,
            status,
            paths: path_reports,
        });
    }

    ValidationReport {
        targets: target_reports,
        totals,
        time_of_interest: cps.get_time_of_interest().as_unix_secs(),
        duration_ms: (Instant::now() - start).as_millis() as u64,
    }
}

/// validate_cert_folder recursively traverses the given `certs_folder` and invokes [validate_cert_file]
/// for each .der, .crt or .cer file that is found.
#[async_recursion::async_recursion]
#[cfg(feature = "std")]
pub async fn validate_cert_folder(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    certs_folder: &str,
    stats: &mut PathValidationStatsGroup,
    args: &Pittv3Args,
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
                            validate_cert_folder(pe, cps, s, stats, args, fresh_uris, threshold)
                                .await;
                        }
                    } else {
                        error!("Skipping file due to invalid Unicode in name",);
                    }
                } else {
                    let mut do_validate = false;
                    if let Some(filename) = path.to_str() {
                        if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                            if ["der", "crt", "cer"].contains(&ext) {
                                do_validate = true;
                            }
                        }

                        if do_validate {
                            stats.init_for_target(filename);
                            if let Some(stats_for_file) = stats.get_mut(filename) {
                                if args.validate_all
                                    || (stats_for_file.valid_paths_per_target == 0
                                        && !stats_for_file.target_is_revoked)
                                {
                                    // validate when validating all or we don't have a definitive answer yet
                                    let _ = validate_cert_file(
                                        pe,
                                        cps,
                                        filename,
                                        stats_for_file,
                                        args,
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

/// generate takes a Pittv3Args structure containing at least `cbor`, `ta-folder` and `ca-folder`
/// options and the calls [`build_graph`](../../certval/builder/graph_builder/fn.build_graph.html).
/// Where dynamic building is in effect, the `download-folder` option will be used if present (else
/// ca-folder is used as destination for downloaded artifacts).
#[cfg(feature = "std")]
pub async fn generate(
    args: &Pittv3Args,
    cps: &mut CertificationPathSettings,
    pe: &mut PkiEnvironment,
) {
    let start = Instant::now();

    #[cfg(feature = "webpki")]
    if args.cbor.is_none()
        || (args.ta_folder.is_none() && !args.webpki_tas)
        || args.ca_folder.is_none()
    {
        println!("ERROR: The cbor and ca-folder options are required when generate is specified plus either ta-folder or webpki-tas");
        return;
    }

    #[cfg(not(feature = "webpki"))]
    if args.cbor.is_none() || args.ta_folder.is_none() || args.ca_folder.is_none() {
        println!("ERROR: The cbor, ta-folder and ca-folder options are required when generate is specified");
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
    if let Ok(graph) = graph {
        if let Some(cbor) = args.cbor.as_ref() {
            fs::write(cbor, graph.as_slice()).expect("Unable to write generated CBOR file");
        }
    } else {
        println!("Failed: {graph:?}");
    }
    println!("Generation took {:?}", Instant::now() - start);
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
                        if !["der", "crt", "cer"].contains(&ext) {
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
                        if !["der", "crt", "cer", "ta"].contains(&ext) {
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
