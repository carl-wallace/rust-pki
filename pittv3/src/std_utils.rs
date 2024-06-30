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
    stats::{PVStats, PathValidationStats, PathValidationStatsGroup},
};

#[cfg(feature = "remote")]
use certval::check_revocation;

/// `validate_cert_file` attempts to validate the certificate read from the file indicated by
/// `cert_filename` using the resources available via the
/// [`PkiEnvironment`](../certval/pki_environment/struct.PkiEnvironment.html) parameter and the settings
/// available via [`CertificationPathSettings`](../certval/path_settings/type.CertificationPathSettings.html)
/// parameter.
///
/// Where dynamic path building is used, path validation is governed by the `threshold` parameter,
/// i.e., only paths with at least one certificate at an index above the threshold will be validated.
/// The `args` parameter contributes `results_folder`, `validate_all`, `error_folder` and `dynamic_build`.
/// Each path that is processed will be saved to the `results_folder`, if present in `args`.
/// If `validate_all` is specified, validation will be attempted for all paths that were found by the builder.
/// If `error_folder` is specified, paths that fail validation will be logged there (in addition to the results_folder).
/// If `dynamic_build` is set, then URIs from the AIA and SIA extension of any trust anchor or
/// intermediate CA cert will be added to `fresh_uris`, if not already present. The caller may use these
/// URIs to fetch additional artifacts that may be used to build and validate additional certification paths.
/// The `stats` parameter is used to aggregate basic path processing statistics.
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
    let time_of_interest = cps.get_time_of_interest();
    let target_bytes = get_file_as_byte_vec_pem(Path::new(&cert_filename))?;

    let target_cert = parse_cert(target_bytes.as_slice(), cert_filename)?;
    info!(
        "Start building and validating path(s) for {}",
        cert_filename
    );

    let start2 = Instant::now();
    stats.files_processed += 1;

    let mut paths: Vec<CertificationPath> = vec![];
    let r = pe.get_paths_for_target(&target_cert, &mut paths, threshold, time_of_interest);
    if let Err(e) = r {
        println!(
            "Failed to find certification paths for target with error {:?}",
            e
        );
        error!(
            "Failed to find certification paths for target with error {:?}",
            e
        );
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
            path.target.decoded_cert.tbs_certificate.subject.to_string()
        );
        let mut cpr = CertificationPathResults::new();

        #[cfg(not(feature = "remote"))]
        let r = pe.validate_path(pe, cps, path, &mut cpr);

        #[cfg(feature = "remote")]
        let mut r = pe.validate_path(pe, cps, path, &mut cpr);

        #[cfg(feature = "remote")]
        if r.is_ok() && cps.get_check_revocation_status() {
            r = check_revocation(pe, cps, path, &mut cpr).await;
        }

        log_path(
            pe,
            &args.results_folder,
            path,
            stats.paths_per_target + i,
            Some(&cpr),
            Some(cps),
        );
        stats.results.push(cpr);
        match r {
            Ok(_) => {
                stats.valid_paths_per_target += 1;

                info!("Successfully validated {}", cert_filename);
                if !args.validate_all {
                    break;
                }
            }
            Err(e) => {
                stats.invalid_paths_per_target += 1;

                log_path(pe, &args.error_folder, path, i, None, None);
                if e == Error::PathValidation(PathValidationStatus::CertificateRevokedEndEntity) {
                    info!("Failed to validate {} with {:?}", cert_filename, e);
                    break;
                } else {
                    info!("Failed to validate {} with {:?}", cert_filename, e);
                }
            }
        }

        #[cfg(feature = "remote")]
        if args.dynamic_build {
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
                            info!("Skipping {}", filename);
                        }
                    }
                }
            }
            _ => {
                error!("Failed to unwrap entry in {}", certs_folder);
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
        println!("Failed: {:?}", graph);
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

                    let target = if let Ok(t) = get_file_as_byte_vec_pem(path) {
                        t
                    } else {
                        vec![]
                    };
                    if target.is_empty() {
                        error!("Failed to read target file at {}", filename);
                        continue;
                    }

                    let mut delete_file = false;
                    match parse_cert(target.as_slice(), filename) {
                        Ok(tc) => {
                            if !t.is_disabled() {
                                let r = valid_at_time(&tc.decoded_cert.tbs_certificate, t, true);
                                if let Err(_e) = r {
                                    delete_file = true;
                                    error!(
                                        "Not valid at indicated time of interest ({}): {}",
                                        t, filename
                                    );
                                }
                            }

                            if is_self_signed(pe, &tc) {
                                delete_file = true;
                                error!("Self-signed: {}", filename);
                            }

                            let bc = tc.get_extension(&ID_CE_BASIC_CONSTRAINTS);
                            if let Ok(Some(PDVExtension::BasicConstraints(bc))) = bc {
                                if !bc.ca {
                                    delete_file = true;
                                    error!("Not a CA per basicConstraints: {}", filename);
                                }
                            } else {
                                delete_file = true;
                                error!("Missing basicConstraints: {}", filename);
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
                println!("Failed to unwrap entry: {}", e);
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

                    let target = if let Ok(t) = get_file_as_byte_vec_pem(e.path()) {
                        t
                    } else {
                        vec![]
                    };
                    if target.is_empty() {
                        error!("Failed to read target file at {}", filename);
                        continue;
                    }

                    let mut delete_file = false;
                    match TrustAnchorChoice::from_der(target.as_slice()) {
                        Ok(ta) => {
                            let r = ta_valid_at_time(&ta, t, true);
                            if r.is_err() {
                                delete_file = true;
                                error!(
                                    "Not valid at indicated time of interest ({}): {}",
                                    t, filename
                                );
                            }
                        }
                        Err(e) => {
                            error!("Failed to parse trust anchor at {} with {}", filename, e);
                            delete_file = true;
                        }
                    }

                    if !report_only && delete_file {
                        delete_or_move_file(error_folder, path, filename);
                    }
                }
            }
            Err(e) => {
                println!("Failed to unwrap entry: {}", e);
            }
        } // end match entry {
    } // end for entry in WalkDir::new(certs_folder)
}

fn delete_or_move_file(error_folder: &str, path: &Path, filename: &str) {
    if error_folder.is_empty() {
        //delete file
        let r = fs::remove_file(path);
        if let Err(e) = r {
            println!("Failed to delete {} with {:?}", filename, e);
            error!("Failed to delete {} with {:?}", filename, e);
        }
    } else if let Some(new_filename) = Path::new(error_folder).join(path).file_name() {
        // move file
        let r = fs::rename(filename, new_filename);
        if let Err(e) = r {
            println!("Failed to delete {} with {:?}", filename, e);
            error!("Failed to delete {} with {:?}", filename, e);
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
