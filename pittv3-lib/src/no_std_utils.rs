//! Provides support for validating a certificate in no-std context

#![cfg(any(not(feature = "std"), doc))]

use crate::{report::NoPathsContext, stats::PathValidationStats, Pittv3Args};
use certval::*;
use log::{error, info};

#[cfg(feature = "std_app")]
use crate::pitt_log::log_path;

/// `validate_cert_file` attempts to validate the certificate notionally read from the file indicated by
/// `cert_filename` using the resources available via the
/// [`PkiEnvironment`](certval::PkiEnvironment) parameter and the settings
/// available via [`CertificationPathSettings`](certval::CertificationPathSettings)
/// parameter.
pub(crate) fn validate_cert(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cert_filename: &str,
    target: &[u8],
    stats: &mut PathValidationStats,
    args: &Pittv3Args,
) -> Result<()> {
    let time_of_interest = cps.get_time_of_interest();
    let target_cert = parse_cert(target, cert_filename)?;
    info!(
        "Start building and validating path(s) for {}",
        cert_filename
    );

    stats.files_processed += 1;

    // Same diagnosis as the std build, from the same feature-free helper. The trust material here is
    // compiled in rather than read from folders, so the causes are narrower -- but "which piece is
    // missing" is exactly as opaque from a zero, and there is no filesystem to go rummage through.
    // Chasing is None: a no-std build has no fetching to suggest.
    let diagnose = || NoPathsContext::collect(pe, &target_cert, time_of_interest, None).hints();

    let mut paths: Vec<CertificationPath> = vec![];
    let r = pe.get_paths_for_target(&target_cert, &mut paths, 0, time_of_interest);
    if let Err(e) = r {
        error!(
            "Failed to find certification paths for target with error {:?}",
            e
        );
        stats.no_paths_hints = diagnose();
        return Err(Error::Unrecognized);
    }

    if paths.is_empty() {
        info!("Failed to find any certification paths for target",);
        stats.no_paths_hints = diagnose();
        return Err(Error::Unrecognized);
    }

    // a path was found, so an earlier diagnosis for this target is stale
    stats.no_paths_hints.clear();

    // the index is only consumed by the std_app log_path call below
    #[allow(clippy::unused_enumerate_index)]
    for (_i, path) in paths.iter_mut().enumerate() {
        info!(
            "Validating {} certificate path for {}",
            (path.intermediates.len() + 2),
            path.target.decoded().tbs_certificate().subject()
        );
        let mut cpr = CertificationPathResults::new();

        // fold RFC 5914 trust anchor constraints into the settings per RFC 5937; this is a no-op
        // clone when enforcement is disabled, and validate_path does not perform it itself
        let path_cps = match enforce_trust_anchor_constraints(cps, &path.trust_anchor) {
            Ok(path_cps) => path_cps,
            Err(e) => {
                error!(
                    "Failed to enforce trust anchor constraints for {} with {:?}",
                    cert_filename, e
                );
                stats.invalid_paths_per_target += 1;
                continue;
            }
        };

        #[cfg(not(feature = "revocation"))]
        let r = pe.validate_path(pe, &path_cps, path, &mut cpr);

        #[cfg(feature = "revocation")]
        let mut r = pe.validate_path(pe, &path_cps, path, &mut cpr);

        #[cfg(feature = "revocation")]
        if r.is_ok() && path_cps.get_check_revocation_status() {
            r = check_revocation_local(pe, &path_cps, path, &mut cpr);
        }

        #[cfg(feature = "std_app")]
        log_path(
            pe,
            &args.results_folder,
            path,
            stats.paths_per_target + _i,
            Some(&cpr),
            Some(&path_cps),
            // No clock in a no-std build, so nothing here times a path.
            None,
        );

        stats.results.push(cpr.clone());
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

                if e == Error::PathValidation(PathValidationStatus::CertificateRevokedEndEntity) {
                    info!("Failed to validate {} with {:?}", cert_filename, e);
                    break;
                } else {
                    info!("Failed to validate {} with {:?}", cert_filename, e);
                }
            }
        }
    }
    stats.paths_per_target += paths.len();
    Ok(())
}
