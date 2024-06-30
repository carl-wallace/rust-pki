//! Provides support for validating a certificate in no-std context

#![cfg(any(not(feature = "std"), doc))]

use crate::{stats::PathValidationStats, Pittv3Args};
use certval::*;
use log::{error, info};

#[cfg(feature = "std_app")]
use crate::pitt_log::log_path;

/// `validate_cert_file` attempts to validate the certificate notionally read from the file indicated by
/// `cert_filename` using the resources available via the
/// [`PkiEnvironment`](../certval/pki_environment/struct.PkiEnvironment.html) parameter and the settings
/// available via [`CertificationPathSettings`](../certval/path_settings/type.CertificationPathSettings.html)
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

    let mut paths: Vec<CertificationPath> = vec![];
    let r = pe.get_paths_for_target(&target_cert, &mut paths, 0, time_of_interest);
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
        info!("Failed to find any certification paths for target",);
        return Err(Error::Unrecognized);
    }

    for (_i, path) in paths.iter_mut().enumerate() {
        info!(
            "Validating {} certificate path for {}",
            (path.intermediates.len() + 2),
            path.target.decoded_cert.tbs_certificate.subject.to_string()
        );
        let mut cpr = CertificationPathResults::new();

        #[cfg(not(feature = "revocation"))]
        let r = pe.validate_path(pe, cps, path, &mut cpr);

        #[cfg(feature = "revocation")]
        let mut r = pe.validate_path(pe, cps, path, &mut cpr);

        #[cfg(feature = "revocation")]
        if r.is_ok() {
            if cps.get_check_revocation_status() {
                r = check_revocation(pe, cps, path, &mut cpr);
            }
        }

        #[cfg(feature = "std_app")]
        log_path(
            pe,
            &args.results_folder,
            path,
            stats.paths_per_target + _i,
            Some(&cpr),
            Some(cps),
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
