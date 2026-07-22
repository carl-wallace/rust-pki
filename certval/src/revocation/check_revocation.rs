//! High level revocation checking functionality
//!
//! The check_revocation module provides a function that implements the [`ValidatePath`](../certval/pki_environment_traits/type.ValidatePath.html) type
//! in support of determining the revocation status of a certificates in a certification path. It
//! relies on several types of capabilities:
//! - Presence of OcspNoCheck extension
//! - Allowlist (i.e., certificates that have been declared "not revoked" by configuration)
//! - Blocklist (i.e., certificates that have been declared "revoked" by configuration)
//! - Cached revocation status (i.e., certificates whose "revoked" or "not revoked" status has been
//!   previously determined and saved in a cache that implements the [`RevocationStatusCache`](../certval/pki_environment_traits/type.RevocationStatusCache.html) trait.
//! - Locally available CRLs (i.e., from file system or provided by application)
//! - Locally available OCSP responses (i.e., provided by application, presumably obtained via stapling)
//! - OCSP responses obtained from an OCSP responder
//! - CRLs obtained from location indicated in a CRL DP
//!
extern crate alloc;

use alloc::vec;
use const_oid::db::rfc6960::ID_PKIX_OCSP_NOCHECK;
use log::info;

use crate::name_to_string;
use crate::revocation::subject_name_and_key::SubjectNameAndKey;
use crate::{
    CertificationPath, CertificationPathResults, CertificationPathSettings, Error,
    ExtensionProcessing, PDVExtension, PathValidationStatus::*, PkiEnvironment, Result,
};

#[cfg(feature = "revocation")]
use crate::{crl::process_crl, ocsp_client::process_ocsp_response};

#[cfg(feature = "remote")]
use crate::revocation::crl::check_revocation_crl_remote;

#[cfg(feature = "remote")]
use crate::revocation::ocsp_client::check_revocation_ocsp;

/// check_revocation is top level revocation checking function supports a variety of revocation status
/// determination mechanisms, including allowlist, blocklist, CRLs and OCSP responses. Assuming all options
/// are enabled, the order of priority is:
/// - OCSP no-check extension
/// - Stapled OCSP response
/// - Stapled CRLs
/// - Cached CRLs
/// - Remote OCSP
/// - Remote CRL
/// - Stale CRLs within grace period (not yet implemented)
///
/// Ok is returned if status for all certificates can be determined and none were revoked. If a certificate is
/// found to be revoked (including when revocation status could not be found for one or more superior certificates)
/// Error::PathValidation(CertificateRevokedEndEntity) or Error::PathValidation(CertificateRevokedIntermediateCa) is
/// returned. If no certificates were found to be revoked but status could not be determined for all certificates
/// in the path, Error::PathValidation(RevocationStatusNotDetermined) is returned.
#[cfg(feature = "std")]
pub async fn check_revocation(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cp: &mut CertificationPath,
    cpr: &mut CertificationPathResults,
) -> Result<()> {
    let check_rev = cps.get_check_revocation_status();
    if !check_rev {
        // nothing to do
        info!("Revocation checking disabled");
        return Ok(());
    }

    if pe.is_cert_a_trust_anchor(&cp.target).is_ok() {
        // nothing to do
        info!("Target is a trust anchor, revocation status determination not required.");
        return Ok(());
    }

    let crl_grace_periods_as_last_resort = cps.get_crl_grace_periods_as_last_resort();
    let check_crls = cps.get_check_crls();

    #[cfg(feature = "remote")]
    let check_crldp_http = cps.get_check_crldp_http();
    #[cfg(feature = "remote")]
    let check_ocsp_from_aia = cps.get_check_ocsp_from_aia();

    // for convenience, combine target into array with the intermediate CA certs
    let mut v = cp.intermediates.clone();
    v.push(cp.target.clone());

    cpr.prepare_revocation_results(v.len())?;

    let max_index = v.len() - 1;

    let toi = cps.get_time_of_interest();

    // save up the statuses and return Ok only if none are RevocationStatusNotDetermined
    let mut statuses = vec![];
    for (pos, ca_cert_ref) in v.iter().enumerate() {
        let cur_cert = ca_cert_ref;
        // The issuer of the current certificate is the trust anchor (for the first certificate) or
        // the preceding certificate in the path. A trust anchor expressed as a name plus public key
        // has no wrapped certificate, so use the SubjectNameAndKey abstraction rather than requiring a
        // CertificateInner (which previously made revocation hard-fail on such anchors).
        let issuer: &dyn SubjectNameAndKey = if pos == 0 {
            &cp.trust_anchor.decoded_ta
        } else {
            v[pos - 1].as_ref()
        };
        let cur_cert_subject = name_to_string(ca_cert_ref.as_ref().tbs_certificate().subject());
        let revoked_error = if pos == max_index {
            CertificateRevokedEndEntity
        } else {
            CertificateRevokedIntermediateCa
        };

        // check revocation status cache
        let mut cur_status = pe.get_status(cur_cert, toi);
        if CertificateRevoked == cur_status {
            info!("Determined revocation status (revoked) using cached status for certificate issued to {cur_cert_subject}");
            cpr.set_validation_status(revoked_error);
            cpr.set_failure_index(pos as u32 + 1);
            return Err(Error::PathValidation(revoked_error));
        }

        if let Ok(Some(PDVExtension::OcspNoCheck(_nc))) =
            ca_cert_ref.get_extension(&ID_PKIX_OCSP_NOCHECK)
        {
            info!("Skipping revocation check due to presence of OCSP no-check extension for certificate issued to {cur_cert_subject}");
            cur_status = Valid;
        }

        if cur_status == RevocationStatusNotDetermined && cp.stapled_rev_info_available() {
            if let Some(enc_ocsp_resp) = &cp.ocsp_responses[pos] {
                match process_ocsp_response(
                    pe,
                    cps,
                    cpr,
                    enc_ocsp_resp,
                    issuer,
                    pos,
                    "stapled",
                    cur_cert,
                ) {
                    Ok(_ok) => {
                        // process_ocsp_response handles adding response (and request) to results, unlike process_crl due to request/response pair in mast cases
                        info!("Determined revocation status (valid) using stapled OCSP for certificate issued to {cur_cert_subject}");
                        cur_status = Valid
                    }
                    Err(Error::PathValidation(CertificateRevoked)) => {
                        info!("Determined revocation status (revoked) using stapled OCSP for certificate issued to {cur_cert_subject}");
                        cpr.set_validation_status(revoked_error);
                        cpr.set_failure_index(pos as u32 + 1);
                        return Err(Error::PathValidation(revoked_error));
                    }
                    Err(e) => {
                        info!("Failed to determine revocation status using stapled OCSP for certificate issued to {cur_cert_subject} with {e}");
                    }
                }
            } else if let Some(crl) = &cp.crls[pos] {
                match process_crl(pe, cps, cpr, cur_cert, issuer, pos, crl, None) {
                    Ok(_ok) => {
                        info!("Determined revocation status (valid) using stapled CRL for certificate issued to {cur_cert_subject}");
                        cpr.add_crl(crl, pos);
                        cur_status = Valid
                    }
                    Err(e) => {
                        cpr.add_crl(crl, pos);
                        if Error::PathValidation(CertificateRevoked) == e {
                            info!("Determined revocation status (revoked) using stapled CRL for certificate issued to {cur_cert_subject}");
                            cpr.set_validation_status(revoked_error);
                            cpr.set_failure_index(pos as u32 + 1);
                            return Err(Error::PathValidation(revoked_error));
                        } else {
                            info!("Failed to determine revocation status using stapled CRL for certificate issued to {cur_cert_subject} with {e}");
                        }
                    }
                };
            }
        }

        if cur_status == RevocationStatusNotDetermined && check_crls {
            if let Ok(crls) = pe.get_crls(cur_cert) {
                for crl in crls {
                    match process_crl(pe, cps, cpr, cur_cert, issuer, pos, crl.as_slice(), None) {
                        Ok(_ok) => {
                            cpr.add_crl(crl.as_slice(), pos);
                            info!("Determined revocation status (valid) using cached CRL for certificate issued to {cur_cert_subject}");
                            cur_status = Valid;
                            break;
                        }
                        Err(Error::PathValidation(CertificateRevoked)) => {
                            cpr.add_crl(crl.as_slice(), pos);
                            info!("Determined revocation status (revoked) using cached CRL for certificate issued to {cur_cert_subject}");
                            cpr.set_validation_status(revoked_error);
                            cpr.set_failure_index(pos as u32 + 1);
                            return Err(Error::PathValidation(revoked_error));
                        }
                        Err(e) => {
                            cpr.add_failed_crl(crl.as_slice(), pos);
                            info!("Failed to determine revocation status using cached CRL for certificate issued to {cur_cert_subject} with {e}");
                        }
                    };
                }
            }
        }

        #[cfg(feature = "remote")]
        if cur_status == RevocationStatusNotDetermined && check_ocsp_from_aia {
            // check_revocation_ocsp emits log message that includes which AIA was used to determine status
            cur_status = check_revocation_ocsp(pe, cps, cpr, cur_cert, issuer, pos).await;
            if CertificateRevoked == cur_status {
                cpr.set_validation_status(revoked_error);
                cpr.set_failure_index(pos as u32 + 1);
                return Err(Error::PathValidation(revoked_error));
            }
        }

        #[cfg(feature = "remote")]
        if cur_status == RevocationStatusNotDetermined && check_crldp_http {
            cur_status = check_revocation_crl_remote(pe, cps, cpr, cur_cert, issuer, pos).await;
            if CertificateRevoked == cur_status {
                cpr.set_validation_status(revoked_error);
                cpr.set_failure_index(pos as u32 + 1);
                return Err(Error::PathValidation(revoked_error));
            }
        }

        if cur_status == RevocationStatusNotDetermined && crl_grace_periods_as_last_resort {
            // TODO recheck CRLs with grace periods
        }

        statuses.push(cur_status);
    }

    if statuses.contains(&RevocationStatusNotDetermined) {
        cpr.set_validation_status(RevocationStatusNotDetermined);
        if let Some(pos) = statuses
            .iter()
            .position(|s| *s == RevocationStatusNotDetermined)
        {
            cpr.set_failure_index(pos as u32 + 1);
        }
        Err(Error::PathValidation(RevocationStatusNotDetermined))
    } else {
        Ok(())
    }
}

/// check_revocation is top level revocation checking function supports a variety of revocation status
/// determination mechanisms, including allowlist, blocklist, CRLs and OCSP responses.
///
/// Ok is returned if status for all certificates can be determined and none were revoked. If a certificate is
/// found to be revoked (including when revocation status could not be found for one or more superior certificates)
/// Error::PathValidation(CertificateRevokedEndEntity) or Error::PathValidation(CertificateRevokedIntermediateCa) is
/// returned. If no certificates were found to be revoked but status could not be determined for all certificates
/// in the path, Error::PathValidation(RevocationStatusNotDetermined) is returned.
#[cfg(not(feature = "std"))]
pub fn check_revocation(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cp: &mut CertificationPath,
    cpr: &mut CertificationPathResults,
) -> Result<()> {
    let check_rev = cps.get_check_revocation_status();
    if !check_rev {
        // nothing to do
        info!("Revocation checking disabled");
        return Ok(());
    }

    if pe.is_cert_a_trust_anchor(&cp.target).is_ok() {
        // nothing to do
        info!("Target is a trust anchor, revocation status determination not required.",);
        return Ok(());
    }

    let crl_grace_periods_as_last_resort = cps.get_crl_grace_periods_as_last_resort();
    let check_crls = cps.get_check_crls();

    #[cfg(feature = "remote")]
    let check_crldp_http = cps.get_check_crldp_http();
    #[cfg(feature = "remote")]
    let check_ocsp_from_aia = cps.get_check_ocsp_from_aia();

    // for convenience, combine target into array with the intermediate CA certs
    let mut v = cp.intermediates.clone();
    v.push(cp.target.clone());

    cpr.prepare_revocation_results(v.len())?;

    let max_index = v.len() - 1;

    let toi = cps.get_time_of_interest();

    // save up the statuses and return Ok only if none are RevocationStatusNotDetermined
    let mut statuses = vec![];
    for (pos, ca_cert_ref) in v.iter().enumerate() {
        let cur_cert = ca_cert_ref;
        // The issuer of the current certificate is the trust anchor (for the first certificate) or
        // the preceding certificate in the path. A trust anchor expressed as a name plus public key
        // has no wrapped certificate, so use the SubjectNameAndKey abstraction rather than requiring a
        // CertificateInner (which previously made revocation hard-fail on such anchors).
        let issuer: &dyn SubjectNameAndKey = if pos == 0 {
            &cp.trust_anchor.decoded_ta
        } else {
            v[pos - 1].as_ref()
        };
        let cur_cert_subject = name_to_string(&ca_cert_ref.as_ref().tbs_certificate().subject());
        let revoked_error = if pos == max_index {
            CertificateRevokedEndEntity
        } else {
            CertificateRevokedIntermediateCa
        };

        // check revocation status cache
        let mut cur_status = pe.get_status(cur_cert, toi);

        if CertificateRevoked == cur_status {
            info!("Determined revocation status (revoked) using cached status for certificate issued to {}", cur_cert_subject);
            cpr.set_validation_status(revoked_error);
            cpr.set_failure_index(pos as u32 + 1);
            return Err(Error::PathValidation(revoked_error));
        }

        if let Ok(Some(PDVExtension::OcspNoCheck(_nc))) =
            ca_cert_ref.get_extension(&ID_PKIX_OCSP_NOCHECK)
        {
            info!("Skipping revocation check due to presence of OCSP no-check extension for certificate issued to {}", cur_cert_subject);
            cur_status = Valid;
        }

        if cur_status == RevocationStatusNotDetermined && cp.stapled_rev_info_available() {
            if let Some(enc_ocsp_resp) = &cp.ocsp_responses[pos] {
                match process_ocsp_response(
                    pe,
                    cps,
                    cpr,
                    enc_ocsp_resp,
                    issuer,
                    pos,
                    "stapled",
                    cur_cert,
                ) {
                    Ok(_ok) => {
                        // process_ocsp_response handles adding response (and request) to results, unlike process_crl due to request/response pair in mast cases
                        info!("Determined revocation status (valid) using stapled OCSP for certificate issued to {}", cur_cert_subject);
                        cur_status = Valid
                    }
                    Err(e) => {
                        if Error::PathValidation(CertificateRevoked) == e {
                            info!("Determined revocation status (revoked) using stapled OCSP for certificate issued to {}", cur_cert_subject);
                            cpr.set_validation_status(revoked_error);
                            cpr.set_failure_index(pos as u32 + 1);
                            return Err(Error::PathValidation(revoked_error));
                        } else {
                            info!("Failed to determine revocation status using stapled OCSP for certificate issued to {} with {}", cur_cert_subject, e);
                        }
                    }
                }
            } else if let Some(crl) = &cp.crls[pos] {
                match process_crl(pe, cps, cpr, cur_cert, issuer, pos, crl, None) {
                    Ok(_ok) => {
                        info!("Determined revocation status (valid) using stapled CRL for certificate issued to {}", cur_cert_subject);
                        cpr.add_crl(crl, pos);
                        cur_status = Valid
                    }
                    Err(e) => {
                        cpr.add_crl(crl, pos);
                        if Error::PathValidation(CertificateRevoked) == e {
                            info!("Determined revocation status (revoked) using stapled CRL for certificate issued to {}", cur_cert_subject);
                            cpr.set_validation_status(revoked_error);
                            cpr.set_failure_index(pos as u32 + 1);
                            return Err(Error::PathValidation(revoked_error));
                        } else {
                            info!("Failed to determine revocation status using stapled CRL for certificate issued to {} with {}", cur_cert_subject, e);
                        }
                    }
                };
            }
        }

        if cur_status == RevocationStatusNotDetermined && check_crls {
            if let Ok(crls) = pe.get_crls(cur_cert) {
                for crl in crls {
                    match process_crl(pe, cps, cpr, cur_cert, issuer, pos, crl.as_slice(), None) {
                        Ok(_ok) => {
                            cpr.add_crl(crl.as_slice(), pos);
                            info!("Determined revocation status (valid) using cached CRL for certificate issued to {}", cur_cert_subject);
                            cur_status = Valid;
                            break;
                        }
                        Err(e) => {
                            if Error::PathValidation(CertificateRevoked) == e {
                                cpr.add_crl(crl.as_slice(), pos);
                                info!("Determined revocation status (revoked) using cached CRL for certificate issued to {}", cur_cert_subject);
                                cpr.set_validation_status(revoked_error);
                                cpr.set_failure_index(pos as u32 + 1);
                                return Err(Error::PathValidation(revoked_error));
                            } else {
                                cpr.add_failed_crl(crl.as_slice(), pos);
                                info!("Failed to determine revocation status using cached CRL for certificate issued to {} with {}", cur_cert_subject, e);
                            }
                        }
                    };
                }
            }
        }

        if cur_status == RevocationStatusNotDetermined && crl_grace_periods_as_last_resort {
            // TODO recheck local CRLs with grace periods
        }

        statuses.push(cur_status);
    }

    if statuses.contains(&RevocationStatusNotDetermined) {
        cpr.set_validation_status(RevocationStatusNotDetermined);
        if let Some(pos) = statuses
            .iter()
            .position(|s| *s == RevocationStatusNotDetermined)
        {
            cpr.set_failure_index(pos as u32 + 1);
        }
        Err(Error::PathValidation(RevocationStatusNotDetermined))
    } else {
        cpr.set_validation_status(Valid);
        Ok(())
    }
}
