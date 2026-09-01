//! High level revocation checking functionality
//!
//! The check_revocation module provides a function that implements the [`ValidatePath`](crate::ValidatePath) type
//! in support of determining the revocation status of a certificates in a certification path. It
//! relies on several types of capabilities:
//! - Presence of OcspNoCheck extension
//! - Allowlist (i.e., certificates that have been declared "not revoked" by configuration)
//! - Blocklist (i.e., certificates that have been declared "revoked" by configuration)
//! - Cached revocation status (i.e., certificates whose "revoked" or "not revoked" status has been
//!   previously determined and saved in a cache that implements the [`RevocationStatusCache`](crate::RevocationStatusCache) trait.
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
    RevocationSource,
};

#[cfg(feature = "revocation")]
use crate::{crl::process_crl, ocsp_client::process_ocsp_response};

#[cfg(feature = "remote")]
use crate::revocation::crl::check_revocation_crl_remote;

#[cfg(feature = "remote")]
use crate::revocation::ocsp_client::check_revocation_ocsp;

/// Determines the revocation status of every certificate in a path, trying each available source in
/// turn until one answers.
///
/// ```text
/// cache → no-check ext → stapled (OCSP | CRL) → local CRLs → OCSP from AIA → remote CRL DP → grace periods
/// ```
///
/// Two gates come first and return `Ok(())` with nothing checked: revocation checking turned off in
/// the settings, and a target that is itself a trust anchor. Then, for each certificate in
/// `[intermediates…, target]` — its issuer being the trust anchor for the first and the preceding
/// certificate thereafter — the chain above is walked, **each step running only while the status is
/// still `RevocationStatusNotDetermined`, so the first source to answer wins.**
///
/// **A revoked verdict short-circuits; an undetermined one accumulates.** A revocation returns
/// immediately from inside the loop, so later certificates are never examined. An undetermined
/// status is pushed and the loop continues, so every certificate is looked at before the path is
/// failed — which is what makes the reported failure index meaningful.
///
/// Notes on the individual links, in order:
///
/// - **cache** — `pe.get_status`, consulted before anything else, including the no-check extension,
///   so a cached revocation wins over a certificate that asks not to be checked.
/// - **no-check ext** — `id-pkix-ocsp-nocheck` sets the status to `Valid` outright rather than
///   merely skipping a source, so nothing after it runs for that certificate.
/// - **stapled OCSP and stapled CRL are alternatives, not a sequence.** The block is entered only
///   when [`CertificationPath::stapled_rev_info_available`] is true, and a stapled OCSP response
///   that is present but fails for any reason other than revocation does **not** fall through to a
///   stapled CRL for the same certificate.
/// - **local CRLs** — every CRL `pe.get_crls` returns is tried: the first that determines `Valid`
///   wins, a revocation aborts, and any other error is logged before moving to the next CRL. Gated
///   on `cps.check_crls`.
/// - **OCSP from AIA** and **remote CRL DP** are gated on `cps.check_ocsp_from_aia` and
///   `cps.check_crldp_http` respectively, and exist only under the `remote` feature.
///   [`check_revocation_local`] is the same chain stopping after local CRLs.
/// - **grace periods** — `cps.crl_grace_periods_as_last_resort` reaches a `TODO`; a stale CRL is
///   never reconsidered today, so the setting changes nothing.
///
/// Returns `Ok` when the status of every certificate was determined and none was revoked. A
/// revocation yields `Error::PathValidation(CertificateRevokedEndEntity)` or
/// `Error::PathValidation(CertificateRevokedIntermediateCa)` according to the certificate's
/// position. If nothing was revoked but some status could not be determined,
/// `Error::PathValidation(RevocationStatusNotDetermined)` is returned.
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
        let cur_cert_subject = name_to_string(ca_cert_ref.decoded().tbs_certificate().subject());
        let revoked_error = if pos == max_index {
            CertificateRevokedEndEntity
        } else {
            CertificateRevokedIntermediateCa
        };

        // check revocation status cache
        let mut cur_status = pe.get_status(cur_cert, issuer, toi);
        if CertificateRevoked == cur_status {
            info!("Determined revocation status (revoked) using cached status for certificate issued to {cur_cert_subject}");
            cpr.set_revocation_source_for_item(pos, RevocationSource::Cache);
            cpr.set_validation_status(revoked_error);
            cpr.set_failure_index(pos as u32 + 1);
            return Err(Error::PathValidation(revoked_error));
        }
        if cur_status != RevocationStatusNotDetermined {
            cpr.set_revocation_source_for_item(pos, RevocationSource::Cache);
        }

        if let Ok(Some(PDVExtension::OcspNoCheck(_nc))) =
            ca_cert_ref.get_extension(&ID_PKIX_OCSP_NOCHECK)
        {
            info!("Skipping revocation check due to presence of OCSP no-check extension for certificate issued to {cur_cert_subject}");
            // Recorded even when the cache already answered: the extension is why no revocation data
            // was examined, which is the more useful thing to report.
            cpr.set_revocation_source_for_item(pos, RevocationSource::NoCheckExtension);
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
                        cpr.set_revocation_source_for_item(pos, RevocationSource::StapledOcsp);
                        cur_status = Valid
                    }
                    Err(Error::PathValidation(CertificateRevoked)) => {
                        info!("Determined revocation status (revoked) using stapled OCSP for certificate issued to {cur_cert_subject}");
                        cpr.set_revocation_source_for_item(pos, RevocationSource::StapledOcsp);
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
                        cpr.set_revocation_source_for_item(pos, RevocationSource::StapledCrl);
                        cur_status = Valid
                    }
                    Err(e) => {
                        if Error::PathValidation(CertificateRevoked) == e {
                            info!("Determined revocation status (revoked) using stapled CRL for certificate issued to {cur_cert_subject}");
                            cpr.set_revocation_source_for_item(pos, RevocationSource::StapledCrl);
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
                            info!("Determined revocation status (valid) using cached CRL for certificate issued to {cur_cert_subject}");
                            cpr.set_revocation_source_for_item(pos, RevocationSource::LocalCrl);
                            cur_status = Valid;
                            break;
                        }
                        Err(Error::PathValidation(CertificateRevoked)) => {
                            info!("Determined revocation status (revoked) using cached CRL for certificate issued to {cur_cert_subject}");
                            cpr.set_revocation_source_for_item(pos, RevocationSource::LocalCrl);
                            cpr.set_validation_status(revoked_error);
                            cpr.set_failure_index(pos as u32 + 1);
                            return Err(Error::PathValidation(revoked_error));
                        }
                        Err(e) => {
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
            if cur_status != RevocationStatusNotDetermined {
                cpr.set_revocation_source_for_item(pos, RevocationSource::OcspFromAia);
            }
            if CertificateRevoked == cur_status {
                cpr.set_validation_status(revoked_error);
                cpr.set_failure_index(pos as u32 + 1);
                return Err(Error::PathValidation(revoked_error));
            }
        }

        #[cfg(feature = "remote")]
        if cur_status == RevocationStatusNotDetermined && check_crldp_http {
            cur_status = check_revocation_crl_remote(pe, cps, cpr, cur_cert, issuer, pos).await;
            if cur_status != RevocationStatusNotDetermined {
                cpr.set_revocation_source_for_item(pos, RevocationSource::RemoteCrlDp);
            }
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

/// Determines revocation status from data the caller has already supplied, retrieving nothing.
///
/// This is steps 1 through 4 of the ladder documented on `check_revocation`, with the same
/// short-circuit on revocation and the same accumulation of undetermined statuses: the environment's
/// revocation status cache, the OCSP no-check extension, an OCSP response or CRL stapled into the
/// path, and any registered [`CrlSource`](crate::CrlSource). Nothing is fetched, so a status that
/// only a responder or a CRL DP could settle stays undetermined.
///
/// This is available whenever `revocation` is, unlike `check_revocation`, which exists only under
/// `std` and is asynchronous. That is a hazard for a caller that cannot see what it got: a crate can
/// `cfg` on its own features but never on a dependency's, so feature unification decides both
/// whether the function is there at all and whether it must be awaited, and the mismatch surfaces as
/// a compile error in code that did nothing wrong. A caller that does its own retrieving — a browser
/// going through a relay, a service that keeps egress under its own policy — should call this and
/// stop caring which flavor of certval it was linked against.
///
/// Returns `Ok` when the status of every certificate was determined and none was revoked, and
/// otherwise the same errors `check_revocation` returns.
pub fn check_revocation_local(
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
        let cur_cert_subject = name_to_string(ca_cert_ref.decoded().tbs_certificate().subject());
        let revoked_error = if pos == max_index {
            CertificateRevokedEndEntity
        } else {
            CertificateRevokedIntermediateCa
        };

        // check revocation status cache
        let mut cur_status = pe.get_status(cur_cert, issuer, toi);

        if CertificateRevoked == cur_status {
            info!("Determined revocation status (revoked) using cached status for certificate issued to {}", cur_cert_subject);
            cpr.set_revocation_source_for_item(pos, RevocationSource::Cache);
            cpr.set_validation_status(revoked_error);
            cpr.set_failure_index(pos as u32 + 1);
            return Err(Error::PathValidation(revoked_error));
        }
        if cur_status != RevocationStatusNotDetermined {
            cpr.set_revocation_source_for_item(pos, RevocationSource::Cache);
        }

        if let Ok(Some(PDVExtension::OcspNoCheck(_nc))) =
            ca_cert_ref.get_extension(&ID_PKIX_OCSP_NOCHECK)
        {
            info!("Skipping revocation check due to presence of OCSP no-check extension for certificate issued to {}", cur_cert_subject);
            cpr.set_revocation_source_for_item(pos, RevocationSource::NoCheckExtension);
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
                        cpr.set_revocation_source_for_item(pos, RevocationSource::StapledOcsp);
                        cur_status = Valid
                    }
                    Err(e) => {
                        if Error::PathValidation(CertificateRevoked) == e {
                            info!("Determined revocation status (revoked) using stapled OCSP for certificate issued to {}", cur_cert_subject);
                            cpr.set_revocation_source_for_item(pos, RevocationSource::StapledOcsp);
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
                        cpr.set_revocation_source_for_item(pos, RevocationSource::StapledCrl);
                        cur_status = Valid
                    }
                    Err(e) => {
                        if Error::PathValidation(CertificateRevoked) == e {
                            info!("Determined revocation status (revoked) using stapled CRL for certificate issued to {}", cur_cert_subject);
                            cpr.set_revocation_source_for_item(pos, RevocationSource::StapledCrl);
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
                            info!("Determined revocation status (valid) using cached CRL for certificate issued to {}", cur_cert_subject);
                            cpr.set_revocation_source_for_item(pos, RevocationSource::LocalCrl);
                            cur_status = Valid;
                            break;
                        }
                        Err(e) => {
                            if Error::PathValidation(CertificateRevoked) == e {
                                info!("Determined revocation status (revoked) using cached CRL for certificate issued to {}", cur_cert_subject);
                                cpr.set_revocation_source_for_item(pos, RevocationSource::LocalCrl);
                                cpr.set_validation_status(revoked_error);
                                cpr.set_failure_index(pos as u32 + 1);
                                return Err(Error::PathValidation(revoked_error));
                            } else {
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
