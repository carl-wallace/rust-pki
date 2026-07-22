//! Structures and functions to perform OCSP client functionality

extern crate alloc;
use alloc::vec::Vec;

use der::{Any, Decode, Encode};
use sha1::{Digest, Sha1};
use x509_cert::certificate::{CertificateInner, Raw};
use x509_cert::ext::Extensions;
use x509_ocsp::*;

use log::{error, warn};

#[cfg(feature = "remote")]
use log::{debug, info};

use crate::revocation::subject_name_and_key::SubjectNameAndKey;
use crate::{
    crl::process_crl, util::pdv_utilities::compare_names, valid_at_time, CertificationPathResults,
    CertificationPathSettings, DeferDecodeSigned, Error, OcspNonceSetting, PDVCertificate,
    PathValidationStatus, PkiEnvironment, Result,
};

#[cfg(feature = "remote")]
use alloc::vec;

#[cfg(feature = "remote")]
use der::asn1::{Ia5String, OctetString};

#[cfg(feature = "remote")]
use reqwest::header::CONTENT_TYPE;

#[cfg(feature = "remote")]
use core::time::Duration;

#[cfg(feature = "remote")]
use x509_cert::ext::pkix::name::GeneralName;
#[cfg(feature = "revocation")]
use x509_cert::ext::pkix::ExtendedKeyUsage;

// Needed by the (stapling-capable) responder EKU check, so gated on `revocation`, not `remote`.
#[cfg(feature = "revocation")]
use const_oid::db::rfc5912::{ID_CE_EXT_KEY_USAGE, ID_KP_OCSP_SIGNING};

// Used only when fetching an OCSP responder URL from AIA (network), so `remote`-only.
#[cfg(feature = "remote")]
use const_oid::db::rfc5912::{ID_AD_OCSP, ID_PE_AUTHORITY_INFO_ACCESS};

#[cfg(feature = "revocation")]
use const_oid::db::rfc6960::{ID_PKIX_OCSP_BASIC, ID_PKIX_OCSP_NOCHECK, ID_PKIX_OCSP_NONCE};

#[cfg(feature = "remote")]
use spki::AlgorithmIdentifier;
use x509_cert::serial_number::SerialNumber;

#[cfg(feature = "remote")]
use x509_ocsp::Version::V1;

#[cfg(feature = "remote")]
use crate::{name_to_string, pdv_extension::ExtensionProcessing, PDVExtension, PKIXALG_SHA1};

#[cfg(feature = "remote")]
use x509_cert::ext::Extension;

#[cfg(feature = "remote")]
use x509_ocsp::ext::Nonce;

fn get_key_hash(issuer: &dyn SubjectNameAndKey) -> Result<Vec<u8>> {
    Ok(Sha1::digest(issuer.spki().subject_public_key.raw_bytes()).to_vec())
}

fn get_subject_name_hash(issuer: &dyn SubjectNameAndKey) -> Result<Vec<u8>> {
    let enc_subject = match issuer.subject_name()?.to_der() {
        Ok(enc_spki) => enc_spki,
        Err(e) => return Err(Error::Asn1Error(e)),
    };

    Ok(Sha1::digest(enc_subject.as_slice()).to_vec())
}

/// unsupported_critical_extensions_present_single_response returns true if any critical extension
/// is present with a SingleResponse
fn unsupported_critical_extensions_present_single_response(sr: &SingleResponse) -> bool {
    match &sr.single_extensions {
        Some(exts) => {
            for e in exts {
                if e.critical {
                    return true;
                }
            }
            false
        }
        None => false,
    }
}

/// unsupported_critical_extensions_present__response returns true if any critical extension
/// is present with a SingleResponse
fn unsupported_critical_extensions_present_response(rd: &ResponseData) -> bool {
    match &rd.response_extensions {
        Some(exts) => {
            for e in exts {
                if e.critical && e.extn_id != ID_PKIX_OCSP_NONCE {
                    return true;
                }
            }
            false
        }
        None => false,
    }
}

/// cert_id_match returns true if the serial number, issuer name hash and issuer key hash in the cert_id object
/// match the values passed as parameters. Else it returns false.
fn cert_id_match(
    cert_id: &CertId,
    serial_number: &SerialNumber<Raw>,
    name_hash: &[u8],
    key_hash: &[u8],
) -> bool {
    if cert_id.serial_number.as_bytes() != serial_number.as_bytes() {
        return false;
    }

    if cert_id.issuer_name_hash.as_bytes() != name_hash {
        return false;
    }
    if cert_id.issuer_key_hash.as_bytes() != key_hash {
        return false;
    }
    true
}

fn check_response_time(cps: &CertificationPathSettings, sr: &SingleResponse) -> bool {
    let time_of_interest = cps.get_time_of_interest();
    if time_of_interest.is_disabled() {
        return true;
    }

    let tu = sr.this_update.0;
    if tu > time_of_interest {
        //future request
        return false;
    }

    match sr.next_update {
        Some(next_update) => {
            if next_update.0 < time_of_interest {
                //stale
                return false;
            }
        }
        None => {
            // No nextUpdate. RFC 6960 4.2.2.1 permits this, but without it the response carries no
            // upper time bound and could be replayed indefinitely. Bound its age from thisUpdate by
            // PS_REVOCATION_MAX_AGE (default 0 => reject as stale; a non-zero value opts into a
            // tolerance window).
            let max_age = cps.get_revocation_max_age().as_secs();
            let age = time_of_interest
                .as_unix_secs()
                .saturating_sub(tu.to_unix_duration().as_secs());
            if age > max_age {
                return false;
            }
        }
    }
    true
}

/// nonce_acceptable enforces the OCSP nonce policy from `PS_OCSP_AIA_NONCE_SETTING`.
///
/// `expected` is the nonce that was sent in the request (None when no nonce was sent, e.g. for a
/// stapled response) and `got` is the nonce echoed by the response (None when the responder omitted
/// it).
///
/// - `DoNotSendNonce`: no nonce was requested, so any response is acceptable.
/// - `SendNonceRequireMatch`: the response MUST echo the exact nonce that was sent; an absent or
///   mismatched nonce is rejected (fail closed).
/// - `SendNonceTolerateMismatchAbsence`: the nonce is best-effort; a missing or mismatched nonce is
///   tolerated.
fn nonce_acceptable(
    setting: OcspNonceSetting,
    expected: Option<&[u8]>,
    got: Option<&[u8]>,
) -> bool {
    match setting {
        OcspNonceSetting::DoNotSendNonce | OcspNonceSetting::SendNonceTolerateMismatchAbsence => {
            true
        }
        OcspNonceSetting::SendNonceRequireMatch => match (expected, got) {
            (Some(e), Some(g)) => e == g,
            _ => false,
        },
    }
}

/// Generates an OCSP nonce using the platform CSPRNG.
#[cfg(feature = "remote")]
fn generate_nonce() -> Result<Vec<u8>> {
    // RFC 8954 recommends a 32-octet nonce and requires responders to accept 1..=32 octets, but
    // widely deployed RFC 6960-era responders (e.g. the DoD PKI responder) silently drop nonces
    // longer than 16 octets — the response then carries no nonce and SendNonceRequireMatch fails
    // against an otherwise healthy responder. 16 octets is the de facto interoperable value
    // (OpenSSL's default) and remains within RFC 8954's permitted range.
    const OCSP_NONCE_LEN: usize = 16;
    let mut bytes = [0u8; OCSP_NONCE_LEN];
    if getrandom::fill(&mut bytes).is_err() {
        error!("Failed to generate a random OCSP nonce");
        return Err(Error::Unrecognized);
    }
    Ok(bytes.to_vec())
}

#[cfg(feature = "remote")]
async fn post_ocsp(uri_to_check: &str, enc_ocsp_req: &[u8], max_bytes: u64) -> Result<Vec<u8>> {
    let client = match crate::builder::uri_utils::shared_http_client() {
        Some(client) => client,
        None => {
            error!("Failed to prepare OCSP client: {uri_to_check}");
            return Err(Error::NetworkError);
        }
    };

    let body = match client
        .post(uri_to_check)
        .body(enc_ocsp_req.to_vec())
        .header(CONTENT_TYPE, "application/ocsp-request")
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(b) => b,
        Err(e) => {
            debug!("OCSP request send failed with {e}: {uri_to_check}");
            return Err(Error::NetworkError);
        }
    };

    crate::builder::uri_utils::read_capped_body(body, max_bytes, uri_to_check).await
}

#[cfg(feature = "remote")]
fn prepare_ocsp_request(
    target_cert: &CertificateInner<Raw>,
    name_hash: &[u8],
    key_hash: &[u8],
    nonce: Option<&[u8]>,
) -> Result<Vec<u8>> {
    // let hash_algorithm = AlgorithmIdentifier {
    //     oid: PKIXALG_SHA1,
    //     parameters: Some(der::asn1::Null.into()),
    // };
    let hash_algorithm = AlgorithmIdentifier {
        oid: PKIXALG_SHA1,
        parameters: None,
    };
    let issuer_name_hash = match OctetString::new(name_hash) {
        Ok(inh) => inh,
        Err(e) => return Err(Error::Asn1Error(e)),
    };
    let issuer_key_hash = match OctetString::new(key_hash) {
        Ok(ikh) => ikh,
        Err(e) => return Err(Error::Asn1Error(e)),
    };

    let req_cert = CertId {
        hash_algorithm,
        issuer_name_hash,
        issuer_key_hash,
        serial_number: target_cert.tbs_certificate().serial_number().clone(),
    };
    let request_list = vec![Request {
        req_cert,
        single_request_extensions: None,
    }];

    // When a nonce is supplied (per PS_OCSP_AIA_NONCE_SETTING), carry it as a non-critical
    // id-pkix-ocsp-nonce request extension. The extension value is the DER encoding of the Nonce
    // (itself an OCTET STRING), matching how responders echo it back and how the response is read.
    let request_extensions = match nonce {
        Some(n) => {
            let nonce = match Nonce::new(n.to_vec()) {
                Ok(nonce) => nonce,
                Err(e) => return Err(Error::Asn1Error(e)),
            };
            let extn_value = match nonce.to_der() {
                Ok(der) => match OctetString::new(der) {
                    Ok(ev) => ev,
                    Err(e) => return Err(Error::Asn1Error(e)),
                },
                Err(e) => return Err(Error::Asn1Error(e)),
            };
            Some(vec![Extension {
                extn_id: ID_PKIX_OCSP_NONCE,
                critical: false,
                extn_value,
            }])
        }
        None => None,
    };

    let tbs_request = TbsRequest {
        version: V1,
        requestor_name: None,
        request_list,
        request_extensions,
    };
    let ocsp_req = OcspRequest {
        tbs_request,
        optional_signature: None,
    };
    let enc_ocsp_req = match ocsp_req.to_der() {
        Ok(eor) => eor,
        Err(e) => return Err(Error::Asn1Error(e)),
    };
    Ok(enc_ocsp_req)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeferDecodeBasicOcspResponse {
    ///   tbsResponseData          ResponseData,
    pub tbs_response_data: Vec<u8>,

    ///   signatureAlgorithm       AlgorithmIdentifier,
    pub signature_algorithm: Vec<u8>,

    ///   signature                BIT STRING,
    pub signature: Vec<u8>,

    ///    certs               \[0\] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
    //#[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub certs: Option<alloc::vec::Vec<Any>>,
}

impl ::der::FixedTag for DeferDecodeBasicOcspResponse {
    const TAG: ::der::Tag = ::der::Tag::Sequence;
}

impl<'a> ::der::DecodeValue<'a> for DeferDecodeBasicOcspResponse {
    type Error = der::Error;
    fn decode_value<R: ::der::Reader<'a>>(
        reader: &mut R,
        header: ::der::Header,
    ) -> ::der::Result<Self> {
        reader.read_nested(header.length(), |reader| {
            let tbs_response_data = reader.tlv_bytes()?;
            let signature_algorithm = reader.tlv_bytes()?;
            let signature = reader.tlv_bytes()?;
            let certs = ::der::asn1::ContextSpecific::decode_explicit(reader, ::der::TagNumber(0))?
                .map(|cs| cs.value);
            Ok(Self {
                tbs_response_data: tbs_response_data.to_vec(),
                signature_algorithm: signature_algorithm.to_vec(),
                signature: signature.to_vec(),
                certs,
            })
        })
    }
}

fn no_check_present(exts: &Option<&Extensions>) -> bool {
    if let Some(exts) = exts {
        for ext in exts.as_slice() {
            if ext.extn_id == ID_PKIX_OCSP_NOCHECK {
                return true;
            }
        }
    }
    false
}

/// Returns true if the certificate asserts the id-kp-OCSPSigning extended key usage.
///
/// RFC 6960 Section 4.2.2.2 requires a delegated OCSP responder certificate (one that is not the
/// certificate issuer signing directly) to include id-kp-OCSPSigning in its extended key usage.
/// A certificate with no EKU extension, an unparseable EKU, or an EKU that lacks this value is not
/// an authorized delegated responder and is rejected (fail closed).
#[cfg(feature = "revocation")]
fn has_ocsp_signing_eku(exts: &Option<&Extensions>) -> bool {
    if let Some(exts) = exts {
        for ext in exts.as_slice() {
            if ext.extn_id == ID_CE_EXT_KEY_USAGE {
                return match ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()) {
                    Ok(eku) => eku.0.contains(&ID_KP_OCSP_SIGNING),
                    Err(_) => false,
                };
            }
        }
    }
    false
}

fn verify_response_signature(
    pe: &PkiEnvironment,
    signer: &dyn SubjectNameAndKey,
    enc_ocsp_resp: &[u8],
    bor: &BasicOcspResponse,
) -> Result<()> {
    let ddbor = match DeferDecodeBasicOcspResponse::from_der(enc_ocsp_resp) {
        Ok(bor) => bor,
        Err(e) => return Err(Error::Asn1Error(e)),
    };

    let signature = if let Some(s) = bor.signature.as_bytes() {
        s
    } else {
        return Err(Error::Unrecognized);
    };

    pe.verify_signature_message(
        pe,
        &ddbor.tbs_response_data,
        signature,
        &bor.signature_algorithm,
        signer.spki(),
    )
}

/// send_ocsp_request sends an OCSP request for `target_cert` to the location identified by `uri_to_check`
/// using information from `issuers_cert`, processes the response per `pe` and `cps` and returns information
/// via `cpr` (in the `result_index` slot) and `enc_resp`.
///
/// The only extension type listed in section 4 of RFC 6960 that is supported by this function is
/// nonce, the usage of which is governed by the PS_OCSP_AIA_NONCE_SETTING setting in the `cps` parameter.
/// Non-critical extensions may be present in a response without error. Presence of any critical
/// extension other than nonce will result in failure.
///
/// This function only supports responses signed by delegated OCSP responders and by CAs. Locally
/// trusted OCSP responders are not currently supported.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "remote")]
pub async fn send_ocsp_request(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    uri_to_check: &str,
    target_cert: &PDVCertificate,
    issuer: &dyn SubjectNameAndKey,
    cpr: &mut CertificationPathResults,
    result_index: usize,
) -> Result<()> {
    if !uri_to_check.starts_with("http") {
        debug!("Ignored non-HTTP URI presented to OCSP client",);
        return Err(Error::InvalidUriScheme);
    }

    let nonce_setting = cps.get_ocsp_aia_nonce_setting();

    let nonce = match nonce_setting {
        OcspNonceSetting::DoNotSendNonce => None,
        OcspNonceSetting::SendNonceRequireMatch
        | OcspNonceSetting::SendNonceTolerateMismatchAbsence => Some(generate_nonce()?),
    };

    // Prepare info for request
    let key_hash = get_key_hash(issuer)?;
    let name_hash = get_subject_name_hash(issuer)?;

    let enc_ocsp_req = prepare_ocsp_request(
        target_cert.as_ref(),
        name_hash.as_slice(),
        key_hash.as_slice(),
        nonce.as_deref(),
    )?;

    let enc_ocsp_resp = match post_ocsp(
        uri_to_check,
        enc_ocsp_req.as_slice(),
        cps.get_max_ocsp_fetch_bytes(),
    )
    .await
    {
        Ok(eor) => eor,
        Err(e) => {
            error!("Failed sending OCSP request to {uri_to_check} with {e:?}");
            cpr.add_failed_ocsp_request(enc_ocsp_req, result_index);
            return Err(Error::NetworkError);
        }
    };

    match process_ocsp_response_internal(
        pe,
        cps,
        cpr,
        &enc_ocsp_resp,
        issuer,
        result_index,
        uri_to_check,
        target_cert,
        name_hash.as_slice(),
        key_hash.as_slice(),
        nonce.as_deref(),
        nonce_setting,
    ) {
        Ok(_) => {
            cpr.add_ocsp_request(enc_ocsp_req, result_index);
            Ok(())
        }
        Err(e) => {
            cpr.add_failed_ocsp_response(enc_ocsp_resp, result_index);
            cpr.add_failed_ocsp_request(enc_ocsp_req, result_index);
            Err(e)
        }
    }
}

/// Processes an OCSP request that may have been dynamically obtained or obtained from CertificationPath
/// due to stapling.
///
/// The [`PkiEnvironment`], [`CertificationPathSettings`] and [`CertificationPathResults`] parameters
/// are assumed to be the same as used for prior validation of a certification path containing the
/// target certificate, which is provided via the `target_certificate` parameter.
///
/// The enc_ocsp_resp parameter provides the response to process. The issuers_cert parameter provides
/// the certificate to use when calculating the name hash and key hash necessary to verify the response.
/// The responders certificate is required to be present in the OCSP response, at present, and must be
/// verified using the issuers_cert.
///
/// The result_index parameter is used when preparing results and the uri_to_check parameter is used
/// when generating log messages.
#[allow(clippy::too_many_arguments)]
pub fn process_ocsp_response(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cpr: &mut CertificationPathResults,
    enc_ocsp_resp: &[u8],
    issuer: &dyn SubjectNameAndKey,
    result_index: usize,
    uri_to_check: &str,
    target_cert: &PDVCertificate,
) -> Result<()> {
    let key_hash = get_key_hash(issuer)?;
    let name_hash = get_subject_name_hash(issuer)?;
    // A stapled/externally-supplied response was not solicited by this library, so no nonce was
    // sent and none is enforced.
    process_ocsp_response_internal(
        pe,
        cps,
        cpr,
        enc_ocsp_resp,
        issuer,
        result_index,
        uri_to_check,
        target_cert,
        name_hash.as_slice(),
        key_hash.as_slice(),
        None,
        OcspNonceSetting::DoNotSendNonce,
    )
}

#[allow(clippy::too_many_arguments)]
fn process_ocsp_response_internal(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cpr: &mut CertificationPathResults,
    enc_ocsp_resp: &[u8],
    issuer: &dyn SubjectNameAndKey,
    result_index: usize,
    uri_to_check: &str,
    target_cert: &PDVCertificate,
    name_hash: &[u8],
    key_hash: &[u8],
    expected_nonce: Option<&[u8]>,
    nonce_setting: OcspNonceSetting,
) -> Result<()> {
    // The issuer's subject name, used to match delegated responder certificates below. Resolved once
    // (a trust anchor lookup can fail); a failure here means we cannot identify the issuer at all.
    let issuer_subject = issuer.subject_name()?;
    let or = match OcspResponse::from_der(enc_ocsp_resp) {
        Ok(or) => or,
        Err(e) => {
            error!("Failed to parse OcspResponse from {uri_to_check}");
            cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
            return Err(Error::Asn1Error(e));
        }
    };

    if or.response_status != OcspResponseStatus::Successful {
        error!(
            "OcspResponse from {uri_to_check} indicates failure ({:?})",
            or.response_status
        );
        cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
        return Err(Error::OcspResponseError);
    }

    let rb = match &or.response_bytes {
        Some(rb) => rb,
        None => {
            error!("OcspResponse from {uri_to_check} contained no response bytes");
            cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
            return Err(Error::OcspResponseError);
        }
    };

    if rb.response_type != ID_PKIX_OCSP_BASIC {
        error!(
            "OcspResponse from {uri_to_check} contained response bytes other than basic type ({})",
            rb.response_type
        );
        cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
        return Err(Error::OcspResponseError);
    }

    let bor = match BasicOcspResponse::from_der(rb.response.as_bytes()) {
        Ok(bor) => bor,
        Err(e) => {
            error!("OcspResponse from {uri_to_check} contained BasicOcspResponse that could not be parsed with: {e}");
            cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
            return Err(Error::Asn1Error(e));
        }
    };

    if unsupported_critical_extensions_present_response(&bor.tbs_response_data) {
        error!(
            "OcspResponse from {uri_to_check} contained at least one unsupported critical extension"
        );
        cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
        return Err(Error::PathValidation(
            PathValidationStatus::UnprocessedCriticalExtension,
        ));
    }

    // Nonce is enforced below, after signature verification.

    // Reject a response whose producedAt post-dates the time of interest. producedAt is when the
    // responder signed the response; like a future thisUpdate (rejected in check_response_time), a
    // producedAt after the time of interest indicates a clock or replay anomaly. thisUpdate/nextUpdate
    // remain the primary freshness anchors, checked per SingleResponse below.
    let time_of_interest = cps.get_time_of_interest();
    if !time_of_interest.is_disabled() && bor.tbs_response_data.produced_at.0 > time_of_interest {
        error!("OCSPResponse from {uri_to_check} carries a producedAt later than the time of interest; rejecting response as not yet valid");
        cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
        return Err(Error::OcspResponseError);
    }

    let mut sigverified = false;
    let mut authorized_responder = false;

    // TODO support responder certs signed by key rollover certs?
    // Verify the response signature. If there are certs in the response, search those for certs signed
    // by the same CA that issued the target cert (i.e., key rollover certs do not apply here presently)
    if let Some(certs) = &bor.certs {
        for a in certs {
            let Ok(certbuf) = a.to_der() else {
                continue;
            };
            let Ok(cert) = CertificateInner::<Raw>::from_der(certbuf.as_slice()) else {
                continue;
            };

            // Order the checks cheapest-first so an echoed certificate that cannot be a valid
            // delegated responder is discarded before any signature verification is attempted. This
            // both reads more clearly and bounds the work a response with many echoed certificates
            // can impose.

            // A delegated responder is issued by the same CA as the target, so its issuer must match
            // that CA's subject. This is a necessary condition for the signature verification below,
            // so a name mismatch lets us skip that verification entirely.
            if !compare_names(cert.tbs_certificate().issuer(), issuer_subject) {
                continue;
            }

            // RFC 6960 4.2.2.2: a delegated OCSP responder certificate MUST assert the
            // id-kp-OCSPSigning EKU; otherwise any CA-issued EE cert could sign OCSP responses.
            if !has_ocsp_signing_eku(&cert.tbs_certificate().extensions()) {
                error!("Candidate responder cert from OCSPResponse from {uri_to_check} lacks the id-kp-OCSPSigning EKU required of a delegated OCSP responder");
                cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
                continue;
            }

            let time_of_interest = cps.get_time_of_interest();
            if !time_of_interest.is_disabled()
                && valid_at_time(cert.tbs_certificate(), time_of_interest, false).is_err()
            {
                error!(
                    "Candidate responder cert from OCSPResponse from {uri_to_check} has expired"
                );
                cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
                continue;
            }

            // Verify the candidate was signed by the issuing CA.
            let Ok(defer_cert) = DeferDecodeSigned::from_der(certbuf.as_slice()) else {
                continue;
            };
            if pe
                .verify_signature_message(
                    pe,
                    &defer_cert.tbs_field,
                    defer_cert.signature.raw_bytes(),
                    &defer_cert.signature_algorithm,
                    issuer.spki(),
                )
                .is_err()
            {
                continue;
            }
            if *cert.tbs_certificate().signature() != defer_cert.signature_algorithm {
                error!("Verified candidate responder cert from OCSPResponse from {uri_to_check} but signature algorithm match failed");
                cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
                continue;
            }

            // The responder cert lacks id-pkix-ocsp-nocheck, so its own revocation status is not
            // waived (RFC 6960 4.2.2.2.1). Check it against locally available CRLs (issued by the
            // same CA as the responder) and reject the response if the responder is revoked. Remote
            // retrieval is not attempted here: this path is synchronous, and responder certs that
            // omit nocheck are rare in practice.
            if !no_check_present(&cert.tbs_certificate().extensions()) {
                let mut responder_revoked = false;
                if let Ok(responder) = PDVCertificate::try_from(certbuf.as_slice()) {
                    if let Ok(crls) = pe.get_crls(&responder) {
                        for crl in &crls {
                            if let Err(Error::PathValidation(
                                PathValidationStatus::CertificateRevoked,
                            )) = process_crl(
                                pe,
                                cps,
                                cpr,
                                &responder,
                                issuer,
                                result_index,
                                crl.as_slice(),
                                None,
                            ) {
                                responder_revoked = true;
                                break;
                            }
                        }
                    }
                }
                if responder_revoked {
                    error!("Delegated OCSP responder cert from {uri_to_check} is revoked per a locally available CRL; rejecting response");
                    cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
                    continue;
                }
            }

            authorized_responder = true;

            if verify_response_signature(pe, &cert, rb.response.as_bytes(), &bor).is_err() {
                error!("Verified candidate responder cert from OCSPResponse from {uri_to_check} but response signature verification failed");
                continue;
            }
            sigverified = true;
        }

        // Direct CA signing (RFC 6960 4.2.2.2): a CA that issued the target certificate may sign
        // its own OCSP responses while still echoing its certificate in `certs`. Such a certificate
        // is not a delegated responder (it does not assert the id-kp-OCSPSigning EKU), so if none of
        // the echoed certificates authorized the response, fall back to the issuing CA's own key.
        if !sigverified
            && verify_response_signature(pe, issuer, rb.response.as_bytes(), &bor).is_ok()
        {
            authorized_responder = true;
            sigverified = true;
        }
    } else {
        // try the issuer's cert
        let r = verify_response_signature(pe, issuer, rb.response.as_bytes(), &bor);
        if r.is_err() {
            error!("OCSPResponse from {uri_to_check} featured no candidate certificate but response signature verification failed using issuing CA certificate");
            cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
            return r;
        } else {
            authorized_responder = true;
            sigverified = true;
        }
    }

    if !authorized_responder {
        error!("Failed to find authorized OCSP responder from {uri_to_check}. Note, responders signed by key rollover certificates are not presently accepted (though this may not have been a factor here).");
        cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
        return Err(Error::Unrecognized);
    }

    if !sigverified {
        error!("Signature on OCSPResponse from {uri_to_check} was not verified.");
        cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
        return Err(Error::Unrecognized);
    }

    // Enforce the nonce policy on the (now signature-verified) response. `expected_nonce` is set
    // only when this library sent the request with a nonce; stapled responses pass None with
    // DoNotSendNonce and are unaffected.
    let response_nonce = bor.nonce();
    let response_nonce = response_nonce.as_ref().map(|n| n.0.as_bytes());
    if !nonce_acceptable(nonce_setting, expected_nonce, response_nonce) {
        error!("OCSPResponse from {uri_to_check} did not echo the expected nonce and PS_OCSP_AIA_NONCE_SETTING requires a match.");
        cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
        return Err(Error::OcspResponseError);
    }
    // Under SendNonceTolerateMismatchAbsence a nonce we chose not to fail on is still worth
    // surfacing: a response echoing a *different* nonce than we sent is more suspect (replay/MITM or
    // a broken responder) than a plain omission, which is common with RFC 6960-era responders.
    if nonce_setting == OcspNonceSetting::SendNonceTolerateMismatchAbsence {
        if let (Some(sent), Some(got)) = (expected_nonce, response_nonce) {
            if sent != got {
                warn!("OCSPResponse from {uri_to_check} echoed a nonce that does not match the one sent; tolerated per PS_OCSP_AIA_NONCE_SETTING.");
            }
        }
    }

    let mut retval = PathValidationStatus::RevocationStatusNotDetermined;
    for sr in bor.tbs_response_data.responses {
        if !cert_id_match(
            &sr.cert_id,
            target_cert.as_ref().tbs_certificate().serial_number(),
            name_hash,
            key_hash,
        ) {
            continue;
        }
        if unsupported_critical_extensions_present_single_response(&sr) {
            error!("OCSPResponse from {uri_to_check} featured unrecognized critical extensions in single response.");
            cpr.add_failed_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
            return Err(Error::PathValidation(
                PathValidationStatus::UnprocessedCriticalExtension,
            ));
        }

        match sr.cert_status {
            CertStatus::Good(_null) => {
                if check_response_time(cps, &sr) {
                    if let Some(nu) = sr.next_update {
                        pe.add_status(
                            target_cert,
                            nu.0.to_unix_duration().as_secs(),
                            PathValidationStatus::Valid,
                        );
                    }
                    retval = PathValidationStatus::Valid;
                }
            }
            CertStatus::Revoked(_revinfo) => {
                if let Some(nu) = sr.next_update {
                    pe.add_status(
                        target_cert,
                        nu.0.to_unix_duration().as_secs(),
                        PathValidationStatus::CertificateRevoked,
                    );
                }
                retval = PathValidationStatus::CertificateRevoked;
            }
            CertStatus::Unknown(_null) => {}
        }
        if retval != PathValidationStatus::RevocationStatusNotDetermined {
            break;
        }
    }

    cpr.add_ocsp_response(enc_ocsp_resp.to_vec(), result_index);
    if retval == PathValidationStatus::Valid {
        Ok(())
    } else {
        Err(Error::PathValidation(retval))
    }
}

#[cfg(feature = "remote")]
fn get_ocsp_aias(target_cert: &PDVCertificate) -> Vec<&Ia5String> {
    let mut retval = vec![];
    if let Ok(Some(PDVExtension::AuthorityInfoAccessSyntax(aias))) =
        target_cert.get_extension(&ID_PE_AUTHORITY_INFO_ACCESS)
    {
        for aia in &aias.0 {
            if aia.access_method == ID_AD_OCSP {
                if let GeneralName::UniformResourceIdentifier(aia) = &aia.access_location {
                    if !retval.contains(&aia) {
                        retval.push(aia);
                    }
                }
            }
        }
    }
    retval
}

#[cfg(feature = "remote")]
pub(crate) async fn check_revocation_ocsp(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cpr: &mut CertificationPathResults,
    target_cert: &PDVCertificate,
    issuer: &dyn SubjectNameAndKey,
    pos: usize,
) -> PathValidationStatus {
    let mut target_status = PathValidationStatus::RevocationStatusNotDetermined;
    let ocsp_aias = get_ocsp_aias(target_cert);
    if ocsp_aias.is_empty() {
        info!(
            "No OCSP AIAs found for {}",
            name_to_string(target_cert.as_ref().tbs_certificate().subject())
        );
    } else {
        for aia in ocsp_aias {
            match send_ocsp_request(pe, cps, aia.as_str(), target_cert, issuer, cpr, pos).await {
                Ok(_r) => target_status = PathValidationStatus::Valid,
                Err(e) => {
                    if let Error::PathValidation(pvs) = e {
                        target_status = pvs;
                    }
                }
            };
            if target_status != PathValidationStatus::RevocationStatusNotDetermined {
                info!(
                        "Determined revocation status ({}) using OCSP for certificate issued to {} via {}",
                        target_status,
                        name_to_string(target_cert.as_ref().tbs_certificate().subject()),
                        aia.as_str(),
                    );
                // no need to consider additional AIAs
                break;
            } else {
                info!(
                    "Failed to determine status for {} via {}",
                    name_to_string(target_cert.as_ref().tbs_certificate().subject()),
                    aia.as_str()
                );
            }
        }
    }
    target_status
}

//todo fix or replace
// #[cfg(feature = "remote")]
// #[tokio::test]
// async fn ocsp_test1_ca_signed() {
//     use crate::pdv_extension::ExtensionProcessing;
//     use crate::{populate_5280_pki_environment, ParsedExtensions, EXTS_OF_INTEREST};
//     use der::Decode;
//
//     let issuers_cert_buf = include_bytes!("../../tests/examples/DigiCertGlobalCAG2.der");
//     let ic = Certificate::from_der(issuers_cert_buf).unwrap();
//     let mut issuers_cert = PDVCertificate {
//         encoded_cert: issuers_cert_buf,
//         decoded_cert: ic,
//         metadata: None,
//         parsed_extensions: ParsedExtensions::new(),
//     };
//     issuers_cert.parse_extensions(EXTS_OF_INTEREST);
//
//     let target_cert_buf = include_bytes!("../../tests/examples/amazon.com/2-target.der");
//     let tc = Certificate::from_der(target_cert_buf).unwrap();
//     let mut target_cert = PDVCertificate {
//         encoded_cert: target_cert_buf,
//         decoded_cert: tc,
//         metadata: None,
//         parsed_extensions: ParsedExtensions::new(),
//     };
//     target_cert.parse_extensions(EXTS_OF_INTEREST);
//
//     let uri_to_check = "http://ocsp.digicert.com";
//     let mut pe = PkiEnvironment::default();
//     populate_5280_pki_environment(&mut pe);
//     let cps = CertificationPathSettings::default();
//     let mut cpr = CertificationPathResults::default();
//     let result_index = 0;
//     let _r = match send_ocsp_request(
//         &pe,
//         &cps,
//         uri_to_check,
//         &target_cert,
//         &issuers_cert.decoded_cert,
//         &mut cpr,
//         result_index,
//     )
//     .await
//     {
//         Ok(_r) => {
//             println!("Successfully executed OCSP")
//         }
//         Err(_e) => {
//             panic!("Failed to send OCSP request")
//         }
//     };
// }

//todo fix or replace
// #[cfg(feature = "remote")]
// #[tokio::test]
// async fn ocsp_test1_delegated() {
//     use crate::pdv_extension::ExtensionProcessing;
//     use crate::{populate_5280_pki_environment, ParsedExtensions, EXTS_OF_INTEREST};
//     use der::Decode;
//
//     let issuers_cert_buf = include_bytes!("../../tests/examples/cert_store_one/email_ca_59.der");
//     let ic = Certificate::from_der(issuers_cert_buf).unwrap();
//     let mut issuers_cert = PDVCertificate {
//         encoded_cert: issuers_cert_buf,
//         decoded_cert: ic,
//         metadata: None,
//         parsed_extensions: ParsedExtensions::new(),
//     };
//     issuers_cert.parse_extensions(EXTS_OF_INTEREST);
//
//     let target_cert_buf = include_bytes!("../../tests/examples/ee.der");
//     let tc = Certificate::from_der(target_cert_buf).unwrap();
//     let mut target_cert = PDVCertificate {
//         encoded_cert: target_cert_buf,
//         decoded_cert: tc,
//         metadata: None,
//         parsed_extensions: ParsedExtensions::new(),
//     };
//     target_cert.parse_extensions(EXTS_OF_INTEREST);
//
//     let uri_to_check = "http://ocsp.disa.mil";
//     let mut pe = PkiEnvironment::default();
//     populate_5280_pki_environment(&mut pe);
//     let cps = CertificationPathSettings::default();
//     let mut cpr = CertificationPathResults::default();
//     let result_index = 0;
//     match send_ocsp_request(
//         &pe,
//         &cps,
//         uri_to_check,
//         &target_cert,
//         &issuers_cert.decoded_cert,
//         &mut cpr,
//         result_index,
//     )
//     .await
//     {
//         Ok(_r) => {
//             panic!("Successfully executed OCSP but expected failure")
//         }
//         Err(e) => {
//             if e == Error::PathValidation(PathValidationStatus::CertificateRevoked) {
//                 println!("Successfully confirmed certificate is revoked");
//             } else {
//                 panic!("Unexpected error")
//             }
//         }
//     };
// }

//todo fix or replace
// #[cfg(feature = "remote")]
// #[tokio::test]
// async fn bad_ocsp_uri() {
//     use crate::{parse_cert, populate_5280_pki_environment, prepare_revocation_results};
//     let ocsp_req = include_bytes!("../../tests/examples/ocsp_tests/2-ocsp.ocspReq");
//     let r = post_ocsp("http://ocsp.example.com", ocsp_req).await;
//     assert!(r.is_err());
//     assert_eq!(Some(Error::NetworkError), r.err());
//
//     let r = post_ocsp("ldap://ssp-ocsp.digicert.com", ocsp_req).await;
//     assert!(r.is_err());
//     assert_eq!(Some(Error::NetworkError), r.err());
//
//     let target = include_bytes!("../../tests/examples/ocsp_tests/2.der");
//     let target_cert = parse_cert(target, "../../tests/examples/ocsp_tests/2.der").unwrap();
//     let issuer = include_bytes!("../../tests/examples/ocsp_tests/1.der");
//     let issuer_cert = Certificate::from_der(issuer).unwrap();
//     let mut pe = PkiEnvironment::default();
//     populate_5280_pki_environment(&mut pe);
//     let cps = CertificationPathSettings::default();
//     let mut cpr = CertificationPathResults::default();
//     prepare_revocation_results(&mut cpr, 1).unwrap();
//
//     // use bad scheme
//     let r = send_ocsp_request(
//         &pe,
//         &cps,
//         "ldap://ssp-ocsp.digicert.com",
//         &target_cert,
//         &issuer_cert,
//         &mut cpr,
//         0,
//     )
//     .await;
//     assert!(r.is_err());
//     assert_eq!(Some(Error::InvalidUriScheme), r.err());
//
//     // use bad host
//     let r = send_ocsp_request(
//         &pe,
//         &cps,
//         "http://ocsp.example.com",
//         &target_cert,
//         &issuer_cert,
//         &mut cpr,
//         0,
//     )
//     .await;
//     assert!(r.is_err());
//     assert_eq!(Some(Error::NetworkError), r.err());
//
//     //send to wrong host
//     let r = send_ocsp_request(
//         &pe,
//         &cps,
//         "http://ocsp.disa.mil",
//         &target_cert,
//         &issuer_cert,
//         &mut cpr,
//         0,
//     )
//     .await;
//     assert!(r.is_err());
//     assert_eq!(Some(Error::OcspResponseError), r.err());
// }

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------------------------
    // Nonce policy (nonce_acceptable) - fully deterministic, no network.
    // ------------------------------------------------------------------------------------------

    #[test]
    fn nonce_acceptable_do_not_send_never_enforces() {
        let s = OcspNonceSetting::DoNotSendNonce;
        assert!(nonce_acceptable(s, None, None));
        assert!(nonce_acceptable(s, Some(&[1, 2, 3]), None));
        assert!(nonce_acceptable(s, None, Some(&[9, 9])));
        assert!(nonce_acceptable(s, Some(&[1, 2, 3]), Some(&[4, 5, 6])));
    }

    #[test]
    fn nonce_acceptable_require_match_is_strict() {
        let s = OcspNonceSetting::SendNonceRequireMatch;
        // exact echo of the sent nonce is the only acceptance
        assert!(nonce_acceptable(s, Some(&[1, 2, 3]), Some(&[1, 2, 3])));
        // mismatch, absence, or a never-sent nonce all fail closed
        assert!(!nonce_acceptable(s, Some(&[1, 2, 3]), Some(&[1, 2, 4])));
        assert!(!nonce_acceptable(s, Some(&[1, 2, 3]), None));
        assert!(!nonce_acceptable(s, None, Some(&[1, 2, 3])));
        assert!(!nonce_acceptable(s, None, None));
    }

    #[test]
    fn nonce_acceptable_tolerate_never_fails_on_nonce() {
        let s = OcspNonceSetting::SendNonceTolerateMismatchAbsence;
        assert!(nonce_acceptable(s, Some(&[1, 2, 3]), Some(&[1, 2, 3])));
        assert!(nonce_acceptable(s, Some(&[1, 2, 3]), Some(&[9, 9]))); // mismatch tolerated
        assert!(nonce_acceptable(s, Some(&[1, 2, 3]), None)); // absence tolerated
    }

    // ------------------------------------------------------------------------------------------
    // Request encoding carries the nonce (deterministic; fixed nonce in -> extension out).
    // ------------------------------------------------------------------------------------------

    #[cfg(feature = "remote")]
    #[test]
    fn prepare_ocsp_request_round_trips_nonce() {
        use x509_ocsp::OcspRequest;

        let target = CertificateInner::<Raw>::from_der(include_bytes!(
            "../../tests/examples/ocsp_dod/47.der"
        ))
        .unwrap();
        let name_hash = [0u8; 20];
        let key_hash = [0u8; 20];
        let nonce = [0xABu8; 32];

        // With a nonce: the encoded request carries an id-pkix-ocsp-nonce extension echoing it.
        let enc = prepare_ocsp_request(&target, &name_hash, &key_hash, Some(&nonce)).unwrap();
        let req: OcspRequest = OcspRequest::from_der(&enc).unwrap();
        let got = req
            .tbs_request
            .nonce()
            .expect("request should carry a nonce extension");
        assert_eq!(got.0.as_bytes(), &nonce);

        // Without a nonce: no request extensions are present.
        let enc = prepare_ocsp_request(&target, &name_hash, &key_hash, None).unwrap();
        let req: OcspRequest = OcspRequest::from_der(&enc).unwrap();
        assert!(req.tbs_request.request_extensions.is_none());
    }

    // ------------------------------------------------------------------------------------------
    // Offline replay of a live-harvested DoD OCSP response (delegated responder + echoed nonce).
    //
    // Fixtures were harvested from ocsp.disa.mil for cert 47 (issued by DOD EMAIL CA-63) on
    // 2026-07-15. The response is signed by a delegated responder (DOD NIPRNET OCSP ..., asserting
    // id-kp-OCSPSigning + id-pkix-ocsp-nocheck) issued by CA-63, and echoes the request nonce. Time
    // of interest is pinned into the freshness window (thisUpdate 2026-07-15T00:00:01Z, nextUpdate
    // 2026-07-22T01:00:00Z) which also lies within the responder cert validity (2026-07-04 ..
    // 2026-08-18), so the replay is stable despite the leaf/responder eventually expiring.
    // ------------------------------------------------------------------------------------------

    #[cfg(all(feature = "std", feature = "rsa"))]
    #[test]
    fn ocsp_offline_replay_delegated_responder_with_nonce() {
        use hex_literal::hex;

        let enc_resp = include_bytes!("../../tests/examples/ocsp_dod/47-ocsp-resp.der").as_slice();
        let ca63 = CertificateInner::<Raw>::from_der(include_bytes!(
            "../../tests/examples/ocsp_dod/ca63.der"
        ))
        .unwrap();
        let mut target = PDVCertificate::try_from(
            include_bytes!("../../tests/examples/ocsp_dod/47.der").as_slice(),
        )
        .unwrap();
        target.parse_extensions(crate::EXTS_OF_INTEREST);

        // The nonce carried in the harvested request and echoed by the response.
        let sent_nonce = hex!("54992C9A49DBE95781C3B8B41456A4B8");

        let name_hash = get_subject_name_hash(&ca63).unwrap();
        let key_hash = get_key_hash(&ca63).unwrap();

        let mut pe = PkiEnvironment::new();
        pe.populate_5280_pki_environment();

        let fresh = crate::TimeOfInterest::from_unix_secs(1784203200).unwrap(); // 2026-07-16T12:00:00Z
        let stale = crate::TimeOfInterest::from_unix_secs(1784980800).unwrap(); // 2026-07-25T12:00:00Z

        let run = |toi, expected_nonce: Option<&[u8]>, setting| {
            let mut cps = CertificationPathSettings::new();
            cps.set_time_of_interest(toi);
            let mut cpr = CertificationPathResults::new();
            cpr.prepare_revocation_results(2).unwrap();
            process_ocsp_response_internal(
                &pe,
                &cps,
                &mut cpr,
                enc_resp,
                &ca63,
                0,
                "offline",
                &target,
                name_hash.as_slice(),
                key_hash.as_slice(),
                expected_nonce,
                setting,
            )
        };

        // (1) Fresh, correct nonce, RequireMatch -> Valid. Exercises delegated-responder signature
        // verification against CA-63, the id-kp-OCSPSigning EKU gate, and the positive nonce match.
        assert!(
            run(
                fresh,
                Some(&sent_nonce),
                OcspNonceSetting::SendNonceRequireMatch
            )
            .is_ok(),
            "fresh response with matching nonce should be Valid"
        );

        // (2) Fresh, wrong nonce, RequireMatch -> rejected.
        assert_eq!(
            run(
                fresh,
                Some(&[0u8; 16]),
                OcspNonceSetting::SendNonceRequireMatch
            ),
            Err(Error::OcspResponseError)
        );

        // (3) The stapled/public entrypoint (DoNotSendNonce) accepts it regardless of nonce.
        {
            let mut cps = CertificationPathSettings::new();
            cps.set_time_of_interest(fresh);
            let mut cpr = CertificationPathResults::new();
            cpr.prepare_revocation_results(2).unwrap();
            let r =
                process_ocsp_response(&pe, &cps, &mut cpr, enc_resp, &ca63, 0, "offline", &target);
            assert!(
                r.is_ok(),
                "public process_ocsp_response should be Valid, got {r:?}"
            );
        }

        // (4) Stale (past nextUpdate), correct nonce, RequireMatch -> not accepted.
        assert!(
            run(
                stale,
                Some(&sent_nonce),
                OcspNonceSetting::SendNonceRequireMatch
            )
            .is_err(),
            "response past nextUpdate should not be accepted"
        );

        // (5) producedAt freshness. producedAt is 2026-07-15T09:07:34Z. With the time of
        // interest at 2026-07-15T05:00:00Z, thisUpdate (00:00:01Z) and nextUpdate (07-22) still
        // bracket it, so the response is otherwise fresh - only the future producedAt rejects it.
        let producedat_future = crate::TimeOfInterest::from_unix_secs(1784091600).unwrap();
        assert_eq!(
            run(
                producedat_future,
                Some(&sent_nonce),
                OcspNonceSetting::SendNonceRequireMatch
            ),
            Err(Error::OcspResponseError),
            "producedAt later than the time of interest should be rejected"
        );
    }

    // ------------------------------------------------------------------------------------------
    // Direct CA signing with the CA certificate echoed in `certs`. A CA that issued the target
    // signs its own OCSP responses (RFC 6960 4.2.2.2) and may still populate `certs` with its own
    // certificate. That certificate is not a delegated responder (no id-kp-OCSPSigning EKU), so the
    // delegated path rejects it; acceptance depends on falling back to the issuing CA's own key.
    //
    // Fixtures (examples/ocsp_direct_ca) were generated with openssl: a self-signed CA (CA:TRUE,
    // keyCertSign+cRLSign, no OCSP-signing EKU), an EE it issued (serial 0x1234), and an OCSP
    // response produced with the CA itself as the responder (-rsigner ca -rkey ca-key), so the
    // response is signed by the CA key and echoes the CA certificate. thisUpdate 2026-07-15,
    // nextUpdate 2036-07-12; the time of interest is pinned into that window and the cert validity.
    // ------------------------------------------------------------------------------------------

    #[cfg(all(feature = "std", feature = "rsa"))]
    #[test]
    fn ocsp_direct_ca_signed_response_echoing_ca_cert() {
        let enc_resp = include_bytes!("../../tests/examples/ocsp_direct_ca/resp.der").as_slice();
        let ca = CertificateInner::<Raw>::from_der(include_bytes!(
            "../../tests/examples/ocsp_direct_ca/ca.der"
        ))
        .unwrap();
        let mut target = PDVCertificate::try_from(
            include_bytes!("../../tests/examples/ocsp_direct_ca/ee.der").as_slice(),
        )
        .unwrap();
        target.parse_extensions(crate::EXTS_OF_INTEREST);

        let name_hash = get_subject_name_hash(&ca).unwrap();
        let key_hash = get_key_hash(&ca).unwrap();

        let mut pe = PkiEnvironment::new();
        pe.populate_5280_pki_environment();

        let mut cps = CertificationPathSettings::new();
        cps.set_time_of_interest(crate::TimeOfInterest::from_unix_secs(1785542400).unwrap()); // 2026-08-01
        let mut cpr = CertificationPathResults::new();
        cpr.prepare_revocation_results(2).unwrap();

        let r = process_ocsp_response_internal(
            &pe,
            &cps,
            &mut cpr,
            enc_resp,
            &ca,
            0,
            "offline-direct-ca",
            &target,
            name_hash.as_slice(),
            key_hash.as_slice(),
            None,
            OcspNonceSetting::DoNotSendNonce,
        );
        assert!(
            r.is_ok(),
            "a CA-signed response echoing the CA cert must be accepted via the direct-CA fallback, got {r:?}"
        );
    }

    // ------------------------------------------------------------------------------------------
    // Freshness of a response that omits nextUpdate. RFC 6960 permits an absent nextUpdate,
    // but without a bound an ancient response would be treated as fresh; PS_REVOCATION_MAX_AGE caps
    // its age from thisUpdate (default 0 => fail closed).
    // ------------------------------------------------------------------------------------------

    #[cfg(all(feature = "std", feature = "revocation"))]
    #[test]
    fn check_response_time_missing_next_update_honours_max_age() {
        use x509_ocsp::{BasicOcspResponse, OcspResponse};

        let enc_resp = include_bytes!("../../tests/examples/ocsp_dod/47-ocsp-resp.der").as_slice();
        let or = OcspResponse::from_der(enc_resp).unwrap();
        let rb = or.response_bytes.unwrap();
        let bor = BasicOcspResponse::from_der(rb.response.as_bytes()).unwrap();
        // A real SingleResponse (thisUpdate 2026-07-15T00:00:01Z, nextUpdate 2026-07-22T01:00:00Z),
        // so the CertId and thisUpdate are well formed; the test varies only nextUpdate and max age.
        let base = bor.tbs_response_data.responses.into_iter().next().unwrap();

        // ~1.5 days after thisUpdate (still inside the original nextUpdate window).
        let toi = crate::TimeOfInterest::from_unix_secs(1784203200).unwrap(); // 2026-07-16T12:00:00Z
        let cps_with = |max_age_secs: u64| {
            let mut cps = CertificationPathSettings::new();
            cps.set_time_of_interest(toi);
            cps.set_revocation_max_age(core::time::Duration::from_secs(max_age_secs));
            cps
        };

        // nextUpdate present: fresh regardless of max age (unchanged path).
        assert!(check_response_time(&cps_with(0), &base));

        // nextUpdate absent: fail closed by default, tolerated under a wide window, and rejected
        // again once the window is shorter than the response's age (~1.5 days).
        let mut no_nu = base.clone();
        no_nu.next_update = None;
        assert!(
            !check_response_time(&cps_with(0), &no_nu),
            "absent nextUpdate must fail closed by default"
        );
        assert!(
            check_response_time(&cps_with(30 * 86400), &no_nu),
            "a wide max age tolerates an absent nextUpdate"
        );
        assert!(
            !check_response_time(&cps_with(3600), &no_nu),
            "a max age shorter than the response age rejects it"
        );
    }
}
