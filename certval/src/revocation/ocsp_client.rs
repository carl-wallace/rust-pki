//! Structures and functions to perform OCSP client functionality

extern crate alloc;
use alloc::vec::Vec;

use der::{Any, Decode, Encode};
use sha1::{Digest, Sha1};
use x509_cert::certificate::{CertificateInner, Raw};
use x509_cert::ext::Extensions;
use x509_ocsp::*;

use log::error;

#[cfg(feature = "remote")]
use log::{debug, info};

use crate::{
    add_failed_ocsp_response, add_ocsp_response, get_time_of_interest, valid_at_time,
    CertificationPathResults, CertificationPathSettings, DeferDecodeSigned, Error, PDVCertificate,
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
use crate::{
    add_failed_ocsp_request, add_ocsp_request, get_ocsp_aia_nonce_setting, name_to_string,
    pdv_extension::ExtensionProcessing, OcspNonceSetting, PDVExtension, PKIXALG_SHA1,
};

fn get_key_hash(cert: &CertificateInner<Raw>) -> Result<Vec<u8>> {
    Ok(Sha1::digest(
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )
    .to_vec())
}

fn get_subject_name_hash(cert: &CertificateInner<Raw>) -> Result<Vec<u8>> {
    let enc_subject = match cert.tbs_certificate.subject.to_der() {
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
    let time_of_interest = get_time_of_interest(cps);
    if 0 == time_of_interest {
        return true;
    }

    // TODO support grace periods?

    let tu = sr.this_update.0.to_unix_duration().as_secs();
    if tu > time_of_interest {
        //future request
        return false;
    }

    if let Some(next_update) = sr.next_update {
        let nu = next_update.0.to_unix_duration().as_secs();
        if nu < time_of_interest {
            //stale
            return false;
        }
    }
    true
}

#[cfg(feature = "remote")]
async fn post_ocsp(uri_to_check: &str, enc_ocsp_req: &[u8]) -> Result<Vec<u8>> {
    let client = if let Ok(client) = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(10))
        .build()
    {
        client
    } else {
        error!("Failed to prepare OCSP client: {}", uri_to_check);
        return Err(Error::NetworkError);
    };

    let body = match client
        .post(uri_to_check)
        .body(enc_ocsp_req.to_vec())
        .header(CONTENT_TYPE, "application/ocsp-request")
        .send()
        .await
    {
        Ok(b) => b,
        Err(e) => {
            debug!("OCSP request send failed with {}: {}", e, uri_to_check);
            return Err(Error::NetworkError);
        }
    };

    let body_bytes = match body.bytes().await {
        Ok(bb) => bb,
        Err(e) => {
            error!("Failed to read OCSP response with {}: {}", e, uri_to_check);
            return Err(Error::NetworkError);
        }
    };

    Ok(body_bytes.to_vec())
}

#[cfg(feature = "remote")]
fn prepare_ocsp_request(
    target_cert: &CertificateInner<Raw>,
    name_hash: &[u8],
    key_hash: &[u8],
    _nonce: Option<&[u8]>,
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
        serial_number: target_cert.tbs_certificate.serial_number.clone(),
    };
    //TODO add nonce support
    let request_list = vec![Request {
        req_cert,
        single_request_extensions: None,
    }];
    let tbs_request = TbsRequest {
        version: V1,
        requestor_name: None,
        request_list,
        request_extensions: None,
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
        use ::der::Reader as _;
        reader.read_nested(header.length, |reader| {
            let tbs_response_data = reader.tlv_bytes()?;
            let signature_algorithm = reader.tlv_bytes()?;
            let signature = reader.tlv_bytes()?;
            let certs =
                ::der::asn1::ContextSpecific::decode_explicit(reader, ::der::TagNumber::N0)?
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

fn no_check_present(exts: &Option<Extensions>) -> bool {
    if let Some(exts) = exts {
        for ext in exts {
            if ext.extn_id == ID_PKIX_OCSP_NOCHECK {
                return true;
            }
        }
    }
    false
}

fn verify_response_signature(
    pe: &PkiEnvironment,
    signers_cert: &CertificateInner<Raw>,
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
        &signers_cert.tbs_certificate.subject_public_key_info,
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
    issuers_cert: &CertificateInner<Raw>,
    cpr: &mut CertificationPathResults,
    result_index: usize,
) -> Result<()> {
    if !uri_to_check.starts_with("http") {
        debug!("Ignored non-HTTP URI presented to OCSP client",);
        return Err(Error::InvalidUriScheme);
    }

    let nonce_setting = get_ocsp_aia_nonce_setting(cps);

    let nonce = if nonce_setting != OcspNonceSetting::DoNotSendNonce {
        //TODO implement me
        todo!()
    } else {
        None
    };

    // Prepare info for request
    let key_hash = get_key_hash(issuers_cert)?;
    let name_hash = get_subject_name_hash(issuers_cert)?;

    let enc_ocsp_req = prepare_ocsp_request(
        &target_cert.decoded_cert,
        name_hash.as_slice(),
        key_hash.as_slice(),
        nonce,
    )?;

    let enc_ocsp_resp = match post_ocsp(uri_to_check, enc_ocsp_req.as_slice()).await {
        Ok(eor) => eor,
        Err(_e) => {
            error!(
                "Failed sending OCSP request to {} with {:?}",
                uri_to_check, _e
            );
            add_failed_ocsp_request(cpr, enc_ocsp_req, result_index);
            return Err(Error::NetworkError);
        }
    };

    match process_ocsp_response_internal(
        pe,
        cps,
        cpr,
        &enc_ocsp_resp,
        issuers_cert,
        result_index,
        uri_to_check,
        target_cert,
        name_hash.as_slice(),
        key_hash.as_slice(),
    ) {
        Ok(_) => {
            add_ocsp_request(cpr, enc_ocsp_req, result_index);
            Ok(())
        }
        Err(e) => {
            add_failed_ocsp_response(cpr, enc_ocsp_resp, result_index);
            add_failed_ocsp_request(cpr, enc_ocsp_req, result_index);
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
    issuers_cert: &CertificateInner<Raw>,
    result_index: usize,
    uri_to_check: &str,
    target_cert: &PDVCertificate,
) -> Result<()> {
    let key_hash = get_key_hash(issuers_cert)?;
    let name_hash = get_subject_name_hash(issuers_cert)?;
    process_ocsp_response_internal(
        pe,
        cps,
        cpr,
        enc_ocsp_resp,
        issuers_cert,
        result_index,
        uri_to_check,
        target_cert,
        name_hash.as_slice(),
        key_hash.as_slice(),
    )
}

#[allow(clippy::too_many_arguments)]
fn process_ocsp_response_internal(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    cpr: &mut CertificationPathResults,
    enc_ocsp_resp: &[u8],
    issuers_cert: &CertificateInner<Raw>,
    result_index: usize,
    uri_to_check: &str,
    target_cert: &PDVCertificate,
    name_hash: &[u8],
    key_hash: &[u8],
) -> Result<()> {
    let or = match OcspResponse::from_der(enc_ocsp_resp) {
        Ok(or) => or,
        Err(e) => {
            error!("Failed to parse OcspResponse from {}", uri_to_check);
            add_failed_ocsp_response(cpr, enc_ocsp_resp.to_vec(), result_index);
            return Err(Error::Asn1Error(e));
        }
    };

    if or.response_status != OcspResponseStatus::Successful {
        error!(
            "OcspResponse from {} indicates failure ({:?})",
            uri_to_check, or.response_status
        );
        add_failed_ocsp_response(cpr, enc_ocsp_resp.to_vec(), result_index);
        return Err(Error::OcspResponseError);
    }

    let rb = match &or.response_bytes {
        Some(rb) => rb,
        None => {
            error!(
                "OcspResponse from {} contained no response bytes",
                uri_to_check
            );
            add_failed_ocsp_response(cpr, enc_ocsp_resp.to_vec(), result_index);
            return Err(Error::OcspResponseError);
        }
    };

    if rb.response_type != ID_PKIX_OCSP_BASIC {
        error!(
            "OcspResponse from {} contained response bytes other than basic type ({})",
            uri_to_check, rb.response_type
        );
        add_failed_ocsp_response(cpr, enc_ocsp_resp.to_vec(), result_index);
        return Err(Error::OcspResponseError);
    }

    let bor = match BasicOcspResponse::from_der(rb.response.as_bytes()) {
        Ok(bor) => bor,
        Err(e) => {
            error!("OcspResponse from {} contained BasicOcspResponse that could not be parsed with: {}", uri_to_check, e);
            add_failed_ocsp_response(cpr, enc_ocsp_resp.to_vec(), result_index);
            return Err(Error::Asn1Error(e));
        }
    };

    if unsupported_critical_extensions_present_response(&bor.tbs_response_data) {
        error!(
            "OcspResponse from {} contained at least one unsupported critical extension",
            uri_to_check
        );
        add_failed_ocsp_response(cpr, enc_ocsp_resp.to_vec(), result_index);
        return Err(Error::PathValidation(
            PathValidationStatus::UnprocessedCriticalExtension,
        ));
    }

    // TODO nonce, produced at

    let mut sigverified = false;
    let mut authorized_responder = false;

    // TODO support responder certs signed by key rollover certs?
    // Verify the response signature. If there are certs in the response, search those for certs signed
    // by the same CA that issued the target cert (i.e., key rollover certs do not apply here presently)
    if let Some(certs) = &bor.certs {
        for a in certs {
            if let Ok(certbuf) = a.to_der() {
                if let Ok(defer_cert) = DeferDecodeSigned::from_der(certbuf.as_slice()) {
                    if let Ok(_r) = pe.verify_signature_message(
                        pe,
                        &defer_cert.tbs_field,
                        defer_cert.signature.raw_bytes(),
                        &defer_cert.signature_algorithm,
                        &issuers_cert.tbs_certificate.subject_public_key_info,
                    ) {
                        if let Ok(cert) = CertificateInner::<Raw>::from_der(certbuf.as_slice()) {
                            if cert.tbs_certificate.signature != defer_cert.signature_algorithm {
                                error!("Verified candidate responder cert from OCSPResponse from {} but signature algorithm match failed", uri_to_check);
                                add_failed_ocsp_response(cpr, enc_ocsp_resp.to_vec(), result_index);
                                continue;
                            }

                            let time_of_interest = get_time_of_interest(cps);
                            if 0 != time_of_interest {
                                let target_ttl =
                                    valid_at_time(&cert.tbs_certificate, time_of_interest, false);
                                if let Err(_e) = target_ttl {
                                    error!("Verified candidate responder cert from OCSPResponse from {} but certificate has expired", uri_to_check);
                                    add_failed_ocsp_response(
                                        cpr,
                                        enc_ocsp_resp.to_vec(),
                                        result_index,
                                    );
                                    continue;
                                }
                            }

                            if !no_check_present(&cert.tbs_certificate.extensions) {
                                //TODO implement revocation checking of responder cert
                                error!("no-check absent");
                            }

                            authorized_responder = true;

                            let r =
                                verify_response_signature(pe, &cert, rb.response.as_bytes(), &bor);
                            if r.is_err() {
                                error!("Verified candidate responder cert from OCSPResponse from {} but response signature verification failed", uri_to_check);
                                continue;
                            } else {
                                sigverified = true;
                            }
                        }
                    }
                }
            }
        }
    } else {
        // try the issuer's cert
        let r = verify_response_signature(pe, issuers_cert, rb.response.as_bytes(), &bor);
        if r.is_err() {
            error!("OCSPResponse from {} featured no candidate certificate but response signature verification failed using issuing CA certificate", uri_to_check);
            add_failed_ocsp_response(cpr, enc_ocsp_resp.to_vec(), result_index);
            return r;
        } else {
            authorized_responder = true;
            sigverified = true;
        }
    }

    if !authorized_responder {
        error!("Failed to find authorized OCSP responder from {}. Note, responders signed by key rollover certificates are not presently accepted (though this may not have been a factor here).", uri_to_check);
        add_failed_ocsp_response(cpr, enc_ocsp_resp.to_vec(), result_index);
        return Err(Error::Unrecognized);
    }

    if !sigverified {
        error!(
            "Signature on OCSPResponse from {} was not verified.",
            uri_to_check
        );
        add_failed_ocsp_response(cpr, enc_ocsp_resp.to_vec(), result_index);
        return Err(Error::Unrecognized);
    }

    let mut retval = PathValidationStatus::RevocationStatusNotDetermined;
    for sr in bor.tbs_response_data.responses {
        if !cert_id_match(
            &sr.cert_id,
            &target_cert.decoded_cert.tbs_certificate.serial_number,
            name_hash,
            key_hash,
        ) {
            continue;
        }
        if unsupported_critical_extensions_present_single_response(&sr) {
            error!("OCSPResponse from {} featured unrecognized critical extensions in single response.", uri_to_check);
            add_failed_ocsp_response(cpr, enc_ocsp_resp.to_vec(), result_index);
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

    add_ocsp_response(cpr, enc_ocsp_resp.to_vec(), result_index);
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
    issuer_cert: &CertificateInner<Raw>,
    pos: usize,
) -> PathValidationStatus {
    let mut target_status = PathValidationStatus::RevocationStatusNotDetermined;
    let ocsp_aias = get_ocsp_aias(target_cert);
    if ocsp_aias.is_empty() {
        info!(
            "No OCSP AIAs found for {}",
            name_to_string(&target_cert.decoded_cert.tbs_certificate.subject)
        );
    } else {
        for aia in ocsp_aias {
            match send_ocsp_request(pe, cps, aia.as_str(), target_cert, issuer_cert, cpr, pos).await
            {
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
                        name_to_string(&target_cert.decoded_cert.tbs_certificate.subject),
                        aia.as_str(),
                    );
                // no need to consider additional AIAs
                break;
            } else {
                info!(
                    "Failed to determine status for {} via {}",
                    name_to_string(&target_cert.decoded_cert.tbs_certificate.subject),
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
