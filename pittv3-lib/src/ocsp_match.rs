//! Deciding which certificate an OCSP response answers about.
//!
//! A CRL says whose it is: its issuer name matches the issuer name of the certificates it covers,
//! which is why stapling one needs nothing cleverer than a name comparison. An OCSP response does
//! not. It carries a `CertID` — the hash of the issuer's name, the hash of the issuer's public key,
//! and the certificate's serial number — and answering "is this response about that certificate?"
//! means building the identity the responder would have been asked about and comparing.
//!
//! That question comes up in two places that must not answer it differently: a browser filing a
//! response the user uploaded, and a command line run filing one named on its arguments. Both
//! reach it through here.
//!
//! **The comparison is certval's own** ([`certval::cert_id_match`]), the one validation applies to
//! a response it processes, so a response filed here is one validation will accept as being about
//! that certificate. It hashes the issuer with the algorithm the response's `CertID` names, SHA-1,
//! SHA-256, SHA-384 or SHA-512; a `CertID` naming any other cannot be matched, which callers report
//! (see [`certval::cert_id_hash_algorithm_supported`]).
#![cfg(feature = "revocation")]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use certval::{cert_id_match, PDVCertificate, SubjectNameAndKey};
use der::Decode;
use x509_cert::certificate::Profile;
use x509_ocsp::{BasicOcspResponse, CertId, OcspResponse, OcspResponseStatus};

/// Reads the `CertID`s an OCSP response reports certificate status for, or says why it reports none.
///
/// A responder that will not say anything about a certificate still answers the request:
/// `tryLater`, `unauthorized` and the rest are `OCSPResponseStatus` values carried in a well-formed
/// response, and `successful` is the one that brings a `BasicOCSPResponse` with the per-certificate
/// statuses in it. So the question here is narrower than whether the responder replied.
///
/// Depends only on the bytes: everything it can reject, it rejects without a path or an environment
/// in sight. The `Err` string is written to be shown to a user as-is.
pub fn cert_ids_from_response(bytes: &[u8]) -> Result<Vec<CertId>, String> {
    let response = OcspResponse::from_der(bytes).map_err(|_| "Not an OCSP response".to_string())?;
    if response.response_status != OcspResponseStatus::Successful {
        return Err(format!(
            "OCSP responder reported {:?}, which carries no certificate status",
            response.response_status
        ));
    }
    let rb = response
        .response_bytes
        .as_ref()
        .ok_or_else(|| "OCSP response carries no response bytes".to_string())?;
    let basic = BasicOcspResponse::from_der(rb.response.as_bytes())
        .map_err(|_| "OCSP response body could not be read".to_string())?;
    let ids: Vec<CertId> = basic
        .tbs_response_data
        .responses
        .iter()
        .map(|single| single.cert_id.clone())
        .collect();
    match ids.is_empty() {
        true => Err("OCSP response contains no certificate IDs".to_string()),
        false => Ok(ids),
    }
}

/// Whether a response, already read into the `CertID`s it answers about (`answered`), answers about
/// `cert` as issued by `issuer`.
pub fn answers_about<P: Profile>(
    answered: &[CertId<P>],
    cert: &PDVCertificate,
    issuer: &dyn SubjectNameAndKey,
) -> bool {
    let serial = cert.decoded().tbs_certificate().serial_number();
    answered.iter().any(|id| cert_id_match(id, serial, issuer))
}
