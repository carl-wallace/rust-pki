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
//! **The comparison is made by building the request certval would have sent**, rather than by
//! hashing the issuer here. That makes the match certval's own notion of identity by construction,
//! and the hash helpers are private to certval anyway. It also means the comparison inherits
//! certval's SHA-1 `CertID`, so a response built with a different hash algorithm cannot be matched
//! this way — which callers report rather than swallow, hence [`SHA1_CERT_ID_OID`].
#![cfg(feature = "revocation")]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use certval::{build_ocsp_request, PDVCertificate, SubjectNameAndKey};
use der::Decode;
use x509_cert::certificate::{Profile, Raw};
use x509_ocsp::{BasicOcspResponse, CertId, OcspRequest, OcspResponse, OcspResponseStatus};

/// The OID of SHA-1, the hash certval builds a `CertID` with. Named so a caller reporting a failed
/// match can say why a response that is otherwise about the right certificate could not be matched.
pub const SHA1_CERT_ID_OID: &str = "1.3.14.3.2.26";

/// Reads the `CertID`s an OCSP response answers about, or says why it answers about none.
///
/// Depends only on the bytes: everything it can reject, it rejects without a path or an environment
/// in sight. The `Err` string is written to be shown to a user as-is.
pub fn answered_cert_ids(bytes: &[u8]) -> Result<Vec<CertId>, String> {
    let response = OcspResponse::from_der(bytes).map_err(|_| "Not an OCSP response".to_string())?;
    if response.response_status != OcspResponseStatus::Successful {
        return Err(format!(
            "OCSP response reports {:?} rather than an answer",
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
        true => Err("OCSP response answers about no certificate".to_string()),
        false => Ok(ids),
    }
}

/// The `CertID` a responder would be asked about for `cert` as issued by `issuer`, or `None` when
/// no request can be built for it.
///
/// Decoded under the `Raw` profile because that is the profile certval encoded it with:
/// `build_ocsp_request` takes the serial straight off a `CertificateInner<Raw>`, and
/// `SerialNumber<Rfc5280>` enforces a length constraint `Raw` does not. Reading it back as Rfc5280
/// would therefore fail for a certificate whose serial is longer than the RFC permits, dropping
/// that certificate from consideration for a reason that has nothing to do with the response.
pub fn asked_cert_id(cert: &PDVCertificate, issuer: &dyn SubjectNameAndKey) -> Option<CertId<Raw>> {
    let request = build_ocsp_request(cert.decoded(), issuer, None).ok()?;
    let request = OcspRequest::<Raw>::from_der(&request).ok()?;
    let asked = request.tbs_request.request_list.first()?;
    Some(asked.req_cert.clone())
}

/// Whether two `CertID`s name the same certificate under the same issuer, compared field by field.
///
/// Generic over the profile because the two sides come from different places: the response was
/// decoded from bytes someone handed us, and the request was built by certval under `Raw`.
pub fn same_cert_id<A: Profile, B: Profile>(a: &CertId<A>, b: &CertId<B>) -> bool {
    a.hash_algorithm.oid == b.hash_algorithm.oid
        && a.issuer_name_hash.as_bytes() == b.issuer_name_hash.as_bytes()
        && a.issuer_key_hash.as_bytes() == b.issuer_key_hash.as_bytes()
        && a.serial_number.as_bytes() == b.serial_number.as_bytes()
}

/// Whether `response`, already read into the `CertID`s it answers about, answers about `cert` as
/// issued by `issuer`. `None` when no request could be built, which is a different outcome from a
/// mismatch and one a caller may want to count separately.
pub fn answers_about<P: Profile>(
    answered: &[CertId<P>],
    cert: &PDVCertificate,
    issuer: &dyn SubjectNameAndKey,
) -> Option<bool> {
    let asked = asked_cert_id(cert, issuer)?;
    Some(answered.iter().any(|id| same_cert_id(id, &asked)))
}
