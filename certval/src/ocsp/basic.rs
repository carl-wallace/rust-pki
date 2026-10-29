//! Basic OCSP Response

use super::{
    ext::Nonce, AsResponseBytes, CertId, CertStatus, OcspGeneralizedTime, ResponderId, Version,
};
use alloc::vec::Vec;
use const_oid::{
    db::rfc6960::{ID_PKIX_OCSP_BASIC, ID_PKIX_OCSP_NONCE},
    AssociatedOid,
};
use core::{default::Default, option::Option};
use der::{
    asn1::{BitString, ObjectIdentifier},
    Decode, Sequence,
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{certificate::Certificate, ext::Extensions};

/// BasicOcspResponse structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// BasicOCSPResponse ::= SEQUENCE {
///   tbsResponseData          ResponseData,
///   signatureAlgorithm       AlgorithmIdentifier,
///   signature                BIT STRING,
///   certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct BasicOcspResponse {
    pub tbs_response_data: ResponseData,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub certs: Option<Vec<Certificate>>,
}

impl BasicOcspResponse {
    /// Returns the response's nonce value, if any. This method will return `None` if the response
    /// has no `Nonce` extension or decoding of the `Nonce` extension fails.
    pub fn nonce(&self) -> Option<Nonce> {
        self.tbs_response_data.nonce()
    }
}

impl AssociatedOid for BasicOcspResponse {
    const OID: ObjectIdentifier = ID_PKIX_OCSP_BASIC;
}

impl AsResponseBytes for BasicOcspResponse {}

/// ResponseData structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// ResponseData ::= SEQUENCE {
///    version              [0] EXPLICIT Version DEFAULT v1,
///    responderID             ResponderID,
///    producedAt              GeneralizedTime,
///    responses               SEQUENCE OF SingleResponse,
///    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct ResponseData {
    #[asn1(
        context_specific = "0",
        default = "Default::default",
        tag_mode = "EXPLICIT"
    )]
    pub version: Version,
    pub responder_id: ResponderId,
    pub produced_at: OcspGeneralizedTime,
    pub responses: Vec<SingleResponse>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub response_extensions: Option<Extensions>,
}

impl ResponseData {
    /// Returns the response's nonce value, if any. This method will return `None` if the response
    /// has no `Nonce` extension or decoding of the `Nonce` extension fails.
    pub fn nonce(&self) -> Option<Nonce> {
        match &self.response_extensions {
            Some(extns) => {
                let mut filter = extns.iter().filter(|e| e.extn_id == ID_PKIX_OCSP_NONCE);
                match filter.next() {
                    Some(extn) => Nonce::from_der(extn.extn_value.as_bytes()).ok(),
                    None => None,
                }
            }
            None => None,
        }
    }
}

/// SingleResponse structure as defined in [RFC 6960 Section 4.2.1].
///
/// ```text
/// SingleResponse ::= SEQUENCE {
///    certID                  CertID,
///    certStatus              CertStatus,
///    thisUpdate              GeneralizedTime,
///    nextUpdate              [0] EXPLICIT GeneralizedTime OPTIONAL,
///    singleExtensions        [1] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// [RFC 6960 Section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct SingleResponse {
    pub cert_id: CertId,
    pub cert_status: CertStatus,
    pub this_update: OcspGeneralizedTime,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    pub next_update: Option<OcspGeneralizedTime>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    pub single_extensions: Option<Extensions>,
}
