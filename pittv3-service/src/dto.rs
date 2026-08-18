//! Request and response bodies.
//!
//! These are the only types that know the wire encoding. Certificates and artifact bodies travel as
//! base64 because JSON has no bytes; everything past this module works in `Vec<u8>`. Keeping the
//! encoding here is what lets the relay and the validation orchestration be exercised from a test
//! with plain Rust values and no HTTP.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use certval::CertificationPathSettings;
use pittv3_lib::report::ValidationReport;
use pittv3_relay::FetchMethod;

/// Base64 for a required byte string.
mod b64 {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(d)?;
        STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Base64 for an optional byte string.
mod b64_opt {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_some(&STANDARD.encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let encoded = Option::<String>::deserialize(d)?;
        match encoded {
            Some(e) => STANDARD
                .decode(e.as_bytes())
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// What a client asks the relay to retrieve.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FetchRequestBody {
    /// URI to retrieve.
    pub uri: String,
    /// Verb to use; `GET` when unstated.
    #[serde(default)]
    pub method: FetchMethod,
    /// Request body, e.g., a DER-encoded OCSP request.
    #[serde(default, with = "b64_opt", skip_serializing_if = "Option::is_none")]
    pub body: Option<Vec<u8>>,
    /// Value for the `Content-Type` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Value for the `If-Modified-Since` header, so a client holding an artifact can learn it is
    /// unchanged without retrieving it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_modified_since: Option<String>,
}

/// What the relay retrieved. The HTTP status is reported rather than translated, because a client
/// distinguishes cases the relay cannot: a 404 on an authority information access URI is a broken
/// certificate, and a 304 answers a conditional request.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FetchResponseBody {
    /// Status code from the repository.
    pub status: u16,
    /// Value of the `Content-Type` header, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Value of the `Last-Modified` header, for the client to store against its next request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// URI the response came from, which differs from the request when a redirect was followed.
    pub final_uri: String,
    /// Response body.
    #[serde(with = "b64")]
    pub body: Vec<u8>,
}

/// A certificate with the name to report it under. The name is the client's label -- an uploaded
/// file name, say -- and appears in the report so a person can tell which result is which.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NamedCertificate {
    /// Name to report this certificate under.
    pub name: String,
    /// DER-encoded certificate. PEM is accepted too, since the validation path decodes either.
    #[serde(with = "b64")]
    pub der: Vec<u8>,
}

/// What a client asks the service to validate.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ValidateRequestBody {
    /// Certificates to validate.
    pub targets: Vec<NamedCertificate>,
    /// Trust anchors to validate against, in addition to any named store.
    #[serde(default)]
    pub trust_anchors: Vec<NamedCertificate>,
    /// Intermediate CA certificates to build paths through, in addition to any named store.
    #[serde(default)]
    pub cas: Vec<NamedCertificate>,
    /// Identifier of a store the service holds, from `GET /api/stores`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_id: Option<String>,
    /// Path settings for the run. Sanitized on arrival; see [`crate::settings`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<CertificationPathSettings>,
    /// Validates every path found for a target rather than stopping at the first that validates.
    #[serde(default)]
    pub validate_all: bool,
}

/// What the service returns from a validation.
///
/// The report is flattened rather than nested so the body is a `ValidationReport` as far as any
/// client that ignores unknown fields is concerned -- the same structure the CLI writes and the
/// GUIs load. `notes` carries what the run has to say about itself: settings that were ignored,
/// retrievals that a budget cut short.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidateResponseBody {
    /// Result of the run.
    #[serde(flatten)]
    pub report: ValidationReport,
    /// Remarks about the run, e.g., settings the service declined to honor.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_bodies_carry_bytes_as_base64() {
        let request: FetchRequestBody = serde_json::from_str(
            r#"{"uri":"http://ocsp.example.com/","method":"POST","body":"AQID"}"#,
        )
        .unwrap();
        assert_eq!(request.method, FetchMethod::Post);
        assert_eq!(request.body, Some(vec![1, 2, 3]));

        // An absent method means GET, and an absent body means none, so the smallest useful request
        // is a URI on its own.
        let request: FetchRequestBody =
            serde_json::from_str(r#"{"uri":"http://crl.example.com/ca.crl"}"#).unwrap();
        assert_eq!(request.method, FetchMethod::Get);
        assert!(request.body.is_none());

        let encoded = serde_json::to_string(&FetchResponseBody {
            status: 200,
            content_type: None,
            last_modified: None,
            final_uri: "http://crl.example.com/ca.crl".to_string(),
            body: vec![4, 5, 6],
        })
        .unwrap();
        assert!(encoded.contains(r#""body":"BAUG""#));
    }

    #[test]
    fn a_validation_response_reads_as_a_report() {
        let body = ValidateResponseBody {
            report: ValidationReport::failed("no trust anchors"),
            notes: vec!["ignored psTrustAnchorFolder".to_string()],
        };
        let encoded = serde_json::to_string(&body).unwrap();

        // Flattened, so a client that only knows about reports still gets one.
        let report: ValidationReport = serde_json::from_str(&encoded).unwrap();
        assert_eq!(report.error.as_deref(), Some("no trust anchors"));
    }
}
