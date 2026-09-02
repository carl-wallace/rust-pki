//! HTTP surface.
//!
//! The handlers are thin on purpose: they decode a body, call something that knows nothing about
//! HTTP, and encode what comes back. Everything worth testing -- the network policy, the budgets,
//! the settings sanitizer, the validation itself -- is reachable without a running server.

use actix_web::{http::header, web, HttpRequest, HttpResponse, Responder};
use log::warn;
use serde::Serialize;

use pittv3_relay::{FetchError, FetchRequest, PeekRequest};

use crate::config::ServiceState;
use crate::dto::{
    FetchRequestBody, FetchResponseBody, PeekRequestBody, PeekResponseBody, ValidateRequestBody,
    ValidateResponseBody,
};
use crate::orchestrate::{self, ValidationInput};
use crate::CACHE_CONTROL_REVALIDATE;

/// Body returned when a request cannot be served.
#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

impl ErrorBody {
    fn new(message: impl Into<String>) -> Self {
        ErrorBody {
            error: message.into(),
        }
    }
}

/// Registers every route the service serves. Static files for the browser application are mounted
/// by the caller, after these, so an application file can never shadow an endpoint.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("/health", web::get().to(health))
            .route("/fetch", web::post().to(fetch))
            .route("/tls", web::post().to(tls))
            .route("/stores", web::get().to(stores))
            .route("/validate", web::post().to(validate)),
    )
    .route("/stores/{id}/{artifact}", web::get().to(store_artifact));
}

/// Reports that the service is up, for a load balancer or a deployment check.
async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({ "status": "ok" }))
}

/// Retrieves one artifact on a client's behalf.
///
/// The response carries whatever the repository said, including a status this service would
/// consider a failure, because the client is the one that knows what a 404 on a given URI means.
/// Only a refusal to make the request at all, or a failure to complete it, becomes an error here.
async fn fetch(
    state: web::Data<ServiceState>,
    body: web::Json<FetchRequestBody>,
) -> impl Responder {
    let body = body.into_inner();
    let request = FetchRequest {
        uri: body.uri,
        method: body.method,
        body: body.body,
        content_type: body.content_type,
        if_modified_since: body.if_modified_since,
        max_response_bytes: None,
        timeout: None,
    };

    match state.relay.fetch(&request).await {
        Ok(response) => HttpResponse::Ok().json(FetchResponseBody {
            status: response.status,
            content_type: response.content_type,
            last_modified: response.last_modified,
            final_uri: response.final_uri,
            body: response.body,
        }),
        Err(e) => fetch_error_response(e),
    }
}

/// Takes the certificates a host presents, so a client that cannot open a socket can validate the
/// certificate a site serves.
///
/// Nothing is requested over the connection and nothing is parsed here: the handshake completes,
/// what the peer sent is returned, and judging it is the client's job.
async fn tls(state: web::Data<ServiceState>, body: web::Json<PeekRequestBody>) -> impl Responder {
    if !state.config.allow_tls_peek {
        return HttpResponse::NotFound().json(ErrorBody::new(
            "this deployment does not make handshakes on a client's behalf",
        ));
    }

    let body = body.into_inner();
    let request = PeekRequest {
        uri: body.normalized_uri(),
        timeout: None,
    };

    match state.relay.peek(&request).await {
        Ok(response) => HttpResponse::Ok().json(PeekResponseBody {
            host: response.host,
            port: response.port,
            protocol: response.protocol,
            certificates: response.certificates,
            stapled_ocsp: response.stapled_ocsp,
        }),
        Err(e) => fetch_error_response(e),
    }
}

/// Maps a retrieval failure onto a status that says whose problem it is: a refusal is the
/// requester's, a failure reaching the repository is the repository's, and a client cannot tell
/// those apart from the message alone.
fn fetch_error_response(error: FetchError) -> HttpResponse {
    match error {
        FetchError::Policy(_) => HttpResponse::BadRequest().json(ErrorBody::new(error.to_string())),
        FetchError::RequestTooLarge(_) => {
            HttpResponse::PayloadTooLarge().json(ErrorBody::new(error.to_string()))
        }
        FetchError::Timeout(_) => {
            HttpResponse::GatewayTimeout().json(ErrorBody::new(error.to_string()))
        }
        FetchError::TooLarge(_) | FetchError::Transport(_) => {
            HttpResponse::BadGateway().json(ErrorBody::new(error.to_string()))
        }
        FetchError::Setup(_) => {
            warn!("Relay could not be used: {error}");
            HttpResponse::InternalServerError().json(ErrorBody::new(error.to_string()))
        }
    }
}

/// Lists the stores the service holds, in the shape the browser application's selector consumes.
async fn stores(state: web::Data<ServiceState>) -> impl Responder {
    HttpResponse::Ok().json(state.stores.listing())
}

/// Serves one half of a store. The artifact is named rather than derived from the identifier so
/// the two URIs in a descriptor are literal, and so nothing in a request reaches the filesystem.
async fn store_artifact(
    req: HttpRequest,
    state: web::Data<ServiceState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    let (id, artifact) = path.into_inner();
    let store = match state.stores.get(&id) {
        Some(s) => s,
        None => {
            return HttpResponse::NotFound().json(ErrorBody::new(format!("no such store: {id}")))
        }
    };
    // An anchors-only store has no CA half to serve, and says so rather than answering with an
    // empty body -- the listing offers no URI for it, so asking for one is a mistake worth
    // reporting rather than a store that happens to hold no intermediates.
    if artifact == "ca.cbor" && store.ca_cbor.is_empty() {
        return HttpResponse::NotFound()
            .json(ErrorBody::new(format!("{id} carries trust anchors only")));
    }
    let (bytes, etag) = match store.artifact(&artifact) {
        Some(pair) => pair,
        None => {
            return HttpResponse::NotFound()
                .json(ErrorBody::new(format!("no such artifact: {artifact}")))
        }
    };

    // A store is fixed for the life of the process, so an entity tag settles whether the client
    // already has it without sending it again. Measured on the deployment before this landed: 44
    // store requests over a month moved 19.7 MB and not one was a 304, because the response carried
    // no validator to ask about -- the same material served as a static file revalidated normally.
    // The static-file middleware deliberately skips /stores/, leaving the header to this handler.
    if client_holds(&req, etag) {
        return HttpResponse::NotModified()
            .insert_header((header::ETAG, quoted(etag)))
            .insert_header((header::CACHE_CONTROL, CACHE_CONTROL_REVALIDATE))
            .finish();
    }
    HttpResponse::Ok()
        .content_type("application/cbor")
        .insert_header((header::ETAG, quoted(etag)))
        .insert_header((header::CACHE_CONTROL, CACHE_CONTROL_REVALIDATE))
        // Cheap: the halves are `Bytes`, so this is a reference count rather than a copy of the
        // several megabytes a CA store can run to.
        .body(bytes.clone())
}

/// An entity tag as it goes on the wire, in the double quotes RFC 9110 §8.8.3 requires.
fn quoted(etag: &str) -> String {
    format!("\"{etag}\"")
}

/// Whether the client's `If-None-Match` says it already holds this version.
///
/// Compared by RFC 9110 §13.1.2's weak rules: `*` matches whatever is there, and a `W/` prefix is
/// ignored, since a weak match is exactly the question being asked -- may this client keep using
/// the copy it has. A header that is absent, unreadable, or names something else is simply not a
/// match, so the artifact is sent; the failure direction is a redundant download, never a stale
/// trust store.
fn client_holds(req: &HttpRequest, etag: &str) -> bool {
    let Some(value) = req.headers().get(header::IF_NONE_MATCH) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    value.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*" || candidate.trim_start_matches("W/").trim_matches('"') == etag
    })
}

/// Validates the certificates in the request.
async fn validate(
    state: web::Data<ServiceState>,
    body: web::Json<ValidateRequestBody>,
) -> impl Responder {
    if !state.config.enable_validation {
        return HttpResponse::NotFound().json(ErrorBody::new(
            "this deployment does not accept certificates for validation",
        ));
    }

    let body = body.into_inner();
    let input = ValidationInput {
        targets: body.targets.into_iter().map(|c| (c.name, c.der)).collect(),
        trust_anchors: body
            .trust_anchors
            .into_iter()
            .map(|c| (c.name, c.der))
            .collect(),
        cas: body.cas.into_iter().map(|c| (c.name, c.der)).collect(),
        store_id: body.store_id,
        settings: crate::settings::with_defaults(body.settings),
        validate_all: body.validate_all,
    };

    let outcome = orchestrate::validate(&state, input).await;
    // A report describing a run that could not be carried out is a bad request rather than a
    // failure of the service: it says the caller sent something the service would not act on.
    let mut response = match outcome.report.error.is_some() {
        true => HttpResponse::BadRequest(),
        false => HttpResponse::Ok(),
    };
    response.json(ValidateResponseBody {
        report: outcome.report,
        notes: outcome.notes,
    })
}

#[cfg(test)]
mod store_artifact_tests {
    use super::*;
    use crate::config::ServiceConfig;
    use actix_web::{http::StatusCode, test, App};
    use std::fs;

    /// A service holding one two-half store and one anchors-only store, and nothing built in.
    fn service_state() -> (web::Data<ServiceState>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("demo_ta.cbor"), b"anchors").unwrap();
        fs::write(dir.path().join("demo_ca.cbor"), b"intermediates").unwrap();
        fs::write(dir.path().join("anchors_only.ta.cbor"), b"anchors").unwrap();
        let config = ServiceConfig {
            builtin_stores: false,
            stores_dir: Some(dir.path().to_path_buf()),
            ..ServiceConfig::default()
        };
        // The directory is handed back because the catalog reads from it and a dropped TempDir
        // takes the files with it.
        (web::Data::new(ServiceState::new(config).unwrap()), dir)
    }

    /// Fetches one artifact, optionally saying what the client already holds.
    async fn get(path: &str, if_none_match: Option<&str>) -> (StatusCode, Option<String>, Vec<u8>) {
        let (state, _dir) = service_state();
        let app = test::init_service(App::new().app_data(state).configure(configure)).await;
        let mut req = test::TestRequest::get().uri(path);
        if let Some(value) = if_none_match {
            req = req.insert_header((header::IF_NONE_MATCH, value));
        }
        let response = test::call_service(&app, req.to_request()).await;
        let status = response.status();
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let cache = response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        if status == StatusCode::OK || status == StatusCode::NOT_MODIFIED {
            assert_eq!(
                cache.as_deref(),
                Some(CACHE_CONTROL_REVALIDATE),
                "a served artifact must say how it may be cached"
            );
        }
        (status, etag, test::read_body(response).await.to_vec())
    }

    #[actix_web::test]
    async fn a_store_is_served_with_an_entity_tag() {
        let (status, etag, body) = get("/stores/demo/ta.cbor", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"anchors");
        let etag = etag.expect("no ETag, so a client has nothing to revalidate against");
        assert!(
            etag.starts_with('"') && etag.ends_with('"'),
            "{etag} unquoted"
        );
        assert_eq!(
            etag.trim_matches('"').len(),
            64,
            "expected a SHA-256 in hex"
        );
    }

    /// The point of the change: the second selection of a store costs a comparison, not a download.
    #[actix_web::test]
    async fn a_client_that_already_holds_the_store_is_not_sent_it_again() {
        let (_, etag, _) = get("/stores/demo/ca.cbor", None).await;
        let etag = etag.unwrap();
        let (status, returned, body) = get("/stores/demo/ca.cbor", Some(&etag)).await;
        assert_eq!(status, StatusCode::NOT_MODIFIED);
        assert!(body.is_empty(), "a 304 must not carry the artifact");
        assert_eq!(returned.as_deref(), Some(etag.as_str()));
    }

    /// A weak validator and a wildcard are both a match: the question is whether the copy the
    /// client has is still usable, which is exactly what a weak comparison answers.
    #[actix_web::test]
    async fn weak_and_wildcard_validators_match() {
        let (_, etag, _) = get("/stores/demo/ta.cbor", None).await;
        let weak = format!("W/{}", etag.unwrap());
        for value in [weak.as_str(), "*"] {
            let (status, _, body) = get("/stores/demo/ta.cbor", Some(value)).await;
            assert_eq!(status, StatusCode::NOT_MODIFIED, "{value} should match");
            assert!(body.is_empty());
        }
    }

    /// Failing towards a redundant download rather than towards a stale trust store.
    #[actix_web::test]
    async fn an_unrecognized_validator_gets_the_store() {
        for value in ["\"0000\"", "not a tag", ""] {
            let (status, _, body) = get("/stores/demo/ta.cbor", Some(value)).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{value} must not be taken as a match"
            );
            assert_eq!(body, b"anchors");
        }
    }

    /// The tag is per artifact, not per store. Were the two halves to share one, a client holding
    /// the anchors would be told its CA store was current and would validate against the wrong one.
    #[actix_web::test]
    async fn the_two_halves_of_a_store_carry_different_tags() {
        let (_, ta, _) = get("/stores/demo/ta.cbor", None).await;
        let (_, ca, _) = get("/stores/demo/ca.cbor", None).await;
        assert_ne!(ta, ca);
        let (status, _, _) = get("/stores/demo/ca.cbor", Some(&ta.unwrap())).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the anchors' tag must not match the CA half"
        );
    }

    /// Conditional handling did not cost the refusals their distinct answers.
    #[actix_web::test]
    async fn the_existing_refusals_are_unchanged() {
        for (path, expected) in [
            ("/stores/nope/ta.cbor", "no such store"),
            ("/stores/demo/nope.cbor", "no such artifact"),
            ("/stores/anchors_only/ca.cbor", "carries trust anchors only"),
        ] {
            let (status, _, body) = get(path, None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            let body = String::from_utf8(body).unwrap();
            assert!(body.contains(expected), "{path} said {body}");
        }
    }
}
