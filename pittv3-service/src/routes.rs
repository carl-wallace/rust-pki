//! HTTP surface.
//!
//! The handlers are thin on purpose: they decode a body, call something that knows nothing about
//! HTTP, and encode what comes back. Everything worth testing -- the network policy, the budgets,
//! the settings sanitizer, the validation itself -- is reachable without a running server.

use actix_web::{web, HttpResponse, Responder};
use log::warn;
use serde::Serialize;

use pittv3_relay::{FetchError, FetchRequest, PeekRequest};

use crate::config::ServiceState;
use crate::dto::{
    FetchRequestBody, FetchResponseBody, PeekRequestBody, PeekResponseBody, ValidateRequestBody,
    ValidateResponseBody,
};
use crate::orchestrate::{self, ValidationInput};

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
    let bytes = match artifact.as_str() {
        "ta.cbor" => &store.ta_cbor,
        "ca.cbor" => &store.ca_cbor,
        other => {
            return HttpResponse::NotFound()
                .json(ErrorBody::new(format!("no such artifact: {other}")))
        }
    };
    HttpResponse::Ok()
        .content_type("application/cbor")
        .body(bytes.clone())
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
        settings: body.settings.unwrap_or_default(),
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
