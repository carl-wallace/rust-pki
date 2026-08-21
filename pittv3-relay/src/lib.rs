#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

pub mod budget;
pub mod peek;
pub mod policy;

use std::sync::Arc;
use std::time::Duration;

use log::debug;
use serde::{Deserialize, Serialize};

pub use budget::{BudgetExhausted, ChaseBudget, ChaseBudgetLimits, FetchBudget};
pub use peek::{PeekRequest, PeekResponse};
pub use policy::{is_public_address, CheckedUri, NetworkPolicy, PolicyError, PolicyResolver};

/// Verbs PKI retrieval needs. `GET` covers certificates and CRLs named by authority information
/// access, subject information access and CRL distribution point extensions; `POST` covers OCSP,
/// which is the only case that carries a request body.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FetchMethod {
    /// Retrieve the artifact named by the URI.
    #[default]
    Get,
    /// Send a request body to the URI and read the reply, as OCSP requires.
    Post,
}

/// What a caller wants retrieved.
///
/// The per-request `max_response_bytes` and `timeout` narrow the relay's configured budget; they
/// cannot widen it. A caller running a chase passes the remains of its [`ChaseBudget`] here so the
/// last retrieval in a sequence cannot overshoot the total the sequence was granted.
#[derive(Clone, Debug, Default)]
pub struct FetchRequest {
    /// URI to retrieve.
    pub uri: String,
    /// Verb to use.
    pub method: FetchMethod,
    /// Request body, meaningful only for `POST`.
    pub body: Option<Vec<u8>>,
    /// Value for the `Content-Type` header, e.g., `application/ocsp-request`.
    pub content_type: Option<String>,
    /// Value for the `If-Modified-Since` header, letting a caller that already holds an artifact
    /// learn it is unchanged rather than retrieving it again.
    pub if_modified_since: Option<String>,
    /// Response cap for this retrieval, when smaller than the configured cap.
    pub max_response_bytes: Option<u64>,
    /// Timeout for this retrieval, when shorter than the configured timeout.
    pub timeout: Option<Duration>,
}

impl FetchRequest {
    /// Builds a request that retrieves the artifact at `uri`.
    pub fn get(uri: impl Into<String>) -> Self {
        FetchRequest {
            uri: uri.into(),
            method: FetchMethod::Get,
            ..Default::default()
        }
    }

    /// Builds a request that posts a DER-encoded OCSP request to a responder.
    pub fn ocsp(uri: impl Into<String>, request: Vec<u8>) -> Self {
        FetchRequest {
            uri: uri.into(),
            method: FetchMethod::Post,
            body: Some(request),
            content_type: Some("application/ocsp-request".to_string()),
            ..Default::default()
        }
    }
}

/// What the relay retrieved.
///
/// The status is reported as it arrived rather than being turned into an error, because a caller
/// distinguishes cases the relay cannot: a 404 from an authority information access URI is a broken
/// certificate, a 304 answers a conditional request, and a 503 is worth retrying later. The body is
/// returned as bytes and is not parsed here.
#[derive(Clone, Debug)]
pub struct FetchResponse {
    /// HTTP status code.
    pub status: u16,
    /// Value of the `Content-Type` header, when present.
    pub content_type: Option<String>,
    /// Value of the `Last-Modified` header, which a caller stores to make its next request
    /// conditional.
    pub last_modified: Option<String>,
    /// URI the response came from, which differs from the requested URI when a redirect was
    /// followed.
    pub final_uri: String,
    /// Response body.
    pub body: Vec<u8>,
}

/// Reasons a retrieval did not produce a response.
#[derive(Clone, Debug)]
pub enum FetchError {
    /// The URI, its host's addresses, or a redirect target was refused by the network policy.
    Policy(PolicyError),
    /// The exchange did not complete within the time allowed, which is reported: "timed out" alone
    /// leaves a caller unable to tell a host that is slow from one that never answers, and unable
    /// to tell either from a budget set too low.
    Timeout(Duration),
    /// The response body exceeded the cap, either as claimed by `Content-Length` or as observed
    /// while streaming. The cap that was exceeded is reported.
    TooLarge(u64),
    /// The request body exceeded the cap.
    RequestTooLarge(usize),
    /// The retrieval failed at the transport, e.g., connection refused or a TLS failure.
    Transport(String),
    /// The HTTP client could not be constructed, e.g., the TLS backend failed to initialize.
    Setup(String),
}

impl core::fmt::Display for FetchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FetchError::Policy(e) => write!(f, "refused by policy: {e}"),
            FetchError::Timeout(after) => write!(f, "timed out after {after:?}"),
            FetchError::TooLarge(cap) => write!(f, "response exceeded the {cap}-byte cap"),
            FetchError::RequestTooLarge(cap) => write!(f, "request exceeded the {cap}-byte cap"),
            FetchError::Transport(e) => write!(f, "transport failure: {e}"),
            FetchError::Setup(e) => write!(f, "could not build an HTTP client: {e}"),
        }
    }
}

impl std::error::Error for FetchError {}

impl From<PolicyError> for FetchError {
    fn from(e: PolicyError) -> Self {
        FetchError::Policy(e)
    }
}

/// Retrieves artifacts subject to a [`NetworkPolicy`] and a [`FetchBudget`].
///
/// One relay is built per deployment and shared: it holds a pooled HTTP client, so a chase that
/// makes several requests to one repository pays for connection setup once. The client is
/// configured to resolve names through the policy and to ignore proxy environment variables, since
/// a proxy would carry the connection to an address the policy never approved.
#[derive(Clone, Debug)]
pub struct Relay {
    policy: Arc<NetworkPolicy>,
    budget: FetchBudget,
    client: reqwest::Client,
}

impl Relay {
    /// Builds a relay enforcing `policy` and `budget`.
    pub fn new(policy: NetworkPolicy, budget: FetchBudget) -> Result<Self, FetchError> {
        let policy = Arc::new(policy);
        let redirect = redirect_policy(policy.clone());
        let client = reqwest::Client::builder()
            .dns_resolver(Arc::new(PolicyResolver::new(policy.clone())))
            .redirect(redirect)
            .no_proxy()
            .build()
            .map_err(|e| FetchError::Setup(e.to_string()))?;
        Ok(Relay {
            policy,
            budget,
            client,
        })
    }

    /// Returns the policy in force, so a caller can reject a URI at admission time with the same
    /// rules the retrieval would apply.
    pub fn policy(&self) -> &NetworkPolicy {
        &self.policy
    }

    /// Returns the budget in force.
    pub fn budget(&self) -> &FetchBudget {
        &self.budget
    }

    /// Retrieves one artifact.
    ///
    /// The URI is checked before a socket is opened; its host is resolved by the policy and the
    /// connection is made to the addresses that check approved. The response body is read with the
    /// cap applied as it streams.
    pub async fn fetch(&self, request: &FetchRequest) -> Result<FetchResponse, FetchError> {
        let dest = self.policy.check_uri(&request.uri)?;

        let body = request.body.clone().unwrap_or_default();
        if body.len() > self.budget.max_request_bytes {
            return Err(FetchError::RequestTooLarge(self.budget.max_request_bytes));
        }

        // Per-request values narrow the configured budget and never widen it, so a caller passing
        // what remains of a chase budget cannot buy itself a larger response or a longer wait.
        let max_bytes = match request.max_response_bytes {
            Some(b) => b.min(self.budget.max_response_bytes),
            None => self.budget.max_response_bytes,
        };
        let timeout = match request.timeout {
            Some(t) => t.min(self.budget.timeout),
            None => self.budget.timeout,
        };

        let mut builder = match request.method {
            FetchMethod::Get => self.client.get(dest.url.clone()),
            FetchMethod::Post => self.client.post(dest.url.clone()).body(body),
        };
        builder = builder.timeout(timeout);
        if let Some(content_type) = &request.content_type {
            builder = builder.header(reqwest::header::CONTENT_TYPE, content_type);
        }
        if let Some(since) = &request.if_modified_since {
            builder = builder.header(reqwest::header::IF_MODIFIED_SINCE, since);
        }

        let response = match builder.send().await {
            Ok(r) => r,
            Err(e) if e.is_timeout() => {
                debug!("Retrieval of {} timed out after {timeout:?}", request.uri);
                return Err(FetchError::Timeout(timeout));
            }
            Err(e) => {
                debug!("Retrieval of {} failed with {e}", request.uri);
                // A refusal raised by the resolver arrives here wrapped in the client's connection
                // error; recovering it keeps "we would not go there" distinct from "we went and it
                // failed", which is the difference between a misdirected certificate and a
                // repository that is down.
                return match policy_error_in(&e) {
                    Some(pe) => Err(FetchError::Policy(pe)),
                    None => Err(FetchError::Transport(e.to_string())),
                };
            }
        };

        let status = response.status().as_u16();
        let final_uri = response.url().to_string();
        let content_type = header_string(&response, reqwest::header::CONTENT_TYPE);
        let last_modified = header_string(&response, reqwest::header::LAST_MODIFIED);
        let body = read_capped_body(response, max_bytes, &request.uri, timeout).await?;

        Ok(FetchResponse {
            status,
            content_type,
            last_modified,
            final_uri,
            body,
        })
    }
}

/// Builds the redirect policy. A redirect names a URI the requester did not present and the
/// admission check therefore never saw, so each hop is put through the same URI check; the
/// addresses each hop resolves to are checked by the resolver the client was built with.
fn redirect_policy(policy: Arc<NetworkPolicy>) -> reqwest::redirect::Policy {
    if policy.max_redirects == 0 {
        return reqwest::redirect::Policy::none();
    }
    let max = policy.max_redirects;
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() > max {
            return attempt.stop();
        }
        match policy.check_uri(attempt.url().as_str()) {
            Ok(_) => attempt.follow(),
            Err(e) => {
                debug!("Refused redirect to {}: {e}", attempt.url());
                attempt.stop()
            }
        }
    })
}

/// Recovers a [`PolicyError`] raised while resolving a name from the client error that carries it.
/// The client wraps a resolver failure in its own connection error, so the refusal is found by
/// walking the error's sources rather than by inspecting the outermost error.
fn policy_error_in(error: &reqwest::Error) -> Option<PolicyError> {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(e) = source {
        if let Some(pe) = e.downcast_ref::<PolicyError>() {
            return Some(pe.clone());
        }
        source = e.source();
    }
    None
}

fn header_string(
    response: &reqwest::Response,
    name: reqwest::header::HeaderName,
) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

/// Reads a response body into memory while enforcing `max_bytes` as it streams, so a hostile
/// responder cannot exhaust memory with an unbounded body. Reading the body in one call would
/// allocate it in full before any size check ran, so the cap is applied at ingest.
///
/// `Content-Length` is supplied by the responder and absent on chunked responses, so it serves only
/// as a fast-fail hint; the running count over the streamed chunks is the guard that matters.
async fn read_capped_body(
    mut response: reqwest::Response,
    max_bytes: u64,
    uri: &str,
    timeout: Duration,
) -> Result<Vec<u8>, FetchError> {
    if let Some(len) = response.content_length() {
        if len > max_bytes {
            debug!("{uri} reported a {len}-byte body exceeding the {max_bytes}-byte cap");
            return Err(FetchError::TooLarge(max_bytes));
        }
    }

    let mut buf: Vec<u8> = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len() as u64 + chunk.len() as u64 > max_bytes {
                    debug!("{uri} streamed a body exceeding the {max_bytes}-byte cap");
                    return Err(FetchError::TooLarge(max_bytes));
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) if e.is_timeout() => return Err(FetchError::Timeout(timeout)),
            Err(e) => {
                debug!("Failed to read the body from {uri} with {e}");
                return Err(FetchError::Transport(e.to_string()));
            }
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refuses_a_uri_the_policy_rejects_without_connecting() {
        let relay = Relay::new(NetworkPolicy::default(), FetchBudget::default()).unwrap();

        // An LDAP URI is the case a real certificate produces; the file URI is the case an attacker
        // does. Neither reaches the transport.
        let err = relay
            .fetch(&FetchRequest::get("ldap://directory.example.com/cn=ca"))
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Policy(PolicyError::Scheme(_))));

        let err = relay
            .fetch(&FetchRequest::get("file:///etc/passwd"))
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Policy(PolicyError::Scheme(_))));
    }

    #[tokio::test]
    async fn refuses_a_host_that_resolves_inward() {
        let relay = Relay::new(NetworkPolicy::default(), FetchBudget::default()).unwrap();
        // Nothing listens on port 80 here in most environments, so the assertion is that the
        // refusal is a policy refusal rather than a connection failure.
        let err = relay
            .fetch(&FetchRequest::get("http://localhost/ca.crl"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, FetchError::Policy(_)),
            "expected a policy refusal, got {err}"
        );
    }

    #[tokio::test]
    async fn refuses_an_oversized_request_body() {
        let budget = FetchBudget {
            max_request_bytes: 8,
            ..Default::default()
        };
        let relay = Relay::new(NetworkPolicy::default(), budget).unwrap();
        let err = relay
            .fetch(&FetchRequest::ocsp("http://ocsp.example.com/", vec![0; 9]))
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::RequestTooLarge(8)));
    }
}
