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
    /// A successful response carried a body that is not an encoded ASN.1 artifact in any of the
    /// three encodings a repository publishes, so it is not what was asked for. The opening bytes
    /// are reported, as text where they are printable, because that is what identifies the real
    /// answer: a login page, a JSON error, a CDN block notice.
    ///
    /// See [`looks_like_an_encoded_artifact`] for what this does and does not establish.
    NotAnArtifact(String),
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
            FetchError::NotAnArtifact(opening) => {
                write!(f, "response is not DER, PEM or base64; it begins {opening}")
            }
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

        let max_bytes = narrowed(request.max_response_bytes, self.budget.max_response_bytes);
        let timeout = narrowed(request.timeout, self.budget.timeout);

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
                debug!(
                    "Retrieval of {} failed with {}",
                    request.uri,
                    error_chain(&e)
                );
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

        // Only for a response that claims to have succeeded. A non-2xx status is information the
        // caller wants -- a 404 tells a user the repository moved -- and refusing its HTML body
        // would replace a useful status with a complaint about encoding. An empty body is left
        // alone for the same reason: the status describes it better than this can.
        if (200..300).contains(&status)
            && !body.is_empty()
            && !looks_like_an_encoded_artifact(&body)
        {
            debug!(
                "Discarded the body from {} as no encoded artifact",
                request.uri
            );
            return Err(FetchError::NotAnArtifact(describe_opening(&body)));
        }

        Ok(FetchResponse {
            status,
            content_type,
            last_modified,
            final_uri,
            body,
        })
    }
}

/// The bound applied to one retrieval: what the caller asked for, never more than what the
/// deployment configured.
///
/// A function rather than two inline `match`es so the rule can be tested without a server, which
/// matters now that the value arrives over the wire: a browser carries its own timeout settings in
/// `api/fetch`, so "a client cannot widen a budget by asking for more of it" went from an internal
/// convenience to something a caller could try.
fn narrowed<T: Ord>(requested: Option<T>, configured: T) -> T {
    match requested {
        Some(r) => r.min(configured),
        None => configured,
    }
}

/// Builds the redirect policy. A redirect names a URI the requester did not present and the
/// admission check therefore never saw, so each hop is put through the same URI check; the
/// addresses each hop resolves to are checked by the resolver the client was built with.
///
/// A hop that is refused, and a chain that outruns the limit, are raised as errors rather than
/// stopped. Stopping hands the 3xx back as the response, which leaves the caller reporting a bare
/// "answered with status 302" -- true, and indistinguishable from a repository that really did
/// serve one. Erroring carries the [`PolicyError`] out through [`policy_error_in`], so a refusal
/// reads as a refusal and names the URI that caused it.
fn redirect_policy(policy: Arc<NetworkPolicy>) -> reqwest::redirect::Policy {
    if policy.max_redirects == 0 {
        return reqwest::redirect::Policy::none();
    }
    let max = policy.max_redirects;
    reqwest::redirect::Policy::custom(move |attempt| {
        let url = attempt.url().to_string();
        // The first entry is the URI originally requested rather than a redirection, so it is
        // excluded from the count -- the same arithmetic reqwest's own `Policy::limited` uses,
        // which is what makes this limit comparable to certval's.
        if attempt.previous().len() > max {
            debug!("Refused redirect to {url}: more than {max} hops");
            return attempt.error(PolicyError::Redirect(url));
        }
        match policy.check_uri(&url) {
            Ok(_) => attempt.follow(),
            Err(e) => {
                debug!("Refused redirect to {url}: {e}");
                attempt.error(PolicyError::Redirect(url))
            }
        }
    })
}

/// `e` followed by each error in its source chain. reqwest's own message stops at "error sending
/// request"; the cause -- a failed lookup, a refused connection, a timeout -- is in the chain.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
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
/// Whether a body begins as an encoded ASN.1 artifact, in any of the three encodings a repository
/// publishes: raw DER, PEM, or bare base64 with no armour.
///
/// **This is what keeps the relay from being an open proxy.** Scheme, port and address limits say
/// *where* it may fetch, and nothing says *what* may come back, so without this a caller can
/// retrieve any public content up to the byte cap and the deployment is the fetcher of record.
/// Every artifact a repository publishes is an ASN.1 SEQUENCE in one of these three wrappings, so
/// admitting them and refusing the rest is the narrowest rule that does not have to enumerate the
/// repositories of the world.
///
/// **It is an encoding check, not a content check.** `0x30` is the tag for a constructed SEQUENCE
/// and says nothing about what the structure contains; what a certificate, CRL or OCSP response
/// *means* is certval's business and deliberately not this crate's. Note `0x30` is also ASCII
/// `'0'`, so a body opening with that digit is admitted: this is a cheap prefix filter, not a
/// parser, and its job is to refuse the HTML page rather than to prove the bytes are a certificate.
///
/// Bare base64 is accepted because DoD and FPKI tooling publishes it, and a relay admitting only
/// DER and PEM would silently discard material the rest of the stack reads today
/// (`pittv3_lib::der_or_pem::decode_bare_base64`). It is checked by decoding the first four
/// characters and looking for the SEQUENCE tag, rather than by matching a prefix like `MII`, which
/// would cover only the two-byte-length case and guess at the others.
/// The pre-encapsulation boundary, the same prefix `pittv3_lib::der_or_pem` matches, so the two
/// cannot disagree about whether a buffer is armored. Five hyphens is what RFC 7468 requires and
/// what that decoder accepts; a body with any other count is refused there too, so refusing it
/// here costs nothing.
const ARMOR: &[u8] = b"-----BEGIN";

fn looks_like_an_encoded_artifact(body: &[u8]) -> bool {
    if body.first() == Some(&0x30) {
        return true;
    }
    // Searched within an opening window rather than required at byte zero: RFC 7468 permits text
    // before the encapsulation boundary and tools emit it, so `pittv3_lib::der_or_pem` looks for
    // the armor anywhere in the buffer. Matching only at the front would refuse a body the rest of
    // the stack reads. The window is what keeps that from becoming a hole: a preamble is short,
    // while armor appended to the end of an arbitrary blob is how this check would be evaded.
    const PREAMBLE: usize = 1024;
    let window = &body[..body.len().min(PREAMBLE)];
    if window.windows(ARMOR.len()).any(|w| w == ARMOR) {
        return true;
    }

    // Bare base64 gets the same allowance, for the same reason: the first four characters after
    // any preamble, not the first four characters of the body.
    let after_preamble = match window.windows(ARMOR.len()).position(|w| w == ARMOR) {
        Some(i) => &body[i..],
        None => body,
    };
    let head: Vec<u8> = after_preamble
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'-')
        .take(4)
        .collect();
    if head.len() < 4 {
        return false;
    }
    match core::str::from_utf8(&head) {
        Ok(text) => {
            use base64ct::Encoding as _;
            matches!(base64ct::Base64::decode_vec(text), Ok(d) if d.first() == Some(&0x30))
        }
        Err(_) => false,
    }
}

/// The opening of a body, as the shortest thing that identifies what was really served.
///
/// Printable ASCII is returned as text, because that is the case worth reading: `<!DOCTYPE html`
/// or `{"error"` names the answer immediately. Anything else is reported as hex, since a
/// half-decoded binary prefix tells a reader less than the bytes do.
fn describe_opening(body: &[u8]) -> String {
    const WINDOW: usize = 24;
    let head = &body[..body.len().min(WINDOW)];
    if head.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        format!("{:?}", String::from_utf8_lossy(head))
    } else {
        head.iter().fold(String::new(), |mut acc, b| {
            use core::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }
}

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
                debug!(
                    "Failed to read the body from {uri} with {}",
                    error_chain(&e)
                );
                return Err(FetchError::Transport(e.to_string()));
            }
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule a client reaches from outside: asking for less than the deployment allows is
    /// honoured, asking for more is not, and asking for nothing takes the deployment's own.
    #[test]
    fn a_requested_bound_narrows_a_budget_but_never_widens_one() {
        let configured = Duration::from_secs(10);
        assert_eq!(
            narrowed(Some(Duration::from_secs(3)), configured),
            Duration::from_secs(3)
        );
        assert_eq!(
            narrowed(Some(Duration::from_secs(600)), configured),
            configured
        );
        assert_eq!(narrowed(None, configured), configured);

        // The byte cap is the same rule on the other field, and is asserted here rather than
        // trusted to stay in step by inspection.
        assert_eq!(narrowed(Some(1_024u64), 16 * 1024), 1_024);
        assert_eq!(narrowed(Some(u64::MAX), 16 * 1024), 16 * 1024);
    }

    /// The three encodings a repository publishes, and the things it serves instead when it is
    /// not serving the artifact. This is the rule that keeps the relay from being an open proxy,
    /// so both directions matter: admitting all three, and refusing the rest.
    #[test]
    fn a_body_is_recognized_as_an_encoded_artifact_or_refused() {
        // DER: the tag for a constructed SEQUENCE, which every published artifact is.
        assert!(looks_like_an_encoded_artifact(&[0x30, 0x82, 0x01, 0x0a]));
        // PEM, including the leading whitespace servers introduce and PEM readers tolerate.
        assert!(looks_like_an_encoded_artifact(
            b"-----BEGIN CERTIFICATE-----\nMIIB"
        ));
        assert!(looks_like_an_encoded_artifact(
            b"\r\n  -----BEGIN X509 CRL-----"
        ));

        // Bare base64, which DoD and FPKI tooling publishes. `MII` is the two-byte-length case
        // and `MIG` the one-byte; both decode to the SEQUENCE tag, which is what is checked
        // rather than the prefix.
        assert!(looks_like_an_encoded_artifact(b"MIIBkTCCATegAwIBAgI"));
        assert!(looks_like_an_encoded_artifact(b"MIGfMA0GCSqGSIb3DQ"));
        // And wrapped, as those tools emit it.
        assert!(looks_like_an_encoded_artifact(b"  MIIB\nkTCC\nATeg"));

        // What a repository returns when it is not serving the artifact.
        assert!(!looks_like_an_encoded_artifact(b"<!DOCTYPE html><html>"));
        assert!(!looks_like_an_encoded_artifact(
            b"{\"error\":\"not found\"}"
        ));
        assert!(!looks_like_an_encoded_artifact(b"Not Found"));
        assert!(!looks_like_an_encoded_artifact(b""));
        // Whitespace is skipped for the text encodings and not for DER, where a leading byte is
        // data rather than layout.
        assert!(!looks_like_an_encoded_artifact(&[0x20, 0x30, 0x82]));

        // A preamble before the boundary is permitted by RFC 7468 and emitted by real tools, so
        // it must not cost a repository its artifact. `der_or_pem` finds the armor anywhere.
        assert!(looks_like_an_encoded_artifact(
            b"Subject: CN=Example CA\nIssuer: CN=Example Root\n\n-----BEGIN CERTIFICATE-----\nMIIB"
        ));
        // But only within the opening window: armor appended to a blob is how this would be
        // evaded, and that is the case the bound exists for.
        let mut blob = vec![b'x'; 4096];
        blob.extend_from_slice(b"-----BEGIN CERTIFICATE-----");
        assert!(!looks_like_an_encoded_artifact(&blob));
    }

    /// The opening is reported so a reader learns what was really served. Text stays text, because
    /// `<!DOCTYPE html` names the answer at a glance; anything else is hex, because a half-decoded
    /// binary prefix says less than the bytes.
    #[test]
    fn the_opening_of_a_rejected_body_identifies_it() {
        assert_eq!(
            describe_opening(b"<!DOCTYPE html><html lang=\"en\">"),
            "\"<!DOCTYPE html><html lan\""
        );
        assert_eq!(describe_opening(&[0x00, 0x01, 0xff]), "0001ff");
        // Short bodies are not padded, and the window bounds long ones.
        assert_eq!(describe_opening(b"nope"), "\"nope\"");
        assert_eq!(describe_opening(&[b'a'; 100]).len(), 26);
    }

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
