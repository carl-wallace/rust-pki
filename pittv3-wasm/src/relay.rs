//! Retrieval through the service's relay, and the tier that decides whether any of it happens.
//!
//! A browser cannot reach a PKI repository itself: it has no sockets, and a cross-origin read of a
//! CRL or an OCSP responder is refused by the same-origin policy no matter how the request is
//! framed. The service that serves this application will make those requests on its behalf
//! (`POST api/fetch`), under the network policy and budgets that live there.
//!
//! What that buys is the asynchronous middle of a retrieving run. The harvesting and folding either
//! side of it are synchronous and shared with every other frontend — see
//! [`pittv3_gui_lib::retrieval`] — so a certificate validated here and the same certificate
//! validated on the server go through the same code and cannot disagree.
//!
//! Nothing here decides *whether* to retrieve. That is [`Tier`], which follows the deployment by
//! default and the user whenever they say otherwise.

use pittv3_gui_lib::retrieval::{
    certificates_in, harvest_chase_uris, MemoryCrlSource, OcspRequestItem, OcspResponses,
};
use pittv3_gui_lib::validate::ResultLine;
use pittv3_lib::uri_check::{FetchOutcome, UriFetcher};
use web_time::Instant;
// Only the browser build exchanges anything with the relay; the host build has no relay to reach,
// so the wire types and their derives are compiled only there.
#[cfg(target_family = "wasm")]
use serde::{Deserialize, Serialize};

/// How much retrieval one Validate click may do.
///
/// A certificate naming a subject information access URI that serves a bundle of further
/// certificates, each naming more, turns one click into an unbounded amount of fetching. The
/// service enforces its own budgets and would stop it eventually; this stops it here, where the
/// person waiting for the answer is.
const MAX_FETCHES: usize = 40;

/// Total retrieved bytes one Validate click may accept.
const MAX_BYTES: usize = 16 * 1024 * 1024;

/// How many times the chase may harvest, retrieve and re-harvest before giving up. Each round can
/// only reach one certificate further from the target, so a small number covers real hierarchies;
/// the loop usually stops earlier by finding nothing new.
const MAX_ROUNDS: usize = 4;

/// Where the relay lives, relative to this application, which the service serves from its own root.
/// Only the browser build calls it; the host build has no relay to reach.
#[cfg(target_family = "wasm")]
const FETCH_URL: &str = "api/fetch";

/// Where the service takes a host's certificates, relative to this application.
#[cfg(target_family = "wasm")]
const TLS_URL: &str = "api/tls";

/// Which of PITTv3's tiers a run uses, i.e., what the browser is permitted to do about material it
/// does not hold.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Tier {
    /// Everything happens in the page. Nothing is retrieved, so a path can only be built from the
    /// selected store and what has been uploaded, and revocation status can only come from
    /// revocation data supplied the same way. This is what this application has always done, and
    /// it is the only tier available when no service is serving it.
    ///
    /// It is this enum's default because it is the only tier that is always correct: a run has to
    /// have somewhere to start before the health request has said whether a relay exists. Which
    /// tier a *served* application settles on is a separate question, answered in `main.rs` when
    /// that request comes back, and the answer there is [`Tier::Relayed`].
    #[default]
    Local,
    /// Path building and revocation checking may retrieve, through the service's relay. The
    /// certificates being validated stay in the page; the URIs they name do not.
    ///
    /// The default wherever a service answers `api/health`: a deployment that runs one is a
    /// deployment that means to retrieve, and the alternative is a first run that reports missing
    /// issuers and undetermined revocation status for want of a switch nobody was told to flip.
    Relayed,
}

impl Tier {
    /// Name for the selector.
    pub fn label(&self) -> &'static str {
        match self {
            Tier::Local => "In this browser only",
            Tier::Relayed => "Retrieve through the service",
        }
    }

    /// What choosing this tier means for what leaves the page, which is the part worth stating
    /// plainly rather than leaving to be inferred from a label.
    pub fn hint(&self) -> &'static str {
        match self {
            Tier::Local => {
                "Nothing leaves this page. Paths are built from the selected store and your uploads, \
                 and revocation status is reported as undetermined unless the data is already at hand."
            }
            Tier::Relayed => {
                "The service retrieves on this page's behalf, so it sees the URIs the certificates \
                 name and, for OCSP, a request identifying the certificate being checked. The \
                 certificates themselves stay in this page."
            }
        }
    }

    /// Whether this tier can retrieve, which is the whole of what it changes about a run.
    pub fn retrieves(&self) -> bool {
        matches!(self, Tier::Relayed)
    }
}

/// What one Validate click has left to spend on retrieval.
pub struct FetchBudget {
    fetches: usize,
    bytes: usize,
}

impl Default for FetchBudget {
    fn default() -> Self {
        FetchBudget {
            fetches: MAX_FETCHES,
            bytes: MAX_BYTES,
        }
    }
}

impl FetchBudget {
    /// Returns a fresh budget for a run.
    pub fn new() -> Self {
        FetchBudget::default()
    }

    /// Reports whether another retrieval is permitted.
    fn available(&self) -> bool {
        self.fetches > 0 && self.bytes > 0
    }

    /// Records a completed retrieval.
    fn spend(&mut self, bytes: usize) {
        self.fetches = self.fetches.saturating_sub(1);
        self.bytes = self.bytes.saturating_sub(bytes);
    }
}

/// A relay request. A CRL or a certificate is a bare `GET`, so those fields are omitted and the
/// service applies its own defaults; an OCSP request is a `POST` carrying the DER request and the
/// content type a responder expects.
#[cfg(target_family = "wasm")]
#[derive(Serialize)]
struct FetchRequestBody<'a> {
    uri: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<&'a str>,
}

/// What the relay retrieved. The body is base64 because the exchange is JSON.
#[cfg(target_family = "wasm")]
#[derive(Deserialize)]
struct FetchResponseBody {
    status: u16,
    #[serde(default)]
    final_uri: String,
    body: String,
}

/// What a host presented during a handshake the service made on this page's behalf.
///
/// A browser cannot obtain this for itself: it holds the certificate of every site it talks to and
/// exposes none of them, and it cannot open a socket to ask. So the certificate someone actually
/// wants to look at — the one their bank, or their agency, or a host that just started failing
/// serves — is the one certificate this application could not be given, until the service made the
/// handshake instead.
pub struct Presented {
    /// Host the handshake was made with.
    pub host: String,
    /// Port connected to.
    pub port: u16,
    /// Protocol version negotiated, when the service reported one.
    pub protocol: Option<String>,
    /// Certificates the host sent, in the order it sent them.
    pub certificates: Vec<Vec<u8>>,
    /// OCSP response the host stapled, if it stapled one.
    pub stapled_ocsp: Option<Vec<u8>>,
}

/// The wire form of what the service answers with. Separate from [`Presented`] because the bytes
/// travel as base64 and nothing above this module should have to know that.
#[cfg(target_family = "wasm")]
#[derive(Deserialize)]
struct PeekResponseBody {
    host: String,
    port: u16,
    #[serde(default)]
    protocol: Option<String>,
    certificates: Vec<String>,
    #[serde(default)]
    stapled_ocsp: Option<String>,
}

/// The request, which is the address bar contents of the site being asked about. The service
/// supplies the scheme when there is none.
#[cfg(target_family = "wasm")]
#[derive(Serialize)]
struct PeekRequestBody<'a> {
    uri: &'a str,
}

/// Asks the service what certificates `uri` presents.
#[cfg(target_family = "wasm")]
pub async fn relay_peek(uri: &str) -> Result<Presented, String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let request = serde_json::to_string(&PeekRequestBody { uri })
        .map_err(|e| format!("could not encode the request: {e}"))?;
    let response = gloo_net::http::Request::post(TLS_URL)
        .header("Content-Type", "application/json")
        .body(request)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let bytes = response.binary().await.map_err(|e| e.to_string())?;
    // As with a retrieval, a refusal carries the rule it ran into, and that message is the whole
    // value of the answer -- "refused by policy: port not permitted: 8443" is actionable in a way
    // that a status code is not.
    if !response.ok() {
        let message = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str().map(str::to_string)))
            .unwrap_or_else(|| format!("HTTP {}", response.status()));
        return Err(message);
    }

    let decoded: PeekResponseBody =
        serde_json::from_slice(&bytes).map_err(|e| format!("unexpected answer: {e}"))?;
    let mut certificates = vec![];
    for encoded in &decoded.certificates {
        let der = STANDARD
            .decode(encoded.as_bytes())
            .map_err(|e| format!("a certificate was not valid base64: {e}"))?;
        certificates.push(der);
    }
    let stapled_ocsp = match &decoded.stapled_ocsp {
        Some(encoded) => Some(
            STANDARD
                .decode(encoded.as_bytes())
                .map_err(|e| format!("the stapled response was not valid base64: {e}"))?,
        ),
        None => None,
    };
    Ok(Presented {
        host: decoded.host,
        port: decoded.port,
        protocol: decoded.protocol,
        certificates,
        stapled_ocsp,
    })
}

/// Host builds have no service to ask, the same as every other exchange in this module.
#[cfg(not(target_family = "wasm"))]
pub async fn relay_peek(_uri: &str) -> Result<Presented, String> {
    Err("retrieval is only available in the browser build".to_string())
}

/// One retrieval's outcome.
pub struct Retrieved {
    /// Status the repository answered with, reported rather than translated: a 404 on an authority
    /// information access URI says the certificate is wrong, which is not the relay's failure.
    pub status: u16,
    /// URI the answer came from, which differs from the request when a redirect was followed.
    pub final_uri: String,
    /// Retrieved bytes.
    pub body: Vec<u8>,
}

/// Retrieves one URI through the relay.
pub async fn relay_fetch(uri: &str) -> Result<Retrieved, String> {
    relay_request(uri, None).await
}

/// Sends one OCSP request through the relay and returns what the responder answered.
pub async fn relay_ocsp(uri: &str, request: &[u8]) -> Result<Retrieved, String> {
    relay_request(uri, Some(request)).await
}

/// Makes one relay request: a `GET` when there is no body, a `POST` of an OCSP request when there
/// is. Everything else about the exchange is the same, which is why they share this.
#[cfg(target_family = "wasm")]
async fn relay_request(uri: &str, ocsp_request: Option<&[u8]>) -> Result<Retrieved, String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let body = FetchRequestBody {
        uri,
        method: ocsp_request.map(|_| "POST"),
        body: ocsp_request.map(|r| STANDARD.encode(r)),
        content_type: ocsp_request.map(|_| "application/ocsp-request"),
    };
    let request =
        serde_json::to_string(&body).map_err(|e| format!("could not encode the request: {e}"))?;
    let response = gloo_net::http::Request::post(FETCH_URL)
        .header("Content-Type", "application/json")
        .body(request)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let bytes = response.binary().await.map_err(|e| e.to_string())?;
    // A refusal carries a JSON error body rather than a retrieval, and the message in it is the
    // useful part -- it says which rule the URI ran into.
    if !response.ok() {
        let message = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str().map(str::to_string)))
            .unwrap_or_else(|| format!("HTTP {}", response.status()));
        return Err(message);
    }

    let decoded: FetchResponseBody =
        serde_json::from_slice(&bytes).map_err(|e| format!("unexpected relay answer: {e}"))?;
    let body = STANDARD
        .decode(decoded.body.as_bytes())
        .map_err(|e| format!("relay answer was not valid base64: {e}"))?;
    Ok(Retrieved {
        status: decoded.status,
        final_uri: decoded.final_uri,
        body,
    })
}

/// Host builds (`cargo check`/`cargo test`) do not run in a browser and have no relay to call; the
/// application itself only ever executes as wasm.
#[cfg(not(target_family = "wasm"))]
async fn relay_request(_uri: &str, _ocsp_request: Option<&[u8]>) -> Result<Retrieved, String> {
    Err("retrieval is only available in the browser build".to_string())
}

fn info(text: String) -> ResultLine {
    ResultLine {
        class: "info",
        text,
    }
}

fn err(text: String) -> ResultLine {
    ResultLine { class: "err", text }
}

/// A note when the artifact came from somewhere other than the URI the certificate named. Worth
/// reporting rather than absorbing: a repository that redirects is a fact about that PKI, and it is
/// the redirected-to host the relay's policy actually judged.
fn redirect_note(requested: &str, response: &Retrieved) -> Option<ResultLine> {
    if response.final_uri.is_empty() || response.final_uri == requested {
        return None;
    }
    // A bare authority redirecting to itself with a path of "/" is the same resource, and saying so
    // is noise: an OCSP responder named without a path does this on every request, which buried the
    // two notes that mattered under four that did not. Anything else -- a different host, a
    // different path, a different scheme -- is still reported, because that is the fact about the
    // PKI worth knowing and it is the redirected-to host the policy actually judged.
    if response.final_uri.trim_end_matches('/') == requested.trim_end_matches('/') {
        return None;
    }
    Some(info(format!(
        "{requested} redirected to {}",
        response.final_uri
    )))
}

/// Chases the authority and subject information access URIs named by `seeds` and whatever they
/// lead to, returning the certificates retrieved and what the attempt has to say about itself.
///
/// The loop is: harvest URIs from everything in hand, retrieve each one not already retrieved, fold
/// the certificates in, harvest again. It stops when a round adds nothing new — a round that
/// retrieved only certificates already held cannot produce a URI the next round has not seen — or
/// when the budget or the round limit is reached.
///
/// A URI that fails is a note and not an error: one broken distribution point should not decide the
/// outcome of a run that other URIs may yet complete.
pub async fn chase_certificates(
    seeds: &[(String, Vec<u8>)],
    budget: &mut FetchBudget,
) -> (Vec<(String, Vec<u8>)>, Vec<ResultLine>) {
    let mut notes = vec![];
    let mut found: Vec<(String, Vec<u8>)> = vec![];
    let mut retrieved: Vec<String> = vec![];

    for _round in 0..MAX_ROUNDS {
        let mut pool = seeds.to_vec();
        pool.extend(found.iter().cloned());
        let uris: Vec<String> = harvest_chase_uris(&pool)
            .into_iter()
            .filter(|u| !retrieved.contains(u))
            .collect();
        if uris.is_empty() {
            break;
        }

        let before = found.len();
        for uri in uris {
            if !budget.available() {
                notes.push(err(
                    "Stopped retrieving certificates: this run's retrieval budget is spent"
                        .to_string(),
                ));
                return (found, notes);
            }
            retrieved.push(uri.clone());

            match relay_fetch(&uri).await {
                Ok(response) => {
                    budget.spend(response.body.len());
                    notes.extend(redirect_note(&uri, &response));
                    if response.status != 200 {
                        notes.push(err(format!(
                            "{uri} answered with status {}",
                            response.status
                        )));
                        continue;
                    }
                    let certs = certificates_in(&response.body);
                    if certs.is_empty() {
                        notes.push(err(format!("{uri} served no certificate")));
                        continue;
                    }
                    for (index, der) in certs.into_iter().enumerate() {
                        let known = seeds.iter().chain(found.iter()).any(|(_, b)| *b == der);
                        if !known {
                            found.push((format!("{uri}#{index}"), der));
                        }
                    }
                }
                Err(e) => {
                    budget.spend(0);
                    notes.push(err(format!("Could not retrieve {uri}: {e}")));
                }
            }
        }

        if found.len() == before {
            break;
        }
    }

    if !found.is_empty() {
        notes.push(info(format!(
            "Retrieved {} certificate(s) by following AIA and SIA URIs",
            found.len()
        )));
    }
    (found, notes)
}

/// Retrieves each CRL distribution point in `uris` into `sink`, returning how many CRLs it holds as
/// a result.
///
/// The sink is shared with the prepared environment, so a CRL added here is consulted by the next
/// validation without anything being rebuilt.
pub async fn retrieve_crls(
    uris: &[String],
    sink: &MemoryCrlSource,
    budget: &mut FetchBudget,
) -> (usize, Vec<ResultLine>) {
    let mut notes = vec![];
    let mut added = 0;

    for uri in uris {
        if !budget.available() {
            notes.push(err(
                "Stopped retrieving CRLs: this run's retrieval budget is spent".to_string(),
            ));
            break;
        }
        match relay_fetch(uri).await {
            Ok(response) => {
                budget.spend(response.body.len());
                notes.extend(redirect_note(uri, &response));
                if response.status != 200 {
                    notes.push(err(format!(
                        "{uri} answered with status {}",
                        response.status
                    )));
                    continue;
                }
                match sink.add(&response.body) {
                    true => added += 1,
                    false => notes.push(err(format!("{uri} did not serve a CRL"))),
                }
            }
            Err(e) => {
                budget.spend(0);
                notes.push(err(format!("Could not retrieve {uri}: {e}")));
            }
        }
    }

    if added > 0 {
        notes.push(info(format!("Retrieved {added} CRL(s)")));
    }
    (added, notes)
}

/// Sends each OCSP request in `items` and puts what comes back into `sink`, returning how many
/// responses were obtained.
///
/// An item whose answer is already held is skipped. That is what makes a certificate naming several
/// responders cost one request rather than several: the first that answers settles it, and the rest
/// are failover that never has to happen.
///
/// The bytes are stored without being examined. Whether a response actually answers the question is
/// for certval's `process_ocsp_response` to decide during validation, with the path and the settings
/// in hand — deciding it here would be a second, weaker implementation of the same judgment.
pub async fn retrieve_ocsp(
    items: &[OcspRequestItem],
    sink: &OcspResponses,
    budget: &mut FetchBudget,
) -> (usize, Vec<ResultLine>) {
    let mut notes = vec![];
    let mut added = 0;

    for item in items {
        if sink.contains(&item.key) {
            continue;
        }
        if !budget.available() {
            notes.push(err(
                "Stopped sending OCSP requests: this run's retrieval budget is spent".to_string(),
            ));
            break;
        }
        match relay_ocsp(&item.uri, &item.request).await {
            Ok(response) => {
                budget.spend(response.body.len());
                notes.extend(redirect_note(&item.uri, &response));
                if response.status != 200 {
                    notes.push(err(format!(
                        "{} answered with status {}",
                        item.uri, response.status
                    )));
                    continue;
                }
                sink.insert(item.key.clone(), response.body);
                added += 1;
            }
            Err(e) => {
                budget.spend(0);
                notes.push(err(format!("Could not reach {}: {e}", item.uri)));
            }
        }
    }

    if added > 0 {
        notes.push(info(format!("Retrieved {added} OCSP response(s)")));
    }
    (added, notes)
}

/// The [`UriFetcher`] the browser uses: every retrieval goes through the relay.
///
/// This is the whole of what the URI checker needed from a browser. The relay already moves exactly
/// these two shapes for revocation retrieval -- a bare `GET` for a certificate bundle or a CRL, and
/// a `POST` of a DER OCSP request -- so the checker reaches repositories a page cannot reach itself
/// without the service growing an endpoint for it.
///
/// A budget is held here rather than by the checker because it is the retrieving that has to be
/// bounded: a certificate naming a subject information access URI that serves a bundle naming more
/// turns one check into an unbounded amount of fetching. Exhaustion reports each further URI as
/// unavailable rather than erroring, which is how the results grid already renders a repository that
/// could not be reached.
pub struct RelayFetcher {
    budget: core::cell::RefCell<FetchBudget>,
}

impl RelayFetcher {
    /// A fetcher with a budget of its own for one check.
    pub fn new() -> Self {
        RelayFetcher {
            budget: core::cell::RefCell::new(FetchBudget::new()),
        }
    }

    /// Records a retrieval and reports whether it was permitted to happen at all.
    fn afford(&self, bytes: usize) -> bool {
        let mut budget = self.budget.borrow_mut();
        let allowed = budget.available();
        budget.spend(bytes);
        allowed
    }
}

impl Default for RelayFetcher {
    fn default() -> Self {
        RelayFetcher::new()
    }
}

impl UriFetcher for RelayFetcher {
    async fn get(&self, uri: &str) -> FetchOutcome {
        if !self.afford(0) {
            return FetchOutcome::default();
        }
        let start = Instant::now();
        let outcome = relay_fetch(uri).await;
        let elapsed_ms = start.elapsed().as_millis() as u64;
        match outcome {
            // The status is reported by the checker, not translated here: a 404 on an authority
            // information access URI is a fact about the certificate, and the grid says so.
            Ok(r) if r.status == 200 => {
                self.afford(r.body.len());
                FetchOutcome {
                    ok: true,
                    body: r.body,
                    elapsed_ms,
                }
            }
            Ok(_) | Err(_) => FetchOutcome {
                elapsed_ms,
                ..Default::default()
            },
        }
    }

    async fn post_ocsp(&self, uri: &str, request: &[u8]) -> FetchOutcome {
        if !self.afford(request.len()) {
            return FetchOutcome::default();
        }
        let start = Instant::now();
        let outcome = relay_ocsp(uri, request).await;
        let elapsed_ms = start.elapsed().as_millis() as u64;
        match outcome {
            Ok(r) if r.status == 200 => {
                self.afford(r.body.len());
                FetchOutcome {
                    ok: true,
                    body: r.body,
                    elapsed_ms,
                }
            }
            Ok(_) | Err(_) => FetchOutcome {
                elapsed_ms,
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_budget_stops_at_its_limits() {
        let mut budget = FetchBudget::new();
        assert!(budget.available());
        budget.spend(MAX_BYTES);
        assert!(!budget.available(), "a spent byte budget stops retrieval");

        let mut budget = FetchBudget::new();
        for _ in 0..MAX_FETCHES {
            assert!(budget.available());
            budget.spend(1);
        }
        assert!(!budget.available(), "a spent fetch budget stops retrieval");
    }

    /// The tier is what a person reads before deciding, so each arm has to say something different
    /// about what leaves the page -- and the local one has to promise nothing does.
    #[test]
    fn each_tier_states_what_leaves_the_page() {
        assert!(!Tier::default().retrieves());
        assert!(Tier::Relayed.retrieves());
        assert!(Tier::Local.hint().contains("Nothing leaves this page"));
        assert_ne!(Tier::Local.hint(), Tier::Relayed.hint());
    }
}
