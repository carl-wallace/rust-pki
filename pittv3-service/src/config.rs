//! Service configuration and the state handlers share.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use pittv3_relay::{ChaseBudgetLimits, FetchBudget, NetworkPolicy, Relay};

use crate::stores::StoreCatalog;

/// Caps applied to a request before any work is scheduled for it.
///
/// These bound the request itself rather than what processing it costs; the retrieval budgets in
/// [`pittv3_relay::budget`] bound that. Both are needed: a small request carrying one certificate
/// with a hostile subject information access extension is cheap to accept and expensive to serve.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct RequestLimits {
    /// Largest JSON body accepted, in bytes.
    pub max_body_bytes: usize,
    /// Most target certificates one validation request may carry.
    pub max_targets: usize,
    /// Most trust anchors one validation request may upload.
    pub max_trust_anchors: usize,
    /// Most CA certificates one validation request may upload.
    pub max_cas: usize,
    /// Largest single DER-encoded certificate accepted, in bytes.
    pub max_certificate_bytes: usize,
}

impl Default for RequestLimits {
    fn default() -> Self {
        RequestLimits {
            max_body_bytes: 8 * 1024 * 1024,
            max_targets: 32,
            max_trust_anchors: 128,
            max_cas: 512,
            // Larger than any certificate has cause to be, while small enough that the per-request
            // ceiling stays governed by the counts above rather than by one enormous upload.
            max_certificate_bytes: 64 * 1024,
        }
    }
}

/// Everything the service needs to run, in a form that can be read from a configuration file as
/// well as assembled from command-line arguments.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ServiceConfig {
    /// Address to listen on.
    pub bind: String,
    /// Directory of static files making up the browser application, i.e., what `trunk build`
    /// produced. Serving it from this origin is what lets the application call the endpoints
    /// without cross-origin arrangements.
    pub client_dir: Option<PathBuf>,
    /// Directory holding trust stores as CBOR pairs, read once at startup and never written to.
    /// See [`StoreCatalog::load`] for the layouts it accepts. What it holds augments the built-in
    /// stores, and replaces one where both name the same store.
    pub stores_dir: Option<PathBuf>,
    /// Offers the stores generated from the trust store providers when the service was built, so a
    /// deployment that configures nothing still has DoD NIPR, the Mozilla set, the U.S. Federal PKI
    /// and the Purebred development environment to validate against. On by default: the flexibility
    /// is in [`stores_dir`](Self::stores_dir), and requiring it before the service can do anything
    /// buys nothing. Turn it off to serve a chosen catalogue and only that. Has no effect on a
    /// build without the `builtin-stores` feature, which carries no such material at all.
    pub builtin_stores: bool,
    /// Rules applied to every URI the service retrieves, whether asked to by a client or led to by
    /// a certificate.
    pub policy: NetworkPolicy,
    /// Bounds on a single retrieval.
    pub fetch_budget: FetchBudget,
    /// Bounds on the retrievals one request may make in total.
    pub chase_budget: ChaseBudgetLimits,
    /// Caps applied to a request as it is accepted.
    pub limits: RequestLimits,
    /// Permits server-side path building that chases authority and subject information access
    /// URIs. Off by default: it turns one uploaded certificate into an unbounded-looking amount of
    /// outbound retrieval, so a deployment opts into it knowingly.
    pub allow_dynamic_build: bool,
    /// Serves `POST /api/validate`. A deployment that wants to offer the relay without accepting
    /// certificates turns this off, which is a meaningful posture rather than a degraded one: the
    /// relayed tier is the one where certificates never leave the browser.
    pub enable_validation: bool,
    /// Retrieves the CRLs named by the paths a validation builds, so revocation status can be
    /// determined rather than reported as undetermined. On by default: a caller that sent
    /// certificates for validation asked for them to be validated, and revocation is part of that.
    /// Unlike chasing, the retrieval is bounded by the paths already built — one distribution point
    /// per certificate on them — and it goes through the relay, so the network policy governs it.
    pub fetch_revocation_data: bool,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        ServiceConfig {
            bind: "127.0.0.1:8080".to_string(),
            client_dir: None,
            stores_dir: None,
            builtin_stores: true,
            policy: NetworkPolicy::default(),
            fetch_budget: FetchBudget::default(),
            chase_budget: ChaseBudgetLimits::default(),
            limits: RequestLimits::default(),
            allow_dynamic_build: false,
            enable_validation: true,
            fetch_revocation_data: true,
        }
    }
}

/// State shared by every handler: the configuration, the relay built from it, and the stores read
/// at startup.
///
/// The relay is built once because it holds a pooled HTTP client; building one per request would
/// pay for a fresh connection and TLS handshake on every retrieval.
#[derive(Debug)]
pub struct ServiceState {
    /// Configuration the service was started with.
    pub config: ServiceConfig,
    /// Relay used for every outbound retrieval.
    pub relay: Relay,
    /// Trust stores the service can validate against and serve.
    pub stores: StoreCatalog,
}

impl ServiceState {
    /// Assembles the shared state, building the relay and the store catalog: the built-in stores
    /// unless they were turned off, then whatever the configured directory holds, which augments
    /// them and replaces any of the same name.
    pub fn new(config: ServiceConfig) -> Result<Self, String> {
        let relay = Relay::new(config.policy.clone(), config.fetch_budget.clone())
            .map_err(|e| e.to_string())?;
        let mut stores = match config.builtin_stores {
            true => StoreCatalog::builtin(),
            false => StoreCatalog::empty(),
        };
        if let Some(dir) = &config.stores_dir {
            stores.merge(
                StoreCatalog::load(dir).map_err(|e| {
                    format!("failed to read trust stores from {}: {e}", dir.display())
                })?,
            );
        }
        Ok(ServiceState {
            config,
            relay,
            stores,
        })
    }
}
