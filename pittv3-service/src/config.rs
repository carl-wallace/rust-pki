//! Service configuration and the state handlers share.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use pittv3_relay::{ChaseBudgetLimits, FetchBudget, NetworkPolicy, Relay};

use crate::limit::RateLimiter;
use crate::stores::StoreCatalog;

/// One period, and what a client may spend within it.
///
/// A zero is unbounded rather than "nothing permitted", so an operator can cap outbound bytes
/// without also capping request count, and writes one number instead of restating the section.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct RateWindow {
    /// Length of the period in seconds. A period of zero would reset on every request and enforce
    /// nothing, so it is replaced by the window's default at startup, with a warning.
    pub seconds: u64,
    /// Calls to the service permitted in the period.
    pub requests: u64,
    /// Retrievals the service may make to third parties on one client's behalf in the period.
    ///
    /// Counted separately from `requests` because the ratio between them is the client's to
    /// choose: `POST /api/fetch` costs exactly one retrieval, while a validation that chases costs
    /// as many as its chase budget allows. Counting only requests would price those the same.
    ///
    /// Note that [`NetworkPolicy::max_redirects`](pittv3_relay::NetworkPolicy::max_redirects)
    /// multiplies this: a retrieval that redirects is one count and several outbound connections.
    /// Raising that limit widens this budget by the same factor.
    pub retrievals: u64,
    /// Bytes those retrievals may bring back in the period.
    pub bytes: u64,
}

impl RateWindow {
    /// The period as a [`Duration`].
    pub fn period(&self) -> Duration {
        Duration::from_secs(self.seconds)
    }
}

impl Default for RateWindow {
    fn default() -> Self {
        RateWindow {
            seconds: 60,
            requests: 120,
            // Above what one full run may cost. The browser will not make more than a quarter
            // again as many retrievals as the end entities it holds, and it holds at most 500, so
            // a cold run over a whole legal upload fits inside one window with room. A limit below
            // that would refuse the tool's own heaviest legitimate use.
            retrievals: 700,
            bytes: 256 * 1024 * 1024,
        }
    }
}

/// How much work one client address may ask for, over time.
///
/// **Derived from one measurement, not from many.** A 58-path run over NIPR and its interoperability
/// material needed twelve CRLs totalling 48.9 MB, one of them 30.2 MB. Validating a folder of
/// certificates is several such runs, and behind a shared address it is that again for each person
/// doing it -- so the defaults are set well above what the tool's own heaviest ordinary use costs.
/// A limiter that denies the thing the service is for is worse than none, and these should be
/// re-set against a real folder run rather than left at arithmetic.
///
/// On by default, because a deployment reachable from the internet should not be unprotected until
/// somebody knows to turn a limiter on. Deployments where it is noise -- one user, or an isolated
/// network -- set `enabled` to false.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct RateLimits {
    /// Whether any of this is enforced.
    pub enabled: bool,
    /// The short window, which catches a runaway loop while someone is still watching it.
    pub burst: RateWindow,
    /// The long window, which catches steady extraction that stays beneath the short limit.
    pub sustained: RateWindow,
    /// Most client addresses tracked at once.
    ///
    /// The table is attack surface of its own: a client holding a range of addresses can present a
    /// fresh one per request. The cap is what stops the limiter becoming the memory exhaustion it
    /// exists to prevent. Unlike the count limits in a window, 0 here does not mean unbounded; it is
    /// replaced by the default at startup, with a warning.
    pub max_tracked_clients: usize,
    /// How many leading bits of an IPv6 address identify one client.
    ///
    /// An IPv6 client is normally assigned a whole prefix rather than one address, 64 bits at the
    /// least, and can present any address within it. Counted by full address, each request could
    /// arrive as a stranger. So an IPv6 address is counted by its first `ipv6_prefix_len` bits,
    /// and everything beneath that is one client. IPv4 addresses are counted whole.
    ///
    /// 64 is the smallest prefix a network is normally given. A client holding a wider one, a /56
    /// or /48 is common, can still arrive as 256 or 65,536 clients; lowering this counts those as
    /// one, at the cost of also joining the unrelated clients a provider numbered from the same
    /// range.
    /// Values above 128 are read as 128.
    pub ipv6_prefix_len: u8,
}

impl RateLimits {
    /// Replaces settings that would silently enforce nothing with their defaults, returning a note
    /// for each so the replacement is logged rather than the service refusing to start.
    ///
    /// A window of 0 seconds resets on every request and would refuse no one, so it takes that
    /// window's default length. A `max_tracked_clients` of 0 is not unbounded, unlike the count
    /// limits, so it takes the default cap.
    pub fn replace_unusable_values(&mut self) -> Vec<String> {
        let mut notes = vec![];
        if !self.enabled {
            return notes;
        }
        let defaults = RateLimits::default();
        for (name, window, default) in [
            ("burst", &mut self.burst, &defaults.burst),
            ("sustained", &mut self.sustained, &defaults.sustained),
        ] {
            if window.seconds == 0 {
                window.seconds = default.seconds;
                notes.push(format!(
                    "rate_limit.{name}.seconds of 0 would enforce nothing; using {}",
                    default.seconds
                ));
            }
        }
        if self.max_tracked_clients == 0 {
            self.max_tracked_clients = defaults.max_tracked_clients;
            notes.push(format!(
                "rate_limit.max_tracked_clients of 0 is not unbounded, unlike the count limits; \
                 using {}",
                defaults.max_tracked_clients
            ));
        }
        notes
    }
}

impl Default for RateLimits {
    fn default() -> Self {
        RateLimits {
            enabled: true,
            burst: RateWindow::default(),
            sustained: RateWindow {
                seconds: 3600,
                requests: 2000,
                retrievals: 7000,
                bytes: 4 * 1024 * 1024 * 1024,
            },
            max_tracked_clients: 10_000,
            ipv6_prefix_len: 64,
        }
    }
}

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
    /// deployment that configures nothing still has DoD NIPR and its JITC operational-test
    /// counterpart, the Mozilla set, the U.S. Federal PKI and the Purebred development environment
    /// to validate against. On by default: the flexibility
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
    /// How much one client address may ask for, over time.
    pub rate_limit: RateLimits,
    /// Permits server-side path building that chases authority and subject information access
    /// URIs. Off by default: it turns one uploaded certificate into an unbounded-looking amount of
    /// outbound retrieval, so a deployment opts into it knowingly.
    pub allow_dynamic_build: bool,
    /// Serves `POST /api/validate`. A deployment that wants to offer the relay without accepting
    /// certificates turns this off, which is a meaningful posture rather than a degraded one: the
    /// relayed tier is the one where certificates never leave the browser.
    pub enable_validation: bool,
    /// Serves `POST /api/tls`, which completes a handshake with a named host and returns the
    /// certificates it presented. On by default: it reaches only public hosts on the ports the
    /// network policy already permits, it sends nothing and asks for nothing, and it is what lets a
    /// browser validate the certificate a site serves at all. Turn it off for a deployment whose
    /// relay is meant to reach PKI repositories and nothing else.
    pub allow_tls_peek: bool,
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
            rate_limit: RateLimits::default(),
            allow_dynamic_build: false,
            enable_validation: true,
            allow_tls_peek: true,
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
    /// What each client address has spent lately, and the limits it is held to.
    ///
    /// Behind an [`Arc`] because every worker thread shares one set of counts: a limiter per worker
    /// would multiply every limit by the worker count, which is a number no operator configured.
    pub limiter: Arc<RateLimiter>,
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
        let limiter = Arc::new(RateLimiter::new(config.rate_limit.clone()));
        Ok(ServiceState {
            config,
            relay,
            stores,
            limiter,
        })
    }
}

#[cfg(test)]
mod config_tests {
    use super::{RateLimits, RateWindow, ServiceConfig};
    use std::path::PathBuf;

    /// The contract a deployment relies on: `client_dir` set in the configuration file alone, with
    /// no command-line flag, is what gets served.
    #[test]
    fn client_dir_is_read_from_the_configuration_file() {
        let json = r#"{
            "bind": "0.0.0.0:8080",
            "client_dir": "/var/lib/pittv3/client",
            "stores_dir": "/var/lib/pittv3/stores"
        }"#;
        let cfg: ServiceConfig = serde_json::from_str(json).expect("should parse");
        assert_eq!(
            cfg.client_dir,
            Some(PathBuf::from("/var/lib/pittv3/client"))
        );
        assert_eq!(
            cfg.stores_dir,
            Some(PathBuf::from("/var/lib/pittv3/stores"))
        );
        assert_eq!(cfg.bind, "0.0.0.0:8080");
        // Untouched fields keep their defaults, so a partial file is a valid file.
        assert!(cfg.builtin_stores);
        assert!(cfg.enable_validation);
        assert!(!cfg.allow_dynamic_build);
    }

    /// The trap worth knowing about: the struct does NOT deny unknown fields, so a misspelled key
    /// is accepted and ignored. `clientDir` or `client-dir` leaves `client_dir` at None and the
    /// service starts happily serving no application at all -- no parse error, no warning.
    #[test]
    fn a_misspelled_key_is_silently_ignored_rather_than_refused() {
        for wrong in [
            r#"{"clientDir": "/var/lib/pittv3/client"}"#,
            r#"{"client-dir": "/var/lib/pittv3/client"}"#,
            r#"{"clientdir": "/var/lib/pittv3/client"}"#,
        ] {
            let cfg: ServiceConfig = serde_json::from_str(wrong).expect("still parses");
            assert_eq!(
                cfg.client_dir, None,
                "{wrong} should not have set client_dir"
            );
        }
    }

    /// A zero window or a zero client cap takes its default while limiting is on, with a note for
    /// each, and is left alone when limiting is off, since nothing reads it then.
    #[test]
    fn unusable_limits_take_their_defaults() {
        let defaults = RateLimits::default();
        assert!(RateLimits::default().replace_unusable_values().is_empty());

        let mut zeroed = RateLimits {
            burst: RateWindow {
                seconds: 0,
                ..RateWindow::default()
            },
            sustained: RateWindow {
                seconds: 0,
                ..defaults.sustained.clone()
            },
            max_tracked_clients: 0,
            ..RateLimits::default()
        };
        assert_eq!(zeroed.replace_unusable_values().len(), 3);
        assert_eq!(zeroed.burst.seconds, defaults.burst.seconds);
        assert_eq!(zeroed.sustained.seconds, defaults.sustained.seconds);
        assert_eq!(zeroed.max_tracked_clients, defaults.max_tracked_clients);

        let mut off = RateLimits {
            enabled: false,
            max_tracked_clients: 0,
            ..RateLimits::default()
        };
        assert!(off.replace_unusable_values().is_empty());
        assert_eq!(off.max_tracked_clients, 0);
    }
}
