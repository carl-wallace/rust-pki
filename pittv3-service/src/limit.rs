//! Per-client rate limiting: how much work one address may ask for, over time.
//!
//! The budgets in [`pittv3_relay::budget`] bound one retrieval and one operation. Nothing bounds a
//! client starting those operations back to back forever, which is what this does. So nothing here
//! re-bounds *size* -- a request that arrives is already capped by [`crate::RequestLimits`], and
//! what serving it may retrieve is already capped by the chase budget. What is counted is the rate
//! at which a client may start them.
//!
//! # Why an address, and what that costs
//!
//! The service holds no sessions -- no login, no cookie, nothing that survives a request -- so the
//! peer address is the only identity available. It is a poor one: an office behind NAT and a
//! carrier-grade NAT range are each a single key, so a limit is shared by people who have never
//! met. That is why the defaults are generous, why exceeding one is a refusal that expires rather
//! than a ban, and why no penalty escalates. A stricter limiter would mostly punish strangers.
//!
//! # Two windows
//!
//! A single window forces a bad trade: wide enough for a legitimate burst is useless against
//! sustained scraping, and tight enough for sustained breaks the burst. A short window catches a
//! runaway loop while someone is still watching it; a long one catches steady extraction that stays
//! politely beneath the short limit all day.
//!
//! # Fixed windows, and the one thing they get wrong
//!
//! Each window is a counter and a start instant, reset when the period elapses. A client can
//! therefore spend a full window's allowance just before a boundary and another just after, so the
//! true short-term worst case is twice the stated limit. A token bucket would not have that edge,
//! and it is not worth its complexity here: the dials carry far more headroom than a factor of two,
//! and a fixed window is legible in a way a bucket is not when an operator is asked what a client
//! was allowed to do.
//!
//! # Check before, charge after
//!
//! What a request will cost in retrievals and bytes is not known until it has been served. So a
//! request is admitted on the client's standing so far, and what it actually spent is recorded
//! afterwards. A client sitting just under a limit can therefore start one more operation and
//! overshoot -- by at most what one operation may spend, which the chase budget already bounds.
//! The alternative, charging an estimate up front, would deny work that was never going to cost
//! what the estimate feared.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::{RateLimits, RateWindow};

/// What serving one request cost in outbound work.
///
/// Read from the [`ChaseBudget`](pittv3_relay::ChaseBudget) a request shares across everything it
/// retrieves, so it covers chasing certificates and fetching revocation data together.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Spend {
    /// Retrievals made to third parties.
    pub retrievals: u64,
    /// Bytes those retrievals brought back.
    pub bytes: u64,
}

impl From<&pittv3_relay::ChaseBudget> for Spend {
    /// Reads what a budget recorded. A request shares one, so its totals are the request's.
    fn from(budget: &pittv3_relay::ChaseBudget) -> Self {
        Spend {
            retrievals: budget.fetches() as u64,
            bytes: budget.bytes(),
        }
    }
}

/// Which limit a client ran into, so a refusal can say so and an operator can tell a client that is
/// asking too often from one that is asking for too much.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dimension {
    /// Calls to the service.
    Requests,
    /// Retrievals the service made to third parties on the client's behalf.
    Retrievals,
    /// Bytes those retrievals brought back.
    Bytes,
}

impl Dimension {
    /// Wording for a client, which has to be actionable rather than merely accurate: the three
    /// cases call for different behaviour from whoever hits them.
    pub fn describe(&self) -> &'static str {
        match self {
            Dimension::Requests => "too many requests",
            Dimension::Retrievals => "too many retrievals",
            Dimension::Bytes => "too many bytes retrieved",
        }
    }
}

/// A refusal: what was exceeded, over which period, and when it will be worth trying again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimited {
    /// Which count was over.
    pub dimension: Dimension,
    /// The window whose limit was reached, in seconds, naming which of the two it was.
    pub window_secs: u64,
    /// How long until that window resets. Sent as `Retry-After`, so a client waits rather than
    /// retrying into a refusal.
    pub retry_after: Duration,
}

/// One window's running counts.
#[derive(Clone, Copy, Debug)]
struct Counts {
    started: Instant,
    requests: u64,
    retrievals: u64,
    bytes: u64,
}

impl Counts {
    fn new(now: Instant) -> Self {
        Counts {
            started: now,
            requests: 0,
            retrievals: 0,
            bytes: 0,
        }
    }

    /// Starts a fresh period when the last one has elapsed.
    fn roll(&mut self, now: Instant, period: Duration) {
        if now.duration_since(self.started) >= period {
            *self = Counts::new(now);
        }
    }

    /// The first limit this window is over, if any. A zero limit is unbounded, so an operator can
    /// cap bytes without capping request count.
    fn exceeded(&self, window: &RateWindow) -> Option<Dimension> {
        if window.requests > 0 && self.requests > window.requests {
            return Some(Dimension::Requests);
        }
        if window.retrievals > 0 && self.retrievals > window.retrievals {
            return Some(Dimension::Retrievals);
        }
        if window.bytes > 0 && self.bytes > window.bytes {
            return Some(Dimension::Bytes);
        }
        None
    }
}

/// What one client has spent in each window.
#[derive(Clone, Copy, Debug)]
struct ClientState {
    burst: Counts,
    sustained: Counts,
    last_seen: Instant,
}

impl ClientState {
    fn new(now: Instant) -> Self {
        ClientState {
            burst: Counts::new(now),
            sustained: Counts::new(now),
            last_seen: now,
        }
    }
}

/// Tracks what each client address has spent and refuses the ones over a limit.
#[derive(Debug)]
pub struct RateLimiter {
    limits: RateLimits,
    clients: Mutex<HashMap<IpAddr, ClientState>>,
}

impl RateLimiter {
    /// Builds a limiter enforcing `limits`.
    pub fn new(limits: RateLimits) -> Self {
        RateLimiter {
            limits,
            clients: Mutex::new(HashMap::new()),
        }
    }

    /// Whether this limiter does anything, so a caller can skip the bookkeeping entirely rather
    /// than maintaining counts nothing consults.
    pub fn enabled(&self) -> bool {
        self.limits.enabled
    }

    /// Admits one request from `client`, or refuses it.
    ///
    /// Admitting records the request. What serving it retrieves is recorded separately by
    /// [`charge`](Self::charge), once that is known.
    pub fn admit(&self, client: IpAddr) -> Result<(), RateLimited> {
        if !self.limits.enabled {
            return Ok(());
        }
        let now = Instant::now();
        let mut clients = match self.clients.lock() {
            Ok(c) => c,
            // A poisoned lock means a handler panicked mid-update. Refusing every request
            // afterwards would turn one panic into an outage, and the counts are an approximation
            // already, so the limiter reopens rather than failing the service closed.
            Err(poisoned) => poisoned.into_inner(),
        };

        self.evict_if_full(&mut clients, now);

        let state = clients
            .entry(client)
            .or_insert_with(|| ClientState::new(now));
        state.last_seen = now;
        state.burst.roll(now, self.limits.burst.period());
        state.sustained.roll(now, self.limits.sustained.period());

        if let Some(refusal) = self.refusal(state, now) {
            return Err(refusal);
        }

        state.burst.requests += 1;
        state.sustained.requests += 1;
        Ok(())
    }

    /// Records what serving a request actually cost, after it has been served.
    ///
    /// Called for work that reached third parties. A request that retrieved nothing costs only the
    /// request itself, already recorded by [`admit`](Self::admit).
    pub fn charge(&self, client: IpAddr, retrievals: u64, bytes: u64) {
        if !self.limits.enabled || (retrievals == 0 && bytes == 0) {
            return;
        }
        let now = Instant::now();
        let mut clients = match self.clients.lock() {
            Ok(c) => c,
            Err(poisoned) => poisoned.into_inner(),
        };
        // No entry means the client was evicted between being admitted and being charged, which
        // only happens under table pressure. Re-inserting would let an attacker who forces eviction
        // also reset everyone's counts, so the charge is dropped instead.
        if let Some(state) = clients.get_mut(&client) {
            state.last_seen = now;
            state.burst.roll(now, self.limits.burst.period());
            state.sustained.roll(now, self.limits.sustained.period());
            state.burst.retrievals += retrievals;
            state.burst.bytes += bytes;
            state.sustained.retrievals += retrievals;
            state.sustained.bytes += bytes;
        }
    }

    /// The first refusal either window produces, with the burst window checked first so a client
    /// that is over both is told about the one that clears sooner.
    fn refusal(&self, state: &ClientState, now: Instant) -> Option<RateLimited> {
        if let Some(dimension) = state.burst.exceeded(&self.limits.burst) {
            return Some(RateLimited {
                dimension,
                window_secs: self.limits.burst.seconds,
                retry_after: remaining(state.burst.started, self.limits.burst.period(), now),
            });
        }
        if let Some(dimension) = state.sustained.exceeded(&self.limits.sustained) {
            return Some(RateLimited {
                dimension,
                window_secs: self.limits.sustained.seconds,
                retry_after: remaining(
                    state.sustained.started,
                    self.limits.sustained.period(),
                    now,
                ),
            });
        }
        None
    }

    /// Keeps the table bounded.
    ///
    /// The table is itself attack surface: a client holding a range of addresses can mint a fresh
    /// key per request, so without a cap the limiter becomes the memory exhaustion it exists to
    /// prevent. Entries whose long window has fully elapsed are dropped first, since those carry no
    /// counts worth keeping; if none has, the least recently seen goes, which is the client least
    /// likely to be mid-burst.
    fn evict_if_full(&self, clients: &mut HashMap<IpAddr, ClientState>, now: Instant) {
        if clients.len() < self.limits.max_tracked_clients {
            return;
        }
        let period = self.limits.sustained.period();
        clients.retain(|_, state| now.duration_since(state.sustained.started) < period);
        if clients.len() < self.limits.max_tracked_clients {
            return;
        }
        if let Some(oldest) = clients
            .iter()
            .min_by_key(|(_, state)| state.last_seen)
            .map(|(key, _)| *key)
        {
            clients.remove(&oldest);
        }
    }
}

/// How long is left of a window that started at `started`.
fn remaining(started: Instant, period: Duration, now: Instant) -> Duration {
    period.saturating_sub(now.duration_since(started))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    /// Limits small enough to reach in a test, which is the only reason they are not the defaults.
    fn limits() -> RateLimits {
        RateLimits {
            enabled: true,
            burst: RateWindow {
                seconds: 60,
                requests: 3,
                retrievals: 5,
                bytes: 1000,
            },
            sustained: RateWindow {
                seconds: 3600,
                requests: 10,
                retrievals: 0,
                bytes: 0,
            },
            max_tracked_clients: 4,
        }
    }

    #[test]
    fn a_disabled_limiter_admits_everything() {
        let limits = RateLimits {
            enabled: false,
            ..limits()
        };
        let limiter = RateLimiter::new(limits);
        for _ in 0..100 {
            assert!(limiter.admit(address(1)).is_ok());
        }
        assert!(!limiter.enabled());
    }

    #[test]
    fn requests_are_counted_until_the_limit_is_passed() {
        let limiter = RateLimiter::new(limits());
        // Three are allowed, so the fourth is the first over: the check is against what has been
        // spent already, which is why the limit is reached rather than merely met.
        for _ in 0..4 {
            assert!(limiter.admit(address(1)).is_ok());
        }
        let refused = limiter.admit(address(1)).unwrap_err();
        assert_eq!(refused.dimension, Dimension::Requests);
        assert_eq!(refused.window_secs, 60);
        assert!(refused.retry_after <= Duration::from_secs(60));
    }

    /// One client's spending must not refuse another's, which is the whole point of keying by
    /// address and the thing a bug in eviction would break silently.
    #[test]
    fn clients_are_counted_separately() {
        let limiter = RateLimiter::new(limits());
        for _ in 0..5 {
            let _ = limiter.admit(address(1));
        }
        assert!(limiter.admit(address(1)).is_err());
        assert!(limiter.admit(address(2)).is_ok());
    }

    /// Retrievals are charged after the fact, so a client under the request limit can still be
    /// refused for what its earlier requests went on to cost.
    #[test]
    fn retrievals_are_charged_after_the_request_that_made_them() {
        let limiter = RateLimiter::new(limits());
        assert!(limiter.admit(address(1)).is_ok());
        limiter.charge(address(1), 6, 0);
        let refused = limiter.admit(address(1)).unwrap_err();
        assert_eq!(refused.dimension, Dimension::Retrievals);
    }

    #[test]
    fn bytes_are_charged_the_same_way() {
        let limiter = RateLimiter::new(limits());
        assert!(limiter.admit(address(1)).is_ok());
        limiter.charge(address(1), 1, 1001);
        let refused = limiter.admit(address(1)).unwrap_err();
        assert_eq!(refused.dimension, Dimension::Bytes);
    }

    /// A zero is unbounded rather than "nothing allowed", so an operator can cap one dimension
    /// without capping the others. The sustained window here states no retrieval or byte limit.
    #[test]
    fn a_zero_limit_is_unbounded() {
        let limiter = RateLimiter::new(limits());
        assert!(limiter.admit(address(1)).is_ok());
        limiter.charge(address(1), 1_000_000, 1_000_000_000);
        // Over the burst retrieval limit, so the refusal must name the burst window rather than
        // the sustained one, which states no retrieval limit at all.
        let refused = limiter.admit(address(1)).unwrap_err();
        assert_eq!(refused.window_secs, 60);
    }

    /// The table cannot grow without bound, because a client with a range of addresses would
    /// otherwise turn the limiter into the exhaustion it exists to prevent.
    #[test]
    fn the_client_table_stays_bounded() {
        let limiter = RateLimiter::new(limits());
        for last in 0..50u8 {
            let _ = limiter.admit(address(last));
        }
        let tracked = limiter.clients.lock().unwrap().len();
        assert!(
            tracked <= limits().max_tracked_clients,
            "tracked {tracked} clients with a cap of {}",
            limits().max_tracked_clients
        );
    }

    /// A charge for a client the table no longer holds is dropped rather than re-inserting it: an
    /// attacker who can force eviction must not also be able to resurrect a cleared entry.
    #[test]
    fn charging_an_untracked_client_does_not_insert_one() {
        let limiter = RateLimiter::new(limits());
        limiter.charge(address(9), 100, 100);
        assert!(limiter.clients.lock().unwrap().is_empty());
    }
}
