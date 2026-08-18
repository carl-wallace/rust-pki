//! Budgets bounding a single retrieval and bounding a sequence of retrievals taken together.
//!
//! certval's own caps are per-artifact and were sized for a local tool run by a patient human: four
//! mebibytes per authority information access fetch, a hundred per CRL, sixty seconds per request.
//! Nothing bounds a chase as a whole, which on a command line is a patience problem and in a service
//! is a way to occupy a worker indefinitely with one certificate carrying a hostile subject
//! information access extension. [`ChaseBudget`] supplies the missing totals, and it is kept here
//! rather than in the service because the browser tier runs the same loop through the relay and
//! wants the same accounting.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Bounds applied to one retrieval.
///
/// The response cap is enforced as the body streams rather than after it arrives, so a responder
/// cannot exhaust memory by promising a small body and sending a large one. The request cap exists
/// because the only request body the relay carries is an OCSP request, which is small.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct FetchBudget {
    /// Largest response body that will be read, in bytes.
    pub max_response_bytes: u64,
    /// Largest request body that will be sent, in bytes.
    pub max_request_bytes: usize,
    /// Time allowed for a single retrieval, connection setup included.
    pub timeout: Duration,
}

impl Default for FetchBudget {
    fn default() -> Self {
        FetchBudget {
            // Comfortably larger than any certificate, certs-only SignedData or OCSP response, and
            // larger than most CRLs while far below certval's hundred-mebibyte per-CRL ceiling: a
            // service pays for that ceiling in memory per concurrent request.
            max_response_bytes: 16 * 1024 * 1024,
            max_request_bytes: 64 * 1024,
            timeout: Duration::from_secs(10),
        }
    }
}

/// Bounds applied to a sequence of retrievals serving one user-visible operation, i.e., one
/// validation with dynamic building or one chase.
///
/// Held by whoever drives the loop and consulted before each retrieval, so exhaustion ends the
/// chase rather than failing the operation: a path found within budget is a good answer, and a
/// budget reached without one is reported as an incomplete search rather than as an error.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ChaseBudgetLimits {
    /// Total bytes that may be retrieved across every fetch in the sequence.
    pub max_total_bytes: u64,
    /// Number of retrievals that may be made.
    pub max_fetches: usize,
    /// Wall-clock time the sequence may occupy.
    pub max_duration: Duration,
}

impl Default for ChaseBudgetLimits {
    fn default() -> Self {
        ChaseBudgetLimits {
            max_total_bytes: 64 * 1024 * 1024,
            max_fetches: 64,
            max_duration: Duration::from_secs(60),
        }
    }
}

/// Reason a sequence of retrievals stopped short.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetExhausted {
    /// The total byte allowance was consumed.
    Bytes,
    /// The fetch count allowance was consumed.
    Fetches,
    /// The wall-clock allowance elapsed.
    Duration,
}

impl core::fmt::Display for BudgetExhausted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BudgetExhausted::Bytes => write!(f, "byte budget exhausted"),
            BudgetExhausted::Fetches => write!(f, "fetch budget exhausted"),
            BudgetExhausted::Duration => write!(f, "time budget exhausted"),
        }
    }
}

/// Running account of what a sequence of retrievals has spent.
#[derive(Clone, Debug)]
pub struct ChaseBudget {
    limits: ChaseBudgetLimits,
    started: Instant,
    bytes: u64,
    fetches: usize,
}

impl ChaseBudget {
    /// Starts an account against the supplied limits. The clock starts here, so create this when
    /// the operation begins rather than when the first retrieval is attempted.
    pub fn new(limits: ChaseBudgetLimits) -> Self {
        ChaseBudget {
            limits,
            started: Instant::now(),
            bytes: 0,
            fetches: 0,
        }
    }

    /// Reports whether another retrieval may be attempted, and why not when it may not.
    pub fn check(&self) -> Result<(), BudgetExhausted> {
        if self.fetches >= self.limits.max_fetches {
            return Err(BudgetExhausted::Fetches);
        }
        if self.bytes >= self.limits.max_total_bytes {
            return Err(BudgetExhausted::Bytes);
        }
        if self.started.elapsed() >= self.limits.max_duration {
            return Err(BudgetExhausted::Duration);
        }
        Ok(())
    }

    /// Records a completed retrieval. A retrieval that failed still counts against the fetch and
    /// time allowances, since the cost of a request that timed out or was refused is real.
    pub fn spend(&mut self, bytes: u64) {
        self.fetches += 1;
        self.bytes = self.bytes.saturating_add(bytes);
    }

    /// Returns the bytes the remaining allowance permits, for use as the per-fetch response cap so
    /// the last retrieval in a sequence cannot overshoot the total.
    pub fn remaining_bytes(&self) -> u64 {
        self.limits.max_total_bytes.saturating_sub(self.bytes)
    }

    /// Returns the time the remaining allowance permits, for use as the per-fetch timeout.
    pub fn remaining_time(&self) -> Duration {
        self.limits
            .max_duration
            .saturating_sub(self.started.elapsed())
    }

    /// Returns how many retrievals have been recorded.
    pub fn fetches(&self) -> usize {
        self.fetches
    }

    /// Returns how many bytes have been recorded.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_stop_the_sequence() {
        let mut budget = ChaseBudget::new(ChaseBudgetLimits {
            max_fetches: 2,
            ..Default::default()
        });
        assert_eq!(budget.check(), Ok(()));
        budget.spend(10);
        assert_eq!(budget.check(), Ok(()));
        budget.spend(10);
        assert_eq!(budget.check(), Err(BudgetExhausted::Fetches));
        assert_eq!(budget.fetches(), 2);
        assert_eq!(budget.bytes(), 20);
    }

    #[test]
    fn byte_totals_stop_the_sequence_and_cap_the_next_fetch() {
        let mut budget = ChaseBudget::new(ChaseBudgetLimits {
            max_total_bytes: 100,
            ..Default::default()
        });
        budget.spend(60);
        assert_eq!(budget.check(), Ok(()));
        assert_eq!(budget.remaining_bytes(), 40);
        budget.spend(60);
        assert_eq!(budget.check(), Err(BudgetExhausted::Bytes));
        assert_eq!(budget.remaining_bytes(), 0);
    }

    #[test]
    fn elapsed_time_stops_the_sequence() {
        let budget = ChaseBudget::new(ChaseBudgetLimits {
            max_duration: Duration::from_secs(0),
            ..Default::default()
        });
        assert_eq!(budget.check(), Err(BudgetExhausted::Duration));
        assert_eq!(budget.remaining_time(), Duration::from_secs(0));
    }
}
