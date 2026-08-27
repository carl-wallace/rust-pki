//! Types related to collection of certification path processing statistics

use alloc::collections::{BTreeMap, BTreeSet};
use certval::CertificationPathResults;

use crate::report::{CertSummary, PathReport, TargetStatus};

/// `PathValidationStats` enables collection of some basic statistics related to path validation.
pub struct PathValidationStats {
    /// Number of certificate files processed for the target
    pub files_processed: i32,
    /// Number of certification paths found for the target
    pub paths_per_target: usize,
    /// Number of certification paths that validated successfully for the target
    pub valid_paths_per_target: usize,
    /// Number of certification paths that failed to validate for the target
    pub invalid_paths_per_target: usize,
    /// Indicates whether the target certificate was determined to be revoked
    #[cfg(feature = "std")]
    pub target_is_revoked: bool,
    /// Results for each certification path processed for the target
    pub results: Vec<CertificationPathResults>,
    /// Structured report for each certification path processed for the target
    pub path_reports: Vec<PathReport>,
    /// Summary details for the target certificate. Recorded when the target is parsed so that a
    /// target for which no path was found can still be named in the report; the path reports are
    /// the only other source and they are empty in exactly that case.
    pub target_summary: Option<CertSummary>,
    /// Why no certification path was found for the target, when none was. Recorded where the
    /// builder returns nothing, since the environment is fully populated there and is torn down
    /// before the report is assembled. Cleared as soon as a path is found, so a diagnosis from an
    /// early pass of the dynamic-building loop does not survive a later pass that succeeds.
    pub no_paths_hints: Vec<String>,
    /// Why no certification path was found for this target, when the reason is the target itself
    /// rather than the material available to build with: the file was not a certificate, or the
    /// certificate was refused before any path was built. Carries the status to report it as and
    /// the reason to show.
    ///
    /// Recorded where the read, the parse or the build refuses, all of which happen before any path
    /// exists, so an entry carrying this has no paths and contributes none to the totals. The
    /// reason belongs on the target for the same reason: nothing was found, so there is nothing for
    /// it to hang off.
    pub no_path_reason: Option<(TargetStatus, String)>,
    /// Fingerprints of the certification paths already reported for this target, one per path, over
    /// the trust anchor followed by the intermediates in order followed by the target.
    ///
    /// The dynamic-building loop validates a target once per pass against a pool that grows between
    /// passes, and the counters and reports below accumulate across those passes rather than a later
    /// pass replacing an earlier one. A path the builder offers on two passes would therefore be
    /// reported twice, and was: a run against a peeked `www.microsoft.com` reported ten paths where
    /// the browser, which has no such loop, reported five. Membership here is what makes a path
    /// reported at most once however many passes surface it.
    ///
    /// The anchor is part of the fingerprint because two paths over the same intermediates but from
    /// different anchors are genuinely different paths, and collapsing them would hide the
    /// cross-certified routes that dynamic building exists to find.
    pub reported_chains: BTreeSet<Vec<u8>>,
}

impl Default for PathValidationStats {
    fn default() -> Self {
        Self::new()
    }
}

impl PathValidationStats {
    /// BuffersAndPaths::new instantiates a new empty BuffersAndPaths.
    pub fn new() -> PathValidationStats {
        PathValidationStats {
            files_processed: 0,
            paths_per_target: 0,
            valid_paths_per_target: 0,
            invalid_paths_per_target: 0,
            #[cfg(feature = "std")]
            target_is_revoked: false,
            results: vec![],
            path_reports: vec![],
            target_summary: None,
            no_paths_hints: vec![],
            no_path_reason: None,
            reported_chains: BTreeSet::new(),
        }
    }
}

/// `PVStats` is used to initialize stats collection for a given target certificate.
pub trait PVStats {
    /// Prepares an empty stats entry for the indicated target certificate file if one is not already present
    fn init_for_target(&mut self, cert_filename: &str);
}

/// `PathValidationStatsGroup` is a typedef for a BTreeMap that associates a string (containing a filename)
/// with a [`PathValidationStats`] instance.
pub type PathValidationStatsGroup = BTreeMap<String, PathValidationStats>;

impl PVStats for PathValidationStatsGroup {
    fn init_for_target(&mut self, cert_filename: &str) {
        if !self.contains_key(cert_filename) {
            self.insert(cert_filename.to_string(), PathValidationStats::default());
        }
    }
}
