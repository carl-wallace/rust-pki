//! Types related to collection of certification path processing statistics

use alloc::collections::BTreeMap;
use certval::CertificationPathResults;

use crate::report::{CertSummary, PathReport};

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
