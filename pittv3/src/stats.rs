//! Types related to collection of certification path processing statistics

use alloc::collections::BTreeMap;
use certval::CertificationPathResults;

/// `PathValidationStats` enables collection of some basic statistics related to path validation.
pub struct PathValidationStats<'a> {
    pub files_processed: i32,
    pub paths_per_target: usize,
    pub valid_paths_per_target: usize,
    pub invalid_paths_per_target: usize,
    pub target_is_revoked: bool,
    pub results: Vec<CertificationPathResults<'a>>,
}

impl<'a> Default for PathValidationStats<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> PathValidationStats<'_> {
    /// BuffersAndPaths::new instantiates a new empty BuffersAndPaths.
    pub fn new() -> PathValidationStats<'a> {
        PathValidationStats {
            files_processed: 0,
            paths_per_target: 0,
            valid_paths_per_target: 0,
            invalid_paths_per_target: 0,
            target_is_revoked: false,
            results: vec![],
        }
    }
}

/// `PVStats` is used to initialize stats collection for a given target certificate.
pub trait PVStats {
    fn init_for_target(&mut self, cert_filename: &str);
}

/// `PathValidationStatsGroup` is a typedef for a BTreeMap that associates a string (containing a filename)
/// with a [`PathValidationStats`] instance.
pub type PathValidationStatsGroup<'a> = BTreeMap<String, PathValidationStats<'a>>;

impl<'a> PVStats for PathValidationStatsGroup<'_> {
    fn init_for_target(&mut self, cert_filename: &str) {
        if !self.contains_key(cert_filename) {
            self.insert(cert_filename.to_string(), PathValidationStats::default());
        }
    }
}
