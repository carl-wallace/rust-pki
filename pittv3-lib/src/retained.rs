//! What a run keeps so its artifacts can be exported after the fact.
//!
//! A results folder is written *during* a run and has to be asked for before it starts. Retention
//! answers the other case: a person who has seen the outcome and only then wants the material
//! behind it. Both produce the same layout — [`crate::pitt_log::log_path`] writes it to a folder
//! and `pittv3_gui_lib::export::path_entries` composes the same files as archive entries — so what
//! differs is when the decision is made, not what comes out.
//!
//! This type lives here rather than beside either producer because there are two: the frontends
//! that prepare an environment and validate against it, and the entry points in
//! [`crate::std_utils`] that do the whole run. A consumer written against this type works with
//! either, which is what lets one set of export buttons outlive a change of producer.

use alloc::string::String;

use certval::{CertificationPath, CertificationPathResults, CertificationPathSettings};

/// One validated path, kept so the artifacts behind it can be exported afterwards.
///
/// The path and the results are what an export is assembled from; the settings are the ones that
/// path was validated under, which is not the run's settings — RFC 5937 trust anchor constraints are
/// folded in per path — so a manifest reporting the run's would describe inputs the path was not
/// judged against.
///
/// Nothing is computed to produce these. The path and results exist for the duration of the
/// validation regardless; retaining them is declining to drop them, which is why this is a caller's
/// choice at the call site rather than a setting a user has to know to turn on before a run they
/// have not seen the outcome of yet.
///
/// **Paths that failed are kept too**: a failure is the case someone most wants the material for.
///
/// Exporting also needs the `PkiEnvironment` the run used, which is not held here — the CRLs that
/// settled a status are recovered from whichever `CrlSource` supplied them, since the results retain
/// only `CrlInfo` and keeping every body per position per path is what made a large distribution
/// point cost megabytes a run. A caller that means to export therefore keeps the environment alive
/// alongside these.
pub struct RetainedPath {
    /// Name of the target this path was built for, as the caller supplied it
    pub target_name: String,
    /// The path as validated
    pub path: CertificationPath,
    /// The settings this path was validated under
    pub cps: CertificationPathSettings,
    /// The results recorded while validating it
    pub cpr: CertificationPathResults,
}
