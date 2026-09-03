#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

extern crate alloc;

pub mod args;
// Available in every build: it is the decode every entry point taking caller bytes has to do, and a
// build that cannot do it is one where a PEM file fails in a way that looks like something else.
pub mod der_or_pem;
#[cfg(feature = "std")]
pub mod graph_cache;
pub mod help;
pub mod no_std_utils;
pub mod ocsp_match;
pub mod options_no_std;
pub mod options_std;
pub mod options_std_app;
pub mod pitt_log;
#[cfg(feature = "std")]
pub mod prepared_graph;
pub mod report;
pub mod retained;
pub mod stats;
pub mod std_utils;
pub mod uri_check;

#[cfg(feature = "sha1_sig")]
pub mod sha1_sig;

/// Runs this build's entry point, for a caller that has an async runtime.
///
/// Choosing the entry point belongs here, not in the binary. The three `options_*` modules gate
/// themselves on *this crate's* features, and a binary can only test its own; cargo unifies features
/// across a workspace build, so the two can disagree. A binary built below `std`, linked against a
/// `pittv3-lib` that a sibling crate pulled up to `std`, would otherwise reach for an entry point
/// that is no longer compiled.
#[cfg(feature = "std")]
pub async fn run(args: &Pittv3Args) -> report::ValidationReport {
    options_std::options_std(args).await
}

/// Runs this build's entry point, for a caller that has an async runtime.
#[cfg(all(feature = "std_app", not(feature = "std")))]
pub async fn run(args: &Pittv3Args) -> report::ValidationReport {
    options_std_app::options_std_app(args);
    report::ValidationReport::default()
}

/// Runs this build's entry point, for a caller that has an async runtime.
#[cfg(not(feature = "std_app"))]
pub async fn run(args: &Pittv3Args) -> report::ValidationReport {
    options_no_std::options_no_std(args);
    report::ValidationReport::default()
}

/// Runs this build's entry point from a synchronous caller.
///
/// The counterpart to [`run`] for a binary built without its own async runtime. Only the `std` arm
/// needs one, and only reachable through feature unification -- see [`run`].
#[cfg(feature = "std")]
pub fn run_blocking(args: &Pittv3Args) -> report::ValidationReport {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt.block_on(options_std::options_std(args)),
        Err(e) => {
            report::ValidationReport::failed(format!("failed to start an async runtime: {e}"))
        }
    }
}

/// Runs this build's entry point from a synchronous caller.
#[cfg(all(feature = "std_app", not(feature = "std")))]
pub fn run_blocking(args: &Pittv3Args) -> report::ValidationReport {
    options_std_app::options_std_app(args);
    report::ValidationReport::default()
}

/// Runs this build's entry point from a synchronous caller.
#[cfg(not(feature = "std_app"))]
pub fn run_blocking(args: &Pittv3Args) -> report::ValidationReport {
    options_no_std::options_no_std(args);
    report::ValidationReport::default()
}

pub use crate::args::Pittv3Args;

/// Re-exported because [`options_std_retaining`](crate::options_std::options_std_retaining) takes
/// one in its signature: a frontend that owns the revocation status cache across runs has to be
/// able to name the type, and not every frontend depends on certval directly.
#[cfg(all(feature = "std", feature = "revocation"))]
pub use certval::RevocationCache;
