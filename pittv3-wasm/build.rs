//! Generates the trust-store artifacts the app fetches at run time.
//!
//! `STORES` in `src/validate.rs` names stores by URL, and Trunk copies
//! `resources/` into `dist/`, so these have to exist as files rather than being
//! linked in: the material is ~9 MB, and embedding it would be paid on every
//! page load whether or not a given store is ever selected. Generating it here
//! from the provider crates keeps it in step with them instead of being
//! refreshed by hand — `resources/webpki_*.cbor` was last built by hand in July
//! 2026, and had no way to notice the upstream root program moving.
//!
//! Writing into the source tree from a build script is unusual, and is done
//! because `resources/` is what Trunk publishes. `write_if_changed` keeps it
//! idempotent: bytes are only written when they differ, so an unchanged
//! regeneration leaves mtimes alone and cannot feed a rebuild loop.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use certval_stores_core::{serialize_environment, TrustStoreProvider};

/// Stamps the time of this build into `PITTV3_BUILD_TIME`, which the header
/// shows so a person can tell whether the page in front of them is the build
/// they just deployed.
///
/// The interesting part is what this script is told to rerun for, because a
/// stamp is only worth showing if it moves when the application does — and
/// only worth having if it does *not* move when the application does not. A
/// value that changed on every invocation would change this crate's
/// compilation inputs on every invocation, and rebuilding pittv3-wasm from
/// scratch costs minutes; that is the cost of "always fresh", and it is not
/// worth paying. So the triggers are the things whose change means a different
/// application: this crate's own sources and manifest, the workspace lock (so
/// an external dependency moving counts), and the in-tree crates the
/// application is built out of. Each of those already forces a recompile, so
/// the stamp rides along for nothing.
///
/// What it therefore cannot notice: a rebuild of byte-identical inputs. That
/// reads as the earlier time, which is the honest answer — it is the same
/// application.
fn stamp_build_time() {
    for path in [
        "build.rs",
        "Cargo.toml",
        "src",
        "../Cargo.lock",
        "../certval/src",
        "../pittv3-lib/src",
        "../pittv3-gui-lib/src",
    ] {
        println!("cargo::rerun-if-changed={path}");
    }

    // A clock before the epoch is not worth a build failure, and 0 renders as a
    // date nobody will mistake for a real one.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("cargo::rustc-env=PITTV3_BUILD_TIME={}", utc_minute(secs));
}

/// Renders a Unix timestamp as `YYYY-MM-DD HH:MM UTC`.
///
/// To the minute: the second a build started is noise next to the question
/// being asked, which is "is this the one I just made". Written out rather than
/// pulled from a date library, because one line of output does not merit a
/// dependency in the build graph.
fn utc_minute(secs: u64) -> String {
    let (days, rest) = ((secs / 86_400) as i64, secs % 86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute) = (rest / 3600, (rest % 3600) / 60);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

/// Days since the Unix epoch to a civil year, month and day, by Howard
/// Hinnant's `civil_from_days`. Verified against `date -u` across the epoch,
/// the 2000 and 2024 leap years and the 2100 century non-leap.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

/// One generated store: which provider environment it comes from, and the file
/// names `STORES` expects. `ca` is `None` for an anchors-only environment.
struct Artifact {
    provider: &'static dyn TrustStoreProvider,
    env: &'static str,
    ta: &'static str,
    ca: Option<&'static str>,
}

/// Adding an entry here adds a redistributed trust set to `dist/`, so it also
/// wants a paragraph in `resources/NOTICE` — that file is the attribution for
/// everything this build script writes, and for the Mozilla material it is the
/// MPL-2.0 Exhibit A notice the CBOR itself cannot carry.
fn artifacts() -> Vec<Artifact> {
    vec![
        Artifact {
            provider: certval_stores_nipr::provider(),
            env: "NIPR",
            ta: "dod_nipr_prod_ta.cbor",
            ca: Some("dod_nipr_prod_ca.cbor"),
        },
        // MOZILLA_ALL rather than MOZILLA_TLS: the CA store hangs off the
        // combined environment only, because 356 of the intermediates chain
        // solely to email-only roots and would be unanchored under the
        // TLS-scoped anchor set. Purpose is gated from the roots' trust bits,
        // not from the anchor set.
        Artifact {
            provider: certval_stores_mozilla::provider(),
            env: "MOZILLA_ALL",
            ta: "webpki_ta.cbor",
            ca: Some("webpki_ca.cbor"),
        },
    ]
    // The ML-DSA PKITS store is not a provider — it is test collateral for the
    // PQC edition, generated elsewhere — so it stays a committed file.
}

fn main() {
    stamp_build_time();

    let dir = Path::new("resources");
    for a in artifacts() {
        let store = match serialize_environment(&[a.provider], a.env) {
            Ok(s) => s,
            // A provider that cannot serialize is a broken build, not a warning
            // to scroll past: the app would fetch a stale store and validate
            // against material nobody chose.
            Err(e) => panic!("failed to serialize the {} store: {e:?}", a.env),
        };

        write_if_changed(&dir.join(a.ta), &store.ta_cbor);
        match (a.ca, store.ca_cbor) {
            (Some(name), Some(bytes)) => write_if_changed(&dir.join(name), &bytes),
            (Some(name), None) => {
                panic!(
                    "{} expects a CA store at {name} but the provider carries none",
                    a.env
                )
            }
            (None, Some(_)) => {
                panic!(
                    "{} carries a CA store but no file name is configured for it",
                    a.env
                )
            }
            (None, None) => {}
        }
    }
}

/// Write `bytes` only if the file does not already hold exactly them, so a
/// no-op regeneration does not touch the file or its mtime.
fn write_if_changed(path: &Path, bytes: &[u8]) {
    if fs::read(path).is_ok_and(|existing| existing == bytes) {
        return;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| panic!("cannot create {parent:?}: {e}"));
    }
    fs::write(path, bytes).unwrap_or_else(|e| panic!("cannot write {path:?}: {e}"));
    println!("cargo::warning=regenerated {}", path.display());
}
