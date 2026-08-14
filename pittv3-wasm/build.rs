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

use certval_stores_core::{serialize_environment, TrustStoreProvider};

/// One generated store: which provider environment it comes from, and the file
/// names `STORES` expects. `ca` is `None` for an anchors-only environment.
struct Artifact {
    provider: &'static dyn TrustStoreProvider,
    env: &'static str,
    ta: &'static str,
    ca: Option<&'static str>,
}

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
    println!("cargo::rerun-if-changed=build.rs");

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
