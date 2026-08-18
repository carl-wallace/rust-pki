//! Generates the trust stores the service offers without being configured with any.
//!
//! A deployment can point `--stores` at a directory and get exactly the stores it put there, and
//! that stays the way to serve anything else — a store built for one community, an export from a
//! desktop run, a chased graph. What it should not have to do is assemble DoD NIPR or the Mozilla
//! set by hand before the service is useful at all, so those are generated here from the
//! `certval_stores_*` providers and linked in.
//!
//! Generating them rather than committing them is the same argument `pittv3-wasm/build.rs` makes:
//! a committed artifact has no way to notice its provider moving. Making it the *same call* those
//! build scripts make is the other half — the browser fetches `webpki_ta.cbor` from the files its
//! own build script wrote, this service serves `webpki` from bytes this one wrote, and both come
//! out of `serialize_environment` for the same environment. That is why the browser can drop a
//! service store whose identifier it already ships: they are the same material by construction, not
//! by anyone remembering to refresh both.
//!
//! Unlike the browser's, these go to `OUT_DIR` and are linked into the binary. There is nothing to
//! publish alongside a server the way Trunk publishes `resources/`, and the material has to be
//! present before the first request rather than fetched.
//!
//! All of this is behind the `builtin-stores` feature, which is on by default. Turning it off
//! drops the provider crates from the build entirely — 7.9 MB of trust material, and a build
//! that no longer reaches the repositories carrying it — leaving a service that serves whatever
//! `--stores` points at and nothing else. The feature governs what is *in the binary*; the
//! `builtin_stores` configuration setting governs whether a binary that has it offers it.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(feature = "builtin-stores")]
use certval_stores_core::{serialize_environment, TrustStoreProvider};

/// One generated store: the provider environment it comes from, and how it is named to a client.
#[cfg(feature = "builtin-stores")]
struct Builtin {
    /// Provider environment, e.g. `NIPR`
    env: &'static str,
    /// Identifier a client names in a request and in a store URI.
    ///
    /// These match the file names `pittv3-wasm/build.rs` writes, minus the `_ta`/`_ca` suffix, so
    /// the identifier a store carries here is the identifier the browser already knows it by.
    id: &'static str,
    /// Name shown to a person choosing a store.
    label: &'static str,
    /// A function pointer because `provider()` is not a const fn.
    provider: fn() -> &'static dyn TrustStoreProvider,
}

/// The catalogue, which is the desktop app's minus its webpki-roots entry: that one is an anchor
/// set certval builds for itself and `TaSource` has no serializer, so there is nothing to embed.
/// Keeping the rest aligned is deliberate — the same product should not offer a different trust
/// catalogue depending on which frontend it is wearing.
#[cfg(feature = "builtin-stores")]
fn builtins() -> Vec<Builtin> {
    vec![
        Builtin {
            env: "NIPR",
            id: "dod_nipr_prod",
            label: "U.S. DoD (NIPR production)",
            provider: certval_stores_nipr::provider,
        },
        // MOZILLA_ALL rather than MOZILLA_TLS: the intermediate store hangs off the combined
        // environment only, because a large share of the CCADB intermediates chain solely to
        // email-only roots and would be unanchored under the TLS-scoped anchor set.
        Builtin {
            env: "MOZILLA_ALL",
            id: "webpki",
            label: "Web PKI (Mozilla roots, TLS + S/MIME, + CCADB intermediates)",
            provider: certval_stores_mozilla::provider,
        },
        // The trust-bit-scoped subsets, which carry anchors and nothing else. Which roots belong to
        // each is CCADB policy rather than anything the certificates record, so the split has to
        // come from the provider.
        Builtin {
            env: "MOZILLA_TLS",
            id: "webpki_tls",
            label: "Web PKI (Mozilla roots, TLS only)",
            provider: certval_stores_mozilla::provider,
        },
        Builtin {
            env: "MOZILLA_EMAIL",
            id: "webpki_email",
            label: "Web PKI (Mozilla roots, S/MIME only)",
            provider: certval_stores_mozilla::provider,
        },
        Builtin {
            env: "FPKI",
            id: "fpki",
            label: "U.S. Federal PKI (Common Policy CA G2)",
            provider: certval_stores_fpki::provider,
        },
        Builtin {
            env: "DEV",
            id: "dod_purebred_dev",
            label: "U.S. DoD (Purebred development)",
            provider: certval_stores_pbdev::provider,
        },
    ]
}

fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    let out = PathBuf::from(env::var("OUT_DIR").expect("cargo did not set OUT_DIR"));

    let mut table = String::new();
    #[cfg(feature = "builtin-stores")]
    generate(&out.join("stores"), &mut table);

    // Written whether or not anything was generated: the table is `include!`d unconditionally, so
    // a build with the feature off has to find an empty one rather than nothing at all.
    let generated =
        format!("/// Stores generated by build.rs. See `builtins()` there for the catalogue.\nstatic BUILTIN: &[Builtin] = &[\n{table}];\n");
    write(&out.join("builtin_stores.rs"), generated.as_bytes());
}

/// Serializes each catalogue entry into `dir` and appends its literal to `table`.
#[cfg(feature = "builtin-stores")]
fn generate(dir: &Path, table: &mut String) {
    fs::create_dir_all(dir).unwrap_or_else(|e| panic!("cannot create {}: {e}", dir.display()));

    for b in builtins() {
        let store = match serialize_environment(&[(b.provider)()], b.env) {
            Ok(s) => s,
            // A provider that cannot serialize is a broken build rather than a warning to scroll
            // past: the service would come up offering fewer stores than it says it does, and
            // nothing at run time would say which one went missing.
            Err(e) => panic!("failed to serialize the {} store: {e:?}", b.env),
        };

        let ta = dir.join(format!("{}_ta.cbor", b.id));
        write(&ta, &store.ta_cbor);
        let ca = match &store.ca_cbor {
            Some(bytes) => {
                let path = dir.join(format!("{}_ca.cbor", b.id));
                write(&path, bytes);
                format!("Some({})", include_bytes_literal(&path))
            }
            None => "None".to_string(),
        };

        table.push_str(&format!(
            "    Builtin {{ id: {:?}, label: {:?}, ta_cbor: {}, ca_cbor: {} }},\n",
            b.id,
            b.label,
            include_bytes_literal(&ta),
            ca
        ));
    }
}

/// An `include_bytes!` invocation naming `path`, written through `Debug` so a Windows path's
/// separators survive being put in a string literal.
#[cfg(feature = "builtin-stores")]
fn include_bytes_literal(path: &Path) -> String {
    format!("include_bytes!({:?})", path.to_string_lossy())
}

fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
}
