//! Built-in trust stores, sourced from the certval trust store providers.
//!
//! Before this existed the desktop app could only be pointed at trust material a user had
//! assembled by hand, and it took the two halves in different shapes: a folder of DER trust
//! anchors, but a CBOR store for the intermediates. A provider's on-disk layout does not
//! reliably answer that — `roots/mozilla` holds every root Mozilla trusts for either purpose
//! while `MOZILLA_TLS` and `MOZILLA_EMAIL` are subsets of it, and `certval_stores_fpki` carries
//! a legacy root with no CA store beside it. The provider contract does answer it, so the
//! catalogue below is expressed in provider environments and the material is taken from
//! [`serialize_environment`], the same call `pittv3-wasm`'s build script makes.
//!
//! The bytes are linked in rather than fetched, since a desktop app has nowhere to fetch them
//! from, and are written out on selection because [`options_std`](pittv3_lib::options_std) is
//! path-shaped: it names its inputs by path, and unifying that with the byte-oriented path in
//! `pittv3-gui-lib` is gated on work that has not happened yet. `store_home` is therefore a
//! cache, not user data — it is rewritten from the linked-in material whenever that differs.

use std::fs;
use std::path::{Path, PathBuf};

use certval_stores_core::{serialize_environment, TrustStoreProvider};
use pittv3_gui_lib::settings_store::app_home;

/// A trust anchor and CA certificate store pair offered by the store selector, named by the
/// provider environment it comes from.
pub(crate) struct BuiltInStore {
    /// Display name for the store
    pub label: &'static str,
    /// Provider environment, e.g. `NIPR`. Also names the cache folder the store is written to.
    pub env: &'static str,
    /// The provider serving `env`. A function pointer because `provider()` is not a const fn.
    pub provider: fn() -> &'static dyn TrustStoreProvider,
}

/// Value of the store selector meaning "none of the below": the TA and CA inputs are used as
/// given, which is how the app behaved before there were built-in stores.
pub(crate) const CUSTOM: usize = 0;

/// Stores available for selection in the UI. The first three match what the browser frontend
/// offers, deliberately: the same product should not present a different trust catalogue
/// depending on which frontend it is wearing.
pub(crate) const STORES: &[BuiltInStore] = &[
    BuiltInStore {
        label: "U.S. DoD (NIPR production)",
        env: "NIPR",
        provider: certval_stores_nipr::provider,
    },
    // MOZILLA_ALL rather than MOZILLA_TLS: the intermediate store hangs off the combined
    // environment only, because a large share of the CCADB intermediates chain solely to
    // email-only roots and would be unanchored under the TLS-scoped anchor set.
    BuiltInStore {
        label: "Web PKI (Mozilla roots, TLS + S/MIME, + CCADB intermediates)",
        env: "MOZILLA_ALL",
        provider: certval_stores_mozilla::provider,
    },
    // The trust-bit-scoped subsets. These carry no CA store, so paths through an intermediate
    // need one supplied — but they are also the two that cannot be assembled by hand at all,
    // since which trust bits a root carries is CCADB policy the DER does not record.
    BuiltInStore {
        label: "Web PKI (Mozilla roots, TLS only)",
        env: "MOZILLA_TLS",
        provider: certval_stores_mozilla::provider,
    },
    BuiltInStore {
        label: "Web PKI (Mozilla roots, S/MIME only)",
        env: "MOZILLA_EMAIL",
        provider: certval_stores_mozilla::provider,
    },
    BuiltInStore {
        label: "U.S. Federal PKI (Common Policy CA G2)",
        env: "FPKI",
        provider: certval_stores_fpki::provider,
    },
    BuiltInStore {
        label: "U.S. DoD (Purebred development)",
        env: "DEV",
        provider: certval_stores_pbdev::provider,
    },
];

/// Label for the selector entry at [`CUSTOM`].
pub(crate) const CUSTOM_LABEL: &str = "Custom (use the paths below)";

/// The folder built-in stores are written to, `stores` beneath the application home.
fn store_home() -> Option<PathBuf> {
    Some(app_home()?.join("stores"))
}

/// Writes the material for the store at `index` and returns the paths to its trust anchor store
/// and, where the environment has one, its CA store. `Ok((None, None))` for [`CUSTOM`].
///
/// A store without a CA half is not an error: an anchors-only environment is a legitimate
/// selection, and the intermediates can come from the CA CBOR field or from dynamic building.
pub(crate) fn materialize(index: usize) -> Result<(Option<String>, Option<String>), String> {
    if index == CUSTOM {
        return Ok((None, None));
    }
    let store = STORES
        .get(index - 1)
        .ok_or_else(|| format!("no built-in store at index {index}"))?;

    let dir = store_home()
        .ok_or_else(|| "no home directory to cache built-in stores in".to_string())?
        .join(store.env);
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

    let serialized = serialize_environment(&[(store.provider)()], store.env)
        .map_err(|e| format!("failed to serialize the {} store: {e:?}", store.env))?;

    let ta_path = dir.join("ta.cbor");
    write_if_changed(&ta_path, &serialized.ta_cbor)?;

    let ca_path = match serialized.ca_cbor {
        Some(bytes) => {
            let p = dir.join("ca.cbor");
            write_if_changed(&p, &bytes)?;
            Some(path_string(&p)?)
        }
        // A CA store written by an earlier version of this app, or by an environment that used
        // to carry one, would otherwise be picked up by a later run that no longer wants it.
        None => {
            let stale = dir.join("ca.cbor");
            if stale.exists() {
                let _ = fs::remove_file(&stale);
            }
            None
        }
    };

    Ok((Some(path_string(&ta_path)?), ca_path))
}

/// Whether the store at `index` carries intermediate CA certificates as well as trust anchors.
/// False for [`CUSTOM`] and for an anchors-only environment.
///
/// Asked of the provider rather than recorded in the catalogue, so the UI cannot claim a CA store
/// the environment has stopped carrying (or miss one it has gained).
pub(crate) fn has_ca_store(index: usize) -> bool {
    if index == CUSTOM {
        return false;
    }
    STORES.get(index - 1).is_some_and(|store| {
        (store.provider)()
            .entries()
            .iter()
            .any(|e| e.env == store.env && e.cert_store_cbor.is_some())
    })
}

/// Recovers the store selection from a saved trust anchor CBOR path, so a run restores the store
/// that produced it rather than reopening as a custom path into the cache folder.
///
/// This is a path comparison only — it does not read or write the cache — so it answers the same
/// way whether or not the material has been written out yet.
pub(crate) fn selection_for(ta_cbor: &Option<String>) -> usize {
    let Some(ta_cbor) = ta_cbor else {
        return CUSTOM;
    };
    let Some(home) = store_home() else {
        return CUSTOM;
    };
    STORES
        .iter()
        .position(|s| home.join(s.env).join("ta.cbor") == Path::new(ta_cbor))
        .map_or(CUSTOM, |i| i + 1)
}

/// Write `bytes` only if the file does not already hold exactly them, so a selection that has
/// not changed since the last run does not rewrite several megabytes.
fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if fs::read(path).is_ok_and(|existing| existing == bytes) {
        return Ok(());
    }
    fs::write(path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("{} is not valid UTF-8", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use certval::{CertSource, CertVector, TaSource};

    /// An environment named here but not served by its provider fails at run time with
    /// `Unrecognized` and nothing else — the catalogue is the only place the two are tied
    /// together, and a rename upstream would not otherwise be noticed here.
    #[test]
    fn every_catalogue_entry_resolves_against_its_provider() {
        for store in STORES {
            let entries = (store.provider)().entries();
            assert!(
                entries.iter().any(|e| e.env == store.env),
                "{} names environment {}, which its provider does not serve; it serves {:?}",
                store.label,
                store.env,
                entries.iter().map(|e| e.env).collect::<Vec<_>>()
            );
        }
    }

    /// Environment labels must be unique across the providers loaded together, and a duplicate
    /// here would also make two selector entries indistinguishable in the cache folder, since it
    /// is named after the environment.
    #[test]
    fn environments_are_distinct() {
        let mut envs: Vec<&str> = STORES.iter().map(|s| s.env).collect();
        envs.sort_unstable();
        let count = envs.len();
        envs.dedup();
        assert_eq!(count, envs.len(), "duplicate environment in the catalogue");
    }

    /// What the selector produces has to be what `options_std` reads back: a trust anchor store it
    /// can load, holding anchors, and a CA store where one is claimed.
    #[test]
    fn every_store_serializes_into_loadable_material() {
        for (i, store) in STORES.iter().enumerate() {
            let selection = i + 1;
            let serialized = serialize_environment(&[(store.provider)()], store.env)
                .unwrap_or_else(|e| panic!("{} failed to serialize: {e:?}", store.label));

            let ta = TaSource::new_from_cbor(&serialized.ta_cbor)
                .unwrap_or_else(|e| panic!("{} wrote an unloadable TA store: {e:?}", store.label));
            assert!(!ta.is_empty(), "{} anchors nothing", store.label);

            assert_eq!(
                serialized.ca_cbor.is_some(),
                has_ca_store(selection),
                "{} disagrees with what the UI says it carries",
                store.label
            );
            if let Some(ca_cbor) = serialized.ca_cbor {
                let ca = CertSource::new_from_cbor(&ca_cbor).unwrap_or_else(|e| {
                    panic!("{} wrote an unloadable CA store: {e:?}", store.label)
                });
                assert!(
                    !ca.is_empty(),
                    "{} claims a CA store that is empty",
                    store.label
                );
            }
        }
    }

    #[test]
    fn custom_selects_nothing() {
        assert!(!has_ca_store(CUSTOM));
        assert_eq!(materialize(CUSTOM).unwrap(), (None, None));
        assert_eq!(selection_for(&None), CUSTOM);
        assert_eq!(
            selection_for(&Some("/some/where/ta.cbor".to_string())),
            CUSTOM
        );
    }

    /// A selection has to survive the round trip through the saved arguments, which carry the path
    /// the store was written to rather than the selection itself.
    #[test]
    fn a_written_store_path_recovers_its_selection() {
        let Some(home) = store_home() else {
            return; // no home directory on this host; nothing to recover a path against
        };
        for (i, store) in STORES.iter().enumerate() {
            let path = home.join(store.env).join("ta.cbor");
            let saved = Some(path.to_str().unwrap().to_string());
            assert_eq!(
                selection_for(&saved),
                i + 1,
                "{} did not round trip",
                store.label
            );
        }
    }
}
