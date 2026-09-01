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
#[cfg(feature = "capi")]
use std::str::FromStr;

#[cfg(feature = "capi")]
use certval::CapiStore;

use certval_stores_core::{serialize_environment, TrustStoreProvider};
use pittv3_gui_lib::settings_store::app_home;
use pittv3_lib::std_utils::cbor_store_to_ders;

/// Where a selectable store's material comes from.
///
/// Two kinds, because webpki-roots is an anchor set certval builds for itself rather than material
/// a provider carries. Making it an entry here instead of a checkbox is not tidying: the selector
/// is single-select, and *combining* anchor sets is the thing to prevent. `--webpki-tas` adds its
/// own `TaSource` and `load_trust_anchors` adds a second one, which is the
/// arrangement that function merges its own two inputs to avoid — two sources sharing an anchor
/// poison its key identifier. webpki-roots being Mozilla's TLS set makes the overlap with the
/// Mozilla entries near total, so that was reachable in one click.
pub(crate) enum StoreSource {
    /// Material linked in from a `certval_stores_*` provider. A function pointer because
    /// `provider()` is not a const fn.
    Provider(fn() -> &'static dyn TrustStoreProvider),
    /// The webpki-roots anchors, reached through the `webpki_tas` argument rather than through a
    /// written store: `TaSource` has no serializer, so there is no CBOR to put on disk.
    Webpki,
    /// Windows certificate stores, reached through the `capi_ta_stores` and `capi_ca_stores`
    /// arguments. Like [`StoreSource::Webpki`] this writes nothing to disk, and for the stronger
    /// reason: the store is live. Materializing it would freeze a snapshot, so a root the user
    /// installed after selecting the store would go unseen until they reselected it.
    #[cfg(feature = "capi")]
    Capi {
        /// Store holding the trust anchors, e.g. `CurrentUser\ROOT`.
        ta: &'static str,
        /// Store holding the intermediates, or `None` for an anchors-only entry.
        ca: Option<&'static str>,
    },
}

/// A trust anchor and CA certificate store pair offered by the store selector, named by the
/// provider environment it comes from.
pub(crate) struct BuiltInStore {
    /// Display name for the store
    pub label: &'static str,
    /// Provider environment, e.g. `NIPR`. Also names the cache folder the store is written to.
    pub env: &'static str,
    /// Where the material comes from
    pub source: StoreSource,
    /// The PKI this store's material comes from, as a noun phrase completing "Trust anchors [and
    /// intermediate CAs] from ___." Only the phrase, because whether the store carries
    /// intermediates is asked of the provider at render time by [`has_ca_store`] — writing it into
    /// the sentence here would let the two disagree.
    pub pki: &'static str,
    /// Anything a user has to know before picking this one, or empty. For a property of the store
    /// that changes what a run does, not for description — the sentence above is the description.
    pub note: &'static str,
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
        source: StoreSource::Provider(certval_stores_nipr::provider),
        pki: "the DoD production PKI on NIPRNet",
        note: "",
    },
    // MOZILLA_ALL rather than MOZILLA_TLS: the intermediate store hangs off the combined
    // environment only, because a large share of the CCADB intermediates chain solely to
    // email-only roots and would be unanchored under the TLS-scoped anchor set.
    BuiltInStore {
        label: "Web PKI (Mozilla roots, TLS + S/MIME, + CCADB intermediates)",
        env: "MOZILLA_ALL",
        source: StoreSource::Provider(certval_stores_mozilla::provider),
        pki: "the Mozilla CA program, covering all purposes it supports",
        note: "",
    },
    // The trust-bit-scoped subsets. These carry no CA store, so paths through an intermediate need
    // one supplied. Which roots belong to each is CCADB policy rather than anything the
    // certificates record, so the split has to come from the provider — it cannot be recovered
    // from the DER of the roots themselves.
    BuiltInStore {
        label: "Web PKI (Mozilla roots, TLS only)",
        env: "MOZILLA_TLS",
        source: StoreSource::Provider(certval_stores_mozilla::provider),
        pki: "the Mozilla CA program, the roots trusted for websites",
        note: "See the CCADB for further details.",
    },
    BuiltInStore {
        label: "Web PKI (Mozilla roots, S/MIME only)",
        env: "MOZILLA_EMAIL",
        source: StoreSource::Provider(certval_stores_mozilla::provider),
        pki: "the Mozilla CA program, the roots trusted for email",
        note: "See the CCADB for further details.",
    },
    // certval's own webpki-roots anchors rather than a provider's material. Kept alongside
    // MOZILLA_TLS deliberately: the two are the same idea from different hands — rustls' snapshot
    // of the Mozilla program against CCADB read directly — and which one a run used is worth being
    // able to say. The blurb is where the difference is stated, since the labels cannot carry it.
    BuiltInStore {
        label: "Web PKI (webpki-roots crate, TLS only)",
        env: "WEBPKI",
        source: StoreSource::Webpki,
        pki: "the webpki-roots crate, rustls' snapshot of the Mozilla program",
        note: "These anchors assert no validity, so anchor validity checking is off for the run.",
    },
    BuiltInStore {
        label: "U.S. Federal PKI (Common Policy CA G2)",
        env: "FPKI",
        source: StoreSource::Provider(certval_stores_fpki::provider),
        pki: "the U.S. Federal PKI",
        note: "Its bridge-era roots are nodes within the PKI, reached by cross-certificate.",
    },
    BuiltInStore {
        label: "U.S. DoD (Purebred development)",
        env: "DEV",
        source: StoreSource::Provider(certval_stores_pbdev::provider),
        pki: "the Purebred development environment",
        note: "Test material: not for judging production certificates.",
    },
    // The Windows stores. Current user first and machine second, because the user's view of a store
    // already includes the machine's entries -- so the first is the broader set despite the
    // narrower-sounding name, and is the one that works without elevation.
    #[cfg(feature = "capi")]
    BuiltInStore {
        label: "Windows certificate store (current user)",
        env: "CAPI_USER",
        source: StoreSource::Capi {
            ta: "CurrentUser\\ROOT",
            ca: Some("CurrentUser\\CA"),
        },
        pki: "this machine's Windows certificate stores, as this user sees them",
        note: "Includes anchors installed for the machine as well as any this user has added.",
    },
    #[cfg(feature = "capi")]
    BuiltInStore {
        label: "Windows certificate store (local machine)",
        env: "CAPI_MACHINE",
        source: StoreSource::Capi {
            ta: "LocalMachine\\ROOT",
            ca: Some("LocalMachine\\CA"),
        },
        pki: "this machine's Windows certificate stores, excluding this user's own additions",
        note: "Requires running as administrator.",
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

    // Nothing to write for the sources a run reaches by argument rather than by path -- webpki,
    // whose anchors the run builds itself, and the Windows stores, which are read live. See
    // [`is_webpki`] and [`capi_stores`], which are what set those arguments.
    let StoreSource::Provider(provider) = store.source else {
        return Ok((None, None));
    };

    let dir = store_home()
        .ok_or_else(|| "no home directory to cache built-in stores in".to_string())?
        .join(store.env);
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

    let serialized = serialize_environment(&[provider()], store.env)
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

/// What an [`export`] wrote, for the message shown when it finishes.
pub(crate) struct Exported {
    /// Folder the material was written to, `<destination>/<env>`
    pub folder: String,
    /// Number of trust anchor DER files written
    pub anchors: usize,
    /// Number of intermediate CA DER files written, unpacked from the CA store
    pub intermediates: usize,
    /// Whether a CA store accompanied the anchors
    pub ca_store: bool,
}

/// A file name for a certificate taken out of a CBOR store, derived from the name the store
/// recorded for it.
///
/// Stores generated from a folder carry the original file names, which are the most useful thing
/// to write back out — but they are a store's data, not this app's, so they are treated as
/// untrusted: only the last component is used, anything outside a conservative set of characters
/// becomes `_`, and a name that survives all that as empty falls back to the index. `seen` keeps
/// two certificates recorded under one name from overwriting each other.
fn der_file_name(stored: &str, index: usize, seen: &mut Vec<String>) -> String {
    let base = stored.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches(['.', '_']).to_string();

    let mut name = if cleaned.is_empty() {
        format!("cert_{index}.der")
    } else if [".der", ".cer", ".crt"]
        .iter()
        .any(|ext| cleaned.to_ascii_lowercase().ends_with(ext))
    {
        cleaned
    } else {
        format!("{cleaned}.der")
    };

    if seen.contains(&name) {
        name = format!("{index}_{name}");
    }
    seen.push(name.clone());
    name
}

/// Writes the material behind the built-in store at `index` into `dest`, so the certificates a run
/// validated against can be inspected, archived or handed to another tool.
///
/// The material is linked into the binary and otherwise reachable only through a run, which is the
/// reason this exists: there is no file to open. Everything lands under `<dest>/<env>` rather than
/// in `dest` itself, so exporting two stores to the same place cannot interleave them.
///
/// Anchors are written as DER, one file per root, named for the label
/// [`serialize_environment`] gives that anchor — so a certificate named in a report or a log is
/// the file of the same name here. The two stores are written as the CBOR a run consumes.
/// Intermediates are not exploded into DER: that would mean decoding the CA store, and this crate
/// deliberately reaches certval only through `pittv3_lib`. The Diagnostics view already dumps
/// buffers from a CBOR store, and it will happily take the `ca.cbor` written here.
pub(crate) fn export(index: usize, dest: &Path) -> Result<Exported, String> {
    if index == CUSTOM {
        return Err("no built-in store is selected".to_string());
    }
    let store = STORES
        .get(index - 1)
        .ok_or_else(|| format!("no built-in store at index {index}"))?;

    // No export for webpki: its anchors live in the run rather than in material this app holds, so
    // there is nothing here to copy out. The button is hidden for it rather than failing here.
    let StoreSource::Provider(provider) = store.source else {
        return Err(format!("{} has no material to export", store.label));
    };

    let dir = dest.join(store.env);
    let tas = dir.join("tas");
    fs::create_dir_all(&tas).map_err(|e| format!("cannot create {}: {e}", tas.display()))?;

    let serialized = serialize_environment(&[provider()], store.env)
        .map_err(|e| format!("failed to serialize the {} store: {e:?}", store.env))?;
    fs::write(dir.join("ta.cbor"), &serialized.ta_cbor)
        .map_err(|e| format!("cannot write ta.cbor: {e}"))?;
    if let Some(bytes) = &serialized.ca_cbor {
        fs::write(dir.join("ca.cbor"), bytes).map_err(|e| format!("cannot write ca.cbor: {e}"))?;
    }

    // The provider hands over the roots as DER already, so nothing here parses a certificate.
    // Duplicates are dropped for the same reason serialize_environment drops them: a root serving
    // two environments is one anchor, and writing it twice would misreport the count.
    let mut anchors = 0;
    let mut seen: Vec<&[u8]> = Vec::new();
    for entry in provider().entries() {
        if entry.env != store.env {
            continue;
        }
        for (i, der) in entry.roots.iter().enumerate() {
            if seen.contains(der) {
                continue;
            }
            seen.push(der);
            let name = format!("{}_root_{i}.der", store.env);
            fs::write(tas.join(&name), der).map_err(|e| format!("cannot write {name}: {e}"))?;
            anchors += 1;
        }
    }

    // The CA store unpacked into loose certificates. The CBOR beside it is what a run consumes, but
    // it is opaque: this is the half a user can read, hand to another tool, or point a CA Folder at
    // — which is the only way to add this material to a run that has already selected a store,
    // since the CBOR arguments hold one path each and the selection occupies them.
    let mut intermediates = 0;
    if let Some(bytes) = &serialized.ca_cbor {
        let certs = cbor_store_to_ders(bytes)?;
        if !certs.is_empty() {
            let cas = dir.join("cas");
            fs::create_dir_all(&cas)
                .map_err(|e| format!("cannot create {}: {e}", cas.display()))?;
            let mut names = Vec::with_capacity(certs.len());
            for (i, (stored, der)) in certs.iter().enumerate() {
                let name = der_file_name(stored, i, &mut names);
                fs::write(cas.join(&name), der).map_err(|e| format!("cannot write {name}: {e}"))?;
                intermediates += 1;
            }
        }
    }

    Ok(Exported {
        folder: path_string(&dir)?,
        anchors,
        intermediates,
        ca_store: serialized.ca_cbor.is_some(),
    })
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
    STORES
        .get(index - 1)
        .is_some_and(|store| match store.source {
            StoreSource::Provider(provider) => provider()
                .entries()
                .iter()
                .any(|e| e.env == store.env && e.cert_store_cbor.is_some()),
            // webpki-roots is anchors and nothing else
            StoreSource::Webpki => false,
            #[cfg(feature = "capi")]
            StoreSource::Capi { ca, .. } => ca.is_some(),
        })
}

/// The CAPI stores the entry at `index` names, as `(trust anchors, intermediates)` arguments.
/// Empty vectors for every other kind of entry, so a caller can assign them unconditionally.
#[cfg(feature = "capi")]
pub(crate) fn capi_stores(index: usize) -> (Vec<String>, Vec<String>) {
    if index == CUSTOM {
        return (vec![], vec![]);
    }
    match STORES.get(index - 1).map(|s| &s.source) {
        Some(StoreSource::Capi { ta, ca }) => (
            vec![ta.to_string()],
            ca.iter().map(|c| c.to_string()).collect(),
        ),
        _ => (vec![], vec![]),
    }
}

/// Whether the entry at `index` can be used by this process.
///
/// False only for a machine store that this process cannot open, which is the usual case when it
/// is not elevated. Every other kind of entry is always usable, so this is safe to ask of any
/// index.
///
/// Opening a store is cheap but not free, and this is asked once per entry per render; a caller
/// rendering often should cache the answer.
pub(crate) fn is_accessible(index: usize) -> bool {
    #[cfg(feature = "capi")]
    {
        if index != CUSTOM {
            if let Some(StoreSource::Capi { ta, .. }) = STORES.get(index - 1).map(|s| &s.source) {
                return CapiStore::from_str(ta).is_ok_and(|s| s.is_accessible());
            }
        }
    }
    let _ = index;
    true
}

/// Whether the store at `index` is the webpki-roots anchor set, which a run reaches through the
/// `webpki_tas` argument rather than through a path. False for [`CUSTOM`].
///
/// This is the whole of what selecting it does, and it is why the argument no longer has a checkbox
/// of its own: as a selection it cannot be combined with another anchor set, which is what the
/// checkbox allowed.
pub(crate) fn is_webpki(index: usize) -> bool {
    if index == CUSTOM {
        return false;
    }
    STORES
        .get(index - 1)
        .is_some_and(|store| matches!(store.source, StoreSource::Webpki))
}

/// Recovers the store selection from a saved trust anchor CBOR path, so a run restores the store
/// that produced it rather than reopening as a custom path into the cache folder.
///
/// This is a path comparison only — it does not read or write the cache — so it answers the same
/// way whether or not the material has been written out yet.
pub(crate) fn selection_for(
    ta_cbor: &Option<String>,
    webpki_tas: bool,
    capi_ta_stores: &[String],
) -> usize {
    // The webpki entry writes no path, so the saved argument is the only trace of it.
    if webpki_tas {
        if let Some(i) = STORES
            .iter()
            .position(|s| matches!(s.source, StoreSource::Webpki))
        {
            return i + 1;
        }
    }
    // Same for the Windows entries, which are read live rather than written out. Matched on the
    // anchor store alone: it is what distinguishes the two entries, and a settings file naming a
    // store no entry offers falls through to Custom rather than selecting the wrong one.
    #[cfg(feature = "capi")]
    if let Some(saved) = capi_ta_stores.first() {
        if let Some(i) = STORES.iter().position(
            |s| matches!(s.source, StoreSource::Capi { ta, .. } if ta.eq_ignore_ascii_case(saved)),
        ) {
            return i + 1;
        }
    }
    let _ = capi_ta_stores;
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
            let StoreSource::Provider(provider) = store.source else {
                continue; // webpki carries no provider to resolve against
            };
            let entries = provider().entries();
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
            let StoreSource::Provider(provider) = store.source else {
                // The entries a run reaches by argument: the webpki anchor set it builds itself,
                // and the Windows stores it reads live. Nothing is written for either, and the
                // argument is the whole of what selecting one does. They differ in whether a CA
                // store is claimed — webpki is anchors alone, a Windows entry names both halves —
                // so that is asked of the source rather than asserted away.
                #[cfg(feature = "capi")]
                let names_a_ca_store =
                    matches!(store.source, StoreSource::Capi { ca: Some(_), .. });
                #[cfg(not(feature = "capi"))]
                let names_a_ca_store = false;

                assert!(is_webpki(selection) || names_a_ca_store || !has_ca_store(selection));
                assert_eq!(has_ca_store(selection), names_a_ca_store);
                assert_eq!(materialize(selection).unwrap(), (None, None));
                continue;
            };
            let serialized = serialize_environment(&[provider()], store.env)
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
        assert_eq!(selection_for(&None, false, &[]), CUSTOM);
        assert_eq!(
            selection_for(&Some("/some/where/ta.cbor".to_string()), false, &[]),
            CUSTOM
        );
    }

    /// An export is only worth offering if what it writes can be used elsewhere: the CBOR has to
    /// load as a store, and each anchor has to be a certificate another tool can parse. FPKI
    /// because it is the smallest environment — the mechanism is the same for all of them, and
    /// MOZILLA_ALL would have the test writing a great many files to prove the same point.
    #[test]
    fn export_writes_usable_material() {
        let dir = tempfile::tempdir().unwrap();
        let selection = STORES.iter().position(|s| s.env == "FPKI").unwrap() + 1;

        let exported = export(selection, dir.path()).unwrap();
        let out = dir.path().join("FPKI");

        let ta = TaSource::new_from_cbor(&fs::read(out.join("ta.cbor")).unwrap())
            .expect("the exported TA store does not load");
        assert!(!ta.is_empty());
        assert_eq!(
            out.join("ca.cbor").is_file(),
            exported.ca_store,
            "the reported CA store and the file on disk disagree"
        );

        let ders: Vec<PathBuf> = fs::read_dir(out.join("tas"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert!(exported.anchors > 0, "exported no anchors");
        assert_eq!(exported.anchors, ders.len(), "reported more than it wrote");
        for der in &ders {
            let bytes = fs::read(der).unwrap();
            certval::parse_cert(&bytes, der.to_str().unwrap())
                .unwrap_or_else(|e| panic!("{} is not a certificate: {e:?}", der.display()));
        }
    }

    /// An environment that carries intermediates unpacks them too, which is the half a user can
    /// point another run at: the CBOR beside them holds the same certificates but nothing except
    /// this app can read it, and the CBOR arguments hold one path each.
    #[test]
    fn export_unpacks_the_ca_store_into_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let selection = STORES.iter().position(|s| s.env == "NIPR").unwrap() + 1;

        let exported = export(selection, dir.path()).unwrap();
        let out = dir.path().join("NIPR");

        assert!(exported.ca_store, "NIPR is expected to carry intermediates");
        assert!(exported.intermediates > 0);

        let ders: Vec<PathBuf> = fs::read_dir(out.join("cas"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(exported.intermediates, ders.len());

        // What was unpacked has to be the store's own contents, certificate for certificate
        let cbor = fs::read(out.join("ca.cbor")).unwrap();
        let ca = CertSource::new_from_cbor(&cbor).unwrap();
        assert_eq!(ca.get_buffers().len(), ders.len());
        for der in &ders {
            let bytes = fs::read(der).unwrap();
            certval::parse_cert(&bytes, der.to_str().unwrap())
                .unwrap_or_else(|e| panic!("{} is not a certificate: {e:?}", der.display()));
        }
    }

    /// Exporting is offered for built-in stores alone, so asking for a custom one is a caller
    /// error rather than an empty folder that looks like a successful export. Same for webpki,
    /// whose anchors this app never holds — the button is hidden, and the call refuses.
    #[test]
    fn export_refuses_what_it_cannot_write() {
        let dir = tempfile::tempdir().unwrap();
        assert!(export(CUSTOM, dir.path()).is_err());
        assert!(export(STORES.len() + 1, dir.path()).is_err());

        let webpki = STORES.iter().position(is_webpki_source).unwrap() + 1;
        assert!(export(webpki, dir.path()).is_err());
    }

    /// Selecting webpki has to survive a restart, and it is the one selection with no path to
    /// recover from: the saved `webpki_tas` argument is its only trace. The pairing also has to be
    /// exclusive — recovering it must not depend on a TA CBOR path being absent, since a stale one
    /// could still be saved alongside.
    #[test]
    fn webpki_recovers_from_the_saved_argument() {
        let webpki = STORES.iter().position(is_webpki_source).unwrap() + 1;

        assert_eq!(selection_for(&None, true, &[]), webpki);
        assert_eq!(
            selection_for(&Some("/some/where/ta.cbor".to_string()), true, &[]),
            webpki
        );
        assert!(is_webpki(webpki));
        assert!(!is_webpki(CUSTOM));
    }

    fn is_webpki_source(store: &BuiltInStore) -> bool {
        matches!(store.source, StoreSource::Webpki)
    }

    /// A selection has to survive the round trip through the saved arguments, which carry the path
    /// the store was written to rather than the selection itself.
    #[test]
    fn a_written_store_path_recovers_its_selection() {
        let Some(home) = store_home() else {
            return; // no home directory on this host; nothing to recover a path against
        };
        for (i, store) in STORES.iter().enumerate() {
            if !is_written_out(store) {
                continue; // never written, so there is no path to recover it from
            }
            let path = home.join(store.env).join("ta.cbor");
            let saved = Some(path.to_str().unwrap().to_string());
            assert_eq!(
                selection_for(&saved, false, &[]),
                i + 1,
                "{} did not round trip",
                store.label
            );
        }
    }

    /// Whether a selection leaves a path behind for [`selection_for`] to recover it from. False for
    /// the entries a run reaches by argument instead.
    fn is_written_out(store: &BuiltInStore) -> bool {
        matches!(store.source, StoreSource::Provider(_))
    }

    /// The Windows entries round trip through their own argument rather than through a path, and
    /// each has to recover itself and not the other — the two differ only in the location.
    #[cfg(feature = "capi")]
    #[test]
    fn a_capi_store_recovers_its_selection() {
        for (i, store) in STORES.iter().enumerate() {
            let StoreSource::Capi { ta, .. } = store.source else {
                continue;
            };
            let saved = vec![ta.to_string()];
            assert_eq!(
                selection_for(&None, false, &saved),
                i + 1,
                "{} did not round trip",
                store.label
            );
        }
        // A store no entry offers is a custom selection, not the nearest entry.
        assert_eq!(
            selection_for(&None, false, &["CurrentUser\\MY".to_string()]),
            CUSTOM
        );
    }

    /// Only the machine entries are ever gated, and whether they are gated depends on how this
    /// process was launched — so the invariant that can be asserted either way is that everything
    /// else stays usable.
    #[test]
    fn only_machine_stores_can_be_inaccessible() {
        assert!(is_accessible(CUSTOM));
        for (i, store) in STORES.iter().enumerate() {
            if is_accessible(i + 1) {
                continue;
            }
            assert!(
                store.label.contains("local machine"),
                "{} was reported inaccessible",
                store.label
            );
        }
    }
}
