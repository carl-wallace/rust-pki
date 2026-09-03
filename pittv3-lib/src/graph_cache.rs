//! Caches the graph a run builds when it augments a CBOR store with other certificates.
//!
//! A validation run that is given intermediates as well as a store folds them together and searches
//! the combined PKI for partial paths. That search is the expensive part of preparing a run —
//! milliseconds against a small community PKI, but the better part of half a second against the
//! Web PKI's CCADB set — and it produces the same graph every time the inputs are the same. This
//! module keeps the result so that only the first of a series of runs pays for it.
//!
//! The key is a fingerprint of everything the graph depends on: the paths that contributed
//! certificates, each one's size and modification time, whether webpki anchors were in play, and the
//! settings as serialized apart from the time of interest. Anything else changing is not a reason to
//! rebuild, and anything in that list changing means the cached graph describes inputs that no
//! longer exist. The time of interest is left out because it is normally "now": keying on it meant
//! the key never repeated, so entries were written and never read.
//! Size and modification time rather than content: reading every input to decide whether to avoid
//! reading every input would spend most of what the cache saves. The failure mode that leaves is a
//! file replaced within the filesystem's timestamp granularity and at exactly its old length, which
//! is worth the trade here — this is a path-building index, and a run that wants no part of it can
//! delete the folder or set `PITTV3_GRAPH_CACHE` to `off`.
//!
//! Only augmented graphs are cached. A run that uses a store alone already has the store's own
//! partial paths and searches nothing, so there is nothing to save; a generate run writes its graph
//! where it was asked to. Both are left alone.

use std::fs;
use std::path::{Path, PathBuf};

use log::{debug, info};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use certval::{
    CertSource, CertVector, CertificationPathBuilderFormats, CertificationPathSettings,
    PS_TIME_OF_INTEREST,
};

use crate::args::Pittv3Args;

/// Environment variable that relocates the cache, or disables it entirely when set to `off`.
const CACHE_ENV: &str = "PITTV3_GRAPH_CACHE";

/// Folder the cached graphs live in, `~/.pittv3/graphs` unless [`CACHE_ENV`] says otherwise.
/// `None` when caching is off or there is no home directory to put it in.
fn cache_dir() -> Option<PathBuf> {
    match std::env::var(CACHE_ENV) {
        Ok(v) if v.eq_ignore_ascii_case("off") => None,
        Ok(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .ok()?;
            Some(Path::new(&home).join(".pittv3").join("graphs"))
        }
    }
}

/// The folder cached graphs live in, as a string, or empty when caching is off or there is no home
/// directory. For a frontend offering to empty it: the cache is written on every run whose key is
/// new and nothing removes an entry, so it grows until someone clears it.
#[cfg(feature = "std")]
pub fn cache_folder() -> String {
    cache_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Folds one input path into `hasher`: the path itself, and the size and modification time of every
/// file it names or contains. A path that cannot be read contributes its name alone, which still
/// distinguishes it from a run that did not name it.
fn hash_path(hasher: &mut Sha256, label: &str, path: &str) {
    hasher.update(label.as_bytes());
    hasher.update(path.as_bytes());
    for entry in WalkDir::new(path).sort_by_file_name() {
        let Ok(entry) = entry else { continue };
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            continue;
        }
        hasher.update(entry.path().to_string_lossy().as_bytes());
        hasher.update(meta.len().to_le_bytes());
        if let Ok(modified) = meta.modified() {
            if let Ok(since) = modified.duration_since(std::time::UNIX_EPOCH) {
                hasher.update(since.as_nanos().to_le_bytes());
            }
        }
    }
}

/// The identity of the graph a run would build, or `None` when the run builds no augmented graph.
///
/// `None` for a generate run, which rewrites its own CA input while it runs, so nothing that can be
/// named before it starts describes what it ends up with. `None` too for a run given a store and
/// nothing else, which already has that store's partial paths and searches nothing, so there is no
/// result to identify.
///
/// Names the graph for both the copy on disk and the one a caller keeps in memory — see
/// [`PreparedGraph`](crate::prepared_graph::PreparedGraph). Deliberately one key: the two hold the
/// same graph at different stages of preparation, and a second key would differ only by the time of
/// interest, which cannot be in this one and has nothing to add to the other. Excluded because it is
/// normally "now", so keying on it meant the key never repeated and the cache was written but never
/// read; and nothing needs it, because the run that has no file to fall back on is the store-only
/// run, which is the run this refuses to key at all.
///
/// Deliberately conservative about the settings: the whole serialized blob goes into the key rather
/// than the handful of values known to reach path building, so a setting that starts mattering
/// cannot silently reuse a graph built without it. The cost is a missed cache when an unrelated
/// setting changes, which costs exactly what there was before this existed.
pub fn saved_graph_fingerprint(
    args: &Pittv3Args,
    cps: &CertificationPathSettings,
) -> Option<String> {
    if args.generate || (args.ca_folder.is_none() && args.ca_inputs.is_empty()) {
        return None;
    }
    // Dynamic building is cached like the rest. The graph does grow as URIs are chased, but the only
    // thing written is pass 0's graph -- `graph_cache::store` is guarded on `0 == pass`, before any
    // chasing has added anything -- so the artifact matches the key: the graph built from the named
    // inputs. Later passes rebuild in memory and are never stored. Refusing to key a dynamic run
    // meant the desktop app, which builds dynamically by default, never cached anything at all.

    let mut hasher = Sha256::new();
    hasher.update(b"pittv3 graph v1");
    // Each pool is folded in after the singular argument it generalizes, and in the order the run
    // will read it. Order-sensitively, on purpose: two orders name the same certificates and would
    // build the same graph, but telling them apart costs only a rebuild while conflating them would
    // hand back a graph the caller never asked for. An empty pool contributes nothing, so a run that
    // names no pool keys exactly as it did before pools existed.
    for path in args.ca_folder.iter().chain(args.ca_inputs.iter()) {
        hash_path(&mut hasher, "ca", path);
    }
    if let Some(cbor) = &args.cbor {
        hash_path(&mut hasher, "cbor", cbor);
    }
    for path in args.ta_folder.iter().chain(args.ta_inputs.iter()) {
        hash_path(&mut hasher, "ta", path);
    }
    if let Some(ta_cbor) = &args.ta_cbor {
        hash_path(&mut hasher, "ta_cbor", ta_cbor);
    }
    #[cfg(feature = "webpki")]
    hasher.update([u8::from(args.webpki_tas)]);
    // The time of interest is deliberately NOT part of the key, and it has to be dropped in two
    // places to stay out: it is not hashed directly here, and it is removed from the settings before
    // they are, because the caller sets it into them just before asking for a fingerprint. What the
    // graph is built from is the PKI, and a change there is caught by hashing each input's size and
    // modification time.
    let mut keyed = cps.clone();
    keyed.0.remove(PS_TIME_OF_INTEREST);
    if let Ok(settings) = serde_json::to_string(&keyed) {
        hasher.update(settings.as_bytes());
    }

    let digest = hasher.finalize();
    Some(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// The fingerprint a run driven by `args` would use, reading the settings that run would read.
///
/// For callers outside a run — the desktop's graph export asks which graph the form in front of it
/// keys to, and computing that a second way would answer a different question.
pub fn fingerprint_for_args(args: &Pittv3Args) -> Option<String> {
    // No need to settle a time of interest first: the key excludes it either way, so the settings
    // as read key identically to the settings a run adjusts.
    let cps = certval::read_settings(&args.settings).ok()?;
    saved_graph_fingerprint(args, &cps)
}

/// Reads the cached graph for `fingerprint` and deserializes it once, returning both forms.
///
/// Once, because the two are the same work: proving the file is not truncated or corrupt means
/// parsing it, and parsing it is what a run does with it anyway. Returning the bytes alongside the
/// source is what lets the caller that wants to hand the file on -- an export -- have them without
/// a second pass over several megabytes.
fn read_cached(fingerprint: &str) -> Option<(Vec<u8>, CertSource)> {
    let path = cache_dir()?.join(format!("{fingerprint}.cbor"));
    let bytes = fs::read(&path).ok()?;
    // A truncated or corrupt cache file must not take the run down with it: fall through to
    // building the graph, which is what a miss does anyway.
    match CertSource::new_from_cbor(&bytes) {
        Ok(source) => Some((bytes, source)),
        Err(_) => {
            debug!("Discarding unreadable cached graph at {}", path.display());
            let _ = fs::remove_file(&path);
            None
        }
    }
}

/// The cached graph for `fingerprint` as the bytes it is stored as, or `None` when there is not one.
/// Says nothing: a caller that wants the fact recorded should say what it is doing with it.
///
/// For handing the artifact on rather than running against it — the desktop's graph export. A run
/// wants [`load`], which does not make it deserialize what this already deserialized.
pub fn cached(fingerprint: &str) -> Option<Vec<u8>> {
    read_cached(fingerprint).map(|(bytes, _)| bytes)
}

/// The cached graph for `fingerprint` as a source ready to be initialized, noting in the log that a
/// run reused it.
pub fn load(fingerprint: &str) -> Option<CertSource> {
    let (_, source) = read_cached(fingerprint)?;
    info!("Reusing the cached graph for this PKI");
    Some(source)
}

/// The cached trust anchors that go with the graph for `fingerprint`, or `None` when there are not
/// any. In the same shape a trust anchor CBOR store takes, so a consumer reads it with
/// `TaSource::new_from_cbor`.
pub fn cached_anchors(fingerprint: &str) -> Option<Vec<u8>> {
    let path = cache_dir()?.join(format!("{fingerprint}.ta.cbor"));
    fs::read(&path).ok()
}

/// Saves the anchors a run assembled alongside its graph.
///
/// The graph is only half of an environment: partial paths terminate at anchors, and the anchors
/// live in a [`TaSource`](certval::TaSource) that never enters the [`CertSource`] — so a graph
/// exported on its own describes paths to certificates it does not carry. Caching both means what
/// is handed out is the whole of what the run validated against, and the two are written under one
/// key, so they cannot be paired with each other's PKI.
pub fn store_anchors(fingerprint: &str, anchors: Vec<certval::CertFile>) {
    let Some(dir) = cache_dir() else { return };
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    // A trust anchor store on disk is a serialized CertSource holding the anchors, which is what
    // `serialize_environment` writes and `TaSource::new_from_cbor` reads.
    let mut as_source = CertSource::new();
    for cf in anchors {
        as_source.push(cf);
    }
    let bytes = match as_source.serialize(CertificationPathBuilderFormats::Cbor) {
        Ok(bytes) => bytes,
        Err(e) => {
            debug!("Cannot serialize the trust anchors for caching: {e:?}");
            return;
        }
    };
    let path = dir.join(format!("{fingerprint}.ta.cbor"));
    if let Err(e) = fs::write(&path, &bytes) {
        debug!("Cannot write the cached anchors {}: {e}", path.display());
    }
}

/// Saves `cert_source`'s graph under `fingerprint`. Failure is logged and otherwise ignored: a
/// cache that cannot be written costs time, not correctness.
pub fn store(fingerprint: &str, cert_source: &CertSource) {
    let Some(dir) = cache_dir() else { return };
    if let Err(e) = fs::create_dir_all(&dir) {
        debug!(
            "Cannot create the graph cache folder {}: {e}",
            dir.display()
        );
        return;
    }
    let bytes = match cert_source.serialize(CertificationPathBuilderFormats::Cbor) {
        Ok(bytes) => bytes,
        Err(e) => {
            debug!("Cannot serialize the graph for caching: {e:?}");
            return;
        }
    };
    let path = dir.join(format!("{fingerprint}.cbor"));
    match fs::write(&path, &bytes) {
        Ok(()) => info!("Cached the graph at {}", path.display()),
        Err(e) => debug!("Cannot write the cached graph {}: {e}", path.display()),
    }
}
