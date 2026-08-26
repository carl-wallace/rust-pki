//! Caches the graph a run builds when it augments a CBOR store with other material.
//!
//! A validation run that is given intermediates as well as a store folds them together and searches
//! the combined material for partial paths. That search is the expensive part of preparing a run —
//! milliseconds against a small community PKI, but the better part of half a second against the
//! Web PKI's CCADB set — and it produces the same graph every time the inputs are the same. This
//! module keeps the result so that only the first of a series of runs pays for it.
//!
//! **What makes a hit.** The key is a fingerprint of everything the graph depends on: the paths
//! that contributed material, each one's size and modification time, the time of interest, whether
//! webpki anchors were in play, and the settings as serialized. Anything else changing is not a
//! reason to rebuild, and anything in that list changing means the cached graph describes inputs
//! that no longer exist. Size and modification time rather than content: reading every input to
//! decide whether to avoid reading every input would spend most of what the cache saves. The
//! failure mode that leaves is a file replaced within the filesystem's timestamp granularity and at
//! exactly its old length, which is worth the trade here — this is a path-building index, and a run
//! that wants no part of it can delete the folder or set `PITTV3_GRAPH_CACHE` to `off`.
//!
//! **Only augmented graphs are cached.** A run that uses a store alone already has the store's own
//! partial paths and searches nothing, so there is nothing to save; a generate run writes its graph
//! where it was asked to. Both are left alone.

use std::fs;
use std::path::{Path, PathBuf};

use log::{debug, info};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use certval::{CertSource, CertVector, CertificationPathBuilderFormats, CertificationPathSettings};

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

/// The identity of the graph a run would build, or `None` when the run builds no augmented graph
/// and so has nothing worth caching.
///
/// Deliberately conservative about the settings: the whole serialized blob goes into the key rather
/// than the handful of values known to reach path building, so a setting that starts mattering
/// cannot silently reuse a graph built without it. The cost is a missed cache when an unrelated
/// setting changes, which costs exactly what there was before this existed.
pub fn fingerprint(args: &Pittv3Args, cps: &CertificationPathSettings) -> Option<String> {
    if args.generate || (args.ca_folder.is_none() && args.ca_inputs.is_empty()) {
        return None;
    }
    #[cfg(feature = "remote")]
    if args.dynamic_build {
        // The graph grows as URIs are chased, so what pass 0 built is not what the run ends with.
        return None;
    }

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
    hasher.update(args.time_of_interest.to_le_bytes());
    if let Ok(settings) = serde_json::to_string(cps) {
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
    let mut cps = certval::read_settings(&args.settings).ok()?;
    if !cps.0.contains_key(certval::PS_TIME_OF_INTEREST) {
        cps.set_time_of_interest(
            certval::TimeOfInterest::from_unix_secs(args.time_of_interest).ok()?,
        );
    }
    fingerprint(args, &cps)
}

/// The cached graph for `fingerprint`, or `None` when there is not one. Says nothing: a caller that
/// wants the fact recorded should say what it is doing with it.
pub fn cached(fingerprint: &str) -> Option<Vec<u8>> {
    let path = cache_dir()?.join(format!("{fingerprint}.cbor"));
    let bytes = fs::read(&path).ok()?;
    // A truncated or corrupt cache file must not take the run down with it: fall through to
    // building the graph, which is what a miss does anyway.
    if CertSource::new_from_cbor(&bytes).is_err() {
        debug!("Discarding unreadable cached graph at {}", path.display());
        let _ = fs::remove_file(&path);
        return None;
    }
    Some(bytes)
}

/// The cached graph for `fingerprint`, noting in the log that a run reused it.
pub fn load(fingerprint: &str) -> Option<Vec<u8>> {
    let bytes = cached(fingerprint)?;
    info!("Reusing the cached graph for this trust material");
    Some(bytes)
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
/// key, so they cannot be paired with each other's material.
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
