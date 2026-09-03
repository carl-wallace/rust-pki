//! The graph a run prepared, kept in memory so the next run over the same PKI does not perform
//! duplicative work.
//!
//! [`graph_cache`](crate::graph_cache) saves a map of a given PKI, so a second run against for the
//! same PKI can reuse it without having to rebuild the graph. However, this serialized may cannot
//! save the work of turning those bytes back into something usable, i.e., deserializing the store,
//! parsing every certificate in it, and indexing them by key identifier and by subject name. The
//! `PreparedGraph` struct provides this capability.

use std::sync::{PoisonError, RwLock};

use certval::CertSource;

/// A prepared graph and the identity of the PKI associated with it.
///
/// Selecting a different PKI simply replaces the entry.
///
/// A caller does not have to invalidate this. The key covers the inputs, the settings and the time
/// of interest, so anything that would make the entry the wrong answer keys differently and misses.
/// [`clear`](PreparedGraph::clear) exists to release the memory, not to preserve correctness.
///
/// One thing it does not cover, which it inherits from the key it shares with the graph on disk: the
/// download folder feeds the graph but is not keyed, so certificates a dynamic build fetched on an
/// earlier run reach a rebuild and do not reach a hit.
#[derive(Default)]
pub struct PreparedGraph {
    /// `None` until a run has prepared something. Poisoning is ignored throughout: a panic in one
    /// run is not a reason to make every later run rebuild, and there is nothing here to leave
    /// inconsistent — the two fields are written together or not at all.
    entry: RwLock<Option<Entry>>,
}

/// A prepared graph and an identifier of the PKI associated with it.
struct Entry {
    /// From [`prepared_key`](crate::graph_cache::prepared_key), so it names the inputs, the settings
    /// and the time of interest together.
    key: String,
    /// Parsed and indexed, and carrying the partial paths the run found among them.
    graph: CertSource,
}

impl PreparedGraph {
    /// A `PreparedGraph` with nothing in it.
    pub fn new() -> Self {
        Self::default()
    }

    /// The graph prepared from the PKI `key` names, or `None` when there is no entry or the entry
    /// came from something else.
    ///
    /// A clone is returned so a dynamic build can append to the graph it is. The next run gets the
    /// same starting point this one got rather than whatever the last run happened to fetch (unless
    /// the updated graph is swapped into place).
    pub fn get(&self, key: &str) -> Option<CertSource> {
        let entry = self.entry.read().unwrap_or_else(PoisonError::into_inner);
        let entry = entry.as_ref()?;
        (entry.key == key).then(|| entry.graph.clone())
    }

    /// Keeps `graph` as the graph prepared from the PKI the `key` names, replacing any entry.
    pub fn keep(&self, key: String, graph: &CertSource) {
        let mut entry = self.entry.write().unwrap_or_else(PoisonError::into_inner);
        *entry = Some(Entry {
            key,
            graph: graph.clone(),
        });
    }

    /// Discards the entry, reporting how many certificates went with it. `None` when there was
    /// nothing to discard, which a frontend needs to tell from having discarded an empty graph.
    pub fn clear(&self) -> Option<usize> {
        let mut entry = self.entry.write().unwrap_or_else(PoisonError::into_inner);
        entry.take().map(|entry| entry.graph.num_certs())
    }

    /// How many certificates are prepared, or `None` when nothing is.
    pub fn certificates(&self) -> Option<usize> {
        let entry = self.entry.read().unwrap_or_else(PoisonError::into_inner);
        entry.as_ref().map(|entry| entry.graph.num_certs())
    }
}
