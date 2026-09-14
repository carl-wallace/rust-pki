//! How current a built-in trust store's material is, phrased once for every frontend.
//!
//! The selector says what each store *is* — whose PKI, which environment — but not how old it
//! is, and for trust material that is the question a user actually has: an anchor set is a
//! snapshot of a publisher's decisions, and a snapshot with no date attached invites the
//! assumption that it is current.
//!
//! The dates come from the provider, as `certval_stores_core::StoreEntry`'s `published` and
//! `collected` (this crate links no provider, so they arrive as plain strings from whichever
//! frontend did). Two of them because they answer different questions and can be far apart — the
//! DoD operational-test stream was published nineteen months before it was fetched — so a
//! frontend showing only the fetch date would report that store as fresh.
//!
//! The sentence lives here rather than in either application because both show it, and the two
//! are meant to agree: a person comparing the browser frontend against the desktop is entitled
//! to read the same words about the same store.

/// A sentence saying how current a store's material is, or an empty string when the provider
/// states neither date.
///
/// Empty rather than "unknown", because a frontend is not obliged to fill silence: a provider
/// that cannot answer honestly says nothing, and a store that says nothing about its age reads
/// as exactly that. See `certval_stores_sipr`, whose provenance is unrecorded.
///
/// The dates are rendered as the provider gives them, `YYYY-MM-DD`, rather than in a local
/// format. They are a publisher's statement about an artifact, not an event in the reader's day,
/// and `certval_stores_core`'s conformance suite already holds providers to that one spelling.
///
/// ```
/// use pittv3_gui_lib::store_provenance::material_age;
///
/// assert_eq!(
///     material_age(Some("2026-06-12"), Some("2026-09-11")),
///     "Published 2026-06-12, collected 2026-09-11."
/// );
/// assert_eq!(material_age(None, Some("2026-08-13")), "Collected 2026-08-13.");
/// assert_eq!(material_age(None, None), "");
/// ```
pub fn material_age(published: Option<&str>, collected: Option<&str>) -> String {
    match (published, collected) {
        // The same day is the uninteresting case and reads oddly said twice, but it is worth
        // distinguishing from a bare "collected": a publisher that dates its release tells you
        // more than a fetch does, even when the two coincide.
        (Some(p), Some(c)) if p == c => format!("Published and collected {p}."),
        (Some(p), Some(c)) => format!("Published {p}, collected {c}."),
        (Some(p), None) => format!("Published {p}."),
        (None, Some(c)) => format!("Collected {c}."),
        (None, None) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::material_age;

    /// The four shapes the providers actually produce, named by the store that produces each:
    /// a wrong sentence here is wrong in both applications at once.
    #[test]
    fn every_combination_of_the_two_dates_reads_as_a_sentence() {
        // certval_stores_nipr: generated from a dated stream, fetched later.
        assert_eq!(
            material_age(Some("2025-02-03"), Some("2026-09-11")),
            "Published 2025-02-03, collected 2026-09-11."
        );
        // certval-stores-mozilla: a live CCADB query, so a fetch date and nothing else.
        assert_eq!(
            material_age(None, Some("2026-08-13")),
            "Collected 2026-08-13."
        );
        // certval_stores_fpki's retired G1 environment states neither a bundle nor a date; the
        // shape is reachable by any provider that records only one of the two.
        assert_eq!(
            material_age(Some("2026-08-10"), None),
            "Published 2026-08-10."
        );
        // certval_stores_sipr, whose provenance is still unrecorded.
        assert_eq!(material_age(None, None), "");
    }

    #[test]
    fn one_day_carrying_both_roles_is_not_said_twice() {
        assert_eq!(
            material_age(Some("2026-08-13"), Some("2026-08-13")),
            "Published and collected 2026-08-13."
        );
    }
}
