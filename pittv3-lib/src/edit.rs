//! Editing a store: what a reader has marked for removal, and the new store that results.
//!
//! An edit never changes what was opened. Baked stores are crate artifacts and a named file is the
//! user's, so applying edits produces *bytes* — a trust anchor store and a certificate store — and
//! leaves it to the frontend to ask where they go. Overwriting what was opened stays possible, by
//! choosing that destination, but it is never what happens by default.
//!
//! Adding material needs nothing here: certificates and anchors named beside a store are already
//! merged into the pool by the assembly, so an addition is an input and arrives by inspecting
//! again. What could not be said before is *removal*, which is what this module carries.
//!
//! Removals are staged rather than applied. A position marked for removal keeps its index for as
//! long as the report is on screen, so every other index a reader is looking at goes on meaning
//! what it meant; the pool is compacted once, when the store is written. That is also the only
//! moment the partial paths are rediscovered, since a pool with certificates taken out of it is a
//! different pool and the paths it was serialized with described the old one.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use certval::{
    is_self_signed, CertSource, CertVector, CertificationPathBuilderFormats,
    CertificationPathSettings, PkiEnvironment, TaSource, TimeOfInterest,
};

use crate::inspect::Inspected;

/// What a reader has marked for removal, by position.
///
/// Two sets because the two index spaces are unrelated: anchor 3 and certificate 3 are different
/// certificates. Positions rather than identities, which is sound only because nothing is compacted
/// until the store is written — see the module documentation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StagedEdits {
    certs: BTreeSet<usize>,
    anchors: BTreeSet<usize>,
}

impl StagedEdits {
    /// Marks a pool position for removal, or unmarks one already marked.
    ///
    /// A toggle because marking is how a reader explores: the count and the struck-through paths
    /// answer "what goes with this", and taking it back has to be as cheap as asking.
    pub fn toggle_cert(&mut self, index: usize) {
        if !self.certs.remove(&index) {
            self.certs.insert(index);
        }
    }

    /// Marks an anchor position for removal, or unmarks one already marked.
    pub fn toggle_anchor(&mut self, index: usize) {
        if !self.anchors.remove(&index) {
            self.anchors.insert(index);
        }
    }

    /// Whether this pool position is marked for removal.
    pub fn cert_removed(&self, index: usize) -> bool {
        self.certs.contains(&index)
    }

    /// Whether this anchor position is marked for removal.
    pub fn anchor_removed(&self, index: usize) -> bool {
        self.anchors.contains(&index)
    }

    /// How many certificates are marked.
    pub fn certs_removed(&self) -> usize {
        self.certs.len()
    }

    /// How many anchors are marked.
    pub fn anchors_removed(&self) -> usize {
        self.anchors.len()
    }

    /// Whether anything is marked at all.
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty() && self.anchors.is_empty()
    }

    /// Discards every mark, leaving the store as it was read.
    pub fn clear(&mut self) {
        self.certs.clear();
        self.anchors.clear();
    }

    /// What applying these would do, in the words a view shows before writing anything.
    pub fn summary(&self) -> String {
        if self.is_empty() {
            return "Nothing marked for removal".to_string();
        }
        let mut parts = vec![];
        if !self.certs.is_empty() {
            parts.push(format!("{} certificate(s)", self.certs.len()));
        }
        if !self.anchors.is_empty() {
            parts.push(format!("{} trust anchor(s)", self.anchors.len()));
        }
        format!("{} marked for removal", parts.join(" and "))
    }
}

/// The pool positions the command line's `--cleanup` would remove, as the rule it applies.
///
/// One rule rather than two: the same four conditions the command line checks, in the same order,
/// so marking by this and cleaning up by that reach the same set. A certificate is a candidate when
/// it does not parse, is not valid at the time asked about, is self-signed, or does not assert cA.
///
/// Self-*signed*, which verifies the signature, rather than self-issued, which only compares the
/// names: a key-rollover certificate is self-issued and legitimate, and the command line keeps it.
/// Verifying needs an environment, so one is built here rather than asked of the caller.
pub fn cleanup_candidates(inspected: &Inspected, time_of_interest: u64) -> Vec<usize> {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let toi = TimeOfInterest::from_unix_secs(time_of_interest).ok();

    let checks_validity = toi.map(|t| !t.is_disabled()).unwrap_or(false);

    let mut candidates = vec![];
    for row in &inspected.report.certs {
        // A position that yielded no usable certificate is a candidate whatever the reason: it did
        // not parse, or the time the source was read at does not cover it.
        let Some(detail) = row.detail() else {
            candidates.push(row.index);
            continue;
        };

        // Not a CA. `is_ca` is false both for a certificate asserting cA false and for one with no
        // basic constraints at all, which the command line treats the same way.
        let mut doomed = !detail.is_ca;

        if checks_validity
            && (time_of_interest < detail.not_before || time_of_interest > detail.not_after)
        {
            doomed = true;
        }

        // The one condition the row cannot answer: verifying the signature needs the certificate.
        if let Some(Some(cert)) = inspected.certs.certs().get(row.index) {
            if is_self_signed(&pe, cert) {
                doomed = true;
            }
        }

        if doomed {
            candidates.push(row.index);
        }
    }
    candidates
}

/// A store written out of an edited pool: the two halves, and what the writing did.
#[derive(Clone, Debug)]
pub struct EditedStore {
    /// The trust anchor store, in the form the providers ship and `--ta-cbor` reads.
    pub ta_cbor: Vec<u8>,
    /// The certificate store, carrying the partial paths rediscovered over what survived.
    pub ca_cbor: Vec<u8>,
    /// How many anchors the written store holds.
    pub anchors: usize,
    /// How many certificates the written store holds.
    pub certs: usize,
    /// How many partial paths were found over them.
    pub paths: usize,
}

impl EditedStore {
    /// One line describing what was written, for a view to report after saving.
    pub fn summary(&self) -> String {
        format!(
            "{} trust anchor(s), {} certificate(s), {} partial path(s)",
            self.anchors, self.certs, self.paths
        )
    }
}

/// Applies the marks to the store the report describes, returning the two halves to be written.
///
/// This is the moment everything deferred happens at once: the surviving buffers are compacted, so
/// the positions in the written store are not the ones on screen, and the partial paths are
/// rediscovered over the result rather than carried across from the store that was read.
///
/// The `time_of_interest` is the one the inspection asked about, so a certificate outside it is
/// treated here exactly as the report treated it. Generation is the same call with an empty
/// `Inspected`: material comes in as inputs and a store comes out, with nothing marked.
pub fn apply_edits(
    inspected: &Inspected,
    edits: &StagedEdits,
    time_of_interest: u64,
) -> Result<EditedStore, String> {
    // Seconds rather than a `TimeOfInterest`, because the frontends carry the time as a number and
    // neither depends on certval directly. Zero is the disabled value, which is what a caller that
    // does not want validity considered passes.
    let toi = TimeOfInterest::from_unix_secs(time_of_interest)
        .map_err(|e| format!("{time_of_interest} is not a time this can use: {e:?}"))?;
    let mut cps = CertificationPathSettings::new();
    cps.set_time_of_interest(toi);

    // --- the anchors ---
    let mut ta_store = TaSource::new();
    let mut anchors = 0;
    for index in 0..inspected.report.anchors.len() {
        if edits.anchor_removed(index) {
            continue;
        }
        let Some(cf) = inspected.anchors.buffer_at(index) else {
            continue;
        };
        ta_store.push(cf.clone());
        anchors += 1;
    }
    ta_store
        .initialize()
        .map_err(|e| format!("the surviving trust anchors would not load: {e:?}"))?;
    let ta_cbor = ta_store
        .serialize(CertificationPathBuilderFormats::Cbor)
        .map_err(|e| format!("failed to write the trust anchor store: {e:?}"))?;

    // --- the certificates ---
    let mut cert_source = CertSource::new();
    let mut certs = 0;
    for index in 0..inspected.report.certs.len() {
        if edits.cert_removed(index) {
            continue;
        }
        let Some(cf) = inspected.certs.buffer_at(index) else {
            continue;
        };
        cert_source.push(cf.clone());
        certs += 1;
    }
    cert_source
        .initialize(&cps)
        .map_err(|e| format!("the surviving certificates would not load: {e:?}"))?;

    // Rediscovered against the anchors that survived, since which paths terminate at an anchor
    // depends on which anchors there are.
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe.add_trust_anchor_source(Box::new(ta_store));
    cert_source.find_all_partial_paths(&pe, &cps);

    let paths = cert_source.num_partial_paths();
    let ca_cbor = cert_source
        .serialize(CertificationPathBuilderFormats::Cbor)
        .map_err(|e| format!("failed to write the certificate store: {e:?}"))?;

    Ok(EditedStore {
        ta_cbor,
        ca_cbor,
        anchors,
        certs,
        paths,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::InspectReport;
    use certval::CertFile;

    /// A store of one anchor and two certificates, one of which the anchor issued. Assembled the
    /// way the views assemble one, so the rows carry the positions `apply_edits` is given.
    fn store() -> Inspected {
        let root = include_bytes!("../../certval/tests/examples/TrustAnchorRootCertificate.crt");
        let good_ca = include_bytes!("../../certval/tests/examples/GoodCACert.crt");
        let unrelated = include_bytes!("../../certval/tests/examples/DigiCertGlobalCAG2.der");

        let mut cps = CertificationPathSettings::new();
        cps.set_time_of_interest(TimeOfInterest::disabled());

        let mut anchors = TaSource::new();
        anchors.push(CertFile {
            filename: "root.der".to_string(),
            bytes: root.to_vec(),
        });
        anchors.initialize().unwrap();

        let mut certs = CertSource::new();
        for (name, bytes) in [
            ("good-ca.der", good_ca.to_vec()),
            ("unrelated.der", unrelated.to_vec()),
        ] {
            certs.push(CertFile {
                filename: name.to_string(),
                bytes,
            });
        }
        certs.initialize(&cps).unwrap();

        let mut pe = PkiEnvironment::default();
        pe.populate_5280_pki_environment();
        pe.add_trust_anchor_source(Box::new(anchors.clone()));
        certs.find_all_partial_paths(&pe, &cps);

        let report = InspectReport {
            anchors: anchors.ta_rows(),
            certs: certs.cert_rows(),
            paths: certs.path_rows(),
            target_paths: None,
        };
        Inspected {
            report,
            certs,
            anchors,
        }
    }

    // What is written is a store, readable by the same types that read a shipped one -- which is
    // what makes an edit produce an artifact rather than bytes nothing will open.
    //
    // Gated on `rsa` because building the partial-path graph verifies the anchor-to-CA signature:
    // without a verification callback no edge is recorded, so the store would be correct and the
    // assertion about its paths would fail for a reason that has nothing to do with editing.
    #[cfg(feature = "rsa")]
    #[test]
    fn an_edited_store_reads_back_without_what_was_marked() {
        let inspected = store();
        assert_eq!(2, inspected.report.certs.len());
        assert_eq!(1, inspected.report.anchors.len());
        assert!(
            !inspected.report.paths.is_empty(),
            "the anchor issued one of these certificates, so there should be a path"
        );

        let mut edits = StagedEdits::default();
        edits.toggle_cert(1);

        let written = apply_edits(&inspected, &edits, 0).expect("an edited store should write");
        assert_eq!(1, written.certs);
        assert_eq!(1, written.anchors);

        let mut reopened =
            CertSource::new_from_cbor(&written.ca_cbor).expect("the certificate store should read");
        let cps = CertificationPathSettings::new();
        reopened.initialize(&cps).unwrap();
        assert_eq!(
            1,
            reopened.num_buffers(),
            "the marked certificate should not be in the written store"
        );

        let reopened_anchors =
            TaSource::new_from_cbor(&written.ta_cbor).expect("the anchor store should read");
        assert_eq!(1, reopened_anchors.get_tas().len());
    }

    // The positions in the written store are not the ones on screen: the survivors are compacted,
    // which is the one moment indices move and the reason nothing moves before it.
    #[test]
    fn saving_compacts_the_positions() {
        let inspected = store();
        let mut edits = StagedEdits::default();
        edits.toggle_cert(0);

        let written = apply_edits(&inspected, &edits, 0).unwrap();
        let reopened = CertSource::new_from_cbor(&written.ca_cbor).unwrap();
        assert_eq!(1, reopened.num_buffers());
        assert_eq!(
            "unrelated.der",
            reopened.buffer_at(0).unwrap().filename,
            "what was at position 1 is at position 0 in the store that was written"
        );
    }

    // Paths are rediscovered rather than carried over: which paths exist depends on which anchors
    // do, so removing the anchor leaves a pool with nothing terminating at one.
    #[cfg(feature = "rsa")]
    #[test]
    fn removing_the_anchor_leaves_no_paths() {
        let inspected = store();
        let before = inspected.report.paths.len();
        assert!(before > 0);

        let mut edits = StagedEdits::default();
        edits.toggle_anchor(0);

        let written = apply_edits(&inspected, &edits, 0).unwrap();
        assert_eq!(0, written.anchors);
        assert_eq!(
            0, written.paths,
            "no anchor means no path terminates at one, so the store carries none"
        );
    }

    // The anchor in this fixture is a self-signed root, and the cleanup rule removes self-signed
    // certificates -- so a store holding one in its CA pool has a candidate, and the unrelated CA
    // that is neither self-signed nor invalid does not.
    #[cfg(feature = "rsa")]
    #[test]
    fn the_cleanup_rule_names_the_certificates_the_command_line_would_remove() {
        let inspected = store();
        let candidates = cleanup_candidates(&inspected, 0);
        assert!(
            !candidates.contains(&0),
            "Good CA is a CA, is not self-signed, and should survive: {candidates:?}"
        );
    }

    // Everything the rule rejects, it rejects by position, so marking by it and saving removes
    // exactly those -- which is what makes the preset and the command line one rule rather than two.
    #[cfg(feature = "rsa")]
    #[test]
    fn marking_the_candidates_removes_them() {
        let inspected = store();
        let mut edits = StagedEdits::default();
        for index in cleanup_candidates(&inspected, 0) {
            edits.toggle_cert(index);
        }
        let before = inspected.report.certs.len();
        let written = apply_edits(&inspected, &edits, 0).unwrap();
        assert_eq!(before - edits.certs_removed(), written.certs);
    }

    // Generation is the same call over an empty base: nothing marked, nothing held, and what comes
    // out is a store that reads as empty rather than an error.
    #[test]
    fn an_empty_base_writes_an_empty_store() {
        let inspected = Inspected {
            report: InspectReport::default(),
            certs: CertSource::new(),
            anchors: TaSource::new(),
        };
        let written = apply_edits(&inspected, &StagedEdits::default(), 0)
            .expect("an empty store should still write");
        assert_eq!(0, written.certs);
        assert_eq!(0, written.anchors);
        assert_eq!(0, written.paths);
        assert!(CertSource::new_from_cbor(&written.ca_cbor).is_ok());
        assert!(TaSource::new_from_cbor(&written.ta_cbor).is_ok());
    }

    #[test]
    fn marking_is_a_toggle() {
        let mut edits = StagedEdits::default();
        assert!(edits.is_empty());

        edits.toggle_cert(7);
        assert!(edits.cert_removed(7));
        assert_eq!(1, edits.certs_removed());
        assert!(!edits.is_empty());

        edits.toggle_cert(7);
        assert!(!edits.cert_removed(7));
        assert!(edits.is_empty());
    }

    // The two index spaces are unrelated, so marking anchor 3 must say nothing about certificate 3.
    #[test]
    fn the_two_index_spaces_are_marked_apart() {
        let mut edits = StagedEdits::default();
        edits.toggle_anchor(3);
        assert!(edits.anchor_removed(3));
        assert!(!edits.cert_removed(3));
        assert_eq!(0, edits.certs_removed());
        assert_eq!(1, edits.anchors_removed());
    }

    #[test]
    fn the_summary_says_what_would_go() {
        let mut edits = StagedEdits::default();
        assert_eq!("Nothing marked for removal", edits.summary());

        edits.toggle_cert(1);
        edits.toggle_cert(2);
        assert_eq!("2 certificate(s) marked for removal", edits.summary());

        edits.toggle_anchor(0);
        assert_eq!(
            "2 certificate(s) and 1 trust anchor(s) marked for removal",
            edits.summary()
        );

        edits.clear();
        assert!(edits.is_empty());
    }
}
