//! Row views over the certificate pool, the partial-path graph and the trust anchor list.
//!
//! A [`CertSource`](crate::CertSource) holds three things a caller may want to see: the pool of
//! certificates, the partial paths discovered over it, and — in a [`TaSource`](crate::TaSource)
//! beside it — the anchors those paths run up to. Until now the only way to see any of them was
//! `log_certs`, `log_partial_paths` and their siblings, which write lines through `log` and return
//! nothing. That serves a command line, which prints and exits. It does not serve a caller that
//! wants to sort the pool, filter it, or follow a partial path to the certificates it names,
//! because the indices those lines carry are the join key and a line of text cannot be joined on.
//!
//! The types here are that same content as data. Each is a projection of state the source already
//! holds, built on demand and owning its strings, so a caller may keep rows past the borrow that
//! produced them.
//!
//! The `log_*` methods are written in terms of these rows, which is what keeps one rendering of the
//! listing rather than two: the text a command line prints and the rows a caller reads come from
//! the same walk of the same state.

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use const_oid::db::rfc5912::{ID_CE_BASIC_CONSTRAINTS, ID_CE_NAME_CONSTRAINTS};

use crate::{
    general_subtree_to_string, get_leaf_rdn,
    source::ta_source::hex_skid_from_cert,
    util::pdv_utilities::{collect_uris_from_aia_and_sia, name_to_string},
    ExtensionProcessing, PDVCertificate, PDVExtension,
};

/// One entry in the certificate pool, including the entries that hold no usable certificate.
///
/// Every position in the pool gets a row, its [`PoolEntry`] carrying either the certificate there
/// or the reason there is none. Reporting the positions that hold nothing usable, rather than
/// skipping them, is what lets a reader tell a pool of 41 certificates from a pool of 43 with two
/// unusable, and tell either from an index that simply does not exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertRow {
    /// Position in the pool. This is the value every listing prints and every index-taking
    /// function expects, and it is a position rather than an identity: removing an entry shifts
    /// the positions after it.
    pub index: usize,
    /// The string the certificate was read under, from the [`CertFile`](crate::CertFile) at this
    /// index — notionally a filename or a URI. Present whether or not the entry parsed, which is
    /// the only description an unusable entry has.
    pub filename: String,
    /// The certificate at this position, or why there is none.
    pub entry: PoolEntry,
}

/// What a pool position holds.
///
/// An enumeration rather than an `Option` and a reason beside it, so that "usable" and "why not"
/// cannot both be answered at once or neither be.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PoolEntry {
    /// The certificate at this position.
    ///
    /// Boxed because the detail is two hundred-odd bytes against the reason's one, and a pool is
    /// read a row at a time: without it every unusable row in a store carries the footprint of a
    /// certificate it does not hold. The detail already owns eight allocations of its own, so the
    /// box is not a ninth anyone will notice.
    Certificate(Box<CertDetail>),
    /// The buffer at this position yielded no usable certificate.
    Unusable(UnusableReason),
}

/// Why a pool position holds no usable certificate.
///
/// The source distinguishes these while populating and has until now only logged the distinction.
/// It is worth keeping: the first is a bad file and the third is a caller who has not finished,
/// while the second says nothing about the certificate except that the question was asked as of a
/// time it does not cover — change the time of interest and it may be usable again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnusableReason {
    /// The buffer did not decode as a certificate.
    Unparsed,
    /// It decoded, but was not valid at the time of interest the source was initialized with.
    NotValidAtTimeOfInterest,
    /// The buffer has not been parsed: `initialize` has not run since it was added.
    NotParsed,
}

/// What is readable from a pool entry that parsed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertDetail {
    /// Key identifier, hex-encoded: the value of the subject key identifier extension, or, where
    /// the certificate carries none, the calculated value the source indexes it under.
    pub skid: String,
    /// Leaf RDN of the issuer — what the listings print.
    pub issuer: String,
    /// Leaf RDN of the subject — what the listings print.
    pub subject: String,
    /// The whole issuer name, for when two certificates share a leaf RDN.
    pub issuer_dn: String,
    /// The whole subject name, for when two certificates share a leaf RDN.
    pub subject_dn: String,
    /// `notBefore`, as seconds since the Unix epoch.
    pub not_before: u64,
    /// `notAfter`, as seconds since the Unix epoch.
    pub not_after: u64,
    /// Whether the basic constraints extension asserts cA.
    pub is_ca: bool,
    /// The HTTP URIs this certificate's AIA and SIA extensions name, in the order
    /// [`collect_uris_from_aia_and_sia`] yields them.
    ///
    /// One field rather than two because that function reads both extensions in one pass and is
    /// the only place that reading is done; splitting the result here would mean a second walk of
    /// the same extensions, which is how the two would come to disagree.
    pub aia_and_sia: Vec<String>,
    /// Permitted subtrees of the name constraints extension, rendered as the listings render them.
    /// Empty where the certificate constrains no names.
    pub permitted: Vec<String>,
    /// Excluded subtrees of the name constraints extension, rendered as the listings render them.
    pub excluded: Vec<String>,
}

impl CertDetail {
    /// Reads a row's worth of detail out of one certificate.
    ///
    /// Public because a caller holding a certificate that is not in a pool — an uploaded target,
    /// say — wants to describe it the same way the pool's own entries are described, and doing
    /// that a second time by hand is how two descriptions of the same certificate come to differ.
    pub fn from_cert(cert: &PDVCertificate) -> Self {
        let tbs = cert.decoded().tbs_certificate();
        let validity = tbs.validity();

        let mut aia_and_sia = vec![];
        collect_uris_from_aia_and_sia(cert, &mut aia_and_sia);

        let mut permitted = vec![];
        let mut excluded = vec![];
        if let Ok(Some(PDVExtension::NameConstraints(nc))) =
            cert.get_extension(&ID_CE_NAME_CONSTRAINTS)
        {
            if let Some(perm) = &nc.permitted_subtrees {
                permitted = perm.iter().map(general_subtree_to_string).collect();
            }
            if let Some(excl) = &nc.excluded_subtrees {
                excluded = excl.iter().map(general_subtree_to_string).collect();
            }
        }

        let mut is_ca = false;
        if let Ok(Some(PDVExtension::BasicConstraints(bc))) =
            cert.get_extension(&ID_CE_BASIC_CONSTRAINTS)
        {
            is_ca = bc.ca;
        }

        CertDetail {
            skid: hex_skid_from_cert(cert),
            issuer: get_leaf_rdn(tbs.issuer()),
            subject: get_leaf_rdn(tbs.subject()),
            issuer_dn: name_to_string(tbs.issuer()),
            subject_dn: name_to_string(tbs.subject()),
            not_before: validity.not_before.to_unix_duration().as_secs(),
            not_after: validity.not_after.to_unix_duration().as_secs(),
            is_ca,
            aia_and_sia,
            permitted,
            excluded,
        }
    }
}

impl CertRow {
    /// The certificate at this position, or `None` where there is none.
    pub fn detail(&self) -> Option<&CertDetail> {
        match &self.entry {
            PoolEntry::Certificate(detail) => Some(detail.as_ref()),
            PoolEntry::Unusable(_) => None,
        }
    }

    /// Why this position holds no usable certificate, or `None` where it holds one.
    pub fn unusable(&self) -> Option<UnusableReason> {
        match &self.entry {
            PoolEntry::Certificate(_) => None,
            PoolEntry::Unusable(reason) => Some(*reason),
        }
    }

    /// The line `log_certs` prints for this row, or `None` for an entry holding no usable
    /// certificate — which that listing passes over in silence.
    pub fn log_line(&self) -> Option<String> {
        self.detail().map(|d| {
            format!(
                "Index: {}; SKID: {}; Issuer: {}; Subject: {}",
                self.index, d.skid, d.issuer, d.subject
            )
        })
    }
}

/// One partial path: the pool indices running from the certificate issued by a trust anchor down
/// to the leaf CA the path terminates at.
///
/// A path is identified by the certificates it names, not by a position of its own — the graph is
/// stored keyed by the leaf CA's key identifier, and several paths reach the same leaf CA whenever
/// its issuer is cross-certified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathRow {
    /// Key identifier of the leaf CA this path terminates at, hex-encoded. This is the key the
    /// graph is stored under.
    pub leaf_ca_skid: String,
    /// Leaf RDN of the leaf CA's subject, or the key identifier where the pool holds no usable
    /// certificate to read a name from.
    pub leaf_ca_subject: String,
    /// Pool indices of the certificates carrying `leaf_ca_skid`.
    ///
    /// Usually one. More than one is a CA that reused a key across certificates — which is why the
    /// subject above is resolved from the first of them that parsed, and why a caller offering
    /// "show me this CA" has a choice to make rather than an answer.
    pub leaf_ca_indices: Vec<usize>,
    /// Leaf RDN of the issuer of the first certificate in the path, i.e. the subject of the trust
    /// anchor this path expects. Read from the certificate rather than from an anchor store, so it
    /// is available whether or not that anchor is held.
    pub ta_subject: String,
    /// The path itself: pool indices, ordered from the anchor-issued certificate to the leaf CA.
    pub indices: Vec<usize>,
}

impl PathRow {
    /// Number of certificates in the path.
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    /// Whether the path names no certificates. A stored path is expected to name at least one;
    /// this reports the degenerate case rather than leaving a caller to index into nothing.
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    /// The line `log_partial_paths` prints for this path, under the label line for its leaf CA.
    pub fn log_line(&self) -> String {
        format!("\t* TA subject: {} - {:?}, ", self.ta_subject, self.indices)
    }
}

/// One entry in the trust anchor list.
///
/// Its `index` is a position in the anchor list and has nothing to do with a [`CertRow`]'s, which
/// is a position in the certificate pool. The two listings have always printed both as `Index`,
/// so a caller rendering them together is the one that has to say which is which.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaRow {
    /// Position in the anchor list.
    pub index: usize,
    /// Key identifier, hex-encoded.
    pub skid: String,
    /// Leaf RDN of the anchor's name, or `None` where no name could be read from it.
    pub subject: Option<String>,
    /// The string the anchor was read under, notionally a filename.
    pub filename: String,
}

impl TaRow {
    /// The line `log_tas` prints for this row.
    pub fn log_line(&self) -> String {
        let subject = match &self.subject {
            Some(s) => s.to_string(),
            None => "No Name".to_string(),
        };
        let index = self.index;
        format!(
            "Index: {index:3}; SKID: {}; Subject: {subject}; Filename: {}",
            self.skid, self.filename
        )
    }
}

// The listings are now rendered from these rows, so what these assert is the text itself: each
// expected string below is what the corresponding `log_*` method printed before the rows existed.
// A change to a format string is a change to output a command line's readers and scripts see, so
// it should fail here and be a decision rather than a side effect.
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn detail() -> CertDetail {
        CertDetail {
            skid: "AABB".to_string(),
            issuer: "CN=Some CA".to_string(),
            subject: "CN=Another CA".to_string(),
            issuer_dn: "C=US,O=Example,CN=Some CA".to_string(),
            subject_dn: "C=US,O=Example,CN=Another CA".to_string(),
            not_before: 0,
            not_after: 0,
            is_ca: true,
            aia_and_sia: vec![],
            permitted: vec![],
            excluded: vec![],
        }
    }

    #[test]
    fn cert_row_renders_the_line_log_certs_prints() {
        let row = CertRow {
            index: 7,
            filename: "7.der".to_string(),
            entry: PoolEntry::Certificate(Box::new(detail())),
        };
        assert_eq!(
            row.log_line().unwrap(),
            "Index: 7; SKID: AABB; Issuer: CN=Some CA; Subject: CN=Another CA"
        );
        assert!(row.detail().is_some());
        assert!(row.unusable().is_none());
    }

    // An entry the pool could not use is passed over by `log_certs` rather than printed as a gap,
    // which is why the row reports the absence instead of rendering a line for it -- and reports
    // which absence it is, since a bad file and a certificate outside the time of interest call
    // for different things from whoever is looking.
    #[test]
    fn an_unusable_row_renders_no_line_but_keeps_its_reason() {
        let row = CertRow {
            index: 1,
            filename: "garbage".to_string(),
            entry: PoolEntry::Unusable(UnusableReason::Unparsed),
        };
        assert!(row.log_line().is_none());
        assert!(row.detail().is_none());
        assert_eq!(row.unusable(), Some(UnusableReason::Unparsed));
    }

    // The anchor listing pads its index to three columns; the certificate listing does not. Both
    // have always been so, and they are printed by different methods, so the difference survives
    // only if something asserts it.
    #[test]
    fn ta_row_renders_the_line_log_tas_prints() {
        let row = TaRow {
            index: 1,
            skid: "6C8A".to_string(),
            subject: Some("CN=DoD Root CA 3".to_string()),
            filename: "~/pitt/tas/11.der".to_string(),
        };
        assert_eq!(
            row.log_line(),
            "Index:   1; SKID: 6C8A; Subject: CN=DoD Root CA 3; Filename: ~/pitt/tas/11.der"
        );
    }

    #[test]
    fn a_nameless_anchor_renders_as_no_name() {
        let row = TaRow {
            index: 0,
            skid: "6C8A".to_string(),
            subject: None,
            filename: "0.der".to_string(),
        };
        assert_eq!(
            row.log_line(),
            "Index:   0; SKID: 6C8A; Subject: No Name; Filename: 0.der"
        );
    }

    // Including the trailing ", " and the leading tab: the path lines are read under a label line
    // and the indentation is what attaches them to it.
    #[test]
    fn path_row_renders_the_line_log_partial_paths_prints() {
        let row = PathRow {
            leaf_ca_skid: "AABB".to_string(),
            leaf_ca_subject: "CN=Another CA".to_string(),
            leaf_ca_indices: vec![42],
            ta_subject: "CN=Some Root".to_string(),
            indices: vec![3, 17, 42],
        };
        assert_eq!(
            row.log_line(),
            "\t* TA subject: CN=Some Root - [3, 17, 42], "
        );
        assert_eq!(row.len(), 3);
        assert!(!row.is_empty());
    }
}
