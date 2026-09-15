//! What a store holds, as rows, and the text form of the same thing.
//!
//! The rows themselves are certval's: [`CertRow`] for each position in the certificate pool,
//! [`PathRow`] for each partial path over it, [`TaRow`] for each anchor. What this module adds is
//! the thing a frontend hands around — one report carrying all three, plus whatever bytes the run
//! was asked to hand back — and the rendering of that report as a document a reader can keep.
//!
//! It lives here rather than in either frontend because both produce one: the desktop and the
//! command line from paths, through [`options_std`](crate::options_std); the browser from uploaded
//! bytes, through `pittv3-gui-lib`. The inputs differ because a filesystem and a file input are
//! different things. What they describe does not, which is why the description is one type.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use certval::{CertRow, CertSource, PathRow, TaRow, TaSource, UnusableReason};

/// What a store holds.
///
/// Every field is a projection of an assembled store rather than a rendering of it, so a view may
/// sort, filter and cross-reference them. The pool positions and the partial paths join on index:
/// the values in [`PathRow::indices`] are positions in [`certs`](Self::certs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InspectReport {
    /// Every trust anchor the store holds. A [`TaRow`]'s `index` is a position in this list, which
    /// is a different space from a [`CertRow`]'s.
    pub anchors: Vec<TaRow>,
    /// Every position in the certificate pool, including those holding nothing usable.
    pub certs: Vec<CertRow>,
    /// Every partial path the pool carries, in the order the listings print them.
    pub paths: Vec<PathRow>,
    /// The partial paths that could certify a supplied target, where one was supplied and parsed.
    /// `Some(vec![])` says the question was asked and answered with none.
    pub target_paths: Option<Vec<PathRow>>,
}

impl InspectReport {
    /// How many pool positions hold a usable certificate.
    pub fn usable(&self) -> usize {
        self.certs.iter().filter(|r| r.detail().is_some()).count()
    }

    /// How many hold none, for any of the reasons [`UnusableReason`] names.
    pub fn unusable(&self) -> usize {
        self.certs.len() - self.usable()
    }

    /// One line describing the store, the way a view heads its tables.
    pub fn summary(&self) -> String {
        let mut out = format!(
            "{} trust anchor(s), {} certificate(s)",
            self.anchors.len(),
            self.certs.len()
        );
        if self.unusable() > 0 {
            out.push_str(&format!(", {} unusable", self.unusable()));
        }
        out.push_str(&format!(", {} partial path(s)", self.paths.len()));
        out
    }
}

/// A report and the store it describes, kept together.
///
/// The rows address the store by position, so a report and a source from different assemblies would
/// still resolve — to the wrong certificates, silently. Holding them as one value is what makes that
/// impossible rather than something to remember: replacing one replaces the other.
pub struct Inspected {
    /// What the store holds.
    pub report: InspectReport,
    /// The certificate pool the report's indices are positions in.
    pub certs: CertSource,
    /// The anchors the report's anchor rows are positions in. A different index space from `certs`.
    pub anchors: TaSource,
}

/// The bytes of the certificates at the given pool positions, named as the command line names them.
///
/// Every position answers, including the ones holding nothing usable: a buffer that would not parse
/// is the one most worth taking away, since it cannot be examined here. A position past the end is
/// skipped rather than reported — the caller passes positions it read off the rows, so one that is
/// out of range means the rows and the source came apart, which [`Inspected`] prevents.
pub fn certificate_bytes(source: &CertSource, indices: &[usize]) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![];
    for index in indices {
        if let Some(cf) = source.buffer_at(*index) {
            out.push((format!("{index}.der"), cf.bytes.clone()));
        }
    }
    out
}

/// The bytes of the trust anchors at the given positions in the anchor list.
///
/// Named apart from [`certificate_bytes`] because the two index spaces are different: anchor 3 and
/// certificate 3 are unrelated, and the listings have always printed both as `Index`.
pub fn anchor_bytes(source: &TaSource, indices: &[usize]) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![];
    for index in indices {
        if let Some(cf) = source.buffer_at(*index) {
            out.push((format!("ta-{index}.der"), cf.bytes.clone()));
        }
    }
    out
}

/// Why a pool position holds no usable certificate, in the words a view shows.
///
/// An empty string for a position that holds one, so a table may put this in a column without
/// asking whether there is anything to say first.
pub fn unusable_text(row: &CertRow) -> &'static str {
    match row.unusable() {
        None => "",
        Some(UnusableReason::Unparsed) => "unusable — did not parse",
        Some(UnusableReason::NotValidAtTimeOfInterest) => "unusable — outside the time of interest",
        Some(UnusableReason::NotParsed) => "not parsed yet",
    }
}

/// Renders epoch seconds as a date and time, or as the raw number where it is not a time this can
/// represent — which beats printing nothing.
///
/// A [`certval::CertDetail`] keeps its validity as epoch seconds, since that is a number every
/// frontend can carry; a reader wants a date, and both frontends wanting the same one is why this
/// is here rather than in either.
pub fn unix_secs_as_date(secs: u64) -> String {
    match der::asn1::GeneralizedTime::from_unix_duration(core::time::Duration::from_secs(secs)) {
        Ok(t) => t.to_date_time().to_string(),
        Err(_) => format!("{secs}"),
    }
}

/// Quotes one field of a CSV record, doubling any quotes inside it.
///
/// Every field is quoted rather than only the ones that need it: a subject name carries commas as a
/// matter of course, and deciding per field means the rule is applied in two places at once.
fn csv_field(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn csv_row(fields: &[String]) -> String {
    let quoted: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
    format!("{}\n", quoted.join(","))
}

/// The certificate rows as CSV, one record per row including the positions holding nothing usable.
///
/// Takes the rows rather than the report so a view exports what is on screen: a filtered table
/// hands over what it filtered to, which is the whole reason the button sits beside it.
pub fn certs_as_csv(rows: &[&CertRow]) -> String {
    let mut out = csv_row(&[
        "index".into(),
        "subject".into(),
        "issuer".into(),
        "key identifier".into(),
        "not before".into(),
        "not after".into(),
        "is ca".into(),
        "state".into(),
        "read from".into(),
    ]);
    for row in rows {
        let (subject, issuer, skid, nb, na, ca) = match row.detail() {
            Some(d) => (
                d.subject.clone(),
                d.issuer.clone(),
                d.skid.clone(),
                unix_secs_as_date(d.not_before),
                unix_secs_as_date(d.not_after),
                match d.is_ca {
                    true => "yes".to_string(),
                    false => "no".to_string(),
                },
            ),
            None => (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ),
        };
        out.push_str(&csv_row(&[
            format!("{}", row.index),
            subject,
            issuer,
            skid,
            nb,
            na,
            ca,
            unusable_text(row).to_string(),
            row.filename.clone(),
        ]));
    }
    out
}

/// The partial paths as CSV, one record per path.
///
/// The path itself is written as its indices separated by spaces, in one field: a path is a
/// sequence and a column per position would be a different width for every store.
pub fn paths_as_csv(rows: &[&PathRow]) -> String {
    let mut out = csv_row(&[
        "leaf ca".into(),
        "leaf ca key identifier".into(),
        "trust anchor".into(),
        "length".into(),
        "indices".into(),
    ]);
    for row in rows {
        let indices: Vec<String> = row.indices.iter().map(|i| format!("{i}")).collect();
        out.push_str(&csv_row(&[
            row.leaf_ca_subject.clone(),
            row.leaf_ca_skid.clone(),
            row.ta_subject.clone(),
            format!("{}", row.len()),
            indices.join(" "),
        ]));
    }
    out
}

/// The trust anchors as CSV, one record per anchor.
pub fn anchors_as_csv(rows: &[TaRow]) -> String {
    let mut out = csv_row(&[
        "index".into(),
        "subject".into(),
        "key identifier".into(),
        "read from".into(),
    ]);
    for row in rows {
        let subject = match &row.subject {
            Some(s) => s.clone(),
            None => "No Name".to_string(),
        };
        out.push_str(&csv_row(&[
            format!("{}", row.index),
            subject,
            row.skid.clone(),
            row.filename.clone(),
        ]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // A subject name carries commas and the occasional quote, so a field that is not quoted and
    // escaped puts the rest of the record in the wrong columns.
    #[test]
    fn a_field_with_commas_and_quotes_survives_the_record() {
        let row = csv_row(&["C=US, O=An \"Example\" CA".to_string(), "plain".to_string()]);
        assert_eq!("\"C=US, O=An \"\"Example\"\" CA\",\"plain\"\n", row);
    }

    #[test]
    fn the_anchor_csv_names_an_anchor_without_a_name() {
        let csv = anchors_as_csv(&[TaRow {
            index: 0,
            skid: "AABB".to_string(),
            subject: None,
            filename: "0.der".to_string(),
        }]);
        assert!(csv.contains("\"No Name\""), "{csv}");
        assert_eq!(2, csv.lines().count(), "a header and one record");
    }

    // The bytes of a position that never parsed are reachable, which is the whole reason the export
    // goes through the buffers rather than the parsed certificates: a file that will not parse here
    // is the one worth taking away to examine elsewhere.
    #[test]
    fn certificate_bytes_reach_a_buffer_that_did_not_parse() {
        use certval::{CertFile, CertVector};

        let garbage = vec![0x30u8, 0x03, 0x02, 0x01, 0x00];
        let mut source = CertSource::new();
        source.push(CertFile {
            filename: "garbage".to_string(),
            bytes: garbage.clone(),
        });

        let files = certificate_bytes(&source, &[0]);
        assert_eq!(1, files.len());
        assert_eq!("0.der", files[0].0);
        assert_eq!(garbage, files[0].1);
    }

    // A position past the end is skipped rather than reported: the caller passes positions read off
    // the rows, so one out of range means the rows and the source came apart -- which `Inspected`
    // is what prevents.
    #[test]
    fn certificate_bytes_skip_a_position_the_source_does_not_hold() {
        let source = CertSource::new();
        assert!(certificate_bytes(&source, &[0, 7]).is_empty());
    }

    #[test]
    fn an_empty_report_describes_itself_as_empty() {
        let report = InspectReport::default();
        assert_eq!(0, report.usable());
        assert_eq!(0, report.unusable());
        assert!(report.summary().contains("0 certificate(s)"));
    }
}
