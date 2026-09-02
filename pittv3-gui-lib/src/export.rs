//! Taking the artifacts behind a validation away with you.
//!
//! A results view can say a path was valid; it cannot hand over what made it so. This assembles, for
//! each certification path a run produced, the material that path was built and judged from — every
//! certificate, the revocation data consulted, the responder certificates that make an OCSP response
//! checkable, and the manifest describing all of it — either as a zip or as the manifests alone.
//!
//! Everything here is derived, not retained. The certificates come off the path, the OCSP artifacts
//! out of the results, the CRLs from whichever source in the environment still holds them, and the
//! manifest is rendered on demand by the same `pittv3_lib::pitt_log` code that writes one into a
//! results folder. So a run pays nothing for an export nobody asks for, and the archive a browser
//! downloads is the same document a CLI run writes to disk.

use std::io::{Cursor, Write};

use certval::{
    CertificationPath, CertificationPathResults, CertificationPathSettings, PkiEnvironment,
};
use pittv3_lib::pitt_log::{cpr_artifact_entries, render_path_manifest};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

/// One file in an export: the name it takes inside a path's folder, and its contents.
pub type ExportEntry = (String, Vec<u8>);

/// Name the manifest takes inside a path's folder. Also the entry [`paths_text`] pulls back out, so
/// the concatenated log and the archived manifests are necessarily the same text.
pub const MANIFEST_NAME: &str = "manifest.txt";

/// The name an export takes when the user has not chosen one. The field is pre-populated with it in
/// both frontends, so the common case needs no typing.
pub const DEFAULT_EXPORT_NAME: &str = "PITTv3Results";

/// A filename stem for an export: what the user typed, sanitized, with a UTC timestamp appended.
///
/// **Sanitized** because the value names a file *and* a folder inside the archive, so a separator in
/// it is not a name but an instruction about where things land.
///
/// **Stamped** because bundles are saved repeatedly -- a second run, the same run after a settings
/// change -- and a fixed name leaves the operating system to disambiguate, which it does by
/// appending `(1)`, `(2)`. Those say nothing about which bundle is which, and they order by when the
/// file was saved rather than when the run happened. The base name is left as the user gave it and
/// the stamp is appended, so a name still says what the run was as well as when it was.
///
/// The stamp is **UTC**, matching the times the manifests inside the archive report, and following
/// the decision already recorded on `epoch_to_datetime_local`: a browser showing local time while
/// the desktop showed UTC made one artifact read two ways. Colons are omitted rather than escaped --
/// they are not legal in a Windows filename.
///
/// `secs` is the caller's rather than read here, so one save action stamps its archive and its path
/// log identically even if it straddles a second, and so the formatting is testable without a clock.
pub fn stamped_export_name(typed: &str, secs: u64) -> String {
    let cleaned: String = typed
        .trim()
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' => '_',
            c => c,
        })
        .collect();
    let base = match cleaned.is_empty() {
        true => DEFAULT_EXPORT_NAME,
        false => cleaned.as_str(),
    };
    match x509_cert::der::DateTime::from_unix_duration(core::time::Duration::from_secs(secs)) {
        Ok(dt) => format!(
            "{base}-{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minutes(),
            dt.seconds()
        ),
        // A clock that yields nothing usable is not a reason to refuse to save. The unstamped name
        // still works; it just leaves collisions to the operating system, as before.
        Err(_) => base.to_string(),
    }
}

/// The files describing one certification path.
///
/// Certificates are numbered by hop with the trust anchor at zero, matching what a results-folder
/// run writes, so the same layout is recognizable however it was produced. Position is the one thing
/// a reader cannot recover from names alone, which is why it leads each one.
pub fn path_entries(
    pe: &PkiEnvironment,
    path: &CertificationPath,
    cps: Option<&CertificationPathSettings>,
    cpr: &CertificationPathResults,
) -> Vec<ExportEntry> {
    let mut out = vec![];

    let mut manifest = Vec::new();
    render_path_manifest(pe, &mut manifest, path, cpr, cps);
    out.push((MANIFEST_NAME.to_string(), manifest));

    out.push(("0-ta.der".to_string(), path.trust_anchor.encoded_ta.clone()));
    for (i, ca) in path.intermediates.iter().enumerate() {
        out.push((format!("{}.der", i + 1), ca.as_bytes().to_vec()));
    }
    out.push((
        format!("{}-target.der", path.intermediates.len() + 1),
        path.target.as_bytes().to_vec(),
    ));

    out.extend(cpr_artifact_entries(cpr));
    out.extend(crl_entries(pe, path, cpr));
    out
}

/// The CRLs that settled a status on this path, recovered from the environment.
///
/// The results retain only `CrlInfo`, deliberately — keeping every CRL body per position per path is
/// what made a 9.5 MB distribution point cost megabytes a run. The bytes are still held by whichever
/// `CrlSource` supplied them, so this asks the environment for the candidates covering each
/// certificate and keeps the ones the results say were actually used.
///
/// Matched on issuer and thisUpdate rather than taken wholesale: `get_crls` answers with candidates
/// by issuer name alone, on purpose, since `process_crl` re-checks scope, validity and signature on
/// everything handed back. Shipping the superset would put CRLs in the bundle that had no bearing on
/// the result. A CRL that has since been pruned from its source simply does not appear, and the
/// manifest's revocation section still records what it was and where it came from.
#[cfg(feature = "revocation")]
fn crl_entries(
    pe: &PkiEnvironment,
    path: &CertificationPath,
    cpr: &CertificationPathResults,
) -> Vec<ExportEntry> {
    use der::{Decode, Encode};
    use x509_cert::certificate::Raw;
    use x509_cert::crl::CertificateList;

    let Some(per_hop) = cpr.get_crl() else {
        return vec![];
    };
    let chain: Vec<&certval::PDVCertificate> = path
        .intermediates
        .iter()
        .chain(core::iter::once(&path.target))
        .collect();

    let mut out = vec![];
    for (hop, infos) in per_hop.iter().enumerate() {
        if infos.is_empty() {
            continue;
        }
        let Some(cert) = chain.get(hop) else {
            continue;
        };
        let Ok(candidates) = pe.get_crls(cert) else {
            continue;
        };
        let suffix = infos.len() > 1;
        for (j, info) in infos.iter().enumerate() {
            let found = candidates.iter().find(|bytes| {
                CertificateList::<Raw>::from_der(bytes)
                    .ok()
                    .map(|crl| {
                        crl.tbs_cert_list.this_update.to_unix_duration().as_secs()
                            == info.this_update
                            && crl
                                .tbs_cert_list
                                .issuer
                                .to_der()
                                .map(|der| der == info.issuer_name_blob)
                                .unwrap_or(false)
                    })
                    .unwrap_or(false)
            });
            if let Some(bytes) = found {
                let name = if suffix {
                    format!("{}-crl-{}.crl", hop + 1, j)
                } else {
                    format!("{}-crl.crl", hop + 1)
                };
                out.push((name, bytes.clone()));
            }
        }
    }
    out
}

#[cfg(not(feature = "revocation"))]
fn crl_entries(
    _pe: &PkiEnvironment,
    _path: &CertificationPath,
    _cpr: &CertificationPathResults,
) -> Vec<ExportEntry> {
    vec![]
}

/// Packages one or more paths' entries as a zip, each path under `<name>/<n>/` numbered from one.
///
/// `name` is the caller's, and it names both the archive and the folder inside it, so extracting
/// leaves one directory rather than scattering numbered folders into wherever it landed.
pub fn zip_paths(name: &str, paths: &[Vec<ExportEntry>]) -> Result<Vec<u8>, String> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut zw = ZipWriter::new(&mut buf);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (i, entries) in paths.iter().enumerate() {
            for (file, bytes) in entries {
                zw.start_file(format!("{name}/{}/{file}", i + 1), options)
                    .map_err(|e| format!("Failed to add {file} to the archive: {e}"))?;
                zw.write_all(bytes)
                    .map_err(|e| format!("Failed to write {file} into the archive: {e}"))?;
            }
        }
        zw.finish()
            .map_err(|e| format!("Failed to finish the archive: {e}"))?;
    }
    Ok(buf.into_inner())
}

/// The manifests alone, one after another, for a caller wanting the account of every path without
/// the material behind it.
///
/// Taken back out of the same entries the archive carries rather than rendered a second time, so the
/// two exports cannot disagree about what the run found.
pub fn paths_text(paths: &[Vec<ExportEntry>]) -> String {
    let mut out = String::new();
    for entries in paths {
        let Some((_, bytes)) = entries.iter().find(|(name, _)| name == MANIFEST_NAME) else {
            continue;
        };
        out.push_str(&String::from_utf8_lossy(bytes));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed instant, so this pins the format rather than agreeing with whatever the clock said.
    /// 2026-09-02T13:45:07Z.
    const WHEN: u64 = 1_788_356_707;

    #[test]
    fn a_name_carries_the_base_and_a_utc_stamp() {
        assert_eq!(
            stamped_export_name("dod run 3", WHEN),
            "dod run 3-20260902T134507Z"
        );
        // cleared field falls back to the name the field starts with, stamped the same way
        assert_eq!(
            stamped_export_name("   ", WHEN),
            "PITTv3Results-20260902T134507Z"
        );
    }

    /// The name reaches a filesystem path and an archive entry, so a separator in it is not a name
    /// but an instruction about where things land. Colons go too: illegal in a Windows filename,
    /// which is also why the stamp has none.
    #[test]
    fn separators_are_not_carried_into_the_name() {
        assert!(stamped_export_name("../etc/passwd", WHEN).starts_with(".._etc_passwd-"));
        assert!(stamped_export_name("C:\\runs\\one", WHEN).starts_with("C__runs_one-"));
        let stamped = stamped_export_name("anything", WHEN);
        assert!(!stamped.contains(':'), "{stamped}");
        assert!(!stamped.contains('/'), "{stamped}");
    }

    /// Two saves of two different runs must not collide -- the whole point of stamping.
    #[test]
    fn different_moments_give_different_names() {
        assert_ne!(
            stamped_export_name("run", WHEN),
            stamped_export_name("run", WHEN + 1)
        );
    }

    /// The archive puts every path under the caller's name, numbered from one, so extracting it
    /// leaves a single directory rather than loose numbered folders.
    #[test]
    fn paths_are_numbered_from_one_under_the_given_name() {
        let paths = vec![
            vec![("manifest.txt".to_string(), b"first".to_vec())],
            vec![("manifest.txt".to_string(), b"second".to_vec())],
        ];
        let zipped = zip_paths("MyExport", &paths).unwrap();
        let mut archive = zip::ZipArchive::new(Cursor::new(zipped)).unwrap();
        let mut names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "MyExport/1/manifest.txt".to_string(),
                "MyExport/2/manifest.txt".to_string()
            ]
        );
    }

    /// The text export is the archive's manifests, so the two cannot describe different runs.
    #[test]
    fn text_export_is_the_manifests_the_archive_carries() {
        let paths = vec![
            vec![
                ("manifest.txt".to_string(), b"path one".to_vec()),
                ("0-ta.der".to_string(), vec![0x30]),
            ],
            vec![("manifest.txt".to_string(), b"path two".to_vec())],
        ];
        let text = paths_text(&paths);
        assert!(text.contains("path one"));
        assert!(text.contains("path two"));
        // the DER rode along in the archive and must not appear in the log
        assert!(!text.contains('\u{30}'.to_string().as_str()) || !text.contains("0-ta"));
    }

    /// A path contributing no manifest is skipped rather than emitting a blank section.
    #[test]
    fn a_path_without_a_manifest_contributes_nothing_to_the_text() {
        let paths = vec![vec![("0-ta.der".to_string(), vec![0x30])]];
        assert!(paths_text(&paths).is_empty());
    }
}
