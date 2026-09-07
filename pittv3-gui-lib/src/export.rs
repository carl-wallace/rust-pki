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

/// Name the rendered validation log takes inside a path's folder. Also the entry [`paths_text`]
/// pulls back out, so the concatenated log and the archived logs are necessarily the same text.
pub const PATH_LOG_NAME: &str = "PathLog.txt";

/// Name of the index of a path's folder: every file in it and what each one is.
///
/// Separate from [`PATH_LOG_NAME`] because they answer different questions. The log is the account
/// of the validation; the manifest is what is on disk beside it, which a reader needs when the
/// filenames are digests and say nothing about their contents on their own.
pub const PATH_MANIFEST_NAME: &str = "PathManifest.txt";

/// The subtree holding what a replay needs: the environment, the settings, the end entity
/// certificates and the command line that reproduces the run.
///
/// Separate from [`PATHS_DIR`] because the two halves disagree about naming and cannot both have
/// the top level. Replay needs the names the CLI flags expect -- `ta.cbor` is what `--ta-cbor` is
/// handed -- while the path material is named by position within its path. One subtree each is what
/// lets both be true of one archive.
pub const INPUTS_DIR: &str = "inputs";

/// The subtree holding what the run *produced* that helps reproduce it.
///
/// **Separate from [`INPUTS_DIR`] because "inputs" has two meanings and they are not the same set.**
/// The inputs used to produce this bundle are what the run was handed; the inputs used to reproduce
/// it include things the run worked out for itself -- the graph it built, the anchors and
/// intermediates its paths actually went through, the revocation data it collected. Filing the
/// second lot under a name that says they were given is how a reader ends up unable to tell what a
/// user supplied from what the run discovered, which is exactly the distinction a fetch-bug
/// investigation turns on. So `inputs/` is the record of what went in, `derived/` is everything else
/// a replay needs, and a reproduction uses both.
pub const DERIVED_DIR: &str = "derived";

/// The subtree holding one numbered folder per certification path, each carrying that path's
/// certificates, the revocation data consulted and the manifest describing them.
///
/// Named for its unit. A path is what a run produces, what a manifest accounts for and what a
/// reader compares against another run, so the folder says so rather than describing what the
/// contents are for.
pub const PATHS_DIR: &str = "paths";

/// Name of the file at the archive's root: what this bundle is, what the run found, and how to
/// load it into each of the three things that can read it.
///
/// The root exists because every other entry lives under a path's folder, so a fact about the run
/// rather than about a path -- how long the whole thing took -- had nowhere to go. It carries the
/// instructions as well because a bundle is handed to someone else, and the layout tells them what
/// is here without telling them what to do with it. One file rather than two: a root with a readme
/// and a summary has two files each claiming to be where you start.
pub const README_NAME: &str = "README.txt";

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

/// The files describing one certification path: the rendered log, an index of the folder, and every
/// certificate and revocation artifact the path was judged from.
///
/// **Every artifact is named by the digest of its own bytes**, so `shasum -a 256 <file>` reproduces
/// the name and two bundles can be compared without trusting either's filenames. The full SHA-256
/// rather than a prefix of it (Carl, 2026-09-07): a whole digest can be checked by eye at both ends,
/// and truncating throws the tail away, which is half of what makes eyeballing work.
///
/// The position and role still lead each name — `0-ta`, `1`, `2-target`, `1-crl` — because position
/// is the one thing a reader cannot recover from a digest, and a folder of bare hashes says nothing
/// about the order of the chain. So a name is `<position and role>.<digest>.<extension>`.
pub fn path_entries(
    pe: &PkiEnvironment,
    path: &CertificationPath,
    cps: Option<&CertificationPathSettings>,
    cpr: &CertificationPathResults,
    duration_ms: Option<u64>,
) -> Vec<ExportEntry> {
    let mut artifacts = vec![];

    artifacts.push(("0-ta.der".to_string(), path.trust_anchor.encoded_ta.clone()));
    for (i, ca) in path.intermediates.iter().enumerate() {
        artifacts.push((format!("{}.der", i + 1), ca.as_bytes().to_vec()));
    }
    artifacts.push((
        format!("{}-target.der", path.intermediates.len() + 1),
        path.target.as_bytes().to_vec(),
    ));
    artifacts.extend(cpr_artifact_entries(cpr));
    artifacts.extend(crl_entries(pe, path, cpr));

    let artifacts: Vec<ExportEntry> = artifacts
        .into_iter()
        .map(|(name, bytes)| (content_addressed_name(&name, &bytes), bytes))
        .collect();

    let mut out = vec![];

    let mut log = Vec::new();
    render_path_manifest(pe, &mut log, path, cpr, cps, duration_ms);
    out.push((PATH_LOG_NAME.to_string(), log));
    out.push((
        PATH_MANIFEST_NAME.to_string(),
        render_folder_manifest(&artifacts).into_bytes(),
    ));
    out.extend(artifacts);
    out
}

/// Inserts the digest of an artifact's bytes into its name, before the extension.
///
/// The positional stem is kept and the digest appended to it, rather than replacing the name, so a
/// folder still reads in chain order. Split at the first dot because the stems this is given carry
/// none, and the extension may be compound -- `failed.ocspResp` is one.
fn content_addressed_name(name: &str, bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    match name.split_once('.') {
        Some((stem, ext)) => format!("{stem}.{hex}.{ext}"),
        None => format!("{name}.{hex}"),
    }
}

/// The index of a path's folder: every file in it, in chain order, and what each one is.
///
/// It exists because the filenames are digests. A digest identifies a file and describes nothing, so
/// without this a reader opening a path folder has a list of hashes and no way to tell the anchor
/// from an intermediate without decoding each one.
fn render_folder_manifest(artifacts: &[ExportEntry]) -> String {
    let mut out = String::from(
        "Files in this folder: the certificates in chain order, then the artifacts consulted.\n\n\
         Each is named <position and role>.<sha256 of its own bytes>.<extension>, so the name can \n\
         be checked against the file: `shasum -a 256 <file>` reproduces the digest in it.\n\n",
    );
    for (name, bytes) in artifacts {
        out.push_str(&format!(
            "{name}\n    {} ({} bytes)\n",
            describe(name),
            bytes.len()
        ));
    }
    out
}

/// What a file in a path's folder is.
///
/// **Extension before stem**, because a request and a response share the `-ocsp` stem and differ
/// only in the extension -- reading the stem first labelled every `.ocspReq` an OCSP *response*,
/// which in an evidence artifact is a statement that something was consulted when it was sent.
fn describe(name: &str) -> &'static str {
    let stem = name.split('.').next().unwrap_or_default();
    match () {
        _ if name.ends_with(".ocspReq") => "OCSP request sent for this position",
        _ if name.ends_with(".failed.ocspResp") => "OCSP response that could not be used",
        _ if name.ends_with(".ocspResp") => "OCSP response consulted for this position",
        _ if name.ends_with(".crl") => "CRL consulted for this position",
        _ if name.ends_with(".crl.txt") => "note recording where a CRL could be re-obtained",
        _ if stem.ends_with("-ta") => "trust anchor",
        _ if stem.ends_with("-target") => "target certificate",
        _ if stem.contains("-cert-") => "certificate that signed an OCSP response",
        _ => "intermediate CA certificate",
    }
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

/// Packages a run as one archive with two named halves and a run-level file at its root.
///
/// ```text
/// <name>/run.txt          what the run as a whole did
/// <name>/inputs/...       what a replay needs
/// <name>/paths/1/...      what path one was judged from
/// <name>/paths/2/...
/// ```
///
/// **Two halves rather than two buttons.** A bundle is wanted for two different reasons -- to hand
/// someone else a run they can reproduce, and to keep a record of what a determination rested on --
/// and those want incompatible filenames: replay needs `ta.cbor` because that is what `--ta-cbor` is
/// handed, while a path's material is named by its position in that path. A subtree each is what
/// lets one archive answer both without either half compromising.
///
/// **This is not the layout earlier exports used**, which put path folders at the top level. A
/// reader who knows the old shape finds the same path folders one level down under
/// [`PATHS_DIR`], with identical contents and the same numbering.
///
/// `name` names both the archive and the single directory inside it, so extracting leaves one
/// folder rather than scattering `inputs`, `paths` and `run.txt` into wherever it landed.
///
/// `inputs` is taken whole rather than pre-rendered, because the root file describes them too --
/// which time of interest to set, which graph to load -- and a caller assembling the subtree itself
/// could hand over a set the instructions did not match. A default `RunInputs` still produces a
/// valid archive of the paths, with the subtree absent rather than present and misleadingly bare.
pub fn zip_bundle(
    name: &str,
    paths: &[Vec<ExportEntry>],
    inputs: &RunInputs,
    run_ms: Option<u64>,
) -> Result<Vec<u8>, String> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut zw = ZipWriter::new(&mut buf);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

        let mut add = |path: String, bytes: &[u8]| -> Result<(), String> {
            zw.start_file(&path, options)
                .map_err(|e| format!("Failed to add {path} to the archive: {e}"))?;
            zw.write_all(bytes)
                .map_err(|e| format!("Failed to write {path} into the archive: {e}"))
        };

        add(
            format!("{name}/{README_NAME}"),
            render_readme(paths, inputs, run_ms).as_bytes(),
        )?;
        // At the root because it names files in both subtrees now, so it is about the bundle rather
        // than about either half of it.
        add(
            format!("{name}/{COMMAND_NAME}"),
            render_replay_command(inputs).as_bytes(),
        )?;
        for (file, bytes) in given_entries(inputs)
            .iter()
            .chain(derived_entries(inputs, paths).iter())
        {
            add(format!("{name}/{file}"), bytes)?;
        }
        for (i, entries) in paths.iter().enumerate() {
            for (file, bytes) in entries {
                add(format!("{name}/{PATHS_DIR}/{}/{file}", i + 1), bytes)?;
            }
        }

        zw.finish()
            .map_err(|e| format!("Failed to finish the archive: {e}"))?;
    }
    Ok(buf.into_inner())
}

/// The revocation artifacts from every path, gathered by kind and deduplicated by content.
///
/// Selected by the names [`path_entries`] gave them, which is where the kind is recorded: a `.crl`
/// is a CRL, a `.ocspResp` is a response. Two things are deliberately left behind. A `.crl.txt` is a
/// note saying where a CRL could be re-obtained, not a CRL, and would fail to parse as one. A
/// `.failed.ocspResp` is a response the run could not use, so feeding it back reproduces the
/// failure rather than avoiding the fetch -- it stays under [`PATHS_DIR`] as evidence, which is what
/// it is good for.
///
/// Numbered rather than keeping their path-local names, which collide once flattened -- every path
/// has a `1-crl.crl`. Provenance is not lost by this: `paths/` still holds each artifact beside the
/// path it settled, and the same bytes appear in both.
fn revocation_entries(paths: &[Vec<ExportEntry>]) -> Vec<ExportEntry> {
    let mut out = vec![];
    let mut seen: Vec<Vec<u8>> = vec![];
    let mut crls = 0;
    let mut responses = 0;
    for (file, bytes) in paths.iter().flatten() {
        let dir = match () {
            _ if file.ends_with(".crl") => CRL_DIR,
            _ if file.ends_with(".failed.ocspResp") => continue,
            _ if file.ends_with(".ocspResp") => OCSP_DIR,
            _ => continue,
        };
        if seen.contains(bytes) {
            continue;
        }
        seen.push(bytes.clone());
        let (n, ext) = match dir {
            CRL_DIR => (&mut crls, "crl"),
            _ => (&mut responses, "ocspResp"),
        };
        out.push((format!("{dir}/{n}.{ext}"), bytes.clone()));
        *n += 1;
    }
    out
}

/// The archive's root file: what the run did, and how to reproduce it in each app that can.
///
/// It exists for one figure and one audience. The figure is the run's elapsed time: every manifest
/// states what its own path took, but a run is not its paths added up -- retrieval, and whatever
/// happened between one path and the next, are in the run figure and in none of theirs -- so it is
/// the one number a reader cannot recover from the rest of the archive. The wording matches the
/// line closing the concatenated path log, so the same fact reads the same way in both exports.
///
/// The audience is whoever the bundle was handed to, which is the whole reason it exists. They may
/// not be a command line user, and the material is loadable by all three frontends -- both GUIs
/// take `.cbor` stores in their trust anchor and intermediate inputs, not only certificates -- so
/// naming the controls is the difference between a bundle that can be used and one that has to be
/// puzzled out.
fn render_readme(paths: &[Vec<ExportEntry>], inputs: &RunInputs, run_ms: Option<u64>) -> String {
    let toi = inputs.time_of_interest;
    // Everything the bundle actually holds, named rather than chosen between. The store and the
    // built graph are different facts and both are worth loading -- the graph carries the partial
    // paths the run found, the store is the wider set and the thing another bundle's store can be
    // compared against -- and the folders are what the paths were actually judged against, which is
    // all a bundle made from uploaded material may have. Naming only one of them was what sent a
    // reader loading the graph and quietly leaving the store behind.
    let join = |parts: Vec<String>| -> String {
        match parts.len() {
            0 => "(not in this bundle)".to_string(),
            _ => parts.join(", and "),
        }
    };
    let mut ta_parts = vec![];
    if inputs.anchors.is_some() {
        ta_parts.push(format!("{INPUTS_DIR}/{TA_NAME}"));
    }
    if !inputs.anchors_used.is_empty() {
        ta_parts.push(format!("the files in {DERIVED_DIR}/{TA_DIR}/"));
    }
    let anchors = join(ta_parts);

    let mut ca_parts = vec![];
    if inputs.built_graph.is_some() {
        ca_parts.push(format!("{DERIVED_DIR}/{BUILT_GRAPH_NAME}"));
    }
    if inputs.graph.is_some() {
        ca_parts.push(format!("{INPUTS_DIR}/{CA_NAME}"));
    }
    if !inputs.intermediates.is_empty() {
        ca_parts.push(format!("the files in {DERIVED_DIR}/{CA_DIR}/"));
    }
    let cas = join(ca_parts);

    let mut out = String::from(
        "PITTv3 bundle\n\nA PITTv3 bundle containing the inputs and results from a validation operation.\n\n",
    );
    out.push_str(&format!("Certification paths: {}\n", paths.len()));
    if let Some(ms) = run_ms {
        out.push_str(&format!("Time for the entire operation: {ms} ms\n"));
    }
    out.push_str(&format!(
        "\n  {INPUTS_DIR}/   inputs to a validation operation, i.e., trust anchors, settings, end entity certificates, etc.\n\
           \x20 {PATHS_DIR}/    the certification paths that were discovered and validated, one numbered folder per path\n\
           \x20 {REVOCATION_DIR}/ the same CRLs and OCSP responses the paths hold, gathered by kind\n"
    ));

    out.push_str("\n\nReproducing this run\n====================\n");
    out.push_str(&format!(
        "\nWhichever way you do it, set the time of interest to {toi}. Left at the current time, a \n\
         replay judges against a different moment and is a different run -- which is the one \n\
         difference most easily mistaken for changed behaviour.\n"
    ));

    out.push_str(&format!(
        "\nCommand line\n------------\n\
         Run the command in {COMMAND_NAME}, from inside this folder.\n"
    ));

    out.push_str(&format!(
        "\nDesktop app\n-----------\n\
         On the Validate view:\n\
         \x20 Trust anchor / CA store:       Custom (use the paths below)\n\
         \x20 Trust Anchors:                 {anchors}\n\
         \x20 Intermediate CA Certificates:  {cas}\n\
         \x20 End Entity Certificates:       the files in {INPUTS_DIR}/{EE_DIR}/\n\
         \x20 Time of Interest:              {toi}\n\
         On the Settings view:\n\
         \x20 Settings file:                 {INPUTS_DIR}/{SETTINGS_NAME}\n"
    ));

    out.push_str(&format!(
        "\nBrowser app\n-----------\n\
         \x20 Trust anchor / CA store:  None (uploaded trust anchors and CA certificates only)\n\
         Under \"Additional trust anchors and intermediates\":\n\
         \x20 Trust anchor(s):    {anchors}\n\
         \x20 Intermediate CA(s): {cas}\n\
         Then upload the certificate(s) in {INPUTS_DIR}/{EE_DIR}/ as the end entities, and \n\
         {INPUTS_DIR}/{SETTINGS_NAME} as the settings.\n"
    ));

    out.push_str(
        "\nThe trust anchor and intermediate inputs of both apps take `.cbor` stores as well as \n\
         certificates, so any .cbor file above goes straight in; it does not have to be unpacked.\n",
    );

    out.push_str(&format!(
        "\nChecking revocation without fetching anything\n\
         --------------------------------------------\n\
         {DERIVED_DIR}/{REVOCATION_DIR}/{CRL_DIR}/ and {DERIVED_DIR}/{REVOCATION_DIR}/{OCSP_DIR}/ hold the revocation artifacts \n\
         this run used, gathered out of the path folders. Supply them on the controls that take \n\
         CRLs and OCSP responses and a replay checks revocation from what is here, without \n\
         reaching a responder or a distribution point -- which is what a browser with no retrieval \n\
         service can do, and what makes a replay give the same answer later as the network moves \n\
         on. The same bytes are under {PATHS_DIR}/ beside the path each one settled.\n\
         \n\
         These folders hold only what the run actually examined. A run whose determinations came \n\
         from the revocation status cache examined nothing, so it has nothing to record and these \n\
         folders are empty -- the cache keeps the verdict, not the CRL or the response behind it. \n\
         Empty here therefore means the cache answered, not that revocation went unchecked. To \n\
         make a bundle that can check revocation offline, turn the revocation cache off for the \n\
         run that produces it.\n"
    ));

    // Say why a file is absent rather than leaving its absence to be interpreted. A reader
    // comparing two bundles cannot otherwise tell "this run built no graph" from "the graph was
    // dropped", and those mean opposite things about whether the bundle is complete.
    match (inputs.built_graph.is_some(), inputs.graph.is_some()) {
        (true, _) => out.push_str(&format!(
            "\n{BUILT_GRAPH_NAME} is the graph this run built, and carries the partial paths it \n\
             found, so loading it replays without building them again. {CA_NAME} beside it is the \n\
             store that graph was built from, unmodified -- it is the half another bundle's store \n\
             can be compared against. They are different files on purpose; load either.\n"
        )),
        (false, true) => out.push_str(&format!(
            "\nThere is no {BUILT_GRAPH_NAME} in this bundle because this run built no graph: it \n\
             validated against a store that already carries its partial paths. The absence means \n\
             nothing was built, not that anything was left out.\n"
        )),
        (false, false) => out.push_str(&format!(
            "\nThis bundle carries no CBOR store or graph -- the run's environment was supplied as \n\
             certificates rather than as a store. {DERIVED_DIR}/{TA_DIR}/ and {DERIVED_DIR}/{CA_DIR}/ hold what the paths were \n\
             actually judged against, which reproduces these targets on its own.\n"
        )),
    }
    out
}

/// Names the replay command expects to find, which are therefore the names [`given_entries`] writes.
///
/// Fixed rather than derived from whatever the run's inputs were called, because the command line in
/// the bundle refers to them: a name that varied would make the command a template a reader has to
/// edit rather than one they can run.
pub const TA_NAME: &str = "ta.cbor";
/// See [`TA_NAME`]. The graph half of the environment.
pub const CA_NAME: &str = "ca.cbor";
/// See [`TA_NAME`]. The path settings, as `-s` reads them.
pub const SETTINGS_NAME: &str = "settings.json";
/// See [`TA_NAME`]. The folder of end entity certificates, as `--end-entity-folder` reads it.
pub const EE_DIR: &str = "ee";
/// See [`TA_NAME`]. The folder of intermediate CA certificates, as `--ca-folder` reads it.
pub const CA_DIR: &str = "ca";
/// See [`TA_NAME`]. The folder of trust anchors, as `--ta` reads it.
pub const TA_DIR: &str = "ta";

/// The subtree gathering the revocation artifacts scattered through [`PATHS_DIR`] into one place
/// per kind, so they can be handed to the controls that take them.
///
/// **The same bytes as the paths hold, arranged for a different job.** Under `paths/` an artifact
/// sits with the path it settled, which is what makes that half a record; but a person feeding the
/// upload controls wants every CRL together and every response together, and gathering them by hand
/// out of numbered folders is the sort of work a bundle exists to save. Deduplicated by content,
/// since one CRL commonly settles a certificate that appears on several paths.
///
/// The case that motivates it is a browser with no retrieval service reachable: supplied revocation
/// data is the only way such a run checks anything, and this is that data, already gathered.
///
/// Under [`DERIVED_DIR`]: these artifacts are what the run collected, not what it was handed.
pub const REVOCATION_DIR: &str = "revocation";
/// Subfolder of [`REVOCATION_DIR`] holding the CRLs, for the supplied-CRL control.
pub const CRL_DIR: &str = "CRLs";
/// Subfolder of [`REVOCATION_DIR`] holding the OCSP responses, for the supplied-response control.
pub const OCSP_DIR: &str = "OCSP";
/// See [`TA_NAME`]. The graph the run built, when it built one.
///
/// Also a valid `ca.cbor` -- it is the same format, and `-b` reads it -- so it is an alternative to
/// [`CA_NAME`] rather than a companion to it, offered because it carries the partial paths the run
/// found and so replays without building them again.
pub const BUILT_GRAPH_NAME: &str = "built-graph.cbor";
/// See [`TA_NAME`]. The command that replays the run against the files beside it.
pub const COMMAND_NAME: &str = "command.txt";

/// Picks a CBOR trust anchor store out of material a user supplied, if one is there.
///
/// **A bundle has to survive being fed back in.** The environment used to be sourced only from how
/// it was configured -- a store the app fetched, a graph it built -- so a store that arrived on an
/// upload control reached the next bundle not at all, and `ta.cbor` and `ca.cbor` vanished after one
/// hop. Both apps already accept a `.cbor` store wherever they accept a certificate; this is the
/// same test they use to tell the two apart, so what the run treated as a store is what the bundle
/// records as one.
pub fn ta_store_among(supplied: &[ExportEntry]) -> Option<Vec<u8>> {
    supplied
        .iter()
        .find(|(_, bytes)| certval::TaSource::new_from_cbor(bytes).is_ok())
        .map(|(_, bytes)| bytes.clone())
}

/// Picks a CBOR CA store out of material a user supplied, if one is there. See [`ta_store_among`].
pub fn ca_store_among(supplied: &[ExportEntry]) -> Option<Vec<u8>> {
    supplied
        .iter()
        .find(|(_, bytes)| certval::CertSource::new_from_cbor(bytes).is_ok())
        .map(|(_, bytes)| bytes.clone())
}

/// What a run needs to be reproduced by someone else.
///
/// **Material, not paths.** A bundle recording `--ta-folder /Users/someone/anchors` is replayable
/// only by the person whose disk that is; a bundle carrying the anchors is replayable by anyone. So
/// the environment travels as bytes and the command line points at the bundle's own files. That is
/// also what lets the browser produce the same bundle as the desktop, having no filesystem paths to
/// record in the first place.
///
/// **Taken from the run, not from the form.** These have to be the values the run used rather than
/// what the inputs view shows at the moment somebody presses save -- the two differ as soon as
/// anything is edited after a run, and a bundle that misreports its own inputs is worse than no
/// bundle. The caller is responsible for that, which is why this is assembled from a run's retained
/// state rather than read here.
#[derive(Clone, Default)]
pub struct RunInputs {
    /// The anchors the run assembled, as a CBOR trust anchor store. `None` when the run's anchors
    /// are built rather than read -- webpki anchors are the case -- and there is nothing to write.
    pub anchors: Option<Vec<u8>>,
    /// The certificates the run searched together with the partial paths found among them, as the
    /// run read them -- the store file, unmodified, so it stays comparable against the store it
    /// came from and against the other frontend's copy of it.
    pub graph: Option<Vec<u8>>,
    /// The graph the run actually built, when building happened, kept **in addition** to [`graph`]
    /// rather than in place of it.
    ///
    /// The two are different facts and both are worth having: `ca.cbor` is the store as fetched,
    /// which is what makes a bundle comparable, and this is what the run made of it, which is what
    /// makes a replay fast and faithful. Writing the built graph as `ca.cbor` -- which is what the
    /// desktop did at first -- silently turns a store snapshot into something that resembles one
    /// and is not, and the difference is invisible in the file.
    ///
    /// [`graph`]: RunInputs::graph
    pub built_graph: Option<Vec<u8>>,
    /// The settings the run was carried out under, serialized as `-s` reads them.
    pub settings: Option<CertificationPathSettings>,
    /// The end entity certificates the run validated, named as they will appear in [`EE_DIR`].
    pub end_entities: Vec<ExportEntry>,
    /// Every anchor the run's paths actually terminated at, for [`TA_DIR`].
    ///
    /// **Taken off the paths so that it does not matter how the environment arrived.** A store the
    /// app fetched, a graph it built, a file somebody dropped on the upload control -- the bundle
    /// used to know about the first two and lose the third, which meant a bundle built from another
    /// bundle carried no anchors at all and the chain broke after one hop. What every route has in
    /// common is the validated path, and the anchor is on it.
    ///
    /// This is the **subset the run used**, where [`anchors`] is the whole store. Both travel when
    /// both exist: the subset always reproduces these targets, and the store is what a wider run
    /// would need and what another bundle's store can be compared against.
    ///
    /// [`anchors`]: RunInputs::anchors
    pub anchors_used: Vec<Vec<u8>>,
    /// Every intermediate the run's paths actually went through, for [`CA_DIR`].
    ///
    /// **The graph is not enough, and a replay proves it.** A run reaches intermediates the store
    /// does not carry -- chased over AIA, presented in a TLS handshake, uploaded by hand -- and
    /// `ca.cbor` is the store, so a bundle carrying only the store rebuilds an environment the run
    /// did not have. The first bundles that carried a complete environment still replayed to zero
    /// paths for exactly this reason, with the missing issuer sitting in the paths half all along.
    /// Taking them off the validated paths is what makes the inputs half assemble from what backed
    /// the run rather than from what the run was configured with.
    ///
    /// **A folder of DER rather than more `ca.cbor`, and the reason is worth keeping.** Folding
    /// these into the CBOR would mean rebuilding the partial-path graph at save time, which is work
    /// the run already did and which can come out differently -- the bundle would then carry a
    /// reconstruction where it now carries a record. It would also cost the property that makes
    /// `ca.cbor` worth comparing: it is the store, byte for byte, as both frontends fetched it. The
    /// graph cache was the other candidate and no CLI flag consumes it; it is keyed by fingerprint,
    /// private in format and desktop-only, so a bundle resting on it could not be replayed at all.
    /// Two files saying two true things beats one file saying a blurred one. The cost is that a
    /// folder carries no precomputed partial paths, so a replay builds them again and takes longer
    /// than the run did.
    ///
    /// Bytes rather than named entries: the names are assigned here, since what identifies a
    /// certificate to the builder is its content and a caller's name for it would only be a name
    /// the two frontends could disagree about.
    pub intermediates: Vec<Vec<u8>>,
    /// The instant the run judged against. In the bundle because a bare replay defaults it to now,
    /// and a run judged against a different moment is a different run.
    pub time_of_interest: u64,
    /// Whether the run pursued every path rather than stopping at the first that validated. In the
    /// bundle for the same reason as the time of interest: it changes what comes out.
    pub validate_all: bool,
    /// Which store the environment came from, when it came from a named one. `"NIPR"` is not a
    /// store -- a particular snapshot of NIPR is -- so this records the label for a reader and does
    /// not pretend to identify the snapshot.
    pub store: Option<String>,
}

/// The [`INPUTS_DIR`] half of a bundle: the material, and the command line that replays it.
///
/// Only what is actually held appears. A missing piece is left out rather than written empty, and
/// the command line names only the files that are there, so it stays a command someone can run
/// instead of one that refers to files the archive does not contain.
pub fn given_entries(inputs: &RunInputs) -> Vec<ExportEntry> {
    let mut out = vec![];
    if let Some(bytes) = &inputs.anchors {
        out.push((format!("{INPUTS_DIR}/{TA_NAME}"), bytes.clone()));
    }
    if let Some(bytes) = &inputs.graph {
        out.push((format!("{INPUTS_DIR}/{CA_NAME}"), bytes.clone()));
    }
    if let Some(cps) = &inputs.settings {
        // A settings file that will not serialize is not a reason to lose the rest of the bundle;
        // the command line drops `-s` to match, and the README still says what the run did.
        if let Ok(json) = serde_json::to_vec_pretty(&replayable_settings(cps)) {
            out.push((format!("{INPUTS_DIR}/{SETTINGS_NAME}"), json));
        }
    }
    // Two targets read from different folders can share a basename, and an archive entry written
    // twice is one file holding whichever was written last. Numbering the repeats keeps both.
    let mut used: Vec<String> = vec![];
    for (name, bytes) in &inputs.end_entities {
        let mut entry = ee_entry_name(name);
        let mut n = 1;
        while used.contains(&entry) {
            entry = format!("{n}-{}", ee_entry_name(name));
            n += 1;
        }
        used.push(entry.clone());
        out.push((format!("{INPUTS_DIR}/{EE_DIR}/{entry}"), bytes.clone()));
    }
    out
}

/// The [`DERIVED_DIR`] subtree: what the run worked out, offered so a replay does not have to work
/// it out again -- or, where the environment was supplied as loose certificates, so that a replay
/// has an environment at all.
pub fn derived_entries(inputs: &RunInputs, paths: &[Vec<ExportEntry>]) -> Vec<ExportEntry> {
    let mut out = vec![];
    if let Some(bytes) = &inputs.built_graph {
        out.push((format!("{DERIVED_DIR}/{BUILT_GRAPH_NAME}"), bytes.clone()));
    }
    // Deduplicated by content: one anchor terminates several paths and one intermediate is commonly
    // on several, and the same bytes written twice is one file either way.
    let mut ta_seen: Vec<&Vec<u8>> = vec![];
    for (i, bytes) in inputs.anchors_used.iter().enumerate() {
        if ta_seen.contains(&bytes) {
            continue;
        }
        ta_seen.push(bytes);
        out.push((format!("{DERIVED_DIR}/{TA_DIR}/{i}.der"), bytes.clone()));
    }
    let mut ca_seen: Vec<&Vec<u8>> = vec![];
    for (i, bytes) in inputs.intermediates.iter().enumerate() {
        if ca_seen.contains(&bytes) {
            continue;
        }
        ca_seen.push(bytes);
        out.push((format!("{DERIVED_DIR}/{CA_DIR}/{i}.der"), bytes.clone()));
    }
    for (file, bytes) in revocation_entries(paths) {
        out.push((format!("{DERIVED_DIR}/{REVOCATION_DIR}/{file}"), bytes));
    }
    out
}

/// The run's settings with the retired keys taken out, for a file someone else will run.
///
/// Both retired names hold an absolute path to a file on the machine that ran the validation, and
/// **neither does anything any more** -- certval logs them and ignores them
/// ([`certval::RETIRED_SETTINGS_KEYS`]). Passing them on would put one person's directory layout
/// into an artifact meant to be handed over, and buy the recipient a warning about a path they do
/// not have, in exchange for nothing. That the list comes from certval rather than being repeated
/// here is what keeps the two from disagreeing later about which names are dead.
///
/// Only these are removed. A live setting that happens to hold a path is left alone: it changed
/// what the run did, so a bundle that dropped it would misreport the run, and misreporting is the
/// worse failure. What to do about those is a separate question from this one.
fn replayable_settings(cps: &CertificationPathSettings) -> CertificationPathSettings {
    let mut out = cps.clone();
    for key in certval::RETIRED_SETTINGS_KEYS {
        out.0.remove(key);
    }
    out
}

/// The name an end entity certificate takes inside [`EE_DIR`].
///
/// End entities are named by whatever the caller called them, and the two frontends call them
/// different things: the desktop knows a target by the path it was read from, the browser by the
/// name of the upload. Reducing both to a basename here is what lets one bundle be compared against
/// the other, and it keeps a local directory layout out of an artifact meant to be handed over --
/// `/Users/someone/.pittv3/peeked/host/0-presented.der` names a file on one machine and identifies
/// nothing on any other.
///
/// A `.der` extension is added when there is none, since the name reaches a folder handed to
/// `--end-entity-folder` and the contents are DER whatever the source called them. An existing
/// extension is left alone rather than having a second one appended.
fn ee_entry_name(name: &str) -> String {
    let base = name
        .trim()
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim();
    let cleaned: String = base
        .chars()
        .map(|c| match c {
            ':' => '_',
            c => c,
        })
        .collect();
    let stem = match cleaned.is_empty() {
        true => "target",
        false => cleaned.as_str(),
    };
    // A dot is not an extension: a target named for the host it was presented by, which is what an
    // upload of a peeked certificate is called, is all dots and no suffix. Matching the suffixes a
    // certificate actually carries is what keeps `www.example.com` from being taken as a `.com`
    // file, and keeps `.der` from being appended to a name that already ends in one.
    let suffixed = CERT_SUFFIXES
        .iter()
        .any(|ext| stem.to_ascii_lowercase().ends_with(ext));
    match suffixed {
        true => stem.to_string(),
        false => format!("{stem}.der"),
    }
}

/// The file suffixes a certificate is commonly given. Only used to decide whether a name already
/// says it is a certificate; the contents are DER regardless of what the name claims.
const CERT_SUFFIXES: [&str; 6] = [".der", ".cer", ".crt", ".pem", ".p7c", ".p7b"];

/// The command line that reproduces the run, run from the bundle's own folder.
///
/// **Replay is the acceptance test for this bundle.** Contents are not the measure -- it is worth
/// having exactly when it can be handed to the CLI and produce the same report -- so the flags here
/// are the ones `pittv3` actually defines rather than a plausible spelling of them. `ta.cbor` is a
/// CBOR trust anchor store and goes to `--ta-cbor`, not to `-t`, which takes a folder of DER
/// anchors; the graph goes to `-b`.
///
/// It names files in both subtrees, because reproducing needs what the run was given *and* what it
/// worked out. That is also why it lives at the root rather than inside either one.
///
/// `-i` is always present. Without it a replay defaults the time of interest to whenever the replay
/// happens, which silently makes it a different run -- the one failure mode most likely to be
/// mistaken for a real difference in behavior.
fn render_replay_command(inputs: &RunInputs) -> String {
    let has_settings = inputs
        .settings
        .as_ref()
        .is_some_and(|cps| serde_json::to_vec(&replayable_settings(cps)).is_ok());

    let mut cmd = String::from("pittv3");
    // The store when there is one, and the anchors the paths used either way. They are not
    // alternatives: the store is the wider set a `-v` sweep needs, the folder is what these targets
    // were actually judged against, and `--ta-cbor` and `--ta` combine their anchors rather than one
    // displacing the other.
    if inputs.anchors.is_some() {
        cmd.push_str(&format!(" --ta-cbor {INPUTS_DIR}/{TA_NAME}"));
    }
    if !inputs.anchors_used.is_empty() {
        cmd.push_str(&format!(" --ta {DERIVED_DIR}/{TA_DIR}"));
    }
    match inputs.built_graph.is_some() {
        true => cmd.push_str(&format!(" -b {DERIVED_DIR}/{BUILT_GRAPH_NAME}")),
        false => {
            if inputs.graph.is_some() {
                cmd.push_str(&format!(" -b {INPUTS_DIR}/{CA_NAME}"));
            }
        }
    }
    if !inputs.intermediates.is_empty() {
        cmd.push_str(&format!(" -c {DERIVED_DIR}/{CA_DIR}"));
    }
    if has_settings {
        cmd.push_str(&format!(" -s {INPUTS_DIR}/{SETTINGS_NAME}"));
    }
    if !inputs.end_entities.is_empty() {
        cmd.push_str(&format!(" --end-entity-folder {INPUTS_DIR}/{EE_DIR}"));
    }
    cmd.push_str(&format!(" -i {}", inputs.time_of_interest));
    if inputs.validate_all {
        cmd.push_str(" -v");
    }

    let mut out =
        String::from("Run this from this folder to reproduce the run this bundle came from.\n\n");
    out.push_str(&cmd);
    out.push('\n');

    let stripped: Vec<&str> = match &inputs.settings {
        None => vec![],
        Some(cps) => certval::RETIRED_SETTINGS_KEYS
            .into_iter()
            .filter(|key| cps.0.contains_key(*key))
            .collect(),
    };
    if !stripped.is_empty() {
        out.push_str(&format!(
            "\n{SETTINGS_NAME} is the run's settings less {} -- retired name(s) the run carried \
             that no longer do anything and that named files on the machine the run happened on. \
             Nothing the run acted on was removed.\n",
            stripped.join(", ")
        ));
    }
    if let Some(store) = &inputs.store {
        // Only claim the material is here when it is. The sentence exists to tell a reader that the
        // files beside it are a snapshot rather than a store name they can look up later, and said
        // over an absent environment it asserts the opposite of the truth.
        match inputs.anchors.is_some() || inputs.graph.is_some() {
            true => out.push_str(&format!(
                "\nThe environment came from the {store} store. {INPUTS_DIR}/ holds that store as \
                 this run read it; the same name may mean different bytes later.\n"
            )),
            false => out.push_str(&format!(
                "\nThe environment came from the {store} store, and the store itself is NOT in \
                 this bundle -- {DERIVED_DIR}/ carries only what these paths were judged against.\n"
            )),
        }
    }
    if inputs.anchors.is_none() && inputs.anchors_used.is_empty() && inputs.store.is_none() {
        out.push_str(
            "\nNo trust anchors are in this bundle, so the command above will not reproduce the \
             run on its own. Supply the environment the run used.\n",
        );
    }
    out
}

/// The manifests alone, one after another, for a caller wanting the account of every path without
/// the material behind it.
///
/// Taken back out of the same entries the archive carries rather than rendered a second time, so the
/// two exports cannot disagree about what the run found.
///
/// `run_ms` closes the log with what the run took. Every manifest already states what its own path
/// took, but the run is not the paths added up -- retrieval, and whatever the run did between one
/// path and the next, are in the run figure and in none of theirs -- so it is the one number a
/// reader cannot recover from the file, and without it comparing this export against another means
/// going back to a terminal that may be gone. It is an `Option` because a caller with no run to time
/// has nothing honest to put there, and a zero would read as a run that took no time.
///
/// **The archive states the same figure in [`README_NAME`] at its root**, in the same words, so the two
/// exports of one run agree about it rather than only one of them knowing. That file is where the
/// figure lives in the archive because every other entry there is about a path, not about the run.
/// The per-path manifests are identical in both exports, which is the property that matters: the
/// concatenated log and the archived manifests are one document, plus a line about the run.
pub fn paths_text(paths: &[Vec<ExportEntry>], run_ms: Option<u64>) -> String {
    let mut out = String::new();
    for entries in paths {
        let Some((_, bytes)) = entries.iter().find(|(name, _)| name == PATH_LOG_NAME) else {
            continue;
        };
        out.push_str(&String::from_utf8_lossy(bytes));
        out.push('\n');
    }

    // Nothing rendered means there was nothing to save, and callers key on that. A trailer alone
    // would turn "no paths" into a file reporting how long it took to find none.
    if out.is_empty() {
        return out;
    }
    if let Some(ms) = run_ms {
        out.push_str(&format!("Time for the entire operation: {ms} ms\n"));
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

    /// Helper: everything the two subtrees hold, for a test that only cares what is present.
    fn all_entries(inputs: &RunInputs) -> Vec<ExportEntry> {
        let mut out = given_entries(inputs);
        out.extend(derived_entries(inputs, &[]));
        out
    }

    /// Helper: the replay command's text.
    fn command_text(inputs: &RunInputs) -> String {
        render_replay_command(inputs)
    }

    /// Helper: every entry name in an archive, sorted.
    fn names_in(zipped: Vec<u8>) -> Vec<String> {
        let mut archive = zip::ZipArchive::new(Cursor::new(zipped)).unwrap();
        let mut names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        names.sort();
        names
    }

    /// The name of an artifact is the digest of its own bytes, in full. A reader can check any file
    /// against its name, and two bundles can be compared without trusting either's filenames.
    #[test]
    fn an_artifact_is_named_by_the_digest_of_its_own_bytes() {
        let named = content_addressed_name("1-crl.crl", b"the bytes");
        // sha256("the bytes"), the whole of it -- a prefix would leave the tail meaningless, and
        // comparing digests by eye uses both ends
        let expected = {
            use sha2::{Digest, Sha256};
            Sha256::digest(b"the bytes")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert_eq!(expected.len(), 64);
        assert_eq!(named, format!("1-crl.{expected}.crl"));

        // the position and role still lead, since a digest cannot say where in the chain a
        // certificate sat
        assert!(named.starts_with("1-crl."), "{named}");

        // a compound extension survives: the split is at the first dot, and the stems carry none
        let failed = content_addressed_name("3-ocsp-0.failed.ocspResp", b"x");
        assert!(failed.ends_with(".failed.ocspResp"), "{failed}");
        assert!(failed.starts_with("3-ocsp-0."), "{failed}");

        // identical bytes under different positions still name the same digest
        let a = content_addressed_name("1.der", b"same");
        let b = content_addressed_name("2.der", b"same");
        assert_eq!(a[2..], b[2..], "{a} vs {b}");
    }

    /// A folder of digests describes nothing on its own, so the manifest says what each file is.
    #[test]
    fn the_folder_manifest_names_every_file_and_what_it_is() {
        let artifacts = vec![
            (
                content_addressed_name("0-ta.der", b"anchor"),
                b"anchor".to_vec(),
            ),
            (content_addressed_name("1.der", b"ca"), b"ca".to_vec()),
            (
                content_addressed_name("2-target.der", b"ee"),
                b"ee".to_vec(),
            ),
            (content_addressed_name("1-crl.crl", b"crl"), b"crl".to_vec()),
        ];
        let manifest = render_folder_manifest(&artifacts);
        for (name, _) in &artifacts {
            assert!(manifest.contains(name), "{name} missing from:\n{manifest}");
        }
        assert!(manifest.contains("trust anchor"), "{manifest}");
        assert!(
            manifest.contains("intermediate CA certificate"),
            "{manifest}"
        );
        assert!(manifest.contains("target certificate"), "{manifest}");
        assert!(manifest.contains("CRL consulted"), "{manifest}");

        // A request and a response share the `-ocsp` stem, so the kind comes off the extension.
        // Calling a request a response asserts something was consulted when it was only sent.
        let ocsp = vec![
            (
                content_addressed_name("1-ocsp.ocspReq", b"req"),
                b"req".to_vec(),
            ),
            (
                content_addressed_name("1-ocsp.ocspResp", b"resp"),
                b"resp".to_vec(),
            ),
            (
                content_addressed_name("2-ocsp-0.failed.ocspResp", b"bad"),
                b"bad".to_vec(),
            ),
        ];
        let m = render_folder_manifest(&ocsp);
        assert!(m.contains("OCSP request sent"), "{m}");
        assert!(m.contains("OCSP response consulted"), "{m}");
        assert!(m.contains("could not be used"), "{m}");
        // and it tells a reader how to check a name against its file
        assert!(manifest.contains("shasum -a 256"), "{manifest}");
    }

    /// The layout the bundle decision settled on: one directory named by the caller, holding a
    /// run-level file and the two halves. Path folders keep their numbering from one, now a level
    /// down under `paths/`.
    #[test]
    fn the_bundle_has_two_halves_and_a_run_file_under_one_name() {
        let paths = vec![
            vec![(PATH_LOG_NAME.to_string(), b"first".to_vec())],
            vec![(PATH_LOG_NAME.to_string(), b"second".to_vec())],
        ];
        let inputs = RunInputs {
            anchors: Some(b"anchors".to_vec()),
            settings: Some(CertificationPathSettings::new()),
            ..Default::default()
        };
        assert_eq!(
            names_in(zip_bundle("MyExport", &paths, &inputs, Some(99)).unwrap()),
            vec![
                "MyExport/README.txt".to_string(),
                "MyExport/command.txt".to_string(),
                "MyExport/inputs/settings.json".to_string(),
                "MyExport/inputs/ta.cbor".to_string(),
                "MyExport/paths/1/PathLog.txt".to_string(),
                "MyExport/paths/2/PathLog.txt".to_string(),
            ]
        );
    }

    /// The revocation artifacts are gathered by kind so they can be handed to the controls that
    /// take them, which is what lets a replay check revocation without reaching the network at all.
    /// Deduplicated by content, since one CRL commonly settles a certificate on several paths.
    #[test]
    fn revocation_artifacts_are_gathered_by_kind() {
        let crl = b"a-crl".to_vec();
        let paths = vec![
            vec![
                (PATH_LOG_NAME.to_string(), b"m".to_vec()),
                ("1-crl.crl".to_string(), crl.clone()),
                ("2-ocsp-0.ocspResp".to_string(), b"a-response".to_vec()),
                // a note about where a CRL could be re-obtained is not a CRL
                ("3-crl.crl.txt".to_string(), b"see http://...".to_vec()),
                // a response the run could not use reproduces the failure rather than avoiding it
                ("3-ocsp-0.failed.ocspResp".to_string(), b"bad".to_vec()),
                // responder certificates are certificates
                ("2-ocsp-0-cert-0.der".to_string(), vec![0x30]),
            ],
            // the same CRL again, on another path
            vec![("1-crl.crl".to_string(), crl)],
        ];

        let names = names_in(zip_bundle("B", &paths, &RunInputs::default(), None).unwrap());
        let rev: Vec<&String> = names
            .iter()
            .filter(|n| n.starts_with("B/derived/revocation/"))
            .collect();
        assert_eq!(
            rev,
            vec![
                &"B/derived/revocation/CRLs/0.crl".to_string(),
                &"B/derived/revocation/OCSP/0.ocspResp".to_string(),
            ],
            "{rev:?}"
        );

        // and the path folders still hold everything, including what the gathering left behind
        assert!(
            names.contains(&"B/paths/1/3-crl.crl.txt".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"B/paths/1/3-ocsp-0.failed.ocspResp".to_string()),
            "{names:?}"
        );
        assert!(
            names.iter().any(|n| n.starts_with("B/paths/2/1-crl.")),
            "{names:?}"
        );
    }

    /// A caller with nothing replayable to offer still produces a usable archive of the paths. The
    /// subtree is absent rather than present and empty, so its presence means something.
    #[test]
    fn no_inputs_means_no_inputs_subtree() {
        let paths = vec![vec![(PATH_LOG_NAME.to_string(), b"only".to_vec())]];
        let names = names_in(zip_bundle("Run", &paths, &RunInputs::default(), None).unwrap());
        // Nothing was given and nothing derived, so neither subtree appears -- present and empty
        // would suggest the run had material worth recording that was dropped.
        assert!(!names.iter().any(|n| n.contains("/inputs/")), "{names:?}");
        assert!(!names.iter().any(|n| n.contains("/derived/")), "{names:?}");
        // The command is written regardless: it is what tells a reader the rest is missing.
        assert!(names.contains(&"Run/command.txt".to_string()), "{names:?}");
        assert!(names.contains(&"Run/paths/1/PathLog.txt".to_string()));
        assert!(names.contains(&"Run/README.txt".to_string()));
    }

    /// The root file carries the one figure no manifest can state, in the same words the
    /// concatenated log closes with, so a reader comparing the two exports of one run is not left
    /// deciding whether two phrasings mean the same thing.
    #[test]
    fn the_readme_states_the_run_figure_the_way_the_log_does() {
        let paths = vec![vec![(PATH_LOG_NAME.to_string(), b"one".to_vec())]];
        let readme = render_readme(&paths, &RunInputs::default(), Some(1234));
        assert!(readme.contains("Time for the entire operation: 1234 ms"));
        assert!(readme.contains("Certification paths: 1"));

        let line = "Time for the entire operation: 1234 ms";
        assert!(paths_text(&paths, Some(1234)).contains(line) && readme.contains(line));

        // A run with no figure to report says nothing rather than reporting a zero, which would
        // read as a run that took no time.
        let untimed = render_readme(&paths, &RunInputs::default(), None);
        assert!(!untimed.contains("Time for the entire operation"));
        assert!(untimed.contains("Certification paths: 1"));
    }

    /// The bundle is handed to someone else, and they may not be a command line user. The root
    /// file names the controls of each app that can load the material, and points at the graph the
    /// bundle actually carries -- the built one where there is one, the store otherwise.
    #[test]
    fn the_readme_tells_each_app_what_to_load() {
        let paths = vec![vec![(PATH_LOG_NAME.to_string(), b"one".to_vec())]];
        let store_only = RunInputs {
            anchors: Some(b"anchors".to_vec()),
            graph: Some(b"store".to_vec()),
            anchors_used: vec![b"an-anchor".to_vec()],
            intermediates: vec![b"an-intermediate".to_vec()],
            settings: Some(CertificationPathSettings::new()),
            end_entities: vec![("ee.der".to_string(), vec![0x30])],
            time_of_interest: 1_788_356_707,
            ..Default::default()
        };
        let readme = render_readme(&paths, &store_only, None);

        // the time of interest is stated once, for every route, because leaving it at now is the
        // difference most easily mistaken for changed behaviour
        assert!(readme.contains("1788356707"), "{readme}");
        // Every file a reader has to find is named. Asserted instead of the prose around them:
        // the wording here is the author's to tune, and a test that breaks on a reword teaches
        // people to stop rewording. Same rule as the run-figure trailer, which pins the figure and
        // not the sentence carrying it.
        for needed in [COMMAND_NAME, TA_NAME, SETTINGS_NAME, EE_DIR, CA_DIR] {
            assert!(readme.contains(needed), "{needed} unnamed in:\n{readme}");
        }
        // The two GUI controls are pinned, because those strings are not prose -- they have to
        // match what is on screen, and a reader typing them into the wrong box gets a different
        // environment rather than an error.
        assert!(readme.contains("Trust anchor / CA store"), "{readme}");
        assert!(readme.contains("Intermediate CA Certificates"), "{readme}");
        assert!(
            readme.contains("Additional trust anchors and intermediates"),
            "{readme}"
        );
        // With no built graph, the store is what it tells them to load -- and the file's absence
        // is explained rather than left to be interpreted. A reader comparing two bundles cannot
        // otherwise tell "this run built no graph" from "the graph was dropped", and those mean
        // opposite things about whether what they are holding is complete.
        assert!(readme.contains(CA_NAME), "{readme}");
        assert!(readme.contains("built no graph"), "{readme}");
        assert!(
            readme.contains("not that anything was left out"),
            "{readme}"
        );

        // Where a run built one, **both** are named. Naming only the graph is what sent a reader
        // loading it and quietly leaving the store behind, and the store is the half another
        // bundle's store can be compared against -- so a bundle that holds both must say so.
        let built = RunInputs {
            built_graph: Some(b"built".to_vec()),
            ..store_only
        };
        let readme = render_readme(&paths, &built, None);
        assert!(readme.contains(BUILT_GRAPH_NAME), "{readme}");
        assert!(readme.contains(CA_NAME), "{readme}");
        assert!(readme.contains(TA_NAME), "{readme}");
        assert!(readme.contains(TA_DIR), "{readme}");
        // and it says the two are deliberate rather than leaving a reader to guess
        assert!(readme.contains("different files on purpose"), "{readme}");
    }

    /// The replay command is the acceptance test for the inputs half, so it must name the flags
    /// `pittv3` actually defines. `ta.cbor` is a CBOR anchor store and goes to `--ta-cbor`; `-t`
    /// takes a folder of DER anchors and would reject it.
    #[test]
    fn the_replay_command_names_the_flags_the_cli_defines() {
        let inputs = RunInputs {
            anchors: Some(b"anchors".to_vec()),
            graph: Some(b"graph".to_vec()),
            settings: Some(CertificationPathSettings::new()),
            end_entities: vec![("target.der".to_string(), vec![0x30])],
            time_of_interest: 1_788_356_707,
            validate_all: true,
            store: Some("dod_nipr_prod".to_string()),
            ..Default::default()
        };
        let command = command_text(&inputs);

        // Every flag points into the subtree that actually holds the file: what the run was given
        // under `inputs/`, what it worked out under `derived/`.
        assert!(command.contains("--ta-cbor inputs/ta.cbor"), "{command}");
        assert!(command.contains("-b inputs/ca.cbor"), "{command}");
        assert!(command.contains("-s inputs/settings.json"), "{command}");
        assert!(
            command.contains("--end-entity-folder inputs/ee"),
            "{command}"
        );
        assert!(command.contains("-v"), "{command}");
        // the store label is a note to a reader, not an input the command can take
        assert!(command.contains("dod_nipr_prod"), "{command}");
        // `-t` would be handed a file it cannot read
        assert!(!command.contains(" -t "), "{command}");
    }

    /// A bundle without the environment is still worth saving, but the file that tells a reader
    /// how to replay it must not say the material is present. The first desktop bundles said
    /// exactly that over an empty inputs half, which is the one failure a replay kit cannot have.
    #[test]
    fn the_command_does_not_claim_an_environment_it_does_not_carry() {
        let absent = RunInputs {
            store: Some("MOZILLA_ALL".to_string()),
            time_of_interest: 1,
            ..Default::default()
        };
        let text = command_text(&absent);
        assert!(text.contains("NOT in this bundle"), "{text}");
        assert!(!text.contains("as this run read it"), "{text}");

        let present = RunInputs {
            anchors: Some(b"anchors".to_vec()),
            store: Some("MOZILLA_ALL".to_string()),
            time_of_interest: 1,
            ..Default::default()
        };
        let text = command_text(&present);
        assert!(text.contains("as this run read it"), "{text}");
        assert!(!text.contains("NOT in this bundle"), "{text}");

        // and with no store named either, the reader is still told the command is incomplete
        let bare = RunInputs {
            time_of_interest: 1,
            ..Default::default()
        };
        let text = command_text(&bare);
        assert!(text.contains("will not reproduce the run"), "{text}");
    }

    /// A bundle made from another bundle carried no anchors at all: the environment was sourced
    /// from how it was configured -- a store fetch, a graph cache -- and material that arrived by
    /// upload reached neither. Taking the anchors off the validated paths is what makes the source
    /// stop mattering, and it is verified: `--ta ta -c ca` with no CBOR at all reproduced a run
    /// exactly, 5 paths and 5 valid.
    #[test]
    fn the_anchors_a_run_used_travel_with_it_however_the_environment_arrived() {
        let shared = b"one-anchor".to_vec();
        let uploaded_only = RunInputs {
            anchors_used: vec![shared.clone(), shared, b"another".to_vec()],
            intermediates: vec![b"an-intermediate".to_vec()],
            time_of_interest: 1,
            ..Default::default()
        };
        let entries = all_entries(&uploaded_only);
        let tas: Vec<&String> = entries
            .iter()
            .map(|(n, _)| n)
            .filter(|n| n.starts_with("derived/ta/"))
            .collect();
        // deduplicated by content: one anchor is commonly the end of several paths
        assert_eq!(tas.len(), 2, "{tas:?}");

        let command = command_text(&uploaded_only);
        assert!(command.contains(" --ta derived/ta"), "{command}");
        // and with anchors present it must not claim the bundle has none
        assert!(!command.contains("will not reproduce the run"), "{command}");

        // where a store was used too, both travel: `--ta-cbor` and `--ta` combine their anchors,
        // the store being the wider set and the folder what these targets were judged against
        let with_store = RunInputs {
            anchors: Some(b"the store".to_vec()),
            ..uploaded_only
        };
        let command = command_text(&with_store);
        assert!(
            command.contains(&format!(" --ta-cbor {INPUTS_DIR}/{TA_NAME}")),
            "{command}"
        );
        assert!(command.contains(" --ta derived/ta"), "{command}");
    }

    /// The intermediates a run reached are not the store, and a replay that gets only the store
    /// finds no path at all -- verified against a real bundle, which replayed to zero paths with
    /// the missing issuer sitting in the paths half the whole time. They travel as a folder the
    /// existing `--ca-folder` reads, deduplicated by content since one intermediate is commonly on
    /// several paths.
    #[test]
    fn the_intermediates_a_run_reached_travel_with_it() {
        let shared = b"one-ca".to_vec();
        let inputs = RunInputs {
            intermediates: vec![shared.clone(), b"another".to_vec(), shared],
            time_of_interest: 1,
            ..Default::default()
        };
        let entries = all_entries(&inputs);
        let cas: Vec<&String> = entries
            .iter()
            .map(|(n, _)| n)
            .filter(|n| n.starts_with("derived/ca/"))
            .collect();
        assert_eq!(cas.len(), 2, "{cas:?}");

        let command = command_text(&inputs);
        assert!(command.contains(" -c derived/ca"), "{command}");
    }

    /// The built graph is kept **in addition** to the store rather than written over it. Both are
    /// true statements and only one of them is comparable against another bundle; a built graph
    /// saved as `ca.cbor` resembles a store snapshot and is not one.
    #[test]
    fn a_built_graph_does_not_displace_the_store_it_was_built_from() {
        let inputs = RunInputs {
            graph: Some(b"the store".to_vec()),
            built_graph: Some(b"what the run made of it".to_vec()),
            time_of_interest: 1,
            ..Default::default()
        };
        let entries = all_entries(&inputs);
        let by_name = |n: &str| {
            entries
                .iter()
                .find(|(name, _)| name == n)
                .map(|(_, b)| b.clone())
        };
        assert_eq!(
            by_name(&format!("{INPUTS_DIR}/{CA_NAME}")),
            Some(b"the store".to_vec())
        );
        assert_eq!(
            by_name(&format!("{DERIVED_DIR}/{BUILT_GRAPH_NAME}")),
            Some(b"what the run made of it".to_vec())
        );

        // the command replays from the built graph; that the store is also there to swap in is
        // the README's job to say, and it is asserted where the README is tested
        let command = command_text(&inputs);
        assert!(
            command.contains(&format!(" -b {DERIVED_DIR}/{BUILT_GRAPH_NAME}")),
            "{command}"
        );

        // with no build to report, the store is what the command names
        let store_only = RunInputs {
            graph: Some(b"the store".to_vec()),
            time_of_interest: 1,
            ..Default::default()
        };
        let command = command_text(&store_only);
        assert!(
            command.contains(&format!(" -b {INPUTS_DIR}/{CA_NAME}")),
            "{command}"
        );
        assert!(!command.contains(BUILT_GRAPH_NAME), "{command}");
    }

    /// The retired names hold an absolute path on the machine that ran the validation and do
    /// nothing, so they are left behind rather than handed to someone else along with one person's
    /// directory layout. Live settings stay, path-valued or not: they changed what the run did, and
    /// a bundle that dropped them would misreport it.
    #[test]
    fn retired_settings_are_left_behind_and_the_reader_is_told() {
        let mut cps = CertificationPathSettings::new();
        cps.set_certification_authority_folder("/Users/someone/cas".to_string());
        for key in certval::RETIRED_SETTINGS_KEYS {
            cps.0.insert(
                key.to_string(),
                certval::CertificationPathProcessingTypes::String(
                    "/Users/someone/thing.json".to_string(),
                ),
            );
        }

        let cps_inputs = RunInputs {
            settings: Some(cps),
            time_of_interest: 1,
            ..Default::default()
        };
        let entries = all_entries(&cps_inputs);
        let by = |n: &str| {
            String::from_utf8(
                entries
                    .iter()
                    .find(|(name, _)| name == n)
                    .unwrap()
                    .1
                    .clone(),
            )
            .unwrap()
        };

        let written = by(&format!("{INPUTS_DIR}/{SETTINGS_NAME}"));
        for key in certval::RETIRED_SETTINGS_KEYS {
            assert!(!written.contains(key), "{written}");
        }
        // the live path-valued setting is untouched -- it changed what the run did
        assert!(written.contains("/Users/someone/cas"), "{written}");

        // and the removal is stated rather than done silently
        let command = command_text(&cps_inputs);
        assert!(command.contains("psLastModifiedMapFile"), "{command}");
        assert!(
            command.contains("Nothing the run acted on was removed"),
            "{command}"
        );

        // settings carrying none of them say nothing about it
        let command = command_text(&RunInputs {
            settings: Some(CertificationPathSettings::new()),
            time_of_interest: 1,
            ..Default::default()
        });
        assert!(!command.contains("retired name"), "{command}");
    }

    /// A replay that defaults the time of interest to whenever it runs is a different run, and one
    /// whose difference is easy to mistake for changed behavior. The flag is never omitted.
    #[test]
    fn the_replay_command_always_pins_the_time_of_interest() {
        let bare = RunInputs {
            time_of_interest: 1_788_356_707,
            ..Default::default()
        };
        let command = command_text(&bare);
        assert!(command.contains("-i 1788356707"), "{command}");
        // nothing was held, so the command names no files it cannot find beside itself
        assert!(!command.contains("inputs/ta.cbor"), "{command}");
        assert!(!command.contains("inputs/settings.json"), "{command}");
        assert!(!command.contains(" -v"), "{command}");
    }

    /// A target is named by whatever named it -- a path on the desktop, an upload in the browser --
    /// and neither name belongs in an artifact meant to be handed over.
    #[test]
    fn an_end_entity_is_named_by_its_basename_not_its_provenance() {
        let inputs = RunInputs {
            end_entities: vec![
                // what the desktop knows a target by: the path it was read from
                (
                    "/Users/someone/.pittv3/peeked/host/0-presented.der".to_string(),
                    vec![0x30],
                ),
                ("C:\\certs\\ee.der".to_string(), vec![0x31]),
                // what the browser knows one by: an upload, often with no extension
                ("www.example.com".to_string(), vec![0x32]),
                ("   ".to_string(), vec![0x33]),
            ],
            ..Default::default()
        };
        let names: Vec<String> = all_entries(&inputs).into_iter().map(|(n, _)| n).collect();
        // no local directory layout rides along
        assert!(
            names.contains(&"inputs/ee/0-presented.der".to_string()),
            "{names:?}"
        );
        assert!(names.contains(&"inputs/ee/ee.der".to_string()), "{names:?}");
        // an extension is supplied when the source had none, and never doubled
        assert!(
            names.contains(&"inputs/ee/www.example.com.der".to_string()),
            "{names:?}"
        );
        assert!(!names.iter().any(|n| n.ends_with(".der.der")), "{names:?}");
        assert!(
            names.contains(&"inputs/ee/target.der".to_string()),
            "{names:?}"
        );
    }

    /// Two targets read from different folders can share a basename. An archive entry written twice
    /// is one file holding whichever was written last, so repeats are numbered instead.
    #[test]
    fn end_entities_sharing_a_basename_both_survive() {
        let inputs = RunInputs {
            end_entities: vec![
                ("/one/ee.der".to_string(), vec![0x30]),
                ("/two/ee.der".to_string(), vec![0x31]),
                ("/three/ee.der".to_string(), vec![0x32]),
            ],
            ..Default::default()
        };
        let names: Vec<String> = all_entries(&inputs).into_iter().map(|(n, _)| n).collect();
        assert!(names.contains(&"inputs/ee/ee.der".to_string()), "{names:?}");
        assert!(
            names.contains(&"inputs/ee/1-ee.der".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"inputs/ee/2-ee.der".to_string()),
            "{names:?}"
        );
    }

    /// End entity certificates land in the folder the command hands to `--end-entity-folder`.
    #[test]
    fn end_entities_land_where_the_command_points() {
        let inputs = RunInputs {
            end_entities: vec![
                ("one.der".to_string(), vec![0x30]),
                ("two.der".to_string(), vec![0x31]),
            ],
            ..Default::default()
        };
        let names: Vec<String> = all_entries(&inputs).into_iter().map(|(n, _)| n).collect();
        assert!(
            names.contains(&"inputs/ee/one.der".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"inputs/ee/two.der".to_string()),
            "{names:?}"
        );
    }

    /// The text export is the archive's manifests, so the two cannot describe different runs.
    #[test]
    fn text_export_is_the_manifests_the_archive_carries() {
        let paths = vec![
            vec![
                (PATH_LOG_NAME.to_string(), b"path one".to_vec()),
                ("0-ta.der".to_string(), vec![0x30]),
            ],
            vec![(PATH_LOG_NAME.to_string(), b"path two".to_vec())],
        ];
        let text = paths_text(&paths, None);
        assert!(text.contains("path one"));
        assert!(text.contains("path two"));
        // the DER rode along in the archive and must not appear in the log
        assert!(!text.contains('\u{30}'.to_string().as_str()) || !text.contains("0-ta"));
    }

    /// A path contributing no manifest is skipped rather than emitting a blank section.
    #[test]
    fn a_path_without_a_manifest_contributes_nothing_to_the_text() {
        let paths = vec![vec![("0-ta.der".to_string(), vec![0x30])]];
        assert!(paths_text(&paths, None).is_empty());
    }

    /// The run figure closes the log because it is the one number the manifests cannot supply --
    /// each states its own path, none states the run. It goes after every manifest so the file
    /// still opens on the first path, and a caller that has no run to time gets the file it got
    /// before.
    #[test]
    fn the_run_figure_closes_the_log_and_is_omitted_when_absent() {
        let paths = vec![
            vec![(PATH_LOG_NAME.to_string(), b"path one".to_vec())],
            vec![(PATH_LOG_NAME.to_string(), b"path two".to_vec())],
        ];

        // The wording of the trailer is the renderer's to choose. What this pins is that the
        // figure is present and that it closes the file rather than landing between two paths.
        let timed = paths_text(&paths, Some(1234));
        assert!(timed.trim_end().ends_with("1234 ms"));
        assert!(timed.starts_with("path one"));

        // The trailer is appended and nothing else moves, so an export made with a run figure and
        // one made without describe the paths identically.
        let untimed = paths_text(&paths, None);
        assert!(!untimed.contains("1234"));
        assert!(timed.starts_with(&untimed));
    }

    /// Nothing to save stays nothing to save: both frontends read an empty string as "no paths are
    /// held" and say so instead of writing a file, so a trailer must not make one out of a run that
    /// produced no paths.
    #[test]
    fn a_run_figure_alone_does_not_make_a_file() {
        assert!(paths_text(&[], Some(1234)).is_empty());
        let no_manifests = vec![vec![("0-ta.der".to_string(), vec![0x30])]];
        assert!(paths_text(&no_manifests, Some(1234)).is_empty());
    }
}
