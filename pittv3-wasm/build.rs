//! Generates the trust-store artifacts the app fetches at run time.
//!
//! `STORES` in `src/validate.rs` names stores by URL, and Trunk copies
//! `resources/` into `dist/`, so these have to exist as files rather than being
//! linked in: the material is ~9 MB, and embedding it would be paid on every
//! page load whether or not a given store is ever selected. Generating it here
//! from the provider crates keeps it in step with them instead of being
//! refreshed by hand — `resources/webpki_*.cbor` was last built by hand in July
//! 2026, and had no way to notice the upstream root program moving.
//!
//! Writing into the source tree from a build script is unusual, and is done
//! because `resources/` is what Trunk publishes. `write_if_changed` keeps it
//! idempotent: bytes are only written when they differ, so an unchanged
//! regeneration leaves mtimes alone and cannot feed a rebuild loop.
//!
//! The artifacts are gitignored here, being output of this script rather than
//! material of this repository — the certificates they carry are versioned in
//! the provider repositories. What this repository keeps is `stores.manifest`,
//! also written here: the anchors each store carries, by subject, and a digest
//! per file. That is the readable form of the same change — a provider moving
//! under a `cargo update` shows up as an anchor added or removed rather than as
//! a rev bump in the lock.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use certval_stores_core::{serialize_environment, TrustStoreProvider};
use sha2::{Digest, Sha256};
use x509_cert::der::Decode;
use x509_cert::Certificate;

/// Stamps the time of this build into `PITTV3_BUILD_TIME`, which the header
/// shows so a person can tell whether the page in front of them is the build
/// they just deployed.
///
/// The interesting part is what this script is told to rerun for, because a
/// stamp is only worth showing if it moves when the application does — and
/// only worth having if it does *not* move when the application does not. A
/// value that changed on every invocation would change this crate's
/// compilation inputs on every invocation, and rebuilding pittv3-wasm from
/// scratch costs minutes; that is the cost of "always fresh", and it is not
/// worth paying. So the triggers are the things whose change means a different
/// application: this crate's own sources and manifest, the workspace lock (so
/// an external dependency moving counts), and the in-tree crates the
/// application is built out of. Each of those already forces a recompile, so
/// the stamp rides along for nothing.
///
/// What it therefore cannot notice: a rebuild of byte-identical inputs. That
/// reads as the earlier time, which is the honest answer — it is the same
/// application.
fn stamp_build_time() {
    for path in [
        "build.rs",
        "Cargo.toml",
        "src",
        "../Cargo.lock",
        "../certval/src",
        "../pittv3-lib/src",
        "../pittv3-gui-lib/src",
    ] {
        println!("cargo::rerun-if-changed={path}");
    }

    // A clock before the epoch is not worth a build failure, and 0 renders as a
    // date nobody will mistake for a real one.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("cargo::rustc-env=PITTV3_BUILD_TIME={}", utc_minute(secs));
}

/// Renders a Unix timestamp as `YYYY-MM-DD HH:MM UTC`.
///
/// To the minute: the second a build started is noise next to the question
/// being asked, which is "is this the one I just made". Written out rather than
/// pulled from a date library, because one line of output does not merit a
/// dependency in the build graph.
fn utc_minute(secs: u64) -> String {
    let (days, rest) = ((secs / 86_400) as i64, secs % 86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute) = (rest / 3600, (rest % 3600) / 60);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

/// Days since the Unix epoch to a civil year, month and day, by Howard
/// Hinnant's `civil_from_days`. Verified against `date -u` across the epoch,
/// the 2000 and 2024 leap years and the 2100 century non-leap.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

/// One generated store: which provider store it comes from, and the file names
/// `STORES` expects. `ca` is `None` for an anchors-only store.
struct Artifact {
    provider: &'static dyn TrustStoreProvider,
    /// The provider's own id for this store, which selects it and names the
    /// environment variables its dates are passed through. Taken from the
    /// provider crate's constant rather than written out, so a store renamed
    /// there stops this build rather than silently matching nothing.
    id: &'static str,
    ta: &'static str,
    ca: Option<&'static str>,
}

/// Adding an entry here adds a redistributed trust set to `dist/`, so it also
/// wants a paragraph in `resources/NOTICE` — that file is the attribution for
/// everything this build script writes, and for the Mozilla material it is the
/// MPL-2.0 Exhibit A notice the CBOR itself cannot carry.
fn artifacts() -> Vec<Artifact> {
    vec![
        Artifact {
            provider: certval_stores_nipr::provider(),
            id: certval_stores_nipr::NIPR_PROD,
            ta: "dod_nipr_prod_ta.cbor",
            ca: Some("dod_nipr_prod_ca.cbor"),
        },
        // The operational-test environment, called JITC by the department and
        // OM_NIPR by the provider. A separate trust set from production: its
        // roots anchor nothing the production DoD roots anchor.
        Artifact {
            provider: certval_stores_nipr::provider(),
            id: certval_stores_nipr::NIPR_OM,
            ta: "dod_nipr_om_ta.cbor",
            ca: Some("dod_nipr_om_ca.cbor"),
        },
        // The External Certification Authority program: vendor CAs issuing to
        // people and systems outside the department that interoperate with it.
        // A separate trust set from NIPR rather than a part of it -- its two
        // roots anchor nothing the DoD roots anchor.
        Artifact {
            provider: certval_stores_eca::provider(),
            id: certval_stores_eca::ECA,
            ta: "dod_eca_ta.cbor",
            ca: Some("dod_eca_ca.cbor"),
        },
        // The WCF PKI, published as its own InstallRoot stream. Its store is two
        // deep -- one intermediate beneath the root, ten signing CAs beneath that
        // -- so ten of its eleven partial paths carry two certificates.
        Artifact {
            provider: certval_stores_wcf::provider(),
            id: certval_stores_wcf::WCF,
            ta: "dod_wcf_ta.cbor",
            ca: Some("dod_wcf_ca.cbor"),
        },
        // MOZILLA_ALL rather than MOZILLA_TLS: the CA store hangs off the
        // combined environment only, because 356 of the intermediates chain
        // solely to email-only roots and would be unanchored under the
        // TLS-scoped anchor set. Purpose is gated from the roots' trust bits,
        // not from the anchor set.
        Artifact {
            provider: certval_stores_mozilla::provider(),
            id: certval_stores_mozilla::ALL,
            ta: "webpki_ta.cbor",
            ca: Some("webpki_ca.cbor"),
        },
    ]
    // The ML-DSA PKITS store is not a provider — it is test collateral for the
    // PQC edition, generated elsewhere — so it stays a committed file.
}

fn main() {
    stamp_build_time();

    // Removing a file from `resources/` is a reason to run again, and the only
    // one this script does not already have: its other triggers are sources.
    // That matters now that the artifacts are untracked -- a clone has none of
    // them, and anyone who clears the directory by hand would otherwise get a
    // build that skips this script and a `dist/` with no stores in it. Writing
    // into a watched directory is safe because `write_if_changed` leaves
    // mtimes alone when the bytes match, so this settles after one rerun
    // rather than looping.
    println!("cargo::rerun-if-changed=resources");

    let dir = Path::new("resources");
    let mut inventory = Vec::new();
    for a in artifacts() {
        let store = match serialize_environment(&[a.provider], a.id) {
            Ok(s) => s,
            // A provider that cannot serialize is a broken build, not a warning
            // to scroll past: the app would fetch a stale store and validate
            // against material nobody chose.
            Err(e) => panic!("failed to serialize the {} store: {e:?}", a.id),
        };

        // The dates ride in on the environment rather than in the CBOR, which has nowhere
        // to hold them: the artifacts are bytes certval loads, not a container this
        // application defines. `option_env!` in `STORES` reads them back, so a store whose
        // provider states no date compiles to `None` with nothing further to arrange.
        stamp_date(a.id, "PUBLISHED", store.published);
        stamp_date(a.id, "COLLECTED", store.collected);
        stamp_label(a.id, store.label);

        write_if_changed(&dir.join(a.ta), &store.ta_cbor);
        let ta = StoreFile::of(a.ta, &store.ta_cbor);

        let ca = match (a.ca, store.ca_cbor) {
            (Some(name), Some(bytes)) => {
                write_if_changed(&dir.join(name), &bytes);
                Some(StoreFile::of(name, &bytes))
            }
            (Some(name), None) => {
                panic!(
                    "{} expects a CA store at {name} but the provider carries none",
                    a.id
                )
            }
            (None, Some(_)) => {
                panic!(
                    "{} carries a CA store but no file name is configured for it",
                    a.id
                )
            }
            (None, None) => None,
        };

        inventory.push(Inventory {
            id: a.id,
            published: store.published,
            collected: store.collected,
            anchors: anchors(&a),
            ta,
            ca,
        });
    }

    write_if_changed(Path::new(MANIFEST), render_manifest(&inventory).as_bytes());
}

/// Pass one of a store's dates to the crate as `PITTV3_STORE_<WHICH>_<ID>`.
///
/// Nothing is emitted when the provider states no date: an unset variable is what
/// makes `option_env!` produce `None`, and emitting an empty string instead would
/// hand the selector a store claiming to have been collected on no day at all.
/// Pass a store's display name to the crate as `PITTV3_STORE_LABEL_<ID>`.
///
/// The browser cannot ask the provider the way the desktop selector does — it never links the
/// provider crates, which is the whole reason this script exists — so the name travels the same
/// road the dates do. Without it `STORES` would hold the one remaining hand-written name for
/// provider material, and a name written twice is a name free to drift: the desktop and the
/// service each had one, and they disagreed about NIPR.
///
/// Unconditional, unlike a date: every store has a name, so `STORES` can treat an unset variable
/// as a build that went wrong rather than as a store with nothing to say.
fn stamp_label(id: &str, label: &str) {
    println!(
        "cargo::rustc-env=PITTV3_STORE_LABEL_{}={label}",
        id.to_ascii_uppercase()
    );
}

fn stamp_date(id: &str, which: &str, date: Option<&str>) {
    if let Some(date) = date {
        println!(
            "cargo::rustc-env=PITTV3_STORE_{which}_{}={date}",
            id.to_ascii_uppercase()
        );
    }
}

/// The record this repository keeps of what the generated artifacts contain.
///
/// At the crate root rather than in `resources/`, because Trunk copies that
/// directory into `dist/` wholesale and this file is for readers of the
/// repository, not of the deployment.
const MANIFEST: &str = "stores.manifest";

/// Heading of `stores.manifest`, saying where the material comes from and what
/// the file is and is not good for.
const MANIFEST_HEADER: &str = "\
# Inventory of the trust-store artifacts in resources/, written by build.rs.
#
# The material is not this crate's: it is tracked in the certval_stores_*
# repositories the workspace lock pins, and build.rs re-serializes it into the
# files Trunk publishes. Those files are build output, so this repository does
# not keep them. It keeps this record instead, so that a provider moving under a
# lock refresh reads as an anchor added or removed rather than as a rev bump.
#
# Generated, not authoritative: the providers at the locked rev are the source.
# What it is good for is history -- `git log -p` over this file says when an
# anchor arrived or left.
#
# Anchors are sorted by subject, so the order carries no meaning and an addition
# does not move its neighbours.

";

/// One artifact as the manifest records it.
struct StoreFile {
    name: &'static str,
    len: usize,
    digest: String,
}

impl StoreFile {
    fn of(name: &'static str, bytes: &[u8]) -> Self {
        StoreFile {
            name,
            len: bytes.len(),
            digest: sha256_hex(bytes),
        }
    }
}

/// One store's entry in the manifest.
struct Inventory {
    id: &'static str,
    published: Option<&'static str>,
    collected: Option<&'static str>,
    /// Subject and digest per trust anchor, sorted by subject.
    anchors: Vec<(String, String)>,
    ta: StoreFile,
    ca: Option<StoreFile>,
}

/// The trust anchors a store carries, as `(subject, digest)` sorted by subject.
///
/// Read from the provider's own `roots` rather than from the CBOR just written,
/// because that is the material: the CBOR is one packaging of it, and reading it
/// back would test the serializer instead of recording what the store holds.
///
/// Deduplicated to match `serialize_environment`, which drops a root a second
/// entry repeats; a manifest listing it twice would claim an anchor set the
/// store does not have.
fn anchors(a: &Artifact) -> Vec<(String, String)> {
    let entries = a.provider.entries();
    let mut rows: Vec<(String, String)> = entries
        .iter()
        .filter(|e| e.id == a.id)
        .flat_map(|e| e.roots.iter().copied())
        .map(|der| (anchor_subject(der), sha256_hex(der)))
        .collect();
    rows.sort();
    rows.dedup();
    rows
}

/// A trust anchor's subject, as the name to recognize it by in a diff.
///
/// A root that does not parse is a broken store rather than a nameless row:
/// `serialize_environment` has already decoded the same bytes by the time this
/// runs, so reaching the panic means the provider and the serializer disagree.
fn anchor_subject(der: &[u8]) -> String {
    match Certificate::from_der(der) {
        Ok(cert) => cert.tbs_certificate().subject().to_string(),
        Err(e) => panic!("a trust anchor does not parse as a certificate: {e}"),
    }
}

/// Lowercase hex of the SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(64);
    for b in Sha256::digest(bytes).iter() {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// One `ta_store` or `ca_store` row.
fn store_file_line(which: &str, f: &StoreFile) -> String {
    format!(
        "  {which}  {}  {} bytes  sha256:{}\n",
        f.name, f.len, f.digest
    )
}

/// Render the manifest.
///
/// Fields are `key=value` and rows are indented by depth, so the file reads as
/// text and diffs a line at a time. Nothing is column-aligned: padding would
/// mean one long subject reflowing every line around it.
fn render_manifest(stores: &[Inventory]) -> String {
    let mut out = String::from(MANIFEST_HEADER);
    for s in stores {
        out.push_str(&format!("[{}]", s.id));
        if let Some(d) = s.published {
            out.push_str(&format!("  published={d}"));
        }
        if let Some(d) = s.collected {
            out.push_str(&format!("  collected={d}"));
        }
        out.push('\n');

        out.push_str(&format!("  anchors {}\n", s.anchors.len()));
        for (subject, digest) in &s.anchors {
            out.push_str(&format!("    {subject}  sha256:{digest}\n"));
        }

        out.push_str(&store_file_line("ta_store", &s.ta));
        if let Some(ca) = &s.ca {
            out.push_str(&store_file_line("ca_store", ca));
        }
        out.push('\n');
    }
    out
}

/// Write `bytes` only if the file does not already hold exactly them, so a
/// no-op regeneration does not touch the file or its mtime.
fn write_if_changed(path: &Path, bytes: &[u8]) {
    if fs::read(path).is_ok_and(|existing| existing == bytes) {
        return;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| panic!("cannot create {parent:?}: {e}"));
    }
    fs::write(path, bytes).unwrap_or_else(|e| panic!("cannot write {path:?}: {e}"));
    println!("cargo::warning=regenerated {}", path.display());
}
