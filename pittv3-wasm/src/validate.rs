//! In-browser certification path validation built on certval with no-default-features plus pqc

use std::io::{Cursor, Read};

use certval::*;
use pittv3_lib::report::{CertSummary, PathReport, TargetReport};
use web_time::Instant;

/// A trust anchor store and CA certificate store pair, referenced by the URL of its CBOR file.
/// The CBOR ships alongside the wasm (see the Trunk `copy-dir` of `resources`) rather than baked
/// into the binary, and is fetched on demand when the store is selected. URLs are relative to
/// index.html so they resolve at any deployment mount point (matching `public_url = "./"`).
pub struct Store {
    /// Display name for the store
    pub label: &'static str,
    /// URL of the CBOR-serialized trust anchor store
    pub ta_url: &'static str,
    /// URL of the CBOR-serialized CA certificate store with partial certification paths, or
    /// `None` for a trust-anchor-only store (e.g. Web PKI roots without preloaded
    /// intermediates); intermediates can then be supplied via upload.
    pub ca_url: Option<&'static str>,
}

/// Stores available for selection in the UI
pub const STORES: &[Store] = &[
    Store {
        label: "ML-DSA-44 PKITS",
        ta_url: "resources/pkits_ml_dsa_44_ta.cbor",
        ca_url: Some("resources/pkits_ml_dsa_44_ca.cbor"),
    },
    Store {
        label: "Web PKI (Mozilla roots + CCADB intermediates)",
        ta_url: "resources/webpki_ta.cbor",
        // CCADB intermediate set with precomputed partial paths; AIA fallback (once the
        // fetch proxy lands) will cover anything not preloaded here
        ca_url: Some("resources/webpki_ca.cbor"),
    },
    Store {
        label: "U.S. DoD (NIPR)",
        ta_url: "resources/dod_nipr_prod_ta.cbor",
        ca_url: Some("resources/dod_nipr_prod_ca.cbor"),
    },
];

/// Sample end entity certificate from the ML-DSA-44 PKITS edition that should validate
pub const SAMPLE_VALID: (&str, &[u8]) = (
    "ValidCertificatePathTest1EE.der",
    include_bytes!("../resources/sample_valid_ml_dsa_44.der"),
);

/// Sample end entity certificate from the ML-DSA-44 PKITS edition that should fail validation
/// with a signature verification error, i.e., the end entity certificate signature is bad
pub const SAMPLE_INVALID: (&str, &[u8]) = (
    "InvalidEESignatureTest3EE.der",
    include_bytes!("../resources/sample_invalid_ml_dsa_44.der"),
);

/// User-editable values that feed the RFC 5280 path validation inputs plus app-level options
pub struct ValidationSettings {
    /// Time of interest as seconds since Unix epoch; 0 disables validity period checks
    pub toi: u64,
    /// Validate every discovered path instead of stopping at the first valid one
    pub validate_all: bool,
    /// initial-explicit-policy input
    pub initial_explicit_policy: bool,
    /// initial-policy-mapping-inhibit input
    pub initial_policy_mapping_inhibit: bool,
    /// initial-any-policy-inhibit input
    pub initial_inhibit_any_policy: bool,
    /// user-initial-policy-set input as whitespace- or comma-separated OIDs; empty means anyPolicy
    pub initial_policy_set: String,
    /// Enforce constraints expressed in trust anchors per RFC 5937
    pub enforce_trust_anchor_constraints: bool,
    /// Require trust anchors to be valid at the time of interest
    pub enforce_trust_anchor_validity: bool,
    /// RFC 5280 initial-permitted-subtrees, one entry per line per name form
    pub permitted_subtrees: NameConstraintInputs,
    /// RFC 5280 initial-excluded-subtrees, one entry per line per name form
    pub excluded_subtrees: NameConstraintInputs,
}

/// Raw text (one entry per line) for the name-constraint forms exposed in the UI. UPN and the
/// "not supported" catch-all are intentionally omitted (UPN enforcement is being removed; the
/// unsupported-forms bucket needs custom enforcement).
#[derive(Default, Clone)]
pub struct NameConstraintInputs {
    /// dNSName subtrees
    pub dns_name: String,
    /// rfc822Name (email) subtrees
    pub rfc822_name: String,
    /// directoryName (DN) subtrees
    pub directory_name: String,
    /// uniformResourceIdentifier subtrees
    pub uniform_resource_identifier: String,
    /// iPAddress subtrees
    pub ip_address: String,
}

/// A line of validation output along with a CSS class used to render it, i.e., "ok", "err" or "info"
pub struct ResultLine {
    /// CSS class: "ok", "err" or "info"
    pub class: &'static str,
    /// Text to display
    pub text: String,
}

fn info(text: String) -> ResultLine {
    ResultLine {
        class: "info",
        text,
    }
}
fn ok(text: String) -> ResultLine {
    ResultLine { class: "ok", text }
}
fn err(text: String) -> ResultLine {
    ResultLine { class: "err", text }
}

/// Returns DER bytes given buffers that may be PEM or DER encoded. DER detection accepts
/// SEQUENCE (certificates and the certificate variant of TrustAnchorChoice) plus the context
/// tags that begin the tbsCert and taInfo variants of a DER-encoded RFC 5914 TrustAnchorChoice.
fn maybe_pem(bytes: &[u8]) -> Result<Vec<u8>> {
    if !bytes.is_empty() && matches!(bytes[0], 0x30 | 0xA1 | 0xA2) {
        Ok(bytes.to_vec())
    } else {
        match pem_rfc7468::decode_vec(bytes) {
            Ok(b) => Ok(b.1),
            Err(_e) => Err(Error::Unrecognized),
        }
    }
}

/// Returns true if `s` is plausibly a dotted-decimal OID
fn looks_like_oid(s: &str) -> bool {
    s.contains('.') && s.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Splits a textarea value into one entry per non-empty trimmed line (line-per-entry avoids
/// ambiguity with directoryName values, which contain commas). None when there are no entries.
fn lines_to_vec(s: &str) -> Option<Vec<String>> {
    let v: Vec<String> = s
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    (!v.is_empty()).then_some(v)
}

/// Builds a [`NameConstraintsSettings`] from the UI inputs, or None when every form is empty.
fn to_name_constraints(nc: &NameConstraintInputs) -> Option<NameConstraintsSettings> {
    let s = NameConstraintsSettings {
        rfc822_name: lines_to_vec(&nc.rfc822_name),
        dns_name: lines_to_vec(&nc.dns_name),
        directory_name: lines_to_vec(&nc.directory_name),
        uniform_resource_identifier: lines_to_vec(&nc.uniform_resource_identifier),
        ip_address: lines_to_vec(&nc.ip_address),
        ..Default::default()
    };
    let empty = s.rfc822_name.is_none()
        && s.dns_name.is_none()
        && s.directory_name.is_none()
        && s.uniform_resource_identifier.is_none()
        && s.ip_address.is_none();
    (!empty).then_some(s)
}

/// Builds a [`CertificationPathSettings`](certval::CertificationPathSettings) from user-supplied
/// values, appending a note for any value that could not be applied as given
fn make_cps(vs: &ValidationSettings, out: &mut Vec<ResultLine>) -> CertificationPathSettings {
    let toi = match TimeOfInterest::from_unix_secs(vs.toi) {
        Ok(t) => t,
        Err(_) => TimeOfInterest::disabled(),
    };
    if toi.is_disabled() {
        out.push(info(
            "Time of interest is 0 (or invalid): validity period checks are disabled".to_string(),
        ));
    }
    let mut cps = CertificationPathSettings::default();
    cps.set_time_of_interest(toi);
    cps.set_initial_explicit_policy_indicator(vs.initial_explicit_policy);
    cps.set_initial_policy_mapping_inhibit_indicator(vs.initial_policy_mapping_inhibit);
    cps.set_initial_inhibit_any_policy_indicator(vs.initial_inhibit_any_policy);
    cps.set_enforce_trust_anchor_constraints(vs.enforce_trust_anchor_constraints);
    cps.set_enforce_trust_anchor_validity(vs.enforce_trust_anchor_validity);
    if let Some(p) = to_name_constraints(&vs.permitted_subtrees) {
        cps.set_initial_permitted_subtrees(p);
    }
    if let Some(e) = to_name_constraints(&vs.excluded_subtrees) {
        cps.set_initial_excluded_subtrees(e);
    }

    let mut oids = vec![];
    for tok in vs
        .initial_policy_set
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
    {
        if looks_like_oid(tok) {
            oids.push(tok.to_string());
        } else {
            out.push(err(format!(
                "Ignoring initial policy set entry that is not a dotted-decimal OID: {tok}"
            )));
        }
    }
    // when no usable OIDs are given, leave the default in place (anyPolicy)
    if !oids.is_empty() {
        cps.set_initial_policy_set(oids);
    }
    cps
}

/// Validates every certificate in `ees` against a single prepared environment: an optional baked-in
/// store plus uploaded trust anchors and intermediate CA certificates. The environment is prepared
/// ONCE — one merged CA store, one partial-path discovery pass — and every target is validated
/// against it. This mirrors the desktop utility (prepare once, validate all) and, crucially, keeps
/// the discovery pass out of the per-target loop. Returns a report per target that reached path
/// building, plus displayable notes.
pub fn validate_batch(
    store: Option<(&str, &[u8], &[u8])>,
    tas: &[(String, Vec<u8>)],
    cas: &[(String, Vec<u8>)],
    ees: &[(String, Vec<u8>)],
    vs: &ValidationSettings,
) -> (Vec<TargetReport>, Vec<ResultLine>) {
    let mut out = vec![];
    let cps = make_cps(vs, &mut out);

    // --- trust anchors: baked store (if any) + uploaded TAs (certs or .cbor stores) ---
    let mut ta_store = match store {
        Some((_, ta_cbor, _)) => match TaSource::new_from_cbor(ta_cbor) {
            Ok(t) => t,
            Err(e) => {
                return (
                    vec![],
                    vec![err(format!("Failed to parse TA store CBOR: {e:?}"))],
                )
            }
        },
        None => TaSource::new(),
    };
    for (name, bytes) in tas {
        // A `.cbor` trust-anchor store (BuffersAndPaths) merges all of its anchors; new_from_cbor
        // rejects anything else, so a PEM/DER certificate falls through to the single-cert path.
        if let Ok(src) = TaSource::new_from_cbor(bytes) {
            for cf in src.get_tas() {
                ta_store.push(cf);
            }
            continue;
        }
        match maybe_pem(bytes) {
            Ok(der) => ta_store.push(CertFile {
                filename: name.clone(),
                bytes: der,
            }),
            Err(_) => out.push(err(format!(
                "Failed to parse uploaded trust anchor {name} as a PEM/DER certificate or a CBOR store"
            ))),
        }
    }
    if ta_store.is_empty() {
        out.push(err(
            "No trust anchors are available. Select a built-in store or upload at least one trust anchor."
                .to_string(),
        ));
        return (vec![], out);
    }
    if let Err(e) = ta_store.initialize() {
        return (
            vec![],
            vec![err(format!("Failed to initialize TA store: {e:?}"))],
        );
    }

    // --- one CA store: the baked store's certificates (with their precomputed partial paths) plus
    // any uploaded intermediates, all in a single pool so path discovery can link across them. An
    // empty CA buffer denotes a trust-anchor-only store (ca_url = None). ---
    let mut cert_source = match store {
        Some((_, _, ca_cbor)) if !ca_cbor.is_empty() => match CertSource::new_from_cbor(ca_cbor) {
            Ok(c) => c,
            Err(e) => {
                return (
                    vec![],
                    vec![err(format!("Failed to parse CA store CBOR: {e:?}"))],
                )
            }
        },
        _ => CertSource::new(),
    };
    for (name, bytes) in cas {
        // A `.cbor` CA store merges all of its buffers; otherwise treat as a single PEM/DER cert.
        if let Ok(src) = CertSource::new_from_cbor(bytes) {
            for cf in src.get_buffers() {
                cert_source.push(cf);
            }
            continue;
        }
        match maybe_pem(bytes) {
            Ok(der) => cert_source.push(CertFile {
                filename: name.clone(),
                bytes: der,
            }),
            Err(_) => out.push(err(format!(
                "Failed to parse uploaded CA certificate {name} as a PEM/DER certificate or a CBOR store"
            ))),
        }
    }
    if let Err(e) = cert_source.initialize(&cps) {
        return (
            vec![],
            vec![err(format!("Failed to initialize CA store: {e:?}"))],
        );
    }

    match (store, tas.is_empty() && cas.is_empty()) {
        (Some((label, _, _)), true) => out.push(info(format!("Using {label} store"))),
        (Some((label, _, _)), false) => out.push(info(format!(
            "Using {label} store with {} uploaded trust anchor(s) and {} uploaded intermediate(s)",
            tas.len(),
            cas.len()
        ))),
        (None, _) => out.push(info(format!(
            "Using {} uploaded trust anchor(s) and {} uploaded intermediate(s)",
            tas.len(),
            cas.len()
        ))),
    }

    // --- prepare the environment ONCE ---
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe.add_trust_anchor_source(Box::new(ta_store));
    // The baked store ships with precomputed partial paths, so discovery runs only when uploads
    // change the merged set. It rebuilds the whole merged pool's paths — but ONCE for the batch, not
    // per target. The TA source must be registered first (discovery consults it).
    if !tas.is_empty() || !cas.is_empty() {
        cert_source.find_all_partial_paths(&pe, &cps);
    }
    pe.add_certificate_source(Box::new(cert_source));

    // --- validate every target against the one prepared environment ---
    let mut reports = vec![];
    for (name, bytes) in ees {
        let (report, lines) = validate_target(&pe, &cps, name, bytes, vs.validate_all);
        out.extend(lines);
        if let Some(r) = report {
            reports.push(r);
        }
    }
    (reports, out)
}

/// Builds and validates certification path(s) for a single target certificate against a fully
/// prepared [`PkiEnvironment`](certval::PkiEnvironment), returning a structured report for the
/// target (absent when the certificate could not be parsed) along with displayable notes
fn validate_target(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    ee_name: &str,
    ee: &[u8],
    validate_all: bool,
) -> (Option<TargetReport>, Vec<ResultLine>) {
    let mut out = vec![];
    let toi = cps.get_time_of_interest();

    let der = match maybe_pem(ee) {
        Ok(der) => der,
        Err(_) => {
            out.push(err(format!("Failed to parse {ee_name} as PEM or DER")));
            return (None, out);
        }
    };
    let target = match parse_cert(&der, ee_name) {
        Ok(t) => t,
        Err(e) => {
            out.push(err(format!("Failed to parse certificate {ee_name}: {e:?}")));
            return (None, out);
        }
    };
    let target_summary = CertSummary::from_cert(&target);

    // validate_path treats a target found in the TA store as trusted and returns success without
    // verifying its signature (and TA store membership requires only a subjectKeyIdentifier and
    // public key match, not an exact certificate match), so when the target is a trust anchor
    // check its signature here to keep bad signatures and unsupported algorithms from being
    // reported as valid
    if pe.is_cert_a_trust_anchor(&target).is_ok() {
        if is_self_signed(pe, &target) {
            out.push(ok(format!(
                "{ee_name} is a trust anchor and is self-signed"
            )));
        } else {
            out.push(err(format!(
                "{ee_name} matches a trust anchor by key but is not self-signed (bad signature or unsupported algorithm)"
            )));
        }
    }

    out.push(info(format!(
        "Building and validating path(s) for {} ({})",
        ee_name,
        target.as_ref().tbs_certificate().subject()
    )));

    let mut paths: Vec<CertificationPath> = vec![];
    if let Err(e) = pe.get_paths_for_target(&target, &mut paths, 0, toi) {
        out.push(err(format!("Failed to find certification paths: {e:?}")));
        return (
            Some(TargetReport {
                name: ee_name.to_string(),
                target: Some(target_summary),
                status: TargetReport::compute_status(&[], false),
                paths: vec![],
            }),
            out,
        );
    }
    if paths.is_empty() {
        out.push(err(
            "No certification paths found (check trust anchors and time of interest)".to_string(),
        ));
        return (
            Some(TargetReport {
                name: ee_name.to_string(),
                target: Some(target_summary),
                status: TargetReport::compute_status(&[], false),
                paths: vec![],
            }),
            out,
        );
    }

    let mut valid = 0;
    let mut invalid = 0;
    let mut path_reports = vec![];
    for (i, path) in paths.iter_mut().enumerate() {
        let path_start = Instant::now();
        let mut cpr = CertificationPathResults::new();
        // fold RFC 5914 trust anchor constraints into the settings per RFC 5937; this is a no-op
        // clone when enforcement is disabled, and validate_path does not perform it itself
        let path_cps = match enforce_trust_anchor_constraints(cps, &path.trust_anchor) {
            Ok(c) => c,
            Err(e) => {
                invalid += 1;
                out.push(err(format!(
                    "Path {}: failed to apply trust anchor constraints: {e:?}",
                    i + 1
                )));
                path_reports.push(PathReport::from_path_results(
                    path,
                    &CertificationPathResults::new(),
                    Some(&e),
                    path_start.elapsed().as_millis() as u64,
                ));
                continue;
            }
        };
        let r = pe.validate_path(pe, &path_cps, path, &mut cpr);
        path_reports.push(PathReport::from_path_results(
            path,
            &cpr,
            r.as_ref().err(),
            path_start.elapsed().as_millis() as u64,
        ));
        let cert_count = path.intermediates.len() + 2;
        match r {
            Ok(_) => {
                valid += 1;
                out.push(ok(format!(
                    "Path {} ({} certificates): VALID",
                    i + 1,
                    cert_count
                )));
                if !validate_all {
                    break;
                }
            }
            Err(e) => {
                invalid += 1;
                out.push(err(format!(
                    "Path {} ({} certificates): INVALID with {e:?}",
                    i + 1,
                    cert_count
                )));
            }
        }
    }

    let summary = format!(
        "{} path(s) considered: {} valid, {} invalid",
        valid + invalid,
        valid,
        invalid
    );
    if valid > 0 {
        out.push(ok(summary));
    } else {
        out.push(err(summary));
    }

    let status = TargetReport::compute_status(&path_reports, true);
    (
        Some(TargetReport {
            name: ee_name.to_string(),
            target: Some(target_summary),
            status,
            paths: path_reports,
        }),
        out,
    )
}

/// Checks whether a certificate is self-signed, i.e., whether its signature verifies using its
/// own public key, as done for trust anchors from hackathon archives. This mirrors the hackathon
/// compatibility matrices and the CLI --validate-self-signed option, which check self-signed-ness
/// only. Full path validation is deliberately not used here: with the trust anchors loaded into
/// the TA store, validate_path treats a target found in the store as trusted and returns success
/// without verifying the signature, reporting certificates signed with unsupported algorithms as
/// valid.
fn validate_self_signed(pe: &PkiEnvironment, name: &str, der: &[u8]) -> Vec<ResultLine> {
    let mut out = vec![];
    let target = match parse_cert(der, name) {
        Ok(t) => t,
        Err(e) => {
            out.push(err(format!("Failed to parse certificate {name}: {e:?}")));
            return out;
        }
    };
    if is_self_signed(pe, &target) {
        out.push(ok(format!("{name} is self-signed")));
    } else {
        out.push(err(format!(
            "{name} is not self-signed (bad signature or unsupported algorithm)"
        )));
    }
    out
}

/// Validates the contents of an IETF Hackathon PQC certificates archive in the R5 format, i.e.,
/// artifacts_certs_r5.zip. Entries named `*_ta.der` form the trust anchor store and entries named
/// `*_ee.der` are validated against it; all other entries (private keys, KEM artifacts, etc.) are
/// ignored. The archive is self-contained: built-in stores and uploads are not consulted. Returns
/// a structured report per end entity certificate along with displayable notes (trust anchor
/// self-signed checks are reported as notes).
pub fn validate_hackathon_zip(
    zip_name: &str,
    bytes: Vec<u8>,
    vs: &ValidationSettings,
) -> (Vec<TargetReport>, Vec<ResultLine>) {
    let mut out = vec![];
    let mut reports = vec![];

    let mut archive = match zip::ZipArchive::new(Cursor::new(bytes)) {
        Ok(a) => a,
        Err(e) => {
            return (
                vec![],
                vec![err(format!("Failed to read {zip_name} as a zip file: {e}"))],
            )
        }
    };

    let mut tas: Vec<(String, Vec<u8>)> = vec![];
    let mut ees: Vec<(String, Vec<u8>)> = vec![];
    let mut ignored = 0usize;
    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(entry) => entry,
            Err(e) => {
                out.push(err(format!("Failed to read entry {i} in {zip_name}: {e}")));
                continue;
            }
        };
        if entry.is_dir() {
            continue;
        }
        // entries may sit under a top-level folder, e.g., artifacts_certs_r5/<name>_ta.der
        let name = match entry.name().rsplit('/').next() {
            Some(n) => n.to_string(),
            None => continue,
        };
        let is_ta = name.ends_with("_ta.der");
        let is_ee = name.ends_with("_ee.der");
        if !is_ta && !is_ee {
            ignored += 1;
            continue;
        }
        let mut buf = vec![];
        if let Err(e) = entry.read_to_end(&mut buf) {
            out.push(err(format!("Failed to decompress {name}: {e}")));
            continue;
        }
        if is_ta {
            tas.push((name, buf));
        } else {
            ees.push((name, buf));
        }
    }
    tas.sort();
    ees.sort();

    out.push(info(format!(
        "{zip_name}: {} trust anchor(s), {} end entity certificate(s), {} other entries ignored",
        tas.len(),
        ees.len(),
        ignored
    )));
    if tas.is_empty() {
        out.push(err(format!(
            "No *_ta.der entries found in {zip_name}; expected an archive in the artifacts_certs_r5.zip format"
        )));
        return (reports, out);
    }

    let mut ta_store = TaSource::new();
    for (name, der) in &tas {
        ta_store.push(CertFile {
            filename: name.clone(),
            bytes: der.clone(),
        });
    }

    let cps = make_cps(vs, &mut out);
    if let Err(e) = ta_store.initialize() {
        out.push(err(format!("Failed to initialize TA store: {e:?}")));
        return (reports, out);
    }

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe.add_trust_anchor_source(Box::new(ta_store));
    // path building for TA-issued targets happens in the certificate source, so one must be
    // registered even though the R5 format carries no intermediate CA certificates
    let mut cert_source = CertSource::new();
    if let Err(e) = cert_source.initialize(&cps) {
        out.push(err(format!("Failed to initialize CA store: {e:?}")));
        return (reports, out);
    }
    pe.add_certificate_source(Box::new(cert_source));

    // trust anchors are self-signed certificates per the R5 format, so each is checked for
    // self-signed-ness (signature verifies with the certificate's own key)
    for (name, der) in &tas {
        out.extend(validate_self_signed(&pe, name, der));
    }
    for (name, der) in &ees {
        let (report, lines) = validate_target(&pe, &cps, name, der, vs.validate_all);
        out.extend(lines);
        if let Some(report) = report {
            reports.push(report);
        }
    }
    (reports, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pittv3_lib::report::TargetStatus;

    // The app fetches store CBOR at runtime; the native tests read it straight from the resources
    // that Trunk copies into dist. The tuple mirrors validate's (label, ta_cbor, ca_cbor) argument.
    const ML_DSA_44: (&str, &[u8], &[u8]) = (
        "ML-DSA-44 PKITS",
        include_bytes!("../resources/pkits_ml_dsa_44_ta.cbor"),
        include_bytes!("../resources/pkits_ml_dsa_44_ca.cbor"),
    );

    fn test_settings() -> ValidationSettings {
        ValidationSettings {
            // 0 disables validity period checks so the baked PKITS edition stays usable
            toi: 0,
            validate_all: true,
            initial_explicit_policy: false,
            initial_policy_mapping_inhibit: false,
            initial_inhibit_any_policy: false,
            initial_policy_set: String::new(),
            enforce_trust_anchor_constraints: false,
            enforce_trust_anchor_validity: true,
            permitted_subtrees: NameConstraintInputs::default(),
            excluded_subtrees: NameConstraintInputs::default(),
        }
    }

    #[test]
    fn sample_valid_reports_valid() {
        let (reports, _lines) = validate_batch(
            Some(ML_DSA_44),
            &[],
            &[],
            &[(SAMPLE_VALID.0.to_string(), SAMPLE_VALID.1.to_vec())],
            &test_settings(),
        );
        let report = reports.into_iter().next().unwrap();
        assert_eq!(report.status, TargetStatus::Valid);
        assert!(!report.paths.is_empty());
        assert_eq!(report.paths[0].certs.len(), 3);
        assert!(report.paths[0].policy.is_some());
    }

    #[test]
    fn sample_invalid_reports_invalid_at_target() {
        let (reports, _lines) = validate_batch(
            Some(ML_DSA_44),
            &[],
            &[],
            &[(SAMPLE_INVALID.0.to_string(), SAMPLE_INVALID.1.to_vec())],
            &test_settings(),
        );
        let report = reports.into_iter().next().unwrap();
        assert_eq!(report.status, TargetStatus::Invalid);
        let path = &report.paths[0];
        assert_eq!(
            path.status,
            Some(PathValidationStatus::SignatureVerificationFailure)
        );
        // trust-anchor-first indexing: 0 = TA, 1 = Good CA, 2 = target
        assert_eq!(path.failure_index, Some(2));
        assert!(path
            .failure_reasons
            .iter()
            .any(|r| r.contains("SignatureVerificationFailure")));
    }
}
