//! In-browser certification path validation built on certval with no-default-features plus pqc

use std::io::{Cursor, Read};

use certval::*;
use pittv3_lib::report::{CertSummary, PathReport, TargetReport};
use web_time::Instant;

/// A trust anchor store and CA certificate store pair baked into the application as CBOR
pub struct Store {
    /// Display name for the store
    pub label: &'static str,
    /// CBOR-serialized trust anchor store
    pub ta_cbor: &'static [u8],
    /// CBOR-serialized CA certificate store with partial certification paths
    pub ca_cbor: &'static [u8],
}

/// Baked-in stores available for selection in the UI
pub const STORES: &[Store] = &[Store {
    label: "ML-DSA-44 PKITS",
    ta_cbor: include_bytes!("../resources/pkits_ml_dsa_44_ta.cbor"),
    ca_cbor: include_bytes!("../resources/pkits_ml_dsa_44_ca.cbor"),
}];

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
    /// Enforce algorithm and key size constraints
    pub enforce_alg_and_key_size_constraints: bool,
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
    cps.set_enforce_alg_and_key_size_constraints(vs.enforce_alg_and_key_size_constraints);

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

/// Validates `ee` against the union of an optional baked-in store and uploaded trust anchors and
/// intermediate CA certificates, returning a structured report for the target (absent when
/// processing failed before path building) along with displayable notes
pub fn validate(
    store: Option<&Store>,
    tas: &[(String, Vec<u8>)],
    cas: &[(String, Vec<u8>)],
    ee_name: &str,
    ee: &[u8],
    vs: &ValidationSettings,
) -> (Option<TargetReport>, Vec<ResultLine>) {
    let mut out = vec![];

    let mut ta_store = match store {
        Some(s) => match TaSource::new_from_cbor(s.ta_cbor) {
            Ok(t) => t,
            Err(e) => {
                return (
                    None,
                    vec![err(format!("Failed to parse TA store CBOR: {e:?}"))],
                )
            }
        },
        None => TaSource::new(),
    };
    for (name, bytes) in tas {
        match maybe_pem(bytes) {
            Ok(der) => ta_store.push(CertFile {
                filename: name.clone(),
                bytes: der,
            }),
            Err(_) => out.push(err(format!(
                "Failed to parse uploaded trust anchor {name} as PEM or DER"
            ))),
        }
    }
    if ta_store.is_empty() {
        out.push(err(
            "No trust anchors are available. Select a built-in store or upload at least one trust anchor."
                .to_string(),
        ));
        return (None, out);
    }

    let mut cert_source = match store {
        Some(s) => match CertSource::new_from_cbor(s.ca_cbor) {
            Ok(c) => c,
            Err(e) => {
                return (
                    None,
                    vec![err(format!("Failed to parse CA store CBOR: {e:?}"))],
                )
            }
        },
        None => CertSource::new(),
    };
    for (name, bytes) in cas {
        match maybe_pem(bytes) {
            Ok(der) => cert_source.push(CertFile {
                filename: name.clone(),
                bytes: der,
            }),
            Err(_) => out.push(err(format!(
                "Failed to parse uploaded CA certificate {name} as PEM or DER"
            ))),
        }
    }

    // baked-in CBOR stores carry precomputed partial paths; any uploaded buffers require a
    // discovery pass over the merged set
    let discover = !tas.is_empty() || !cas.is_empty();
    match (store, discover) {
        (Some(s), false) => out.push(info(format!("Using {} store", s.label))),
        (Some(s), true) => out.push(info(format!(
            "Using {} store with {} uploaded trust anchor(s) and {} uploaded intermediate(s)",
            s.label,
            tas.len(),
            cas.len()
        ))),
        (None, _) => out.push(info(format!(
            "Using {} uploaded trust anchor(s) and {} uploaded intermediate(s)",
            tas.len(),
            cas.len()
        ))),
    }

    let (report, lines) = run_validation(ta_store, cert_source, discover, ee_name, ee, vs);
    out.extend(lines);
    (report, out)
}

fn run_validation(
    mut ta_store: TaSource,
    mut cert_source: CertSource,
    discover_partial_paths: bool,
    ee_name: &str,
    ee: &[u8],
    vs: &ValidationSettings,
) -> (Option<TargetReport>, Vec<ResultLine>) {
    let mut out = vec![];

    let cps = make_cps(vs, &mut out);

    if let Err(e) = ta_store.initialize() {
        return (
            None,
            vec![err(format!("Failed to initialize TA store: {e:?}"))],
        );
    }
    if let Err(e) = cert_source.initialize(&cps) {
        return (
            None,
            vec![err(format!("Failed to initialize CA store: {e:?}"))],
        );
    }

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe.add_trust_anchor_source(Box::new(ta_store));
    // discover partial paths linking CA certificates to the trust anchors (the TA source must be
    // registered with the environment before discovery)
    if discover_partial_paths {
        cert_source.find_all_partial_paths(&pe, &cps);
    }
    pe.add_certificate_source(Box::new(cert_source));

    let (report, lines) = validate_target(&pe, &cps, ee_name, ee, vs.validate_all);
    out.extend(lines);
    (report, out)
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
            enforce_alg_and_key_size_constraints: false,
        }
    }

    #[test]
    fn sample_valid_reports_valid() {
        let (report, _lines) = validate(
            Some(&STORES[0]),
            &[],
            &[],
            SAMPLE_VALID.0,
            SAMPLE_VALID.1,
            &test_settings(),
        );
        let report = report.unwrap();
        assert_eq!(report.status, TargetStatus::Valid);
        assert!(!report.paths.is_empty());
        assert_eq!(report.paths[0].certs.len(), 3);
        assert!(report.paths[0].policy.is_some());
    }

    #[test]
    fn sample_invalid_reports_invalid_at_target() {
        let (report, _lines) = validate(
            Some(&STORES[0]),
            &[],
            &[],
            SAMPLE_INVALID.0,
            SAMPLE_INVALID.1,
            &test_settings(),
        );
        let report = report.unwrap();
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
