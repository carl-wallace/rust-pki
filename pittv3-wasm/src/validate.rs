//! In-browser certification path validation built on certval with no-default-features plus pqc

use std::io::{Cursor, Read};

use certval::*;

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
pub const STORES: &[Store] = &[
    Store {
        label: "ML-DSA-44 PKITS",
        ta_cbor: include_bytes!("../resources/pkits_ml_dsa_44_ta.cbor"),
        ca_cbor: include_bytes!("../resources/pkits_ml_dsa_44_ca.cbor"),
    },
    Store {
        label: "ML-DSA-65 PKITS",
        ta_cbor: include_bytes!("../resources/pkits_ml_dsa_65_ta.cbor"),
        ca_cbor: include_bytes!("../resources/pkits_ml_dsa_65_ca.cbor"),
    },
    Store {
        label: "ML-DSA-87 PKITS",
        ta_cbor: include_bytes!("../resources/pkits_ml_dsa_87_ta.cbor"),
        ca_cbor: include_bytes!("../resources/pkits_ml_dsa_87_ca.cbor"),
    },
    Store {
        label: "SLH-DSA-SHA2-128s PKITS",
        ta_cbor: include_bytes!("../resources/pkits_slh_dsa_sha2_128s_ta.cbor"),
        ca_cbor: include_bytes!("../resources/pkits_slh_dsa_sha2_128s_ca.cbor"),
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
/// intermediate CA certificates, returning displayable results
pub fn validate(
    store: Option<&Store>,
    tas: &[(String, Vec<u8>)],
    cas: &[(String, Vec<u8>)],
    ee_name: &str,
    ee: &[u8],
    vs: &ValidationSettings,
) -> Vec<ResultLine> {
    let mut out = vec![];

    let mut ta_store = match store {
        Some(s) => match TaSource::new_from_cbor(s.ta_cbor) {
            Ok(t) => t,
            Err(e) => return vec![err(format!("Failed to parse TA store CBOR: {e:?}"))],
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
        return out;
    }

    let mut cert_source = match store {
        Some(s) => match CertSource::new_from_cbor(s.ca_cbor) {
            Ok(c) => c,
            Err(e) => return vec![err(format!("Failed to parse CA store CBOR: {e:?}"))],
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

    out.extend(run_validation(
        ta_store,
        cert_source,
        discover,
        ee_name,
        ee,
        vs,
    ));
    out
}

fn run_validation(
    mut ta_store: TaSource,
    mut cert_source: CertSource,
    discover_partial_paths: bool,
    ee_name: &str,
    ee: &[u8],
    vs: &ValidationSettings,
) -> Vec<ResultLine> {
    let mut out = vec![];

    let cps = make_cps(vs, &mut out);

    if let Err(e) = ta_store.initialize() {
        return vec![err(format!("Failed to initialize TA store: {e:?}"))];
    }
    if let Err(e) = cert_source.initialize(&cps) {
        return vec![err(format!("Failed to initialize CA store: {e:?}"))];
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

    out.extend(validate_target(&pe, &cps, ee_name, ee, vs.validate_all));
    out
}

/// Builds and validates certification path(s) for a single target certificate against a fully
/// prepared [`PkiEnvironment`](certval::PkiEnvironment), returning displayable results
fn validate_target(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    ee_name: &str,
    ee: &[u8],
    validate_all: bool,
) -> Vec<ResultLine> {
    let mut out = vec![];
    let toi = cps.get_time_of_interest();

    let der = match maybe_pem(ee) {
        Ok(der) => der,
        Err(_) => {
            out.push(err(format!("Failed to parse {ee_name} as PEM or DER")));
            return out;
        }
    };
    let target = match parse_cert(&der, ee_name) {
        Ok(t) => t,
        Err(e) => {
            out.push(err(format!("Failed to parse certificate {ee_name}: {e:?}")));
            return out;
        }
    };

    out.push(info(format!(
        "Building and validating path(s) for {} ({})",
        ee_name,
        target.as_ref().tbs_certificate().subject()
    )));

    let mut paths: Vec<CertificationPath> = vec![];
    if let Err(e) = pe.get_paths_for_target(&target, &mut paths, 0, toi) {
        out.push(err(format!("Failed to find certification paths: {e:?}")));
        return out;
    }
    if paths.is_empty() {
        out.push(err(
            "No certification paths found (check trust anchors and time of interest)".to_string(),
        ));
        return out;
    }

    let mut valid = 0;
    let mut invalid = 0;
    for (i, path) in paths.iter_mut().enumerate() {
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
                continue;
            }
        };
        let r = pe.validate_path(pe, &path_cps, path, &mut cpr);
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
    out
}

/// Validates a self-signed certificate as a target anchored at itself, i.e., as done for trust
/// anchors from hackathon archives (path building declines self-signed targets, so the path is
/// constructed directly)
fn validate_self_signed(
    pe: &PkiEnvironment,
    cps: &CertificationPathSettings,
    name: &str,
    der: &[u8],
) -> Vec<ResultLine> {
    let mut out = vec![];
    let ta_choice = match PDVTrustAnchorChoice::create(der, name) {
        Ok(t) => t,
        Err(e) => {
            out.push(err(format!("Failed to parse trust anchor {name}: {e:?}")));
            return out;
        }
    };
    let target = match parse_cert(der, name) {
        Ok(t) => t,
        Err(e) => {
            out.push(err(format!("Failed to parse certificate {name}: {e:?}")));
            return out;
        }
    };
    let mut path = CertificationPath::new(ta_choice, Default::default(), target);

    // fold RFC 5914 trust anchor constraints into the settings per RFC 5937; this is a no-op
    // clone when enforcement is disabled, and validate_path does not perform it itself
    let path_cps = match enforce_trust_anchor_constraints(cps, &path.trust_anchor) {
        Ok(c) => c,
        Err(e) => {
            out.push(err(format!(
                "Self-signed {name}: failed to apply trust anchor constraints: {e:?}"
            )));
            return out;
        }
    };
    let mut cpr = CertificationPathResults::new();
    match pe.validate_path(pe, &path_cps, &mut path, &mut cpr) {
        Ok(_) => out.push(ok(format!("Self-signed {name}: VALID"))),
        Err(e) => out.push(err(format!("Self-signed {name}: INVALID with {e:?}"))),
    }
    out
}

/// Validates the contents of an IETF Hackathon PQC certificates archive in the R5 format, i.e.,
/// artifacts_certs_r5.zip. Entries named `*_ta.der` form the trust anchor store and entries named
/// `*_ee.der` are validated against it; all other entries (private keys, KEM artifacts, etc.) are
/// ignored. The archive is self-contained: built-in stores and uploads are not consulted.
pub fn validate_hackathon_zip(
    zip_name: &str,
    bytes: Vec<u8>,
    vs: &ValidationSettings,
) -> Vec<ResultLine> {
    let mut out = vec![];

    let mut archive = match zip::ZipArchive::new(Cursor::new(bytes)) {
        Ok(a) => a,
        Err(e) => return vec![err(format!("Failed to read {zip_name} as a zip file: {e}"))],
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
        return out;
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
        return out;
    }

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe.add_trust_anchor_source(Box::new(ta_store));
    // path building for TA-issued targets happens in the certificate source, so one must be
    // registered even though the R5 format carries no intermediate CA certificates
    let mut cert_source = CertSource::new();
    if let Err(e) = cert_source.initialize(&cps) {
        out.push(err(format!("Failed to initialize CA store: {e:?}")));
        return out;
    }
    pe.add_certificate_source(Box::new(cert_source));

    // trust anchors are self-signed certificates per the R5 format, so each is also validated
    // as a target anchored at itself
    for (name, der) in &tas {
        out.extend(validate_self_signed(&pe, &cps, name, der));
    }
    for (name, der) in &ees {
        out.extend(validate_target(&pe, &cps, name, der, vs.validate_all));
    }
    out
}
