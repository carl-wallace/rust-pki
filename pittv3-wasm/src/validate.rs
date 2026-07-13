//! In-browser certification path validation built on certval with no-default-features plus pqc

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

/// A line of validation output along with a CSS class used to render it, i.e., "ok", "err" or "info"
pub struct ResultLine {
    /// CSS class: "ok", "err" or "info"
    pub class: &'static str,
    /// Text to display
    pub text: String,
}

fn info(text: String) -> ResultLine {
    ResultLine { class: "info", text }
}
fn ok(text: String) -> ResultLine {
    ResultLine { class: "ok", text }
}
fn err(text: String) -> ResultLine {
    ResultLine { class: "err", text }
}

/// Returns DER bytes given buffers that may be PEM or DER encoded
fn maybe_pem(bytes: &[u8]) -> Result<Vec<u8>> {
    if !bytes.is_empty() && bytes[0] != 0x30 {
        match pem_rfc7468::decode_vec(bytes) {
            Ok(b) => Ok(b.1),
            Err(_e) => Err(Error::Unrecognized),
        }
    } else {
        Ok(bytes.to_vec())
    }
}

/// Validates `ee` against one of the baked-in stores, returning displayable results
pub fn validate_against_store(
    store: &Store,
    ee_name: &str,
    ee: &[u8],
    toi: u64,
    validate_all: bool,
) -> Vec<ResultLine> {
    let ta_store = match TaSource::new_from_cbor(store.ta_cbor) {
        Ok(t) => t,
        Err(e) => return vec![err(format!("Failed to parse TA store CBOR: {e:?}"))],
    };
    let cert_source = match CertSource::new_from_cbor(store.ca_cbor) {
        Ok(c) => c,
        Err(e) => return vec![err(format!("Failed to parse CA store CBOR: {e:?}"))],
    };
    let mut out = vec![info(format!("Using {} store", store.label))];
    // CBOR stores carry precomputed partial paths, so no discovery pass is needed
    out.extend(run_validation(
        ta_store,
        cert_source,
        false,
        ee_name,
        ee,
        toi,
        validate_all,
    ));
    out
}

/// Validates `ee` against uploaded trust anchors and, optionally, uploaded intermediate CA
/// certificates, returning displayable results
pub fn validate_against_uploads(
    tas: &[(String, Vec<u8>)],
    cas: &[(String, Vec<u8>)],
    ee_name: &str,
    ee: &[u8],
    toi: u64,
    validate_all: bool,
) -> Vec<ResultLine> {
    if tas.is_empty() {
        return vec![err(
            "No trust anchors have been uploaded. Upload at least one trust anchor first."
                .to_string(),
        )];
    }
    let mut out = vec![];
    let mut ta_store = TaSource::new();
    for (name, bytes) in tas {
        match maybe_pem(bytes) {
            Ok(der) => {
                out.push(info(format!("Using uploaded trust anchor {name}")));
                ta_store.push(CertFile {
                    filename: name.clone(),
                    bytes: der,
                });
            }
            Err(_) => out.push(err(format!("Failed to parse {name} as PEM or DER"))),
        }
    }
    let mut cert_source = CertSource::new();
    for (name, bytes) in cas {
        match maybe_pem(bytes) {
            Ok(der) => {
                out.push(info(format!("Using uploaded CA certificate {name}")));
                cert_source.push(CertFile {
                    filename: name.clone(),
                    bytes: der,
                });
            }
            Err(_) => out.push(err(format!("Failed to parse {name} as PEM or DER"))),
        }
    }
    // uploaded buffers have no precomputed partial paths, so run discovery
    out.extend(run_validation(
        ta_store,
        cert_source,
        true,
        ee_name,
        ee,
        toi,
        validate_all,
    ));
    out
}

fn run_validation(
    mut ta_store: TaSource,
    mut cert_source: CertSource,
    discover_partial_paths: bool,
    ee_name: &str,
    ee: &[u8],
    toi: u64,
    validate_all: bool,
) -> Vec<ResultLine> {
    let mut out = vec![];

    let toi = match TimeOfInterest::from_unix_secs(toi) {
        Ok(t) => t,
        Err(_) => TimeOfInterest::disabled(),
    };
    let mut cps = CertificationPathSettings::default();
    cps.set_time_of_interest(toi);

    if let Err(e) = ta_store.initialize() {
        return vec![err(format!("Failed to initialize TA store: {e:?}"))];
    }
    if let Err(e) = cert_source.initialize(&cps) {
        return vec![err(format!("Failed to initialize CA store: {e:?}"))];
    }

    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    pe.add_trust_anchor_source(Box::new(ta_store));
    // for uploaded buffers, discover partial paths linking CA certificates to the trust anchors
    // (the TA source must be registered with the environment before discovery)
    if discover_partial_paths {
        cert_source.find_all_partial_paths(&pe, &cps);
    }
    pe.add_certificate_source(Box::new(cert_source));

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
        let r = pe.validate_path(&pe, &cps, path, &mut cpr);
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
