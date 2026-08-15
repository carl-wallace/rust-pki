//! Store catalogue and demo material for the in-browser app.
//!
//! The validation itself lives in [`pittv3_gui_lib::validate`] and is re-exported here, so the
//! app's imports are unchanged. What stays is what is specific to *this* deployment: the store
//! URLs, which are relative to index.html so they resolve at any mount point, and the sample
//! certificates the demo offers.

pub use pittv3_gui_lib::validate::*;

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
    // The anchors are the provider's MOZILLA_ALL environment — every root carrying a websites
    // OR an email trust bit — so the anchor set does not gate purpose: a TLS certificate can
    // validate here against a root Mozilla trusts only for S/MIME, and vice versa. The label
    // says "TLS + S/MIME" for that reason. Judging the purpose means reading the trust bits
    // Mozilla records beside each root, which are out-of-band policy that RFC 5280 processing
    // cannot see and a certval CBOR store does not carry.
    Store {
        label: "Web PKI (Mozilla roots, TLS + S/MIME, + CCADB intermediates)",
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

#[cfg(test)]
mod tests {
    // These exercise the shared validation path against this crate's generated store resources,
    // so they live here rather than in pittv3-gui-lib, which has no fixtures of its own. certval
    // is named explicitly because the module above re-exports the validation API rather than
    // glob-importing certval the way the pre-split file did.
    use super::*;
    use certval::*;
    use pittv3_gui_lib::gui_settings_model::SettingsModel;
    use pittv3_lib::report::{TargetReport, TargetStatus};

    // The app fetches store CBOR at runtime; the native tests read it straight from the resources
    // that Trunk copies into dist. The tuple mirrors validate's (label, ta_cbor, ca_cbor) argument.
    const ML_DSA_44: (&str, &[u8], &[u8]) = (
        "ML-DSA-44 PKITS",
        include_bytes!("../resources/pkits_ml_dsa_44_ta.cbor"),
        include_bytes!("../resources/pkits_ml_dsa_44_ca.cbor"),
    );

    /// The settings a test run uses, built through the same SettingsModel the settings form edits.
    fn test_settings() -> CertificationPathSettings {
        let model = SettingsModel {
            // 0 disables validity period checks so the baked PKITS edition stays usable
            time_of_interest: Some(0),
            ..SettingsModel::default()
        };
        let mut cps = CertificationPathSettings::default();
        model.apply(&mut cps);
        cps
    }

    /// Prepares an environment for `store` and validates `ees` against it in one call, as the
    /// frontend's cached prepare/validate split does across clicks.
    fn validate_batch(
        store: (&str, &[u8], &[u8]),
        ees: &[(String, Vec<u8>)],
        cps: &CertificationPathSettings,
    ) -> (Vec<TargetReport>, Vec<ResultLine>) {
        let mut notes = vec![];
        let (prepared, prep_notes) = prepare_validation(Some(store), &[], &[], cps).unwrap();
        notes.extend(prep_notes);
        let (reports, lines) = validate_prepared(&prepared, cps, ees, true);
        notes.extend(lines);
        (reports, notes)
    }

    #[test]
    fn sample_valid_reports_valid() {
        let (reports, _lines) = validate_batch(
            ML_DSA_44,
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
            ML_DSA_44,
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

    // The settings file is certval's CertificationPathSettings JSON. certval is built here with its
    // `std` feature off (the wasm dependency set), so these exercise the no_std serde path the
    // browser build relies on for save/load.

    #[test]
    fn cps_json_round_trips_no_std() {
        let model = SettingsModel {
            time_of_interest: Some(1647264981),
            initial_explicit_policy_indicator: Some(true),
            initial_policy_set: Some(vec!["2.16.840.1.101.3.2.1.48.1".to_string()]),
            ..SettingsModel::default()
        };
        let mut cps = CertificationPathSettings::default();
        model.apply(&mut cps);
        let json = serde_json::to_string(&cps).unwrap();
        // current certval stores the time of interest as the TimeOfInterest variant (a bare u64),
        // not the legacy psTimeOfInterest {"U64": ...} form that predates the TimeOfInterest type
        assert!(json.contains(r#""psTimeOfInterest":{"TimeOfInterest":1647264981}"#));
        let back: CertificationPathSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(cps, back);
    }

    #[test]
    fn cps_keyusage_serde_round_trips_no_std() {
        // KeyUsageValue is (de)serialized via a custom u16-bits impl (not flagset/serde, which would
        // pull serde/std and break no_std). Confirm the wire form is the raw integer and it round-trips.
        let mut cps = CertificationPathSettings::new();
        let ku = KeyUsageSettings::new_truncated(0b0000_0101); // digitalSignature + keyEncipherment
        cps.set_target_key_usage(ku);
        let json = serde_json::to_string(&cps).unwrap();
        assert!(json.contains(r#""KeyUsageValue":5"#));
        let back: CertificationPathSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(cps, back);
        assert_eq!(back.get_target_key_usage(), Some(ku));
    }

    #[test]
    fn parses_cps_file() {
        // shape produced by make_cps / the CLI and desktop apps today
        let json = r#"{"psInitialExplicitPolicyIndicator":{"Bool":true},"psInitialPolicySet":{"Strings":["2.16.840.1.101.3.2.1.48.1"]},"psTimeOfInterest":{"TimeOfInterest":1647264981}}"#;
        let cps: CertificationPathSettings = serde_json::from_str(json).unwrap();
        assert!(cps.get_initial_explicit_policy_indicator());
        assert_eq!(cps.get_time_of_interest().as_unix_secs(), 1647264981);
        assert_eq!(
            cps.get_initial_policy_set(),
            vec!["2.16.840.1.101.3.2.1.48.1".to_string()]
        );
    }
}
