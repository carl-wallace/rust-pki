//! Store catalogue and demo material for the in-browser app.
//!
//! The validation itself lives in [`pittv3_gui_lib::validate`] and is re-exported here, so the
//! app's imports are unchanged. What stays is what is specific to *this* deployment: the store
//! URLs, which are relative to index.html so they resolve at any mount point, and the sample
//! certificates the demo offers.
//!
//! The catalogue has two sources. [`STORES`] ships with the application and is always there. When
//! the application is served by `pittv3-service`, the stores that service holds are added to it at
//! startup from `GET api/stores` — see [`merge_service_stores`]. A statically hosted deployment
//! asks and gets nothing, which is not an error condition: it is the arrangement this application
//! was built for and still the default.

use serde::Deserialize;

pub use pittv3_gui_lib::validate::*;

/// A trust anchor store and CA certificate store pair, referenced by the URL of its CBOR file.
/// The CBOR ships alongside the wasm (see the Trunk `copy-dir` of `resources`) rather than baked
/// into the binary, and is fetched on demand when the store is selected. URLs are relative to
/// index.html so they resolve at any deployment mount point (matching `public_url = "./"`).
pub struct Store {
    /// Identifier, matching the one `pittv3-service` gives the same material, which is how a store
    /// served by that service is recognized as one this application already ships. It is also what
    /// a server-side validation request would name.
    pub id: &'static str,
    /// Display name for the store
    pub label: &'static str,
    /// URL of the CBOR-serialized trust anchor store
    pub ta_url: &'static str,
    /// URL of the CBOR-serialized CA certificate store with partial certification paths, or
    /// `None` for a trust-anchor-only store (e.g. Web PKI roots without preloaded
    /// intermediates); intermediates can then be supplied via upload.
    pub ca_url: Option<&'static str>,
}

/// Stores shipped alongside the application, always available
pub const STORES: &[Store] = &[
    Store {
        id: "pkits_ml_dsa_44",
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
        id: "webpki",
        label: "Web PKI (Mozilla roots, TLS + S/MIME, + CCADB intermediates)",
        ta_url: "resources/webpki_ta.cbor",
        // CCADB intermediate set with precomputed partial paths; AIA fallback (once the
        // fetch proxy lands) will cover anything not preloaded here
        ca_url: Some("resources/webpki_ca.cbor"),
    },
    Store {
        id: "dod_nipr_prod",
        label: "U.S. DoD (NIPR)",
        ta_url: "resources/dod_nipr_prod_ta.cbor",
        ca_url: Some("resources/dod_nipr_prod_ca.cbor"),
    },
];

/// Where a store in the selector came from, which is as much as this application can say about how
/// far to trust what it holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreOrigin {
    /// Generated from a certval trust store provider and published with this application.
    Shipped,
    /// Held by the service, generated from a certval trust store provider when it was built. Every
    /// certificate has a citable origin, the same as a shipped store.
    ServiceProvider,
    /// Held by the service, from the store directory its deployment configured. Worth
    /// distinguishing: such a store may have been assembled by chasing authority information access
    /// URIs, in which case the provenance of a certificate in it is "some repository served it".
    ServiceConfigured,
}

impl StoreOrigin {
    /// A phrase for the selector, completing "This store is ___."
    pub fn hint(&self) -> &'static str {
        match self {
            StoreOrigin::Shipped => "published with this application, from a trust store provider",
            StoreOrigin::ServiceProvider => {
                "held by the service, from a trust store provider built into it"
            }
            StoreOrigin::ServiceConfigured => {
                "held by the service, from the store directory it was configured with"
            }
        }
    }
}

/// A store the selector can offer, from either source.
///
/// Owned rather than `&'static` because the served half arrives at run time. The URLs are used the
/// same way whichever source they came from — fetched when the store is selected — which is the
/// point: the selector renders both without knowing which is which.
#[derive(Clone, Debug, PartialEq)]
pub struct CatalogEntry {
    /// Identifier the service knows this store by; also what distinguishes the two sources' stores
    /// from each other.
    pub id: String,
    /// Display name for the store
    pub label: String,
    /// URL of the CBOR-serialized trust anchor store
    pub ta_url: String,
    /// URL of the CBOR-serialized CA certificate store, or `None` for anchors alone
    pub ca_url: Option<String>,
    /// Where the material came from
    pub origin: StoreOrigin,
}

/// Where a service says one of its stores came from, as `GET api/stores` reports it.
///
/// An unstated provenance reads as [`Provenance::Configured`], which is the conservative of the
/// two: a service that does not say is not one to take a claim of provider material from.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Provenance {
    /// Generated from a trust store provider when the service was built.
    Provider,
    /// Read from the store directory the deployment configured.
    #[default]
    Configured,
}

/// One store as `GET api/stores` describes it. The URLs are relative to the service root, which is
/// where this application is served from when there is a service at all, so they are used exactly
/// as the shipped stores' `resources/…` URLs are.
#[derive(Clone, Debug, Deserialize)]
pub struct StoreDescriptor {
    /// Identifier the service knows the store by
    pub id: String,
    /// Name to show
    pub label: String,
    /// URL of the CBOR-serialized trust anchor store
    pub ta_url: String,
    /// URL of the CBOR-serialized CA certificate store, absent for a store carrying anchors alone
    #[serde(default)]
    pub ca_url: Option<String>,
    /// Where the service says the material came from
    #[serde(default)]
    pub provenance: Provenance,
}

/// The catalogue as it stands before any service has been asked.
pub fn shipped_catalog() -> Vec<CatalogEntry> {
    STORES
        .iter()
        .map(|s| CatalogEntry {
            id: s.id.to_string(),
            label: s.label.to_string(),
            ta_url: s.ta_url.to_string(),
            ca_url: s.ca_url.map(str::to_string),
            origin: StoreOrigin::Shipped,
        })
        .collect()
}

/// Adds the stores a service holds to `catalog`, returning how many were added.
///
/// A served store whose identifier this application already ships is dropped rather than offered
/// twice. That is not deduplication by name and luck: `pittv3-service` generates its built-in
/// stores by the same `serialize_environment` call on the same provider environment that this
/// crate's build script makes, and names them accordingly, so `webpki` there and `webpki` here are
/// the same material by construction. A deployment that means to override one puts it in the
/// service's store directory, where it replaces the built-in of that name before the listing is
/// ever produced — so what arrives here under a shipped identifier is only ever the same store.
pub fn merge_service_stores(
    catalog: &mut Vec<CatalogEntry>,
    served: Vec<StoreDescriptor>,
) -> usize {
    let mut added = 0;
    for d in served {
        if catalog.iter().any(|e| e.id == d.id) {
            continue;
        }
        let origin = match d.provenance {
            Provenance::Provider => StoreOrigin::ServiceProvider,
            Provenance::Configured => StoreOrigin::ServiceConfigured,
        };
        catalog.push(CatalogEntry {
            id: d.id,
            label: d.label,
            ta_url: d.ta_url,
            ca_url: d.ca_url,
            origin,
        });
        added += 1;
    }
    added
}

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
    ///
    /// The revocation line mirrors `run_settings` in main.rs and has to stay in step with it: certval
    /// defaults revocation checking *on*, the browser cannot fetch what the check would consult, and
    /// the shared validation path now makes the call -- so applying the model alone would leave
    /// every run here reporting undetermined status, which is not what the app does. This module is
    /// compiled into the ziptest binary as well, whose crate root has no `run_settings` to call.
    fn test_settings() -> CertificationPathSettings {
        let model = SettingsModel {
            // 0 disables validity period checks so the baked PKITS edition stays usable
            time_of_interest: Some(0),
            ..SettingsModel::default()
        };
        let mut cps = CertificationPathSettings::default();
        model.apply(&mut cps);
        cps.set_check_revocation_status(false);
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

    #[test]
    fn revocation_checking_is_reached_and_reports_undetermined_without_data() {
        // The same certificate that validates above, with revocation checking asked for. The
        // browser has no CRL source registered and nothing stapled into the path, so the honest
        // answer is that status could not be determined -- and the fact that the answer changes at
        // all is what proves the call site is reached. This is the shape a relayed run improves on
        // by filling the path's stapled slots before validating.
        //
        // The outcome depends on how the tree was built, which is worth asserting rather than
        // wishing away: certval's revocation checker is asynchronous under its `std` feature and
        // synchronous otherwise, and this synchronous path can only make the call in the second
        // case. Building this crate on its own gives the no-std certval the browser ships and the
        // check runs; a workspace-wide build unifies certval's features with the CLI's and the
        // check cannot be made, which the run says outright in its notes. Both are correct
        // behavior for the build in question, and the note is what keeps the difference visible.
        let mut cps = test_settings();
        cps.set_check_revocation_status(true);

        let (reports, lines) = validate_batch(
            ML_DSA_44,
            &[(SAMPLE_VALID.0.to_string(), SAMPLE_VALID.1.to_vec())],
            &cps,
        );
        let report = reports.into_iter().next().unwrap();
        let declined = lines
            .iter()
            .any(|l| l.text.contains("revocation checker is asynchronous"));
        if declined {
            assert_eq!(report.status, TargetStatus::Valid);
        } else {
            assert_eq!(
                report.status,
                TargetStatus::ValidExceptRevocationUndetermined
            );
            assert_eq!(
                report.paths[0].status,
                Some(PathValidationStatus::RevocationStatusNotDetermined)
            );
        }

        // Left off, the same run is simply valid: the check is what changed the outcome, not the
        // certificates.
        let (reports, _lines) = validate_batch(
            ML_DSA_44,
            &[(SAMPLE_VALID.0.to_string(), SAMPLE_VALID.1.to_vec())],
            &test_settings(),
        );
        assert_eq!(reports[0].status, TargetStatus::Valid);
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

    /// The listing is `pittv3-service`'s `StoreCatalog::listing` verbatim, so this is the wire form
    /// as that service emits it -- including a store carrying anchors alone, which offers no CA URL
    /// rather than one that would serve nothing.
    #[test]
    fn a_service_listing_parses_and_extends_the_catalogue() {
        let json = r#"[
            {"id":"fpki","label":"U.S. Federal PKI (Common Policy CA G2)",
             "ta_url":"stores/fpki/ta.cbor","ca_url":"stores/fpki/ca.cbor","provenance":"provider"},
            {"id":"webpki_tls","label":"Web PKI (Mozilla roots, TLS only)",
             "ta_url":"stores/webpki_tls/ta.cbor","ca_url":null,"provenance":"provider"},
            {"id":"local_pki","label":"Something this deployment built",
             "ta_url":"stores/local_pki/ta.cbor","ca_url":"stores/local_pki/ca.cbor",
             "provenance":"configured"}
        ]"#;
        let served: Vec<StoreDescriptor> = serde_json::from_str(json).unwrap();

        let mut catalog = shipped_catalog();
        let shipped = catalog.len();
        assert_eq!(merge_service_stores(&mut catalog, served), 3);
        assert_eq!(catalog.len(), shipped + 3);

        // Shipped stores keep their position, so a selection made before the listing arrived still
        // names the store it named.
        assert!(catalog[..shipped]
            .iter()
            .all(|e| e.origin == StoreOrigin::Shipped));
        assert_eq!(catalog[shipped].id, "fpki");
        assert_eq!(catalog[shipped].origin, StoreOrigin::ServiceProvider);
        assert_eq!(catalog[shipped + 1].ca_url, None);
        assert_eq!(
            catalog[shipped + 2].origin,
            StoreOrigin::ServiceConfigured,
            "a store from the service's own directory is not provider material"
        );
    }

    /// A service built from the same providers offers stores this application already ships, and
    /// they are the same material by construction -- so they are dropped rather than shown twice
    /// under two origins.
    #[test]
    fn a_store_already_shipped_is_not_offered_twice() {
        let served = vec![
            StoreDescriptor {
                id: "webpki".to_string(),
                label: "Web PKI (Mozilla roots, TLS + S/MIME, + CCADB intermediates)".to_string(),
                ta_url: "stores/webpki/ta.cbor".to_string(),
                ca_url: Some("stores/webpki/ca.cbor".to_string()),
                provenance: Provenance::Provider,
            },
            StoreDescriptor {
                id: "dod_nipr_prod".to_string(),
                label: "U.S. DoD (NIPR production)".to_string(),
                ta_url: "stores/dod_nipr_prod/ta.cbor".to_string(),
                ca_url: Some("stores/dod_nipr_prod/ca.cbor".to_string()),
                provenance: Provenance::Provider,
            },
        ];

        let mut catalog = shipped_catalog();
        let shipped = catalog.len();
        assert_eq!(merge_service_stores(&mut catalog, served), 0);
        assert_eq!(catalog.len(), shipped);
        // and the shipped URLs are the ones still in use, not the service's
        let webpki = catalog.iter().find(|e| e.id == "webpki").unwrap();
        assert_eq!(webpki.ta_url, "resources/webpki_ta.cbor");
    }

    /// A service that says nothing about where a store came from gets the conservative reading:
    /// unstated is not provider material.
    #[test]
    fn an_unstated_provenance_is_not_taken_for_provider_material() {
        let json = r#"[{"id":"x","label":"X","ta_url":"stores/x/ta.cbor"}]"#;
        let served: Vec<StoreDescriptor> = serde_json::from_str(json).unwrap();
        assert_eq!(served[0].provenance, Provenance::Configured);
        assert_eq!(served[0].ca_url, None);
    }
}
