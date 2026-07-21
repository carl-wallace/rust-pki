//! Form-friendly model of [`CertificationPathSettings`](certval::CertificationPathSettings)
//! values.
//!
//! [`SettingsModel`] carries one `Option` per setting, where `None` means the setting is absent
//! from the underlying map (i.e., the certval default applies). [`SettingsModel::from_cps`] and
//! [`SettingsModel::apply`] translate between the model and a settings map without touching
//! settings the model does not cover (e.g., `PS_CERTIFICATES`), so editing a file through the
//! model preserves unknown content. The model is plain data — no UI types — so it is unit-testable
//! and shared by the desktop and web frontends.

use certval::*;

/// Composed presentation of the revocation-checking settings as a single mode selection.
///
/// The underlying settings (`PS_CHECK_REVOCATION_STATUS`, `PS_CHECK_CRLS`,
/// `PS_CHECK_OCSP_FROM_AIA`, `PS_CHECK_CRLDP_HTTP`) express more combinations than these modes;
/// combinations that do not correspond to a mode are reported as `Custom` and left untouched when
/// `Custom` is applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationMode {
    /// Revocation status is not checked
    Disabled,
    /// Status may be determined using CRLs or OCSP responses
    CrlOrOcsp,
    /// Status may only be determined using CRLs
    CrlOnly,
    /// Status may only be determined using OCSP responses
    OcspOnly,
    /// The individual settings express a combination not covered by the other modes
    Custom,
}

/// One `Option` per [`CertificationPathSettings`] value, where `None` denotes absence from the
/// map (the certval default applies). Grouped by the tabs presented in the settings editor.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SettingsModel {
    // ---- policy ----
    /// initial-explicit-policy input
    pub initial_explicit_policy_indicator: Option<bool>,
    /// initial-policy-mapping-inhibit input
    pub initial_policy_mapping_inhibit_indicator: Option<bool>,
    /// initial-any-policy-inhibit input
    pub initial_inhibit_any_policy_indicator: Option<bool>,
    /// user-initial-policy-set input as OID strings
    pub initial_policy_set: Option<Vec<String>>,

    // ---- name constraints ----
    /// initial-permitted-subtrees input
    pub initial_permitted_subtrees: Option<NameConstraintsSettings>,
    /// initial-excluded-subtrees input
    pub initial_excluded_subtrees: Option<NameConstraintsSettings>,

    // ---- trust anchors and path ----
    /// Enforce constraints expressed in trust anchors per RFC 5937
    pub enforce_trust_anchor_constraints: Option<bool>,
    /// Require trust anchors to be valid at the time of interest
    pub enforce_trust_anchor_validity: Option<bool>,
    /// Require certification paths to terminate at a trust anchor from the store
    pub require_ta_store: Option<bool>,
    /// Maximum number of non-self-issued intermediate certificates permitted in a path
    pub initial_path_length_constraint: Option<u8>,
    /// Use validation checks to filter candidate paths while building
    pub use_validator_filter_when_building: Option<bool>,

    // ---- target ----
    /// Key usage bits the target certificate must assert
    pub target_key_usage: Option<KeyUsageSettings>,
    /// Extended key usage OIDs the target certificate must satisfy
    pub extended_key_usage: Option<Vec<String>>,
    /// Enforce the intersection of extended key usage values across the path
    pub extended_key_usage_path: Option<bool>,
    /// Reject self-signed end entity certificates
    pub forbid_self_signed_ee: Option<bool>,
    /// Enforce algorithm and key size constraints
    pub enforce_alg_and_key_size_constraints: Option<bool>,

    // ---- time ----
    /// Time of interest as seconds since Unix epoch (0 disables validity checks)
    pub time_of_interest: Option<u64>,
    /// Ignore expired certificates when building paths
    pub ignore_expired: Option<bool>,

    // ---- revocation ----
    /// Master switch for revocation status determination
    pub check_revocation_status: Option<bool>,
    /// Consider CRLs when determining status
    pub check_crls: Option<bool>,
    /// Consider OCSP responders from AIA when determining status
    pub check_ocsp_from_aia: Option<bool>,
    /// Fetch CRLs from HTTP CRL DP locations when determining status
    pub check_crldp_http: Option<bool>,
    /// Fetch CRLs from LDAP CRL DP locations when determining status (no LDAP support at present)
    pub check_crldp_ldap: Option<bool>,
    /// Nonce handling for OCSP requests
    pub ocsp_aia_nonce_setting: Option<OcspNonceSetting>,
    /// Allow stale CRLs within grace periods as a last resort
    pub crl_grace_periods_as_last_resort: Option<bool>,
    /// Maximum age in seconds for cached revocation information (0 disables the check)
    pub revocation_max_age_secs: Option<u64>,
    /// Timeout in seconds for CRL retrieval
    pub crl_timeout_secs: Option<u64>,

    // ---- fetching ----
    /// Retrieve certificates from HTTP AIA and SIA locations while building paths
    pub retrieve_from_aia_sia_http: Option<bool>,
    /// Retrieve certificates from LDAP AIA and SIA locations (no LDAP support at present)
    pub retrieve_from_aia_sia_ldap: Option<bool>,
    /// Maximum number of certificates to retrieve via AIA and SIA
    pub max_aia_sia_certs: Option<u64>,

    // ---- countries ----
    /// Require country codes in target certificates to satisfy the permitted/excluded lists
    pub require_country_code_indicator: Option<bool>,
    /// Permitted country codes
    pub perm_countries: Option<Vec<String>>,
    /// Excluded country codes
    pub excl_countries: Option<Vec<String>>,

    // ---- folders and files (desktop-only tab) ----
    /// Folder containing trust anchors
    pub trust_anchor_folder: Option<String>,
    /// Folder containing intermediate CA certificates
    pub certification_authority_folder: Option<String>,
    /// Folder to receive downloaded artifacts
    pub download_folder: Option<String>,
    /// File containing the last-modified map used when fetching
    pub last_modified_map_file: Option<String>,
    /// File containing the URI blocklist used when fetching
    pub uri_blocklist_file: Option<String>,
    /// Generated CBOR contains only trust anchors
    pub cbor_ta_store: Option<bool>,
}

/// Returns true when `key` is present in the settings map
fn present(cps: &CertificationPathSettings, key: &str) -> bool {
    cps.0.contains_key(key)
}

impl SettingsModel {
    /// Prepares a [`SettingsModel`] from a settings map. Each field is `Some` only when the
    /// corresponding setting is present in the map.
    pub fn from_cps(cps: &CertificationPathSettings) -> SettingsModel {
        SettingsModel {
            initial_explicit_policy_indicator: present(cps, PS_INITIAL_EXPLICIT_POLICY_INDICATOR)
                .then(|| cps.get_initial_explicit_policy_indicator()),
            initial_policy_mapping_inhibit_indicator: present(
                cps,
                PS_INITIAL_POLICY_MAPPING_INHIBIT_INDICATOR,
            )
            .then(|| cps.get_initial_policy_mapping_inhibit_indicator()),
            initial_inhibit_any_policy_indicator: present(
                cps,
                PS_INITIAL_INHIBIT_ANY_POLICY_INDICATOR,
            )
            .then(|| cps.get_initial_inhibit_any_policy_indicator()),
            initial_policy_set: present(cps, PS_INITIAL_POLICY_SET)
                .then(|| cps.get_initial_policy_set()),
            initial_permitted_subtrees: cps.get_initial_permitted_subtrees(),
            initial_excluded_subtrees: cps.get_initial_excluded_subtrees(),
            enforce_trust_anchor_constraints: present(cps, PS_ENFORCE_TRUST_ANCHOR_CONSTRAINTS)
                .then(|| cps.get_enforce_trust_anchor_constraints()),
            enforce_trust_anchor_validity: present(cps, PS_ENFORCE_TRUST_ANCHOR_VALIDITY)
                .then(|| cps.get_enforce_trust_anchor_validity()),
            require_ta_store: present(cps, PS_REQUIRE_TA_STORE).then(|| cps.get_require_ta_store()),
            initial_path_length_constraint: present(cps, PS_INITIAL_PATH_LENGTH_CONSTRAINT)
                .then(|| cps.get_initial_path_length_constraint()),
            use_validator_filter_when_building: present(cps, PS_USE_VALIDATOR_FILTER_WHEN_BUILDING)
                .then(|| cps.get_use_validator_filter_when_building()),
            target_key_usage: cps.get_target_key_usage(),
            extended_key_usage: cps.get_extended_key_usage(),
            extended_key_usage_path: present(cps, PS_EXTENDED_KEY_USAGE_PATH)
                .then(|| cps.get_extended_key_usage_path()),
            forbid_self_signed_ee: present(cps, PS_FORBID_SELF_SIGNED_EE)
                .then(|| cps.get_forbid_self_signed_ee()),
            enforce_alg_and_key_size_constraints: present(
                cps,
                PS_ENFORCE_ALG_AND_KEY_SIZE_CONSTRAINTS,
            )
            .then(|| cps.get_enforce_alg_and_key_size_constraints()),
            time_of_interest: present(cps, PS_TIME_OF_INTEREST)
                .then(|| cps.get_time_of_interest().as_unix_secs()),
            ignore_expired: present(cps, PS_IGNORE_EXPIRED).then(|| cps.get_ignore_expired()),
            check_revocation_status: present(cps, PS_CHECK_REVOCATION_STATUS)
                .then(|| cps.get_check_revocation_status()),
            check_crls: present(cps, PS_CHECK_CRLS).then(|| cps.get_check_crls()),
            check_ocsp_from_aia: present(cps, PS_CHECK_OCSP_FROM_AIA)
                .then(|| cps.get_check_ocsp_from_aia()),
            check_crldp_http: present(cps, PS_CHECK_CRLDP_HTTP).then(|| cps.get_check_crldp_http()),
            check_crldp_ldap: present(cps, PS_CHECK_CRLDP_LDAP).then(|| cps.get_check_crldp_ldap()),
            ocsp_aia_nonce_setting: present(cps, PS_OCSP_AIA_NONCE_SETTING)
                .then(|| cps.get_ocsp_aia_nonce_setting()),
            crl_grace_periods_as_last_resort: present(cps, PS_CRL_GRACE_PERIODS_AS_LAST_RESORT)
                .then(|| cps.get_crl_grace_periods_as_last_resort()),
            revocation_max_age_secs: present(cps, PS_REVOCATION_MAX_AGE)
                .then(|| cps.get_revocation_max_age().as_secs()),
            crl_timeout_secs: present(cps, PS_CRL_TIMEOUT).then(|| cps.get_crl_timeout().as_secs()),
            retrieve_from_aia_sia_http: present(cps, PS_RETRIEVE_FROM_AIA_SIA_HTTP)
                .then(|| cps.get_retrieve_from_aia_sia_http()),
            retrieve_from_aia_sia_ldap: present(cps, PS_RETRIEVE_FROM_AIA_SIA_LDAP)
                .then(|| cps.get_retrieve_from_aia_sia_ldap()),
            max_aia_sia_certs: present(cps, PS_MAX_AIA_SIA_CERTS)
                .then(|| cps.get_max_aia_sia_certs()),
            require_country_code_indicator: present(cps, PS_REQUIRE_COUNTRY_CODE_INDICATOR)
                .then(|| cps.get_require_country_code_indicator()),
            perm_countries: cps.get_perm_countries(),
            excl_countries: cps.get_excl_countries(),
            trust_anchor_folder: cps.get_trust_anchor_folder(),
            certification_authority_folder: cps.get_certification_authority_folder(),
            download_folder: cps.get_download_folder(),
            last_modified_map_file: cps.get_last_modified_map_file(),
            uri_blocklist_file: cps.get_uri_blocklist_file(),
            cbor_ta_store: present(cps, PS_CBOR_TA_STORE).then(|| cps.get_cbor_ta_store()),
        }
    }

    /// Applies the model to a settings map: `Some` fields are written and `None` fields are
    /// removed, so the map's covered settings match the model exactly afterwards. Settings the
    /// model does not cover are preserved.
    pub fn apply(&self, cps: &mut CertificationPathSettings) {
        fn set_or_remove<T>(
            cps: &mut CertificationPathSettings,
            key: &str,
            v: &Option<T>,
            setter: impl FnOnce(&mut CertificationPathSettings, T),
        ) where
            T: Clone,
        {
            match v {
                Some(v) => setter(cps, v.clone()),
                None => {
                    cps.0.remove(key);
                }
            }
        }

        set_or_remove(
            cps,
            PS_INITIAL_EXPLICIT_POLICY_INDICATOR,
            &self.initial_explicit_policy_indicator,
            |c, v| c.set_initial_explicit_policy_indicator(v),
        );
        set_or_remove(
            cps,
            PS_INITIAL_POLICY_MAPPING_INHIBIT_INDICATOR,
            &self.initial_policy_mapping_inhibit_indicator,
            |c, v| c.set_initial_policy_mapping_inhibit_indicator(v),
        );
        set_or_remove(
            cps,
            PS_INITIAL_INHIBIT_ANY_POLICY_INDICATOR,
            &self.initial_inhibit_any_policy_indicator,
            |c, v| c.set_initial_inhibit_any_policy_indicator(v),
        );
        set_or_remove(
            cps,
            PS_INITIAL_POLICY_SET,
            &self.initial_policy_set,
            |c, v| c.set_initial_policy_set(v),
        );
        set_or_remove(
            cps,
            PS_INITIAL_PERMITTED_SUBTREES,
            &self.initial_permitted_subtrees,
            |c, v| c.set_initial_permitted_subtrees(v),
        );
        set_or_remove(
            cps,
            PS_INITIAL_EXCLUDED_SUBTREES,
            &self.initial_excluded_subtrees,
            |c, v| c.set_initial_excluded_subtrees(v),
        );
        set_or_remove(
            cps,
            PS_ENFORCE_TRUST_ANCHOR_CONSTRAINTS,
            &self.enforce_trust_anchor_constraints,
            |c, v| c.set_enforce_trust_anchor_constraints(v),
        );
        set_or_remove(
            cps,
            PS_ENFORCE_TRUST_ANCHOR_VALIDITY,
            &self.enforce_trust_anchor_validity,
            |c, v| c.set_enforce_trust_anchor_validity(v),
        );
        set_or_remove(cps, PS_REQUIRE_TA_STORE, &self.require_ta_store, |c, v| {
            c.set_require_ta_store(v)
        });
        set_or_remove(
            cps,
            PS_INITIAL_PATH_LENGTH_CONSTRAINT,
            &self.initial_path_length_constraint,
            |c, v| c.set_initial_path_length_constraint(v),
        );
        set_or_remove(
            cps,
            PS_USE_VALIDATOR_FILTER_WHEN_BUILDING,
            &self.use_validator_filter_when_building,
            |c, v| c.set_use_validator_filter_when_building(v),
        );
        set_or_remove(cps, PS_KEY_USAGE, &self.target_key_usage, |c, v| {
            c.set_target_key_usage(v)
        });
        set_or_remove(
            cps,
            PS_EXTENDED_KEY_USAGE,
            &self.extended_key_usage,
            |c, v| c.set_extended_key_usage(v),
        );
        set_or_remove(
            cps,
            PS_EXTENDED_KEY_USAGE_PATH,
            &self.extended_key_usage_path,
            |c, v| c.set_extended_key_usage_path(v),
        );
        set_or_remove(
            cps,
            PS_FORBID_SELF_SIGNED_EE,
            &self.forbid_self_signed_ee,
            |c, v| c.set_forbid_self_signed_ee(v),
        );
        set_or_remove(
            cps,
            PS_ENFORCE_ALG_AND_KEY_SIZE_CONSTRAINTS,
            &self.enforce_alg_and_key_size_constraints,
            |c, v| c.set_enforce_alg_and_key_size_constraints(v),
        );
        match self.time_of_interest {
            Some(secs) => {
                let toi = match TimeOfInterest::from_unix_secs(secs) {
                    Ok(toi) => toi,
                    Err(_e) => TimeOfInterest::disabled(),
                };
                cps.set_time_of_interest(toi);
            }
            None => {
                cps.0.remove(PS_TIME_OF_INTEREST);
            }
        }
        set_or_remove(cps, PS_IGNORE_EXPIRED, &self.ignore_expired, |c, v| {
            c.set_ignore_expired(v)
        });
        set_or_remove(
            cps,
            PS_CHECK_REVOCATION_STATUS,
            &self.check_revocation_status,
            |c, v| c.set_check_revocation_status(v),
        );
        set_or_remove(cps, PS_CHECK_CRLS, &self.check_crls, |c, v| {
            c.set_check_crls(v)
        });
        set_or_remove(
            cps,
            PS_CHECK_OCSP_FROM_AIA,
            &self.check_ocsp_from_aia,
            |c, v| c.set_check_ocsp_from_aia(v),
        );
        set_or_remove(cps, PS_CHECK_CRLDP_HTTP, &self.check_crldp_http, |c, v| {
            c.set_check_crldp_http(v)
        });
        set_or_remove(cps, PS_CHECK_CRLDP_LDAP, &self.check_crldp_ldap, |c, v| {
            c.set_check_crldp_ldap(v)
        });
        set_or_remove(
            cps,
            PS_OCSP_AIA_NONCE_SETTING,
            &self.ocsp_aia_nonce_setting,
            |c, v| c.set_ocsp_aia_nonce_setting(v),
        );
        set_or_remove(
            cps,
            PS_CRL_GRACE_PERIODS_AS_LAST_RESORT,
            &self.crl_grace_periods_as_last_resort,
            |c, v| c.set_crl_grace_periods_as_last_resort(v),
        );
        set_or_remove(
            cps,
            PS_REVOCATION_MAX_AGE,
            &self.revocation_max_age_secs,
            |c, v| c.set_revocation_max_age(core::time::Duration::from_secs(v)),
        );
        set_or_remove(cps, PS_CRL_TIMEOUT, &self.crl_timeout_secs, |c, v| {
            c.set_crl_timeout(core::time::Duration::from_secs(v))
        });
        set_or_remove(
            cps,
            PS_RETRIEVE_FROM_AIA_SIA_HTTP,
            &self.retrieve_from_aia_sia_http,
            |c, v| c.set_retrieve_from_aia_sia_http(v),
        );
        set_or_remove(
            cps,
            PS_RETRIEVE_FROM_AIA_SIA_LDAP,
            &self.retrieve_from_aia_sia_ldap,
            |c, v| c.set_retrieve_from_aia_sia_ldap(v),
        );
        set_or_remove(
            cps,
            PS_MAX_AIA_SIA_CERTS,
            &self.max_aia_sia_certs,
            |c, v| c.set_max_aia_sia_certs(v),
        );
        set_or_remove(
            cps,
            PS_REQUIRE_COUNTRY_CODE_INDICATOR,
            &self.require_country_code_indicator,
            |c, v| c.set_require_country_code_indicator(v),
        );
        set_or_remove(cps, PS_PERM_COUNTRIES, &self.perm_countries, |c, v| {
            c.set_perm_countries(v)
        });
        set_or_remove(cps, PS_EXCL_COUNTRIES, &self.excl_countries, |c, v| {
            c.set_excl_countries(v)
        });
        set_or_remove(
            cps,
            PS_TRUST_ANCHOR_FOLDER,
            &self.trust_anchor_folder,
            |c, v| c.set_trust_anchor_folder(v),
        );
        set_or_remove(
            cps,
            PS_CERTIFICATION_AUTHORITY_FOLDER,
            &self.certification_authority_folder,
            |c, v| c.set_certification_authority_folder(v),
        );
        set_or_remove(cps, PS_DOWNLOAD_FOLDER, &self.download_folder, |c, v| {
            c.set_download_folder(v)
        });
        set_or_remove(
            cps,
            PS_LAST_MODIFIED_MAP_FILE,
            &self.last_modified_map_file,
            |c, v| c.set_last_modified_map_file(v),
        );
        set_or_remove(
            cps,
            PS_URI_BLOCKLIST_FILE,
            &self.uri_blocklist_file,
            |c, v| c.set_uri_blocklist_file(v),
        );
        set_or_remove(cps, PS_CBOR_TA_STORE, &self.cbor_ta_store, |c, v| {
            c.set_cbor_ta_store(v)
        });
    }

    /// Prepares a settings map containing exactly the `Some` fields of the model
    pub fn to_cps(&self) -> CertificationPathSettings {
        let mut cps = CertificationPathSettings::new();
        self.apply(&mut cps);
        cps
    }

    /// Derives the composed [`RevocationMode`] from the individual revocation settings, using
    /// certval defaults for absent settings. Combinations not matching a mode are `Custom`.
    pub fn revocation_mode(&self) -> RevocationMode {
        let status = self.check_revocation_status.unwrap_or(true);
        if !status {
            return RevocationMode::Disabled;
        }
        let crls = self.check_crls.unwrap_or(true);
        let ocsp = self.check_ocsp_from_aia.unwrap_or(true);
        let crldp = self.check_crldp_http.unwrap_or(true);
        match (crls, crldp, ocsp) {
            (true, true, true) => RevocationMode::CrlOrOcsp,
            (true, true, false) => RevocationMode::CrlOnly,
            (false, false, true) => RevocationMode::OcspOnly,
            _ => RevocationMode::Custom,
        }
    }

    /// Applies a composed [`RevocationMode`] to the individual revocation settings. `Custom`
    /// leaves the individual settings untouched.
    pub fn set_revocation_mode(&mut self, mode: RevocationMode) {
        match mode {
            RevocationMode::Disabled => {
                self.check_revocation_status = Some(false);
            }
            RevocationMode::CrlOrOcsp => {
                self.check_revocation_status = Some(true);
                self.check_crls = Some(true);
                self.check_crldp_http = Some(true);
                self.check_ocsp_from_aia = Some(true);
            }
            RevocationMode::CrlOnly => {
                self.check_revocation_status = Some(true);
                self.check_crls = Some(true);
                self.check_crldp_http = Some(true);
                self.check_ocsp_from_aia = Some(false);
            }
            RevocationMode::OcspOnly => {
                self.check_revocation_status = Some(true);
                self.check_crls = Some(false);
                self.check_crldp_http = Some(false);
                self.check_ocsp_from_aia = Some(true);
            }
            RevocationMode::Custom => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cps_yields_default_model() {
        let cps = CertificationPathSettings::new();
        let model = SettingsModel::from_cps(&cps);
        assert_eq!(model, SettingsModel::default());
    }

    #[test]
    fn model_cps_round_trip() {
        let mut model = SettingsModel {
            initial_explicit_policy_indicator: Some(true),
            initial_policy_set: Some(vec!["2.5.29.32.0".to_string()]),
            enforce_trust_anchor_validity: Some(false),
            initial_path_length_constraint: Some(7),
            extended_key_usage: Some(vec!["1.3.6.1.5.5.7.3.1".to_string()]),
            time_of_interest: Some(1648039783),
            check_revocation_status: Some(true),
            check_crls: Some(false),
            check_ocsp_from_aia: Some(true),
            check_crldp_http: Some(false),
            ocsp_aia_nonce_setting: Some(OcspNonceSetting::SendNonceRequireMatch),
            revocation_max_age_secs: Some(3600),
            crl_timeout_secs: Some(30),
            max_aia_sia_certs: Some(100),
            perm_countries: Some(vec!["US".to_string()]),
            trust_anchor_folder: Some("/tas".to_string()),
            initial_permitted_subtrees: Some(NameConstraintsSettings {
                dns_name: Some(vec!["example.com".to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        model.target_key_usage = {
            let mut ks = KeyUsageSettings::default();
            ks |= x509_cert::ext::pkix::KeyUsages::DigitalSignature;
            Some(ks)
        };

        let cps = model.to_cps();
        let round_tripped = SettingsModel::from_cps(&cps);
        assert_eq!(model, round_tripped);
    }

    #[test]
    fn apply_removes_none_fields_and_preserves_uncovered() {
        let mut cps = CertificationPathSettings::new();
        cps.set_check_revocation_status(false);
        cps.set_ignore_expired(true);

        let model = SettingsModel {
            ignore_expired: Some(false),
            ..Default::default()
        };
        model.apply(&mut cps);

        // check_revocation_status was None in the model, so the key is gone (default applies)
        assert!(!cps.0.contains_key(PS_CHECK_REVOCATION_STATUS));
        assert!(cps.get_check_revocation_status());
        assert!(!cps.get_ignore_expired());
    }

    #[test]
    fn revocation_mode_derivation() {
        let mut model = SettingsModel::default();
        // defaults: everything on
        assert_eq!(model.revocation_mode(), RevocationMode::CrlOrOcsp);

        model.check_revocation_status = Some(false);
        assert_eq!(model.revocation_mode(), RevocationMode::Disabled);

        model.check_revocation_status = Some(true);
        model.check_ocsp_from_aia = Some(false);
        assert_eq!(model.revocation_mode(), RevocationMode::CrlOnly);

        model.check_ocsp_from_aia = Some(true);
        model.check_crls = Some(false);
        model.check_crldp_http = Some(false);
        assert_eq!(model.revocation_mode(), RevocationMode::OcspOnly);

        // mixed combination reports as Custom rather than mis-binning
        model.check_crls = Some(true);
        model.check_crldp_http = Some(false);
        assert_eq!(model.revocation_mode(), RevocationMode::Custom);
    }

    #[test]
    fn revocation_mode_apply_round_trip() {
        for mode in [
            RevocationMode::Disabled,
            RevocationMode::CrlOrOcsp,
            RevocationMode::CrlOnly,
            RevocationMode::OcspOnly,
        ] {
            let mut model = SettingsModel::default();
            model.set_revocation_mode(mode);
            assert_eq!(model.revocation_mode(), mode);
        }

        // applying Custom leaves an existing combination untouched
        let mut model = SettingsModel {
            check_revocation_status: Some(true),
            check_crls: Some(true),
            check_crldp_http: Some(false),
            ..Default::default()
        };
        let before = model.clone();
        model.set_revocation_mode(RevocationMode::Custom);
        assert_eq!(model, before);
    }
}
