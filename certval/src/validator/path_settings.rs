//! Structures and functions related to configuring certification path processing operations

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::{vec, vec::Vec};
use core::str::FromStr;
use core::time::Duration;

use flagset::FlagSet;
use serde::{Deserialize, Serialize};

use const_oid::db::rfc5280::ANY_POLICY;
use der::asn1::ObjectIdentifier;
use x509_cert::ext::pkix::KeyUsages;

use pkiprocmacros::*;

use crate::alloc::string::ToString;
use crate::pdv_certificate::*;
use crate::{
    name_constraints_set_to_name_constraints_settings,
    name_constraints_settings_to_name_constraints_set, NameConstraintsSet, NameConstraintsSettings,
    Result,
};

#[cfg(feature = "std")]
use std::path::Path;
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "std")]
use serde_json::Result as SerdeResult;

#[cfg(feature = "std")]
use crate::builder::file_utils::get_file_as_byte_vec;
#[cfg(feature = "std")]
use crate::Error;

//-----------------------------------------------------------------------------------------------
// Type definitions used in the definition of path settings
//-----------------------------------------------------------------------------------------------
/// `ObjectIdentifierSet` is a typedef for a vector of ObjectIdentifier values.
/// #[Derive(Serialize, Deserialize)]
pub type ObjectIdentifierSet = BTreeSet<ObjectIdentifier>;

/// `Strings` is a typedef for a vector of String values.
pub type Strings = Vec<String>;

/// `Buffers` is a typedef for a vector of `Vec<u8>` values.
pub type Buffers = Vec<Vec<u8>>;

/// `ListOfBuffers` is a typedef for a vector of vectors of `Vec<u8>` values.
pub type ListOfBuffers = Vec<Vec<Vec<u8>>>;

/// `Bools` is a typedef for a vector bool values.
pub type Bools = Vec<bool>;

/// `CertificationPathSettings` is a typedef for a `BTreeMap` that maps arbitrary string values to a
/// variant map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct CertificationPathSettings(pub BTreeMap<String, CertificationPathProcessingTypes>);

impl CertificationPathSettings {
    /// Creates a new empty [`CertificationPathSettings`]
    pub fn new() -> Self {
        Self::default()
    }
}

/// `CertificateChain` is a typedef for a vector of `PDVCertificate`.
pub type CertificateChain = Vec<PDVCertificate>;

//-----------------------------------------------------------------------------------------------
// A few enum and struct definitions used in the definition of path settings
//-----------------------------------------------------------------------------------------------
/// `OcspNonceSetting` controls how OCSP responses are processed with respect to nonce values.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OcspNonceSetting {
    /// DoNotSendNonce indicates that the OCSP client should not include nonce values in OCSP requests
    DoNotSendNonce,
    /// SendNonceRequireMatch indicates that the OCSP client should include nonce values in OCSP requests
    /// and should fail when responses do not feature the value.
    SendNonceRequireMatch,
    /// SendNonceRequireMatch indicates that the OCSP client should include nonce values in OCSP requests
    /// and should not fail when responses do not feature the value.
    SendNonceTolerateMismatchAbsence,
}

/// The `ValidPolicyTreeNode` is used to represent nodes returned via a `PR_VALID_POLICY_TREE` entry in a
/// [`CertificationPathResults`](../certval/path_settings/type.CertificationPathResults.html) instance. Each node in the valid_policy_tree includes three data
//  objects: the valid policy, a set of associated policy qualifiers, and a set of one or more expected
//  policy values. Each node relative to a depth x.
#[derive(Clone, Debug)]
pub struct ValidPolicyTreeNode {
    /// The valid_policy is a single policy OID representing a valid policy for the path of length x.
    pub valid_policy: ObjectIdentifier,
    /// The qualifier_set is a set of policy qualifiers associated with the valid policy in certificate x.
    pub qualifier_set: Option<Vec<u8>>,
    /// The expected_policy_set contains one or more policy OIDs that would satisfy this policy in the certificate x+1.
    pub expected_policy_set: ObjectIdentifierSet,
}

/// Define a type to serve as the final value of the valid_policy_tree returned from [`check_certificate_policies`](../path_validator/fn.check_certificate_policies.html)
/// (or similar implementation).
pub type FinalValidPolicyTree = Vec<Vec<ValidPolicyTreeNode>>;

/// KeyUsageSettings provides a flagset that can be used to serialize key usage settings
pub type KeyUsageSettings = FlagSet<KeyUsages>;

//-----------------------------------------------------------------------------------------------
// Enum used to define all path settings and results
//-----------------------------------------------------------------------------------------------
/// `CertificationPathProcessingTypes` is used to define a variant map with types associated with
/// performing certification path discovery and validation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum CertificationPathProcessingTypes {
    /// Represents bool values
    Bool(bool),
    /// Represents u8 values
    U8(u8),
    /// Represents u16 values
    U16(u16),
    /// Represents u64 values
    U64(u64),
    /// Represents NameConstraintsSet values
    NameConstraintsSettings(NameConstraintsSettings),
    /// Represents String values
    String(String),
    /// Represents vectors of u8 values
    Buffer(Vec<u8>),
    /// Represents vectors of Strings
    Strings(Strings),
    /// Represents vectors of bools
    Bools(Vec<bool>),
    /// Represents vectors of buffers
    Buffers(Vec<Vec<u8>>),
    /// Represents vectors of vectors of buffers
    ListOfBuffers(Vec<Vec<Vec<u8>>>),
    /// Represents KeyUsageValues values
    KeyUsageValue(KeyUsageSettings),
    /// Represents instruction for nonce handling in OCSP client
    OcspNonceSetting(OcspNonceSetting),
    /// Represents duration or a timeout
    Duration(Duration),
}

//-----------------------------------------------------------------------------------------------
// Types of path settings
//-----------------------------------------------------------------------------------------------
/// `PS_INITIAL_EXPLICIT_POLICY_INDICATOR` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. This corresponds to the initial-explicit-policy value described in
/// [RFC 5280 Section 6.1.1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.1>. By default,
// /// this setting is set to false.
pub static PS_INITIAL_EXPLICIT_POLICY_INDICATOR: &str = "psInitialExplicitPolicyIndicator";

/// `PS_INITIAL_POLICY_MAPPING_INHIBIT_INDICATOR` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. This corresponds to the initial-policy-mapping-inhibit value described in
/// [RFC 5280 Section 6.1.1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.1>. By default,
// /// this setting is set to false.
pub static PS_INITIAL_POLICY_MAPPING_INHIBIT_INDICATOR: &str =
    "psInitialPolicyMappingInhibitIndicator";

/// `PS_INITIAL_INHIBIT_ANY_POLICY_INDICATOR` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. This corresponds to the initial-any-policy-inhibit value described in
/// [RFC 5280 Section 6.1.1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.1>. By default,
/// this setting is set to false.
pub static PS_INITIAL_INHIBIT_ANY_POLICY_INDICATOR: &str = "psInitialInhibitAnyPolicyIndicator";

/// `PS_INITIAL_POLICY_SET` is used to retrieve an ObjectIdentifierSet value from a [`CertificationPathSettings`]
/// object. This corresponds to the user-initial-policy-set value described in
/// [RFC 5280 Section 6.1.1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.1>. By default,
/// a set containing ANY_POLICY is used.
pub static PS_INITIAL_POLICY_SET: &str = "psInitialPolicySet";

/// `PS_INITIAL_PERMITTED_SUBTREES` is used to retrieve a NameConstraints value from a [`CertificationPathSettings`]
/// object. This corresponds to the initial-permitted-subtrees value described in
/// [RFC 5280 Section 6.1.1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.1>.
pub static PS_INITIAL_PERMITTED_SUBTREES: &str = "psInitialPermittedSubtrees";

/// `PS_INITIAL_EXCLUDED_SUBTREES` is used to retrieve a NameConstraints value from a [`CertificationPathSettings`]
/// object. This corresponds to the initial-excluded-subtrees value described in
/// [RFC 5280 Section 6.1.1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.1>.
pub static PS_INITIAL_EXCLUDED_SUBTREES: &str = "psInitialExcludedSubtrees";

/// `PS_TIME_OF_INTEREST` is used to retrieve a Time value from a [`CertificationPathSettings`]
/// object. This corresponds to the current date/time value described in
/// [RFC 5280 Section 6.1.1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1.1>. The value
/// need not be current data/time and can be a time in the past to support retrospective validation.
/// The value is expressed as a u64 containing seconds since Unix epoch (i.e., 1970-01-01T00:00:00Z).
/// By default, the value is set to current time if std is available, else the value defaults to 0.
pub static PS_TIME_OF_INTEREST: &str = "psTimeOfInterest";

/// `PS_ENFORCE_TRUST_ANCHOR_CONSTRAINTS` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. This corresponds to the enforceTrustAnchorConstraints value described in
/// [RFC 5937 Section 3.1]: <https://datatracker.ietf.org/doc/html/rfc5937#section-3.1>. By default,
/// this value is set to false, i.e., trust anchor constraints are not enforced delta possible
/// EKU enforcement per the PS_EXTENDED_KEY_USAGE_PATH setting.
pub static PS_ENFORCE_TRUST_ANCHOR_CONSTRAINTS: &str = "psEnforceTrustAnchorConstraints";

/// `PS_ENFORCE_TRUST_ANCHOR_VALIDITY` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. By default, this setting is set to true (per industry convention, RFC5280 does not
/// require checking trust anchor (TA) validity. Turn this value off to refrain from checking TA validity.
pub static PS_ENFORCE_TRUST_ANCHOR_VALIDITY: &str = "psEnforceTrustAnchorValidity";

/// `PS_KEY_USAGE` is used to retrieve a u16 value from a [`CertificationPathSettings`] object.
/// The first 9 bits from the value will be considered (all other bits are ignored) when evaluating
/// the target certificate, i.e., the target certificate must have a KeyUsage extension with the at
/// least the bits indicated set. When this is absent, KeyUsage values in the target certificate are
/// not considered when validating a certification path.
pub static PS_KEY_USAGE: &str = "psKeyUsage";

/// `PS_EXTENDED_KEY_USAGE` is used to retrieve an ObjectIdentifierSet from a [`CertificationPathSettings`]
/// object. There is no default. Absence of this configuration indicates EKU usage is unconstrained
/// by the caller. EKU processing for the path may still occur per the PS_EXTENDED_KEY_USAGE_PATH
/// configuration value.
pub static PS_EXTENDED_KEY_USAGE: &str = "psExtendedKeyUsage";

/// `PS_EXTENDED_KEY_USAGE_PATH` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. The default value is false. When true, certification path validation should ensure the
/// intersection of extended key usage values that appear in a certification path is not empty,
/// consistent with the prevailing practices.
pub static PS_EXTENDED_KEY_USAGE_PATH: &str = "psExtendedKeyUsagePath";

/// `PS_INITIAL_PATH_LENGTH_CONSTRAINT` is used to retrieve a u8 value from a [`CertificationPathSettings`]
/// object. This value is used in concert with BasicConstraints extensions during certification
/// path validation by establishing the maximum path length that will be accepted. By default, the
/// value is set to 15, as defined by `PS_MAX_PATH_LENGTH_CONSTRAINT`.
pub static PS_INITIAL_PATH_LENGTH_CONSTRAINT: &str = "psInitialPathLengthConstraint";

/// `PS_MAX_PATH_LENGTH_CONSTRAINT` sets the maximum length path accepted by validation implementation
pub static PS_MAX_PATH_LENGTH_CONSTRAINT: u8 = 15;

/// `PS_CRL_TIMEOUT_DEFAULT` sets the maximum amount of time to spend downloading a CRL expressed in seconds.
pub static PS_CRL_TIMEOUT_DEFAULT: Duration = Duration::from_secs(60);

/// `PS_CRL_TIMEOUT` is used to a u64 that expresses the maximum amount of time to spend downloading a CRL expressed in seconds.
pub static PS_CRL_TIMEOUT: &str = "psCrlTimeout";

/// `PS_ENFORCE_ALG_AND_KEY_SIZE_CONSTRAINTS` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. The default value is false. When true, certification path validation should ensure the
/// no operative algorithm or key size constraints are violated.
pub static PS_ENFORCE_ALG_AND_KEY_SIZE_CONSTRAINTS: &str = "psEnforceAlgAndKeySizeConstraints";

/// `PS_USE_VALIDATOR_FILTER_WHEN_BUILDING` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. The default value is true. When true, certification path building should employ relevant
/// certification path validation practices during path building (see RFC 4158).
pub static PS_USE_VALIDATOR_FILTER_WHEN_BUILDING: &str = "psUseValidatorFilterWhenBuilding";

/// `PS_CHECK_REVOCATION_STATUS` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. The default value is true. When true, certification path validation should perform
/// revocation status checks via available means, i.e., CRLs, OCSP, etc.
pub static PS_CHECK_REVOCATION_STATUS: &str = "psCheckRevocationStatus";

/// `PS_CHECK_OCSP_FROM_AIA` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. The default value is true. When true, certification path validation should perform
/// revocation status checks via OCSP as indicated in operative AIA extension.
pub static PS_CHECK_OCSP_FROM_AIA: &str = "psCheckOcspFromAia";

/// `PS_RETRIEVE_FROM_AIA_SIA_HTTP` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. The default value is true. When true, certification path building should fetch certificates
/// from locations identified by HTTP/HTTPS URIs in AIA extensions.
pub static PS_RETRIEVE_FROM_AIA_SIA_HTTP: &str = "psRetrieveFromAiaSiaHttp";

/// `PS_RETRIEVE_FROM_AIA_SIA_LDAP` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. The default value is false. When true, certification path building should fetch certificates
/// from locations identified by LDAP URIs in AIA extensions.
pub static PS_RETRIEVE_FROM_AIA_SIA_LDAP: &str = "psRetrieveFromAiaSiaLdap";

/// `PS_CHECK_CRLS` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. The default value is true. When true, certification path validation should perform
/// revocation status checks via available CRLs.
pub static PS_CHECK_CRLS: &str = "psCheckCrls";

/// `PS_CHECK_CRLDP_HTTP` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. The default value is true. When true, certification path building should fetch CRLs
/// from locations identified by HTTP/HTTPS URIs in AIA extensions.
pub static PS_CHECK_CRLDP_HTTP: &str = "psCheckCrlDpHttp";

/// `PS_CHECK_CRLDP_LDAP` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. The default value is false. When true, certification path building should fetch CRLs
/// from locations identified by LDAP URIs in AIA extensions.
pub static PS_CHECK_CRLDP_LDAP: &str = "psCheckCrlDpLdap";

/// `PS_CRL_GRACE_PERIODS_AS_LAST_RESORT` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. The default value is true. When true, certification path validation should process CRLs
/// using grace periods only after exhausting other notionally current options.
pub static PS_CRL_GRACE_PERIODS_AS_LAST_RESORT: &str = "psCrlGracePeriodsAsLastResort";

/// `PS_IGNORE_EXPIRED` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. The default value is false. When true, certification path validation should ignore certificate
/// expiry errors. This is useful only in limited cases, such as when processing iOS device certificates
/// issued by expired CAs (see warning in Apple's Over-the-Air Profile Delivery and Configuration specification).
pub static PS_IGNORE_EXPIRED: &str = "psIgnoreExpired";

/// `PS_OCSP_AIA_NONCE_SETTING` is used to retrieve an i8 value indicating an enumerated value that
/// determines whether or not OCSP requests associated with OCSP responders arrived at via AIA extensions
/// should include a nonce value.
pub static PS_OCSP_AIA_NONCE_SETTING: &str = "psOcspAiaNonceSetting";

/// `PS_CERTIFICATES` is used to retrieve a set of potentially useful certificates from a [`CertificationPathSettings`]
/// object.
pub static PS_CERTIFICATES: &str = "psCertificates";

/// `PS_REQUIRE_COUNTRY_CODE_INDICATOR` is used to retrieve a boolean value from a [`CertificationPathSettings`]
/// object. The default value is false. When true, certification path validation should process require
/// target certificates to feature a subjectDirectoryAttributes extension containing a country code.
pub static PS_REQUIRE_COUNTRY_CODE_INDICATOR: &str = "psRequireCountryCodeIndicator";

/// `PS_PERM_COUNTRIES` is used to retrieve a Strings value, i.e., vector of String, from a [`CertificationPathSettings`]
/// object. When present, target certificates featuring a subjectDirectoryAttributes extension containing a country code
/// will be evaluated to affirm the values in the certificate are permitted.
pub static PS_PERM_COUNTRIES: &str = "psPermCountries";

/// `PS_EXCL_COUNTRIES` is used to retrieve a Strings value, i.e., vector of String, from a [`CertificationPathSettings`]
/// object. When present, target certificates featuring a subjectDirectoryAttributes extension containing a country code
/// will be evaluated to affirm the values in the certificate are not exluded.
pub static PS_EXCL_COUNTRIES: &str = "psExclCountries";

/// PS_TRUST_ANCHOR_FOLDER is used to retrieve a String value containing the full path of a folder containing trust anchors
pub static PS_TRUST_ANCHOR_FOLDER: &str = "psTrustAnchorFolder";
/// PS_CERTIFICATION_AUTHORITY_FOLDER is used to retrieve a String value containing the full path of a folder containing CA certificates
pub static PS_CERTIFICATION_AUTHORITY_FOLDER: &str = "psCertificationAuthorityFolder";
/// PS_DOWNLOAD_FOLDER is used to retrieve a String value containing the full path of a folder where certificates downloaded via SIA or AIA should be stored
pub static PS_DOWNLOAD_FOLDER: &str = "psDownloadFolder";
/// PS_LAST_MODIFIED_MAP_FILE is used to retrieve a String value containing the full path and filename of a file mapping URIs to last modified values
pub static PS_LAST_MODIFIED_MAP_FILE: &str = "psLastModifiedMapFile";
/// PS_URI_BLOCKLIST_FILE is used to retrieve a String value containing the full path and filename of a file that lists non-functional URIs that should be avoided
pub static PS_URI_BLOCKLIST_FILE: &str = "psUriBlocklistFile";
/// PS_CBOR_TA_STORE is used to indicate a generated graph will include only trust anchors, so no need for partial paths and no need to exclude self-signed certificates.
pub static PS_CBOR_TA_STORE: &str = "psCborTaStore";
/// PS_REQUIRE_TA_STORE is used to indicate that the validator should require a TA to affirm given TA is actually a TA.
pub static PS_REQUIRE_TA_STORE: &str = "psRequireTaStore";
/// PS_USE_POLICY_GRAPH is used to indicate that the validator should use policy graph-based certificate policy processing.
pub static PS_USE_POLICY_GRAPH: &str = "psUsePolicyGraph";

//-----------------------------------------------------------------------------------------------
// Getters/setters for settings
//-----------------------------------------------------------------------------------------------
cps_gets_and_sets_with_default!(PS_INITIAL_EXPLICIT_POLICY_INDICATOR, bool, false);
cps_gets_and_sets_with_default!(PS_INITIAL_POLICY_MAPPING_INHIBIT_INDICATOR, bool, false);
cps_gets_and_sets_with_default!(PS_INITIAL_INHIBIT_ANY_POLICY_INDICATOR, bool, false);
// cps_gets_and_sets_with_default!(PS_INITIAL_POLICY_SET, Strings, {
//     let mut bts = BTreeSet::new();
//     bts.insert(ANY_POLICY.to_string());
//     bts
// });
impl CertificationPathSettings {
    ///`get_initial_policy_set` is used to retrieve `PS_INITIAL_POLICY_SET` items from a [`CertificationPathSettings`] instance
    pub fn get_initial_policy_set(&self) -> Strings {
        if self.0.contains_key(PS_INITIAL_POLICY_SET) {
            return match &self.0[PS_INITIAL_POLICY_SET] {
                CertificationPathProcessingTypes::Strings(v) => v.clone(),
                _ => {
                    vec![ANY_POLICY.to_string()]
                }
            };
        }
        {
            vec![ANY_POLICY.to_string()]
        }
    }
    ///`set_initial_policy_set` is used to set `PS_INITIAL_POLICY_SET` items in a [`CertificationPathSettings`] instance
    pub fn set_initial_policy_set(&mut self, v: Strings) {
        self.0.insert(
            PS_INITIAL_POLICY_SET.to_string(),
            CertificationPathProcessingTypes::Strings(v),
        );
    }

    /// `set_initial_policy_set_from_oid_set` is used to set `PS_INITIAL_POLICY_SET` items in a [`CertificationPathSettings`] instance
    /// given an ObjectIdentifierSet object instead of a Strings object.
    pub fn set_initial_policy_set_from_oid_set(&mut self, v: ObjectIdentifierSet) {
        let mut s = Strings::new();
        for o in v {
            s.push(o.to_string());
        }

        self.0.insert(
            PS_INITIAL_POLICY_SET.to_string(),
            CertificationPathProcessingTypes::Strings(s),
        );
    }

    ///`get_initial_policy_set_as_oid_set` is used to retrieve `PS_INITIAL_POLICY_SET` items from a [`CertificationPathSettings`] instance
    /// as an ObjectIdentifierSet object instead of a Strings object.
    pub fn get_initial_policy_set_as_oid_set(&self) -> ObjectIdentifierSet {
        let strs = self.get_initial_policy_set();
        let mut bts = BTreeSet::new();
        for s in strs {
            if let Ok(oid) = ObjectIdentifier::from_str(s.as_str()) {
                bts.insert(oid);
            }
        }
        bts
    }

    // PS_INITIAL_EXCLUDED_SUBTREES (will need lifetime aware macro)

    /// `get_initial_permitted_subtrees` retrieves the `PS_INITIAL_PERMITTED_SUBTREES` value from a
    /// [`CertificationPathSettings`] map. If present, a [`NameConstraintsSettings`] value is returned, else None is returned.
    pub fn get_initial_permitted_subtrees(&self) -> Option<NameConstraintsSettings> {
        if self.0.contains_key(PS_INITIAL_PERMITTED_SUBTREES) {
            return match &self.0[PS_INITIAL_PERMITTED_SUBTREES] {
                CertificationPathProcessingTypes::NameConstraintsSettings(ncs) => Some(ncs.clone()),
                _ => None,
            };
        }
        None
    }

    /// `get_initial_permitted_subtrees` retrieves the `PS_INITIAL_PERMITTED_SUBTREES` value from a
    /// [`CertificationPathSettings`] map as a NameConstraintsSet object instead of as a NameConstraintsSettings object.
    /// If present, a [`NameConstraintsSet`] value is returned, else None is returned.
    pub fn get_initial_permitted_subtrees_as_set(
        &self,
        bufs: &mut BTreeMap<String, Vec<Vec<u8>>>,
    ) -> Result<Option<NameConstraintsSet>> {
        if self.0.contains_key(PS_INITIAL_PERMITTED_SUBTREES) {
            return match &self.0[PS_INITIAL_PERMITTED_SUBTREES] {
                CertificationPathProcessingTypes::NameConstraintsSettings(ncs) => {
                    match name_constraints_settings_to_name_constraints_set(ncs, bufs) {
                        Ok(nc) => Ok(Some(nc)),
                        Err(e) => Err(e),
                    }
                }
                _ => Ok(None),
            };
        }
        Ok(None)
    }

    /// `get_initial_permitted_subtrees_with_default_as_set` retrieves the `PS_INITIAL_PERMITTED_SUBTREES` value from a
    /// [`CertificationPathSettings`] map as a NameConstraintsSet object instead of as a NameConstraintsSettings object.
    /// If present, a [`NameConstraintsSet`] value containing configured values is returned, else a default
    /// instance is returned.
    pub fn get_initial_permitted_subtrees_with_default_as_set(
        &self,
        bufs: &mut BTreeMap<String, Vec<Vec<u8>>>,
    ) -> Result<NameConstraintsSet> {
        if self.0.contains_key(PS_INITIAL_PERMITTED_SUBTREES) {
            return match &self.0[PS_INITIAL_PERMITTED_SUBTREES] {
                CertificationPathProcessingTypes::NameConstraintsSettings(ncs) => {
                    match name_constraints_settings_to_name_constraints_set(ncs, bufs) {
                        Ok(nc) => Ok(nc),
                        Err(e) => Err(e),
                    }
                }
                _ => Ok(NameConstraintsSet::default()),
            };
        }
        Ok(NameConstraintsSet::default())
    }

    /// `get_initial_permitted_subtrees` retrieves the `PS_INITIAL_PERMITTED_SUBTREES` value from a
    /// [`CertificationPathSettings`] map. If present, a [`NameConstraintsSet`] value is returned, else NameConstraintsSet::default() is returned.
    pub fn get_initial_permitted_subtrees_with_default(&self) -> NameConstraintsSettings {
        if self.0.contains_key(PS_INITIAL_PERMITTED_SUBTREES) {
            return match &self.0[PS_INITIAL_PERMITTED_SUBTREES] {
                CertificationPathProcessingTypes::NameConstraintsSettings(ncs) => ncs.clone(),
                _ => NameConstraintsSettings::default(),
            };
        }
        NameConstraintsSettings::default()
    }

    /// `set_initial_permitted_subtrees` is used to set the `PS_INITIAL_PERMITTED_SUBTREES` value in
    /// a [`CertificationPathSettings`] map.
    pub fn set_initial_permitted_subtrees(&mut self, ncs: NameConstraintsSettings) {
        self.0.insert(
            PS_INITIAL_PERMITTED_SUBTREES.to_string(),
            CertificationPathProcessingTypes::NameConstraintsSettings(ncs),
        );
    }

    /// `set_initial_permitted_subtrees` is used to set the `PS_INITIAL_PERMITTED_SUBTREES` value in
    /// a [`CertificationPathSettings`] map given a NameConstraintsSet object instead of a NameConstraintsSettings object.
    pub fn set_initial_permitted_subtrees_from_set(
        &mut self,
        ncs: &NameConstraintsSet,
    ) -> Result<()> {
        self.0.insert(
            PS_INITIAL_PERMITTED_SUBTREES.to_string(),
            CertificationPathProcessingTypes::NameConstraintsSettings(
                name_constraints_set_to_name_constraints_settings(ncs)?,
            ),
        );
        Ok(())
    }

    /// `get_initial_excluded_subtrees` retrieves the `PS_INITIAL_EXCLUDED_SUBTREES` value from a
    /// [`CertificationPathSettings`] map. If present, a [`NameConstraintsSettings`] value is returned, else None is returned.
    pub fn get_initial_excluded_subtrees(&self) -> Option<NameConstraintsSettings> {
        if self.0.contains_key(PS_INITIAL_EXCLUDED_SUBTREES) {
            return match &self.0[PS_INITIAL_EXCLUDED_SUBTREES] {
                CertificationPathProcessingTypes::NameConstraintsSettings(ncs) => Some(ncs.clone()),
                _ => None,
            };
        }
        None
    }

    /// `get_initial_excluded_subtrees` retrieves the `PS_INITIAL_EXCLUDED_SUBTREES` value from a
    /// [`CertificationPathSettings`] map as a NameConstraintsSet instead of as a NameConstraintsSetttings.
    /// If present, a [`NameConstraintsSet`] value is returned, else None is returned.
    pub fn get_initial_excluded_subtrees_as_set(
        &self,
        bufs: &mut BTreeMap<String, Vec<Vec<u8>>>,
    ) -> Result<Option<NameConstraintsSet>> {
        if self.0.contains_key(PS_INITIAL_EXCLUDED_SUBTREES) {
            return match &self.0[PS_INITIAL_EXCLUDED_SUBTREES] {
                CertificationPathProcessingTypes::NameConstraintsSettings(ncs) => {
                    match name_constraints_settings_to_name_constraints_set(ncs, bufs) {
                        Ok(nc) => Ok(Some(nc)),
                        Err(e) => Err(e),
                    }
                }
                _ => Ok(None),
            };
        }
        Ok(None)
    }

    /// `get_initial_excluded_subtrees` retrieves the `PS_INITIAL_EXCLUDED_SUBTREES` value from a
    /// [`CertificationPathSettings`] map as a NameConstraintsSet instead of as a NameConstraintsSetttings.
    /// If present, a [`NameConstraintsSet`] value is returned, else a default instance is returned.
    pub fn get_initial_excluded_subtrees_with_default_as_set(
        &self,
        bufs: &mut BTreeMap<String, Vec<Vec<u8>>>,
    ) -> Result<NameConstraintsSet> {
        if self.0.contains_key(PS_INITIAL_EXCLUDED_SUBTREES) {
            return match &self.0[PS_INITIAL_EXCLUDED_SUBTREES] {
                CertificationPathProcessingTypes::NameConstraintsSettings(ncs) => {
                    match name_constraints_settings_to_name_constraints_set(ncs, bufs) {
                        Ok(nc) => Ok(nc),
                        Err(e) => Err(e),
                    }
                }
                _ => Ok(NameConstraintsSet::default()),
            };
        }
        Ok(NameConstraintsSet::default())
    }

    /// `get_initial_excluded_subtrees` retrieves the `PS_INITIAL_EXCLUDED_SUBTREES` value from a
    /// [`CertificationPathSettings`] map. If present, a [`NameConstraintsSettings`] value is returned, else NameConstraintsSet::default() is returned.
    pub fn get_initial_excluded_subtrees_with_default(&self) -> NameConstraintsSettings {
        if self.0.contains_key(PS_INITIAL_EXCLUDED_SUBTREES) {
            return match &self.0[PS_INITIAL_EXCLUDED_SUBTREES] {
                CertificationPathProcessingTypes::NameConstraintsSettings(ncs) => ncs.clone(),
                _ => NameConstraintsSettings::default(),
            };
        }
        NameConstraintsSettings::default()
    }

    /// `set_initial_excluded_subtrees` is used to set the `PS_INITIAL_EXCLUDED_SUBTREES` value in
    /// a [`CertificationPathSettings`] map.
    pub fn set_initial_excluded_subtrees(&mut self, ncs: NameConstraintsSettings) {
        self.0.insert(
            PS_INITIAL_EXCLUDED_SUBTREES.to_string(),
            CertificationPathProcessingTypes::NameConstraintsSettings(ncs),
        );
    }

    /// `set_initial_excluded_subtrees_from_set` is used to set the `PS_INITIAL_EXCLUDED_SUBTREES` value in
    /// a [`CertificationPathSettings`] map given a NameConstraintsSet object instead of a NameConstraintsSettings object.
    pub fn set_initial_excluded_subtrees_from_set(
        &mut self,
        ncs: &NameConstraintsSet,
    ) -> Result<()> {
        self.0.insert(
            PS_INITIAL_EXCLUDED_SUBTREES.to_string(),
            CertificationPathProcessingTypes::NameConstraintsSettings(
                name_constraints_set_to_name_constraints_settings(ncs)?,
            ),
        );
        Ok(())
    }
}

cps_gets_and_sets_with_default!(PS_TIME_OF_INTEREST, u64, {
    #[cfg(feature = "std")]
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => 0,
    }
    #[cfg(not(feature = "std"))]
    0
});
cps_gets_and_sets_with_default!(PS_ENFORCE_TRUST_ANCHOR_CONSTRAINTS, bool, false);
cps_gets_and_sets_with_default!(PS_ENFORCE_TRUST_ANCHOR_VALIDITY, bool, true);

impl CertificationPathSettings {
    // PS_KEY_USAGE (see below, need lifetime aware macro to avoid manual implementation)
    //cps_gets_and_sets!(PS_EXTENDED_KEY_USAGE, Strings);
    ///`get_extended_key_usage` is used to retrieve `PS_EXTENDED_KEY_USAGE` items from a [`CertificationPathSettings`] instance
    pub fn get_extended_key_usage(&self) -> Option<Strings> {
        if self.0.contains_key(PS_EXTENDED_KEY_USAGE) {
            return match &self.0[PS_EXTENDED_KEY_USAGE] {
                CertificationPathProcessingTypes::Strings(v) => Some(v.clone()),
                _ => None,
            };
        }
        None
    }

    ///`set_extended_key_usage` is used to set `PS_EXTENDED_KEY_USAGE` items in a [`CertificationPathSettings`] instance
    pub fn set_extended_key_usage(&mut self, v: Strings) {
        self.0.insert(
            PS_EXTENDED_KEY_USAGE.to_string(),
            CertificationPathProcessingTypes::Strings(v),
        );
    }

    ///`set_extended_key_usage` is used to set `PS_EXTENDED_KEY_USAGE` items in a [`CertificationPathSettings`] instance
    /// given an ObjectIdentifierSet instead of a Strings object.
    pub fn set_extended_key_usage_from_oid_set(&mut self, v: ObjectIdentifierSet) {
        let mut s = Strings::new();
        for o in v {
            s.push(o.to_string());
        }

        self.0.insert(
            PS_EXTENDED_KEY_USAGE.to_string(),
            CertificationPathProcessingTypes::Strings(s),
        );
    }

    ///`get_extended_key_usage_as_oid_set` is used to retrieve `PS_EXTENDED_KEY_USAGE` items from a [`CertificationPathSettings`] instance
    /// as an ObjectIdentifierSet object instead of a Strings object.
    pub fn get_extended_key_usage_as_oid_set(&self) -> Option<ObjectIdentifierSet> {
        let mut bts = BTreeSet::new();
        if let Some(strs) = self.get_extended_key_usage() {
            for s in strs {
                if let Ok(oid) = ObjectIdentifier::from_str(s.as_str()) {
                    bts.insert(oid);
                }
            }
            Some(bts)
        } else {
            None
        }
    }
}

cps_gets_and_sets_with_default!(PS_EXTENDED_KEY_USAGE_PATH, bool, false);
cps_gets_and_sets_with_default!(
    PS_INITIAL_PATH_LENGTH_CONSTRAINT,
    u8,
    PS_MAX_PATH_LENGTH_CONSTRAINT
);
cps_gets_and_sets_with_default!(PS_CRL_TIMEOUT, Duration, PS_CRL_TIMEOUT_DEFAULT);

cps_gets_and_sets_with_default!(PS_ENFORCE_ALG_AND_KEY_SIZE_CONSTRAINTS, bool, false);
cps_gets_and_sets_with_default!(PS_USE_VALIDATOR_FILTER_WHEN_BUILDING, bool, true);
cps_gets_and_sets_with_default!(PS_CHECK_REVOCATION_STATUS, bool, true);
cps_gets_and_sets_with_default!(PS_CHECK_OCSP_FROM_AIA, bool, true);
cps_gets_and_sets_with_default!(PS_RETRIEVE_FROM_AIA_SIA_HTTP, bool, true);
cps_gets_and_sets_with_default!(PS_RETRIEVE_FROM_AIA_SIA_LDAP, bool, false);
cps_gets_and_sets_with_default!(PS_CHECK_CRLS, bool, true);
cps_gets_and_sets_with_default!(PS_CHECK_CRLDP_HTTP, bool, true);
cps_gets_and_sets_with_default!(PS_CHECK_CRLDP_LDAP, bool, false);
cps_gets_and_sets_with_default!(PS_CRL_GRACE_PERIODS_AS_LAST_RESORT, bool, true);
cps_gets_and_sets_with_default!(PS_IGNORE_EXPIRED, bool, false);
cps_gets_and_sets_with_default!(
    PS_OCSP_AIA_NONCE_SETTING,
    OcspNonceSetting,
    OcspNonceSetting::DoNotSendNonce
);
// PS_MAXIMUM_PATH_DEPTH (ditch this and use PS_INITIAL_PATH_LENGTH_CONSTRAINT)
// PS_CERTIFICATES (will need lifetime aware macro)
cps_gets_and_sets_with_default!(PS_REQUIRE_COUNTRY_CODE_INDICATOR, bool, false);
cps_gets_and_sets!(PS_PERM_COUNTRIES, Strings);
cps_gets_and_sets!(PS_EXCL_COUNTRIES, Strings);
cps_gets_and_sets_with_default!(PS_REQUIRE_TA_STORE, bool, true);
cps_gets_and_sets_with_default!(PS_USE_POLICY_GRAPH, bool, false);

impl CertificationPathSettings {
    /// `get_target_key_usage` retrieves the `PS_KEY_USAGE` value from a
    /// [`CertificationPathSettings`] map. If present, a u8 value is returned, else None is returned.
    pub fn get_target_key_usage(&self) -> Option<KeyUsageSettings> {
        if self.0.contains_key(PS_KEY_USAGE) {
            return match &self.0[PS_KEY_USAGE] {
                CertificationPathProcessingTypes::KeyUsageValue(v) => Some(*v),
                _ => None,
            };
        }
        None
    }

    /// `set_target_key_usage` is used to set the [`PS_KEY_USAGE`] value in a [`CertificationPathSettings`] map.
    pub fn set_target_key_usage(&mut self, v: KeyUsageSettings) {
        self.0.insert(
            PS_KEY_USAGE.to_string(),
            CertificationPathProcessingTypes::KeyUsageValue(v),
        );
    }
}

/// `read_settings` accepts a string containing the name of a file that notionally contains JSON data that
/// represents CertificationPathSettings.
///
/// The map is expressed as a BTreeMap<String, String> with a URI as the key and last modified time
/// returned from that resource as the value.
#[cfg(feature = "std")]
pub fn read_settings(fname: &Option<String>) -> Result<CertificationPathSettings> {
    if let Some(fname) = fname {
        let p = Path::new(fname.as_str());
        if Path::exists(p) {
            if let Ok(json) = get_file_as_byte_vec(p) {
                let r: SerdeResult<CertificationPathSettings> = serde_json::from_slice(&json);
                match r {
                    Ok(cps) => {
                        return Ok(cps);
                    }
                    Err(_e) => return Err(Error::ParseError),
                };
            }
        }
    }
    Ok(CertificationPathSettings::new())
}

cps_gets_and_sets!(PS_TRUST_ANCHOR_FOLDER, String);
cps_gets_and_sets!(PS_CERTIFICATION_AUTHORITY_FOLDER, String);
cps_gets_and_sets!(PS_DOWNLOAD_FOLDER, String);
cps_gets_and_sets!(PS_LAST_MODIFIED_MAP_FILE, String);
cps_gets_and_sets!(PS_URI_BLOCKLIST_FILE, String);
cps_gets_and_sets_with_default!(PS_CBOR_TA_STORE, bool, false);

#[test]
fn test_default_gets_cps() {
    let cps = CertificationPathSettings::default();

    assert!(!cps.get_initial_explicit_policy_indicator());
    assert!(!cps.get_initial_policy_mapping_inhibit_indicator());
    assert!(!cps.get_initial_inhibit_any_policy_indicator());

    #[cfg(feature = "std")]
    {
        let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1000));
        assert!(cps.get_time_of_interest() > before.as_secs());
    }
    #[cfg(not(feature = "std"))]
    {
        assert_eq!(cps.get_time_of_interest(), 0);
    }

    assert!(!cps.get_enforce_trust_anchor_constraints());
    assert!(cps.get_enforce_trust_anchor_validity());
    assert!(!cps.get_extended_key_usage_path());
    assert_eq!(Duration::from_secs(60), cps.get_crl_timeout());
    assert!(!cps.get_enforce_alg_and_key_size_constraints());

    assert!(cps.get_use_validator_filter_when_building());
    assert!(cps.get_check_revocation_status());
    assert!(cps.get_check_ocsp_from_aia());
    assert!(cps.get_retrieve_from_aia_sia_http());
    assert!(!cps.get_retrieve_from_aia_sia_ldap());
    assert!(cps.get_check_crls());
    assert!(cps.get_check_crldp_http());
    assert!(!cps.get_check_crldp_ldap());
    assert!(cps.get_crl_grace_periods_as_last_resort());
    assert!(!cps.get_ignore_expired());
    assert_eq!(
        OcspNonceSetting::DoNotSendNonce,
        cps.get_ocsp_aia_nonce_setting()
    );
    assert!(!cps.get_require_country_code_indicator());

    assert_eq!(vec![ANY_POLICY.to_string()], cps.get_initial_policy_set());
    assert!(!cps.get_cbor_ta_store());
}

#[test]
fn test_no_default_gets_cps() {
    let cps = CertificationPathSettings::default();

    assert_eq!(None, cps.get_perm_countries());
    assert_eq!(None, cps.get_excl_countries());
    assert_eq!(None, cps.get_initial_permitted_subtrees());
    let mut bufs1 = BTreeMap::new();
    assert_eq!(
        None,
        cps.get_initial_permitted_subtrees_as_set(&mut bufs1)
            .unwrap()
    );
    assert_eq!(
        NameConstraintsSettings::default(),
        cps.get_initial_permitted_subtrees_with_default()
    );
    assert_eq!(
        NameConstraintsSet::default(),
        cps.get_initial_permitted_subtrees_with_default_as_set(&mut bufs1)
            .unwrap()
    );
    assert_eq!(None, cps.get_initial_excluded_subtrees());
    let mut bufs2 = BTreeMap::new();
    assert_eq!(
        None,
        cps.get_initial_excluded_subtrees_as_set(&mut bufs2)
            .unwrap()
    );
    assert_eq!(
        NameConstraintsSet::default(),
        cps.get_initial_excluded_subtrees_with_default_as_set(&mut bufs2)
            .unwrap()
    );
    assert_eq!(
        NameConstraintsSettings::default(),
        cps.get_initial_excluded_subtrees_with_default()
    );
    assert_eq!(None, cps.get_extended_key_usage());
    assert_eq!(None, cps.get_target_key_usage());

    assert_eq!(None, cps.get_trust_anchor_folder());
    assert_eq!(None, cps.get_certification_authority_folder());
    assert_eq!(None, cps.get_download_folder());
    assert_eq!(None, cps.get_last_modified_map_file());
    assert_eq!(None, cps.get_uri_blocklist_file());
}

#[test]
fn test_default_sets_cps() {
    use const_oid::db::rfc5912::ID_CE_POLICY_MAPPINGS;

    let mut cps = CertificationPathSettings::default();

    cps.set_initial_explicit_policy_indicator(true);
    assert!(cps.get_initial_explicit_policy_indicator());
    cps.set_initial_policy_mapping_inhibit_indicator(true);
    assert!(cps.get_initial_policy_mapping_inhibit_indicator());
    cps.set_initial_inhibit_any_policy_indicator(true);
    assert!(cps.get_initial_inhibit_any_policy_indicator());

    #[cfg(feature = "std")]
    {
        let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        cps.set_time_of_interest(before.as_secs());
        assert_eq!(cps.get_time_of_interest(), before.as_secs());
    }
    #[cfg(not(feature = "std"))]
    {
        cps.set_time_of_interest(1);
        assert_eq!(cps.get_time_of_interest(), 1);
    }

    cps.set_enforce_trust_anchor_constraints(true);
    assert!(cps.get_enforce_trust_anchor_constraints());
    cps.set_enforce_trust_anchor_validity(false);
    assert!(!cps.get_enforce_trust_anchor_validity());
    cps.set_extended_key_usage_path(true);
    assert!(cps.get_extended_key_usage_path());
    cps.set_crl_timeout(Duration::from_secs(120));
    assert_eq!(Duration::from_secs(120), cps.get_crl_timeout());
    cps.set_enforce_alg_and_key_size_constraints(true);
    assert!(cps.get_enforce_alg_and_key_size_constraints());

    cps.set_use_validator_filter_when_building(false);
    assert!(!cps.get_use_validator_filter_when_building());
    cps.set_check_revocation_status(false);
    assert!(!cps.get_check_revocation_status());
    cps.set_check_ocsp_from_aia(false);
    assert!(!cps.get_check_ocsp_from_aia());
    cps.set_retrieve_from_aia_sia_http(false);
    assert!(!cps.get_retrieve_from_aia_sia_http());

    cps.set_retrieve_from_aia_sia_ldap(true);
    assert!(cps.get_retrieve_from_aia_sia_ldap());

    cps.set_check_crls(false);
    assert!(!cps.get_check_crls());
    cps.set_check_crldp_http(false);
    assert!(!cps.get_check_crldp_http());

    cps.set_check_crldp_ldap(true);
    assert!(cps.get_check_crldp_ldap());

    cps.set_crl_grace_periods_as_last_resort(false);
    assert!(!cps.get_crl_grace_periods_as_last_resort());

    cps.set_ignore_expired(true);
    assert!(cps.get_ignore_expired());

    cps.set_ocsp_aia_nonce_setting(OcspNonceSetting::SendNonceRequireMatch);
    assert_eq!(
        OcspNonceSetting::SendNonceRequireMatch,
        cps.get_ocsp_aia_nonce_setting()
    );

    cps.set_require_country_code_indicator(true);
    assert!(cps.get_require_country_code_indicator());

    cps.set_initial_policy_set(vec![ID_CE_POLICY_MAPPINGS.to_string()]);
    assert_eq!(
        vec![ID_CE_POLICY_MAPPINGS.to_string()],
        cps.get_initial_policy_set()
    );

    cps.set_cbor_ta_store(true);
    assert!(cps.get_cbor_ta_store());
}

#[test]
fn test_no_default_sets_cps() {
    use der::asn1::Ia5String;
    use x509_cert::ext::pkix::constraints::name::GeneralSubtree;
    use x509_cert::ext::pkix::name::GeneralName;

    let mut cps = CertificationPathSettings::default();

    let v = vec!["US".to_string()];
    cps.set_perm_countries(v.clone());
    assert_eq!(&v, &cps.get_perm_countries().unwrap());
    cps.set_excl_countries(v.clone());
    assert_eq!(&v, &cps.get_excl_countries().unwrap());

    assert_eq!(None, cps.get_initial_permitted_subtrees());
    let mut bufs1 = BTreeMap::new();
    assert_eq!(
        None,
        cps.get_initial_permitted_subtrees_as_set(&mut bufs1)
            .unwrap()
    );
    assert_eq!(
        NameConstraintsSettings::default(),
        cps.get_initial_permitted_subtrees_with_default()
    );
    assert_eq!(
        NameConstraintsSet::default(),
        cps.get_initial_permitted_subtrees_with_default_as_set(&mut bufs1)
            .unwrap()
    );
    cps.set_initial_permitted_subtrees(crate::NameConstraintsSettings {
        directory_name: Some(vec!["CN=Joe,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["x@example.com".to_string()]),
        user_principal_name: Some(vec!["1234567890@mil".to_string()]),
        dns_name: Some(vec!["j.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://j.example.com".to_string()]),
        ip_address: None,
        not_supported: None,
    });
    let perm = cps.get_initial_permitted_subtrees().unwrap();
    assert_eq!(
        Some(vec!["https://j.example.com".to_string()]),
        perm.uniform_resource_identifier
    );
    assert_eq!(Some(vec!["j.example.com".to_string()]), perm.dns_name);
    assert_eq!(
        Some(vec!["1234567890@mil".to_string()]),
        perm.user_principal_name
    );
    assert_eq!(Some(vec!["x@example.com".to_string()]), perm.rfc822_name);
    assert_eq!(
        Some(vec!["CN=Joe,OU=Org Unit,O=Org,C=US".to_string()]),
        perm.directory_name
    );
    let perm_set = cps
        .get_initial_permitted_subtrees_as_set(&mut bufs1)
        .unwrap()
        .unwrap();
    let ia5 = Ia5String::new("x@example.com").unwrap();
    let gn = GeneralName::Rfc822Name(ia5);
    let gn = GeneralSubtree {
        base: gn,
        minimum: 0,
        maximum: None,
    };
    assert_eq!(vec![gn], perm_set.rfc822_name);
    assert_eq!(1, perm_set.uniform_resource_identifier.len());
    assert_eq!(1, perm_set.dns_name.len());
    assert_eq!(1, perm_set.user_principal_name.len());
    assert_eq!(1, perm_set.directory_name.len());

    assert_eq!(None, cps.get_initial_excluded_subtrees());
    let mut bufs2 = BTreeMap::new();
    assert_eq!(
        None,
        cps.get_initial_excluded_subtrees_as_set(&mut bufs2)
            .unwrap()
    );
    assert_eq!(
        NameConstraintsSet::default(),
        cps.get_initial_excluded_subtrees_with_default_as_set(&mut bufs2)
            .unwrap()
    );
    assert_eq!(
        NameConstraintsSettings::default(),
        cps.get_initial_excluded_subtrees_with_default()
    );
    cps.set_initial_excluded_subtrees(crate::NameConstraintsSettings {
        directory_name: Some(vec!["CN=Sue,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["y@example.com".to_string()]),
        user_principal_name: Some(vec!["0987654321@mil".to_string()]),
        dns_name: Some(vec!["s.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://s.example.com".to_string()]),
        ip_address: None,
        not_supported: None,
    });
    let excl = cps.get_initial_excluded_subtrees().unwrap();
    assert_eq!(
        Some(vec!["https://s.example.com".to_string()]),
        excl.uniform_resource_identifier
    );
    assert_eq!(Some(vec!["s.example.com".to_string()]), excl.dns_name);
    assert_eq!(
        Some(vec!["0987654321@mil".to_string()]),
        excl.user_principal_name
    );
    assert_eq!(Some(vec!["y@example.com".to_string()]), excl.rfc822_name);
    assert_eq!(
        Some(vec!["CN=Sue,OU=Org Unit,O=Org,C=US".to_string()]),
        excl.directory_name
    );
    let excl_set = cps
        .get_initial_excluded_subtrees_as_set(&mut bufs1)
        .unwrap()
        .unwrap();
    let ia5 = Ia5String::new("y@example.com").unwrap();
    let gn = GeneralName::Rfc822Name(ia5);
    let gn = GeneralSubtree {
        base: gn,
        minimum: 0,
        maximum: None,
    };
    assert_eq!(vec![gn], excl_set.rfc822_name);
    assert_eq!(1, excl_set.uniform_resource_identifier.len());
    assert_eq!(1, excl_set.dns_name.len());
    assert_eq!(1, excl_set.user_principal_name.len());
    assert_eq!(1, excl_set.directory_name.len());

    let v = vec!["1.2.3.4.5".to_string()];
    cps.set_extended_key_usage(v.clone());
    assert_eq!(&v, &cps.get_extended_key_usage().unwrap());
    let eku_set = cps.get_extended_key_usage_as_oid_set().unwrap();
    let eku_setb = cps.get_extended_key_usage_as_oid_set().unwrap();
    let mut cps_eku_set = CertificationPathSettings::default();
    cps_eku_set.set_extended_key_usage_from_oid_set(eku_set);
    let eku_set_copy = cps_eku_set.get_extended_key_usage_as_oid_set().unwrap();
    assert_eq!(eku_setb, eku_set_copy);

    assert_eq!(None, cps.get_target_key_usage());

    let f = "/some/folder".to_string();
    cps.set_trust_anchor_folder(f.clone());
    assert_eq!(&f, &cps.get_trust_anchor_folder().unwrap());

    cps.set_certification_authority_folder(f.clone());
    assert_eq!(&f, &cps.get_certification_authority_folder().unwrap());
    cps.set_download_folder(f.clone());
    assert_eq!(&f, &cps.get_download_folder().unwrap());

    let f = "/some/file.txt".to_string();
    cps.set_last_modified_map_file(f.clone());
    assert_eq!(&f, &cps.get_last_modified_map_file().unwrap());
    cps.set_uri_blocklist_file(f.clone());
    assert_eq!(&f, &cps.get_uri_blocklist_file().unwrap());
}
