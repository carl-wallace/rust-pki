//! Structures and functions related to configuring certification path processing operations

use crate::{pdv_certificate::*, pdv_utilities::*, Error, PkiEnvironment};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use pkiprocmacros::*;
use url::Url;
use x509::{
    pkix_oids::PKIX_CE_ANYPOLICY, Certificate, GeneralName, GeneralSubtree, GeneralSubtrees,
    KeyUsageValues, Name, ObjectIdentifier, SubjectAltName, Time,
};

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

/// `ObjectIdentifierSet` is a typedef for a vector of ObjectIdentifier values.
pub type ObjectIdentifierSet = BTreeSet<ObjectIdentifier>;

/// `Strings` is a typedef for a vector of String values.
pub type Strings = Vec<String>;

/// `CertificationPathSettings` is a typedef for a `BTreeMap` that maps arbitrary string values to a
/// variant map.
pub type CertificationPathSettings<'a> = BTreeMap<&'a str, CertificationPathProcessingTypes<'a>>;

/// `CertificateChain` is a typedef for a vector of `PDVCertificate`.
pub type CertificateChain<'a> = Vec<&'a PDVCertificate<'a>>;

/// `CertificationPathResults` is a typedef for a `BTreeMap` that maps arbitrary string values to a
/// variant map. At present, it is the same as CertificationPathSettings (and so macros to generate
/// getters and setters are reused).
pub type CertificationPathResults<'a> = BTreeMap<&'a str, CertificationPathProcessingTypes<'a>>;

/// Microsoft User Principal Name OID (see <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/ea9ef420-4cbf-44bc-b093-c4175139f90f>)
pub const MSFT_USER_PRINCIPAL_NAME: ObjectIdentifier =
    ObjectIdentifier::new("1.3.6.1.4.1.311.20.2.3");

/// The `NameConstraintsSet` structure is used to define inputs for path validation, i.e.,
/// initial-excluded-subtrees and initial-permitted-subtrees, as well as to track processing
/// permitted_subtrees and excluded_subtrees during path validation.
///
/// For each field except notSupported, an Option containing an empty vector indicates nothing has
/// been set (i.e., no excluded names and infinite permitted names) and an Option containing None
/// indicates an intersection operation resulted in NULL). Empty vectors are created by default, with
/// None used only to signify an operational result.
///
/// The notSupported field collects unsupported name constraints values observed during path validation.
///
/// [RFC 5280 Section 6.1]: <https://datatracker.ietf.org/doc/html/rfc5280#section-6.1>
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct NameConstraintsSet<'a> {
    /// user_principal_name governs use of UPN values in otherName instances in SANs
    pub user_principal_name: Vec<GeneralSubtree<'a>>, //t = 0 (only form of otherName supported is UPN)
    /// user_principal_name_null is initialized to false and set to true if an intersection operation yields empty set
    pub user_principal_name_null: bool,
    /// rfc822_name governs use of email addresses in SANs
    pub rfc822_name: Vec<GeneralSubtree<'a>>, //t = 2
    /// rfc822_name_null is initialized to false and set to true if an intersection operation yields empty set
    pub rfc822_name_null: bool,
    /// dns_name governs use of DNS names in SANs
    pub dns_name: Vec<GeneralSubtree<'a>>, //t = 3
    /// dns_name_null is initialized to false and set to true if an intersection operation yields empty set
    pub dns_name_null: bool,
    /// directory_name governs use of DNs in SANs and issuer and subject fields
    pub directory_name: Vec<GeneralSubtree<'a>>, //t = 5
    /// directory_name_null is initialized to false and set to true if an intersection operation yields empty set
    pub directory_name_null: bool,
    /// uniform_resource_identifier governs use of URIs in SANs
    pub uniform_resource_identifier: Vec<GeneralSubtree<'a>>, //t = 7
    /// uniform_resource_identifier_null is initialized to false and set to true if an intersection operation yields empty set
    pub uniform_resource_identifier_null: bool,
    /// not_supported can be used to pile up unsupported name values
    pub not_supported: Vec<GeneralSubtree<'a>>, //t = everything else
}

impl<'a, 'b, 'c> NameConstraintsSet<'a>
where
    'a: 'b,
    'a: 'c,
{
    //----------------------------------------------------------------------------
    // public
    //----------------------------------------------------------------------------
    /// `calculate_intersection` calculates the intersection of self and ext and saves the result in self.
    pub(crate) fn calculate_intersection(
        &'c mut self,
        pe: &PkiEnvironment<'_>,
        ext: &'a GeneralSubtrees<'a>,
    ) {
        self.calculate_intersection_upn(ext);
        self.calculate_intersection_rfc822(ext);
        self.calculate_intersection_dns_name(ext);
        self.calculate_intersection_dn(pe, ext);
        self.calculate_intersection_uri(ext);
    }

    /// `calculate_union calculates` the union of self and ext and saves the result in self.
    pub(crate) fn calculate_union(&'c mut self, ext: &'a GeneralSubtrees<'a>) {
        for subtree in ext {
            let gn = &subtree.base;

            // accumulate names in the appropriate buckets. only accumulate where bucket is not None
            // as None signifies a failure.
            match gn {
                GeneralName::OtherName(on) => {
                    if on.type_id != MSFT_USER_PRINCIPAL_NAME {
                        self.user_principal_name_null = true;
                    } else if !self.user_principal_name_null {
                        self.user_principal_name.push(subtree.clone());
                    }
                }
                GeneralName::Rfc822Name(_rfc822) => {
                    if !self.rfc822_name_null {
                        self.rfc822_name.push(subtree.clone());
                    }
                }
                GeneralName::DnsName(_dns) => {
                    if !self.dns_name_null {
                        self.dns_name.push(subtree.clone());
                    }
                }
                GeneralName::DirectoryName(_dn) => {
                    if !self.directory_name_null {
                        self.directory_name.push(subtree.clone());
                    }
                }
                GeneralName::UniformResourceIdentifier(_uri) => {
                    if !self.uniform_resource_identifier_null {
                        self.uniform_resource_identifier.push(subtree.clone());
                    }
                }
                // not supporting name constraints for x400Address, ediPartyName, iPAddress or registeredID
                _ => {
                    self.not_supported.push(subtree.clone());
                }
            }
        }
    }

    /// `are_any_empty` returns true if any of the supported name constraints buckets have been set to None,
    /// which signifies failure.
    pub fn are_any_empty(&self) -> bool {
        if self.user_principal_name_null
            || self.rfc822_name_null
            || self.dns_name_null
            || self.directory_name_null
            || self.uniform_resource_identifier_null
        {
            return true;
        }
        false
    }

    /// `subject_within_excluded_subtrees` returns true if subject is within at least one excluded subtree
    /// known to self.
    pub fn subject_within_permitted_subtrees(
        &'b self,
        pe: &PkiEnvironment<'_>,
        subject: &'a Name<'a>,
    ) -> bool {
        if subject.is_empty() {
            // NULL subjects get a free pass
            return true;
        }

        if self.directory_name_null {
            return false;
        }

        if self.directory_name.is_empty() {
            return true;
        }

        for gn_state in &self.directory_name {
            if let GeneralName::DirectoryName(dn_state) = &gn_state.base {
                if descended_from_dn(pe, dn_state, subject, gn_state.minimum, gn_state.maximum) {
                    return true;
                }
            }
        }
        false
    }

    /// `san_within_permitted_subtrees` returns true if san is within at least one permitted subtree
    /// known to self.
    pub fn san_within_permitted_subtrees(
        &'b self,
        pe: &PkiEnvironment<'_>,
        san: &'a Option<&SubjectAltName<'a>>,
    ) -> bool {
        if san.is_none() {
            return true;
        }

        for gn_san in san {
            for subtree_san in gn_san.iter() {
                match subtree_san {
                    GeneralName::DirectoryName(dn_san) => {
                        if self.directory_name_null {
                            return false;
                        }

                        if self.directory_name.is_empty() {
                            return true;
                        }

                        for gn_state in &self.directory_name {
                            if let GeneralName::DirectoryName(dn_state) = &gn_state.base {
                                if descended_from_dn(
                                    pe,
                                    dn_state,
                                    dn_san,
                                    gn_state.minimum,
                                    gn_state.maximum,
                                ) {
                                    return true;
                                }
                            }
                        }
                        return false;
                    } // end GeneralName::DirectoryName
                    GeneralName::Rfc822Name(rfc822_san) => {
                        if self.rfc822_name_null {
                            return false;
                        }

                        if self.rfc822_name.is_empty() {
                            return true;
                        }

                        for gn_state in &self.rfc822_name {
                            if let GeneralName::Rfc822Name(rfc822_state) = gn_state.base {
                                if descended_from_rfc822(&rfc822_state, rfc822_san) {
                                    return true;
                                }
                            }
                        }
                        return false;
                    } // end GeneralName::Rfc822Name
                    GeneralName::DnsName(dns_san) => {
                        if self.dns_name_null {
                            return false;
                        }

                        if self.dns_name.is_empty() {
                            return true;
                        }

                        for gn_state in &self.dns_name {
                            if let GeneralName::DnsName(dns_state) = gn_state.base {
                                if descended_from_host(&dns_state, dns_san.as_str(), false) {
                                    return true;
                                }
                            }
                        }
                        return false;
                    } // end GeneralName::DnsName
                    GeneralName::UniformResourceIdentifier(uri_san) => {
                        if self.uniform_resource_identifier_null {
                            return false;
                        }

                        if self.uniform_resource_identifier.is_empty() {
                            return true;
                        }

                        for gn_state in &self.uniform_resource_identifier {
                            if let GeneralName::UniformResourceIdentifier(uri_state) = gn_state.base
                            {
                                if let Ok(url) = Url::parse(uri_san.as_str()) {
                                    if let Some(host) = url.host() {
                                        if descended_from_host(
                                            &uri_state,
                                            host.to_string().as_str(),
                                            true,
                                        ) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                        return false;
                    } // end GeneralName::UniformResourceIdentifier
                    _ => {}
                }
            }
        }
        // does not match a supported constraint so is unconstrained
        true
    }

    /// `subject_within_excluded_subtrees` returns true if subject is within at least one excluded subtree
    /// known to self.
    pub fn subject_within_excluded_subtrees(
        &'b self,
        pe: &PkiEnvironment<'_>,
        subject: &'a Name<'a>,
    ) -> bool {
        if subject.is_empty() {
            // NULL subjects get a free pass
            return false;
        }

        if self.directory_name_null {
            return false;
        }

        if self.directory_name.is_empty() {
            return false;
        }

        for gn_state in &self.directory_name {
            if let GeneralName::DirectoryName(dn_state) = &gn_state.base {
                if descended_from_dn(pe, dn_state, subject, gn_state.minimum, gn_state.maximum) {
                    return true;
                }
            }
        }
        false
    }

    /// `san_within_excluded_subtrees` returns true if san is within at least one excluded subtree
    /// known to self.
    pub fn san_within_excluded_subtrees(
        &'b self,
        pe: &PkiEnvironment<'_>,
        san: &'a Option<&SubjectAltName<'a>>,
    ) -> bool {
        if san.is_none() {
            return false;
        }

        for gn_san in san {
            for subtree_san in gn_san.iter() {
                match subtree_san {
                    GeneralName::DirectoryName(dn_san) => {
                        if self.directory_name_null {
                            return false;
                        }

                        if self.directory_name.is_empty() {
                            return false;
                        }

                        for gn_state in &self.directory_name {
                            if let GeneralName::DirectoryName(dn_state) = &gn_state.base {
                                if descended_from_dn(
                                    pe,
                                    dn_state,
                                    dn_san,
                                    gn_state.minimum,
                                    gn_state.maximum,
                                ) {
                                    return true;
                                }
                            }
                        }
                        return false;
                    }
                    GeneralName::Rfc822Name(rfc822_san) => {
                        if self.rfc822_name_null {
                            return false;
                        }

                        if self.rfc822_name.is_empty() {
                            return false;
                        }

                        for gn_state in &self.rfc822_name {
                            if let GeneralName::Rfc822Name(rfc822_state) = gn_state.base {
                                if descended_from_rfc822(&rfc822_state, rfc822_san) {
                                    return true;
                                }
                            }
                        }
                        return false;
                    }
                    GeneralName::DnsName(dns_san) => {
                        if self.dns_name_null {
                            return false;
                        }

                        if self.dns_name.is_empty() {
                            return false;
                        }

                        for gn_state in &self.dns_name {
                            if let GeneralName::DnsName(dns_state) = gn_state.base {
                                if descended_from_host(&dns_state, dns_san.as_str(), false) {
                                    return true;
                                }
                            }
                        }
                        return false;
                    }
                    GeneralName::UniformResourceIdentifier(uri_san) => {
                        if self.uniform_resource_identifier_null {
                            return false;
                        }

                        if self.uniform_resource_identifier.is_empty() {
                            return false;
                        }

                        for gn_state in &self.uniform_resource_identifier {
                            if let GeneralName::UniformResourceIdentifier(uri_state) = gn_state.base
                            {
                                if let Ok(url) = Url::parse(uri_san.as_str()) {
                                    if let Some(host) = url.host() {
                                        if descended_from_host(
                                            &uri_state,
                                            host.to_string().as_str(),
                                            true,
                                        ) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                        return false;
                    }
                    _ => {}
                }
            }
        }
        false
    }

    //----------------------------------------------------------------------------
    // private
    //----------------------------------------------------------------------------
    fn calculate_intersection_upn(&'c mut self, new_names: &'a GeneralSubtrees<'a>)
    where
        'a: 'b,
    {
        if self.user_principal_name_null || !has_upn(new_names) {
            // nothing to intersect (either state has become NULL or there are no names to add)
            return;
        }

        let new_set = Vec::new();

        //TODO support UPN name constraints

        // for new_name in &new_names.user_principal_name {
        //     for prev_name in &self.user_principal_name {
        //         if new_name == prev_name {
        //             new_set.push(prev_name.clone());
        //         }
        //         else if descended_from_rfc822(prev_name, new_name) {
        //             new_set.push(prev_name.clone());
        //         }
        //     }
        // }

        if !new_set.is_empty() {
            self.user_principal_name = new_set;
        } else {
            self.user_principal_name_null = true;
        }
    }

    fn calculate_intersection_rfc822(&'c mut self, new_names: &'a GeneralSubtrees<'a>)
    where
        'a: 'b,
    {
        if self.rfc822_name_null || !has_rfc822(new_names) {
            // nothing to intersect (either state has become NULL or there are no names to add)
            return;
        }

        let mut new_set = Vec::new();

        for new_name in new_names {
            if let GeneralName::Rfc822Name(new_rfc822) = &new_name.base {
                if self.rfc822_name.is_empty() {
                    new_set.push(new_name.clone());
                } else {
                    for prev_name in &self.rfc822_name {
                        if let GeneralName::Rfc822Name(prev_rfc822) = &prev_name.base {
                            if new_name == prev_name
                                || descended_from_rfc822(prev_rfc822, new_rfc822)
                            {
                                new_set.push(prev_name.clone());
                            }
                        }
                    }
                }
            }
        }

        if !new_set.is_empty() {
            self.rfc822_name = new_set;
        } else {
            self.rfc822_name_null = true;
        }
    }

    fn calculate_intersection_dns_name(&'c mut self, new_names: &'a GeneralSubtrees<'a>)
    where
        'a: 'b,
    {
        if self.dns_name_null || !has_dns_name(new_names) {
            // nothing to intersect (either state has become NULL or there are no names to add)
            return;
        }

        let mut new_set = Vec::new();

        for new_name in new_names {
            if let GeneralName::DnsName(new_dns) = &new_name.base {
                if self.dns_name.is_empty() {
                    new_set.push(new_name.clone());
                } else {
                    for prev_name in &self.dns_name {
                        if let GeneralName::DnsName(prev_dns) = &prev_name.base {
                            if new_name == prev_name
                                || descended_from_host(prev_dns, new_dns.as_str(), false)
                            {
                                new_set.push(prev_name.clone());
                            }
                        }
                    }
                }
            }
        }

        if !new_set.is_empty() {
            self.dns_name = new_set;
        } else {
            self.dns_name_null = true;
        }
    }

    fn calculate_intersection_dn(
        &'c mut self,
        pe: &PkiEnvironment<'_>,
        new_names: &'a GeneralSubtrees<'a>,
    ) where
        'a: 'b,
    {
        if self.directory_name_null || !has_dn(new_names) {
            // nothing to intersect (either state has become NULL or there are no names to add)
            return;
        }

        let mut new_set = Vec::new();

        for new_name in new_names {
            if let GeneralName::DirectoryName(new_dn) = &new_name.base {
                if self.directory_name.is_empty() {
                    new_set.push(new_name.clone());
                } else {
                    for prev_name in &self.directory_name {
                        if let GeneralName::DirectoryName(prev_dn) = &prev_name.base {
                            if new_name == prev_name {
                                new_set.push(prev_name.clone());
                            } else if descended_from_dn(
                                pe,
                                prev_dn,
                                new_dn,
                                prev_name.minimum,
                                prev_name.maximum,
                            ) {
                                new_set.push(new_name.clone());
                            }
                        }
                    }
                }
            }
        }

        if !new_set.is_empty() {
            self.directory_name = new_set;
        } else {
            self.directory_name_null = true;
        }
    }

    fn calculate_intersection_uri(&'c mut self, new_names: &'a GeneralSubtrees<'a>)
    where
        'a: 'b,
    {
        if self.uniform_resource_identifier_null || !has_uri(new_names) {
            // nothing to intersect (either state has become NULL or there are no names to add)
            return;
        }

        let mut new_set = Vec::new();

        for new_name in new_names {
            if let GeneralName::UniformResourceIdentifier(new_uri) = &new_name.base {
                if self.uniform_resource_identifier.is_empty() {
                    new_set.push(new_name.clone());
                } else {
                    for prev_name in &self.dns_name {
                        if let GeneralName::UniformResourceIdentifier(prev_uri) = &prev_name.base {
                            if new_name == prev_name
                                || descended_from_host(prev_uri, new_uri.as_str(), true)
                            {
                                new_set.push(prev_name.clone());
                            }
                        }
                    }
                }
            }
        }

        if !new_set.is_empty() {
            self.uniform_resource_identifier = new_set;
        } else {
            self.uniform_resource_identifier_null = true;
        }
    }

    // TODO support IP address name constraints
}

/*
//TODO possibly restore when OCSP support is added
/// `OcspNonceSetting` controls how OCSP responses are processed with respect to nonce values.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
 */

/// `CertificationPathProcessingTypes` is used to define a variant map with types associated with
/// performing certification path discovery and validation.
#[derive(Clone)]
pub enum CertificationPathProcessingTypes<'a> {
    /// Represents bool values
    Bool(bool),
    /// Represents i8 values
    I8(i8),
    /// Represents u8 values
    U8(u8),
    /// Represents i32 values
    I32(i32),
    /// Represents u32 values
    U32(u32),
    /// Represents i64 values
    I64(i64),
    /// Represents u64 values
    U64(u64),
    /// Represents Time values
    Time(Time),
    /// Represents ObjectIdentifier values
    ObjectIdentifier(ObjectIdentifier),
    /// Represents ObjectIdentifierSet values
    ObjectIdentifierSet(ObjectIdentifierSet),
    /// Represents NameConstraintsSet values
    NameConstraintsSet(NameConstraintsSet<'a>),
    /// Represents vectors of Certificate values
    Certificates(Vec<Certificate<'a>>),
    /// Represents String values
    String(String),
    /// Represents vectors of u8 values
    Buffer(Vec<u8>),
    /// Represents vectors of i32 values
    VecI32(Vec<i32>),
    /// Represents vectors of u32 values
    VecU32(Vec<u32>),
    /// Represents vectors of Strings
    Strings(Strings),
    /// Represents vectors of buffers
    Buffers(Vec<Vec<u8>>),
    /// Represents KeyUsageValues values
    KeyUsageValue(KeyUsageValues),
    /// Represents FinalValidPolicyTree value
    FinalValidPolicyTree(FinalValidPolicyTree),
    /// Represents valiation result
    Error(Error),
}

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
/// a set containing PKIX_CE_ANYPOLICY is used.
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

/// `PS_KEY_USAGE` is used to retrieve a Vec<u8> value from a [`CertificationPathSettings`] object.
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

/// `PR_PROCESS_EXTENSIONS` is used to retrieve an ObjectIdentifierSet value, i.e., BTreeSet of ObjectIdentifier,
/// from a [`CertificationPathResults`] object. This list is populated as extensions are processed then used
/// to check for unprocessed critical extensions.
pub static PR_PROCESSED_EXTENSIONS: &str = "cprProcessedExtensions";

/// `PR_FINAL_VALID_POLICY_TREE` is used to retrieve a FinalValidPolicyTree value from a [`CertificationPathResults`]
/// object.
pub static PR_FINAL_VALID_POLICY_TREE: &str = "cprValidPolicyTree";

/// `PR_VALIDATION_STATUS` is used to retrieve a status code indicating validation result.
pub static PR_VALIDATION_STATUS: &str = "cprValidationStatus";

/// `CertificationPath` is used to represent the trust anchor, intermediate CA certificates and target certificate
/// that comprise a certification path.
pub struct CertificationPath<'a> {
    /// `target` contains the target certificate for the certification path
    pub target: &'a PDVCertificate<'a>,
    /// `intermediates` contains zero or more intermediate CA certificates, beginning with the certificate that
    /// was issued by `trust_anchor` and proceeding in order to a certificate that issued the target, i.e.,
    /// `intermediates\[0\]` can be used to verify `intermediates\[1\]`, `intermediates\[1\]` can be used to verify
    /// `intermediates\[2\]`, etc. until `intermediates[intermediates.len() - 1]` can be used to verify `target`.
    pub intermediates: CertificateChain<'a>,
    /// `trust_anchor` contains the trust anchor for the certification path
    pub trust_anchor: &'a PDVTrustAnchorChoice<'a>,
}

/// The `ValidPolicyTreeNode` is used to represent nodes returned via a `PR_VALID_POLICY_TREE` entry in a
/// [`CertificationPathResults`] instance. Each node in the valid_policy_tree includes three data
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

//-----------------------------------------------------------------------------------------------
// Getters/setters for dealing with the variant settings and results maps
//-----------------------------------------------------------------------------------------------
cps_gets_and_sets_with_default!(PR_PROCESSED_EXTENSIONS, ObjectIdentifierSet, {
    BTreeSet::new()
});
cps_gets_and_sets!(PR_FINAL_VALID_POLICY_TREE, FinalValidPolicyTree);
cps_gets_and_sets!(PR_VALIDATION_STATUS, Error);

cps_gets_and_sets_with_default!(PS_INITIAL_EXPLICIT_POLICY_INDICATOR, bool, false);
cps_gets_and_sets_with_default!(PS_INITIAL_POLICY_MAPPING_INHIBIT_INDICATOR, bool, false);
cps_gets_and_sets_with_default!(PS_INITIAL_INHIBIT_ANY_POLICY_INDICATOR, bool, false);
cps_gets_and_sets_with_default!(PS_INITIAL_POLICY_SET, ObjectIdentifierSet, {
    let mut bts = BTreeSet::new();
    bts.insert(PKIX_CE_ANYPOLICY);
    bts
});
// PS_INITIAL_EXCLUDED_SUBTREES (will need lifetime aware macro)

/// `get_initial_permitted_subtrees` retrieves the `PS_INITIAL_PERMITTED_SUBTREES` value from a
/// [`CertificationPathSettings`] map. If present, a [`NameConstraintsSet`] value is returned, else None is returned.
pub fn get_initial_permitted_subtrees<'a>(
    cps: &'a CertificationPathSettings<'a>,
) -> Option<NameConstraintsSet<'a>> {
    if cps.contains_key(PS_INITIAL_PERMITTED_SUBTREES) {
        return match &cps[PS_INITIAL_PERMITTED_SUBTREES] {
            CertificationPathProcessingTypes::NameConstraintsSet(ncs) => Some(ncs.clone()),
            _ => None,
        };
    }
    None
}

/// `get_initial_permitted_subtrees` retrieves the `PS_INITIAL_PERMITTED_SUBTREES` value from a
/// [`CertificationPathSettings`] map. If present, a [`NameConstraintsSet`] value is returned, else NameConstraintsSet::default() is returned.
pub fn get_initial_permitted_subtrees_with_default<'a>(
    cps: &'a CertificationPathSettings<'a>,
) -> NameConstraintsSet<'a> {
    if cps.contains_key(PS_INITIAL_PERMITTED_SUBTREES) {
        return match &cps[PS_INITIAL_PERMITTED_SUBTREES] {
            CertificationPathProcessingTypes::NameConstraintsSet(ncs) => ncs.clone(),
            _ => NameConstraintsSet::default(),
        };
    }
    NameConstraintsSet::default()
}

/// `set_initial_permitted_subtrees` is used to set the `PS_INITIAL_PERMITTED_SUBTREES` value in
/// a [`CertificationPathSettings`] map.
pub fn set_initial_permitted_subtrees<'a>(
    cps: &mut CertificationPathSettings<'a>,
    ncs: NameConstraintsSet<'a>,
) {
    cps.insert(
        PS_INITIAL_PERMITTED_SUBTREES,
        CertificationPathProcessingTypes::NameConstraintsSet(ncs),
    );
}

/// `get_initial_excluded_subtrees` retrieves the `PS_INITIAL_EXCLUDED_SUBTREES` value from a
/// [`CertificationPathSettings`] map. If present, a [`NameConstraintsSet`] value is returned, else None is returned.
pub fn get_initial_excluded_subtrees<'a>(
    cps: &'a CertificationPathSettings<'a>,
) -> Option<NameConstraintsSet<'a>> {
    if cps.contains_key(PS_INITIAL_EXCLUDED_SUBTREES) {
        return match &cps[PS_INITIAL_EXCLUDED_SUBTREES] {
            CertificationPathProcessingTypes::NameConstraintsSet(ncs) => Some(ncs.clone()),
            _ => None,
        };
    }
    None
}

/// `get_initial_excluded_subtrees` retrieves the `PS_INITIAL_EXCLUDED_SUBTREES` value from a
/// [`CertificationPathSettings`] map. If present, a [`NameConstraintsSet`] value is returned, else NameConstraintsSet::default() is returned.
pub fn get_initial_excluded_subtrees_with_default<'a>(
    cps: &'a CertificationPathSettings<'a>,
) -> NameConstraintsSet<'a> {
    if cps.contains_key(PS_INITIAL_EXCLUDED_SUBTREES) {
        return match &cps[PS_INITIAL_EXCLUDED_SUBTREES] {
            CertificationPathProcessingTypes::NameConstraintsSet(ncs) => ncs.clone(),
            _ => NameConstraintsSet::default(),
        };
    }
    NameConstraintsSet::default()
}

/// `set_initial_excluded_subtrees` is used to set the `PS_INITIAL_EXCLUDED_SUBTREES` value in
/// a [`CertificationPathSettings`] map.
pub fn set_initial_excluded_subtrees<'a>(
    cps: &mut CertificationPathSettings<'a>,
    ncs: NameConstraintsSet<'a>,
) {
    cps.insert(
        PS_INITIAL_EXCLUDED_SUBTREES,
        CertificationPathProcessingTypes::NameConstraintsSet(ncs),
    );
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
// PS_KEY_USAGE (see below, need lifetime aware macro to avoid manual implementation)
cps_gets_and_sets!(PS_EXTENDED_KEY_USAGE, ObjectIdentifierSet);
cps_gets_and_sets_with_default!(PS_EXTENDED_KEY_USAGE_PATH, bool, false);
cps_gets_and_sets_with_default!(
    PS_INITIAL_PATH_LENGTH_CONSTRAINT,
    u8,
    PS_MAX_PATH_LENGTH_CONSTRAINT
);
cps_gets_and_sets_with_default!(PS_ENFORCE_ALG_AND_KEY_SIZE_CONSTRAINTS, bool, false);
cps_gets_and_sets_with_default!(PS_USE_VALIDATOR_FILTER_WHEN_BUILDING, bool, true);
cps_gets_and_sets_with_default!(PS_CHECK_REVOCATION_STATUS, bool, true);
cps_gets_and_sets_with_default!(PS_CHECK_OCSP_FROM_AIA, bool, true);
cps_gets_and_sets_with_default!(PS_RETRIEVE_FROM_AIA_SIA_HTTP, bool, true);
cps_gets_and_sets_with_default!(PS_RETRIEVE_FROM_AIA_SIA_LDAP, bool, false);
cps_gets_and_sets_with_default!(PS_CHECK_CRLS, bool, true);
cps_gets_and_sets_with_default!(PS_CHECK_CRLDP_HTTP, bool, false);
cps_gets_and_sets_with_default!(PS_CHECK_CRLDP_LDAP, bool, false);
cps_gets_and_sets_with_default!(PS_CRL_GRACE_PERIODS_AS_LAST_RESORT, bool, true);
cps_gets_and_sets_with_default!(PS_IGNORE_EXPIRED, bool, false);
// PS_OCSP_AIA_NONCE_SETTING (will need i8 to enum conversion, probably)
// PS_MAXIMUM_PATH_DEPTH (ditch this and use PS_INITIAL_PATH_LENGTH_CONSTRAINT)
// PS_CERTIFICATES (will need lifetime aware macro)
cps_gets_and_sets_with_default!(PS_REQUIRE_COUNTRY_CODE_INDICATOR, bool, false);
cps_gets_and_sets!(PS_PERM_COUNTRIES, Strings);
cps_gets_and_sets!(PS_EXCL_COUNTRIES, Strings);

/// `get_target_key_usage` retrieves the `PS_KEY_USAGE` value from a
/// [`CertificationPathSettings`] map. If present, a u8 value is returned, else None is returned.
pub fn get_target_key_usage<'a>(cps: &'a CertificationPathSettings<'a>) -> Option<&'a Vec<u8>> {
    if cps.contains_key(PS_KEY_USAGE) {
        return match &cps[PS_KEY_USAGE] {
            CertificationPathProcessingTypes::Buffer(v) => Some(v),
            _ => None,
        };
    }
    None
}

/// `set_target_key_usage` is used to set the [`PS_KEY_USAGE`] value in a [`CertificationPathSettings`] map.
pub fn set_target_key_usage(cps: &mut CertificationPathSettings<'_>, v: Vec<u8>) {
    cps.insert(PS_KEY_USAGE, CertificationPathProcessingTypes::Buffer(v));
}
