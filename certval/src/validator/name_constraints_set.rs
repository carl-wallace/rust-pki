//! Structures and functions related to processing name constraints

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use url::Url;

use der::asn1::{PrintableString, Utf8StringRef};
use der::{
    asn1::{Any, Ia5String, ObjectIdentifier},
    Decode, Encode, Tag, Tagged,
};
use subtle_encoding::hex;
use x509_cert::ext::pkix::{
    constraints::name::{GeneralSubtree, GeneralSubtrees},
    name::{GeneralName, OtherName},
    SubjectAltName,
};
use x509_cert::name::Name;

use crate::{util::pdv_utilities::*, Error, Result, buffer_to_hex};

/// Microsoft User Principal Name OID (see <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/ea9ef420-4cbf-44bc-b093-c4175139f90f>)
pub const MSFT_USER_PRINCIPAL_NAME: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.20.2.3");

/// OID for uid attribute from RFC4519: 0.9.2342.19200300.100.1.1
pub const UID: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.9.2342.19200300.100.1.1");

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
pub struct NameConstraintsSet {
    /// user_principal_name governs use of UPN values in otherName instances in SANs
    pub user_principal_name: Vec<GeneralSubtree>, //t = 0 (only form of otherName supported is UPN)
    /// user_principal_name_null is initialized to false and set to true if an intersection operation yields empty set
    pub user_principal_name_null: bool,
    /// rfc822_name governs use of email addresses in SANs
    pub rfc822_name: Vec<GeneralSubtree>, //t = 2
    /// rfc822_name_null is initialized to false and set to true if an intersection operation yields empty set
    pub rfc822_name_null: bool,
    /// dns_name governs use of DNS names in SANs
    pub dns_name: Vec<GeneralSubtree>, //t = 3
    /// dns_name_null is initialized to false and set to true if an intersection operation yields empty set
    pub dns_name_null: bool,
    /// directory_name governs use of DNs in SANs and issuer and subject fields
    pub directory_name: Vec<GeneralSubtree>, //t = 5
    /// directory_name_null is initialized to false and set to true if an intersection operation yields empty set
    pub directory_name_null: bool,
    /// uniform_resource_identifier governs use of URIs in SANs
    pub uniform_resource_identifier: Vec<GeneralSubtree>, //t = 7
    /// uniform_resource_identifier_null is initialized to false and set to true if an intersection operation yields empty set
    pub uniform_resource_identifier_null: bool,
    /// not_supported can be used to pile up unsupported name values
    pub not_supported: Vec<GeneralSubtree>, //t = everything else
}

impl NameConstraintsSet {
    //----------------------------------------------------------------------------
    // public
    //----------------------------------------------------------------------------
    /// `calculate_intersection` calculates the intersection of self and ext and saves the result in self.
    pub(crate) fn calculate_intersection(&mut self, ext: &GeneralSubtrees) {
        self.calculate_intersection_dn(ext);

        self.calculate_intersection_rfc822(ext);
        self.calculate_intersection_dns_name(ext);
        self.calculate_intersection_uri(ext);
    }

    /// `calculate_union calculates` the union of self and ext and saves the result in self.
    pub(crate) fn calculate_union(&mut self, ext: &GeneralSubtrees) {
        for subtree in ext {
            let gn = &subtree.base;

            // accumulate names in the appropriate buckets. only accumulate where bucket is not None
            // as None signifies a failure.
            match gn {
                GeneralName::Rfc822Name(_rfc822) => {
                    #[cfg(feature = "std")]
                    if !self.rfc822_name_null {
                        self.rfc822_name.push(subtree.clone());
                    }
                    #[cfg(not(feature = "std"))]
                    {
                        self.rfc822_name_null = true;
                    }
                }
                GeneralName::DnsName(_dns) => {
                    #[cfg(feature = "std")]
                    if !self.dns_name_null {
                        self.dns_name.push(subtree.clone());
                    }
                    #[cfg(not(feature = "std"))]
                    {
                        self.dns_name_null = true;
                    }
                }
                GeneralName::DirectoryName(_dn) => {
                    if !self.directory_name_null {
                        self.directory_name.push(subtree.clone());
                    }
                }
                GeneralName::UniformResourceIdentifier(_uri) => {
                    #[cfg(feature = "std")]
                    if !self.uniform_resource_identifier_null {
                        self.uniform_resource_identifier.push(subtree.clone());
                    }
                    #[cfg(not(feature = "std"))]
                    {
                        self.uniform_resource_identifier_null = true;
                    }
                }
                // not supporting name constraints for otherName, x400Address, ediPartyName, iPAddress or registeredID
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
    pub fn subject_within_permitted_subtrees(&self, subject: &Name) -> bool {
        if subject.0.is_empty() {
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
                if descended_from_dn(dn_state, subject, gn_state.minimum, gn_state.maximum) {
                    return true;
                }
            }
        }
        false
    }

    /// `san_within_permitted_subtrees` returns true if san is within at least one permitted subtree
    /// known to self. RFC822, DNS and URI name constraints are not supported for no-std and will fail.
    pub fn san_within_permitted_subtrees(&self, san: &Option<&SubjectAltName>) -> bool {
        if san.is_none() {
            return true;
        }

        for gn_san in san {
            for subtree_san in gn_san.0.iter() {
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

                    #[allow(unused_variables)]
                    GeneralName::Rfc822Name(rfc822_san) => {
                        if self.rfc822_name_null {
                            return false;
                        }

                        if self.rfc822_name.is_empty() {
                            return true;
                        }

                        #[cfg(feature = "std")]
                        for gn_state in &self.rfc822_name {
                            if let GeneralName::Rfc822Name(rfc822_state) = &gn_state.base {
                                if descended_from_rfc822(rfc822_state, rfc822_san) {
                                    return true;
                                }
                            }
                        }
                        return false;
                    } // end GeneralName::Rfc822Name

                    #[allow(unused_variables)]
                    GeneralName::DnsName(dns_san) => {
                        if self.dns_name_null {
                            return false;
                        }

                        if self.dns_name.is_empty() {
                            return true;
                        }

                        #[cfg(feature = "std")]
                        for gn_state in &self.dns_name {
                            if let GeneralName::DnsName(dns_state) = &gn_state.base {
                                if descended_from_host(dns_state, dns_san.as_str(), false) {
                                    return true;
                                }
                            }
                        }
                        return false;
                    } // end GeneralName::DnsName

                    #[allow(unused_variables)]
                    GeneralName::UniformResourceIdentifier(uri_san) => {
                        if self.uniform_resource_identifier_null {
                            return false;
                        }

                        if self.uniform_resource_identifier.is_empty() {
                            return true;
                        }

                        #[cfg(feature = "std")]
                        for gn_state in &self.uniform_resource_identifier {
                            if let GeneralName::UniformResourceIdentifier(uri_state) =
                                &gn_state.base
                            {
                                if let Ok(url) = Url::parse(uri_san.as_str()) {
                                    if let Some(host) = url.host() {
                                        if descended_from_host(
                                            uri_state,
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
                    GeneralName::IpAddress(_) => {
                        for ns in &self.not_supported {
                            if let GeneralName::IpAddress(_) = ns.base {
                                return false;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        // does not match a supported constraint so is unconstrained
        true
    }

    /// `subject_within_excluded_subtrees` returns true if subject is within at least one excluded subtree
    /// known to self.
    pub fn subject_within_excluded_subtrees(&self, subject: &Name) -> bool {
        if subject.0.is_empty() {
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
                if descended_from_dn(dn_state, subject, gn_state.minimum, gn_state.maximum) {
                    return true;
                }
            }
        }
        false
    }

    /// `san_within_excluded_subtrees` returns true if san is within at least one excluded subtree
    /// known to self.
    pub fn san_within_excluded_subtrees(&self, san: &Option<&SubjectAltName>) -> bool {
        if san.is_none() {
            return false;
        }

        for gn_san in san {
            for subtree_san in gn_san.0.iter() {
                match subtree_san {
                    GeneralName::DirectoryName(dn_san) => {
                        if self.directory_name_null {
                            return true;
                        }

                        if self.directory_name.is_empty() {
                            return false;
                        }

                        for gn_state in &self.directory_name {
                            if let GeneralName::DirectoryName(dn_state) = &gn_state.base {
                                if descended_from_dn(
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
                    #[allow(unused_variables)]
                    GeneralName::Rfc822Name(rfc822_san) => {
                        if self.rfc822_name_null {
                            return true;
                        }

                        if self.rfc822_name.is_empty() {
                            return false;
                        }

                        #[cfg(feature = "std")]
                        for gn_state in &self.rfc822_name {
                            if let GeneralName::Rfc822Name(rfc822_state) = &gn_state.base {
                                if descended_from_rfc822(rfc822_state, rfc822_san) {
                                    return true;
                                }
                            }
                        }
                        return false;
                    }
                    #[allow(unused_variables)]
                    GeneralName::DnsName(dns_san) => {
                        if self.dns_name_null {
                            return true;
                        }

                        if self.dns_name.is_empty() {
                            return false;
                        }

                        #[cfg(feature = "std")]
                        for gn_state in &self.dns_name {
                            if let GeneralName::DnsName(dns_state) = &gn_state.base {
                                if descended_from_host(dns_state, dns_san.as_str(), false) {
                                    return true;
                                }
                            }
                        }
                        return false;
                    }

                    #[allow(unused_variables)]
                    GeneralName::UniformResourceIdentifier(uri_san) => {
                        if self.uniform_resource_identifier_null {
                            return true;
                        }

                        if self.uniform_resource_identifier.is_empty() {
                            return false;
                        }

                        #[cfg(feature = "std")]
                        for gn_state in &self.uniform_resource_identifier {
                            if let GeneralName::UniformResourceIdentifier(uri_state) =
                                &gn_state.base
                            {
                                if let Ok(url) = Url::parse(uri_san.as_str()) {
                                    if let Some(host) = url.host() {
                                        if descended_from_host(
                                            uri_state,
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
                    GeneralName::IpAddress(_) => {
                        for ns in &self.not_supported {
                            if let GeneralName::IpAddress(_) = ns.base {
                                return true;
                            }
                        }
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
    fn calculate_intersection_rfc822(&mut self, new_names: &GeneralSubtrees) {
        if self.rfc822_name_null || !has_rfc822(new_names) {
            // nothing to intersect (either state has become NULL or there are no names to add)
            return;
        }

        #[cfg(not(feature = "std"))]
        {
            self.rfc822_name_null = true;
        }

        #[cfg(feature = "std")]
        {
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
    }

    fn calculate_intersection_dns_name(&mut self, new_names: &GeneralSubtrees) {
        if self.dns_name_null || !has_dns_name(new_names) {
            // nothing to intersect (either state has become NULL or there are no names to add)
            return;
        }

        #[cfg(not(feature = "std"))]
        {
            self.dns_name_null = true;
        }

        #[cfg(feature = "std")]
        {
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
    }

    fn calculate_intersection_dn(&mut self, new_names: &GeneralSubtrees) {
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

    fn calculate_intersection_uri(&mut self, new_names: &GeneralSubtrees) {
        if self.uniform_resource_identifier_null || !has_uri(new_names) {
            // nothing to intersect (either state has become NULL or there are no names to add)
            return;
        }

        #[cfg(not(feature = "std"))]
        {
            self.uniform_resource_identifier_null = true;
        }

        #[cfg(feature = "std")]
        {
            let mut new_set = Vec::new();

            for new_name in new_names {
                if let GeneralName::UniformResourceIdentifier(new_uri) = &new_name.base {
                    if self.uniform_resource_identifier.is_empty() {
                        new_set.push(new_name.clone());
                    } else {
                        for prev_name in &self.uniform_resource_identifier {
                            if let GeneralName::UniformResourceIdentifier(prev_uri) =
                                &prev_name.base
                            {
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
    }

    // TODO support IP address and UPN name constraints
}

/// NameConstraintsSettings is a serializable equivalent of NameConstraintsSet. The getters and setters
/// for CertificationPathSettings handle translating from one to the other.
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct NameConstraintsSettings {
    /// user_principal_name governs use of UPN values in otherName instances in SANs
    pub user_principal_name: Option<Vec<String>>, //t = 0 (only form of otherName supported is UPN)
    /// rfc822_name governs use of email addresses in SANs
    pub rfc822_name: Option<Vec<String>>, //t = 2
    /// dns_name governs use of DNS names in SANs
    pub dns_name: Option<Vec<String>>, //t = 3
    /// directory_name governs use of DNs in SANs and issuer and subject fields
    pub directory_name: Option<Vec<String>>, //t = 5
    /// uniform_resource_identifier governs use of URIs in SANs
    pub uniform_resource_identifier: Option<Vec<String>>, //t = 7
    pub not_supported: Option<Vec<String>> //ASCII hex encodings of unsupported name forms
}

pub(crate) fn name_constraints_settings_to_name_constraints_set(
    settings: &NameConstraintsSettings,
    bufs: &mut BTreeMap<String, Vec<Vec<u8>>>,
) -> Result<NameConstraintsSet> {
    let mut rfcbufs: Vec<Vec<u8>> = vec![];
    if let Some(rfc822_name) = &settings.rfc822_name {
        for n in rfc822_name {
            match Any::new(Tag::Ia5String, n.as_bytes()) {
                Ok(a) => match Ia5String::try_from(&a) {
                    Ok(ia5) => {
                        let gn = GeneralName::Rfc822Name(ia5);
                        let gs = GeneralSubtree {
                            base: gn,
                            maximum: None,
                            minimum: 0,
                        };
                        match gs.to_der() {
                            Ok(b) => {
                                rfcbufs.push(b);
                            }
                            Err(e) => return Err(Error::Asn1Error(e)),
                        }
                    }
                    Err(e) => return Err(Error::Asn1Error(e)),
                },
                Err(e) => return Err(Error::Asn1Error(e)),
            }
        }
    }
    bufs.insert("rfc822".to_string(), rfcbufs);

    let mut dnsbufs: Vec<Vec<u8>> = vec![];
    if let Some(dns_name) = &settings.dns_name {
        for n in dns_name {
            match Any::new(Tag::Ia5String, n.as_bytes()) {
                Ok(a) => match Ia5String::try_from(&a) {
                    Ok(ia5) => {
                        let gn = GeneralName::DnsName(ia5);
                        let gs = GeneralSubtree {
                            base: gn,
                            maximum: None,
                            minimum: 0,
                        };
                        match gs.to_der() {
                            Ok(b) => {
                                dnsbufs.push(b);
                            }
                            Err(e) => return Err(Error::Asn1Error(e)),
                        }
                    }
                    Err(e) => return Err(Error::Asn1Error(e)),
                },
                Err(e) => return Err(Error::Asn1Error(e)),
            }
        }
    }
    bufs.insert("dns".to_string(), dnsbufs);

    let mut dnbufs: Vec<Vec<u8>> = vec![];
    if let Some(directory_name) = &settings.directory_name {
        for n in directory_name {
            let en = encode_dn_from_string(n.as_str())?;
            match Name::from_der(en.as_slice()) {
                Ok(n) => {
                    let gn = GeneralName::DirectoryName(n);
                    let gs = GeneralSubtree {
                        base: gn,
                        maximum: None,
                        minimum: 0,
                    };
                    match gs.to_der() {
                        Ok(b) => {
                            dnbufs.push(b);
                        }
                        Err(e) => return Err(Error::Asn1Error(e)),
                    }
                }
                Err(e) => return Err(Error::Asn1Error(e)),
            }
        }
    }
    bufs.insert("dn".to_string(), dnbufs);

    let mut uribufs: Vec<Vec<u8>> = vec![];
    if let Some(uniform_resource_identifier) = &settings.uniform_resource_identifier {
        for n in uniform_resource_identifier {
            match Any::new(Tag::Ia5String, n.as_bytes()) {
                Ok(a) => match Ia5String::try_from(&a) {
                    Ok(ia5) => {
                        let gn = GeneralName::UniformResourceIdentifier(ia5);
                        let gs = GeneralSubtree {
                            base: gn,
                            maximum: None,
                            minimum: 0,
                        };
                        match gs.to_der() {
                            Ok(b) => {
                                uribufs.push(b);
                            }
                            Err(e) => return Err(Error::Asn1Error(e)),
                        }
                    }
                    Err(e) => return Err(Error::Asn1Error(e)),
                },
                Err(e) => return Err(Error::Asn1Error(e)),
            }
        }
    }
    bufs.insert("uri".to_string(), uribufs);

    let mut nsbufs: Vec<Vec<u8>> = vec![];
    if let Some(not_supported) = &settings.not_supported {
       for n in not_supported {
           if let Ok(buf) = hex::decode_upper(&n) {
               nsbufs.push(buf);
           }
       }
    }
    bufs.insert("not_supported".to_string(), nsbufs);

    let mut upnbufs: Vec<Vec<u8>> = vec![];
    if let Some(user_principal_name) = &settings.user_principal_name {
        for n in user_principal_name {
            match Any::new(Tag::Ia5String, n.as_bytes()) {
                Ok(a) => {
                    let on = OtherName {
                        type_id: MSFT_USER_PRINCIPAL_NAME,
                        value: a,
                    };
                    let gn = GeneralName::OtherName(on);
                    let gs = GeneralSubtree {
                        base: gn,
                        maximum: None,
                        minimum: 0,
                    };
                    match gs.to_der() {
                        Ok(b) => {
                            upnbufs.push(b);
                        }
                        Err(e) => return Err(Error::Asn1Error(e)),
                    }
                }
                Err(e) => return Err(Error::Asn1Error(e)),
            }
        }
    }
    bufs.insert("upn".to_string(), upnbufs);

    let mut vrfc = vec![];
    for b in &bufs["rfc822"] {
        match GeneralSubtree::from_der(b.as_slice()) {
            Ok(v) => vrfc.push(v),
            Err(e) => return Err(Error::Asn1Error(e)),
        }
    }
    let mut vdns = vec![];
    for b in &bufs["dns"] {
        match GeneralSubtree::from_der(b.as_slice()) {
            Ok(v) => vdns.push(v),
            Err(e) => return Err(Error::Asn1Error(e)),
        }
    }

    let mut vdn = vec![];
    for b in &bufs["dn"] {
        match GeneralSubtree::from_der(b.as_slice()) {
            Ok(v) => vdn.push(v),
            Err(e) => return Err(Error::Asn1Error(e)),
        }
    }

    let mut vuri = vec![];
    for b in &bufs["uri"] {
        match GeneralSubtree::from_der(b.as_slice()) {
            Ok(v) => vuri.push(v),
            Err(e) => return Err(Error::Asn1Error(e)),
        }
    }
    let mut vupn = vec![];
    for b in &bufs["upn"] {
        match GeneralSubtree::from_der(b.as_slice()) {
            Ok(v) => vupn.push(v),
            Err(e) => return Err(Error::Asn1Error(e)),
        }
    }

    let mut vns = vec![];
    for b in &bufs["not_supported"] {
        match GeneralSubtree::from_der(b.as_slice()) {
            Ok(v) => vns.push(v),
            Err(e) => return Err(Error::Asn1Error(e)),
        }
    }

    Ok(NameConstraintsSet {
        rfc822_name: vrfc,
        rfc822_name_null: false,
        dns_name: vdns,
        dns_name_null: false,
        directory_name: vdn,
        directory_name_null: false,
        user_principal_name: vupn,
        user_principal_name_null: false,
        uniform_resource_identifier: vuri,
        uniform_resource_identifier_null: false,
        not_supported: vns,
    })
}

pub(crate) fn name_constraints_set_to_name_constraints_settings(
    set: &NameConstraintsSet,
) -> NameConstraintsSettings {
    let mut vrfc: Option<Vec<String>> = None;
    if !set.rfc822_name.is_empty() {
        let mut tmp = vec![];
        for gs in &set.rfc822_name {
            if let GeneralName::Rfc822Name(rfc822) = &gs.base {
                tmp.push(rfc822.to_string());
            }
        }
        vrfc = Some(tmp);
    }

    let mut vdns: Option<Vec<String>> = None;
    if !set.dns_name.is_empty() {
        let mut tmp = vec![];
        for gs in &set.dns_name {
            if let GeneralName::DnsName(dns) = &gs.base {
                tmp.push(dns.to_string());
            }
        }
        vdns = Some(tmp);
    }

    let mut vdn: Option<Vec<String>> = None;
    if !set.directory_name.is_empty() {
        let mut tmp = vec![];
        for gs in &set.directory_name {
            if let GeneralName::DirectoryName(dn) = &gs.base {
                tmp.push(name_to_string(dn));
            }
        }
        vdn = Some(tmp);
    }

    let mut vuri: Option<Vec<String>> = None;
    if !set.uniform_resource_identifier.is_empty() {
        let mut tmp = vec![];
        for gs in &set.uniform_resource_identifier {
            if let GeneralName::UniformResourceIdentifier(uri) = &gs.base {
                tmp.push(uri.to_string());
            }
        }
        vuri = Some(tmp);
    }

    let mut vupn: Option<Vec<String>> = None;
    if !set.user_principal_name.is_empty() {
        let mut tmp = vec![];
        for gs in &set.user_principal_name {
            if let GeneralName::OtherName(on) = &gs.base {
                if on.type_id == MSFT_USER_PRINCIPAL_NAME {
                    if on.value.tag() == Tag::Ia5String {
                        if let Ok(ia5) = on.value.decode_as::<Ia5String>() {
                            tmp.push(ia5.to_string());
                        }
                    } else if on.value.tag() == Tag::Utf8String {
                        if let Ok(utf) = on.value.decode_as::<Utf8StringRef<'_>>() {
                            tmp.push(utf.to_string());
                        }
                    } else if on.value.tag() == Tag::PrintableString {
                        if let Ok(ps) = on.value.decode_as::<PrintableString>() {
                            tmp.push(ps.to_string());
                        }
                    } else {
                        //todo how to access?
                        //tmp.push(crate::buffer_to_hex(on.value.value()));
                    }
                }
            }
        }
        vupn = Some(tmp);
    }

    let mut vns: Option<Vec<String>> = None;
    if !set.not_supported.is_empty() {
        let mut tmp = vec![];
        for gs in &set.not_supported {
            match gs.to_der() {
                Ok(gs) => {
                    tmp.push(buffer_to_hex(&gs));
                },
                Err(e) => {
                    // todo handle error?
                }
            }
        }
        vns = Some(tmp);
    }

    NameConstraintsSettings {
        rfc822_name: vrfc,
        dns_name: vdns,
        directory_name: vdn,
        uniform_resource_identifier: vuri,
        user_principal_name: vupn,
        not_supported: vns
    }
}

#[test]
fn intersection_tests() {
    use crate::path_settings::*;
    let perm = crate::NameConstraintsSettings {
        directory_name: Some(vec!["CN=Joe,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["x@example.com".to_string()]),
        user_principal_name: Some(vec!["1234567890@mil".to_string()]),
        dns_name: Some(vec!["j.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://j.example.com".to_string()]),
        not_supported: None
    };
    let perm_copy = crate::NameConstraintsSettings {
        directory_name: Some(vec!["CN=Joe,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["x@example.com".to_string()]),
        user_principal_name: Some(vec!["1234567890@mil".to_string()]),
        dns_name: Some(vec!["j.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://j.example.com".to_string()]),
        not_supported: None
    };
    let perm2 = crate::NameConstraintsSettings {
        directory_name: Some(vec!["CN=Sue,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["y@example.com".to_string()]),
        user_principal_name: Some(vec!["0987654321@mil".to_string()]),
        dns_name: Some(vec!["s.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://s.example.com".to_string()]),
        not_supported: None
    };
    let perm3 = crate::NameConstraintsSettings {
        directory_name: Some(vec!["CN=Abe,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["z@example.com".to_string()]),
        user_principal_name: Some(vec!["1236547890@mil".to_string()]),
        dns_name: Some(vec!["t.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://t.example.com".to_string()]),
        not_supported: None
    };

    let mut cps = CertificationPathSettings::default();
    set_initial_permitted_subtrees(&mut cps, perm);
    let mut cps2 = CertificationPathSettings::default();
    set_initial_permitted_subtrees(&mut cps2, perm2);
    let mut cps3 = CertificationPathSettings::default();
    set_initial_permitted_subtrees(&mut cps3, perm3);

    let mut bufs1 = BTreeMap::new();
    let mut perm_set = get_initial_permitted_subtrees_as_set(&cps, &mut bufs1)
        .unwrap()
        .unwrap();
    let mut bufs1_b = BTreeMap::new();
    let perm_set_b =
        get_initial_permitted_subtrees_with_default_as_set(&cps, &mut bufs1_b).unwrap();
    assert_eq!(perm_set, perm_set_b);
    let perm_ncs = get_initial_permitted_subtrees_with_default(&cps);
    assert_eq!(perm_ncs, perm_copy);

    let mut bufs2 = BTreeMap::new();
    let perm_set2 = get_initial_permitted_subtrees_as_set(&cps2, &mut bufs2)
        .unwrap()
        .unwrap();
    let mut bufs2_b = BTreeMap::new();
    let perm_set2_b =
        get_initial_permitted_subtrees_with_default_as_set(&cps2, &mut bufs2_b).unwrap();
    assert_eq!(perm_set2, perm_set2_b);
    let mut bufs3 = BTreeMap::new();
    let perm_set3 = get_initial_permitted_subtrees_as_set(&cps3, &mut bufs3)
        .unwrap()
        .unwrap();
    let mut bufs3_b = BTreeMap::new();
    let perm_set3_b =
        get_initial_permitted_subtrees_with_default_as_set(&cps3, &mut bufs3_b).unwrap();
    assert_eq!(perm_set3, perm_set3_b);

    let perm_roundtrip = name_constraints_set_to_name_constraints_settings(&perm_set);
    assert_eq!(perm_roundtrip, perm_copy);

    assert_eq!(1, perm_set.directory_name.len());
    perm_set.calculate_union(&perm_set2.directory_name);
    assert_eq!(2, perm_set.directory_name.len());

    assert!(!perm_set.directory_name_null);
    perm_set.calculate_intersection(&perm_set2.directory_name);
    assert_eq!(1, perm_set.directory_name.len());
    perm_set.calculate_intersection(&perm_set3.directory_name);
    assert!(perm_set.directory_name_null);

    #[cfg(feature = "std")]
    {
        assert_eq!(1, perm_set.rfc822_name.len());
        perm_set.calculate_union(&perm_set2.rfc822_name);
        assert_eq!(2, perm_set.rfc822_name.len());

        assert_eq!(1, perm_set.dns_name.len());
        perm_set.calculate_union(&perm_set2.dns_name);
        assert_eq!(2, perm_set.dns_name.len());

        assert_eq!(1, perm_set.uniform_resource_identifier.len());
        perm_set.calculate_union(&perm_set2.uniform_resource_identifier);
        assert_eq!(2, perm_set.uniform_resource_identifier.len());

        assert!(!perm_set.rfc822_name_null);
        perm_set.calculate_intersection(&perm_set2.rfc822_name);
        assert_eq!(1, perm_set.rfc822_name.len());
        perm_set.calculate_intersection(&perm_set3.rfc822_name);
        assert!(perm_set.rfc822_name_null);

        assert!(!perm_set.dns_name_null);
        perm_set.calculate_intersection(&perm_set2.dns_name);
        assert_eq!(1, perm_set.dns_name.len());
        perm_set.calculate_intersection(&perm_set3.dns_name);
        assert!(perm_set.dns_name_null);

        assert!(!perm_set.uniform_resource_identifier_null);
        perm_set.calculate_intersection(&perm_set2.uniform_resource_identifier);
        assert_eq!(1, perm_set.uniform_resource_identifier.len());
        perm_set.calculate_intersection(&perm_set3.uniform_resource_identifier);
        assert!(perm_set.uniform_resource_identifier_null);
    }

    let mut cps_set = CertificationPathSettings::default();
    set_initial_permitted_subtrees_from_set(&mut cps_set, &perm_set3);
    let mut bufs3_c = BTreeMap::new();
    let perm_set3_copy = get_initial_permitted_subtrees_as_set(&cps_set, &mut bufs3_c)
        .unwrap()
        .unwrap();
    assert_eq!(perm_set3, perm_set3_copy);
}
