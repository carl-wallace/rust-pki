//! Structures and functions related to processing name constraints

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::str::FromStr;

use serde::{Deserialize, Serialize};

// URI name-constraint matching extracts the SAN host with the `url` crate, which needs std; the
// other supported forms (rfc822, DNS, directory, IP) are no_std. IP uses core::net (stable since
// 1.77) plus the cidr crate built without its std feature.
#[cfg(feature = "std")]
use url::Url;

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};

use der::asn1::OctetString;

use der::{
    asn1::{Any, Ia5String, ObjectIdentifier},
    Decode, Encode, Tag,
};
use subtle_encoding::hex;
use x509_cert::ext::pkix::{
    constraints::name::{GeneralSubtree, GeneralSubtrees},
    name::GeneralName,
    SubjectAltName,
};
use x509_cert::name::Name;

use crate::{buffer_to_hex, util::pdv_utilities::*, Error, Result};

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
    /// rfc822_name governs use of email addresses in SANs
    pub rfc822_name: Vec<GeneralSubtree>, //t = 1
    /// rfc822_name_null is initialized to false and set to true if an intersection operation yields empty set
    pub rfc822_name_null: bool,
    /// dns_name governs use of DNS names in SANs
    pub dns_name: Vec<GeneralSubtree>, //t = 2
    /// dns_name_null is initialized to false and set to true if an intersection operation yields empty set
    pub dns_name_null: bool,
    /// directory_name governs use of DNs in SANs and issuer and subject fields
    pub directory_name: Vec<GeneralSubtree>, //t = 4
    /// directory_name_null is initialized to false and set to true if an intersection operation yields empty set
    pub directory_name_null: bool,
    /// uniform_resource_identifier governs use of URIs in SANs
    pub uniform_resource_identifier: Vec<GeneralSubtree>, //t = 6
    /// uniform_resource_identifier_null is initialized to false and set to true if an intersection operation yields empty set
    pub uniform_resource_identifier_null: bool,
    /// ip_address governs use of IP addresses in SANs
    pub ip_address: Vec<GeneralSubtree>, //t = 7
    /// ip_address_null is initialized to false and set to true if an intersection operation yields empty set
    pub ip_address_null: bool,
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
        self.calculate_intersection_ip(ext);

        // collect all unsupported instances (not intersection)
        for gs in ext {
            match &gs.base {
                GeneralName::EdiPartyName(_)
                | GeneralName::OtherName(_)
                | GeneralName::RegisteredId(_) => {
                    self.not_supported.push(gs.clone());
                }
                _ => {
                    // handled by intersections above
                }
            }
        }
    }

    /// `calculate_union calculates` the union of self and ext and saves the result in self.
    pub(crate) fn calculate_union(&mut self, ext: &GeneralSubtrees) {
        for subtree in ext {
            let gn = &subtree.base;

            // accumulate names in the appropriate buckets. only accumulate where bucket is not None
            // as None signifies a failure.
            match gn {
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
                    #[cfg(feature = "std")]
                    if !self.uniform_resource_identifier_null {
                        self.uniform_resource_identifier.push(subtree.clone());
                    }
                    #[cfg(not(feature = "std"))]
                    {
                        self.uniform_resource_identifier_null = true;
                    }
                }
                GeneralName::IpAddress(_ip) => {
                    if !self.ip_address_null {
                        self.ip_address.push(subtree.clone());
                    }
                }
                // not supporting name constraints for x400Address, ediPartyName, registeredID or otherName
                _ => {
                    self.not_supported.push(subtree.clone());
                }
            }
        }
    }

    /// `are_any_empty` returns true if any of the supported name constraints buckets have been set to None,
    /// which signifies failure.
    pub fn are_any_empty(&self) -> bool {
        if self.rfc822_name_null
            || self.dns_name_null
            || self.directory_name_null
            || self.uniform_resource_identifier_null
            || self.ip_address_null
        {
            return true;
        }
        false
    }

    /// `subject_within_excluded_subtrees` returns true if subject is within at least one excluded subtree
    /// known to self.
    pub fn subject_within_permitted_subtrees(&self, subject: &Name) -> bool {
        if subject.is_empty() {
            // NULL subjects get a free pass
            return true;
        }

        // rfc822 name constraints are also applied to a PKCS#9 emailAddress attribute in the
        // subject DN (legacy RFC 3280 behavior, as OpenSSL does), not just rfc822 SANs. Only
        // inspect the DN when an rfc822 constraint is present.
        {
            if self.rfc822_name_null || !self.rfc822_name.is_empty() {
                for email in emails_from_dn(subject) {
                    // a NULL permitted set excludes every address
                    if self.rfc822_name_null {
                        return false;
                    }
                    // otherwise the address must fall within one of the permitted rfc822 subtrees
                    let mut permitted = false;
                    for gn in &self.rfc822_name {
                        if let GeneralName::Rfc822Name(subtree) = &gn.base {
                            if descended_from_rfc822(subtree, &email) {
                                permitted = true;
                                break;
                            }
                        }
                    }
                    if !permitted {
                        return false;
                    }
                }
            }
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

        if let Some(gn_san) = san {
            for subtree_san in gn_san.0.iter() {
                match subtree_san {
                    #[allow(unused_mut)]
                    GeneralName::DirectoryName(dn_san) => {
                        if self.directory_name_null {
                            return false;
                        }

                        if self.directory_name.is_empty() {
                            continue;
                        }

                        let mut dn_ok = false;
                        for gn_state in &self.directory_name {
                            if let GeneralName::DirectoryName(dn_state) = &gn_state.base {
                                if descended_from_dn(
                                    dn_state,
                                    dn_san,
                                    gn_state.minimum,
                                    gn_state.maximum,
                                ) {
                                    dn_ok = true;
                                    break;
                                }
                            }
                        }
                        if !dn_ok {
                            return false;
                        }
                    } // end GeneralName::DirectoryName
                    #[allow(unused_variables, unused_mut)]
                    GeneralName::Rfc822Name(rfc822_san) => {
                        if self.rfc822_name_null {
                            return false;
                        }

                        if self.rfc822_name.is_empty() {
                            continue;
                        }

                        let mut rfc822_ok = false;

                        for gn_state in &self.rfc822_name {
                            if let GeneralName::Rfc822Name(rfc822_state) = &gn_state.base {
                                if descended_from_rfc822(rfc822_state, rfc822_san) {
                                    rfc822_ok = true;
                                    break;
                                }
                            }
                        }
                        if !rfc822_ok {
                            return false;
                        }
                    } // end GeneralName::Rfc822Name

                    #[allow(unused_variables, unused_mut)]
                    GeneralName::DnsName(dns_san) => {
                        if self.dns_name_null {
                            return false;
                        }

                        if self.dns_name.is_empty() {
                            continue;
                        }

                        let mut dns_ok = false;

                        for gn_state in &self.dns_name {
                            if let GeneralName::DnsName(dns_state) = &gn_state.base {
                                if descended_from_host(dns_state, dns_san.as_str(), false) {
                                    dns_ok = true;
                                    break;
                                }
                            }
                        }
                        if !dns_ok {
                            return false;
                        }
                    } // end GeneralName::DnsName

                    #[allow(unused_variables, unused_mut)]
                    GeneralName::UniformResourceIdentifier(uri_san) => {
                        if self.uniform_resource_identifier_null {
                            return false;
                        }

                        if self.uniform_resource_identifier.is_empty() {
                            continue;
                        }

                        let mut uri_ok = false;

                        // Parse the SAN URI's host once; it does not vary across the permitted
                        // subtrees compared below.
                        #[cfg(feature = "std")]
                        if let Some(host) = Url::parse(uri_san.as_str())
                            .ok()
                            .and_then(|url| url.host().map(|h| h.to_string()))
                        {
                            for gn_state in &self.uniform_resource_identifier {
                                if let GeneralName::UniformResourceIdentifier(uri_state) =
                                    &gn_state.base
                                {
                                    if descended_from_host(uri_state, host.as_str(), true) {
                                        uri_ok = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if !uri_ok {
                            return false;
                        }
                    } // end GeneralName::UniformResourceIdentifier
                    #[allow(unused_variables, unused_mut)]
                    GeneralName::IpAddress(ip_san) => {
                        if self.ip_address_null {
                            return false;
                        }

                        if self.ip_address.is_empty() {
                            continue;
                        }

                        let mut ip_ok = false;

                        for gn_state in &self.ip_address {
                            if let GeneralName::IpAddress(ip_state) = &gn_state.base {
                                let cidr_subtree = match get_cidr_for_subtree(ip_state.as_bytes()) {
                                    Ok(cidr) => cidr,
                                    Err(_e) => return false, // just fail on malformed
                                };

                                let addr_san = match get_ip_addr_for_san(ip_san.as_bytes()) {
                                    Ok(addr_san) => addr_san,
                                    Err(_e) => return false, // just fail on malformed
                                };

                                if cidr_subtree.contains(&addr_san) {
                                    ip_ok = true;
                                    break;
                                }
                            }
                        }
                        if !ip_ok {
                            return false;
                        }
                    }
                    GeneralName::OtherName(_) => {
                        // otherName SANs are unsupported; any otherName name constraint excludes them
                        for ns in &self.not_supported {
                            if let GeneralName::OtherName(_) = ns.base {
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
        if subject.is_empty() {
            // NULL subjects get a free pass
            return false;
        }

        // rfc822 name constraints are also applied to a PKCS#9 emailAddress attribute in the
        // subject DN (legacy RFC 3280 behavior, as OpenSSL does), not just rfc822 SANs. If any
        // such address falls within an excluded rfc822 subtree, reject.
        {
            if self.rfc822_name_null || !self.rfc822_name.is_empty() {
                for email in emails_from_dn(subject) {
                    // a NULL excluded set excludes every address
                    if self.rfc822_name_null {
                        return true;
                    }
                    // otherwise reject if the address falls within an excluded rfc822 subtree
                    for gn in &self.rfc822_name {
                        if let GeneralName::Rfc822Name(subtree) = &gn.base {
                            if descended_from_rfc822(subtree, &email) {
                                return true;
                            }
                        }
                    }
                }
            }
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

        if let Some(gn_san) = san {
            for subtree_san in gn_san.0.iter() {
                match subtree_san {
                    GeneralName::DirectoryName(dn_san) => {
                        if self.directory_name_null {
                            return true;
                        }

                        if self.directory_name.is_empty() {
                            continue;
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
                    }
                    #[allow(unused_variables)]
                    GeneralName::Rfc822Name(rfc822_san) => {
                        if self.rfc822_name_null {
                            return true;
                        }

                        if self.rfc822_name.is_empty() {
                            continue;
                        }

                        for gn_state in &self.rfc822_name {
                            if let GeneralName::Rfc822Name(rfc822_state) = &gn_state.base {
                                if descended_from_rfc822(rfc822_state, rfc822_san) {
                                    return true;
                                }
                            }
                        }
                    }
                    #[allow(unused_variables)]
                    GeneralName::DnsName(dns_san) => {
                        if self.dns_name_null {
                            return true;
                        }

                        if self.dns_name.is_empty() {
                            continue;
                        }

                        for gn_state in &self.dns_name {
                            if let GeneralName::DnsName(dns_state) = &gn_state.base {
                                if descended_from_host(dns_state, dns_san.as_str(), false) {
                                    return true;
                                }
                            }
                        }
                    }

                    #[allow(unused_variables)]
                    GeneralName::UniformResourceIdentifier(uri_san) => {
                        if self.uniform_resource_identifier_null {
                            return true;
                        }

                        if self.uniform_resource_identifier.is_empty() {
                            continue;
                        }

                        // Parse the SAN URI's host once; it does not vary across the excluded
                        // subtrees compared below.
                        #[cfg(feature = "std")]
                        if let Some(host) = Url::parse(uri_san.as_str())
                            .ok()
                            .and_then(|url| url.host().map(|h| h.to_string()))
                        {
                            for gn_state in &self.uniform_resource_identifier {
                                if let GeneralName::UniformResourceIdentifier(uri_state) =
                                    &gn_state.base
                                {
                                    if descended_from_host(uri_state, host.as_str(), true) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                    #[allow(unused_variables)]
                    GeneralName::IpAddress(ip_san) => {
                        if self.ip_address_null {
                            return true;
                        }

                        if self.ip_address.is_empty() {
                            continue;
                        }

                        for gn_state in &self.ip_address {
                            if let GeneralName::IpAddress(ip_state) = &gn_state.base {
                                let cidr_subtree = match get_cidr_for_subtree(ip_state.as_bytes()) {
                                    Ok(cidr) => cidr,
                                    Err(e) => return true, // fail on malformed
                                };

                                let addr_san = match get_ip_addr_for_san(ip_san.as_bytes()) {
                                    Ok(addr_san) => addr_san,
                                    Err(e) => return true, // fail on malformed
                                };

                                if cidr_subtree.contains(&addr_san) {
                                    return true;
                                }
                            }
                        }
                    }
                    GeneralName::OtherName(_) => {
                        // otherName SANs are unsupported; any otherName name constraint excludes them
                        for ns in &self.not_supported {
                            if let GeneralName::OtherName(_) = ns.base {
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
                                    new_set.push(new_name.clone());
                                } else if descended_from_rfc822(new_rfc822, prev_rfc822) {
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
                                    new_set.push(new_name.clone());
                                } else if descended_from_host(new_dns, prev_dns.as_str(), false) {
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
                            } else if descended_from_dn(
                                new_dn,
                                prev_dn,
                                new_name.minimum,
                                new_name.maximum,
                            ) {
                                new_set.push(prev_name.clone());
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
                                    new_set.push(new_name.clone());
                                } else if descended_from_host(new_uri, prev_uri.as_str(), true) {
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

    fn calculate_intersection_ip(&mut self, new_names: &GeneralSubtrees) {
        if self.ip_address_null || !has_ip(new_names) {
            // nothing to intersect (either state has become NULL or there are no names to add)
            return;
        }

        {
            let mut new_set = Vec::new();

            for new_name in new_names {
                if let GeneralName::IpAddress(new_ip) = &new_name.base {
                    if self.ip_address.is_empty() {
                        new_set.push(new_name.clone());
                    } else {
                        for prev_name in &self.ip_address {
                            if let GeneralName::IpAddress(prev_ip) = &prev_name.base {
                                if new_name == prev_name {
                                    // if the constraints are the same, keep it
                                    new_set.push(prev_name.clone());
                                } else {
                                    let new_cidr = match get_cidr_for_subtree(new_ip.as_bytes()) {
                                        Ok(new_cidr) => new_cidr,
                                        Err(_e) => {
                                            continue;
                                        }
                                    };
                                    let prev_cidr = match get_cidr_for_subtree(prev_ip.as_bytes()) {
                                        Ok(prev_cidr) => prev_cidr,
                                        Err(_e) => {
                                            continue;
                                        }
                                    };
                                    if prev_cidr.contains(&new_cidr.first_address())
                                        && prev_cidr.contains(&new_cidr.last_address())
                                    {
                                        // if the new constraint falls within the old, use the new one
                                        new_set.push(new_name.clone());
                                    } else if new_cidr.contains(&prev_cidr.first_address())
                                        && new_cidr.contains(&prev_cidr.last_address())
                                    {
                                        // if the old constraint falls within the new, keep the old one
                                        new_set.push(prev_name.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if !new_set.is_empty() {
                self.ip_address = new_set;
            } else {
                self.ip_address_null = true;
            }
        }
    }
    pub(crate) fn len(&self) -> usize {
        self.rfc822_name.len()
            + self.dns_name.len()
            + self.directory_name.len()
            + self.uniform_resource_identifier.len()
            + self.ip_address.len()
            + self.not_supported.len()
    }
}

/// NameConstraintsSettings is a serializable equivalent of NameConstraintsSet. The getters and setters
/// for CertificationPathSettings handle translating from one to the other.
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct NameConstraintsSettings {
    /// rfc822_name governs use of email addresses in SANs
    pub rfc822_name: Option<Vec<String>>, //t = 1
    /// dns_name governs use of DNS names in SANs
    pub dns_name: Option<Vec<String>>, //t = 2
    /// directory_name governs use of DNs in SANs and issuer and subject fields
    pub directory_name: Option<Vec<String>>, //t = 4
    /// uniform_resource_identifier governs use of URIs in SANs
    pub uniform_resource_identifier: Option<Vec<String>>, //t = 6
    /// ip_address governs use of URIs in SANs
    pub ip_address: Option<Vec<String>>, //t = 7
    /// ASCII hex encoding of unsupported GeneralSubtree
    pub not_supported: Option<Vec<String>>, //ASCII hex encodings of unsupported name forms
}

fn get_cidr_for_subtree(ip_bytes: &[u8]) -> Result<IpCidr> {
    if ip_bytes.len() == 8 {
        let mut tmp_addr: [u8; 4] = Default::default();
        tmp_addr.copy_from_slice(&ip_bytes[..4]);
        let addr = Ipv4Addr::from(tmp_addr);
        match Ipv4Cidr::new(addr, count_bits(&ip_bytes[4..])) {
            Ok(cidr) => Ok(IpCidr::from(cidr)),
            Err(_e) => Err(Error::ParseError),
        }
    } else if ip_bytes.len() == 32 {
        let mut tmp_addr: [u8; 16] = Default::default();
        tmp_addr.copy_from_slice(&ip_bytes[..16]);
        let addr = Ipv6Addr::from(tmp_addr);
        match Ipv6Cidr::new(addr, count_bits(&ip_bytes[16..])) {
            Ok(cidr) => Ok(IpCidr::from(cidr)),
            Err(_e) => Err(Error::ParseError),
        }
    } else {
        Err(Error::ParseError)
    }
}

/// Creates an IpAddr from buffer with encoded address
pub fn get_ip_addr_for_san(ip_bytes: &[u8]) -> Result<IpAddr> {
    if ip_bytes.len() == 4 {
        let mut tmp_addr: [u8; 4] = Default::default();
        tmp_addr.copy_from_slice(&ip_bytes[..4]);
        let addr = Ipv4Addr::from(tmp_addr);
        Ok(IpAddr::from(addr))
    } else if ip_bytes.len() == 16 {
        let mut tmp_addr: [u8; 16] = Default::default();
        tmp_addr.copy_from_slice(&ip_bytes[..16]);
        let addr = Ipv6Addr::from(tmp_addr);
        Ok(IpAddr::from(addr))
    } else {
        Err(Error::ParseError)
    }
}
/// Converts a NameConstraintsSettings object to a NameConstraintsSet object
pub fn name_constraints_settings_to_name_constraints_set(
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

    let mut ipbufs: Vec<Vec<u8>> = vec![];
    if let Some(ips) = &settings.ip_address {
        for ip in ips {
            let parts: Vec<&str> = ip.split('/').collect();
            if parts.len() != 2 {
                return Err(Error::ParseError);
            }
            let mask = match parts[1].parse::<u8>() {
                Ok(mask) => mask,
                Err(_) => return Err(Error::ParseError),
            };
            let ip_vec = if let Ok(ip) = Ipv4Addr::from_str(parts[0]) {
                let mut buf = vec![0x00; 4];
                buf = set_bits(&buf, mask);
                let mut ip_vec = ip.octets().to_vec();
                ip_vec.append(&mut buf);
                ip_vec
            } else if let Ok(ip) = Ipv6Addr::from_str(parts[0]) {
                let mut buf = vec![0x00; 16];
                buf = set_bits(&buf, mask);
                let mut ip_vec = ip.octets().to_vec();
                ip_vec.append(&mut buf);
                ip_vec
            } else {
                continue;
            };

            let gn = GeneralName::IpAddress(OctetString::new(ip_vec.as_slice())?);
            let gs = GeneralSubtree {
                base: gn,
                maximum: None,
                minimum: 0,
            };
            match gs.to_der() {
                Ok(b) => {
                    ipbufs.push(b);
                }
                Err(e) => return Err(Error::Asn1Error(e)),
            }
        }
    }
    bufs.insert("ip".to_string(), ipbufs);

    let mut nsbufs: Vec<Vec<u8>> = vec![];
    if let Some(not_supported) = &settings.not_supported {
        for n in not_supported {
            if let Ok(buf) = hex::decode_upper(n) {
                nsbufs.push(buf);
            }
        }
    }
    bufs.insert("not_supported".to_string(), nsbufs);

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

    let mut ips = vec![];
    for b in &bufs["ip"] {
        match GeneralSubtree::from_der(b.as_slice()) {
            Ok(v) => ips.push(v),
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
        uniform_resource_identifier: vuri,
        uniform_resource_identifier_null: false,
        ip_address: ips,
        ip_address_null: false,
        not_supported: vns,
    })
}

fn count_bits(buf: &[u8]) -> u8 {
    let mut num_bits = 0;
    let bits = vec![0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];
    for byte in buf {
        for check in &bits {
            if check & byte == *check {
                num_bits += 1;
            } else {
                return num_bits;
            }
        }
    }
    num_bits
}

fn set_bits(buf: &[u8], num_bits: u8) -> Vec<u8> {
    // Set the high-order `num_bits` bits (Msb0: bit 0 is the top bit of the first byte), matching the
    // CIDR prefix semantics count_bits reads back. Plain bit math keeps this no_std (no bitvec).
    let mut out = buf.to_vec();
    let mut remaining = num_bits as usize;
    for byte in out.iter_mut() {
        if remaining >= 8 {
            *byte |= 0xFF;
            remaining -= 8;
        } else if remaining > 0 {
            *byte |= 0xFFu8 << (8 - remaining);
            remaining = 0;
        } else {
            break;
        }
    }
    out
}

#[test]
fn set_bits_count_bits_round_trip() {
    // Non-byte-aligned prefixes must survive the round trip. With Lsb0 ordering
    // (as before this test existed), a /15 mask read back as /8, widening the
    // permitted IP set.
    for prefix in [0u8, 1, 7, 8, 9, 15, 16, 24, 31, 32] {
        assert_eq!(count_bits(&set_bits(&[0u8; 4], prefix)), prefix);
    }
    assert_eq!(set_bits(&[0u8; 4], 15), vec![0xFF, 0xFE, 0x00, 0x00]);
    assert_eq!(set_bits(&[0u8; 4], 9), vec![0xFF, 0x80, 0x00, 0x00]);
}

pub(crate) fn name_constraints_set_to_name_constraints_settings(
    set: &NameConstraintsSet,
) -> Result<NameConstraintsSettings> {
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

    let mut vips: Option<Vec<String>> = None;
    {
        if !set.ip_address.is_empty() {
            let mut tmp = vec![];
            for gs in &set.ip_address {
                if let GeneralName::IpAddress(ip_os) = &gs.base {
                    let ip_bytes = ip_os.as_bytes();
                    let ip = if ip_bytes.len() == 8 {
                        let mut tmp_addr: [u8; 4] = Default::default();
                        tmp_addr.copy_from_slice(&ip_bytes[..4]);
                        let addr = Ipv4Addr::from(tmp_addr);
                        format!("{}/{}", addr, count_bits(&ip_bytes[4..]))
                    } else if ip_bytes.len() == 32 {
                        let mut tmp_addr: [u8; 16] = Default::default();
                        tmp_addr.copy_from_slice(&ip_bytes[..16]);
                        let addr = Ipv6Addr::from(tmp_addr);
                        format!("{}/{}", addr, count_bits(&ip_bytes[16..]))
                    } else {
                        return Err(Error::ParseError);
                    };

                    tmp.push(ip);
                }
            }
            vips = Some(tmp);
        }
    }
    let mut vns: Option<Vec<String>> = None;
    if !set.not_supported.is_empty() {
        let mut tmp = vec![];
        for gs in &set.not_supported {
            match gs.to_der() {
                Ok(gs) => {
                    tmp.push(buffer_to_hex(&gs));
                }
                Err(_e) => {
                    // todo handle error?
                }
            }
        }
        vns = Some(tmp);
    }

    Ok(NameConstraintsSettings {
        rfc822_name: vrfc,
        dns_name: vdns,
        directory_name: vdn,
        uniform_resource_identifier: vuri,
        ip_address: vips,
        not_supported: vns,
    })
}

// Intersecting permitted subtrees must retain the narrower subtree for rfc822/dNSName/URI
// (RFC 5280 6.1.4(g)), regardless of which side is narrower. Keeping the broader subtree
// silently widens a subordinate CA's name constraint.
#[cfg(feature = "std")]
#[test]
fn intersection_keeps_narrower_subtree() {
    use crate::path_settings::*;

    let broad = NameConstraintsSettings {
        directory_name: Some(vec!["OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["example.com".to_string()]),
        dns_name: Some(vec!["example.com".to_string()]),
        uniform_resource_identifier: Some(vec![".example.com".to_string()]),
        ip_address: Some(vec!["192.168.0.0/16".to_string()]),
        not_supported: None,
    };
    let narrow = NameConstraintsSettings {
        directory_name: Some(vec!["CN=Joe,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["x@example.com".to_string()]),
        dns_name: Some(vec!["sub.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["sub.example.com".to_string()]),
        ip_address: Some(vec!["192.168.10.0/24".to_string()]),
        not_supported: None,
    };

    let mut cps_broad = CertificationPathSettings::default();
    cps_broad.set_initial_permitted_subtrees(broad.clone());
    let mut cps_narrow = CertificationPathSettings::default();
    cps_narrow.set_initial_permitted_subtrees(narrow.clone());

    // broad state intersected with narrower constraint -> narrower constraint survives
    let mut bufs1 = BTreeMap::new();
    let mut set_broad = cps_broad
        .get_initial_permitted_subtrees_as_set(&mut bufs1)
        .unwrap()
        .unwrap();
    let mut bufs2 = BTreeMap::new();
    let set_narrow = cps_narrow
        .get_initial_permitted_subtrees_as_set(&mut bufs2)
        .unwrap()
        .unwrap();
    set_broad.calculate_intersection(&set_narrow.rfc822_name);
    set_broad.calculate_intersection(&set_narrow.dns_name);
    set_broad.calculate_intersection(&set_narrow.uniform_resource_identifier);
    set_broad.calculate_intersection(&set_narrow.directory_name);
    set_broad.calculate_intersection(&set_narrow.ip_address);
    let result = name_constraints_set_to_name_constraints_settings(&set_broad).unwrap();
    assert_eq!(result.rfc822_name, narrow.rfc822_name);
    assert_eq!(result.dns_name, narrow.dns_name);
    assert_eq!(
        result.uniform_resource_identifier,
        narrow.uniform_resource_identifier
    );
    assert_eq!(result.directory_name, narrow.directory_name);
    assert_eq!(result.ip_address, narrow.ip_address);

    // narrow state intersected with broader constraint -> narrower state survives
    let mut bufs3 = BTreeMap::new();
    let mut set_narrow2 = cps_narrow
        .get_initial_permitted_subtrees_as_set(&mut bufs3)
        .unwrap()
        .unwrap();
    let mut bufs4 = BTreeMap::new();
    let set_broad2 = cps_broad
        .get_initial_permitted_subtrees_as_set(&mut bufs4)
        .unwrap()
        .unwrap();
    set_narrow2.calculate_intersection(&set_broad2.rfc822_name);
    set_narrow2.calculate_intersection(&set_broad2.dns_name);
    set_narrow2.calculate_intersection(&set_broad2.uniform_resource_identifier);
    set_narrow2.calculate_intersection(&set_broad2.directory_name);
    set_narrow2.calculate_intersection(&set_broad2.ip_address);
    let result2 = name_constraints_set_to_name_constraints_settings(&set_narrow2).unwrap();
    assert_eq!(result2.rfc822_name, narrow.rfc822_name);
    assert_eq!(result2.dns_name, narrow.dns_name);
    assert_eq!(
        result2.uniform_resource_identifier,
        narrow.uniform_resource_identifier
    );
    assert_eq!(result2.directory_name, narrow.directory_name);
    assert_eq!(result2.ip_address, narrow.ip_address);
}

// A permitted subtree set whose bucket for one name form has intersected to empty (NULL) must
// reject only certificates that actually present a name of that form; a certificate carrying names
// of other forms is unaffected. This per-form gating is what lets path validation drop the whole
// certificate once a permitted bucket empties: an empty form no certificate uses is vacuously
// satisfied, and an empty form a certificate does use is still rejected here.
#[cfg(feature = "std")]
#[test]
fn null_permitted_bucket_gates_only_its_own_name_form() {
    // Model an intermediate whose permitted dNSName subtree intersected to empty.
    let set = NameConstraintsSet {
        dns_name_null: true,
        ..Default::default()
    };

    // A SAN of a different form (rfc822, with no operative rfc822 constraint) is unconstrained and
    // therefore permitted, even though the dNSName bucket is NULL.
    let rfc822_san = SubjectAltName(vec![GeneralName::Rfc822Name(
        Ia5String::new("user@example.test").unwrap(),
    )]);
    assert!(
        set.san_within_permitted_subtrees(&Some(&rfc822_san)),
        "a NULL dNSName bucket must not reject an rfc822 name"
    );

    // A SAN that does present a dNSName is still rejected by the NULL bucket.
    let dns_san = SubjectAltName(vec![GeneralName::DnsName(
        Ia5String::new("host.example.test").unwrap(),
    )]);
    assert!(
        !set.san_within_permitted_subtrees(&Some(&dns_san)),
        "a NULL dNSName bucket must still reject a dNSName"
    );
}

#[cfg(feature = "std")]
#[test]
fn intersection_tests() {
    use crate::path_settings::*;
    let perm = NameConstraintsSettings {
        directory_name: Some(vec!["CN=Joe,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["x@example.com".to_string()]),
        dns_name: Some(vec!["j.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://j.example.com".to_string()]),
        ip_address: Some(vec!["192.168.0.0/16".to_string()]),
        not_supported: None,
    };
    let perm_copy = NameConstraintsSettings {
        directory_name: Some(vec!["CN=Joe,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["x@example.com".to_string()]),
        dns_name: Some(vec!["j.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://j.example.com".to_string()]),
        ip_address: Some(vec!["192.168.0.0/16".to_string()]),
        not_supported: None,
    };
    let perm2 = NameConstraintsSettings {
        directory_name: Some(vec!["CN=Sue,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["y@example.com".to_string()]),
        dns_name: Some(vec!["s.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://s.example.com".to_string()]),
        ip_address: Some(vec!["2.2.2.0/24".to_string()]),
        not_supported: None,
    };
    let perm3 = NameConstraintsSettings {
        directory_name: Some(vec!["CN=Abe,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["z@example.com".to_string()]),
        dns_name: Some(vec!["t.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://t.example.com".to_string()]),
        ip_address: Some(vec!["1.1.0.0/16".to_string()]),
        not_supported: None,
    };

    let perm4 = NameConstraintsSettings {
        directory_name: None,
        rfc822_name: None,
        dns_name: None,
        uniform_resource_identifier: None,
        ip_address: Some(vec!["192.168.0.0/16".to_string()]),
        not_supported: None,
    };
    let perm5 = NameConstraintsSettings {
        directory_name: None,
        rfc822_name: None,
        dns_name: None,
        uniform_resource_identifier: None,
        ip_address: Some(vec!["192.168.0.0/24".to_string()]),
        not_supported: None,
    };
    let perm6 = NameConstraintsSettings {
        directory_name: None,
        rfc822_name: None,
        dns_name: None,
        uniform_resource_identifier: None,
        ip_address: Some(vec!["192.168.0.0/15".to_string()]),
        not_supported: None,
    };

    let mut cps = CertificationPathSettings::default();
    cps.set_initial_permitted_subtrees(perm);
    let mut cps2 = CertificationPathSettings::default();
    cps2.set_initial_permitted_subtrees(perm2);
    let mut cps3 = CertificationPathSettings::default();
    cps3.set_initial_permitted_subtrees(perm3);
    let mut cps4 = CertificationPathSettings::default();
    cps4.set_initial_permitted_subtrees(perm4);
    let mut cps5 = CertificationPathSettings::default();
    cps5.set_initial_permitted_subtrees(perm5);
    let mut cps6 = CertificationPathSettings::default();
    cps6.set_initial_permitted_subtrees(perm6);

    let mut bufs1 = BTreeMap::new();
    let mut perm_set = cps
        .get_initial_permitted_subtrees_as_set(&mut bufs1)
        .unwrap()
        .unwrap();
    let mut bufs1_b = BTreeMap::new();
    let perm_set_b = cps
        .get_initial_permitted_subtrees_with_default_as_set(&mut bufs1_b)
        .unwrap();
    assert_eq!(perm_set, perm_set_b);
    let perm_ncs = cps.get_initial_permitted_subtrees_with_default();
    assert_eq!(perm_ncs, perm_copy);

    let mut bufs2 = BTreeMap::new();
    let perm_set2 = cps2
        .get_initial_permitted_subtrees_as_set(&mut bufs2)
        .unwrap()
        .unwrap();
    let mut bufs2_b = BTreeMap::new();
    let perm_set2_b = cps2
        .get_initial_permitted_subtrees_with_default_as_set(&mut bufs2_b)
        .unwrap();
    assert_eq!(perm_set2, perm_set2_b);
    let mut bufs3 = BTreeMap::new();
    let perm_set3 = cps3
        .get_initial_permitted_subtrees_as_set(&mut bufs3)
        .unwrap()
        .unwrap();
    let mut bufs3_b = BTreeMap::new();
    let perm_set3_b = cps3
        .get_initial_permitted_subtrees_with_default_as_set(&mut bufs3_b)
        .unwrap();
    assert_eq!(perm_set3, perm_set3_b);
    let mut bufs4 = BTreeMap::new();
    let mut perm_set4 = cps4
        .get_initial_permitted_subtrees_as_set(&mut bufs4)
        .unwrap()
        .unwrap();
    let mut bufs4_b = BTreeMap::new();
    let perm_set4_b = cps4
        .get_initial_permitted_subtrees_with_default_as_set(&mut bufs4_b)
        .unwrap();
    assert_eq!(perm_set4, perm_set4_b);
    let mut bufs5 = BTreeMap::new();
    let perm_set5 = cps5
        .get_initial_permitted_subtrees_as_set(&mut bufs5)
        .unwrap()
        .unwrap();
    let mut bufs6 = BTreeMap::new();
    let perm_set6 = cps6
        .get_initial_permitted_subtrees_as_set(&mut bufs6)
        .unwrap()
        .unwrap();

    let perm_roundtrip = name_constraints_set_to_name_constraints_settings(&perm_set).unwrap();
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

        assert_eq!(1, perm_set.ip_address.len());
        perm_set.calculate_union(&perm_set2.ip_address);
        assert_eq!(2, perm_set.ip_address.len());

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

        assert!(!perm_set.ip_address_null);
        perm_set.calculate_intersection(&perm_set2.ip_address);
        assert_eq!(1, perm_set.ip_address.len());
        perm_set.calculate_intersection(&perm_set3.ip_address);
        assert!(perm_set.ip_address_null);

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

        assert!(!perm_set4.ip_address_null);
        perm_set4.calculate_intersection(&perm_set5.ip_address);
        assert_eq!(1, perm_set4.ip_address.len());
        assert_eq!(perm_set4.ip_address, perm_set5.ip_address);

        // intersecting the /24 state with the broader /15 retains the narrower /24
        assert!(!perm_set4.ip_address_null);
        perm_set4.calculate_intersection(&perm_set6.ip_address);
        assert_eq!(1, perm_set4.ip_address.len());
        assert_eq!(perm_set4.ip_address, perm_set5.ip_address);
    }

    let mut cps_set = CertificationPathSettings::default();
    let _ = cps_set.set_initial_permitted_subtrees_from_set(&perm_set3);
    let mut bufs3_c = BTreeMap::new();
    let perm_set3_copy = cps_set
        .get_initial_permitted_subtrees_as_set(&mut bufs3_c)
        .unwrap()
        .unwrap();
    assert_eq!(perm_set3, perm_set3_copy);
}

#[cfg(not(feature = "std"))]
#[test]
fn intersection_tests_no_std() {
    use crate::path_settings::*;
    let perm = NameConstraintsSettings {
        directory_name: Some(vec!["CN=Joe,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["x@example.com".to_string()]),
        dns_name: Some(vec!["j.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://j.example.com".to_string()]),
        ip_address: None,
        not_supported: None,
    };
    let perm_copy = NameConstraintsSettings {
        directory_name: Some(vec!["CN=Joe,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["x@example.com".to_string()]),
        dns_name: Some(vec!["j.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://j.example.com".to_string()]),
        ip_address: None,
        not_supported: None,
    };
    let perm2 = NameConstraintsSettings {
        directory_name: Some(vec!["CN=Sue,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["y@example.com".to_string()]),
        dns_name: Some(vec!["s.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://s.example.com".to_string()]),
        ip_address: None,
        not_supported: None,
    };
    let perm3 = NameConstraintsSettings {
        directory_name: Some(vec!["CN=Abe,OU=Org Unit,O=Org,C=US".to_string()]),
        rfc822_name: Some(vec!["z@example.com".to_string()]),
        dns_name: Some(vec!["t.example.com".to_string()]),
        uniform_resource_identifier: Some(vec!["https://t.example.com".to_string()]),
        ip_address: None,
        not_supported: None,
    };

    let mut cps = CertificationPathSettings::default();
    cps.set_initial_permitted_subtrees(perm);
    let mut cps2 = CertificationPathSettings::default();
    cps2.set_initial_permitted_subtrees(perm2);
    let mut cps3 = CertificationPathSettings::default();
    cps3.set_initial_permitted_subtrees(perm3);

    let mut bufs1 = BTreeMap::new();
    let mut perm_set = cps
        .get_initial_permitted_subtrees_as_set(&mut bufs1)
        .unwrap()
        .unwrap();
    let mut bufs1_b = BTreeMap::new();
    let perm_set_b = cps
        .get_initial_permitted_subtrees_with_default_as_set(&mut bufs1_b)
        .unwrap();
    assert_eq!(perm_set, perm_set_b);
    let perm_ncs = cps.get_initial_permitted_subtrees_with_default();
    assert_eq!(perm_ncs, perm_copy);

    let mut bufs2 = BTreeMap::new();
    let perm_set2 = cps2
        .get_initial_permitted_subtrees_as_set(&mut bufs2)
        .unwrap()
        .unwrap();
    let mut bufs2_b = BTreeMap::new();
    let perm_set2_b = cps2
        .get_initial_permitted_subtrees_with_default_as_set(&mut bufs2_b)
        .unwrap();
    assert_eq!(perm_set2, perm_set2_b);
    let mut bufs3 = BTreeMap::new();
    let perm_set3 = cps3
        .get_initial_permitted_subtrees_as_set(&mut bufs3)
        .unwrap()
        .unwrap();
    let mut bufs3_b = BTreeMap::new();
    let perm_set3_b = cps3
        .get_initial_permitted_subtrees_with_default_as_set(&mut bufs3_b)
        .unwrap();
    assert_eq!(perm_set3, perm_set3_b);

    let perm_roundtrip = name_constraints_set_to_name_constraints_settings(&perm_set).unwrap();
    assert_eq!(perm_roundtrip, perm_copy);

    assert_eq!(1, perm_set.directory_name.len());
    perm_set.calculate_union(&perm_set2.directory_name);
    assert_eq!(2, perm_set.directory_name.len());

    assert!(!perm_set.directory_name_null);
    perm_set.calculate_intersection(&perm_set2.directory_name);
    assert_eq!(1, perm_set.directory_name.len());
    perm_set.calculate_intersection(&perm_set3.directory_name);
    assert!(perm_set.directory_name_null);

    let mut cps_set = CertificationPathSettings::default();
    let _ = cps_set.set_initial_permitted_subtrees_from_set(&perm_set3);
    let mut bufs3_c = BTreeMap::new();
    let perm_set3_copy = cps_set
        .get_initial_permitted_subtrees_as_set(&mut bufs3_c)
        .unwrap()
        .unwrap();
    assert_eq!(perm_set3, perm_set3_copy);
}
