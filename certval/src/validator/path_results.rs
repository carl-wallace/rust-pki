//! Structures and functions related to results from certification path processing operations

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::{vec, vec::Vec};

use der::asn1::ObjectIdentifier;

use pkiprocmacros::*;

use crate::path_settings::*;
use crate::validator::name_constraints_set::NameConstraintsSet;
use crate::Error;
use crate::PathValidationStatus;
use crate::Result;

/// `CertificationPathProcessingTypes` is used to define a variant map with types associated with
/// performing certification path discovery and validation.
#[derive(Clone)]
#[non_exhaustive]
pub enum CertificationPathResultsTypes {
    /// Represents ObjectIdentifierSet values
    ObjectIdentifierSet(ObjectIdentifierSet),
    /// Represents vectors of bools
    Bools(Vec<bool>),
    /// Represents vectors of buffers
    Buffers(Vec<Vec<u8>>),
    /// Represents vectors of vectors of buffers
    ListOfBuffers(Vec<Vec<Vec<u8>>>),
    /// Represents FinalValidPolicyTree value
    FinalValidPolicyTree(FinalValidPolicyTree),
    /// Represents validation result
    PathValidationStatus(PathValidationStatus),
    /// Represents error
    Error(Error),
    /// Represents u32 values
    U32(u32),
    /// Represents a terminal name-constraints working set (permitted or excluded subtrees)
    NameConstraintsSet(NameConstraintsSet),
    /// Represents per-position CRL metadata records ([`CrlInfoLists`]) -- notes which CRLs were
    /// consulted without retaining the CRL bodies
    #[cfg(feature = "revocation")]
    CrlInfoLists(CrlInfoLists),
    /// Represents which source settled each position ([`RevocationSource`])
    RevocationSources(RevocationSources),
}

/// Which source settled a certificate's revocation status.
///
/// The revocation checker consults its sources in a fixed order and stops at the first that answers,
/// so this records the rung that did. It is recorded rather than inferred because the sources do not
/// all leave an artifact behind: a determination served from the status cache examines no revocation
/// data at all, and a stapled response is indistinguishable from a fetched one once both are simply
/// "an OCSP response in the results".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationSource {
    /// Nothing settled this certificate
    None,
    /// A determination reached earlier and still within the validity of the data behind it
    Cache,
    /// The id-pkix-ocsp-nocheck extension, which asks that status not be checked
    NoCheckExtension,
    /// An OCSP response supplied alongside the path
    StapledOcsp,
    /// A CRL supplied alongside the path
    StapledCrl,
    /// A CRL from a CRL source registered on the environment
    LocalCrl,
    /// An OCSP response retrieved from an authority information access URI
    OcspFromAia,
    /// A CRL retrieved from a distribution point
    RemoteCrlDp,
}

/// `CertificationPathResults` is a typedef for a `BTreeMap` that maps arbitrary string values to a
/// variant map. At present, it is the same as CertificationPathSettings (and so macros to generate
/// getters and setters are reused).
#[derive(Clone, Default)]
pub struct CertificationPathResults(pub BTreeMap<&'static str, CertificationPathResultsTypes>);

impl CertificationPathResults {
    /// Creates a new [`CertificationPathResults`]
    pub fn new() -> Self {
        Self(Default::default())
    }
}

/// `PR_PROCESS_EXTENSIONS` is used to retrieve an ObjectIdentifierSet value, i.e., BTreeSet of ObjectIdentifier,
/// from a [`CertificationPathResults`] object. This list is populated as extensions are processed then used
/// to check for unprocessed critical extensions.
pub static PR_PROCESSED_EXTENSIONS: &str = "cprProcessedExtensions";

/// `PR_FINAL_VALID_POLICY_GRAPH` is used to retrieve a FinalValidPolicyGraph value from a [`CertificationPathResults`]
/// object.
pub static PR_FINAL_VALID_POLICY_GRAPH: &str = "cprValidPolicyTree";

/// `PR_VALIDATION_STATUS` is used to retrieve a status code indicating validation result.
pub static PR_VALIDATION_STATUS: &str = "cprValidationStatus";

/// `PR_FAILED_OCSP_REQUESTS` is used to retrieve OCSP requests that did not result in a useful OCSP response, i.e., could not determine status.
pub static PR_FAILED_OCSP_REQUESTS: &str = "cprFailedOcspRequests";
/// `PR_FAILED_OCSP_RESPONSES` is used to retrieve OCSP responses that did not result in a useful OCSP response, i.e., could not determine status.
pub static PR_FAILED_OCSP_RESPONSES: &str = "cprFailedOcspResponses";

/// `PR_OCSP_REQUESTS` is used to retrieve OCSP request(s) used for each item in certification path.
pub static PR_OCSP_REQUESTS: &str = "cprOcspRequests";

/// `PR_OCSP_RESPONSES` is used to retrieve OCSP response(s) used for each item in certification path.
pub static PR_OCSP_RESPONSES: &str = "cprOcspResponses";

/// `PR_OCSP_ENTRY` is used to retrieve OCSP entries used for each item in certification path.
pub static PR_OCSP_ENTRY: &str = "cprOcspEntry";

/// `PR_CRL` is used to retrieve CRL(s) used for each item in certification path.
pub static PR_CRL: &str = "cprCrl";

/// `PR_FAILED_CRLS` is used to retrieve CRLs that did not result in determination of status.
pub static PR_FAILED_CRLS: &str = "cprFailedCrls";

/// `PR_CRL_ENTRY` is used to retrieve CRL entries used for each item in certification path.
pub static PR_CRL_ENTRY: &str = "cprCrlEntry";

/// `PR_BLOCKLIST_USAGE` is used to retrieve indicator of blocklist usage for each item in certification path.
pub static PR_BLOCKLIST_USAGE: &str = "cprBlockListUsage";

/// `PR_ALLOWLIST_USAGE` is used to retrieve indicator of allowlist usage for each item in certification path.
pub static PR_ALLOWLIST_USAGE: &str = "cprAllowListUsage";

/// `PR_NOCHECK_USAGE` is used to retrieve indicator of no check usage for each item in certification path.
pub static PR_NOCHECK_USAGE: &str = "cprNoCheckUsage";

/// `PR_REVOCATION_SOURCE` is used to retrieve which source settled each item in a certification
/// path, as a [`RevocationSource`] per position. See that type for why this is recorded rather than
/// inferred from the artifacts the sources leave behind.
pub static PR_REVOCATION_SOURCE: &str = "cprRevocationSource";

/// `PR_FAILURE_INDEX` is used to retrieve the index of the certificate at which certification path
/// validation or revocation status determination failed. Indexing is trust-anchor-first: 0 denotes
/// the trust anchor, 1 denotes the intermediate CA certificate issued by the trust anchor (if any),
/// and so on through intermediates.len() + 1, which denotes the target certificate. Absent when
/// validation succeeded or when a failure is not attributable to a single certificate.
pub static PR_FAILURE_INDEX: &str = "cprFailureIndex";

/// `PR_FINAL_EXPLICIT_POLICY` is used to retrieve the final value of the explicit_policy state
/// variable from RFC 5280 section 6.1 upon completion of certificate policy processing.
pub static PR_FINAL_EXPLICIT_POLICY: &str = "cprFinalExplicitPolicy";

/// `PR_FINAL_POLICY_MAPPING` is used to retrieve the final value of the policy_mapping state
/// variable from RFC 5280 section 6.1 upon completion of certificate policy processing.
pub static PR_FINAL_POLICY_MAPPING: &str = "cprFinalPolicyMapping";

/// `PR_FINAL_INHIBIT_ANY_POLICY` is used to retrieve the final value of the inhibit_anyPolicy state
/// variable from RFC 5280 section 6.1 upon completion of certificate policy processing.
pub static PR_FINAL_INHIBIT_ANY_POLICY: &str = "cprFinalInhibitAnyPolicy";

/// `PR_FINAL_PERMITTED_SUBTREES` is used to retrieve the terminal permitted_subtrees name-constraints
/// state from RFC 5280 section 6.1 upon completion of name-constraints processing. The stored
/// [`NameConstraintsSet`] preserves the null-vs-empty distinction per form: a `_null` bucket denotes
/// a permitted set that intersected to empty (nothing permitted), distinct from an empty `Vec`
/// (unconstrained). Absent when no name-constraints processing occurred.
pub static PR_FINAL_PERMITTED_SUBTREES: &str = "cprFinalPermittedSubtrees";

/// `PR_FINAL_EXCLUDED_SUBTREES` is used to retrieve the terminal excluded_subtrees name-constraints
/// state from RFC 5280 section 6.1 upon completion of name-constraints processing. The stored
/// [`NameConstraintsSet`] accumulates the union of excluded subtrees across the path. Absent when no
/// name-constraints processing occurred.
pub static PR_FINAL_EXCLUDED_SUBTREES: &str = "cprFinalExcludedSubtrees";

//-----------------------------------------------------------------------------------------------
// Getters/setters for results
//-----------------------------------------------------------------------------------------------
cpr_gets_and_sets_with_default!(PR_PROCESSED_EXTENSIONS, ObjectIdentifierSet, {
    BTreeSet::new()
});
cpr_gets_and_sets!(PR_FINAL_VALID_POLICY_GRAPH, FinalValidPolicyTree);
cpr_gets_and_sets!(PR_VALIDATION_STATUS, PathValidationStatus);
cpr_gets_and_sets!(PR_FAILURE_INDEX, u32);
cpr_gets_and_sets!(PR_FINAL_EXPLICIT_POLICY, u32);
cpr_gets_and_sets!(PR_FINAL_POLICY_MAPPING, u32);
cpr_gets_and_sets!(PR_FINAL_INHIBIT_ANY_POLICY, u32);
cpr_gets_and_sets!(PR_FINAL_PERMITTED_SUBTREES, NameConstraintsSet);
cpr_gets_and_sets!(PR_FINAL_EXCLUDED_SUBTREES, NameConstraintsSet);
cpr_gets_and_sets!(PR_FAILED_OCSP_REQUESTS, ListOfBuffers);
impl CertificationPathResults {
    /// Add a failed OCSP request to list maintained by CertificationPathResults
    pub fn add_failed_ocsp_request(&mut self, req: Vec<u8>, pos: usize) {
        let mut v: ListOfBuffers = if let Some(v) = self.get_failed_ocsp_requests() {
            v
        } else {
            return;
        };
        if v.len() > pos {
            v[pos].push(req);
        }
        self.set_failed_ocsp_requests(v);
    }
}
cpr_gets_and_sets!(PR_FAILED_OCSP_RESPONSES, ListOfBuffers);
impl CertificationPathResults {
    /// Add a failed OCSP response to list maintained by CertificationPathResults
    pub fn add_failed_ocsp_response(&mut self, resp: Vec<u8>, pos: usize) {
        let mut v: ListOfBuffers = if let Some(v) = self.get_failed_ocsp_responses() {
            v
        } else {
            return;
        };
        if v.len() > pos {
            v[pos].push(resp);
        }
        self.set_failed_ocsp_responses(v);
    }
}

#[cfg(feature = "revocation")]
cpr_gets_and_sets!(PR_FAILED_CRLS, CrlInfoLists);
#[cfg(feature = "revocation")]
impl CertificationPathResults {
    /// Notes a CRL that was consulted but did not yield a status determination (i.e., was discarded
    /// as incompatible, stale, or otherwise unusable). Only the compact
    /// [`CrlInfo`](crate::revocation::crl::CrlInfo) metadata is
    /// retained, not the (potentially very large) CRL body.
    pub fn add_failed_crl(&mut self, crl: crate::revocation::crl::CrlInfo, pos: usize) {
        let mut v: CrlInfoLists = if let Some(v) = self.get_failed_crls() {
            v
        } else {
            return;
        };
        if v.len() > pos {
            v[pos].push(crl);
        }
        self.set_failed_crls(v);
    }
}

#[cfg(feature = "revocation")]
cpr_gets_and_sets!(PR_CRL, CrlInfoLists);
#[cfg(feature = "revocation")]
impl CertificationPathResults {
    /// Notes a CRL that contributed to a revocation status determination (valid or revoked). Only
    /// the compact [`CrlInfo`](crate::revocation::crl::CrlInfo) metadata is retained, not the CRL
    /// body; the metadata carries a
    /// [`CrlInfo::uri`](crate::revocation::crl::CrlInfo::uri) clue for where the full CRL was obtained.
    pub fn add_crl(&mut self, crl: crate::revocation::crl::CrlInfo, pos: usize) {
        let mut v: CrlInfoLists = if let Some(v) = self.get_crl() {
            v
        } else {
            return;
        };
        if v.len() > pos {
            v[pos].push(crl);
        }
        self.set_crl(v);
    }
}

cpr_gets_and_sets!(PR_CRL_ENTRY, ListOfBuffers);
impl CertificationPathResults {
    /// Add a failed OCSP request to list maintained by CertificationPathResults
    pub fn add_crl_entry(&mut self, crl_entry: Vec<u8>, pos: usize) {
        let mut v: ListOfBuffers = if let Some(v) = self.get_crl_entry() {
            v
        } else {
            return;
        };
        if v.len() > pos {
            v[pos].push(crl_entry);
        }
        self.set_crl_entry(v);
    }
}

cpr_gets_and_sets!(PR_OCSP_REQUESTS, ListOfBuffers);
impl CertificationPathResults {
    /// Add a failed OCSP request to list maintained by CertificationPathResults
    pub fn add_ocsp_request(&mut self, req: Vec<u8>, pos: usize) {
        let mut v: ListOfBuffers = if let Some(v) = self.get_ocsp_requests() {
            v
        } else {
            return;
        };
        if v.len() > pos {
            v[pos].push(req);
        }
        self.set_ocsp_requests(v);
    }
}

cpr_gets_and_sets!(PR_OCSP_RESPONSES, ListOfBuffers);
impl CertificationPathResults {
    /// Add a failed OCSP request to list maintained by CertificationPathResults
    pub fn add_ocsp_response(&mut self, req: Vec<u8>, pos: usize) {
        let mut v: ListOfBuffers = if let Some(v) = self.get_ocsp_responses() {
            v
        } else {
            return;
        };
        if v.len() > pos {
            v[pos].push(req);
        }
        self.set_ocsp_responses(v);
    }
}

cpr_gets_and_sets!(PR_OCSP_ENTRY, ListOfBuffers);
impl CertificationPathResults {
    /// Add a failed OCSP request to list maintained by CertificationPathResults
    pub fn add_ocsp_entry(&mut self, req: Vec<u8>, pos: usize) {
        let mut v: ListOfBuffers = if let Some(v) = self.get_ocsp_entry() {
            v
        } else {
            return;
        };
        if v.len() > pos {
            v[pos].push(req);
        }
        self.set_ocsp_entry(v);
    }
}

cpr_gets_and_sets!(PR_BLOCKLIST_USAGE, Bools);
impl CertificationPathResults {
    /// Add a failed OCSP request to list maintained by CertificationPathResults
    pub fn set_blocklist_usage_for_item(&mut self, pos: usize) {
        let mut v: Vec<bool> = if let Some(v) = self.get_blocklist_usage() {
            v
        } else {
            return;
        };
        if v.len() > pos {
            v[pos] = true;
        }
        self.set_blocklist_usage(v);
    }
}

cpr_gets_and_sets!(PR_ALLOWLIST_USAGE, Bools);
impl CertificationPathResults {
    /// Add a failed OCSP request to list maintained by CertificationPathResults
    pub fn set_allowlist_usage_for_item(&mut self, pos: usize) {
        let mut v: Vec<bool> = if let Some(v) = self.get_allowlist_usage() {
            v
        } else {
            return;
        };
        if v.len() > pos {
            v[pos] = true;
        }
        self.set_allowlist_usage(v);
    }
}

cpr_gets_and_sets!(PR_NOCHECK_USAGE, Bools);
cpr_gets_and_sets!(PR_REVOCATION_SOURCE, RevocationSources);
impl CertificationPathResults {
    /// Add a failed OCSP request to list maintained by CertificationPathResults
    pub fn set_nocheck_for_item(&mut self, pos: usize) {
        let mut v: Vec<bool> = if let Some(v) = self.get_nocheck_usage() {
            v
        } else {
            return;
        };
        if v.len() > pos {
            v[pos] = true;
        }
        self.set_nocheck_usage(v);
    }

    /// Records which source settled the certificate at `pos`. The first source to answer wins, so
    /// this is written once per position and later sources never reach it.
    pub fn set_revocation_source_for_item(&mut self, pos: usize, source: RevocationSource) {
        let Some(mut v) = self.get_revocation_source() else {
            return;
        };
        if v.len() > pos {
            v[pos] = source;
            self.set_revocation_source(v);
        }
    }

    /// `prepare_revocation_results` takes the number of certificates in a certification path (not
    /// counting the trust anchor) and prepares the revocation-related results variables in this
    /// [`CertificationPathResults`], sized to that capacity.
    pub fn prepare_revocation_results(&mut self, num_certs: usize) -> Result<()> {
        self.set_nocheck_usage(vec![false; num_certs]);
        self.set_revocation_source(vec![RevocationSource::None; num_certs]);
        self.set_blocklist_usage(vec![false; num_certs]);
        self.set_allowlist_usage(vec![false; num_certs]);
        self.set_ocsp_requests(vec![vec![]; num_certs]);
        self.set_ocsp_responses(vec![vec![]; num_certs]);
        self.set_failed_ocsp_requests(vec![vec![]; num_certs]);
        self.set_failed_ocsp_responses(vec![vec![]; num_certs]);
        #[cfg(feature = "revocation")]
        self.set_failed_crls(vec![vec![]; num_certs]);
        self.set_ocsp_entry(vec![vec![]; num_certs]);
        #[cfg(feature = "revocation")]
        self.set_crl(vec![vec![]; num_certs]);
        self.set_crl_entry(vec![vec![]; num_certs]);
        Ok(())
    }

    /// `add_processed_extension` retrieves (or adds then retrieves) this
    /// [`CertificationPathResults`] entry for [`PR_PROCESSED_EXTENSIONS`], to which the oid is added
    /// if not already present.
    pub(crate) fn add_processed_extension(&mut self, oid: ObjectIdentifier) {
        let mut oids = self.get_processed_extensions();
        if !oids.contains(&oid) {
            oids.insert(oid);
            self.set_processed_extensions(oids);
        }
    }
}

#[test]
fn check_prepared_results() {
    let mut cpr = CertificationPathResults::default();
    assert!(cpr.prepare_revocation_results(4).is_ok());
    assert_eq!(4, cpr.get_nocheck_usage().unwrap().len());
    assert_eq!(4, cpr.get_blocklist_usage().unwrap().len());
    assert_eq!(4, cpr.get_allowlist_usage().unwrap().len());
    assert_eq!(4, cpr.get_ocsp_requests().unwrap().len());
    assert_eq!(4, cpr.get_ocsp_responses().unwrap().len());
    assert_eq!(4, cpr.get_failed_ocsp_requests().unwrap().len());
    assert_eq!(4, cpr.get_failed_ocsp_responses().unwrap().len());
    #[cfg(feature = "revocation")]
    assert_eq!(4, cpr.get_failed_crls().unwrap().len());
    assert_eq!(4, cpr.get_ocsp_entry().unwrap().len());
    #[cfg(feature = "revocation")]
    assert_eq!(4, cpr.get_crl().unwrap().len());
    assert_eq!(4, cpr.get_crl_entry().unwrap().len());

    let mut cpr = CertificationPathResults::default();
    assert!(cpr.prepare_revocation_results(0).is_ok());
    assert_eq!(0, cpr.get_nocheck_usage().unwrap().len());
    assert_eq!(0, cpr.get_blocklist_usage().unwrap().len());
    assert_eq!(0, cpr.get_allowlist_usage().unwrap().len());
    assert_eq!(0, cpr.get_ocsp_requests().unwrap().len());
    assert_eq!(0, cpr.get_ocsp_responses().unwrap().len());
    assert_eq!(0, cpr.get_failed_ocsp_requests().unwrap().len());
    assert_eq!(0, cpr.get_failed_ocsp_responses().unwrap().len());
    #[cfg(feature = "revocation")]
    assert_eq!(0, cpr.get_failed_crls().unwrap().len());
    assert_eq!(0, cpr.get_ocsp_entry().unwrap().len());
    #[cfg(feature = "revocation")]
    assert_eq!(0, cpr.get_crl().unwrap().len());
    assert_eq!(0, cpr.get_crl_entry().unwrap().len());
}
