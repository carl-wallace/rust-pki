//! Structures and functions related to results from certification path processing operations

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::{vec, vec::Vec};

use der::asn1::ObjectIdentifier;

use pkiprocmacros::*;

use crate::path_settings::*;
use crate::Error;
use crate::PathValidationStatus;
use crate::Result;

/// `CertificationPathProcessingTypes` is used to define a variant map with types associated with
/// performing certification path discovery and validation.
#[derive(Clone)]
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

/// `PR_FINAL_VALID_POLICY_TREE` is used to retrieve a FinalValidPolicyTree value from a [`CertificationPathResults`]
/// object.
pub static PR_FINAL_VALID_POLICY_TREE: &str = "cprValidPolicyTree";

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

//-----------------------------------------------------------------------------------------------
// Getters/setters for results
//-----------------------------------------------------------------------------------------------
cpr_gets_and_sets_with_default!(PR_PROCESSED_EXTENSIONS, ObjectIdentifierSet, {
    BTreeSet::new()
});
cpr_gets_and_sets!(PR_FINAL_VALID_POLICY_TREE, FinalValidPolicyTree);
cpr_gets_and_sets!(PR_FINAL_VALID_POLICY_GRAPH, FinalValidPolicyTree);
cpr_gets_and_sets!(PR_VALIDATION_STATUS, PathValidationStatus);
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

cpr_gets_and_sets!(PR_FAILED_CRLS, ListOfBuffers);
impl CertificationPathResults {
    /// Add a failed OCSP response to list maintained by CertificationPathResults
    pub fn add_failed_crl(&mut self, crl: &[u8], pos: usize) {
        let mut v: ListOfBuffers = if let Some(v) = self.get_failed_crls() {
            v
        } else {
            return;
        };
        if v.len() > pos {
            v[pos].push(crl.to_vec());
        }
        self.set_failed_crls(v);
    }
}

//TODO use Vec<CrlInfo> instead?
cpr_gets_and_sets!(PR_CRL, ListOfBuffers);
impl CertificationPathResults {
    /// Add a failed OCSP request to list maintained by CertificationPathResults
    pub fn add_crl(&mut self, crl: &[u8], pos: usize) {
        let mut v: ListOfBuffers = if let Some(v) = self.get_crl() {
            v
        } else {
            return;
        };
        if v.len() > pos {
            v[pos].push(crl.to_vec());
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

    /// prepare_revocation_results takes a CertificationPathResults and the number of certificates in a certification
    /// path (not counting the trust anchor). It prepares results variables set to appropriate capacity to receive
    /// revocation-related results.
    pub fn prepare_revocation_results(&mut self, num_certs: usize) -> Result<()> {
        self.set_nocheck_usage(vec![false; num_certs]);
        self.set_blocklist_usage(vec![false; num_certs]);
        self.set_allowlist_usage(vec![false; num_certs]);
        self.set_ocsp_requests(vec![vec![]; num_certs]);
        self.set_ocsp_responses(vec![vec![]; num_certs]);
        self.set_failed_ocsp_requests(vec![vec![]; num_certs]);
        self.set_failed_ocsp_responses(vec![vec![]; num_certs]);
        self.set_failed_crls(vec![vec![]; num_certs]);
        self.set_ocsp_entry(vec![vec![]; num_certs]);
        self.set_crl(vec![vec![]; num_certs]);
        self.set_crl_entry(vec![vec![]; num_certs]);
        Ok(())
    }

    /// `add_processed_extension` takes a [`CertificationPathResults`] and retrieves (or adds then retrieves)
    /// an entry for [`PR_PROCESSED_EXTENSIONS`] to which the oid is added if not already present.
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
    assert_eq!(4, cpr.get_failed_crls().unwrap().len());
    assert_eq!(4, cpr.get_ocsp_entry().unwrap().len());
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
    assert_eq!(0, cpr.get_failed_crls().unwrap().len());
    assert_eq!(0, cpr.get_ocsp_entry().unwrap().len());
    assert_eq!(0, cpr.get_crl().unwrap().len());
    assert_eq!(0, cpr.get_crl_entry().unwrap().len());
}
