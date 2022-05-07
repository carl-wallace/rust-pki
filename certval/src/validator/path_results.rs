//! Structures and functions related to results from certification path processing operations

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::{vec, vec::Vec};

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
pub type CertificationPathResults<'a> = BTreeMap<&'a str, CertificationPathResultsTypes>;

/// `PR_PROCESS_EXTENSIONS` is used to retrieve an ObjectIdentifierSet value, i.e., BTreeSet of ObjectIdentifier,
/// from a [`CertificationPathResults`] object. This list is populated as extensions are processed then used
/// to check for unprocessed critical extensions.
pub static PR_PROCESSED_EXTENSIONS: &str = "cprProcessedExtensions";

/// `PR_FINAL_VALID_POLICY_TREE` is used to retrieve a FinalValidPolicyTree value from a [`CertificationPathResults`]
/// object.
pub static PR_FINAL_VALID_POLICY_TREE: &str = "cprValidPolicyTree";

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
cpr_gets_and_sets!(PR_VALIDATION_STATUS, PathValidationStatus);
cpr_gets_and_sets!(PR_FAILED_OCSP_REQUESTS, ListOfBuffers);
/// Add a failed OCSP request to list maintained by CertificationPathResults
pub fn add_failed_ocsp_request(cpr: &mut CertificationPathResults<'_>, req: Vec<u8>, pos: usize) {
    let mut v: ListOfBuffers = if let Some(v) = get_failed_ocsp_requests(cpr) {
        v
    } else {
        return;
    };
    if v.len() > pos {
        v[pos].push(req);
    }
    set_failed_ocsp_requests(cpr, v);
}
cpr_gets_and_sets!(PR_FAILED_OCSP_RESPONSES, ListOfBuffers);
/// Add a failed OCSP response to list maintained by CertificationPathResults
pub fn add_failed_ocsp_response(cpr: &mut CertificationPathResults<'_>, resp: Vec<u8>, pos: usize) {
    let mut v: ListOfBuffers = if let Some(v) = get_failed_ocsp_responses(cpr) {
        v
    } else {
        return;
    };
    if v.len() > pos {
        v[pos].push(resp);
    }
    set_failed_ocsp_responses(cpr, v);
}

cpr_gets_and_sets!(PR_FAILED_CRLS, ListOfBuffers);
/// Add a failed OCSP response to list maintained by CertificationPathResults
pub fn add_failed_crl(cpr: &mut CertificationPathResults<'_>, crl: &[u8], pos: usize) {
    let mut v: ListOfBuffers = if let Some(v) = get_failed_crls(cpr) {
        v
    } else {
        return;
    };
    if v.len() > pos {
        v[pos].push(crl.to_vec());
    }
    set_failed_crls(cpr, v);
}
//TODO use Vec<CrlInfo> instead?
cpr_gets_and_sets!(PR_CRL, ListOfBuffers);
/// Add a failed OCSP request to list maintained by CertificationPathResults
pub fn add_crl(cpr: &mut CertificationPathResults<'_>, crl: &[u8], pos: usize) {
    let mut v: ListOfBuffers = if let Some(v) = get_crl(cpr) {
        v
    } else {
        return;
    };
    if v.len() > pos {
        v[pos].push(crl.to_vec());
    }
    set_crl(cpr, v);
}

cpr_gets_and_sets!(PR_CRL_ENTRY, ListOfBuffers);
/// Add a failed OCSP request to list maintained by CertificationPathResults
pub fn add_crl_entry(cpr: &mut CertificationPathResults<'_>, crl_entry: Vec<u8>, pos: usize) {
    let mut v: ListOfBuffers = if let Some(v) = get_crl_entry(cpr) {
        v
    } else {
        return;
    };
    if v.len() > pos {
        v[pos].push(crl_entry);
    }
    set_crl_entry(cpr, v);
}

cpr_gets_and_sets!(PR_OCSP_REQUESTS, ListOfBuffers);
/// Add a failed OCSP request to list maintained by CertificationPathResults
pub fn add_ocsp_request(cpr: &mut CertificationPathResults<'_>, req: Vec<u8>, pos: usize) {
    let mut v: ListOfBuffers = if let Some(v) = get_ocsp_requests(cpr) {
        v
    } else {
        return;
    };
    if v.len() > pos {
        v[pos].push(req);
    }
    set_ocsp_requests(cpr, v);
}

cpr_gets_and_sets!(PR_OCSP_RESPONSES, ListOfBuffers);
/// Add a failed OCSP request to list maintained by CertificationPathResults
pub fn add_ocsp_response(cpr: &mut CertificationPathResults<'_>, req: Vec<u8>, pos: usize) {
    let mut v: ListOfBuffers = if let Some(v) = get_ocsp_responses(cpr) {
        v
    } else {
        return;
    };
    if v.len() > pos {
        v[pos].push(req);
    }
    set_ocsp_responses(cpr, v);
}

cpr_gets_and_sets!(PR_OCSP_ENTRY, ListOfBuffers);
/// Add a failed OCSP request to list maintained by CertificationPathResults
pub fn add_ocsp_entry(cpr: &mut CertificationPathResults<'_>, req: Vec<u8>, pos: usize) {
    let mut v: ListOfBuffers = if let Some(v) = get_ocsp_entry(cpr) {
        v
    } else {
        return;
    };
    if v.len() > pos {
        v[pos].push(req);
    }
    set_ocsp_entry(cpr, v);
}

cpr_gets_and_sets!(PR_BLOCKLIST_USAGE, Bools);
/// Add a failed OCSP request to list maintained by CertificationPathResults
pub fn set_blocklist_usage_for_item(cpr: &mut CertificationPathResults<'_>, pos: usize) {
    let mut v: Vec<bool> = if let Some(v) = get_blocklist_usage(cpr) {
        v
    } else {
        return;
    };
    if v.len() > pos {
        v[pos] = true;
    }
    set_blocklist_usage(cpr, v);
}

cpr_gets_and_sets!(PR_ALLOWLIST_USAGE, Bools);
/// Add a failed OCSP request to list maintained by CertificationPathResults
pub fn set_allowlist_usage_for_item(cpr: &mut CertificationPathResults<'_>, pos: usize) {
    let mut v: Vec<bool> = if let Some(v) = get_allowlist_usage(cpr) {
        v
    } else {
        return;
    };
    if v.len() > pos {
        v[pos] = true;
    }
    set_allowlist_usage(cpr, v);
}

cpr_gets_and_sets!(PR_NOCHECK_USAGE, Bools);
/// Add a failed OCSP request to list maintained by CertificationPathResults
pub fn set_nocheck_for_item(cpr: &mut CertificationPathResults<'_>, pos: usize) {
    let mut v: Vec<bool> = if let Some(v) = get_nocheck_usage(cpr) {
        v
    } else {
        return;
    };
    if v.len() > pos {
        v[pos] = true;
    }
    set_nocheck_usage(cpr, v);
}

/// prepare_revocation_results takes a CertificationPathResults and the number of certificates in a certification
/// path (not counting the trust anchor). It prepares results variables set to appropriate capacity to receive
/// revocation-related results.
pub fn prepare_revocation_results(
    cpr: &mut CertificationPathResults<'_>,
    num_certs: usize,
) -> Result<()> {
    set_nocheck_usage(cpr, vec![false; num_certs]);
    set_blocklist_usage(cpr, vec![false; num_certs]);
    set_allowlist_usage(cpr, vec![false; num_certs]);
    set_ocsp_requests(cpr, vec![vec![]; num_certs]);
    set_ocsp_responses(cpr, vec![vec![]; num_certs]);
    set_failed_ocsp_requests(cpr, vec![vec![]; num_certs]);
    set_failed_ocsp_responses(cpr, vec![vec![]; num_certs]);
    set_failed_crls(cpr, vec![vec![]; num_certs]);
    set_ocsp_entry(cpr, vec![vec![]; num_certs]);
    set_crl(cpr, vec![vec![]; num_certs]);
    set_crl_entry(cpr, vec![vec![]; num_certs]);
    Ok(())
}

#[test]
fn check_prepared_results() {
    let mut cpr = CertificationPathResults::default();
    assert!(prepare_revocation_results(&mut cpr, 4).is_ok());
    assert_eq!(4, get_nocheck_usage(&cpr).unwrap().len());
    assert_eq!(4, get_blocklist_usage(&cpr).unwrap().len());
    assert_eq!(4, get_allowlist_usage(&cpr).unwrap().len());
    assert_eq!(4, get_ocsp_requests(&cpr).unwrap().len());
    assert_eq!(4, get_ocsp_responses(&cpr).unwrap().len());
    assert_eq!(4, get_failed_ocsp_requests(&cpr).unwrap().len());
    assert_eq!(4, get_failed_ocsp_responses(&cpr).unwrap().len());
    assert_eq!(4, get_failed_crls(&cpr).unwrap().len());
    assert_eq!(4, get_ocsp_entry(&cpr).unwrap().len());
    assert_eq!(4, get_crl(&cpr).unwrap().len());
    assert_eq!(4, get_crl_entry(&cpr).unwrap().len());

    let mut cpr = CertificationPathResults::default();
    assert!(prepare_revocation_results(&mut cpr, 0).is_ok());
    assert_eq!(0, get_nocheck_usage(&cpr).unwrap().len());
    assert_eq!(0, get_blocklist_usage(&cpr).unwrap().len());
    assert_eq!(0, get_allowlist_usage(&cpr).unwrap().len());
    assert_eq!(0, get_ocsp_requests(&cpr).unwrap().len());
    assert_eq!(0, get_ocsp_responses(&cpr).unwrap().len());
    assert_eq!(0, get_failed_ocsp_requests(&cpr).unwrap().len());
    assert_eq!(0, get_failed_ocsp_responses(&cpr).unwrap().len());
    assert_eq!(0, get_failed_crls(&cpr).unwrap().len());
    assert_eq!(0, get_ocsp_entry(&cpr).unwrap().len());
    assert_eq!(0, get_crl(&cpr).unwrap().len());
    assert_eq!(0, get_crl_entry(&cpr).unwrap().len());
}
