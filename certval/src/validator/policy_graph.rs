//! Policy graph-based certificate policy processing

use crate::alloc::borrow::ToOwned;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::{vec, vec::Vec};
use core::cell::RefCell;
use core::ops::Deref;

use crate::{
    environment::pki_environment::*, path_results::*, path_settings::*, pdv_extension::*,
    util::error::*, util::pdv_utilities::*, validator::policy_utilities::*, CertificationPath,
};
use const_oid::db::rfc5280::ANY_POLICY;
use const_oid::db::rfc5912::*;
use der::{asn1::ObjectIdentifier, Encode};

/// `check_certificate_policies_graph` implements certificate policy processing per draft-davidben-x509-policy-graph-01.
///
/// It references the following certificate extensions:
/// - ID_CE_CERTIFICATE_POLICIES,
/// - ID_CE_POLICY_MAPPINGS,
/// - ID_CE_POLICY_CONSTRAINTS,
/// - ID_CE_INHIBIT_ANY_POLICY
///
/// It references the following values in the [`CertificationPathSettings`] parameter:
/// - PS_INITIAL_EXPLICIT_POLICY_INDICATOR,
/// - PS_INITIAL_POLICY_MAPPING_INHIBIT_INDICATOR,
/// - PS_INITIAL_INHIBIT_ANY_POLICY_INDICATOR,
/// - PS_INITIAL_POLICY_SET.
///
/// It contributes to the PR_PROCESSED_EXTENSION value and PR_FINAL_VALID_POLICY_GRAPH value of the
/// CertificationPathResults instance.
///
/// This function does not process certificate policy information conveyed in a trust anchor and assumes
/// that if such processing is desired the information has already been factored into the [`CertificationPathSettings`]
/// as per RFC 5937 and as provided for in [`enforce_trust_anchor_constraints`].
pub fn check_certificate_policies_graph(
    _pe: &PkiEnvironment<'_>,
    cps: &CertificationPathSettings,
    cp: &mut CertificationPath<'_>,
    cpr: &mut CertificationPathResults<'_>,
) -> Result<()> {
    add_processed_extension(cpr, ID_CE_CERTIFICATE_POLICIES);
    add_processed_extension(cpr, ID_CE_INHIBIT_ANY_POLICY);
    add_processed_extension(cpr, ID_CE_POLICY_CONSTRAINTS);
    add_processed_extension(cpr, ID_CE_POLICY_MAPPINGS);

    let certs_in_cert_path: u32 = (cp.intermediates.len() + 1) as u32;
    // vector to own nodes that appear in the valid_policy_tree
    let pool = RefCell::new(PolicyPool::new());
    let pm = &mut pool.borrow_mut();

    // Harvest the relevant settings from the path settings object ( RFC5280 6.1.1 c, e, f and g)
    let initial_policy_set: ObjectIdentifierSet = get_initial_policy_set_as_oid_set(cps);
    let initial_policy_mapping_inhibit_indicator: bool =
        get_initial_policy_mapping_inhibit_indicator(cps);
    let initial_explicit_policy_indicator: bool = get_initial_explicit_policy_indicator(cps);
    let initial_inhibit_any_policy_indicator: bool = get_initial_inhibit_any_policy_indicator(cps);

    // Initialize state variables (RFC 6.1.2 a, d, e, and f)
    let mut valid_policy_graph = Vec::<PolicyTreeRow<'_>>::new();
    let mut explicit_policy: u32 = if let true = initial_explicit_policy_indicator {
        0
    } else {
        certs_in_cert_path + 1
    };
    let mut inhibit_any_policy: u32 = if let true = initial_inhibit_any_policy_indicator {
        0
    } else {
        certs_in_cert_path + 1
    };
    let mut policy_mapping: u32 = if let true = initial_policy_mapping_inhibit_indicator {
        0
    } else {
        certs_in_cert_path + 1
    };

    // Create first node per 6.1.2.a:
    // The initial value of the valid_policy_graph is a single node
    // with valid_policy anyPolicy, an empty qualifier_set, and an
    // expected_policy_set with the single value anyPolicy. This node
    // is considered to be at depth zero.
    let root_index = make_new_policy_node_add_to_pool2(
        pm,
        ANY_POLICY,
        &None,
        BTreeSet::from([ANY_POLICY]),
        0,
        &None,
    )?;
    let pol_tree_row = PolicyTreeRow::from([root_index]);
    valid_policy_graph.push(pol_tree_row);
    let mut valid_policy_graph_is_null = false;

    // for convenience, combine target into array with the intermediate CA certs
    let mut v = cp.intermediates.clone();
    v.push(cp.target);

    // Iterate over the list of intermediate CA certificates (target cert will be processed below loop)
    //for (pos, ca_cert) in cp.intermediates.iter_mut().enumerate() {
    for (pos, ca_cert_ref) in v.iter().enumerate() {
        let ca_cert = ca_cert_ref.deref();
        // save pos in variable named i starting from 1 (to account for root node not being in this loop)
        // to make reading spec language easier
        let i = pos + 1;

        // has_any_policy is used to signify when anyPolicy appears in a cert. any_policy_qualifiers
        // captures the encoded qualifiers, if present.
        let mut has_any_policy = false;
        let mut ap_q: Option<Vec<u8>> = None;

        let new_row = PolicyTreeRow::new();
        valid_policy_graph.push(new_row);
        let row = valid_policy_graph.len() - 1;

        if !valid_policy_graph_is_null {
            if let Some(PDVExtension::CertificatePolicies(cps_from_ext)) =
                ca_cert.get_extension(&ID_CE_CERTIFICATE_POLICIES)?
            {
                // (d) If the certificate policies extension is present in the
                // certificate and the valid_policy_graph is not NULL, process the
                // policy information by performing the following steps in order:
                for cp in &cps_from_ext.0 {
                    if ANY_POLICY != cp.policy_identifier {
                        //(1)  For each policy P not equal to anyPolicy in the
                        // certificate policies extension, let P-OID denote the OID
                        // for policy P and P-Q denote the qualifier set for policy P.
                        // Perform the following steps in order:
                        let p_oid = &cp.policy_identifier;
                        let mut p_q: Option<Vec<u8>> = None;
                        if cp.policy_qualifiers.is_some() {
                            p_q = match cp.policy_qualifiers.to_der() {
                                Ok(encoded_qualifers) => Some(encoded_qualifers),
                                // ignore qualifiers that don't encode
                                Err(_e) => None,
                            };
                        }

                        // for i and ii, save the indices of any parents and add the nodes below to avoid
                        // mutable borrow inside the loop for step i.

                        // (i)  Let parent_nodes be the nodes at depth i-1 in the
                        // valid_policy_graph where P-OID is in the
                        // expected_policy_set. If parent_nodes is not empty,
                        // create a child node as follows: set the
                        // valid_policy to P-OID, set the qualifier_set to P-Q,
                        // set the expected_policy_set to {P-OID}, and set
                        // the parent nodes to parent_nodes.
                        let mut parent_nodes = PolicyTreeRow::new();
                        let mut match_found = false;
                        for ps_index in &valid_policy_graph[i - 1] {
                            let ps = &pm[*ps_index];
                            if ps.expected_policy_set.contains(p_oid) {
                                parent_nodes.push(*ps_index);
                                match_found = true;
                            }
                        }

                        // (ii)  If there was no match in step (i) and the valid_policy_graph
                        // includes a node of depth i-1 with the valid_policy anyPolicy, generate
                        // a child node with the following values: set the valid_policy to P-OID,
                        // set the qualifier_set to P-Q, set the expected_policy_set to {P-OID},
                        // and set the parent node to the anyPolicy node at depth i-1.
                        if !match_found {
                            if let Some(parent_index) = policy_tree_row_contains_policy(
                                pm,
                                &valid_policy_graph[i - 1],
                                ANY_POLICY,
                            ) {
                                parent_nodes.push(parent_index);
                            }
                        }

                        // add the items as per i and ii, if there is anything to add. parent_nodes
                        // will be empty, contain 1 or more parents or contain a single anyPolicy parent
                        if !parent_nodes.is_empty() {
                            let new_node_index = make_new_policy_node_add_to_pool2_graph(
                                pm,
                                *p_oid,
                                &p_q,
                                ObjectIdentifierSet::from([*p_oid]),
                                row as u8,
                                parent_nodes,
                            )?;
                            valid_policy_graph[row].push(new_node_index);
                        }
                    } else {
                        //save indication that anyPolicy was observed along with qualifiers, if present, for
                        //use when processing step (2) below.
                        has_any_policy = true;
                        if cp.policy_qualifiers.is_some() {
                            ap_q = match cp.policy_qualifiers.to_der() {
                                Ok(encoded_qualifers) => Some(encoded_qualifers),
                                // ignore qualifiers that don't encode
                                Err(_e) => None,
                            }
                        }
                    }
                }

                let mut nodes_to_add = vec![];
                let mut parent_nodes = BTreeMap::<ObjectIdentifier, Vec<usize>>::new();

                // (2)  If the certificate policies extension includes the policy
                // anyPolicy with the qualifier set AP-Q and either (a)
                // inhibit_anyPolicy is greater than 0 or (b) i<n and the
                // certificate is self-issued, then:
                // no need to check i < n since this loop is for intermediate CAs only (so we are not at the target)
                if has_any_policy
                    && (inhibit_any_policy > 0
                        || (i < certs_in_cert_path as usize
                            && is_self_issued(&ca_cert.decoded_cert)))
                {
                    for p_index in &valid_policy_graph[i - 1] {
                        // For each policy OID P-OID (including anyPolicy) which
                        // appears in the expected_policy_set of some node in the
                        // valid_policy_graph for depth i-1, if P-OID does not
                        // appear as the valid_policy of some node at depth i,
                        // create a single child node with the following values: set
                        // the valid_policy to P-OID, set the qualifier_set to AP-Q,
                        // set the expected_policy_set to {P-OID}, and set the
                        // parents to the nodes at depth i-1 where P-OID appears in
                        // expected_policy_set.
                        let parent = &pm[*p_index];
                        for ep in &parent.expected_policy_set {
                            if !has_child_node(pm, &parent.children, ep) {
                                if parent_nodes.contains_key(ep) {
                                    if let Some(val) = parent_nodes.get_mut(ep) {
                                        val.push(*p_index)
                                    }
                                } else {
                                    parent_nodes.insert(*ep, vec![*p_index]);
                                }
                            }
                        }
                    }
                    for p in &parent_nodes {
                        let new_node = make_new_policy_node_graph(
                            *p.0,
                            &ap_q,
                            BTreeSet::from([*p.0]),
                            row as u8,
                            p.1,
                        )?;
                        nodes_to_add.push(new_node);
                    }
                }

                for node in nodes_to_add {
                    let node_index = pm.len();
                    let valid_policy = node.valid_policy;
                    pm.push(node);
                    for p in &parent_nodes[&valid_policy] {
                        let parent = &pm[*p];
                        add_child_if_not_present(pm, &parent.children, node_index);
                    }
                    valid_policy_graph[i].push(node_index);
                }

                for r in &mut valid_policy_graph[0..i] {
                    // (3)  If there is a node in the valid_policy_tree of depth i-1
                    //       or less without any child nodes, delete that node.  Repeat
                    //       this step until there are no nodes of depth i-1 or less
                    //       without children.
                    //
                    //       For example, consider the valid_policy_tree shown in
                    //       Figure 7 below.  The two nodes at depth i-1 that are
                    //       marked with an 'X' have no children, and they are deleted.
                    //       Applying this rule to the resulting tree will cause the
                    //       node at depth i-2 that is marked with a 'Y' to be deleted.
                    //       In the resulting tree, there are no nodes of depth i-1 or
                    //       less without children, and this step is complete.
                    r.retain(|x| !num_kids_is_zero(pm, *x));
                }
                if valid_policy_graph[i].is_empty() {
                    valid_policy_graph_is_null = true;
                }
            } else {
                //(e)  If the certificate policies extension is not present, set the
                // valid_policy_graph to NULL.
                valid_policy_graph_is_null = true;
            }
        } else {
            // this else or the one immediately above can go away when let chains are available
            //(e)  If the certificate policies extension is not present, set the valid_policy_graph to NULL.
            valid_policy_graph_is_null = true;
        }

        // (f) Verify that either explicit_policy is greater than 0
        // or the valid_policy_graph is not equal to NULL
        if explicit_policy == 0 && valid_policy_graph_is_null {
            log_error_for_ca(
                ca_cert,
                "NULL policy set while processing intermediate CA certificate",
            );
            set_validation_status(cpr, PathValidationStatus::NullPolicySet);
            return Err(Error::PathValidation(PathValidationStatus::NullPolicySet));
        }

        if i != certs_in_cert_path as usize {
            //prepare for next certificate (always occurs in this loop given target is processed later)
            let pdv_ext: Option<&PDVExtension> = ca_cert.get_extension(&ID_CE_POLICY_MAPPINGS)?;
            if let Some(PDVExtension::PolicyMappings(policy_mappings)) = pdv_ext {
                add_processed_extension(cpr, ID_CE_POLICY_MAPPINGS);

                // collect everything that maps to a given issuer domain policy for convenience while
                // looking for anyPolicy in the extension
                let mut mappings: BTreeMap<ObjectIdentifier, ObjectIdentifierSet> = BTreeMap::new();

                //(a)  If a policy mappings extension is present, verify that the
                //special value anyPolicy does not appear as an
                //issuerDomainPolicy or a subjectDomainPolicy.
                for mapping in &policy_mappings.0 {
                    if ANY_POLICY == mapping.issuer_domain_policy
                        || ANY_POLICY == mapping.subject_domain_policy
                    {
                        log_error_for_ca(
                            ca_cert,
                            "NULL policy set while processing intermediate CA certificate",
                        );
                        return Err(Error::PathValidation(PathValidationStatus::NullPolicySet));
                    } else {
                        mappings
                            .entry(mapping.issuer_domain_policy)
                            .or_insert_with(BTreeSet::new)
                            .insert(mapping.subject_domain_policy);
                    }
                }

                // (b)  If a policy mappings extension is present, then for each
                //       issuerDomainPolicy ID-P in the policy mappings extension:
                if policy_mapping > 0 {
                    // (1)  If the policy_mapping variable is greater than 0, if
                    // there is a node in the valid_policy_graph of depth i
                    // where ID-P is the valid_policy, set expected_policy_set
                    // to the set of subjectDomainPolicy values that are
                    // specified as equivalent to ID-P by the policy mappings
                    // extension.
                    let mut ap: Option<usize> = None;
                    for p_index in &valid_policy_graph[i] {
                        let p = &mut pm[*p_index];
                        if mappings.contains_key(&p.valid_policy) {
                            p.expected_policy_set.clear();

                            for s in &mappings[&p.valid_policy] {
                                p.expected_policy_set.insert(*s);
                            }
                            // remove the mappings that we actually process
                            mappings.remove(&p.valid_policy);
                        }
                        if ANY_POLICY == p.valid_policy {
                            ap = Some(*p_index);
                        }
                    }

                    // If no node of depth i in the valid_policy_tree has a
                    // valid_policy of ID-P but there is a node of depth i with a
                    // valid_policy of anyPolicy, then generate a child node of
                    // the node of depth i-1 that has a valid_policy of anyPolicy
                    // as follows:
                    //
                    // (i) set the valid_policy to ID-P;
                    //
                    // (ii) set the qualifier_set to the qualifier set of the
                    //      policy anyPolicy in the certificate policies
                    //      extension of certificate i; and
                    //
                    // (iii) set the expected_policy_set to the set of
                    //       subjectDomainPolicy values that are specified as
                    //       equivalent to ID-P by the policy mappings extension.
                    if !mappings.is_empty() {
                        if let Some(parent_index) = ap {
                            let mut nodes_to_add = vec![];
                            let parent = &pm[parent_index];
                            for m in mappings {
                                let new_node = make_new_policy_node(
                                    m.0,
                                    &parent.qualifier_set,
                                    m.1.clone(),
                                    row as u8,
                                    &Some(parent_index),
                                )?;
                                nodes_to_add.push(new_node);
                            }
                            for node in nodes_to_add {
                                let parent_index = node.parent.as_ref().map(|p| p.borrow()[0]);

                                let node_index = pm.len();
                                pm.push(node);
                                if let Some(parent_index) = parent_index {
                                    let parent = &pm[parent_index];
                                    add_child_if_not_present(pm, &parent.children, node_index);
                                }
                                valid_policy_graph[row].push(node_index);
                            }
                        }
                    }
                } else {
                    // (2)  If the policy_mapping variable is equal to 0:
                    //
                    //     (i)    delete each node of depth i in the valid_policy_tree
                    //            where ID-P is the valid_policy.
                    for m in mappings {
                        valid_policy_graph[i].retain(|x| !row_elem_is_policy(pm, x, m.0))
                    }

                    for r in &mut valid_policy_graph[0..i - 1] {
                        //     (ii)   If there is a node in the valid_policy_tree of depth
                        //            i-1 or less without any child nodes, delete that
                        //            node.  Repeat this step until there are no nodes of
                        //            depth i-1 or less without children.
                        r.retain(|x| !num_kids_is_zero(pm, *x));
                    }
                }
            }

            if !is_self_issued(&ca_cert.decoded_cert) {
                explicit_policy = explicit_policy.saturating_sub(1);
                inhibit_any_policy = inhibit_any_policy.saturating_sub(1);
                policy_mapping = policy_mapping.saturating_sub(1);
            }

            let pdv_ext: Option<&PDVExtension> =
                ca_cert.get_extension(&ID_CE_POLICY_CONSTRAINTS)?;
            if let Some(PDVExtension::PolicyConstraints(pc)) = pdv_ext {
                add_processed_extension(cpr, ID_CE_POLICY_CONSTRAINTS);
                if let Some(rep) = pc.require_explicit_policy {
                    explicit_policy = explicit_policy.min(rep)
                }
                if let Some(ipm) = pc.inhibit_policy_mapping {
                    policy_mapping = policy_mapping.min(ipm)
                }
            }
            let pdv_ext: Option<&PDVExtension> =
                ca_cert.get_extension(&ID_CE_INHIBIT_ANY_POLICY)?;
            if let Some(PDVExtension::InhibitAnyPolicy(iap)) = pdv_ext {
                add_processed_extension(cpr, ID_CE_INHIBIT_ANY_POLICY);
                inhibit_any_policy = inhibit_any_policy.min(iap.0);
            }
        }
        // end if(i != certs_in_cert_path as usize) {
        else {
            // 6.1.5 wrap-up procedure

            // (a)  If explicit_policy is not 0, decrement explicit_policy by 1.
            explicit_policy = explicit_policy.saturating_sub(1);

            let pdv_ext: Option<&PDVExtension> =
                ca_cert.get_extension(&ID_CE_POLICY_CONSTRAINTS)?;
            if let Some(PDVExtension::PolicyConstraints(pc)) = pdv_ext {
                // (b)  If a policy constraints extension is included in the
                //      certificate and requireExplicitPolicy is present and has a
                //      value of 0, set the explicit_policy state variable to 0.
                add_processed_extension(cpr, ID_CE_POLICY_CONSTRAINTS);
                if let Some(rep) = pc.require_explicit_policy {
                    explicit_policy = explicit_policy.min(rep)
                }
            }

            //both of these result in a no-op, i.e., valid_policy_tree is unchanged.
            //(i)    If the valid_policy_tree is NULL, the intersection is
            //NULL.

            //(ii)   If the valid_policy_tree is not NULL and the user-
            //initial-policy-set is any-policy, the intersection is
            //the entire valid_policy_tree.
            if !valid_policy_graph_is_null
                && !initial_policy_set.contains(&ANY_POLICY)
                && valid_policy_graph.len() > 1
            {
                //the valid_policy_tree is not null and the initial policy set does not contain anyPolicy
                //so the intersection of the two needs to be calculated

                //(iii)  If the valid_policy_tree is not NULL and the user-
                //initial-policy-set is not any-policy, calculate the
                //intersection of the valid_policy_tree and the user-
                //initial-policy-set as follows:

                //1.  Determine the set of policy nodes whose parent nodes
                //have a valid_policy of anyPolicy.  This is the
                //valid_policy_node_set.
                let mut valid_policy_node_set: Vec<usize> = Vec::new();
                let valid_policy_root = &pm[root_index];
                harvest_valid_policy_node_set(pm, valid_policy_root, &mut valid_policy_node_set);

                //2.  If the valid_policy of any node in the
                //valid_policy_node_set is not in the user-initial-
                //policy-set and is not anyPolicy, delete this node and
                //all its children.
                purge_policies(
                    pm,
                    &initial_policy_set,
                    &valid_policy_node_set,
                    &mut valid_policy_graph,
                );

                for r in &mut valid_policy_graph[0..i - 1] {
                    //4.  If there is a node in the valid_policy_tree of depth
                    //n-1 or less without any child nodes, delete that node.
                    //Repeat this step until there are no nodes of depth n-1
                    //or less without children.
                    r.retain(|x| !num_kids_is_zero(pm, *x));
                }

                // 3.  If the valid_policy_tree includes a node of depth n
                //     with the valid_policy anyPolicy and the user-initial-
                //     policy-set is not any-policy, perform the following
                //     steps:
                let mut nodes_to_add = vec![];
                if !initial_policy_set.contains(&ANY_POLICY) {
                    if let Some(parent_index) =
                        policy_tree_row_contains_policy(pm, &valid_policy_graph[i], ANY_POLICY)
                    {
                        //   a.  Set P-Q to the qualifier_set in the node of depth n
                        //       with valid_policy anyPolicy.
                        //
                        //   b.  For each P-OID in the user-initial-policy-set that is
                        //       not the valid_policy of a node in the
                        //       valid_policy_node_set, create a child node whose
                        //       parent is the node of depth n-1 with the valid_policy
                        //       anyPolicy.  Set the values in the child node as
                        //       follows: set the valid_policy to P-OID, set the
                        //       qualifier_set to P-Q, and set the expected_policy_set
                        //       to {P-OID}.
                        //
                        //   c.  Delete the node of depth n with the valid_policy
                        //       anyPolicy.

                        let parent = &pm[parent_index];
                        let p_q = &parent.qualifier_set;

                        for p in &initial_policy_set {
                            let parent_index = parent.parent.as_ref().map(|pi| pi.borrow()[0]);

                            let new_node = make_new_policy_node(
                                *p,
                                p_q,
                                ObjectIdentifierSet::from([*p]),
                                row as u8,
                                &parent_index,
                            )?;
                            nodes_to_add.push(new_node);
                        }
                        valid_policy_graph[row].retain(|x| *x != parent_index);
                    }
                }

                for node in nodes_to_add {
                    let parent_index = node.parent.as_ref().map(|p| p.borrow()[0]);

                    let node_index = pm.len();
                    pm.push(node);
                    if let Some(parent_index) = parent_index {
                        let parent = &pm[parent_index];
                        add_child_if_not_present(pm, &parent.children, node_index);
                    }
                    valid_policy_graph[row].push(node_index);
                }

                if valid_policy_graph[row].is_empty() {
                    valid_policy_graph_is_null = true;
                }
            }
            if explicit_policy == 0 && valid_policy_graph_is_null {
                log_error_for_ca(
                    ca_cert,
                    "NULL policy set while processing intermediate CA certificate",
                );
                set_validation_status(cpr, PathValidationStatus::NullPolicySet);
                return Err(Error::PathValidation(PathValidationStatus::NullPolicySet));
            }
        }
    } // end for (pos, ca_cert) in cp.intermediates.iter_mut().enumerate() {

    let mut final_valid_policy_tree: FinalValidPolicyTree = FinalValidPolicyTree::new();
    for row in valid_policy_graph {
        let mut new_row = Vec::new();
        for node in row {
            let p = &pm[node];
            let vptn = ValidPolicyTreeNode {
                valid_policy: p.valid_policy,
                qualifier_set: p.qualifier_set.clone(),
                expected_policy_set: p.expected_policy_set.clone(),
            };
            new_row.push(vptn);
        }
        final_valid_policy_tree.push(new_row);
    }
    set_final_valid_policy_graph(cpr, final_valid_policy_tree);

    Ok(())
}

fn make_new_policy_node_graph(
    valid_policy: ObjectIdentifier,
    qualifiers: &Option<Vec<u8>>,
    expected_policy_set: ObjectIdentifierSet,
    depth: u8,
    parent: &[usize],
) -> Result<PolicyProcessingData> {
    Ok(PolicyProcessingData {
        valid_policy,
        qualifier_set: qualifiers.clone(),
        expected_policy_set,
        depth,
        parent: Some(RefCell::new(parent.to_owned())),
        children: RefCell::new(vec![]),
    })
}

fn make_new_policy_node_add_to_pool2_graph(
    pm: &mut PolicyPool<'_>,
    valid_policy: ObjectIdentifier,
    qualifiers: &Option<Vec<u8>>,
    expected_policy_set: ObjectIdentifierSet,
    depth: u8,
    parents: Vec<usize>,
) -> Result<usize> {
    let node = PolicyProcessingData {
        valid_policy,
        qualifier_set: qualifiers.clone(),
        expected_policy_set,
        depth,
        parent: Some(RefCell::new(parents.clone())),
        children: RefCell::new(vec![]),
    };
    let cur_index = pm.len();
    pm.push(node);

    for p in parents {
        let parent = &pm[p];
        add_child_if_not_present(pm, &parent.children, cur_index);
    }

    Ok(cur_index)
}
