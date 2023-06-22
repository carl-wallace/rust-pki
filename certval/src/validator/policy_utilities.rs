//! Utility functions related to certificate policy-related certification path validation operations.
//! Functions, structures, etc. in this file are pub(crate).

use alloc::{vec, vec::Vec};
use core::cell::RefCell;

use const_oid::db::rfc5280::ANY_POLICY;
use der::asn1::ObjectIdentifier;

use crate::util::error::*;
use crate::ObjectIdentifierSet;

/// PolicyProcessingData is internally used by check_certificate_policies to perform certificate
/// policy-related checks in support of certification path validation. This struct is used as the
/// node type in the valid_policy_tree. The first three fields correspond to the three fields show
/// in Figure 3 in section 6.1.2 of RFC5280. The depth field indicates the row in the valid_policy_tree
/// where the node was added. All nodes in the valid_policy_tree expect the root node have a parent.
/// The parent is the node whose evaluation caused a child node to be added. Child-less nodes are
/// periodically pruned from the valid_policy_tree.
///
/// The first five fields are established when a node is created and are not altered. The children
/// field is updated as subordinate nodes are added or removed.
///
/// The valid_policy_tree is backed by a PolicyPool instance that holds references to all
/// PolicyProcessingData instances that comprise the valid_policy_tree.
///
/// Upon completion of policy processing, an instance of FinalValidPolicyTree is prepared and returned
/// to the caller.
#[derive(Clone)]
pub(crate) struct PolicyProcessingData {
    pub(crate) valid_policy: ObjectIdentifier,
    pub(crate) qualifier_set: Option<Vec<u8>>,
    pub(crate) expected_policy_set: ObjectIdentifierSet,
    pub(crate) depth: u8,
    pub(crate) parent: Option<usize>,
    pub(crate) children: RefCell<Vec<usize>>,
}

impl PartialEq for PolicyProcessingData {
    fn eq(&self, other: &Self) -> bool {
        self.valid_policy == other.valid_policy
    }
}

/// The PolicyPool type is used to maintain a list of PolicyProcessingData instances that are used
/// to represent a valid_policy_tree.
pub(crate) type PolicyPool<'a> = Vec<PolicyProcessingData>;

/// The PolicyTreeRow type is used to represent rows in the valid_policy_tree. Each element is an
/// index into the PolicyPool instance that supports the valid_policy_tree.
pub(crate) type PolicyTreeRow<'a> = Vec<usize>;

pub(crate) fn has_child_node(
    pool: &PolicyPool<'_>,
    children: &RefCell<Vec<usize>>,
    oid: &ObjectIdentifier,
) -> bool {
    for ps_index in children.borrow().iter() {
        let ps = &pool[*ps_index];
        if ps.valid_policy == *oid {
            return true;
        }
    }
    false
}

pub(crate) fn add_child_if_not_present(
    pool: &PolicyPool<'_>,
    children: &RefCell<Vec<usize>>,
    new_child_index: usize,
) {
    let new_child = &pool[new_child_index];
    let mut found = false;
    for ps in pool.iter().take(children.borrow().len()) {
        if ps.valid_policy == new_child.valid_policy {
            found = true;
            break;
        }
    }
    if !found {
        children.borrow_mut().push(new_child_index);
    }
}

pub(crate) fn row_elem_is_policy(
    pool: &PolicyPool<'_>,
    elem: &usize,
    oid: ObjectIdentifier,
) -> bool {
    let item = &pool[*elem];
    if item.valid_policy == oid {
        return true;
    }
    false
}

/// policy_tree_row_contains_policy searches row for policy_oid and returns the index of the PolicyProcessingData
/// item in the pool if it is found. None is returned if not found.
pub(crate) fn policy_tree_row_contains_policy(
    pool: &PolicyPool<'_>,
    row: &PolicyTreeRow<'_>,
    policy_oid: ObjectIdentifier,
) -> Option<usize> {
    for item_index in row {
        let item = &pool[*item_index];
        if item.valid_policy == policy_oid {
            return Some(*item_index);
        }
    }
    None
}

pub(crate) fn num_kids_is_zero(pool: &PolicyPool<'_>, index: usize) -> bool {
    if pool.len() > index {
        let p = &pool[index];
        let retval = p.children.borrow().len();
        return retval == 0;
    }
    true
}

pub(crate) fn make_new_policy_node_add_to_pool2(
    pm: &mut PolicyPool<'_>,
    valid_policy: ObjectIdentifier,
    qualifiers: &Option<Vec<u8>>,
    expected_policy_set: ObjectIdentifierSet,
    depth: u8,
    parent: &Option<usize>,
) -> Result<usize> {
    let node = PolicyProcessingData {
        valid_policy,
        qualifier_set: qualifiers.clone(),
        expected_policy_set,
        depth,
        parent: *parent,
        children: RefCell::new(vec![]),
    };
    let cur_index = pm.len();
    pm.push(node);
    Ok(cur_index)
}

pub(crate) fn make_new_policy_node(
    valid_policy: ObjectIdentifier,
    qualifiers: &Option<Vec<u8>>,
    expected_policy_set: ObjectIdentifierSet,
    depth: u8,
    parent: &Option<usize>,
) -> Result<PolicyProcessingData> {
    Ok(PolicyProcessingData {
        valid_policy,
        qualifier_set: qualifiers.clone(),
        expected_policy_set,
        depth,
        parent: *parent,
        children: RefCell::new(vec![]),
    })
}

pub(crate) fn harvest_valid_policy_node_set(
    pool: &PolicyPool<'_>,
    cur_node: &PolicyProcessingData,
    valid_policy_node_set: &mut Vec<usize>,
) {
    if cur_node.valid_policy == ANY_POLICY {
        for c_index in cur_node.children.borrow().iter() {
            valid_policy_node_set.push(*c_index);
            let c = &pool[*c_index];
            harvest_valid_policy_node_set(pool, c, valid_policy_node_set);
        }
    }
}

pub(crate) fn purge_policies(
    pool: &PolicyPool<'_>,
    initial_policy_set: &ObjectIdentifierSet,
    valid_policy_node_set: &[usize],
    valid_policy_tree: &mut Vec<PolicyTreeRow<'_>>,
) {
    for pol in valid_policy_node_set {
        let p = &pool[*pol];
        if p.valid_policy != ANY_POLICY && !initial_policy_set.contains(&p.valid_policy) {
            if let Some(parent_index) = p.parent {
                let parent = &pool[parent_index];
                parent
                    .children
                    .borrow_mut()
                    .retain(|x| !row_elem_is_policy(pool, x, p.valid_policy));
                remove_node_and_children(pool, valid_policy_tree, p, pol);
            }
        }
    }
}

pub(crate) fn remove_node_and_children(
    pool: &PolicyPool<'_>,
    valid_policy_tree: &mut Vec<PolicyTreeRow<'_>>,
    node: &PolicyProcessingData,
    node_index: &usize,
) {
    for c_index in node.children.borrow_mut().iter_mut() {
        let c = &pool[*c_index];
        remove_node_and_children(pool, valid_policy_tree, c, c_index);
    }
    node.children.borrow_mut().clear();
    valid_policy_tree[node.depth as usize].retain(|x| *x != *node_index);
}
