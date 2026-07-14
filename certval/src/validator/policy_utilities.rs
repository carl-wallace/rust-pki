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
#[derive(Clone, Debug)]
pub(crate) struct PolicyProcessingData {
    pub(crate) valid_policy: ObjectIdentifier,
    pub(crate) qualifier_set: Option<Vec<u8>>,
    pub(crate) expected_policy_set: ObjectIdentifierSet,
    pub(crate) depth: u8,
    pub(crate) parent: Option<RefCell<Vec<usize>>>,
    pub(crate) children: RefCell<Vec<usize>>,
}

impl PartialEq for PolicyProcessingData {
    fn eq(&self, other: &Self) -> bool {
        self.valid_policy == other.valid_policy
    }
}

/// The PolicyPool type is used to maintain a list of PolicyProcessingData instances that are used
/// to represent a valid_policy_tree.
pub(crate) type PolicyPool = Vec<PolicyProcessingData>;

/// The PolicyTreeRow type is used to represent rows in the valid_policy_tree. Each element is an
/// index into the PolicyPool instance that supports the valid_policy_tree.
pub(crate) type PolicyTreeRow = Vec<usize>;

pub(crate) fn has_child_node(
    pool: &PolicyPool,
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
    pool: &PolicyPool,
    children: &RefCell<Vec<usize>>,
    new_child_index: usize,
) {
    // Dedup against the parent's actual children (indices into the pool), keyed by valid_policy.
    let new_child_policy = pool[new_child_index].valid_policy;
    if !has_child_node(pool, children, &new_child_policy) {
        children.borrow_mut().push(new_child_index);
    }
}

pub(crate) fn row_elem_is_policy(pool: &PolicyPool, elem: &usize, oid: ObjectIdentifier) -> bool {
    let item = &pool[*elem];
    if item.valid_policy == oid {
        return true;
    }
    false
}

/// policy_tree_row_contains_policy searches row for policy_oid and returns the index of the PolicyProcessingData
/// item in the pool if it is found. None is returned if not found.
pub(crate) fn policy_tree_row_contains_policy(
    pool: &PolicyPool,
    row: &PolicyTreeRow,
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

pub(crate) fn num_kids_is_zero(pool: &PolicyPool, index: usize) -> bool {
    if pool.len() > index {
        let p = &pool[index];
        let retval = p.children.borrow().len();
        return retval == 0;
    }
    true
}

/// Prunes childless nodes from rows `0..=max_depth` of `valid_policy_graph`, cascading upward.
///
/// Implements the "delete each node of depth i-1 (or n-1) or less without any child nodes; repeat
/// until there are no such nodes" step of RFC 5280 §6.1.3(d)(3), §6.1.4(b)(2)(ii), and §6.1.5. A
/// removed node is also stripped from each of its parents' `children` lists, so a parent left with
/// no children is pruned on a later pass (the cascade). The outer loop repeats full passes over the
/// rows until one removes nothing, so every newly-childless parent is caught regardless of the
/// order in which rows are visited.
pub(crate) fn prune_childless_nodes(
    pool: &PolicyPool,
    valid_policy_graph: &mut [PolicyTreeRow],
    max_depth: usize,
) {
    let mut changed = true;
    while changed {
        changed = false;
        for row in valid_policy_graph.iter_mut().take(max_depth + 1) {
            let before = row.len();
            row.retain(|node_index| {
                if num_kids_is_zero(pool, *node_index) {
                    // strip this childless node from each parent so the parent's child count
                    // reflects the removal, enabling the upward cascade
                    if let Some(parents) = &pool[*node_index].parent {
                        for parent_index in parents.borrow().iter() {
                            pool[*parent_index]
                                .children
                                .borrow_mut()
                                .retain(|c| c != node_index);
                        }
                    }
                    false
                } else {
                    true
                }
            });
            if row.len() != before {
                changed = true;
            }
        }
    }
}

pub(crate) fn make_new_policy_node_add_to_pool2(
    pm: &mut PolicyPool,
    valid_policy: ObjectIdentifier,
    qualifiers: &Option<Vec<u8>>,
    expected_policy_set: ObjectIdentifierSet,
    depth: u8,
    parent: &Option<usize>,
) -> Result<usize> {
    let parent_opt = parent.as_ref().map(|p| RefCell::new(vec![*p]));
    let node = PolicyProcessingData {
        valid_policy,
        qualifier_set: qualifiers.clone(),
        expected_policy_set,
        depth,
        parent: parent_opt,
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
    let parent_opt = parent.as_ref().map(|p| RefCell::new(vec![*p]));

    Ok(PolicyProcessingData {
        valid_policy,
        qualifier_set: qualifiers.clone(),
        expected_policy_set,
        depth,
        parent: parent_opt,
        children: RefCell::new(vec![]),
    })
}

pub(crate) fn harvest_valid_policy_node_set(
    pool: &PolicyPool,
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
    pool: &PolicyPool,
    initial_policy_set: &ObjectIdentifierSet,
    valid_policy_node_set: &[usize],
    valid_policy_tree: &mut Vec<PolicyTreeRow>,
) {
    for pol in valid_policy_node_set {
        let p = &pool[*pol];
        if p.valid_policy != ANY_POLICY && !initial_policy_set.contains(&p.valid_policy) {
            if let Some(parent_index) = &p.parent {
                let parent = &pool[parent_index.borrow()[0]];
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
    pool: &PolicyPool,
    valid_policy_tree: &mut Vec<PolicyTreeRow>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::cell::RefCell;
    use der::asn1::ObjectIdentifier;

    fn node(
        policy: ObjectIdentifier,
        depth: u8,
        parent: Option<Vec<usize>>,
        children: Vec<usize>,
    ) -> PolicyProcessingData {
        PolicyProcessingData {
            valid_policy: policy,
            qualifier_set: None,
            expected_policy_set: ObjectIdentifierSet::new(),
            depth,
            parent: parent.map(RefCell::new),
            children: RefCell::new(children),
        }
    }

    // Dedup keys on the parent's actual children: pool[0] shares policy X with the candidate but is
    // not one of the parent's children, so the candidate must still be added.
    #[test]
    fn add_child_if_not_present_scans_actual_children() {
        let x = ObjectIdentifier::new_unwrap("1.2.3.1");
        let a = ObjectIdentifier::new_unwrap("1.2.3.2");
        let pool: PolicyPool = vec![
            node(x, 1, Some(vec![]), vec![]),  // 0: pool-prefix decoy, policy X
            node(a, 1, Some(vec![]), vec![]),  // 1: the parent's sole real child, policy A
            node(x, 2, Some(vec![1]), vec![]), // 2: candidate, policy X (not among children)
            node(a, 2, Some(vec![1]), vec![]), // 3: candidate, policy A (already a child)
        ];
        let children = RefCell::new(vec![1usize]);

        add_child_if_not_present(&pool, &children, 2);
        assert_eq!(
            *children.borrow(),
            vec![1, 2],
            "policy X is not a child yet; must be added"
        );

        add_child_if_not_present(&pool, &children, 3);
        assert_eq!(
            *children.borrow(),
            vec![1, 2],
            "policy A already a child; must be a no-op"
        );
    }

    // Pruning a childless node strips it from its parent's `children`, so a parent left childless
    // is itself pruned on a later pass (the cascade).
    #[test]
    fn prune_childless_nodes_strips_parent_and_cascades() {
        let root = ObjectIdentifier::new_unwrap("2.5.29.32.0");
        let p = ObjectIdentifier::new_unwrap("1.2.3.10");
        let q = ObjectIdentifier::new_unwrap("1.2.3.11");

        // root(0) -> {dead(1) childless, live(2) -> leaf(3)}. Prune rows 0..=1; the leaf's row 2 is
        // the anchor (not pruned). The dead node goes and is stripped from root's children.
        let pool: PolicyPool = vec![
            node(root, 0, None, vec![1, 2]),
            node(p, 1, Some(vec![0]), vec![]),
            node(q, 1, Some(vec![0]), vec![3]),
            node(p, 2, Some(vec![2]), vec![]),
        ];
        let mut graph = vec![vec![0usize], vec![1, 2], vec![3]];
        prune_childless_nodes(&pool, &mut graph, 1);
        assert_eq!(graph[1], vec![2], "childless node pruned from its row");
        assert_eq!(
            *pool[0].children.borrow(),
            vec![2],
            "pruned node stripped from parent"
        );
        assert_eq!(graph[0], vec![0]);
        assert_eq!(graph[2], vec![3], "anchor row untouched");

        // Full upward collapse: a lone childless leaf at the deepest pruned row must cascade all the
        // way to the root. A single shallow-first pass (old behavior) would stop after the leaf.
        let chain: PolicyPool = vec![
            node(root, 0, None, vec![1]),
            node(p, 1, Some(vec![0]), vec![2]),
            node(q, 2, Some(vec![1]), vec![]),
        ];
        let mut cg = vec![vec![0usize], vec![1], vec![2]];
        prune_childless_nodes(&chain, &mut cg, 2);
        assert!(
            cg[0].is_empty() && cg[1].is_empty() && cg[2].is_empty(),
            "childless leaf must cascade-prune its entire ancestry, got {cg:?}"
        );
    }
}
