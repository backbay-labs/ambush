//! Hierarchical budget governance: org -> dept -> team -> agent.
//!
//! A tree-structured policy that sits above the flat per-lane
//! [`crate::budget::BudgetEnforcer`]. Ported from the Arc/Chio
//! `budget_hierarchy.rs` and collapsed onto [`AggregateSpend`] /
//! [`BudgetLimit`]. Parents cap children at every level: an evaluation walks
//! from the leaf to the root and, at each ancestor, charges the draft against
//! that node's **subtree roll-up** (the node's own spend plus all descendants'
//! spend). The deny reason references the offender closest to the root so the
//! broadest policy boundary surfaces first.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::budget::{BudgetLimit, BudgetViolation};
use crate::spend::AggregateSpend;

/// Identifier for a node in a budget tree.
///
/// Conventionally `scope/name`, e.g. `org/acme`, `dept/acme/research`,
/// `agent/alice`. The tree requires unique ids and acyclic parent references;
/// no other shape is enforced.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BudgetNodeId(pub String);

impl BudgetNodeId {
    /// Construct a new node identifier.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for BudgetNodeId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for BudgetNodeId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl std::fmt::Display for BudgetNodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A single node in a budget tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetNode {
    /// Unique identifier for this node.
    pub id: BudgetNodeId,
    /// Parent node identifier, if any. `None` marks a root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<BudgetNodeId>,
    /// Per-dimension limits applied at this node.
    #[serde(default)]
    pub limits: BudgetLimit,
    /// When `false`, the node denies all draft spend with
    /// [`BudgetDenyReason::NodeDisabled`].
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl BudgetNode {
    /// Construct a new enabled root node with empty limits.
    #[must_use]
    pub fn new(id: impl Into<BudgetNodeId>) -> Self {
        Self {
            id: id.into(),
            parent: None,
            limits: BudgetLimit::default(),
            enabled: true,
        }
    }

    /// Builder: set the parent node.
    #[must_use]
    pub fn with_parent(mut self, parent: impl Into<BudgetNodeId>) -> Self {
        self.parent = Some(parent.into());
        self
    }

    /// Builder: set the per-dimension limits.
    #[must_use]
    pub fn with_limits(mut self, limits: BudgetLimit) -> Self {
        self.limits = limits;
        self
    }

    /// Builder: disable the node.
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// Snapshot of *direct* spend per node. Callers read this from whatever backing
/// store they use; nodes absent from the map are treated as zero. Roll-up to
/// ancestors is computed by the tree, not stored here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendSnapshot {
    /// Direct spend keyed by node id.
    #[serde(default)]
    pub per_node: HashMap<BudgetNodeId, AggregateSpend>,
}

impl SpendSnapshot {
    /// Create an empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or overwrite the direct spend for a node.
    pub fn set(&mut self, id: impl Into<BudgetNodeId>, spend: AggregateSpend) {
        self.per_node.insert(id.into(), spend);
    }

    /// Direct spend for a node (zero if absent).
    #[must_use]
    pub fn get(&self, id: &BudgetNodeId) -> AggregateSpend {
        self.per_node.get(id).cloned().unwrap_or_default()
    }
}

/// Why a draft spend was denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum BudgetDenyReason {
    /// The evaluated leaf id is not in the tree (fail-closed on unknown).
    UnknownNode {
        /// The id that was looked up.
        node: BudgetNodeId,
    },
    /// The node or one of its ancestors is disabled.
    NodeDisabled {
        /// The disabled node.
        node: BudgetNodeId,
    },
    /// A per-dimension cap would be exceeded at `node` after roll-up.
    Exceeded {
        /// The node whose subtree cap was hit.
        node: BudgetNodeId,
        /// The dimension/limit detail. `violation.lane` carries the node id.
        violation: BudgetViolation,
    },
}

/// Outcome of an evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum BudgetDecision {
    /// The draft spend is within every ancestor's cap.
    Allow,
    /// The draft spend would exceed a cap, or the leaf is unknown.
    Deny {
        /// Cause of the denial (closest-to-root offender).
        reason: BudgetDenyReason,
    },
}

/// Errors from tree construction.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BudgetError {
    /// Attempted to insert a node whose id already exists.
    #[error("duplicate node id `{node}`")]
    Duplicate {
        /// The id that was already present.
        node: BudgetNodeId,
    },
    /// Parent referenced by a node is missing from the tree.
    #[error("parent `{parent}` of node `{node}` is not present in the tree")]
    MissingParent {
        /// The node referencing a missing parent.
        node: BudgetNodeId,
        /// The missing parent id.
        parent: BudgetNodeId,
    },
    /// Insertion would create a cycle.
    #[error("cycle detected while inserting node `{node}`")]
    Cycle {
        /// The node whose insertion would have created the cycle.
        node: BudgetNodeId,
    },
}

/// A tree of budget nodes supporting parent-capped, roll-up evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BudgetTree {
    nodes: HashMap<BudgetNodeId, BudgetNode>,
    children: HashMap<BudgetNodeId, Vec<BudgetNodeId>>,
}

impl BudgetTree {
    /// Create an empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of nodes in the tree.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree has no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Look up a node by id.
    #[must_use]
    pub fn get(&self, id: &BudgetNodeId) -> Option<&BudgetNode> {
        self.nodes.get(id)
    }

    /// Insert a node. Rejects duplicates, missing parents, and cycles.
    pub fn insert(&mut self, node: BudgetNode) -> Result<(), BudgetError> {
        if self.nodes.contains_key(&node.id) {
            return Err(BudgetError::Duplicate {
                node: node.id.clone(),
            });
        }
        if let Some(parent) = &node.parent {
            if !self.nodes.contains_key(parent) {
                return Err(BudgetError::MissingParent {
                    node: node.id.clone(),
                    parent: parent.clone(),
                });
            }
            // Walk from parent upward; landing on node.id means a cycle.
            let mut cursor: Option<BudgetNodeId> = Some(parent.clone());
            let mut visited: HashSet<BudgetNodeId> = HashSet::new();
            while let Some(current) = cursor {
                if current == node.id || !visited.insert(current.clone()) {
                    return Err(BudgetError::Cycle {
                        node: node.id.clone(),
                    });
                }
                cursor = self.nodes.get(&current).and_then(|n| n.parent.clone());
            }
        }

        if let Some(parent) = &node.parent {
            self.children
                .entry(parent.clone())
                .or_default()
                .push(node.id.clone());
        }
        self.nodes.insert(node.id.clone(), node);
        Ok(())
    }

    /// Ancestors of `id` in leaf-to-root order, including `id` at position 0.
    /// Empty if `id` is absent.
    #[must_use]
    pub fn ancestors(&self, id: &BudgetNodeId) -> Vec<BudgetNodeId> {
        let mut out = Vec::new();
        let mut visited: HashSet<BudgetNodeId> = HashSet::new();
        let mut cursor: Option<BudgetNodeId> = if self.nodes.contains_key(id) {
            Some(id.clone())
        } else {
            None
        };
        while let Some(current) = cursor {
            if !visited.insert(current.clone()) {
                break;
            }
            let next = self.nodes.get(&current).and_then(|n| n.parent.clone());
            out.push(current);
            cursor = next;
        }
        out
    }

    /// Every descendant of `id` (not including `id`), breadth-first.
    #[must_use]
    pub fn descendants(&self, id: &BudgetNodeId) -> Vec<BudgetNodeId> {
        let mut out = Vec::new();
        if !self.nodes.contains_key(id) {
            return out;
        }
        let mut queue: Vec<BudgetNodeId> = self.children.get(id).cloned().unwrap_or_default();
        let mut visited: HashSet<BudgetNodeId> = HashSet::new();
        while !queue.is_empty() {
            let current = queue.remove(0);
            if !visited.insert(current.clone()) {
                continue;
            }
            if let Some(next) = self.children.get(&current) {
                for c in next {
                    queue.push(c.clone());
                }
            }
            out.push(current);
        }
        out
    }

    /// Rolled-up spend for the subtree rooted at `id`: the node's own direct
    /// spend plus every descendant's direct spend (saturating).
    #[must_use]
    pub fn subtree_spend(&self, id: &BudgetNodeId, snapshot: &SpendSnapshot) -> AggregateSpend {
        let mut total = snapshot.get(id);
        for d in self.descendants(id) {
            total = total.saturating_add(&snapshot.get(&d));
        }
        total
    }

    /// Evaluate whether `draft` may be charged to leaf `id`.
    ///
    /// Walks leaf-to-root. At each ancestor, the draft is charged against the
    /// node's subtree roll-up. Denies if any node is disabled or any cap is
    /// exceeded; the reason references the offender closest to the root.
    #[must_use]
    pub fn evaluate(
        &self,
        id: &BudgetNodeId,
        draft: &AggregateSpend,
        snapshot: &SpendSnapshot,
    ) -> BudgetDecision {
        if !self.nodes.contains_key(id) {
            return BudgetDecision::Deny {
                reason: BudgetDenyReason::UnknownNode { node: id.clone() },
            };
        }

        // ancestors() is leaf-to-root; the last offender we set is the
        // root-most, so the broadest boundary surfaces first.
        let mut offender: Option<BudgetDenyReason> = None;
        for node_id in self.ancestors(id) {
            let Some(node) = self.nodes.get(&node_id) else {
                continue;
            };
            if !node.enabled {
                offender = Some(BudgetDenyReason::NodeDisabled {
                    node: node_id.clone(),
                });
                continue;
            }
            let current = self.subtree_spend(&node_id, snapshot);
            if let Err(violation) = node.limits.check(node_id.as_str(), &current, draft) {
                offender = Some(BudgetDenyReason::Exceeded {
                    node: node_id.clone(),
                    violation,
                });
            }
        }

        match offender {
            None => BudgetDecision::Allow,
            Some(reason) => BudgetDecision::Deny { reason },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::spend::Dimension;

    fn node(id: &str, parent: Option<&str>, limits: BudgetLimit) -> BudgetNode {
        let mut n = BudgetNode::new(id).with_limits(limits);
        if let Some(p) = parent {
            n = n.with_parent(p);
        }
        n
    }

    /// org caps total usd_micros at 1_000; two teams each under their own
    /// 800 cap, but their spend rolls up past the org cap.
    fn org_tree() -> BudgetTree {
        let mut tree = BudgetTree::new();
        tree.insert(node(
            "org/acme",
            None,
            BudgetLimit::default().with_max_usd_micros(1_000),
        ))
        .unwrap();
        tree.insert(node(
            "team/a",
            Some("org/acme"),
            BudgetLimit::default().with_max_usd_micros(800),
        ))
        .unwrap();
        tree.insert(node(
            "team/b",
            Some("org/acme"),
            BudgetLimit::default().with_max_usd_micros(800),
        ))
        .unwrap();
        tree
    }

    #[test]
    fn hierarchy_rollup_denies_at_root_even_when_leaf_is_fine() {
        let tree = org_tree();
        let mut snap = SpendSnapshot::new();
        snap.set("team/a", AggregateSpend::with_usd_micros(600));
        snap.set("team/b", AggregateSpend::with_usd_micros(600));

        // 600 + 100 = 700 <= 800 at team/a, but org subtree = 1200 + 100 = 1300 > 1000.
        let decision = tree.evaluate(
            &BudgetNodeId::new("team/a"),
            &AggregateSpend::with_usd_micros(100),
            &snap,
        );
        match decision {
            BudgetDecision::Deny {
                reason: BudgetDenyReason::Exceeded { node, violation },
            } => {
                assert_eq!(node.as_str(), "org/acme");
                assert_eq!(violation.dimension, Dimension::UsdMicros);
                assert_eq!(violation.limit, 1_000);
                assert_eq!(violation.current, 1_200);
                assert_eq!(violation.requested, 100);
            }
            other => panic!("expected org-level deny, got {other:?}"),
        }
    }

    #[test]
    fn hierarchy_rollup_allows_within_every_ancestor() {
        let tree = org_tree();
        let mut snap = SpendSnapshot::new();
        snap.set("team/a", AggregateSpend::with_usd_micros(300));
        snap.set("team/b", AggregateSpend::with_usd_micros(300));
        // org subtree = 600 + 100 = 700 <= 1000; team/a = 300 + 100 = 400 <= 800.
        let decision = tree.evaluate(
            &BudgetNodeId::new("team/a"),
            &AggregateSpend::with_usd_micros(100),
            &snap,
        );
        assert_eq!(decision, BudgetDecision::Allow);
    }

    #[test]
    fn disabled_ancestor_denies() {
        let mut tree = BudgetTree::new();
        tree.insert(node("org/x", None, BudgetLimit::default()).disabled())
            .unwrap();
        tree.insert(node("team/y", Some("org/x"), BudgetLimit::default()))
            .unwrap();
        let decision = tree.evaluate(
            &BudgetNodeId::new("team/y"),
            &AggregateSpend::with_tokens(1),
            &SpendSnapshot::new(),
        );
        assert!(matches!(
            decision,
            BudgetDecision::Deny {
                reason: BudgetDenyReason::NodeDisabled { ref node }
            } if node.as_str() == "org/x"
        ));
    }

    #[test]
    fn unknown_leaf_is_fail_closed() {
        let tree = org_tree();
        let decision = tree.evaluate(
            &BudgetNodeId::new("agent/ghost"),
            &AggregateSpend::default(),
            &SpendSnapshot::new(),
        );
        assert!(matches!(
            decision,
            BudgetDecision::Deny {
                reason: BudgetDenyReason::UnknownNode { .. }
            }
        ));
    }

    #[test]
    fn insert_rejects_duplicate_and_missing_parent() {
        let mut tree = BudgetTree::new();
        tree.insert(node("org/acme", None, BudgetLimit::default()))
            .unwrap();
        assert!(matches!(
            tree.insert(node("org/acme", None, BudgetLimit::default())),
            Err(BudgetError::Duplicate { .. })
        ));
        assert!(matches!(
            tree.insert(node("team/x", Some("dept/missing"), BudgetLimit::default())),
            Err(BudgetError::MissingParent { .. })
        ));
    }

    #[test]
    fn ancestors_and_descendants_walk_the_chain() {
        let tree = org_tree();
        assert_eq!(
            tree.ancestors(&BudgetNodeId::new("team/a")),
            vec![BudgetNodeId::new("team/a"), BudgetNodeId::new("org/acme")]
        );
        let mut desc = tree.descendants(&BudgetNodeId::new("org/acme"));
        desc.sort();
        assert_eq!(desc, vec![BudgetNodeId::new("team/a"), BudgetNodeId::new("team/b")]);
    }
}
