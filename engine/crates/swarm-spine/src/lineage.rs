//! Chain-of-custody lineage DAG projected over spine envelopes.
//!
//! This is a pure-data port of the upstream `chio-lineage` schema
//! (`LineageGraph` / `LineageNode` / `LineageEdge`, the
//! [`EvidenceClass`] taxonomy, and the bounded-traversal
//! [`TruncationMarker`]) adapted to the Ambush spine. None of the
//! upstream NDJSON + sqlite ingest is brought across: nodes are held
//! in memory and the graph is projected from the existing signed
//! [`crate::envelope`] hash chain.
//!
//! Evidence-class preservation rules (mirrored from upstream):
//!
//! - [`EvidenceClass::Asserted`]: caller-supplied attributes carried
//!   inside an envelope `fact` that are not signed independently.
//! - [`EvidenceClass::Observed`]: local runtime kernel truth — the
//!   hash-chain links the spine itself recorded between envelopes.
//! - [`EvidenceClass::Verified`]: independently signed or proof-checked
//!   facts, such as a verified signed envelope or checkpoint anchor.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::spine_error::{SpineError, SpineResult};

/// Schema identifier for v1 lineage graph projections.
pub const LINEAGE_GRAPH_SCHEMA_V1: &str = "swarm.spine.lineage.v1";

/// Provenance evidence class. Mirrors the caller-supplied vs
/// locally-observed vs independently-verified taxonomy used by the
/// audit story.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    /// Caller-supplied or imported attributes that have not been signed
    /// or independently verified by this kernel.
    Asserted,
    /// Local kernel runtime truth (links the spine itself recorded).
    Observed,
    /// Independently signed or proof-checked.
    Verified,
}

/// Lineage node kinds. Every node belongs to exactly one kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Prompt,
    Capability,
    GuardVerdict,
    ToolCall,
    Receipt,
    Envelope,
    Checkpoint,
}

/// Lineage edge kinds, typed by the relation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    PromptToCapability,
    CapabilityParent,
    CapabilityToGuard,
    GuardToToolCall,
    ToolCallToReceipt,
    ReceiptToChildRequest,
    RequestToRequest,
    ReceiptLineageParent,
    /// Hash-chain parent link between two spine envelopes.
    EnvelopeParent,
    /// Projection edge from an envelope to a receipt it carries.
    EnvelopeToReceipt,
    /// Anchor edge from a checkpoint to the envelope it commits.
    CheckpointAnchors,
}

/// A graph node. Stable id, kind, evidence class, and optional
/// projection metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageNode {
    pub id: String,
    pub kind: NodeKind,
    pub evidence_class: EvidenceClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_table: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
}

impl LineageNode {
    /// Construct a node with only the required fields populated.
    pub fn new(
        id: impl Into<String>,
        kind: NodeKind,
        evidence_class: EvidenceClass,
    ) -> Self {
        Self {
            id: id.into(),
            kind,
            evidence_class,
            tenant_id: None,
            recorded_at: None,
            label: None,
            source_table: None,
            source_id: None,
        }
    }

    /// Attach a human-readable label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Attach a recorded-at epoch-millis timestamp.
    #[must_use]
    pub fn with_recorded_at(mut self, recorded_at: i64) -> Self {
        self.recorded_at = Some(recorded_at);
        self
    }
}

/// A graph edge. `from` is the parent (earlier / source of custody);
/// `to` is the child (later / derived fact).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageEdge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    pub evidence_class: EvidenceClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_table: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<i64>,
}

impl LineageEdge {
    /// Construct an edge with only the required fields populated.
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
        kind: EdgeKind,
        evidence_class: EvidenceClass,
    ) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            kind,
            evidence_class,
            source_table: None,
            source_id: None,
            tenant_id: None,
            recorded_at: None,
        }
    }
}

/// Truncation marker emitted when a bounded query exceeds the
/// documented depth or node cap. Its shape is pinned to bound the
/// traversal risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruncationMarker {
    pub truncated: bool,
    pub depth_reached: u32,
    pub limit: u32,
}

impl TruncationMarker {
    /// Produce the canonical "depth reached the cap" marker.
    pub fn at_depth(depth_reached: u32, limit: u32) -> Self {
        Self {
            truncated: true,
            depth_reached,
            limit,
        }
    }

    /// Produce a marker for a query stopped by the node cap.
    pub fn at_node_cap(depth_reached: u32, limit: u32) -> Self {
        Self {
            truncated: true,
            depth_reached,
            limit,
        }
    }
}

/// Bounds applied to a traversal query to keep results finite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraversalBounds {
    /// Maximum number of hops away from the start node.
    pub max_depth: u32,
    /// Maximum number of distinct nodes to include (start included).
    pub max_nodes: u32,
}

impl TraversalBounds {
    /// Construct explicit bounds.
    pub fn new(max_depth: u32, max_nodes: u32) -> Self {
        Self {
            max_depth,
            max_nodes,
        }
    }
}

impl Default for TraversalBounds {
    fn default() -> Self {
        // Mirrors the conservative recursive-CTE caps upstream pinned.
        Self {
            max_depth: 20,
            max_nodes: 1_000,
        }
    }
}

/// Top-level lineage graph projection. A complete graph or a
/// query-bounded subgraph (with optional truncation marker).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageGraph {
    pub schema_version: String,
    pub nodes: Vec<LineageNode>,
    pub edges: Vec<LineageEdge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<TruncationMarker>,
}

impl LineageGraph {
    /// Construct an empty graph stamped with the current schema version.
    pub fn empty() -> Self {
        Self {
            schema_version: LINEAGE_GRAPH_SCHEMA_V1.to_string(),
            nodes: Vec::new(),
            edges: Vec::new(),
            truncated: None,
        }
    }

    /// Mark this projection as truncated at the documented depth bound.
    #[must_use]
    pub fn with_truncation(mut self, depth_reached: u32, limit: u32) -> Self {
        self.truncated = Some(TruncationMarker::at_depth(depth_reached, limit));
        self
    }

    /// Return true if any node or edge carries the requested evidence
    /// class.
    pub fn contains_evidence(&self, class: EvidenceClass) -> bool {
        self.nodes.iter().any(|n| n.evidence_class == class)
            || self.edges.iter().any(|e| e.evidence_class == class)
    }

    /// Return true if the projection was bounded short of completeness.
    pub fn is_truncated(&self) -> bool {
        self.truncated.map(|m| m.truncated).unwrap_or(false)
    }
}

/// In-memory builder that accumulates lineage nodes and edges and can
/// project the existing spine envelope hash chain.
#[derive(Debug, Default)]
pub struct LineageBuilder {
    nodes: BTreeMap<String, LineageNode>,
    edges: Vec<LineageEdge>,
}

impl LineageBuilder {
    /// Start an empty builder.
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edges: Vec::new(),
        }
    }

    /// Insert or replace a node (keyed by `id`).
    pub fn add_node(&mut self, node: LineageNode) -> &mut Self {
        self.nodes.insert(node.id.clone(), node);
        self
    }

    /// Append an edge.
    pub fn add_edge(&mut self, edge: LineageEdge) -> &mut Self {
        self.edges.push(edge);
        self
    }

    /// Project a chain of signed spine envelopes into lineage nodes and
    /// edges.
    ///
    /// Each envelope becomes a [`NodeKind::Envelope`] node identified by
    /// its `envelope_hash` and classed [`EvidenceClass::Verified`] (a
    /// signed, hash-committed fact). Each non-null `prev_envelope_hash`
    /// produces an [`EdgeKind::EnvelopeParent`] edge from the parent to
    /// the child, classed [`EvidenceClass::Observed`] (a link the spine
    /// recorded locally).
    ///
    /// The input should be a verified chain; this projector only reads
    /// already-present fields and never trusts the chain order itself.
    pub fn project_envelope_chain(&mut self, envelopes: &[Value]) -> SpineResult<&mut Self> {
        for envelope in envelopes {
            let envelope_hash = envelope
                .get("envelope_hash")
                .and_then(Value::as_str)
                .ok_or(SpineError::MissingField("envelope_hash"))?;
            let seq = envelope
                .get("seq")
                .and_then(Value::as_u64)
                .ok_or(SpineError::MissingField("seq"))?;
            let issuer = envelope
                .get("issuer")
                .and_then(Value::as_str)
                .ok_or(SpineError::MissingField("issuer"))?;
            let prev_hash = envelope
                .get("prev_envelope_hash")
                .ok_or(SpineError::MissingField("prev_envelope_hash"))?;

            let recorded_at = envelope
                .get("issued_at")
                .and_then(Value::as_str)
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.timestamp_millis());

            // Only claim Verified when the envelope's signature + hash actually verify; otherwise
            // it is merely Asserted (do not stamp the top trust tier on an unverified projection).
            let evidence = match crate::envelope::verify_envelope(envelope) {
                Ok(true) => EvidenceClass::Verified,
                _ => EvidenceClass::Asserted,
            };
            let mut node = LineageNode::new(envelope_hash, NodeKind::Envelope, evidence)
                .with_label(format!("{issuer}#{seq}"));
            node.source_id = Some(envelope_hash.to_string());
            node.source_table = Some("spine.envelope".to_string());
            if let Some(ms) = recorded_at {
                node.recorded_at = Some(ms);
            }
            self.add_node(node);

            if !prev_hash.is_null() {
                let parent = prev_hash
                    .as_str()
                    .ok_or(SpineError::MissingField("prev_envelope_hash"))?;
                let mut edge = LineageEdge::new(
                    parent,
                    envelope_hash,
                    EdgeKind::EnvelopeParent,
                    EvidenceClass::Observed,
                );
                edge.source_table = Some("spine.envelope".to_string());
                if let Some(ms) = recorded_at {
                    edge.recorded_at = Some(ms);
                }
                self.add_edge(edge);
            }
        }
        Ok(self)
    }

    /// Materialize the accumulated graph (full, untruncated).
    pub fn build_graph(&self) -> LineageGraph {
        LineageGraph {
            schema_version: LINEAGE_GRAPH_SCHEMA_V1.to_string(),
            nodes: self.nodes.values().cloned().collect(),
            edges: self.edges.clone(),
            truncated: None,
        }
    }

    /// Build a queryable index over the accumulated graph.
    pub fn build(&self) -> Lineage {
        Lineage::from_parts(
            self.nodes.values().cloned().collect(),
            self.edges.clone(),
        )
    }
}

/// Indexed, queryable lineage over in-memory nodes.
///
/// Holds forward (parent -> child) and reverse (child -> parent)
/// adjacency so ancestry and descendant queries are cheap and bounded.
#[derive(Debug, Default)]
pub struct Lineage {
    nodes: BTreeMap<String, LineageNode>,
    edges: Vec<LineageEdge>,
    /// child id -> indices of edges whose `to` equals the child.
    incoming: BTreeMap<String, Vec<usize>>,
    /// parent id -> indices of edges whose `from` equals the parent.
    outgoing: BTreeMap<String, Vec<usize>>,
}

impl Lineage {
    /// Build an index from a flat graph.
    pub fn from_graph(graph: LineageGraph) -> Self {
        Self::from_parts(graph.nodes, graph.edges)
    }

    fn from_parts(nodes: Vec<LineageNode>, edges: Vec<LineageEdge>) -> Self {
        let mut node_map = BTreeMap::new();
        for node in nodes {
            node_map.insert(node.id.clone(), node);
        }
        let mut incoming: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut outgoing: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, edge) in edges.iter().enumerate() {
            incoming.entry(edge.to.clone()).or_default().push(index);
            outgoing.entry(edge.from.clone()).or_default().push(index);
        }
        Self {
            nodes: node_map,
            edges,
            incoming,
            outgoing,
        }
    }

    /// Number of indexed nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of indexed edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Look up a node by id.
    pub fn node(&self, id: &str) -> Option<&LineageNode> {
        self.nodes.get(id)
    }

    /// Materialize the full graph (no truncation).
    pub fn graph(&self) -> LineageGraph {
        LineageGraph {
            schema_version: LINEAGE_GRAPH_SCHEMA_V1.to_string(),
            nodes: self.nodes.values().cloned().collect(),
            edges: self.edges.clone(),
            truncated: None,
        }
    }

    /// Bounded ancestry: the subgraph reachable by walking parent edges
    /// backward from `start`. Includes `start`. Stops and stamps a
    /// [`TruncationMarker`] when either bound is hit.
    pub fn ancestry(&self, start: &str, bounds: TraversalBounds) -> LineageGraph {
        self.traverse(start, bounds, Direction::Backward)
    }

    /// Bounded descendants: the subgraph reachable by walking child
    /// edges forward from `start`. Includes `start`.
    pub fn descendants(&self, start: &str, bounds: TraversalBounds) -> LineageGraph {
        self.traverse(start, bounds, Direction::Forward)
    }

    fn traverse(
        &self,
        start: &str,
        bounds: TraversalBounds,
        direction: Direction,
    ) -> LineageGraph {
        let mut out = LineageGraph::empty();

        // Unknown start id yields an empty (untruncated) projection.
        let Some(start_node) = self.nodes.get(start) else {
            return out;
        };

        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut seen_edges: BTreeSet<usize> = BTreeSet::new();
        let mut frontier: VecDeque<(String, u32)> = VecDeque::new();

        visited.insert(start.to_string());
        out.nodes.push(start_node.clone());
        frontier.push_back((start.to_string(), 0));

        let mut max_depth_seen: u32 = 0;
        let mut truncated: Option<TruncationMarker> = None;

        while let Some((current, depth)) = frontier.pop_front() {
            // Do not expand past the depth bound; record the boundary.
            if depth >= bounds.max_depth {
                let adjacency = match direction {
                    Direction::Backward => self.incoming.get(&current),
                    Direction::Forward => self.outgoing.get(&current),
                };
                if adjacency.map(|e| !e.is_empty()).unwrap_or(false) {
                    truncated = Some(TruncationMarker::at_depth(depth, bounds.max_depth));
                }
                continue;
            }

            let adjacency = match direction {
                Direction::Backward => self.incoming.get(&current),
                Direction::Forward => self.outgoing.get(&current),
            };
            let Some(edge_indices) = adjacency else {
                continue;
            };

            for &edge_index in edge_indices {
                let Some(edge) = self.edges.get(edge_index) else {
                    continue;
                };
                let neighbor = match direction {
                    Direction::Backward => edge.from.clone(),
                    Direction::Forward => edge.to.clone(),
                };

                if !visited.contains(&neighbor) {
                    if (visited.len() as u32) >= bounds.max_nodes {
                        truncated =
                            Some(TruncationMarker::at_node_cap(depth + 1, bounds.max_nodes));
                        continue;
                    }
                    if let Some(node) = self.nodes.get(&neighbor) {
                        visited.insert(neighbor.clone());
                        out.nodes.push(node.clone());
                        let next_depth = depth + 1;
                        max_depth_seen = max_depth_seen.max(next_depth);
                        frontier.push_back((neighbor.clone(), next_depth));
                    } else {
                        // Edge points outside the indexed node set.
                        continue;
                    }
                }

                if seen_edges.insert(edge_index) {
                    out.edges.push(edge.clone());
                }
            }
        }

        let _ = max_depth_seen;
        out.truncated = truncated;
        out
    }
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    /// Walk parent edges (toward ancestors).
    Backward,
    /// Walk child edges (toward descendants).
    Forward,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{build_signed_envelope, chain_head_from_envelope, now_rfc3339};
    use serde_json::json;
    use swarm_crypto::Keypair;

    fn custody_chain() -> Lineage {
        // asserted -> observed -> verified
        let mut builder = LineageBuilder::new();
        builder
            .add_node(
                LineageNode::new("prompt", NodeKind::Prompt, EvidenceClass::Asserted)
                    .with_label("caller prompt"),
            )
            .add_node(LineageNode::new(
                "tool",
                NodeKind::ToolCall,
                EvidenceClass::Observed,
            ))
            .add_node(LineageNode::new(
                "receipt",
                NodeKind::Receipt,
                EvidenceClass::Verified,
            ))
            .add_edge(LineageEdge::new(
                "prompt",
                "tool",
                EdgeKind::GuardToToolCall,
                EvidenceClass::Asserted,
            ))
            .add_edge(LineageEdge::new(
                "tool",
                "receipt",
                EdgeKind::ToolCallToReceipt,
                EvidenceClass::Observed,
            ));
        builder.build()
    }

    #[test]
    fn truncation_marker_shape_is_pinned() {
        let marker = TruncationMarker::at_depth(20, 20);
        let json = serde_json::to_value(marker).unwrap();
        assert_eq!(json["truncated"], serde_json::json!(true));
        assert_eq!(json["depth_reached"], serde_json::json!(20));
        assert_eq!(json["limit"], serde_json::json!(20));
    }

    #[test]
    fn empty_graph_carries_schema_version() {
        let g = LineageGraph::empty();
        assert_eq!(g.schema_version, LINEAGE_GRAPH_SCHEMA_V1);
        assert!(g.nodes.is_empty());
        assert!(g.edges.is_empty());
        assert!(g.truncated.is_none());
    }

    #[test]
    fn evidence_class_round_trips_snake_case() {
        let v = serde_json::to_value(EvidenceClass::Asserted).unwrap();
        assert_eq!(v, serde_json::json!("asserted"));
        let v = serde_json::to_value(EvidenceClass::Observed).unwrap();
        assert_eq!(v, serde_json::json!("observed"));
        let v = serde_json::to_value(EvidenceClass::Verified).unwrap();
        assert_eq!(v, serde_json::json!("verified"));
    }

    #[test]
    fn contains_evidence_walks_nodes_and_edges() {
        let g = custody_chain().graph();
        assert!(g.contains_evidence(EvidenceClass::Asserted));
        assert!(g.contains_evidence(EvidenceClass::Observed));
        assert!(g.contains_evidence(EvidenceClass::Verified));
    }

    #[test]
    fn ancestry_walks_asserted_to_verified_custody() {
        let lineage = custody_chain();
        let g = lineage.ancestry("receipt", TraversalBounds::default());

        let ids: BTreeSet<&str> = g.nodes.iter().map(|n| n.id.as_str()).collect();
        assert!(ids.contains("receipt"));
        assert!(ids.contains("tool"));
        assert!(ids.contains("prompt"));
        assert_eq!(ids.len(), 3);
        assert_eq!(g.edges.len(), 2);
        assert!(!g.is_truncated());
        // The full evidence taxonomy is preserved in the ancestry view.
        assert!(g.contains_evidence(EvidenceClass::Asserted));
        assert!(g.contains_evidence(EvidenceClass::Verified));
    }

    #[test]
    fn descendants_walks_forward_from_prompt() {
        let lineage = custody_chain();
        let g = lineage.descendants("prompt", TraversalBounds::default());
        let ids: BTreeSet<&str> = g.nodes.iter().map(|n| n.id.as_str()).collect();
        assert!(ids.contains("prompt"));
        assert!(ids.contains("tool"));
        assert!(ids.contains("receipt"));
        assert!(!g.is_truncated());
    }

    #[test]
    fn ancestry_of_unknown_node_is_empty() {
        let lineage = custody_chain();
        let g = lineage.ancestry("nope", TraversalBounds::default());
        assert!(g.nodes.is_empty());
        assert!(g.edges.is_empty());
        assert!(!g.is_truncated());
    }

    #[test]
    fn bounded_traversal_truncates_at_depth() {
        // Build a deep linear chain n0 <- n1 <- ... <- n10, where each
        // edge points from the older node to the newer one, so ancestry
        // of the tip must walk backward through every parent.
        let mut builder = LineageBuilder::new();
        for i in 0..=10 {
            builder.add_node(LineageNode::new(
                format!("n{i}"),
                NodeKind::Envelope,
                EvidenceClass::Verified,
            ));
        }
        for i in 0..10 {
            builder.add_edge(LineageEdge::new(
                format!("n{i}"),
                format!("n{}", i + 1),
                EdgeKind::EnvelopeParent,
                EvidenceClass::Observed,
            ));
        }
        let lineage = builder.build();

        // Cap depth at 3: from the tip we can reach n10, n9, n8, n7.
        let bounds = TraversalBounds::new(3, 1_000);
        let g = lineage.ancestry("n10", bounds);

        assert!(g.is_truncated(), "deep chain must be truncated");
        let marker = g.truncated.unwrap();
        assert!(marker.truncated);
        assert_eq!(marker.depth_reached, 3);
        assert_eq!(marker.limit, 3);

        let ids: BTreeSet<&str> = g.nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids.len(), 4);
        assert!(ids.contains("n10"));
        assert!(ids.contains("n7"));
        assert!(!ids.contains("n6"));
    }

    #[test]
    fn bounded_traversal_truncates_at_node_cap() {
        let mut builder = LineageBuilder::new();
        for i in 0..=10 {
            builder.add_node(LineageNode::new(
                format!("n{i}"),
                NodeKind::Envelope,
                EvidenceClass::Verified,
            ));
        }
        for i in 0..10 {
            builder.add_edge(LineageEdge::new(
                format!("n{i}"),
                format!("n{}", i + 1),
                EdgeKind::EnvelopeParent,
                EvidenceClass::Observed,
            ));
        }
        let lineage = builder.build();

        // Generous depth, but cap nodes at 2 (start + one parent).
        let bounds = TraversalBounds::new(100, 2);
        let g = lineage.ancestry("n10", bounds);

        assert!(g.is_truncated());
        let ids: BTreeSet<&str> = g.nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn projects_signed_envelope_chain() {
        let keypair = Keypair::generate();
        let first =
            build_signed_envelope(&keypair, 1, None, json!({"type": "init"}), now_rfc3339())
                .unwrap();
        let first_hash = chain_head_from_envelope(&first).unwrap().envelope_hash;
        let second = build_signed_envelope(
            &keypair,
            2,
            Some(first_hash.clone()),
            json!({"type": "step"}),
            now_rfc3339(),
        )
        .unwrap();
        let second_hash = chain_head_from_envelope(&second).unwrap().envelope_hash;

        let mut builder = LineageBuilder::new();
        builder
            .project_envelope_chain(&[first, second])
            .unwrap();
        let lineage = builder.build();

        assert_eq!(lineage.node_count(), 2);
        assert_eq!(lineage.edge_count(), 1);

        let head = lineage.node(&second_hash).unwrap();
        assert_eq!(head.kind, NodeKind::Envelope);
        assert_eq!(head.evidence_class, EvidenceClass::Verified);

        // Ancestry of the chain head reaches the genesis envelope.
        let g = lineage.ancestry(&second_hash, TraversalBounds::default());
        let ids: BTreeSet<&str> = g.nodes.iter().map(|n| n.id.as_str()).collect();
        assert!(ids.contains(first_hash.as_str()));
        assert!(ids.contains(second_hash.as_str()));
        // Signed envelopes are Verified; the recorded link is Observed.
        assert!(g.contains_evidence(EvidenceClass::Verified));
        assert!(g.contains_evidence(EvidenceClass::Observed));
    }

    #[test]
    fn project_envelope_chain_rejects_missing_hash() {
        let mut builder = LineageBuilder::new();
        let bad = json!({"seq": 1, "issuer": "x", "prev_envelope_hash": null});
        let err = builder.project_envelope_chain(&[bad]).unwrap_err();
        assert!(matches!(err, SpineError::MissingField("envelope_hash")));
    }

    #[test]
    fn lineage_graph_serde_roundtrip() {
        let g = custody_chain().graph();
        let json = serde_json::to_string(&g).unwrap();
        let restored: LineageGraph = serde_json::from_str(&json).unwrap();
        assert_eq!(g, restored);
    }
}
