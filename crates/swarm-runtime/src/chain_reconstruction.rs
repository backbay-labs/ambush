//! CHAIN-01: kill-chain reconstruction — a read-only walker over the
//! knowledge graph (`sphinx_agent::KnowledgeGraphSnapshot`) that maps
//! observed technique/stage paths onto the stage ordering declared by a
//! `sequences/kill-chain-v1.yaml` rule's `attack_chain`.
//!
//! ## Where the stage ordering comes from
//!
//! `sequence_detector::KillChainSequenceRule`/`KillChainTechnique` (the
//! parsed form of `attack_chain`) are private to that module — CHAIN-02
//! (`sphinx_agent::extract_kill_chain_sequence_match`) already established
//! the precedent of reading the rule/technique shape independently rather
//! than reaching into those private types. This module follows the same
//! precedent: [`load_kill_chain_stage_rules`] parses the same YAML shape on
//! its own into [`KillChainStageRule`]/[`KillChainStageTechnique`], and
//! [`load_kill_chain_stage_rules_from_profile`] takes the loaded
//! `sequence_detector::KillChainSequenceProfile` (its `rules_path`) so a
//! caller that already holds the profile the detector was configured with
//! can hand it straight to reconstruction without re-deriving a path.
//!
//! ## How an "observed path" maps onto `attack_chain`
//!
//! A rule's `attack_chain` is an ORDERED list of
//! `(technique_id, kill_chain_stage)` pairs — the kill chain's canonical
//! stage sequence. The graph does not independently discover that order (a
//! single sequence-detector match persists as a star: one `Engagement` node
//! fanned out to each matched `AttackTechnique` node by its own
//! `SemanticRelation::KillChainStage` edge — see CHAIN-02 — which is
//! symmetric under `provenance_paths`' undirected traversal and carries no
//! ordering by itself). So the mapping anchors on the RULE's declared
//! order and asks the graph only "were these stages actually observed, and
//! observed close enough together to be the same chain":
//!
//! 1. Walk `attack_chain` from index 0. For each technique, look up whether
//!    an `AttackTechniqueNode` with that `technique_id` exists anywhere in
//!    the snapshot (nodes merge by `technique_id`, so there is at most one).
//!    The first technique with no matching node ends the walk.
//! 2. For each consecutive pair in that run, [`stage_connection`] decides
//!    whether they are connected within `max_hops`. If no path connects
//!    them — including through a shared `Engagement` hub, a causal chain
//!    (`ProcessParentChild`/`NetworkFlowOrigin`/...), or a temporal
//!    co-occurrence edge — the run stops there too: two techniques that
//!    were each observed but never in the same causal/temporal/semantic
//!    context are not treated as one kill chain.
//! 3. The longest such run, if it reaches at least
//!    [`MIN_RECONSTRUCTED_STAGES`] stages, is returned as a
//!    [`ReconstructedChain`] carrying the matched ordered stages, technique
//!    ids, graph node ids, and the per-hop [`ProvenancePath`] evidence.
//!
//! This mirrors `sequence_detector::evaluate_rule`'s own prefix semantics
//! (it also anchors on `attack_chain`'s declared order from index 0 and
//! accepts a `>= MIN_PARTIAL_PREFIX_LEN`-long prefix as a partial match) —
//! reconstruction is the same "prefix of the declared order" shape, read
//! back out of durable graph evidence instead of a live event window.
//!
//! ## The hub-degree cap, and why a naive pairwise walk is not enough
//!
//! [`KnowledgeGraphSnapshot::provenance_paths`] is the graph's SOLE
//! multi-hop read path (this module never re-walks `edges`/`nodes` to build
//! its own adjacency), and [`stage_connection`] always tries it directly
//! first: `provenance_paths(stage_i, stage_j, max_hops)`. For a CHAIN-02
//! sequence match this walks `stage_i -> Engagement -> stage_j` — but the
//! Engagement is reached at hop > 0 in that call, so Phase 296's hub-degree
//! cap (`PROVENANCE_HUB_DEGREE_CAP`, 32) applies to it: if that Engagement's
//! TOTAL degree exceeds the cap it is never expanded through. Critically,
//! that degree is not just this chain's 3-ish stage edges — every OTHER
//! edge the Engagement carries counts too, including entity edges to
//! unrelated entities and one temporal edge per OTHER engagement sharing an
//! entity in the temporal window (`sphinx_agent.rs`'s `ingest_pheromone`,
//! ~531-568). A busy Engagement can cross 32 for reasons that have nothing
//! to do with this specific rule match, and a naive pairwise walk would
//! then silently return no reconstruction for an already-detected,
//! legitimate multi-stage chain.
//!
//! `provenance_paths`'s cap explicitly EXEMPTS the literal `from` node's own
//! first expansion (it is the query's own starting point, not a hub the
//! search wandered into). So when the direct pairwise call fails,
//! `stage_connection` falls back to querying FROM every KillChainStage
//! anchor already known to reach either stage, found by
//! [`kill_chain_stage_anchors`] (a plain edge-attribute scan, not a second
//! traversal): `provenance_paths(anchor, stage_i, max_hops)` and
//! `provenance_paths(anchor, stage_j, max_hops)`, each with the anchor as
//! the literal `from` and therefore cap-exempt for its own first expansion.
//! If both succeed the two paths are spliced (via [`splice_through_anchor`])
//! into the logical `stage_i -> anchor -> stage_j` path.
//!
//! **This fallback is scoped to `Engagement` anchors ONLY, never
//! `ThreatPattern`.** `sphinx_agent.rs` emits `KillChainStage` edges from
//! both node kinds, but they have very different lineage: an `Engagement`
//! is keyed by `observation_id` (one observation, one hunt) — anchoring on
//! it is safe because it IS the observation record that produced the
//! evidence being reconstructed, so the exemption never reaches past that
//! one observation's own (possibly-unrelated) degree. A `ThreatPattern` is
//! keyed only by `threat_class` and merged GLOBALLY across every
//! observation of that class over the graph's whole lifetime — anchoring
//! on it would let the exemption bridge mutually-disconnected hunts that
//! merely share a threat class into one fabricated chain, exactly what the
//! hub-degree cap
//! (`provenance_paths_hub_degree_cap_prevents_bridging_unrelated_hunt_subgraphs`
//! in `sphinx_agent.rs`) exists to prevent. [`kill_chain_stage_anchors`]
//! therefore filters candidates to actual `EngagementNode`s in the
//! snapshot (by node kind, not merely by which edge named them) — see
//! `reconstruct_kill_chains_does_not_bridge_disconnected_hunts_through_a_shared_threat_pattern`
//! for the pinned regression, and
//! `reconstruct_kill_chains_survives_a_high_degree_engagement_hub` for the
//! truncation case this fallback still fixes.
//!
//! A rule whose stages happen to span multiple `Engagement` anchors
//! connected to each other by causal/temporal edges is still handled by
//! the direct pairwise call as long as those intermediate nodes
//! individually stay under the cap; a chain that would need to bridge
//! through more than one over-cap `Engagement` remains a known, narrower
//! residual limitation.
//!
//! Read-only: nothing here calls `upsert_node`/`upsert_edge` or otherwise
//! mutates a `KnowledgeGraphSnapshot`.

use serde::Deserialize;
use std::fs;

use crate::sequence_detector::KillChainSequenceProfile;
use crate::sphinx_agent::{
    KnowledgeGraphEdge, KnowledgeGraphNode, KnowledgeGraphSnapshot, ProvenancePath,
    SemanticRelation,
};
use swarm_spine::{ReconstructedChainHop, ReconstructedKillChain};

/// A prefix shorter than this (a single observed stage with nothing
/// connected to it) is not a reconstructed chain — mirrors
/// `sequence_detector::MIN_PARTIAL_PREFIX_LEN`.
const MIN_RECONSTRUCTED_STAGES: usize = 2;

#[derive(Debug, thiserror::Error)]
pub enum ChainReconstructionError {
    #[error("failed to read kill-chain rules `{path}`: {source}")]
    ReadRules {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse kill-chain rules `{path}`: {source}")]
    ParseRules {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },
}

/// One `sequences/kill-chain-v1.yaml` rule's declared `attack_chain` stage
/// ordering, as loaded by [`load_kill_chain_stage_rules`]. Intentionally a
/// separate, minimal type from `sequence_detector::KillChainSequenceRule`
/// (private to that module, and carrying detector-matching fields —
/// `steps`, `max_span_ms`, `threat_class`, ... — this module never needs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillChainStageRule {
    pub rule_id: String,
    pub rule_name: String,
    pub attack_chain: Vec<KillChainStageTechnique>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillChainStageTechnique {
    pub technique_id: String,
    pub name: String,
    pub kill_chain_stage: String,
}

/// A rule's `attack_chain` prefix that reconstruction found observed and
/// connected, in the rule's declared order. `stages`, `technique_ids` and
/// `node_ids` are parallel (same length, same order); `hops[i]` is the
/// `provenance_paths` evidence connecting `node_ids[i]` to `node_ids[i + 1]`,
/// so `hops.len() == node_ids.len() - 1`.
#[derive(Debug, Clone, PartialEq)]
pub struct ReconstructedChain {
    pub rule_id: String,
    pub rule_name: String,
    pub stages: Vec<String>,
    pub technique_ids: Vec<String>,
    pub node_ids: Vec<String>,
    pub hops: Vec<ProvenancePath>,
}

/// Parses the `sequences/kill-chain-v1.yaml` shape at `rules_path` into its
/// stage-ordering view (`id`/`name`/`attack_chain` only — every other field
/// the file carries, e.g. `steps`/`max_span_ms`/`threat_class`, is ignored
/// rather than rejected, since this is a read of a file another detector
/// owns, not a schema this module is responsible for validating).
pub fn load_kill_chain_stage_rules(
    rules_path: &str,
) -> Result<Vec<KillChainStageRule>, ChainReconstructionError> {
    let path = rules_path.trim();
    let raw = fs::read_to_string(path).map_err(|source| ChainReconstructionError::ReadRules {
        path: path.to_string(),
        source,
    })?;
    let file: KillChainRuleSetFile =
        serde_yaml::from_str(&raw).map_err(|source| ChainReconstructionError::ParseRules {
            path: path.to_string(),
            source,
        })?;
    Ok(file
        .rules
        .into_iter()
        .map(|rule| KillChainStageRule {
            rule_id: rule.id,
            rule_name: rule.name,
            attack_chain: rule
                .attack_chain
                .into_iter()
                .map(|technique| KillChainStageTechnique {
                    technique_id: technique.technique_id,
                    name: technique.name,
                    kill_chain_stage: technique.kill_chain_stage,
                })
                .collect(),
        })
        .collect())
}

/// Same as [`load_kill_chain_stage_rules`], reading the path out of an
/// already-loaded `sequence_detector::KillChainSequenceProfile` (the
/// profile `KillChainSequenceDetector::from_profile` is itself constructed
/// from) rather than requiring the caller to re-derive the rules path.
pub fn load_kill_chain_stage_rules_from_profile(
    profile: &KillChainSequenceProfile,
) -> Result<Vec<KillChainStageRule>, ChainReconstructionError> {
    load_kill_chain_stage_rules(&profile.rules_path)
}

#[derive(Debug, Clone, Deserialize)]
struct KillChainRuleSetFile {
    #[serde(default)]
    rules: Vec<KillChainRuleFile>,
}

#[derive(Debug, Clone, Deserialize)]
struct KillChainRuleFile {
    id: String,
    #[serde(default)]
    name: String,
    attack_chain: Vec<KillChainTechniqueFile>,
}

#[derive(Debug, Clone, Deserialize)]
struct KillChainTechniqueFile {
    technique_id: String,
    #[serde(default)]
    name: String,
    kill_chain_stage: String,
}

/// Reconstructs every rule in `rules` that has an observed, connected
/// `attack_chain` prefix of at least [`MIN_RECONSTRUCTED_STAGES`] stages in
/// `snapshot` — see the module doc for the mapping rule. Read-only: `snapshot`
/// is never mutated. `max_hops` bounds each individual stage-to-stage hop
/// (not the whole chain), passed straight through to
/// `KnowledgeGraphSnapshot::provenance_paths`, which already bounds its own
/// BFS by `max_hops` and by its hub-degree cap — so this walk terminates for
/// any finite snapshot regardless of cycles in its edges.
pub fn reconstruct_kill_chains(
    snapshot: &KnowledgeGraphSnapshot,
    rules: &[KillChainStageRule],
    max_hops: usize,
) -> Vec<ReconstructedChain> {
    rules
        .iter()
        .filter_map(|rule| reconstruct_rule(snapshot, rule, max_hops))
        .collect()
}

fn reconstruct_rule(
    snapshot: &KnowledgeGraphSnapshot,
    rule: &KillChainStageRule,
    max_hops: usize,
) -> Option<ReconstructedChain> {
    let mut node_ids: Vec<String> = Vec::new();
    let mut hops: Vec<ProvenancePath> = Vec::new();

    for technique in &rule.attack_chain {
        let Some(node_id) = attack_technique_node_id(snapshot, &technique.technique_id) else {
            // This technique was never observed: the declared-order prefix
            // ends here, whatever comes later in `attack_chain`.
            break;
        };
        if let Some(previous_node_id) = node_ids.last() {
            let Some(hop) = stage_connection(snapshot, previous_node_id, &node_id, max_hops) else {
                // Observed, but not connected to the previous stage within
                // `max_hops`: not the same chain, so the prefix ends here.
                break;
            };
            hops.push(hop);
        }
        node_ids.push(node_id);
    }

    if node_ids.len() < MIN_RECONSTRUCTED_STAGES {
        return None;
    }

    let matched = &rule.attack_chain[..node_ids.len()];
    Some(ReconstructedChain {
        rule_id: rule.rule_id.clone(),
        rule_name: rule.rule_name.clone(),
        stages: matched
            .iter()
            .map(|technique| technique.kill_chain_stage.clone())
            .collect(),
        technique_ids: matched
            .iter()
            .map(|technique| technique.technique_id.clone())
            .collect(),
        node_ids,
        hops,
    })
}

/// Looks up the `AttackTechniqueNode` matching `technique_id` (there is at
/// most one — `SphinxAgent::upsert_node` merges every observation of a
/// given `technique_id` into a single node, regardless of which rule or
/// detector reported it) and returns its graph `node_id`. A plain scan of
/// the snapshot's public `nodes`, not a graph walk — the graph's SOLE
/// multi-hop traversal stays `provenance_paths`.
fn attack_technique_node_id(
    snapshot: &KnowledgeGraphSnapshot,
    technique_id: &str,
) -> Option<String> {
    snapshot.nodes.iter().find_map(|node| match node {
        KnowledgeGraphNode::AttackTechnique(technique)
            if technique.technique_id == technique_id =>
        {
            Some(technique.node_id.clone())
        }
        _ => None,
    })
}

/// Whether `from_node` connects to `to_node` within `max_hops`, returning
/// the connecting evidence if so. See the module doc's "hub-degree cap"
/// section for the full rationale; in short: try the direct provenance
/// path first, and if a busy KillChainStage anchor's degree blocks it,
/// fall back to querying FROM that anchor (cap-exempt for its own first
/// expansion) to each side independently.
fn stage_connection(
    snapshot: &KnowledgeGraphSnapshot,
    from_node: &str,
    to_node: &str,
    max_hops: usize,
) -> Option<ProvenancePath> {
    if let Some(path) = snapshot
        .provenance_paths(from_node, to_node, max_hops)
        .into_iter()
        .next()
    {
        return Some(path);
    }

    for anchor in kill_chain_stage_anchors(snapshot, from_node, to_node) {
        let anchor_to_from = snapshot
            .provenance_paths(&anchor, from_node, max_hops)
            .into_iter()
            .next();
        let anchor_to_to = snapshot
            .provenance_paths(&anchor, to_node, max_hops)
            .into_iter()
            .next();
        if let (Some(anchor_to_from), Some(anchor_to_to)) = (anchor_to_from, anchor_to_to) {
            return Some(splice_through_anchor(anchor_to_from, anchor_to_to));
        }
    }

    None
}

/// Candidate busy-hub-fallback anchors for the `from_node`/`to_node` pair:
/// every **`EngagementNode`** that is the `from_node_id` of a
/// `SemanticRelation::KillChainStage` edge landing on either one.
///
/// `sphinx_agent.rs` emits `KillChainStage` edges from TWO different node
/// kinds: `Engagement` (keyed by `observation_id` — one observation, one
/// hunt) and `ThreatPattern` (keyed only by `threat_class` — merged
/// GLOBALLY across every observation of that class, over the graph's whole
/// lifetime, regardless of hunt). Anchoring the busy-hub fallback on an
/// `Engagement` is safe: it IS the single observation record that produced
/// the evidence being reconstructed, so the `from`-exemption never does
/// more than let reconstruction see past that one observation's own,
/// possibly-unrelated, degree. Anchoring on a `ThreatPattern` would NOT be
/// safe — it is exactly the kind of shared, hunt-agnostic hub Phase 296's
/// hub-degree cap exists to stop from bridging mutually-disconnected hunts
/// (`provenance_paths_hub_degree_cap_prevents_bridging_unrelated_hunt_subgraphs`
/// in `sphinx_agent.rs`), and the `from`-exemption would defeat that cap
/// for it precisely because it IS the query's own starting point in this
/// fallback. So this function filters candidates to `Engagement` nodes
/// ONLY — a `ThreatPattern` (or any other node kind) is never returned,
/// no matter its degree. See
/// `reconstruct_kill_chains_does_not_bridge_disconnected_hunts_through_a_shared_threat_pattern`
/// for the regression this excludes.
///
/// Implementation: a plain linear scan of the snapshot's public `edges` by
/// attribute, filtered against the snapshot's public `nodes` by kind — not
/// a graph walk. The graph's SOLE multi-hop traversal stays
/// `provenance_paths`.
fn kill_chain_stage_anchors(
    snapshot: &KnowledgeGraphSnapshot,
    from_node: &str,
    to_node: &str,
) -> Vec<String> {
    let mut anchors = snapshot
        .edges
        .iter()
        .filter_map(|edge| match edge {
            KnowledgeGraphEdge::Semantic(semantic)
                if semantic.relation == SemanticRelation::KillChainStage
                    && (semantic.to_node_id == from_node || semantic.to_node_id == to_node) =>
            {
                Some(semantic.from_node_id.clone())
            }
            _ => None,
        })
        .filter(|candidate| is_single_observation_anchor(snapshot, candidate))
        .collect::<Vec<_>>();
    anchors.sort();
    anchors.dedup();
    anchors
}

/// True only if `node_id` names an `EngagementNode` in `snapshot` — the
/// single-observation, single-hunt node kind `kill_chain_stage_anchors` is
/// restricted to. `ThreatPattern` (globally merged by `threat_class`) and
/// every other node kind return `false`, including when `node_id` names no
/// node at all (an unknown id is never treated as a safe anchor by
/// default).
fn is_single_observation_anchor(snapshot: &KnowledgeGraphSnapshot, node_id: &str) -> bool {
    snapshot.nodes.iter().any(|node| {
        matches!(node, KnowledgeGraphNode::Engagement(engagement) if engagement.node_id == node_id)
    })
}

/// Splices `anchor -> from_node` and `anchor -> to_node` provenance paths
/// into the logical `from_node -> anchor -> to_node` path: reverses the
/// first, then appends the second's nodes/edges (skipping its leading
/// `anchor` node, already the reversed first path's last node, so the
/// result stays a well-formed [`ProvenancePath`] — `edge_ids.len() ==
/// node_ids.len() - 1`).
fn splice_through_anchor(
    anchor_to_from: ProvenancePath,
    anchor_to_to: ProvenancePath,
) -> ProvenancePath {
    let mut node_ids = anchor_to_from.node_ids;
    node_ids.reverse();
    let mut edge_ids = anchor_to_from.edge_ids;
    edge_ids.reverse();

    node_ids.extend(anchor_to_to.node_ids.into_iter().skip(1));
    edge_ids.extend(anchor_to_to.edge_ids);

    ProvenancePath { node_ids, edge_ids }
}

/// One side of a cross-hunt kill-chain join candidate (CHAIN-03): an
/// incident plus the graph node id that anchors its own observations — its
/// `Engagement` node id in the knowledge graph.
///
/// Resolving a `hunt_id`/`CorrelatedIncident` to that anchor id is producer
/// wiring, the same kind of scope [`load_kill_chain_stage_rules`]'s module
/// doc and Task 2's report both name as deliberately out of CHAIN-01/02's
/// scope; [`join_cross_hunt_kill_chain`] follows
/// `CorrelationEngine::graph_provenance_link`'s existing precedent instead
/// (`correlation.rs`): that function takes literal graph node ids and
/// leaves resolving a domain concept to one entirely to its caller, rather
/// than doing that resolution itself. The caller here already holds both
/// the `CorrelatedIncident` and the graph snapshot, so it is in the right
/// position to supply the anchor directly.
#[derive(Debug, Clone, Copy)]
pub struct CrossHuntIncidentAnchor<'a> {
    pub incident_id: &'a str,
    pub hunt_ids: &'a [String],
    pub anchor_node_id: &'a str,
}

/// True only if `node_id` names a node that is GLOBALLY merged across every
/// hunt's whole lifetime, by a bare CLASSIFICATION key rather than by any
/// hunt- or observation-specific identity: `ThreatPattern` (merged by
/// `threat_class`) and `AttackTechnique` (merged by `technique_id` — see
/// `sphinx_agent.rs`'s `attack_technique_node_id`/`SphinxAgent::upsert_node`,
/// which folds every observation of a given `technique_id` into ONE node
/// regardless of hunt, exactly the same way `ThreatPattern` folds every
/// observation of a `threat_class`). Neither is evidence of a genuine
/// relationship between two hunts that both happen to touch it. See the
/// module doc's "hub-degree cap" section for why `Engagement`
/// (single-observation, single-hunt) is safe here and these two are not.
///
/// **Fix round 1 (Critical):** the original version of this function
/// excluded only `ThreatPattern`. A review PoC showed `AttackTechnique` is
/// merged the exact same way and is reached constantly in this module's own
/// traversal (it is what `chain.node_ids` names) — hunt-a's own
/// self-contained, genuine chain got relabeled as "spanning hunt-b" merely
/// because hunt-b independently touched the same shared, low-degree
/// `AttackTechnique` node, with `cross_hunt_bridges` literally routed
/// through it. See
/// `join_cross_hunt_kill_chain_does_not_bridge_hunts_through_a_shared_attack_technique`
/// for the pinned regression (verified to fail before this fix, in the
/// same session, before being fixed).
///
/// `Entity`/`Process` nodes are ALSO shared across observations, but keyed
/// by a concrete entity/process identity (an actual host, user, or pid)
/// rather than by classification alone — two hunts genuinely touching the
/// same host or process IS itself real, hunt-specific evidence, not a
/// classification coincidence, so those are deliberately NOT excluded here.
/// [`causal_bridge`] reaches such a concrete node only via a `Causal`-only
/// walk ([`KnowledgeGraphSnapshot::causal_provenance_paths`]), so a shared
/// `Entity` tied to the two hunts by non-causal edges alone is never even on
/// the bridge path — see
/// `join_cross_hunt_kill_chain_does_not_bridge_hunts_that_share_an_entity_without_a_causal_edge`.
fn is_globally_merged_classification_node(
    snapshot: &KnowledgeGraphSnapshot,
    node_id: &str,
) -> bool {
    snapshot.nodes.iter().any(|node| {
        matches!(node, KnowledgeGraphNode::ThreatPattern(pattern) if pattern.node_id == node_id)
            || matches!(node, KnowledgeGraphNode::AttackTechnique(technique) if technique.node_id == node_id)
    })
}

/// Whether `path` touches NO globally-merged classification node anywhere
/// on it (either endpoint or any interior hop) per
/// [`is_globally_merged_classification_node`].
///
/// This is deliberately stricter than [`stage_connection`]'s hub-degree-cap
/// reliance: `provenance_paths` only refuses to *expand through* an
/// over-cap node, so a LOW-degree classification node — e.g. one linked to
/// only the two hunts under test, nowhere near
/// `KnowledgeGraphSnapshot::PROVENANCE_HUB_DEGREE_CAP` — would sail through
/// the cap entirely and still get returned as a "connecting" path. Cross-hunt
/// joining is exactly the place CHAIN-02/T2's fabricated-bridging failure
/// mode would resurface if this module trusted `provenance_paths`' hub cap
/// alone (see the module doc's "hub-degree cap" section and Task 2's
/// report), so this checks node KIND directly, independent of degree.
fn path_is_free_of_globally_merged_classification_nodes(
    snapshot: &KnowledgeGraphSnapshot,
    path: &ProvenancePath,
) -> bool {
    !path
        .node_ids
        .iter()
        .any(|node_id| is_globally_merged_classification_node(snapshot, node_id))
}

fn hunts_are_disjoint(hunt_ids_a: &[String], hunt_ids_b: &[String]) -> bool {
    !hunt_ids_a
        .iter()
        .any(|hunt_id| hunt_ids_b.contains(hunt_id))
}

fn to_reconstructed_chain_hop(path: ProvenancePath) -> ReconstructedChainHop {
    ReconstructedChainHop {
        node_ids: path.node_ids,
        edge_ids: path.edge_ids,
    }
}

/// A bounded-hop connection between `from` and `to` that qualifies as a
/// genuine cross-hunt CAUSAL bridge (CHAIN-03's own wording, "connected by a
/// causal path").
///
/// **Traversal is `Causal`-only.** This walks
/// [`KnowledgeGraphSnapshot::causal_provenance_paths`], NOT the all-edge
/// `provenance_paths`, so every edge on the returned path is a genuine
/// `Causal` edge by construction. This is the structural fix for the
/// cross-hunt fabricated-bridging class: an all-edge path plus a post-hoc
/// "does SOME edge on it happen to be causal?" check was position-blind — a
/// causal edge entirely INTERNAL to one hunt's own subgraph satisfied it
/// while the actual cross-hunt hop was made of non-causal
/// `Entity`/`Semantic`/`Temporal` connectivity (mere co-reference of a
/// shared host, not a causal relationship). Under a causal-only walk a
/// shared waypoint is reachable ONLY if BOTH hunts genuinely causally
/// interacted with it, so that whole class cannot arise. See
/// `join_cross_hunt_kill_chain_does_not_bridge_through_an_intra_hunt_causal_edge_and_a_shared_entity`
/// for the pinned regression (verified to fail before this fix, in the same
/// session, before being fixed).
///
/// **The classification-node exclusion still applies.** A globally-merged
/// classification node (`ThreatPattern`/`AttackTechnique`) does not model a
/// concrete causal actor and must never be a bridge waypoint even if some
/// producer were to attach `Causal` edges to it, so the causal-only path is
/// still rejected when it routes through one, per
/// [`path_is_free_of_globally_merged_classification_nodes`] — see
/// `join_cross_hunt_kill_chain_does_not_bridge_hunts_through_a_shared_threat_pattern`.
/// A shared CONCRETE node (`Entity`/`Process`/`File`/`NetworkFlow`) reached
/// by genuine causal edges on both sides IS a real causal relationship and
/// is accepted, bounded by the causal-only hub-degree cap for popular
/// infrastructure — see
/// `join_cross_hunt_kill_chain_joins_two_disjoint_hunts_through_a_shared_causal_process`.
///
/// `causal_provenance_paths` returns at most one path (its BFS returns as
/// soon as it reaches `to`), so there is no "try a different path" fallback
/// here: if the one path it finds routes through a classification node, this
/// reports no connection at all, the same fail-closed choice
/// [`stage_connection`]'s callers already make for "not the same chain" -- a
/// false negative (missing a genuine but longer alternate path) is
/// preferable to a false positive (trusting a fabricated bridge).
fn causal_bridge(
    snapshot: &KnowledgeGraphSnapshot,
    from: &str,
    to: &str,
    max_hops: usize,
) -> Option<ProvenancePath> {
    let path = snapshot
        .causal_provenance_paths(from, to, max_hops)
        .into_iter()
        .next()?;
    if path_is_free_of_globally_merged_classification_nodes(snapshot, &path) {
        Some(path)
    } else {
        None
    }
}

/// Whether `chain`'s own reconstructed evidence is directly attributable to
/// the hunt `anchor` anchors: true if `anchor` has a bounded ONE-HOP edge to
/// at least one of `chain.node_ids` — the exact shape CHAIN-02 emits
/// (`Engagement --KillChainStage--> AttackTechnique`), i.e. this hunt's own
/// direct observation, not a multi-hop inference through anything else.
///
/// Deliberately NOT a general multi-hop reachability search (what this
/// function used to be, via [`causal_bridge`], before fix round 1).
/// `chain.node_ids` are always `AttackTechnique` nodes — a globally-merged
/// classification node BY DEFINITION as the intended destination here,
/// unlike [`causal_bridge`]'s own endpoints, which must never be one.
/// Widening this to a multi-hop search would reopen the exact same
/// fabricated-attribution risk one level removed: an anchor could "reach"
/// an unrelated rule's technique node via some OTHER shared classification
/// node that has nothing to do with the actually-validated hunt-to-hunt
/// bridge. A direct, one-hop edge is exactly what CHAIN-02 already means by
/// "this hunt observed this stage" and cannot be satisfied by routing
/// through any third node at all, so it carries none of that risk.
fn chain_is_reachable_from_anchor(
    snapshot: &KnowledgeGraphSnapshot,
    chain: &ReconstructedChain,
    anchor: &str,
) -> bool {
    chain
        .node_ids
        .iter()
        .any(|node_id| !snapshot.provenance_paths(anchor, node_id, 1).is_empty())
}

/// CHAIN-03: joins two incidents that reference DISJOINT `hunt_id`s into ONE
/// [`ReconstructedKillChain`] per rule, when a genuine CAUSAL path in
/// `snapshot` connects their anchors -- never when the only thing tying them
/// together is a shared, globally-merged classification node such as a
/// `ThreatPattern` or `AttackTechnique` node, and never via connectivity
/// that never crosses an actual `Causal` edge at all (see [`causal_bridge`];
/// neither is evidence of a real relationship between the two hunts, the
/// lesson Task 2's `ThreatPattern` fabricated-bridging fix, and this
/// module's own fix round 1 for `AttackTechnique`, both carry forward).
///
/// Returns one [`ReconstructedKillChain`] for every rule in `rules` whose
/// whole-snapshot reconstruction (via [`reconstruct_kill_chains`] -- this
/// function does not re-derive stage-to-stage connectivity, only validates
/// the cross-hunt link and labels the result) is reachable from BOTH
/// anchors per [`chain_is_reachable_from_anchor`]; empty when the hunts
/// are not disjoint, are not connected at all, are connected only via a
/// rejected classification node, are connected only by non-causal
/// connectivity, or no rule's reconstruction is attributable to both sides.
pub fn join_cross_hunt_kill_chain(
    snapshot: &KnowledgeGraphSnapshot,
    rules: &[KillChainStageRule],
    incident_a: &CrossHuntIncidentAnchor<'_>,
    incident_b: &CrossHuntIncidentAnchor<'_>,
    max_hops: usize,
    created_at_ms: i64,
) -> Vec<ReconstructedKillChain> {
    if !hunts_are_disjoint(incident_a.hunt_ids, incident_b.hunt_ids) {
        return Vec::new();
    }

    let Some(bridge) = causal_bridge(
        snapshot,
        incident_a.anchor_node_id,
        incident_b.anchor_node_id,
        max_hops,
    ) else {
        return Vec::new();
    };

    let mut hunt_ids = incident_a.hunt_ids.to_vec();
    for hunt_id in incident_b.hunt_ids {
        if !hunt_ids.contains(hunt_id) {
            hunt_ids.push(hunt_id.clone());
        }
    }
    let mut incident_ids = vec![
        incident_a.incident_id.to_string(),
        incident_b.incident_id.to_string(),
    ];
    incident_ids.sort();
    let cross_hunt_bridges = vec![to_reconstructed_chain_hop(bridge)];

    reconstruct_kill_chains(snapshot, rules, max_hops)
        .into_iter()
        .filter(|chain| {
            chain_is_reachable_from_anchor(snapshot, chain, incident_a.anchor_node_id)
                && chain_is_reachable_from_anchor(snapshot, chain, incident_b.anchor_node_id)
        })
        .map(|chain| ReconstructedKillChain {
            chain_id: format!(
                "chain:{}:{}:{}",
                chain.rule_id, incident_ids[0], incident_ids[1]
            ),
            rule_id: chain.rule_id,
            rule_name: chain.rule_name,
            created_at_ms,
            stages: chain.stages,
            technique_ids: chain.technique_ids,
            node_ids: chain.node_ids,
            hops: chain
                .hops
                .into_iter()
                .map(to_reconstructed_chain_hop)
                .collect(),
            hunt_ids: hunt_ids.clone(),
            incident_ids: incident_ids.clone(),
            cross_hunt_bridges: cross_hunt_bridges.clone(),
        })
        .collect()
}

/// CHAIN-04: a non-empty, stage-by-stage human-readable narrative of a
/// [`ReconstructedKillChain`], in reconstructed order (`chain.stages[0]` is
/// narrated first, matching the rule's declared `attack_chain` order --
/// [`reconstruct_kill_chains`] never reorders it). Always non-empty: a
/// persisted `ReconstructedKillChain` always has at least
/// [`MIN_RECONSTRUCTED_STAGES`] stages, so there is always a header line
/// plus at least two numbered stage lines.
pub fn narrate(chain: &ReconstructedKillChain) -> String {
    let mut lines = Vec::with_capacity(chain.stages.len() + 2);

    let hunts = if chain.hunt_ids.is_empty() {
        "an unspecified hunt".to_string()
    } else {
        chain.hunt_ids.join(", ")
    };
    lines.push(format!(
        "Reconstructed kill chain \"{}\" ({}), spanning hunt(s): {hunts}.",
        chain.rule_name, chain.rule_id
    ));

    for (index, (stage, technique_id)) in chain
        .stages
        .iter()
        .zip(chain.technique_ids.iter())
        .enumerate()
    {
        lines.push(format!(
            "  Stage {}: {stage} (technique {technique_id}).",
            index + 1
        ));
    }

    if chain.hunt_ids.len() > 1 || chain.incident_ids.len() > 1 {
        lines.push(format!(
            "This chain spans {} disjoint hunt(s) via {} corroborating causal link(s), \
             joined from incident(s): {}.",
            chain.hunt_ids.len(),
            chain.cross_hunt_bridges.len(),
            chain.incident_ids.join(", ")
        ));
    }

    lines.join("\n")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        CrossHuntIncidentAnchor, KillChainStageRule, KillChainStageTechnique,
        join_cross_hunt_kill_chain, load_kill_chain_stage_rules,
        load_kill_chain_stage_rules_from_profile, narrate, reconstruct_kill_chains,
    };
    use crate::sequence_detector::KillChainSequenceProfile;
    use crate::sphinx_agent::{
        AttackTechniqueNode, CausalEdge, CausalRelation, EngagementNode, EntityEdge, EntityKind,
        EntityNode, KnowledgeGraphEdge, KnowledgeGraphNode, KnowledgeGraphSnapshot, ProcessNode,
        SemanticEdge, SemanticRelation, TemporalEdge, ThreatPatternNode,
    };
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::types::Severity;
    use swarm_spine::ReconstructedKillChain;

    fn temp_yaml_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "chain-reconstruction-{label}-{}-{}.yaml",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    fn write_yaml(label: &str, contents: &str) -> PathBuf {
        let path = temp_yaml_path(label);
        fs::write(&path, contents).expect("test fixture should write");
        path
    }

    /// The `outlook_mshta_transfer` rule verbatim from
    /// `sequences/kill-chain-v1.yaml`, as its `KillChainStageRule` view.
    fn rule_fixture() -> KillChainStageRule {
        KillChainStageRule {
            rule_id: "outlook_mshta_transfer".to_string(),
            rule_name: "Outlook installer proxy to mshta download chain".to_string(),
            attack_chain: vec![
                KillChainStageTechnique {
                    technique_id: "T1218.007".to_string(),
                    name: "Msiexec".to_string(),
                    kill_chain_stage: "execution".to_string(),
                },
                KillChainStageTechnique {
                    technique_id: "T1218.005".to_string(),
                    name: "Mshta".to_string(),
                    kill_chain_stage: "defense_evasion".to_string(),
                },
                KillChainStageTechnique {
                    technique_id: "T1105".to_string(),
                    name: "Ingress Tool Transfer".to_string(),
                    kill_chain_stage: "command_and_control".to_string(),
                },
            ],
        }
    }

    fn attack_technique_node(technique: &KillChainStageTechnique) -> KnowledgeGraphNode {
        KnowledgeGraphNode::AttackTechnique(AttackTechniqueNode {
            node_id: format!("attack_technique:{}", technique.technique_id),
            technique_id: technique.technique_id.clone(),
            name: technique.name.clone(),
            kill_chain_stage: technique.kill_chain_stage.clone(),
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            observation_count: 1,
        })
    }

    fn technique_node_id(technique: &KillChainStageTechnique) -> String {
        format!("attack_technique:{}", technique.technique_id)
    }

    /// An `EngagementNode` for `node_id` -- the single-observation,
    /// single-hunt anchor kind `kill_chain_stage_anchors` restricts its
    /// busy-hub fallback to.
    fn engagement_node(node_id: &str) -> KnowledgeGraphNode {
        KnowledgeGraphNode::Engagement(EngagementNode {
            node_id: node_id.to_string(),
            observation_id: node_id.to_string(),
            source_agent_id: "sphinx:test".to_string(),
            threat_class: "command_and_control".to_string(),
            severity: Severity::High,
            summary: "test engagement".to_string(),
            observed_at_ms: 0,
            related_entity_ids: BTreeSet::new(),
            attack_technique_ids: BTreeSet::new(),
            analyst_feedback_ids: BTreeSet::new(),
            analyst_disposition: None,
            analyst_note: None,
            analyst_feedback_at_ms: None,
            outcome_reward_override: None,
        })
    }

    /// A `ThreatPatternNode` for `node_id` -- the GLOBALLY-MERGED,
    /// hunt-agnostic node kind `kill_chain_stage_anchors` must NEVER treat
    /// as a busy-hub-fallback anchor.
    fn threat_pattern_node(node_id: &str) -> KnowledgeGraphNode {
        KnowledgeGraphNode::ThreatPattern(ThreatPatternNode {
            node_id: node_id.to_string(),
            threat_class: "command_and_control".to_string(),
            title: "command_and_control threat pattern".to_string(),
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            observation_count: 3,
            latest_severity: Severity::High,
            attack_technique_ids: BTreeSet::new(),
            kill_chain_stages: BTreeSet::new(),
        })
    }

    /// A concrete `ProcessNode` for `node_id` -- a CONCRETE-IDENTITY node
    /// (keyed by an actual process, not a classification key), so it is NOT a
    /// globally-merged classification node and MAY legitimately be a
    /// cross-hunt causal bridge waypoint when both hunts causally touch it.
    fn process_node(node_id: &str) -> KnowledgeGraphNode {
        KnowledgeGraphNode::Process(ProcessNode {
            node_id: node_id.to_string(),
            process_key: node_id.to_string(),
            pid: None,
            host_id: None,
            executable_path: None,
            command_line: None,
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            observation_count: 2,
        })
    }

    /// A concrete host `EntityNode` for `node_id`.
    fn host_entity_node(node_id: &str) -> KnowledgeGraphNode {
        KnowledgeGraphNode::Entity(EntityNode {
            node_id: node_id.to_string(),
            entity_kind: EntityKind::Host,
            value: node_id.to_string(),
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            observation_count: 2,
        })
    }

    #[test]
    fn load_kill_chain_stage_rules_parses_attack_chain_stage_order_from_yaml() {
        let path = write_yaml(
            "load",
            r#"
version: 1
rules:
  - id: outlook_mshta_transfer
    name: Outlook installer proxy to mshta download chain
    description: unused by this loader
    threat_class: command_and_control
    severity: CRITICAL
    confidence: 0.96
    max_span_ms: 180000
    tags: [sequence]
    attack_chain:
      - technique_id: T1218.007
        name: Msiexec
        kill_chain_stage: execution
      - technique_id: T1218.005
        name: Mshta
        kill_chain_stage: defense_evasion
      - technique_id: T1105
        name: Ingress Tool Transfer
        kill_chain_stage: command_and_control
    steps: []
"#,
        );

        let rules = load_kill_chain_stage_rules(&path.display().to_string())
            .expect("well-formed rules file should parse");
        let _ = fs::remove_file(&path);

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule_id, "outlook_mshta_transfer");
        assert_eq!(
            rules[0]
                .attack_chain
                .iter()
                .map(|technique| technique.kill_chain_stage.as_str())
                .collect::<Vec<_>>(),
            vec!["execution", "defense_evasion", "command_and_control"],
        );
    }

    #[test]
    fn load_kill_chain_stage_rules_from_profile_reads_the_profiles_rules_path() {
        let path = write_yaml(
            "profile",
            r#"
version: 1
rules:
  - id: remote_service_stager
    name: Remote service controller stages an operator script
    description: unused by this loader
    threat_class: lateral_movement
    severity: HIGH
    confidence: 0.91
    max_span_ms: 180000
    attack_chain:
      - technique_id: T1021.002
        name: SMB/Windows Admin Shares
        kill_chain_stage: lateral_movement
      - technique_id: T1569.002
        name: Service Execution
        kill_chain_stage: execution
    steps: []
"#,
        );

        let profile = KillChainSequenceProfile {
            rules_path: path.display().to_string(),
        };
        let rules = load_kill_chain_stage_rules_from_profile(&profile)
            .expect("well-formed rules file should parse via the profile's rules_path");
        let _ = fs::remove_file(&path);

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule_id, "remote_service_stager");
    }

    /// The primary real-world producer: CHAIN-02 persists a sequence-detector
    /// match as one `Engagement` node fanned out to each matched technique
    /// by its own `:sequence:<rule_id>`-namespaced `KillChainStage` semantic
    /// edge (a star, not a chain). Reconstruction must still map this onto
    /// the rule's declared order by walking stage-to-stage through the
    /// shared hub (two hops per consecutive pair).
    #[test]
    fn reconstruct_kill_chains_maps_engagement_fanout_semantic_edges_onto_rule_stage_order() {
        let rule = rule_fixture();
        let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
        for technique in &rule.attack_chain {
            snapshot.nodes.push(attack_technique_node(technique));
        }
        let hub = "engagement:evt-1";
        for technique in &rule.attack_chain {
            snapshot
                .edges
                .push(KnowledgeGraphEdge::Semantic(SemanticEdge {
                    edge_id: format!(
                        "semantic:{hub}:{}:sequence:{}",
                        technique.technique_id, rule.rule_id
                    ),
                    from_node_id: hub.to_string(),
                    to_node_id: technique_node_id(technique),
                    relation: SemanticRelation::KillChainStage,
                    kill_chain_stage: technique.kill_chain_stage.clone(),
                    first_observed_at_ms: 0,
                    last_observed_at_ms: 0,
                    occurrence_count: 1,
                }));
        }

        let reconstructed = reconstruct_kill_chains(&snapshot, std::slice::from_ref(&rule), 2);

        assert_eq!(reconstructed.len(), 1);
        let chain = &reconstructed[0];
        assert_eq!(chain.rule_id, "outlook_mshta_transfer");
        assert_eq!(
            chain.stages,
            vec!["execution", "defense_evasion", "command_and_control"]
        );
        assert_eq!(chain.technique_ids, vec!["T1218.007", "T1218.005", "T1105"]);
        assert_eq!(chain.node_ids.len(), 3);
        assert_eq!(
            chain.hops.len(),
            2,
            "one hop per consecutive stage pair, each two edges through the shared hub"
        );
    }

    /// Regression: a busy Engagement hub whose TOTAL degree exceeds
    /// `PROVENANCE_HUB_DEGREE_CAP` (32) for reasons entirely unrelated to
    /// this sequence match — here, 40 temporal edges to other engagements,
    /// exactly the "shares an entity in the temporal window" mechanism
    /// `sphinx_agent.rs`'s `ingest_pheromone` uses (~531-568) — must not
    /// silently truncate reconstruction of an already-detected, legitimate
    /// 3-stage chain. A pairwise `stage_i -> hub -> stage_j` walk would hit
    /// the hub at hop > 0 and refuse to expand through it (the cap is not
    /// exempt there), which is exactly why `stage_connection` falls back to
    /// querying FROM the hub itself once the direct call fails.
    #[test]
    fn reconstruct_kill_chains_survives_a_high_degree_engagement_hub() {
        let rule = rule_fixture();
        let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
        for technique in &rule.attack_chain {
            snapshot.nodes.push(attack_technique_node(technique));
        }
        let hub = "engagement:evt-busy";
        snapshot.nodes.push(engagement_node(hub));
        for technique in &rule.attack_chain {
            snapshot
                .edges
                .push(KnowledgeGraphEdge::Semantic(SemanticEdge {
                    edge_id: format!(
                        "semantic:{hub}:{}:sequence:{}",
                        technique.technique_id, rule.rule_id
                    ),
                    from_node_id: hub.to_string(),
                    to_node_id: technique_node_id(technique),
                    relation: SemanticRelation::KillChainStage,
                    kill_chain_stage: technique.kill_chain_stage.clone(),
                    first_observed_at_ms: 0,
                    last_observed_at_ms: 0,
                    occurrence_count: 1,
                }));
        }
        // Inflate the hub's degree past the cap with temporal edges to
        // unrelated OTHER engagements -- nothing to do with this sequence
        // match, just this Engagement being independently busy.
        for index in 0..40 {
            snapshot
                .edges
                .push(KnowledgeGraphEdge::Temporal(TemporalEdge {
                    edge_id: format!("temporal:{hub}:other-{index}"),
                    from_node_id: hub.to_string(),
                    to_node_id: format!("engagement:other-{index}"),
                    temporal_window_secs: 3_600,
                    shared_entity_ids: BTreeSet::new(),
                    first_observed_at_ms: 0,
                    last_observed_at_ms: 0,
                    occurrence_count: 1,
                }));
        }
        let hub_degree = snapshot
            .edges
            .iter()
            .filter(|edge| match edge {
                KnowledgeGraphEdge::Semantic(semantic) => semantic.from_node_id == hub,
                KnowledgeGraphEdge::Temporal(temporal) => temporal.from_node_id == hub,
                _ => false,
            })
            .count();
        assert!(
            hub_degree > KnowledgeGraphSnapshot::PROVENANCE_HUB_DEGREE_CAP,
            "test setup must actually exceed the hub-degree cap, got degree {hub_degree}"
        );

        let reconstructed = reconstruct_kill_chains(&snapshot, std::slice::from_ref(&rule), 2);

        assert_eq!(
            reconstructed.len(),
            1,
            "a busy engagement hub must not silently truncate an already-detected chain"
        );
        assert_eq!(
            reconstructed[0].stages,
            vec!["execution", "defense_evasion", "command_and_control"]
        );
        assert_eq!(
            reconstructed[0].technique_ids,
            vec!["T1218.007", "T1218.005", "T1105"]
        );
    }

    /// Security-property pin (fix round 2, CRITICAL): a `ThreatPatternNode`
    /// is keyed only by `threat_class` and merged GLOBALLY across every
    /// observation of that class over the graph's whole lifetime -- unlike
    /// an `EngagementNode` (keyed by `observation_id`, one observation, one
    /// hunt). Three MUTUALLY-DISCONNECTED "hunts", each touching exactly
    /// one of the rule's technique nodes and nothing else, tied together
    /// ONLY by a single shared `ThreatPattern` pushed over the hub-degree
    /// cap via unrelated filler edges, must NEVER be bridged into one
    /// fabricated multi-stage `ReconstructedChain` -- that is exactly what
    /// Phase 296's hub-degree cap
    /// (`provenance_paths_hub_degree_cap_prevents_bridging_unrelated_hunt_subgraphs`
    /// in `sphinx_agent.rs`) exists to prevent, and what the round-1 fix's
    /// anchor fallback would have defeated by including `ThreatPattern`
    /// candidates.
    #[test]
    fn reconstruct_kill_chains_does_not_bridge_disconnected_hunts_through_a_shared_threat_pattern()
    {
        let rule = rule_fixture();
        let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
        for technique in &rule.attack_chain {
            snapshot.nodes.push(attack_technique_node(technique));
        }

        // A single ThreatPattern, shared by every hunt that happens to
        // observe this rule's threat_class -- the real emission shape
        // (`sphinx_agent.rs` links EVERY engagement observing a class to
        // the SAME ThreatPattern node).
        let shared_pattern = "threat_pattern:shared";
        snapshot.nodes.push(threat_pattern_node(shared_pattern));

        // Three mutually-disconnected "hunts": the shared ThreatPattern
        // fans a KillChainStage edge out to each technique individually,
        // and NOTHING else ties the three technique nodes together (no
        // shared Engagement, no causal/temporal edge between them).
        for technique in &rule.attack_chain {
            snapshot
                .edges
                .push(KnowledgeGraphEdge::Semantic(SemanticEdge {
                    edge_id: format!("semantic:{shared_pattern}:{}", technique.technique_id),
                    from_node_id: shared_pattern.to_string(),
                    to_node_id: technique_node_id(technique),
                    relation: SemanticRelation::KillChainStage,
                    kill_chain_stage: technique.kill_chain_stage.clone(),
                    first_observed_at_ms: 0,
                    last_observed_at_ms: 0,
                    occurrence_count: 1,
                }));
        }
        // Push the ThreatPattern's degree past the cap with unrelated
        // filler edges -- proving the exclusion is by NODE KIND, not
        // merely by degree: this anchor must be rejected whether or not it
        // is over the cap.
        for index in 0..40 {
            snapshot
                .edges
                .push(KnowledgeGraphEdge::Temporal(TemporalEdge {
                    edge_id: format!("temporal:{shared_pattern}:filler-{index}"),
                    from_node_id: shared_pattern.to_string(),
                    to_node_id: format!("threat_pattern_filler:{index}"),
                    temporal_window_secs: 3_600,
                    shared_entity_ids: BTreeSet::new(),
                    first_observed_at_ms: 0,
                    last_observed_at_ms: 0,
                    occurrence_count: 1,
                }));
        }
        let shared_pattern_degree = snapshot
            .edges
            .iter()
            .filter(|edge| match edge {
                KnowledgeGraphEdge::Semantic(semantic) => semantic.from_node_id == shared_pattern,
                KnowledgeGraphEdge::Temporal(temporal) => temporal.from_node_id == shared_pattern,
                _ => false,
            })
            .count();
        assert!(
            shared_pattern_degree > KnowledgeGraphSnapshot::PROVENANCE_HUB_DEGREE_CAP,
            "test setup must actually exceed the hub-degree cap, got degree {shared_pattern_degree}"
        );

        let reconstructed = reconstruct_kill_chains(&snapshot, std::slice::from_ref(&rule), 6);

        assert!(
            reconstructed.is_empty(),
            "a shared, hunt-agnostic ThreatPattern must never bridge mutually-disconnected \
             hunts into a fabricated chain: {reconstructed:?}"
        );
    }

    /// The same mapping also holds for a direct causal chain between
    /// technique nodes (no shared hub) — CHAIN-01 walks causal edges, not
    /// only the semantic ones CHAIN-02 adds.
    #[test]
    fn reconstruct_kill_chains_maps_direct_causal_chain_onto_rule_stage_order() {
        let rule = rule_fixture();
        let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
        for technique in &rule.attack_chain {
            snapshot.nodes.push(attack_technique_node(technique));
        }
        for (index, pair) in rule.attack_chain.windows(2).enumerate() {
            snapshot.edges.push(KnowledgeGraphEdge::Causal(CausalEdge {
                edge_id: format!("causal:{index}"),
                from_node_id: technique_node_id(&pair[0]),
                to_node_id: technique_node_id(&pair[1]),
                relation: CausalRelation::ProcessParentChild,
                first_observed_at_ms: 0,
                last_observed_at_ms: 0,
                occurrence_count: 1,
            }));
        }

        let reconstructed = reconstruct_kill_chains(&snapshot, &[rule], 1);

        assert_eq!(reconstructed.len(), 1);
        assert_eq!(
            reconstructed[0].node_ids,
            vec![
                "attack_technique:T1218.007",
                "attack_technique:T1218.005",
                "attack_technique:T1105",
            ]
        );
        assert_eq!(reconstructed[0].hops.len(), 2);
    }

    #[test]
    fn reconstruct_kill_chains_returns_none_when_stages_are_disconnected() {
        let rule = rule_fixture();
        let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
        for technique in &rule.attack_chain {
            snapshot.nodes.push(attack_technique_node(technique));
        }
        // Every technique was observed, but never in the same
        // causal/temporal/semantic context -- no edges at all connect them.
        // CHAIN-01 must not fabricate a chain out of unrelated observations.
        let reconstructed = reconstruct_kill_chains(&snapshot, &[rule], 8);
        assert!(
            reconstructed.is_empty(),
            "disconnected technique observations must not reconstruct a chain"
        );
    }

    #[test]
    fn reconstruct_kill_chains_returns_none_when_no_technique_ever_observed() {
        let rule = rule_fixture();
        let snapshot = KnowledgeGraphSnapshot::new(3_600);
        let reconstructed = reconstruct_kill_chains(&snapshot, &[rule], 8);
        assert!(reconstructed.is_empty());
    }

    #[test]
    fn reconstruct_kill_chains_requires_at_least_two_connected_stages() {
        let rule = rule_fixture();
        let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
        snapshot
            .nodes
            .push(attack_technique_node(&rule.attack_chain[0]));

        let reconstructed = reconstruct_kill_chains(&snapshot, &[rule], 8);
        assert!(
            reconstructed.is_empty(),
            "a single observed stage with nothing connected to it is not a reconstructed chain"
        );
    }

    #[test]
    fn reconstruct_kill_chains_returns_the_longest_connected_prefix_when_a_later_stage_is_missing()
    {
        let rule = rule_fixture();
        let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
        // Only the first two stages were ever observed; the third
        // (command_and_control / T1105) never fires.
        snapshot
            .nodes
            .push(attack_technique_node(&rule.attack_chain[0]));
        snapshot
            .nodes
            .push(attack_technique_node(&rule.attack_chain[1]));
        snapshot.edges.push(KnowledgeGraphEdge::Causal(CausalEdge {
            edge_id: "causal:0".to_string(),
            from_node_id: technique_node_id(&rule.attack_chain[0]),
            to_node_id: technique_node_id(&rule.attack_chain[1]),
            relation: CausalRelation::ProcessParentChild,
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            occurrence_count: 1,
        }));

        let reconstructed = reconstruct_kill_chains(&snapshot, &[rule], 4);

        assert_eq!(reconstructed.len(), 1);
        assert_eq!(
            reconstructed[0].stages,
            vec!["execution", "defense_evasion"],
            "reconstruction stops at the first undeclared/missing stage"
        );
    }

    /// Bounded walk: a cycle in the graph's edges must not make
    /// reconstruction loop. `provenance_paths`' `seen` set visits each node
    /// at most once regardless of cycles, so this both terminates promptly
    /// and still returns the correct forward stage order.
    #[test]
    fn reconstruct_kill_chains_terminates_on_a_cyclic_graph() {
        let rule = rule_fixture();
        let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
        for technique in &rule.attack_chain {
            snapshot.nodes.push(attack_technique_node(technique));
        }
        let ids = rule
            .attack_chain
            .iter()
            .map(technique_node_id)
            .collect::<Vec<_>>();
        // Forward chain 0 -> 1 -> 2, PLUS a back-edge 2 -> 0 closing a cycle.
        for (index, pair) in ids.windows(2).enumerate() {
            snapshot.edges.push(KnowledgeGraphEdge::Causal(CausalEdge {
                edge_id: format!("causal:forward:{index}"),
                from_node_id: pair[0].clone(),
                to_node_id: pair[1].clone(),
                relation: CausalRelation::ProcessParentChild,
                first_observed_at_ms: 0,
                last_observed_at_ms: 0,
                occurrence_count: 1,
            }));
        }
        snapshot.edges.push(KnowledgeGraphEdge::Causal(CausalEdge {
            edge_id: "causal:back-edge".to_string(),
            from_node_id: ids[2].clone(),
            to_node_id: ids[0].clone(),
            relation: CausalRelation::ProcessParentChild,
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            occurrence_count: 1,
        }));

        let reconstructed = reconstruct_kill_chains(&snapshot, &[rule], 4);

        assert_eq!(reconstructed.len(), 1);
        assert_eq!(
            reconstructed[0].stages,
            vec!["execution", "defense_evasion", "command_and_control"]
        );
    }

    /// SC4 / CHAIN-03: two DISJOINT-hunt incidents, each of which reconstructs
    /// NOTHING on its own (hunt-a alone only ever observed stage 0; hunt-b
    /// alone only ever observed stages 1-2, so `attack_chain`'s walk from
    /// index 0 breaks immediately for hunt-b in isolation), joined into ONE
    /// `ReconstructedKillChain` once a genuine causal edge directly connects
    /// their own `Engagement` anchors.
    #[test]
    fn join_cross_hunt_kill_chain_joins_two_disjoint_hunts_connected_by_a_causal_path() {
        let rule = rule_fixture();
        let engagement_a = "engagement:hunt-a";
        let engagement_b = "engagement:hunt-b";

        let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
        for technique in &rule.attack_chain {
            snapshot.nodes.push(attack_technique_node(technique));
        }
        snapshot.nodes.push(engagement_node(engagement_a));
        snapshot.nodes.push(engagement_node(engagement_b));

        // hunt-a observed only stage 0 (execution / T1218.007).
        snapshot
            .edges
            .push(KnowledgeGraphEdge::Semantic(SemanticEdge {
                edge_id: "semantic:hunt-a:0".to_string(),
                from_node_id: engagement_a.to_string(),
                to_node_id: technique_node_id(&rule.attack_chain[0]),
                relation: SemanticRelation::KillChainStage,
                kill_chain_stage: rule.attack_chain[0].kill_chain_stage.clone(),
                first_observed_at_ms: 0,
                last_observed_at_ms: 0,
                occurrence_count: 1,
            }));
        // hunt-b observed stages 1 and 2 (defense_evasion / T1218.005 and
        // command_and_control / T1105) -- never stage 0.
        for technique in &rule.attack_chain[1..] {
            snapshot
                .edges
                .push(KnowledgeGraphEdge::Semantic(SemanticEdge {
                    edge_id: format!("semantic:hunt-b:{}", technique.technique_id),
                    from_node_id: engagement_b.to_string(),
                    to_node_id: technique_node_id(technique),
                    relation: SemanticRelation::KillChainStage,
                    kill_chain_stage: technique.kill_chain_stage.clone(),
                    first_observed_at_ms: 0,
                    last_observed_at_ms: 0,
                    occurrence_count: 1,
                }));
        }

        // Confirm neither hunt reconstructs anything on its own before the
        // bridge is even added -- this is the "not two disjoint incidents"
        // baseline the join is supposed to improve on.
        let hunt_a_only = {
            let mut only_a = KnowledgeGraphSnapshot::new(3_600);
            only_a
                .nodes
                .push(attack_technique_node(&rule.attack_chain[0]));
            only_a.nodes.push(engagement_node(engagement_a));
            only_a.edges = snapshot
                .edges
                .iter()
                .filter(|edge| matches!(edge, KnowledgeGraphEdge::Semantic(s) if s.from_node_id == engagement_a))
                .cloned()
                .collect();
            only_a
        };
        assert!(
            reconstruct_kill_chains(&hunt_a_only, std::slice::from_ref(&rule), 4).is_empty(),
            "hunt-a alone (one observed stage) must not reconstruct a chain"
        );
        let hunt_b_only = {
            let mut only_b = KnowledgeGraphSnapshot::new(3_600);
            for technique in &rule.attack_chain[1..] {
                only_b.nodes.push(attack_technique_node(technique));
            }
            only_b.nodes.push(engagement_node(engagement_b));
            only_b.edges = snapshot
                .edges
                .iter()
                .filter(|edge| matches!(edge, KnowledgeGraphEdge::Semantic(s) if s.from_node_id == engagement_b))
                .cloned()
                .collect();
            only_b
        };
        assert!(
            reconstruct_kill_chains(&hunt_b_only, std::slice::from_ref(&rule), 4).is_empty(),
            "hunt-b alone (missing the rule's declared first stage) must not reconstruct a chain"
        );

        // Now add the genuine cross-hunt causal link and join.
        snapshot.edges.push(KnowledgeGraphEdge::Causal(CausalEdge {
            edge_id: "causal:hunt-a-to-hunt-b".to_string(),
            from_node_id: engagement_a.to_string(),
            to_node_id: engagement_b.to_string(),
            relation: CausalRelation::ProcessParentChild,
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            occurrence_count: 1,
        }));

        let incident_a = CrossHuntIncidentAnchor {
            incident_id: "incident:hunt-a:1",
            hunt_ids: &["hunt-a".to_string()],
            anchor_node_id: engagement_a,
        };
        let incident_b = CrossHuntIncidentAnchor {
            incident_id: "incident:hunt-b:1",
            hunt_ids: &["hunt-b".to_string()],
            anchor_node_id: engagement_b,
        };

        let joined = join_cross_hunt_kill_chain(
            &snapshot,
            std::slice::from_ref(&rule),
            &incident_a,
            &incident_b,
            4,
            1_700_000_000_000,
        );

        assert_eq!(
            joined.len(),
            1,
            "the two disjoint hunts must reconstruct into exactly ONE chain, not zero and not two"
        );
        let chain = &joined[0];
        assert_eq!(chain.rule_id, "outlook_mshta_transfer");
        assert_eq!(
            chain.stages,
            vec!["execution", "defense_evasion", "command_and_control"]
        );
        assert_eq!(chain.technique_ids, vec!["T1218.007", "T1218.005", "T1105"]);
        assert_eq!(
            chain.hunt_ids,
            vec!["hunt-a".to_string(), "hunt-b".to_string()]
        );
        assert_eq!(
            chain.incident_ids,
            vec![
                "incident:hunt-a:1".to_string(),
                "incident:hunt-b:1".to_string()
            ]
        );
        assert_eq!(chain.cross_hunt_bridges.len(), 1);
        assert_eq!(
            chain.cross_hunt_bridges[0].node_ids,
            vec![engagement_a.to_string(), engagement_b.to_string()]
        );

        let narrative = narrate(chain);
        assert!(!narrative.is_empty());
        assert!(narrative.contains("hunt-a"));
        assert!(narrative.contains("hunt-b"));
    }

    /// Security-property pin, mirroring T2's `ThreatPattern` lesson at the
    /// cross-hunt level: two mutually-disconnected hunts whose ONLY tie is a
    /// shared `ThreatPattern` node must NOT join into one chain, even though
    /// a plain `provenance_paths` call WOULD find that 2-hop path (the
    /// `ThreatPattern`'s degree here is deliberately kept far under
    /// `PROVENANCE_HUB_DEGREE_CAP`, proving the exclusion is by node KIND,
    /// not by degree -- the hub-degree cap alone would not have caught this).
    #[test]
    fn join_cross_hunt_kill_chain_does_not_bridge_hunts_through_a_shared_threat_pattern() {
        let rule = rule_fixture();
        let engagement_a = "engagement:hunt-a";
        let engagement_b = "engagement:hunt-b";
        let shared_pattern = "threat_pattern:shared";

        let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
        for technique in &rule.attack_chain {
            snapshot.nodes.push(attack_technique_node(technique));
        }
        snapshot.nodes.push(engagement_node(engagement_a));
        snapshot.nodes.push(engagement_node(engagement_b));
        snapshot.nodes.push(threat_pattern_node(shared_pattern));

        snapshot
            .edges
            .push(KnowledgeGraphEdge::Semantic(SemanticEdge {
                edge_id: "semantic:hunt-a:0".to_string(),
                from_node_id: engagement_a.to_string(),
                to_node_id: technique_node_id(&rule.attack_chain[0]),
                relation: SemanticRelation::KillChainStage,
                kill_chain_stage: rule.attack_chain[0].kill_chain_stage.clone(),
                first_observed_at_ms: 0,
                last_observed_at_ms: 0,
                occurrence_count: 1,
            }));
        for technique in &rule.attack_chain[1..] {
            snapshot
                .edges
                .push(KnowledgeGraphEdge::Semantic(SemanticEdge {
                    edge_id: format!("semantic:hunt-b:{}", technique.technique_id),
                    from_node_id: engagement_b.to_string(),
                    to_node_id: technique_node_id(technique),
                    relation: SemanticRelation::KillChainStage,
                    kill_chain_stage: technique.kill_chain_stage.clone(),
                    first_observed_at_ms: 0,
                    last_observed_at_ms: 0,
                    occurrence_count: 1,
                }));
        }
        // The ONLY thing tying hunt-a and hunt-b together: a shared
        // ThreatPattern, low-degree (2 edges total), nowhere near the cap.
        snapshot.edges.push(KnowledgeGraphEdge::Causal(CausalEdge {
            edge_id: "causal:hunt-a-to-shared-pattern".to_string(),
            from_node_id: engagement_a.to_string(),
            to_node_id: shared_pattern.to_string(),
            relation: CausalRelation::ProcessParentChild,
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            occurrence_count: 1,
        }));
        snapshot.edges.push(KnowledgeGraphEdge::Causal(CausalEdge {
            edge_id: "causal:shared-pattern-to-hunt-b".to_string(),
            from_node_id: shared_pattern.to_string(),
            to_node_id: engagement_b.to_string(),
            relation: CausalRelation::ProcessParentChild,
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            occurrence_count: 1,
        }));
        let shared_pattern_degree = snapshot
            .edges
            .iter()
            .filter(|edge| match edge {
                KnowledgeGraphEdge::Causal(causal) => {
                    causal.from_node_id == shared_pattern || causal.to_node_id == shared_pattern
                }
                _ => false,
            })
            .count();
        assert!(
            shared_pattern_degree <= KnowledgeGraphSnapshot::PROVENANCE_HUB_DEGREE_CAP,
            "test setup must prove the exclusion is by node KIND, not merely by degree; \
             got degree {shared_pattern_degree}, which must stay under the cap"
        );

        let incident_a = CrossHuntIncidentAnchor {
            incident_id: "incident:hunt-a:1",
            hunt_ids: &["hunt-a".to_string()],
            anchor_node_id: engagement_a,
        };
        let incident_b = CrossHuntIncidentAnchor {
            incident_id: "incident:hunt-b:1",
            hunt_ids: &["hunt-b".to_string()],
            anchor_node_id: engagement_b,
        };

        // Sanity: a plain, non-hub-aware `provenance_paths` call DOES find
        // this path -- proving the rejection below comes from the explicit
        // node-kind check, not from an accidental absence of connectivity.
        assert!(
            !snapshot
                .provenance_paths(engagement_a, engagement_b, 4)
                .is_empty(),
            "test setup must have a plain graph-reachable path through the shared pattern"
        );

        let joined = join_cross_hunt_kill_chain(
            &snapshot,
            std::slice::from_ref(&rule),
            &incident_a,
            &incident_b,
            4,
            1_700_000_000_000,
        );

        assert!(
            joined.is_empty(),
            "a shared ThreatPattern must never bridge two disjoint hunts into a fabricated \
             cross-hunt chain: {joined:?}"
        );
    }

    /// Fix round 1, CRITICAL: `AttackTechnique` is ALSO globally merged (by
    /// `technique_id`, exactly as `ThreatPattern` is merged by
    /// `threat_class` -- see `sphinx_agent.rs`'s
    /// `attack_technique_node_id`/`SphinxAgent::upsert_node`, which folds
    /// every observation of a given `technique_id` into ONE node regardless
    /// of hunt). hunt-a has its OWN, fully self-contained genuine 3-stage
    /// chain (all three stages fanned from its own `Engagement`, the
    /// ordinary CHAIN-02 star shape); hunt-b independently touches ONLY the
    /// SAME shared `technique:T1218.007` node via its own, entirely separate
    /// edge -- nothing else ties hunt-a and hunt-b together. hunt-a's
    /// genuine chain must never get relabeled as "spanning hunt-b" merely
    /// because hunt-b also happens to classify to the same technique.
    #[test]
    fn join_cross_hunt_kill_chain_does_not_bridge_hunts_through_a_shared_attack_technique() {
        let rule = rule_fixture();
        let engagement_a = "engagement:hunt-a";
        let engagement_b = "engagement:hunt-b";

        let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
        for technique in &rule.attack_chain {
            snapshot.nodes.push(attack_technique_node(technique));
        }
        snapshot.nodes.push(engagement_node(engagement_a));
        snapshot.nodes.push(engagement_node(engagement_b));

        // hunt-a's OWN, fully self-contained 3-stage chain -- the ordinary
        // CHAIN-02 star shape, entirely within hunt-a.
        for technique in &rule.attack_chain {
            snapshot
                .edges
                .push(KnowledgeGraphEdge::Semantic(SemanticEdge {
                    edge_id: format!("semantic:hunt-a:{}", technique.technique_id),
                    from_node_id: engagement_a.to_string(),
                    to_node_id: technique_node_id(technique),
                    relation: SemanticRelation::KillChainStage,
                    kill_chain_stage: technique.kill_chain_stage.clone(),
                    first_observed_at_ms: 0,
                    last_observed_at_ms: 0,
                    occurrence_count: 1,
                }));
        }
        // hunt-b independently touches ONLY the shared T1218.007 node --
        // its own, unrelated edge. Nothing else connects hunt-a and hunt-b.
        snapshot
            .edges
            .push(KnowledgeGraphEdge::Semantic(SemanticEdge {
                edge_id: "semantic:hunt-b:T1218.007".to_string(),
                from_node_id: engagement_b.to_string(),
                to_node_id: technique_node_id(&rule.attack_chain[0]),
                relation: SemanticRelation::KillChainStage,
                kill_chain_stage: rule.attack_chain[0].kill_chain_stage.clone(),
                first_observed_at_ms: 0,
                last_observed_at_ms: 0,
                occurrence_count: 1,
            }));

        let incident_a = CrossHuntIncidentAnchor {
            incident_id: "incident:hunt-a:1",
            hunt_ids: &["hunt-a".to_string()],
            anchor_node_id: engagement_a,
        };
        let incident_b = CrossHuntIncidentAnchor {
            incident_id: "incident:hunt-b:1",
            hunt_ids: &["hunt-b".to_string()],
            anchor_node_id: engagement_b,
        };

        // Sanity: a plain, non-hub-aware `provenance_paths` call DOES find a
        // 2-hop path through the shared technique node -- proving the
        // rejection below comes from the explicit classification-node-kind
        // check, not from an accidental absence of connectivity.
        assert!(
            !snapshot
                .provenance_paths(engagement_a, engagement_b, 4)
                .is_empty(),
            "test setup must have a plain graph-reachable path through the shared technique"
        );

        let joined = join_cross_hunt_kill_chain(
            &snapshot,
            std::slice::from_ref(&rule),
            &incident_a,
            &incident_b,
            4,
            1_700_000_000_000,
        );

        assert!(
            joined.is_empty(),
            "a shared AttackTechnique must never bridge hunt-a's own self-contained chain into \
             a fabricated claim that it spans hunt-b: {joined:?}"
        );
    }

    /// A causal edge alone is not sufficient without the classification-node
    /// exclusion, and a classification-node-free path alone is not
    /// sufficient without a genuine causal edge: two hunts sharing ONLY an
    /// `Entity` node (e.g. the same host), with NO `Causal` edge anywhere on
    /// the path between them, must not join either. `Entity` is NOT a
    /// globally-merged classification node (it is keyed by concrete
    /// identity, e.g. an actual host), so this pins the causal-edge
    /// requirement specifically, independent of the classification-node
    /// check the two tests above pin.
    #[test]
    fn join_cross_hunt_kill_chain_does_not_bridge_hunts_that_share_an_entity_without_a_causal_edge()
    {
        let rule = rule_fixture();
        let engagement_a = "engagement:hunt-a";
        let engagement_b = "engagement:hunt-b";
        let shared_host = "entity:host:shared";

        let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
        for technique in &rule.attack_chain {
            snapshot.nodes.push(attack_technique_node(technique));
        }
        snapshot.nodes.push(engagement_node(engagement_a));
        snapshot.nodes.push(engagement_node(engagement_b));
        snapshot.nodes.push(KnowledgeGraphNode::Entity(EntityNode {
            node_id: shared_host.to_string(),
            entity_kind: EntityKind::Host,
            value: "shared-host".to_string(),
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            observation_count: 2,
        }));

        snapshot
            .edges
            .push(KnowledgeGraphEdge::Semantic(SemanticEdge {
                edge_id: "semantic:hunt-a:0".to_string(),
                from_node_id: engagement_a.to_string(),
                to_node_id: technique_node_id(&rule.attack_chain[0]),
                relation: SemanticRelation::KillChainStage,
                kill_chain_stage: rule.attack_chain[0].kill_chain_stage.clone(),
                first_observed_at_ms: 0,
                last_observed_at_ms: 0,
                occurrence_count: 1,
            }));
        for technique in &rule.attack_chain[1..] {
            snapshot
                .edges
                .push(KnowledgeGraphEdge::Semantic(SemanticEdge {
                    edge_id: format!("semantic:hunt-b:{}", technique.technique_id),
                    from_node_id: engagement_b.to_string(),
                    to_node_id: technique_node_id(technique),
                    relation: SemanticRelation::KillChainStage,
                    kill_chain_stage: technique.kill_chain_stage.clone(),
                    first_observed_at_ms: 0,
                    last_observed_at_ms: 0,
                    occurrence_count: 1,
                }));
        }
        // The ONLY thing tying hunt-a and hunt-b together: both reference
        // the SAME Entity (host), via plain Entity edges -- NO Causal edge
        // anywhere.
        snapshot.edges.push(KnowledgeGraphEdge::Entity(EntityEdge {
            edge_id: "entity:hunt-a-to-host".to_string(),
            from_node_id: engagement_a.to_string(),
            to_node_id: shared_host.to_string(),
            role: "host".to_string(),
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            occurrence_count: 1,
        }));
        snapshot.edges.push(KnowledgeGraphEdge::Entity(EntityEdge {
            edge_id: "entity:hunt-b-to-host".to_string(),
            from_node_id: engagement_b.to_string(),
            to_node_id: shared_host.to_string(),
            role: "host".to_string(),
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            occurrence_count: 1,
        }));

        let incident_a = CrossHuntIncidentAnchor {
            incident_id: "incident:hunt-a:1",
            hunt_ids: &["hunt-a".to_string()],
            anchor_node_id: engagement_a,
        };
        let incident_b = CrossHuntIncidentAnchor {
            incident_id: "incident:hunt-b:1",
            hunt_ids: &["hunt-b".to_string()],
            anchor_node_id: engagement_b,
        };

        // Sanity: the shared Entity DOES make the two anchors plainly
        // graph-reachable -- proving the rejection comes from the missing
        // Causal edge, not from an accidental absence of connectivity.
        assert!(
            !snapshot
                .provenance_paths(engagement_a, engagement_b, 4)
                .is_empty(),
            "test setup must have a plain graph-reachable path through the shared entity"
        );

        let joined = join_cross_hunt_kill_chain(
            &snapshot,
            std::slice::from_ref(&rule),
            &incident_a,
            &incident_b,
            4,
            1_700_000_000_000,
        );

        assert!(
            joined.is_empty(),
            "a shared Entity with no Causal edge between the two hunts' subgraphs is not causal \
             evidence of a relationship, and must not join them: {joined:?}"
        );
    }

    /// **Fix round 2, CRITICAL (re-review PoC, pinned).** A causal edge that
    /// is entirely INTERNAL to one hunt's own subgraph must never vouch for a
    /// cross-hunt hop that is itself non-causal. hunt-a observes only stage 0
    /// and hunt-b only stages 1-2 (exactly SC4's "each hunt alone
    /// reconstructs nothing" baseline). Their ONLY connection: hunt-a has a
    /// `Causal` edge to its OWN process node (a fact purely about hunt-a),
    /// and that process shares a host `Entity` with hunt-b via plain,
    /// non-causal `Entity` edges. A flat "does some edge on the path happen
    /// to be causal?" check accepted this (the intra-hunt causal edge is on
    /// the path); the `Causal`-only walk does not, because the shared host is
    /// unreachable without crossing a non-causal edge. Verified to fail
    /// before the causal-only fix and pass after, in the same session.
    #[test]
    fn join_cross_hunt_kill_chain_does_not_bridge_through_an_intra_hunt_causal_edge_and_a_shared_entity()
     {
        let rule = rule_fixture();
        let engagement_a = "engagement:hunt-a";
        let engagement_b = "engagement:hunt-b";
        let hunt_a_process = "process:hunt-a-only";
        let shared_host = "entity:host:shared";

        let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
        for technique in &rule.attack_chain {
            snapshot.nodes.push(attack_technique_node(technique));
        }
        snapshot.nodes.push(engagement_node(engagement_a));
        snapshot.nodes.push(engagement_node(engagement_b));
        snapshot.nodes.push(process_node(hunt_a_process));
        snapshot.nodes.push(host_entity_node(shared_host));

        // hunt-a observed only stage 0; hunt-b only stages 1 and 2 -- neither
        // reconstructs the rule's chain alone.
        snapshot
            .edges
            .push(KnowledgeGraphEdge::Semantic(SemanticEdge {
                edge_id: "semantic:hunt-a:0".to_string(),
                from_node_id: engagement_a.to_string(),
                to_node_id: technique_node_id(&rule.attack_chain[0]),
                relation: SemanticRelation::KillChainStage,
                kill_chain_stage: rule.attack_chain[0].kill_chain_stage.clone(),
                first_observed_at_ms: 0,
                last_observed_at_ms: 0,
                occurrence_count: 1,
            }));
        for technique in &rule.attack_chain[1..] {
            snapshot
                .edges
                .push(KnowledgeGraphEdge::Semantic(SemanticEdge {
                    edge_id: format!("semantic:hunt-b:{}", technique.technique_id),
                    from_node_id: engagement_b.to_string(),
                    to_node_id: technique_node_id(technique),
                    relation: SemanticRelation::KillChainStage,
                    kill_chain_stage: technique.kill_chain_stage.clone(),
                    first_observed_at_ms: 0,
                    last_observed_at_ms: 0,
                    occurrence_count: 1,
                }));
        }
        // The lone causal edge is INTERNAL to hunt-a: its own engagement
        // caused its own process. It says nothing about hunt-b.
        snapshot.edges.push(KnowledgeGraphEdge::Causal(CausalEdge {
            edge_id: "causal:hunt-a-to-its-own-process".to_string(),
            from_node_id: engagement_a.to_string(),
            to_node_id: hunt_a_process.to_string(),
            relation: CausalRelation::ProcessParentChild,
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            occurrence_count: 1,
        }));
        // The actual cross-hunt hop is non-causal: a shared host reached by
        // plain Entity edges on both sides.
        snapshot.edges.push(KnowledgeGraphEdge::Entity(EntityEdge {
            edge_id: "entity:process-to-shared-host".to_string(),
            from_node_id: hunt_a_process.to_string(),
            to_node_id: shared_host.to_string(),
            role: "host".to_string(),
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            occurrence_count: 1,
        }));
        snapshot.edges.push(KnowledgeGraphEdge::Entity(EntityEdge {
            edge_id: "entity:shared-host-to-hunt-b".to_string(),
            from_node_id: shared_host.to_string(),
            to_node_id: engagement_b.to_string(),
            role: "host".to_string(),
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            occurrence_count: 1,
        }));

        let incident_a = CrossHuntIncidentAnchor {
            incident_id: "incident:hunt-a:1",
            hunt_ids: &["hunt-a".to_string()],
            anchor_node_id: engagement_a,
        };
        let incident_b = CrossHuntIncidentAnchor {
            incident_id: "incident:hunt-b:1",
            hunt_ids: &["hunt-b".to_string()],
            anchor_node_id: engagement_b,
        };

        // The two anchors ARE plainly graph-reachable over the all-edge
        // walk ...
        assert!(
            !snapshot
                .provenance_paths(engagement_a, engagement_b, 4)
                .is_empty(),
            "test setup must have a plain (all-edge) graph-reachable path"
        );
        // ... but NOT over the causal-only subgraph: the only causal edge is
        // internal to hunt-a; the cross-hunt hop is made of Entity edges.
        assert!(
            snapshot
                .causal_provenance_paths(engagement_a, engagement_b, 4)
                .is_empty(),
            "there must be NO all-causal path between the two hunts"
        );

        let joined = join_cross_hunt_kill_chain(
            &snapshot,
            std::slice::from_ref(&rule),
            &incident_a,
            &incident_b,
            4,
            1_700_000_000_000,
        );

        assert!(
            joined.is_empty(),
            "an intra-hunt-a-only causal edge plus a non-causal shared-host hop must never \
             fabricate a cross-hunt kill chain: {joined:?}"
        );
    }

    /// The deliberate CONCRETE-node counterpart to
    /// `join_cross_hunt_kill_chain_does_not_bridge_hunts_through_a_shared_threat_pattern`:
    /// the SAME two-causal-edges-through-one-shared-node shape, but the
    /// shared node is a concrete `Process` (both hunts genuinely causally
    /// touched the same process), not a globally-merged classification node.
    /// This IS a real causal relationship -- "connected by a causal path"
    /// per CHAIN-03 -- so it MUST join, proving the causal-only walk is not
    /// over-strict and that the UNDIRECTED walk preserves the
    /// shared-causal-actor (fork/pivot) signal a directed-only walk would
    /// silently drop.
    #[test]
    fn join_cross_hunt_kill_chain_joins_two_disjoint_hunts_through_a_shared_causal_process() {
        let rule = rule_fixture();
        let engagement_a = "engagement:hunt-a";
        let engagement_b = "engagement:hunt-b";
        let shared_process = "process:shared";

        let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
        for technique in &rule.attack_chain {
            snapshot.nodes.push(attack_technique_node(technique));
        }
        snapshot.nodes.push(engagement_node(engagement_a));
        snapshot.nodes.push(engagement_node(engagement_b));
        snapshot.nodes.push(process_node(shared_process));

        // hunt-a observed only stage 0; hunt-b only stages 1 and 2.
        snapshot
            .edges
            .push(KnowledgeGraphEdge::Semantic(SemanticEdge {
                edge_id: "semantic:hunt-a:0".to_string(),
                from_node_id: engagement_a.to_string(),
                to_node_id: technique_node_id(&rule.attack_chain[0]),
                relation: SemanticRelation::KillChainStage,
                kill_chain_stage: rule.attack_chain[0].kill_chain_stage.clone(),
                first_observed_at_ms: 0,
                last_observed_at_ms: 0,
                occurrence_count: 1,
            }));
        for technique in &rule.attack_chain[1..] {
            snapshot
                .edges
                .push(KnowledgeGraphEdge::Semantic(SemanticEdge {
                    edge_id: format!("semantic:hunt-b:{}", technique.technique_id),
                    from_node_id: engagement_b.to_string(),
                    to_node_id: technique_node_id(technique),
                    relation: SemanticRelation::KillChainStage,
                    kill_chain_stage: technique.kill_chain_stage.clone(),
                    first_observed_at_ms: 0,
                    last_observed_at_ms: 0,
                    occurrence_count: 1,
                }));
        }
        // Both hunts causally touched the SAME concrete process -- a genuine
        // shared causal actor. Both edges point INTO the shared process (the
        // fork/pivot shape), which only an UNDIRECTED causal walk joins.
        snapshot.edges.push(KnowledgeGraphEdge::Causal(CausalEdge {
            edge_id: "causal:hunt-a-to-shared-process".to_string(),
            from_node_id: engagement_a.to_string(),
            to_node_id: shared_process.to_string(),
            relation: CausalRelation::ProcessParentChild,
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            occurrence_count: 1,
        }));
        snapshot.edges.push(KnowledgeGraphEdge::Causal(CausalEdge {
            edge_id: "causal:hunt-b-to-shared-process".to_string(),
            from_node_id: engagement_b.to_string(),
            to_node_id: shared_process.to_string(),
            relation: CausalRelation::ProcessParentChild,
            first_observed_at_ms: 0,
            last_observed_at_ms: 0,
            occurrence_count: 1,
        }));
        let shared_process_causal_degree = snapshot
            .edges
            .iter()
            .filter(|edge| match edge {
                KnowledgeGraphEdge::Causal(causal) => {
                    causal.from_node_id == shared_process || causal.to_node_id == shared_process
                }
                _ => false,
            })
            .count();
        assert!(
            shared_process_causal_degree <= KnowledgeGraphSnapshot::PROVENANCE_HUB_DEGREE_CAP,
            "the shared process must be low-degree (a genuine shared actor, not a popular hub); \
             got causal degree {shared_process_causal_degree}"
        );

        let incident_a = CrossHuntIncidentAnchor {
            incident_id: "incident:hunt-a:1",
            hunt_ids: &["hunt-a".to_string()],
            anchor_node_id: engagement_a,
        };
        let incident_b = CrossHuntIncidentAnchor {
            incident_id: "incident:hunt-b:1",
            hunt_ids: &["hunt-b".to_string()],
            anchor_node_id: engagement_b,
        };

        let joined = join_cross_hunt_kill_chain(
            &snapshot,
            std::slice::from_ref(&rule),
            &incident_a,
            &incident_b,
            4,
            1_700_000_000_000,
        );

        assert_eq!(
            joined.len(),
            1,
            "two hunts sharing a genuine causal path through one concrete process must \
             reconstruct into exactly ONE chain: {joined:?}"
        );
        let chain = &joined[0];
        assert_eq!(
            chain.stages,
            vec!["execution", "defense_evasion", "command_and_control"]
        );
        assert_eq!(
            chain.hunt_ids,
            vec!["hunt-a".to_string(), "hunt-b".to_string()]
        );
        assert_eq!(chain.cross_hunt_bridges.len(), 1);
        assert_eq!(
            chain.cross_hunt_bridges[0].node_ids,
            vec![
                engagement_a.to_string(),
                shared_process.to_string(),
                engagement_b.to_string()
            ]
        );
    }

    #[test]
    fn join_cross_hunt_kill_chain_returns_empty_when_hunt_ids_are_not_disjoint() {
        let rule = rule_fixture();
        let engagement_a = "engagement:hunt-shared";
        let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
        for technique in &rule.attack_chain {
            snapshot.nodes.push(attack_technique_node(technique));
        }
        snapshot.nodes.push(engagement_node(engagement_a));

        let incident_a = CrossHuntIncidentAnchor {
            incident_id: "incident:hunt-shared:1",
            hunt_ids: &["hunt-shared".to_string()],
            anchor_node_id: engagement_a,
        };
        let incident_b = CrossHuntIncidentAnchor {
            incident_id: "incident:hunt-shared:2",
            hunt_ids: &["hunt-shared".to_string()],
            anchor_node_id: engagement_a,
        };

        let joined = join_cross_hunt_kill_chain(
            &snapshot,
            std::slice::from_ref(&rule),
            &incident_a,
            &incident_b,
            4,
            1_700_000_000_000,
        );

        assert!(
            joined.is_empty(),
            "two incidents naming the SAME hunt are not a cross-hunt join candidate at all"
        );
    }

    /// CHAIN-04: `narrate()` over >= 2 of the REAL `sequences/kill-chain-v1.yaml`
    /// fixtures, asserting the narrated stage order EXACTLY matches each
    /// rule's own declared `attack_chain` order, and that the narrative is
    /// always non-empty.
    #[test]
    fn narrate_produces_a_non_empty_stage_by_stage_narrative_matching_each_fixtures_declared_chain()
    {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let rules_path = repo_root.join("sequences/kill-chain-v1.yaml");
        let rules = load_kill_chain_stage_rules(&rules_path.display().to_string())
            .expect("the real sequences/kill-chain-v1.yaml must load");

        for rule_id in ["outlook_mshta_transfer", "remote_service_stager"] {
            let rule = rules
                .iter()
                .find(|rule| rule.rule_id == rule_id)
                .unwrap_or_else(|| panic!("fixture rule `{rule_id}` must exist in the real file"))
                .clone();
            assert!(
                rule.attack_chain.len() >= 3,
                "fixture `{rule_id}` must be multi-stage"
            );

            let mut snapshot = KnowledgeGraphSnapshot::new(3_600);
            for technique in &rule.attack_chain {
                snapshot.nodes.push(attack_technique_node(technique));
            }
            for (index, pair) in rule.attack_chain.windows(2).enumerate() {
                snapshot.edges.push(KnowledgeGraphEdge::Causal(CausalEdge {
                    edge_id: format!("causal:{rule_id}:{index}"),
                    from_node_id: technique_node_id(&pair[0]),
                    to_node_id: technique_node_id(&pair[1]),
                    relation: CausalRelation::ProcessParentChild,
                    first_observed_at_ms: 0,
                    last_observed_at_ms: 0,
                    occurrence_count: 1,
                }));
            }

            let reconstructed = reconstruct_kill_chains(&snapshot, std::slice::from_ref(&rule), 1);
            assert_eq!(
                reconstructed.len(),
                1,
                "fixture `{rule_id}` must fully reconstruct from its own direct causal chain"
            );
            let declared_order = rule
                .attack_chain
                .iter()
                .map(|technique| technique.kill_chain_stage.clone())
                .collect::<Vec<_>>();
            assert_eq!(
                reconstructed[0].stages, declared_order,
                "reconstruction itself must match the fixture's declared attack_chain order"
            );

            let chain = ReconstructedKillChain {
                chain_id: format!("chain:{rule_id}:hunt-narrate"),
                rule_id: reconstructed[0].rule_id.clone(),
                rule_name: reconstructed[0].rule_name.clone(),
                created_at_ms: 1_700_000_000_000,
                stages: reconstructed[0].stages.clone(),
                technique_ids: reconstructed[0].technique_ids.clone(),
                node_ids: reconstructed[0].node_ids.clone(),
                hops: reconstructed[0]
                    .hops
                    .iter()
                    .cloned()
                    .map(super::to_reconstructed_chain_hop)
                    .collect(),
                hunt_ids: vec!["hunt-narrate".to_string()],
                incident_ids: Vec::new(),
                cross_hunt_bridges: Vec::new(),
            };

            let narrative = narrate(&chain);
            assert!(
                !narrative.is_empty(),
                "narrate() must always produce a non-empty narrative"
            );

            let narrated_stage_order = narrative
                .lines()
                .filter_map(|line| {
                    let trimmed = line.trim_start();
                    let rest = trimmed.strip_prefix("Stage ")?;
                    let (_, rest) = rest.split_once(": ")?;
                    let (stage, _) = rest.split_once(" (technique ")?;
                    Some(stage.to_string())
                })
                .collect::<Vec<_>>();
            assert_eq!(
                narrated_stage_order, declared_order,
                "fixture `{rule_id}`: narrated stage order must exactly match the declared \
                 attack_chain order"
            );
        }
    }
}
