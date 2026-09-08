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
//! 2. For each consecutive pair in that run, call
//!    [`KnowledgeGraphSnapshot::provenance_paths`] (the Phase 296 traversal —
//!    the graph's SOLE multi-hop read path; this module never re-walks
//!    `edges`/`nodes` to build its own adjacency) bounded by `max_hops`. If
//!    no path connects them — including through a shared `Engagement` hub,
//!    a causal chain (`ProcessParentChild`/`NetworkFlowOrigin`/...), or a
//!    temporal co-occurrence edge — the run stops there too: two techniques
//!    that were each observed but never in the same causal/temporal/semantic
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
//! Read-only: nothing here calls `upsert_node`/`upsert_edge` or otherwise
//! mutates a `KnowledgeGraphSnapshot`.

use serde::Deserialize;
use std::fs;

use crate::sequence_detector::KillChainSequenceProfile;
use crate::sphinx_agent::{KnowledgeGraphNode, KnowledgeGraphSnapshot, ProvenancePath};

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
            let Some(hop) = snapshot
                .provenance_paths(previous_node_id, &node_id, max_hops)
                .into_iter()
                .next()
            else {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        KillChainStageRule, KillChainStageTechnique, load_kill_chain_stage_rules,
        load_kill_chain_stage_rules_from_profile, reconstruct_kill_chains,
    };
    use crate::sequence_detector::KillChainSequenceProfile;
    use crate::sphinx_agent::{
        AttackTechniqueNode, CausalEdge, CausalRelation, KnowledgeGraphEdge, KnowledgeGraphNode,
        KnowledgeGraphSnapshot, SemanticEdge, SemanticRelation,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

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
}
