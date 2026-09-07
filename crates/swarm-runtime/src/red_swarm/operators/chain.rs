//! `ChainOperator` (Chain): bridge two kill-chain-adjacent steps.
//!
//! Chain reads the plan so far for two steps whose threat classes are adjacent
//! in the kill chain -- a predecessor and its immediate successor -- and proposes
//! a technique that advances the chain into the successor class, linked back to
//! the predecessor through `Chain(from)`. It only bridges genuine adjacencies.
//!
//! **Kill-chain order.** The brief spells the adjacency as
//! `initial_access -> execution -> persistence -> credential_access ->
//! lateral_movement -> exfiltration -> impact` and attributes it to
//! `escalation::standard_threat_classes()`. That function actually returns a
//! *different* order (lateral_movement first, impact last -- an escalation /
//! severity order, not a kill chain), so the spelled-out adjacency is pinned
//! here directly rather than derived from it. (`exfiltration` is
//! [`ThreatClass::DataExfiltration`].)

use super::super::genome::{GeneStep, OperatorRole, StepIntent};
use super::super::graph::{TargetGraph, TechniqueNode};
use super::super::rng::RedGenomeRng;
use super::{RedOperator, choose_distinct, choose_scenario, step_from, usable_techniques};
use swarm_core::pheromone::ThreatClass;

/// The kill-chain stages, in the order Chain advances along.
fn kill_chain() -> [ThreatClass; 7] {
    [
        ThreatClass::InitialAccess,
        ThreatClass::Execution,
        ThreatClass::Persistence,
        ThreatClass::CredentialAccess,
        ThreatClass::LateralMovement,
        ThreatClass::DataExfiltration,
        ThreatClass::Impact,
    ]
}

/// The class immediately after `class` in the kill chain, if any.
fn successor(class: &ThreatClass) -> Option<ThreatClass> {
    let chain = kill_chain();
    let position = chain.iter().position(|stage| stage == class)?;
    chain.get(position + 1).cloned()
}

/// Chain operator: proposes `Chain` steps that bridge adjacent stages.
#[derive(Debug, Clone, Copy)]
pub struct ChainOperator {
    steps_per_operator: u8,
}

impl ChainOperator {
    /// A chain operator that proposes up to `steps_per_operator` bridges.
    pub fn new(steps_per_operator: u8) -> Self {
        Self { steps_per_operator }
    }
}

impl Default for ChainOperator {
    fn default() -> Self {
        Self::new(3)
    }
}

impl RedOperator for ChainOperator {
    fn role(&self) -> OperatorRole {
        OperatorRole::Chain
    }

    fn propose_steps(
        &self,
        graph: &TargetGraph,
        rng: &mut RedGenomeRng,
        so_far: &[GeneStep],
    ) -> Vec<GeneStep> {
        if so_far.is_empty() {
            return Vec::new();
        }
        let usable = usable_techniques(graph);
        let budget = usize::from(self.steps_per_operator);
        let mut steps = Vec::new();
        let mut bridged_from: Vec<usize> = Vec::new();

        for (index, step) in so_far.iter().enumerate() {
            if steps.len() >= budget {
                break;
            }
            if bridged_from.contains(&index) {
                continue;
            }
            let Some(successor_class) = successor(&step.threat_class) else {
                continue;
            };
            // Require a second existing step already in the successor class: the
            // two adjacent steps whose transition this bridge reinforces.
            let has_successor_step = so_far.iter().enumerate().any(|(other, candidate)| {
                other != index && candidate.threat_class == successor_class
            });
            if !has_successor_step {
                continue;
            }
            // Bridge with a usable technique in the successor class.
            let bridge_pool: Vec<&TechniqueNode> = usable
                .iter()
                .copied()
                .filter(|node| node.threat_classes.contains(&successor_class))
                .collect();
            let Some(node) = choose_distinct(rng, &bridge_pool, 1).into_iter().next() else {
                continue;
            };
            let Some(scenario) = choose_scenario(rng, node) else {
                continue;
            };
            steps.push(step_from(
                OperatorRole::Chain,
                node,
                successor_class,
                scenario,
                StepIntent::Chain { from: index },
            ));
            bridged_from.push(index);
        }
        steps
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::red_swarm::genome::GeneStep;
    use crate::red_swarm::graph::{ScenarioRef, TargetGraph};
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn repo_graph() -> TargetGraph {
        let catalog = repo_root().join("rulesets/evasion/attack-technique-catalog.yaml");
        let suites: Vec<PathBuf> = [
            "scenario-suites/command-line-deobfuscation-v1.yaml",
            "scenario-suites/evasion-breadth-v1.yaml",
            "scenario-suites/hellcat-office-v1.yaml",
            "scenario-suites/kill-chain-sequences-v1.yaml",
        ]
        .iter()
        .map(|rel| repo_root().join(rel))
        .collect();
        TargetGraph::from_repo(&catalog, &suites).unwrap()
    }

    fn step(threat_class: ThreatClass) -> GeneStep {
        GeneStep {
            operator: OperatorRole::Auth,
            technique: "placeholder".to_string(),
            threat_class,
            scenario: ScenarioRef {
                suite: "s".to_string(),
                scenario: "s".to_string(),
                event_count: 1,
            },
            event_indices: vec![0],
            host_slot: 0,
            offset_ms: 0,
            intent: StepIntent::Exploit,
        }
    }

    #[test]
    fn the_chain_operator_only_bridges_adjacent_classes() {
        let graph = repo_graph();
        let chain = ChainOperator::new(3);

        // A credential_access step and a lateral_movement step form an adjacency
        // (credential_access -> lateral_movement). Chain must bridge into the
        // successor class and link back to the predecessor.
        let so_far = vec![
            step(ThreatClass::CredentialAccess),
            step(ThreatClass::LateralMovement),
        ];
        let mut rng = RedGenomeRng::from_u64(3);
        let bridges = chain.propose_steps(&graph, &mut rng, &so_far);
        assert!(!bridges.is_empty(), "an adjacent pair should be bridged");
        for bridge in &bridges {
            let StepIntent::Chain { from } = &bridge.intent else {
                panic!("chain step must carry Chain intent");
            };
            let predecessor = &so_far[*from];
            assert_eq!(
                successor(&predecessor.threat_class),
                Some(bridge.threat_class.clone()),
                "bridge class is not the kill-chain successor of the from-step"
            );
        }

        // Two impact steps are not adjacent to anything reachable, so nothing
        // bridges: the operator is total and only bridges real adjacencies.
        let non_adjacent = vec![step(ThreatClass::Impact), step(ThreatClass::Impact)];
        let mut rng = RedGenomeRng::from_u64(3);
        assert!(
            chain
                .propose_steps(&graph, &mut rng, &non_adjacent)
                .is_empty()
        );
    }
}
