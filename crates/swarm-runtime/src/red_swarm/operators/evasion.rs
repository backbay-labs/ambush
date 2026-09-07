//! `EvasionOperator` (Evade): rewrite a step toward a detector's declared gap.
//!
//! Evasion reads the plan so far for a step whose technique a detector declared
//! intentionally uncovered, and proposes a *different* technique the same
//! detector also declared uncovered. That is the essence of evasion here:
//! stay inside the same detector's blind spot while changing the technique it
//! sees. It invents nothing -- both the original and the replacement are
//! catalogued gaps -- and it is total: with no rewriteable step, it proposes
//! nothing.

use super::super::genome::{GeneStep, OperatorRole, StepIntent};
use super::super::graph::{TargetGraph, TechniqueNode};
use super::super::rng::RedGenomeRng;
use super::{
    RedOperator, choose_distinct, choose_scenario, class_for, step_from, usable_techniques,
};
use swarm_core::pheromone::ThreatClass;

/// Evasion operator: proposes `Evade` steps toward same-detector gaps.
#[derive(Debug, Clone, Copy)]
pub struct EvasionOperator {
    steps_per_operator: u8,
}

impl EvasionOperator {
    /// An evasion operator that proposes up to `steps_per_operator` rewrites.
    pub fn new(steps_per_operator: u8) -> Self {
        Self { steps_per_operator }
    }
}

impl Default for EvasionOperator {
    fn default() -> Self {
        Self::new(3)
    }
}

impl RedOperator for EvasionOperator {
    fn role(&self) -> OperatorRole {
        OperatorRole::Evasion
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
        let mut chosen_ids: Vec<String> = Vec::new();

        for step in so_far {
            if steps.len() >= budget {
                break;
            }
            let Some(original) = graph.technique(&step.technique) else {
                continue;
            };
            if original.declared_uncovered_by.is_empty() {
                continue;
            }
            // A different usable technique the SAME detector also declares
            // uncovered -- the blind spot the rewrite stays inside.
            let alternatives: Vec<&TechniqueNode> = usable
                .iter()
                .copied()
                .filter(|candidate| {
                    candidate.id != original.id
                        && !chosen_ids.contains(&candidate.id)
                        && candidate
                            .declared_uncovered_by
                            .iter()
                            .any(|detector| original.declared_uncovered_by.contains(detector))
                })
                .collect();
            let Some(alternative) = choose_distinct(rng, &alternatives, 1).into_iter().next()
            else {
                continue;
            };
            let Some(class) = class_for(alternative, &[ThreatClass::DefenseEvasion]) else {
                continue;
            };
            let Some(scenario) = choose_scenario(rng, alternative) else {
                continue;
            };
            steps.push(step_from(
                OperatorRole::Evasion,
                alternative,
                class,
                scenario,
                StepIntent::Evade,
            ));
            chosen_ids.push(alternative.id.clone());
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

    fn step(technique: &str, threat_class: ThreatClass) -> GeneStep {
        GeneStep {
            operator: OperatorRole::Injection,
            technique: technique.to_string(),
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
    fn the_evasion_operator_only_rewrites_toward_a_declared_gap() {
        let graph = repo_graph();
        let evasion = EvasionOperator::new(3);

        // T1106 is declared uncovered by `fileless_execution`, which also
        // declares T1620 uncovered: a same-detector alternative exists.
        let original = graph.technique("T1106").expect("T1106 is a catalogued gap");
        let so_far = vec![step("T1106", ThreatClass::DefenseEvasion)];
        let mut rng = RedGenomeRng::from_u64(9);
        let rewrites = evasion.propose_steps(&graph, &mut rng, &so_far);
        assert!(
            !rewrites.is_empty(),
            "a same-detector gap should be reachable"
        );
        for rewrite in &rewrites {
            assert_eq!(rewrite.intent, StepIntent::Evade);
            assert_ne!(
                rewrite.technique, "T1106",
                "a rewrite must change the technique"
            );
            let node = graph
                .technique(&rewrite.technique)
                .expect("rewrite names a graph technique");
            let shares_detector = node
                .declared_uncovered_by
                .iter()
                .any(|detector| original.declared_uncovered_by.contains(detector));
            assert!(
                shares_detector,
                "rewrite {} is not a gap of any detector that declared T1106 uncovered",
                rewrite.technique
            );
        }

        // A step whose technique is not a declared gap has nothing to rewrite
        // toward: the operator is total.
        let no_gap = vec![step("T1059.001", ThreatClass::Execution)];
        let mut rng = RedGenomeRng::from_u64(9);
        assert!(evasion.propose_steps(&graph, &mut rng, &no_gap).is_empty());
    }
}
