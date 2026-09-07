//! `OpsecOperator` (Cover): hide a noisy step behind benign-control activity.
//!
//! Opsec reads the plan so far for a noisy step -- an exploitation step -- and
//! proposes a `Cover(step)` step that replays a benign-control scenario's events
//! (the corpus's `class: Benign` scenarios, exposed by
//! [`TargetGraph::benign_scenarios`]) so the loud step travels next to genuinely
//! benign traffic. The cover step keeps the covered step's technique id -- a real
//! graph node, so the plan still resolves against the graph (OPFOR-04) -- while
//! its events come from the benign scenario, not from an attack scenario. It
//! proposes at most `steps_per_operator` covers and is total: with no noisy step,
//! or no benign material in the graph, it proposes nothing.

use super::super::genome::{GeneStep, OperatorRole, StepIntent};
use super::super::graph::{ScenarioRef, TargetGraph};
use super::super::rng::RedGenomeRng;
use super::RedOperator;

/// Opsec operator: proposes `Cover` steps for noisy exploitation steps.
#[derive(Debug, Clone, Copy)]
pub struct OpsecOperator {
    steps_per_operator: u8,
}

impl OpsecOperator {
    /// An opsec operator that proposes up to `steps_per_operator` covers.
    pub fn new(steps_per_operator: u8) -> Self {
        Self { steps_per_operator }
    }
}

impl Default for OpsecOperator {
    fn default() -> Self {
        Self::new(3)
    }
}

/// Whether a step is loud enough to warrant cover. Exploitation steps are the
/// noisy ones; probes and existing covers are not.
fn is_noisy(step: &GeneStep) -> bool {
    matches!(step.intent, StepIntent::Exploit)
}

impl RedOperator for OpsecOperator {
    fn role(&self) -> OperatorRole {
        OperatorRole::Opsec
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
        // Event-backed benign controls are the cover material.
        let benign: Vec<&ScenarioRef> = graph
            .benign_scenarios()
            .iter()
            .filter(|scenario| scenario.event_count > 0)
            .collect();
        if benign.is_empty() {
            return Vec::new();
        }

        let budget = usize::from(self.steps_per_operator);
        let noisy: Vec<(usize, &GeneStep)> = so_far
            .iter()
            .enumerate()
            .filter(|(_, step)| is_noisy(step))
            .take(budget)
            .collect();
        if noisy.is_empty() {
            return Vec::new();
        }

        let mut steps = Vec::new();
        for (index, covered) in noisy {
            let Some(cover) = rng.choose(&benign).copied() else {
                continue;
            };
            // The cover keeps the covered step's technique (a real graph node),
            // so the plan resolves, but replays the benign scenario's events.
            steps.push(GeneStep {
                operator: OperatorRole::Opsec,
                technique: covered.technique.clone(),
                threat_class: covered.threat_class.clone(),
                scenario: cover.clone(),
                event_indices: (0..cover.event_count).collect(),
                host_slot: 0,
                offset_ms: 0,
                intent: StepIntent::Cover { step: index },
            });
        }
        steps
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use swarm_core::pheromone::ThreatClass;

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

    fn exploit_step() -> GeneStep {
        GeneStep {
            operator: OperatorRole::Injection,
            technique: "T1059.001".to_string(),
            threat_class: ThreatClass::Execution,
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
    fn the_opsec_operator_covers_a_noisy_step_with_a_benign_scenario() {
        let graph = repo_graph();
        let opsec = OpsecOperator::new(3);

        // A noisy exploitation step draws cover, and the cover replays a benign
        // scenario while keeping a real graph technique.
        let so_far = vec![exploit_step()];
        let mut rng = RedGenomeRng::from_u64(4);
        let covers = opsec.propose_steps(&graph, &mut rng, &so_far);
        assert!(!covers.is_empty(), "a noisy step should draw cover");
        let benign = graph.benign_scenarios();
        for cover in &covers {
            assert!(matches!(cover.intent, StepIntent::Cover { .. }));
            assert!(
                benign.contains(&cover.scenario),
                "cover scenario {:?} is not a benign one",
                cover.scenario
            );
            assert!(
                graph.is_technique(&cover.technique),
                "cover technique {} is not a graph node",
                cover.technique
            );
        }

        // No noisy step -> nothing to cover: the operator is total.
        let probe_only = vec![GeneStep {
            intent: StepIntent::Probe,
            ..exploit_step()
        }];
        let mut rng = RedGenomeRng::from_u64(4);
        assert!(
            opsec
                .propose_steps(&graph, &mut rng, &probe_only)
                .is_empty()
        );
    }
}
