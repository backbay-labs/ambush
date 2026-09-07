//! `InjectionOperator` (Exploit): execution and fileless injection.
//!
//! Injection exercises the execution surface and the gaps of the detectors that
//! watch it -- `suspicious_scripting`, `fileless_execution`,
//! `suspicious_process_tree`. It prefers those detectors' declared gaps (they
//! are what this role exists to press on) and fills the rest of its budget with
//! plain execution techniques.

use super::super::genome::{GeneStep, OperatorRole, StepIntent};
use super::super::graph::{TargetGraph, TechniqueNode};
use super::super::rng::RedGenomeRng;
use super::{
    RedOperator, choose_preferred_then_fill, choose_scenario, class_for, step_from,
    usable_techniques,
};
use swarm_core::pheromone::ThreatClass;

/// The detectors whose gaps this role targets, alongside execution techniques.
const TARGET_DETECTORS: [&str; 3] = [
    "suspicious_scripting",
    "fileless_execution",
    "suspicious_process_tree",
];

/// Injection operator: proposes `Exploit` steps over execution material.
#[derive(Debug, Clone, Copy)]
pub struct InjectionOperator {
    steps_per_operator: u8,
}

impl InjectionOperator {
    /// An injection operator that proposes up to `steps_per_operator` exploits.
    pub fn new(steps_per_operator: u8) -> Self {
        Self { steps_per_operator }
    }
}

impl Default for InjectionOperator {
    fn default() -> Self {
        Self::new(3)
    }
}

fn targets_injection_detector(node: &TechniqueNode) -> bool {
    node.declared_uncovered_by
        .iter()
        .any(|detector| TARGET_DETECTORS.contains(&detector.as_str()))
}

impl RedOperator for InjectionOperator {
    fn role(&self) -> OperatorRole {
        OperatorRole::Injection
    }

    fn propose_steps(
        &self,
        graph: &TargetGraph,
        rng: &mut RedGenomeRng,
        _so_far: &[GeneStep],
    ) -> Vec<GeneStep> {
        let usable = usable_techniques(graph);
        let candidates: Vec<&TechniqueNode> = usable
            .iter()
            .copied()
            .filter(|node| {
                node.threat_classes.contains(&ThreatClass::Execution)
                    || targets_injection_detector(node)
            })
            .collect();
        if candidates.is_empty() {
            return Vec::new();
        }

        // Prefer the targeted detectors' gaps, then fill with execution techniques.
        let gaps: Vec<&TechniqueNode> = candidates
            .iter()
            .copied()
            .filter(|node| targets_injection_detector(node))
            .collect();
        let chosen = choose_preferred_then_fill(
            rng,
            &gaps,
            &candidates,
            usize::from(self.steps_per_operator),
        );

        let mut steps = Vec::new();
        for node in chosen {
            let Some(class) = class_for(node, &[ThreatClass::Execution]) else {
                continue;
            };
            let Some(scenario) = choose_scenario(rng, node) else {
                continue;
            };
            steps.push(step_from(
                OperatorRole::Injection,
                node,
                class,
                scenario,
                StepIntent::Exploit,
            ));
        }
        steps
    }
}
