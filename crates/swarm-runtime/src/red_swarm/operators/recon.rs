//! `ReconOperator` (Probe): reconnaissance goes to the gaps first.
//!
//! Recon prefers discovery / initial-access techniques, because that is where a
//! campaign opens. The shipped corpus, though, carries no usable initial-access
//! technique (its only one is a scenario-less catalog gap), so the brief's
//! fallback applies: when no discovery/initial-access technique is usable, Recon
//! still probes the quietest activity it can see. Throughout it prefers
//! techniques a detector declared uncovered -- the gaps are exactly where
//! reconnaissance is most productive.

use super::super::genome::{GeneStep, OperatorRole, StepIntent};
use super::super::graph::{TargetGraph, TechniqueNode};
use super::super::rng::RedGenomeRng;
use super::{
    RedOperator, choose_distinct, class_for, quietest_scenario, step_from, usable_techniques,
};
use swarm_core::pheromone::ThreatClass;

/// Reconnaissance operator: proposes `Probe` steps over the recon surface.
#[derive(Debug, Clone, Copy)]
pub struct ReconOperator {
    steps_per_operator: u8,
}

impl ReconOperator {
    /// A recon operator that proposes up to `steps_per_operator` probes.
    pub fn new(steps_per_operator: u8) -> Self {
        Self { steps_per_operator }
    }
}

impl Default for ReconOperator {
    fn default() -> Self {
        Self::new(3)
    }
}

impl RedOperator for ReconOperator {
    fn role(&self) -> OperatorRole {
        OperatorRole::Recon
    }

    fn propose_steps(
        &self,
        graph: &TargetGraph,
        rng: &mut RedGenomeRng,
        _so_far: &[GeneStep],
    ) -> Vec<GeneStep> {
        let usable = usable_techniques(graph);
        if usable.is_empty() {
            return Vec::new();
        }

        // Primary: discovery / initial_access. Fall back across classes only
        // when the corpus has no usable recon technique.
        let recon_classes = [ThreatClass::Discovery, ThreatClass::InitialAccess];
        let primary: Vec<&TechniqueNode> = usable
            .iter()
            .copied()
            .filter(|node| {
                recon_classes
                    .iter()
                    .any(|class| node.threat_classes.contains(class))
            })
            .collect();
        let pool = if primary.is_empty() { usable } else { primary };

        // Prefer the gaps: techniques a detector declared uncovered.
        let gaps: Vec<&TechniqueNode> = pool
            .iter()
            .copied()
            .filter(|node| !node.declared_uncovered_by.is_empty())
            .collect();
        let pool = if gaps.is_empty() { pool } else { gaps };

        let chosen = choose_distinct(rng, &pool, usize::from(self.steps_per_operator));
        let mut steps = Vec::new();
        for node in chosen {
            let Some(class) = class_for(node, &recon_classes) else {
                continue;
            };
            // Recon reads the quietest scenario: the "lowest severity" fallback.
            let Some(scenario) = quietest_scenario(node) else {
                continue;
            };
            steps.push(step_from(
                OperatorRole::Recon,
                node,
                class,
                scenario,
                StepIntent::Probe,
            ));
        }
        steps
    }
}
