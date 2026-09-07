//! `AuthOperator` (Exploit): credential access and lateral movement.
//!
//! Auth exercises the two stages an intruder crosses once inside: taking
//! credentials and moving between hosts. When the graph has both, it deliberately
//! proposes at least one of each, so the plan carries a
//! credential_access -> lateral_movement adjacency the [`ChainOperator`] can
//! bridge; it then fills the rest of its budget from either stage.

use super::super::genome::{GeneStep, OperatorRole, StepIntent};
use super::super::graph::{TargetGraph, TechniqueNode};
use super::super::rng::RedGenomeRng;
use super::super::weights::TechniqueWeights;
use super::{RedOperator, choose_distinct, choose_scenario, step_from, usable_techniques};
use swarm_core::pheromone::ThreatClass;

/// Auth operator: proposes `Exploit` steps over credential / lateral material.
#[derive(Debug, Clone, Copy)]
pub struct AuthOperator {
    steps_per_operator: u8,
}

impl AuthOperator {
    /// An auth operator that proposes up to `steps_per_operator` steps.
    pub fn new(steps_per_operator: u8) -> Self {
        Self { steps_per_operator }
    }
}

impl Default for AuthOperator {
    fn default() -> Self {
        Self::new(3)
    }
}

impl RedOperator for AuthOperator {
    fn role(&self) -> OperatorRole {
        OperatorRole::Auth
    }

    fn propose_steps(
        &self,
        graph: &TargetGraph,
        rng: &mut RedGenomeRng,
        _so_far: &[GeneStep],
        weights: Option<&TechniqueWeights>,
    ) -> Vec<GeneStep> {
        let usable = usable_techniques(graph);
        let credential: Vec<&TechniqueNode> = usable
            .iter()
            .copied()
            .filter(|node| node.threat_classes.contains(&ThreatClass::CredentialAccess))
            .collect();
        let lateral: Vec<&TechniqueNode> = usable
            .iter()
            .copied()
            .filter(|node| node.threat_classes.contains(&ThreatClass::LateralMovement))
            .collect();
        if credential.is_empty() && lateral.is_empty() {
            return Vec::new();
        }

        let budget = usize::from(self.steps_per_operator);
        let mut picks: Vec<(&TechniqueNode, ThreatClass)> = Vec::new();

        // One credential step, then one lateral step distinct from it, so the
        // adjacency exists; then fill from either stage. `choose_distinct` yields
        // nothing on an empty pool, so no separate emptiness guard is needed.
        if let Some(node) = choose_distinct(rng, &credential, 1, weights)
            .into_iter()
            .next()
        {
            picks.push((node, ThreatClass::CredentialAccess));
        }
        if picks.len() < budget {
            let lateral_pool: Vec<&TechniqueNode> = lateral
                .iter()
                .copied()
                .filter(|candidate| !picks.iter().any(|(picked, _)| picked.id == candidate.id))
                .collect();
            if let Some(node) = choose_distinct(rng, &lateral_pool, 1, weights)
                .into_iter()
                .next()
            {
                picks.push((node, ThreatClass::LateralMovement));
            }
        }
        if picks.len() < budget {
            let mut union: Vec<&TechniqueNode> = Vec::new();
            for node in credential.iter().copied().chain(lateral.iter().copied()) {
                let already = union.iter().any(|existing| existing.id == node.id)
                    || picks.iter().any(|(picked, _)| picked.id == node.id);
                if !already {
                    union.push(node);
                }
            }
            for node in choose_distinct(rng, &union, budget - picks.len(), weights) {
                let class = if node.threat_classes.contains(&ThreatClass::CredentialAccess) {
                    ThreatClass::CredentialAccess
                } else {
                    ThreatClass::LateralMovement
                };
                picks.push((node, class));
            }
        }

        let mut steps = Vec::new();
        for (node, class) in picks {
            let Some(scenario) = choose_scenario(rng, node) else {
                continue;
            };
            steps.push(step_from(
                OperatorRole::Auth,
                node,
                class,
                scenario,
                StepIntent::Exploit,
            ));
        }
        steps
    }
}
