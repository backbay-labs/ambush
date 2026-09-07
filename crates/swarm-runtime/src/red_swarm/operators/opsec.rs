//! `OpsecOperator` (Cover): hide a noisy step behind quiet activity.
//!
//! Opsec reads the plan so far for a noisy step -- an exploitation step -- and
//! proposes a `Cover(step)` step that replays the quietest catalogued activity
//! available, so the loud step travels next to low-signal traffic. It proposes
//! at most `steps_per_operator` covers and is total: with no noisy step, it
//! proposes nothing.
//!
//! DEVIATION PENDING CONFIRMATION (see task escalation). The brief specifies
//! that a cover reuses a *benign-control* scenario's events (`class: Benign`).
//! Task 1's `TargetGraph` excludes benign scenarios entirely and exposes no
//! benign material, and an operator can reach only the graph, so a benign source
//! is not reachable here. Until the graph exposes benign scenarios, "cover" is
//! read as "the quietest catalogued scenario" (fewest events), which is the
//! nearest low-signal material the graph offers. If the graph gains a
//! `benign_scenarios()` accessor, only the cover-selection below changes.

use super::super::genome::{GeneStep, OperatorRole, StepIntent};
use super::super::graph::{TargetGraph, TechniqueNode};
use super::super::rng::RedGenomeRng;
use super::{RedOperator, choose_distinct, quietest_scenario, step_from, usable_techniques};

/// The largest event count a scenario may have and still count as "quiet" cover.
const COVER_MAX_EVENTS: usize = 3;

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
        // The quiet cover tier: usable techniques whose quietest scenario is
        // small. This stands in for benign-control scenarios (see module note).
        let cover_tier: Vec<&TechniqueNode> = usable_techniques(graph)
            .into_iter()
            .filter(|node| {
                quietest_scenario(node)
                    .is_some_and(|scenario| scenario.event_count <= COVER_MAX_EVENTS)
            })
            .collect();
        if cover_tier.is_empty() {
            return Vec::new();
        }

        let budget = usize::from(self.steps_per_operator);
        let noisy_indices: Vec<usize> = so_far
            .iter()
            .enumerate()
            .filter(|(_, step)| is_noisy(step))
            .map(|(index, _)| index)
            .take(budget)
            .collect();
        if noisy_indices.is_empty() {
            return Vec::new();
        }

        let covers = choose_distinct(rng, &cover_tier, noisy_indices.len());
        let mut steps = Vec::new();
        for (node, &noisy_index) in covers.iter().zip(noisy_indices.iter()) {
            let Some(scenario) = quietest_scenario(node) else {
                continue;
            };
            let Some(class) = node.threat_classes.iter().next().cloned() else {
                continue;
            };
            steps.push(step_from(
                OperatorRole::Opsec,
                node,
                class,
                scenario,
                StepIntent::Cover { step: noisy_index },
            ));
        }
        steps
    }
}
