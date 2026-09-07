//! The red operators: the shared [`RedOperator`] trait, the built-in registry,
//! and the helpers the six roles share (OPFOR-01).
//!
//! An operator is a bounded, deterministic heuristic that turns the target
//! graph into a handful of proposed [`GeneStep`]s. Every operator obeys two
//! rules that make the arms race classical and safe:
//!   - **It invents nothing.** A step may only name a technique the graph
//!     contains and one of that technique's own scenarios. An operator that
//!     cannot find applicable graph material returns an empty `Vec` -- it is
//!     *total*, never a panic.
//!   - **It draws only from the stream it is handed.** No clock, no entropy; the
//!     planner forks each operator its own stream so its draws are reproducible
//!     and independent of the others'.

use super::genome::{GeneStep, OperatorRole, StepIntent};
use super::graph::{ScenarioRef, TargetGraph, TechniqueNode};
use super::rng::RedGenomeRng;
use swarm_core::pheromone::ThreatClass;

mod auth;
mod chain;
mod evasion;
mod injection;
mod opsec;
mod recon;

pub use auth::AuthOperator;
pub use chain::ChainOperator;
pub use evasion::EvasionOperator;
pub use injection::InjectionOperator;
pub use opsec::OpsecOperator;
pub use recon::ReconOperator;

/// A red operator role: a heuristic that proposes steps from the graph.
///
/// **Signature note (recorded deviation from OPFOR-01).** OPFOR-01 states
/// `propose_steps(&self, graph, rng) -> Vec<GeneStep>`. This trait extends it
/// with `so_far`, the steps proposed before this operator ran. The Evasion,
/// Chain and Opsec roles *amend* the plan taking shape -- Evasion rewrites an
/// earlier step toward a detector's gap, Chain bridges two earlier steps, Opsec
/// covers an earlier noisy step -- and cannot do that from `(graph, rng)` alone.
/// The planner calls the operators in a fixed order and passes each the prefix
/// proposed so far. This is the one place the brief's signature is extended.
pub trait RedOperator: Send + Sync {
    /// The role this operator plays; the planner uses it to label the operator's
    /// PRNG stream and to attribute each step.
    fn role(&self) -> OperatorRole;

    /// Propose zero or more steps from the graph, drawing only from `rng`, given
    /// the plan proposed `so_far`. Total: an empty applicable set yields `vec![]`.
    fn propose_steps(
        &self,
        graph: &TargetGraph,
        rng: &mut RedGenomeRng,
        so_far: &[GeneStep],
    ) -> Vec<GeneStep>;
}

/// The six built-in operators, constructed with `steps_per_operator`, in the
/// planner's fixed call order: Recon, Auth, Injection, Chain, Evasion, Opsec.
/// That order is what the `round_robin_v1` scheduler string names; reordering it
/// changes the plan's bytes and so must change that string too.
pub fn builtin_operators(steps_per_operator: u8) -> Vec<Box<dyn RedOperator>> {
    vec![
        Box::new(ReconOperator::new(steps_per_operator)),
        Box::new(AuthOperator::new(steps_per_operator)),
        Box::new(InjectionOperator::new(steps_per_operator)),
        Box::new(ChainOperator::new(steps_per_operator)),
        Box::new(EvasionOperator::new(steps_per_operator)),
        Box::new(OpsecOperator::new(steps_per_operator)),
    ]
}

// --- helpers shared by the role files -------------------------------------

/// A technique is usable by an operator only when some scenario realises it with
/// at least one event: a step must point at real events, and a scenario-less
/// catalog gap (e.g. `T1204.001`) has none to point at.
pub(super) fn is_usable(node: &TechniqueNode) -> bool {
    node.scenarios
        .iter()
        .any(|scenario| scenario.event_count > 0)
}

/// Every technique in the graph that is usable for a step.
pub(super) fn usable_techniques(graph: &TargetGraph) -> Vec<&TechniqueNode> {
    graph.techniques().filter(|node| is_usable(node)).collect()
}

/// The usable scenario with the fewest events. The corpus carries no scenario
/// severity, so "lowest severity" is read as "least noisy" = fewest events; ties
/// break by the canonical [`ScenarioRef`] order, keeping the choice deterministic.
pub(super) fn quietest_scenario(node: &TechniqueNode) -> Option<&ScenarioRef> {
    node.scenarios
        .iter()
        .filter(|scenario| scenario.event_count > 0)
        .min_by(|a, b| a.event_count.cmp(&b.event_count).then_with(|| a.cmp(b)))
}

/// Choose one usable scenario for a technique uniformly from the operator's own
/// stream, or `None` when the technique has no event-backed scenario.
pub(super) fn choose_scenario<'a>(
    rng: &mut RedGenomeRng,
    node: &'a TechniqueNode,
) -> Option<&'a ScenarioRef> {
    let usable: Vec<&ScenarioRef> = node
        .scenarios
        .iter()
        .filter(|scenario| scenario.event_count > 0)
        .collect();
    rng.choose(&usable).copied()
}

/// The threat class a step should carry for a technique: the first of the
/// operator's `preferred` classes the technique actually declares, else the
/// technique's lowest declared class (which every usable technique has).
pub(super) fn class_for(node: &TechniqueNode, preferred: &[ThreatClass]) -> Option<ThreatClass> {
    for class in preferred {
        if node.threat_classes.contains(class) {
            return Some(class.clone());
        }
    }
    node.threat_classes.iter().next().cloned()
}

/// Choose up to `n` distinct techniques uniformly without replacement (a partial
/// Fisher-Yates from the operator's own stream), so a role never proposes the
/// same technique twice and its choice stays reproducible.
pub(super) fn choose_distinct<'a>(
    rng: &mut RedGenomeRng,
    items: &[&'a TechniqueNode],
    n: usize,
) -> Vec<&'a TechniqueNode> {
    let mut pool: Vec<&TechniqueNode> = items.to_vec();
    let mut out = Vec::new();
    let take = n.min(pool.len());
    for _ in 0..take {
        let len = u64::try_from(pool.len()).unwrap_or(0);
        let index = usize::try_from(rng.next_below(len)).unwrap_or(0);
        if index < pool.len() {
            out.push(pool.swap_remove(index));
        }
    }
    out
}

/// Choose up to `n` distinct techniques, taking from `preferred` first and then
/// filling from `all`. Used where a role wants to guarantee it exercises certain
/// techniques (its detector gaps) yet still fill the remaining budget broadly.
pub(super) fn choose_preferred_then_fill<'a>(
    rng: &mut RedGenomeRng,
    preferred: &[&'a TechniqueNode],
    all: &[&'a TechniqueNode],
    n: usize,
) -> Vec<&'a TechniqueNode> {
    let mut out = choose_distinct(rng, preferred, n);
    if out.len() < n {
        let rest: Vec<&TechniqueNode> = all
            .iter()
            .copied()
            .filter(|candidate| !out.iter().any(|picked| picked.id == candidate.id))
            .collect();
        out.extend(choose_distinct(rng, &rest, n - out.len()));
    }
    out
}

/// Build a step for a technique: its id (a real graph node), a class it
/// declares, the chosen scenario, all of that scenario's events in order, and
/// the operator's intent. `host_slot` is `0` (Phase 289 binds it) and
/// `offset_ms` is `0` (the planner assigns the schedule).
pub(super) fn step_from(
    role: OperatorRole,
    node: &TechniqueNode,
    threat_class: ThreatClass,
    scenario: &ScenarioRef,
    intent: StepIntent,
) -> GeneStep {
    GeneStep {
        operator: role,
        technique: node.id.clone(),
        threat_class,
        scenario: scenario.clone(),
        event_indices: (0..scenario.event_count).collect(),
        host_slot: 0,
        offset_ms: 0,
        intent,
    }
}
