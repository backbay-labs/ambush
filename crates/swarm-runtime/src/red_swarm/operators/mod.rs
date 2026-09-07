//! The red operators: the shared [`RedOperator`] trait, the built-in registry,
//! and the helpers the six roles share (OPFOR-01).
//!
//! An operator is a bounded, deterministic heuristic that turns the target
//! graph into a handful of proposed [`GeneStep`]s. Every operator obeys two
//! rules that make the arms race classical and safe:
//!   - **It invents nothing.** A step may only name a technique the graph
//!     contains and replay real corpus events: one of that technique's own
//!     scenarios, or -- for an Opsec cover step -- a benign-control scenario the
//!     graph carries. An operator that finds no applicable material returns an
//!     empty `Vec` -- it is *total*, never a panic.
//!   - **It draws only from the stream it is handed.** No clock, no entropy; the
//!     planner forks each operator its own stream, so no two operators share a
//!     draw. The streams are not order-independent, though: `fork` advances the
//!     parent once per call, so the operator call order is part of the
//!     determinism contract (the `scheduler` string names it), not something a
//!     reorder may change silently.

use super::genome::{GeneStep, OperatorRole, StepIntent};
use super::graph::{ScenarioRef, TargetGraph, TechniqueNode};
use super::rng::RedGenomeRng;
use super::weights::TechniqueWeights;
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
/// twice:
///   - with `so_far`, the steps proposed before this operator ran. The Evasion,
///     Chain and Opsec roles *amend* the plan taking shape -- Evasion rewrites an
///     earlier step toward a detector's gap, Chain bridges two earlier steps, Opsec
///     covers an earlier noisy step -- and cannot do that from `(graph, rng)` alone.
///     The planner calls the operators in a fixed order and passes each the prefix
///     proposed so far;
///   - with `weights` (Phase 290, COEVOLVE-01/-03/-04): an optional bias toward
///     techniques a [`TechniqueWeights`] snapshot prices as more likely to evade.
///     `None` MUST route every technique choice through the exact unweighted draw
///     Phase 288 shipped -- see [`choose_distinct`] -- so a caller that never
///     passes weights sees byte-identical plans forever.
///
/// This is the one place (this trait method) either extension lives.
pub trait RedOperator: Send + Sync {
    /// The role this operator plays; the planner uses it to label the operator's
    /// PRNG stream and to attribute each step.
    fn role(&self) -> OperatorRole;

    /// Propose zero or more steps from the graph, drawing only from `rng`, given
    /// the plan proposed `so_far` and, optionally, a technique-weight bias.
    /// Total: an empty applicable set yields `vec![]`.
    fn propose_steps(
        &self,
        graph: &TargetGraph,
        rng: &mut RedGenomeRng,
        so_far: &[GeneStep],
        weights: Option<&TechniqueWeights>,
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

/// Choose up to `n` distinct techniques from `items`, optionally biased by
/// `weights` (COEVOLVE-01/-03/-04).
///
/// `weights: None` calls [`choose_distinct_uniform`] and nothing else -- the
/// exact partial Fisher-Yates draw Phase 288 shipped, unchanged, so this arm
/// alone is what makes `RedGenome::plan_weighted(.., None)` byte-identical to
/// `RedGenome::plan`. `weights: Some` calls [`choose_distinct_weighted`]
/// instead: a different draw, deterministic in its own right, but never the
/// one `None` takes.
pub(super) fn choose_distinct<'a>(
    rng: &mut RedGenomeRng,
    items: &[&'a TechniqueNode],
    n: usize,
    weights: Option<&TechniqueWeights>,
) -> Vec<&'a TechniqueNode> {
    match weights {
        None => choose_distinct_uniform(rng, items, n),
        Some(weights) => choose_distinct_weighted(rng, items, n, weights),
    }
}

/// The Phase 288 draw: `n` distinct techniques chosen uniformly without
/// replacement (a partial Fisher-Yates from the operator's own stream), so a
/// role never proposes the same technique twice and its choice stays
/// reproducible. Every technique is equally likely regardless of the pool's
/// order, one `rng.next_below` call per pick.
fn choose_distinct_uniform<'a>(
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

/// The Phase 290 weighted draw: `n` distinct techniques chosen without
/// replacement, one at a time, each pick's probability proportional to its
/// [`TechniqueWeights::weight_for`] value among whatever remains in the pool
/// (sequential weighted sampling, the same swap-remove shape
/// [`choose_distinct_uniform`] uses, with a weighted index in place of a
/// uniform one). Exactly one `rng.next_below` call per pick, over the pool's
/// scaled weight total rather than its length -- no extra draw, and nothing
/// but `rng` and `weights` decides the outcome, so a fixed
/// `(rng state, items, n, weights)` always picks the same techniques in the
/// same order.
fn choose_distinct_weighted<'a>(
    rng: &mut RedGenomeRng,
    items: &[&'a TechniqueNode],
    n: usize,
    weights: &TechniqueWeights,
) -> Vec<&'a TechniqueNode> {
    let mut pool: Vec<&TechniqueNode> = items.to_vec();
    let mut out = Vec::new();
    let take = n.min(pool.len());
    for _ in 0..take {
        let scaled: Vec<u64> = pool
            .iter()
            .map(|node| scaled_weight(weights.weight_for(&node.id)))
            .collect();
        // Every scaled weight is >= 1 (see `scaled_weight`) and `pool` is
        // non-empty here (`take <= pool.len()` and the loop removes one
        // element per iteration), so `total` is always >= 1: `next_below`
        // never sees a zero bound.
        let total: u64 = scaled.iter().sum();
        let draw = rng.next_below(total);
        let mut cumulative = 0u64;
        let mut chosen = pool.len() - 1;
        for (index, weight) in scaled.iter().enumerate() {
            cumulative += weight;
            if draw < cumulative {
                chosen = index;
                break;
            }
        }
        out.push(pool.swap_remove(chosen));
    }
    out
}

/// Fixed-point scale a `[0.0, 1.0]` weight is mapped onto before it feeds
/// [`choose_distinct_weighted`]'s cumulative draw. Large enough that a `1.0`
/// vs `0.0` contrast is overwhelming, small enough to stay well inside `u64`
/// even summed over a large pool.
const WEIGHT_SCALE: f64 = 1_000_000.0;

/// Scale `weight` onto [`WEIGHT_SCALE`] and floor it at `1`, so a technique
/// this snapshot prices at `0.0` (always caught) is deprioritised rather than
/// starved outright -- it keeps a `1`-in-`WEIGHT_SCALE`-ish share of every
/// pick instead of becoming unreachable -- and so the pool's scaled total is
/// never zero.
///
/// `f64::clamp` alone is not enough: it leaves `NaN` untouched (clamp only
/// bounds an already-ordered value, and `NaN` has no order), so a `NaN`
/// `weight` would otherwise survive to the `scaled < 1.0` check below --
/// `false` under IEEE-754, since `NaN` compares `false` against everything
/// -- and fall through to `NaN as u64`, which saturates to `0` and silently
/// breaks the "every scaled weight is >= 1" invariant
/// [`choose_distinct_weighted`] relies on to keep its scaled total non-zero.
/// A non-finite `weight` -- `NaN` or either infinity escaping some future
/// caller's own domain check -- is therefore mapped to `0.0` first, the same
/// floor a `0.0` weight already gets and the same reading `scoring`'s
/// `normalize_catch_rate` gives a non-finite `catch_rate`: an untrusted
/// number is deprioritised, never propagated into a `NaN`/panic.
///
/// Unreachable today: every live `weight` is
/// [`super::weights::TechniqueWeights::weight_for`]'s return, itself always
/// [`super::pattern_db::AttackPatternDb::technique_success_rate`] or the
/// `1.0` neutral default -- both always finite in `[0.0, 1.0]`. This guards
/// the invariant at the draw itself (defense-in-depth), rather than assuming
/// every future weight source stays finite, and changes nothing for any
/// finite `weight`: `clamp` alone already handled `[0.0, 1.0]` and both
/// infinities correctly.
fn scaled_weight(weight: f64) -> u64 {
    let clamped = if weight.is_finite() {
        weight.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let scaled = (clamped * WEIGHT_SCALE).round();
    if scaled < 1.0 { 1 } else { scaled as u64 }
}

/// Choose up to `n` distinct techniques, taking from `preferred` first and then
/// filling from `all`. Used where a role wants to guarantee it exercises certain
/// techniques (its detector gaps) yet still fill the remaining budget broadly.
/// `weights` (see [`choose_distinct`]) applies to both the preferred draw and
/// the fill draw.
pub(super) fn choose_preferred_then_fill<'a>(
    rng: &mut RedGenomeRng,
    preferred: &[&'a TechniqueNode],
    all: &[&'a TechniqueNode],
    n: usize,
    weights: Option<&TechniqueWeights>,
) -> Vec<&'a TechniqueNode> {
    let mut out = choose_distinct(rng, preferred, n, weights);
    if out.len() < n {
        let rest: Vec<&TechniqueNode> = all
            .iter()
            .copied()
            .filter(|candidate| !out.iter().any(|picked| picked.id == candidate.id))
            .collect();
        out.extend(choose_distinct(rng, &rest, n - out.len(), weights));
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// A usable technique node with one single-event scenario, in
    /// `Discovery`, and no declared gaps -- enough for [`choose_distinct`]'s
    /// tests, which only ever look at a node's `id`.
    fn technique(id: &str) -> TechniqueNode {
        TechniqueNode {
            id: id.to_string(),
            threat_classes: BTreeSet::from([ThreatClass::Discovery]),
            scenarios: vec![ScenarioRef {
                suite: "s".to_string(),
                scenario: "s".to_string(),
                event_count: 1,
            }],
            declared_uncovered_by: Vec::new(),
        }
    }

    fn ids<'a>(nodes: &'a [&'a TechniqueNode]) -> Vec<&'a str> {
        nodes.iter().map(|node| node.id.as_str()).collect()
    }

    #[test]
    fn choose_distinct_with_none_matches_the_uniform_draw_byte_for_byte() {
        let pool_nodes: Vec<TechniqueNode> = (0..6).map(|i| technique(&format!("T{i}"))).collect();
        let pool: Vec<&TechniqueNode> = pool_nodes.iter().collect();

        for seed in 0..10u64 {
            let mut uniform_rng = RedGenomeRng::from_u64(seed);
            let uniform = choose_distinct_uniform(&mut uniform_rng, &pool, 3);

            let mut none_rng = RedGenomeRng::from_u64(seed);
            let via_none = choose_distinct(&mut none_rng, &pool, 3, None);

            assert_eq!(ids(&uniform), ids(&via_none), "seed {seed} diverged");
            assert_eq!(
                uniform_rng, none_rng,
                "seed {seed}: post-draw rng state diverged"
            );
        }
    }

    #[test]
    fn choose_distinct_favors_a_high_weight_technique_over_a_seed_sweep() {
        let pool_nodes: Vec<TechniqueNode> = (0..8).map(|i| technique(&format!("T{i}"))).collect();
        let pool: Vec<&TechniqueNode> = pool_nodes.iter().collect();
        let weight_pairs = (0..8).map(|i| (format!("T{i}"), if i == 0 { 1.0 } else { 0.0 }));
        let weights = TechniqueWeights::for_test(weight_pairs);

        const SEEDS: u64 = 200;
        let mut uniform_hits: u32 = 0;
        let mut weighted_hits: u32 = 0;
        for seed in 0..SEEDS {
            let mut rng = RedGenomeRng::from_u64(seed);
            if choose_distinct(&mut rng, &pool, 1, None)
                .first()
                .is_some_and(|node| node.id == "T0")
            {
                uniform_hits += 1;
            }

            let mut rng = RedGenomeRng::from_u64(seed);
            if choose_distinct(&mut rng, &pool, 1, Some(&weights))
                .first()
                .is_some_and(|node| node.id == "T0")
            {
                weighted_hits += 1;
            }
        }

        assert!(
            weighted_hits > uniform_hits * 2,
            "weighting toward T0 should measurably increase its pick rate: \
             uniform {uniform_hits}/{SEEDS}, weighted {weighted_hits}/{SEEDS}"
        );
    }

    #[test]
    fn choose_distinct_with_weights_is_deterministic_for_identical_inputs() {
        let pool_nodes: Vec<TechniqueNode> = (0..5).map(|i| technique(&format!("T{i}"))).collect();
        let pool: Vec<&TechniqueNode> = pool_nodes.iter().collect();
        let weights = TechniqueWeights::for_test([("T0", 0.9), ("T1", 0.1)]);

        let mut first_rng = RedGenomeRng::from_u64(77);
        let first = choose_distinct(&mut first_rng, &pool, 3, Some(&weights));
        let mut second_rng = RedGenomeRng::from_u64(77);
        let second = choose_distinct(&mut second_rng, &pool, 3, Some(&weights));

        assert_eq!(ids(&first), ids(&second));
    }

    /// T2a: a non-finite `weight` must floor to the exact same `1` a `0.0`
    /// weight already gets, never fall through to `NaN as u64`'s saturating
    /// `0`. Direct and deterministic, unlike the statistical sweep below --
    /// this pins the scaled number itself.
    #[test]
    fn scaled_weight_maps_every_non_finite_input_to_the_same_floor_as_zero() {
        let floor = scaled_weight(0.0);
        assert_eq!(
            floor, 1,
            "sanity: the documented floor for a 0.0 weight is 1"
        );
        assert_eq!(scaled_weight(f64::NAN), floor);
        assert_eq!(scaled_weight(f64::INFINITY), floor);
        assert_eq!(scaled_weight(f64::NEG_INFINITY), floor);
    }

    /// T2a: a `NaN` weight must not be silently starved out of the draw. Before
    /// [`scaled_weight`]'s finite guard, `scaled_weight(f64::NAN)` saturated to
    /// `0` (via `NaN as u64`) rather than the documented `1` floor, giving that
    /// technique a zero-width slot in [`choose_distinct_weighted`]'s cumulative
    /// draw -- mathematically unreachable, not merely deprioritised. With every
    /// other technique here floored to the same `1` (a `0.0` weight), a correct
    /// implementation picks the `NaN`-weighted one about a quarter of the time;
    /// getting zero hits over 200 seeds is a ~0.75^200 event, not a flake.
    #[test]
    fn a_non_finite_weight_keeps_its_technique_reachable_rather_than_starved() {
        let pool_nodes: Vec<TechniqueNode> = (0..4).map(|i| technique(&format!("T{i}"))).collect();
        let pool: Vec<&TechniqueNode> = pool_nodes.iter().collect();
        let weights =
            TechniqueWeights::for_test([("T0", f64::NAN), ("T1", 0.0), ("T2", 0.0), ("T3", 0.0)]);

        const SEEDS: u64 = 200;
        let mut nan_hits: u32 = 0;
        for seed in 0..SEEDS {
            let mut rng = RedGenomeRng::from_u64(seed);
            if choose_distinct(&mut rng, &pool, 1, Some(&weights))
                .first()
                .is_some_and(|node| node.id == "T0")
            {
                nan_hits += 1;
            }
        }

        assert!(
            nan_hits > 0,
            "T2a: a NaN weight must floor to the same reachable share a 0.0 \
             weight gets (here, one of four equally-floored techniques), never \
             starve its technique outright -- got 0 hits for T0 over {SEEDS} seeds"
        );
    }

    /// T2a, end to end: a non-finite weight anywhere in the pool must never
    /// panic or shrink the pick count, whatever finite weights sit alongside
    /// it (mixing in an ordinary weighted technique too, unlike the uniform
    /// floor above).
    #[test]
    fn choose_distinct_weighted_does_not_panic_when_a_pool_weight_is_non_finite() {
        let pool_nodes: Vec<TechniqueNode> = (0..4).map(|i| technique(&format!("T{i}"))).collect();
        let pool: Vec<&TechniqueNode> = pool_nodes.iter().collect();
        let weights = TechniqueWeights::for_test([
            ("T0", f64::NAN),
            ("T1", 0.5),
            ("T2", f64::INFINITY),
            ("T3", f64::NEG_INFINITY),
        ]);

        for seed in 0..20u64 {
            let mut rng = RedGenomeRng::from_u64(seed);
            let picked = choose_distinct(&mut rng, &pool, 2, Some(&weights));

            assert_eq!(
                picked.len(),
                2,
                "seed {seed}: a non-finite weight must not shrink the pick count"
            );
            let picked_ids: BTreeSet<&str> = picked.iter().map(|node| node.id.as_str()).collect();
            assert_eq!(
                picked_ids.len(),
                2,
                "seed {seed}: picks must stay distinct even with a non-finite weight in the pool"
            );
        }
    }
}
