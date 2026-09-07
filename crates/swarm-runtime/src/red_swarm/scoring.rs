//! Red-plan attack fitness scoring (ATKSCORE-01, SC 1).
//!
//! A red plan only earns its place in the population if it is worse for the
//! blue detectors than the plan it replaced. [`AttackScorer`] is the pure
//! function that turns a [`RedPlan`] and a measured detector coverage
//! snapshot into that judgement: how much of the plan's technique surface
//! the current detectors would have missed, scaled by how quietly the plan
//! got there. Scoring has no opinion about how "quietly" is computed --
//! `stealth` is a caller-supplied factor a later budget task derives from the
//! plan's shape (host reuse, timing, event volume). This module does not know
//! that type exists yet; it only multiplies by whatever `f64` it is handed.
//!
//! Scoring reads a [`crate::evasion_coverage::EvasionCoverageSnapshot`], and
//! never recomputes one: the snapshot is blue's already-measured truth, and
//! red is not allowed to grade its own homework by re-running detectors
//! itself. A technique the snapshot has no record of is not a scoring error
//! -- it is exactly the case red is hunting for, so it counts as a clean miss
//! (catch `0.0`), never a panic or a skipped step.
//!
//! Nothing here can reach response authority: this module reads a plan and a
//! snapshot and returns numbers, with no adapter, no broadcaster, and no path
//! to `swarm_response`.

use super::genome::RedPlan;
use crate::evasion_coverage::EvasionCoverageSnapshot;
use serde::Serialize;

/// The fitness of one red plan against one measured detector snapshot.
///
/// `evasion_rate` is meaningful on its own -- it is "how much of this plan's
/// technique surface would the detectors have missed", independent of any
/// budget model -- so a caller that only cares about detector coverage (a
/// regression check against a fixed plan, say) can read it without also
/// carrying a stealth score. `red_fitness` is what a red genome is actually
/// selected on.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AttackFitness {
    /// `1.0 -` the plan's mean per-technique catch rate: the share of the
    /// plan's technique surface the current detectors did not catch.
    pub evasion_rate: f64,
    /// The budget-supplied quietness factor this score was computed with,
    /// carried alongside the result so a reader never has to guess which
    /// budget produced it. This module treats it as an opaque multiplier.
    pub stealth: f64,
    /// `evasion_rate * stealth` -- the score a red genome is actually
    /// selected on. A plan the detectors fully caught scores `0.0` here
    /// regardless of how quiet it was; a plan the detectors never touch is
    /// bounded only by its stealth.
    pub red_fitness: f64,
}

/// Scores [`RedPlan`]s against a detector coverage snapshot (SC 1).
///
/// Stateless by design: like [`super::RedGenome`], it is a namespace for a
/// pure function, not a thing with its own history. Two calls on the same
/// arguments return bit-identical results -- no wall clock, no entropy, no
/// hidden dependency on call order -- so a fitness regression can always be
/// pinned on the plan or the snapshot, never on the scorer.
#[derive(Debug, Clone, Copy, Default)]
pub struct AttackScorer;

impl AttackScorer {
    /// Scores `plan` against `coverage`, weighted by the caller-supplied
    /// `stealth` factor.
    ///
    /// For each step, the technique's catch rate is the **max** `catch_rate`
    /// over every detector/scenario pairing in `coverage` whose `techniques`
    /// names it: a technique is caught if *any* detector catches a scenario
    /// that realises it, so one strong detector is enough to call it covered.
    /// A technique `coverage` has no record of at all catches nothing
    /// (`0.0`) rather than erroring -- an uncovered technique is the exact
    /// condition this scorer exists to surface, not a malformed input.
    ///
    /// `evasion_rate` is `1.0` minus the mean of that per-step catch rate
    /// across `plan.steps`. A plan with no steps has no technique surface to
    /// have missed, so it is defined as fully evasive (`evasion_rate ==
    /// 1.0`) rather than left undefined by a `0.0 / 0` -- an empty plan is
    /// the degenerate case of "the detectors caught none of it", not a
    /// special error.
    pub fn score(
        &self,
        plan: &RedPlan,
        coverage: &EvasionCoverageSnapshot,
        stealth: f64,
    ) -> AttackFitness {
        let evasion_rate = 1.0 - mean_technique_catch_rate(plan, coverage);
        AttackFitness {
            evasion_rate,
            stealth,
            red_fitness: evasion_rate * stealth,
        }
    }

    /// [`Self::score`] with `stealth` fixed at `1.0`, for callers with no
    /// budget model yet -- SC 1's fixtures, or any later caller that only
    /// wants detector-coverage fitness. `red_fitness == evasion_rate` at this
    /// `stealth`.
    pub fn score_unbudgeted(
        &self,
        plan: &RedPlan,
        coverage: &EvasionCoverageSnapshot,
    ) -> AttackFitness {
        self.score(plan, coverage, 1.0)
    }
}

/// The plan's mean per-technique catch rate, or `0.0` for a plan with no
/// steps (see [`AttackScorer::score`]'s doc for why that boundary is `0.0`
/// catch / `1.0` evasion rather than an error).
fn mean_technique_catch_rate(plan: &RedPlan, coverage: &EvasionCoverageSnapshot) -> f64 {
    if plan.steps.is_empty() {
        return 0.0;
    }
    let total: f64 = plan
        .steps
        .iter()
        .map(|step| technique_catch_rate(coverage, &step.technique))
        .sum();
    total / plan.steps.len() as f64
}

/// The catch rate `coverage` records for `technique`: the max `catch_rate`
/// over every scenario, under every detector, whose `techniques` list names
/// it.
///
/// `coverage` carries no top-level technique index -- each
/// [`crate::evasion_coverage::DetectorEvasionCoverageReport`] only carries its
/// own per-scenario breakdown -- so this walks all of them rather than
/// assuming a shortcut the type does not offer. `fold`'s `0.0` identity
/// element is also the answer for a technique no scenario names: uncovered,
/// not missing data. Each scenario's raw `catch_rate` is normalized (see
/// [`normalize_catch_rate`]) before the fold, so a malformed snapshot can
/// never carry an out-of-range or non-finite rate into the max.
fn technique_catch_rate(coverage: &EvasionCoverageSnapshot, technique: &str) -> f64 {
    coverage
        .detectors
        .iter()
        .flat_map(|detector| detector.scenarios.iter())
        .filter(|scenario| scenario.techniques.iter().any(|named| named == technique))
        .map(|scenario| normalize_catch_rate(scenario.catch_rate))
        .fold(0.0_f64, f64::max)
}

/// Normalizes a scenario's raw `catch_rate` into the `[0.0, 1.0]` domain
/// every caller of [`technique_catch_rate`] assumes.
///
/// `f64::clamp` alone is not enough: it leaves `NaN` untouched (clamp only
/// bounds an already-ordered value, and `NaN` has no order), so a `NaN`
/// `catch_rate` would otherwise survive the fold and poison `evasion_rate`
/// and `red_fitness` into `NaN` too. A non-finite rate -- `NaN` or either
/// infinity -- is therefore mapped to `0.0` first: an unmeasurable scenario
/// caught nothing we can trust, the same reading this module already gives
/// a technique `coverage` has no record of at all. A finite rate outside
/// `[0.0, 1.0]` (a `catch_rate` above `1.0`, say) is a plain out-of-range
/// value once that guard is past, so `f64::clamp` alone is sufficient for
/// it.
///
/// Unreachable today: the `--coverage` deserializer this snapshot's data
/// arrives through already rejects non-finite JSON numbers, so no live
/// input can trigger the `NaN`/infinity branch. This guards the domain
/// invariant at the scorer itself rather than assuming every future caller
/// -- Phase 290's in-process snapshots included -- routes through that same
/// deserializer.
fn normalize_catch_rate(catch_rate: f64) -> f64 {
    if catch_rate.is_finite() {
        catch_rate.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::super::genome::{Determinism, GeneStep, OperatorRole, StepIntent};
    use super::super::graph::ScenarioRef;
    use super::*;
    use crate::evasion_coverage::{DetectorEvasionCoverageReport, EvasionScenarioCoverage};
    use swarm_core::pheromone::ThreatClass;

    /// One detector's report of one scenario that realises `technique` at
    /// `catch_rate`. Tests compose several of these under one or more
    /// detectors to build a snapshot by hand -- SC 1's fixtures must not
    /// depend on the live corpus for exact numbers.
    fn scenario_report(technique: &str, catch_rate: f64) -> EvasionScenarioCoverage {
        let detected_payloads = if catch_rate > 0.0 { 1 } else { 0 };
        EvasionScenarioCoverage {
            scenario_name: format!("{technique}_scenario"),
            threat_class: ThreatClass::Execution,
            total_payloads: 1,
            detected_payloads,
            catch_rate,
            techniques: vec![technique.to_string()],
        }
    }

    /// A snapshot with a single synthetic detector reporting one scenario
    /// per `(technique, catch_rate)` pair. A technique not named here is
    /// absent from the snapshot entirely -- that is how a test builds the
    /// "uncovered" case: no report at all, not a zeroed-out entry.
    fn snapshot(entries: &[(&str, f64)]) -> EvasionCoverageSnapshot {
        let scenarios: Vec<EvasionScenarioCoverage> = entries
            .iter()
            .map(|(technique, catch_rate)| scenario_report(technique, *catch_rate))
            .collect();
        let total_payloads = scenarios.len();
        let detected_payloads = scenarios
            .iter()
            .filter(|entry| entry.catch_rate > 0.0)
            .count();
        EvasionCoverageSnapshot {
            generated_at_ms: 0,
            suite_name: "test-suite".to_string(),
            suite_path: "scenario-suites/test-suite.yaml".to_string(),
            corpus_version: "test".to_string(),
            detectors: vec![DetectorEvasionCoverageReport {
                detector: "test_detector".to_string(),
                total_payloads,
                detected_payloads,
                catch_rate: if total_payloads == 0 {
                    0.0
                } else {
                    detected_payloads as f64 / total_payloads as f64
                },
                threat_classes: Vec::new(),
                scenarios,
                intentionally_uncovered: Vec::new(),
            }],
        }
    }

    /// A plan with one step per entry in `techniques`, in order. The scorer
    /// only reads `step.technique`, so every other `GeneStep` field is a
    /// fixed, otherwise-arbitrary placeholder.
    fn plan_for(techniques: &[&str]) -> RedPlan {
        let steps = techniques
            .iter()
            .enumerate()
            .map(|(index, technique)| GeneStep {
                operator: OperatorRole::Recon,
                technique: technique.to_string(),
                threat_class: ThreatClass::Execution,
                scenario: ScenarioRef {
                    suite: "test-suite".to_string(),
                    scenario: format!("{technique}_scenario"),
                    event_count: 1,
                },
                event_indices: vec![0],
                host_slot: 0,
                offset_ms: index as i64 * 1_000,
                intent: StepIntent::Probe,
            })
            .collect();
        RedPlan {
            generation: 0,
            campaign: "test-campaign".to_string(),
            graph_fingerprint: [0u8; 32],
            steps,
            determinism: Determinism {
                rng_seed: 0,
                virtual_clock_start_ms: 0,
                scheduler: "round_robin_v1",
            },
        }
    }

    #[test]
    fn a_fully_detected_plan_scores_zero_red_fitness() {
        let plan = plan_for(&["T1055", "T1059.001"]);
        let coverage = snapshot(&[("T1055", 1.0), ("T1059.001", 1.0)]);

        let fitness = AttackScorer.score_unbudgeted(&plan, &coverage);

        assert_eq!(fitness.evasion_rate, 0.0);
        assert_eq!(fitness.red_fitness, 0.0);
    }

    #[test]
    fn a_fully_uncovered_plan_scores_red_fitness_above_one_half() {
        // Neither technique has any report in `coverage` -- the
        // declared-uncovered case, not a `catch_rate: 0.0` entry.
        let plan = plan_for(&["T1055", "T1059.001"]);
        let coverage = snapshot(&[]);

        let fitness = AttackScorer.score_unbudgeted(&plan, &coverage);

        assert_eq!(fitness.evasion_rate, 1.0);
        assert_eq!(fitness.stealth, 1.0);
        assert!(fitness.red_fitness > 0.5);
        assert_eq!(fitness.red_fitness, 1.0);
    }

    #[test]
    fn a_mixed_plan_scores_strictly_between_caught_and_uncovered() {
        // One technique fully caught, three with no report at all: mean
        // catch rate is 1.0 / 4 == 0.25, exactly representable so the
        // assertion below needs no epsilon.
        let plan = plan_for(&["T1055", "T1059.001", "T1071", "T1021"]);
        let coverage = snapshot(&[("T1055", 1.0)]);

        let fitness = AttackScorer.score_unbudgeted(&plan, &coverage);

        assert_eq!(fitness.evasion_rate, 0.75);
        assert!(fitness.red_fitness > 0.0);
        assert!(fitness.red_fitness < 1.0);
    }

    #[test]
    fn red_fitness_scales_linearly_with_stealth() {
        let plan = plan_for(&["T1055", "T1059.001", "T1071", "T1021"]);
        let coverage = snapshot(&[("T1055", 1.0)]);
        let scorer = AttackScorer;

        let full_stealth = scorer.score(&plan, &coverage, 1.0);
        let half_stealth = scorer.score(&plan, &coverage, 0.5);

        assert_eq!(half_stealth.red_fitness, full_stealth.red_fitness / 2.0);
    }

    #[test]
    fn score_is_deterministic_for_identical_inputs() {
        let plan = plan_for(&["T1055", "T1059.001"]);
        let coverage = snapshot(&[("T1055", 0.6), ("T1059.001", 0.0)]);
        let scorer = AttackScorer;

        let first = scorer.score(&plan, &coverage, 0.8);
        let second = scorer.score(&plan, &coverage, 0.8);

        assert_eq!(first, second);
    }

    #[test]
    fn a_technique_caught_by_any_detector_uses_the_best_catch_rate() {
        // Two detectors both report a scenario for the same technique; the
        // weaker one must not drag the technique's catch rate down -- a
        // technique is caught if any mapped detector catches it.
        let mut coverage = snapshot(&[("T1055", 0.2)]);
        coverage.detectors.push(DetectorEvasionCoverageReport {
            detector: "second_detector".to_string(),
            total_payloads: 1,
            detected_payloads: 1,
            catch_rate: 1.0,
            threat_classes: Vec::new(),
            scenarios: vec![scenario_report("T1055", 1.0)],
            intentionally_uncovered: Vec::new(),
        });
        let plan = plan_for(&["T1055"]);

        let fitness = AttackScorer.score_unbudgeted(&plan, &coverage);

        assert_eq!(fitness.evasion_rate, 0.0);
    }

    #[test]
    fn a_plan_with_no_steps_is_fully_evasive() {
        let plan = plan_for(&[]);
        let coverage = snapshot(&[("T1055", 1.0)]);

        let fitness = AttackScorer.score_unbudgeted(&plan, &coverage);

        assert_eq!(fitness.evasion_rate, 1.0);
        assert_eq!(fitness.red_fitness, 1.0);
    }

    #[test]
    fn a_scenario_with_an_infinite_catch_rate_scores_a_finite_red_fitness() {
        // `f64::clamp` alone does not defuse a non-finite value's poisoning
        // reach for `NaN` -- and this pins that an out-of-domain infinity is
        // also normalized away, not merely clamped to `1.0` as "fully
        // caught" would be.
        let plan = plan_for(&["T1055", "T1059.001"]);
        let coverage = snapshot(&[("T1055", f64::INFINITY)]);

        let fitness = AttackScorer.score_unbudgeted(&plan, &coverage);

        assert!(fitness.evasion_rate.is_finite());
        assert!(fitness.red_fitness.is_finite());
        assert_eq!(
            fitness.evasion_rate, 1.0,
            "an unmeasurable catch_rate must not be trusted as a catch"
        );
        assert_eq!(fitness.red_fitness, 1.0);
    }

    #[test]
    fn a_scenario_with_a_nan_catch_rate_scores_a_finite_red_fitness() {
        let plan = plan_for(&["T1055", "T1059.001"]);
        let coverage = snapshot(&[("T1055", f64::NAN)]);

        let fitness = AttackScorer.score_unbudgeted(&plan, &coverage);

        assert!(fitness.evasion_rate.is_finite());
        assert!(fitness.red_fitness.is_finite());
        assert_eq!(
            fitness.evasion_rate, 1.0,
            "an unmeasurable catch_rate must not be trusted as a catch"
        );
        assert_eq!(fitness.red_fitness, 1.0);
    }
}
