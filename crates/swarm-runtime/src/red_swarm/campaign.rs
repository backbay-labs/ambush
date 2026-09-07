//! One generation's measured run (Phase 290, COEVOLVE-01 part A "one
//! generation"): plan (weighted) -> materialize -> run the real detectors ->
//! per-technique catch -> red fitness + blue catch rate + pattern records.
//!
//! [`run_generation`] is the single-generation primitive the campaign loop
//! (Task 3) repeats: it is a pure function of its arguments -- no clock, no
//! entropy, no I/O beyond re-reading the same tracked corpus files
//! [`super::genome_adapter::GenomeRedSwarm`] already re-reads on every call
//! -- so two calls with identical arguments produce a byte-identical
//! [`GenerationOutcome`] (see this module's tests).
//!
//! # Pipeline
//!
//!   1. **plan** -- [`RedGenome::plan_weighted`] against `seed`, `generation`,
//!      `campaign` and `graph`, optionally biased by `weights`;
//!   2. **budget** -- `budget.apply` bounds the plan to its emitted steps and
//!      binds their host slots (ATKSCORE-02);
//!   3. **materialize** -- [`GenomeRedSwarm::materialize_by_step`]
//!      re-plans and re-budgets identically (see "Why the plan is drawn
//!      twice" below) and re-stamps the emitted steps into real corpus
//!      events, grouped by step and tagged with each step's technique;
//!   4. **detect** -- every enabled `detection.strategies` entry is built
//!      into a real [`RuntimeDetector`] and run over every emitted step's
//!      events, in plan order, on the SAME detector instance across steps
//!      (mirrors [`crate::evasion_coverage::evaluate_evasion_coverage`]'s own
//!      one-detector-instance-per-corpus discipline, so a stateful detector
//!      sees the whole generation's corpus as one sequence, not one fresh
//!      instance per step);
//!   5. **score** -- the live catches are assembled into a minimal
//!      [`EvasionCoverageSnapshot`] and handed to [`AttackScorer::score`]
//!      (289's scorer, reused verbatim -- this module does not reimplement
//!      fitness scoring).
//!
//! # Attribution
//!
//! A [`swarm_whisker::TelemetryEvent`] carries no technique field, so mapping
//! a detector finding back to the technique that produced it requires the
//! step-to-technique grouping [`GenomeRedSwarm::materialize_by_step`]
//! preserves (see that method's doc) -- this module never reconstructs that
//! grouping by slicing a flattened, re-sorted artifact.
//!
//! # Granularity: distinct technique, not distinct step
//!
//! A technique may be emitted by more than one admitted step (a repeat
//! [`super::budget::StealthBudget`] allows, or a
//! [`super::genome::StepIntent::Cover`] step -- see "Cover steps are
//! excluded from attribution" below). This module attributes catches at the
//! DISTINCT-TECHNIQUE granularity, not once per step: a `(technique,
//! detector)` pair is `detected` if *any* (non-Cover) step naming that
//! technique drew a finding from that detector on *any* of its events. One
//! [`AttackPatternRecord`] is produced per distinct `(technique, detector)`
//! pair evaluated -- never one per `(step, detector)` -- which is also
//! exactly what the assembled [`EvasionCoverageSnapshot`] needs, since
//! [`AttackScorer::score`]'s per-technique catch rate is already a max over
//! every scenario naming a technique, so a step-level and a technique-level
//! assembly agree there regardless.
//!
//! # Cover steps are excluded from attribution
//!
//! [`super::operators::OpsecOperator`] deliberately builds a `Cover` step
//! that keeps its *covered* exploit step's `technique` string (so the plan
//! still resolves against the graph -- OPFOR-04) but replays a **benign**
//! control scenario's events, unrelated to that technique's actual attack
//! realization. If a Cover step's benign events were allowed to feed the
//! same `hits` entry as the technique's real attack step, a detector that
//! merely fires on the cover material -- a false positive, or a heuristic
//! that matches generically on borderline-benign activity -- would flip that
//! technique from evaded to detected without blue ever having caught the
//! attack itself; because the merge is OR-only, this can only ever inflate
//! the catch signal, never deflate it. [`attribute_catches`] therefore skips
//! every [`super::genome::StepIntent::Cover`] step entirely: its events are
//! never fed to a detector for attribution purposes (though they are still
//! part of the materialized corpus [`GenomeRedSwarm::materialize_by_step`]
//! returns -- blue still runs its detectors over them, this module simply
//! does not let the result count toward the technique's catch bit). A
//! technique is never lost by this exclusion: `genome.rs`'s private
//! `resolve_back_references` anchors every `Cover{step}` reference to an
//! earlier, already-final step, so a Cover step survives
//! [`super::budget::StealthBudget`]'s contiguous-prefix truncation only if
//! the step it covers -- appearing earlier in final order -- survived too;
//! the covered step alone already supplies the technique to
//! `emitted_techniques`/`hits`.
//!
//! This exclusion is scoped to *attribution* only. [`AttackScorer::score`]
//! itself is untouched and keeps reading every `emitted_plan.steps` entry's
//! `technique` uniformly, Cover included -- `emitted_plan` (fed to the
//! scorer) is built from `outcome.steps` unfiltered, exactly as before this
//! fix. Only the separate `hits`/`emitted_techniques` bookkeeping this
//! module derives for `blue_catch_rate`, `evaded_techniques`, and `records`
//! now skips Cover steps.
//!
//! # Catch criterion
//!
//! A step is caught by a detector iff that detector's
//! [`swarm_whisker::DetectionStrategy::evaluate`] returns *any* finding on
//! *any* of the step's events -- no threat-class filter, unlike
//! [`crate::evasion_coverage::evaluate_evasion_coverage`]'s stricter
//! same-threat-class match. This mirrors this task's brief exactly; a
//! future task that wants the stricter criterion should thread it through
//! explicitly rather than have this module guess at it.
//!
//! # Why the plan is drawn twice
//!
//! [`run_generation`] calls [`RedGenome::plan_weighted`] and `budget.apply`
//! directly (for [`super::budget::BudgetOutcome::stealth`] and to build the
//! emitted [`RedPlan`] [`AttackScorer::score`] reads), and separately
//! constructs a [`GenomeRedSwarm`] and calls
//! [`GenomeRedSwarm::materialize_by_step`] (which re-derives the identical
//! plan and budget internally) for the grouped events. Both calls share the
//! same `(seed, generation, campaign, graph, budget, weights)`, and every
//! step of that pipeline is a pure function of exactly those arguments (SC 2
//! / SC 4), so the two computations are guaranteed byte-identical -- this
//! module's own determinism and attribution tests pin that guarantee rather
//! than merely asserting it in prose. The alternative (widening
//! [`GenomeRedSwarm`]'s public surface to hand back its intermediate
//! [`super::budget::BudgetOutcome`]) was rejected to keep that struct's
//! contract exactly the one this task's brief sketched; a max-24-step
//! re-plan costs nothing worth trading that contract away for.
//!
//! # A parameter beyond this task's brief: `suite_paths`
//!
//! The brief's sketch of [`run_generation`] omits a `suite_paths` argument,
//! but [`GenomeRedSwarm`] cannot materialize without one -- a [`TargetGraph`]
//! keeps only lightweight [`super::graph::ScenarioRef`]s, never the events
//! themselves (see [`GenomeRedSwarm`]'s module doc's "Why `suite_paths` is a
//! field" section) -- so this module adds the parameter rather than ship an
//! unimplementable signature. Task 3's campaign loop needs to thread the
//! same paths it used to build `graph` through unchanged on every call.
//!
//! # Empty-corpus convention
//!
//! A generation that emits no techniques at all (an exhausted budget, or a
//! campaign/graph pairing with nothing to plan) has nothing for a detector to
//! have caught: [`GenerationOutcome::blue_catch_rate`] is defined as `0.0`
//! in that case -- "an empty corpus catches nothing" -- rather than the `1.0`
//! [`AttackScorer::score`] would separately assign such a plan's
//! `evasion_rate` (an empty plan has no technique surface to have missed,
//! which is a different question). The two numbers disagreeing at this one
//! boundary is intentional, not a bug: one reports what blue caught, the
//! other what red evaded, and a vacuous corpus is a vacuous "catch nothing"
//! by the first reading and a vacuous "evade everything" by the second.

use super::RedSwarmError;
use super::ThreatContext;
use super::budget::StealthBudget;
use super::genome::{CampaignParams, GeneStep, RedGenome, RedPlan, StepIntent};
use super::genome_adapter::GenomeRedSwarm;
use super::graph::TargetGraph;
use super::pattern_db::AttackPatternRecord;
use super::scoring::{AttackFitness, AttackScorer};
use super::weights::TechniqueWeights;
use crate::detector_factory::{RuntimeDetector, build_detector_from_strategy};
use crate::evasion_coverage::{
    DetectorEvasionCoverageReport, EvasionCoverageSnapshot, EvasionScenarioCoverage,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use swarm_core::config::DetectionConfig;
use swarm_core::pheromone::ThreatClass;
use swarm_whisker::{DetectionStrategy, TelemetryEvent};

/// The measured result of running exactly one generation's red/blue round
/// (see the module doc for the full pipeline).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct GenerationOutcome {
    /// The generation this outcome was measured for, echoing the caller's
    /// own argument (never re-derived from anything else).
    pub generation: u32,
    /// Red's fitness against the live catches this run measured -- 289's
    /// [`AttackScorer::score`], reused verbatim.
    pub red_fitness: AttackFitness,
    /// The share of this generation's distinct emitted techniques that at
    /// least one enabled detector caught, in `[0.0, 1.0]`. `0.0` for a
    /// generation that emitted no techniques at all (see the module doc's
    /// "Empty-corpus convention" section).
    pub blue_catch_rate: f64,
    /// One [`AttackPatternRecord`] per distinct `(technique, detector)` pair
    /// this run evaluated (see the module doc's "Granularity" section) --
    /// ready to append to an [`super::pattern_db::AttackPatternDb`].
    pub records: Vec<AttackPatternRecord>,
    /// The distinct emitted techniques no enabled detector caught, sorted.
    /// Exactly the emitted techniques absent from every caught set --
    /// disjoint from, and complementary to, the caught techniques
    /// [`Self::records`] and [`Self::blue_catch_rate`] were built from.
    pub evaded_techniques: Vec<String>,
}

/// Runs one generation's measured red/blue round (see the module doc).
///
/// `suite_paths` MUST be the paths `graph` was built from -- the same
/// requirement [`GenomeRedSwarm::new`] documents -- since this function
/// materializes through that adapter; a mismatch surfaces as
/// [`RedSwarmError::UnresolvedScenario`], never a panic. Pure and
/// deterministic in every other argument: identical `(generation, seed,
/// campaign, graph, suite_paths' file contents, detection, budget, weights)`
/// always produces a byte-identical [`GenerationOutcome`] (SC 2 / SC 4).
///
/// Eight arguments -- one over clippy's default lint threshold -- because
/// this keeps the flat, positional shape the task brief sketched (seven
/// arguments) plus exactly the one necessary addition, `suite_paths` (see
/// the module doc's "A parameter beyond this task's brief" section), rather
/// than introducing a parameter-bundling struct the brief never asked for.
#[allow(clippy::too_many_arguments)]
pub fn run_generation(
    generation: u32,
    seed: u64,
    campaign: &CampaignParams,
    graph: &TargetGraph,
    suite_paths: &[PathBuf],
    detection: &DetectionConfig,
    budget: &StealthBudget,
    weights: Option<&TechniqueWeights>,
) -> Result<GenerationOutcome, RedSwarmError> {
    // 1. Plan (weighted) and budget, directly: `AttackScorer::score` needs
    //    the emitted `RedPlan` and `budget_outcome.stealth`, neither of which
    //    `GenomeRedSwarm`'s own materialization exposes (see the module
    //    doc's "Why the plan is drawn twice" section).
    let plan = RedGenome::plan_weighted(seed, generation, campaign, graph, weights)?;
    let RedPlan {
        campaign: plan_campaign,
        graph_fingerprint,
        steps,
        determinism,
        ..
    } = plan;
    let outcome = budget.apply(steps);
    let emitted_plan = RedPlan {
        generation,
        campaign: plan_campaign,
        graph_fingerprint,
        steps: outcome.steps,
        determinism,
    };
    let threat_class_by_technique = threat_classes_by_technique(&emitted_plan.steps);

    // 2. Materialize the same emitted steps, grouped by step/technique,
    //    through `GenomeRedSwarm` -- never re-deriving its re-stamping logic
    //    here (see `GenomeRedSwarm::materialize_by_step`'s doc).
    let mut genome = GenomeRedSwarm::new(
        graph.clone(),
        suite_paths.to_vec(),
        campaign.clone(),
        seed,
        generation,
        *budget,
    );
    if let Some(weights) = weights {
        genome = genome.with_weights(weights.clone());
    }
    let grouped = genome.materialize_by_step(&measurement_context(generation))?;

    // 3. Build every enabled detector for real. NOTE: if `detection.strategies`
    //    ever names the same strategy id twice, the two `RuntimeDetector`
    //    instances share one `id()` and therefore one `hits` key below --
    //    the second silently collapses into the first rather than doubling
    //    up. No caller in this crate constructs a `DetectionConfig` that
    //    way today.
    let detectors: Vec<RuntimeDetector> = detection
        .strategies
        .iter()
        .map(|strategy_id| build_detector_from_strategy(strategy_id, detection))
        .collect::<Result<_, _>>()?;

    // 4. Attribute catches to distinct techniques, excluding Cover steps
    //    (see the module doc's "Cover steps are excluded from attribution"
    //    section).
    let (hits, emitted_techniques) = attribute_catches(&emitted_plan.steps, &grouped, &detectors);

    // 5. Blue catch rate, the evaded set, and one `AttackPatternRecord` per
    //    distinct `(technique, detector)` pair (see the module doc's
    //    "Empty-corpus convention" and "Granularity" sections).
    let (blue_catch_rate, evaded_techniques, records) =
        summarize_catches(generation, &hits, &emitted_techniques);

    // 6. Assemble a minimal `EvasionCoverageSnapshot` from the same live
    //    catches and score with 289's scorer, verbatim.
    let snapshot = build_snapshot(
        generation,
        campaign,
        graph,
        &detectors,
        &emitted_techniques,
        &threat_class_by_technique,
        &hits,
    );
    let red_fitness = AttackScorer.score(&emitted_plan, &snapshot, outcome.stealth);

    Ok(GenerationOutcome {
        generation,
        red_fitness,
        blue_catch_rate,
        records,
        evaded_techniques,
    })
}

/// A fixed, deterministic [`ThreatContext`] used only to satisfy
/// [`GenomeRedSwarm::materialize_by_step`]'s validation gate
/// ([`super::validate_context`]). None of its fields reach the returned
/// grouping: [`GenomeRedSwarm`]'s materialized events depend only on
/// `(seed, generation, campaign, graph, budget, weights, suite_paths' file
/// contents)` (see that struct's module doc's "Determinism" section), never
/// on `context` -- so a fixed placeholder here costs `run_generation`
/// nothing on determinism (no clock, no entropy) while still satisfying the
/// shared [`GenomeRedSwarm`] contract.
fn measurement_context(generation: u32) -> ThreatContext {
    ThreatContext::new(
        PathBuf::new(),
        1,
        format!("run-generation-gen-{generation}"),
    )
}

/// Attributes detector catches to distinct emitted techniques (see the
/// module doc's "Granularity" section), skipping every
/// [`StepIntent::Cover`] step (see "Cover steps are excluded from
/// attribution").
///
/// `steps` and `grouped` MUST be the same plan's emitted steps, in the same
/// order -- `run_generation` passes `&emitted_plan.steps` (from its own
/// direct `plan_weighted` + `budget.apply` call) alongside `grouped` (from
/// [`GenomeRedSwarm::materialize_by_step`]'s independent re-derivation of
/// the identical plan and budget); see the module doc's "Why the plan is
/// drawn twice" section for why the two are guaranteed to agree, index for
/// index, on both length and technique.
///
/// Returns the `(technique, detector id)` -> detected map (deduplicated by
/// construction, one entry per distinct pair evaluated) and the set of
/// distinct non-Cover emitted techniques.
fn attribute_catches(
    steps: &[GeneStep],
    grouped: &[(String, Vec<TelemetryEvent>)],
    detectors: &[RuntimeDetector],
) -> (BTreeMap<(String, String), bool>, BTreeSet<String>) {
    let mut hits: BTreeMap<(String, String), bool> = BTreeMap::new();
    let mut emitted_techniques: BTreeSet<String> = BTreeSet::new();
    for (step, (technique, events)) in steps.iter().zip(grouped.iter()) {
        if matches!(step.intent, StepIntent::Cover { .. }) {
            continue;
        }
        emitted_techniques.insert(technique.clone());
        for detector in detectors {
            // `fold`, deliberately not the `any` clippy suggests: `any`
            // short-circuits on the first hit, which would skip feeding a
            // caught step's later events to a stateful detector (e.g.
            // `behavioral_anomaly`, which updates an internal baseline on
            // every call) -- matching `evaluate_evasion_coverage`'s own
            // unconditional per-event walk rather than starving the
            // detector's state of events later steps' catches could depend
            // on.
            #[allow(clippy::unnecessary_fold)]
            let caught = events.iter().fold(false, |any_hit, event| {
                any_hit || !detector.evaluate(event).is_empty()
            });
            let entry = hits
                .entry((technique.clone(), detector.id().to_string()))
                .or_insert(false);
            *entry = *entry || caught;
        }
    }
    (hits, emitted_techniques)
}

/// Derives `blue_catch_rate`, `evaded_techniques`, and `records` from
/// [`attribute_catches`]'s output. Pure and total: an empty
/// `emitted_techniques` (the module doc's "Empty-corpus convention") yields
/// `blue_catch_rate: 0.0`, no records, and no evaded techniques.
///
/// Returns `(blue_catch_rate, evaded_techniques, records)`.
fn summarize_catches(
    generation: u32,
    hits: &BTreeMap<(String, String), bool>,
    emitted_techniques: &BTreeSet<String>,
) -> (f64, Vec<String>, Vec<AttackPatternRecord>) {
    let caught_techniques: BTreeSet<String> = hits
        .iter()
        .filter(|(_, detected)| **detected)
        .map(|((technique, _), _)| technique.clone())
        .collect();
    let blue_catch_rate = if emitted_techniques.is_empty() {
        0.0
    } else {
        caught_techniques.len() as f64 / emitted_techniques.len() as f64
    };
    // `BTreeSet::difference` iterates in sorted order, so `evaded_techniques`
    // is already sorted -- no further ordering pass needed to stay
    // deterministic.
    let evaded_techniques: Vec<String> = emitted_techniques
        .difference(&caught_techniques)
        .cloned()
        .collect();

    // One `AttackPatternRecord` per distinct `(technique, detector)` pair
    // evaluated. `hits` iterates in key order, so `records` is already
    // sorted too.
    let records: Vec<AttackPatternRecord> = hits
        .iter()
        .map(|((technique, detector), detected)| AttackPatternRecord {
            generation,
            technique: technique.clone(),
            detector: detector.clone(),
            detected: *detected,
        })
        .collect();

    (blue_catch_rate, evaded_techniques, records)
}

/// The first-seen threat class per technique, read off the emitted steps
/// themselves. Used only to fill [`EvasionScenarioCoverage::threat_class`]
/// for readability -- [`AttackScorer::score`] never reads that field (only
/// `techniques` and `catch_rate`), so this has no effect on `red_fitness`.
fn threat_classes_by_technique(steps: &[GeneStep]) -> BTreeMap<String, ThreatClass> {
    let mut by_technique = BTreeMap::new();
    for step in steps {
        by_technique
            .entry(step.technique.clone())
            .or_insert_with(|| step.threat_class.clone());
    }
    by_technique
}

/// Assembles a minimal [`EvasionCoverageSnapshot`] from this run's live
/// catches: one [`DetectorEvasionCoverageReport`] per enabled detector, each
/// naming every distinct emitted technique at `catch_rate 1.0` if that
/// detector caught it this generation, `0.0` if not. [`AttackScorer::score`]
/// takes the max `catch_rate` across every detector/scenario pairing that
/// names a technique, so one row per `(detector, distinct technique)` -- as
/// opposed to one row per `(detector, step)` -- computes the identical
/// per-technique catch rate either way; this assembly uses the simpler,
/// already-deduplicated form.
///
/// The snapshot's own top-level metadata (`generated_at_ms`, `suite_name`,
/// `suite_path`, `corpus_version`) and each report's roll-up fields
/// (`total_payloads`, `detected_payloads`, `catch_rate`, `threat_classes`,
/// `intentionally_uncovered`) are informational only -- `AttackScorer::score`
/// reads none of them, only `detectors[*].scenarios[*].{techniques,
/// catch_rate}` -- so they are filled with deterministic, non-wall-clock
/// values (`campaign.virtual_clock_start_ms`, a synthetic `suite_path`
/// marker mirroring [`GenomeRedSwarm`]'s own `genome://` marker, and the
/// graph's own fingerprint) for a reader's sake, never for the scorer's.
fn build_snapshot(
    generation: u32,
    campaign: &CampaignParams,
    graph: &TargetGraph,
    detectors: &[RuntimeDetector],
    emitted_techniques: &BTreeSet<String>,
    threat_class_by_technique: &BTreeMap<String, ThreatClass>,
    hits: &BTreeMap<(String, String), bool>,
) -> EvasionCoverageSnapshot {
    let mut detector_reports = Vec::with_capacity(detectors.len());
    for detector in detectors {
        let mut scenarios = Vec::with_capacity(emitted_techniques.len());
        let mut detected_payloads = 0usize;
        for technique in emitted_techniques {
            let detected = hits
                .get(&(technique.clone(), detector.id().to_string()))
                .copied()
                .unwrap_or(false);
            if detected {
                detected_payloads += 1;
            }
            scenarios.push(EvasionScenarioCoverage {
                scenario_name: format!("red_swarm::run_generation::gen{generation}::{technique}"),
                threat_class: threat_class_by_technique
                    .get(technique)
                    .cloned()
                    .unwrap_or(ThreatClass::Execution),
                total_payloads: 1,
                detected_payloads: if detected { 1 } else { 0 },
                catch_rate: if detected { 1.0 } else { 0.0 },
                techniques: vec![technique.clone()],
            });
        }
        let total_payloads = emitted_techniques.len();
        detector_reports.push(DetectorEvasionCoverageReport {
            detector: detector.id().to_string(),
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
        });
    }

    EvasionCoverageSnapshot {
        generated_at_ms: campaign.virtual_clock_start_ms,
        suite_name: campaign.name.clone(),
        suite_path: format!("red_swarm://run_generation/gen-{generation}"),
        corpus_version: hex::encode(graph.fingerprint()),
        detectors: detector_reports,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::red_swarm::OperatorRole;
    use crate::red_swarm::graph::{ScenarioRef, TargetGraph};
    use std::path::PathBuf;
    use swarm_whisker::{ProcessStartEvent, TelemetryPayload};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn catalog_path() -> PathBuf {
        repo_root().join("rulesets/evasion/attack-technique-catalog.yaml")
    }

    fn suite_paths() -> Vec<PathBuf> {
        [
            "scenario-suites/command-line-deobfuscation-v1.yaml",
            "scenario-suites/evasion-breadth-v1.yaml",
            "scenario-suites/hellcat-office-v1.yaml",
            "scenario-suites/kill-chain-sequences-v1.yaml",
        ]
        .iter()
        .map(|rel| repo_root().join(rel))
        .collect()
    }

    fn repo_graph() -> TargetGraph {
        TargetGraph::from_repo(&catalog_path(), &suite_paths()).expect("graph should build")
    }

    fn campaign() -> CampaignParams {
        CampaignParams::new("coevolve_test_campaign", 1_700_000_000_000)
    }

    fn detection_config(strategies: &[&str]) -> DetectionConfig {
        DetectionConfig {
            strategy: strategies
                .first()
                .unwrap_or(&"kill_chain_sequence")
                .to_string(),
            strategies: strategies.iter().map(|s| s.to_string()).collect(),
            high_confidence_threshold: 0.9,
            medium_confidence_threshold: 0.7,
            profiles: swarm_core::config::DetectorProfilesConfig::default(),
        }
    }

    #[test]
    fn run_generation_yields_a_catch_rate_in_bounds_with_one_record_per_technique_and_detector() {
        let graph = repo_graph();
        let detection = detection_config(&["suspicious_process_tree", "behavioral_anomaly"]);

        let outcome = run_generation(
            3,
            11,
            &campaign(),
            &graph,
            &suite_paths(),
            &detection,
            &StealthBudget::DEFAULT,
            None,
        )
        .expect("run_generation should succeed");

        assert!(outcome.blue_catch_rate >= 0.0 && outcome.blue_catch_rate <= 1.0);

        let distinct_techniques: BTreeSet<String> = outcome
            .records
            .iter()
            .map(|record| record.technique.clone())
            .collect();
        assert_eq!(
            outcome.records.len(),
            distinct_techniques.len() * detection.strategies.len(),
            "expected exactly one record per (technique, detector) pair"
        );

        // Every evaded technique is genuinely absent from the caught set: no
        // detector's record for it is `detected: true`.
        for evaded in &outcome.evaded_techniques {
            assert!(
                outcome
                    .records
                    .iter()
                    .filter(|record| &record.technique == evaded)
                    .all(|record| !record.detected),
                "technique {evaded} is in evaded_techniques but some record says it was caught"
            );
        }
    }

    #[test]
    fn run_generation_is_deterministic_for_identical_arguments() {
        let graph = repo_graph();
        let detection = detection_config(&["suspicious_process_tree", "fileless_execution"]);

        let first = run_generation(
            2,
            42,
            &campaign(),
            &graph,
            &suite_paths(),
            &detection,
            &StealthBudget::DEFAULT,
            None,
        )
        .expect("first run should succeed");
        let second = run_generation(
            2,
            42,
            &campaign(),
            &graph,
            &suite_paths(),
            &detection,
            &StealthBudget::DEFAULT,
            None,
        )
        .expect("second run should succeed");

        assert_eq!(first, second);
    }

    #[test]
    fn a_detection_config_with_no_enabled_strategies_catches_nothing_and_scores_high_fitness() {
        let graph = repo_graph();
        let detection = detection_config(&[]);

        let outcome = run_generation(
            0,
            5,
            &campaign(),
            &graph,
            &suite_paths(),
            &detection,
            &StealthBudget::DEFAULT,
            None,
        )
        .expect("run_generation should succeed");

        assert_eq!(outcome.blue_catch_rate, 0.0);
        assert!(outcome.records.is_empty());
        assert!(!outcome.evaded_techniques.is_empty());
        assert!(
            outcome.red_fitness.red_fitness > 0.5,
            "red_fitness was {}",
            outcome.red_fitness.red_fitness
        );
    }

    #[test]
    fn a_noop_only_detection_config_catches_nothing_and_scores_high_fitness() {
        let graph = repo_graph();
        let detection = detection_config(&["kill_chain_sequence"]);

        let outcome = run_generation(
            1,
            9,
            &campaign(),
            &graph,
            &suite_paths(),
            &detection,
            &StealthBudget::DEFAULT,
            None,
        )
        .expect("run_generation should succeed");

        assert_eq!(outcome.blue_catch_rate, 0.0);
        assert!(outcome.records.iter().all(|record| !record.detected));
        assert!(outcome.red_fitness.red_fitness > 0.5);
    }

    /// Every strategy [`crate::detector_factory::build_detector_from_strategy`]
    /// supports, so a test that wants "every real detector is enabled" does
    /// not have to enumerate the factory's match arms itself.
    fn all_detector_strategies() -> [&'static str; 13] {
        [
            "suspicious_process_tree",
            "fileless_execution",
            "behavioral_anomaly",
            "dns_exfiltration",
            "lateral_movement",
            "credential_access",
            "suspicious_scripting",
            "persistence",
            "supply_chain",
            "network_connect",
            "infrastructure_anomaly",
            "cloudtrail",
            "kubernetes_audit",
        ]
    }

    #[test]
    fn a_config_whose_detectors_catch_every_emitted_technique_scores_zero_red_fitness() {
        // A one-step plan against the real corpus, with every real detector
        // strategy enabled: at (seed 0, generation 1) this deterministically
        // emits a single technique (`T1620`) that `behavioral_anomaly`,
        // `fileless_execution`, and `suspicious_scripting` all catch on its
        // real materialized events -- found by sweeping seeds 0..200 and
        // generations 0..3 for a fully-caught one-step plan (440 of the 600
        // combinations swept were fully caught; this pins one).
        let graph = repo_graph();
        let detection = detection_config(&all_detector_strategies());
        let mut small_campaign = campaign();
        small_campaign.steps_per_operator = 1;
        small_campaign.max_steps = 1;

        let outcome = run_generation(
            1,
            0,
            &small_campaign,
            &graph,
            &suite_paths(),
            &detection,
            &StealthBudget::DEFAULT,
            None,
        )
        .expect("run_generation should succeed");

        assert_eq!(outcome.blue_catch_rate, 1.0);
        assert!(outcome.evaded_techniques.is_empty());
        assert!(!outcome.records.is_empty());
        assert!(
            outcome.records.iter().any(|record| record.detected),
            "expected at least one detector to have caught the emitted technique"
        );
        assert_eq!(outcome.red_fitness.evasion_rate, 0.0);
        assert_eq!(outcome.red_fitness.red_fitness, 0.0);
    }

    #[test]
    fn a_technique_a_detector_catches_is_detected_true_and_absent_from_evaded() {
        // Same deterministic (seed 0, generation 1) one-step plan as the
        // fully-caught test above: it emits exactly `T1620`, which
        // `behavioral_anomaly` catches and `suspicious_process_tree` does
        // not (pinned by the same seed sweep).
        let graph = repo_graph();
        let mut small_campaign = campaign();
        small_campaign.steps_per_operator = 1;
        small_campaign.max_steps = 1;

        let catching = run_generation(
            1,
            0,
            &small_campaign,
            &graph,
            &suite_paths(),
            &detection_config(&["behavioral_anomaly"]),
            &StealthBudget::DEFAULT,
            None,
        )
        .expect("run_generation should succeed");

        assert_eq!(catching.records.len(), 1);
        assert_eq!(catching.records[0].technique, "T1620");
        assert_eq!(catching.records[0].detector, "behavioral_anomaly");
        assert!(catching.records[0].detected);
        assert!(!catching.evaded_techniques.contains(&"T1620".to_string()));
        assert_eq!(catching.blue_catch_rate, 1.0);

        let missing = run_generation(
            1,
            0,
            &small_campaign,
            &graph,
            &suite_paths(),
            &detection_config(&["suspicious_process_tree"]),
            &StealthBudget::DEFAULT,
            None,
        )
        .expect("run_generation should succeed");

        assert_eq!(missing.records.len(), 1);
        assert_eq!(missing.records[0].technique, "T1620");
        assert_eq!(missing.records[0].detector, "suspicious_process_tree");
        assert!(!missing.records[0].detected);
        assert_eq!(missing.evaded_techniques, vec!["T1620".to_string()]);
        assert_eq!(missing.blue_catch_rate, 0.0);
    }

    /// A `GeneStep` naming `technique` with `intent`, carrying no real
    /// scenario reference of its own -- `attribute_catches` and
    /// `summarize_catches` read only `.technique` and `.intent` off a
    /// `GeneStep`, so every other field is a fixed, otherwise-arbitrary
    /// placeholder (mirrors `scoring.rs` and `budget.rs`'s own fixture
    /// helpers, which make the identical simplification for the identical
    /// reason).
    fn step_with_intent(technique: &str, intent: StepIntent) -> GeneStep {
        GeneStep {
            operator: OperatorRole::Opsec,
            technique: technique.to_string(),
            threat_class: ThreatClass::Execution,
            scenario: ScenarioRef {
                suite: "test-suite".to_string(),
                scenario: format!("{technique}_scenario"),
                event_count: 1,
            },
            event_indices: vec![0],
            host_slot: 0,
            offset_ms: 0,
            intent,
        }
    }

    /// A `process_start` event naming `parent_process`/`process_name` --
    /// `suspicious_process_tree`'s default profile catches any pairing where
    /// the (lowercased) parent is in `["winword", "excel", "outlook",
    /// "acrord32", "teams"]` and the (lowercased) child is in
    /// `["powershell", "pwsh", "cmd", "sh", "bash", "curl", "wget"]`
    /// (`swarm_whisker::detector::default_suspicious_parents`/
    /// `default_suspicious_children`) -- used here to hand-build one event
    /// that is guaranteed caught (`"winword"`/`"powershell"`) and one that
    /// is guaranteed not (`"explorer"`/`"notepad"`), without depending on
    /// the real corpus's content.
    fn process_event(event_id: &str, parent_process: &str, process_name: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "test".to_string(),
            event_id: event_id.to_string(),
            timestamp: 0,
            host_id: Some("host-test".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: parent_process.to_string(),
                process_name: process_name.to_string(),
                command_line: format!("{process_name} --test"),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    #[test]
    fn a_cover_steps_benign_events_do_not_falsely_catch_the_technique_it_covers() {
        // The covered (non-Cover) step realises `T9001` with a benign-shaped
        // event `suspicious_process_tree` does not match ("explorer" is not
        // a suspicious parent). Its `Cover` step keeps the SAME technique
        // (exactly as `OpsecOperator` builds one -- see the module doc's
        // "Cover steps are excluded from attribution" section) but carries a
        // benign-control event that WOULD trip the detector
        // ("winword"/"powershell") if it were allowed to count.
        let steps = vec![
            step_with_intent("T9001", StepIntent::Probe),
            step_with_intent("T9001", StepIntent::Cover { step: 0 }),
        ];
        let grouped = vec![
            (
                "T9001".to_string(),
                vec![process_event("evt-covered", "explorer", "notepad")],
            ),
            (
                "T9001".to_string(),
                vec![process_event("evt-cover", "winword", "powershell")],
            ),
        ];
        let detection = detection_config(&["suspicious_process_tree"]);
        let detectors: Vec<RuntimeDetector> = detection
            .strategies
            .iter()
            .map(|strategy_id| {
                build_detector_from_strategy(strategy_id, &detection)
                    .expect("detector should build")
            })
            .collect();

        let (hits, emitted_techniques) = attribute_catches(&steps, &grouped, &detectors);
        let (blue_catch_rate, evaded_techniques, records) =
            summarize_catches(0, &hits, &emitted_techniques);

        assert!(emitted_techniques.contains("T9001"));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].technique, "T9001");
        assert_eq!(records[0].detector, "suspicious_process_tree");
        assert!(
            !records[0].detected,
            "the Cover step's benign-control event must not count toward T9001's catch"
        );
        assert_eq!(evaded_techniques, vec!["T9001".to_string()]);
        assert_eq!(blue_catch_rate, 0.0);
    }

    #[test]
    fn an_unsupported_detector_strategy_fails_closed_instead_of_silently_skipping_it() {
        let graph = repo_graph();
        let detection = detection_config(&["not_a_real_strategy"]);

        let result = run_generation(
            0,
            1,
            &campaign(),
            &graph,
            &suite_paths(),
            &detection,
            &StealthBudget::DEFAULT,
            None,
        );

        assert!(matches!(result, Err(RedSwarmError::DetectorBuild(_))));
    }
}
