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
//!
//! # The campaign loop (Task 3, COEVOLVE-01 part B / COEVOLVE-02)
//!
//! [`RedSwarmCampaign::run`] repeats [`run_generation`] across a bounded
//! sequence of generations, threading three things forward between calls
//! that a single [`run_generation`] call never sees on its own:
//!
//!   - **red's memory** -- every generation's [`GenerationOutcome::records`]
//!     is appended to an [`super::pattern_db::AttackPatternDb`] that starts
//!     empty and only grows; the [`TechniqueWeights`] snapshot handed to the
//!     NEXT generation's `run_generation` call is built fresh from that
//!     accumulated db every time. At generation 0 the db is empty, so every
//!     technique's weight is the explicit, shared neutral `1.0`
//!     ([`TechniqueWeights::weight_for`]'s documented default for an
//!     unrecorded technique) -- but `run` always passes `Some(&weights)`,
//!     never `None`, so generation 0 still routes through
//!     [`super::operators::choose_distinct`]'s WEIGHTED arm, not its
//!     uniform one. That is a different draw from [`RedGenome::plan`]'s
//!     fully-unweighted `None` path -- deterministic in its own right (the
//!     same `(seed, generation, campaign, graph, weights)` always plans the
//!     same bytes), but never byte-identical to `plan()`'s, per
//!     `choose_distinct`'s own doc. Generation 0's plan is "unweighted" only
//!     in the sense that nothing in the snapshot yet prefers one technique
//!     over another, not in the sense of matching [`RedGenome::plan`]'s
//!     bytes;
//!   - **blue's coverage** -- a `DetectionConfig` that starts at
//!     [`CampaignConfig::initial_detection`] and only ever gains strategies,
//!     never loses one, via [`close_blue_gaps`] below;
//!   - **red's fitness history** -- the sequence of
//!     [`AttackFitness::red_fitness`] values the stopping rule's plateau
//!     check reads.
//!
//! ## Blue's move: gap-closing, monotonic
//!
//! After each generation, [`close_blue_gaps`] walks that generation's
//! [`GenerationOutcome::evaded_techniques`] (already sorted -- see that
//! field's own doc) and, for each one, tries every strategy id NOT already
//! present in the live `DetectionConfig`, in [`ALL_DETECTOR_STRATEGIES`]'s
//! fixed order, building a REAL detector via
//! [`crate::detector_factory::build_detector_from_strategy`] and running it
//! over that technique's own materialized events
//! ([`technique_events_for_generation`] re-derives them independently --
//! see that function's doc for why re-deriving, rather than widening
//! [`run_generation`]'s own return type, is this task's choice). The FIRST
//! candidate that catches anything is enabled; probing for that technique
//! stops there. A technique no available candidate catches is left alone --
//! still evaded, and the live detection config is not widened on its
//! account this generation. Because a strategy is only ever pushed, never
//! removed, and the same "already enabled" membership check that stops a
//! technique from being probed against a strategy it does not need also
//! stops that strategy from being pushed twice, the enabled set is
//! strictly, monotonically non-shrinking across the whole campaign.
//!
//! ## The stopping rule (COEVOLVE-02)
//!
//! Evaluated once per generation, immediately after that generation's
//! outcome and blue move are both recorded, in this fixed order -- so when
//! more than one condition holds at once, the earlier-listed reason is the
//! one recorded:
//!
//!   1. **`MaxGenerations`** -- `generation + 1 == max_generations`. The
//!      unconditional backstop: with `generation` drawn from
//!      `0..max_generations`, this is true on the loop's last possible
//!      iteration NO MATTER what the other two conditions say, which is the
//!      whole of [`RedSwarmCampaign::run`]'s termination proof (see
//!      "Termination" below).
//!   2. **`Plateau`** -- [`plateaued`]: the last `convergence.patience`
//!      consecutive generation-to-generation changes in `red_fitness` are
//!      all smaller in magnitude than `convergence.min_delta`. False while
//!      fewer than `patience + 1` generations have run -- a partial window
//!      proves nothing either way.
//!   3. **`FullCoverage`** -- blue's move closed nothing this generation
//!      (`close_blue_gaps` returned an empty list) AND this generation
//!      actually emitted a non-Cover technique. The second clause matters:
//!      an all-nothing generation ([`GenerationOutcome::evaded_techniques`]
//!      empty **and** `blue_catch_rate == 0.0` -- the "empty-corpus
//!      convention" the doc above this one documents) trivially closes
//!      nothing because there was nothing TO close, and that is not
//!      evidence blue has caught everything catchable -- it is the absence
//!      of a measurement. Only a generation that emitted something, for
//!      which every emitted technique is EITHER already caught OR was just
//!      proven uncoverable by every strategy not yet enabled, counts as
//!      having reached the ceiling of what this campaign's corpus and
//!      detector catalog can settle between them.
//!
//! `Plateau` is deliberately checked before `FullCoverage`: the two
//! conditions are not mutually exclusive (a generation that closes nothing
//! can simultaneously complete a flat-fitness window), and when both hold
//! this module reports the convergence signal rather than the coverage one
//! -- a caller reading `stop_reason` learns more from "red stopped
//! improving" than from "blue ran out of headroom" when both are true at
//! once.
//!
//! ## Termination
//!
//! [`RedSwarmCampaign::run`]'s outer loop is `for generation in
//! 0..config.max_generations` -- syntactically bounded by a `u32` already
//! fixed before the loop starts, with no way to extend it from inside the
//! body. Every iteration either breaks (recording one of the three
//! [`StopReason`]s) or falls through to the next; the `MaxGenerations`
//! check is unconditionally true on `generation == max_generations - 1`
//! (the loop's last iteration, by construction of the range), so the
//! function cannot fail to break by the time that iteration ends.
//! `max_generations == 0` is handled before the loop even starts (an empty
//! report, trivially `MaxGenerations`, since there is no generation zero
//! for either of the other two reasons to have measured anything against).
//! Every step inside one generation -- [`run_generation`],
//! [`close_blue_gaps`], [`plateaued`] -- is itself a finite, non-looping
//! computation over finite data, so the whole function terminates for
//! every [`CampaignConfig`].
//!
//! ## Determinism
//!
//! [`RedSwarmCampaign::run`] reads nothing but `config`: no clock, no
//! entropy, no filesystem beyond the same tracked corpus files
//! [`run_generation`] and [`technique_events_for_generation`] already
//! re-read on every call (see [`GenomeRedSwarm`]'s own determinism
//! section). Two calls with an identical `config` -- including identical
//! `suite_paths` file contents -- therefore produce a byte-identical
//! [`CampaignReport`] (this module's own determinism test pins it), the
//! same guarantee [`run_generation`] itself carries, extended across the
//! whole loop.

use super::RedSwarmError;
use super::ThreatContext;
use super::budget::StealthBudget;
use super::genome::{CampaignParams, GeneStep, RedGenome, RedPlan, StepIntent};
use super::genome_adapter::GenomeRedSwarm;
use super::graph::TargetGraph;
use super::pattern_db::{AttackPatternDb, AttackPatternRecord};
use super::scoring::{AttackFitness, AttackScorer};
use super::weights::TechniqueWeights;
use crate::detector_factory::{RuntimeDetector, build_detector_from_strategy};
use crate::evasion_coverage::{
    DetectorEvasionCoverageReport, EvasionCoverageSnapshot, EvasionScenarioCoverage,
};
use serde::{Deserialize, Serialize};
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

/// Every strategy id [`crate::detector_factory::build_detector_from_strategy`]
/// supports, in the exact order that function's own match arms declare
/// them. [`close_blue_gaps`] tries a technique's not-yet-enabled candidates
/// in this fixed order, so which one gets enabled when more than one would
/// catch a technique is itself deterministic, never an artifact of
/// iterating a `Vec` or a map in whatever order construction happened to
/// leave it.
const ALL_DETECTOR_STRATEGIES: [&str; 14] = [
    "kill_chain_sequence",
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
];

/// A generation-to-generation convergence rule for the `Plateau` stop
/// condition (COEVOLVE-02); see [`RedSwarmCampaign::run`]'s "The stopping
/// rule" doc section.
///
/// Neither field has a built-in floor: `patience: 0` makes [`plateaued`]
/// true as soon as one fitness value has been recorded (a window of zero
/// required transitions is vacuously satisfied), and a negative `min_delta`
/// makes it permanently false (no non-negative magnitude is ever smaller
/// than a negative number). Both are honoured literally rather than
/// rejected -- validating a caller's [`CampaignConfig`] is that caller's
/// concern, not this type's.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Convergence {
    /// The largest generation-to-generation change in `red_fitness` still
    /// considered "no change".
    pub min_delta: f64,
    /// How many CONSECUTIVE such small changes in a row count as a plateau.
    pub patience: u32,
}

/// Every input [`RedSwarmCampaign::run`] needs to run one bounded red/blue
/// campaign (COEVOLVE-01 part B). The whole run is a pure function of this
/// struct -- see [`RedSwarmCampaign::run`]'s "Determinism" doc section.
#[derive(Debug, Clone)]
pub struct CampaignConfig {
    /// The base seed every generation's [`run_generation`] call derives its
    /// own effective seed from (see [`RedGenome::plan_weighted`]'s doc).
    pub seed: u64,
    /// The campaign's step-count bounds, shared by every generation.
    pub campaign: CampaignParams,
    /// The target graph every generation plans against.
    pub graph: TargetGraph,
    /// The suite paths `graph` was built from. REQUIRED to be the same
    /// paths, for the same reason [`GenomeRedSwarm::new`] documents, since
    /// both [`run_generation`] and this module's own
    /// [`technique_events_for_generation`] materialize through that
    /// adapter. Not part of this struct's original brief sketch -- see
    /// [`run_generation`]'s doc's "A parameter beyond this task's brief"
    /// section for why that function already needs it; [`CampaignConfig`]
    /// carries it for the identical, unavoidable reason.
    pub suite_paths: Vec<PathBuf>,
    /// The stealth budget every generation's plan is bounded by.
    pub budget: StealthBudget,
    /// Blue's starting detection config, before any generation's
    /// gap-closing move. [`RedSwarmCampaign::run`] never mutates this field
    /// itself -- it clones it once into a local, growing copy when the run
    /// starts.
    pub initial_detection: DetectionConfig,
    /// The hard cap on how many generations `run` will ever execute,
    /// regardless of what the convergence or coverage checks say (see
    /// [`RedSwarmCampaign::run`]'s "Termination" doc section). `0` runs no
    /// generations at all.
    pub max_generations: u32,
    /// The plateau rule for the `Plateau` stop condition.
    pub convergence: Convergence,
}

/// Why [`RedSwarmCampaign::run`] stopped (COEVOLVE-02). See that method's
/// "The stopping rule" doc section for the exact, ordered conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// `generation + 1 == max_generations`: the hard cap was reached.
    MaxGenerations,
    /// Red's fitness stopped moving: `convergence.patience` consecutive
    /// generation-to-generation changes each fell under
    /// `convergence.min_delta`.
    Plateau,
    /// Blue's gap-closing move closed nothing this generation, on a
    /// generation that emitted at least one non-Cover technique -- every
    /// technique still evaded was just proven uncoverable by every
    /// strategy not yet enabled.
    FullCoverage,
}

/// The directory `swarmctl red-swarm campaign` persists each report under,
/// and the same directory `swarmctl evolution status` reads the freshest
/// one back from (Phase 291, ARMSCI-04) -- the SINGLE canonical value for
/// that path. The write side (`crates/swarm-cli/src/red_swarm_cmd.rs`'s
/// `run_campaign`) and the read side
/// (`crate::evolution_status::load_red_swarm_campaign_summary`) both import
/// this constant rather than each keeping an independent copy of the
/// literal, so the two paths cannot silently drift apart -- a prior
/// revision had exactly that: two separate `"data/red-swarm/campaigns"`
/// literals with nothing but a doc comment on each pointing at the other.
///
/// Repository/cwd-relative, mirroring every other cwd-relative `data/...`
/// store default in this codebase (`data/canaries/`, `data/replay-runs/`,
/// etc.) -- resolved relative to the current working directory by BOTH
/// sides, never through `SwarmConfig` or a `--config` file's own
/// directory. Deliberately a plain constant rather than a `--output-dir`
/// CLI flag or config field: only `run_campaign` (the write side's
/// process-exit shell) and `evolution status` (the read side) use it
/// directly in production, and each side's own tests inject their own
/// temp directory instead of touching this path.
pub const CAMPAIGNS_DIR: &str = "data/red-swarm/campaigns";

/// The full record of one bounded [`RedSwarmCampaign::run`] call: every
/// generation's measured outcome, in order, why the run stopped, and the
/// last generation's blue catch rate for a quick read without re-deriving
/// it from `generations.last()`.
///
/// Deliberately carries no timestamp and no persistence identity
/// (`generated_at_ms`, `corpus_sequence_id`): this is the in-memory result
/// of a pure computation over a [`CampaignConfig`], and a later task's
/// persistence layer should stamp those onto it (or onto an enclosing
/// envelope) at the point it is actually written down -- never inside this
/// module, which would break the "identical config -> identical report"
/// guarantee this struct's whole reason for existing depends on.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CampaignReport {
    /// One entry per generation actually run, in generation order. Length
    /// is always `<= max_generations`, and exactly the number of
    /// generations [`RedSwarmCampaign::run`] executed before `stop_reason`
    /// fired.
    pub generations: Vec<GenerationOutcome>,
    /// Why the run stopped.
    pub stop_reason: StopReason,
    /// `generations.last().blue_catch_rate`, or `0.0` if `generations` is
    /// empty (`max_generations == 0`) -- the same "an empty run caught
    /// nothing" convention [`GenerationOutcome::blue_catch_rate`]'s own doc
    /// uses for an empty corpus.
    pub final_blue_catch_rate: f64,
}

/// The `"generation-<n>"` corpus sequence id for generation `generation`
/// (Task 4, COEVOLVE-04), matching the existing
/// `EvolutionEpisodeRecord::adversarial_corpus_sequence_id` convention (see
/// `crate::evolution_status::EvolutionAdversarialSummary`'s own
/// `corpus_sequence_id`, which that record's value flows into unchanged --
/// that struct's shape test pins the id this function produces still fits
/// its existing `Option<String>` field).
///
/// A pure string format, deliberately kept OUT of [`CampaignReport`] and
/// [`GenerationOutcome`] themselves (see [`CampaignReport`]'s doc's
/// "Deliberately carries no timestamp and no persistence identity"
/// paragraph): this function is the shared source of truth for the id's
/// shape, called from the CLI persistence layer (Task 4) to label each
/// [`GenerationOutcome`] it serializes, never stored on the outcome itself.
pub fn generation_corpus_sequence_id(generation: u32) -> String {
    format!("generation-{generation}")
}

/// The bidirectional red/blue campaign loop (Phase 290, COEVOLVE-01 part B /
/// COEVOLVE-02). A namespace for [`Self::run`], not a thing with its own
/// state -- like [`RedGenome`], it holds nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct RedSwarmCampaign;

impl RedSwarmCampaign {
    /// Runs a bounded red/blue campaign against `config` (see the module
    /// doc's "The campaign loop" section for the full pipeline, the blue
    /// move, the stopping rule, its termination proof, and its determinism
    /// guarantee).
    pub fn run(config: &CampaignConfig) -> Result<CampaignReport, RedSwarmError> {
        // A zero-generation campaign runs nothing; `MaxGenerations` is the
        // only reason that could possibly apply, and there is no generation
        // zero for either of the other two to have measured anything
        // against.
        if config.max_generations == 0 {
            return Ok(CampaignReport {
                generations: Vec::new(),
                stop_reason: StopReason::MaxGenerations,
                final_blue_catch_rate: 0.0,
            });
        }

        let mut generations: Vec<GenerationOutcome> = Vec::new();
        let mut db = AttackPatternDb::default();
        let mut detection = config.initial_detection.clone();
        let mut fitness_history: Vec<f64> = Vec::new();
        let mut final_blue_catch_rate = 0.0;
        let mut stop_reason = StopReason::MaxGenerations;

        for generation in 0..config.max_generations {
            // 1. Weight from whatever red's memory holds so far -- empty at
            //    generation 0, so every technique gets the shared neutral
            //    weight `1.0`, but this is still `Some(&weights)`, not
            //    `None`: generation 0 routes through `choose_distinct`'s
            //    weighted arm, a different (still deterministic) draw than
            //    `RedGenome::plan`'s fully-unweighted path -- see the
            //    module doc's "The campaign loop" section.
            let weights = TechniqueWeights::from_pattern_db(&db, &config.graph);

            // 2. Run the generation against blue's CURRENT (pre-move)
            //    detection config, then fold its records into red's memory.
            let outcome = run_generation(
                generation,
                config.seed,
                &config.campaign,
                &config.graph,
                &config.suite_paths,
                &detection,
                &config.budget,
                Some(&weights),
            )?;
            for record in &outcome.records {
                db.append(record.clone());
            }
            final_blue_catch_rate = outcome.blue_catch_rate;
            fitness_history.push(outcome.red_fitness.red_fitness);

            // 3. Blue's move: close whatever gaps this generation's evaded
            //    techniques admit, over that generation's own materialized
            //    events (re-derived only when there is anything evaded to
            //    probe at all -- see the module doc's "Blue's move"
            //    section).
            let nothing_emitted =
                outcome.evaded_techniques.is_empty() && outcome.blue_catch_rate == 0.0;
            let closed = if outcome.evaded_techniques.is_empty() {
                Vec::new()
            } else {
                let events_by_technique = technique_events_for_generation(
                    generation,
                    config.seed,
                    &config.campaign,
                    &config.graph,
                    &config.suite_paths,
                    &config.budget,
                    Some(&weights),
                )?;
                close_blue_gaps(
                    &mut detection,
                    &outcome.evaded_techniques,
                    &events_by_technique,
                )?
            };

            generations.push(outcome);

            // 4. The stopping rule, in its documented, fixed order (see the
            //    module doc's "The stopping rule" section).
            if generation + 1 == config.max_generations {
                stop_reason = StopReason::MaxGenerations;
                break;
            }
            if plateaued(&fitness_history, &config.convergence) {
                stop_reason = StopReason::Plateau;
                break;
            }
            if !nothing_emitted && closed.is_empty() {
                stop_reason = StopReason::FullCoverage;
                break;
            }
        }

        Ok(CampaignReport {
            generations,
            stop_reason,
            final_blue_catch_rate,
        })
    }
}

/// Whether `history`'s last `convergence.patience` consecutive
/// generation-to-generation changes are all smaller in magnitude than
/// `convergence.min_delta` (the `Plateau` stop condition, COEVOLVE-02).
///
/// `false` while `history` holds `patience` or fewer values -- a window
/// that is not yet full proves nothing, so this never fires early just
/// because too little history exists to disprove it.
fn plateaued(history: &[f64], convergence: &Convergence) -> bool {
    let patience = convergence.patience as usize;
    if history.len() <= patience {
        return false;
    }
    history
        .windows(2)
        .rev()
        .take(patience)
        .all(|pair| (pair[1] - pair[0]).abs() < convergence.min_delta)
}

/// Blue's gap-closing move for one generation (see the module doc's "Blue's
/// move" section).
///
/// For each technique in `evaded` (in the given order -- `run_generation`
/// hands this a sorted, deterministic list), tries every strategy id in
/// [`ALL_DETECTOR_STRATEGIES`] not already present in `detection.strategies`,
/// building a REAL detector via
/// [`crate::detector_factory::build_detector_from_strategy`] and running it
/// over `events_by_technique`'s events for that technique
/// ([`technique_events_for_generation`]'s output); the first candidate that
/// catches anything is pushed onto `detection.strategies` and probing for
/// that technique stops there. A technique absent from `events_by_technique`
/// (never expected in practice -- see that function's doc) is treated as
/// having no events to be caught by, rather than a lookup failure.
///
/// `detection.strategies` only ever grows: the membership check that skips
/// an already-enabled candidate also means this never pushes a duplicate,
/// and nothing in this function ever removes an entry.
///
/// Returns the subset of `evaded` this call actually closed, in the same
/// order -- the stopping rule's `FullCoverage` check reads whether this is
/// empty to know whether blue made any progress this generation.
fn close_blue_gaps(
    detection: &mut DetectionConfig,
    evaded: &[String],
    events_by_technique: &BTreeMap<String, Vec<TelemetryEvent>>,
) -> Result<Vec<String>, RedSwarmError> {
    let mut closed = Vec::new();
    for technique in evaded {
        let events = events_by_technique
            .get(technique)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let mut newly_enabled: Option<&'static str> = None;
        for candidate in ALL_DETECTOR_STRATEGIES {
            if detection
                .strategies
                .iter()
                .any(|enabled| enabled == candidate)
            {
                continue;
            }
            if technique_is_caught_by(events, candidate, detection)? {
                newly_enabled = Some(candidate);
                break;
            }
        }
        if let Some(strategy_id) = newly_enabled {
            detection.strategies.push(strategy_id.to_string());
            closed.push(technique.clone());
        }
    }
    Ok(closed)
}

/// Whether a real detector built from `strategy_id` finds anything on any of
/// `events` -- the same "any finding on any event" catch criterion
/// [`attribute_catches`] uses, but built fresh for this one probe and
/// discarded immediately after, never reused across techniques or steps --
/// so unlike [`attribute_catches`]'s deliberate `fold`, nothing is lost by
/// letting `any` short-circuit: there is no later step this same instance
/// would otherwise have missed feeding.
fn technique_is_caught_by(
    events: &[TelemetryEvent],
    strategy_id: &str,
    detection: &DetectionConfig,
) -> Result<bool, RedSwarmError> {
    let detector = build_detector_from_strategy(strategy_id, detection)?;
    Ok(events
        .iter()
        .any(|event| !detector.evaluate(event).is_empty()))
}

/// Re-derives generation `generation`'s emitted, non-[`StepIntent::Cover`]
/// steps' materialized events, grouped by technique (a technique named by
/// more than one admitted step collects every one of those steps' events,
/// in step order).
///
/// Mirrors [`run_generation`]'s own steps 1 and 2 exactly -- plan, budget,
/// materialize through [`GenomeRedSwarm::materialize_by_step`] -- run
/// independently here so [`close_blue_gaps`]'s probe has real events to run
/// a candidate detector over, without widening [`run_generation`]'s own
/// return type (see the module doc's "Why the plan is drawn twice" section
/// for the underlying equivalence this relies on). Pure and deterministic
/// in exactly the arguments `run_generation` is itself pure in, so a call
/// with the arguments [`RedSwarmCampaign::run`] just called `run_generation`
/// with reproduces that same call's own internal materialization byte for
/// byte.
fn technique_events_for_generation(
    generation: u32,
    seed: u64,
    campaign: &CampaignParams,
    graph: &TargetGraph,
    suite_paths: &[PathBuf],
    budget: &StealthBudget,
    weights: Option<&TechniqueWeights>,
) -> Result<BTreeMap<String, Vec<TelemetryEvent>>, RedSwarmError> {
    let plan = RedGenome::plan_weighted(seed, generation, campaign, graph, weights)?;
    let outcome = budget.apply(plan.steps);

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

    let mut by_technique: BTreeMap<String, Vec<TelemetryEvent>> = BTreeMap::new();
    for (step, (technique, events)) in outcome.steps.iter().zip(grouped.iter()) {
        if matches!(step.intent, StepIntent::Cover { .. }) {
            continue;
        }
        by_technique
            .entry(technique.clone())
            .or_default()
            .extend(events.iter().cloned());
    }
    Ok(by_technique)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::evasion_coverage::EvasionTechniqueCatalog;
    use crate::red_swarm::OperatorRole;
    use crate::red_swarm::graph::{LoadedSuite, ScenarioRef, TargetGraph};
    use crate::replay::{
        LoadedReplayScenario, ReplayExpectations, ReplayScenarioClass, ReplayScenarioInput,
        ReplayScenarioManifest, ReplayScenarioMetadata, ReplayScenarioStep, ReplaySuiteManifest,
        ReplaySuiteMetadata,
    };
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::types::ResponseAction;
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

    /// A fresh, uniquely-named directory under the OS temp dir, mirroring
    /// `replay::tests::unique_temp_dir` (this module cannot reuse that one --
    /// it is private to `replay::tests` -- but needs the identical shape for
    /// the identical reason: [`SC3_TECHNIQUES`]'s fixture writes real,
    /// on-disk suite/scenario YAML so [`GenomeRedSwarm`] can materialize it
    /// exactly as it would the tracked repository corpus). `SystemTime` here
    /// names a THROWAWAY fixture directory only, so parallel test runs never
    /// collide -- it has no bearing on the campaign loop's own determinism,
    /// which depends only on `CampaignConfig`, never on when a test happened
    /// to build the files that config's `suite_paths` point at.
    fn sc3_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "swarm-runtime-red-swarm-campaign-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("temp fixture dir should be creatable");
        path
    }

    /// Six hand-picked `(technique id, catching strategy id, event)` triples,
    /// each event chosen (by direct sweep against every real detector this
    /// crate ships) to trip EXACTLY one of the fourteen strategies in
    /// [`ALL_DETECTOR_STRATEGIES`] and none of the other thirteen -- so a
    /// generation built from these techniques never has an accidental
    /// double-catch that would collapse the multi-generation ramp SC3 (see
    /// `run_closes_gaps_gradually_and_shifts_red_away_from_caught_techniques`
    /// below) needs to observe. `process_event`'s
    /// winword/powershell pairing is the same fixture the cover-steps test
    /// above already relies on for `suspicious_process_tree`; the other five
    /// events are this test's own, one payload variant per strategy family
    /// that specific strategy's default profile is tuned to notice.
    fn sc3_techniques() -> Vec<(&'static str, &'static str, TelemetryEvent)> {
        vec![
            (
                "SC3-PROC-TREE",
                "suspicious_process_tree",
                process_event("sc3-proc-tree", "winword", "powershell"),
            ),
            (
                "SC3-FILELESS",
                "fileless_execution",
                TelemetryEvent {
                    source: "sc3-fixture".to_string(),
                    event_id: "sc3-fileless".to_string(),
                    timestamp: 0,
                    host_id: Some("host-sc3".to_string()),
                    payload: TelemetryPayload::ProcessMemoryAccess(
                        swarm_whisker::ProcessMemoryAccessEvent {
                            source_process: "explorer.exe".to_string(),
                            target_process: "lsass.exe".to_string(),
                            allocation_type: "private".to_string(),
                            protection_flags: vec!["PAGE_EXECUTE_READWRITE".to_string()],
                            region_size: 8192,
                            call_stack_hint: Some("unbacked".to_string()),
                        },
                    ),
                },
            ),
            (
                "SC3-NETCONNECT",
                "network_connect",
                TelemetryEvent {
                    source: "sc3-fixture".to_string(),
                    event_id: "sc3-netconnect".to_string(),
                    timestamp: 0,
                    host_id: Some("host-sc3".to_string()),
                    payload: TelemetryPayload::NetworkConnect(swarm_whisker::NetworkConnectEvent {
                        process_name: "svchost.exe".to_string(),
                        destination_ip: "198.51.100.23".to_string(),
                        destination_port: 4444,
                        protocol: "tcp".to_string(),
                    }),
                },
            ),
            (
                "SC3-DNSEXFIL",
                "dns_exfiltration",
                TelemetryEvent {
                    source: "sc3-fixture".to_string(),
                    event_id: "sc3-dnsexfil".to_string(),
                    timestamp: 0,
                    host_id: Some("host-sc3".to_string()),
                    payload: TelemetryPayload::DnsQuery(swarm_whisker::DnsQueryEvent {
                        query_name:
                            "dGhpc2lzYXZlcnlsb25nZW5jb2RlZHN1YmRvbWFpbnN0cmluZw.badguy.example"
                                .to_string(),
                        query_type: "TXT".to_string(),
                        source_ip: Some("10.1.2.3".to_string()),
                        process_name: Some("powershell.exe".to_string()),
                        response_code: Some("NOERROR".to_string()),
                    }),
                },
            ),
            (
                "SC3-PERSIST",
                "persistence",
                TelemetryEvent {
                    source: "sc3-fixture".to_string(),
                    event_id: "sc3-persist".to_string(),
                    timestamp: 0,
                    host_id: Some("host-sc3".to_string()),
                    payload: TelemetryPayload::RegistryPersistence(
                        swarm_whisker::RegistryPersistenceEvent {
                            process_name: "powershell.exe".to_string(),
                            registry_path:
                                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                                    .to_string(),
                            value_name: Some("Updater".to_string()),
                            value_data: Some("C:\\Users\\Public\\evil.exe".to_string()),
                            access_type: "write".to_string(),
                        },
                    ),
                },
            ),
            (
                "SC3-SCRIPT",
                "suspicious_scripting",
                TelemetryEvent {
                    source: "sc3-fixture".to_string(),
                    event_id: "sc3-script".to_string(),
                    timestamp: 0,
                    host_id: Some("host-sc3".to_string()),
                    payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                        parent_process: "cmd.exe".to_string(),
                        process_name: "powershell.exe".to_string(),
                        command_line: "powershell -enc SGVsbG8gV29ybGQgdGhpcyBpcyBhIHRlc3Q="
                            .to_string(),
                        user: Some("alice".to_string()),
                        executable_path: None,
                        signer: None,
                        signature_valid: None,
                    }),
                },
            ),
        ]
    }

    /// Builds the on-disk suite/scenario YAML [`sc3_techniques`] describes
    /// (real files, in a fresh [`sc3_temp_dir`], loaded through the exact
    /// same [`crate::replay`] loaders the tracked repository corpus goes
    /// through -- see [`GenomeRedSwarm`]'s module doc for why that real,
    /// on-disk materialization cannot be swapped for an in-memory-only
    /// fixture) and the matching in-memory [`TargetGraph`] (via
    /// [`TargetGraph::from_parts`], since a graph needs no disk access of
    /// its own -- see that method's doc). Returns the graph and the
    /// `suite_paths` a [`CampaignConfig`] should carry to materialize it.
    ///
    /// A fresh call writes a fresh directory; the files are never cleaned up
    /// (they sit under the OS temp dir, where the existing
    /// `replay::tests::unique_temp_dir` fixtures already leave theirs).
    fn sc3_fixture() -> (TargetGraph, Vec<PathBuf>) {
        let root = sc3_temp_dir("sc3-fixture");
        let suite_name = "sc3-fixture-suite".to_string();

        let mut scenario_refs = Vec::new();
        let mut loaded_scenarios = Vec::new();
        for (technique, _strategy, event) in sc3_techniques() {
            let scenario_name = format!("{}-scenario", technique.to_lowercase());
            let manifest = ReplayScenarioManifest {
                name: scenario_name.clone(),
                description: format!("SC3 fixture scenario realising {technique}"),
                seed_time_ms: 1,
                requested_by: "sc3-fixture".to_string(),
                receipt_chain: Vec::new(),
                metadata: ReplayScenarioMetadata {
                    class: ReplayScenarioClass::Adversarial,
                    threat_class: Some(ThreatClass::Execution),
                    campaign: None,
                    techniques: vec![technique.to_string()],
                    tags: Vec::new(),
                },
                input: ReplayScenarioInput::Events {
                    events: vec![ReplayScenarioStep {
                        action: ResponseAction::IsolateHost {
                            host_id: "host-sc3".to_string(),
                        },
                        event,
                    }],
                },
                expectations: ReplayExpectations::default(),
            };
            let file_name = format!("{scenario_name}.yaml");
            let file_path = root.join(&file_name);
            std::fs::write(
                &file_path,
                serde_yaml::to_string(&manifest).expect("scenario manifest should serialize"),
            )
            .expect("scenario manifest should write");
            scenario_refs.push(file_name);
            loaded_scenarios.push(LoadedReplayScenario {
                path: file_path,
                manifest,
            });
        }

        let suite_manifest = ReplaySuiteManifest {
            name: suite_name.clone(),
            description: "SC3 fixture suite".to_string(),
            corpus_version: "sc3-fixture-v1".to_string(),
            metadata: ReplaySuiteMetadata::default(),
            scenarios: scenario_refs,
        };
        let suite_path = root.join("suite.yaml");
        std::fs::write(
            &suite_path,
            serde_yaml::to_string(&suite_manifest).expect("suite manifest should serialize"),
        )
        .expect("suite manifest should write");

        let loaded_suite = LoadedSuite {
            name: suite_name,
            scenarios: loaded_scenarios,
        };
        let catalog = EvasionTechniqueCatalog {
            schema_version: 1,
            suite: "synthetic://sc3-fixture".to_string(),
            detectors: Vec::new(),
        };
        let graph = TargetGraph::from_parts(&catalog, &[loaded_suite]);

        (graph, vec![suite_path])
    }

    /// A campaign with `max_steps: 0` always emits an empty plan --
    /// `round_robin` (`genome.rs`) returns `[]` the instant `out.len() >=
    /// max_steps` is checked with `max_steps == 0`, before any operator's
    /// proposal is even considered, regardless of seed, generation, or
    /// weights. [`budget.apply`](StealthBudget::apply) on an empty plan
    /// proposes zero events, so `stealth == 1.0` (the "nothing proposed"
    /// branch, not a `0.0 / 0.0`); [`AttackScorer::score`] on an empty plan
    /// takes `evasion_rate == 1.0` (the empty-plan branch
    /// `mean_technique_catch_rate` documents) times that `stealth`, so
    /// `red_fitness == 1.0`, EVERY generation, unconditionally -- no
    /// dependence on the real corpus's content at all. Used by the
    /// stopping-rule mechanism tests below to get a `red_fitness` (and a
    /// `blue_catch_rate`/`evaded_techniques`, via the "empty-corpus
    /// convention") that is trivially, provably constant, so those tests
    /// pin the LOOP's own behaviour rather than an accident of which
    /// techniques a chosen seed happens to sample from the tracked corpus.
    fn empty_plan_campaign() -> CampaignParams {
        let mut campaign = campaign();
        campaign.max_steps = 0;
        campaign
    }

    #[test]
    fn run_executes_exactly_max_generations_and_never_a_seventh() {
        // `empty_plan_campaign` makes `red_fitness` provably constant, so
        // `Plateau` could fire the moment its window fills; `patience: 100`
        // makes that window (101 generations) unreachable within this run's
        // `max_generations: 6`, so `MaxGenerations` is the only reachable
        // stop reason. `FullCoverage` is structurally excluded regardless
        // of `patience`: an empty plan emits nothing, so `run`'s
        // `nothing_emitted` guard (see the module doc's "The stopping rule"
        // section) forces `full_coverage` false every generation.
        let config = CampaignConfig {
            seed: 7,
            campaign: empty_plan_campaign(),
            graph: repo_graph(),
            suite_paths: suite_paths(),
            budget: StealthBudget::DEFAULT,
            initial_detection: detection_config(&[]),
            max_generations: 6,
            convergence: Convergence {
                min_delta: 1e-9,
                patience: 100,
            },
        };

        let report = RedSwarmCampaign::run(&config).expect("run should succeed");

        assert_eq!(
            report.generations.len(),
            6,
            "SC1: expected exactly 6 generations"
        );
        assert_eq!(report.stop_reason, StopReason::MaxGenerations);
        // A 7th generation is never even attempted: `generations` has no
        // index 6, and `run`'s loop range is `0..6` regardless.
        assert!(report.generations.get(6).is_none());
    }

    #[test]
    fn run_stops_at_plateau_before_max_generations_when_fitness_never_moves() {
        // Same empty-plan trick, but with a `patience` small enough (2) for
        // its window (3 generations) to fill well before `max_generations`
        // (50): `red_fitness` is EXACTLY `1.0` every generation (see
        // `empty_plan_campaign`'s doc), so the plateau condition
        // (`|delta| < min_delta`) is satisfied the instant there is history
        // enough to check it.
        let config = CampaignConfig {
            seed: 3,
            campaign: empty_plan_campaign(),
            graph: repo_graph(),
            suite_paths: suite_paths(),
            budget: StealthBudget::DEFAULT,
            initial_detection: detection_config(&[]),
            max_generations: 50,
            convergence: Convergence {
                min_delta: 1e-9,
                patience: 2,
            },
        };

        let report = RedSwarmCampaign::run(&config).expect("run should succeed");

        assert_eq!(
            report.generations.len(),
            3,
            "SC2: plateau should fire as soon as its 3-generation window fills"
        );
        assert_eq!(report.stop_reason, StopReason::Plateau);
        assert!(
            report.generations.len() < 50,
            "plateau must stop the run well before max_generations"
        );
        for outcome in &report.generations {
            assert_eq!(outcome.red_fitness.red_fitness, 1.0);
            assert_eq!(outcome.blue_catch_rate, 0.0);
            assert!(outcome.evaded_techniques.is_empty());
        }
    }

    /// M1 (fix round 1): `plateaued` directly, at the boundary the SC2
    /// integration test above only pins indirectly.
    #[test]
    fn plateaued_is_false_while_the_window_is_not_yet_full() {
        let convergence = Convergence {
            min_delta: 1e-9,
            patience: 2,
        };

        // `patience` values of flat history: one short of the 3 values a
        // `patience: 2` window needs (2 deltas), so nothing has been
        // disproved yet -- `plateaued` must not fire early.
        assert!(!plateaued(&[1.0, 1.0], &convergence));
    }

    #[test]
    fn plateaued_is_true_the_instant_the_window_fills_with_flat_deltas() {
        let convergence = Convergence {
            min_delta: 1e-9,
            patience: 2,
        };

        // Exactly `patience + 1` values: the window is full and both
        // deltas are `0.0`, which is `< 1e-9`.
        assert!(plateaued(&[1.0, 1.0, 1.0], &convergence));
    }

    #[test]
    fn plateaued_with_zero_patience_is_true_as_soon_as_one_value_exists() {
        let convergence = Convergence {
            min_delta: 1e-9,
            patience: 0,
        };

        // A window of zero required transitions is vacuously satisfied the
        // moment there is at least one recorded value (see `Convergence`'s
        // own doc for why this is honoured literally, not rejected).
        assert!(plateaued(&[1.0], &convergence));
    }

    #[test]
    fn plateaued_never_fires_on_a_nan_delta() {
        let convergence = Convergence {
            min_delta: 1e9,
            patience: 1,
        };

        // A `NaN` delta compares `false` against any threshold under
        // IEEE-754 (`NaN < x` is always `false`), including this
        // deliberately huge `min_delta` that would trivially satisfy any
        // REAL delta -- so a `NaN` anywhere in the window means "never
        // plateau", not a panic and not a false positive.
        assert!(!plateaued(&[0.0, f64::NAN], &convergence));
        assert!(!plateaued(&[f64::NAN, f64::NAN, f64::NAN], &convergence));
    }

    #[test]
    fn plateaued_never_fires_with_a_negative_min_delta() {
        let convergence = Convergence {
            min_delta: -0.001,
            patience: 2,
        };

        // Otherwise-perfectly-flat history (every delta exactly `0.0`)
        // still never plateaus once `min_delta` is negative: no
        // non-negative magnitude is ever smaller than a negative number
        // (see `Convergence`'s own doc).
        assert!(!plateaued(&[1.0, 1.0, 1.0], &convergence));
    }

    /// M1 (fix round 1): the `max_generations == 1` case the review traced
    /// by hand (`MaxGenerations` fires on generation 0 itself, before
    /// `plateaued`/`FullCoverage` are even reached) is now backed by a
    /// test rather than left to inspection.
    #[test]
    fn run_stops_at_max_generations_when_max_generations_is_one() {
        let config = CampaignConfig {
            seed: 5,
            campaign: empty_plan_campaign(),
            graph: repo_graph(),
            suite_paths: suite_paths(),
            budget: StealthBudget::DEFAULT,
            initial_detection: detection_config(&[]),
            max_generations: 1,
            convergence: Convergence {
                min_delta: 1e-9,
                patience: 100,
            },
        };

        let report = RedSwarmCampaign::run(&config).expect("run should succeed");

        assert_eq!(report.generations.len(), 1);
        assert_eq!(report.stop_reason, StopReason::MaxGenerations);
    }

    /// M2 (fix round 1): a fixture where `MaxGenerations` and `Plateau`
    /// are BOTH true on the same final generation, pinning the documented
    /// precedence order (`MaxGenerations` checked first, so it is the one
    /// recorded) rather than leaving it an untested claim.
    #[test]
    fn max_generations_takes_precedence_over_plateau_when_both_fire_together() {
        let convergence = Convergence {
            min_delta: 1e-9,
            patience: 2,
        };
        // `empty_plan_campaign` makes `red_fitness` a provable constant
        // `1.0` every generation (see that fixture's own doc), so by
        // generation 2 (the 3rd generation, 0-indexed) the accumulated
        // history is `[1.0, 1.0, 1.0]` -- exactly the flat window
        // `plateaued_is_true_the_instant_the_window_fills_with_flat_deltas`
        // already proves satisfies `plateaued` on its own. Confirm that
        // directly here, independent of the loop, so the "both true"
        // premise this test's name claims is verified, not assumed.
        assert!(plateaued(&[1.0, 1.0, 1.0], &convergence));

        let config = CampaignConfig {
            seed: 11,
            campaign: empty_plan_campaign(),
            graph: repo_graph(),
            suite_paths: suite_paths(),
            budget: StealthBudget::DEFAULT,
            initial_detection: detection_config(&[]),
            // `max_generations: 3` makes `generation + 1 == max_generations`
            // ALSO true at generation 2 -- the same generation the
            // plateau window fills at, by construction of `patience: 2`
            // above (window needs `patience + 1 == 3` values).
            max_generations: 3,
            convergence,
        };

        let report = RedSwarmCampaign::run(&config).expect("run should succeed");

        assert_eq!(report.generations.len(), 3);
        assert_eq!(
            report.stop_reason,
            StopReason::MaxGenerations,
            "MaxGenerations is checked first and must win over the \
             simultaneously-true Plateau condition"
        );
    }

    #[test]
    fn run_stops_at_full_coverage_when_every_strategy_is_already_enabled() {
        // With every strategy `close_blue_gaps` could ever enable already
        // live in `initial_detection`, its "not yet enabled" candidate pool
        // is empty from generation 0 on: whatever that generation emits
        // (certainly something, against the real corpus's default campaign
        // bounds), it closes nothing new, because there is nothing left
        // to try. That is exactly the stopping rule's `FullCoverage`
        // condition: no evaded technique could be closed by any AVAILABLE
        // detector, because no detector is available any more.
        let config = CampaignConfig {
            seed: 21,
            campaign: campaign(),
            graph: repo_graph(),
            suite_paths: suite_paths(),
            budget: StealthBudget::DEFAULT,
            initial_detection: detection_config(&ALL_DETECTOR_STRATEGIES),
            max_generations: 10,
            convergence: Convergence {
                min_delta: 0.0,
                patience: 1_000,
            },
        };

        let report = RedSwarmCampaign::run(&config).expect("run should succeed");

        assert_eq!(report.stop_reason, StopReason::FullCoverage);
        assert_eq!(report.generations.len(), 1);
    }

    #[test]
    fn run_closes_gaps_over_several_generations_and_shifts_red_away_from_a_gen0_catch() {
        // A small, fully controlled six-technique corpus (`sc3_fixture`):
        // each technique's one hand-crafted event is caught by exactly one
        // of the fourteen real strategies and none of the other thirteen
        // (pinned by `zzz`-prefixed diagnostics during this task's own
        // development; the six catching pairs are asserted directly in
        // `sc3_fixture_techniques_are_each_caught_by_exactly_one_strategy`
        // below). With only `suspicious_process_tree` enabled at the start
        // and two techniques sampled per generation, seed `1557`
        // deterministically: catches `SC3-PROC-TREE` (the one technique
        // that detector catches) in generation 0 while a second, different
        // technique goes evaded and gets closed by a freshly-enabled
        // detector; repeats that gap-closing pattern for two more
        // generations; and on generation 3 resamples something already
        // covered by a by-then-enabled detector, catching everything and
        // triggering `FullCoverage` -- found by sweeping seeds against this
        // fixture for a run that both catches something in generation 0 and
        // reaches at least 4 generations, mirroring this crate's own
        // documented seed-sweep practice (see `run_generation`'s
        // `a_config_whose_detectors_catch_every_emitted_technique_...`
        // test).
        let (graph, suite_paths) = sc3_fixture();
        let config = CampaignConfig {
            seed: 1557,
            campaign: {
                let mut c = campaign();
                c.steps_per_operator = 1;
                c.max_steps = 2;
                c
            },
            graph,
            suite_paths,
            budget: StealthBudget::DEFAULT,
            initial_detection: detection_config(&["suspicious_process_tree"]),
            max_generations: 8,
            convergence: Convergence {
                min_delta: 0.0,
                patience: 1_000,
            },
        };

        let report = RedSwarmCampaign::run(&config).expect("run should succeed");

        assert!(
            report.generations.len() >= 4,
            "SC3: expected at least 4 generations, ran {}",
            report.generations.len()
        );
        assert_eq!(report.stop_reason, StopReason::FullCoverage);

        // SC3 part 1: `blue_catch_rate` is non-decreasing on average --
        // here, monotonic non-decreasing outright, and strictly higher by
        // the last generation than the first.
        let rates: Vec<f64> = report
            .generations
            .iter()
            .map(|outcome| outcome.blue_catch_rate)
            .collect();
        for window in rates.windows(2) {
            assert!(
                window[1] >= window[0],
                "blue_catch_rate regressed within the run: {rates:?}"
            );
        }
        assert!(
            rates.last() > rates.first(),
            "blue_catch_rate should be strictly higher by the last generation: {rates:?}"
        );

        // SC3 part 2: a technique caught in generation 0 has a strictly
        // lower selection weight by the last generation than the neutral
        // `1.0` every technique's weight starts at (generation 0 plans
        // against an empty `AttackPatternDb`).
        let gen0_caught: Vec<String> = report.generations[0]
            .records
            .iter()
            .filter(|record| record.detected)
            .map(|record| record.technique.clone())
            .collect();
        assert!(
            !gen0_caught.is_empty(),
            "expected generation 0 to have caught at least one technique"
        );

        let mut final_db = AttackPatternDb::default();
        for outcome in &report.generations {
            for record in &outcome.records {
                final_db.append(record.clone());
            }
        }
        let final_weights = TechniqueWeights::from_pattern_db(&final_db, &config.graph);
        for technique in &gen0_caught {
            let weight = final_weights.weight_for(technique);
            assert!(
                weight < 1.0,
                "technique {technique} caught in generation 0 should have a strictly lower \
                 weight by the last generation (neutral is 1.0), got {weight}"
            );
        }
    }

    #[test]
    fn sc3_fixture_techniques_are_each_caught_by_exactly_one_strategy() {
        // Pins the six catching pairs
        // `run_closes_gaps_over_several_generations_and_shifts_red_away_from_a_gen0_catch`
        // relies on, directly against the fixture's own materialized
        // events -- so a future change to a detector's default profile that
        // silently broke that test's premise would fail HERE first, with an
        // exact `(technique, expected strategy)` mismatch, rather than as a
        // confusing assertion failure three layers up.
        let (graph, suite_paths) = sc3_fixture();
        let detection = detection_config(&ALL_DETECTOR_STRATEGIES);
        let mut small_campaign = campaign();
        small_campaign.steps_per_operator = 1;
        small_campaign.max_steps = 1;

        for (technique, expected_strategy, _event) in sc3_techniques() {
            // Every technique is realised by exactly one scenario carrying
            // exactly one event, so a one-step plan naming it (found by
            // sweeping seed/generation, mirroring this crate's own
            // documented practice) exercises exactly that event.
            let mut found = false;
            'search: for seed in 0u64..50 {
                for generation in 0u32..5 {
                    let outcome = run_generation(
                        generation,
                        seed,
                        &small_campaign,
                        &graph,
                        &suite_paths,
                        &detection,
                        &StealthBudget::DEFAULT,
                        None,
                    )
                    .expect("run_generation should succeed");
                    if outcome.records.iter().any(|r| r.technique == technique) {
                        let caught_by: Vec<&str> = outcome
                            .records
                            .iter()
                            .filter(|r| r.technique == technique && r.detected)
                            .map(|r| r.detector.as_str())
                            .collect();
                        assert_eq!(
                            caught_by,
                            vec![expected_strategy],
                            "technique {technique} should be caught by exactly \
                             {expected_strategy} and no other strategy"
                        );
                        found = true;
                        break 'search;
                    }
                }
            }
            assert!(
                found,
                "technique {technique} was never emitted by the sweep"
            );
        }
    }

    #[test]
    fn run_is_deterministic_for_an_identical_config() {
        let (graph, suite_paths) = sc3_fixture();
        let config = CampaignConfig {
            seed: 1557,
            campaign: {
                let mut c = campaign();
                c.steps_per_operator = 1;
                c.max_steps = 2;
                c
            },
            graph,
            suite_paths,
            budget: StealthBudget::DEFAULT,
            initial_detection: detection_config(&["suspicious_process_tree"]),
            max_generations: 8,
            convergence: Convergence {
                min_delta: 0.0,
                patience: 1_000,
            },
        };

        let first = RedSwarmCampaign::run(&config).expect("first run should succeed");
        let second = RedSwarmCampaign::run(&config).expect("second run should succeed");

        assert_eq!(first, second);
    }

    #[test]
    fn run_executes_zero_generations_when_max_generations_is_zero() {
        let config = CampaignConfig {
            seed: 1,
            campaign: campaign(),
            graph: repo_graph(),
            suite_paths: suite_paths(),
            budget: StealthBudget::DEFAULT,
            initial_detection: detection_config(&[]),
            max_generations: 0,
            convergence: Convergence {
                min_delta: 0.0,
                patience: 1,
            },
        };

        let report = RedSwarmCampaign::run(&config).expect("run should succeed");

        assert!(report.generations.is_empty());
        assert_eq!(report.stop_reason, StopReason::MaxGenerations);
        assert_eq!(report.final_blue_catch_rate, 0.0);
    }

    #[test]
    fn generation_corpus_sequence_id_formats_as_generation_dash_n() {
        assert_eq!(generation_corpus_sequence_id(0), "generation-0");
        assert_eq!(generation_corpus_sequence_id(7), "generation-7");
        assert_eq!(generation_corpus_sequence_id(42), "generation-42");
    }

    #[test]
    fn generation_corpus_sequence_id_is_distinct_per_generation_and_deterministic() {
        let first = generation_corpus_sequence_id(3);
        let second = generation_corpus_sequence_id(3);
        let third = generation_corpus_sequence_id(4);

        assert_eq!(
            first, second,
            "identical generations must format identically"
        );
        assert_ne!(first, third, "distinct generations must format distinctly");
    }
}
