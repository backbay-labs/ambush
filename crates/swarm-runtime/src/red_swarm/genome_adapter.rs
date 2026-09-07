//! `GenomeRedSwarm`: materializes a [`RedGenome`] plan into telemetry events
//! and implements [`RedSwarmAdapter`] (COEVOLVE-03).
//!
//! [`super::SuiteRedSwarmAdapter`] draws its corpus from one tracked replay
//! *suite* on disk. `GenomeRedSwarm` draws it from a [`RedGenome`] plan drawn
//! against a [`TargetGraph`] -- the red lane's own generated adversary, not a
//! hand-authored one. The two share one contract ([`RedSwarmAdapter`]) and one
//! re-stamping discipline: every emitted event is a real corpus event, cloned
//! and re-addressed onto this sequence's identity, never an invented payload
//! (OPFOR-04).
//!
//! # Materialization
//!
//! [`GenomeRedSwarm::generate_sequence_artifact`] mirrors
//! [`super::SuiteRedSwarmAdapter::generate_sequence_artifact`]'s shape:
//!
//!   1. **plan** -- [`RedGenome::plan`] against `self`'s seed, generation,
//!      campaign and graph;
//!   2. **budget** -- [`StealthBudget::apply`] bounds the plan's steps and
//!      binds each admitted step's `host_slot`;
//!   3. **materialize** -- each admitted [`GeneStep`] names a [`ScenarioRef`]
//!      and a set of `event_indices` into it; this step re-loads that
//!      scenario's real events (through the same loaders
//!      [`TargetGraph::from_repo`] uses) and re-stamps exactly the events the
//!      step names -- a new `event_id`, a `host_id` derived from
//!      `host_slot`, a `source` namespaced to this genome, and a timestamp
//!      anchored to the plan's own virtual schedule. It invents no event
//!      shape: every field but those four is an untouched clone of a real
//!      scenario event's payload.
//!
//! # Why `suite_paths` is a field
//!
//! A [`TargetGraph`] keeps only [`ScenarioRef`]s -- a suite *name*, a
//! scenario *name*, and an event count -- never the events themselves (see
//! that module's doc: "here the reference is enough for a planner to know the
//! technique has real material behind it and where to find it"). Materializing
//! real events therefore needs the same suite files the graph was built from,
//! so `GenomeRedSwarm` keeps their paths and re-reads them once per
//! materialize call -- exactly the way `SuiteRedSwarmAdapter` re-reads its one
//! suite path on every call: no cache to invalidate, and identical disk
//! content always re-parses identically, so this costs nothing on the
//! determinism contract below. `suite_paths` MUST be the set `graph` was built
//! from ([`TargetGraph::from_repo`]'s `suite_paths` argument, or the suites
//! backing a `graph` built via [`TargetGraph::from_parts`]); a mismatch
//! surfaces as [`RedSwarmError::UnresolvedScenario`] when a plan step's
//! scenario cannot be found, never a panic.
//!
//! # Determinism (SC 2 / SC 4)
//!
//! `.events` is a pure function of `(self.seed, self.generation,
//! self.campaign, self.graph, self.budget, self.weights, self.suite_paths'
//! file contents)` alone. `context: &ThreatContext` is accepted only because
//! [`RedSwarmAdapter`] is the one trait shared with the suite-backed adapter;
//! it contributes `generated_at_ms` to the artifact -- mirroring
//! `SuiteRedSwarmAdapter`, which sets that field from `context.requested_at_ms`
//! too -- and the artifact's own `sequence_id`, and nothing else: never a
//! step's technique, timing, host, or event content. Two calls on the same
//! `GenomeRedSwarm`, even with two different contexts, produce byte-identical
//! `.events` (see this module's tests).
//!
//! Event timestamps come from the plan's own virtual schedule
//! (`campaign.virtual_clock_start_ms + step.offset_ms`, plus each event's
//! position within its step's own referenced slice), never from
//! `context.requested_at_ms`: `step.offset_ms` is defined as an offset from
//! `virtual_clock_start_ms` (see [`super::genome::Determinism`]), so anchoring
//! anywhere else would let a materialized event disagree with the plan's own
//! determinism record.
//!
//! # Field choices on [`AdversarialSequenceArtifact`]
//!
//! A genome plan has no single backing suite file, so the fields
//! `SuiteRedSwarmAdapter` fills from one suite manifest are filled from the
//! genome's own identity instead, documented here so a reader never has to
//! guess:
//!   - `suite_name` is the campaign name; `suite_path` is a synthetic
//!     `genome://<campaign>/seed-<seed>/gen-<generation>` marker -- there is
//!     no file, so the marker names the plan instead of a path;
//!   - `corpus_version` is the hex-encoded [`super::genome::RedPlan`]
//!     `graph_fingerprint` -- the graph's own fingerprint is already the
//!     mechanism [`TargetGraph::fingerprint`] provides for "the precise graph
//!     [a plan] was planned against", so this reuses it rather than inventing
//!     a second version scheme;
//!   - `tags` is the set of [`OperatorRole`]s that contributed an admitted
//!     step (e.g. `"recon"`, `"opsec"`), since a genome plan carries no
//!     free-form tag metadata of its own;
//!   - `techniques` / `scenario_names` are drawn only from non-cover admitted
//!     steps; `benign_control_scenarios` is drawn only from `Cover` steps'
//!     scenarios. Unlike `SuiteRedSwarmAdapter` (where a benign scenario is
//!     *excluded* from `events` and named in `benign_control_scenarios`
//!     instead), a genome `Cover` step's benign events ARE in `events` --
//!     Opsec placed them there deliberately as cover material -- so this
//!     field names benign material that is present, not material that was
//!     dropped.
//!
//! # Weighted planning
//!
//! [`GenomeRedSwarm::with_weights`] (Phase 290, COEVOLVE-01/-03) attaches an
//! optional [`TechniqueWeights`] snapshot after construction;
//! [`GenomeRedSwarm::new`] leaves it unset, so every existing call site
//! keeps planning through [`RedGenome::plan_weighted`]'s `None` arm --
//! byte-identical to Phase 288's `RedGenome::plan` forever (see that
//! function's doc). Both [`GenomeRedSwarm::generate_sequence_artifact`] and
//! [`GenomeRedSwarm::materialize_by_step`] plan through the same
//! `self.weights.as_ref()`, so the two entry points never disagree about
//! which plan they are materializing.
//!
//! # Step-grouped materialization
//!
//! [`GenomeRedSwarm::materialize_by_step`] (Phase 290, COEVOLVE-01 part B)
//! runs the same plan -> budget -> materialize pipeline as
//! [`GenomeRedSwarm::generate_sequence_artifact`], reusing the private
//! `materialize_step` for the re-stamping itself, but returns each admitted
//! step's events grouped by that step instead of flattened and globally
//! re-sorted. A [`TelemetryEvent`] carries no technique field, so a caller
//! that must map a detector finding back to the technique that produced it
//! -- red_swarm's own measured run, [`super::campaign::run_generation`] --
//! needs exactly this grouping, which the flattened artifact has already
//! discarded by the time it leaves
//! [`GenomeRedSwarm::generate_sequence_artifact`].

use super::budget::StealthBudget;
use super::genome::{CampaignParams, GeneStep, OperatorRole, RedGenome, StepIntent};
use super::graph::{ScenarioRef, TargetGraph};
use super::weights::TechniqueWeights;
use super::{
    AdversarialSequenceArtifact, RedSwarmAdapter, RedSwarmError, ThreatContext,
    sanitize_identifier, validate_context,
};
use crate::replay::{
    LoadedReplayScenario, ReplayScenarioInput, ReplayScenarioStep, load_replay_suite_manifest,
    load_scenario_manifest, resolve_manifest_relative_path,
};
use async_trait::async_trait;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use swarm_whisker::TelemetryEvent;

/// Deterministic, genome-backed [`RedSwarmAdapter`]: plans with
/// [`RedGenome::plan`], bounds the plan with a [`StealthBudget`], and
/// materializes the survivors into an [`AdversarialSequenceArtifact`] of real,
/// re-stamped corpus events (COEVOLVE-03). See the module doc for the full
/// contract.
#[derive(Debug, Clone)]
pub struct GenomeRedSwarm {
    graph: TargetGraph,
    suite_paths: Vec<PathBuf>,
    campaign: CampaignParams,
    seed: u64,
    generation: u32,
    budget: StealthBudget,
    weights: Option<TechniqueWeights>,
}

impl GenomeRedSwarm {
    /// A genome-backed adapter that plans generation `generation` of
    /// `campaign` against `graph` with `seed`, then bounds the plan with
    /// `budget`. `suite_paths` MUST be the paths `graph` was built from (see
    /// the module doc's "Why `suite_paths` is a field" section); a mismatch
    /// is not checked here -- it surfaces as
    /// [`RedSwarmError::UnresolvedScenario`] the first time a plan step's
    /// scenario fails to resolve.
    ///
    /// Plans unweighted (see [`Self::with_weights`]) until a caller opts in.
    pub fn new(
        graph: TargetGraph,
        suite_paths: Vec<PathBuf>,
        campaign: CampaignParams,
        seed: u64,
        generation: u32,
        budget: StealthBudget,
    ) -> Self {
        Self {
            graph,
            suite_paths,
            campaign,
            seed,
            generation,
            budget,
            weights: None,
        }
    }

    /// Attaches a [`TechniqueWeights`] snapshot: every later plan drawn by
    /// this adapter (through [`Self::generate_sequence_artifact`] or
    /// [`Self::materialize_by_step`]) biases technique selection through it,
    /// via [`RedGenome::plan_weighted`]. See the module doc's "Weighted
    /// planning" section for the determinism contract this preserves.
    pub fn with_weights(mut self, weights: TechniqueWeights) -> Self {
        self.weights = Some(weights);
        self
    }

    /// Plans, budgets, and materializes one generation's
    /// [`AdversarialSequenceArtifact`]. Mirrors
    /// [`super::SuiteRedSwarmAdapter::generate_sequence_artifact`]'s shape and
    /// re-stamping discipline; see the module doc for exactly what depends on
    /// `context` and what does not.
    pub async fn generate_sequence_artifact(
        &self,
        context: &ThreatContext,
    ) -> Result<AdversarialSequenceArtifact, RedSwarmError> {
        validate_context(context)?;

        let plan = RedGenome::plan_weighted(
            self.seed,
            self.generation,
            &self.campaign,
            &self.graph,
            self.weights.as_ref(),
        )?;
        let graph_fingerprint = plan.graph_fingerprint;
        let outcome = self.budget.apply(plan.steps);
        let scenario_index = self.load_scenario_index()?;

        let mut events = Vec::new();
        let mut techniques = BTreeSet::new();
        let mut scenario_names = BTreeSet::new();
        let mut benign_control_scenarios = BTreeSet::new();
        let mut operator_roles: BTreeSet<OperatorRole> = BTreeSet::new();

        for (step_index, step) in outcome.steps.iter().enumerate() {
            operator_roles.insert(step.operator);
            if matches!(step.intent, StepIntent::Cover { .. }) {
                benign_control_scenarios.insert(step.scenario.scenario.clone());
            } else {
                techniques.insert(step.technique.clone());
                scenario_names.insert(step.scenario.scenario.clone());
            }

            let scenario_events = resolve_scenario_events(&scenario_index, &step.scenario)?;
            events.extend(self.materialize_step(step_index, step, scenario_events)?);
        }

        // Mirrors `SuiteRedSwarmAdapter::generate_sequence_artifact`'s final
        // sort, so both adapters hand a caller events in the same canonical
        // order regardless of source.
        events.sort_by(|left, right| {
            left.timestamp
                .cmp(&right.timestamp)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });

        let campaign_tag = sanitize_identifier(&self.campaign.name);
        Ok(AdversarialSequenceArtifact {
            sequence_id: sanitize_identifier(&context.sequence_id),
            suite_name: self.campaign.name.clone(),
            suite_path: format!(
                "genome://{campaign_tag}/seed-{}/gen-{}",
                self.seed, self.generation
            ),
            corpus_version: hex::encode(graph_fingerprint),
            generated_at_ms: context.requested_at_ms,
            campaign: Some(self.campaign.name.clone()),
            techniques: techniques.into_iter().collect(),
            tags: operator_roles
                .into_iter()
                .map(|role| operator_tag(role).to_string())
                .collect(),
            scenario_names: scenario_names.into_iter().collect(),
            benign_control_scenarios: benign_control_scenarios.into_iter().collect(),
            events,
        })
    }

    /// Plans, budgets, and materializes one generation's corpus exactly as
    /// [`Self::generate_sequence_artifact`] does, but returns each admitted
    /// step's re-stamped events grouped by that step -- one entry per
    /// [`GeneStep`], tagged with the step's own `technique` -- instead of one
    /// flattened, globally re-sorted [`AdversarialSequenceArtifact`] (Phase
    /// 290, COEVOLVE-01 part B). See the module doc's "Step-grouped
    /// materialization" section for why this exists.
    ///
    /// Reuses [`Self::materialize_step`] for the re-stamping itself, so
    /// nothing about how an event is re-addressed is duplicated between this
    /// method and [`Self::generate_sequence_artifact`]; the only difference
    /// is the final assembly (grouped here, flattened-and-sorted there).
    ///
    /// Entries are in the plan's own final schedule order (never re-sorted
    /// the way [`Self::generate_sequence_artifact`]'s `.events` is). Depends
    /// on exactly the inputs that method's doc names -- `context` only gates
    /// [`validate_context`] here too; it contributes nothing to the returned
    /// events, so two calls on the same adapter with two different valid
    /// contexts return identical groupings (mirrors
    /// [`Self::generate_sequence_artifact`]'s own determinism contract).
    pub fn materialize_by_step(
        &self,
        context: &ThreatContext,
    ) -> Result<Vec<(String, Vec<TelemetryEvent>)>, RedSwarmError> {
        validate_context(context)?;

        let plan = RedGenome::plan_weighted(
            self.seed,
            self.generation,
            &self.campaign,
            &self.graph,
            self.weights.as_ref(),
        )?;
        let outcome = self.budget.apply(plan.steps);
        let scenario_index = self.load_scenario_index()?;

        let mut grouped = Vec::with_capacity(outcome.steps.len());
        for (step_index, step) in outcome.steps.iter().enumerate() {
            let scenario_events = resolve_scenario_events(&scenario_index, &step.scenario)?;
            let events = self.materialize_step(step_index, step, scenario_events)?;
            grouped.push((step.technique.clone(), events));
        }
        Ok(grouped)
    }

    /// Every scenario named by `self.suite_paths`, keyed by `(suite name,
    /// scenario name)` -- the same two fields a [`ScenarioRef`] carries -- so
    /// a step's scenario reference resolves in one lookup. Loaded fresh on
    /// every call through the same loaders [`TargetGraph::from_repo`] uses
    /// (no cache); see the module doc's "Why `suite_paths` is a field"
    /// section for why that is safe for the determinism contract.
    fn load_scenario_index(
        &self,
    ) -> Result<BTreeMap<(String, String), LoadedReplayScenario>, RedSwarmError> {
        let mut index = BTreeMap::new();
        for suite_path in &self.suite_paths {
            let suite = load_replay_suite_manifest(suite_path)?;
            for scenario_ref in &suite.scenarios {
                let scenario_path = resolve_manifest_relative_path(suite_path, scenario_ref);
                let loaded = load_scenario_manifest(&scenario_path)?;
                index.insert((suite.name.clone(), loaded.manifest.name.clone()), loaded);
            }
        }
        Ok(index)
    }

    /// Re-stamps exactly the events `step.event_indices` names in
    /// `scenario_events` -- never the whole scenario -- with a new
    /// `event_id`, a `host_id` derived from `step.host_slot`, a `source`
    /// namespaced to this genome, and a timestamp anchored to the plan's
    /// virtual schedule (`campaign.virtual_clock_start_ms + step.offset_ms`,
    /// plus the event's own position within the step's referenced slice, so a
    /// step that replays a sub-range of a scenario keeps that sub-range's
    /// internal spacing rather than the whole scenario's).
    ///
    /// Every other field -- `payload` above all -- is an untouched clone: no
    /// event shape is invented here (OPFOR-04).
    fn materialize_step(
        &self,
        step_index: usize,
        step: &GeneStep,
        scenario_events: &[ReplayScenarioStep],
    ) -> Result<Vec<TelemetryEvent>, RedSwarmError> {
        let mut referenced = Vec::with_capacity(step.event_indices.len());
        for &event_index in &step.event_indices {
            let scenario_step = scenario_events.get(event_index).ok_or_else(|| {
                RedSwarmError::UnresolvedScenario {
                    suite: step.scenario.suite.clone(),
                    scenario: step.scenario.scenario.clone(),
                    reason: format!(
                        "event index {event_index} is out of range for {} loaded events",
                        scenario_events.len()
                    ),
                }
            })?;
            referenced.push(scenario_step);
        }

        // Anchor to the step's OWN referenced events, not the scenario's
        // whole timeline, so a step that replays a sub-range keeps that
        // sub-range's internal spacing.
        let step_min_timestamp = referenced
            .iter()
            .map(|scenario_step| scenario_step.event.timestamp)
            .min()
            .unwrap_or(0);
        let step_base_ms = self
            .campaign
            .virtual_clock_start_ms
            .saturating_add(step.offset_ms);
        let host_id = format!("genome-host-{:02}", step.host_slot);
        let campaign_tag = sanitize_identifier(&self.campaign.name);
        let scenario_tag = sanitize_identifier(&step.scenario.scenario);
        let source_prefix = format!("red_swarm::genome::{campaign_tag}::gen{}", self.generation);

        let mut materialized = Vec::with_capacity(referenced.len());
        for scenario_step in referenced {
            let event = &scenario_step.event;
            let intra_offset = event.timestamp.saturating_sub(step_min_timestamp);
            let mut restamped = event.clone();
            restamped.timestamp = step_base_ms.saturating_add(intra_offset);
            restamped.host_id = Some(host_id.clone());
            restamped.event_id = format!(
                "{campaign_tag}:gen{}:{step_index}:{scenario_tag}:{}",
                self.generation, event.event_id
            );
            restamped.source = format!("{source_prefix}::{}", sanitize_identifier(&event.source));
            materialized.push(restamped);
        }
        Ok(materialized)
    }
}

#[async_trait]
impl RedSwarmAdapter for GenomeRedSwarm {
    async fn generate_adversarial_sequence(
        &self,
        context: &ThreatContext,
    ) -> Result<Vec<TelemetryEvent>, RedSwarmError> {
        Ok(self.generate_sequence_artifact(context).await?.events)
    }
}

/// Looks `scenario` up in `index` and confirms it carries real, inline events
/// (OPFOR-04): a [`ScenarioRef`] naming a replay-bundle scenario is
/// [`RedSwarmError::UnsupportedScenarioInput`], the same error
/// `SuiteRedSwarmAdapter` raises for the same shape. A `(suite, scenario)`
/// pair `index` does not contain at all is
/// [`RedSwarmError::UnresolvedScenario`] -- see [`GenomeRedSwarm`]'s module
/// doc for why that should never happen for a correctly-paired graph and
/// suite set.
fn resolve_scenario_events<'a>(
    index: &'a BTreeMap<(String, String), LoadedReplayScenario>,
    scenario: &ScenarioRef,
) -> Result<&'a [ReplayScenarioStep], RedSwarmError> {
    let key = (scenario.suite.clone(), scenario.scenario.clone());
    let loaded = index
        .get(&key)
        .ok_or_else(|| RedSwarmError::UnresolvedScenario {
            suite: scenario.suite.clone(),
            scenario: scenario.scenario.clone(),
            reason: "not found among the configured suite paths".to_string(),
        })?;
    match &loaded.manifest.input {
        ReplayScenarioInput::Events { events } => Ok(events),
        ReplayScenarioInput::ReplayBundles { .. } => Err(RedSwarmError::UnsupportedScenarioInput {
            scenario: loaded.manifest.name.clone(),
        }),
    }
}

/// The artifact `tags` entry for one operator role (e.g. `"recon"`,
/// `"opsec"`). Kept as its own explicit mapping -- [`OperatorRole`]'s
/// stream-label mapping is private to [`super::genome`] -- but produces the
/// same strings, since both exist only to name the same six roles.
fn operator_tag(role: OperatorRole) -> &'static str {
    match role {
        OperatorRole::Recon => "recon",
        OperatorRole::Injection => "injection",
        OperatorRole::Auth => "auth",
        OperatorRole::Evasion => "evasion",
        OperatorRole::Chain => "chain",
        OperatorRole::Opsec => "opsec",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::SuiteRedSwarmAdapter;
    use super::*;

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

    fn adapter(seed: u64, generation: u32) -> GenomeRedSwarm {
        GenomeRedSwarm::new(
            repo_graph(),
            suite_paths(),
            campaign(),
            seed,
            generation,
            StealthBudget::DEFAULT,
        )
    }

    /// Like [`adapter`], but with a non-trivial [`TechniqueWeights`] snapshot
    /// attached via [`GenomeRedSwarm::with_weights`] -- Phase 290's weighted
    /// planning path (M3), rather than the unweighted `None` arm every other
    /// helper in this module exercises. Weights alternate a low and a high
    /// value across the graph's own techniques, in `id` order, so the
    /// snapshot is neither uniformly neutral (`1.0` everywhere, which plans
    /// identically to unweighted and would prove nothing) nor hand-picked
    /// technique ids a future catalog edit could silently drop out from
    /// under this test.
    fn weighted_adapter(seed: u64, generation: u32) -> GenomeRedSwarm {
        let graph = repo_graph();
        let weight_pairs: Vec<(String, f64)> = graph
            .techniques()
            .enumerate()
            .map(|(index, node)| {
                let weight = if index % 2 == 0 { 0.1 } else { 0.9 };
                (node.id.clone(), weight)
            })
            .collect();
        let weights = TechniqueWeights::for_test(weight_pairs);

        GenomeRedSwarm::new(
            graph,
            suite_paths(),
            campaign(),
            seed,
            generation,
            StealthBudget::DEFAULT,
        )
        .with_weights(weights)
    }

    fn context(requested_at_ms: i64, sequence_id: &str) -> ThreatContext {
        ThreatContext::new(
            PathBuf::from("unused-for-genome-materialization"),
            requested_at_ms,
            sequence_id,
        )
    }

    /// A comparable fingerprint of an event, since `TelemetryEvent` derives
    /// no `PartialEq` -- mirrors the helper `red_swarm::tests` uses for the
    /// same reason.
    fn event_fingerprint(events: &[TelemetryEvent]) -> Vec<(String, i64, Option<String>, String)> {
        events
            .iter()
            .map(|event| {
                (
                    event.event_id.clone(),
                    event.timestamp,
                    event.host_id.clone(),
                    serde_json::to_string(&event.payload).expect("payload should encode"),
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn genome_red_swarm_is_usable_as_a_trait_object_alongside_the_suite_adapter() {
        let genome = adapter(7, 1);
        let suite = SuiteRedSwarmAdapter;
        let objects: Vec<&dyn RedSwarmAdapter> = vec![&genome, &suite];

        let genome_events = objects[0]
            .generate_adversarial_sequence(&context(1_800_000_000_000, "genome-object"))
            .await
            .expect("genome adapter should generate through the trait object");
        let suite_context = ThreatContext::new(
            repo_root().join("scenario-suites/hellcat-office-v1.yaml"),
            1_900_000_000_000,
            "suite-object",
        );
        let suite_events = objects[1]
            .generate_adversarial_sequence(&suite_context)
            .await
            .expect("suite adapter should generate through the trait object");

        assert!(!genome_events.is_empty());
        assert!(!suite_events.is_empty());
    }

    #[tokio::test]
    async fn materialization_is_byte_identical_for_the_same_seed_generation_campaign_and_graph() {
        let genome = adapter(11, 2);

        // Two different contexts: proves `.events` depends only on
        // `(seed, generation, campaign, graph, budget)`, never on `context`.
        let first = genome
            .generate_sequence_artifact(&context(1_800_000_000_000, "call-one"))
            .await
            .expect("first materialization should succeed");
        let second = genome
            .generate_sequence_artifact(&context(42, "call-two-a-different-context"))
            .await
            .expect("second materialization should succeed");

        assert!(
            !first.events.is_empty(),
            "fixture campaign should admit at least one event"
        );
        assert_eq!(
            event_fingerprint(&first.events),
            event_fingerprint(&second.events)
        );
        // Only the context-derived artifact metadata may differ.
        assert_eq!(first.generated_at_ms, 1_800_000_000_000);
        assert_eq!(second.generated_at_ms, 42);
    }

    /// Pins the load-bearing equivalence the module doc's "Step-grouped
    /// materialization" section claims: [`GenomeRedSwarm::materialize_by_step`]
    /// and [`GenomeRedSwarm::generate_sequence_artifact`] re-derive the same
    /// underlying event set for the same adapter -- the only difference is
    /// final assembly (grouped and left in plan order, vs. flattened and
    /// globally sorted by `(timestamp, event_id)`). `run_generation`
    /// (`campaign.rs`) depends on this: it calls `generate_sequence_artifact`'s
    /// plan-and-budget steps directly for scoring and
    /// `materialize_by_step` separately for attribution, and trusts the two
    /// to agree byte for byte. This test would fail red if a future edit to
    /// either method (e.g. a change to which steps are included, or to how
    /// `step_index` is computed) ever broke that agreement.
    #[tokio::test]
    async fn materialize_by_step_reproduces_generate_sequence_artifacts_events() {
        let genome = adapter(13, 2);

        let artifact = genome
            .generate_sequence_artifact(&context(1_800_000_000_000, "compare-artifact"))
            .await
            .expect("artifact materialization should succeed");
        let grouped = genome
            .materialize_by_step(&context(1_800_000_000_000, "compare-grouped"))
            .expect("grouped materialization should succeed");

        assert!(
            !artifact.events.is_empty(),
            "fixture campaign should admit at least one event"
        );

        // Flatten and sort exactly the way `generate_sequence_artifact`
        // does internally, since `materialize_by_step` leaves its events in
        // plan order rather than pre-sorting them.
        let mut flattened: Vec<TelemetryEvent> =
            grouped.into_iter().flat_map(|(_, events)| events).collect();
        flattened.sort_by(|left, right| {
            left.timestamp
                .cmp(&right.timestamp)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });

        assert_eq!(
            event_fingerprint(&artifact.events),
            event_fingerprint(&flattened)
        );
    }

    /// M3: pins the same equivalence
    /// [`materialize_by_step_reproduces_generate_sequence_artifacts_events`]
    /// pins, but for a [`GenomeRedSwarm`] carrying a non-trivial
    /// [`TechniqueWeights`] snapshot (see [`weighted_adapter`]). Both
    /// [`GenomeRedSwarm::generate_sequence_artifact`] and
    /// [`GenomeRedSwarm::materialize_by_step`] plan through the same
    /// `self.weights.as_ref()` (see the module doc's "Weighted planning"
    /// section), so the unweighted case agreeing proves nothing about the
    /// weighted one -- a future edit that only threaded `weights` through
    /// one of the two call sites would pass the unweighted sibling test and
    /// still break `run_generation`'s trust that the two agree.
    #[tokio::test]
    async fn materialize_by_step_reproduces_generate_sequence_artifacts_events_when_weighted() {
        let genome = weighted_adapter(13, 2);

        let artifact = genome
            .generate_sequence_artifact(&context(1_800_000_000_000, "compare-artifact-weighted"))
            .await
            .expect("weighted artifact materialization should succeed");
        let grouped = genome
            .materialize_by_step(&context(1_800_000_000_000, "compare-grouped-weighted"))
            .expect("weighted grouped materialization should succeed");

        assert!(
            !artifact.events.is_empty(),
            "fixture campaign should admit at least one event under weighted planning too"
        );

        // Flatten and sort exactly the way `generate_sequence_artifact`
        // does internally, since `materialize_by_step` leaves its events in
        // plan order rather than pre-sorting them.
        let mut flattened: Vec<TelemetryEvent> =
            grouped.into_iter().flat_map(|(_, events)| events).collect();
        flattened.sort_by(|left, right| {
            left.timestamp
                .cmp(&right.timestamp)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });

        assert_eq!(
            event_fingerprint(&artifact.events),
            event_fingerprint(&flattened)
        );
    }

    #[tokio::test]
    async fn every_materialized_event_traces_to_a_real_scenario_event() {
        let genome = adapter(3, 0);
        let artifact = genome
            .generate_sequence_artifact(&context(1_800_000_000_000, "trace"))
            .await
            .expect("materialization should succeed");
        assert!(!artifact.events.is_empty());

        // Rebuild the suite -> scenario -> events index independently of
        // `GenomeRedSwarm`'s own loader, then confirm every materialized
        // event's payload matches some real scenario event's payload, and
        // that its event_id carries a real event's own id as a suffix.
        let mut real_payloads = Vec::new();
        let mut real_ids = BTreeSet::new();
        for suite_path in suite_paths() {
            let suite = load_replay_suite_manifest(&suite_path).expect("suite should load");
            for scenario_ref in &suite.scenarios {
                let scenario_path = resolve_manifest_relative_path(&suite_path, scenario_ref);
                let loaded = load_scenario_manifest(&scenario_path).expect("scenario should load");
                if let ReplayScenarioInput::Events { events } = &loaded.manifest.input {
                    for step in events {
                        real_payloads.push(
                            serde_json::to_string(&step.event.payload)
                                .expect("payload should encode"),
                        );
                        real_ids.insert(step.event.event_id.clone());
                    }
                }
            }
        }

        for event in &artifact.events {
            let payload = serde_json::to_string(&event.payload).expect("payload should encode");
            assert!(
                real_payloads.contains(&payload),
                "materialized event payload does not match any real scenario event"
            );
            assert!(
                real_ids
                    .iter()
                    .any(|real_id| event.event_id.ends_with(real_id.as_str())),
                "materialized event_id {} does not trace to a real event id",
                event.event_id
            );
        }
    }

    #[tokio::test]
    async fn materialized_event_count_equals_the_budgets_events_emitted() {
        let graph = repo_graph();
        let campaign_params = campaign();
        let plan = RedGenome::plan(5, 4, &campaign_params, &graph);
        let outcome = StealthBudget::DEFAULT.apply(plan.steps);

        let genome = GenomeRedSwarm::new(
            repo_graph(),
            suite_paths(),
            campaign_params,
            5,
            4,
            StealthBudget::DEFAULT,
        );
        let artifact = genome
            .generate_sequence_artifact(&context(1_800_000_000_000, "count"))
            .await
            .expect("materialization should succeed");

        assert_eq!(artifact.events.len(), outcome.events_emitted as usize);
    }

    #[tokio::test]
    async fn a_budget_that_admits_no_steps_still_produces_a_valid_empty_artifact() {
        let genome = GenomeRedSwarm::new(
            repo_graph(),
            suite_paths(),
            campaign(),
            1,
            0,
            StealthBudget {
                max_events_per_generation: 0,
                max_distinct_hosts: 0,
                max_technique_repeats: 0,
            },
        );

        let artifact = genome
            .generate_sequence_artifact(&context(1_800_000_000_000, "empty"))
            .await
            .expect("an empty admitted plan should still materialize");

        assert!(artifact.events.is_empty());
        assert!(artifact.techniques.is_empty());
        assert!(artifact.tags.is_empty());
    }

    #[tokio::test]
    async fn a_cover_steps_scenario_is_named_as_benign_control_not_as_a_technique_scenario() {
        // A wide seed/generation sweep so the assertion does not depend on
        // one seed happening to draw an Opsec cover step.
        for seed in 0..12u64 {
            let genome = adapter(seed, 0);
            let artifact = genome
                .generate_sequence_artifact(&context(1_800_000_000_000, "cover-sweep"))
                .await
                .expect("materialization should succeed");
            if !artifact.benign_control_scenarios.is_empty() {
                for benign in &artifact.benign_control_scenarios {
                    assert!(
                        !artifact.scenario_names.contains(benign),
                        "benign control scenario {benign} should not double as an attack scenario name"
                    );
                }
                return;
            }
        }
        panic!("expected at least one seed in the sweep to draw an Opsec cover step");
    }
}
