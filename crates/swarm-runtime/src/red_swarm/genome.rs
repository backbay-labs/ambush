//! The red genome, the plan it produces, and the pure planner (OPFOR-01, OPFOR-04).
//!
//! A red campaign is a sequence of [`GeneStep`]s: each names a technique the
//! [`TargetGraph`] already contains, the scenario whose events realise it, and
//! an intent that says why the operator placed it. The planner
//! ([`RedGenome::plan`]) is the composition root for the six operators. It is a
//! *pure function of its arguments* -- seed, generation, campaign, graph -- and
//! nothing else: no clock, no I/O, no globals. That is the whole point of the
//! red lane. The blue detectors are scored against this adversary, so the
//! adversary has to be reproducible to the byte, or a detector regression cannot
//! be told from planner noise (SC 2).
//!
//! Reproducibility is built from three deterministic choices, all recorded in
//! the plan's [`Determinism`] block so a reader can re-derive it:
//!   - the seed is `seed ^ (generation as u64).rotate_left(32)`, so a generation
//!     shifts the whole stream without colliding with a nearby seed;
//!   - each operator draws from its *own* forked stream, labelled by role, so no
//!     two operators share a draw; the operator call order is itself part of the
//!     contract (`fork` advances the parent once per call, coupling a later
//!     operator's stream to its position), so the `scheduler` string names that
//!     order and a reorder is a declared breaking change, not a transparent one;
//!   - offsets come from a monotone virtual schedule with a bounded jitter drawn
//!     from the planner's own stream, never from the wall clock (SC 4).
//!
//! Every emitted step is validated against the graph before it leaves the
//! planner (OPFOR-04): an operator that named a technique the graph does not
//! contain is rejected with [`RedSwarmError::UnknownTechnique`], not silently
//! shipped as an unrealisable step.

use super::RedSwarmError;
use super::graph::{ScenarioRef, TargetGraph};
use super::operators::{RedOperator, builtin_operators};
use super::rng::RedGenomeRng;
use serde::{Deserialize, Serialize};
use swarm_core::pheromone::ThreatClass;

/// The scheduler that assembles operator proposals into a plan. The string is a
/// contract: it names the fixed operator call order (Recon, Auth, Injection,
/// Chain, Evasion, Opsec) and the round-robin interleave. Changing either
/// changes the plan's bytes, so it must change this string too (SC 4).
const SCHEDULER: &str = "round_robin_v1";

/// The fork label for the planner's own jitter stream, kept distinct from every
/// operator's role label so schedule jitter is independent of operator draws.
const SCHEDULE_STREAM_LABEL: &str = "schedule";

/// Milliseconds between consecutive steps on the virtual schedule. Larger than
/// [`JITTER_BOUND`] so the schedule stays strictly monotone after jitter.
const STEP_SPACING_MS: i64 = 1_000;

/// Exclusive upper bound on per-step jitter, in milliseconds. Strictly less than
/// [`STEP_SPACING_MS`] so consecutive offsets never cross (SC 2 / test 6).
const JITTER_BOUND: u64 = 250;

/// Which of the six red operators placed a step. Serialised into the plan so a
/// reader can attribute each step to the role whose heuristic chose it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole {
    /// Reconnaissance: probes discovery / initial-access surface and the gaps.
    Recon,
    /// Execution / fileless injection.
    Injection,
    /// Credential access and lateral movement.
    Auth,
    /// Rewrites a step toward a detector's declared gap.
    Evasion,
    /// Bridges two kill-chain-adjacent steps.
    Chain,
    /// Covers a noisy step with benign-shaped activity.
    Opsec,
}

impl OperatorRole {
    /// The stable fork label for this role's PRNG stream. The label decorrelates
    /// sibling streams -- two forks of the same parent state with different labels
    /// diverge -- but it does NOT make an operator's stream position-independent:
    /// `fork` advances the parent once per call, so inserting or reordering an
    /// operator shifts every later operator's draws. The operator order is a
    /// versioned contract instead: the `scheduler` string names it, and changing
    /// the order changes that string, so a reorder is a declared breaking change.
    fn stream_label(self) -> &'static str {
        match self {
            OperatorRole::Recon => "recon",
            OperatorRole::Injection => "injection",
            OperatorRole::Auth => "auth",
            OperatorRole::Evasion => "evasion",
            OperatorRole::Chain => "chain",
            OperatorRole::Opsec => "opsec",
        }
    }
}

/// Why an operator placed a step. `Chain` and `Cover` carry the index of the
/// step they relate to; the planner rewrites those indices from proposal order
/// to final-plan order before the plan leaves it, so they name real steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepIntent {
    /// Reconnaissance probe.
    Probe,
    /// Exploitation of an execution / credential / lateral technique.
    Exploit,
    /// Persistence establishment (reserved; Phase 289 may emit it).
    Persist,
    /// Defensive evasion: this step rewrites toward a declared detector gap.
    Evade,
    /// This step advances the kill chain from the step at `from`.
    Chain {
        /// Final-plan index of the predecessor step this one chains from.
        from: usize,
    },
    /// This step covers the noisy step at `step` with benign-shaped activity.
    Cover {
        /// Final-plan index of the noisy step this one covers.
        step: usize,
    },
}

/// One step of a red campaign: a catalogued technique, the scenario events that
/// realise it, and the operator's intent. It carries no invented payload -- only
/// a reference into the [`TargetGraph`] and one of its scenarios (OPFOR-04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeneStep {
    /// The operator role that proposed this step.
    pub operator: OperatorRole,
    /// A technique id that resolves to a [`TargetGraph`] node -- always.
    pub technique: String,
    /// A threat class the technique declares.
    pub threat_class: ThreatClass,
    /// The scenario whose events this step replays.
    pub scenario: ScenarioRef,
    /// Which of that scenario's events, in order. Never empty for an emitted
    /// step: the planner only builds steps over scenarios that carry events.
    pub event_indices: Vec<usize>,
    /// Host slot in `0..max_distinct_hosts`; Phase 289 binds it to a real host.
    /// The planner emits slot `0` as an unbound placeholder.
    pub host_slot: u8,
    /// Milliseconds from the campaign's virtual clock start -- never wall clock.
    pub offset_ms: i64,
    /// Why this step is here.
    pub intent: StepIntent,
}

/// The reproducibility record stamped on every plan: everything a reader needs
/// to re-derive the plan's bytes. If any of these changed, the plan changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Determinism {
    /// The effective seed the planner drew from (`seed ^ generation`).
    pub rng_seed: u64,
    /// The virtual clock origin the step offsets are measured from.
    pub virtual_clock_start_ms: i64,
    /// The scheduler identifier: [`SCHEDULER`].
    pub scheduler: &'static str,
}

/// A complete red plan for one generation of one campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedPlan {
    /// The generation this plan was drawn for.
    pub generation: u32,
    /// The campaign name it belongs to.
    pub campaign: String,
    /// The fingerprint of the graph it was planned against, so a reader can
    /// prove the plan and the graph agree.
    pub graph_fingerprint: [u8; 32],
    /// The plan's steps, in final schedule order.
    pub steps: Vec<GeneStep>,
    /// The reproducibility record.
    pub determinism: Determinism,
}

/// The tunable parameters of one campaign. `steps_per_operator` bounds how many
/// steps each role proposes; `max_steps` bounds the interleaved total.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignParams {
    /// The campaign name, copied onto the plan.
    pub name: String,
    /// The virtual clock origin for step offsets.
    pub virtual_clock_start_ms: i64,
    /// How many steps each operator proposes (before interleave / truncation).
    pub steps_per_operator: u8,
    /// The maximum number of steps in the interleaved plan.
    pub max_steps: u16,
}

impl CampaignParams {
    /// The default steps-per-operator (brief default: 3).
    pub const DEFAULT_STEPS_PER_OPERATOR: u8 = 3;
    /// The default max-steps (brief default: 24).
    pub const DEFAULT_MAX_STEPS: u16 = 24;

    /// A campaign with the default step bounds and the given name and clock.
    pub fn new(name: impl Into<String>, virtual_clock_start_ms: i64) -> Self {
        Self {
            name: name.into(),
            virtual_clock_start_ms,
            steps_per_operator: Self::DEFAULT_STEPS_PER_OPERATOR,
            max_steps: Self::DEFAULT_MAX_STEPS,
        }
    }
}

/// How the planner treats a step whose technique is not in the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Validation {
    /// Drop the offending step. Used by the built-in path, whose operators never
    /// invent a technique, so nothing is ever dropped -- it only lets the public
    /// entry point stay infallible while still guaranteeing OPFOR-04.
    Skip,
    /// Reject the whole plan with [`RedSwarmError::UnknownTechnique`]. Used when
    /// a caller supplies its own operators, so an invented technique is caught.
    Reject,
}

/// The red genome: the planner that composes the operators into a plan. It holds
/// no state; it is a namespace for the pure planning functions.
#[derive(Debug, Clone, Copy, Default)]
pub struct RedGenome;

impl RedGenome {
    /// Plan one generation of one campaign against `graph`, using the six
    /// built-in operators (OPFOR-01/04). Pure: identical arguments produce a
    /// byte-identical [`RedPlan`]. Infallible: the built-in operators only ever
    /// name graph techniques, so validation drops nothing.
    pub fn plan(
        seed: u64,
        generation: u32,
        campaign: &CampaignParams,
        graph: &TargetGraph,
    ) -> RedPlan {
        let operators = builtin_operators(campaign.steps_per_operator);
        let refs: Vec<&dyn RedOperator> = operators.iter().map(|operator| &**operator).collect();
        match Self::assemble(&refs, seed, generation, campaign, graph, Validation::Skip) {
            Ok(plan) => plan,
            // Skip never rejects, so this arm is dead; returning a valid empty
            // plan rather than reaching for a panic keeps the runtime contract.
            Err(_) => Self::empty_plan(seed, generation, campaign, graph),
        }
    }

    /// Plan with a caller-supplied operator set, validating every step against
    /// the graph. A step naming a technique the graph does not contain is
    /// rejected with [`RedSwarmError::UnknownTechnique`] (OPFOR-04). This is the
    /// entry the negative-control test drives with an operator that invents an
    /// id; the built-in [`RedGenome::plan`] cannot reach the error.
    pub fn plan_with_operators(
        operators: &[&dyn RedOperator],
        seed: u64,
        generation: u32,
        campaign: &CampaignParams,
        graph: &TargetGraph,
    ) -> Result<RedPlan, RedSwarmError> {
        Self::assemble(
            operators,
            seed,
            generation,
            campaign,
            graph,
            Validation::Reject,
        )
    }

    /// The effective seed: a generation shifts the whole stream by rotating its
    /// bits into the high half before the xor, so adjacent seeds and adjacent
    /// generations do not collide.
    fn effective_seed(seed: u64, generation: u32) -> u64 {
        seed ^ u64::from(generation).rotate_left(32)
    }

    /// The shared planning core. Forks a stream per operator (in call order) and
    /// one for jitter, collects each operator's proposal (feeding it the plan so
    /// far), round-robin interleaves the proposals up to `max_steps`, validates,
    /// remaps `Chain`/`Cover` references to final indices, and assigns offsets.
    fn assemble(
        operators: &[&dyn RedOperator],
        seed: u64,
        generation: u32,
        campaign: &CampaignParams,
        graph: &TargetGraph,
        validation: Validation,
    ) -> Result<RedPlan, RedSwarmError> {
        let rng_seed = Self::effective_seed(seed, generation);
        let mut root = RedGenomeRng::from_u64(rng_seed);

        // Fork one child per operator, in call order, then the jitter stream.
        // `so_far` accumulates the proposals in that order; because each
        // operator's `so_far` is a prefix of the whole, a reference an operator
        // records is a valid index into the global proposal order.
        let mut proposals: Vec<Vec<GeneStep>> = Vec::with_capacity(operators.len());
        let mut so_far: Vec<GeneStep> = Vec::new();
        for op in operators {
            let mut child = root.fork(op.role().stream_label());
            let steps = op.propose_steps(graph, &mut child, &so_far);
            so_far.extend(steps.iter().cloned());
            proposals.push(steps);
        }
        let mut jitter = root.fork(SCHEDULE_STREAM_LABEL);

        let max_steps = usize::from(campaign.max_steps);
        let mut steps = round_robin(&proposals, max_steps);

        // Validate against the graph (OPFOR-04). Reject fails the whole plan;
        // Skip drops the offending step, keeping the survivors contiguous.
        match validation {
            Validation::Reject => {
                for step in &steps {
                    if !graph.is_technique(&step.technique) {
                        return Err(RedSwarmError::UnknownTechnique {
                            technique: step.technique.clone(),
                        });
                    }
                }
            }
            Validation::Skip => {
                steps.retain(|step| graph.is_technique(&step.technique));
            }
        }

        // Resolve Chain/Cover references against FINAL order so none points
        // forward, then assign the monotone jittered schedule (own stream).
        resolve_back_references(&mut steps, &so_far);
        for (index, step) in steps.iter_mut().enumerate() {
            let jit = i64::try_from(jitter.next_below(JITTER_BOUND)).unwrap_or(0);
            let ordinal = i64::try_from(index).unwrap_or(0);
            step.offset_ms = ordinal * STEP_SPACING_MS + jit;
        }

        Ok(RedPlan {
            generation,
            campaign: campaign.name.clone(),
            graph_fingerprint: graph.fingerprint(),
            steps,
            determinism: Determinism {
                rng_seed,
                virtual_clock_start_ms: campaign.virtual_clock_start_ms,
                scheduler: SCHEDULER,
            },
        })
    }

    /// A valid, empty plan with the right determinism block. Only the dead
    /// error arm of [`RedGenome::plan`] reaches it.
    fn empty_plan(
        seed: u64,
        generation: u32,
        campaign: &CampaignParams,
        graph: &TargetGraph,
    ) -> RedPlan {
        RedPlan {
            generation,
            campaign: campaign.name.clone(),
            graph_fingerprint: graph.fingerprint(),
            steps: Vec::new(),
            determinism: Determinism {
                rng_seed: Self::effective_seed(seed, generation),
                virtual_clock_start_ms: campaign.virtual_clock_start_ms,
                scheduler: SCHEDULER,
            },
        }
    }
}

/// Round-robin interleave: take proposal `0` from each operator list in call
/// order, then proposal `1`, and so on, stopping at `max_steps`. The result is
/// the plan's final step order; references are resolved against it afterwards.
fn round_robin(proposals: &[Vec<GeneStep>], max_steps: usize) -> Vec<GeneStep> {
    let depth = proposals.iter().map(Vec::len).max().unwrap_or(0);
    let mut out: Vec<GeneStep> = Vec::new();
    for round in 0..depth {
        for list in proposals {
            if out.len() >= max_steps {
                return out;
            }
            if let Some(step) = list.get(round) {
                out.push(step.clone());
            }
        }
    }
    out
}

/// Resolve every `Chain{from}`/`Cover{step}` reference to point STRICTLY BACKWARD
/// in final order, so a Chain step names an earlier predecessor and a Cover step
/// an earlier noisy step -- never the referrer's own future.
///
/// An operator records its referent in PROPOSAL order (an index into the plan so
/// far it was handed). Round-robin interleaving can move that referent AFTER the
/// referring step in final order, which would make the reference point forward
/// (this happened at the documented smoke seed before this pass existed). So the
/// reference is resolved here, against final order: each referring step is
/// re-anchored to the nearest EARLIER final step of the correct kind -- for a
/// Chain step, a non-cover step in the kill-chain predecessor's class (read from
/// the referent the operator picked, so the planner needs no kill-chain table of
/// its own); for a Cover step, a preceding noisy (exploitation) step. If no such
/// referent exists -- which the default bounds never reach, since a Chain step is never
/// earlier than the fourth final slot and a Cover step never earlier than the
/// sixth -- the annotation drops to a plain intent rather than ship forward.
fn resolve_back_references(steps: &mut [GeneStep], so_far: &[GeneStep]) {
    // Snapshot each step's class, whether it is a noisy step, and whether it is
    // a benign cover step, from the pre-resolution intents, so the resolution
    // never depends on its own order.
    let classes: Vec<ThreatClass> = steps.iter().map(|s| s.threat_class.clone()).collect();
    let noisy: Vec<bool> = steps
        .iter()
        .map(|s| matches!(s.intent, StepIntent::Exploit))
        .collect();
    let is_cover: Vec<bool> = steps
        .iter()
        .map(|s| matches!(s.intent, StepIntent::Cover { .. }))
        .collect();

    for (index, step) in steps.iter_mut().enumerate() {
        let resolved = match &step.intent {
            StepIntent::Chain { from } => {
                // The class of the predecessor the operator chose is the
                // kill-chain predecessor of this step's class; re-anchor to the
                // nearest earlier NON-cover step of that class. Cover steps are
                // benign filler, and the operator never chains from one (Opsec
                // runs after Chain), so excluding them keeps the chain honest.
                let predecessor_class = so_far.get(*from).map(|s| s.threat_class.clone());
                match predecessor_class.and_then(|class| {
                    (0..index)
                        .rev()
                        .find(|&j| !is_cover[j] && classes[j] == class)
                }) {
                    Some(j) => StepIntent::Chain { from: j },
                    None => StepIntent::Exploit,
                }
            }
            StepIntent::Cover { .. } => match (0..index).rev().find(|&j| noisy[j]) {
                Some(j) => StepIntent::Cover { step: j },
                None => StepIntent::Probe,
            },
            other => other.clone(),
        };
        // A shipped Chain/Cover reference must point strictly backward. This
        // holds by construction (the search range is `0..index`); the debug
        // assertion is a regression tripwire, compiled out of the release daemon.
        match &resolved {
            StepIntent::Chain { from } => debug_assert!(*from < index),
            StepIntent::Cover { step } => debug_assert!(*step < index),
            _ => {}
        }
        step.intent = resolved;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

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
        TargetGraph::from_repo(&catalog_path(), &suite_paths()).unwrap()
    }

    fn campaign(max_steps: u16) -> CampaignParams {
        CampaignParams {
            name: "test_campaign".to_string(),
            virtual_clock_start_ms: 1_700_000_000_000,
            steps_per_operator: CampaignParams::DEFAULT_STEPS_PER_OPERATOR,
            max_steps,
        }
    }

    /// Every step names a real graph technique, over a wide seed/generation
    /// sweep, and each step's scenario and event indices are real (SC 3).
    #[test]
    fn every_generated_step_names_a_graph_technique() {
        let graph = repo_graph();
        let campaign = campaign(CampaignParams::DEFAULT_MAX_STEPS);
        for seed in 0..20u64 {
            for generation in 0..3u32 {
                let plan = RedGenome::plan(seed, generation, &campaign, &graph);
                for step in &plan.steps {
                    let node = graph.technique(&step.technique).unwrap_or_else(|| {
                        panic!("step named unknown technique {}", step.technique)
                    });
                    // Every step names a real technique. A cover step replays a
                    // benign-control scenario (not one of its technique's own);
                    // every other step's scenario is one the technique realises.
                    if matches!(step.intent, StepIntent::Cover { .. }) {
                        assert!(
                            graph.benign_scenarios().contains(&step.scenario),
                            "cover step scenario {:?} is not a benign one",
                            step.scenario
                        );
                    } else {
                        assert!(
                            node.scenarios.contains(&step.scenario),
                            "technique {} does not carry scenario {:?}",
                            step.technique,
                            step.scenario
                        );
                    }
                    assert!(!step.event_indices.is_empty());
                    for &index in &step.event_indices {
                        assert!(
                            index < step.scenario.event_count,
                            "event index {index} out of range for {:?}",
                            step.scenario
                        );
                    }
                }
            }
        }
    }

    /// An operator that invents a technique id is caught by the planner's
    /// validation: the negative control for the test above (SC 3).
    struct InventingOperator;

    impl RedOperator for InventingOperator {
        fn role(&self) -> OperatorRole {
            OperatorRole::Recon
        }

        fn propose_steps(
            &self,
            _graph: &TargetGraph,
            _rng: &mut RedGenomeRng,
            _so_far: &[GeneStep],
        ) -> Vec<GeneStep> {
            vec![GeneStep {
                operator: OperatorRole::Recon,
                technique: "T9999.999".to_string(),
                threat_class: ThreatClass::Discovery,
                scenario: ScenarioRef {
                    suite: "invented".to_string(),
                    scenario: "invented".to_string(),
                    event_count: 1,
                },
                event_indices: vec![0],
                host_slot: 0,
                offset_ms: 0,
                intent: StepIntent::Probe,
            }]
        }
    }

    #[test]
    fn the_planner_rejects_an_operator_that_invents_a_technique() {
        let graph = repo_graph();
        let campaign = campaign(CampaignParams::DEFAULT_MAX_STEPS);
        let inventing = InventingOperator;
        let operators: [&dyn RedOperator; 1] = [&inventing];
        let result = RedGenome::plan_with_operators(&operators, 7, 0, &campaign, &graph);
        match result {
            Err(RedSwarmError::UnknownTechnique { technique }) => {
                assert_eq!(technique, "T9999.999");
            }
            other => panic!("expected UnknownTechnique, got {other:?}"),
        }
    }

    /// Identical arguments produce byte-identical serialised plans (SC 2).
    #[test]
    fn plan_is_byte_identical_for_identical_arguments() {
        let graph = repo_graph();
        let campaign = campaign(CampaignParams::DEFAULT_MAX_STEPS);
        let first = RedGenome::plan(42, 1, &campaign, &graph);
        let second = RedGenome::plan(42, 1, &campaign, &graph);
        let first_bytes = serde_json::to_vec(&first).unwrap();
        let second_bytes = serde_json::to_vec(&second).unwrap();
        assert_eq!(first_bytes, second_bytes);
    }

    /// A twenty-seed sweep produces at least one differing step per seed: no two
    /// adjacent seeds plan the same campaign (SC 2).
    #[test]
    fn a_twenty_seed_sweep_differs_in_at_least_one_step_per_seed() {
        let graph = repo_graph();
        let campaign = campaign(CampaignParams::DEFAULT_MAX_STEPS);
        let plans: Vec<RedPlan> = (0..20u64)
            .map(|seed| RedGenome::plan(seed, 0, &campaign, &graph))
            .collect();
        for pair in plans.windows(2) {
            assert_ne!(
                pair[0].steps, pair[1].steps,
                "two adjacent seeds produced identical steps"
            );
        }
    }

    /// The scheduler string is pinned and all six roles appear in a full plan.
    #[test]
    fn each_operator_role_appears_and_the_scheduler_string_is_pinned() {
        let graph = repo_graph();
        let campaign = campaign(CampaignParams::DEFAULT_MAX_STEPS);
        let plan = RedGenome::plan(0, 0, &campaign, &graph);
        assert_eq!(plan.determinism.scheduler, "round_robin_v1");

        let roles: BTreeSet<OperatorRole> = plan.steps.iter().map(|s| s.operator).collect();
        for role in [
            OperatorRole::Recon,
            OperatorRole::Auth,
            OperatorRole::Injection,
            OperatorRole::Chain,
            OperatorRole::Evasion,
            OperatorRole::Opsec,
        ] {
            assert!(
                roles.contains(&role),
                "role {role:?} did not appear in the plan"
            );
        }
    }

    /// With a graph whose only techniques are scenario-less `impact` gaps, Recon
    /// and Auth find nothing applicable and propose nothing, and the plan is
    /// still valid (empty). Every operator is total.
    #[test]
    fn an_operator_with_nothing_applicable_proposes_nothing() {
        use crate::evasion_coverage::{
            EvasionTechniqueCatalog, EvasionTechniqueCatalogDetector, EvasionTechniqueGap,
        };
        use crate::red_swarm::graph::LoadedSuite;

        let catalog = EvasionTechniqueCatalog {
            schema_version: 1,
            suite: "scenario-suites/synthetic.yaml".to_string(),
            detectors: vec![EvasionTechniqueCatalogDetector {
                detector: "infrastructure_anomaly".to_string(),
                intentionally_uncovered: vec![EvasionTechniqueGap {
                    technique: "T1496".to_string(),
                    threat_class: ThreatClass::Impact,
                    rationale: "synthetic".to_string(),
                }],
            }],
        };
        // No suites, so the only technique (T1496) is a scenario-less gap: not
        // usable for a step, and not discovery/initial_access or credential/
        // lateral, so Recon and Auth have nothing.
        let suites: Vec<LoadedSuite> = Vec::new();
        let graph = TargetGraph::from_parts(&catalog, &suites);

        let recon = crate::red_swarm::operators::ReconOperator::new(3);
        let auth = crate::red_swarm::operators::AuthOperator::new(3);
        let mut rng = RedGenomeRng::from_u64(1);
        assert!(recon.propose_steps(&graph, &mut rng, &[]).is_empty());
        assert!(auth.propose_steps(&graph, &mut rng, &[]).is_empty());

        // The whole plan is valid and empty.
        let campaign = campaign(CampaignParams::DEFAULT_MAX_STEPS);
        let plan = RedGenome::plan(5, 0, &campaign, &graph);
        assert!(plan.steps.is_empty());
        assert_eq!(plan.determinism.scheduler, "round_robin_v1");
        assert_eq!(plan.graph_fingerprint, graph.fingerprint());
    }

    /// Offsets strictly increase and are a function of index and the planner's
    /// own jitter stream, never the wall clock (SC 4 / test 6).
    #[test]
    fn offsets_are_monotone_and_never_from_the_wall_clock() {
        let graph = repo_graph();
        let campaign = campaign(CampaignParams::DEFAULT_MAX_STEPS);
        let plan = RedGenome::plan(11, 2, &campaign, &graph);
        assert!(plan.steps.len() >= 2);
        for pair in plan.steps.windows(2) {
            assert!(
                pair[1].offset_ms > pair[0].offset_ms,
                "offsets are not strictly increasing: {} then {}",
                pair[0].offset_ms,
                pair[1].offset_ms
            );
        }
        // The first offset is below one full step of spacing, so it is a virtual
        // schedule value (index 0 * spacing + jitter), not a wall-clock stamp.
        assert!(plan.steps[0].offset_ms < STEP_SPACING_MS);
    }

    /// Every `Chain{from}` and `Cover{step}` reference names a strictly EARLIER
    /// step in final order: a Chain step chains from a predecessor, a Cover step
    /// covers a preceding noisy step. Round-robin ordering must never leave a
    /// reference pointing at the referrer's own future (seed 7 was a
    /// counterexample before references were resolved against final order).
    #[test]
    fn every_chain_and_cover_reference_points_strictly_backward() {
        let graph = repo_graph();
        let campaign = campaign(CampaignParams::DEFAULT_MAX_STEPS);
        for seed in 0..20u64 {
            for generation in 0..2u32 {
                let plan = RedGenome::plan(seed, generation, &campaign, &graph);
                for (index, step) in plan.steps.iter().enumerate() {
                    match &step.intent {
                        StepIntent::Chain { from } => assert!(
                            *from < index,
                            "seed {seed} gen {generation}: step {index} chains from {from}, not strictly earlier"
                        ),
                        StepIntent::Cover { step: covered } => assert!(
                            *covered < index,
                            "seed {seed} gen {generation}: step {index} covers {covered}, not strictly earlier"
                        ),
                        _ => {}
                    }
                }
            }
        }
    }
}
