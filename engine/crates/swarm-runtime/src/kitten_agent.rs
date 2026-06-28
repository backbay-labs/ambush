use crate::calico_agent::parse_calico_deception_interaction;
use crate::drafting::{DefaultEvolutionDraftingHarness, EvolutionDraftCreateRequest};
use crate::evasion_coverage::{
    actionable_gaps_for_detector, evaluate_repo_evasion_coverage, resolve_repo_root,
};
use crate::evolution::DefaultEvolutionProofHarness;
use crate::evolution_status::{FileKittenStatusStore, KittenExecutionState, KittenStatusRecord};
use crate::mutation::{
    DefaultEvolutionMutationHarness, EvolutionAdversarialPressureRequest,
    EvolutionAutonomousFitnessMeasurement, EvolutionAutonomousMutationSpecCreateRequest,
    EvolutionBenchmarkRunLookup, EvolutionBenchmarkRunReport, EvolutionEvasionGapFocus,
    EvolutionEvasionPressureInput, EvolutionMutationError, EvolutionPopulationCandidate,
    FileEvolutionBenchmarkStore, FileEvolutionPopulationStore, benchmark_fitness_delta,
    summarize_evolution_benchmark_baseline, summarize_evolution_benchmark_generation,
};
use crate::red_swarm::{SuiteRedSwarmAdapter, ThreatContext};
use crate::replay::{
    DefaultReplayHarness, DetectorCandidateManifest, DetectorVerificationRecord,
    DetectorVerificationReport, load_detector_experiment_manifest,
};
use crate::strategy::{
    DefaultStrategyScorecardHarness, StrategyAdvisoryRecommendation, StrategyMemoryOutcomeKind,
    StrategyMemoryRecord, StrategyScorecard, StrategyScorecardRecord,
};
use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use swarm_core::agent::{
    AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError, SwarmEvent,
};
use swarm_core::config::{EvolutionPathsConfig, SwarmConfig};
use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
use swarm_core::types::{
    AgentId, ProvidenceFeedbackAction, SPHINX_MEMORY_PHEROMONE_SCHEMA_VERSION,
    SPHINX_MEMORY_THREAT_CLASS, Severity, SphinxMemoryAnswer, SphinxMemoryPayloadKind,
    SphinxMemoryQuery, SwarmAction, SwarmFeedbackSignal,
};
use swarm_pheromone::{ConfiguredPheromoneSubstrate, DepositSigningPayload, PheromoneSubstrate};
use tokio::task::JoinHandle;

const MEMORY_QUERY_MIN_MATCHES: usize = 2;
const MEMORY_QUERY_MAX_WAIT_TICKS: u8 = 2;
const MEMORY_FITNESS_BLEND_WEIGHT: f64 = 0.25;
const DISMISS_FEEDBACK_FITNESS_PENALTY: f64 = 0.20;

pub struct KittenAgent {
    id: AgentId,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    substrate: ConfiguredPheromoneSubstrate,
    role: AgentRole,
    health: AgentHealth,
    config_path: PathBuf,
    runtime_config: SwarmConfig,
    drift_detector: ConceptDriftDetector,
    state: KittenState,
    #[cfg(test)]
    last_cycle_error: Option<String>,
}

#[allow(clippy::large_enum_variant)]
enum KittenState {
    AwaitingDrift,
    Mutating(PendingMutationCycle),
    Evaluating(RunningValidationCycle),
    Verifying(ReadyValidationCycle),
    AwaitingMemory(PendingMemoryRetrieval),
    Proposing(ProposedCandidate),
}

struct PendingMutationCycle {
    assessment: DriftAssessment,
}

struct RunningValidationCycle {
    cycle: MutationCycle,
    task: JoinHandle<Result<ValidationTaskOutput, String>>,
}

struct ReadyValidationCycle {
    cycle: MutationCycle,
    validation: ValidationTaskOutput,
}

#[derive(Clone)]
struct MutationCycle {
    observation_count: usize,
    degraded_ratio: f64,
    pressure_source: PressureSource,
    pressure_id: String,
    evasion_pressure: Option<EvolutionEvasionPressureInput>,
    draft_id: String,
    mutation_spec_id: String,
    materialization_batch_id: String,
}

struct PendingMemoryRetrieval {
    proposal: ProposedCandidate,
    query: SphinxMemoryQuery,
    waited_ticks: u8,
}

struct ProposedCandidate {
    generation: usize,
    generation_created_at_ms: i64,
    ranking_id: String,
    validation_batch_id: String,
    strategy_id: String,
    experiment_id: String,
    experiment_path: PathBuf,
    materialization_id: String,
    validation_bundle_id: String,
    base_fitness: f64,
    fitness: f64,
    autonomous_fitness: Option<EvolutionAutonomousFitnessMeasurement>,
    strategy: Value,
}

struct ValidationTaskOutput {
    validation_batch_id: String,
}

#[derive(Debug, Clone)]
pub struct EvolutionBenchmarkRequest {
    pub benchmark_id: String,
    pub label: String,
    pub generation_count: usize,
    pub baseline_experiment_path: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum EvolutionBenchmarkError {
    #[error(transparent)]
    Replay(#[from] crate::replay::ReplayHarnessError),

    #[error(transparent)]
    Strategy(#[from] crate::strategy::StrategyAdvisorError),

    #[error(transparent)]
    Drafting(#[from] crate::drafting::EvolutionDraftingError),

    #[error(transparent)]
    Mutation(#[from] EvolutionMutationError),

    #[error(transparent)]
    BenchmarkStore(#[from] crate::mutation::EvolutionBenchmarkStoreError),

    #[error("failed to build benchmark evasion pressure input: {0}")]
    EvasionPressure(String),

    #[error("benchmark validation task failed: {0}")]
    ValidationTask(String),

    #[error("invalid benchmark request: {reason}")]
    InvalidRequest { reason: String },

    #[error("benchmark run `{benchmark_id}` could not be reloaded after persistence")]
    MissingPersistedRun { benchmark_id: String },
}

#[derive(Debug, Clone)]
struct DriftAssessment {
    observation_count: usize,
    degraded_count: usize,
    degraded_ratio: f64,
    pressure_source: Option<PressureSource>,
}

#[derive(Debug, Clone)]
enum PressureSource {
    Scorecard { scorecard_id: String },
    Verification { verification_id: String },
}

struct ConceptDriftDetector {
    config: swarm_core::config::EvolutionConfig,
    last_cycle_completed_at_ms: Option<i64>,
}

#[derive(Debug, Clone)]
struct ResolvedEvolutionPaths {
    replay_results_dir: PathBuf,
    experiment_results_dir: PathBuf,
    verification_results_dir: PathBuf,
    shadow_results_dir: PathBuf,
    strategy_memory_results_dir: PathBuf,
    strategy_scorecard_results_dir: PathBuf,
    evolution_proof_results_dir: PathBuf,
    evolution_queue_results_dir: PathBuf,
    evolution_pressure_results_dir: PathBuf,
    evolution_draft_results_dir: PathBuf,
    evolution_draft_promotion_results_dir: PathBuf,
    evolution_materialization_results_dir: PathBuf,
    evolution_validation_results_dir: PathBuf,
    evolution_reconciliation_results_dir: PathBuf,
    evolution_mutation_results_dir: PathBuf,
    evolution_mutation_materialization_batch_results_dir: PathBuf,
    evolution_mutation_validation_batch_results_dir: PathBuf,
    evolution_ranking_results_dir: PathBuf,
    evolution_population_results_dir: PathBuf,
}

#[derive(Debug, Deserialize)]
struct RecordIndex<T> {
    entries: Vec<T>,
}

#[derive(Debug)]
struct DriftObservation {
    observed_at_ms: i64,
    degraded: bool,
    pressure_source: Option<PressureSource>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackSignalDisposition {
    Applied,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KittenFeedbackSignalRecord {
    pub signal_id: String,
    pub recorded_at_ms: i64,
    pub action: ProvidenceFeedbackAction,
    pub incident_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_class: Option<ThreatClass>,
    pub analyst_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub disposition: FeedbackSignalDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub penalty_applied: Option<f64>,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct KittenFeedbackRoutingResult {
    pub disposition: FeedbackSignalDisposition,
    pub penalty_applied: Option<f64>,
    pub details: String,
}

#[derive(Debug, Clone)]
struct FileKittenFeedbackStore {
    path: PathBuf,
}

impl FileKittenFeedbackStore {
    fn open(root: impl AsRef<Path>) -> Result<Self, String> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)
            .map_err(|error| format!("failed to create kitten feedback store root: {error}"))?;
        Ok(Self {
            path: root.join("feedback-signals.jsonl"),
        })
    }

    fn append(&self, record: &KittenFeedbackSignalRecord) -> Result<(), String> {
        use std::io::Write;

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| format!("failed to open kitten feedback store: {error}"))?;
        let line = serde_json::to_string(record)
            .map_err(|error| format!("failed to encode kitten feedback signal: {error}"))?;
        writeln!(file, "{line}")
            .map_err(|error| format!("failed to append kitten feedback signal: {error}"))
    }

    #[cfg(test)]
    fn load(&self) -> Result<Vec<KittenFeedbackSignalRecord>, String> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let raw = fs::read_to_string(&self.path)
            .map_err(|error| format!("failed to read kitten feedback store: {error}"))?;
        raw.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line)
                    .map_err(|error| format!("failed to parse kitten feedback signal: {error}"))
            })
            .collect()
    }
}

#[cfg(test)]
pub fn load_feedback_signal_records(
    root: impl AsRef<Path>,
) -> Result<Vec<KittenFeedbackSignalRecord>, String> {
    FileKittenFeedbackStore::open(root)?.load()
}

pub fn route_feedback_signal(
    config_path: &Path,
    runtime_config: &SwarmConfig,
    kitten_deployed: bool,
    signal: &SwarmFeedbackSignal,
) -> Result<KittenFeedbackRoutingResult, String> {
    let paths = resolve_evolution_paths(config_path, &runtime_config.evolution.paths);
    let store = FileKittenFeedbackStore::open(&paths.evolution_population_results_dir)?;
    let mut record = KittenFeedbackSignalRecord {
        signal_id: format!(
            "feedback:{}:{}:{}",
            sanitize_id(&signal.incident_id),
            sanitize_id(signal.finding_id.as_deref().unwrap_or("unknown")),
            signal.recorded_at_ms.max(1)
        ),
        recorded_at_ms: signal.recorded_at_ms.max(1),
        action: signal.action,
        incident_id: signal.incident_id.clone(),
        finding_id: signal.finding_id.clone(),
        strategy_id: signal.strategy_id.clone(),
        threat_class: signal.threat_class.clone(),
        analyst_id: signal.analyst_id.clone(),
        reason: signal.reason.clone(),
        disposition: FeedbackSignalDisposition::Pending,
        penalty_applied: None,
        details: String::new(),
    };

    if signal.action != ProvidenceFeedbackAction::Dismiss {
        record.details = "only dismiss feedback is routed into kitten fitness".to_string();
        store.append(&record)?;
        return Ok(KittenFeedbackRoutingResult {
            disposition: record.disposition,
            penalty_applied: None,
            details: record.details,
        });
    }

    if !runtime_config.evolution.enabled {
        record.details =
            "evolution is disabled; feedback persisted for later consumption".to_string();
        store.append(&record)?;
        return Ok(KittenFeedbackRoutingResult {
            disposition: record.disposition,
            penalty_applied: None,
            details: record.details,
        });
    }

    if !kitten_deployed {
        record.details =
            "kitten is not deployed; feedback persisted for later consumption".to_string();
        store.append(&record)?;
        return Ok(KittenFeedbackRoutingResult {
            disposition: record.disposition,
            penalty_applied: None,
            details: record.details,
        });
    }

    let Some(strategy_id) = signal.strategy_id.as_deref() else {
        record.details =
            "dismiss feedback could not resolve a strategy_id; persisted as pending".to_string();
        store.append(&record)?;
        return Ok(KittenFeedbackRoutingResult {
            disposition: record.disposition,
            penalty_applied: None,
            details: record.details,
        });
    };

    let population_store =
        FileEvolutionPopulationStore::open(&paths.evolution_population_results_dir)
            .map_err(|error| error.to_string())?;
    let Some(mut state) = population_store.load().map_err(|error| error.to_string())? else {
        record.details =
            "no durable kitten population exists yet; feedback persisted as pending".to_string();
        store.append(&record)?;
        return Ok(KittenFeedbackRoutingResult {
            disposition: record.disposition,
            penalty_applied: None,
            details: record.details,
        });
    };

    let Some(candidate) = state
        .members
        .iter_mut()
        .find(|candidate| candidate.strategy_id == strategy_id)
    else {
        record.details = format!(
            "no durable kitten population candidate matched strategy `{strategy_id}`; feedback persisted as pending"
        );
        store.append(&record)?;
        return Ok(KittenFeedbackRoutingResult {
            disposition: record.disposition,
            penalty_applied: None,
            details: record.details,
        });
    };

    penalize_candidate(candidate);
    rerank_population_members(&mut state.members);
    state.updated_at_ms = record.recorded_at_ms;
    population_store
        .persist(&state)
        .map_err(|error| error.to_string())?;

    record.disposition = FeedbackSignalDisposition::Applied;
    record.penalty_applied = Some(DISMISS_FEEDBACK_FITNESS_PENALTY);
    record.details = format!("applied analyst false-positive penalty to strategy `{strategy_id}`");
    store.append(&record)?;
    Ok(KittenFeedbackRoutingResult {
        disposition: record.disposition,
        penalty_applied: record.penalty_applied,
        details: record.details,
    })
}

fn penalize_candidate(candidate: &mut EvolutionPopulationCandidate) {
    candidate.fitness = (candidate.fitness - DISMISS_FEEDBACK_FITNESS_PENALTY).max(0.0);
    if !candidate
        .blocking_reason_names
        .iter()
        .any(|reason| reason == "analyst_false_positive_feedback")
    {
        candidate
            .blocking_reason_names
            .push("analyst_false_positive_feedback".to_string());
    }
    if !candidate
        .summary
        .contains("analyst false-positive feedback")
    {
        candidate.summary = format!("{} | analyst false-positive feedback", candidate.summary);
    }
}

fn rerank_population_members(candidates: &mut [EvolutionPopulationCandidate]) {
    candidates.sort_by(|left, right| {
        right
            .fitness
            .partial_cmp(&left.fitness)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.strategy_id.cmp(&right.strategy_id))
    });
    for (index, candidate) in candidates.iter_mut().enumerate() {
        candidate.population_rank = index + 1;
    }
}

impl KittenAgent {
    pub fn new(
        id: AgentId,
        config_path: impl Into<PathBuf>,
        runtime_config: SwarmConfig,
        substrate: ConfiguredPheromoneSubstrate,
    ) -> Self {
        Self::new_with_signing_key(
            id,
            SigningKey::generate(&mut OsRng),
            config_path,
            runtime_config,
            substrate,
        )
    }

    pub fn new_with_signing_key(
        id: AgentId,
        signing_key: SigningKey,
        config_path: impl Into<PathBuf>,
        runtime_config: SwarmConfig,
        substrate: ConfiguredPheromoneSubstrate,
    ) -> Self {
        let verifying_key = signing_key.verifying_key();

        Self {
            id,
            signing_key,
            verifying_key,
            substrate,
            role: AgentRole::Kitten,
            health: AgentHealth::Healthy,
            config_path: config_path.into(),
            drift_detector: ConceptDriftDetector::new(runtime_config.evolution.clone()),
            runtime_config,
            state: KittenState::AwaitingDrift,
            #[cfg(test)]
            last_cycle_error: None,
        }
    }

    fn handle_cycle_error(&mut self, now_ms: i64, error: impl AsRef<str>) -> KittenState {
        self.health = AgentHealth::Degraded;
        self.drift_detector.note_cycle_completed(now_ms);
        #[cfg(test)]
        {
            self.last_cycle_error = Some(error.as_ref().to_string());
        }
        tracing::warn!(
            agent_id = %self.id,
            reason = %error.as_ref(),
            module = module_path!(),
            "kitten cycle failed"
        );
        KittenState::AwaitingDrift
    }

    fn start_mutation_cycle(
        &self,
        assessment: DriftAssessment,
        now_ms: i64,
    ) -> Result<KittenState, String> {
        let paths =
            resolve_evolution_paths(&self.config_path, &self.runtime_config.evolution.paths);
        let drafting = DefaultEvolutionDraftingHarness::from_config(
            self.config_path.clone(),
            self.runtime_config.clone(),
            &paths.evolution_pressure_results_dir,
            &paths.evolution_draft_results_dir,
            &paths.evolution_draft_promotion_results_dir,
            &paths.evolution_materialization_results_dir,
            &paths.evolution_validation_results_dir,
            &paths.evolution_reconciliation_results_dir,
        )
        .map_err(|error| error.to_string())?;
        let mutation = DefaultEvolutionMutationHarness::from_path(
            &paths.evolution_mutation_results_dir,
            &paths.evolution_mutation_materialization_batch_results_dir,
            &paths.evolution_mutation_validation_batch_results_dir,
            &paths.evolution_ranking_results_dir,
        )
        .map_err(|error| error.to_string())?;

        let pressure = match assessment
            .pressure_source
            .clone()
            .ok_or_else(|| "concept drift lacked a supported pressure source".to_string())?
        {
            PressureSource::Scorecard { scorecard_id } => {
                let scorecards = DefaultStrategyScorecardHarness::from_config(
                    self.config_path.clone(),
                    self.runtime_config.clone(),
                    &paths.strategy_memory_results_dir,
                    &paths.strategy_scorecard_results_dir,
                )
                .map_err(|error| error.to_string())?;
                (
                    PressureSource::Scorecard {
                        scorecard_id: scorecard_id.clone(),
                    },
                    drafting
                        .create_pressure_from_scorecard(&scorecards, &scorecard_id)
                        .map_err(|error| error.to_string())?,
                )
            }
            PressureSource::Verification { verification_id } => {
                let replay = DefaultReplayHarness::from_config(
                    self.config_path.clone(),
                    self.runtime_config.clone(),
                    &paths.replay_results_dir,
                )
                .map_err(|error| error.to_string())?;
                (
                    PressureSource::Verification {
                        verification_id: verification_id.clone(),
                    },
                    drafting
                        .create_pressure_from_verification(
                            &replay,
                            &paths.verification_results_dir,
                            &verification_id,
                        )
                        .map_err(|error| error.to_string())?,
                )
            }
        };

        let evasion_pressure = self.current_evasion_pressure_input()?;
        let candidate_root = sanitize_id(&format!("{}_kitten", pressure.1.report.strategy_id));
        let draft = drafting
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.1.report.pressure_id.clone(),
                strategy_id: format!("{candidate_root}_{now_ms}"),
                strategy_description: format!(
                    "Kitten candidate derived from {}",
                    pressure.1.report.strategy_description
                ),
                mutation: "runtime_drift_response".to_string(),
                rationale: format!(
                    "Runtime drift detector observed {} degraded observations out of {} ({:.2} degraded ratio)",
                    assessment.degraded_count,
                    assessment.observation_count,
                    assessment.degraded_ratio
                ),
            })
            .map_err(|error| error.to_string())?;

        let spec = mutation
            .create_autonomous_mutation_spec(
                &drafting,
                &paths.evolution_population_results_dir,
                EvolutionAutonomousMutationSpecCreateRequest {
                    draft_id: draft.report.draft_id.clone(),
                    strategy_root: draft.report.strategy_id.clone(),
                    rationale: draft.report.lineage_rationale.clone(),
                    max_variants: self.runtime_config.evolution.max_variants_per_cycle.max(1),
                    base_experiment_path: None,
                    evasion_pressure: evasion_pressure.clone(),
                },
            )
            .map_err(|error| error.to_string())?;

        let batch = mutation
            .materialize_batch(&drafting, &spec.report.mutation_spec_id)
            .map_err(|error| error.to_string())?;

        let config_path = self.config_path.clone();
        let runtime_config = self.runtime_config.clone();
        let task_paths = paths.clone();
        let batch_id = batch.report.batch_id.clone();
        let validation_task = tokio::spawn(async move {
            run_validation_task(config_path, runtime_config, task_paths, batch_id).await
        });

        Ok(KittenState::Evaluating(RunningValidationCycle {
            cycle: MutationCycle {
                observation_count: assessment.observation_count,
                degraded_ratio: assessment.degraded_ratio,
                pressure_source: pressure.0,
                pressure_id: pressure.1.report.pressure_id.clone(),
                evasion_pressure,
                draft_id: draft.report.draft_id.clone(),
                mutation_spec_id: spec.report.mutation_spec_id.clone(),
                materialization_batch_id: batch.report.batch_id.clone(),
            },
            task: validation_task,
        }))
    }

    fn finish_validation_cycle(
        &self,
        ready: ReadyValidationCycle,
        now_ms: i64,
    ) -> Result<KittenState, String> {
        let paths =
            resolve_evolution_paths(&self.config_path, &self.runtime_config.evolution.paths);
        let drafting = DefaultEvolutionDraftingHarness::from_config(
            self.config_path.clone(),
            self.runtime_config.clone(),
            &paths.evolution_pressure_results_dir,
            &paths.evolution_draft_results_dir,
            &paths.evolution_draft_promotion_results_dir,
            &paths.evolution_materialization_results_dir,
            &paths.evolution_validation_results_dir,
            &paths.evolution_reconciliation_results_dir,
        )
        .map_err(|error| error.to_string())?;
        let mutation = DefaultEvolutionMutationHarness::from_path(
            &paths.evolution_mutation_results_dir,
            &paths.evolution_mutation_materialization_batch_results_dir,
            &paths.evolution_mutation_validation_batch_results_dir,
            &paths.evolution_ranking_results_dir,
        )
        .map_err(|error| error.to_string())?;

        let ranking = mutation
            .rank_candidates(
                &paths.evolution_queue_results_dir,
                &ready.validation.validation_batch_id,
                self.runtime_config.evolution.shortlist_count,
            )
            .map_err(|error| error.to_string())?;

        mutation
            .refresh_population(
                &paths.evolution_population_results_dir,
                &drafting,
                &paths.experiment_results_dir,
                &paths.verification_results_dir,
                &ranking.report,
                self.runtime_config.evolution.population_size,
                self.runtime_config.evolution.pareto_tournament_size,
                &self.runtime_config.evolution.fitness_weights,
                ready.cycle.evasion_pressure.as_ref(),
            )
            .map_err(|error| error.to_string())?;

        let Some(candidate) = mutation
            .select_population_candidate(
                &paths.evolution_population_results_dir,
                self.runtime_config.evolution.max_proposals_per_hour,
                now_ms,
            )
            .map_err(|error| error.to_string())?
        else {
            tracing::info!(
                agent_id = %self.id,
                mutation_spec_id = %ready.cycle.mutation_spec_id,
                validation_batch_id = %ready.validation.validation_batch_id,
                ranking_id = %ranking.report.ranking_id,
                module = module_path!(),
                "kitten validation cycle refreshed the durable population without an immediately proposal-ready candidate"
            );
            return Ok(KittenState::AwaitingDrift);
        };

        Ok(KittenState::Proposing(self.build_population_proposal(
            &paths,
            candidate,
            "fresh_validation_cycle",
            Some(&ready.cycle),
        )?))
    }

    fn restore_population_candidate(&self, now_ms: i64) -> Result<Option<KittenState>, String> {
        let paths =
            resolve_evolution_paths(&self.config_path, &self.runtime_config.evolution.paths);
        let mutation = DefaultEvolutionMutationHarness::from_path(
            &paths.evolution_mutation_results_dir,
            &paths.evolution_mutation_materialization_batch_results_dir,
            &paths.evolution_mutation_validation_batch_results_dir,
            &paths.evolution_ranking_results_dir,
        )
        .map_err(|error| error.to_string())?;
        let Some(candidate) = mutation
            .select_population_candidate(
                &paths.evolution_population_results_dir,
                self.runtime_config.evolution.max_proposals_per_hour,
                now_ms,
            )
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        Ok(Some(KittenState::Proposing(
            self.build_population_proposal(&paths, candidate, "restored_population", None)?,
        )))
    }

    fn build_population_proposal(
        &self,
        paths: &ResolvedEvolutionPaths,
        candidate: crate::mutation::EvolutionPopulationCandidate,
        selection_source: &str,
        cycle: Option<&MutationCycle>,
    ) -> Result<ProposedCandidate, String> {
        let drafting = DefaultEvolutionDraftingHarness::from_config(
            self.config_path.clone(),
            self.runtime_config.clone(),
            &paths.evolution_pressure_results_dir,
            &paths.evolution_draft_results_dir,
            &paths.evolution_draft_promotion_results_dir,
            &paths.evolution_materialization_results_dir,
            &paths.evolution_validation_results_dir,
            &paths.evolution_reconciliation_results_dir,
        )
        .map_err(|error| error.to_string())?;
        let validation = drafting
            .load_validation_bundle(&candidate.validation_bundle_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| {
                format!(
                    "missing validation bundle `{}` for kitten population candidate",
                    candidate.validation_bundle_id
                )
            })?;
        let materialization = drafting
            .load_materialization(&candidate.materialization_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| {
                format!(
                    "missing materialization `{}` for kitten population candidate",
                    candidate.materialization_id
                )
            })?;
        let replay_fitness = candidate.baseline_fitness.unwrap_or(candidate.fitness);
        let evasion_adjusted_fitness = candidate.fitness;
        let evasion_pressure = candidate.evasion_pressure.clone();

        let mut strategy = json!({
            "source": "kitten_population_candidate",
            "selection_source": selection_source,
            "population_rank": candidate.population_rank,
            "pareto_front": candidate.pareto_front,
            "ranking_id": candidate.ranking_id,
            "validation_batch_id": candidate.validation_batch_id,
            "validation_bundle_id": validation.report.validation_bundle_id,
            "materialization_id": materialization.report.materialization_id,
            "experiment_id": materialization.report.experiment_id,
            "experiment_path": materialization.report.experiment_path,
            "strategy_description": materialization.report.strategy_description,
            "lineage": materialization.report.lineage,
            "profile": materialization.report.profile,
            "proof_status": validation.report.proof_status,
            "advisory": validation.report.advisory,
            "summary": candidate.summary,
            "ranking_score": candidate.ranking_score,
            "population_fitness": evasion_adjusted_fitness,
            "population_fitness_replay": replay_fitness,
            "population_fitness_evasion": evasion_adjusted_fitness,
            "fitness_objectives": candidate.objectives,
        });
        if let Some(cycle) = cycle
            && let Some(strategy_object) = strategy.as_object_mut()
        {
            strategy_object.insert(
                "observation_count".to_string(),
                serde_json::Value::from(cycle.observation_count),
            );
            strategy_object.insert(
                "degraded_ratio".to_string(),
                serde_json::Value::from(cycle.degraded_ratio),
            );
            strategy_object.insert(
                "pressure_source".to_string(),
                serde_json::Value::from(pressure_source_label(&cycle.pressure_source)),
            );
            strategy_object.insert(
                "pressure_id".to_string(),
                serde_json::Value::from(cycle.pressure_id.clone()),
            );
            strategy_object.insert(
                "draft_id".to_string(),
                serde_json::Value::from(cycle.draft_id.clone()),
            );
            strategy_object.insert(
                "mutation_spec_id".to_string(),
                serde_json::Value::from(cycle.mutation_spec_id.clone()),
            );
            strategy_object.insert(
                "materialization_batch_id".to_string(),
                serde_json::Value::from(cycle.materialization_batch_id.clone()),
            );
        }
        if let Some(strategy_object) = strategy.as_object_mut()
            && let Some(evasion_pressure) = evasion_pressure
        {
            strategy_object.insert(
                "evasion_pressure".to_string(),
                serde_json::to_value(evasion_pressure)
                    .map_err(|error| format!("failed to encode evasion pressure: {error}"))?,
            );
        }

        Ok(ProposedCandidate {
            generation: candidate.generation,
            generation_created_at_ms: candidate.generation_created_at_ms,
            ranking_id: candidate.ranking_id,
            validation_batch_id: candidate.validation_batch_id,
            strategy_id: candidate.strategy_id,
            experiment_id: materialization.report.experiment_id,
            experiment_path: PathBuf::from(materialization.report.experiment_path),
            materialization_id: materialization.report.materialization_id,
            validation_bundle_id: validation.report.validation_bundle_id,
            base_fitness: evasion_adjusted_fitness,
            fitness: evasion_adjusted_fitness,
            autonomous_fitness: candidate.autonomous_fitness.clone(),
            strategy,
        })
    }

    async fn maybe_begin_memory_query(
        &mut self,
        env: &SwarmEnvironment,
        proposal: ProposedCandidate,
        now_ms: i64,
    ) -> Result<(KittenState, Vec<SwarmAction>), String> {
        if !self.runtime_config.memory.enabled {
            let proposal = self.apply_adversarial_pressure(proposal, now_ms).await?;
            return Ok((KittenState::Proposing(proposal), Vec::new()));
        }
        let Some(query) = self.build_memory_query(env, &proposal, now_ms) else {
            let proposal = self.apply_adversarial_pressure(proposal, now_ms).await?;
            return Ok((KittenState::Proposing(proposal), Vec::new()));
        };
        let indicator = serde_json::to_value(&query)
            .map_err(|error| format!("failed to encode Sphinx memory query: {error}"))?;
        let deposit = signed_memory_pheromone_deposit(
            &self.signing_key,
            &self.id,
            &self.runtime_config,
            env.now,
            indicator.clone(),
        )?;
        self.substrate
            .deposit(deposit)
            .await
            .map_err(|error| format!("failed to deposit Sphinx memory query: {error}"))?;
        Ok((
            KittenState::AwaitingMemory(PendingMemoryRetrieval {
                proposal,
                query,
                waited_ticks: 0,
            }),
            vec![SwarmAction::DepositPheromone {
                threat_class: SPHINX_MEMORY_THREAT_CLASS.to_string(),
                severity: Severity::Low,
                indicator,
                confidence: 0.0,
            }],
        ))
    }

    fn build_memory_query(
        &self,
        env: &SwarmEnvironment,
        proposal: &ProposedCandidate,
        now_ms: i64,
    ) -> Option<SphinxMemoryQuery> {
        let context = MemoryQueryContext::from_env(env);
        if context.observation_count == 0 {
            return None;
        }
        let selection_source = proposal
            .strategy
            .get("selection_source")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        Some(SphinxMemoryQuery {
            schema_version: SPHINX_MEMORY_PHEROMONE_SCHEMA_VERSION,
            kind: SphinxMemoryPayloadKind::Query,
            query_id: format!(
                "sphinx_query:{}:{now_ms}",
                sanitize_id(&proposal.strategy_id)
            ),
            requested_by_agent_id: self.id.to_string(),
            strategy_id: proposal.strategy_id.clone(),
            selection_source,
            observation_count: context.observation_count,
            base_fitness: proposal.base_fitness,
            requested_at_ms: now_ms,
            threat_classes: context.threat_classes,
            attack_technique_ids: context.attack_technique_ids,
            entity_values: context.entity_values,
        })
    }

    fn apply_memory_answer(
        &self,
        mut proposal: ProposedCandidate,
        answer: &SphinxMemoryAnswer,
    ) -> Result<ProposedCandidate, String> {
        let q_value_score = q_value_style_memory_score(proposal.base_fitness, answer);
        let fitness = proposal.base_fitness * (1.0 - MEMORY_FITNESS_BLEND_WEIGHT)
            + q_value_score * MEMORY_FITNESS_BLEND_WEIGHT;
        let memory_retrieval = json!({
            "query_id": answer.query_id,
            "matching_engagement_count": answer.matching_engagement_count,
            "retrieval_score": answer.retrieval_score,
            "q_value_score": q_value_score,
            "fallback_applied": answer.sparse,
            "answered_at_ms": answer.answered_at_ms,
            "answered_by_agent_id": answer.answered_by_agent_id,
            "contributions": answer.contributions,
        });
        let Some(strategy_object) = proposal.strategy.as_object_mut() else {
            return Err("kitten proposal payload was not an object".to_string());
        };
        let replay_fitness = strategy_object
            .get("population_fitness_replay")
            .and_then(Value::as_f64)
            .unwrap_or(proposal.base_fitness);
        let evasion_adjusted_fitness = strategy_object
            .get("population_fitness_evasion")
            .and_then(Value::as_f64)
            .unwrap_or(proposal.base_fitness);
        strategy_object.insert("population_fitness".to_string(), Value::from(fitness));
        strategy_object.insert(
            "population_fitness_memory".to_string(),
            Value::from(fitness),
        );
        strategy_object.insert(
            "population_fitness_replay".to_string(),
            Value::from(replay_fitness),
        );
        strategy_object.insert(
            "population_fitness_evasion".to_string(),
            Value::from(evasion_adjusted_fitness),
        );
        strategy_object.insert("memory_retrieval".to_string(), memory_retrieval);
        proposal.fitness = fitness;
        Ok(proposal)
    }

    fn apply_memory_fallback(
        &self,
        mut proposal: ProposedCandidate,
        query: &SphinxMemoryQuery,
        reason: &str,
    ) -> Result<ProposedCandidate, String> {
        let Some(strategy_object) = proposal.strategy.as_object_mut() else {
            return Err("kitten proposal payload was not an object".to_string());
        };
        let replay_fitness = strategy_object
            .get("population_fitness_replay")
            .and_then(Value::as_f64)
            .unwrap_or(proposal.base_fitness);
        let evasion_adjusted_fitness = strategy_object
            .get("population_fitness_evasion")
            .and_then(Value::as_f64)
            .unwrap_or(proposal.base_fitness);
        strategy_object.insert(
            "population_fitness".to_string(),
            Value::from(proposal.base_fitness),
        );
        strategy_object.insert(
            "population_fitness_memory".to_string(),
            Value::from(proposal.base_fitness),
        );
        strategy_object.insert(
            "population_fitness_replay".to_string(),
            Value::from(replay_fitness),
        );
        strategy_object.insert(
            "population_fitness_evasion".to_string(),
            Value::from(evasion_adjusted_fitness),
        );
        strategy_object.insert(
            "memory_retrieval".to_string(),
            json!({
                "query_id": query.query_id,
                "status": "fallback",
                "reason": reason,
                "fallback_applied": true,
                "retrieval_score": proposal.base_fitness,
                "q_value_score": proposal.base_fitness,
                "matching_engagement_count": 0,
                "contributions": [],
            }),
        );
        proposal.fitness = proposal.base_fitness;
        Ok(proposal)
    }

    fn apply_deception_signal(
        &self,
        mut proposal: ProposedCandidate,
        env: &SwarmEnvironment,
    ) -> Result<ProposedCandidate, String> {
        let interactions = env
            .pheromones
            .iter()
            .filter_map(|deposit| {
                if deposit.agent_role != Some(AgentRole::Calico) {
                    return None;
                }
                parse_calico_deception_interaction(&deposit.indicator)
                    .map(|payload| (deposit, payload))
            })
            .collect::<Vec<_>>();
        let Some(strategy_object) = proposal.strategy.as_object_mut() else {
            return Err("kitten proposal payload was not an object".to_string());
        };

        if interactions.is_empty() {
            strategy_object.insert(
                "population_fitness_deception".to_string(),
                Value::from(proposal.fitness),
            );
            strategy_object.insert(
                "deception_signal".to_string(),
                json!({
                    "signal_count": 0,
                    "signal_score": 0.0,
                    "fitness_weight": self.runtime_config.deception.interaction_fitness_weight,
                    "triggered_assets": [],
                    "playbook_entries": [],
                }),
            );
            return Ok(proposal);
        }

        let signal_count = interactions.len();
        let severity_confidence = interactions
            .iter()
            .map(|(deposit, _)| {
                deception_signal_severity_weight(deposit.severity) * deposit.confidence
            })
            .sum::<f64>()
            / signal_count as f64;
        let density_score = (signal_count as f64 / 3.0).clamp(0.0, 1.0);
        let signal_score = (severity_confidence * 0.7 + density_score * 0.3).clamp(0.0, 1.0);
        let adjusted_fitness = (proposal.fitness
            + (1.0 - proposal.fitness)
                * signal_score
                * self.runtime_config.deception.interaction_fitness_weight)
            .clamp(0.0, 1.0);
        let triggered_assets = interactions
            .iter()
            .map(|(_, payload)| payload.asset_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let playbook_entries = interactions
            .iter()
            .map(|(_, payload)| payload.playbook_entry.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let matched_values = interactions
            .iter()
            .map(|(_, payload)| payload.matched_value.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let strongest_confidence = interactions
            .iter()
            .map(|(deposit, _)| deposit.confidence)
            .fold(0.0_f64, f64::max);

        strategy_object.insert(
            "population_fitness_deception".to_string(),
            Value::from(adjusted_fitness),
        );
        strategy_object.insert(
            "deception_signal".to_string(),
            json!({
                "signal_count": signal_count,
                "signal_score": signal_score,
                "fitness_weight": self.runtime_config.deception.interaction_fitness_weight,
                "strongest_confidence": strongest_confidence,
                "triggered_assets": triggered_assets,
                "playbook_entries": playbook_entries,
                "matched_values": matched_values,
            }),
        );
        proposal.fitness = adjusted_fitness;
        Ok(proposal)
    }

    async fn apply_adversarial_pressure(
        &self,
        mut proposal: ProposedCandidate,
        now_ms: i64,
    ) -> Result<ProposedCandidate, String> {
        let paths =
            resolve_evolution_paths(&self.config_path, &self.runtime_config.evolution.paths);
        let mutation = DefaultEvolutionMutationHarness::from_path(
            &paths.evolution_mutation_results_dir,
            &paths.evolution_mutation_materialization_batch_results_dir,
            &paths.evolution_mutation_validation_batch_results_dir,
            &paths.evolution_ranking_results_dir,
        )
        .map_err(|error| error.to_string())?;
        let corpus = SuiteRedSwarmAdapter
            .generate_sequence_artifact(&self.generation_threat_context(&proposal))
            .await
            .map_err(|error| format!("failed to generate adversarial corpus: {error}"))?;
        let replay_fitness = proposal
            .strategy
            .get("population_fitness_replay")
            .and_then(Value::as_f64)
            .unwrap_or(proposal.base_fitness);
        let evasion_adjusted_fitness = proposal
            .strategy
            .get("population_fitness_evasion")
            .and_then(Value::as_f64)
            .unwrap_or(proposal.base_fitness);
        let memory_adjusted_fitness = proposal
            .strategy
            .get("population_fitness")
            .and_then(Value::as_f64)
            .unwrap_or(evasion_adjusted_fitness);
        let deception_adjusted_fitness = proposal
            .strategy
            .get("population_fitness_deception")
            .and_then(Value::as_f64)
            .unwrap_or(memory_adjusted_fitness);
        let evasion_pressure_score = proposal
            .strategy
            .get("evasion_pressure")
            .and_then(|value| value.get("pressure_score"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let evasion_gap_closure_rate = proposal
            .strategy
            .get("evasion_pressure")
            .and_then(|value| value.get("gap_closure_rate"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let evasion_focus_gap_count = proposal
            .strategy
            .get("evasion_pressure")
            .and_then(|value| value.get("gap_count"))
            .and_then(Value::as_u64)
            .map(|value| value as usize)
            .unwrap_or(0);
        let deception_signal_score = proposal
            .strategy
            .get("deception_signal")
            .and_then(|value| value.get("signal_score"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let result = mutation
            .evaluate_adversarial_pressure(
                &paths.evolution_population_results_dir,
                EvolutionAdversarialPressureRequest {
                    ranking_id: proposal.ranking_id.clone(),
                    validation_batch_id: proposal.validation_batch_id.clone(),
                    generation: proposal.generation,
                    evaluated_at_ms: now_ms,
                    strategy_id: proposal.strategy_id.clone(),
                    experiment_id: proposal.experiment_id.clone(),
                    experiment_path: proposal.experiment_path.clone(),
                    materialization_id: proposal.materialization_id.clone(),
                    validation_bundle_id: proposal.validation_bundle_id.clone(),
                    autonomous_fitness: proposal.autonomous_fitness.clone(),
                    replay_fitness,
                    evasion_adjusted_fitness,
                    evasion_pressure_score,
                    evasion_gap_closure_rate,
                    evasion_focus_gap_count,
                    memory_adjusted_fitness,
                    deception_adjusted_fitness,
                    deception_signal_score,
                    adversarial_corpus_sequence_id: corpus.sequence_id.clone(),
                    adversarial_corpus_suite_name: corpus.suite_name.clone(),
                    adversarial_corpus_version: corpus.corpus_version.clone(),
                    adversarial_corpus_events: corpus.events.clone(),
                },
            )
            .map_err(|error| error.to_string())?;

        let Some(strategy_object) = proposal.strategy.as_object_mut() else {
            return Err("kitten proposal payload was not an object".to_string());
        };
        strategy_object.insert(
            "population_fitness_memory".to_string(),
            Value::from(memory_adjusted_fitness),
        );
        strategy_object.insert(
            "population_fitness_evasion".to_string(),
            Value::from(evasion_adjusted_fitness),
        );
        strategy_object.insert(
            "population_fitness_deception".to_string(),
            Value::from(deception_adjusted_fitness),
        );
        strategy_object.insert(
            "population_fitness".to_string(),
            Value::from(result.final_fitness),
        );
        strategy_object.insert(
            "adversarial_corpus".to_string(),
            json!({
                "sequence_id": corpus.sequence_id,
                "suite_name": corpus.suite_name,
                "suite_path": corpus.suite_path,
                "corpus_version": corpus.corpus_version,
                "generated_at_ms": corpus.generated_at_ms,
                "campaign": corpus.campaign,
                "techniques": corpus.techniques,
                "tags": corpus.tags,
                "scenario_names": corpus.scenario_names,
                "benign_control_scenarios": corpus.benign_control_scenarios,
                "event_count": corpus.events.len(),
            }),
        );
        strategy_object.insert(
            "adversarial_pressure".to_string(),
            json!({
                "episode_id": result.episode.episode_id,
                "pressure_score": result.pressure_score,
                "final_fitness": result.final_fitness,
                "replay_fitness": replay_fitness,
                "evasion_adjusted_fitness": evasion_adjusted_fitness,
                "evasion_pressure_score": evasion_pressure_score,
                "evasion_gap_closure_rate": evasion_gap_closure_rate,
                "evasion_focus_gap_count": evasion_focus_gap_count,
                "deception_adjusted_fitness": result.episode.blue_fitness.deception_adjusted_fitness,
                "deception_signal_score": result.episode.blue_fitness.deception_signal_score,
                "event_detection_rate": result.episode.red_fitness.event_detection_rate,
                "event_evasion_rate": result.episode.red_fitness.event_evasion_rate,
                "threat_class_detection_rate": result.episode.red_fitness.threat_class_detection_rate,
                "threat_class_evasion_rate": result.episode.red_fitness.threat_class_evasion_rate,
                "threat_class_coverage": result.episode.threat_class_coverage,
                "blue_genome_hash": result.episode.blue_genome_hash,
            }),
        );
        proposal.fitness = result.final_fitness;
        Ok(proposal)
    }

    fn generation_threat_context(&self, proposal: &ProposedCandidate) -> ThreatContext {
        ThreatContext {
            suite_path: repo_root_from_config_path(&self.config_path)
                .join("scenario-suites/hellcat-office-v1.yaml"),
            requested_at_ms: proposal.generation_created_at_ms.max(1),
            sequence_id: format!(
                "evolution_generation:{}:{}",
                proposal.generation,
                sanitize_id(&proposal.ranking_id)
            ),
            include_benign_controls: false,
        }
    }

    fn mark_population_candidate_proposed(
        &self,
        strategy_id: &str,
        now_ms: i64,
    ) -> Result<(), String> {
        let paths =
            resolve_evolution_paths(&self.config_path, &self.runtime_config.evolution.paths);
        let mutation = DefaultEvolutionMutationHarness::from_path(
            &paths.evolution_mutation_results_dir,
            &paths.evolution_mutation_materialization_batch_results_dir,
            &paths.evolution_mutation_validation_batch_results_dir,
            &paths.evolution_ranking_results_dir,
        )
        .map_err(|error| error.to_string())?;
        mutation
            .mark_population_candidate_proposed(
                &paths.evolution_population_results_dir,
                strategy_id,
                now_ms,
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn current_evasion_pressure_input(
        &self,
    ) -> Result<Option<EvolutionEvasionPressureInput>, String> {
        Ok(Some(build_evasion_pressure_input(
            &self.config_path,
            &self.runtime_config,
        )?))
    }

    fn persist_status(&self, now_ms: i64) {
        let paths =
            resolve_evolution_paths(&self.config_path, &self.runtime_config.evolution.paths);
        let record = match &self.state {
            KittenState::AwaitingDrift => KittenStatusRecord {
                updated_at_ms: now_ms,
                state: KittenExecutionState::AwaitingDrift,
                observation_count: None,
                degraded_ratio: None,
                strategy_id: None,
                fitness: None,
                last_error: None,
            },
            KittenState::Mutating(pending) => KittenStatusRecord {
                updated_at_ms: now_ms,
                state: KittenExecutionState::Mutating,
                observation_count: Some(pending.assessment.observation_count),
                degraded_ratio: Some(pending.assessment.degraded_ratio),
                strategy_id: None,
                fitness: None,
                last_error: None,
            },
            KittenState::Evaluating(running) => KittenStatusRecord {
                updated_at_ms: now_ms,
                state: KittenExecutionState::Evaluating,
                observation_count: Some(running.cycle.observation_count),
                degraded_ratio: Some(running.cycle.degraded_ratio),
                strategy_id: None,
                fitness: None,
                last_error: None,
            },
            KittenState::Verifying(ready) => KittenStatusRecord {
                updated_at_ms: now_ms,
                state: KittenExecutionState::Verifying,
                observation_count: Some(ready.cycle.observation_count),
                degraded_ratio: Some(ready.cycle.degraded_ratio),
                strategy_id: None,
                fitness: None,
                last_error: None,
            },
            KittenState::AwaitingMemory(pending) => KittenStatusRecord {
                updated_at_ms: now_ms,
                state: KittenExecutionState::Proposing,
                observation_count: Some(pending.query.observation_count),
                degraded_ratio: None,
                strategy_id: Some(pending.proposal.strategy_id.clone()),
                fitness: Some(pending.proposal.base_fitness),
                last_error: None,
            },
            KittenState::Proposing(proposal) => KittenStatusRecord {
                updated_at_ms: now_ms,
                state: KittenExecutionState::Proposing,
                observation_count: None,
                degraded_ratio: None,
                strategy_id: Some(proposal.strategy_id.clone()),
                fitness: Some(proposal.fitness),
                last_error: None,
            },
        };

        if let Err(error) = FileKittenStatusStore::open(&paths.evolution_population_results_dir)
            .and_then(|store| store.persist(&record))
        {
            tracing::warn!(
                agent_id = %self.id,
                reason = %error,
                module = module_path!(),
                "kitten failed to persist runtime status"
            );
        }
    }

    #[cfg(test)]
    fn state_label(&self) -> &'static str {
        match self.state {
            KittenState::AwaitingDrift => "awaiting_drift",
            KittenState::Mutating(_) => "mutating",
            KittenState::Evaluating(_) => "evaluating",
            KittenState::Verifying(_) => "verifying",
            KittenState::AwaitingMemory(_) => "awaiting_memory",
            KittenState::Proposing(_) => "proposing",
        }
    }

    #[cfg(test)]
    fn last_cycle_error(&self) -> Option<&str> {
        self.last_cycle_error.as_deref()
    }
}

#[async_trait]
impl SwarmAgent for KittenAgent {
    fn identity(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    fn id(&self) -> &AgentId {
        &self.id
    }

    fn role(&self) -> AgentRole {
        self.role
    }

    fn observe_event(&mut self, event: &SwarmEvent) -> Result<(), SwarmError> {
        match event {
            SwarmEvent::RoleShift {
                agent_id, new_role, ..
            } if agent_id == &self.id => {
                self.role = *new_role;
            }
            _ => {}
        }
        Ok(())
    }

    async fn tick(&mut self, env: &SwarmEnvironment) -> Result<Vec<SwarmAction>, SwarmError> {
        let now_ms = env.now.saturating_mul(1000);
        let current_state = std::mem::replace(&mut self.state, KittenState::AwaitingDrift);
        let (next_state, actions) = match current_state {
            KittenState::AwaitingDrift => match self.restore_population_candidate(now_ms) {
                Ok(Some(KittenState::Proposing(proposal))) => {
                    self.health = AgentHealth::Healthy;
                    match self.maybe_begin_memory_query(env, proposal, now_ms).await {
                        Ok(result) => result,
                        Err(error) => (self.handle_cycle_error(now_ms, error), Vec::new()),
                    }
                }
                Ok(Some(state)) => (state, Vec::new()),
                Ok(None) => {
                    match self.drift_detector.evaluate(
                        &self.config_path,
                        &self.runtime_config.evolution.paths,
                        now_ms,
                    ) {
                        Ok(assessment) if assessment.pressure_source.is_some() => {
                            tracing::info!(
                                agent_id = %self.id,
                                degraded_count = assessment.degraded_count,
                                observation_count = assessment.observation_count,
                                degraded_ratio = assessment.degraded_ratio,
                                module = module_path!(),
                                "kitten drift detector activated"
                            );
                            (
                                KittenState::Mutating(PendingMutationCycle { assessment }),
                                Vec::new(),
                            )
                        }
                        Ok(_) => (KittenState::AwaitingDrift, Vec::new()),
                        Err(error) => (self.handle_cycle_error(now_ms, error), Vec::new()),
                    }
                }
                Err(error) => (self.handle_cycle_error(now_ms, error), Vec::new()),
            },
            KittenState::Mutating(pending) => {
                match self.start_mutation_cycle(pending.assessment, now_ms) {
                    Ok(state) => {
                        self.health = AgentHealth::Healthy;
                        (state, Vec::new())
                    }
                    Err(error) => (self.handle_cycle_error(now_ms, error), Vec::new()),
                }
            }
            KittenState::Evaluating(running) => {
                if !running.task.is_finished() {
                    (KittenState::Evaluating(running), Vec::new())
                } else {
                    match running.task.await {
                        Ok(Ok(validation)) => {
                            self.health = AgentHealth::Healthy;
                            (
                                KittenState::Verifying(ReadyValidationCycle {
                                    cycle: running.cycle,
                                    validation,
                                }),
                                Vec::new(),
                            )
                        }
                        Ok(Err(error)) => (self.handle_cycle_error(now_ms, error), Vec::new()),
                        Err(error) => (
                            self.handle_cycle_error(
                                now_ms,
                                format!("validation task join failure: {error}"),
                            ),
                            Vec::new(),
                        ),
                    }
                }
            }
            KittenState::Verifying(ready) => match self.finish_validation_cycle(ready, now_ms) {
                Ok(KittenState::AwaitingDrift) => {
                    self.drift_detector.note_cycle_completed(now_ms);
                    (KittenState::AwaitingDrift, Vec::new())
                }
                Ok(KittenState::Proposing(proposal)) => {
                    self.health = AgentHealth::Healthy;
                    match self.maybe_begin_memory_query(env, proposal, now_ms).await {
                        Ok(result) => result,
                        Err(error) => (self.handle_cycle_error(now_ms, error), Vec::new()),
                    }
                }
                Ok(state) => (state, Vec::new()),
                Err(error) => (self.handle_cycle_error(now_ms, error), Vec::new()),
            },
            KittenState::AwaitingMemory(mut pending) => {
                match find_sphinx_memory_answer(&env.pheromones, &pending.query.query_id) {
                    Some(answer) => match self.apply_memory_answer(pending.proposal, &answer) {
                        Ok(proposal) => match self.apply_deception_signal(proposal, env) {
                            Ok(proposal) => {
                                match self.apply_adversarial_pressure(proposal, now_ms).await {
                                    Ok(proposal) => (KittenState::Proposing(proposal), Vec::new()),
                                    Err(error) => {
                                        (self.handle_cycle_error(now_ms, error), Vec::new())
                                    }
                                }
                            }
                            Err(error) => (self.handle_cycle_error(now_ms, error), Vec::new()),
                        },
                        Err(error) => (self.handle_cycle_error(now_ms, error), Vec::new()),
                    },
                    None if pending.waited_ticks + 1 >= MEMORY_QUERY_MAX_WAIT_TICKS => {
                        match self.apply_memory_fallback(
                            pending.proposal,
                            &pending.query,
                            "sphinx_answer_unavailable",
                        ) {
                            Ok(proposal) => match self.apply_deception_signal(proposal, env) {
                                Ok(proposal) => match self
                                    .apply_adversarial_pressure(proposal, now_ms)
                                    .await
                                {
                                    Ok(proposal) => (KittenState::Proposing(proposal), Vec::new()),
                                    Err(error) => {
                                        (self.handle_cycle_error(now_ms, error), Vec::new())
                                    }
                                },
                                Err(error) => (self.handle_cycle_error(now_ms, error), Vec::new()),
                            },
                            Err(error) => (self.handle_cycle_error(now_ms, error), Vec::new()),
                        }
                    }
                    None => {
                        pending.waited_ticks += 1;
                        (KittenState::AwaitingMemory(pending), Vec::new())
                    }
                }
            }
            KittenState::Proposing(proposal) => {
                match self.mark_population_candidate_proposed(&proposal.strategy_id, now_ms) {
                    Ok(()) => {
                        self.drift_detector.note_cycle_completed(now_ms);
                        tracing::info!(
                            agent_id = %self.id,
                            strategy_id = %proposal.strategy_id,
                            fitness = proposal.fitness,
                            module = module_path!(),
                            "kitten emitted bounded strategy proposal"
                        );
                        (
                            KittenState::AwaitingDrift,
                            vec![SwarmAction::ProposeStrategy {
                                strategy_id: proposal.strategy_id,
                                strategy: proposal.strategy,
                                fitness: proposal.fitness,
                            }],
                        )
                    }
                    Err(error) => (self.handle_cycle_error(now_ms, error), Vec::new()),
                }
            }
        };

        self.state = next_state;
        self.persist_status(now_ms);
        Ok(actions)
    }

    fn health(&self) -> AgentHealth {
        self.health
    }
}

impl ConceptDriftDetector {
    fn new(config: swarm_core::config::EvolutionConfig) -> Self {
        Self {
            config,
            last_cycle_completed_at_ms: None,
        }
    }

    fn note_cycle_completed(&mut self, now_ms: i64) {
        self.last_cycle_completed_at_ms = Some(now_ms);
    }

    fn evaluate(
        &self,
        config_path: &Path,
        paths: &EvolutionPathsConfig,
        now_ms: i64,
    ) -> Result<DriftAssessment, String> {
        if let Some(last_cycle_completed_at_ms) = self.last_cycle_completed_at_ms {
            let cooldown_until_ms = last_cycle_completed_at_ms
                .saturating_add((self.config.cooldown_secs as i64).saturating_mul(1000));
            if now_ms < cooldown_until_ms {
                return Ok(DriftAssessment {
                    observation_count: 0,
                    degraded_count: 0,
                    degraded_ratio: 0.0,
                    pressure_source: None,
                });
            }
        }

        let resolved = resolve_evolution_paths(config_path, paths);
        let mut observations = self.recent_verification_observations(&resolved, now_ms)?;
        observations.extend(self.recent_scorecard_observations(&resolved, now_ms)?);
        observations.extend(self.recent_memory_observations(&resolved, now_ms)?);
        observations.sort_by_key(|entry| std::cmp::Reverse(entry.observed_at_ms));

        let observation_count = observations.len();
        if observation_count < self.config.minimum_observations {
            return Ok(DriftAssessment {
                observation_count,
                degraded_count: observations.iter().filter(|entry| entry.degraded).count(),
                degraded_ratio: 0.0,
                pressure_source: None,
            });
        }

        let degraded_count = observations.iter().filter(|entry| entry.degraded).count();
        let degraded_ratio = degraded_count as f64 / observation_count as f64;
        if degraded_ratio < self.config.drift_threshold_pct {
            return Ok(DriftAssessment {
                observation_count,
                degraded_count,
                degraded_ratio,
                pressure_source: None,
            });
        }

        let pressure_source = observations
            .iter()
            .find_map(|entry| entry.pressure_source.clone());

        Ok(DriftAssessment {
            observation_count,
            degraded_count,
            degraded_ratio,
            pressure_source,
        })
    }

    fn recent_verification_observations(
        &self,
        paths: &ResolvedEvolutionPaths,
        now_ms: i64,
    ) -> Result<Vec<DriftObservation>, String> {
        let records = read_index::<DetectorVerificationRecord>(&paths.verification_results_dir)?;
        let cutoff_ms = now_ms.saturating_sub((self.config.observation_window_secs as i64) * 1000);
        let mut observations = Vec::new();

        for record in records {
            if record.created_at_ms < cutoff_ms {
                continue;
            }
            let report: DetectorVerificationReport = read_json(Path::new(&record.bundle_path))
                .map_err(|error| {
                    format!(
                        "failed to read verification report `{}`: {error}",
                        record.bundle_path
                    )
                })?;
            observations.push(DriftObservation {
                observed_at_ms: record.created_at_ms,
                degraded: !report.passed,
                pressure_source: (!report.passed).then(|| PressureSource::Verification {
                    verification_id: record.verification_id.clone(),
                }),
            });
        }

        Ok(observations)
    }

    fn recent_scorecard_observations(
        &self,
        paths: &ResolvedEvolutionPaths,
        now_ms: i64,
    ) -> Result<Vec<DriftObservation>, String> {
        let records = read_index::<StrategyScorecardRecord>(&paths.strategy_scorecard_results_dir)?;
        let cutoff_ms = now_ms.saturating_sub((self.config.observation_window_secs as i64) * 1000);
        let mut observations = Vec::new();

        for record in records {
            if record.created_at_ms < cutoff_ms {
                continue;
            }
            let report: StrategyScorecard =
                read_json(Path::new(&record.bundle_path)).map_err(|error| {
                    format!(
                        "failed to read strategy scorecard `{}`: {error}",
                        record.bundle_path
                    )
                })?;
            let degraded = report.recommendation == StrategyAdvisoryRecommendation::RetainBaseline
                && report.score_delta < 0.0;
            observations.push(DriftObservation {
                observed_at_ms: record.created_at_ms,
                degraded,
                pressure_source: degraded.then(|| PressureSource::Scorecard {
                    scorecard_id: record.scorecard_id.clone(),
                }),
            });
        }

        Ok(observations)
    }

    fn recent_memory_observations(
        &self,
        paths: &ResolvedEvolutionPaths,
        now_ms: i64,
    ) -> Result<Vec<DriftObservation>, String> {
        let records = read_index::<StrategyMemoryRecord>(&paths.strategy_memory_results_dir)?;
        let cutoff_ms = now_ms.saturating_sub((self.config.observation_window_secs as i64) * 1000);
        Ok(records
            .into_iter()
            .filter(|record| record.observed_at_ms >= cutoff_ms)
            .map(|record| DriftObservation {
                observed_at_ms: record.observed_at_ms,
                degraded: matches!(
                    record.outcome_kind,
                    StrategyMemoryOutcomeKind::Blocked | StrategyMemoryOutcomeKind::Halted
                ),
                pressure_source: None,
            })
            .collect())
    }
}

#[derive(Default)]
struct MemoryQueryContext {
    observation_count: usize,
    threat_classes: Vec<String>,
    attack_technique_ids: Vec<String>,
    entity_values: Vec<String>,
}

impl MemoryQueryContext {
    fn from_env(env: &SwarmEnvironment) -> Self {
        let mut threat_classes = BTreeSet::new();
        let mut attack_technique_ids = BTreeSet::new();
        let mut entity_values = BTreeSet::new();
        let mut observation_count = 0;

        for deposit in env
            .pheromones
            .iter()
            .filter(|deposit| !is_memory_deposit(deposit))
        {
            observation_count += 1;
            threat_classes.insert(threat_class_name(&deposit.threat_class));
            attack_technique_ids.extend(extract_attack_technique_ids(&deposit.indicator));
            entity_values.extend(extract_entity_values(&deposit.indicator));
        }

        Self {
            observation_count,
            threat_classes: threat_classes.into_iter().collect(),
            attack_technique_ids: attack_technique_ids.into_iter().take(8).collect(),
            entity_values: entity_values.into_iter().take(8).collect(),
        }
    }
}

fn find_sphinx_memory_answer(
    pheromones: &[PheromoneDeposit],
    query_id: &str,
) -> Option<SphinxMemoryAnswer> {
    pheromones
        .iter()
        .filter_map(parse_sphinx_memory_answer)
        .find(|answer| answer.query_id == query_id)
}

fn parse_sphinx_memory_answer(deposit: &PheromoneDeposit) -> Option<SphinxMemoryAnswer> {
    if !is_memory_deposit(deposit) {
        return None;
    }
    let answer = serde_json::from_value::<SphinxMemoryAnswer>(deposit.indicator.clone()).ok()?;
    (answer.kind == SphinxMemoryPayloadKind::Answer).then_some(answer)
}

fn q_value_style_memory_score(base_fitness: f64, answer: &SphinxMemoryAnswer) -> f64 {
    if answer.matching_engagement_count == 0 {
        return base_fitness;
    }
    if answer.matching_engagement_count >= MEMORY_QUERY_MIN_MATCHES {
        return answer.retrieval_score;
    }
    let live_weight = answer.matching_engagement_count as f64;
    let fallback_weight = (MEMORY_QUERY_MIN_MATCHES - answer.matching_engagement_count) as f64;
    ((answer.retrieval_score * live_weight) + (base_fitness * fallback_weight))
        / MEMORY_QUERY_MIN_MATCHES as f64
}

fn deception_signal_severity_weight(severity: Severity) -> f64 {
    match severity {
        Severity::Low => 0.25,
        Severity::Medium => 0.50,
        Severity::High => 0.75,
        Severity::Critical => 1.0,
    }
}

fn is_memory_deposit(deposit: &PheromoneDeposit) -> bool {
    matches!(
        &deposit.threat_class,
        ThreatClass::Custom(value) if value == SPHINX_MEMORY_THREAT_CLASS
    )
}

fn signed_memory_pheromone_deposit(
    signing_key: &SigningKey,
    _agent_id: &AgentId,
    runtime_config: &SwarmConfig,
    timestamp: i64,
    indicator: Value,
) -> Result<PheromoneDeposit, String> {
    let threat_class = ThreatClass::Custom(SPHINX_MEMORY_THREAT_CLASS.to_string());
    let policy = runtime_config.pheromone.resolve_threat_class_policy(None);
    let derived_agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
    let mut deposit = PheromoneDeposit {
        schema_version: PheromoneDeposit::current_schema_version(),
        indicator,
        threat_class,
        severity: Severity::Low,
        confidence: 0.0,
        timestamp,
        decay_half_life: policy.half_life_secs,
        agent_id: derived_agent_id.clone(),
        agent_identity: derived_agent_id.0,
        agent_role: Some(AgentRole::Kitten),
        signature: Vec::new(),
        agent_key: Vec::new(),
    };
    let signing_payload = DepositSigningPayload {
        schema_version: deposit.schema_version,
        indicator: &deposit.indicator,
        threat_class: &deposit.threat_class,
        severity: &deposit.severity,
        confidence: deposit.confidence,
        timestamp: deposit.timestamp,
        decay_half_life: deposit.decay_half_life,
        agent_id: &deposit.agent_id,
        agent_identity: &deposit.agent_identity,
        agent_role: deposit.agent_role,
    };
    let payload_bytes = serde_json::to_vec(&signing_payload)
        .map_err(|error| format!("failed to encode pheromone signing payload: {error}"))?;
    let signature = signing_key.sign(&payload_bytes);
    deposit.signature = signature.to_bytes().to_vec();
    deposit.agent_key = signing_key.verifying_key().to_bytes().to_vec();
    Ok(deposit)
}

async fn run_validation_task(
    config_path: PathBuf,
    runtime_config: SwarmConfig,
    paths: ResolvedEvolutionPaths,
    batch_id: String,
) -> Result<ValidationTaskOutput, String> {
    let replay = DefaultReplayHarness::from_config(
        config_path.clone(),
        runtime_config.clone(),
        &paths.replay_results_dir,
    )
    .map_err(|error| error.to_string())?;
    let proof = DefaultEvolutionProofHarness::from_config(
        config_path.clone(),
        runtime_config.clone(),
        &paths.evolution_proof_results_dir,
    )
    .map_err(|error| error.to_string())?;
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        config_path.clone(),
        runtime_config.clone(),
        &paths.strategy_memory_results_dir,
        &paths.strategy_scorecard_results_dir,
    )
    .map_err(|error| error.to_string())?;
    let drafting = DefaultEvolutionDraftingHarness::from_config(
        config_path,
        runtime_config,
        &paths.evolution_pressure_results_dir,
        &paths.evolution_draft_results_dir,
        &paths.evolution_draft_promotion_results_dir,
        &paths.evolution_materialization_results_dir,
        &paths.evolution_validation_results_dir,
        &paths.evolution_reconciliation_results_dir,
    )
    .map_err(|error| error.to_string())?;
    let mutation = DefaultEvolutionMutationHarness::from_path(
        &paths.evolution_mutation_results_dir,
        &paths.evolution_mutation_materialization_batch_results_dir,
        &paths.evolution_mutation_validation_batch_results_dir,
        &paths.evolution_ranking_results_dir,
    )
    .map_err(|error| error.to_string())?;

    let validation = mutation
        .refresh_validation_batch(
            &drafting,
            &replay,
            &proof,
            &scorecards,
            &paths.experiment_results_dir,
            &paths.verification_results_dir,
            &paths.shadow_results_dir,
            &batch_id,
        )
        .await
        .map_err(|error| error.to_string())?;

    Ok(ValidationTaskOutput {
        validation_batch_id: validation.report.validation_batch_id,
    })
}

fn build_evasion_pressure_input(
    config_path: &Path,
    runtime_config: &SwarmConfig,
) -> Result<EvolutionEvasionPressureInput, String> {
    let repo_root = resolve_repo_root(config_path);
    let snapshot = evaluate_repo_evasion_coverage(runtime_config, &repo_root)
        .map_err(|error| error.to_string())?;
    let gaps = actionable_gaps_for_detector(&snapshot, &runtime_config.detection.strategy);
    Ok(EvolutionEvasionPressureInput {
        detector: runtime_config.detection.strategy.clone(),
        suite_name: snapshot.suite_name,
        suite_path: PathBuf::from(snapshot.suite_path),
        corpus_version: snapshot.corpus_version,
        gaps: gaps
            .into_iter()
            .map(|gap| EvolutionEvasionGapFocus {
                threat_class: gap.threat_class,
                total_payloads: gap.total_payloads,
                missed_payloads: gap.missed_payloads,
                catch_rate: gap.catch_rate,
                actionable_techniques: gap.actionable_techniques,
            })
            .collect(),
    })
}

fn build_benchmark_evasion_pressure_input(
    config_path: &Path,
    runtime_config: &SwarmConfig,
    baseline_experiment_path: &Path,
) -> Result<EvolutionEvasionPressureInput, String> {
    let manifest = load_detector_experiment_manifest(baseline_experiment_path)
        .map_err(|error| error.to_string())?;
    let mut benchmark_config = runtime_config.clone();
    let detector = match &manifest.candidate {
        DetectorCandidateManifest::SuspiciousProcessTree { profile, .. } => {
            benchmark_config.detection.strategy = "suspicious_process_tree".to_string();
            benchmark_config.detection.profiles.suspicious_process_tree =
                Some(serde_json::to_value(profile).map_err(|error| error.to_string())?);
            benchmark_config.detection.high_confidence_threshold =
                profile.high_confidence_threshold;
            benchmark_config.detection.medium_confidence_threshold =
                profile.medium_confidence_threshold;
            "suspicious_process_tree".to_string()
        }
        other => {
            return Err(format!(
                "benchmark evasion pressure is not yet supported for detector `{}`",
                other.strategy_id()
            ));
        }
    };
    let repo_root = resolve_repo_root(config_path);
    let snapshot = evaluate_repo_evasion_coverage(&benchmark_config, &repo_root)
        .map_err(|error| error.to_string())?;
    let gaps = actionable_gaps_for_detector(&snapshot, &detector);
    Ok(EvolutionEvasionPressureInput {
        detector,
        suite_name: snapshot.suite_name,
        suite_path: PathBuf::from(snapshot.suite_path),
        corpus_version: snapshot.corpus_version,
        gaps: gaps
            .into_iter()
            .map(|gap| EvolutionEvasionGapFocus {
                threat_class: gap.threat_class,
                total_payloads: gap.total_payloads,
                missed_payloads: gap.missed_payloads,
                catch_rate: gap.catch_rate,
                actionable_techniques: gap.actionable_techniques,
            })
            .collect(),
    })
}

pub async fn run_bounded_evolution_benchmark(
    config_path: impl AsRef<Path>,
    runtime_config: SwarmConfig,
    request: EvolutionBenchmarkRequest,
) -> Result<EvolutionBenchmarkRunLookup, EvolutionBenchmarkError> {
    if !runtime_config.evolution.enabled {
        return Err(EvolutionBenchmarkError::InvalidRequest {
            reason: "evolution must be enabled for the measured benchmark harness".to_string(),
        });
    }
    if request.generation_count == 0 {
        return Err(EvolutionBenchmarkError::InvalidRequest {
            reason: "generation_count must be greater than zero".to_string(),
        });
    }
    if request.benchmark_id.trim().is_empty() {
        return Err(EvolutionBenchmarkError::InvalidRequest {
            reason: "benchmark_id must not be empty".to_string(),
        });
    }
    if !request.baseline_experiment_path.exists() {
        return Err(EvolutionBenchmarkError::InvalidRequest {
            reason: format!(
                "baseline experiment `{}` does not exist",
                request.baseline_experiment_path.display()
            ),
        });
    }

    let config_path = config_path.as_ref().to_path_buf();
    let paths = resolve_evolution_paths(&config_path, &runtime_config.evolution.paths);
    let replay = DefaultReplayHarness::from_config(
        config_path.clone(),
        runtime_config.clone(),
        &paths.replay_results_dir,
    )?;
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        config_path.clone(),
        runtime_config.clone(),
        &paths.strategy_memory_results_dir,
        &paths.strategy_scorecard_results_dir,
    )?;
    let drafting = DefaultEvolutionDraftingHarness::from_config(
        config_path.clone(),
        runtime_config.clone(),
        &paths.evolution_pressure_results_dir,
        &paths.evolution_draft_results_dir,
        &paths.evolution_draft_promotion_results_dir,
        &paths.evolution_materialization_results_dir,
        &paths.evolution_validation_results_dir,
        &paths.evolution_reconciliation_results_dir,
    )?;
    let mutation = DefaultEvolutionMutationHarness::from_path(
        &paths.evolution_mutation_results_dir,
        &paths.evolution_mutation_materialization_batch_results_dir,
        &paths.evolution_mutation_validation_batch_results_dir,
        &paths.evolution_ranking_results_dir,
    )?;
    let benchmark_store = FileEvolutionBenchmarkStore::open(
        paths.evolution_population_results_dir.join("benchmarks"),
    )?;
    let evasion_pressure = build_benchmark_evasion_pressure_input(
        &config_path,
        &runtime_config,
        &request.baseline_experiment_path,
    )
    .map_err(EvolutionBenchmarkError::EvasionPressure)?;
    let verification = replay
        .evaluate_verification_path(
            &request.baseline_experiment_path,
            &paths.verification_results_dir,
        )
        .await?;
    let scorecard = scorecards
        .create_scorecard(
            &replay,
            &request.baseline_experiment_path,
            &paths.experiment_results_dir,
            &paths.verification_results_dir,
            &verification.report.verification_id,
        )
        .await?;
    let pressure =
        drafting.create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)?;
    let experiment = replay
        .load_experiment(
            &paths.experiment_results_dir,
            &scorecard.report.experiment_id,
        )?
        .ok_or_else(|| EvolutionBenchmarkError::InvalidRequest {
            reason: format!(
                "experiment `{}` was not found after scorecard creation",
                scorecard.report.experiment_id
            ),
        })?;
    let mut report = EvolutionBenchmarkRunReport {
        benchmark_id: request.benchmark_id.clone(),
        label: if request.label.trim().is_empty() {
            request.benchmark_id.clone()
        } else {
            request.label.clone()
        },
        detector: evasion_pressure.detector.clone(),
        baseline_experiment_path: request.baseline_experiment_path.display().to_string(),
        baseline: summarize_evolution_benchmark_baseline(
            &request.baseline_experiment_path,
            &experiment.report,
            &verification.report,
            &runtime_config.evolution.fitness_weights,
            Some(&evasion_pressure),
        )?,
        created_at_ms: scorecard.report.created_at_ms,
        updated_at_ms: scorecard.report.created_at_ms,
        requested_generation_count: request.generation_count,
        completed_generation_count: 0,
        max_variants_per_generation: runtime_config.evolution.max_variants_per_cycle.max(1),
        population_size: runtime_config.evolution.population_size,
        corpus_suite_name: evasion_pressure.suite_name.clone(),
        corpus_version: evasion_pressure.corpus_version.clone(),
        suite_path: evasion_pressure.suite_path.display().to_string(),
        notes: "Single bounded benchmark run using Phase 197 autonomous measured-fitness artifacts; includes explicit staged-baseline measurement plus raw generation deltas only.".to_string(),
        generations: Vec::new(),
    };
    benchmark_store.persist(&report)?;

    let strategy_root = sanitize_id(&format!("{}_benchmark", report.label));
    for generation in 1..=request.generation_count {
        let draft = drafting.create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: format!("{strategy_root}_g{generation}"),
            strategy_description: format!(
                "Measured evolution benchmark generation {generation} candidate root"
            ),
            mutation: "measured_evolution_benchmark".to_string(),
            rationale: format!(
                "Run bounded measured evolution benchmark generation {generation} of {}",
                request.generation_count
            ),
        })?;
        let spec = mutation.create_autonomous_mutation_spec(
            &drafting,
            &paths.evolution_population_results_dir,
            EvolutionAutonomousMutationSpecCreateRequest {
                draft_id: draft.report.draft_id.clone(),
                strategy_root: draft.report.strategy_id.clone(),
                rationale: draft.report.lineage_rationale.clone(),
                max_variants: runtime_config.evolution.max_variants_per_cycle.max(1),
                base_experiment_path: Some(request.baseline_experiment_path.clone()),
                evasion_pressure: Some(evasion_pressure.clone()),
            },
        )?;
        let batch = mutation.materialize_batch(&drafting, &spec.report.mutation_spec_id)?;
        let validation = run_validation_task(
            config_path.clone(),
            runtime_config.clone(),
            paths.clone(),
            batch.report.batch_id.clone(),
        )
        .await
        .map_err(EvolutionBenchmarkError::ValidationTask)?;
        let validation_batch = mutation
            .load_validation_batch(&validation.validation_batch_id)?
            .ok_or_else(|| EvolutionBenchmarkError::InvalidRequest {
                reason: format!(
                    "validation batch `{}` was not found after refresh",
                    validation.validation_batch_id
                ),
            })?;
        let ranking = mutation.rank_candidates(
            &paths.evolution_queue_results_dir,
            &validation_batch.report.validation_batch_id,
            runtime_config.evolution.shortlist_count,
        )?;
        let population = mutation.refresh_population(
            &paths.evolution_population_results_dir,
            &drafting,
            &paths.experiment_results_dir,
            &paths.verification_results_dir,
            &ranking.report,
            runtime_config.evolution.population_size,
            runtime_config.evolution.pareto_tournament_size,
            &runtime_config.evolution.fitness_weights,
            Some(&evasion_pressure),
        )?;
        let mut generation_report = summarize_evolution_benchmark_generation(
            &report.benchmark_id,
            generation,
            population.updated_at_ms,
            &draft.report.draft_id,
            &spec.report.mutation_spec_id,
            &batch.report.batch_id,
            &validation_batch.report.validation_batch_id,
            &ranking.report.ranking_id,
            &population,
        )?;
        if let Some(previous) = report.generations.last() {
            generation_report.delta_from_previous =
                Some(benchmark_fitness_delta(&generation_report, previous));
        }
        if let Some(first) = report.generations.first() {
            generation_report.delta_from_first =
                Some(benchmark_fitness_delta(&generation_report, first));
        }
        report.completed_generation_count = generation;
        report.updated_at_ms = generation_report.created_at_ms;
        report.generations.push(generation_report);
        benchmark_store.persist(&report)?;
    }

    benchmark_store.load(&report.benchmark_id)?.ok_or(
        EvolutionBenchmarkError::MissingPersistedRun {
            benchmark_id: report.benchmark_id,
        },
    )
}

fn resolve_evolution_paths(
    config_path: &Path,
    paths: &EvolutionPathsConfig,
) -> ResolvedEvolutionPaths {
    ResolvedEvolutionPaths {
        replay_results_dir: resolve_repo_relative(config_path, &paths.replay_results_dir),
        experiment_results_dir: resolve_repo_relative(config_path, &paths.experiment_results_dir),
        verification_results_dir: resolve_repo_relative(
            config_path,
            &paths.verification_results_dir,
        ),
        shadow_results_dir: resolve_repo_relative(config_path, &paths.shadow_results_dir),
        strategy_memory_results_dir: resolve_repo_relative(
            config_path,
            &paths.strategy_memory_results_dir,
        ),
        strategy_scorecard_results_dir: resolve_repo_relative(
            config_path,
            &paths.strategy_scorecard_results_dir,
        ),
        evolution_proof_results_dir: resolve_repo_relative(
            config_path,
            &paths.evolution_proof_results_dir,
        ),
        evolution_queue_results_dir: resolve_repo_relative(
            config_path,
            &paths.evolution_queue_results_dir,
        ),
        evolution_pressure_results_dir: resolve_repo_relative(
            config_path,
            &paths.evolution_pressure_results_dir,
        ),
        evolution_draft_results_dir: resolve_repo_relative(
            config_path,
            &paths.evolution_draft_results_dir,
        ),
        evolution_draft_promotion_results_dir: resolve_repo_relative(
            config_path,
            &paths.evolution_draft_promotion_results_dir,
        ),
        evolution_materialization_results_dir: resolve_repo_relative(
            config_path,
            &paths.evolution_materialization_results_dir,
        ),
        evolution_validation_results_dir: resolve_repo_relative(
            config_path,
            &paths.evolution_validation_results_dir,
        ),
        evolution_reconciliation_results_dir: resolve_repo_relative(
            config_path,
            &paths.evolution_reconciliation_results_dir,
        ),
        evolution_mutation_results_dir: resolve_repo_relative(
            config_path,
            &paths.evolution_mutation_results_dir,
        ),
        evolution_mutation_materialization_batch_results_dir: resolve_repo_relative(
            config_path,
            &paths.evolution_mutation_materialization_batch_results_dir,
        ),
        evolution_mutation_validation_batch_results_dir: resolve_repo_relative(
            config_path,
            &paths.evolution_mutation_validation_batch_results_dir,
        ),
        evolution_ranking_results_dir: resolve_repo_relative(
            config_path,
            &paths.evolution_ranking_results_dir,
        ),
        evolution_population_results_dir: resolve_repo_relative(
            config_path,
            &paths.evolution_population_results_dir,
        ),
    }
}

fn resolve_repo_relative(config_path: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        return path;
    }
    repo_root_from_config_path(config_path).join(path)
}

fn repo_root_from_config_path(config_path: &Path) -> PathBuf {
    if let Some(parent) = config_path.parent() {
        if parent.file_name().is_some_and(|name| name == "rulesets") {
            return parent.parent().unwrap_or(parent).to_path_buf();
        }
        return parent.to_path_buf();
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn pressure_source_label(source: &PressureSource) -> &'static str {
    match source {
        PressureSource::Scorecard { .. } => "scorecard",
        PressureSource::Verification { .. } => "verification",
    }
}

fn sanitize_id(raw: &str) -> String {
    let mut sanitized = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_lowercase());
        } else {
            sanitized.push('_');
        }
    }
    while sanitized.contains("__") {
        sanitized = sanitized.replace("__", "_");
    }
    sanitized.trim_matches('_').to_string()
}

fn threat_class_name(threat_class: &ThreatClass) -> String {
    match threat_class {
        ThreatClass::LateralMovement => "lateral_movement".to_string(),
        ThreatClass::DataExfiltration => "data_exfiltration".to_string(),
        ThreatClass::PrivilegeEscalation => "privilege_escalation".to_string(),
        ThreatClass::CommandAndControl => "command_and_control".to_string(),
        ThreatClass::InitialAccess => "initial_access".to_string(),
        ThreatClass::Persistence => "persistence".to_string(),
        ThreatClass::SupplyChain => "supply_chain".to_string(),
        ThreatClass::DefenseEvasion => "defense_evasion".to_string(),
        ThreatClass::CredentialAccess => "credential_access".to_string(),
        ThreatClass::Discovery => "discovery".to_string(),
        ThreatClass::Execution => "execution".to_string(),
        ThreatClass::Impact => "impact".to_string(),
        ThreatClass::Custom(value) => value.clone(),
    }
}

fn extract_attack_technique_ids(indicator: &Value) -> BTreeSet<String> {
    indicator
        .get("attack_techniques")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

fn extract_entity_values(indicator: &Value) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    for key in [
        "host_id",
        "user",
        "process_name",
        "parent_process_name",
        "source_ip",
        "destination_ip",
    ] {
        if let Some(value) = indicator.get(key).and_then(Value::as_str) {
            values.insert(value.to_string());
        }
    }
    values
}

fn read_index<T>(root: &Path) -> Result<Vec<T>, String>
where
    T: DeserializeOwned,
{
    let index_path = root.join("index.json");
    if !index_path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(&index_path)
        .map_err(|error| format!("failed to read `{}`: {error}", index_path.display()))?;
    let parsed: RecordIndex<T> = serde_json::from_str(&raw)
        .map_err(|error| format!("failed to parse `{}`: {error}", index_path.display()))?;
    Ok(parsed.entries)
}

fn read_json<T>(path: &Path) -> Result<T, String>
where
    T: DeserializeOwned,
{
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("failed to read `{}`: {error}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|error| format!("failed to parse `{}`: {error}", path.display()))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{
        EvolutionBenchmarkRequest, KittenAgent, ProposedCandidate,
        build_benchmark_evasion_pressure_input, build_evasion_pressure_input,
        resolve_evolution_paths, run_bounded_evolution_benchmark, run_validation_task,
    };
    use crate::calico_agent::{CalicoDeceptionInteractionPayload, CalicoLifecycleStage};
    use crate::config::load_config;
    use crate::drafting::{DefaultEvolutionDraftingHarness, EvolutionDraftCreateRequest};
    use crate::evasion_coverage::{actionable_gaps_for_detector, evaluate_repo_evasion_coverage};
    use crate::mutation::{
        DefaultEvolutionMutationHarness, EvolutionAutonomousMutationSpecCreateRequest,
        EvolutionEvasionGapFocus, EvolutionEvasionPressureInput, FileEvolutionBenchmarkStore,
        FileEvolutionEpisodeStore,
    };
    use crate::replay::{
        DefaultReplayHarness, DetectorVerificationRecord, DetectorVerificationReport,
        ExperimentLineage, VerificationInvariantResult,
    };
    use crate::sphinx_agent::SphinxAgent;
    use crate::strategy::DefaultStrategyScorecardHarness;
    use serde_json::json;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::agent::{AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmMode};
    use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
    use swarm_core::types::AgentId;
    use swarm_pheromone::{ConfiguredPheromoneSubstrate, PheromoneSubstrate};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn config_path() -> PathBuf {
        repo_root().join("rulesets/default.yaml")
    }

    fn office_control_experiment() -> PathBuf {
        repo_root().join("experiments/office-baseline-control.yaml")
    }

    fn office_conservative_experiment() -> PathBuf {
        repo_root().join("experiments/office-conservative-control.yaml")
    }

    fn copy_dir_recursive(source: &Path, destination: &Path) {
        if !source.exists() {
            return;
        }

        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let entry_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_dir_recursive(&entry_path, &destination_path);
            } else {
                fs::copy(&entry_path, &destination_path).unwrap();
            }
        }
    }

    fn stage_experiment(root: &Path, source: &Path) -> PathBuf {
        let experiments_dir = root.join("experiments");
        fs::create_dir_all(&experiments_dir).unwrap();
        let destination = experiments_dir.join(source.file_name().unwrap());
        fs::copy(&source, &destination).unwrap();
        if let Some(source_root) = source.parent().and_then(Path::parent) {
            copy_dir_recursive(
                &source_root.join("scenario-suites"),
                &root.join("scenario-suites"),
            );
            copy_dir_recursive(
                &source_root.join("verifications"),
                &root.join("verifications"),
            );
            copy_dir_recursive(&source_root.join("scenarios"), &root.join("scenarios"));
        }
        destination
    }

    fn stage_baseline_experiment(root: &Path) -> PathBuf {
        stage_experiment(root, &office_control_experiment())
    }

    fn sample_evasion_pressure_input(detector: &str) -> EvolutionEvasionPressureInput {
        EvolutionEvasionPressureInput {
            detector: detector.to_string(),
            suite_name: "evasion_breadth_v1".to_string(),
            suite_path: repo_root().join("scenario-suites/evasion-breadth-v1.yaml"),
            corpus_version: "2026-04-10".to_string(),
            gaps: vec![
                EvolutionEvasionGapFocus {
                    threat_class: ThreatClass::Execution,
                    total_payloads: 2,
                    missed_payloads: 1,
                    catch_rate: 0.5,
                    actionable_techniques: vec!["T1204.002".to_string()],
                },
                EvolutionEvasionGapFocus {
                    threat_class: ThreatClass::DefenseEvasion,
                    total_payloads: 1,
                    missed_payloads: 1,
                    catch_rate: 0.0,
                    actionable_techniques: vec!["T1055".to_string()],
                },
            ],
        }
    }

    fn temp_root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-kitten-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn env(now: i64) -> SwarmEnvironment {
        SwarmEnvironment {
            pheromones: Vec::new(),
            mode: SwarmMode::Normal,
            mode_transition_at: None,
            now,
            peer_findings: Vec::new(),
            agent_health: Vec::new(),
        }
    }

    fn env_with_pheromones(pheromones: Vec<PheromoneDeposit>, now: i64) -> SwarmEnvironment {
        SwarmEnvironment {
            pheromones,
            mode: SwarmMode::Alert,
            mode_transition_at: Some(now - 5),
            now,
            peer_findings: Vec::new(),
            agent_health: Vec::new(),
        }
    }

    fn substrate(config: &swarm_core::config::SwarmConfig) -> ConfiguredPheromoneSubstrate {
        ConfiguredPheromoneSubstrate::from_config(&config.pheromone)
            .expect("test substrate should initialize")
    }

    #[test]
    fn evasion_actionable_gaps_build_pressure_input_for_active_detector() {
        let root = temp_root("evasion-pressure-input");
        let config_path = config_path();
        let mut config = load_config(&config_path).unwrap();
        configure_paths(&mut config, &root);
        let repo_root = super::resolve_repo_root(&config_path);
        let snapshot = evaluate_repo_evasion_coverage(&config, &repo_root).unwrap();
        let (detector, expected_gaps) = snapshot
            .detectors
            .iter()
            .find_map(|report| {
                let gaps = actionable_gaps_for_detector(&snapshot, &report.detector);
                (!gaps.is_empty()).then_some((report.detector.clone(), gaps))
            })
            .expect("repo evasion suite should expose at least one actionable detector gap");
        config.detection.strategy = detector.clone();

        let agent = KittenAgent::new(
            AgentId::new("kitten", "primary"),
            &config_path,
            config.clone(),
            substrate(&config),
        );
        let pressure = agent
            .current_evasion_pressure_input()
            .unwrap()
            .expect("actionable detector should yield evasion pressure");

        assert_eq!(pressure.detector, detector);
        assert_eq!(pressure.suite_name, snapshot.suite_name);
        assert_eq!(pressure.corpus_version, snapshot.corpus_version);
        assert_eq!(pressure.gaps.len(), expected_gaps.len());
        assert_eq!(
            pressure.gaps[0].missed_payloads,
            expected_gaps[0].missed_payloads
        );
        assert_eq!(
            pressure.gaps[0].actionable_techniques,
            expected_gaps[0].actionable_techniques
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn benchmark_evasion_pressure_uses_staged_baseline_profile() {
        let root = temp_root("benchmark-evasion-pressure");
        let config_path = config_path();
        let mut config = load_config(&config_path).unwrap();
        configure_paths(&mut config, &root);
        let conservative_experiment = stage_experiment(&root, &office_conservative_experiment());

        let default_pressure = build_evasion_pressure_input(&config_path, &config).unwrap();
        let benchmark_pressure =
            build_benchmark_evasion_pressure_input(&config_path, &config, &conservative_experiment)
                .unwrap();

        let default_execution_missed = default_pressure
            .gaps
            .iter()
            .find(|gap| gap.threat_class == ThreatClass::Execution)
            .map(|gap| gap.missed_payloads)
            .unwrap_or(0);
        let benchmark_execution_gap = benchmark_pressure
            .gaps
            .iter()
            .find(|gap| gap.threat_class == ThreatClass::Execution)
            .expect("conservative baseline should expose an execution gap");

        assert_eq!(benchmark_pressure.detector, "suspicious_process_tree");
        assert!(
            benchmark_execution_gap.missed_payloads > default_execution_missed,
            "benchmark pressure should be derived from the staged baseline profile"
        );
        assert!(
            benchmark_execution_gap
                .actionable_techniques
                .contains(&"T1204.002".to_string())
        );

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn autonomous_variants_increase_threshold_nudge_for_measured_gaps() {
        let root = temp_root("evasion-variants");
        let config_path = config_path();
        let mut config = load_config(&config_path).unwrap();
        configure_paths(&mut config, &root);

        let paths = resolve_evolution_paths(&config_path, &config.evolution.paths);
        let replay = DefaultReplayHarness::from_config(
            config_path.clone(),
            config.clone(),
            &paths.replay_results_dir,
        )
        .unwrap();
        let verification = replay
            .evaluate_verification_path(
                office_control_experiment(),
                &paths.verification_results_dir,
            )
            .await
            .unwrap();
        let scorecards = DefaultStrategyScorecardHarness::from_config(
            config_path.clone(),
            config.clone(),
            &paths.strategy_memory_results_dir,
            &paths.strategy_scorecard_results_dir,
        )
        .unwrap();
        let scorecard = scorecards
            .create_scorecard(
                &replay,
                office_control_experiment(),
                &paths.experiment_results_dir,
                &paths.verification_results_dir,
                &verification.report.verification_id,
            )
            .await
            .unwrap();
        let drafting = DefaultEvolutionDraftingHarness::from_config(
            config_path.clone(),
            config.clone(),
            &paths.evolution_pressure_results_dir,
            &paths.evolution_draft_results_dir,
            &paths.evolution_draft_promotion_results_dir,
            &paths.evolution_materialization_results_dir,
            &paths.evolution_validation_results_dir,
            &paths.evolution_reconciliation_results_dir,
        )
        .unwrap();
        let mutation = DefaultEvolutionMutationHarness::from_path(
            &paths.evolution_mutation_results_dir,
            &paths.evolution_mutation_materialization_batch_results_dir,
            &paths.evolution_mutation_validation_batch_results_dir,
            &paths.evolution_ranking_results_dir,
        )
        .unwrap();
        let pressure = drafting
            .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
            .unwrap();
        let baseline_draft = drafting
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.report.pressure_id.clone(),
                strategy_id: format!("{}_kitten_baseline", pressure.report.strategy_id),
                strategy_description: "Kitten autonomous baseline fixture".to_string(),
                mutation: "runtime_drift_response".to_string(),
                rationale: "seed a baseline autonomous perturbation".to_string(),
            })
            .unwrap();
        let pressured_draft = drafting
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.report.pressure_id.clone(),
                strategy_id: format!("{}_kitten_pressured", pressure.report.strategy_id),
                strategy_description: "Kitten autonomous pressure fixture".to_string(),
                mutation: "runtime_drift_response".to_string(),
                rationale: "seed a gap-aware autonomous perturbation".to_string(),
            })
            .unwrap();
        let pressure = sample_evasion_pressure_input(&config.detection.strategy);
        let baseline = mutation
            .create_autonomous_mutation_spec(
                &drafting,
                &paths.evolution_population_results_dir,
                EvolutionAutonomousMutationSpecCreateRequest {
                    draft_id: baseline_draft.report.draft_id.clone(),
                    strategy_root: baseline_draft.report.strategy_id.clone(),
                    rationale: baseline_draft.report.lineage_rationale.clone(),
                    max_variants: config.evolution.max_variants_per_cycle,
                    base_experiment_path: None,
                    evasion_pressure: None,
                },
            )
            .unwrap();
        let pressured = mutation
            .create_autonomous_mutation_spec(
                &drafting,
                &paths.evolution_population_results_dir,
                EvolutionAutonomousMutationSpecCreateRequest {
                    draft_id: pressured_draft.report.draft_id.clone(),
                    strategy_root: pressured_draft.report.strategy_id.clone(),
                    rationale: pressured_draft.report.lineage_rationale.clone(),
                    max_variants: config.evolution.max_variants_per_cycle,
                    base_experiment_path: None,
                    evasion_pressure: Some(pressure.clone()),
                },
            )
            .unwrap();
        let baseline_nudge = baseline
            .report
            .variants
            .iter()
            .find(|request| request.mutation == "autonomous_bounded_perturbation")
            .expect("baseline spec should contain a perturbation variant");
        let pressured_nudge = pressured
            .report
            .variants
            .iter()
            .find(|request| request.mutation == "autonomous_bounded_perturbation")
            .expect("pressured spec should contain a perturbation variant");
        let baseline_high = baseline_nudge
            .overrides
            .high_confidence_threshold
            .as_deref()
            .unwrap()
            .parse::<f64>()
            .unwrap();
        let pressured_high = pressured_nudge
            .overrides
            .high_confidence_threshold
            .as_deref()
            .unwrap()
            .parse::<f64>()
            .unwrap();

        assert!(pressured_nudge.rationale.contains("measured evasion gaps"));
        assert!(
            pressured_high < baseline_high,
            "gap pressure should make the threshold nudge more aggressive"
        );
        assert_eq!(
            pressured
                .report
                .autonomous_generation
                .as_ref()
                .unwrap()
                .generator,
            "bounded_population_variants_v1"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn measured_evolution_benchmark_persists_generation_deltas() {
        let root = temp_root("measured-benchmark");
        let config_path = config_path();
        let mut config = load_config(&config_path).unwrap();
        configure_paths(&mut config, &root);
        let baseline_experiment_path = stage_baseline_experiment(&root);

        let run = run_bounded_evolution_benchmark(
            &config_path,
            config.clone(),
            EvolutionBenchmarkRequest {
                benchmark_id: "benchmark:test".to_string(),
                label: "office benchmark".to_string(),
                generation_count: 3,
                baseline_experiment_path,
            },
        )
        .await
        .unwrap();

        assert_eq!(run.report.completed_generation_count, 3);
        assert_eq!(run.report.generations.len(), 3);
        assert_eq!(run.report.detector, config.detection.strategy);
        assert_eq!(run.report.corpus_suite_name, "evasion_breadth_v1");
        assert!(run.report.baseline.is_some());
        assert!(
            run.report
                .generations
                .iter()
                .all(|generation| !generation.leader_strategy_id.is_empty())
        );
        assert!(
            run.report.generations[1].delta_from_previous.is_some(),
            "second generation should capture a delta from generation one"
        );
        assert!(
            run.report.generations[2].delta_from_first.is_some(),
            "final generation should capture a delta from the opening generation"
        );

        let benchmark_store =
            FileEvolutionBenchmarkStore::open(root.join("evolution-population").join("benchmarks"))
                .unwrap();
        let latest = benchmark_store.latest(1).unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].benchmark_id, "benchmark:test".to_string());

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn measured_evolution_benchmark_improves_over_conservative_seed() {
        let root = temp_root("measured-benchmark-conservative");
        let config_path = config_path();
        let mut config = load_config(&config_path).unwrap();
        configure_paths(&mut config, &root);
        config.evolution.max_variants_per_cycle = 2;
        let conservative_experiment = stage_experiment(&root, &office_conservative_experiment());

        let run = run_bounded_evolution_benchmark(
            &config_path,
            config,
            EvolutionBenchmarkRequest {
                benchmark_id: "benchmark:conservative".to_string(),
                label: "office conservative".to_string(),
                generation_count: 1,
                baseline_experiment_path: conservative_experiment,
            },
        )
        .await
        .unwrap();

        let baseline = run
            .report
            .baseline
            .as_ref()
            .expect("benchmark run should persist baseline metrics");
        let generation = run
            .report
            .generations
            .first()
            .expect("benchmark run should persist generation one");

        assert!(
            generation.leader_measured_fitness > baseline.measured_fitness,
            "gap expansion should outperform the conservative seed baseline"
        );
        assert!(
            generation.leader_catch_rate > baseline.catch_rate,
            "generation leader should close the conservative execution gap"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn evasion_gap_driven_population_proposal_preserves_pressure_metadata() {
        let root = temp_root("evasion-proposal");
        let config_path = config_path();
        let mut config = load_config(&config_path).unwrap();
        configure_paths(&mut config, &root);

        let agent = KittenAgent::new(
            AgentId::new("kitten", "primary"),
            &config_path,
            config.clone(),
            substrate(&config),
        );
        let paths = resolve_evolution_paths(&config_path, &config.evolution.paths);
        let replay = DefaultReplayHarness::from_config(
            config_path.clone(),
            config.clone(),
            &paths.replay_results_dir,
        )
        .unwrap();
        let verification = replay
            .evaluate_verification_path(
                office_control_experiment(),
                &paths.verification_results_dir,
            )
            .await
            .unwrap();
        let scorecards = DefaultStrategyScorecardHarness::from_config(
            config_path.clone(),
            config.clone(),
            &paths.strategy_memory_results_dir,
            &paths.strategy_scorecard_results_dir,
        )
        .unwrap();
        let scorecard = scorecards
            .create_scorecard(
                &replay,
                office_control_experiment(),
                &paths.experiment_results_dir,
                &paths.verification_results_dir,
                &verification.report.verification_id,
            )
            .await
            .unwrap();
        let drafting = DefaultEvolutionDraftingHarness::from_config(
            config_path.clone(),
            config.clone(),
            &paths.evolution_pressure_results_dir,
            &paths.evolution_draft_results_dir,
            &paths.evolution_draft_promotion_results_dir,
            &paths.evolution_materialization_results_dir,
            &paths.evolution_validation_results_dir,
            &paths.evolution_reconciliation_results_dir,
        )
        .unwrap();
        let mutation = DefaultEvolutionMutationHarness::from_path(
            &paths.evolution_mutation_results_dir,
            &paths.evolution_mutation_materialization_batch_results_dir,
            &paths.evolution_mutation_validation_batch_results_dir,
            &paths.evolution_ranking_results_dir,
        )
        .unwrap();
        let pressure = drafting
            .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
            .unwrap();
        let draft = drafting
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.report.pressure_id.clone(),
                strategy_id: format!("{}_kitten_evasion", pressure.report.strategy_id),
                strategy_description: "Kitten evasion fixture".to_string(),
                mutation: "runtime_drift_response".to_string(),
                rationale: "seed a proposal-ready candidate with evasion pressure".to_string(),
            })
            .unwrap();
        let evasion_input = sample_evasion_pressure_input(&config.detection.strategy);
        let spec = mutation
            .create_autonomous_mutation_spec(
                &drafting,
                &paths.evolution_population_results_dir,
                EvolutionAutonomousMutationSpecCreateRequest {
                    draft_id: draft.report.draft_id.clone(),
                    strategy_root: draft.report.strategy_id.clone(),
                    rationale: draft.report.lineage_rationale.clone(),
                    max_variants: config.evolution.max_variants_per_cycle,
                    base_experiment_path: None,
                    evasion_pressure: Some(evasion_input.clone()),
                },
            )
            .unwrap();
        let batch = mutation
            .materialize_batch(&drafting, &spec.report.mutation_spec_id)
            .unwrap();
        let validation = run_validation_task(
            config_path.clone(),
            config.clone(),
            paths.clone(),
            batch.report.batch_id.clone(),
        )
        .await
        .unwrap();
        let validation_batch = mutation
            .load_validation_batch(&validation.validation_batch_id)
            .unwrap()
            .unwrap();
        let ranking = mutation
            .rank_candidates(
                &paths.evolution_queue_results_dir,
                &validation_batch.report.validation_batch_id,
                config.evolution.shortlist_count,
            )
            .unwrap();
        let population = mutation
            .refresh_population(
                &paths.evolution_population_results_dir,
                &drafting,
                &paths.experiment_results_dir,
                &paths.verification_results_dir,
                &ranking.report,
                config.evolution.population_size,
                config.evolution.pareto_tournament_size,
                &config.evolution.fitness_weights,
                Some(&evasion_input),
            )
            .unwrap();
        let candidate = population
            .members
            .first()
            .cloned()
            .expect("population should contain a proposal-ready candidate");
        assert!(
            candidate.evasion_pressure.is_some(),
            "population candidate should retain evasion pressure metadata"
        );
        assert!(
            candidate.baseline_fitness.is_some(),
            "population candidate should retain replay fitness separately"
        );
        let autonomous_fitness = candidate
            .autonomous_fitness
            .as_ref()
            .expect("autonomous candidate should retain measured fitness attribution");
        assert_eq!(autonomous_fitness.lineage.parent_strategy_ids.len(), 1);
        assert!(autonomous_fitness.catch_rate > 0.0);
        assert!(autonomous_fitness.measured_fitness > 0.0);

        let proposal = agent
            .build_population_proposal(&paths, candidate.clone(), "evasion_test", None)
            .unwrap();
        let pressure = proposal
            .strategy
            .get("evasion_pressure")
            .expect("proposal should preserve evasion pressure metadata");
        assert_eq!(
            proposal
                .strategy
                .get("population_fitness_replay")
                .and_then(serde_json::Value::as_f64),
            candidate.baseline_fitness
        );
        assert_eq!(
            proposal
                .strategy
                .get("population_fitness_evasion")
                .and_then(serde_json::Value::as_f64),
            Some(candidate.fitness)
        );
        assert_eq!(
            pressure
                .get("gap_count")
                .and_then(serde_json::Value::as_u64),
            candidate
                .evasion_pressure
                .as_ref()
                .map(|summary| summary.gap_count as u64)
        );
        assert!(
            proposal.strategy.get("autonomous_fitness").is_none(),
            "autonomous measured fitness should stay runtime-owned, not widen the proposal payload"
        );

        let proposal = agent
            .apply_adversarial_pressure(proposal, 1_800_730_001_000)
            .await
            .unwrap();
        let episode_id = proposal
            .strategy
            .get("adversarial_pressure")
            .and_then(|value| value.get("episode_id"))
            .and_then(serde_json::Value::as_str)
            .expect("adversarial evaluation should persist an episode");
        let episode = FileEvolutionEpisodeStore::open(
            paths.evolution_population_results_dir.join("episodes"),
        )
        .unwrap()
        .load(episode_id)
        .unwrap()
        .expect("episode should load from durable store");
        let persisted_autonomous = episode
            .report
            .autonomous_fitness
            .as_ref()
            .expect("episode should preserve autonomous measured fitness lineage");
        assert_eq!(
            persisted_autonomous.lineage.parent_strategy_ids,
            autonomous_fitness.lineage.parent_strategy_ids
        );
        assert_eq!(
            persisted_autonomous.catch_rate,
            autonomous_fitness.catch_rate
        );

        let _ = fs::remove_dir_all(root);
    }

    fn runtime_pheromone(event_id: &str, timestamp: i64) -> PheromoneDeposit {
        PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::json!({
                "event_id": event_id,
                "summary": "suspicious powershell execution",
                "host_id": "host-1",
                "user": "alice",
                "process_name": "powershell.exe",
                "parent_process_name": "winword.exe",
                "source_ip": "10.0.0.5",
                "destination_ip": "198.51.100.7",
                "attack_techniques": [
                    {"id": "T1059", "name": "Command and Scripting Interpreter", "kill_chain_stage": "execution"}
                ],
                "observed_at_ms": timestamp * 1000
            }),
            threat_class: ThreatClass::Execution,
            severity: swarm_core::types::Severity::High,
            confidence: 0.95,
            timestamp,
            decay_half_life: 3_600.0,
            agent_id: AgentId::new("whisker", "primary"),
            agent_identity: String::new(),
            agent_role: None,
            signature: Vec::new(),
            agent_key: Vec::new(),
        }
    }

    fn calico_interaction_pheromone(asset_id: &str, timestamp: i64) -> PheromoneDeposit {
        PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::to_value(CalicoDeceptionInteractionPayload {
                schema: crate::calico_agent::CALICO_DECEPTION_INTERACTION_SCHEMA.to_string(),
                schema_version: 1,
                asset_id: asset_id.to_string(),
                playbook_entry: "finance-canary".to_string(),
                generation: 1,
                lifecycle_stage: CalicoLifecycleStage::Monitor,
                decoy_type: "canary_token".to_string(),
                target_zone: "finance".to_string(),
                host_profile: "linux-app".to_string(),
                placement_strategy: "high_value_path".to_string(),
                interaction_signal: "file_path".to_string(),
                matched_value: "/srv/data/finance/payroll.xlsx".to_string(),
                source_event_id: Some("evt-calico-1".to_string()),
                source_hunt_id: None,
                source_agent_id: AgentId::new("whisker", "primary").to_string(),
                source_indicator: serde_json::json!({
                    "event_id": "evt-calico-1",
                    "summary": "unexpected finance file access",
                    "observed_at_ms": timestamp * 1000
                }),
            })
            .unwrap(),
            threat_class: ThreatClass::InitialAccess,
            severity: swarm_core::types::Severity::High,
            confidence: 0.99,
            timestamp,
            decay_half_life: 3_600.0,
            agent_id: AgentId::new("calico", "primary"),
            agent_identity: String::new(),
            agent_role: Some(AgentRole::Calico),
            signature: Vec::new(),
            agent_key: Vec::new(),
        }
    }

    fn configure_paths(config: &mut swarm_core::config::SwarmConfig, root: &Path) {
        config.evolution.enabled = true;
        config.evolution.observation_window_secs = 3_600;
        config.evolution.drift_threshold_pct = 0.5;
        config.evolution.minimum_observations = 2;
        config.evolution.cooldown_secs = 60;
        config.evolution.max_variants_per_cycle = 2;
        config.evolution.shortlist_count = 1;
        config.evolution.population_size = 8;
        config.evolution.pareto_tournament_size = 2;
        config.evolution.max_proposals_per_hour = 4;
        config.evolution.paths.replay_results_dir = root.join("replay-runs").display().to_string();
        config.evolution.paths.experiment_results_dir =
            root.join("experiments-data").display().to_string();
        config.evolution.paths.verification_results_dir =
            root.join("verifications").display().to_string();
        config.evolution.paths.shadow_results_dir = root.join("shadows").display().to_string();
        config.evolution.paths.strategy_memory_results_dir =
            root.join("strategy-memory").display().to_string();
        config.evolution.paths.strategy_scorecard_results_dir =
            root.join("strategy-scorecards").display().to_string();
        config.evolution.paths.evolution_proof_results_dir =
            root.join("evolution-proofs").display().to_string();
        config.evolution.paths.evolution_queue_results_dir =
            root.join("evolution-queue").display().to_string();
        config.evolution.paths.evolution_selection_results_dir =
            root.join("evolution-selections").display().to_string();
        config.evolution.paths.evolution_bridge_results_dir = root
            .join("evolution-selection-bridges")
            .display()
            .to_string();
        config.evolution.paths.evolution_handoff_results_dir =
            root.join("evolution-handoffs").display().to_string();
        config.evolution.paths.evolution_pressure_results_dir =
            root.join("evolution-pressures").display().to_string();
        config.evolution.paths.evolution_draft_results_dir =
            root.join("evolution-drafts").display().to_string();
        config.evolution.paths.evolution_draft_promotion_results_dir = root
            .join("evolution-draft-promotions")
            .display()
            .to_string();
        config.evolution.paths.evolution_materialization_results_dir = root
            .join("evolution-materializations")
            .display()
            .to_string();
        config.evolution.paths.evolution_validation_results_dir = root
            .join("evolution-validation-bundles")
            .display()
            .to_string();
        config.evolution.paths.evolution_reconciliation_results_dir =
            root.join("evolution-reconciliations").display().to_string();
        config.evolution.paths.evolution_mutation_results_dir =
            root.join("evolution-mutations").display().to_string();
        config
            .evolution
            .paths
            .evolution_mutation_materialization_batch_results_dir = root
            .join("evolution-mutation-materialization-batches")
            .display()
            .to_string();
        config
            .evolution
            .paths
            .evolution_mutation_validation_batch_results_dir = root
            .join("evolution-mutation-validation-batches")
            .display()
            .to_string();
        config.evolution.paths.evolution_ranking_results_dir =
            root.join("evolution-rankings").display().to_string();
        config.evolution.paths.evolution_population_results_dir =
            root.join("evolution-population").display().to_string();
        config.evolution.paths.canary_results_dir = root.join("canaries").display().to_string();
    }

    fn configure_memory(config: &mut swarm_core::config::SwarmConfig, root: &Path) {
        config.memory.enabled = true;
        config.memory.knowledge_graph_results_dir =
            root.join("knowledge-graph").display().to_string();
        config.memory.temporal_window_secs = 3_600;
    }

    fn seed_failed_verifications(root: &Path, now_ms: i64, count: usize) {
        let verifications_root = root.join("verifications");
        let reports_dir = verifications_root.join("reports");
        fs::create_dir_all(&reports_dir).unwrap();

        let mut entries = Vec::new();
        for index in 0..count {
            let verification_id = format!("verification:office_baseline_control:{index}");
            let bundle_path = reports_dir.join(format!("office_baseline_control_{index}.json"));
            let report = DetectorVerificationReport {
                verification_id: verification_id.clone(),
                experiment_id: "experiment:office_baseline_control:office_baseline_control"
                    .to_string(),
                experiment_name: "office_baseline_control".to_string(),
                corpus_name: "office_detector_safety_v1".to_string(),
                corpus_path: repo_root()
                    .join("verifications/office-detector-safety-v1.yaml")
                    .display()
                    .to_string(),
                created_at_ms: now_ms - ((index as i64) * 1000),
                lineage: ExperimentLineage {
                    parent_strategy_id: "suspicious_process_tree".to_string(),
                    mutation: "drift_probe".to_string(),
                    rationale: "seed a drift-triggering verification artifact".to_string(),
                },
                candidate_strategy_id: "office_baseline_control".to_string(),
                candidate_description: "seed candidate".to_string(),
                invariants: vec![VerificationInvariantResult {
                    name: "known_bad_coverage".to_string(),
                    passed: false,
                    expected: json!(true),
                    actual: json!(false),
                    details: "coverage regressed in the seeded verification artifact".to_string(),
                    counterexamples: Vec::new(),
                }],
                passed: false,
            };
            fs::write(&bundle_path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
            entries.push(DetectorVerificationRecord {
                verification_id,
                experiment_id: report.experiment_id.clone(),
                candidate_strategy_id: report.candidate_strategy_id.clone(),
                corpus_name: report.corpus_name.clone(),
                created_at_ms: report.created_at_ms,
                passed: report.passed,
                bundle_path: bundle_path.display().to_string(),
            });
        }

        fs::write(
            verifications_root.join("index.json"),
            serde_json::to_string_pretty(&serde_json::json!({ "entries": entries })).unwrap(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn drift_detector_requires_minimum_observations_and_respects_cooldown() {
        let root = temp_root("drift-detector");
        let now = 1_800_000_000_i64;
        let now_ms = now * 1000;
        let mut config = load_config(config_path()).unwrap();
        configure_paths(&mut config, &root);
        seed_failed_verifications(&root, now_ms, 2);

        let mut agent = KittenAgent::new(
            AgentId::new("kitten", "primary"),
            config_path(),
            config.clone(),
            substrate(&config),
        );
        assert_eq!(agent.state_label(), "awaiting_drift");

        agent.tick(&env(now)).await.unwrap();
        assert_eq!(agent.state_label(), "mutating");

        for _ in 0..40 {
            let actions = agent.tick(&env(now)).await.unwrap();
            if !actions.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        let proposal_actions = agent.tick(&env(now)).await.unwrap();
        assert!(proposal_actions.is_empty());

        agent
            .tick(&env(now + 1))
            .await
            .expect("cooldown tick should not fail");
        assert_eq!(agent.state_label(), "awaiting_drift");

        agent
            .tick(&env(now + 30))
            .await
            .expect("cooldown should suppress reactivation");
        assert_eq!(agent.state_label(), "awaiting_drift");

        agent
            .tick(&env(now + 61))
            .await
            .expect("post-cooldown drift tick should succeed");
        assert_eq!(agent.state_label(), "mutating");

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn kitten_agent_advances_state_machine_and_emits_proposal() {
        let root = temp_root("proposal");
        let now = 1_800_100_000_i64;
        let now_ms = now * 1000;
        let mut config = load_config(config_path()).unwrap();
        configure_paths(&mut config, &root);
        seed_failed_verifications(&root, now_ms, 3);

        let mut agent = KittenAgent::new(
            AgentId::new("kitten", "primary"),
            config_path(),
            config.clone(),
            substrate(&config),
        );
        let mut proposal = None;

        for tick in 0..200 {
            let actions = agent.tick(&env(now + tick)).await.unwrap();
            if let Some(action) = actions.into_iter().next() {
                proposal = Some(action);
                break;
            }
            if agent.state_label() == "proposing" {
                let mut actions = agent.tick(&env(now + tick + 1)).await.unwrap();
                if let Some(action) = actions.pop() {
                    proposal = Some(action);
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        let action = proposal.unwrap_or_else(|| {
            panic!(
                "kitten should eventually emit a strategy proposal; state={} last_error={:?}",
                agent.state_label(),
                agent.last_cycle_error()
            )
        });
        match action {
            swarm_core::types::SwarmAction::ProposeStrategy {
                strategy_id,
                fitness,
                strategy,
            } => {
                assert!(strategy_id.contains("office_baseline_control"));
                assert!(fitness > 0.0);
                assert_eq!(
                    strategy.get("source").and_then(serde_json::Value::as_str),
                    Some("kitten_population_candidate")
                );
                assert_eq!(
                    strategy
                        .get("selection_source")
                        .and_then(serde_json::Value::as_str),
                    Some("fresh_validation_cycle")
                );
            }
            other => panic!("expected propose_strategy, got {other:?}"),
        }
        assert_eq!(agent.role(), AgentRole::Kitten);
        assert_eq!(agent.health(), AgentHealth::Healthy);

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn kitten_validation_task_refreshes_materialized_batch() {
        let root = temp_root("validation");
        let now = 1_800_200_000_i64;
        let now_ms = now * 1000;
        let config_path = config_path();
        let mut config = load_config(&config_path).unwrap();
        configure_paths(&mut config, &root);
        seed_failed_verifications(&root, now_ms, 3);

        let _agent = KittenAgent::new(
            AgentId::new("kitten", "primary"),
            &config_path,
            config.clone(),
            substrate(&config),
        );
        let paths = resolve_evolution_paths(&config_path, &config.evolution.paths);
        let replay = DefaultReplayHarness::from_config(
            config_path.clone(),
            config.clone(),
            &paths.replay_results_dir,
        )
        .unwrap();
        let drafting = DefaultEvolutionDraftingHarness::from_config(
            config_path.clone(),
            config.clone(),
            &paths.evolution_pressure_results_dir,
            &paths.evolution_draft_results_dir,
            &paths.evolution_draft_promotion_results_dir,
            &paths.evolution_materialization_results_dir,
            &paths.evolution_validation_results_dir,
            &paths.evolution_reconciliation_results_dir,
        )
        .unwrap();
        let mutation = DefaultEvolutionMutationHarness::from_path(
            &paths.evolution_mutation_results_dir,
            &paths.evolution_mutation_materialization_batch_results_dir,
            &paths.evolution_mutation_validation_batch_results_dir,
            &paths.evolution_ranking_results_dir,
        )
        .unwrap();

        let pressure = drafting
            .create_pressure_from_verification(
                &replay,
                &paths.verification_results_dir,
                "verification:office_baseline_control:0",
            )
            .unwrap();
        let draft = drafting
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.report.pressure_id.clone(),
                strategy_id: format!("{}_kitten_validation", pressure.report.strategy_id),
                strategy_description: "Kitten validation fixture".to_string(),
                mutation: "runtime_drift_response".to_string(),
                rationale: "seed a direct validation cycle for the runtime kitten".to_string(),
            })
            .unwrap();
        let spec = mutation
            .create_autonomous_mutation_spec(
                &drafting,
                &paths.evolution_population_results_dir,
                EvolutionAutonomousMutationSpecCreateRequest {
                    draft_id: draft.report.draft_id.clone(),
                    strategy_root: draft.report.strategy_id.clone(),
                    rationale: draft.report.lineage_rationale.clone(),
                    max_variants: config.evolution.max_variants_per_cycle,
                    base_experiment_path: None,
                    evasion_pressure: None,
                },
            )
            .unwrap();
        let batch = mutation
            .materialize_batch(&drafting, &spec.report.mutation_spec_id)
            .unwrap();

        let validation = match run_validation_task(
            config_path.clone(),
            config.clone(),
            paths.clone(),
            batch.report.batch_id.clone(),
        )
        .await
        {
            Ok(validation) => validation,
            Err(error) => panic!("kitten validation task should succeed: {error}"),
        };
        let stored_batch = mutation
            .load_validation_batch(&validation.validation_batch_id)
            .unwrap();
        assert!(
            stored_batch.is_some(),
            "validation batch `{}` should be persisted",
            validation.validation_batch_id
        );

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn kitten_restores_persisted_population_candidate_before_drift() {
        let root = temp_root("population-restore");
        let now = 1_800_300_000_i64;
        let config_path = config_path();
        let mut config = load_config(&config_path).unwrap();
        configure_paths(&mut config, &root);

        let _seed_agent = KittenAgent::new(
            AgentId::new("kitten", "seed"),
            &config_path,
            config.clone(),
            substrate(&config),
        );
        let paths = resolve_evolution_paths(&config_path, &config.evolution.paths);
        let replay = DefaultReplayHarness::from_config(
            config_path.clone(),
            config.clone(),
            &paths.replay_results_dir,
        )
        .unwrap();
        let verification = replay
            .evaluate_verification_path(
                office_control_experiment(),
                &paths.verification_results_dir,
            )
            .await
            .unwrap();
        let scorecards = DefaultStrategyScorecardHarness::from_config(
            config_path.clone(),
            config.clone(),
            &paths.strategy_memory_results_dir,
            &paths.strategy_scorecard_results_dir,
        )
        .unwrap();
        let scorecard = scorecards
            .create_scorecard(
                &replay,
                office_control_experiment(),
                &paths.experiment_results_dir,
                &paths.verification_results_dir,
                &verification.report.verification_id,
            )
            .await
            .unwrap();
        let drafting = DefaultEvolutionDraftingHarness::from_config(
            config_path.clone(),
            config.clone(),
            &paths.evolution_pressure_results_dir,
            &paths.evolution_draft_results_dir,
            &paths.evolution_draft_promotion_results_dir,
            &paths.evolution_materialization_results_dir,
            &paths.evolution_validation_results_dir,
            &paths.evolution_reconciliation_results_dir,
        )
        .unwrap();
        let mutation = DefaultEvolutionMutationHarness::from_path(
            &paths.evolution_mutation_results_dir,
            &paths.evolution_mutation_materialization_batch_results_dir,
            &paths.evolution_mutation_validation_batch_results_dir,
            &paths.evolution_ranking_results_dir,
        )
        .unwrap();
        let pressure = drafting
            .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
            .unwrap();
        let draft = drafting
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.report.pressure_id.clone(),
                strategy_id: format!("{}_kitten_restore", pressure.report.strategy_id),
                strategy_description: "Kitten population restore fixture".to_string(),
                mutation: "runtime_population_restore".to_string(),
                rationale: "seed a durable ready candidate before restarting the kitten loop"
                    .to_string(),
            })
            .unwrap();
        let spec = mutation
            .create_autonomous_mutation_spec(
                &drafting,
                &paths.evolution_population_results_dir,
                EvolutionAutonomousMutationSpecCreateRequest {
                    draft_id: draft.report.draft_id.clone(),
                    strategy_root: draft.report.strategy_id.clone(),
                    rationale: draft.report.lineage_rationale.clone(),
                    max_variants: config.evolution.max_variants_per_cycle,
                    base_experiment_path: None,
                    evasion_pressure: None,
                },
            )
            .unwrap();
        let batch = mutation
            .materialize_batch(&drafting, &spec.report.mutation_spec_id)
            .unwrap();
        let validation = run_validation_task(
            config_path.clone(),
            config.clone(),
            paths.clone(),
            batch.report.batch_id.clone(),
        )
        .await
        .unwrap();
        let validation_batch = mutation
            .load_validation_batch(&validation.validation_batch_id)
            .unwrap()
            .unwrap();
        let ranking = mutation
            .rank_candidates(
                &paths.evolution_queue_results_dir,
                &validation_batch.report.validation_batch_id,
                config.evolution.shortlist_count,
            )
            .unwrap();
        let population = mutation
            .refresh_population(
                &paths.evolution_population_results_dir,
                &drafting,
                &paths.experiment_results_dir,
                &paths.verification_results_dir,
                &ranking.report,
                config.evolution.population_size,
                config.evolution.pareto_tournament_size,
                &config.evolution.fitness_weights,
                None,
            )
            .unwrap();
        assert!(
            !population.members.is_empty(),
            "population should contain at least one ready candidate"
        );

        let mut restored_agent = KittenAgent::new(
            AgentId::new("kitten", "restore"),
            &config_path,
            config.clone(),
            substrate(&config),
        );
        let first_tick_actions = restored_agent.tick(&env(now)).await.unwrap();
        assert!(first_tick_actions.is_empty());
        assert_eq!(restored_agent.state_label(), "proposing");

        let second_tick_actions = restored_agent.tick(&env(now + 1)).await.unwrap();
        assert_eq!(second_tick_actions.len(), 1);
        match &second_tick_actions[0] {
            swarm_core::types::SwarmAction::ProposeStrategy {
                strategy_id,
                fitness,
                strategy,
            } => {
                assert!(!strategy_id.is_empty());
                assert!(*fitness > 0.0);
                assert_eq!(
                    strategy.get("source").and_then(serde_json::Value::as_str),
                    Some("kitten_population_candidate")
                );
                assert_eq!(
                    strategy
                        .get("selection_source")
                        .and_then(serde_json::Value::as_str),
                    Some("restored_population")
                );
                assert!(
                    strategy.get("adversarial_corpus").is_some(),
                    "restored proposal should include frozen adversarial corpus metadata"
                );
                assert!(
                    strategy.get("adversarial_pressure").is_some(),
                    "restored proposal should include adversarial pressure metadata"
                );
            }
            other => panic!("expected propose_strategy, got {other:?}"),
        }

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn kitten_memory_answer_enriches_pending_proposal_fitness() {
        let root = temp_root("memory-answer");
        let config_path = config_path();
        let mut config = load_config(&config_path).unwrap();
        configure_paths(&mut config, &root);
        configure_memory(&mut config, &root);
        let substrate = substrate(&config);

        let mut kitten = KittenAgent::new(
            AgentId::new("kitten", "primary"),
            &config_path,
            config.clone(),
            substrate.clone(),
        );
        let mut sphinx = SphinxAgent::new(
            AgentId::new("sphinx", "primary"),
            &config_path,
            config.clone(),
            substrate.clone(),
        )
        .unwrap();
        let proposal = ProposedCandidate {
            generation: 7,
            generation_created_at_ms: 1_800_800_000_000,
            ranking_id: "ranking:test:7".to_string(),
            validation_batch_id: "validation:test:7".to_string(),
            strategy_id: "office_baseline_control_kitten".to_string(),
            experiment_id: "experiment:office_baseline_control".to_string(),
            experiment_path: office_control_experiment(),
            materialization_id: "materialization:test:7".to_string(),
            validation_bundle_id: "validation-bundle:test:7".to_string(),
            base_fitness: 0.55,
            fitness: 0.55,
            autonomous_fitness: None,
            strategy: json!({
                "source": "kitten_population_candidate",
                "selection_source": "restored_population",
                "population_fitness": 0.55,
                "population_fitness_replay": 0.55,
            }),
        };
        let runtime_env = env_with_pheromones(
            vec![
                runtime_pheromone("evt-1", 1_800_800_000),
                runtime_pheromone("evt-2", 1_800_800_030),
            ],
            1_800_800_031,
        );
        sphinx.tick(&runtime_env).await.unwrap();

        let (memory_state, actions) = kitten
            .maybe_begin_memory_query(&runtime_env, proposal, 1_800_800_031_000)
            .await
            .unwrap();
        assert_eq!(actions.len(), 1);
        kitten.state = memory_state;
        assert_eq!(kitten.state_label(), "awaiting_memory");

        let query_env =
            env_with_pheromones(substrate.recent_deposits(10).await.unwrap(), 1_800_800_032);
        sphinx.tick(&query_env).await.unwrap();

        let answer_env =
            env_with_pheromones(substrate.recent_deposits(10).await.unwrap(), 1_800_800_033);
        let actions = kitten.tick(&answer_env).await.unwrap();
        assert!(actions.is_empty());
        assert_eq!(kitten.state_label(), "proposing");
        match &kitten.state {
            super::KittenState::Proposing(proposal) => {
                assert!(
                    proposal
                        .strategy
                        .get("population_fitness_memory")
                        .and_then(serde_json::Value::as_f64)
                        .unwrap_or_default()
                        > proposal.base_fitness
                );
                let retrieval = proposal
                    .strategy
                    .get("memory_retrieval")
                    .expect("memory retrieval should be recorded");
                assert!(
                    retrieval
                        .get("matching_engagement_count")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or_default()
                        >= 1
                );
                assert!(
                    proposal.strategy.get("adversarial_corpus").is_some(),
                    "memory-enriched proposal should include adversarial corpus metadata"
                );
                assert!(
                    proposal.strategy.get("adversarial_pressure").is_some(),
                    "memory-enriched proposal should include adversarial pressure metadata"
                );
            }
            other => panic!(
                "expected proposing state after memory answer, got {:?}",
                other_state_label(other)
            ),
        }

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn kitten_memory_query_falls_back_when_sphinx_is_unavailable() {
        let root = temp_root("memory-fallback");
        let config_path = config_path();
        let mut config = load_config(&config_path).unwrap();
        configure_paths(&mut config, &root);
        configure_memory(&mut config, &root);
        let substrate = substrate(&config);

        let mut kitten = KittenAgent::new(
            AgentId::new("kitten", "primary"),
            &config_path,
            config.clone(),
            substrate,
        );
        let proposal = ProposedCandidate {
            generation: 7,
            generation_created_at_ms: 1_800_810_000_000,
            ranking_id: "ranking:test:7".to_string(),
            validation_batch_id: "validation:test:7".to_string(),
            strategy_id: "office_baseline_control_kitten".to_string(),
            experiment_id: "experiment:office_baseline_control".to_string(),
            experiment_path: office_control_experiment(),
            materialization_id: "materialization:test:7".to_string(),
            validation_bundle_id: "validation-bundle:test:7".to_string(),
            base_fitness: 0.61,
            fitness: 0.61,
            autonomous_fitness: None,
            strategy: json!({
                "source": "kitten_population_candidate",
                "selection_source": "restored_population",
                "population_fitness": 0.61,
                "population_fitness_replay": 0.61,
            }),
        };
        let runtime_env = env_with_pheromones(
            vec![runtime_pheromone("evt-1", 1_800_810_000)],
            1_800_810_001,
        );
        let (memory_state, _) = kitten
            .maybe_begin_memory_query(&runtime_env, proposal, 1_800_810_001_000)
            .await
            .unwrap();
        kitten.state = memory_state;

        kitten.tick(&env(1_800_810_002)).await.unwrap();
        assert_eq!(kitten.state_label(), "awaiting_memory");
        kitten.tick(&env(1_800_810_003)).await.unwrap();
        assert_eq!(kitten.state_label(), "proposing");
        match &kitten.state {
            super::KittenState::Proposing(proposal) => {
                assert_eq!(
                    proposal
                        .strategy
                        .get("population_fitness_memory")
                        .and_then(serde_json::Value::as_f64),
                    Some(proposal.base_fitness)
                );
                assert_eq!(
                    proposal
                        .strategy
                        .get("memory_retrieval")
                        .and_then(|value| value.get("status"))
                        .and_then(serde_json::Value::as_str),
                    Some("fallback")
                );
                assert!(
                    proposal.strategy.get("adversarial_corpus").is_some(),
                    "fallback proposal should still include adversarial corpus metadata"
                );
                assert!(
                    proposal.strategy.get("adversarial_pressure").is_some(),
                    "fallback proposal should still include adversarial pressure metadata"
                );
            }
            other => panic!(
                "expected proposing fallback state, got {:?}",
                other_state_label(other)
            ),
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn deception_interactions_raise_pending_proposal_fitness() {
        let root = temp_root("deception-fitness");
        let config_path = config_path();
        let mut config = load_config(&config_path).unwrap();
        configure_paths(&mut config, &root);
        let substrate = substrate(&config);

        let kitten = KittenAgent::new(
            AgentId::new("kitten", "primary"),
            &config_path,
            config,
            substrate,
        );
        let proposal = ProposedCandidate {
            generation: 7,
            generation_created_at_ms: 1_800_815_000_000,
            ranking_id: "ranking:test:7".to_string(),
            validation_batch_id: "validation:test:7".to_string(),
            strategy_id: "office_baseline_control_kitten".to_string(),
            experiment_id: "experiment:office_baseline_control".to_string(),
            experiment_path: office_control_experiment(),
            materialization_id: "materialization:test:7".to_string(),
            validation_bundle_id: "validation-bundle:test:7".to_string(),
            base_fitness: 0.55,
            fitness: 0.62,
            autonomous_fitness: None,
            strategy: json!({
                "source": "kitten_population_candidate",
                "selection_source": "restored_population",
                "population_fitness": 0.62,
                "population_fitness_replay": 0.55,
            }),
        };

        let enriched = kitten
            .apply_deception_signal(
                proposal,
                &env_with_pheromones(
                    vec![calico_interaction_pheromone(
                        "calico:finance_canary:1",
                        1_800_815_000,
                    )],
                    1_800_815_001,
                ),
            )
            .unwrap();

        assert!(enriched.fitness > 0.62);
        assert_eq!(
            enriched
                .strategy
                .get("deception_signal")
                .and_then(|value| value.get("signal_count"))
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert!(
            enriched
                .strategy
                .get("population_fitness_deception")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or_default()
                > 0.62
        );

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn deception_interactions_persist_into_adversarial_pressure_metadata() {
        let root = temp_root("deception-pressure");
        let config_path = config_path();
        let mut config = load_config(&config_path).unwrap();
        configure_paths(&mut config, &root);
        let substrate = substrate(&config);

        let kitten = KittenAgent::new(
            AgentId::new("kitten", "primary"),
            &config_path,
            config,
            substrate,
        );
        let proposal = ProposedCandidate {
            generation: 9,
            generation_created_at_ms: 1_800_816_000_000,
            ranking_id: "ranking:test:9".to_string(),
            validation_batch_id: "validation:test:9".to_string(),
            strategy_id: "office_baseline_control_kitten".to_string(),
            experiment_id: "experiment:office_baseline_control".to_string(),
            experiment_path: office_control_experiment(),
            materialization_id: "materialization:test:9".to_string(),
            validation_bundle_id: "validation-bundle:test:9".to_string(),
            base_fitness: 0.55,
            fitness: 0.62,
            autonomous_fitness: None,
            strategy: json!({
                "source": "kitten_population_candidate",
                "selection_source": "restored_population",
                "population_fitness": 0.62,
                "population_fitness_replay": 0.55,
            }),
        };

        let proposal = kitten
            .apply_deception_signal(
                proposal,
                &env_with_pheromones(
                    vec![calico_interaction_pheromone(
                        "calico:finance_canary:1",
                        1_800_816_000,
                    )],
                    1_800_816_001,
                ),
            )
            .unwrap();
        let proposal = kitten
            .apply_adversarial_pressure(proposal, 1_800_816_001_000)
            .await
            .unwrap();

        let pressure = proposal
            .strategy
            .get("adversarial_pressure")
            .expect("adversarial pressure metadata should exist");
        assert!(
            pressure
                .get("deception_adjusted_fitness")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or_default()
                > 0.62
        );
        assert!(
            pressure
                .get("deception_signal_score")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or_default()
                > 0.0
        );

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn kitten_freezes_adversarial_corpus_per_generation() {
        let root = temp_root("generation-corpus");
        let config_path = config_path();
        let mut config = load_config(&config_path).unwrap();
        configure_paths(&mut config, &root);
        let substrate = substrate(&config);

        let kitten = KittenAgent::new(
            AgentId::new("kitten", "primary"),
            &config_path,
            config,
            substrate,
        );

        let proposal_for =
            |strategy_id: &str, generation: usize, ranking_id: &str| ProposedCandidate {
                generation,
                generation_created_at_ms: 1_800_820_000_000 + generation as i64,
                ranking_id: ranking_id.to_string(),
                validation_batch_id: format!("validation:{generation}"),
                strategy_id: strategy_id.to_string(),
                experiment_id: "experiment:office_baseline_control".to_string(),
                experiment_path: office_control_experiment(),
                materialization_id: format!("materialization:{strategy_id}"),
                validation_bundle_id: format!("validation-bundle:{strategy_id}"),
                base_fitness: 0.60,
                fitness: 0.60,
                autonomous_fitness: None,
                strategy: json!({
                    "source": "kitten_population_candidate",
                    "selection_source": "restored_population",
                    "population_fitness": 0.60,
                    "population_fitness_replay": 0.60,
                }),
            };

        let first = kitten
            .apply_adversarial_pressure(
                proposal_for("candidate-a", 9, "ranking:g9"),
                1_800_820_001_000,
            )
            .await
            .unwrap();
        let second = kitten
            .apply_adversarial_pressure(
                proposal_for("candidate-b", 9, "ranking:g9"),
                1_800_820_002_000,
            )
            .await
            .unwrap();
        let third = kitten
            .apply_adversarial_pressure(
                proposal_for("candidate-c", 10, "ranking:g10"),
                1_800_820_003_000,
            )
            .await
            .unwrap();

        let first_sequence = first
            .strategy
            .get("adversarial_corpus")
            .and_then(|value| value.get("sequence_id"))
            .and_then(serde_json::Value::as_str)
            .unwrap();
        let second_sequence = second
            .strategy
            .get("adversarial_corpus")
            .and_then(|value| value.get("sequence_id"))
            .and_then(serde_json::Value::as_str)
            .unwrap();
        let third_sequence = third
            .strategy
            .get("adversarial_corpus")
            .and_then(|value| value.get("sequence_id"))
            .and_then(serde_json::Value::as_str)
            .unwrap();

        assert_eq!(first_sequence, second_sequence);
        assert_ne!(first_sequence, third_sequence);

        let _ = fs::remove_dir_all(root);
    }

    fn other_state_label(state: &super::KittenState) -> &'static str {
        match state {
            super::KittenState::AwaitingDrift => "awaiting_drift",
            super::KittenState::Mutating(_) => "mutating",
            super::KittenState::Evaluating(_) => "evaluating",
            super::KittenState::Verifying(_) => "verifying",
            super::KittenState::AwaitingMemory(_) => "awaiting_memory",
            super::KittenState::Proposing(_) => "proposing",
        }
    }
}
