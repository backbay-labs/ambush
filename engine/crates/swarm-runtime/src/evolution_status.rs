use crate::canary::{CanaryRunRecord, CanaryRunStatus};
use crate::config::load_config;
use crate::evolution::{
    EvolutionAssuranceRolloutState, EvolutionHandoffRecord, EvolutionHandoffReport,
    EvolutionProofStoreError, EvolutionProposalAssuranceDecision, EvolutionProposalReviewState,
    EvolutionProposalStoreError, EvolutionSolverProofStatus, FileEvolutionProofStore,
    FileEvolutionProposalStore, active_assurance_waiver, assurance_rollout_state,
};
use crate::mutation::{
    EvolutionAutonomousVariantRecipeKind, EvolutionBenchmarkRunReport, EvolutionEpisodeRecord,
    EvolutionEpisodeStoreError, EvolutionMutationRankingRecord, EvolutionMutationRankingReport,
    EvolutionPopulationState, FileEvolutionBenchmarkStore, FileEvolutionEpisodeStore,
};
use crate::selection::EvolutionRankedCandidateSelectionRecord;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use swarm_core::config::SwarmConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KittenExecutionState {
    AwaitingDrift,
    Mutating,
    Evaluating,
    Verifying,
    Proposing,
}

impl KittenExecutionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingDrift => "awaiting_drift",
            Self::Mutating => "mutating",
            Self::Evaluating => "evaluating",
            Self::Verifying => "verifying",
            Self::Proposing => "proposing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KittenStatusRecord {
    pub updated_at_ms: i64,
    pub state: KittenExecutionState,
    pub observation_count: Option<usize>,
    pub degraded_ratio: Option<f64>,
    pub strategy_id: Option<String>,
    pub fitness: Option<f64>,
    pub last_error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum KittenStatusStoreError {
    #[error("failed to read kitten status file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write kitten status file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse kitten status file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Clone)]
pub struct FileKittenStatusStore {
    path: PathBuf,
}

impl FileKittenStatusStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, KittenStatusStoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|source| KittenStatusStoreError::Write {
            path: root.clone(),
            source,
        })?;
        Ok(Self {
            path: root.join("kitten-status.json"),
        })
    }

    pub fn load(&self) -> Result<Option<KittenStatusRecord>, KittenStatusStoreError> {
        if !self.path.exists() {
            return Ok(None);
        }
        let raw =
            fs::read_to_string(&self.path).map_err(|source| KittenStatusStoreError::Read {
                path: self.path.clone(),
                source,
            })?;
        let record =
            serde_json::from_str(&raw).map_err(|source| KittenStatusStoreError::Parse {
                path: self.path.clone(),
                source,
            })?;
        Ok(Some(record))
    }

    pub fn persist(&self, record: &KittenStatusRecord) -> Result<(), KittenStatusStoreError> {
        let raw = serde_json::to_string_pretty(record).map_err(|source| {
            KittenStatusStoreError::Parse {
                path: self.path.clone(),
                source,
            }
        })?;
        fs::write(&self.path, raw).map_err(|source| KittenStatusStoreError::Write {
            path: self.path.clone(),
            source,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionPopulationSummary {
    pub configured_population_size: usize,
    pub current_population_size: usize,
    pub ready_for_review: usize,
    pub unique_strategies: usize,
    pub diversity: f64,
    pub best_fitness: Option<f64>,
    pub mean_fitness: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionVerificationSummary {
    pub latest_ranking_id: Option<String>,
    pub candidate_count: usize,
    pub ready_for_review: usize,
    pub blocked: usize,
    pub pass_rate: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionAdmissionSummary {
    pub total_selections: usize,
    pub pending_review: usize,
    pub accepted_for_canary: usize,
    pub rejected: usize,
    pub blocked: usize,
    pub deferred: usize,
    pub active_canaries: usize,
    pub completed_canaries: usize,
    pub rolled_back_canaries: usize,
    pub halted_canaries: usize,
    pub canary_admission_rate: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionFormalProofSummary {
    pub latest_proof_id: Option<String>,
    pub proof_system: Option<String>,
    pub solver_status: Option<EvolutionSolverProofStatus>,
    pub timed_out: bool,
    pub counterexample_present: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionAssuranceStatusSummary {
    pub latest_proposal_id: Option<String>,
    pub latest_handoff_id: Option<String>,
    pub rollout_state: Option<EvolutionAssuranceRolloutState>,
    pub decision: Option<EvolutionProposalAssuranceDecision>,
    pub blocked_reason_count: usize,
    pub detector: Option<String>,
    pub required_catch_rate: Option<f64>,
    pub actual_catch_rate: Option<f64>,
    pub actionable_gap_count: Option<usize>,
    pub solver_status: Option<EvolutionSolverProofStatus>,
    pub active_waiver_id: Option<String>,
    pub active_waiver_operator_id: Option<String>,
    pub waived_gap_count: Option<usize>,
    pub waiver_expires_at_ms: Option<i64>,
    pub waiver_reason: Option<String>,
    pub latest_rollout_gate: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionAdversarialSummary {
    pub current_generation: Option<usize>,
    pub latest_episode_id: Option<String>,
    pub latest_strategy_id: Option<String>,
    pub corpus_sequence_id: Option<String>,
    pub corpus_suite_name: Option<String>,
    pub corpus_version: Option<String>,
    pub best_genome_hash: Option<String>,
    pub latest_final_fitness: Option<f64>,
    pub latest_evasion_pressure_score: Option<f64>,
    pub latest_evasion_gap_closure_rate: Option<f64>,
    pub latest_evasion_focus_gap_count: Option<usize>,
    pub latest_event_detection_rate: Option<f64>,
    pub latest_event_evasion_rate: Option<f64>,
    pub latest_threat_class_detection_rate: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionAutonomousFitnessSummary {
    pub evaluated_candidate_count: usize,
    pub latest_strategy_id: Option<String>,
    pub latest_recipe_kind: Option<EvolutionAutonomousVariantRecipeKind>,
    pub latest_parent_strategy_ids: Vec<String>,
    pub latest_measured_fitness: Option<f64>,
    pub latest_catch_rate: Option<f64>,
    pub latest_false_positive_rate: Option<f64>,
    pub latest_false_positive_fitness: Option<f64>,
    pub latest_max_detect_latency_us: Option<u64>,
    pub latest_latency_budget_us: Option<u64>,
    pub latest_latency_fitness: Option<f64>,
    pub latest_corpus_suite_name: Option<String>,
    pub latest_corpus_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionBenchmarkSummary {
    pub latest_benchmark_id: Option<String>,
    pub label: Option<String>,
    pub requested_generation_count: usize,
    pub completed_generation_count: usize,
    pub latest_leader_strategy_id: Option<String>,
    pub latest_leader_generation: Option<usize>,
    pub latest_measured_fitness: Option<f64>,
    pub latest_catch_rate: Option<f64>,
    pub latest_delta_from_previous: Option<f64>,
    pub latest_delta_from_first: Option<f64>,
    pub corpus_suite_name: Option<String>,
    pub corpus_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionStatusReport {
    pub enabled: bool,
    pub generation_count: usize,
    pub current_generation: Option<usize>,
    pub kitten_state: Option<KittenExecutionState>,
    pub kitten_status_updated_at_ms: Option<i64>,
    pub latest_strategy_id: Option<String>,
    pub latest_fitness: Option<f64>,
    pub observation_count: Option<usize>,
    pub degraded_ratio: Option<f64>,
    pub last_error: Option<String>,
    pub population: EvolutionPopulationSummary,
    pub verification: EvolutionVerificationSummary,
    pub admission: EvolutionAdmissionSummary,
    pub formal_proof: EvolutionFormalProofSummary,
    pub assurance: EvolutionAssuranceStatusSummary,
    pub adversarial: EvolutionAdversarialSummary,
    pub autonomous: EvolutionAutonomousFitnessSummary,
    pub benchmark: EvolutionBenchmarkSummary,
}

#[derive(Debug, thiserror::Error)]
pub enum EvolutionStatusError {
    #[error(transparent)]
    Config(#[from] crate::config::RuntimeConfigError),

    #[error(transparent)]
    KittenStatus(#[from] KittenStatusStoreError),

    #[error(transparent)]
    EpisodeStore(#[from] EvolutionEpisodeStoreError),

    #[error(transparent)]
    BenchmarkStore(#[from] crate::mutation::EvolutionBenchmarkStoreError),

    #[error(transparent)]
    ProofStore(#[from] EvolutionProofStoreError),

    #[error(transparent)]
    ProposalStore(#[from] EvolutionProposalStoreError),

    #[error("failed to read artifact file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse artifact file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Clone)]
struct EvolutionStatusPaths {
    ranking_results_dir: PathBuf,
    selection_results_dir: PathBuf,
    canary_results_dir: PathBuf,
    handoff_results_dir: PathBuf,
    population_results_dir: PathBuf,
    episode_results_dir: PathBuf,
    benchmark_results_dir: PathBuf,
    proof_results_dir: PathBuf,
    queue_results_dir: PathBuf,
}

pub struct DefaultEvolutionStatusHarness {
    config: SwarmConfig,
    paths: EvolutionStatusPaths,
}

impl DefaultEvolutionStatusHarness {
    pub fn from_path(config_path: impl AsRef<Path>) -> Result<Self, EvolutionStatusError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config(config_path, config)
    }

    pub fn from_config(
        config_path: impl AsRef<Path>,
        config: SwarmConfig,
    ) -> Result<Self, EvolutionStatusError> {
        let base = config_path
            .as_ref()
            .parent()
            .unwrap_or_else(|| Path::new("."));
        let paths = &config.evolution.paths;
        let population_results_dir =
            resolve_repo_relative_path(base, &paths.evolution_population_results_dir);
        Ok(Self {
            paths: EvolutionStatusPaths {
                ranking_results_dir: resolve_repo_relative_path(
                    base,
                    &paths.evolution_ranking_results_dir,
                ),
                selection_results_dir: resolve_repo_relative_path(
                    base,
                    &paths.evolution_selection_results_dir,
                ),
                canary_results_dir: resolve_repo_relative_path(base, &paths.canary_results_dir),
                handoff_results_dir: resolve_repo_relative_path(
                    base,
                    &paths.evolution_handoff_results_dir,
                ),
                episode_results_dir: population_results_dir.join("episodes"),
                benchmark_results_dir: population_results_dir.join("benchmarks"),
                population_results_dir,
                proof_results_dir: resolve_repo_relative_path(
                    base,
                    &paths.evolution_proof_results_dir,
                ),
                queue_results_dir: resolve_repo_relative_path(
                    base,
                    &paths.evolution_queue_results_dir,
                ),
            },
            config,
        })
    }

    pub fn status(&self) -> Result<EvolutionStatusReport, EvolutionStatusError> {
        let ranking_records =
            load_index::<RankingIndex>(self.paths.ranking_results_dir.join("index.json"))?
                .map(|index| index.entries)
                .unwrap_or_default();
        let latest_ranking = ranking_records
            .first()
            .map(|record| {
                load_json::<EvolutionMutationRankingReport>(Path::new(&record.bundle_path))
            })
            .transpose()?
            .flatten();
        let population = load_json::<EvolutionPopulationState>(
            self.paths.population_results_dir.join("state.json"),
        )?;
        let selections =
            load_index::<SelectionIndex>(self.paths.selection_results_dir.join("index.json"))?
                .map(|index| index.entries)
                .unwrap_or_default();
        let canaries = load_index::<CanaryIndex>(self.paths.canary_results_dir.join("index.json"))?
            .map(|index| index.entries)
            .unwrap_or_default();
        let kitten_status =
            FileKittenStatusStore::open(&self.paths.population_results_dir)?.load()?;
        let episode_store = if self.paths.episode_results_dir.exists() {
            Some(FileEvolutionEpisodeStore::open(
                &self.paths.episode_results_dir,
            )?)
        } else {
            None
        };
        let episode_records = match &episode_store {
            Some(store) => store.latest(usize::MAX)?,
            None => Vec::new(),
        };
        let latest_episode = episode_records.first().cloned();
        let latest_episode_report = match (&episode_store, latest_episode.as_ref()) {
            (Some(store), Some(record)) => {
                store.load(&record.episode_id)?.map(|lookup| lookup.report)
            }
            _ => None,
        };
        let latest_benchmark_report = if self.paths.benchmark_results_dir.exists() {
            let store = FileEvolutionBenchmarkStore::open(&self.paths.benchmark_results_dir)?;
            match store.latest(1)?.first() {
                Some(record) => store
                    .load(&record.benchmark_id)?
                    .map(|lookup| lookup.report),
                None => None,
            }
        } else {
            None
        };
        let best_episode = episode_records.iter().cloned().max_by(|left, right| {
            left.final_fitness
                .partial_cmp(&right.final_fitness)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.created_at_ms.cmp(&right.created_at_ms))
        });
        let best_genome_hash = match (&episode_store, best_episode.as_ref()) {
            (Some(store), Some(record)) => store
                .load(&record.episode_id)?
                .map(|lookup| lookup.report.blue_genome_hash),
            _ => None,
        };
        let latest_solver_proof = load_latest_solver_proof(&self.paths.proof_results_dir)?;
        let latest_proposal = load_latest_proposal(&self.paths.queue_results_dir)?;
        let latest_handoff = load_latest_handoff(&self.paths.handoff_results_dir)?;
        let current_generation = latest_episode
            .as_ref()
            .map(|record| record.generation)
            .or_else(|| {
                population.as_ref().and_then(|state| {
                    state
                        .members
                        .iter()
                        .map(|candidate| candidate.generation)
                        .max()
                })
            })
            .or_else(|| (!ranking_records.is_empty()).then_some(ranking_records.len()));

        let population_summary =
            build_population_summary(self.config.evolution.population_size, population.as_ref());
        let verification = build_verification_summary(
            ranking_records
                .first()
                .map(|record| record.ranking_id.clone()),
            latest_ranking.as_ref(),
        );
        let admission = build_admission_summary(&selections, &canaries);
        let latest_strategy_id = latest_episode
            .as_ref()
            .map(|record| record.strategy_id.clone())
            .or_else(|| {
                population
                    .as_ref()
                    .and_then(|state| {
                        state
                            .members
                            .iter()
                            .min_by_key(|candidate| candidate.population_rank)
                    })
                    .map(|candidate| candidate.strategy_id.clone())
            })
            .or_else(|| {
                kitten_status
                    .as_ref()
                    .and_then(|status| status.strategy_id.clone())
            });
        let latest_fitness = latest_episode
            .as_ref()
            .map(|record| record.final_fitness)
            .or_else(|| {
                population.as_ref().and_then(|state| {
                    state
                        .members
                        .iter()
                        .max_by(|left, right| {
                            left.fitness
                                .partial_cmp(&right.fitness)
                                .unwrap_or(std::cmp::Ordering::Equal)
                        })
                        .map(|candidate| candidate.fitness)
                })
            })
            .or_else(|| kitten_status.as_ref().and_then(|status| status.fitness));

        Ok(EvolutionStatusReport {
            enabled: self.config.evolution.enabled,
            generation_count: ranking_records.len(),
            current_generation,
            kitten_state: kitten_status.as_ref().map(|status| status.state),
            kitten_status_updated_at_ms: kitten_status.as_ref().map(|status| status.updated_at_ms),
            latest_strategy_id,
            latest_fitness,
            observation_count: kitten_status
                .as_ref()
                .and_then(|status| status.observation_count),
            degraded_ratio: kitten_status
                .as_ref()
                .and_then(|status| status.degraded_ratio),
            last_error: kitten_status
                .as_ref()
                .and_then(|status| status.last_error.clone()),
            population: population_summary,
            verification,
            admission,
            formal_proof: build_formal_proof_summary(latest_solver_proof.as_ref()),
            assurance: build_assurance_summary(
                &self.config,
                latest_proposal.as_ref(),
                latest_handoff.as_ref(),
            ),
            adversarial: build_adversarial_summary(
                current_generation,
                latest_episode.as_ref(),
                best_genome_hash,
            ),
            autonomous: build_autonomous_fitness_summary(
                population.as_ref(),
                latest_episode_report.as_ref(),
            ),
            benchmark: build_benchmark_summary(latest_benchmark_report.as_ref()),
        })
    }
}

pub fn render_evolution_status(report: &EvolutionStatusReport) -> String {
    let mut lines = vec![
        "Swarm Team Six Evolution Status".to_string(),
        format!("Enabled: {}", report.enabled),
        format!("Generation count: {}", report.generation_count),
        format!(
            "Current generation: {}",
            report
                .current_generation
                .map(|generation| generation.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        ),
        format!(
            "Drift state: {}",
            report
                .kitten_state
                .map(KittenExecutionState::as_str)
                .unwrap_or("unknown")
        ),
        format!(
            "Population: {}/{} ready={} diversity={:.3}",
            report.population.current_population_size,
            report.population.configured_population_size,
            report.population.ready_for_review,
            report.population.diversity
        ),
        format!(
            "Fitness: best={} mean={} latest={}",
            format_optional_f64(report.population.best_fitness),
            format_optional_f64(report.population.mean_fitness),
            format_optional_f64(report.latest_fitness)
        ),
        format!(
            "Verification: candidates={} ready={} blocked={} pass_rate={:.3}",
            report.verification.candidate_count,
            report.verification.ready_for_review,
            report.verification.blocked,
            report.verification.pass_rate
        ),
        format!(
            "Admission: selections={} accepted={} blocked={} rejected={} active_canaries={} admission_rate={:.3}",
            report.admission.total_selections,
            report.admission.accepted_for_canary,
            report.admission.blocked,
            report.admission.rejected,
            report.admission.active_canaries,
            report.admission.canary_admission_rate
        ),
    ];

    if let Some(strategy_id) = &report.latest_strategy_id {
        lines.push(format!("Latest strategy: {strategy_id}"));
    }
    if let Some(proof_id) = &report.formal_proof.latest_proof_id {
        lines.push(format!(
            "Formal proof: {} | status={} | timed_out={} | counterexample_present={}",
            proof_id,
            report
                .formal_proof
                .solver_status
                .map(solver_proof_status_label)
                .unwrap_or("n/a"),
            report.formal_proof.timed_out,
            report.formal_proof.counterexample_present
        ));
    }
    if report.assurance.latest_proposal_id.is_some()
        || report.assurance.latest_handoff_id.is_some()
        || report.assurance.latest_rollout_gate.is_some()
    {
        lines.push(format!(
            "Assurance: proposal={} decision={} rollout={} detector={} catch_rate={}/{} blocked_checks={} solver={}",
            report.assurance.latest_proposal_id.as_deref().unwrap_or("n/a"),
            report
                .assurance
                .decision
                .map(assurance_decision_label)
                .unwrap_or("n/a"),
            report
                .assurance
                .rollout_state
                .map(assurance_rollout_state_label)
                .unwrap_or("n/a"),
            report.assurance.detector.as_deref().unwrap_or("n/a"),
            format_optional_f64(report.assurance.actual_catch_rate),
            format_optional_f64(report.assurance.required_catch_rate),
            report.assurance.blocked_reason_count,
            report
                .assurance
                .solver_status
                .map(solver_proof_status_label)
                .unwrap_or("n/a")
        ));
        if let Some(handoff_id) = &report.assurance.latest_handoff_id {
            lines.push(format!("Latest handoff: {handoff_id}"));
        }
        if let Some(waiver_id) = &report.assurance.active_waiver_id {
            lines.push(format!(
                "Active waiver: {} | operator={} | expires_at={} | waived_gaps={}",
                waiver_id,
                report
                    .assurance
                    .active_waiver_operator_id
                    .as_deref()
                    .unwrap_or("n/a"),
                report
                    .assurance
                    .waiver_expires_at_ms
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                report.assurance.waived_gap_count.unwrap_or_default()
            ));
            if let Some(reason) = &report.assurance.waiver_reason {
                lines.push(format!("Waiver reason: {reason}"));
            }
        }
        if let Some(gate) = &report.assurance.latest_rollout_gate {
            lines.push(format!("Rollout gate: {gate}"));
        }
    }
    if let (Some(suite_name), Some(version)) = (
        report.adversarial.corpus_suite_name.as_deref(),
        report.adversarial.corpus_version.as_deref(),
    ) {
        lines.push(format!("Adversarial corpus: {suite_name}@{version}"));
    }
    if let Some(episode_id) = &report.adversarial.latest_episode_id {
        lines.push(format!("Latest episode: {episode_id}"));
    }
    if let Some(genome_hash) = &report.adversarial.best_genome_hash {
        lines.push(format!("Best genome: {genome_hash}"));
    }
    if report.autonomous.evaluated_candidate_count > 0 {
        lines.push(format!(
            "Autonomous fitness: candidates={} strategy={} measured={} catch_rate={} fp_rate={} latency={}/{} recipe={}",
            report.autonomous.evaluated_candidate_count,
            report.autonomous.latest_strategy_id.as_deref().unwrap_or("n/a"),
            format_optional_f64(report.autonomous.latest_measured_fitness),
            format_optional_f64(report.autonomous.latest_catch_rate),
            format_optional_f64(report.autonomous.latest_false_positive_rate),
            format_optional_u64(report.autonomous.latest_max_detect_latency_us),
            format_optional_u64(report.autonomous.latest_latency_budget_us),
            report
                .autonomous
                .latest_recipe_kind
                .map(autonomous_recipe_label)
                .unwrap_or("n/a")
        ));
        if !report.autonomous.latest_parent_strategy_ids.is_empty() {
            lines.push(format!(
                "Autonomous parents: {}",
                report.autonomous.latest_parent_strategy_ids.join(", ")
            ));
        }
    }
    if report.benchmark.completed_generation_count > 0 {
        lines.push(format!(
            "Benchmark: run={} generations={}/{} leader={} gen={} measured={} catch_rate={} delta_prev={} delta_first={}",
            report
                .benchmark
                .latest_benchmark_id
                .as_deref()
                .unwrap_or("n/a"),
            report.benchmark.completed_generation_count,
            report.benchmark.requested_generation_count,
            report
                .benchmark
                .latest_leader_strategy_id
                .as_deref()
                .unwrap_or("n/a"),
            report
                .benchmark
                .latest_leader_generation
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string()),
            format_optional_f64(report.benchmark.latest_measured_fitness),
            format_optional_f64(report.benchmark.latest_catch_rate),
            format_optional_f64(report.benchmark.latest_delta_from_previous),
            format_optional_f64(report.benchmark.latest_delta_from_first),
        ));
    }
    if let Some(observation_count) = report.observation_count {
        lines.push(format!("Latest observation window: {observation_count}"));
    }
    if let Some(degraded_ratio) = report.degraded_ratio {
        lines.push(format!("Latest degraded ratio: {degraded_ratio:.3}"));
    }
    if let Some(updated_at_ms) = report.kitten_status_updated_at_ms {
        lines.push(format!("Kitten updated: {updated_at_ms}"));
    }
    if let Some(error) = &report.last_error {
        lines.push(format!("Last error: {error}"));
    }

    lines.join("\n")
}

fn build_adversarial_summary(
    current_generation: Option<usize>,
    latest_episode: Option<&EvolutionEpisodeRecord>,
    best_genome_hash: Option<String>,
) -> EvolutionAdversarialSummary {
    EvolutionAdversarialSummary {
        current_generation,
        latest_episode_id: latest_episode.map(|record| record.episode_id.clone()),
        latest_strategy_id: latest_episode.map(|record| record.strategy_id.clone()),
        corpus_sequence_id: latest_episode
            .map(|record| record.adversarial_corpus_sequence_id.clone()),
        corpus_suite_name: latest_episode
            .map(|record| record.adversarial_corpus_suite_name.clone()),
        corpus_version: latest_episode.map(|record| record.adversarial_corpus_version.clone()),
        best_genome_hash,
        latest_final_fitness: latest_episode.map(|record| record.final_fitness),
        latest_evasion_pressure_score: latest_episode.map(|record| record.evasion_pressure_score),
        latest_evasion_gap_closure_rate: latest_episode
            .map(|record| record.evasion_gap_closure_rate),
        latest_evasion_focus_gap_count: latest_episode.map(|record| record.evasion_focus_gap_count),
        latest_event_detection_rate: latest_episode.map(|record| record.event_detection_rate),
        latest_event_evasion_rate: latest_episode.map(|record| record.event_evasion_rate),
        latest_threat_class_detection_rate: latest_episode
            .map(|record| record.threat_class_detection_rate),
    }
}

fn build_autonomous_fitness_summary(
    population: Option<&EvolutionPopulationState>,
    latest_episode_report: Option<&crate::mutation::EvolutionEpisodeReport>,
) -> EvolutionAutonomousFitnessSummary {
    let population_autonomous_count = population
        .map(|state| {
            state
                .members
                .iter()
                .filter(|candidate| candidate.autonomous_fitness.is_some())
                .count()
        })
        .unwrap_or_default();
    let latest_population_candidate = population.and_then(|state| {
        state
            .members
            .iter()
            .filter_map(|candidate| {
                candidate
                    .autonomous_fitness
                    .as_ref()
                    .map(|measurement| (candidate, measurement))
            })
            .max_by(|(left, _), (right, _)| {
                left.generation
                    .cmp(&right.generation)
                    .then_with(|| {
                        left.generation_created_at_ms
                            .cmp(&right.generation_created_at_ms)
                    })
                    .then_with(|| right.population_rank.cmp(&left.population_rank))
            })
    });
    let selected = latest_episode_report
        .and_then(|report| {
            report
                .autonomous_fitness
                .as_ref()
                .map(|measurement| (report.strategy_id.as_str(), measurement))
        })
        .or_else(|| {
            latest_population_candidate
                .map(|(candidate, measurement)| (candidate.strategy_id.as_str(), measurement))
        });

    let evaluated_candidate_count = if population_autonomous_count == 0 && selected.is_some() {
        1
    } else {
        population_autonomous_count
    };

    match selected {
        Some((strategy_id, measurement)) => EvolutionAutonomousFitnessSummary {
            evaluated_candidate_count,
            latest_strategy_id: Some(strategy_id.to_string()),
            latest_recipe_kind: Some(measurement.lineage.recipe_kind),
            latest_parent_strategy_ids: measurement.lineage.parent_strategy_ids.clone(),
            latest_measured_fitness: Some(measurement.measured_fitness),
            latest_catch_rate: Some(measurement.catch_rate),
            latest_false_positive_rate: Some(measurement.false_positive_rate),
            latest_false_positive_fitness: Some(measurement.false_positive_fitness),
            latest_max_detect_latency_us: Some(measurement.max_detect_latency_us),
            latest_latency_budget_us: Some(measurement.latency_budget_us),
            latest_latency_fitness: Some(measurement.latency_fitness),
            latest_corpus_suite_name: Some(measurement.corpus_suite_name.clone()),
            latest_corpus_version: Some(measurement.corpus_version.clone()),
        },
        None => EvolutionAutonomousFitnessSummary {
            evaluated_candidate_count,
            latest_strategy_id: None,
            latest_recipe_kind: None,
            latest_parent_strategy_ids: Vec::new(),
            latest_measured_fitness: None,
            latest_catch_rate: None,
            latest_false_positive_rate: None,
            latest_false_positive_fitness: None,
            latest_max_detect_latency_us: None,
            latest_latency_budget_us: None,
            latest_latency_fitness: None,
            latest_corpus_suite_name: None,
            latest_corpus_version: None,
        },
    }
}

fn build_benchmark_summary(
    latest_benchmark_report: Option<&EvolutionBenchmarkRunReport>,
) -> EvolutionBenchmarkSummary {
    let Some(report) = latest_benchmark_report else {
        return EvolutionBenchmarkSummary {
            latest_benchmark_id: None,
            label: None,
            requested_generation_count: 0,
            completed_generation_count: 0,
            latest_leader_strategy_id: None,
            latest_leader_generation: None,
            latest_measured_fitness: None,
            latest_catch_rate: None,
            latest_delta_from_previous: None,
            latest_delta_from_first: None,
            corpus_suite_name: None,
            corpus_version: None,
        };
    };
    let latest_generation = report.generations.last();
    EvolutionBenchmarkSummary {
        latest_benchmark_id: Some(report.benchmark_id.clone()),
        label: Some(report.label.clone()),
        requested_generation_count: report.requested_generation_count,
        completed_generation_count: report.completed_generation_count,
        latest_leader_strategy_id: latest_generation
            .map(|generation| generation.leader_strategy_id.clone()),
        latest_leader_generation: latest_generation.map(|generation| generation.leader_generation),
        latest_measured_fitness: latest_generation
            .map(|generation| generation.leader_measured_fitness),
        latest_catch_rate: latest_generation.map(|generation| generation.leader_catch_rate),
        latest_delta_from_previous: latest_generation
            .and_then(|generation| generation.delta_from_previous.as_ref())
            .map(|delta| delta.measured_fitness),
        latest_delta_from_first: latest_generation
            .and_then(|generation| generation.delta_from_first.as_ref())
            .map(|delta| delta.measured_fitness),
        corpus_suite_name: Some(report.corpus_suite_name.clone()),
        corpus_version: Some(report.corpus_version.clone()),
    }
}

fn build_population_summary(
    configured_population_size: usize,
    population: Option<&EvolutionPopulationState>,
) -> EvolutionPopulationSummary {
    let Some(population) = population else {
        return EvolutionPopulationSummary {
            configured_population_size,
            current_population_size: 0,
            ready_for_review: 0,
            unique_strategies: 0,
            diversity: 0.0,
            best_fitness: None,
            mean_fitness: None,
        };
    };

    let current_population_size = population.members.len();
    let ready_for_review = population
        .members
        .iter()
        .filter(|candidate| candidate.ready_for_review)
        .count();
    let unique_strategies = population
        .members
        .iter()
        .map(|candidate| candidate.strategy_id.clone())
        .collect::<HashSet<_>>()
        .len();
    let diversity = if current_population_size == 0 {
        0.0
    } else {
        unique_strategies as f64 / current_population_size as f64
    };
    let best_fitness = population
        .members
        .iter()
        .map(|candidate| candidate.fitness)
        .reduce(f64::max);
    let mean_fitness = if current_population_size == 0 {
        None
    } else {
        Some(
            population
                .members
                .iter()
                .map(|candidate| candidate.fitness)
                .sum::<f64>()
                / current_population_size as f64,
        )
    };

    EvolutionPopulationSummary {
        configured_population_size,
        current_population_size,
        ready_for_review,
        unique_strategies,
        diversity,
        best_fitness,
        mean_fitness,
    }
}

fn build_verification_summary(
    latest_ranking_id: Option<String>,
    latest_ranking: Option<&EvolutionMutationRankingReport>,
) -> EvolutionVerificationSummary {
    let Some(ranking) = latest_ranking else {
        return EvolutionVerificationSummary {
            latest_ranking_id,
            candidate_count: 0,
            ready_for_review: 0,
            blocked: 0,
            pass_rate: 0.0,
        };
    };
    let candidate_count = ranking.ranked_candidates.len();
    let ready_for_review = ranking
        .ranked_candidates
        .iter()
        .filter(|candidate| candidate.ready_for_review)
        .count();
    let blocked = candidate_count.saturating_sub(ready_for_review);
    let pass_rate = if candidate_count == 0 {
        0.0
    } else {
        ready_for_review as f64 / candidate_count as f64
    };

    EvolutionVerificationSummary {
        latest_ranking_id,
        candidate_count,
        ready_for_review,
        blocked,
        pass_rate,
    }
}

fn build_admission_summary(
    selections: &[EvolutionRankedCandidateSelectionRecord],
    canaries: &[CanaryRunRecord],
) -> EvolutionAdmissionSummary {
    let total_selections = selections.len();
    let pending_review =
        count_review_state(selections, EvolutionProposalReviewState::PendingReview);
    let accepted_for_canary =
        count_review_state(selections, EvolutionProposalReviewState::AcceptedForCanary);
    let rejected = count_review_state(selections, EvolutionProposalReviewState::Rejected);
    let blocked = count_review_state(selections, EvolutionProposalReviewState::Blocked);
    let deferred = count_review_state(selections, EvolutionProposalReviewState::Deferred);
    let active_canaries = count_canary_status(canaries, CanaryRunStatus::Active);
    let completed_canaries = count_canary_status(canaries, CanaryRunStatus::Completed);
    let rolled_back_canaries = count_canary_status(canaries, CanaryRunStatus::RolledBack);
    let halted_canaries = count_canary_status(canaries, CanaryRunStatus::Halted);
    let canary_admission_rate = if total_selections == 0 {
        0.0
    } else {
        accepted_for_canary as f64 / total_selections as f64
    };

    EvolutionAdmissionSummary {
        total_selections,
        pending_review,
        accepted_for_canary,
        rejected,
        blocked,
        deferred,
        active_canaries,
        completed_canaries,
        rolled_back_canaries,
        halted_canaries,
        canary_admission_rate,
    }
}

fn build_formal_proof_summary(
    latest_solver_proof: Option<&crate::evolution::EvolutionProofLookup>,
) -> EvolutionFormalProofSummary {
    let Some(proof) = latest_solver_proof else {
        return EvolutionFormalProofSummary {
            latest_proof_id: None,
            proof_system: None,
            solver_status: None,
            timed_out: false,
            counterexample_present: false,
        };
    };

    let solver_status = proof
        .report
        .solver_summary
        .as_ref()
        .map(|summary| summary.status);
    let timed_out = proof
        .report
        .solver_summary
        .as_ref()
        .map(|summary| summary.timed_out_count > 0)
        .unwrap_or(false);
    let counterexample_present = proof
        .report
        .solver_summary
        .as_ref()
        .map(|summary| summary.counterexample_binding_count > 0)
        .unwrap_or(false);

    EvolutionFormalProofSummary {
        latest_proof_id: Some(proof.report.proof_id.clone()),
        proof_system: Some(proof.report.proof_system.clone()),
        solver_status,
        timed_out,
        counterexample_present,
    }
}

fn build_assurance_summary(
    config: &SwarmConfig,
    latest_proposal: Option<&crate::evolution::EvolutionProposalLookup>,
    latest_handoff: Option<&EvolutionHandoffReport>,
) -> EvolutionAssuranceStatusSummary {
    let Some(proposal) = latest_proposal else {
        return EvolutionAssuranceStatusSummary {
            latest_proposal_id: None,
            latest_handoff_id: latest_handoff.map(|handoff| handoff.handoff_id.clone()),
            rollout_state: None,
            decision: None,
            blocked_reason_count: 0,
            detector: None,
            required_catch_rate: None,
            actual_catch_rate: None,
            actionable_gap_count: None,
            solver_status: None,
            active_waiver_id: None,
            active_waiver_operator_id: None,
            waived_gap_count: None,
            waiver_expires_at_ms: None,
            waiver_reason: None,
            latest_rollout_gate: latest_handoff.and_then(assurance_rollout_gate_from_handoff),
        };
    };

    let assurance = proposal.report.assurance.as_ref();
    let current_time_ms = current_time_ms();
    let rollout_state =
        assurance.map(|summary| assurance_rollout_state(Some(summary), config, current_time_ms));
    let active_waiver = assurance
        .and_then(|summary| active_assurance_waiver(Some(summary), config, current_time_ms));
    let proposal_blocked_reason_count = proposal
        .report
        .blocking_reasons
        .iter()
        .filter(|reason| reason.source == "assurance")
        .count();
    let handoff_blocked_reason_count = latest_handoff
        .map(|handoff| {
            handoff
                .blocking_reasons
                .iter()
                .filter(|reason| reason.source == "assurance")
                .count()
        })
        .unwrap_or(0);
    EvolutionAssuranceStatusSummary {
        latest_proposal_id: Some(proposal.report.proposal_id.clone()),
        latest_handoff_id: latest_handoff.map(|handoff| handoff.handoff_id.clone()),
        rollout_state,
        decision: assurance.map(|summary| summary.decision),
        blocked_reason_count: proposal_blocked_reason_count.max(handoff_blocked_reason_count),
        detector: assurance.map(|summary| summary.coverage.detector.clone()),
        required_catch_rate: assurance.map(|summary| summary.coverage.required_catch_rate),
        actual_catch_rate: assurance.and_then(|summary| summary.coverage.actual_catch_rate),
        actionable_gap_count: assurance.map(|summary| summary.coverage.actionable_gap_count),
        solver_status: assurance.and_then(|summary| summary.solver.status),
        active_waiver_id: active_waiver.map(|waiver| waiver.waiver_id.clone()),
        active_waiver_operator_id: active_waiver.map(|waiver| waiver.operator_id.clone()),
        waived_gap_count: active_waiver.map(|waiver| waiver.waived_gap_count),
        waiver_expires_at_ms: active_waiver.map(|waiver| waiver.expires_at_ms),
        waiver_reason: active_waiver.map(|waiver| waiver.reason.clone()),
        latest_rollout_gate: if rollout_state == Some(EvolutionAssuranceRolloutState::Blocked) {
            latest_handoff
                .and_then(assurance_rollout_gate_from_handoff)
                .or_else(|| {
                    assurance_rollout_gate_from_proposal(
                        proposal.report.blocking_reasons.as_slice(),
                    )
                })
        } else {
            None
        },
    }
}

fn assurance_rollout_gate_from_proposal(
    reasons: &[crate::evolution::EvolutionProposalBlockingReason],
) -> Option<String> {
    reasons
        .iter()
        .find(|reason| reason.source == "assurance")
        .map(|reason| format!("queue {}: {}", reason.name, reason.details))
}

fn assurance_rollout_gate_from_handoff(handoff: &EvolutionHandoffReport) -> Option<String> {
    handoff
        .blocking_reasons
        .iter()
        .find(|reason| reason.source == "assurance")
        .map(|reason| format!("handoff {}: {}", reason.name, reason.details))
}

fn count_review_state(
    selections: &[EvolutionRankedCandidateSelectionRecord],
    state: EvolutionProposalReviewState,
) -> usize {
    selections
        .iter()
        .filter(|record| record.review_state == state)
        .count()
}

fn count_canary_status(canaries: &[CanaryRunRecord], status: CanaryRunStatus) -> usize {
    canaries
        .iter()
        .filter(|record| record.status == status)
        .count()
}

fn load_latest_solver_proof(
    proof_results_dir: &Path,
) -> Result<Option<crate::evolution::EvolutionProofLookup>, EvolutionStatusError> {
    if !proof_results_dir.exists() {
        return Ok(None);
    }
    let store = FileEvolutionProofStore::open(proof_results_dir)?;
    for record in store.records()? {
        let Some(lookup) = store.load(&record.proof_id)? else {
            continue;
        };
        if lookup.report.solver_summary.is_some() {
            return Ok(Some(lookup));
        }
    }
    Ok(None)
}

fn load_latest_proposal(
    queue_results_dir: &Path,
) -> Result<Option<crate::evolution::EvolutionProposalLookup>, EvolutionStatusError> {
    if !queue_results_dir.exists() {
        return Ok(None);
    }
    let store = FileEvolutionProposalStore::open(queue_results_dir)?;
    let Some(record) = store.list(None, None)?.proposals.into_iter().next() else {
        return Ok(None);
    };
    store.load(&record.proposal_id).map_err(Into::into)
}

fn load_latest_handoff(
    handoff_results_dir: &Path,
) -> Result<Option<EvolutionHandoffReport>, EvolutionStatusError> {
    let Some(index) = load_index::<HandoffIndex>(handoff_results_dir.join("index.json"))? else {
        return Ok(None);
    };
    let Some(record) = index.entries.first() else {
        return Ok(None);
    };
    load_json::<EvolutionHandoffReport>(Path::new(&record.bundle_path))
}

fn format_optional_f64(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.3}"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn format_optional_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".to_string())
}

fn autonomous_recipe_label(kind: EvolutionAutonomousVariantRecipeKind) -> &'static str {
    match kind {
        EvolutionAutonomousVariantRecipeKind::SeedControl => "seed_control",
        EvolutionAutonomousVariantRecipeKind::BoundedPerturbation => "bounded_perturbation",
        EvolutionAutonomousVariantRecipeKind::GapExpansion => "gap_expansion",
        EvolutionAutonomousVariantRecipeKind::BoundedCrossover => "bounded_crossover",
    }
}

fn solver_proof_status_label(status: EvolutionSolverProofStatus) -> &'static str {
    match status {
        EvolutionSolverProofStatus::Proved => "proved",
        EvolutionSolverProofStatus::Counterexample => "counterexample",
        EvolutionSolverProofStatus::Timeout => "timeout",
        EvolutionSolverProofStatus::Disabled => "disabled",
        EvolutionSolverProofStatus::Error => "error",
    }
}

fn assurance_decision_label(decision: EvolutionProposalAssuranceDecision) -> &'static str {
    match decision {
        EvolutionProposalAssuranceDecision::Passed => "passed",
        EvolutionProposalAssuranceDecision::Blocked => "blocked",
    }
}

fn assurance_rollout_state_label(state: EvolutionAssuranceRolloutState) -> &'static str {
    match state {
        EvolutionAssuranceRolloutState::Clear => "clear",
        EvolutionAssuranceRolloutState::Waived => "waived",
        EvolutionAssuranceRolloutState::Blocked => "blocked",
    }
}

fn current_time_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HandoffIndex {
    entries: Vec<EvolutionHandoffRecord>,
}

fn resolve_repo_relative_path(base: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn load_json<T>(path: impl Into<PathBuf>) -> Result<Option<T>, EvolutionStatusError>
where
    T: DeserializeOwned,
{
    let path = path.into();
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path).map_err(|source| EvolutionStatusError::Read {
        path: path.clone(),
        source,
    })?;
    let value = serde_json::from_str(&raw).map_err(|source| EvolutionStatusError::Parse {
        path: path.clone(),
        source,
    })?;
    Ok(Some(value))
}

fn load_index<T>(path: impl Into<PathBuf>) -> Result<Option<T>, EvolutionStatusError>
where
    T: DeserializeOwned,
{
    load_json(path)
}

#[derive(Debug, Deserialize, Default)]
struct RankingIndex {
    #[serde(default)]
    entries: Vec<EvolutionMutationRankingRecord>,
}

#[derive(Debug, Deserialize, Default)]
struct SelectionIndex {
    #[serde(default)]
    entries: Vec<EvolutionRankedCandidateSelectionRecord>,
}

#[derive(Debug, Deserialize, Default)]
struct CanaryIndex {
    #[serde(default)]
    entries: Vec<CanaryRunRecord>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        DefaultEvolutionStatusHarness, FileKittenStatusStore, KittenExecutionState,
        KittenStatusRecord, render_evolution_status,
    };
    use crate::canary::{CanaryRecommendation, CanaryRunRecord, CanaryRunStatus};
    use crate::drafting::EvolutionValidationBundleStatus;
    use crate::evolution::{
        EvolutionAssuranceRolloutState, EvolutionHandoffReport, EvolutionHandoffStatus,
        EvolutionProofReport, EvolutionProposalAssuranceCoverageSummary,
        EvolutionProposalAssuranceDecision, EvolutionProposalAssuranceSolverSummary,
        EvolutionProposalAssuranceSummary, EvolutionProposalBlockingReason,
        EvolutionProposalDecisionRecord, EvolutionProposalProofStatus,
        EvolutionProposalProofSummary, EvolutionProposalReport, EvolutionProposalReviewState,
        EvolutionSolverInvariantArtifact, EvolutionSolverProofStatus, EvolutionSolverProofSummary,
        FileEvolutionHandoffStore, FileEvolutionProofStore, FileEvolutionProposalStore,
        build_assurance_waiver_summary,
    };
    use crate::mutation::{
        EvolutionAutonomousFitnessMeasurement, EvolutionAutonomousVariantLineage,
        EvolutionAutonomousVariantRecipeKind, EvolutionBenchmarkBaselineReport,
        EvolutionBenchmarkFitnessDelta, EvolutionBenchmarkGenerationReport,
        EvolutionBenchmarkRunReport, EvolutionCandidateRankingEntry,
        EvolutionEpisodeBlueFitnessVector, EvolutionEpisodeRedFitnessVector,
        EvolutionEpisodeReport, EvolutionEpisodeThreatClassCoverage,
        EvolutionMutationRankingRecord, EvolutionMutationRankingReport,
        EvolutionPopulationCandidate, EvolutionPopulationFitnessObjectives,
        EvolutionPopulationState, FileEvolutionBenchmarkStore, FileEvolutionEpisodeStore,
    };
    use crate::replay::ExperimentLineage;
    use crate::selection::EvolutionRankedCandidateSelectionRecord;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::AgentId;
    use swarm_crypto::Ed25519Signer;
    fn temp_dir(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("swarm-evolution-status-{label}-{suffix}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn active_waiver(
        operator_id: &str,
        secret_material: &str,
        assurance: &EvolutionProposalAssuranceSummary,
    ) -> crate::evolution::EvolutionAssuranceWaiverSummary {
        let signer = Ed25519Signer::from_secret_material(secret_material);
        build_assurance_waiver_summary(
            "proposal-1",
            assurance,
            operator_id,
            &signer,
            super::current_time_ms() - 1_000,
            300,
            "bounded status waiver",
        )
        .unwrap()
    }

    fn sample_autonomous_fitness() -> EvolutionAutonomousFitnessMeasurement {
        EvolutionAutonomousFitnessMeasurement {
            lineage: EvolutionAutonomousVariantLineage {
                recipe_kind: EvolutionAutonomousVariantRecipeKind::BoundedPerturbation,
                base_parent_strategy_id: "office_baseline_control".to_string(),
                parent_strategy_ids: vec!["office_baseline_control".to_string()],
                parent_materialization_ids: vec!["materialization-parent".to_string()],
                parent_genome_sha256: vec!["genome-parent".to_string()],
                inherited_suspicious_parents: Vec::new(),
                inherited_suspicious_children: Vec::new(),
                target_high_confidence_threshold: Some("0.880".to_string()),
                target_medium_confidence_threshold: Some("0.640".to_string()),
            },
            corpus_suite_name: "evasion_breadth_v1".to_string(),
            corpus_version: "2026-04-10".to_string(),
            measured_event_count: 4,
            detected_event_count: 3,
            catch_rate: 0.75,
            false_positive_rate: 0.05,
            false_positive_fitness: 0.95,
            max_detect_latency_us: 800,
            latency_budget_us: 1_000,
            latency_fitness: 0.556,
            verification_threat_class_coverage: 1.0,
            measured_fitness: 0.802,
        }
    }

    #[test]
    fn evolution_status_harness_summarizes_durable_artifacts() {
        let root = temp_dir("summary");
        let ranking_dir = root.join("rankings");
        let selection_dir = root.join("selections");
        let canary_dir = root.join("canaries");
        let handoff_dir = root.join("handoffs");
        let population_dir = root.join("population");
        let episode_dir = population_dir.join("episodes");
        let proof_dir = root.join("proofs");
        let queue_dir = root.join("queue");
        fs::create_dir_all(ranking_dir.join("reports")).unwrap();
        fs::create_dir_all(&selection_dir).unwrap();
        fs::create_dir_all(&canary_dir).unwrap();
        fs::create_dir_all(&handoff_dir).unwrap();
        fs::create_dir_all(&population_dir).unwrap();
        fs::create_dir_all(&proof_dir).unwrap();
        fs::create_dir_all(&queue_dir).unwrap();

        let ranking_report = EvolutionMutationRankingReport {
            ranking_id: "ranking-1".to_string(),
            mutation_spec_id: "mutation-1".to_string(),
            validation_batch_id: "validation-1".to_string(),
            created_at_ms: 1_700_000_001_000,
            shortlist_count: 1,
            ranked_candidates: vec![
                EvolutionCandidateRankingEntry {
                    rank: 1,
                    variant_id: "variant-a".to_string(),
                    strategy_id: "strategy-a".to_string(),
                    materialization_id: "materialization-a".to_string(),
                    validation_bundle_id: "validation-a".to_string(),
                    queue_proposal_id: None,
                    queue_review_state: None,
                    score: 0.91,
                    status: EvolutionValidationBundleStatus::ReadyForQueue,
                    proof_status: EvolutionProposalProofStatus::Proved,
                    advisory_recommendation: None,
                    advisory_score_delta: None,
                    blocking_reason_names: Vec::new(),
                    assurance_case_count: 2,
                    assurance_case_ids: vec!["case-a".to_string(), "case-b".to_string()],
                    ready_for_review: true,
                    summary: "ready".to_string(),
                },
                EvolutionCandidateRankingEntry {
                    rank: 2,
                    variant_id: "variant-b".to_string(),
                    strategy_id: "strategy-b".to_string(),
                    materialization_id: "materialization-b".to_string(),
                    validation_bundle_id: "validation-b".to_string(),
                    queue_proposal_id: None,
                    queue_review_state: None,
                    score: 0.22,
                    status: EvolutionValidationBundleStatus::Blocked,
                    proof_status: EvolutionProposalProofStatus::Missing,
                    advisory_recommendation: None,
                    advisory_score_delta: None,
                    blocking_reason_names: vec!["blocked".to_string()],
                    assurance_case_count: 0,
                    assurance_case_ids: Vec::new(),
                    ready_for_review: false,
                    summary: "blocked".to_string(),
                },
            ],
            review_packets: Vec::new(),
        };
        let ranking_bundle = ranking_dir.join("reports/ranking-1.json");
        fs::write(
            &ranking_bundle,
            serde_json::to_string_pretty(&ranking_report).unwrap(),
        )
        .unwrap();
        fs::write(
            ranking_dir.join("index.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "entries": [EvolutionMutationRankingRecord {
                    ranking_id: "ranking-1".to_string(),
                    mutation_spec_id: "mutation-1".to_string(),
                    validation_batch_id: "validation-1".to_string(),
                    shortlist_count: 1,
                    created_at_ms: 1_700_000_001_000,
                    bundle_path: ranking_bundle.display().to_string(),
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let population = EvolutionPopulationState {
            updated_at_ms: 1_700_000_002_000,
            ranking_id: "ranking-1".to_string(),
            validation_batch_id: "validation-1".to_string(),
            population_size: 4,
            pareto_tournament_size: 2,
            proposal_timestamps_ms: Vec::new(),
            members: vec![
                EvolutionPopulationCandidate {
                    generation: 1,
                    generation_created_at_ms: 1_700_000_001_000,
                    population_rank: 1,
                    pareto_front: 1,
                    ranking_id: "ranking-1".to_string(),
                    validation_batch_id: "validation-1".to_string(),
                    variant_id: "variant-a".to_string(),
                    strategy_id: "strategy-a".to_string(),
                    materialization_id: "materialization-a".to_string(),
                    validation_bundle_id: "validation-a".to_string(),
                    experiment_id: "experiment-a".to_string(),
                    verification_id: "verification-a".to_string(),
                    ready_for_review: true,
                    status: EvolutionValidationBundleStatus::ReadyForQueue,
                    proof_status: EvolutionProposalProofStatus::Proved,
                    queue_review_state: Some(EvolutionProposalReviewState::AcceptedForCanary),
                    advisory_recommendation: None,
                    blocking_reason_names: Vec::new(),
                    ranking_score: 0.91,
                    baseline_fitness: None,
                    fitness: 0.88,
                    evasion_pressure: None,
                    autonomous_fitness: Some(sample_autonomous_fitness()),
                    proposed_at_ms: Some(1_700_000_003_000),
                    objectives: EvolutionPopulationFitnessObjectives {
                        detection_rate: 1.0,
                        false_positive_cost: 0.0,
                        speed: 0.7,
                        threat_class_coverage: 1.0,
                    },
                    summary: "candidate a".to_string(),
                },
                EvolutionPopulationCandidate {
                    generation: 1,
                    generation_created_at_ms: 1_700_000_001_000,
                    population_rank: 2,
                    pareto_front: 1,
                    ranking_id: "ranking-1".to_string(),
                    validation_batch_id: "validation-1".to_string(),
                    variant_id: "variant-c".to_string(),
                    strategy_id: "strategy-c".to_string(),
                    materialization_id: "materialization-c".to_string(),
                    validation_bundle_id: "validation-c".to_string(),
                    experiment_id: "experiment-c".to_string(),
                    verification_id: "verification-c".to_string(),
                    ready_for_review: true,
                    status: EvolutionValidationBundleStatus::ReadyForQueue,
                    proof_status: EvolutionProposalProofStatus::Proved,
                    queue_review_state: None,
                    advisory_recommendation: None,
                    blocking_reason_names: Vec::new(),
                    ranking_score: 0.72,
                    baseline_fitness: None,
                    fitness: 0.64,
                    evasion_pressure: None,
                    autonomous_fitness: None,
                    proposed_at_ms: None,
                    objectives: EvolutionPopulationFitnessObjectives {
                        detection_rate: 0.9,
                        false_positive_cost: 0.1,
                        speed: 0.6,
                        threat_class_coverage: 0.8,
                    },
                    summary: "candidate c".to_string(),
                },
            ],
        };
        fs::write(
            population_dir.join("state.json"),
            serde_json::to_string_pretty(&population).unwrap(),
        )
        .unwrap();

        fs::write(
            selection_dir.join("index.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "entries": [
                    EvolutionRankedCandidateSelectionRecord {
                        selection_id: "selection-1".to_string(),
                        ranking_id: "ranking-1".to_string(),
                        strategy_id: "strategy-a".to_string(),
                        review_state: EvolutionProposalReviewState::AcceptedForCanary,
                        created_at_ms: 1_700_000_004_000,
                        bundle_path: "/tmp/selection-1.json".to_string(),
                    },
                    EvolutionRankedCandidateSelectionRecord {
                        selection_id: "selection-2".to_string(),
                        ranking_id: "ranking-1".to_string(),
                        strategy_id: "strategy-b".to_string(),
                        review_state: EvolutionProposalReviewState::Rejected,
                        created_at_ms: 1_700_000_004_500,
                        bundle_path: "/tmp/selection-2.json".to_string(),
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        fs::write(
            canary_dir.join("index.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "entries": [CanaryRunRecord {
                    run_id: "canary-1".to_string(),
                    slot_id: "canary-primary".to_string(),
                    experiment_id: "experiment-a".to_string(),
                    candidate_strategy_id: "strategy-a".to_string(),
                    created_at_ms: 1_700_000_005_000,
                    updated_at_ms: 1_700_000_006_000,
                    status: CanaryRunStatus::Active,
                    recommendation: CanaryRecommendation::Observing,
                    bundle_path: "/tmp/canary-1.json".to_string(),
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        FileKittenStatusStore::open(&population_dir)
            .unwrap()
            .persist(&KittenStatusRecord {
                updated_at_ms: 1_700_000_007_000,
                state: KittenExecutionState::AwaitingDrift,
                observation_count: Some(12),
                degraded_ratio: Some(0.5),
                strategy_id: Some("strategy-a".to_string()),
                fitness: Some(0.88),
                last_error: None,
            })
            .unwrap();

        FileEvolutionEpisodeStore::open(&episode_dir)
            .unwrap()
            .persist(&EvolutionEpisodeReport {
                episode_id: "episode-1".to_string(),
                created_at_ms: 1_700_000_008_000,
                generation: 1,
                ranking_id: "ranking-1".to_string(),
                validation_batch_id: "validation-1".to_string(),
                strategy_id: "strategy-a".to_string(),
                experiment_id: "experiment-a".to_string(),
                materialization_id: "materialization-a".to_string(),
                validation_bundle_id: "validation-a".to_string(),
                adversarial_corpus_sequence_id: "generation-1".to_string(),
                adversarial_corpus_suite_name: "hellcat_office_v1".to_string(),
                adversarial_corpus_version: "2026-04-03".to_string(),
                blue_genome_hash: "genome-a".to_string(),
                threat_class_coverage: vec![EvolutionEpisodeThreatClassCoverage {
                    threat_class: ThreatClass::Execution,
                    total_events: 1,
                    detected_events: 1,
                    detection_coverage: 1.0,
                    evasion_coverage: 0.0,
                }],
                autonomous_fitness: Some(sample_autonomous_fitness()),
                blue_fitness: EvolutionEpisodeBlueFitnessVector {
                    replay_fitness: 0.88,
                    evasion_adjusted_fitness: 0.89,
                    memory_adjusted_fitness: 0.89,
                    deception_adjusted_fitness: 0.90,
                    deception_signal_score: 0.85,
                    evasion_pressure_score: 0.75,
                    evasion_gap_closure_rate: 0.75,
                    evasion_focus_gap_count: 2,
                    adversarial_pressure_score: 1.0,
                    adversarial_detection_rate: 1.0,
                    final_fitness: 0.912,
                },
                red_fitness: EvolutionEpisodeRedFitnessVector {
                    event_detection_rate: 1.0,
                    event_evasion_rate: 0.0,
                    threat_class_detection_rate: 1.0,
                    threat_class_evasion_rate: 0.0,
                },
            })
            .unwrap();
        FileEvolutionBenchmarkStore::open(population_dir.join("benchmarks"))
            .unwrap()
            .persist(&EvolutionBenchmarkRunReport {
                benchmark_id: "benchmark-1".to_string(),
                label: "office benchmark".to_string(),
                detector: "suspicious_process_tree".to_string(),
                baseline_experiment_path: "experiments/office-baseline-control.yaml".to_string(),
                baseline: Some(EvolutionBenchmarkBaselineReport {
                    strategy_id: "office_baseline_control".to_string(),
                    corpus_suite_name: "evasion_breadth_v1".to_string(),
                    corpus_version: "2026-04-10".to_string(),
                    measured_event_count: 4,
                    detected_event_count: 3,
                    measured_fitness: 0.802,
                    catch_rate: 0.75,
                    false_positive_rate: 0.05,
                    false_positive_fitness: 0.95,
                    latency_fitness: 0.556,
                    max_detect_latency_us: 800,
                    latency_budget_us: 1_000,
                }),
                created_at_ms: 1_700_000_008_250,
                updated_at_ms: 1_700_000_008_900,
                requested_generation_count: 3,
                completed_generation_count: 3,
                max_variants_per_generation: 2,
                population_size: 4,
                corpus_suite_name: "evasion_breadth_v1".to_string(),
                corpus_version: "2026-04-10".to_string(),
                suite_path: "scenario-suites/evasion-breadth-v1.yaml".to_string(),
                notes: "raw deltas only".to_string(),
                generations: vec![
                    EvolutionBenchmarkGenerationReport {
                        benchmark_id: "benchmark-1".to_string(),
                        generation: 1,
                        created_at_ms: 1_700_000_008_300,
                        draft_id: "draft-1".to_string(),
                        mutation_spec_id: "mutation-1".to_string(),
                        materialization_batch_id: "batch-1".to_string(),
                        validation_batch_id: "validation-1".to_string(),
                        ranking_id: "ranking-1".to_string(),
                        tracked_candidate_count: 1,
                        leader_generation: 1,
                        leader_population_rank: 1,
                        leader_strategy_id: "strategy-a".to_string(),
                        leader_variant_id: "variant-a".to_string(),
                        leader_materialization_id: "materialization-a".to_string(),
                        leader_validation_bundle_id: "validation-a".to_string(),
                        leader_recipe_kind:
                            EvolutionAutonomousVariantRecipeKind::BoundedPerturbation,
                        leader_parent_strategy_ids: vec!["office_baseline_control".to_string()],
                        corpus_suite_name: "evasion_breadth_v1".to_string(),
                        corpus_version: "2026-04-10".to_string(),
                        measured_event_count: 4,
                        detected_event_count: 3,
                        leader_measured_fitness: 0.802,
                        mean_measured_fitness: 0.802,
                        leader_catch_rate: 0.75,
                        leader_false_positive_rate: 0.05,
                        leader_false_positive_fitness: 0.95,
                        leader_latency_fitness: 0.556,
                        leader_max_detect_latency_us: 800,
                        leader_latency_budget_us: 1_000,
                        delta_from_previous: None,
                        delta_from_first: None,
                    },
                    EvolutionBenchmarkGenerationReport {
                        benchmark_id: "benchmark-1".to_string(),
                        generation: 2,
                        created_at_ms: 1_700_000_008_600,
                        draft_id: "draft-2".to_string(),
                        mutation_spec_id: "mutation-2".to_string(),
                        materialization_batch_id: "batch-2".to_string(),
                        validation_batch_id: "validation-2".to_string(),
                        ranking_id: "ranking-2".to_string(),
                        tracked_candidate_count: 2,
                        leader_generation: 2,
                        leader_population_rank: 1,
                        leader_strategy_id: "strategy-b".to_string(),
                        leader_variant_id: "variant-b".to_string(),
                        leader_materialization_id: "materialization-b".to_string(),
                        leader_validation_bundle_id: "validation-b".to_string(),
                        leader_recipe_kind:
                            EvolutionAutonomousVariantRecipeKind::BoundedPerturbation,
                        leader_parent_strategy_ids: vec!["strategy-a".to_string()],
                        corpus_suite_name: "evasion_breadth_v1".to_string(),
                        corpus_version: "2026-04-10".to_string(),
                        measured_event_count: 4,
                        detected_event_count: 4,
                        leader_measured_fitness: 0.824,
                        mean_measured_fitness: 0.813,
                        leader_catch_rate: 1.0,
                        leader_false_positive_rate: 0.05,
                        leader_false_positive_fitness: 0.95,
                        leader_latency_fitness: 0.556,
                        leader_max_detect_latency_us: 800,
                        leader_latency_budget_us: 1_000,
                        delta_from_previous: Some(EvolutionBenchmarkFitnessDelta {
                            measured_fitness: 0.022,
                            catch_rate: 0.25,
                            false_positive_rate: 0.0,
                            false_positive_fitness: 0.0,
                            latency_fitness: 0.0,
                        }),
                        delta_from_first: Some(EvolutionBenchmarkFitnessDelta {
                            measured_fitness: 0.022,
                            catch_rate: 0.25,
                            false_positive_rate: 0.0,
                            false_positive_fitness: 0.0,
                            latency_fitness: 0.0,
                        }),
                    },
                ],
            })
            .unwrap();

        FileEvolutionProofStore::open(&proof_dir)
            .unwrap()
            .persist(&EvolutionProofReport {
                proof_id: "proof-z3-1".to_string(),
                experiment_id: "experiment-a".to_string(),
                experiment_name: "office-baseline-control".to_string(),
                verification_id: "verification-a".to_string(),
                created_at_ms: 1_700_000_008_500,
                strategy_id: "strategy-a".to_string(),
                candidate_description: "candidate a".to_string(),
                lineage: ExperimentLineage {
                    parent_strategy_id: "office_baseline_control".to_string(),
                    mutation: "threshold_nudge".to_string(),
                    rationale: "status summary".to_string(),
                },
                corpus_name: "office-detector-safety-v1".to_string(),
                proof_system: "formal_safety_gate_v2+z3_smt_v1".to_string(),
                experiment_manifest_sha256: "experiment-sha".to_string(),
                strategy_genome_sha256: "strategy-sha".to_string(),
                verification_report_sha256: "verification-sha".to_string(),
                lineage_sha256: "lineage-sha".to_string(),
                attestation_sha256: "attestation-sha".to_string(),
                invariants: Vec::new(),
                formal_safety_bundle_sha256: vec!["bundle-sha".to_string()],
                solver_summary: Some(EvolutionSolverProofSummary {
                    status: EvolutionSolverProofStatus::Timeout,
                    invariant_count: 1,
                    proved_count: 0,
                    counterexample_invariant_count: 0,
                    counterexample_binding_count: 0,
                    timed_out_count: 1,
                    disabled_count: 0,
                    error_count: 0,
                    timeout_ms: 30_000,
                    proof_signature_sha256: "solver-proof-sha".to_string(),
                }),
                solver_artifacts: vec![EvolutionSolverInvariantArtifact {
                    invariant_name: "timeout-proof".to_string(),
                    solver: "z3".to_string(),
                    status: EvolutionSolverProofStatus::Timeout,
                    timeout_ms: 30_000,
                    duration_ms: 30_000,
                    compiled_query_sha256: "compiled-query-sha".to_string(),
                    attestation_sha256: "artifact-sha".to_string(),
                    counterexamples: Vec::new(),
                    reason_unknown: Some("timeout".to_string()),
                }],
            })
            .unwrap();
        FileEvolutionProposalStore::open(&queue_dir)
            .unwrap()
            .persist(&EvolutionProposalReport {
                proposal_id: "proposal-1".to_string(),
                experiment_id: "experiment-a".to_string(),
                experiment_name: "office-baseline-control".to_string(),
                experiment_path: "experiments/office-baseline-control.yaml".to_string(),
                created_at_ms: 1_700_000_008_750,
                strategy_id: "strategy-a".to_string(),
                strategy_description: "candidate a".to_string(),
                lineage: ExperimentLineage {
                    parent_strategy_id: "office_baseline_control".to_string(),
                    mutation: "threshold_nudge".to_string(),
                    rationale: "assurance summary".to_string(),
                },
                verification_id: Some("verification-a".to_string()),
                verification_passed: true,
                proof_status: EvolutionProposalProofStatus::Proved,
                proof: Some(EvolutionProposalProofSummary {
                    proof_id: "proof-z3-1".to_string(),
                    proof_system: "formal_safety_gate_v2+z3_smt_v1".to_string(),
                    attestation_sha256: "attestation-sha".to_string(),
                    invariant_count: 1,
                }),
                advisory: None,
                assurance: Some(EvolutionProposalAssuranceSummary {
                    decision: EvolutionProposalAssuranceDecision::Blocked,
                    coverage: EvolutionProposalAssuranceCoverageSummary {
                        detector: "strategy-a".to_string(),
                        suite_name: Some("evasion-breadth-v1".to_string()),
                        corpus_version: Some("2026-04-03".to_string()),
                        required_catch_rate: 0.75,
                        actual_catch_rate: Some(0.25),
                        actionable_gap_count: 2,
                    },
                    solver: EvolutionProposalAssuranceSolverSummary {
                        required: true,
                        status: Some(EvolutionSolverProofStatus::Timeout),
                        allowed_statuses: vec![EvolutionSolverProofStatus::Proved],
                    },
                    harvested_case_ids: vec!["case-a".to_string(), "case-b".to_string()],
                    waiver: None,
                }),
                review_state: EvolutionProposalReviewState::Blocked,
                blocking_reasons: vec![EvolutionProposalBlockingReason {
                    source: "assurance".to_string(),
                    name: "coverage_floor_not_met".to_string(),
                    details: "coverage below floor".to_string(),
                    references: vec!["evasion-breadth-v1".to_string()],
                }],
                decision_history: Vec::<EvolutionProposalDecisionRecord>::new(),
            })
            .unwrap();
        FileEvolutionHandoffStore::open(&handoff_dir)
            .unwrap()
            .persist(&EvolutionHandoffReport {
                handoff_id: "handoff-1".to_string(),
                proposal_id: "proposal-1".to_string(),
                experiment_id: "experiment-a".to_string(),
                experiment_name: "office-baseline-control".to_string(),
                experiment_path: "experiments/office-baseline-control.yaml".to_string(),
                created_at_ms: 1_700_000_008_900,
                launched_at_ms: None,
                strategy_id: "strategy-a".to_string(),
                strategy_description: "candidate a".to_string(),
                lineage: ExperimentLineage {
                    parent_strategy_id: "office_baseline_control".to_string(),
                    mutation: "threshold_nudge".to_string(),
                    rationale: "handoff assurance".to_string(),
                },
                verification_id: "verification-a".to_string(),
                proof: EvolutionProposalProofSummary {
                    proof_id: "proof-z3-1".to_string(),
                    proof_system: "formal_safety_gate_v2+z3_smt_v1".to_string(),
                    attestation_sha256: "attestation-sha".to_string(),
                    invariant_count: 1,
                },
                advisory: None,
                assurance: Some(EvolutionProposalAssuranceSummary {
                    decision: EvolutionProposalAssuranceDecision::Blocked,
                    coverage: EvolutionProposalAssuranceCoverageSummary {
                        detector: "strategy-a".to_string(),
                        suite_name: Some("evasion-breadth-v1".to_string()),
                        corpus_version: Some("2026-04-03".to_string()),
                        required_catch_rate: 0.75,
                        actual_catch_rate: Some(0.25),
                        actionable_gap_count: 2,
                    },
                    solver: EvolutionProposalAssuranceSolverSummary {
                        required: true,
                        status: Some(EvolutionSolverProofStatus::Timeout),
                        allowed_statuses: vec![EvolutionSolverProofStatus::Proved],
                    },
                    harvested_case_ids: vec!["case-a".to_string(), "case-b".to_string()],
                    waiver: None,
                }),
                shadow_id: "shadow-a".to_string(),
                shadow_passed: false,
                suite_name: "evasion-breadth-v1".to_string(),
                corpus_version: "2026-04-03".to_string(),
                launch_status: EvolutionHandoffStatus::Blocked,
                blocking_reasons: vec![EvolutionProposalBlockingReason {
                    source: "assurance".to_string(),
                    name: "assurance_gate_unsatisfied".to_string(),
                    details: "assurance decision `blocked` does not permit rollout progression"
                        .to_string(),
                    references: vec!["case-a".to_string(), "case-b".to_string()],
                }],
                canary_run_id: None,
            })
            .unwrap();

        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let mut config =
            crate::config::load_config(repo_root.join("rulesets/default.yaml")).unwrap();
        config.evolution.enabled = true;
        config.evolution.population_size = 4;
        config.evolution.paths.evolution_ranking_results_dir = ranking_dir.display().to_string();
        config.evolution.paths.evolution_selection_results_dir =
            selection_dir.display().to_string();
        config.evolution.paths.canary_results_dir = canary_dir.display().to_string();
        config.evolution.paths.evolution_handoff_results_dir = handoff_dir.display().to_string();
        config.evolution.paths.evolution_population_results_dir =
            population_dir.display().to_string();
        config.evolution.paths.evolution_proof_results_dir = proof_dir.display().to_string();
        config.evolution.paths.evolution_queue_results_dir = queue_dir.display().to_string();

        let report = DefaultEvolutionStatusHarness::from_config("inline", config)
            .unwrap()
            .status()
            .unwrap();

        assert_eq!(report.generation_count, 1);
        assert_eq!(report.current_generation, Some(1));
        assert_eq!(
            report.kitten_state,
            Some(KittenExecutionState::AwaitingDrift)
        );
        assert_eq!(report.population.current_population_size, 2);
        assert_eq!(report.population.ready_for_review, 2);
        assert_eq!(report.population.unique_strategies, 2);
        assert_eq!(report.verification.candidate_count, 2);
        assert_eq!(report.verification.ready_for_review, 1);
        assert_eq!(report.admission.total_selections, 2);
        assert_eq!(report.admission.accepted_for_canary, 1);
        assert_eq!(report.admission.active_canaries, 1);
        assert_eq!(report.latest_strategy_id.as_deref(), Some("strategy-a"));
        assert_eq!(report.latest_fitness, Some(0.912));
        assert_eq!(
            report.adversarial.corpus_version.as_deref(),
            Some("2026-04-03")
        );
        assert_eq!(
            report.adversarial.best_genome_hash.as_deref(),
            Some("genome-a")
        );
        assert_eq!(report.adversarial.current_generation, Some(1));
        assert_eq!(
            report.formal_proof.latest_proof_id.as_deref(),
            Some("proof-z3-1")
        );
        assert_eq!(
            report.formal_proof.solver_status,
            Some(EvolutionSolverProofStatus::Timeout)
        );
        assert!(report.formal_proof.timed_out);
        assert!(!report.formal_proof.counterexample_present);
        assert_eq!(
            report.assurance.latest_proposal_id.as_deref(),
            Some("proposal-1")
        );
        assert_eq!(
            report.assurance.latest_handoff_id.as_deref(),
            Some("handoff-1")
        );
        assert_eq!(
            report.assurance.decision,
            Some(EvolutionProposalAssuranceDecision::Blocked)
        );
        assert_eq!(report.assurance.blocked_reason_count, 1);
        assert_eq!(report.assurance.required_catch_rate, Some(0.75));
        assert_eq!(report.assurance.actual_catch_rate, Some(0.25));
        assert_eq!(report.assurance.actionable_gap_count, Some(2));
        assert_eq!(
            report.assurance.solver_status,
            Some(EvolutionSolverProofStatus::Timeout)
        );
        assert_eq!(
            report.assurance.latest_rollout_gate.as_deref(),
            Some(
                "handoff assurance_gate_unsatisfied: assurance decision `blocked` does not permit rollout progression"
            )
        );
        assert_eq!(report.autonomous.evaluated_candidate_count, 1);
        assert_eq!(
            report.autonomous.latest_strategy_id.as_deref(),
            Some("strategy-a")
        );
        assert_eq!(
            report.autonomous.latest_recipe_kind,
            Some(EvolutionAutonomousVariantRecipeKind::BoundedPerturbation)
        );
        assert_eq!(report.autonomous.latest_measured_fitness, Some(0.802));
        assert_eq!(report.autonomous.latest_catch_rate, Some(0.75));
        assert_eq!(report.autonomous.latest_false_positive_rate, Some(0.05));
        assert_eq!(report.autonomous.latest_latency_fitness, Some(0.556));
        assert_eq!(
            report.autonomous.latest_parent_strategy_ids,
            vec!["office_baseline_control".to_string()]
        );
        assert_eq!(
            report.benchmark.latest_benchmark_id.as_deref(),
            Some("benchmark-1")
        );
        assert_eq!(report.benchmark.completed_generation_count, 3);
        assert_eq!(report.benchmark.requested_generation_count, 3);
        assert_eq!(
            report.benchmark.latest_leader_strategy_id.as_deref(),
            Some("strategy-b")
        );
        assert_eq!(report.benchmark.latest_leader_generation, Some(2));
        assert_eq!(report.benchmark.latest_measured_fitness, Some(0.824));
        assert_eq!(report.benchmark.latest_delta_from_previous, Some(0.022));
        assert!(
            render_evolution_status(&report).contains("Autonomous fitness:"),
            "rendered status should surface measured autonomous fitness"
        );
        assert!(
            render_evolution_status(&report).contains("Benchmark: run=benchmark-1"),
            "rendered status should surface the latest benchmark summary"
        );
    }

    #[test]
    fn evolution_status_harness_surfaces_active_assurance_waiver_lineage() {
        let root = temp_dir("waived-assurance");
        let queue_dir = root.join("queue");
        let handoff_dir = root.join("handoffs");
        let population_dir = root.join("population");
        let proof_dir = root.join("proofs");
        fs::create_dir_all(&queue_dir).unwrap();
        fs::create_dir_all(&handoff_dir).unwrap();
        fs::create_dir_all(&population_dir).unwrap();
        fs::create_dir_all(&proof_dir).unwrap();

        let secret_material = "phase-175-status-waiver";
        let operator_id = AgentId::from_public_key_hex(
            Ed25519Signer::from_secret_material(secret_material).public_key_hex(),
        )
        .to_string();
        let mut config: swarm_core::config::SwarmConfig =
            serde_yaml::from_str(include_str!("../../../rulesets/default.yaml")).unwrap();
        config.evolution.enabled = true;
        config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
        config.evolution.paths.evolution_queue_results_dir = queue_dir.display().to_string();
        config.evolution.paths.evolution_handoff_results_dir = handoff_dir.display().to_string();
        config.evolution.paths.evolution_population_results_dir =
            population_dir.display().to_string();
        config.evolution.paths.evolution_proof_results_dir = proof_dir.display().to_string();

        let mut assurance = EvolutionProposalAssuranceSummary {
            decision: EvolutionProposalAssuranceDecision::Blocked,
            coverage: EvolutionProposalAssuranceCoverageSummary {
                detector: "strategy-a".to_string(),
                suite_name: Some("evasion-breadth-v1".to_string()),
                corpus_version: Some("2026-04-03".to_string()),
                required_catch_rate: 0.75,
                actual_catch_rate: Some(0.25),
                actionable_gap_count: 2,
            },
            solver: EvolutionProposalAssuranceSolverSummary {
                required: true,
                status: Some(EvolutionSolverProofStatus::Timeout),
                allowed_statuses: vec![EvolutionSolverProofStatus::Proved],
            },
            harvested_case_ids: vec!["case-a".to_string(), "case-b".to_string()],
            waiver: None,
        };
        assurance.waiver = Some(active_waiver(&operator_id, secret_material, &assurance));

        FileEvolutionProposalStore::open(&queue_dir)
            .unwrap()
            .persist(&EvolutionProposalReport {
                proposal_id: "proposal-1".to_string(),
                experiment_id: "experiment-a".to_string(),
                experiment_name: "office-baseline-control".to_string(),
                experiment_path: "experiments/office-baseline-control.yaml".to_string(),
                created_at_ms: 1_700_000_008_000,
                strategy_id: "strategy-a".to_string(),
                strategy_description: "candidate a".to_string(),
                lineage: ExperimentLineage {
                    parent_strategy_id: "office_baseline_control".to_string(),
                    mutation: "threshold_nudge".to_string(),
                    rationale: "waived assurance".to_string(),
                },
                verification_id: Some("verification-a".to_string()),
                verification_passed: true,
                proof_status: EvolutionProposalProofStatus::Proved,
                proof: Some(EvolutionProposalProofSummary {
                    proof_id: "proof-z3-1".to_string(),
                    proof_system: "formal_safety_gate_v2+z3_smt_v1".to_string(),
                    attestation_sha256: "attestation-sha".to_string(),
                    invariant_count: 1,
                }),
                advisory: None,
                assurance: Some(assurance.clone()),
                review_state: EvolutionProposalReviewState::Blocked,
                blocking_reasons: vec![EvolutionProposalBlockingReason {
                    source: "assurance".to_string(),
                    name: "assurance_gate_unsatisfied".to_string(),
                    details: "assurance decision `blocked` does not permit rollout progression"
                        .to_string(),
                    references: vec!["case-a".to_string()],
                }],
                decision_history: vec![EvolutionProposalDecisionRecord {
                    decided_at_ms: 1_700_000_008_100,
                    action: crate::evolution::EvolutionProposalDecisionAction::ApplyAssuranceWaiver,
                    reason: "bounded status waiver".to_string(),
                }],
            })
            .unwrap();
        FileEvolutionHandoffStore::open(&handoff_dir)
            .unwrap()
            .persist(&EvolutionHandoffReport {
                handoff_id: "handoff-1".to_string(),
                proposal_id: "proposal-1".to_string(),
                experiment_id: "experiment-a".to_string(),
                experiment_name: "office-baseline-control".to_string(),
                experiment_path: "experiments/office-baseline-control.yaml".to_string(),
                created_at_ms: 1_700_000_008_900,
                launched_at_ms: None,
                strategy_id: "strategy-a".to_string(),
                strategy_description: "candidate a".to_string(),
                lineage: ExperimentLineage {
                    parent_strategy_id: "office_baseline_control".to_string(),
                    mutation: "threshold_nudge".to_string(),
                    rationale: "handoff assurance".to_string(),
                },
                verification_id: "verification-a".to_string(),
                proof: EvolutionProposalProofSummary {
                    proof_id: "proof-z3-1".to_string(),
                    proof_system: "formal_safety_gate_v2+z3_smt_v1".to_string(),
                    attestation_sha256: "attestation-sha".to_string(),
                    invariant_count: 1,
                },
                advisory: None,
                assurance: Some(assurance),
                shadow_id: "shadow-a".to_string(),
                shadow_passed: true,
                suite_name: "evasion-breadth-v1".to_string(),
                corpus_version: "2026-04-03".to_string(),
                launch_status: EvolutionHandoffStatus::PendingLaunch,
                blocking_reasons: Vec::new(),
                canary_run_id: None,
            })
            .unwrap();

        let report = DefaultEvolutionStatusHarness::from_config("inline", config)
            .unwrap()
            .status()
            .unwrap();

        assert_eq!(
            report.assurance.rollout_state,
            Some(EvolutionAssuranceRolloutState::Waived)
        );
        assert_eq!(
            report.assurance.active_waiver_operator_id.as_deref(),
            Some(operator_id.as_str())
        );
        assert_eq!(report.assurance.waived_gap_count, Some(2));
        assert!(report.assurance.active_waiver_id.is_some());
        assert_eq!(
            report.assurance.waiver_reason.as_deref(),
            Some("bounded status waiver")
        );
        assert_eq!(report.assurance.latest_rollout_gate, None);
        assert!(render_evolution_status(&report).contains("rollout=waived"));
        assert!(render_evolution_status(&report).contains("Active waiver:"));
    }
}
