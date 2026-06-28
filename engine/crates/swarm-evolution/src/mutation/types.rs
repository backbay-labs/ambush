use super::*;

/// Errors surfaced by the guided mutation workflow.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionMutationError {
    #[error(transparent)]
    Drafting(#[from] EvolutionDraftingError),

    #[error(transparent)]
    Replay(#[from] ReplayHarnessError),

    #[error(transparent)]
    ExperimentStore(#[from] ExperimentStoreError),

    #[error(transparent)]
    VerificationStore(#[from] VerificationStoreError),

    #[error(transparent)]
    PromotionStore(#[from] EvolutionDraftPromotionStoreError),

    #[error(transparent)]
    ProposalStore(#[from] EvolutionProposalStoreError),

    #[error(transparent)]
    MaterializationStore(#[from] EvolutionMaterializationStoreError),

    #[error(transparent)]
    Strategy(#[from] StrategyAdvisorError),

    #[error(transparent)]
    MutationStore(#[from] EvolutionMutationStoreError),

    #[error(transparent)]
    MutationMaterializationBatchStore(#[from] EvolutionMutationMaterializationBatchStoreError),

    #[error(transparent)]
    MutationValidationBatchStore(#[from] EvolutionMutationValidationBatchStoreError),

    #[error(transparent)]
    MutationRankingStore(#[from] EvolutionMutationRankingStoreError),

    #[error(transparent)]
    PopulationStore(#[from] EvolutionPopulationStoreError),

    #[error(transparent)]
    EpisodeStore(#[from] EvolutionEpisodeStoreError),

    #[error(transparent)]
    BenchmarkStore(#[from] EvolutionBenchmarkStoreError),

    #[error(transparent)]
    DetectorFactory(#[from] DetectorFactoryError),

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    #[error("invalid mutation spec request: {reason}")]
    InvalidMutationSpecRequest { reason: String },

    #[error("mutation spec `{mutation_spec_id}` was not found")]
    MutationSpecNotFound { mutation_spec_id: String },

    #[error("mutation spec `{mutation_spec_id}` already defines variant `{variant_id}`")]
    DuplicateVariantId {
        mutation_spec_id: String,
        variant_id: String,
    },

    #[error("mutation spec `{mutation_spec_id}` already defines strategy `{strategy_id}`")]
    DuplicateStrategyId {
        mutation_spec_id: String,
        strategy_id: String,
    },

    #[error("mutation spec `{mutation_spec_id}` does not define any variants yet")]
    MutationSpecHasNoVariants { mutation_spec_id: String },

    #[error("materialization batch `{batch_id}` was not found")]
    MaterializationBatchNotFound { batch_id: String },

    #[error("validation batch `{validation_batch_id}` was not found")]
    ValidationBatchNotFound { validation_batch_id: String },

    #[error("candidate ranking `{ranking_id}` was not found")]
    RankingNotFound { ranking_id: String },

    #[error("failed to read experiment search path `{path}`: {source}")]
    ManifestReadDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to serialize materialized experiment manifest `{path}`: {source}")]
    ManifestSerialize {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("failed to write materialized experiment manifest `{path}`: {source}")]
    ManifestWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Stable source kind for one mutation spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionMutationSourceKind {
    Draft,
    Materialization,
    Autonomous,
}

/// Structured profile overrides applied to one variant candidate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMutationProfileOverrides {
    pub add_suspicious_parents: Vec<String>,
    pub remove_suspicious_parents: Vec<String>,
    pub add_suspicious_children: Vec<String>,
    pub remove_suspicious_children: Vec<String>,
    pub high_confidence_threshold: Option<String>,
    pub medium_confidence_threshold: Option<String>,
}

impl EvolutionMutationProfileOverrides {
    pub(crate) fn to_materialization_request(
        &self,
        draft_id: String,
        base_experiment_path: PathBuf,
    ) -> Result<EvolutionDraftMaterializationRequest, EvolutionMutationError> {
        let high_confidence_threshold = parse_optional_threshold(
            self.high_confidence_threshold.as_deref(),
            "high_confidence_threshold",
        )?;
        let medium_confidence_threshold = parse_optional_threshold(
            self.medium_confidence_threshold.as_deref(),
            "medium_confidence_threshold",
        )?;
        if let (Some(high), Some(medium)) = (high_confidence_threshold, medium_confidence_threshold)
            && medium > high
        {
            return Err(EvolutionMutationError::InvalidMutationSpecRequest {
                reason: format!(
                    "medium_confidence_threshold {medium:.3} cannot exceed high_confidence_threshold {high:.3}"
                ),
            });
        }

        Ok(EvolutionDraftMaterializationRequest {
            draft_id,
            base_experiment_path: Some(base_experiment_path),
            add_suspicious_parents: normalize_entries(&self.add_suspicious_parents),
            remove_suspicious_parents: normalize_entries(&self.remove_suspicious_parents),
            add_suspicious_children: normalize_entries(&self.add_suspicious_children),
            remove_suspicious_children: normalize_entries(&self.remove_suspicious_children),
            high_confidence_threshold,
            medium_confidence_threshold,
        })
    }

    pub(crate) fn dimensions(&self) -> Vec<String> {
        let mut dimensions = Vec::new();
        if !self.add_suspicious_parents.is_empty() {
            dimensions.push("add_suspicious_parent".to_string());
        }
        if !self.remove_suspicious_parents.is_empty() {
            dimensions.push("remove_suspicious_parent".to_string());
        }
        if !self.add_suspicious_children.is_empty() {
            dimensions.push("add_suspicious_child".to_string());
        }
        if !self.remove_suspicious_children.is_empty() {
            dimensions.push("remove_suspicious_child".to_string());
        }
        if self.high_confidence_threshold.is_some() {
            dimensions.push("high_confidence_threshold".to_string());
        }
        if self.medium_confidence_threshold.is_some() {
            dimensions.push("medium_confidence_threshold".to_string());
        }
        if dimensions.is_empty() {
            dimensions.push("profile_copy".to_string());
        }
        dimensions
    }
}

/// Request used to create one durable mutation spec from a draft or materialization.
#[derive(Debug, Clone)]
pub struct EvolutionMutationSpecCreateRequest {
    pub draft_id: Option<String>,
    pub materialization_id: Option<String>,
    pub base_experiment_path: Option<PathBuf>,
    pub rationale: String,
}

/// Request used to generate one autonomous mutation spec from durable winning genomes.
#[derive(Debug, Clone)]
pub struct EvolutionAutonomousMutationSpecCreateRequest {
    pub draft_id: String,
    pub strategy_root: String,
    pub rationale: String,
    pub max_variants: usize,
    pub base_experiment_path: Option<PathBuf>,
    pub evasion_pressure: Option<EvolutionEvasionPressureInput>,
}

/// One variant attached to a mutation spec.
#[derive(Debug, Clone)]
pub struct EvolutionMutationVariantCreateRequest {
    pub variant_id: Option<String>,
    pub strategy_id: String,
    pub strategy_description: String,
    pub mutation: String,
    pub rationale: String,
    pub overrides: EvolutionMutationProfileOverrides,
}

/// Durable lineage recorded for one autonomous generation parent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionMutationParentGenome {
    pub strategy_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub materialization_id: Option<String>,
    pub experiment_id: String,
    pub experiment_path: String,
    pub generation: usize,
    pub population_rank: usize,
    pub fitness: f64,
    pub genome_sha256: String,
}

/// Stable autonomous recipe used to derive one generated variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionAutonomousVariantRecipeKind {
    SeedControl,
    BoundedPerturbation,
    GapExpansion,
    BoundedCrossover,
}

/// Replayable lineage recorded for one autonomously generated variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionAutonomousVariantLineage {
    pub recipe_kind: EvolutionAutonomousVariantRecipeKind,
    pub base_parent_strategy_id: String,
    pub parent_strategy_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_materialization_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_genome_sha256: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inherited_suspicious_parents: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inherited_suspicious_children: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_high_confidence_threshold: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_medium_confidence_threshold: Option<String>,
}

/// Structured replay trace preserved for one autonomous mutation spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionAutonomousGenerationTrace {
    pub generator: String,
    pub requested_variant_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub population_ranking_id: Option<String>,
    pub base_parent_strategy_id: String,
    pub parents: Vec<EvolutionMutationParentGenome>,
}

/// Durable mutation variant preserved on a mutation spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMutationVariantSpec {
    pub variant_id: String,
    pub strategy_id: String,
    pub strategy_description: String,
    pub mutation: String,
    pub rationale: String,
    pub mutation_dimensions: Vec<String>,
    pub overrides: EvolutionMutationProfileOverrides,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autonomous_lineage: Option<EvolutionAutonomousVariantLineage>,
}

/// Durable mutation spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionMutationSpecReport {
    pub mutation_spec_id: String,
    pub created_at_ms: i64,
    pub source_kind: EvolutionMutationSourceKind,
    pub draft_id: String,
    pub materialization_id: Option<String>,
    pub pressure_id: String,
    pub promotion_id: Option<String>,
    pub queue_proposal_id: Option<String>,
    pub source_strategy_id: String,
    pub source_strategy_description: String,
    pub source_lineage: ExperimentLineage,
    pub source_pressure_kind: EvolutionPressureSourceKind,
    pub source_experiment_id: String,
    pub source_experiment_name: String,
    pub base_experiment_path: String,
    pub operator_rationale: String,
    pub variants: Vec<EvolutionMutationVariantSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autonomous_generation: Option<EvolutionAutonomousGenerationTrace>,
}

/// Metadata surfaced for one persisted mutation spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMutationSpecRecord {
    pub mutation_spec_id: String,
    pub source_kind: EvolutionMutationSourceKind,
    pub source_strategy_id: String,
    pub variant_count: usize,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionMutationSpecRecord {
    pub(crate) fn from_report(report: &EvolutionMutationSpecReport, bundle_path: String) -> Self {
        Self {
            mutation_spec_id: report.mutation_spec_id.clone(),
            source_kind: report.source_kind,
            source_strategy_id: report.source_strategy_id.clone(),
            variant_count: report.variants.len(),
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted mutation spec loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionMutationSpecLookup {
    pub record: EvolutionMutationSpecRecord,
    pub report: EvolutionMutationSpecReport,
}

/// One candidate materialized from a mutation spec variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionMutationMaterializationEntry {
    pub variant_id: String,
    pub strategy_id: String,
    pub materialization_id: String,
    pub experiment_id: String,
    pub experiment_path: String,
    pub mutation_dimensions: Vec<String>,
    pub promotion_id: Option<String>,
    pub queue_proposal_id: Option<String>,
}

/// Durable batch artifact linking a mutation spec to several materialized candidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionMutationMaterializationBatchReport {
    pub batch_id: String,
    pub mutation_spec_id: String,
    pub created_at_ms: i64,
    pub source_strategy_id: String,
    pub candidate_count: usize,
    pub entries: Vec<EvolutionMutationMaterializationEntry>,
}

/// Metadata surfaced for one persisted materialization batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMutationMaterializationBatchRecord {
    pub batch_id: String,
    pub mutation_spec_id: String,
    pub candidate_count: usize,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionMutationMaterializationBatchRecord {
    pub(crate) fn from_report(
        report: &EvolutionMutationMaterializationBatchReport,
        bundle_path: String,
    ) -> Self {
        Self {
            batch_id: report.batch_id.clone(),
            mutation_spec_id: report.mutation_spec_id.clone(),
            candidate_count: report.candidate_count,
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted materialization batch loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionMutationMaterializationBatchLookup {
    pub record: EvolutionMutationMaterializationBatchRecord,
    pub report: EvolutionMutationMaterializationBatchReport,
}

/// One validation result attached to one mutation-spec candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionMutationValidationEntry {
    pub variant_id: String,
    pub strategy_id: String,
    pub materialization_id: String,
    pub validation_bundle_id: String,
    pub status: EvolutionValidationBundleStatus,
    pub proof_status: EvolutionProposalProofStatus,
    pub advisory: Option<EvolutionProposalAdvisorySummary>,
    pub promotion_id: Option<String>,
    pub queue_proposal_id: Option<String>,
    pub blocking_reason_names: Vec<String>,
}

/// Durable batch artifact linking a mutation-spec candidate set to validation results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionMutationValidationBatchReport {
    pub validation_batch_id: String,
    pub mutation_spec_id: String,
    pub materialization_batch_id: String,
    pub created_at_ms: i64,
    pub ready_count: usize,
    pub blocked_count: usize,
    pub entries: Vec<EvolutionMutationValidationEntry>,
}

/// Metadata surfaced for one persisted validation batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMutationValidationBatchRecord {
    pub validation_batch_id: String,
    pub mutation_spec_id: String,
    pub materialization_batch_id: String,
    pub ready_count: usize,
    pub blocked_count: usize,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionMutationValidationBatchRecord {
    pub(crate) fn from_report(
        report: &EvolutionMutationValidationBatchReport,
        bundle_path: String,
    ) -> Self {
        Self {
            validation_batch_id: report.validation_batch_id.clone(),
            mutation_spec_id: report.mutation_spec_id.clone(),
            materialization_batch_id: report.materialization_batch_id.clone(),
            ready_count: report.ready_count,
            blocked_count: report.blocked_count,
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted validation batch loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionMutationValidationBatchLookup {
    pub record: EvolutionMutationValidationBatchRecord,
    pub report: EvolutionMutationValidationBatchReport,
}

/// One deterministic ranking entry derived from a validated mutation candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionCandidateRankingEntry {
    pub rank: usize,
    pub variant_id: String,
    pub strategy_id: String,
    pub materialization_id: String,
    pub validation_bundle_id: String,
    pub queue_proposal_id: Option<String>,
    pub queue_review_state: Option<EvolutionProposalReviewState>,
    pub score: f64,
    pub status: EvolutionValidationBundleStatus,
    pub proof_status: EvolutionProposalProofStatus,
    pub advisory_recommendation: Option<StrategyAdvisoryRecommendation>,
    pub advisory_score_delta: Option<f64>,
    pub blocking_reason_names: Vec<String>,
    #[serde(default)]
    pub assurance_case_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assurance_case_ids: Vec<String>,
    pub ready_for_review: bool,
    pub summary: String,
}

/// One durable review packet extracted from the top-ranked candidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionCandidateReviewPacket {
    pub packet_id: String,
    pub rank: usize,
    pub variant_id: String,
    pub strategy_id: String,
    pub materialization_id: String,
    pub validation_bundle_id: String,
    pub queue_proposal_id: Option<String>,
    pub queue_review_state: Option<EvolutionProposalReviewState>,
    pub advisory_scorecard_id: Option<String>,
    #[serde(default)]
    pub assurance_case_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assurance_case_ids: Vec<String>,
    pub score: f64,
    pub summary: String,
}

/// Durable ranking report for one validated mutation batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionMutationRankingReport {
    pub ranking_id: String,
    pub mutation_spec_id: String,
    pub validation_batch_id: String,
    pub created_at_ms: i64,
    pub shortlist_count: usize,
    pub ranked_candidates: Vec<EvolutionCandidateRankingEntry>,
    pub review_packets: Vec<EvolutionCandidateReviewPacket>,
}

/// Metadata surfaced for one persisted ranking report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMutationRankingRecord {
    pub ranking_id: String,
    pub mutation_spec_id: String,
    pub validation_batch_id: String,
    pub shortlist_count: usize,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionMutationRankingRecord {
    pub(crate) fn from_report(
        report: &EvolutionMutationRankingReport,
        bundle_path: String,
    ) -> Self {
        Self {
            ranking_id: report.ranking_id.clone(),
            mutation_spec_id: report.mutation_spec_id.clone(),
            validation_batch_id: report.validation_batch_id.clone(),
            shortlist_count: report.shortlist_count,
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted ranking report loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionMutationRankingLookup {
    pub record: EvolutionMutationRankingRecord,
    pub report: EvolutionMutationRankingReport,
}

/// Multi-objective fitness vector persisted for one validated candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionPopulationFitnessObjectives {
    pub detection_rate: f64,
    pub false_positive_cost: f64,
    pub speed: f64,
    pub threat_class_coverage: f64,
}

/// Measured autonomous fitness preserved for one generated candidate lineage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionAutonomousFitnessMeasurement {
    pub lineage: EvolutionAutonomousVariantLineage,
    pub corpus_suite_name: String,
    pub corpus_version: String,
    pub measured_event_count: usize,
    pub detected_event_count: usize,
    pub catch_rate: f64,
    pub false_positive_rate: f64,
    pub false_positive_fitness: f64,
    pub max_detect_latency_us: u64,
    pub latency_budget_us: u64,
    pub latency_fitness: f64,
    pub verification_threat_class_coverage: f64,
    pub measured_fitness: f64,
}

/// One durable candidate retained in the population pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionPopulationCandidate {
    pub generation: usize,
    pub generation_created_at_ms: i64,
    pub population_rank: usize,
    pub pareto_front: usize,
    pub ranking_id: String,
    pub validation_batch_id: String,
    pub variant_id: String,
    pub strategy_id: String,
    pub materialization_id: String,
    pub validation_bundle_id: String,
    pub experiment_id: String,
    pub verification_id: String,
    pub ready_for_review: bool,
    pub status: EvolutionValidationBundleStatus,
    pub proof_status: EvolutionProposalProofStatus,
    pub queue_review_state: Option<EvolutionProposalReviewState>,
    pub advisory_recommendation: Option<StrategyAdvisoryRecommendation>,
    pub blocking_reason_names: Vec<String>,
    pub ranking_score: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_fitness: Option<f64>,
    pub fitness: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evasion_pressure: Option<EvolutionPopulationEvasionSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autonomous_fitness: Option<EvolutionAutonomousFitnessMeasurement>,
    pub proposed_at_ms: Option<i64>,
    pub objectives: EvolutionPopulationFitnessObjectives,
    pub summary: String,
}

/// Durable persisted population of proposal-ready candidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionPopulationState {
    pub updated_at_ms: i64,
    pub ranking_id: String,
    pub validation_batch_id: String,
    pub population_size: usize,
    pub pareto_tournament_size: usize,
    pub proposal_timestamps_ms: Vec<i64>,
    pub members: Vec<EvolutionPopulationCandidate>,
}

/// Per-threat-class coverage preserved for one red-blue evolution episode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionEpisodeThreatClassCoverage {
    pub threat_class: ThreatClass,
    pub total_events: usize,
    pub detected_events: usize,
    pub detection_coverage: f64,
    pub evasion_coverage: f64,
}

/// Blue-side fitness vector persisted for one episode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionEpisodeBlueFitnessVector {
    pub replay_fitness: f64,
    #[serde(default)]
    pub evasion_adjusted_fitness: f64,
    pub memory_adjusted_fitness: f64,
    #[serde(default)]
    pub deception_adjusted_fitness: f64,
    #[serde(default)]
    pub deception_signal_score: f64,
    #[serde(default)]
    pub evasion_pressure_score: f64,
    #[serde(default)]
    pub evasion_gap_closure_rate: f64,
    #[serde(default)]
    pub evasion_focus_gap_count: usize,
    pub adversarial_pressure_score: f64,
    pub adversarial_detection_rate: f64,
    pub final_fitness: f64,
}

/// Red-side fitness vector persisted for one episode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionEpisodeRedFitnessVector {
    pub event_detection_rate: f64,
    pub event_evasion_rate: f64,
    pub threat_class_detection_rate: f64,
    pub threat_class_evasion_rate: f64,
}

/// Durable red-blue episode report for one evaluated candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionEpisodeReport {
    pub episode_id: String,
    pub created_at_ms: i64,
    pub generation: usize,
    pub ranking_id: String,
    pub validation_batch_id: String,
    pub strategy_id: String,
    pub experiment_id: String,
    pub materialization_id: String,
    pub validation_bundle_id: String,
    pub adversarial_corpus_sequence_id: String,
    pub adversarial_corpus_suite_name: String,
    pub adversarial_corpus_version: String,
    pub blue_genome_hash: String,
    pub threat_class_coverage: Vec<EvolutionEpisodeThreatClassCoverage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autonomous_fitness: Option<EvolutionAutonomousFitnessMeasurement>,
    pub blue_fitness: EvolutionEpisodeBlueFitnessVector,
    pub red_fitness: EvolutionEpisodeRedFitnessVector,
}

/// Index record for one persisted evolution episode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionEpisodeRecord {
    pub episode_id: String,
    pub generation: usize,
    pub strategy_id: String,
    pub adversarial_corpus_sequence_id: String,
    pub adversarial_corpus_suite_name: String,
    pub adversarial_corpus_version: String,
    pub blue_genome_hash: String,
    pub created_at_ms: i64,
    pub final_fitness: f64,
    pub evasion_pressure_score: f64,
    pub evasion_gap_closure_rate: f64,
    pub evasion_focus_gap_count: usize,
    pub event_detection_rate: f64,
    pub event_evasion_rate: f64,
    pub threat_class_detection_rate: f64,
    pub bundle_path: String,
}

impl EvolutionEpisodeRecord {
    pub(crate) fn from_report(report: &EvolutionEpisodeReport, bundle_path: String) -> Self {
        Self {
            episode_id: report.episode_id.clone(),
            generation: report.generation,
            strategy_id: report.strategy_id.clone(),
            adversarial_corpus_sequence_id: report.adversarial_corpus_sequence_id.clone(),
            adversarial_corpus_suite_name: report.adversarial_corpus_suite_name.clone(),
            adversarial_corpus_version: report.adversarial_corpus_version.clone(),
            blue_genome_hash: report.blue_genome_hash.clone(),
            created_at_ms: report.created_at_ms,
            final_fitness: report.blue_fitness.final_fitness,
            evasion_pressure_score: report.blue_fitness.evasion_pressure_score,
            evasion_gap_closure_rate: report.blue_fitness.evasion_gap_closure_rate,
            evasion_focus_gap_count: report.blue_fitness.evasion_focus_gap_count,
            event_detection_rate: report.blue_fitness.adversarial_detection_rate,
            event_evasion_rate: report.red_fitness.event_evasion_rate,
            threat_class_detection_rate: report.red_fitness.threat_class_detection_rate,
            bundle_path,
        }
    }
}

/// Persisted evolution episode loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionEpisodeLookup {
    pub record: EvolutionEpisodeRecord,
    pub report: EvolutionEpisodeReport,
}

/// Input contract for one adversarial-pressure evaluation.
#[derive(Debug, Clone)]
pub struct EvolutionAdversarialPressureRequest {
    pub ranking_id: String,
    pub validation_batch_id: String,
    pub generation: usize,
    pub evaluated_at_ms: i64,
    pub strategy_id: String,
    pub experiment_id: String,
    pub experiment_path: PathBuf,
    pub materialization_id: String,
    pub validation_bundle_id: String,
    pub autonomous_fitness: Option<EvolutionAutonomousFitnessMeasurement>,
    pub replay_fitness: f64,
    pub evasion_adjusted_fitness: f64,
    pub evasion_pressure_score: f64,
    pub evasion_gap_closure_rate: f64,
    pub evasion_focus_gap_count: usize,
    pub memory_adjusted_fitness: f64,
    pub deception_adjusted_fitness: f64,
    pub deception_signal_score: f64,
    pub adversarial_corpus_sequence_id: String,
    pub adversarial_corpus_suite_name: String,
    pub adversarial_corpus_version: String,
    pub adversarial_corpus_events: Vec<TelemetryEvent>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionEvasionGapFocus {
    pub threat_class: ThreatClass,
    pub total_payloads: usize,
    pub missed_payloads: usize,
    pub catch_rate: f64,
    pub actionable_techniques: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionEvasionPressureInput {
    pub detector: String,
    pub suite_name: String,
    pub suite_path: PathBuf,
    pub corpus_version: String,
    pub gaps: Vec<EvolutionEvasionGapFocus>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionPopulationEvasionSummary {
    pub detector: String,
    pub suite_name: String,
    pub corpus_version: String,
    pub gap_count: usize,
    pub focused_event_count: usize,
    pub detected_event_count: usize,
    pub gap_closure_rate: f64,
    pub pressure_score: f64,
    pub threat_classes: Vec<ThreatClass>,
    pub actionable_techniques: Vec<String>,
}

/// Result returned after applying adversarial pressure to one candidate.
#[derive(Debug, Clone)]
pub struct EvolutionAdversarialPressureResult {
    pub episode: EvolutionEpisodeReport,
    pub pressure_score: f64,
    pub final_fitness: f64,
}

/// Generation-over-generation delta captured for one benchmark population leader.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionBenchmarkFitnessDelta {
    pub measured_fitness: f64,
    pub catch_rate: f64,
    pub false_positive_rate: f64,
    pub false_positive_fitness: f64,
    pub latency_fitness: f64,
}

/// Durable benchmark summary for one completed generation inside a bounded run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionBenchmarkGenerationReport {
    pub benchmark_id: String,
    pub generation: usize,
    pub created_at_ms: i64,
    pub draft_id: String,
    pub mutation_spec_id: String,
    pub materialization_batch_id: String,
    pub validation_batch_id: String,
    pub ranking_id: String,
    pub tracked_candidate_count: usize,
    pub leader_generation: usize,
    pub leader_population_rank: usize,
    pub leader_strategy_id: String,
    pub leader_variant_id: String,
    pub leader_materialization_id: String,
    pub leader_validation_bundle_id: String,
    pub leader_recipe_kind: EvolutionAutonomousVariantRecipeKind,
    pub leader_parent_strategy_ids: Vec<String>,
    pub corpus_suite_name: String,
    pub corpus_version: String,
    pub measured_event_count: usize,
    pub detected_event_count: usize,
    pub leader_measured_fitness: f64,
    pub mean_measured_fitness: f64,
    pub leader_catch_rate: f64,
    pub leader_false_positive_rate: f64,
    pub leader_false_positive_fitness: f64,
    pub leader_latency_fitness: f64,
    pub leader_max_detect_latency_us: u64,
    pub leader_latency_budget_us: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_from_previous: Option<EvolutionBenchmarkFitnessDelta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_from_first: Option<EvolutionBenchmarkFitnessDelta>,
}

/// Durable baseline metrics recorded for the staged seed experiment in a bounded benchmark run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvolutionBenchmarkBaselineReport {
    pub strategy_id: String,
    pub corpus_suite_name: String,
    pub corpus_version: String,
    pub measured_event_count: usize,
    pub detected_event_count: usize,
    pub measured_fitness: f64,
    pub catch_rate: f64,
    pub false_positive_rate: f64,
    pub false_positive_fitness: f64,
    pub latency_fitness: f64,
    pub max_detect_latency_us: u64,
    pub latency_budget_us: u64,
}

/// One bounded benchmark run persisted in the durable evolution store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionBenchmarkRunReport {
    pub benchmark_id: String,
    pub label: String,
    pub detector: String,
    pub baseline_experiment_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<EvolutionBenchmarkBaselineReport>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub requested_generation_count: usize,
    pub completed_generation_count: usize,
    pub max_variants_per_generation: usize,
    pub population_size: usize,
    pub corpus_suite_name: String,
    pub corpus_version: String,
    pub suite_path: String,
    pub notes: String,
    pub generations: Vec<EvolutionBenchmarkGenerationReport>,
}

/// Index metadata surfaced for one persisted benchmark run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionBenchmarkRunRecord {
    pub benchmark_id: String,
    pub label: String,
    pub detector: String,
    pub requested_generation_count: usize,
    pub completed_generation_count: usize,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionBenchmarkRunRecord {
    pub(crate) fn from_report(report: &EvolutionBenchmarkRunReport, bundle_path: String) -> Self {
        Self {
            benchmark_id: report.benchmark_id.clone(),
            label: report.label.clone(),
            detector: report.detector.clone(),
            requested_generation_count: report.requested_generation_count,
            completed_generation_count: report.completed_generation_count,
            created_at_ms: report.created_at_ms,
            updated_at_ms: report.updated_at_ms,
            bundle_path,
        }
    }
}

/// Persisted benchmark run loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionBenchmarkRunLookup {
    pub record: EvolutionBenchmarkRunRecord,
    pub report: EvolutionBenchmarkRunReport,
}
