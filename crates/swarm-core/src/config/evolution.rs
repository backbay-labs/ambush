use super::*;

/// Repo-owned evolution settings for runtime Kitten orchestration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionConfig {
    /// Whether the runtime-owned evolution lane is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Sliding observation window used when evaluating recent drift evidence.
    #[serde(default = "default_evolution_observation_window_secs")]
    pub observation_window_secs: u64,
    /// Fraction of degraded observations required to trigger drift.
    #[serde(default = "default_evolution_drift_threshold_pct")]
    pub drift_threshold_pct: f64,
    /// Minimum number of recent observations required before drift can trigger.
    #[serde(default = "default_evolution_minimum_observations")]
    pub minimum_observations: usize,
    /// Cooldown window after one proposal cycle completes.
    #[serde(default = "default_evolution_cooldown_secs")]
    pub cooldown_secs: u64,
    /// Maximum number of candidate variants materialized during one cycle.
    #[serde(default = "default_evolution_max_variants_per_cycle")]
    pub max_variants_per_cycle: usize,
    /// Number of ranked candidates preserved for proposal review.
    #[serde(default = "default_evolution_shortlist_count")]
    pub shortlist_count: usize,
    /// Maximum number of persisted candidates retained across generations.
    #[serde(default = "default_evolution_population_size")]
    pub population_size: usize,
    /// Tournament width used when selecting Pareto survivors from the population.
    #[serde(default = "default_evolution_pareto_tournament_size")]
    pub pareto_tournament_size: usize,
    /// Maximum number of candidate proposals emitted during a rolling one-hour window.
    #[serde(default = "default_evolution_max_proposals_per_hour")]
    pub max_proposals_per_hour: usize,
    /// Multi-objective weights used when scoring validated candidates.
    #[serde(default)]
    pub fitness_weights: EvolutionFitnessWeightsConfig,
    /// Repo-owned formal safety gate settings for canary admission.
    #[serde(default)]
    pub safety_gate: EvolutionSafetyGateConfig,
    /// Repo-owned assurance policy that turns robustness artifacts into gate inputs.
    #[serde(default)]
    pub assurance: EvolutionAssuranceConfig,
    /// Durable artifact directories shared with the extracted evolution workflows.
    #[serde(default)]
    pub paths: EvolutionPathsConfig,
}

/// Weighting used by the runtime evolution lane when combining replay-derived objectives.
///
/// Three of these four weights are applied. `speed` is not -- see the field
/// comment and [`EvolutionFitnessWeightsConfig::applied`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionFitnessWeightsConfig {
    #[serde(default = "default_evolution_fitness_detection_rate_weight")]
    pub detection_rate: f64,
    #[serde(default = "default_evolution_fitness_false_positive_cost_weight")]
    pub false_positive_cost: f64,
    /// ACCEPTED FOR COMPATIBILITY, NO LONGER APPLIED.
    ///
    /// This weighted a `speed` objective derived from a wall-clock `Instant`
    /// delta around the detect stage, which made a candidate's rank a function
    /// of the machine and build profile that happened to measure it rather than
    /// of the candidate. Latency is still measured and still recorded; it no
    /// longer ranks anything.
    ///
    /// The field cannot be deleted. This struct is `deny_unknown_fields` and
    /// the repo's own `rulesets/default.yaml` carries a `speed:` entry, as does
    /// every ruleset already deployed; removing it would turn a config that
    /// loads today into a hard startup failure. `rulesets/` is additionally
    /// covered by the signed `rulesets/attestation.json`, whose signing key is
    /// deliberately not in this repository, so the tracked ruleset could not be
    /// edited to drop the key either.
    ///
    /// The configured share is redistributed proportionally across the three
    /// weights that remain, so the total weight -- and therefore the scale that
    /// `fitness` is blended and compared on -- is unchanged. The value is still
    /// validated (finite, non-negative) rather than silently ignored, but it can
    /// no longer be the ONLY non-zero weight: see `validate` below.
    #[serde(default = "default_evolution_fitness_speed_weight")]
    pub speed: f64,
    #[serde(default = "default_evolution_fitness_threat_class_coverage_weight")]
    pub threat_class_coverage: f64,
}

/// The weights the evolution lane actually applies to the ranking objectives.
///
/// Produced by [`EvolutionFitnessWeightsConfig::applied`]. Distinct from the
/// config struct so that a caller cannot reach for the inert `speed` weight by
/// accident.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EvolutionAppliedFitnessWeights {
    pub detection_rate: f64,
    pub false_positive_cost: f64,
    pub threat_class_coverage: f64,
}

/// Repo-owned formal safety gate settings used before canary admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionSafetyGateConfig {
    /// Bundle files defining deterministic safety invariants for evolved candidates.
    #[serde(default = "default_evolution_safety_invariant_bundle_paths")]
    pub invariant_bundle_paths: Vec<String>,
    /// Optional Z3-backed proof mode toggle for future strict verification.
    #[serde(default)]
    pub enable_z3: bool,
}

/// Repo-owned assurance policy used when deciding whether a candidate can stay queue-eligible.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionAssuranceConfig {
    /// Whether a solver summary must be present on proposal proofs.
    #[serde(default)]
    pub require_solver_summary: bool,
    /// Global minimum detector catch rate required across the repo-owned evasion suite.
    #[serde(default = "default_evolution_assurance_min_detector_catch_rate")]
    pub min_detector_catch_rate: f64,
    /// Solver outcomes that remain eligible under the assurance policy.
    #[serde(default = "default_evolution_assurance_allowed_solver_statuses")]
    pub allowed_solver_statuses: Vec<EvolutionAssuranceSolverStatusConfig>,
    /// Per-detector catch-rate overrides for stricter or looser assurance floors.
    #[serde(default)]
    pub coverage_overrides: Vec<EvolutionAssuranceCoverageOverrideConfig>,
    /// Bounded durable regeneration settings for harvested assurance cases.
    #[serde(default)]
    pub harvest: EvolutionAssuranceHarvestConfig,
    /// Bounded signed waiver limits for one blocked assurance decision.
    #[serde(default)]
    pub waiver: EvolutionAssuranceWaiverConfig,
}

/// Repo-owned solver-proof outcomes allowed by the assurance policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionAssuranceSolverStatusConfig {
    Proved,
    Counterexample,
    Timeout,
    Disabled,
    Error,
}

/// Per-detector assurance floor override.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionAssuranceCoverageOverrideConfig {
    pub detector: String,
    pub min_catch_rate: f64,
}

/// Repo-owned harvest settings for replayable assurance cases.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionAssuranceHarvestConfig {
    #[serde(default = "default_evolution_assurance_harvest_results_dir")]
    pub results_dir: String,
    #[serde(default = "default_evolution_assurance_harvest_max_cases_per_proposal")]
    pub max_cases_per_proposal: usize,
    #[serde(default = "default_evolution_assurance_harvest_max_events_per_case")]
    pub max_events_per_case: usize,
}

/// Repo-owned limits that bound one signed assurance waiver.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionAssuranceWaiverConfig {
    #[serde(default)]
    pub allowed_operator_ids: Vec<String>,
    #[serde(default = "default_evolution_assurance_waiver_max_ttl_secs")]
    pub max_ttl_secs: u64,
    #[serde(default = "default_evolution_assurance_waiver_max_actionable_gap_count")]
    pub max_actionable_gap_count: usize,
}

/// Durable artifact paths used by the runtime evolution lane.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionPathsConfig {
    #[serde(default = "default_replay_results_dir")]
    pub replay_results_dir: String,
    #[serde(default = "default_experiment_results_dir")]
    pub experiment_results_dir: String,
    #[serde(default = "default_verification_results_dir")]
    pub verification_results_dir: String,
    #[serde(default = "default_shadow_results_dir")]
    pub shadow_results_dir: String,
    #[serde(default = "default_strategy_memory_results_dir")]
    pub strategy_memory_results_dir: String,
    #[serde(default = "default_strategy_scorecard_results_dir")]
    pub strategy_scorecard_results_dir: String,
    #[serde(default = "default_evolution_proof_results_dir")]
    pub evolution_proof_results_dir: String,
    #[serde(default = "default_evolution_queue_results_dir")]
    pub evolution_queue_results_dir: String,
    #[serde(default = "default_evolution_selection_results_dir")]
    pub evolution_selection_results_dir: String,
    #[serde(default = "default_evolution_bridge_results_dir")]
    pub evolution_bridge_results_dir: String,
    #[serde(default = "default_evolution_handoff_results_dir")]
    pub evolution_handoff_results_dir: String,
    #[serde(default = "default_evolution_pressure_results_dir")]
    pub evolution_pressure_results_dir: String,
    #[serde(default = "default_evolution_draft_results_dir")]
    pub evolution_draft_results_dir: String,
    #[serde(default = "default_evolution_draft_promotion_results_dir")]
    pub evolution_draft_promotion_results_dir: String,
    #[serde(default = "default_evolution_materialization_results_dir")]
    pub evolution_materialization_results_dir: String,
    #[serde(default = "default_evolution_validation_results_dir")]
    pub evolution_validation_results_dir: String,
    #[serde(default = "default_evolution_reconciliation_results_dir")]
    pub evolution_reconciliation_results_dir: String,
    #[serde(default = "default_evolution_mutation_results_dir")]
    pub evolution_mutation_results_dir: String,
    #[serde(default = "default_evolution_mutation_materialization_batch_results_dir")]
    pub evolution_mutation_materialization_batch_results_dir: String,
    #[serde(default = "default_evolution_mutation_validation_batch_results_dir")]
    pub evolution_mutation_validation_batch_results_dir: String,
    #[serde(default = "default_evolution_ranking_results_dir")]
    pub evolution_ranking_results_dir: String,
    #[serde(default = "default_evolution_population_results_dir")]
    pub evolution_population_results_dir: String,
    #[serde(default = "default_canary_results_dir")]
    pub canary_results_dir: String,
}

impl EvolutionConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.observation_window_secs == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.observation_window_secs",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        if !(0.0..=1.0).contains(&self.drift_threshold_pct) || self.drift_threshold_pct == 0.0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.drift_threshold_pct",
                reason: "must be greater than 0.0 and less than or equal to 1.0".to_string(),
            });
        }
        if self.minimum_observations == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.minimum_observations",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        if self.cooldown_secs == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.cooldown_secs",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        if self.max_variants_per_cycle == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.max_variants_per_cycle",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        if self.shortlist_count == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.shortlist_count",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        if self.population_size == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.population_size",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        if self.pareto_tournament_size == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.pareto_tournament_size",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        if self.max_proposals_per_hour == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.max_proposals_per_hour",
                reason: "must be greater than zero when evolution is enabled".to_string(),
            });
        }
        self.fitness_weights.validate()?;
        self.safety_gate.validate()?;
        self.assurance.validate()?;
        self.paths.validate()
    }
}

impl EvolutionFitnessWeightsConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        let components = [
            (
                "evolution.fitness_weights.detection_rate",
                self.detection_rate,
            ),
            (
                "evolution.fitness_weights.false_positive_cost",
                self.false_positive_cost,
            ),
            ("evolution.fitness_weights.speed", self.speed),
            (
                "evolution.fitness_weights.threat_class_coverage",
                self.threat_class_coverage,
            ),
        ];
        for (field, value) in components {
            if !value.is_finite() || value < 0.0 {
                return Err(ConfigValidationError::InvalidField {
                    field,
                    reason: "must be finite and greater than or equal to zero".to_string(),
                });
            }
        }
        // `speed` is deliberately absent from this total. It used to count, so a
        // config that set ONLY `speed` passed validation and produced a working
        // ranking. Under the applied weights that same config yields a fitness
        // of exactly zero for every candidate -- a silent total tie in which
        // survivor selection falls through to tie-breaks and the operator's
        // stated objective is never expressed. Fail closed at load instead.
        if self.applied_weight_total() <= 0.0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.fitness_weights",
                reason: "at least one of `detection_rate`, `false_positive_cost` or \
                         `threat_class_coverage` must be greater than zero (`speed` is accepted \
                         for compatibility but no longer contributes)"
                    .to_string(),
            });
        }
        Ok(())
    }

    fn applied_weight_total(&self) -> f64 {
        self.detection_rate + self.false_positive_cost + self.threat_class_coverage
    }

    /// The weights actually applied to the ranking objectives.
    ///
    /// `speed`'s configured share is redistributed proportionally across the
    /// three remaining weights, so the total weight is whatever the operator
    /// wrote and only the split changes.
    ///
    /// Redistribution rather than a plain drop: `fitness` is not only ranked, it
    /// is blended against rate-scaled quantities (see the evasion-pressure blend
    /// in the runtime's population refresh, which mixes fitness with a 0..1
    /// closure rate). Dropping `speed`'s share outright would shrink the fitness
    /// side of that blend by its weight while the rate side kept its full range,
    /// quietly re-weighting a second thing that has nothing to do with latency.
    /// Redistribution is also order-preserving with respect to a plain drop: it
    /// scales every candidate's fitness by the same positive constant, so it
    /// changes no ranking relative to simply removing the term.
    ///
    /// Rankings DO change relative to the pre-fix behaviour that included
    /// `speed`. That is the point: they stop depending on the machine.
    pub fn applied(&self) -> EvolutionAppliedFitnessWeights {
        let applied_total = self.applied_weight_total();
        // `validate` rejects a non-positive applied total, so this is only
        // reachable for a hand-built config that skipped validation. Fall back to
        // the configured weights verbatim rather than dividing by zero.
        if applied_total <= 0.0 {
            return EvolutionAppliedFitnessWeights {
                detection_rate: self.detection_rate,
                false_positive_cost: self.false_positive_cost,
                threat_class_coverage: self.threat_class_coverage,
            };
        }
        let scale = (applied_total + self.speed) / applied_total;
        EvolutionAppliedFitnessWeights {
            detection_rate: self.detection_rate * scale,
            false_positive_cost: self.false_positive_cost * scale,
            threat_class_coverage: self.threat_class_coverage * scale,
        }
    }
}

impl EvolutionSafetyGateConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.invariant_bundle_paths.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.safety_gate.invariant_bundle_paths",
                reason: "must include at least one repo-owned invariant bundle when evolution is enabled"
                    .to_string(),
            });
        }
        for (index, path) in self.invariant_bundle_paths.iter().enumerate() {
            if path.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "evolution.safety_gate.invariant_bundle_paths",
                    reason: format!("entry {index} must not be empty"),
                });
            }
        }
        Ok(())
    }
}

impl EvolutionAssuranceConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        if !self.min_detector_catch_rate.is_finite()
            || !(0.0..=1.0).contains(&self.min_detector_catch_rate)
        {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.assurance.min_detector_catch_rate",
                reason: "must be between 0.0 and 1.0".to_string(),
            });
        }
        if self.allowed_solver_statuses.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.assurance.allowed_solver_statuses",
                reason: "must include at least one allowed solver outcome".to_string(),
            });
        }
        for (index, override_config) in self.coverage_overrides.iter().enumerate() {
            if override_config.detector.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "evolution.assurance.coverage_overrides.detector",
                    reason: format!("entry {index} must not be empty"),
                });
            }
            if !override_config.min_catch_rate.is_finite()
                || !(0.0..=1.0).contains(&override_config.min_catch_rate)
            {
                return Err(ConfigValidationError::InvalidField {
                    field: "evolution.assurance.coverage_overrides.min_catch_rate",
                    reason: "must be between 0.0 and 1.0".to_string(),
                });
            }
        }
        self.harvest.validate()?;
        self.waiver.validate()?;
        Ok(())
    }
}

impl EvolutionAssuranceHarvestConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_non_empty("evolution.assurance.harvest.results_dir", &self.results_dir)?;
        if self.max_cases_per_proposal == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.assurance.harvest.max_cases_per_proposal",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.max_events_per_case == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.assurance.harvest.max_events_per_case",
                reason: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

impl EvolutionAssuranceWaiverConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.max_ttl_secs == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.assurance.waiver.max_ttl_secs",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.max_actionable_gap_count == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "evolution.assurance.waiver.max_actionable_gap_count",
                reason: "must be greater than zero".to_string(),
            });
        }
        for (index, operator_id) in self.allowed_operator_ids.iter().enumerate() {
            if operator_id.trim().is_empty() {
                return Err(ConfigValidationError::InvalidField {
                    field: "evolution.assurance.waiver.allowed_operator_ids",
                    reason: format!("entry {index} must not be empty"),
                });
            }
            if !operator_id.starts_with("swarm:ed25519:") {
                return Err(ConfigValidationError::InvalidField {
                    field: "evolution.assurance.waiver.allowed_operator_ids",
                    reason: format!("entry {index} must start with swarm:ed25519:"),
                });
            }
        }
        Ok(())
    }
}

impl EvolutionPathsConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_non_empty(
            "evolution.paths.replay_results_dir",
            &self.replay_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.experiment_results_dir",
            &self.experiment_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.verification_results_dir",
            &self.verification_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.shadow_results_dir",
            &self.shadow_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.strategy_memory_results_dir",
            &self.strategy_memory_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.strategy_scorecard_results_dir",
            &self.strategy_scorecard_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_proof_results_dir",
            &self.evolution_proof_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_queue_results_dir",
            &self.evolution_queue_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_selection_results_dir",
            &self.evolution_selection_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_bridge_results_dir",
            &self.evolution_bridge_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_handoff_results_dir",
            &self.evolution_handoff_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_pressure_results_dir",
            &self.evolution_pressure_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_draft_results_dir",
            &self.evolution_draft_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_draft_promotion_results_dir",
            &self.evolution_draft_promotion_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_materialization_results_dir",
            &self.evolution_materialization_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_validation_results_dir",
            &self.evolution_validation_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_reconciliation_results_dir",
            &self.evolution_reconciliation_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_mutation_results_dir",
            &self.evolution_mutation_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_mutation_materialization_batch_results_dir",
            &self.evolution_mutation_materialization_batch_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_mutation_validation_batch_results_dir",
            &self.evolution_mutation_validation_batch_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_ranking_results_dir",
            &self.evolution_ranking_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.evolution_population_results_dir",
            &self.evolution_population_results_dir,
        )?;
        validate_non_empty(
            "evolution.paths.canary_results_dir",
            &self.canary_results_dir,
        )?;
        Ok(())
    }
}

impl Default for EvolutionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            observation_window_secs: default_evolution_observation_window_secs(),
            drift_threshold_pct: default_evolution_drift_threshold_pct(),
            minimum_observations: default_evolution_minimum_observations(),
            cooldown_secs: default_evolution_cooldown_secs(),
            max_variants_per_cycle: default_evolution_max_variants_per_cycle(),
            shortlist_count: default_evolution_shortlist_count(),
            population_size: default_evolution_population_size(),
            pareto_tournament_size: default_evolution_pareto_tournament_size(),
            max_proposals_per_hour: default_evolution_max_proposals_per_hour(),
            fitness_weights: EvolutionFitnessWeightsConfig::default(),
            safety_gate: EvolutionSafetyGateConfig::default(),
            assurance: EvolutionAssuranceConfig::default(),
            paths: EvolutionPathsConfig::default(),
        }
    }
}

impl Default for EvolutionAssuranceConfig {
    fn default() -> Self {
        Self {
            require_solver_summary: false,
            min_detector_catch_rate: default_evolution_assurance_min_detector_catch_rate(),
            allowed_solver_statuses: default_evolution_assurance_allowed_solver_statuses(),
            coverage_overrides: Vec::new(),
            harvest: EvolutionAssuranceHarvestConfig::default(),
            waiver: EvolutionAssuranceWaiverConfig::default(),
        }
    }
}

impl Default for EvolutionAssuranceHarvestConfig {
    fn default() -> Self {
        Self {
            results_dir: default_evolution_assurance_harvest_results_dir(),
            max_cases_per_proposal: default_evolution_assurance_harvest_max_cases_per_proposal(),
            max_events_per_case: default_evolution_assurance_harvest_max_events_per_case(),
        }
    }
}

impl Default for EvolutionAssuranceWaiverConfig {
    fn default() -> Self {
        Self {
            allowed_operator_ids: Vec::new(),
            max_ttl_secs: default_evolution_assurance_waiver_max_ttl_secs(),
            max_actionable_gap_count: default_evolution_assurance_waiver_max_actionable_gap_count(),
        }
    }
}

impl Default for EvolutionFitnessWeightsConfig {
    fn default() -> Self {
        Self {
            detection_rate: default_evolution_fitness_detection_rate_weight(),
            false_positive_cost: default_evolution_fitness_false_positive_cost_weight(),
            speed: default_evolution_fitness_speed_weight(),
            threat_class_coverage: default_evolution_fitness_threat_class_coverage_weight(),
        }
    }
}

impl Default for EvolutionSafetyGateConfig {
    fn default() -> Self {
        Self {
            invariant_bundle_paths: default_evolution_safety_invariant_bundle_paths(),
            enable_z3: false,
        }
    }
}

impl Default for EvolutionPathsConfig {
    fn default() -> Self {
        Self {
            replay_results_dir: default_replay_results_dir(),
            experiment_results_dir: default_experiment_results_dir(),
            verification_results_dir: default_verification_results_dir(),
            shadow_results_dir: default_shadow_results_dir(),
            strategy_memory_results_dir: default_strategy_memory_results_dir(),
            strategy_scorecard_results_dir: default_strategy_scorecard_results_dir(),
            evolution_proof_results_dir: default_evolution_proof_results_dir(),
            evolution_queue_results_dir: default_evolution_queue_results_dir(),
            evolution_selection_results_dir: default_evolution_selection_results_dir(),
            evolution_bridge_results_dir: default_evolution_bridge_results_dir(),
            evolution_handoff_results_dir: default_evolution_handoff_results_dir(),
            evolution_pressure_results_dir: default_evolution_pressure_results_dir(),
            evolution_draft_results_dir: default_evolution_draft_results_dir(),
            evolution_draft_promotion_results_dir: default_evolution_draft_promotion_results_dir(),
            evolution_materialization_results_dir: default_evolution_materialization_results_dir(),
            evolution_validation_results_dir: default_evolution_validation_results_dir(),
            evolution_reconciliation_results_dir: default_evolution_reconciliation_results_dir(),
            evolution_mutation_results_dir: default_evolution_mutation_results_dir(),
            evolution_mutation_materialization_batch_results_dir:
                default_evolution_mutation_materialization_batch_results_dir(),
            evolution_mutation_validation_batch_results_dir:
                default_evolution_mutation_validation_batch_results_dir(),
            evolution_ranking_results_dir: default_evolution_ranking_results_dir(),
            evolution_population_results_dir: default_evolution_population_results_dir(),
            canary_results_dir: default_canary_results_dir(),
        }
    }
}
