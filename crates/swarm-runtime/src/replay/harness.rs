use super::helpers::{
    equality_check, experiment_id_for_manifest, latency_check, normalize_groups, now_ms,
    promotion_review_id_for_packet, resolve_relative_path, run_id_for_manifest,
    scenario_paths_in_dir, verification_id_for_experiment,
};
use super::metrics::{
    compare_suite_reports, evaluate_experiment_gates, shadow_report_from_experiment,
    technique_groups_from_suite,
};
use super::stores::{
    FileExperimentStore, FilePromotionReviewStore, FileReplayRunStore, FileShadowStore,
    FileVerificationStore, ReplayRunStore,
};
use super::types::{
    DetectorCandidateManifest, DetectorVerificationLookup, DetectorVerificationReport,
    LoadedDetectorExperiment, LoadedReplayScenario, PromotionReviewLookup, PromotionReviewPacket,
    PromotionReviewRecommendation, ReplayDeterministicSummary, ReplayEvaluationCheck,
    ReplayEvaluationReport, ReplayHarnessError, ReplayRunBundle, ReplayRunLookup,
    ReplayScenarioInput, ReplayScenarioStep, ReplaySuiteReport, ReplaySuiteScenarioReport,
    ReplaySuiteSourceKind, StrategyExperimentLookup, StrategyExperimentReport,
    StrategyShadowLookup, StrategyShadowReport,
};
use super::validation::{
    load_experiment_manifest, load_scenario_manifest, load_suite_manifest,
    load_verification_manifest,
};
use super::verification::{
    collect_review_blocking_reasons, observe_detect_latency, verify_canonical_templates,
    verify_false_positive_bound, verify_known_bad_coverage, verify_total_detection_budget,
};
use crate::config::load_config;
use crate::correlation::{CorrelationEngine, CorrelationOutcome};
use crate::detector_factory::{
    DetectorFactoryError, RuntimeDetector, build_detector_from_candidate,
    build_detector_from_strategy,
};
use crate::investigation::{
    InvestigationStrategy, SummaryInvestigator, compute_priority, decide_outcome,
};
use crate::service::{EventExecutionContext, RuntimeService};
use crate::{RuntimeMode, SwarmRuntime};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use swarm_core::config::{CorrelationConfig, SwarmConfig};
use swarm_core::types::AgentId;
use swarm_pheromone::InMemoryPheromoneSubstrate;
use swarm_policy::ApprovalContext;
use swarm_policy::configurable_gate::ConfigurableApprovalGate;
use swarm_response::adapters::SandboxExecutor;
use swarm_spine::{
    CorrelatedIncident, InvestigationBundle, InvestigationBundleStore, InvestigationStatus,
    MemoryIncidentStore, MemoryInvestigationBundleStore, ReplayBundle,
};

/// Offline replay harness that reuses the production Rust types without executing live actions.
pub struct DefaultReplayHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub results_dir: PathBuf,
    detector: RuntimeDetector,
    result_store: FileReplayRunStore,
}

/// Fixed seed for the replay lane's in-memory simulation identity. Documented at the
/// use site; deliberately constant so two replay runs of the same scenario produce
/// comparable `agent_id`s.
const REPLAY_SIMULATION_SIGNING_SEED: [u8; 32] = [42u8; 32];

impl DefaultReplayHarness {
    /// Build the harness from repository config plus a durable replay-results directory.
    pub fn from_path(
        config_path: impl AsRef<Path>,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, ReplayHarnessError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config(config_path, config, results_dir)
    }

    /// Build the harness from an already-validated config.
    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, ReplayHarnessError> {
        let detector = replay_detector(&config)?;
        let result_store = FileReplayRunStore::open(results_dir.as_ref())?;
        Ok(Self {
            config_path: config_path.into(),
            config,
            results_dir: results_dir.as_ref().to_path_buf(),
            detector,
            result_store,
        })
    }

    /// Execute one scenario manifest, persist the result bundle, and return the durable lookup.
    pub async fn run_scenario_path(
        &self,
        scenario_path: impl AsRef<Path>,
    ) -> Result<ReplayRunLookup, ReplayHarnessError> {
        let loaded = load_scenario_manifest(scenario_path)?;
        let run_bundle = self.run_loaded_scenario(&self.detector, &loaded).await?;
        let record = self.result_store.persist(&run_bundle)?;

        Ok(ReplayRunLookup {
            record,
            bundle: run_bundle,
        })
    }

    /// Load a persisted replay run by its stable run id.
    pub fn load_run(&self, run_id: &str) -> Result<Option<ReplayRunLookup>, ReplayHarnessError> {
        Ok(self.result_store.load_by_run_id(run_id)?)
    }

    /// Load a persisted replay run using the stable run id derived from a scenario manifest.
    pub fn load_run_for_scenario_path(
        &self,
        scenario_path: impl AsRef<Path>,
    ) -> Result<Option<ReplayRunLookup>, ReplayHarnessError> {
        let loaded = load_scenario_manifest(scenario_path)?;
        self.load_run(&run_id_for_manifest(&loaded.manifest))
    }

    /// Execute one scenario and immediately evaluate the result bundle.
    pub async fn evaluate_scenario_path(
        &self,
        scenario_path: impl AsRef<Path>,
    ) -> Result<ReplayEvaluationReport, ReplayHarnessError> {
        let lookup = self.run_scenario_path(scenario_path).await?;
        Ok(self.evaluate_run(&lookup.bundle))
    }

    /// Evaluate every tracked scenario in one directory and aggregate the results.
    pub async fn evaluate_scenarios_dir(
        &self,
        scenarios_dir: impl AsRef<Path>,
    ) -> Result<ReplaySuiteReport, ReplayHarnessError> {
        let scenarios_dir = scenarios_dir.as_ref().to_path_buf();
        let scenario_paths = scenario_paths_in_dir(&scenarios_dir)?;
        if scenario_paths.is_empty() {
            return Err(ReplayHarnessError::ScenarioValidation {
                path: scenarios_dir,
                reason: "scenario directory did not contain any .yaml scenarios".to_string(),
            });
        }

        self.evaluate_suite_selection(
            &self.detector,
            scenario_paths,
            ReplaySuiteSelection {
                source: scenarios_dir.display().to_string(),
                source_kind: ReplaySuiteSourceKind::ScenariosDir,
                suite_name: None,
                suite_description: None,
                corpus_version: None,
            },
        )
        .await
    }

    /// Evaluate one named suite manifest and aggregate the result by suite and technique.
    pub async fn evaluate_suite_path(
        &self,
        suite_path: impl AsRef<Path>,
    ) -> Result<ReplaySuiteReport, ReplayHarnessError> {
        let loaded_suite = load_suite_manifest(suite_path)?;
        let scenario_paths = loaded_suite
            .manifest
            .scenarios
            .iter()
            .map(|scenario| resolve_relative_path(&loaded_suite.path, scenario))
            .collect::<Vec<_>>();
        self.evaluate_suite_selection(
            &self.detector,
            scenario_paths,
            ReplaySuiteSelection {
                source: loaded_suite.path.display().to_string(),
                source_kind: ReplaySuiteSourceKind::SuiteManifest,
                suite_name: Some(loaded_suite.manifest.name.clone()),
                suite_description: Some(loaded_suite.manifest.description.clone()),
                corpus_version: Some(loaded_suite.manifest.corpus_version.clone()),
            },
        )
        .await
    }

    /// Evaluate and persist one baseline-vs-candidate detector experiment.
    pub async fn evaluate_experiment_path(
        &self,
        experiment_path: impl AsRef<Path>,
        experiments_dir: impl AsRef<Path>,
    ) -> Result<StrategyExperimentLookup, ReplayHarnessError> {
        let loaded_experiment = load_experiment_manifest(experiment_path)?;
        let (report, _) = self.build_experiment_report(&loaded_experiment).await?;
        self.persist_experiment_report(experiments_dir.as_ref(), report)
    }

    /// Evaluate and persist one detector experiment plus its shadow report from a single run.
    pub async fn evaluate_experiment_and_shadow_path(
        &self,
        experiment_path: impl AsRef<Path>,
        experiments_dir: impl AsRef<Path>,
        shadows_dir: impl AsRef<Path>,
    ) -> Result<(StrategyExperimentLookup, StrategyShadowLookup), ReplayHarnessError> {
        let loaded_experiment = load_experiment_manifest(experiment_path)?;
        let (report, source_artifacts) = self.build_experiment_report(&loaded_experiment).await?;
        let experiment =
            self.persist_experiment_report(experiments_dir.as_ref(), report.clone())?;
        let shadow = self.persist_shadow_report(
            shadows_dir.as_ref(),
            shadow_report_from_experiment(&report, source_artifacts),
        )?;
        Ok((experiment, shadow))
    }

    /// Load a persisted detector experiment by its stable id.
    pub fn load_experiment(
        &self,
        experiments_dir: impl AsRef<Path>,
        experiment_id: &str,
    ) -> Result<Option<StrategyExperimentLookup>, ReplayHarnessError> {
        let store = FileExperimentStore::open(experiments_dir.as_ref())?;
        Ok(store.load(experiment_id)?)
    }

    /// Evaluate and persist one candidate verification report against the repo-owned corpus.
    pub async fn evaluate_verification_path(
        &self,
        experiment_path: impl AsRef<Path>,
        verifications_dir: impl AsRef<Path>,
    ) -> Result<DetectorVerificationLookup, ReplayHarnessError> {
        let loaded_experiment = load_experiment_manifest(experiment_path)?;
        let report = self.build_verification_report(&loaded_experiment).await?;
        let store = FileVerificationStore::open(verifications_dir.as_ref())?;
        let record = store.persist(&report)?;
        Ok(DetectorVerificationLookup { record, report })
    }

    /// Load a persisted candidate verification report by its stable id.
    pub fn load_verification(
        &self,
        verifications_dir: impl AsRef<Path>,
        verification_id: &str,
    ) -> Result<Option<DetectorVerificationLookup>, ReplayHarnessError> {
        let store = FileVerificationStore::open(verifications_dir.as_ref())?;
        Ok(store.load(verification_id)?)
    }

    /// Evaluate and persist one offline shadow comparison report.
    pub async fn evaluate_shadow_path(
        &self,
        experiment_path: impl AsRef<Path>,
        shadows_dir: impl AsRef<Path>,
    ) -> Result<StrategyShadowLookup, ReplayHarnessError> {
        let loaded_experiment = load_experiment_manifest(experiment_path)?;
        let (report, source_artifacts) = self.build_experiment_report(&loaded_experiment).await?;
        self.persist_shadow_report(
            shadows_dir.as_ref(),
            shadow_report_from_experiment(&report, source_artifacts),
        )
    }

    /// Load a persisted shadow report by its stable id.
    pub fn load_shadow(
        &self,
        shadows_dir: impl AsRef<Path>,
        shadow_id: &str,
    ) -> Result<Option<StrategyShadowLookup>, ReplayHarnessError> {
        let store = FileShadowStore::open(shadows_dir.as_ref())?;
        Ok(store.load(shadow_id)?)
    }

    /// Create and persist one promotion review packet from stable verification and shadow ids.
    pub fn create_promotion_review_packet(
        &self,
        experiment_path: impl AsRef<Path>,
        verifications_dir: impl AsRef<Path>,
        verification_id: &str,
        shadows_dir: impl AsRef<Path>,
        shadow_id: &str,
        reviews_dir: impl AsRef<Path>,
    ) -> Result<PromotionReviewLookup, ReplayHarnessError> {
        let loaded_experiment = load_experiment_manifest(experiment_path)?;
        let experiment_id = experiment_id_for_manifest(&loaded_experiment.manifest);
        let verification = self
            .load_verification(verifications_dir, verification_id)?
            .ok_or_else(|| ReplayHarnessError::ArtifactMissing {
                kind: "verification",
                id: verification_id.to_string(),
            })?;
        let shadow = self.load_shadow(shadows_dir, shadow_id)?.ok_or_else(|| {
            ReplayHarnessError::ArtifactMissing {
                kind: "shadow",
                id: shadow_id.to_string(),
            }
        })?;

        if verification.report.experiment_id != experiment_id {
            return Err(ReplayHarnessError::ReviewValidation {
                reason: format!(
                    "verification `{}` does not belong to experiment `{}`",
                    verification_id, experiment_id
                ),
            });
        }
        if shadow.report.experiment_id != experiment_id {
            return Err(ReplayHarnessError::ReviewValidation {
                reason: format!(
                    "shadow `{}` does not belong to experiment `{}`",
                    shadow_id, experiment_id
                ),
            });
        }

        let blocking_reasons =
            collect_review_blocking_reasons(&verification.report, &shadow.report);
        let recommendation = if verification.report.passed && shadow.report.passed {
            PromotionReviewRecommendation::ReadyForManualReview
        } else {
            PromotionReviewRecommendation::Blocked
        };

        let packet = PromotionReviewPacket {
            review_id: promotion_review_id_for_packet(&loaded_experiment.manifest, &shadow.report),
            experiment_id,
            experiment_name: loaded_experiment.manifest.name.clone(),
            created_at_ms: now_ms(),
            suite_name: shadow.report.suite_name.clone(),
            corpus_version: shadow.report.corpus_version.clone(),
            lineage: loaded_experiment.manifest.lineage.clone(),
            candidate_strategy_id: loaded_experiment
                .manifest
                .candidate
                .strategy_id()
                .to_string(),
            candidate_description: loaded_experiment
                .manifest
                .candidate
                .description()
                .to_string(),
            verification_id: verification.report.verification_id.clone(),
            verification_passed: verification.report.passed,
            shadow_id: shadow.report.shadow_id.clone(),
            shadow_passed: shadow.report.passed,
            detection_rate_delta: shadow.report.comparison.delta.detection_rate_delta,
            false_positive_rate_delta: shadow.report.comparison.delta.false_positive_rate_delta,
            max_detect_latency_delta_us: shadow.report.comparison.delta.max_detect_latency_delta_us,
            recommendation,
            blocking_reasons,
        };
        let store = FilePromotionReviewStore::open(reviews_dir.as_ref())?;
        let record = store.persist(&packet)?;
        Ok(PromotionReviewLookup { record, packet })
    }

    /// Load a persisted promotion review packet by its stable id.
    pub fn load_promotion_review(
        &self,
        reviews_dir: impl AsRef<Path>,
        review_id: &str,
    ) -> Result<Option<PromotionReviewLookup>, ReplayHarnessError> {
        let store = FilePromotionReviewStore::open(reviews_dir.as_ref())?;
        Ok(store.load(review_id)?)
    }

    /// Evaluate one persisted or freshly-executed replay run against repo-owned expectations.
    pub fn evaluate_run(&self, run: &ReplayRunBundle) -> ReplayEvaluationReport {
        let mut checks = Vec::new();
        let summary = &run.deterministic_summary;

        if let Some(expected) = run.expectations.replay_bundle_count {
            checks.push(equality_check(
                "replay_bundle_count",
                json!(expected),
                json!(summary.replay_bundle_count),
                "replay bundle count matched expected scenario output",
            ));
        }
        if let Some(expected) = run.expectations.investigation_count {
            checks.push(equality_check(
                "investigation_count",
                json!(expected),
                json!(summary.investigation_count),
                "investigation bundle count matched expected scenario output",
            ));
        }
        if let Some(expected) = run.expectations.incident_count {
            checks.push(equality_check(
                "incident_count",
                json!(expected),
                json!(summary.incident_count),
                "incident count matched expected scenario output",
            ));
        }

        for expected in &run.expectations.hunts {
            let actual = summary
                .hunts
                .iter()
                .find(|outcome| outcome.hunt_id == expected.hunt_id);
            let (passed, actual_value, details) = match actual {
                Some(actual) => {
                    let actual_value = json!({
                        "action_kind": actual.action_kind,
                        "policy_verdict": actual.policy_verdict,
                        "response_kind": actual.response_kind,
                    });
                    let passed = actual.action_kind == expected.action_kind
                        && actual.policy_verdict == expected.policy_verdict
                        && actual.response_kind == expected.response_kind;
                    let details = if passed {
                        format!(
                            "hunt `{}` matched expected action, policy, and response",
                            expected.hunt_id
                        )
                    } else {
                        format!(
                            "hunt `{}` diverged from expected action, policy, or response",
                            expected.hunt_id
                        )
                    };
                    (passed, actual_value, details)
                }
                None => (
                    false,
                    serde_json::Value::Null,
                    format!(
                        "hunt `{}` was not present in replay output",
                        expected.hunt_id
                    ),
                ),
            };
            checks.push(ReplayEvaluationCheck {
                name: format!("hunt:{}", expected.hunt_id),
                passed,
                expected: json!({
                    "action_kind": expected.action_kind,
                    "policy_verdict": expected.policy_verdict,
                    "response_kind": expected.response_kind,
                }),
                actual: actual_value,
                details,
            });
        }

        if !run.expectations.incident_hunt_groups.is_empty() {
            checks.push(equality_check(
                "incident_hunt_groups",
                json!(normalize_groups(&run.expectations.incident_hunt_groups)),
                json!(normalize_groups(&summary.incident_hunt_groups)),
                "incident hunt group membership matched replay expectations",
            ));
        }

        if let Some(expected) = run.expectations.max_detect_latency_us {
            checks.push(latency_check(
                "max_detect_latency_us",
                expected,
                run.performance.detect.max_latency_us,
            ));
        }
        if let Some(expected) = run.expectations.max_policy_latency_us {
            checks.push(latency_check(
                "max_policy_latency_us",
                expected,
                run.performance.policy.max_latency_us,
            ));
        }
        if let Some(expected) = run.expectations.max_response_latency_us {
            checks.push(latency_check(
                "max_response_latency_us",
                expected,
                run.performance.response.max_latency_us,
            ));
        }

        let passed = checks.iter().all(|check| check.passed);
        ReplayEvaluationReport {
            run_id: run.run_id.clone(),
            scenario_name: run.scenario_name.clone(),
            scenario_path: run.scenario_path.clone(),
            metadata: run.metadata.clone(),
            passed,
            checks,
            deterministic_summary: summary.clone(),
            performance: run.performance.clone(),
        }
    }

    async fn build_experiment_report(
        &self,
        loaded_experiment: &LoadedDetectorExperiment,
    ) -> Result<(StrategyExperimentReport, Vec<String>), ReplayHarnessError> {
        let suite_path = resolve_relative_path(
            &loaded_experiment.path,
            &loaded_experiment.manifest.corpus.suite,
        );
        let loaded_suite = load_suite_manifest(&suite_path)?;
        let scenario_paths = loaded_suite
            .manifest
            .scenarios
            .iter()
            .map(|scenario| resolve_relative_path(&loaded_suite.path, scenario))
            .collect::<Vec<_>>();
        let source_artifacts = scenario_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        let selection = ReplaySuiteSelection {
            source: loaded_suite.path.display().to_string(),
            source_kind: ReplaySuiteSourceKind::SuiteManifest,
            suite_name: Some(loaded_suite.manifest.name.clone()),
            suite_description: Some(loaded_suite.manifest.description.clone()),
            corpus_version: Some(loaded_suite.manifest.corpus_version.clone()),
        };

        let baseline_strategy_id =
            resolve_experiment_baseline_strategy_id(&self.config, loaded_experiment)?;
        let baseline_detector =
            build_detector_from_strategy(&baseline_strategy_id, &self.config.detection)
                .map_err(detector_factory_error)?;
        let baseline_report = self
            .evaluate_suite_selection(
                &baseline_detector,
                scenario_paths.clone(),
                selection.clone(),
            )
            .await?;
        let candidate_detector = detector_from_candidate(&loaded_experiment.manifest.candidate)?;
        let candidate_report = self
            .evaluate_suite_selection(&candidate_detector, scenario_paths, selection)
            .await?;
        let comparison = compare_suite_reports(&baseline_report, &candidate_report);
        let gates = evaluate_experiment_gates(&loaded_experiment.manifest.gates, &comparison);
        let passed = gates.iter().all(|gate| gate.passed);
        let report = StrategyExperimentReport {
            experiment_id: experiment_id_for_manifest(&loaded_experiment.manifest),
            experiment_name: loaded_experiment.manifest.name.clone(),
            description: loaded_experiment.manifest.description.clone(),
            created_at_ms: now_ms(),
            suite_name: loaded_suite.manifest.name.clone(),
            suite_path: loaded_suite.path.display().to_string(),
            corpus_version: loaded_suite.manifest.corpus_version.clone(),
            lineage: loaded_experiment.manifest.lineage.clone(),
            baseline_strategy_id,
            candidate_strategy_id: loaded_experiment
                .manifest
                .candidate
                .strategy_id()
                .to_string(),
            candidate_description: loaded_experiment
                .manifest
                .candidate
                .description()
                .to_string(),
            baseline_report,
            candidate_report,
            comparison,
            gates,
            passed,
        };
        Ok((report, source_artifacts))
    }

    fn persist_experiment_report(
        &self,
        experiments_dir: &Path,
        report: StrategyExperimentReport,
    ) -> Result<StrategyExperimentLookup, ReplayHarnessError> {
        let store = FileExperimentStore::open(experiments_dir)?;
        let record = store.persist(&report)?;
        Ok(StrategyExperimentLookup { record, report })
    }

    fn persist_shadow_report(
        &self,
        shadows_dir: &Path,
        report: StrategyShadowReport,
    ) -> Result<StrategyShadowLookup, ReplayHarnessError> {
        let store = FileShadowStore::open(shadows_dir)?;
        let record = store.persist(&report)?;
        Ok(StrategyShadowLookup { record, report })
    }

    async fn build_verification_report(
        &self,
        loaded_experiment: &LoadedDetectorExperiment,
    ) -> Result<DetectorVerificationReport, ReplayHarnessError> {
        let _baseline_strategy_id =
            resolve_experiment_baseline_strategy_id(&self.config, loaded_experiment)?;
        let verification_path = resolve_relative_path(
            &loaded_experiment.path,
            &loaded_experiment.manifest.verification.corpus,
        );
        let verification_manifest = load_verification_manifest(&verification_path)?;
        let candidate_detector = detector_from_candidate(&loaded_experiment.manifest.candidate)?;

        let known_bad_suite_path =
            resolve_relative_path(&verification_path, &verification_manifest.known_bad.suite);
        let known_bad_suite = load_suite_manifest(&known_bad_suite_path)?;
        let known_bad_paths = known_bad_suite
            .manifest
            .scenarios
            .iter()
            .map(|scenario| resolve_relative_path(&known_bad_suite.path, scenario))
            .collect::<Vec<_>>();
        let known_bad_report = self
            .evaluate_suite_selection(
                &candidate_detector,
                known_bad_paths,
                ReplaySuiteSelection {
                    source: known_bad_suite.path.display().to_string(),
                    source_kind: ReplaySuiteSourceKind::SuiteManifest,
                    suite_name: Some(known_bad_suite.manifest.name.clone()),
                    suite_description: Some(known_bad_suite.manifest.description.clone()),
                    corpus_version: Some(known_bad_suite.manifest.corpus_version.clone()),
                },
            )
            .await?;

        let benign_paths = verification_manifest
            .benign_controls
            .scenarios
            .iter()
            .map(|scenario| resolve_relative_path(&verification_path, scenario))
            .collect::<Vec<_>>();
        let benign_report = self
            .evaluate_suite_selection(
                &candidate_detector,
                benign_paths,
                ReplaySuiteSelection {
                    source: verification_path.display().to_string(),
                    source_kind: ReplaySuiteSourceKind::ScenarioList,
                    suite_name: Some(format!("{} benign controls", verification_manifest.name)),
                    suite_description: Some(
                        "verification-corpus benign control selection".to_string(),
                    ),
                    corpus_version: None,
                },
            )
            .await?;

        // GATING. Every entry here is a deterministic function of fixture
        // content -- counts and rates over the corpus -- so it computes the same
        // value on any machine, under any load, on any architecture. Do not add
        // anything derived from a clock: see `observations` below.
        let invariants = vec![
            verify_known_bad_coverage(&known_bad_report),
            verify_canonical_templates(
                &candidate_detector,
                &verification_manifest.canonical_templates,
            ),
            verify_false_positive_bound(
                &benign_report,
                verification_manifest
                    .resource_budgets
                    .max_false_positive_rate,
            ),
            verify_total_detection_budget(
                &[&known_bad_report, &benign_report],
                verification_manifest.resource_budgets.max_total_detections,
            ),
        ];
        // NON-GATING. Measured and recorded in full; reduced over by nothing.
        let observations = vec![observe_detect_latency(
            &[&known_bad_report, &benign_report],
            verification_manifest.resource_budgets.max_detect_latency_us,
        )];
        let passed = invariants.iter().all(|invariant| invariant.passed);

        Ok(DetectorVerificationReport {
            verification_id: verification_id_for_experiment(
                &loaded_experiment.manifest,
                &verification_manifest,
            ),
            experiment_id: experiment_id_for_manifest(&loaded_experiment.manifest),
            experiment_name: loaded_experiment.manifest.name.clone(),
            corpus_name: verification_manifest.name,
            corpus_path: verification_path.display().to_string(),
            created_at_ms: now_ms(),
            lineage: loaded_experiment.manifest.lineage.clone(),
            candidate_strategy_id: loaded_experiment
                .manifest
                .candidate
                .strategy_id()
                .to_string(),
            candidate_description: loaded_experiment
                .manifest
                .candidate
                .description()
                .to_string(),
            invariants,
            observations,
            passed,
        })
    }

    async fn evaluate_suite_selection(
        &self,
        detector: &RuntimeDetector,
        scenario_paths: Vec<PathBuf>,
        selection: ReplaySuiteSelection,
    ) -> Result<ReplaySuiteReport, ReplayHarnessError> {
        let mut scenario_reports = Vec::with_capacity(scenario_paths.len());
        for scenario_path in scenario_paths {
            let loaded = load_scenario_manifest(&scenario_path)?;
            let bundle = self.run_loaded_scenario(detector, &loaded).await?;
            let evaluation = self.evaluate_run(&bundle);
            scenario_reports.push(ReplaySuiteScenarioReport {
                scenario_name: bundle.scenario_name.clone(),
                scenario_path: bundle.scenario_path.clone(),
                metadata: bundle.metadata.clone(),
                evaluation,
            });
        }

        let passed_scenarios = scenario_reports
            .iter()
            .filter(|report| report.evaluation.passed)
            .count();
        let failed_scenarios = scenario_reports.len().saturating_sub(passed_scenarios);

        Ok(ReplaySuiteReport {
            source: selection.source,
            source_kind: selection.source_kind,
            suite_name: selection.suite_name,
            suite_description: selection.suite_description,
            corpus_version: selection.corpus_version,
            total_scenarios: scenario_reports.len(),
            passed_scenarios,
            failed_scenarios,
            passed: failed_scenarios == 0,
            technique_groups: technique_groups_from_suite(&scenario_reports),
            scenario_reports,
        })
    }

    async fn run_loaded_scenario(
        &self,
        detector: &RuntimeDetector,
        loaded: &LoadedReplayScenario,
    ) -> Result<ReplayRunBundle, ReplayHarnessError> {
        let steps = self.materialize_steps(loaded)?;
        // TEST-ONLY SEAM (compiled out entirely by `#[cfg(test)]`): substitute a
        // delegating detector that can burn wall-clock time inside the detect
        // stage, so the load-differential regression test can drive the real
        // measurement without a hook in the live critical lane. See
        // `replay::detect_stall`. Inert unless a `DetectStallGuard` is armed.
        #[cfg(test)]
        let stalling_detector = super::detect_stall::StallingDetector::new(detector.clone());
        #[cfg(test)]
        let detector = &stalling_detector;
        let service = self.build_service()?;
        let substrate = InMemoryPheromoneSubstrate::new(self.config.pheromone.clone());
        // Deterministic simulation identity, NOT a credential. Replay runs entirely
        // in memory (`InMemoryPheromoneSubstrate`, `MemoryInvestigationBundleStore`)
        // with `live_mode: false`, and comparing two replay runs requires a stable
        // `agent_id`, so this seed is fixed on purpose. Receipts it signs attest to a
        // simulation and must never be treated as authentic operational evidence.
        // Contrast `evolution_mutation_signing_key` in the CLI, which had a fixed seed
        // by mistake and now loads the persisted Kitten identity.
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&REPLAY_SIMULATION_SIGNING_SEED);
        let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());

        let mut replay_bundles = Vec::new();
        for (index, step) in steps.iter().enumerate() {
            let approval = ApprovalContext {
                live_mode: false,
                receipt_chain: loaded.manifest.receipt_chain.clone(),
                correlation_id: None,
                now_ms: loaded.manifest.seed_time_ms + index as i64,
            };
            let execution = EventExecutionContext {
                agent_id: &agent_id,
                approval: &approval,
                signing_key: &signing_key,
            };

            if let Some(bundle) = service
                .process_event(detector, &substrate, &step.event, execution, |_| {
                    Some(step.action.clone())
                })
                .await?
            {
                replay_bundles.push(bundle);
            }
        }

        let investigation_store = MemoryInvestigationBundleStore::default();
        let investigations = self
            .run_inline_investigations(
                &investigation_store,
                &replay_bundles,
                loaded.manifest.seed_time_ms + 10_000,
            )
            .await?;
        let incidents = self
            .run_inline_correlation(&investigation_store, loaded.manifest.seed_time_ms + 20_000)?;
        let deterministic_summary =
            ReplayDeterministicSummary::from_outputs(&replay_bundles, &investigations, &incidents);

        Ok(ReplayRunBundle {
            run_id: run_id_for_manifest(&loaded.manifest),
            scenario_name: loaded.manifest.name.clone(),
            scenario_path: loaded.path.display().to_string(),
            description: loaded.manifest.description.clone(),
            metadata: loaded.manifest.metadata.clone(),
            input_kind: loaded.manifest.input.kind(),
            seed_time_ms: loaded.manifest.seed_time_ms,
            created_at_ms: loaded.manifest.seed_time_ms,
            requested_by: loaded.manifest.requested_by.clone(),
            expectations: loaded.manifest.expectations.clone(),
            replay_bundles,
            investigations,
            incidents,
            deterministic_summary,
            performance: service.metrics_snapshot(),
        })
    }

    fn build_service(
        &self,
    ) -> Result<RuntimeService<ConfigurableApprovalGate, SandboxExecutor>, ReplayHarnessError> {
        let mut offline_config = self.config.clone();
        offline_config.runtime.mode = RuntimeMode::DetectOnly;
        offline_config.runtime.require_durable_live_response = false;
        let runtime = SwarmRuntime::new(
            RuntimeMode::DetectOnly,
            ConfigurableApprovalGate::from_config(&offline_config.policy),
            SandboxExecutor,
        );
        Ok(RuntimeService::new(offline_config, runtime).with_configured_sequence_detector()?)
    }

    fn materialize_steps(
        &self,
        loaded: &LoadedReplayScenario,
    ) -> Result<Vec<ReplayScenarioStep>, ReplayHarnessError> {
        match &loaded.manifest.input {
            ReplayScenarioInput::Events { events } => Ok(events.clone()),
            ReplayScenarioInput::ReplayBundles { paths } => {
                let mut steps = Vec::with_capacity(paths.len());
                for path in paths {
                    let resolved = resolve_relative_path(&loaded.path, path);
                    let raw = fs::read_to_string(&resolved).map_err(|source| {
                        ReplayHarnessError::BundleRead {
                            path: resolved.clone(),
                            source,
                        }
                    })?;
                    let bundle: ReplayBundle = serde_json::from_str(&raw).map_err(|source| {
                        ReplayHarnessError::BundleParse {
                            path: resolved.clone(),
                            source,
                        }
                    })?;
                    steps.push(ReplayScenarioStep {
                        action: bundle.action_request.action,
                        event: bundle.event,
                    });
                }
                Ok(steps)
            }
        }
    }

    async fn run_inline_investigations(
        &self,
        store: &MemoryInvestigationBundleStore,
        replay_bundles: &[ReplayBundle],
        base_time_ms: i64,
    ) -> Result<Vec<InvestigationBundle>, ReplayHarnessError> {
        let investigator = SummaryInvestigator;
        let mut investigations = Vec::with_capacity(replay_bundles.len());

        for (index, replay) in replay_bundles.iter().enumerate() {
            let queued_at_ms = base_time_ms + index as i64 * 10;
            let started_at_ms = queued_at_ms + 1;
            let completed_at_ms = queued_at_ms + 2;
            let investigation_id =
                format!("investigation:{}:{}", replay.audit.hunt_id, queued_at_ms);
            let queued = InvestigationBundle::queued_from_bundle(
                replay,
                investigation_id,
                queued_at_ms,
                compute_priority(replay, queued_at_ms),
            );
            let running =
                queued.with_status(InvestigationStatus::Running, Some(started_at_ms), None);
            let terminal = match investigator.investigate(replay).await {
                Ok(outcome) => {
                    let mut completed = running.with_summary(
                        outcome.summary,
                        outcome.evidence_points,
                        outcome.correlation_keys,
                        outcome.candidate_interpretations.clone(),
                        outcome.vote_lineage.clone(),
                        decide_outcome(
                            &outcome.candidate_interpretations,
                            &outcome.vote_lineage,
                            swarm_core::config::InvestigationConfig::default()
                                .ambiguity_margin_basis_points,
                        ),
                        completed_at_ms,
                    );
                    completed.started_at_ms = Some(started_at_ms);
                    completed
                }
                Err(reason) => {
                    let mut failed =
                        running.with_failure(InvestigationStatus::Failed, reason, completed_at_ms);
                    failed.started_at_ms = Some(started_at_ms);
                    failed
                }
            };
            store.persist(&terminal)?;
            investigations.push(terminal);
        }

        Ok(investigations)
    }

    fn run_inline_correlation(
        &self,
        investigation_store: &MemoryInvestigationBundleStore,
        base_time_ms: i64,
    ) -> Result<Vec<CorrelatedIncident>, ReplayHarnessError> {
        let engine = CorrelationEngine::new(offline_correlation_config(&self.config));
        let incident_store = MemoryIncidentStore::default();
        let investigations = investigation_store.recent(usize::MAX)?;
        let mut ordered_hunts = investigations
            .iter()
            .map(|record| record.hunt_id.clone())
            .collect::<Vec<_>>();
        ordered_hunts.sort();
        ordered_hunts.dedup();

        let mut covered_hunts = Vec::<String>::new();
        let mut incidents = Vec::new();
        for (index, hunt_id) in ordered_hunts.into_iter().enumerate() {
            if covered_hunts.iter().any(|existing| existing == &hunt_id) {
                continue;
            }
            let maybe_outcome = engine.correlate_hunt_at(
                investigation_store,
                &incident_store,
                &hunt_id,
                base_time_ms + index as i64,
            )?;
            if let Some(CorrelationOutcome { incident, .. }) = maybe_outcome {
                for included_hunt_id in incident.included_hunt_ids() {
                    if !covered_hunts
                        .iter()
                        .any(|existing| existing == &included_hunt_id)
                    {
                        covered_hunts.push(included_hunt_id);
                    }
                }
                incidents.push(incident);
            }
        }
        incidents.sort_by(|left, right| left.incident_id.cmp(&right.incident_id));
        Ok(incidents)
    }
}

pub(super) fn replay_detector(config: &SwarmConfig) -> Result<RuntimeDetector, ReplayHarnessError> {
    build_detector_from_strategy(&config.detection.strategy, &config.detection)
        .map_err(detector_factory_error)
}

pub(super) fn detector_from_candidate(
    candidate: &DetectorCandidateManifest,
) -> Result<RuntimeDetector, ReplayHarnessError> {
    build_detector_from_candidate(candidate).map_err(detector_factory_error)
}

fn resolve_experiment_baseline_strategy_id(
    config: &SwarmConfig,
    loaded_experiment: &LoadedDetectorExperiment,
) -> Result<String, ReplayHarnessError> {
    let baseline_strategy_id = config
        .detection
        .resolve_rollout_strategy_id(
            "canary.strategy_id",
            config.canary.strategy_id.as_deref(),
            true,
        )
        .map_err(|source| ReplayHarnessError::ExperimentValidation {
            path: loaded_experiment.path.clone(),
            reason: source.to_string(),
        })?;
    if loaded_experiment.manifest.lineage.parent_strategy_id != baseline_strategy_id {
        return Err(ReplayHarnessError::ExperimentValidation {
            path: loaded_experiment.path.clone(),
            reason: format!(
                "lineage.parent_strategy_id `{}` must match resolved rollout baseline `{}`",
                loaded_experiment.manifest.lineage.parent_strategy_id, baseline_strategy_id
            ),
        });
    }
    Ok(baseline_strategy_id)
}

fn detector_factory_error(error: DetectorFactoryError) -> ReplayHarnessError {
    match error {
        DetectorFactoryError::DetectorProfile(source) => {
            ReplayHarnessError::DetectorProfile(source)
        }
        DetectorFactoryError::UnsupportedDetector { strategy } => {
            ReplayHarnessError::UnsupportedDetector { strategy }
        }
    }
}

fn offline_correlation_config(config: &SwarmConfig) -> CorrelationConfig {
    let mut correlation = config.correlation.clone();
    correlation.enabled = true;
    if correlation.time_window_ms <= 0 {
        correlation.time_window_ms = 300_000;
    }
    if correlation.min_shared_keys == 0 {
        correlation.min_shared_keys = 1;
    }
    if correlation.candidate_limit == 0 {
        correlation.candidate_limit = 32;
    }
    correlation
}

#[derive(Debug, Clone)]
struct ReplaySuiteSelection {
    source: String,
    source_kind: ReplaySuiteSourceKind,
    suite_name: Option<String>,
    suite_description: Option<String>,
    corpus_version: Option<String>,
}
