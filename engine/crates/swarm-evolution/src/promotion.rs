use crate::canary::{
    CanaryRecommendation, CanaryRunReport, CanaryRunStatus, CanaryStoreError, FileCanaryStore,
};
use crate::config::{DetectorProfileError, RuntimeConfigError, load_config};
use crate::detector_factory::{
    DetectorFactoryError, build_candidate_manifest_from_strategy, build_detector_from_candidate,
};
use crate::evolution::{
    EvolutionProposalAssuranceSummary, assurance_gate_block_reason, render_assurance_summary_lines,
};
use crate::replay::{DetectorCandidateManifest, ExperimentLineage};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use swarm_core::config::{ConfigValidationError, PromotionConfig, SwarmConfig};
use swarm_core::types::Severity;
use swarm_crypto::{
    DetachedSignature, PublicKey, Signature, canonical_json_bytes, verify_detached_signature,
};
use swarm_whisker::stream::{evaluate_event, findings_to_deposits};
use swarm_whisker::{DetectionFinding, TelemetryEvent};

/// Errors surfaced by the controlled production-promotion lane.
#[derive(Debug, thiserror::Error)]
pub enum ProductionPromotionError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    CanaryStore(#[from] CanaryStoreError),

    #[error(transparent)]
    ConfigValidation(#[from] ConfigValidationError),

    #[error(transparent)]
    DetectorProfile(#[from] DetectorProfileError),

    #[error(transparent)]
    ProfileValidation(#[from] swarm_whisker::ProfileValidationError),

    #[error(transparent)]
    Store(#[from] ProductionPromotionStoreError),

    #[error("failed to read telemetry event `{path}`: {source}")]
    EventRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse telemetry event `{path}`: {source}")]
    EventParse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("controlled production promotion is disabled in the repo-owned config")]
    Disabled,

    #[error("canary run `{run_id}` was not found")]
    CanaryNotFound { run_id: String },

    #[error(
        "canary run `{run_id}` is not ready for production promotion (status `{status:?}`, recommendation `{recommendation:?}`)"
    )]
    CanaryNotReady {
        run_id: String,
        status: CanaryRunStatus,
        recommendation: CanaryRecommendation,
    },

    #[error("canary run `{run_id}` does not carry satisfied assurance lineage: {reason}")]
    AssuranceNotSatisfied { run_id: String, reason: String },

    #[error("canary baseline mismatch: expected current production `{expected}`, found `{actual}`")]
    BaselineMismatch { expected: String, actual: String },

    #[error("promotion baseline `{strategy_id}` is not active in detection.active_strategies()")]
    InactiveBaselineScope { strategy_id: String },

    #[error(
        "an active production promotion already exists for window `{window_id}`: `{promotion_id}`"
    )]
    ActiveRunExists {
        window_id: String,
        promotion_id: String,
    },

    #[error("production promotion `{promotion_id}` was not found")]
    RunNotFound { promotion_id: String },

    #[error("production promotion `{promotion_id}` is not active (status `{status:?}`)")]
    RunNotActive {
        promotion_id: String,
        status: ProductionPromotionStatus,
    },

    #[error(
        "production promotion `{promotion_id}` is not pending human approval (status `{status:?}`)"
    )]
    RunNotPending {
        promotion_id: String,
        status: ProductionPromotionStatus,
    },

    #[error("quorum not met: {have} of {need} votes, missing voters: {missing}")]
    QuorumNotMet {
        have: usize,
        need: usize,
        missing: String,
    },

    #[error("vote signature verification failed for voter `{voter_id}`")]
    VoteSignatureInvalid { voter_id: String },

    #[error("consensus receipt signature verification failed for receipt `{receipt_id}`")]
    ReceiptSignatureInvalid { receipt_id: String },

    #[error("unsupported detector strategy `{strategy}`")]
    UnsupportedDetector { strategy: String },
}

/// Errors raised by the persisted production-promotion store.
#[derive(Debug, thiserror::Error)]
pub enum ProductionPromotionStoreError {
    #[error("failed to read production promotion store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write production promotion store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse production promotion store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Runtime status for one production-promotion run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionPromotionStatus {
    Active,
    HumanApprovalPending,
    Completed,
    RolledBack,
    Halted,
}

/// Final operator recommendation for one production-promotion run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionPromotionRecommendation {
    Observing,
    PendingHumanApproval,
    StableInProduction,
    Blocked,
}

/// Automatic or manual source of one production rollback-like action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionPromotionRollbackTrigger {
    AutomaticThreshold,
    AutomaticBudget,
    ManualHalt,
    ManualRollback,
}

/// One persisted rollback or halt event for a production promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionPromotionRollbackRecord {
    pub trigger: ProductionPromotionRollbackTrigger,
    pub reason: String,
    pub occurred_at_ms: i64,
    pub window_id: String,
    pub restored_baseline_strategy_id: String,
    pub observed_events: usize,
}

/// One threshold verdict preserved in the production-promotion artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductionPromotionThresholdResult {
    pub name: String,
    pub passed: bool,
    pub expected: serde_json::Value,
    pub actual: serde_json::Value,
    pub details: String,
}

/// One recent promoted finding preserved for operator inspection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductionPromotionFindingPreview {
    pub event_id: String,
    pub strategy_id: String,
    pub severity: Severity,
    pub confidence: f64,
    pub shared_with_fallback: bool,
}

/// Reference to a signed approval vote for one promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionApprovalVoteRef {
    pub voter_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
    pub approved_at_ms: i64,
    pub ledger_entry_id: String,
}

/// Durable consensus receipt linking a promotion to its approval verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionConsensusReceipt {
    pub receipt_id: String,
    pub approval_set_id: String,
    pub verdict_id: String,
    pub ledger_id: String,
    pub threshold_met: bool,
    pub vote_count: usize,
    pub threshold_required: usize,
    pub receipt_signature_hex: String,
    pub receipt_signer_key_id: String,
    pub receipt_signer_public_key_hex: String,
    pub created_at_ms: i64,
}

/// Review packet persisted when a promotion enters human-approval-pending state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionPendingReviewPacket {
    pub gate_reason: String,
    pub severity: Severity,
    pub canary_run_id: String,
    pub promoted_strategy_id: String,
    pub canary_recommendation: CanaryRecommendation,
    pub pending_since_ms: i64,
}

/// Structural quorum-gate configuration for the promotion path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionQuorumGateConfig {
    pub required_threshold: Option<usize>,
    pub required_voter_ids: Vec<String>,
}

/// Aggregate metrics recorded over the production observation window.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProductionPromotionMetrics {
    pub total_events: usize,
    pub fallback_detections: usize,
    pub promoted_detections: usize,
    pub shared_detections: usize,
    pub promoted_only_detections: usize,
    pub fallback_only_detections: usize,
    pub promoted_only_rate: f64,
    pub fallback_recovery_rate: f64,
    pub total_fallback_detect_latency_us: u64,
    pub average_fallback_detect_latency_us: u64,
    pub max_fallback_detect_latency_us: u64,
    pub total_promoted_detect_latency_us: u64,
    pub average_promoted_detect_latency_us: u64,
    pub max_promoted_detect_latency_us: u64,
    pub total_promoted_deposits: usize,
}

impl ProductionPromotionMetrics {
    fn observe(
        &mut self,
        fallback_findings: &[DetectionFinding],
        promoted_findings: &[DetectionFinding],
        fallback_latency_us: u64,
        promoted_latency_us: u64,
        promoted_deposit_count: usize,
    ) {
        self.total_events = self.total_events.saturating_add(1);
        self.total_fallback_detect_latency_us = self
            .total_fallback_detect_latency_us
            .saturating_add(fallback_latency_us);
        self.total_promoted_detect_latency_us = self
            .total_promoted_detect_latency_us
            .saturating_add(promoted_latency_us);
        self.max_fallback_detect_latency_us =
            self.max_fallback_detect_latency_us.max(fallback_latency_us);
        self.max_promoted_detect_latency_us =
            self.max_promoted_detect_latency_us.max(promoted_latency_us);
        self.average_fallback_detect_latency_us =
            self.total_fallback_detect_latency_us / self.total_events as u64;
        self.average_promoted_detect_latency_us =
            self.total_promoted_detect_latency_us / self.total_events as u64;
        self.total_promoted_deposits = self
            .total_promoted_deposits
            .saturating_add(promoted_deposit_count);

        let fallback_detected = !fallback_findings.is_empty();
        let promoted_detected = !promoted_findings.is_empty();
        if fallback_detected {
            self.fallback_detections = self.fallback_detections.saturating_add(1);
        }
        if promoted_detected {
            self.promoted_detections = self.promoted_detections.saturating_add(1);
        }
        if fallback_detected && promoted_detected {
            self.shared_detections = self.shared_detections.saturating_add(1);
        } else if promoted_detected {
            self.promoted_only_detections = self.promoted_only_detections.saturating_add(1);
        } else if fallback_detected {
            self.fallback_only_detections = self.fallback_only_detections.saturating_add(1);
        }

        self.promoted_only_rate = if self.total_events == 0 {
            0.0
        } else {
            self.promoted_only_detections as f64 / self.total_events as f64
        };
        self.fallback_recovery_rate = if self.fallback_detections == 0 {
            0.0
        } else {
            self.fallback_only_detections as f64 / self.fallback_detections as f64
        };
    }
}

/// Stable assignment details for one production-promotion run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionPromotionAssignment {
    pub canary_run_id: String,
    pub canary_report: CanaryRunReport,
    pub experiment_id: String,
    pub experiment_name: String,
    pub suite_name: String,
    pub corpus_version: String,
    pub previous_production_strategy_id: String,
    pub promoted_strategy_id: String,
    pub promoted_description: String,
    pub previous_production_candidate: DetectorCandidateManifest,
    pub promoted_candidate: DetectorCandidateManifest,
    pub lineage: ExperimentLineage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance: Option<EvolutionProposalAssuranceSummary>,
    pub promotion: PromotionConfig,
}

/// Persisted production-promotion artifact exposed to operators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionPromotionReport {
    pub promotion_id: String,
    pub window_id: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub status: ProductionPromotionStatus,
    pub recommendation: ProductionPromotionRecommendation,
    pub assignment: ProductionPromotionAssignment,
    pub metrics: ProductionPromotionMetrics,
    pub threshold_results: Vec<ProductionPromotionThresholdResult>,
    pub recent_promoted_findings: Vec<ProductionPromotionFindingPreview>,
    pub rollback_history: Vec<ProductionPromotionRollbackRecord>,
    pub pending_review: Option<PromotionPendingReviewPacket>,
    pub approval_votes: Vec<PromotionApprovalVoteRef>,
    pub consensus_receipt: Option<PromotionConsensusReceipt>,
    pub approval_severity: Option<Severity>,
    pub quorum_gate_config: Option<PromotionQuorumGateConfig>,
}

/// Metadata surfaced for one persisted production-promotion run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionPromotionRecord {
    pub promotion_id: String,
    pub window_id: String,
    pub canary_run_id: String,
    pub promoted_strategy_id: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub status: ProductionPromotionStatus,
    pub recommendation: ProductionPromotionRecommendation,
    pub bundle_path: String,
}

impl ProductionPromotionRecord {
    fn from_report(report: &ProductionPromotionReport, bundle_path: String) -> Self {
        Self {
            promotion_id: report.promotion_id.clone(),
            window_id: report.window_id.clone(),
            canary_run_id: report.assignment.canary_run_id.clone(),
            promoted_strategy_id: report.assignment.promoted_strategy_id.clone(),
            created_at_ms: report.created_at_ms,
            updated_at_ms: report.updated_at_ms,
            status: report.status,
            recommendation: report.recommendation,
            bundle_path,
        }
    }
}

/// Persisted production promotion loaded with metadata.
#[derive(Debug, Clone)]
pub struct ProductionPromotionLookup {
    pub record: ProductionPromotionRecord,
    pub report: ProductionPromotionReport,
}

/// Operator-facing production promotion listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionPromotionList {
    pub total_count: usize,
    pub promotions: Vec<ProductionPromotionRecord>,
}

/// File-backed store used for controlled production-promotion runs.
#[derive(Debug, Clone)]
pub struct FileProductionPromotionStore {
    root: PathBuf,
}

impl FileProductionPromotionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ProductionPromotionStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ProductionPromotionStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, promotion_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(promotion_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ProductionPromotionIndex, ProductionPromotionStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ProductionPromotionIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| ProductionPromotionStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| ProductionPromotionStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &ProductionPromotionIndex,
    ) -> Result<(), ProductionPromotionStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            ProductionPromotionStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| ProductionPromotionStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &ProductionPromotionReport,
    ) -> Result<ProductionPromotionRecord, ProductionPromotionStoreError> {
        let path = self.report_path(&report.promotion_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            ProductionPromotionStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| ProductionPromotionStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = ProductionPromotionRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.promotion_id != record.promotion_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.updated_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        promotion_id: &str,
    ) -> Result<Option<ProductionPromotionLookup>, ProductionPromotionStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.promotion_id == promotion_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| ProductionPromotionStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let report =
            serde_json::from_str(&raw).map_err(|source| ProductionPromotionStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Some(ProductionPromotionLookup { record, report }))
    }

    pub fn load_active(
        &self,
        window_id: &str,
    ) -> Result<Option<ProductionPromotionLookup>, ProductionPromotionStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| {
                entry.window_id == window_id
                    && matches!(
                        entry.status,
                        ProductionPromotionStatus::Active
                            | ProductionPromotionStatus::HumanApprovalPending
                    )
            })
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| ProductionPromotionStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let report =
            serde_json::from_str(&raw).map_err(|source| ProductionPromotionStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Some(ProductionPromotionLookup { record, report }))
    }

    pub fn list(
        &self,
        status: Option<ProductionPromotionStatus>,
    ) -> Result<ProductionPromotionList, ProductionPromotionStoreError> {
        let mut index = self.read_index()?;
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.updated_at_ms));
        let promotions = index
            .entries
            .into_iter()
            .filter(|entry| status.is_none_or(|value| entry.status == value))
            .collect::<Vec<_>>();
        Ok(ProductionPromotionList {
            total_count: promotions.len(),
            promotions,
        })
    }
}

/// Runtime-side production-promotion harness built from repo-owned config.
pub struct DefaultProductionPromotionHarness {
    pub config_path: PathBuf,
    pub config: SwarmConfig,
    pub store: FileProductionPromotionStore,
}

impl DefaultProductionPromotionHarness {
    pub fn from_path(
        config_path: impl AsRef<Path>,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, ProductionPromotionError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config(config_path, config, results_dir)
    }

    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        results_dir: impl AsRef<Path>,
    ) -> Result<Self, ProductionPromotionError> {
        let store = FileProductionPromotionStore::open(results_dir)?;
        Ok(Self {
            config_path: config_path.into(),
            config,
            store,
        })
    }

    pub fn start_run(
        &self,
        canary_results_dir: impl AsRef<Path>,
        canary_run_id: &str,
    ) -> Result<ProductionPromotionLookup, ProductionPromotionError> {
        self.start_run_with_severity(canary_results_dir, canary_run_id, None)
    }

    pub fn start_run_with_severity(
        &self,
        canary_results_dir: impl AsRef<Path>,
        canary_run_id: &str,
        severity_override: Option<Severity>,
    ) -> Result<ProductionPromotionLookup, ProductionPromotionError> {
        if !self.config.promotion.enabled {
            return Err(ProductionPromotionError::Disabled);
        }

        if let Some(active) = self.store.load_active(&self.config.promotion.window_id)? {
            return Err(ProductionPromotionError::ActiveRunExists {
                window_id: self.config.promotion.window_id.clone(),
                promotion_id: active.record.promotion_id,
            });
        }

        let canary_store = FileCanaryStore::open(canary_results_dir)?;
        let canary = canary_store.load(canary_run_id)?.ok_or_else(|| {
            ProductionPromotionError::CanaryNotFound {
                run_id: canary_run_id.to_string(),
            }
        })?;
        if canary.report.status != CanaryRunStatus::Completed
            || canary.report.recommendation != CanaryRecommendation::ReadyForPromotionReview
        {
            return Err(ProductionPromotionError::CanaryNotReady {
                run_id: canary_run_id.to_string(),
                status: canary.report.status,
                recommendation: canary.report.recommendation,
            });
        }
        if let Some(reason) = promotion_assurance_block_reason(
            &self.config,
            canary.report.assignment.assurance.as_ref(),
        ) {
            return Err(ProductionPromotionError::AssuranceNotSatisfied {
                run_id: canary_run_id.to_string(),
                reason,
            });
        }

        let now_ms = now_ms();
        let previous_production_strategy_id =
            resolve_promotion_rollout_strategy_id(&self.config, &canary.report)?;
        let previous_production_candidate =
            baseline_candidate_from_config(&self.config, &previous_production_strategy_id)?;
        let assignment = ProductionPromotionAssignment {
            canary_run_id: canary.report.run_id.clone(),
            canary_report: canary.report.clone(),
            experiment_id: canary.report.assignment.experiment_id.clone(),
            experiment_name: canary.report.assignment.experiment_name.clone(),
            suite_name: canary.report.assignment.suite_name.clone(),
            corpus_version: canary.report.assignment.corpus_version.clone(),
            previous_production_strategy_id,
            promoted_strategy_id: canary.report.assignment.candidate_strategy_id.clone(),
            promoted_description: canary.report.assignment.candidate_description.clone(),
            previous_production_candidate,
            promoted_candidate: canary.report.assignment.candidate.clone(),
            lineage: canary.report.assignment.lineage.clone(),
            assurance: canary.report.assignment.assurance.clone(),
            promotion: self.config.promotion.clone(),
        };
        let promotion_id =
            production_promotion_id(&self.config.promotion.window_id, &assignment, now_ms);
        let threshold_results = evaluate_thresholds(
            &ProductionPromotionMetrics::default(),
            &assignment.promotion,
        );
        let approval_severity =
            severity_override.unwrap_or_else(|| promotion_severity(&canary.report));
        let gated = approval_severity == Severity::Critical;
        let report = ProductionPromotionReport {
            promotion_id,
            window_id: self.config.promotion.window_id.clone(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            status: if gated {
                ProductionPromotionStatus::HumanApprovalPending
            } else {
                ProductionPromotionStatus::Active
            },
            recommendation: if gated {
                ProductionPromotionRecommendation::PendingHumanApproval
            } else {
                ProductionPromotionRecommendation::Observing
            },
            assignment,
            metrics: ProductionPromotionMetrics::default(),
            threshold_results,
            recent_promoted_findings: Vec::new(),
            rollback_history: Vec::new(),
            pending_review: gated.then(|| PromotionPendingReviewPacket {
                gate_reason: format!(
                    "promotion requires human approval because severity is {:?}",
                    approval_severity
                ),
                severity: approval_severity,
                canary_run_id: canary.report.run_id.clone(),
                promoted_strategy_id: canary.report.assignment.candidate_strategy_id.clone(),
                canary_recommendation: canary.report.recommendation,
                pending_since_ms: now_ms,
            }),
            approval_votes: Vec::new(),
            consensus_receipt: None,
            approval_severity: Some(approval_severity),
            quorum_gate_config: Some(self.quorum_config()),
        };
        let record = self.store.persist(&report)?;
        Ok(ProductionPromotionLookup { record, report })
    }

    pub fn ingest_event_path(
        &self,
        promotion_id: &str,
        event_path: impl AsRef<Path>,
    ) -> Result<ProductionPromotionLookup, ProductionPromotionError> {
        let event_path = event_path.as_ref().to_path_buf();
        let raw = fs::read_to_string(&event_path).map_err(|source| {
            ProductionPromotionError::EventRead {
                path: event_path.clone(),
                source,
            }
        })?;
        let event = serde_yaml::from_str::<TelemetryEvent>(&raw).map_err(|source| {
            ProductionPromotionError::EventParse {
                path: event_path.clone(),
                source,
            }
        })?;
        self.ingest_event(promotion_id, &event)
    }

    pub fn ingest_event(
        &self,
        promotion_id: &str,
        event: &TelemetryEvent,
    ) -> Result<ProductionPromotionLookup, ProductionPromotionError> {
        let mut lookup = self.store.load(promotion_id)?.ok_or_else(|| {
            ProductionPromotionError::RunNotFound {
                promotion_id: promotion_id.to_string(),
            }
        })?;
        if lookup.report.status != ProductionPromotionStatus::Active {
            return Err(ProductionPromotionError::RunNotActive {
                promotion_id: promotion_id.to_string(),
                status: lookup.report.status,
            });
        }

        let fallback =
            detector_from_candidate(&lookup.report.assignment.previous_production_candidate)?;
        let promoted = detector_from_candidate(&lookup.report.assignment.promoted_candidate)?;

        let fallback_started = Instant::now();
        let fallback_findings = evaluate_event(&fallback, event);
        let fallback_latency_us = fallback_started.elapsed().as_micros() as u64;

        let promoted_started = Instant::now();
        let promoted_findings = evaluate_event(&promoted, event);
        let promoted_latency_us = promoted_started.elapsed().as_micros() as u64;

        let promoted_deposits = findings_to_deposits(
            &promoted_findings,
            event,
            &swarm_core::types::AgentId(format!("production:{}", lookup.report.window_id)),
            &self.config.pheromone,
        );

        lookup.report.metrics.observe(
            &fallback_findings,
            &promoted_findings,
            fallback_latency_us,
            promoted_latency_us,
            promoted_deposits.len(),
        );
        append_recent_promoted_findings(
            &mut lookup.report.recent_promoted_findings,
            &promoted_findings,
            !fallback_findings.is_empty(),
        );

        lookup.report.threshold_results =
            evaluate_thresholds(&lookup.report.metrics, &lookup.report.assignment.promotion);
        lookup.report.updated_at_ms = now_ms();

        if let Some(failure) = lookup
            .report
            .threshold_results
            .iter()
            .find(|result| !result.passed)
        {
            let trigger = rollback_trigger_for_threshold(&failure.name);
            lookup.report.status = ProductionPromotionStatus::RolledBack;
            lookup.report.recommendation = ProductionPromotionRecommendation::Blocked;
            lookup
                .report
                .rollback_history
                .push(ProductionPromotionRollbackRecord {
                    trigger,
                    reason: failure.details.clone(),
                    occurred_at_ms: lookup.report.updated_at_ms,
                    window_id: lookup.report.window_id.clone(),
                    restored_baseline_strategy_id: lookup
                        .report
                        .assignment
                        .previous_production_strategy_id
                        .clone(),
                    observed_events: lookup.report.metrics.total_events,
                });
        } else if lookup.report.metrics.total_events
            >= lookup.report.assignment.promotion.observation_window_events
        {
            lookup.report.status = ProductionPromotionStatus::Completed;
            lookup.report.recommendation = ProductionPromotionRecommendation::StableInProduction;
        } else {
            lookup.report.status = ProductionPromotionStatus::Active;
            lookup.report.recommendation = ProductionPromotionRecommendation::Observing;
        }

        lookup.record = self.store.persist(&lookup.report)?;
        Ok(lookup)
    }

    pub fn halt_run(
        &self,
        promotion_id: &str,
        reason: &str,
    ) -> Result<ProductionPromotionLookup, ProductionPromotionError> {
        self.finalize_run(
            promotion_id,
            reason,
            ProductionPromotionStatus::Halted,
            ProductionPromotionRollbackTrigger::ManualHalt,
        )
    }

    pub fn rollback_run(
        &self,
        promotion_id: &str,
        reason: &str,
    ) -> Result<ProductionPromotionLookup, ProductionPromotionError> {
        self.finalize_run(
            promotion_id,
            reason,
            ProductionPromotionStatus::RolledBack,
            ProductionPromotionRollbackTrigger::ManualRollback,
        )
    }

    pub fn load_run(
        &self,
        promotion_id: &str,
    ) -> Result<Option<ProductionPromotionLookup>, ProductionPromotionError> {
        Ok(self.store.load(promotion_id)?)
    }

    pub fn list_runs(
        &self,
        status: Option<ProductionPromotionStatus>,
    ) -> Result<ProductionPromotionList, ProductionPromotionError> {
        Ok(self.store.list(status)?)
    }

    pub fn approve_pending_run(
        &self,
        promotion_id: &str,
        votes: Vec<PromotionApprovalVoteRef>,
        consensus_receipt: Option<PromotionConsensusReceipt>,
        _reason: &str,
    ) -> Result<ProductionPromotionLookup, ProductionPromotionError> {
        let mut lookup = self.store.load(promotion_id)?.ok_or_else(|| {
            ProductionPromotionError::RunNotFound {
                promotion_id: promotion_id.to_string(),
            }
        })?;
        if lookup.report.status != ProductionPromotionStatus::HumanApprovalPending {
            return Err(ProductionPromotionError::RunNotPending {
                promotion_id: promotion_id.to_string(),
                status: lookup.report.status,
            });
        }

        let quorum_config = lookup
            .report
            .quorum_gate_config
            .clone()
            .unwrap_or_else(|| self.quorum_config());
        validate_quorum_gate(&votes, &quorum_config)?;
        for vote in &votes {
            if !verify_vote_signature(vote, promotion_id) {
                return Err(ProductionPromotionError::VoteSignatureInvalid {
                    voter_id: vote.voter_id.clone(),
                });
            }
        }
        if let Some(receipt) = &consensus_receipt
            && !verify_consensus_receipt_signature(receipt)
        {
            return Err(ProductionPromotionError::ReceiptSignatureInvalid {
                receipt_id: receipt.receipt_id.clone(),
            });
        }

        lookup.report.status = ProductionPromotionStatus::Active;
        lookup.report.recommendation = ProductionPromotionRecommendation::Observing;
        lookup.report.updated_at_ms = now_ms();
        lookup.report.pending_review = None;
        lookup.report.approval_votes = votes;
        lookup.report.consensus_receipt = consensus_receipt;
        lookup.report.quorum_gate_config = Some(quorum_config);
        lookup.record = self.store.persist(&lookup.report)?;
        Ok(lookup)
    }

    fn finalize_run(
        &self,
        promotion_id: &str,
        reason: &str,
        status: ProductionPromotionStatus,
        trigger: ProductionPromotionRollbackTrigger,
    ) -> Result<ProductionPromotionLookup, ProductionPromotionError> {
        let mut lookup = self.store.load(promotion_id)?.ok_or_else(|| {
            ProductionPromotionError::RunNotFound {
                promotion_id: promotion_id.to_string(),
            }
        })?;
        if !matches!(
            lookup.report.status,
            ProductionPromotionStatus::Active | ProductionPromotionStatus::HumanApprovalPending
        ) {
            return Err(ProductionPromotionError::RunNotActive {
                promotion_id: promotion_id.to_string(),
                status: lookup.report.status,
            });
        }

        lookup.report.status = status;
        lookup.report.recommendation = ProductionPromotionRecommendation::Blocked;
        lookup.report.updated_at_ms = now_ms();
        lookup
            .report
            .rollback_history
            .push(ProductionPromotionRollbackRecord {
                trigger,
                reason: reason.to_string(),
                occurred_at_ms: lookup.report.updated_at_ms,
                window_id: lookup.report.window_id.clone(),
                restored_baseline_strategy_id: lookup
                    .report
                    .assignment
                    .previous_production_strategy_id
                    .clone(),
                observed_events: lookup.report.metrics.total_events,
            });
        lookup.record = self.store.persist(&lookup.report)?;
        Ok(lookup)
    }

    fn quorum_config(&self) -> PromotionQuorumGateConfig {
        PromotionQuorumGateConfig::default()
    }
}

fn promotion_assurance_block_reason(
    config: &SwarmConfig,
    assurance: Option<&EvolutionProposalAssuranceSummary>,
) -> Option<String> {
    assurance_gate_block_reason(assurance, config, now_ms(), "promotion entry")
}

pub fn render_production_promotion_report(report: &ProductionPromotionReport) -> String {
    let mut lines = vec![
        "Production Promotion Run".to_string(),
        format!("Promotion ID: {}", report.promotion_id),
        format!("Window: {}", report.window_id),
        format!("Status: {:?}", report.status),
        format!("Recommendation: {:?}", report.recommendation),
        format!("Approval Severity: {:?}", report.approval_severity),
        format!(
            "Rollback target: {} | Promoted: {}",
            report.assignment.previous_production_strategy_id,
            report.assignment.promoted_strategy_id
        ),
        format!(
            "Canary handoff: {} | status={:?} | recommendation={:?}",
            report.assignment.canary_run_id,
            report.assignment.canary_report.status,
            report.assignment.canary_report.recommendation
        ),
        format!(
            "Observed events: {} / {}",
            report.metrics.total_events, report.assignment.promotion.observation_window_events
        ),
        format!(
            "Detections: fallback={} promoted={} shared={}",
            report.metrics.fallback_detections,
            report.metrics.promoted_detections,
            report.metrics.shared_detections
        ),
        format!(
            "Divergence: promoted_only={} rate={:.2}",
            report.metrics.promoted_only_detections, report.metrics.promoted_only_rate
        ),
        format!(
            "Fallback recovery: {} rate={:.2}",
            report.metrics.fallback_only_detections, report.metrics.fallback_recovery_rate
        ),
        format!(
            "Latency us: fallback_avg={} promoted_avg={} promoted_max={}",
            report.metrics.average_fallback_detect_latency_us,
            report.metrics.average_promoted_detect_latency_us,
            report.metrics.max_promoted_detect_latency_us
        ),
        format!(
            "Promoted detection volume: {}",
            report.metrics.total_promoted_deposits
        ),
    ];

    if let Some(assurance) = &report.assignment.assurance {
        lines.extend(render_assurance_summary_lines(assurance));
    } else {
        lines.push("Assurance: unavailable".to_string());
    }

    if let Some(pending_review) = &report.pending_review {
        lines.push("PENDING HUMAN APPROVAL".to_string());
        lines.push(format!("Gate reason: {}", pending_review.gate_reason));
        lines.push(format!("Severity: {:?}", pending_review.severity));
        lines.push(format!(
            "Pending since: {} | Canary: {}",
            pending_review.pending_since_ms, pending_review.canary_run_id
        ));
    }

    if report.threshold_results.is_empty() {
        lines.push("Thresholds: none".to_string());
    } else {
        lines.push("Thresholds:".to_string());
        for result in &report.threshold_results {
            lines.push(format!(
                "- {}: {} | {}",
                result.name,
                if result.passed { "pass" } else { "fail" },
                result.details
            ));
        }
    }

    if let Some(config) = &report.quorum_gate_config {
        let threshold = config
            .required_threshold
            .map(|value| value.to_string())
            .unwrap_or_else(|| "advisory-only".to_string());
        lines.push(format!(
            "Quorum Gate: threshold={} required_voters={}",
            threshold,
            if config.required_voter_ids.is_empty() {
                "none".to_string()
            } else {
                config.required_voter_ids.join(", ")
            }
        ));
    }

    if report.rollback_history.is_empty() {
        lines.push("Rollback history: none".to_string());
    } else {
        lines.push("Rollback history:".to_string());
        for rollback in &report.rollback_history {
            lines.push(format!(
                "- {:?} at {} | reason={} | restored_baseline={} | observed_events={}",
                rollback.trigger,
                rollback.occurred_at_ms,
                rollback.reason,
                rollback.restored_baseline_strategy_id,
                rollback.observed_events
            ));
        }
    }

    if report.approval_votes.is_empty() {
        lines.push("Approval votes: none".to_string());
    } else {
        lines.push("Approval votes:".to_string());
        for vote in &report.approval_votes {
            lines.push(format!(
                "- {} at {} ledger_entry={} verified={}",
                vote.voter_id,
                vote.approved_at_ms,
                vote.ledger_entry_id,
                verify_vote_signature(vote, &report.promotion_id)
            ));
        }
    }

    if let Some(receipt) = &report.consensus_receipt {
        lines.push(format!(
            "Consensus receipt: {} threshold_met={} vote_count={} threshold_required={} verified={}",
            receipt.receipt_id,
            receipt.threshold_met,
            receipt.vote_count,
            receipt.threshold_required,
            verify_consensus_receipt_signature(receipt)
        ));
    } else {
        lines.push("Consensus receipt: none".to_string());
    }

    if report.recent_promoted_findings.is_empty() {
        lines.push("Recent promoted findings: none".to_string());
    } else {
        lines.push("Recent promoted findings:".to_string());
        for finding in &report.recent_promoted_findings {
            lines.push(format!(
                "- {} via {} severity={:?} confidence={:.2} shared_with_fallback={}",
                finding.event_id,
                finding.strategy_id,
                finding.severity,
                finding.confidence,
                finding.shared_with_fallback
            ));
        }
    }

    lines.join("\n")
}

pub fn render_production_promotion_list(list: &ProductionPromotionList) -> String {
    let mut lines = vec![format!("Production Promotions ({})", list.total_count)];
    if list.promotions.is_empty() {
        lines.push("none".to_string());
        return lines.join("\n");
    }

    lines.extend(list.promotions.iter().map(|record| {
        format!(
            "- {} status={:?} recommendation={:?} strategy={}",
            record.promotion_id, record.status, record.recommendation, record.promoted_strategy_id
        )
    }));
    lines.join("\n")
}

pub fn validate_quorum_gate(
    votes: &[PromotionApprovalVoteRef],
    config: &PromotionQuorumGateConfig,
) -> Result<(), ProductionPromotionError> {
    let Some(required_threshold) = config.required_threshold else {
        return Ok(());
    };

    let missing_voters = config
        .required_voter_ids
        .iter()
        .filter(|required| !votes.iter().any(|vote| &vote.voter_id == *required))
        .cloned()
        .collect::<Vec<_>>();
    if votes.len() < required_threshold || !missing_voters.is_empty() {
        return Err(ProductionPromotionError::QuorumNotMet {
            have: votes.len(),
            need: required_threshold,
            missing: if missing_voters.is_empty() {
                "none".to_string()
            } else {
                missing_voters.join(", ")
            },
        });
    }
    Ok(())
}

pub fn verify_vote_signature(vote: &PromotionApprovalVoteRef, promotion_id: &str) -> bool {
    let Ok(payload) = canonical_json_bytes(&PromotionApprovalVotePayload {
        promotion_id,
        voter_id: &vote.voter_id,
        approved_at_ms: vote.approved_at_ms,
        ledger_entry_id: &vote.ledger_entry_id,
    }) else {
        return false;
    };
    if vote.voter_id != format!("swarm:ed25519:{}", vote.public_key_hex) {
        return false;
    }
    let Ok(public_key) = PublicKey::from_hex(&vote.public_key_hex) else {
        return false;
    };
    let Ok(signature) = Signature::from_hex(&vote.signature_hex) else {
        return false;
    };
    public_key.verify(&payload, &signature)
}

pub fn verify_consensus_receipt_signature(receipt: &PromotionConsensusReceipt) -> bool {
    let Ok(payload) = canonical_json_bytes(&PromotionConsensusReceiptPayload {
        receipt_id: &receipt.receipt_id,
        approval_set_id: &receipt.approval_set_id,
        verdict_id: &receipt.verdict_id,
        ledger_id: &receipt.ledger_id,
        threshold_met: receipt.threshold_met,
        vote_count: receipt.vote_count,
        threshold_required: receipt.threshold_required,
        created_at_ms: receipt.created_at_ms,
    }) else {
        return false;
    };
    let detached = DetachedSignature {
        algorithm: "ed25519".to_string(),
        key_id: receipt.receipt_signer_key_id.clone(),
        public_key_hex: receipt.receipt_signer_public_key_hex.clone(),
        signature_hex: receipt.receipt_signature_hex.clone(),
    };
    verify_detached_signature(&payload, &detached).is_ok()
}

#[derive(Serialize)]
struct PromotionApprovalVotePayload<'a> {
    promotion_id: &'a str,
    voter_id: &'a str,
    approved_at_ms: i64,
    ledger_entry_id: &'a str,
}

#[derive(Serialize)]
struct PromotionConsensusReceiptPayload<'a> {
    receipt_id: &'a str,
    approval_set_id: &'a str,
    verdict_id: &'a str,
    ledger_id: &'a str,
    threshold_met: bool,
    vote_count: usize,
    threshold_required: usize,
    created_at_ms: i64,
}

fn promotion_severity(report: &CanaryRunReport) -> Severity {
    report
        .recent_candidate_findings
        .iter()
        .map(|finding| finding.severity)
        .max()
        .unwrap_or(Severity::High)
}

fn baseline_candidate_from_config(
    config: &SwarmConfig,
    strategy_id: &str,
) -> Result<DetectorCandidateManifest, ProductionPromotionError> {
    build_candidate_manifest_from_strategy(
        strategy_id,
        &config.detection,
        "production baseline at promotion start",
    )
    .map_err(detector_factory_error)
}

fn detector_from_candidate(
    candidate: &DetectorCandidateManifest,
) -> Result<crate::detector_factory::RuntimeDetector, ProductionPromotionError> {
    build_detector_from_candidate(candidate).map_err(detector_factory_error)
}

fn resolve_promotion_rollout_strategy_id(
    config: &SwarmConfig,
    canary: &CanaryRunReport,
) -> Result<String, ProductionPromotionError> {
    if let Some(strategy_id) = config.promotion.strategy_id.as_deref() {
        let Some(strategy_id) = config
            .detection
            .validate_rollout_strategy_id("promotion.strategy_id", Some(strategy_id))?
        else {
            return Err(ProductionPromotionError::ConfigValidation(
                ConfigValidationError::InvalidField {
                    field: "promotion.strategy_id",
                    reason: "must not be empty when provided".to_string(),
                },
            ));
        };
        if strategy_id != canary.assignment.baseline_strategy_id {
            return Err(ProductionPromotionError::BaselineMismatch {
                expected: strategy_id,
                actual: canary.assignment.baseline_strategy_id.clone(),
            });
        }
        return Ok(strategy_id);
    }

    let inherited = canary.assignment.baseline_strategy_id.trim().to_string();
    if config
        .detection
        .active_strategies()
        .iter()
        .any(|entry| entry == &inherited)
    {
        Ok(inherited)
    } else {
        Err(ProductionPromotionError::InactiveBaselineScope {
            strategy_id: inherited,
        })
    }
}

fn detector_factory_error(error: DetectorFactoryError) -> ProductionPromotionError {
    match error {
        DetectorFactoryError::DetectorProfile(source) => {
            ProductionPromotionError::DetectorProfile(source)
        }
        DetectorFactoryError::UnsupportedDetector { strategy } => {
            ProductionPromotionError::UnsupportedDetector { strategy }
        }
    }
}

fn evaluate_thresholds(
    metrics: &ProductionPromotionMetrics,
    config: &PromotionConfig,
) -> Vec<ProductionPromotionThresholdResult> {
    vec![
        float_threshold(
            "promoted_only_rate",
            config.max_promoted_only_rate,
            metrics.promoted_only_rate,
            "promoted-only detection rate stayed within the configured bound",
            "promoted-only detection rate exceeded the configured bound",
        ),
        float_threshold(
            "fallback_recovery_rate",
            config.max_fallback_recovery_rate,
            metrics.fallback_recovery_rate,
            "fallback recovery rate stayed within the configured bound",
            "fallback recovery rate exceeded the configured bound",
        ),
        int_threshold(
            "detect_latency_threshold",
            config.max_detect_latency_us as u128,
            metrics.max_promoted_detect_latency_us as u128,
            "promoted detect latency stayed within the configured bound",
            "promoted detect latency exceeded the configured bound",
        ),
        int_threshold(
            "total_detection_budget",
            config.max_total_detections as u128,
            metrics.total_promoted_deposits as u128,
            "promoted detection volume stayed within the configured budget",
            "promoted detection volume exceeded the configured budget",
        ),
    ]
}

fn float_threshold(
    name: &str,
    expected: f64,
    actual: f64,
    success_details: &str,
    failure_details: &str,
) -> ProductionPromotionThresholdResult {
    let passed = actual <= expected;
    ProductionPromotionThresholdResult {
        name: name.to_string(),
        passed,
        expected: serde_json::json!(expected),
        actual: serde_json::json!(actual),
        details: if passed {
            success_details.to_string()
        } else {
            failure_details.to_string()
        },
    }
}

fn int_threshold(
    name: &str,
    expected: u128,
    actual: u128,
    success_details: &str,
    failure_details: &str,
) -> ProductionPromotionThresholdResult {
    let passed = actual <= expected;
    ProductionPromotionThresholdResult {
        name: name.to_string(),
        passed,
        expected: serde_json::json!(expected),
        actual: serde_json::json!(actual),
        details: if passed {
            success_details.to_string()
        } else {
            failure_details.to_string()
        },
    }
}

fn append_recent_promoted_findings(
    previews: &mut Vec<ProductionPromotionFindingPreview>,
    findings: &[DetectionFinding],
    shared_with_fallback: bool,
) {
    for finding in findings {
        previews.push(ProductionPromotionFindingPreview {
            event_id: finding.event_id.clone(),
            strategy_id: finding.strategy_id.clone(),
            severity: finding.severity,
            confidence: finding.confidence,
            shared_with_fallback,
        });
    }
    if previews.len() > 10 {
        let drop_count = previews.len() - 10;
        previews.drain(0..drop_count);
    }
}

fn rollback_trigger_for_threshold(name: &str) -> ProductionPromotionRollbackTrigger {
    match name {
        "total_detection_budget" => ProductionPromotionRollbackTrigger::AutomaticBudget,
        _ => ProductionPromotionRollbackTrigger::AutomaticThreshold,
    }
}

fn production_promotion_id(
    window_id: &str,
    assignment: &ProductionPromotionAssignment,
    started_at_ms: i64,
) -> String {
    format!(
        "promotion:{}:{}:{}",
        window_id, assignment.promoted_strategy_id, started_at_ms
    )
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ProductionPromotionIndex {
    entries: Vec<ProductionPromotionRecord>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        DefaultProductionPromotionHarness, ProductionPromotionError,
        ProductionPromotionRecommendation, ProductionPromotionRollbackTrigger,
        ProductionPromotionStatus, PromotionApprovalVoteRef, PromotionConsensusReceipt,
        PromotionQuorumGateConfig, render_production_promotion_report, validate_quorum_gate,
        verify_consensus_receipt_signature, verify_vote_signature,
    };
    use crate::canary::{
        CanaryAssignment, CanaryFindingPreview, CanaryRecommendation, CanaryRunReport,
        CanaryRunStatus, FileCanaryStore,
    };
    use crate::config::RuntimeMode;
    use crate::evolution::{
        EvolutionProposalAssuranceCoverageSummary, EvolutionProposalAssuranceDecision,
        EvolutionProposalAssuranceSolverSummary, EvolutionProposalAssuranceSummary,
        build_assurance_waiver_summary,
    };
    use crate::replay::{DetectorCandidateManifest, ExperimentLineage};
    use std::fs;
    use std::path::PathBuf;
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, CanaryConfig, CorrelationConfig, DetectionConfig,
        DetectorProfilesConfig, InvestigationConfig, PheromoneBackendConfig, PheromoneConfig,
        PolicyConfig, PromotionConfig, ResponseAdapterConfig, RuntimeSettings, SwarmConfig,
        TelemetrySourceConfig,
    };
    use swarm_core::types::{AgentId, Severity};
    use swarm_crypto::{Ed25519Signer, canonical_json_bytes};
    use swarm_whisker::{
        DetectionStrategy, NetworkConnectProfile, ProcessStartEvent, SuspiciousProcessTreeProfile,
        TelemetryEvent, TelemetryPayload,
    };

    fn unique_temp_dir(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-promotion-{label}-{}",
            std::process::id()
        ));
        if root.exists() {
            let _ = fs::remove_dir_all(&root);
        }
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn promotion_config() -> SwarmConfig {
        SwarmConfig {
            schema_version: 1,
            name: "promotion-test".to_string(),
            description: "production promotion test config".to_string(),
            runtime: RuntimeSettings {
                mode: RuntimeMode::DetectOnly,
                demo_mode: false,
                telemetry_sources: vec![TelemetrySourceConfig {
                    name: "synthetic".to_string(),
                    subject: "telemetry.synthetic.process".to_string(),
                    bridge: None,
                }],
                max_in_flight_actions: 2,
                drain_timeout_ms: 30_000,
                require_durable_live_response: false,
                max_heap_pressure: 0.90,
                secret_dir: None,
                anti_tamper: Default::default(),
                temporal_event_window: swarm_core::config::TemporalEventWindowConfig::default(),
                agent_tick_timeout_ms: 500,
                governance_degraded_tick_threshold: 3,
                partition_contingency_lease_ttl_ms: 300_000,
                partition_contingency_blast_radius_cap: 1,
                max_dead_letter_bytes: None,
            },
            detection: DetectionConfig {
                strategy: "suspicious_process_tree".to_string(),
                strategies: Vec::new(),
                high_confidence_threshold: 0.9,
                medium_confidence_threshold: 0.7,
                profiles: DetectorProfilesConfig::default(),
            },
            pheromone: PheromoneConfig {
                default_half_life_secs: 3600.0,
                evaporation_threshold: 0.01,
                min_sources_for_escalation: 2,
                alert_threshold: 2.0,
                incident_threshold: 5.0,
                deescalation_cooldown_secs: 300,
                response_playbook: Default::default(),
                backend: PheromoneBackendConfig::InMemory,
            },
            policy: PolicyConfig {
                human_gate_severity: Severity::High,
                lease_ttl_ms: 60_000,
                ..PolicyConfig::default()
            },
            response_adapter: ResponseAdapterConfig::Sandbox,
            siem_forward: None,
            notification_channels: std::collections::BTreeMap::new(),
            notification_routing: swarm_core::config::NotificationRoutingConfig::default(),
            audit: AuditConfig {
                bundle_store: BundleStoreConfig::Memory,
                recent_decisions_limit: 20,
            },
            investigation: InvestigationConfig::default(),
            correlation: CorrelationConfig::default(),
            canary: CanaryConfig {
                enabled: true,
                slot_id: "canary-primary".to_string(),
                strategy_id: Some("suspicious_process_tree".to_string()),
                observation_window_events: 2,
                max_candidate_only_rate: 0.0,
                max_baseline_miss_rate: 0.0,
                max_detect_latency_us: 10_000,
                max_total_detections: 4,
            },
            promotion: PromotionConfig {
                enabled: true,
                window_id: "production-primary".to_string(),
                strategy_id: None,
                observation_window_events: 2,
                max_promoted_only_rate: 0.0,
                max_fallback_recovery_rate: 0.0,
                max_detect_latency_us: 10_000,
                max_total_detections: 4,
            },
            evolution: swarm_core::config::EvolutionConfig::default(),
            deception: swarm_core::config::DeceptionConfig::default(),
            memory: swarm_core::config::MemoryConfig::default(),
            identity: swarm_core::config::IdentityConfig::default(),
            platform_api: Default::default(),
            operator: swarm_core::config::OperatorSurfaceConfig::default(),
            tls: None,
        }
    }

    fn control_candidate() -> DetectorCandidateManifest {
        DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id: "office_baseline_control".to_string(),
            description: "control candidate".to_string(),
            profile: SuspiciousProcessTreeProfile::default(),
        }
    }

    fn broadened_candidate() -> DetectorCandidateManifest {
        DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id: "office_python_parent_broadening".to_string(),
            description: "broaden parent set with python".to_string(),
            profile: SuspiciousProcessTreeProfile {
                suspicious_parents: vec![
                    "winword".to_string(),
                    "excel".to_string(),
                    "outlook".to_string(),
                    "acrord32".to_string(),
                    "teams".to_string(),
                    "python".to_string(),
                ],
                ..SuspiciousProcessTreeProfile::default()
            },
        }
    }

    #[test]
    fn network_connect_promotion_baselines_and_candidates_are_supported()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = promotion_config();
        config.detection.strategy = "network_connect".to_string();
        config.canary.strategy_id = Some("network_connect".to_string());

        let baseline = super::baseline_candidate_from_config(&config, "network_connect")?;
        assert_eq!(baseline.strategy_id(), "network_connect");

        let promoted =
            super::detector_from_candidate(&DetectorCandidateManifest::NetworkConnect {
                strategy_id: "network_connect_candidate".to_string(),
                description: "network connect candidate".to_string(),
                profile: NetworkConnectProfile {
                    suspicious_ports: vec![4444],
                    ..NetworkConnectProfile::default()
                },
            })?;
        assert_eq!(promoted.id(), "network_connect_candidate");
        Ok(())
    }

    #[test]
    fn promotion_start_rejects_configured_scope_mismatch() {
        let root = unique_temp_dir("scope-mismatch");
        let results_dir = root.join("promotions");
        let mut config = promotion_config();
        config.detection.strategies = vec![
            "suspicious_process_tree".to_string(),
            "dns_exfiltration".to_string(),
        ];
        config.promotion.strategy_id = Some("dns_exfiltration".to_string());
        let ready_canary = ready_canary_report(&config, control_candidate());
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let error = harness
            .start_run(&canaries_dir, &canary_run_id)
            .unwrap_err();

        assert!(matches!(
            error,
            ProductionPromotionError::BaselineMismatch {
                expected,
                actual,
            } if expected == "dns_exfiltration" && actual == "suspicious_process_tree"
        ));
    }

    #[test]
    fn promotion_start_rejects_inherited_scope_that_is_no_longer_active() {
        let root = unique_temp_dir("inactive-inherited-scope");
        let results_dir = root.join("promotions");
        let mut config = promotion_config();
        config.detection.strategy = "dns_exfiltration".to_string();
        config.detection.strategies = vec![
            "dns_exfiltration".to_string(),
            "network_connect".to_string(),
        ];
        config.canary.strategy_id = Some("dns_exfiltration".to_string());
        let mut ready_canary = ready_canary_report(&config, control_candidate());
        ready_canary.assignment.baseline_strategy_id = "suspicious_process_tree".to_string();
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let error = harness
            .start_run(&canaries_dir, &canary_run_id)
            .unwrap_err();

        assert!(matches!(
            error,
            ProductionPromotionError::InactiveBaselineScope { strategy_id }
                if strategy_id == "suspicious_process_tree"
        ));
    }

    fn rollout_baseline_strategy_id(config: &SwarmConfig) -> String {
        config
            .canary
            .strategy_id
            .clone()
            .unwrap_or_else(|| config.detection.strategy.clone())
    }

    fn passed_assurance_summary() -> EvolutionProposalAssuranceSummary {
        EvolutionProposalAssuranceSummary {
            decision: EvolutionProposalAssuranceDecision::Passed,
            coverage: EvolutionProposalAssuranceCoverageSummary {
                detector: "office_baseline_control".to_string(),
                suite_name: Some("evasion-breadth-v1".to_string()),
                corpus_version: Some("2026-04-03".to_string()),
                required_catch_rate: 0.75,
                actual_catch_rate: Some(1.0),
                actionable_gap_count: 0,
            },
            solver: EvolutionProposalAssuranceSolverSummary {
                required: false,
                status: None,
                allowed_statuses: Vec::new(),
            },
            harvested_case_ids: Vec::new(),
            waiver: None,
        }
    }

    fn waived_assurance_summary(
        operator_id: &str,
        secret_material: &str,
    ) -> EvolutionProposalAssuranceSummary {
        let signer = Ed25519Signer::from_secret_material(secret_material);
        let mut summary = EvolutionProposalAssuranceSummary {
            decision: EvolutionProposalAssuranceDecision::Blocked,
            coverage: EvolutionProposalAssuranceCoverageSummary {
                detector: "office_baseline_control".to_string(),
                suite_name: Some("evasion-breadth-v1".to_string()),
                corpus_version: Some("2026-04-03".to_string()),
                required_catch_rate: 0.75,
                actual_catch_rate: Some(0.25),
                actionable_gap_count: 2,
            },
            solver: EvolutionProposalAssuranceSolverSummary {
                required: false,
                status: None,
                allowed_statuses: Vec::new(),
            },
            harvested_case_ids: vec!["case-a".to_string()],
            waiver: None,
        };
        summary.waiver = Some(
            build_assurance_waiver_summary(
                "proposal-test",
                &summary,
                operator_id,
                &signer,
                super::now_ms() - 1_000,
                300,
                "bounded promotion waiver",
            )
            .unwrap(),
        );
        summary
    }

    fn ready_canary_report(
        config: &SwarmConfig,
        candidate: DetectorCandidateManifest,
    ) -> CanaryRunReport {
        let baseline_strategy_id = rollout_baseline_strategy_id(config);
        CanaryRunReport {
            run_id: format!(
                "canary:canary-primary:{}:1700000000000",
                candidate.strategy_id()
            ),
            slot_id: config.canary.slot_id.clone(),
            created_at_ms: 1_700_000_000_000,
            updated_at_ms: 1_700_000_000_100,
            status: CanaryRunStatus::Completed,
            recommendation: CanaryRecommendation::ReadyForPromotionReview,
            assignment: CanaryAssignment {
                experiment_id: format!("experiment:test:{}", candidate.strategy_id()),
                experiment_name: "test".to_string(),
                experiment_path: "experiments/test.yaml".to_string(),
                suite_name: "hellcat_office_v1".to_string(),
                corpus_version: "2026-04-03".to_string(),
                baseline_strategy_id: baseline_strategy_id.clone(),
                candidate_strategy_id: candidate.strategy_id().to_string(),
                candidate_description: candidate.description().to_string(),
                candidate: candidate.clone(),
                lineage: ExperimentLineage {
                    parent_strategy_id: baseline_strategy_id,
                    mutation: "test".to_string(),
                    rationale: "test rationale".to_string(),
                },
                verification_id: format!("verification:test:{}", candidate.strategy_id()),
                verification_passed: true,
                shadow_id: format!("shadow:test:{}", candidate.strategy_id()),
                shadow_passed: true,
                assurance: Some(passed_assurance_summary()),
                canary: config.canary.clone(),
            },
            metrics: Default::default(),
            threshold_results: Vec::new(),
            recent_candidate_findings: Vec::new(),
            rollback_history: Vec::new(),
        }
    }

    fn ready_canary_report_with_severity(
        config: &SwarmConfig,
        candidate: DetectorCandidateManifest,
        severity: Severity,
    ) -> CanaryRunReport {
        let mut report = ready_canary_report(config, candidate);
        report.recent_candidate_findings.push(CanaryFindingPreview {
            event_id: format!("event:{severity:?}"),
            strategy_id: report.assignment.candidate_strategy_id.clone(),
            severity,
            confidence: 0.99,
            shared_with_baseline: false,
        });
        report
    }

    fn persist_ready_canary(root: &std::path::Path, report: &CanaryRunReport) -> (PathBuf, String) {
        let canaries_dir = root.join("canaries");
        let store = FileCanaryStore::open(&canaries_dir).unwrap();
        let record = store.persist(report).unwrap();
        (canaries_dir, record.run_id)
    }

    fn signed_vote(
        promotion_id: &str,
        secret_material: &str,
        approved_at_ms: i64,
        ledger_entry_id: &str,
    ) -> PromotionApprovalVoteRef {
        let signer = Ed25519Signer::from_secret_material(secret_material);
        let voter_id = format!("swarm:ed25519:{}", signer.public_key_hex());
        let signature = signer
            .sign(
                &canonical_json_bytes(&super::PromotionApprovalVotePayload {
                    promotion_id,
                    voter_id: &voter_id,
                    approved_at_ms,
                    ledger_entry_id,
                })
                .unwrap(),
            )
            .signature_hex;
        PromotionApprovalVoteRef {
            voter_id,
            public_key_hex: signer.public_key_hex().to_string(),
            signature_hex: signature,
            approved_at_ms,
            ledger_entry_id: ledger_entry_id.to_string(),
        }
    }

    fn signed_receipt(secret_material: &str, created_at_ms: i64) -> PromotionConsensusReceipt {
        let signer = Ed25519Signer::from_secret_material(secret_material);
        let payload = canonical_json_bytes(&super::PromotionConsensusReceiptPayload {
            receipt_id: "receipt:test",
            approval_set_id: "approval-set:test",
            verdict_id: "approval-verdict:test",
            ledger_id: "approval-ledger:test",
            threshold_met: true,
            vote_count: 2,
            threshold_required: 2,
            created_at_ms,
        })
        .unwrap();
        let signature = signer.sign(&payload);
        PromotionConsensusReceipt {
            receipt_id: "receipt:test".to_string(),
            approval_set_id: "approval-set:test".to_string(),
            verdict_id: "approval-verdict:test".to_string(),
            ledger_id: "approval-ledger:test".to_string(),
            threshold_met: true,
            vote_count: 2,
            threshold_required: 2,
            receipt_signature_hex: signature.signature_hex,
            receipt_signer_key_id: signature.key_id,
            receipt_signer_public_key_hex: signer.public_key_hex().to_string(),
            created_at_ms,
        }
    }

    fn suspicious_event(event_id: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "WINWORD".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc AAA=".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    fn benign_python_event(event_id: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "python".to_string(),
                process_name: "curl".to_string(),
                command_line: "curl https://example.invalid/script.ps1".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    #[test]
    fn promotion_run_starts_from_ready_canary() {
        let root = unique_temp_dir("start");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let ready_canary = ready_canary_report(&config, control_candidate());
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let lookup = harness.start_run(&canaries_dir, &canary_run_id).unwrap();

        assert_eq!(lookup.report.status, ProductionPromotionStatus::Active);
        assert_eq!(
            lookup.report.recommendation,
            ProductionPromotionRecommendation::Observing
        );
        assert_eq!(
            lookup.report.assignment.previous_production_strategy_id,
            "suspicious_process_tree"
        );
        assert_eq!(
            lookup.report.assignment.promoted_strategy_id,
            "office_baseline_control"
        );
    }

    #[test]
    fn promotion_rejects_canary_without_passed_assurance_lineage() {
        let root = unique_temp_dir("missing-assurance");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let mut ready_canary = ready_canary_report(&config, control_candidate());
        ready_canary.assignment.assurance = None;
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let error = harness
            .start_run(&canaries_dir, &canary_run_id)
            .unwrap_err();

        assert!(matches!(
            error,
            ProductionPromotionError::AssuranceNotSatisfied { .. }
        ));
    }

    #[test]
    fn promotion_accepts_canary_with_active_waived_assurance_lineage() {
        let root = unique_temp_dir("waived-assurance");
        let results_dir = root.join("promotions");
        let mut config = promotion_config();
        let secret_material = "phase-175-promotion-waiver";
        let operator_id = AgentId::from_public_key_hex(
            Ed25519Signer::from_secret_material(secret_material).public_key_hex(),
        )
        .to_string();
        config.evolution.assurance.waiver.allowed_operator_ids = vec![operator_id.clone()];
        let mut ready_canary = ready_canary_report(&config, control_candidate());
        ready_canary.assignment.assurance =
            Some(waived_assurance_summary(&operator_id, secret_material));
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let started = harness.start_run(&canaries_dir, &canary_run_id).unwrap();

        assert_eq!(started.report.status, ProductionPromotionStatus::Active);
        assert!(render_production_promotion_report(&started.report).contains("Assurance waiver:"));
        assert!(
            render_production_promotion_report(&started.report)
                .contains("Waiver reason: bounded promotion waiver")
        );
    }

    #[test]
    fn promotion_control_candidate_completes_after_window() {
        let root = unique_temp_dir("complete");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let ready_canary = ready_canary_report(&config, control_candidate());
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let started = harness.start_run(&canaries_dir, &canary_run_id).unwrap();

        let after_first = harness
            .ingest_event(
                &started.record.promotion_id,
                &suspicious_event("evt-promotion-1"),
            )
            .unwrap();
        assert_eq!(after_first.report.status, ProductionPromotionStatus::Active);

        let completed = harness
            .ingest_event(
                &started.record.promotion_id,
                &suspicious_event("evt-promotion-2"),
            )
            .unwrap();
        assert_eq!(
            completed.report.status,
            ProductionPromotionStatus::Completed
        );
        assert_eq!(
            completed.report.recommendation,
            ProductionPromotionRecommendation::StableInProduction
        );
        assert!(
            render_production_promotion_report(&completed.report)
                .contains("Production Promotion Run")
        );
    }

    #[test]
    fn critical_severity_promotion_starts_pending_human_approval() {
        let root = unique_temp_dir("pending");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let ready_canary =
            ready_canary_report_with_severity(&config, control_candidate(), Severity::Critical);
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let lookup = harness.start_run(&canaries_dir, &canary_run_id).unwrap();

        assert_eq!(
            lookup.report.status,
            ProductionPromotionStatus::HumanApprovalPending
        );
        assert_eq!(
            lookup.report.recommendation,
            ProductionPromotionRecommendation::PendingHumanApproval
        );
        assert_eq!(lookup.report.approval_severity, Some(Severity::Critical));
        assert!(lookup.report.pending_review.is_some());
        assert!(
            render_production_promotion_report(&lookup.report).contains("PENDING HUMAN APPROVAL")
        );
    }

    #[test]
    fn non_critical_promotion_starts_active() {
        let root = unique_temp_dir("active-high");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let ready_canary =
            ready_canary_report_with_severity(&config, control_candidate(), Severity::High);
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let lookup = harness.start_run(&canaries_dir, &canary_run_id).unwrap();

        assert_eq!(lookup.report.status, ProductionPromotionStatus::Active);
        assert_eq!(
            lookup.report.recommendation,
            ProductionPromotionRecommendation::Observing
        );
    }

    #[test]
    fn promotion_auto_rollback_triggers_on_promoted_only_detection() {
        let root = unique_temp_dir("rollback");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let ready_canary = ready_canary_report(&config, broadened_candidate());
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let started = harness.start_run(&canaries_dir, &canary_run_id).unwrap();

        let rolled_back = harness
            .ingest_event(
                &started.record.promotion_id,
                &benign_python_event("evt-promotion-python"),
            )
            .unwrap();
        assert_eq!(
            rolled_back.report.status,
            ProductionPromotionStatus::RolledBack
        );
        assert_eq!(
            rolled_back.report.recommendation,
            ProductionPromotionRecommendation::Blocked
        );
        assert_eq!(rolled_back.report.rollback_history.len(), 1);
        assert_eq!(
            rolled_back.report.rollback_history[0].trigger,
            ProductionPromotionRollbackTrigger::AutomaticThreshold
        );
        assert!(
            rolled_back
                .report
                .threshold_results
                .iter()
                .any(|result| result.name == "promoted_only_rate" && !result.passed)
        );
    }

    #[test]
    fn pending_promotion_requires_explicit_approval_before_events() {
        let root = unique_temp_dir("pending-event");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let ready_canary =
            ready_canary_report_with_severity(&config, control_candidate(), Severity::Critical);
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let started = harness.start_run(&canaries_dir, &canary_run_id).unwrap();
        let error = harness
            .ingest_event(
                &started.record.promotion_id,
                &suspicious_event("evt-pending"),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            super::ProductionPromotionError::RunNotActive { .. }
        ));
    }

    #[test]
    fn pending_promotion_can_be_approved_and_persists_votes_and_receipt() {
        let root = unique_temp_dir("approve");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let ready_canary =
            ready_canary_report_with_severity(&config, control_candidate(), Severity::Critical);
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let started = harness.start_run(&canaries_dir, &canary_run_id).unwrap();
        let vote_a = signed_vote(
            &started.record.promotion_id,
            "alpha",
            1_700_000_000_500,
            "ledger-entry-a",
        );
        let vote_b = signed_vote(
            &started.record.promotion_id,
            "bravo",
            1_700_000_000_501,
            "ledger-entry-b",
        );
        let receipt = signed_receipt("receipt-signer", 1_700_000_000_502);

        let approved = harness
            .approve_pending_run(
                &started.record.promotion_id,
                vec![vote_a.clone(), vote_b.clone()],
                Some(receipt.clone()),
                "approved by operator",
            )
            .unwrap();
        assert_eq!(approved.report.status, ProductionPromotionStatus::Active);
        assert!(approved.report.pending_review.is_none());
        assert_eq!(
            approved.report.approval_votes,
            vec![vote_a.clone(), vote_b.clone()]
        );
        assert_eq!(approved.report.consensus_receipt, Some(receipt.clone()));

        let reloaded = harness
            .load_run(&started.record.promotion_id)
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.report.approval_votes, vec![vote_a, vote_b]);
        assert_eq!(reloaded.report.consensus_receipt, Some(receipt));
        let rendered = render_production_promotion_report(&reloaded.report);
        assert!(rendered.contains("Approval votes:"));
        assert!(rendered.contains("Consensus receipt:"));
    }

    #[test]
    fn approving_non_pending_promotion_fails() {
        let root = unique_temp_dir("approve-active");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let ready_canary =
            ready_canary_report_with_severity(&config, control_candidate(), Severity::High);
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let started = harness.start_run(&canaries_dir, &canary_run_id).unwrap();
        let error = harness
            .approve_pending_run(
                &started.record.promotion_id,
                vec![signed_vote(
                    &started.record.promotion_id,
                    "alpha",
                    1_700_000_000_500,
                    "ledger-entry-a",
                )],
                None,
                "should fail",
            )
            .unwrap_err();
        assert!(matches!(
            error,
            super::ProductionPromotionError::RunNotPending { .. }
        ));
    }

    #[test]
    fn pending_promotions_can_still_be_halted_or_rolled_back() {
        let root = unique_temp_dir("pending-finalize");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let ready_canary =
            ready_canary_report_with_severity(&config, control_candidate(), Severity::Critical);
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config.clone(),
            &results_dir,
        )
        .unwrap();
        let started = harness.start_run(&canaries_dir, &canary_run_id).unwrap();
        let halted = harness
            .halt_run(&started.record.promotion_id, "operator requested stop")
            .unwrap();
        assert_eq!(halted.report.status, ProductionPromotionStatus::Halted);

        let second_root = unique_temp_dir("pending-rollback");
        let second_results = second_root.join("promotions");
        let second_ready_canary =
            ready_canary_report_with_severity(&config, control_candidate(), Severity::Critical);
        let (second_canaries_dir, second_canary_run_id) =
            persist_ready_canary(&second_root, &second_ready_canary);
        let second_harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            promotion_config(),
            &second_results,
        )
        .unwrap();
        let second_started = second_harness
            .start_run(&second_canaries_dir, &second_canary_run_id)
            .unwrap();
        let rolled_back = second_harness
            .rollback_run(&second_started.record.promotion_id, "operator rollback")
            .unwrap();
        assert_eq!(
            rolled_back.report.status,
            ProductionPromotionStatus::RolledBack
        );
    }

    #[test]
    fn quorum_gate_and_signature_helpers_behave_as_expected() {
        let advisory = PromotionQuorumGateConfig::default();
        assert!(validate_quorum_gate(&[], &advisory).is_ok());

        let vote_a = signed_vote(
            "promotion:test",
            "alpha",
            1_700_000_000_600,
            "ledger-entry-a",
        );
        let vote_b = signed_vote(
            "promotion:test",
            "bravo",
            1_700_000_000_601,
            "ledger-entry-b",
        );
        assert!(verify_vote_signature(&vote_a, "promotion:test"));
        let mut tampered_vote = vote_a.clone();
        tampered_vote.signature_hex = "deadbeef".to_string();
        assert!(!verify_vote_signature(&tampered_vote, "promotion:test"));

        let thresholded = PromotionQuorumGateConfig {
            required_threshold: Some(2),
            required_voter_ids: vec![vote_a.voter_id.clone()],
        };
        assert!(validate_quorum_gate(&[vote_a.clone(), vote_b.clone()], &thresholded).is_ok());
        assert!(matches!(
            validate_quorum_gate(std::slice::from_ref(&vote_a), &thresholded),
            Err(super::ProductionPromotionError::QuorumNotMet { .. })
        ));

        let receipt = signed_receipt("receipt-signer", 1_700_000_000_602);
        assert!(verify_consensus_receipt_signature(&receipt));
        let mut tampered_receipt = receipt.clone();
        tampered_receipt.receipt_signature_hex = "deadbeef".to_string();
        assert!(!verify_consensus_receipt_signature(&tampered_receipt));
    }

    #[test]
    fn pending_approval_respects_persisted_quorum_gate_configuration() {
        let root = unique_temp_dir("quorum-block");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let ready_canary =
            ready_canary_report_with_severity(&config, control_candidate(), Severity::Critical);
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let started = harness.start_run(&canaries_dir, &canary_run_id).unwrap();
        let mut pending = harness
            .load_run(&started.record.promotion_id)
            .unwrap()
            .unwrap();
        pending.report.quorum_gate_config = Some(PromotionQuorumGateConfig {
            required_threshold: Some(2),
            required_voter_ids: Vec::new(),
        });
        harness.store.persist(&pending.report).unwrap();

        let error = harness
            .approve_pending_run(
                &started.record.promotion_id,
                vec![signed_vote(
                    &started.record.promotion_id,
                    "alpha",
                    1_700_000_000_700,
                    "ledger-entry-a",
                )],
                None,
                "insufficient quorum",
            )
            .unwrap_err();
        assert!(matches!(
            error,
            super::ProductionPromotionError::QuorumNotMet { .. }
        ));
    }

    #[test]
    fn promotion_manual_halt_records_reason() {
        let root = unique_temp_dir("halt");
        let results_dir = root.join("promotions");
        let config = promotion_config();
        let ready_canary = ready_canary_report(&config, control_candidate());
        let (canaries_dir, canary_run_id) = persist_ready_canary(&root, &ready_canary);

        let harness = DefaultProductionPromotionHarness::from_config(
            "rulesets/default.yaml",
            config,
            &results_dir,
        )
        .unwrap();
        let started = harness.start_run(&canaries_dir, &canary_run_id).unwrap();

        let halted = harness
            .halt_run(&started.record.promotion_id, "operator requested stop")
            .unwrap();
        assert_eq!(halted.report.status, ProductionPromotionStatus::Halted);
        assert_eq!(halted.report.rollback_history.len(), 1);
        assert_eq!(
            halted.report.rollback_history[0].trigger,
            ProductionPromotionRollbackTrigger::ManualHalt
        );
        assert_eq!(
            halted.report.rollback_history[0].reason,
            "operator requested stop"
        );
    }
}
