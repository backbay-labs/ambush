use crate::approval::{ApprovalError, DefaultApprovalHarness};
use crate::config::{
    DetectorProfileError, RuntimeConfigError, kill_chain_sequence_profile, load_config,
    validate_all_detector_profiles,
};
use crate::detector_factory::{DetectorFactoryError, build_detector_from_strategy};
use crate::evolution_status::{DefaultEvolutionStatusHarness, EvolutionStatusError};
use crate::ingest::{
    FirstRunWizardError, FirstRunWizardReport, FirstRunWizardRequest, IngestBuildError,
    IngestState, run_first_run_wizard,
};
use crate::investigation::SummaryInvestigator;
use crate::sequence_detector::{KILL_CHAIN_SEQUENCE_STRATEGY_ID, KillChainSequenceDetector};
use crate::service::{
    ConfiguredRuntimeStack, OperatorStatusReport, ResponsePlaybookPreviewReport,
    ResponsePlaybookPreviewRequest, ServiceError,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::{DetectionConfig, RuntimeMode, SwarmConfig, TelemetryBridgeConfig};
use swarm_core::pheromone::{ThreatClassConfig, ThreatIntelEntry, ThreatIntelIndicatorType};
use swarm_core::types::Severity;
use swarm_crypto::Ed25519Signer;
use swarm_ingest_json::{CloudTrailBridge, GenericJsonBridge};
use swarm_pheromone::{PheromoneSubstrate, SubstrateError};
use swarm_response::{
    DeadLetterEntry, DispatchingExecutor, NotificationError, NotificationReplayResult,
};
use swarm_spine::{
    CorrelatedIncident, IncidentRecord, InvestigationBundle, InvestigationBundleRecord,
    ReplayBundle, ReplayBundleRecord, ReplayPreview,
};
use swarm_whisker::{CompositeDetector, DetectionStrategy};

/// Errors surfaced by the repo-owned operator control surface.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    Service(#[from] ServiceError),

    #[error(transparent)]
    Substrate(#[from] SubstrateError),

    #[error(transparent)]
    DetectorProfile(#[from] DetectorProfileError),

    #[error(transparent)]
    Notification(#[from] NotificationError),

    #[error(transparent)]
    EvolutionStatus(#[from] EvolutionStatusError),

    #[error(transparent)]
    Approval(#[from] ApprovalError),

    #[error(transparent)]
    IngestBuild(Box<IngestBuildError>),

    #[error(transparent)]
    FirstRunWizard(#[from] FirstRunWizardError),

    #[error("unsupported detector strategy `{strategy}`")]
    UnsupportedDetector { strategy: String },

    #[error("{entity} `{lookup}` was not found")]
    NotFound {
        entity: &'static str,
        lookup: String,
    },
}

/// Marks whether control output reflects live runtime state, persisted runtime artifacts, or replay results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlDataOrigin {
    LiveRuntimeStatus,
    PersistedRuntimeArtifact,
    OfflineReplayArtifact,
    ConfigDiagnostic,
    GuidedFirstRun,
    PlaybookDryRun,
}

pub const CURRENT_OPERATOR_API_SCHEMA_VERSION: u32 = 1;
pub const OPERATOR_API_SCHEMA_VERSION_HEADER: &str = "x-swarm-schema-version";

pub fn resolve_operator_api_schema_version(requested: Option<u32>) -> Result<u32, String> {
    let schema_version = requested.unwrap_or(CURRENT_OPERATOR_API_SCHEMA_VERSION);
    if schema_version == CURRENT_OPERATOR_API_SCHEMA_VERSION {
        Ok(schema_version)
    } else {
        Err(format!(
            "unsupported operator API schema version `{schema_version}`"
        ))
    }
}

/// Serializable wrapper around one control-surface payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEnvelope<T> {
    pub schema_version: u32,
    pub origin: ControlDataOrigin,
    pub generated_at_ms: i64,
    pub config_name: String,
    pub data: T,
}

impl<T> ControlEnvelope<T> {
    fn new(
        origin: ControlDataOrigin,
        generated_at_ms: i64,
        config_name: impl Into<String>,
        data: T,
    ) -> Self {
        Self {
            schema_version: CURRENT_OPERATOR_API_SCHEMA_VERSION,
            origin,
            generated_at_ms,
            config_name: config_name.into(),
            data,
        }
    }
}

/// Replay bundle lookup result exposed by the control surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayArtifactView {
    pub record: ReplayBundleRecord,
    pub preview: ReplayPreview,
    pub bundle: ReplayBundle,
}

/// Investigation bundle lookup result exposed by the control surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationArtifactView {
    pub record: InvestigationBundleRecord,
    pub bundle: InvestigationBundle,
}

/// Incident lookup result exposed by the control surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentArtifactView {
    pub record: IncidentRecord,
    pub incident: CorrelatedIncident,
}

/// Top-level control output rendered by `swarmctl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OperatorControlOutput {
    Status(Box<ControlEnvelope<OperatorStatusReport>>),
    Readiness(Box<ControlEnvelope<ReadinessDiagnosticReport>>),
    FirstRun(Box<ControlEnvelope<FirstRunDiagnosticReport>>),
    PlaybookPreview(Box<ControlEnvelope<ResponsePlaybookPreviewReport>>),
    Replay(Box<ControlEnvelope<ReplayArtifactView>>),
    Investigation(Box<ControlEnvelope<InvestigationArtifactView>>),
    Incident(Box<ControlEnvelope<IncidentArtifactView>>),
}

/// One telemetry-source onboarding verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySourceReadiness {
    pub name: String,
    pub transport: String,
    pub ready: bool,
    pub status: String,
    pub details: String,
}

/// Aggregated telemetry-source readiness used by guided first-run onboarding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryReadinessReport {
    pub ready: bool,
    pub configured_sources: usize,
    pub ready_sources: usize,
    pub entries: Vec<TelemetrySourceReadiness>,
}

/// One detector-activation verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorActivationReadiness {
    pub strategy: String,
    pub ready: bool,
    pub details: String,
}

/// Aggregated detector-activation readiness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorReadinessReport {
    pub ready: bool,
    pub active_strategies: Vec<String>,
    pub entries: Vec<DetectorActivationReadiness>,
}

/// Substrate readiness verdict used by first-run onboarding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubstrateReadinessReport {
    pub ready: bool,
    pub backend: String,
    pub durable: bool,
    pub durable_required: bool,
    pub details: String,
}

/// Repo-owned onboarding readiness report shared by later guided first-run work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessDiagnosticReport {
    pub ready: bool,
    pub mode: RuntimeMode,
    pub telemetry: TelemetryReadinessReport,
    pub detectors: DetectorReadinessReport,
    pub substrate: SubstrateReadinessReport,
    pub warnings: Vec<String>,
    pub blocking_failures: Vec<String>,
}

/// Result-state for the guided first-run walkthrough.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirstRunStatus {
    Blocked,
    Completed,
}

/// Filesystem locations used by the guided first-run approval flow.
#[derive(Debug, Clone)]
pub struct FirstRunWizardPaths {
    pub approval_verdict_results_dir: PathBuf,
    pub approval_receipt_pack_results_dir: PathBuf,
    pub approval_set_results_dir: PathBuf,
    pub approval_ledger_results_dir: PathBuf,
}

/// Operator-controlled inputs for the guided first-run walkthrough.
#[derive(Debug, Clone)]
pub struct FirstRunWizardOptions {
    pub scenario_path: Option<PathBuf>,
    pub pace_ms: u64,
    pub voter_signing_key_env: String,
    pub evidence_signer_id: String,
    pub evidence_signing_key_env: String,
    pub paths: FirstRunWizardPaths,
}

/// Readiness-gated first-run walkthrough report exposed through `swarmctl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirstRunDiagnosticReport {
    pub status: FirstRunStatus,
    pub readiness: ReadinessDiagnosticReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub walkthrough: Option<FirstRunWizardReport>,
}

/// Stable selectors for replay-bundle lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayLookupSelector<'a> {
    BundleId(&'a str),
    HuntId(&'a str),
    ReceiptId(&'a str),
}

/// Stable selectors for investigation-bundle lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvestigationLookupSelector<'a> {
    InvestigationId(&'a str),
    HuntId(&'a str),
    ReceiptId(&'a str),
}

/// Stable selectors for incident lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentLookupSelector<'a> {
    IncidentId(&'a str),
    HuntId(&'a str),
}

/// Default operator control plane built from repo-owned config and the shipped runtime defaults.
pub struct DefaultControlPlane {
    pub config_path: PathBuf,
    pub stack: ConfiguredRuntimeStack<
        swarm_policy::configurable_gate::ConfigurableApprovalGate,
        DispatchingExecutor,
        SummaryInvestigator,
    >,
    detector: CompositeDetector,
}

impl DefaultControlPlane {
    /// Build the control plane from a repository-owned config file.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ControlError> {
        let path = path.as_ref();
        let config = load_config(path)?;
        Self::from_config(path, config)
    }

    /// Build the control plane from an already-validated config.
    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: swarm_core::config::SwarmConfig,
    ) -> Result<Self, ControlError> {
        let detector = build_composite_detector(&config.detection)?;
        let stack = ConfiguredRuntimeStack::from_config(config, SummaryInvestigator)?;

        Ok(Self {
            config_path: config_path.into(),
            stack,
            detector,
        })
    }

    /// Read the current operator review surface from the configured runtime stack.
    pub async fn status(&self) -> Result<ControlEnvelope<OperatorStatusReport>, ControlError> {
        let mut report = self.stack.operator_review_status(&self.detector).await?;
        if self.stack.service.config.evolution.enabled {
            let evolution = DefaultEvolutionStatusHarness::from_config(
                &self.config_path,
                self.stack.service.config.clone(),
            )?
            .status()?;
            report = report.with_evolution(evolution);
        }
        Ok(ControlEnvelope::new(
            ControlDataOrigin::LiveRuntimeStatus,
            now_ms(),
            self.stack.service.config.name.clone(),
            report,
        ))
    }

    /// Run the repo-owned first-run readiness diagnostic.
    pub async fn readiness(
        &self,
    ) -> Result<ControlEnvelope<ReadinessDiagnosticReport>, ControlError> {
        let config = &self.stack.service.config;
        let telemetry = telemetry_readiness_from_config(config).await;
        let detectors = detector_readiness_from_config(config, &self.stack.service.runtime);
        let substrate = substrate_readiness_from_stack(&self.stack).await;
        let mut warnings = Vec::new();
        let mut blocking_failures = Vec::new();

        if telemetry.entries.is_empty() {
            blocking_failures
                .push("no telemetry sources are configured for first-run onboarding".to_string());
        }

        for entry in &telemetry.entries {
            if entry.ready {
                if entry.status == "configured" {
                    warnings.push(format!(
                        "telemetry source `{}` is configuration-validated only; live subscription is established when serve mode starts",
                        entry.name
                    ));
                }
            } else {
                blocking_failures.push(format!(
                    "telemetry source `{}` is not ready: {}",
                    entry.name, entry.details
                ));
            }
        }

        for entry in &detectors.entries {
            if !entry.ready {
                blocking_failures.push(format!(
                    "detector `{}` failed activation: {}",
                    entry.strategy, entry.details
                ));
            }
        }

        if !substrate.ready {
            blocking_failures.push(format!(
                "substrate backend `{}` is not ready: {}",
                substrate.backend, substrate.details
            ));
        }

        let ready = telemetry.ready && detectors.ready && substrate.ready;
        Ok(ControlEnvelope::new(
            ControlDataOrigin::ConfigDiagnostic,
            now_ms(),
            config.name.clone(),
            ReadinessDiagnosticReport {
                ready,
                mode: config.runtime.mode,
                telemetry,
                detectors,
                substrate,
                warnings,
                blocking_failures,
            },
        ))
    }

    /// Run the repo-owned readiness-gated first-run walkthrough.
    pub async fn first_run(
        &self,
        options: FirstRunWizardOptions,
    ) -> Result<ControlEnvelope<FirstRunDiagnosticReport>, ControlError> {
        let readiness = self.readiness().await?;
        if !readiness.data.ready {
            return Ok(ControlEnvelope::new(
                ControlDataOrigin::GuidedFirstRun,
                now_ms(),
                self.stack.service.config.name.clone(),
                FirstRunDiagnosticReport {
                    status: FirstRunStatus::Blocked,
                    readiness: readiness.data,
                    walkthrough: None,
                },
            ));
        }

        let harness = DefaultApprovalHarness::from_path(
            &self.config_path,
            &options.paths.approval_verdict_results_dir,
            &options.paths.approval_receipt_pack_results_dir,
            &options.paths.approval_set_results_dir,
            &options.paths.approval_ledger_results_dir,
        )?;
        let config =
            guided_first_run_config(&self.stack.service.config, &options.voter_signing_key_env)?;
        let state = IngestState::from_config(self.config_path.clone(), config)
            .map_err(|error| ControlError::IngestBuild(Box::new(error)))?
            .with_approval_harness(harness);
        let walkthrough = run_first_run_wizard(
            state,
            FirstRunWizardRequest {
                scenario_path: options.scenario_path.map(|path| path.display().to_string()),
                pace_ms: options.pace_ms,
                voter_signing_key_env: options.voter_signing_key_env,
                evidence_signer_id: options.evidence_signer_id,
                evidence_signing_key_env: options.evidence_signing_key_env,
            },
        )
        .await?;

        Ok(ControlEnvelope::new(
            ControlDataOrigin::GuidedFirstRun,
            now_ms(),
            self.stack.service.config.name.clone(),
            FirstRunDiagnosticReport {
                status: FirstRunStatus::Completed,
                readiness: readiness.data,
                walkthrough: Some(walkthrough),
            },
        ))
    }

    /// Build a side-effect free dry-run preview for one matched response playbook.
    pub fn playbook_preview(
        &self,
        request: ResponsePlaybookPreviewRequest,
    ) -> Result<ControlEnvelope<ResponsePlaybookPreviewReport>, ControlError> {
        let generated_at_ms = now_ms();
        Ok(ControlEnvelope::new(
            ControlDataOrigin::PlaybookDryRun,
            generated_at_ms,
            self.stack.service.config.name.clone(),
            self.stack
                .service
                .playbook_preview(request, generated_at_ms)?,
        ))
    }

    /// List persisted threat-class pheromone policy records from the configured substrate.
    pub async fn threat_class_configs(
        &self,
    ) -> Result<ControlEnvelope<Vec<ThreatClassConfig>>, ControlError> {
        let configs = self.stack.substrate.query_threat_class_configs().await?;
        Ok(ControlEnvelope::new(
            ControlDataOrigin::PersistedRuntimeArtifact,
            now_ms(),
            self.stack.service.config.name.clone(),
            configs,
        ))
    }

    /// Store one threat-class pheromone policy record in the configured substrate.
    pub async fn store_threat_class_config(
        &self,
        config: ThreatClassConfig,
    ) -> Result<ControlEnvelope<ThreatClassConfig>, ControlError> {
        self.stack
            .substrate
            .store_threat_class_config(config.clone())
            .await?;
        Ok(ControlEnvelope::new(
            ControlDataOrigin::PersistedRuntimeArtifact,
            now_ms(),
            self.stack.service.config.name.clone(),
            config,
        ))
    }

    /// Store one threat-intel record in the configured substrate.
    pub async fn store_threat_intel_entry(
        &self,
        entry: ThreatIntelEntry,
    ) -> Result<ControlEnvelope<ThreatIntelEntry>, ControlError> {
        self.stack
            .substrate
            .store_threat_intel_entry(entry.clone())
            .await?;
        Ok(ControlEnvelope::new(
            ControlDataOrigin::PersistedRuntimeArtifact,
            now_ms(),
            self.stack.service.config.name.clone(),
            entry,
        ))
    }

    /// Query one exact threat-intel record from the configured substrate.
    pub async fn query_threat_intel_entry(
        &self,
        indicator_type: ThreatIntelIndicatorType,
        value: impl AsRef<str>,
        now: i64,
    ) -> Result<ControlEnvelope<Option<ThreatIntelEntry>>, ControlError> {
        let entry = self
            .stack
            .substrate
            .query_threat_intel_entry(&indicator_type, value.as_ref(), now)
            .await?;
        Ok(ControlEnvelope::new(
            ControlDataOrigin::PersistedRuntimeArtifact,
            now_ms(),
            self.stack.service.config.name.clone(),
            entry,
        ))
    }

    /// List notification dead-letter entries for one named channel.
    pub async fn notification_dead_letters(
        &self,
        channel: impl AsRef<str>,
        limit: Option<usize>,
    ) -> Result<ControlEnvelope<Vec<DeadLetterEntry>>, ControlError> {
        let router =
            self.stack
                .service
                .notification_router()
                .ok_or_else(|| ControlError::NotFound {
                    entity: "notification channel",
                    lookup: channel.as_ref().to_string(),
                })?;
        let entries = router.list_dead_letters(channel.as_ref(), limit).await?;
        Ok(ControlEnvelope::new(
            ControlDataOrigin::PersistedRuntimeArtifact,
            now_ms(),
            self.stack.service.config.name.clone(),
            entries,
        ))
    }

    /// Replay suppressed notification dead-letter entries for one named channel.
    pub async fn replay_notification_dead_letters(
        &self,
        channel: impl AsRef<str>,
        receipt_ids: Option<Vec<String>>,
    ) -> Result<ControlEnvelope<Vec<NotificationReplayResult>>, ControlError> {
        let router =
            self.stack
                .service
                .notification_router()
                .ok_or_else(|| ControlError::NotFound {
                    entity: "notification channel",
                    lookup: channel.as_ref().to_string(),
                })?;
        let results = router
            .replay_dead_letters(channel.as_ref(), receipt_ids)
            .await?;
        Ok(ControlEnvelope::new(
            ControlDataOrigin::PersistedRuntimeArtifact,
            now_ms(),
            self.stack.service.config.name.clone(),
            results,
        ))
    }

    /// Load a replay bundle through one stable identifier.
    pub fn replay_lookup(
        &self,
        selector: ReplayLookupSelector<'_>,
    ) -> Result<ControlEnvelope<ReplayArtifactView>, ControlError> {
        let (lookup_label, lookup) = match selector {
            ReplayLookupSelector::BundleId(bundle_id) => (
                format!("bundle_id:{bundle_id}"),
                self.stack.replay_bundle_by_bundle_id(bundle_id)?,
            ),
            ReplayLookupSelector::HuntId(hunt_id) => (
                format!("hunt_id:{hunt_id}"),
                self.stack.replay_bundle_by_hunt_id(hunt_id)?,
            ),
            ReplayLookupSelector::ReceiptId(receipt_id) => (
                format!("receipt_id:{receipt_id}"),
                self.stack.replay_bundle_by_receipt_id(receipt_id)?,
            ),
        };

        let lookup = lookup.ok_or(ControlError::NotFound {
            entity: "replay bundle",
            lookup: lookup_label,
        })?;
        Ok(ControlEnvelope::new(
            ControlDataOrigin::PersistedRuntimeArtifact,
            now_ms(),
            self.stack.service.config.name.clone(),
            ReplayArtifactView {
                preview: ReplayPreview::from_bundle(&lookup.bundle),
                record: lookup.record,
                bundle: lookup.bundle,
            },
        ))
    }

    /// Load an investigation bundle through one stable identifier.
    pub fn investigation_lookup(
        &self,
        selector: InvestigationLookupSelector<'_>,
    ) -> Result<ControlEnvelope<InvestigationArtifactView>, ControlError> {
        let (lookup_label, lookup) = match selector {
            InvestigationLookupSelector::InvestigationId(investigation_id) => (
                format!("investigation_id:{investigation_id}"),
                self.stack
                    .investigation_by_investigation_id(investigation_id)?,
            ),
            InvestigationLookupSelector::HuntId(hunt_id) => (
                format!("hunt_id:{hunt_id}"),
                self.stack.investigation_by_hunt_id(hunt_id)?,
            ),
            InvestigationLookupSelector::ReceiptId(receipt_id) => (
                format!("receipt_id:{receipt_id}"),
                self.stack.investigation_by_receipt_id(receipt_id)?,
            ),
        };

        let lookup = lookup.ok_or(ControlError::NotFound {
            entity: "investigation bundle",
            lookup: lookup_label,
        })?;
        Ok(ControlEnvelope::new(
            ControlDataOrigin::PersistedRuntimeArtifact,
            now_ms(),
            self.stack.service.config.name.clone(),
            InvestigationArtifactView {
                record: lookup.record,
                bundle: lookup.bundle,
            },
        ))
    }

    /// Load an incident through one stable identifier.
    pub fn incident_lookup(
        &self,
        selector: IncidentLookupSelector<'_>,
    ) -> Result<ControlEnvelope<IncidentArtifactView>, ControlError> {
        let (lookup_label, lookup) = match selector {
            IncidentLookupSelector::IncidentId(incident_id) => (
                format!("incident_id:{incident_id}"),
                self.stack.incident_by_incident_id(incident_id)?,
            ),
            IncidentLookupSelector::HuntId(hunt_id) => (
                format!("hunt_id:{hunt_id}"),
                self.stack.incident_by_hunt_id(hunt_id)?,
            ),
        };

        let lookup = lookup.ok_or(ControlError::NotFound {
            entity: "incident",
            lookup: lookup_label,
        })?;
        Ok(ControlEnvelope::new(
            ControlDataOrigin::PersistedRuntimeArtifact,
            now_ms(),
            self.stack.service.config.name.clone(),
            IncidentArtifactView {
                record: lookup.record,
                incident: lookup.incident,
            },
        ))
    }
}

/// Render control output in a concise human-readable format.
pub fn render_output(output: &OperatorControlOutput) -> String {
    match output {
        OperatorControlOutput::Status(envelope) => render_status(envelope),
        OperatorControlOutput::Readiness(envelope) => render_readiness(envelope),
        OperatorControlOutput::FirstRun(envelope) => render_first_run(envelope),
        OperatorControlOutput::PlaybookPreview(envelope) => render_playbook_preview(envelope),
        OperatorControlOutput::Replay(envelope) => render_replay(envelope),
        OperatorControlOutput::Investigation(envelope) => render_investigation(envelope),
        OperatorControlOutput::Incident(envelope) => render_incident(envelope),
    }
}

pub fn build_composite_detector(
    config: &DetectionConfig,
) -> Result<CompositeDetector, ControlError> {
    validate_all_detector_profiles(config)?;
    let detectors = config
        .active_strategies()
        .into_iter()
        .map(|strategy| build_single_detector(strategy.as_str(), config))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CompositeDetector::new(detectors))
}

fn build_single_detector(
    strategy_name: &str,
    config: &DetectionConfig,
) -> Result<Box<dyn DetectionStrategy>, ControlError> {
    Ok(Box::new(
        build_detector_from_strategy(strategy_name, config).map_err(|error| match error {
            DetectorFactoryError::DetectorProfile(source) => ControlError::DetectorProfile(source),
            DetectorFactoryError::UnsupportedDetector { strategy } => {
                ControlError::UnsupportedDetector { strategy }
            }
        })?,
    ))
}

fn guided_first_run_config(
    config: &SwarmConfig,
    voter_signing_key_env: &str,
) -> Result<SwarmConfig, FirstRunWizardError> {
    let voter_secret = std::env::var(voter_signing_key_env)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| FirstRunWizardError::MissingVoterSigningKey {
            env_name: voter_signing_key_env.to_string(),
        })?;
    let voter = Ed25519Signer::from_secret_material(&voter_secret);
    let mut guided = config.clone();
    guided.runtime.demo_mode = true;
    guided.runtime.mode = RuntimeMode::LiveResponse;
    guided.runtime.require_durable_live_response = false;
    guided.policy.human_gate_severity = Severity::Low;
    guided.response_adapter = swarm_core::config::ResponseAdapterConfig::Sandbox;
    guided.investigation.enabled = true;
    guided.correlation.enabled = true;
    guided.operator.auth.operator_id = format!("swarm:ed25519:{}", voter.public_key_hex());
    Ok(guided)
}

fn render_status(envelope: &ControlEnvelope<OperatorStatusReport>) -> String {
    let report = &envelope.data;
    let mut lines = vec![
        "Swarm Team Six Operator Status".to_string(),
        format!("Schema version: {}", envelope.schema_version),
        format!("Origin: {}", origin_label(envelope.origin)),
        format!("Config: {}", envelope.config_name),
        format!("Mode: {:?}", report.mode),
        format!(
            "Degradation: level={} ingest={} detection={} live_response={} writes={}",
            report.degradation.level.as_str(),
            report.degradation.capabilities.accepts_ingest,
            report.degradation.capabilities.allows_detection,
            report.degradation.capabilities.allows_live_response,
            report.degradation.capabilities.allows_artifact_writes
        ),
        format!(
            "Recent decisions: {} | warnings: {}",
            report.recent_decisions.len(),
            report.warnings.len()
        ),
        format!(
            "Latest hot-path decision: {}",
            format_timestamp(report.freshness.latest_hot_path_decision_at_ms)
        ),
        format!(
            "Async lane: status={} queued={} running={} remaining={} investigations={} incidents={}",
            report.async_lane.status.as_str(),
            report.async_lane.queued_jobs,
            report.async_lane.running_jobs,
            report.async_lane.queue_budget_remaining,
            report.async_lane.recent_investigations,
            report.async_lane.recent_incidents
        ),
    ];

    if !report.degradation.triggers.is_empty() {
        lines.push(format!(
            "Degradation summary: {}",
            report.degradation.summary
        ));
        for trigger in &report.degradation.triggers {
            lines.push(format!(
                "Degradation trigger: [{}] {}",
                serde_json::to_string(&trigger.kind)
                    .unwrap_or_else(|_| "\"unknown\"".to_string())
                    .trim_matches('"'),
                trigger.details
            ));
        }
    }

    if let Some(reason) = &report.async_lane.last_failure_reason {
        lines.push(format!("Async lane last failure: {reason}"));
    }

    if let Some(review) = &report.investigation_review {
        lines.push(format!(
            "Investigation queue: enabled={} queued={} completed={} failed={}",
            review.queue.enabled,
            review.queue.queued_jobs,
            review.queue.completed_jobs,
            review.queue.failed_jobs
        ));
    } else {
        lines.push("Investigation queue: unavailable".to_string());
    }

    if let Some(review) = &report.incident_review {
        lines.push(format!("Recent incidents: {}", review.recent.len()));
    } else {
        lines.push("Recent incidents: unavailable".to_string());
    }

    lines.push(format!(
        "False-positive tracking: reviewed={} false_positive={} rate={:.3}",
        report.false_positive_tracking.reviewed_findings,
        report.false_positive_tracking.false_positive_findings,
        report.false_positive_tracking.false_positive_rate
    ));
    if let Some(detector) = report.false_positive_tracking.detectors.first() {
        lines.push(format!(
            "Top detector FP: {} {}/{} ({:.3})",
            detector.strategy_id,
            detector.false_positive_findings,
            detector.reviewed_findings,
            detector.false_positive_rate
        ));
    }
    if let Some(host) = report.false_positive_tracking.hosts.first() {
        lines.push(format!(
            "Top host FP: {} {}/{} ({:.3})",
            host.host_id,
            host.false_positive_findings,
            host.reviewed_findings,
            host.false_positive_rate
        ));
    }
    lines.push(format!(
        "Alert tuning: recommendations={}",
        report.alert_tuning.recommendation_count
    ));
    if let Some(recommendation) = report.alert_tuning.recommendations.first() {
        lines.push(format!(
            "Top tuning recommendation: [{}] {}",
            recommendation.priority.as_str(),
            recommendation.summary
        ));
    }

    if let Some(bridges) = &report.bridges {
        lines.push(format!(
            "Bridges: configured={} ok={} degraded={} idle={}",
            bridges.configured, bridges.ok, bridges.degraded, bridges.idle
        ));
    }

    if let Some(providence) = &report.providence {
        lines.push(format!(
            "Providence: status={} reachable={} authenticated={} accepting_writes={}",
            providence.status,
            providence.reachable,
            providence.authenticated,
            providence.accepting_writes
        ));
    }

    if let Some(evolution) = &report.evolution {
        lines.push(format!(
            "Evolution: generation={} population={}/{} drift={} best={} mean={} verify_pass={:.3} admit_rate={:.3}",
            evolution.generation_count,
            evolution.population.current_population_size,
            evolution.population.configured_population_size,
            evolution
                .kitten_state
                .map(|state| state.as_str())
                .unwrap_or("unknown"),
            evolution
                .population
                .best_fitness
                .map(|value| format!("{value:.3}"))
                .unwrap_or_else(|| "n/a".to_string()),
            evolution
                .population
                .mean_fitness
                .map(|value| format!("{value:.3}"))
                .unwrap_or_else(|| "n/a".to_string()),
            evolution.verification.pass_rate,
            evolution.admission.canary_admission_rate
        ));
    }

    if !report.warnings.is_empty() {
        lines.push("Warnings:".to_string());
        for warning in &report.warnings {
            lines.push(format!("- {warning}"));
        }
    }

    lines.join("\n")
}

fn render_readiness(envelope: &ControlEnvelope<ReadinessDiagnosticReport>) -> String {
    let report = &envelope.data;
    let mut lines = vec![
        "Swarm Team Six Readiness Diagnostic".to_string(),
        format!("Schema version: {}", envelope.schema_version),
        format!("Origin: {}", origin_label(envelope.origin)),
        format!("Config: {}", envelope.config_name),
        format!("Mode: {:?}", report.mode),
        format!("Ready: {}", report.ready),
        format!(
            "Telemetry: {}/{} ready",
            report.telemetry.ready_sources, report.telemetry.configured_sources
        ),
    ];

    for entry in &report.telemetry.entries {
        lines.push(format!(
            "- telemetry {} [{}] {}: {}",
            entry.name, entry.transport, entry.status, entry.details
        ));
    }

    lines.push(format!(
        "Detectors: {}/{} ready",
        report
            .detectors
            .entries
            .iter()
            .filter(|entry| entry.ready)
            .count(),
        report.detectors.entries.len()
    ));
    for entry in &report.detectors.entries {
        lines.push(format!(
            "- detector {}: {}",
            entry.strategy,
            if entry.ready {
                format!("ready ({})", entry.details)
            } else {
                format!("failed ({})", entry.details)
            }
        ));
    }

    lines.push(format!(
        "Substrate: {} durable={} required={}",
        report.substrate.backend, report.substrate.durable, report.substrate.durable_required
    ));
    lines.push(format!("Substrate details: {}", report.substrate.details));

    if !report.warnings.is_empty() {
        lines.push("Warnings:".to_string());
        for warning in &report.warnings {
            lines.push(format!("- {warning}"));
        }
    }

    if !report.blocking_failures.is_empty() {
        lines.push("Blocking failures:".to_string());
        for failure in &report.blocking_failures {
            lines.push(format!("- {failure}"));
        }
    }

    lines.join("\n")
}

fn render_first_run(envelope: &ControlEnvelope<FirstRunDiagnosticReport>) -> String {
    let report = &envelope.data;
    let mut lines = vec![
        "Swarm Team Six First-Run Wizard".to_string(),
        format!("Schema version: {}", envelope.schema_version),
        format!("Origin: {}", origin_label(envelope.origin)),
        format!("Config: {}", envelope.config_name),
        format!("Status: {:?}", report.status),
        format!("Readiness passed: {}", report.readiness.ready),
        format!(
            "Telemetry ready: {}/{}",
            report.readiness.telemetry.ready_sources, report.readiness.telemetry.configured_sources
        ),
    ];

    if !report.readiness.blocking_failures.is_empty() {
        lines.push("Blocking failures:".to_string());
        for failure in &report.readiness.blocking_failures {
            lines.push(format!("- {failure}"));
        }
    }

    if let Some(walkthrough) = &report.walkthrough {
        lines.push(format!("Scenario: {}", walkthrough.scenario_name));
        lines.push(format!("Run: {}", walkthrough.run_id));
        if let Some(approval_set_id) = walkthrough.artifacts.approval_set_id.as_deref() {
            lines.push(format!("Approval set: {approval_set_id}"));
        }
        if let Some(receipt_pack_id) = walkthrough.artifacts.receipt_pack_id.as_deref() {
            lines.push(format!("Receipt pack: {receipt_pack_id}"));
        }
        if let Some(incident_id) = walkthrough.artifacts.incident_id.as_deref() {
            lines.push(format!("Incident: {incident_id}"));
        }
        if let Some(proof_root) = walkthrough.artifacts.proof_merkle_root.as_deref() {
            lines.push(format!("Proof Merkle root: {proof_root}"));
        }
        lines.push("Walkthrough steps:".to_string());
        for step in &walkthrough.steps {
            lines.push(format!(
                "- {} [{}] {}",
                step.name, step.status, step.details
            ));
        }
    }

    lines.join("\n")
}

fn render_playbook_preview(envelope: &ControlEnvelope<ResponsePlaybookPreviewReport>) -> String {
    let report = &envelope.data;
    let mut lines = vec![
        "Swarm Team Six Playbook Preview".to_string(),
        format!("Schema version: {}", envelope.schema_version),
        format!("Origin: {}", origin_label(envelope.origin)),
        format!("Config: {}", envelope.config_name),
        format!(
            "Configured runtime mode: {:?}",
            report.configured_runtime_mode
        ),
        format!(
            "Preview context: mode={} threat_class={} severity={} confidence={:.3}",
            serialized_value_label(&report.request.mode),
            serialized_value_label(&report.request.threat_class),
            serialized_value_label(&report.request.severity),
            report.request.confidence
        ),
        format!("Status: {}", serialized_value_label(&report.status)),
        format!(
            "Approval summary: allow={} require_human={} deny={}",
            report.approval_summary.allow_count,
            report.approval_summary.require_human_count,
            report.approval_summary.deny_count
        ),
    ];

    if let Some(matched) = &report.matched_rule {
        lines.push(format!(
            "Matched rule: #{} threat_class={} severity={} confidence={:.3}..{:.3}",
            matched.rule_index,
            serialized_value_label(&matched.threat_class),
            serialized_value_label(&matched.severity),
            matched.min_confidence,
            matched.max_confidence
        ));
        match &matched.branch {
            Some(branch) => lines.push(format!(
                "Matched branch: #{} {}",
                branch.index,
                branch.name.clone().unwrap_or_else(|| "unnamed".to_string())
            )),
            None => lines.push("Matched branch: fallback actions".to_string()),
        }
    } else {
        lines.push("Matched rule: none".to_string());
    }

    for action in &report.actions {
        lines.push(format!(
            "Action {}: {}",
            action.order + 1,
            action.action.kind()
        ));
        lines.push(format!(
            "Policy: {} [{}] {}",
            serialized_value_label(&action.policy.verdict),
            action.policy.rule_name,
            action.policy.reason
        ));
        if let Some(scope) = &action.policy.lease_scope {
            lines.push(format!("Lease scope: {scope}"));
        }
        lines.push(format!(
            "Blast radius: {}",
            action.rehearsal.blast_radius.summary
        ));
        lines.push(format!(
            "Rollback: required={} {}",
            action.rehearsal.rollback.required, action.rehearsal.rollback.summary
        ));
    }

    if !report.notes.is_empty() {
        lines.push("Notes:".to_string());
        for note in &report.notes {
            lines.push(format!("- {note}"));
        }
    }

    lines.join("\n")
}

fn render_replay(envelope: &ControlEnvelope<ReplayArtifactView>) -> String {
    let view = &envelope.data;
    [
        "Swarm Team Six Replay Bundle".to_string(),
        format!("Schema version: {}", envelope.schema_version),
        format!("Origin: {}", origin_label(envelope.origin)),
        format!("Config: {}", envelope.config_name),
        format!("Bundle: {}", view.record.bundle_id),
        format!("Hunt: {}", view.record.hunt_id),
        format!("Response: {}", view.record.response_kind),
        format!("Action: {}", view.record.action_kind),
        format!("Note: {}", view.preview.note),
    ]
    .join("\n")
}

fn render_investigation(envelope: &ControlEnvelope<InvestigationArtifactView>) -> String {
    let view = &envelope.data;
    [
        "Swarm Team Six Investigation Bundle".to_string(),
        format!("Schema version: {}", envelope.schema_version),
        format!("Origin: {}", origin_label(envelope.origin)),
        format!("Config: {}", envelope.config_name),
        format!("Investigation: {}", view.record.investigation_id),
        format!("Hunt: {}", view.record.hunt_id),
        format!("Status: {:?}", view.record.status),
        format!(
            "Summary: {}",
            view.record
                .summary_preview
                .clone()
                .unwrap_or_else(|| "none".to_string())
        ),
    ]
    .join("\n")
}

fn render_incident(envelope: &ControlEnvelope<IncidentArtifactView>) -> String {
    let view = &envelope.data;
    [
        "Swarm Team Six Incident".to_string(),
        format!("Schema version: {}", envelope.schema_version),
        format!("Origin: {}", origin_label(envelope.origin)),
        format!("Config: {}", envelope.config_name),
        format!("Incident: {}", view.record.incident_id),
        format!(
            "Created: {}",
            format_timestamp(Some(view.record.created_at_ms))
        ),
        format!(
            "Included hunts: {}",
            view.record.included_hunt_ids.join(", ")
        ),
        format!("Summary: {}", view.record.summary),
    ]
    .join("\n")
}

fn origin_label(origin: ControlDataOrigin) -> &'static str {
    match origin {
        ControlDataOrigin::LiveRuntimeStatus => "live_runtime_status",
        ControlDataOrigin::PersistedRuntimeArtifact => "persisted_runtime_artifact",
        ControlDataOrigin::OfflineReplayArtifact => "offline_replay_artifact",
        ControlDataOrigin::ConfigDiagnostic => "config_diagnostic",
        ControlDataOrigin::GuidedFirstRun => "guided_first_run",
        ControlDataOrigin::PlaybookDryRun => "playbook_dry_run",
    }
}

fn serialized_value_label<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "\"unknown\"".to_string())
        .trim_matches('"')
        .to_string()
}

async fn telemetry_readiness_from_config(config: &SwarmConfig) -> TelemetryReadinessReport {
    let mut entries = Vec::new();
    let http_client = Client::new();

    for source in &config.runtime.telemetry_sources {
        entries.push(probe_telemetry_source(&http_client, source).await);
    }

    TelemetryReadinessReport {
        ready: !entries.is_empty() && entries.iter().all(|entry| entry.ready),
        configured_sources: entries.len(),
        ready_sources: entries.iter().filter(|entry| entry.ready).count(),
        entries,
    }
}

async fn probe_telemetry_source(
    http_client: &Client,
    source: &swarm_core::config::TelemetrySourceConfig,
) -> TelemetrySourceReadiness {
    match source.bridge.as_ref() {
        None => {
            let subject = source.subject.trim();
            if subject.is_empty() {
                TelemetrySourceReadiness {
                    name: source.name.clone(),
                    transport: "subject".to_string(),
                    ready: false,
                    status: "missing".to_string(),
                    details: "telemetry source must define either a subject or bridge".to_string(),
                }
            } else {
                TelemetrySourceReadiness {
                    name: source.name.clone(),
                    transport: "subject".to_string(),
                    ready: true,
                    status: "configured".to_string(),
                    details: format!("subject `{subject}` is configured"),
                }
            }
        }
        Some(TelemetryBridgeConfig::CloudTrail { config }) => {
            match CloudTrailBridge::from_config(config) {
                Ok(_) => TelemetrySourceReadiness {
                    name: source.name.clone(),
                    transport: "cloud_trail".to_string(),
                    ready: true,
                    status: "validated".to_string(),
                    details: format!("readable CloudTrail source `{}`", config.source.path),
                },
                Err(error) => TelemetrySourceReadiness {
                    name: source.name.clone(),
                    transport: "cloud_trail".to_string(),
                    ready: false,
                    status: "invalid".to_string(),
                    details: error.to_string(),
                },
            }
        }
        Some(TelemetryBridgeConfig::GenericJson { config }) => {
            match GenericJsonBridge::from_config(config) {
                Ok(_) => TelemetrySourceReadiness {
                    name: source.name.clone(),
                    transport: "generic_json".to_string(),
                    ready: true,
                    status: "validated".to_string(),
                    details: format!(
                        "readable JSON source `{}` with a valid field mapping",
                        config.source.path
                    ),
                },
                Err(error) => TelemetrySourceReadiness {
                    name: source.name.clone(),
                    transport: "generic_json".to_string(),
                    ready: false,
                    status: "invalid".to_string(),
                    details: error.to_string(),
                },
            }
        }
        Some(TelemetryBridgeConfig::Sentinel { config }) => {
            match probe_http_endpoint(http_client, &config.endpoint, config.scrape_timeout_ms).await
            {
                Ok(details) => TelemetrySourceReadiness {
                    name: source.name.clone(),
                    transport: "sentinel".to_string(),
                    ready: true,
                    status: "reachable".to_string(),
                    details,
                },
                Err(details) => TelemetrySourceReadiness {
                    name: source.name.clone(),
                    transport: "sentinel".to_string(),
                    ready: false,
                    status: "unreachable".to_string(),
                    details,
                },
            }
        }
        Some(TelemetryBridgeConfig::Tetragon { config }) => {
            match probe_socket_endpoint(&config.endpoint, config.event_timeout_secs * 1_000).await {
                Ok(details) => TelemetrySourceReadiness {
                    name: source.name.clone(),
                    transport: "tetragon".to_string(),
                    ready: true,
                    status: "reachable".to_string(),
                    details,
                },
                Err(details) => TelemetrySourceReadiness {
                    name: source.name.clone(),
                    transport: "tetragon".to_string(),
                    ready: false,
                    status: "unreachable".to_string(),
                    details,
                },
            }
        }
    }
}

async fn probe_http_endpoint(
    client: &Client,
    url: &str,
    timeout_ms: u64,
) -> Result<String, String> {
    let response = client
        .get(url)
        .timeout(std::time::Duration::from_millis(timeout_ms.max(250)))
        .send()
        .await
        .map_err(|error| format!("HTTP probe failed: {error}"))?;
    let status = response.status();
    if status.is_success() {
        Ok(format!("HTTP probe returned {}", status.as_u16()))
    } else {
        Err(format!("HTTP probe returned {}", status.as_u16()))
    }
}

async fn probe_socket_endpoint(endpoint: &str, timeout_ms: u64) -> Result<String, String> {
    let url = reqwest::Url::parse(endpoint)
        .map_err(|error| format!("invalid endpoint URL `{endpoint}`: {error}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| format!("endpoint URL `{endpoint}` is missing a host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| format!("endpoint URL `{endpoint}` is missing a port"))?;
    tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms.max(250)),
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    .map_err(|_| format!("TCP probe to {host}:{port} timed out"))?
    .map(|_| format!("TCP probe reached {host}:{port}"))
    .map_err(|error| format!("TCP probe failed: {error}"))
}

fn detector_readiness_from_config(
    config: &SwarmConfig,
    runtime: &crate::SwarmRuntime<
        swarm_policy::configurable_gate::ConfigurableApprovalGate,
        swarm_response::DispatchingExecutor,
    >,
) -> DetectorReadinessReport {
    let active_strategies = config.detection.active_strategies();
    let entries = active_strategies
        .iter()
        .map(|strategy| probe_detector_activation(config, runtime, strategy))
        .collect::<Vec<_>>();
    DetectorReadinessReport {
        ready: !entries.is_empty() && entries.iter().all(|entry| entry.ready),
        active_strategies,
        entries,
    }
}

fn probe_detector_activation(
    config: &SwarmConfig,
    runtime: &crate::SwarmRuntime<
        swarm_policy::configurable_gate::ConfigurableApprovalGate,
        swarm_response::DispatchingExecutor,
    >,
    strategy: &str,
) -> DetectorActivationReadiness {
    if strategy == KILL_CHAIN_SEQUENCE_STRATEGY_ID {
        return match kill_chain_sequence_profile(&config.detection)
            .map_err(|error| error.to_string())
            .and_then(|profile| {
                KillChainSequenceDetector::from_profile(
                    strategy,
                    profile,
                    runtime.temporal_event_window(),
                )
                .map(|_| ())
                .map_err(|error| error.to_string())
            }) {
            Ok(()) => DetectorActivationReadiness {
                strategy: strategy.to_string(),
                ready: true,
                details: "sequence rules loaded successfully".to_string(),
            },
            Err(details) => DetectorActivationReadiness {
                strategy: strategy.to_string(),
                ready: false,
                details,
            },
        };
    }

    match build_detector_from_strategy(strategy, &config.detection) {
        Ok(detector) => DetectorActivationReadiness {
            strategy: strategy.to_string(),
            ready: true,
            details: format!("detector `{}` built successfully", detector.id()),
        },
        Err(error) => DetectorActivationReadiness {
            strategy: strategy.to_string(),
            ready: false,
            details: error.to_string(),
        },
    }
}

async fn substrate_readiness_from_stack(
    stack: &ConfiguredRuntimeStack<
        swarm_policy::configurable_gate::ConfigurableApprovalGate,
        swarm_response::DispatchingExecutor,
        SummaryInvestigator,
    >,
) -> SubstrateReadinessReport {
    let durable_required = stack.service.config.runtime.mode == RuntimeMode::LiveResponse
        && stack.service.config.runtime.require_durable_live_response;
    match stack.substrate.health().await {
        Ok(health) => {
            let ready = health.ready && (!durable_required || health.durable);
            let details = if !health.ready {
                format!(
                    "backend `{}` reported not ready: {}",
                    health.backend, health.details
                )
            } else if durable_required && !health.durable {
                format!(
                    "backend `{}` is healthy but not durable enough for live response",
                    health.backend
                )
            } else {
                health.details
            };
            SubstrateReadinessReport {
                ready,
                backend: health.backend,
                durable: health.durable,
                durable_required,
                details,
            }
        }
        Err(error) => SubstrateReadinessReport {
            ready: false,
            backend: "unknown".to_string(),
            durable: false,
            durable_required,
            details: error.to_string(),
        },
    }
}

fn format_timestamp(timestamp_ms: Option<i64>) -> String {
    match timestamp_ms {
        Some(value) => value.to_string(),
        None => "none".to_string(),
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        CURRENT_OPERATOR_API_SCHEMA_VERSION, ControlDataOrigin, DefaultControlPlane,
        FirstRunStatus, FirstRunWizardOptions, FirstRunWizardPaths, IncidentLookupSelector,
        InvestigationLookupSelector, OperatorControlOutput, ReplayLookupSelector, render_output,
    };
    use crate::RuntimeMode;
    use crate::escalation::ConcentrationMonitor;
    use crate::service::{EventExecutionContext, ResponsePlaybookPreviewRequest};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::agent::SwarmMode;
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, CanaryConfig, CorrelationConfig, InvestigationConfig,
        PheromoneBackendConfig, PheromoneConfig, PolicyConfig, PolicyRuleConfig,
        PolicyRuleDecision, PromotionConfig, ResponseAdapterConfig, ResponsePlaybookBranch,
        ResponsePlaybookCondition, ResponsePlaybookConfig, ResponsePlaybookRule, RuntimeSettings,
        SwarmConfig, TelemetrySourceConfig,
    };
    use swarm_core::pheromone::{
        ThreatClass, ThreatClassConfig, ThreatIntelEntry, ThreatIntelIndicatorType,
    };
    use swarm_core::types::{AgentId, ProvidenceFeedbackAction, ResponseAction, Severity};
    use swarm_crypto::Ed25519Signer;
    use swarm_pheromone::PheromoneSubstrate;
    use swarm_policy::ApprovalContext;
    use swarm_spine::{
        CorrelatedIncident, FalsePositiveMeasurement, IncidentMemberDecision, IncidentStore,
    };
    use swarm_whisker::{ProcessStartEvent, TelemetryEvent, TelemetryPayload};

    fn unique_temp_dir(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("swarm-runtime-control-{label}-{suffix}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn first_run_options(root: &std::path::Path) -> FirstRunWizardOptions {
        FirstRunWizardOptions {
            scenario_path: None,
            pace_ms: 0,
            voter_signing_key_env: "SWARM_FIRST_RUN_TEST_VOTER_KEY".to_string(),
            evidence_signer_id: "first-run-test-signer".to_string(),
            evidence_signing_key_env: "SWARM_FIRST_RUN_TEST_EVIDENCE_KEY".to_string(),
            paths: FirstRunWizardPaths {
                approval_verdict_results_dir: root.join("approval-verdicts"),
                approval_receipt_pack_results_dir: root.join("approval-receipt-packs"),
                approval_set_results_dir: root.join("approval-sets"),
                approval_ledger_results_dir: root.join("approval-ledgers"),
            },
        }
    }

    fn permissive_policy_rules() -> Vec<PolicyRuleConfig> {
        vec![PolicyRuleConfig {
            name: "control-test-allow-execution".to_string(),
            decision: PolicyRuleDecision::Allow,
            threat_class: ThreatClass::Execution,
            actions: Vec::new(),
            min_severity: Severity::Low,
            max_severity: Severity::Critical,
            time_window_utc: None,
            max_actions_per_agent_per_minute: None,
            reason: Some("control-plane tests allow execution responses".to_string()),
        }]
    }

    fn branching_playbook() -> ResponsePlaybookConfig {
        ResponsePlaybookConfig {
            rules: vec![ResponsePlaybookRule {
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                min_confidence: 0.90,
                max_confidence: 1.0,
                actions: vec![ResponseAction::Escalate {
                    summary: "fallback execution review".to_string(),
                    urgency: Severity::High,
                }],
                branches: vec![ResponsePlaybookBranch {
                    name: Some("incident_containment".to_string()),
                    when: ResponsePlaybookCondition {
                        min_confidence: Some(0.97),
                        modes: vec![SwarmMode::Incident],
                        ..ResponsePlaybookCondition::default()
                    },
                    actions: vec![
                        ResponseAction::BlockEgress {
                            target: "203.0.113.10".to_string(),
                        },
                        ResponseAction::IsolateHost {
                            host_id: "host-1".to_string(),
                        },
                    ],
                }],
            }],
        }
    }

    fn control_config() -> SwarmConfig {
        SwarmConfig {
            schema_version: 1,
            name: "control-test".to_string(),
            description: "control surface test config".to_string(),
            runtime: RuntimeSettings {
                mode: RuntimeMode::LiveResponse,
                demo_mode: false,
                telemetry_sources: vec![TelemetrySourceConfig {
                    name: "synthetic".to_string(),
                    subject: "telemetry.synthetic.process".to_string(),
                    bridge: None,
                }],
                max_in_flight_actions: 4,
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
            detection: swarm_core::config::DetectionConfig {
                strategy: "suspicious_process_tree".to_string(),
                strategies: Vec::new(),
                high_confidence_threshold: 0.9,
                medium_confidence_threshold: 0.7,
                profiles: swarm_core::config::DetectorProfilesConfig::default(),
            },
            pheromone: PheromoneConfig {
                default_half_life_secs: 3600.0,
                evaporation_threshold: 0.01,
                min_sources_for_escalation: 2,
                alert_threshold: 2.0,
                incident_threshold: 5.0,
                deescalation_cooldown_secs: 300,
                response_playbook: branching_playbook(),
                backend: PheromoneBackendConfig::InMemory,
            },
            policy: PolicyConfig {
                human_gate_severity: Severity::High,
                lease_ttl_ms: 60_000,
                rules: permissive_policy_rules(),
                ..PolicyConfig::default()
            },
            response_adapter: ResponseAdapterConfig::Sandbox,
            siem_forward: None,
            notification_channels: std::collections::BTreeMap::new(),
            notification_routing: swarm_core::config::NotificationRoutingConfig::default(),
            audit: AuditConfig {
                bundle_store: BundleStoreConfig::Memory,
                recent_decisions_limit: 10,
            },
            investigation: InvestigationConfig {
                enabled: true,
                worker_count: 1,
                max_pending_jobs: 4,
                time_budget_ms: 250,
                bundle_store: BundleStoreConfig::Memory,
                ..InvestigationConfig::default()
            },
            correlation: CorrelationConfig {
                enabled: true,
                time_window_ms: 10_000,
                min_shared_keys: 1,
                candidate_limit: 16,
                incident_store: BundleStoreConfig::Memory,
            },
            canary: CanaryConfig::default(),
            promotion: PromotionConfig::default(),
            evolution: swarm_core::config::EvolutionConfig::default(),
            deception: swarm_core::config::DeceptionConfig::default(),
            memory: swarm_core::config::MemoryConfig::default(),
            identity: swarm_core::config::IdentityConfig::default(),
            platform_api: Default::default(),
            operator: swarm_core::config::OperatorSurfaceConfig::default(),
            tls: None,
        }
    }

    fn event(event_id: &str, command_line: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: command_line.to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    fn context(now_ms: i64) -> ApprovalContext {
        ApprovalContext {
            live_mode: true,
            receipt_chain: vec![format!("receipt-upstream-{now_ms}")],
            correlation_id: None,
            now_ms,
        }
    }

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
    }

    fn test_agent_id() -> AgentId {
        AgentId::from_verifying_key(&test_signing_key().verifying_key())
    }

    fn signing_material_for(label: &str) -> (ed25519_dalek::SigningKey, AgentId) {
        let mut seed = [0u8; 32];
        seed[0] = label
            .as_bytes()
            .iter()
            .fold(0u8, |acc, byte| acc.wrapping_add(*byte));
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        (signing_key, agent_id)
    }

    fn measured_incident(
        incident_id: &str,
        hunt_id: &str,
        host_id: &str,
        strategy_id: &str,
        false_positive: bool,
        created_at_ms: i64,
    ) -> CorrelatedIncident {
        CorrelatedIncident {
            incident_id: incident_id.to_string(),
            summary: format!("incident for {hunt_id}"),
            created_at_ms,
            window_start_ms: created_at_ms,
            window_end_ms: created_at_ms + 1,
            correlation_keys: vec![format!("host:{host_id}")],
            related_receipt_ids: vec![format!("receipt:{hunt_id}")],
            included_members: vec![IncidentMemberDecision {
                investigation_id: format!("investigation:{hunt_id}"),
                hunt_id: hunt_id.to_string(),
                finding_id: format!("finding:{hunt_id}"),
                reason: "control false-positive fixture".to_string(),
                shared_keys: vec![format!("host:{host_id}")],
                evidence_links: Vec::new(),
                confidence_score: 1.0,
            }],
            rejected_members: Vec::new(),
            graph_dimensions: Vec::new(),
            confidence_score: 1.0,
            trigger_event_id: Some(hunt_id.to_string()),
            trigger_finding_id: Some(format!("finding:{hunt_id}")),
            trigger_strategy_id: Some(strategy_id.to_string()),
            threat_class: Some(ThreatClass::Execution),
            severity: Some(Severity::High),
            external_references: Vec::new(),
            providence_reconciliation: None,
            providence_callback_audit_entries: Vec::new(),
            feedback_audit_entries: Vec::new(),
            false_positive_measurements: vec![FalsePositiveMeasurement {
                finding_id: format!("finding:{hunt_id}"),
                hunt_id: hunt_id.to_string(),
                strategy_id: strategy_id.to_string(),
                host_id: Some(host_id.to_string()),
                feedback_id: format!("feedback:{hunt_id}"),
                reviewed_at_ms: created_at_ms + 10,
                analyst_id: "analyst-control".to_string(),
                action: if false_positive {
                    ProvidenceFeedbackAction::Dismiss
                } else {
                    ProvidenceFeedbackAction::Confirm
                },
                reason: Some("operator review fixture".to_string()),
                false_positive,
            }],
        }
    }

    #[tokio::test]
    async fn status_output_uses_live_runtime_origin() {
        let plane = DefaultControlPlane::from_config("inline", control_config()).unwrap();
        let signing_key = test_signing_key();
        let agent_id = test_agent_id();

        let _ = plane
            .stack
            .process_event(
                &swarm_whisker::SuspiciousProcessTreeDetector::default(),
                &event("evt-control-1", "powershell.exe -enc AAA="),
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context(1_700_000_000_001),
                    signing_key: &signing_key,
                },
                |_finding| {
                    Some(swarm_core::types::ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let _ = plane.stack.correlate_hunt("evt-control-1").unwrap();

        let status = plane.status().await.unwrap();
        assert_eq!(status.origin, ControlDataOrigin::LiveRuntimeStatus);
        assert_eq!(status.schema_version, CURRENT_OPERATOR_API_SCHEMA_VERSION);
        assert_eq!(status.data.recent_decisions.len(), 1);
        assert!(status.data.investigation_review.is_some());
        assert!(status.data.incident_review.is_some());
        assert_eq!(status.data.degradation.level.as_str(), "full");
        assert!(status.data.degradation.triggers.is_empty());

        let rendered = render_output(&OperatorControlOutput::Status(Box::new(status.clone())));
        assert!(rendered.contains("Schema version: 1"));
        assert!(rendered.contains("Origin: live_runtime_status"));
        assert!(rendered.contains("Degradation: level=full"));
        assert!(rendered.contains("Async lane: status="));

        let json = serde_json::to_string(&OperatorControlOutput::Status(Box::new(status))).unwrap();
        assert!(json.contains("\"schema_version\":1"));
        assert!(json.contains("\"origin\":\"live_runtime_status\""));
        assert!(json.contains("\"degradation\""));
    }

    #[tokio::test]
    async fn status_output_surfaces_detect_only_degradation_contract() {
        let mut config = control_config();
        config.runtime.mode = RuntimeMode::DetectOnly;
        let plane = DefaultControlPlane::from_config("inline", config).unwrap();

        let status = plane.status().await.unwrap();
        assert_eq!(status.data.degradation.level.as_str(), "detect_only");
        assert!(
            status
                .data
                .degradation
                .triggers
                .iter()
                .any(|trigger| trigger.details.contains("configured runtime mode"))
        );

        let rendered = render_output(&OperatorControlOutput::Status(Box::new(status.clone())));
        assert!(rendered.contains("Degradation: level=detect_only"));
        assert!(
            rendered.contains("Degradation summary: runtime is limited to detect-only execution")
        );

        let json = serde_json::to_string(&OperatorControlOutput::Status(Box::new(status))).unwrap();
        assert!(json.contains("\"level\":\"detect_only\""));
    }

    #[tokio::test]
    async fn status_output_surfaces_false_positive_tracking() {
        let plane = DefaultControlPlane::from_config("inline", control_config()).unwrap();
        plane
            .stack
            .incident_store
            .persist(&measured_incident(
                "incident-fp-dismiss",
                "hunt-fp-dismiss",
                "host-dismiss",
                "suspicious_process_tree",
                true,
                1_700_000_100_000,
            ))
            .unwrap();
        plane
            .stack
            .incident_store
            .persist(&measured_incident(
                "incident-fp-confirm",
                "hunt-fp-confirm",
                "host-confirm",
                "suspicious_process_tree",
                false,
                1_700_000_100_100,
            ))
            .unwrap();

        let status = plane.status().await.unwrap();
        assert_eq!(status.data.false_positive_tracking.reviewed_findings, 2);
        assert_eq!(
            status.data.false_positive_tracking.false_positive_findings,
            1
        );
        assert_eq!(status.data.false_positive_tracking.false_positive_rate, 0.5);
        assert_eq!(
            status.data.false_positive_tracking.detectors[0].strategy_id,
            "suspicious_process_tree"
        );
        let rendered = render_output(&OperatorControlOutput::Status(Box::new(status.clone())));
        assert!(
            rendered.contains("False-positive tracking: reviewed=2 false_positive=1 rate=0.500")
        );
        assert!(rendered.contains("Top detector FP: suspicious_process_tree 1/2 (0.500)"));
        let json = serde_json::to_string(&OperatorControlOutput::Status(Box::new(status))).unwrap();
        assert!(json.contains("\"false_positive_tracking\""));
    }

    #[tokio::test]
    async fn status_output_surfaces_alert_tuning_recommendations() {
        let plane = DefaultControlPlane::from_config("inline", control_config()).unwrap();
        for (incident_id, hunt_id, host_id, false_positive, created_at_ms) in [
            (
                "incident-fp-a-1",
                "hunt-fp-a-1",
                "host-a",
                true,
                1_700_000_101_000,
            ),
            (
                "incident-fp-a-2",
                "hunt-fp-a-2",
                "host-a",
                true,
                1_700_000_101_100,
            ),
            (
                "incident-fp-b-1",
                "hunt-fp-b-1",
                "host-b",
                true,
                1_700_000_101_200,
            ),
            (
                "incident-fp-c-1",
                "hunt-fp-c-1",
                "host-c",
                false,
                1_700_000_101_300,
            ),
            (
                "incident-fp-d-1",
                "hunt-fp-d-1",
                "host-d",
                false,
                1_700_000_101_400,
            ),
        ] {
            plane
                .stack
                .incident_store
                .persist(&measured_incident(
                    incident_id,
                    hunt_id,
                    host_id,
                    "suspicious_process_tree",
                    false_positive,
                    created_at_ms,
                ))
                .unwrap();
        }

        let status = plane.status().await.unwrap();
        assert_eq!(status.data.alert_tuning.recommendation_count, 2);
        assert!(
            status
                .data
                .alert_tuning
                .recommendations
                .iter()
                .any(|entry| {
                    entry.host_id.as_deref() == Some("host-a")
                        && entry.summary.contains("scoped exclusion")
                })
        );
        assert!(
            status
                .data
                .alert_tuning
                .recommendations
                .iter()
                .any(|entry| {
                    entry.strategy_id.as_deref() == Some("suspicious_process_tree")
                        && entry.summary.contains("thresholding")
                })
        );
        let rendered = render_output(&OperatorControlOutput::Status(Box::new(status.clone())));
        assert!(rendered.contains("Alert tuning: recommendations=2"));
        assert!(rendered.contains("Top tuning recommendation:"));
        let json = serde_json::to_string(&OperatorControlOutput::Status(Box::new(status))).unwrap();
        assert!(json.contains("\"alert_tuning\""));
    }

    #[tokio::test]
    async fn lookup_outputs_resolve_stable_ids_and_persisted_origin() {
        let plane = DefaultControlPlane::from_config("inline", control_config()).unwrap();
        let signing_key = test_signing_key();
        let agent_id = test_agent_id();

        let processed = plane
            .stack
            .process_event(
                &swarm_whisker::SuspiciousProcessTreeDetector::default(),
                &event("evt-control-2", "powershell.exe -enc BBB="),
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context(1_700_000_000_002),
                    signing_key: &signing_key,
                },
                |_finding| {
                    Some(swarm_core::types::ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let incident = plane
            .stack
            .correlate_hunt("evt-control-2")
            .unwrap()
            .unwrap();
        let receipt_id = processed.replay.record.response_receipt_id.clone().unwrap();
        let investigation_id = processed.investigation.clone().unwrap().investigation_id;

        let replay = plane
            .replay_lookup(ReplayLookupSelector::ReceiptId(&receipt_id))
            .unwrap();
        let investigation = plane
            .investigation_lookup(InvestigationLookupSelector::InvestigationId(
                &investigation_id,
            ))
            .unwrap();
        let incident = plane
            .incident_lookup(IncidentLookupSelector::IncidentId(
                &incident.record.incident_id,
            ))
            .unwrap();

        assert_eq!(replay.origin, ControlDataOrigin::PersistedRuntimeArtifact);
        assert_eq!(
            investigation.origin,
            ControlDataOrigin::PersistedRuntimeArtifact
        );
        assert_eq!(incident.origin, ControlDataOrigin::PersistedRuntimeArtifact);
        assert_eq!(replay.data.record.hunt_id, "evt-control-2");
        assert_eq!(investigation.data.record.hunt_id, "evt-control-2");
        assert_eq!(
            incident.data.record.included_hunt_ids,
            vec!["evt-control-2"]
        );

        let rendered = render_output(&OperatorControlOutput::Replay(Box::new(replay)));
        assert!(rendered.contains("Origin: persisted_runtime_artifact"));
    }

    #[tokio::test]
    async fn readiness_reports_subject_sources_and_detector_activation() {
        let plane = DefaultControlPlane::from_config("inline", control_config()).unwrap();

        let readiness = plane.readiness().await.unwrap();
        assert_eq!(readiness.origin, ControlDataOrigin::ConfigDiagnostic);
        assert_eq!(
            readiness.schema_version,
            CURRENT_OPERATOR_API_SCHEMA_VERSION
        );
        assert!(readiness.data.ready);
        assert_eq!(readiness.data.telemetry.configured_sources, 1);
        assert_eq!(readiness.data.telemetry.entries[0].status, "configured");
        assert!(readiness.data.detectors.ready);
        assert!(readiness.data.substrate.ready);
        assert_eq!(readiness.data.blocking_failures.len(), 0);
        assert!(!readiness.data.warnings.is_empty());

        let rendered = render_output(&OperatorControlOutput::Readiness(Box::new(
            readiness.clone(),
        )));
        assert!(rendered.contains("Swarm Team Six Readiness Diagnostic"));
        assert!(rendered.contains("Schema version: 1"));
        assert!(rendered.contains("Origin: config_diagnostic"));

        let json =
            serde_json::to_string(&OperatorControlOutput::Readiness(Box::new(readiness))).unwrap();
        assert!(json.contains("\"kind\":\"readiness\""));
        assert!(json.contains("\"schema_version\":1"));
    }

    #[tokio::test]
    async fn readiness_reports_blocking_failures_for_missing_telemetry() {
        let mut config = control_config();
        config.runtime.telemetry_sources.clear();
        let plane = DefaultControlPlane::from_config("inline", config).unwrap();

        let readiness = plane.readiness().await.unwrap();
        assert!(!readiness.data.ready);
        assert_eq!(readiness.data.telemetry.configured_sources, 0);
        assert!(
            readiness
                .data
                .blocking_failures
                .iter()
                .any(|failure| failure.contains("no telemetry sources"))
        );
    }

    #[tokio::test]
    async fn first_run_reports_blocked_when_readiness_fails() {
        let mut config = control_config();
        config.runtime.telemetry_sources.clear();
        let plane = DefaultControlPlane::from_config("inline", config).unwrap();
        let temp_dir = unique_temp_dir("first-run-blocked");

        let report = plane.first_run(first_run_options(&temp_dir)).await.unwrap();
        assert_eq!(report.origin, ControlDataOrigin::GuidedFirstRun);
        assert_eq!(report.schema_version, CURRENT_OPERATOR_API_SCHEMA_VERSION);
        assert_eq!(report.data.status, FirstRunStatus::Blocked);
        assert!(report.data.walkthrough.is_none());
        assert!(
            report
                .data
                .readiness
                .blocking_failures
                .iter()
                .any(|failure| failure.contains("no telemetry sources"))
        );

        let rendered = render_output(&OperatorControlOutput::FirstRun(Box::new(report)));
        assert!(rendered.contains("Swarm Team Six First-Run Wizard"));
        assert!(rendered.contains("Schema version: 1"));
        assert!(rendered.contains("Origin: guided_first_run"));
    }

    #[tokio::test]
    async fn first_run_completes_detection_approval_and_proof() {
        unsafe {
            std::env::set_var("SWARM_FIRST_RUN_TEST_VOTER_KEY", "first-run-vote-key");
            std::env::set_var(
                "SWARM_FIRST_RUN_TEST_EVIDENCE_KEY",
                "first-run-evidence-key",
            );
        }

        let mut config = control_config();
        let voter = Ed25519Signer::from_secret_material("first-run-vote-key");
        config.runtime.mode = RuntimeMode::DetectOnly;
        config.investigation.enabled = false;
        config.correlation.enabled = false;
        config.operator.auth.operator_id = format!("swarm:ed25519:{}", voter.public_key_hex());
        let plane = DefaultControlPlane::from_config("inline", config).unwrap();
        let temp_dir = unique_temp_dir("first-run-complete");

        let report = plane.first_run(first_run_options(&temp_dir)).await.unwrap();
        assert_eq!(report.origin, ControlDataOrigin::GuidedFirstRun);
        assert_eq!(report.schema_version, CURRENT_OPERATOR_API_SCHEMA_VERSION);
        assert_eq!(report.data.status, FirstRunStatus::Completed);
        let walkthrough = report.data.walkthrough.as_ref().unwrap();
        assert_eq!(walkthrough.injected_events, 1);
        assert!(walkthrough.artifacts.approval_set_id.is_some());
        assert!(walkthrough.artifacts.receipt_pack_id.is_some());
        assert!(walkthrough.artifacts.incident_id.is_some());
        assert!(walkthrough.artifacts.proof_merkle_root.is_some());
        assert_eq!(
            walkthrough.proof.final_incident.incident_id,
            walkthrough.artifacts.incident_id.clone().unwrap()
        );
        assert!(
            walkthrough
                .run
                .timeline
                .iter()
                .any(|entry| entry.stage == "approval_paused")
        );
        assert!(
            walkthrough
                .run
                .timeline
                .iter()
                .any(|entry| entry.stage == "approval_resumed")
        );

        let rendered = render_output(&OperatorControlOutput::FirstRun(Box::new(report.clone())));
        assert!(rendered.contains("Schema version: 1"));
        assert!(rendered.contains("Origin: guided_first_run"));
        assert!(rendered.contains("Receipt pack:"));

        let json =
            serde_json::to_string(&OperatorControlOutput::FirstRun(Box::new(report))).unwrap();
        assert!(json.contains("\"kind\":\"first_run\""));
        assert!(json.contains("\"schema_version\":1"));
        assert!(json.contains("\"status\":\"completed\""));
    }

    #[tokio::test]
    async fn playbook_preview_renders_branch_and_policy_summary() {
        let plane = DefaultControlPlane::from_config("inline", control_config()).unwrap();

        let preview = plane
            .playbook_preview(ResponsePlaybookPreviewRequest {
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                confidence: 0.98,
                mode: SwarmMode::Incident,
            })
            .unwrap();

        assert_eq!(preview.origin, ControlDataOrigin::PlaybookDryRun);
        assert_eq!(preview.schema_version, CURRENT_OPERATOR_API_SCHEMA_VERSION);
        assert_eq!(preview.data.actions.len(), 2);
        assert_eq!(preview.data.approval_summary.allow_count, 2);
        assert_eq!(
            preview
                .data
                .matched_rule
                .as_ref()
                .and_then(|matched| matched.branch.as_ref())
                .and_then(|branch| branch.name.as_deref()),
            Some("incident_containment")
        );

        let rendered = render_output(&OperatorControlOutput::PlaybookPreview(Box::new(
            preview.clone(),
        )));
        assert!(rendered.contains("Swarm Team Six Playbook Preview"));
        assert!(rendered.contains("Schema version: 1"));
        assert!(rendered.contains("Origin: playbook_dry_run"));
        assert!(rendered.contains("Matched branch: #0 incident_containment"));
        assert!(rendered.contains("Approval summary: allow=2 require_human=0 deny=0"));

        let json =
            serde_json::to_string(&OperatorControlOutput::PlaybookPreview(Box::new(preview)))
                .unwrap();
        assert!(json.contains("\"kind\":\"playbook_preview\""));
        assert!(json.contains("\"schema_version\":1"));
        assert!(json.contains("\"origin\":\"playbook_dry_run\""));
    }

    #[tokio::test]
    async fn stored_threat_class_config_is_visible_to_live_runtime_without_restart() {
        let plane = DefaultControlPlane::from_config("inline", control_config()).unwrap();
        plane
            .store_threat_class_config(ThreatClassConfig {
                threat_class: ThreatClass::Execution,
                half_life_secs: 3600.0,
                evaporation_threshold: 0.01,
                alert_threshold: 1.5,
                incident_threshold: 5.0,
            })
            .await
            .unwrap();

        let substrate = Arc::new(plane.stack.substrate.clone());
        for agent in ["agent-a", "agent-b"] {
            let (signing_key, agent_id) = signing_material_for(agent);
            let mut deposit = swarm_core::pheromone::PheromoneDeposit {
                schema_version: swarm_core::pheromone::PheromoneDeposit::current_schema_version(),
                indicator: serde_json::json!({"signal": "execution"}),
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                confidence: 0.8,
                timestamp: 1_700_000_000,
                decay_half_life: 3600.0,
                agent_id: agent_id.clone(),
                agent_identity: agent_id.0.clone(),
                agent_role: None,
                signature: Vec::new(),
                agent_key: Vec::new(),
            };
            let payload = swarm_pheromone::DepositSigningPayload {
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
            let payload_bytes = serde_json::to_vec(&payload).unwrap();
            let sig = ed25519_dalek::Signer::sign(&signing_key, &payload_bytes);
            deposit.signature = sig.to_bytes().to_vec();
            deposit.agent_key = signing_key.verifying_key().to_bytes().to_vec();
            substrate.deposit(deposit).await.unwrap();
        }

        let mut monitor =
            ConcentrationMonitor::new(control_config().pheromone.clone(), Arc::clone(&substrate));
        let outcome = monitor.evaluate_all(1_700_000_000).await.unwrap();
        assert_eq!(outcome.current_mode, swarm_core::agent::SwarmMode::Alert);
    }

    #[tokio::test]
    async fn stored_threat_intel_entry_is_visible_to_live_query_without_restart() {
        let plane = DefaultControlPlane::from_config("inline", control_config()).unwrap();
        plane
            .store_threat_intel_entry(ThreatIntelEntry {
                indicator_type: ThreatIntelIndicatorType::Domain,
                value: " Example.COM. ".to_string(),
                confidence: 0.94,
                expires_at: 1_700_000_000_100,
            })
            .await
            .unwrap();

        let stored = plane
            .query_threat_intel_entry(
                ThreatIntelIndicatorType::Domain,
                "example.com",
                1_700_000_000_000,
            )
            .await
            .unwrap();
        assert_eq!(stored.origin, ControlDataOrigin::PersistedRuntimeArtifact);
        assert_eq!(stored.data.as_ref().unwrap().value, "example.com");
        assert_eq!(stored.data.as_ref().unwrap().confidence, 0.94);

        let expired = plane
            .query_threat_intel_entry(
                ThreatIntelIndicatorType::Domain,
                "example.com",
                1_700_000_000_100,
            )
            .await
            .unwrap();
        assert!(expired.data.is_none());
    }
}
