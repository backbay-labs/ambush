use crate::config::{RuntimeConfigError, load_config};
use crate::investigation::SummaryInvestigator;
use crate::service::{ConfiguredRuntimeStack, OperatorStatusReport, ServiceError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_response::adapters::SandboxExecutor;
use swarm_spine::{
    CorrelatedIncident, IncidentRecord, InvestigationBundle, InvestigationBundleRecord,
    ReplayBundle, ReplayBundleRecord, ReplayPreview,
};
use swarm_whisker::{DetectionStrategy, SuspiciousProcessTreeDetector};

/// Errors surfaced by the repo-owned operator control surface.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    Service(#[from] ServiceError),

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
}

/// Serializable wrapper around one control-surface payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEnvelope<T> {
    pub origin: ControlDataOrigin,
    pub generated_at_ms: i64,
    pub config_name: String,
    pub data: T,
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
    Replay(Box<ControlEnvelope<ReplayArtifactView>>),
    Investigation(Box<ControlEnvelope<InvestigationArtifactView>>),
    Incident(Box<ControlEnvelope<IncidentArtifactView>>),
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

#[derive(Debug, Clone)]
enum SupportedDetector {
    SuspiciousProcessTree(SuspiciousProcessTreeDetector),
}

impl DetectionStrategy for SupportedDetector {
    fn id(&self) -> &str {
        match self {
            Self::SuspiciousProcessTree(detector) => detector.id(),
        }
    }

    fn evaluate(
        &self,
        event: &swarm_whisker::TelemetryEvent,
    ) -> Vec<swarm_whisker::DetectionFinding> {
        match self {
            Self::SuspiciousProcessTree(detector) => detector.evaluate(event),
        }
    }
}

/// Default operator control plane built from repo-owned config and the shipped runtime defaults.
pub struct DefaultControlPlane {
    pub config_path: PathBuf,
    pub stack: ConfiguredRuntimeStack<StaticApprovalGate, SandboxExecutor, SummaryInvestigator>,
    detector: SupportedDetector,
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
        let detector = supported_detector(&config.detection.strategy)?;
        let stack = ConfiguredRuntimeStack::from_components(
            config,
            StaticApprovalGate::default(),
            SandboxExecutor,
            SummaryInvestigator,
        )?;

        Ok(Self {
            config_path: config_path.into(),
            stack,
            detector,
        })
    }

    /// Read the current operator review surface from the configured runtime stack.
    pub async fn status(&self) -> Result<ControlEnvelope<OperatorStatusReport>, ControlError> {
        let report = self.stack.operator_review_status(&self.detector).await?;
        Ok(ControlEnvelope {
            origin: ControlDataOrigin::LiveRuntimeStatus,
            generated_at_ms: now_ms(),
            config_name: self.stack.service.config.name.clone(),
            data: report,
        })
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
        Ok(ControlEnvelope {
            origin: ControlDataOrigin::PersistedRuntimeArtifact,
            generated_at_ms: now_ms(),
            config_name: self.stack.service.config.name.clone(),
            data: ReplayArtifactView {
                preview: ReplayPreview::from_bundle(&lookup.bundle),
                record: lookup.record,
                bundle: lookup.bundle,
            },
        })
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
        Ok(ControlEnvelope {
            origin: ControlDataOrigin::PersistedRuntimeArtifact,
            generated_at_ms: now_ms(),
            config_name: self.stack.service.config.name.clone(),
            data: InvestigationArtifactView {
                record: lookup.record,
                bundle: lookup.bundle,
            },
        })
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
        Ok(ControlEnvelope {
            origin: ControlDataOrigin::PersistedRuntimeArtifact,
            generated_at_ms: now_ms(),
            config_name: self.stack.service.config.name.clone(),
            data: IncidentArtifactView {
                record: lookup.record,
                incident: lookup.incident,
            },
        })
    }
}

/// Render control output in a concise human-readable format.
pub fn render_output(output: &OperatorControlOutput) -> String {
    match output {
        OperatorControlOutput::Status(envelope) => render_status(envelope),
        OperatorControlOutput::Replay(envelope) => render_replay(envelope),
        OperatorControlOutput::Investigation(envelope) => render_investigation(envelope),
        OperatorControlOutput::Incident(envelope) => render_incident(envelope),
    }
}

fn supported_detector(strategy: &str) -> Result<SupportedDetector, ControlError> {
    match strategy {
        "suspicious_process_tree" => Ok(SupportedDetector::SuspiciousProcessTree(
            SuspiciousProcessTreeDetector::default(),
        )),
        other => Err(ControlError::UnsupportedDetector {
            strategy: other.to_string(),
        }),
    }
}

fn render_status(envelope: &ControlEnvelope<OperatorStatusReport>) -> String {
    let report = &envelope.data;
    let mut lines = vec![
        "Swarm Team Six Operator Status".to_string(),
        format!("Origin: {}", origin_label(envelope.origin)),
        format!("Config: {}", envelope.config_name),
        format!("Mode: {:?}", report.mode),
        format!(
            "Recent decisions: {} | warnings: {}",
            report.recent_decisions.len(),
            report.warnings.len()
        ),
        format!(
            "Latest hot-path decision: {}",
            format_timestamp(report.freshness.latest_hot_path_decision_at_ms)
        ),
    ];

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

    if !report.warnings.is_empty() {
        lines.push("Warnings:".to_string());
        for warning in &report.warnings {
            lines.push(format!("- {warning}"));
        }
    }

    lines.join("\n")
}

fn render_replay(envelope: &ControlEnvelope<ReplayArtifactView>) -> String {
    let view = &envelope.data;
    [
        "Swarm Team Six Replay Bundle".to_string(),
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
mod tests {
    use super::{
        ControlDataOrigin, DefaultControlPlane, IncidentLookupSelector,
        InvestigationLookupSelector, OperatorControlOutput, ReplayLookupSelector, render_output,
    };
    use crate::RuntimeMode;
    use crate::service::EventExecutionContext;
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, CorrelationConfig, InvestigationConfig,
        PheromoneBackendConfig, PheromoneConfig, PolicyConfig, RuntimeSettings, SwarmConfig,
        TelemetrySourceConfig,
    };
    use swarm_core::types::{AgentId, Severity};
    use swarm_policy::ApprovalContext;
    use swarm_whisker::{ProcessStartEvent, TelemetryEvent, TelemetryPayload};

    fn control_config() -> SwarmConfig {
        SwarmConfig {
            name: "control-test".to_string(),
            description: "control surface test config".to_string(),
            runtime: RuntimeSettings {
                mode: RuntimeMode::LiveResponse,
                telemetry_sources: vec![TelemetrySourceConfig {
                    name: "synthetic".to_string(),
                    subject: "telemetry.synthetic.process".to_string(),
                }],
                max_in_flight_actions: 4,
                require_durable_live_response: false,
            },
            detection: swarm_core::config::DetectionConfig {
                strategy: "suspicious_process_tree".to_string(),
                high_confidence_threshold: 0.9,
                medium_confidence_threshold: 0.7,
            },
            pheromone: PheromoneConfig {
                default_half_life_secs: 3600.0,
                evaporation_threshold: 0.01,
                min_sources_for_escalation: 2,
                alert_threshold: 2.0,
                incident_threshold: 5.0,
                backend: PheromoneBackendConfig::InMemory,
            },
            policy: PolicyConfig {
                human_gate_severity: Severity::High,
                lease_ttl_ms: 60_000,
            },
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
            },
            correlation: CorrelationConfig {
                enabled: true,
                time_window_ms: 10_000,
                min_shared_keys: 1,
                candidate_limit: 16,
                incident_store: BundleStoreConfig::Memory,
            },
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
            }),
        }
    }

    fn context(now_ms: i64) -> ApprovalContext {
        ApprovalContext {
            live_mode: true,
            receipt_chain: vec![format!("receipt-upstream-{now_ms}")],
            now_ms,
        }
    }

    #[tokio::test]
    async fn status_output_uses_live_runtime_origin() {
        let plane = DefaultControlPlane::from_config("inline", control_config()).unwrap();
        let agent_id = AgentId("whisker-a".to_string());

        let _ = plane
            .stack
            .process_event(
                &swarm_whisker::SuspiciousProcessTreeDetector::default(),
                &event("evt-control-1", "powershell.exe -enc AAA="),
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context(1_700_000_000_001),
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
        assert_eq!(status.data.recent_decisions.len(), 1);
        assert!(status.data.investigation_review.is_some());
        assert!(status.data.incident_review.is_some());

        let rendered = render_output(&OperatorControlOutput::Status(Box::new(status.clone())));
        assert!(rendered.contains("Origin: live_runtime_status"));

        let json = serde_json::to_string(&OperatorControlOutput::Status(Box::new(status))).unwrap();
        assert!(json.contains("\"origin\":\"live_runtime_status\""));
    }

    #[tokio::test]
    async fn lookup_outputs_resolve_stable_ids_and_persisted_origin() {
        let plane = DefaultControlPlane::from_config("inline", control_config()).unwrap();
        let agent_id = AgentId("whisker-a".to_string());

        let processed = plane
            .stack
            .process_event(
                &swarm_whisker::SuspiciousProcessTreeDetector::default(),
                &event("evt-control-2", "powershell.exe -enc BBB="),
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context(1_700_000_000_002),
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
}
