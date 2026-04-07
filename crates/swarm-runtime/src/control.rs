use crate::config::{
    DetectorProfileError, RuntimeConfigError, credential_access_profile, dns_exfiltration_profile,
    lateral_movement_profile, load_config, persistence_profile, supply_chain_profile,
    suspicious_process_tree_profile, suspicious_scripting_profile,
};
use crate::investigation::SummaryInvestigator;
use crate::service::{ConfiguredRuntimeStack, OperatorStatusReport, ServiceError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::DetectionConfig;
use swarm_core::pheromone::{ThreatClassConfig, ThreatIntelEntry, ThreatIntelIndicatorType};
use swarm_pheromone::{PheromoneSubstrate, SubstrateError};
use swarm_response::{
    DeadLetterEntry, DispatchingExecutor, NotificationError, NotificationReplayResult,
};
use swarm_spine::{
    CorrelatedIncident, IncidentRecord, InvestigationBundle, InvestigationBundleRecord,
    ReplayBundle, ReplayBundleRecord, ReplayPreview,
};
use swarm_whisker::{
    CredentialAccessDetector, DetectionStrategy, DnsExfiltrationDetector, LateralMovementDetector,
    PersistenceDetector, SupplyChainDetector, SuspiciousProcessTreeDetector,
    SuspiciousScriptingDetector,
};

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
pub enum SupportedDetector {
    SuspiciousProcessTree(SuspiciousProcessTreeDetector),
    DnsExfiltration(DnsExfiltrationDetector),
    LateralMovement(LateralMovementDetector),
    CredentialAccess(CredentialAccessDetector),
    SuspiciousScripting(SuspiciousScriptingDetector),
    Persistence(PersistenceDetector),
    SupplyChain(SupplyChainDetector),
}

impl DetectionStrategy for SupportedDetector {
    fn id(&self) -> &str {
        match self {
            Self::SuspiciousProcessTree(detector) => detector.id(),
            Self::DnsExfiltration(detector) => detector.id(),
            Self::LateralMovement(detector) => detector.id(),
            Self::CredentialAccess(detector) => detector.id(),
            Self::SuspiciousScripting(detector) => detector.id(),
            Self::Persistence(detector) => detector.id(),
            Self::SupplyChain(detector) => detector.id(),
        }
    }

    fn evaluate(
        &self,
        event: &swarm_whisker::TelemetryEvent,
    ) -> Vec<swarm_whisker::DetectionFinding> {
        match self {
            Self::SuspiciousProcessTree(detector) => detector.evaluate(event),
            Self::DnsExfiltration(detector) => detector.evaluate(event),
            Self::LateralMovement(detector) => detector.evaluate(event),
            Self::CredentialAccess(detector) => detector.evaluate(event),
            Self::SuspiciousScripting(detector) => detector.evaluate(event),
            Self::Persistence(detector) => detector.evaluate(event),
            Self::SupplyChain(detector) => detector.evaluate(event),
        }
    }
}

/// Default operator control plane built from repo-owned config and the shipped runtime defaults.
pub struct DefaultControlPlane {
    pub config_path: PathBuf,
    pub stack: ConfiguredRuntimeStack<
        swarm_policy::static_gate::StaticApprovalGate,
        DispatchingExecutor,
        SummaryInvestigator,
    >,
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
        let detector = supported_detector(&config.detection)?;
        let stack = ConfiguredRuntimeStack::from_config(config, SummaryInvestigator)?;

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

    /// List persisted threat-class pheromone policy records from the configured substrate.
    pub async fn threat_class_configs(
        &self,
    ) -> Result<ControlEnvelope<Vec<ThreatClassConfig>>, ControlError> {
        let configs = self.stack.substrate.query_threat_class_configs().await?;
        Ok(ControlEnvelope {
            origin: ControlDataOrigin::PersistedRuntimeArtifact,
            generated_at_ms: now_ms(),
            config_name: self.stack.service.config.name.clone(),
            data: configs,
        })
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
        Ok(ControlEnvelope {
            origin: ControlDataOrigin::PersistedRuntimeArtifact,
            generated_at_ms: now_ms(),
            config_name: self.stack.service.config.name.clone(),
            data: config,
        })
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
        Ok(ControlEnvelope {
            origin: ControlDataOrigin::PersistedRuntimeArtifact,
            generated_at_ms: now_ms(),
            config_name: self.stack.service.config.name.clone(),
            data: entry,
        })
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
        Ok(ControlEnvelope {
            origin: ControlDataOrigin::PersistedRuntimeArtifact,
            generated_at_ms: now_ms(),
            config_name: self.stack.service.config.name.clone(),
            data: entry,
        })
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
        Ok(ControlEnvelope {
            origin: ControlDataOrigin::PersistedRuntimeArtifact,
            generated_at_ms: now_ms(),
            config_name: self.stack.service.config.name.clone(),
            data: entries,
        })
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
        Ok(ControlEnvelope {
            origin: ControlDataOrigin::PersistedRuntimeArtifact,
            generated_at_ms: now_ms(),
            config_name: self.stack.service.config.name.clone(),
            data: results,
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

pub fn supported_detector(config: &DetectionConfig) -> Result<SupportedDetector, ControlError> {
    match config.strategy.as_str() {
        "suspicious_process_tree" => Ok(SupportedDetector::SuspiciousProcessTree(
            SuspiciousProcessTreeDetector::from_profile(suspicious_process_tree_profile(config)?)
                .map_err(|source| DetectorProfileError::Validation {
                strategy: "suspicious_process_tree",
                source,
            })?,
        )),
        "dns_exfiltration" => Ok(SupportedDetector::DnsExfiltration(
            DnsExfiltrationDetector::from_profile(dns_exfiltration_profile(config)?).map_err(
                |source| DetectorProfileError::Validation {
                    strategy: "dns_exfiltration",
                    source,
                },
            )?,
        )),
        "lateral_movement" => Ok(SupportedDetector::LateralMovement(
            LateralMovementDetector::from_profile(lateral_movement_profile(config)?).map_err(
                |source| DetectorProfileError::Validation {
                    strategy: "lateral_movement",
                    source,
                },
            )?,
        )),
        "credential_access" => Ok(SupportedDetector::CredentialAccess(
            CredentialAccessDetector::from_profile(credential_access_profile(config)?).map_err(
                |source| DetectorProfileError::Validation {
                    strategy: "credential_access",
                    source,
                },
            )?,
        )),
        "suspicious_scripting" => Ok(SupportedDetector::SuspiciousScripting(
            SuspiciousScriptingDetector::from_profile(suspicious_scripting_profile(config)?)
                .map_err(|source| DetectorProfileError::Validation {
                    strategy: "suspicious_scripting",
                    source,
                })?,
        )),
        "persistence" => Ok(SupportedDetector::Persistence(
            PersistenceDetector::from_profile(persistence_profile(config)?).map_err(|source| {
                DetectorProfileError::Validation {
                    strategy: "persistence",
                    source,
                }
            })?,
        )),
        "supply_chain" => Ok(SupportedDetector::SupplyChain(
            SupplyChainDetector::from_profile(supply_chain_profile(config)?).map_err(|source| {
                DetectorProfileError::Validation {
                    strategy: "supply_chain",
                    source,
                }
            })?,
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

    if let Some(bridges) = &report.bridges {
        lines.push(format!(
            "Bridges: configured={} ok={} degraded={} idle={}",
            bridges.configured, bridges.ok, bridges.degraded, bridges.idle
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        ControlDataOrigin, DefaultControlPlane, IncidentLookupSelector,
        InvestigationLookupSelector, OperatorControlOutput, ReplayLookupSelector, render_output,
    };
    use crate::RuntimeMode;
    use crate::escalation::ConcentrationMonitor;
    use crate::service::EventExecutionContext;
    use std::sync::Arc;
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, CanaryConfig, CorrelationConfig, InvestigationConfig,
        PheromoneBackendConfig, PheromoneConfig, PolicyConfig, PromotionConfig,
        ResponseAdapterConfig, RuntimeSettings, SwarmConfig, TelemetrySourceConfig,
    };
    use swarm_core::pheromone::{
        ThreatClass, ThreatClassConfig, ThreatIntelEntry, ThreatIntelIndicatorType,
    };
    use swarm_core::types::{AgentId, Severity};
    use swarm_pheromone::PheromoneSubstrate;
    use swarm_policy::ApprovalContext;
    use swarm_whisker::{ProcessStartEvent, TelemetryEvent, TelemetryPayload};

    fn control_config() -> SwarmConfig {
        SwarmConfig {
            schema_version: 1,
            name: "control-test".to_string(),
            description: "control surface test config".to_string(),
            runtime: RuntimeSettings {
                mode: RuntimeMode::LiveResponse,
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
            },
            detection: swarm_core::config::DetectionConfig {
                strategy: "suspicious_process_tree".to_string(),
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
                backend: PheromoneBackendConfig::InMemory,
            },
            policy: PolicyConfig {
                human_gate_severity: Severity::High,
                lease_ttl_ms: 60_000,
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
            operator: swarm_core::config::OperatorSurfaceConfig::default(),
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
            substrate
                .deposit(swarm_core::pheromone::PheromoneDeposit {
                    indicator: serde_json::json!({"signal": "execution"}),
                    threat_class: ThreatClass::Execution,
                    severity: Severity::High,
                    confidence: 0.8,
                    timestamp: 1_700_000_000,
                    decay_half_life: 3600.0,
                    agent_id: AgentId(agent.to_string()),
                    signature: Vec::new(),
                    agent_key: Vec::new(),
                })
                .await
                .unwrap();
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
