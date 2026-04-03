use crate::config::RuntimeConfig;
use crate::investigation::{InvestigationCoordinator, InvestigationError, InvestigationStrategy};
use crate::pipeline::{DetectionPipelineOutcome, PipelineError, detect_and_deposit};
use crate::{RuntimeError, RuntimeMode, SwarmRuntime};
use serde::{Deserialize, Serialize};
use std::any::type_name;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use swarm_core::config::SwarmConfig;
use swarm_core::types::{AgentId, ResponseAction};
use swarm_pheromone::{PheromoneSubstrate, SubstrateError, SubstrateHealth};
use swarm_policy::ApprovalGate;
use swarm_policy::{ActionRequest, ApprovalContext};
use swarm_response::ResponseExecutor;
use swarm_spine::{
    InvestigationBundleLookup, InvestigationBundleRecord, InvestigationBundleStore, ReplayBundle,
    ReplayBundleLookup, ReplayBundleRecord, ReplayBundleStore, ReplayPreview, ReplayStoreError,
    ReplayStoreHealth,
};
use swarm_whisker::{DetectionFinding, DetectionStrategy, TelemetryEvent};

/// Errors raised by the runtime service wrapper.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error(transparent)]
    Pipeline(#[from] PipelineError),

    #[error(transparent)]
    Substrate(#[from] SubstrateError),

    #[error(transparent)]
    Runtime(#[from] RuntimeError),

    #[error(transparent)]
    ReplayStore(#[from] ReplayStoreError),

    #[error(transparent)]
    Investigation(#[from] InvestigationError),

    #[error("failed to write replay bundle `{path}`: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read replay bundle `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to serialize replay bundle: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("runtime readiness check failed for {component}: {reason}")]
    Readiness {
        component: &'static str,
        reason: String,
    },
}

/// Inputs that stay constant while processing one event through the critical lane.
pub struct EventExecutionContext<'a> {
    pub agent_id: &'a AgentId,
    pub approval: &'a ApprovalContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyBucketSnapshot {
    pub upper_bound_us: u64,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageMetricsSnapshot {
    pub successes: u64,
    pub failures: u64,
    pub total_latency_us: u64,
    pub max_latency_us: u64,
    pub average_latency_us: u64,
    pub latency_buckets: Vec<LatencyBucketSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeMetricsSnapshot {
    pub detect: StageMetricsSnapshot,
    pub policy: StageMetricsSnapshot,
    pub persist: StageMetricsSnapshot,
    pub response: StageMetricsSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub ready: bool,
    pub durable: Option<bool>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorStatusReport {
    pub mode: RuntimeMode,
    pub detector: ComponentStatus,
    pub substrate: ComponentStatus,
    pub policy: ComponentStatus,
    pub response: ComponentStatus,
    pub replay_store: ComponentStatus,
    pub metrics: RuntimeMetricsSnapshot,
    pub recent_decisions: Vec<ReplayBundleRecord>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PersistedReplayBundle {
    pub record: ReplayBundleRecord,
    pub bundle: ReplayBundle,
}

#[derive(Debug, Clone)]
pub struct PersistedReplayBundleWithInvestigation {
    pub replay: PersistedReplayBundle,
    pub investigation: Option<InvestigationBundleRecord>,
}

#[derive(Debug, Clone, Default)]
struct RuntimeMetrics {
    inner: Arc<Mutex<RuntimeMetricsInner>>,
}

#[derive(Debug, Clone, Default)]
struct RuntimeMetricsInner {
    detect: StageMetrics,
    policy: StageMetrics,
    persist: StageMetrics,
    response: StageMetrics,
}

#[derive(Debug, Clone)]
struct StageMetrics {
    successes: u64,
    failures: u64,
    total_latency_us: u64,
    max_latency_us: u64,
    bucket_counts: [u64; LATENCY_BUCKETS_US.len()],
}

impl Default for StageMetrics {
    fn default() -> Self {
        Self {
            successes: 0,
            failures: 0,
            total_latency_us: 0,
            max_latency_us: 0,
            bucket_counts: [0; LATENCY_BUCKETS_US.len()],
        }
    }
}

impl RuntimeMetrics {
    fn record(&self, stage: RuntimeStage, elapsed_us: u64, success: bool) {
        let mut guard = self.inner.lock().expect("metrics lock");
        let target = match stage {
            RuntimeStage::Detect => &mut guard.detect,
            RuntimeStage::Policy => &mut guard.policy,
            RuntimeStage::Persist => &mut guard.persist,
            RuntimeStage::Response => &mut guard.response,
        };

        if success {
            target.successes = target.successes.saturating_add(1);
        } else {
            target.failures = target.failures.saturating_add(1);
        }
        target.total_latency_us = target.total_latency_us.saturating_add(elapsed_us);
        target.max_latency_us = target.max_latency_us.max(elapsed_us);
        let bucket_index = LATENCY_BUCKETS_US
            .iter()
            .position(|upper_bound| elapsed_us <= *upper_bound)
            .unwrap_or(LATENCY_BUCKETS_US.len() - 1);
        target.bucket_counts[bucket_index] = target.bucket_counts[bucket_index].saturating_add(1);
    }

    fn snapshot(&self) -> RuntimeMetricsSnapshot {
        let guard = self.inner.lock().expect("metrics lock");
        RuntimeMetricsSnapshot {
            detect: StageMetricsSnapshot::from_metrics(&guard.detect),
            policy: StageMetricsSnapshot::from_metrics(&guard.policy),
            persist: StageMetricsSnapshot::from_metrics(&guard.persist),
            response: StageMetricsSnapshot::from_metrics(&guard.response),
        }
    }
}

impl StageMetricsSnapshot {
    fn from_metrics(metrics: &StageMetrics) -> Self {
        let total = metrics.successes + metrics.failures;
        Self {
            successes: metrics.successes,
            failures: metrics.failures,
            total_latency_us: metrics.total_latency_us,
            max_latency_us: metrics.max_latency_us,
            average_latency_us: if total == 0 {
                0
            } else {
                metrics.total_latency_us / total
            },
            latency_buckets: LATENCY_BUCKETS_US
                .iter()
                .zip(metrics.bucket_counts.iter())
                .map(|(upper_bound_us, count)| LatencyBucketSnapshot {
                    upper_bound_us: *upper_bound_us,
                    count: *count,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum RuntimeStage {
    Detect,
    Policy,
    Persist,
    Response,
}

const LATENCY_BUCKETS_US: [u64; 7] = [100, 500, 1_000, 5_000, 10_000, 50_000, u64::MAX];

/// Thin service wrapper around the first Rust-only runtime slice.
pub struct RuntimeService<P, E> {
    pub config: SwarmConfig,
    pub runtime: SwarmRuntime<P, E>,
    metrics: RuntimeMetrics,
}

impl<P, E> RuntimeService<P, E>
where
    P: ApprovalGate,
    E: ResponseExecutor,
{
    pub fn new(config: SwarmConfig, runtime: SwarmRuntime<P, E>) -> Self {
        Self {
            config,
            runtime,
            metrics: RuntimeMetrics::default(),
        }
    }

    pub fn mode(&self) -> RuntimeMode {
        self.runtime.mode()
    }

    pub fn runtime_config(&self) -> &RuntimeConfig {
        &self.config.runtime
    }

    pub async fn ensure_substrate_ready<S>(
        &self,
        substrate: &S,
    ) -> Result<SubstrateHealth, ServiceError>
    where
        S: PheromoneSubstrate,
    {
        let health = substrate.health().await?;
        if self.runtime.mode() == RuntimeMode::LiveResponse
            && self.config.runtime.require_durable_live_response
        {
            if !health.ready {
                return Err(ServiceError::Readiness {
                    component: "substrate",
                    reason: format!("backend `{}` is not ready", health.backend),
                });
            }
            if !health.durable {
                return Err(ServiceError::Readiness {
                    component: "substrate",
                    reason: format!(
                        "backend `{}` is not durable but live response requires durability",
                        health.backend
                    ),
                });
            }
        }
        Ok(health)
    }

    /// Run the full critical lane for one event and build a replay bundle.
    pub async fn process_event<D, S, F>(
        &self,
        detector: &D,
        substrate: &S,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
    ) -> Result<Option<ReplayBundle>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
    {
        let substrate_health = self.ensure_substrate_ready(substrate).await?;
        tracing::debug!(
            backend = %substrate_health.backend,
            durable = substrate_health.durable,
            ready = substrate_health.ready,
            "substrate health verified"
        );

        let detect_started = Instant::now();
        let detection_result = detect_and_deposit(
            detector,
            substrate,
            event,
            execution.agent_id,
            &self.config.pheromone,
        )
        .await;
        let detect_elapsed_us = detect_started.elapsed().as_micros() as u64;
        self.metrics.record(
            RuntimeStage::Detect,
            detect_elapsed_us,
            detection_result.is_ok(),
        );

        let DetectionPipelineOutcome {
            event,
            findings,
            deposits,
        } = detection_result?;

        let Some(primary_finding) = findings.first().cloned() else {
            tracing::info!("no findings emitted for event");
            return Ok(None);
        };

        let Some(action) = request_builder(&primary_finding) else {
            tracing::info!(event_id = %primary_finding.event_id, "no action proposed for finding");
            return Ok(None);
        };

        let request = ActionRequest {
            hunt_id: swarm_core::types::HuntId(primary_finding.event_id.clone()),
            requested_by: execution.agent_id.clone(),
            action,
            severity: primary_finding.severity,
            evidence: primary_finding.evidence.clone(),
        };
        let execution_started = Instant::now();
        let execution_result = self
            .runtime
            .audit_authorize_and_execute_instrumented(
                &primary_finding,
                &request,
                execution.approval,
            )
            .await;
        let execution_report = match execution_result {
            Ok(report) => report,
            Err(error) => {
                let elapsed_us = execution_started.elapsed().as_micros() as u64;
                self.metrics.record(RuntimeStage::Policy, elapsed_us, false);
                return Err(error.into());
            }
        };
        self.metrics.record(
            RuntimeStage::Policy,
            execution_report.policy_elapsed_us,
            true,
        );
        if let Some(response_elapsed_us) = execution_report.response_elapsed_us {
            self.metrics.record(
                RuntimeStage::Response,
                response_elapsed_us,
                execution_report.response_succeeded,
            );
        }

        Ok(Some(ReplayBundle {
            bundle_id: format!("bundle:{}:{}", request.hunt_id.0, execution.approval.now_ms),
            event,
            findings,
            deposits,
            action_request: request,
            audit: execution_report.audit,
        }))
    }

    pub fn metrics_snapshot(&self) -> RuntimeMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn persist_replay_bundle<Store>(
        &self,
        store: &Store,
        bundle: &ReplayBundle,
    ) -> Result<ReplayBundleRecord, ServiceError>
    where
        Store: ReplayBundleStore,
    {
        let started = Instant::now();
        let persisted = store.persist(bundle);
        let elapsed_us = started.elapsed().as_micros() as u64;
        self.metrics
            .record(RuntimeStage::Persist, elapsed_us, persisted.is_ok());
        let record = persisted?;
        tracing::info!(
            hunt_id = %record.hunt_id,
            trail_id = %record.trail_id,
            bundle_id = %record.bundle_id,
            response_receipt_id = ?record.response_receipt_id,
            "persisted replay bundle"
        );
        Ok(record)
    }

    pub async fn process_event_with_store<D, S, F, Store>(
        &self,
        detector: &D,
        substrate: &S,
        store: &Store,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
    ) -> Result<Option<PersistedReplayBundle>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
        Store: ReplayBundleStore,
    {
        let Some(bundle) = self
            .process_event(detector, substrate, event, execution, request_builder)
            .await?
        else {
            return Ok(None);
        };
        let record = self.persist_replay_bundle(store, &bundle)?;
        Ok(Some(PersistedReplayBundle { record, bundle }))
    }

    pub async fn process_event_with_store_and_investigation<
        D,
        S,
        F,
        Store,
        Strategy,
        InvestigationStore,
    >(
        &self,
        detector: &D,
        substrate: &S,
        store: &Store,
        investigation: &InvestigationCoordinator<Strategy, InvestigationStore>,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
    ) -> Result<Option<PersistedReplayBundleWithInvestigation>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
        Store: ReplayBundleStore,
        Strategy: InvestigationStrategy,
        InvestigationStore: InvestigationBundleStore + Clone + Send + Sync + 'static,
    {
        let Some(replay) = self
            .process_event_with_store(
                detector,
                substrate,
                store,
                event,
                execution,
                request_builder,
            )
            .await?
        else {
            return Ok(None);
        };
        let investigation_record = investigation.submit(&replay.bundle)?;
        Ok(Some(PersistedReplayBundleWithInvestigation {
            replay,
            investigation: investigation_record,
        }))
    }

    pub fn load_persisted_bundle_by_hunt_id<Store>(
        &self,
        store: &Store,
        hunt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ServiceError>
    where
        Store: ReplayBundleStore,
    {
        Ok(store.load_by_hunt_id(hunt_id)?)
    }

    pub fn load_persisted_bundle_by_receipt_id<Store>(
        &self,
        store: &Store,
        receipt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ServiceError>
    where
        Store: ReplayBundleStore,
    {
        Ok(store.load_by_receipt_id(receipt_id)?)
    }

    pub fn load_persisted_investigation_by_hunt_id<Store>(
        &self,
        store: &Store,
        hunt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, ServiceError>
    where
        Store: InvestigationBundleStore,
    {
        Ok(store
            .load_by_hunt_id(hunt_id)
            .map_err(InvestigationError::from)?)
    }

    pub fn load_persisted_investigation_by_receipt_id<Store>(
        &self,
        store: &Store,
        receipt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, ServiceError>
    where
        Store: InvestigationBundleStore,
    {
        Ok(store
            .load_by_receipt_id(receipt_id)
            .map_err(InvestigationError::from)?)
    }

    pub fn replay_preview(&self, bundle: &ReplayBundle) -> ReplayPreview {
        ReplayPreview::from_bundle(bundle)
    }

    pub async fn operator_status<D, S, Store>(
        &self,
        detector: &D,
        substrate: &S,
        store: &Store,
    ) -> Result<OperatorStatusReport, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        Store: ReplayBundleStore,
    {
        let substrate_health = substrate.health().await?;
        let replay_store_health = store.health()?;
        let mut warnings = Vec::new();
        if self.runtime.mode() == RuntimeMode::LiveResponse
            && self.config.runtime.require_durable_live_response
            && !substrate_health.durable
        {
            warnings.push("live response requires a durable substrate backend".to_string());
        }
        if !substrate_health.ready {
            warnings.push(format!(
                "substrate backend `{}` is not ready",
                substrate_health.backend
            ));
        }
        if self.runtime.mode() == RuntimeMode::LiveResponse
            && self.config.audit.bundle_store.is_durable()
            && !replay_store_health.ready
        {
            warnings.push("durable replay store is not ready".to_string());
        }

        Ok(OperatorStatusReport {
            mode: self.runtime.mode(),
            detector: ComponentStatus {
                ready: true,
                durable: None,
                details: format!("strategy `{}`", detector.id()),
            },
            substrate: component_status_from_substrate(&substrate_health),
            policy: ComponentStatus {
                ready: true,
                durable: None,
                details: type_name::<P>().to_string(),
            },
            response: ComponentStatus {
                ready: true,
                durable: None,
                details: type_name::<E>().to_string(),
            },
            replay_store: component_status_from_replay_store(&replay_store_health),
            metrics: self.metrics_snapshot(),
            recent_decisions: store.recent(self.config.audit.recent_decisions_limit)?,
            warnings,
        })
    }

    pub fn save_replay_bundle(
        &self,
        bundle: &ReplayBundle,
        path: impl AsRef<Path>,
    ) -> Result<(), ServiceError> {
        let path = path.as_ref();
        let serialized = serde_json::to_string_pretty(bundle)?;
        fs::write(path, serialized).map_err(|source| ServiceError::Write {
            path: path.display().to_string(),
            source,
        })
    }

    pub fn load_replay_bundle(&self, path: impl AsRef<Path>) -> Result<ReplayBundle, ServiceError> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(|source| ServiceError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Ok(serde_json::from_str(&raw)?)
    }
}

fn component_status_from_substrate(health: &SubstrateHealth) -> ComponentStatus {
    ComponentStatus {
        ready: health.ready,
        durable: Some(health.durable),
        details: format!("{} ({})", health.backend, health.details),
    }
}

fn component_status_from_replay_store(health: &ReplayStoreHealth) -> ComponentStatus {
    ComponentStatus {
        ready: health.ready,
        durable: Some(health.durable),
        details: format!("{} ({})", health.backend, health.details),
    }
}

#[cfg(test)]
mod tests {
    use super::{EventExecutionContext, RuntimeService};
    use crate::investigation::{InvestigationOutcome, InvestigationStrategy};
    use crate::{RuntimeMode, SwarmRuntime};
    use async_trait::async_trait;
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, InvestigationConfig, PheromoneBackendConfig,
        PheromoneConfig, PolicyConfig, RuntimeSettings, SwarmConfig, TelemetrySourceConfig,
    };
    use swarm_core::types::AgentId;
    use swarm_core::types::Severity;
    use swarm_pheromone::{InMemoryPheromoneSubstrate, LocalJournalPheromoneSubstrate};
    use swarm_policy::ApprovalContext;
    use swarm_policy::static_gate::StaticApprovalGate;
    use swarm_response::ResponseStatus;
    use swarm_response::adapters::SandboxExecutor;
    use swarm_spine::{
        AuditResponseRecord, FileReplayBundleStore, MemoryInvestigationBundleStore, ReplayBundle,
        ReplayBundleStore,
    };
    use swarm_whisker::{
        ProcessStartEvent, SuspiciousProcessTreeDetector, TelemetryEvent, TelemetryPayload,
    };

    fn service_config(
        mode: RuntimeMode,
        backend: PheromoneBackendConfig,
        require_durable: bool,
    ) -> SwarmConfig {
        SwarmConfig {
            name: "test".to_string(),
            description: "test config".to_string(),
            runtime: RuntimeSettings {
                mode,
                telemetry_sources: vec![TelemetrySourceConfig {
                    name: "synthetic".to_string(),
                    subject: "telemetry.synthetic.process".to_string(),
                }],
                max_in_flight_actions: 4,
                require_durable_live_response: require_durable,
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
                backend,
            },
            policy: PolicyConfig {
                human_gate_severity: Severity::High,
                lease_ttl_ms: 60_000,
            },
            audit: AuditConfig {
                bundle_store: BundleStoreConfig::Memory,
                recent_decisions_limit: 20,
            },
            investigation: InvestigationConfig::default(),
        }
    }

    fn runtime_service() -> RuntimeService<StaticApprovalGate, SandboxExecutor> {
        RuntimeService::new(
            service_config(
                RuntimeMode::LiveResponse,
                PheromoneBackendConfig::InMemory,
                false,
            ),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        )
    }

    #[derive(Debug, Clone)]
    struct SlowInvestigator {
        delay_ms: u64,
    }

    #[async_trait]
    impl InvestigationStrategy for SlowInvestigator {
        fn id(&self) -> &str {
            "slow_service_test_investigator"
        }

        async fn investigate(&self, replay: &ReplayBundle) -> Result<InvestigationOutcome, String> {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            Ok(InvestigationOutcome {
                summary: format!("investigated {}", replay.audit.hunt_id),
                evidence_points: vec!["host_id=host-1".to_string()],
                correlation_keys: vec!["host:host-1".to_string()],
            })
        }
    }

    #[tokio::test]
    async fn process_event_creates_and_replays_bundle() {
        let service = runtime_service();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc AAA=".to_string(),
                user: Some("alice".to_string()),
            }),
        };
        let context = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-1".to_string()],
            now_ms: 1_700_000_000_000,
        };
        let agent_id = AgentId("whisker-a".to_string());

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
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

        match &bundle.audit.response {
            AuditResponseRecord::Success(receipt) => {
                assert_eq!(receipt.status, ResponseStatus::Executed);
            }
            other => panic!("expected successful response record, got {other:?}"),
        }

        let path = std::env::temp_dir().join("swarm-runtime-replay-bundle.json");
        service.save_replay_bundle(&bundle, &path).unwrap();
        let replayed = service.load_replay_bundle(&path).unwrap();

        assert_eq!(replayed.audit.trail_id, bundle.audit.trail_id);
        assert_eq!(replayed.findings.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn live_response_requires_durable_substrate_when_enabled() {
        let service = RuntimeService::new(
            service_config(
                RuntimeMode::LiveResponse,
                PheromoneBackendConfig::InMemory,
                true,
            ),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());

        let error = service
            .ensure_substrate_ready(&substrate)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not durable but live response requires durability")
        );
    }

    #[tokio::test]
    async fn local_journal_satisfies_durable_live_response_readiness() {
        let path = std::env::temp_dir().join("swarm-runtime-durable-substrate.jsonl");
        let service = RuntimeService::new(
            service_config(
                RuntimeMode::LiveResponse,
                PheromoneBackendConfig::LocalJournal {
                    path: path.display().to_string(),
                },
                true,
            ),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let substrate =
            LocalJournalPheromoneSubstrate::open(service.config.pheromone.clone(), &path).unwrap();

        let health = service.ensure_substrate_ready(&substrate).await.unwrap();
        assert!(health.ready);
        assert!(health.durable);

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn process_event_with_store_persists_and_loads_by_receipt_id() {
        let service = runtime_service();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let store_root = std::env::temp_dir().join("swarm-runtime-file-store");
        let _ = std::fs::remove_dir_all(&store_root);
        let store = FileReplayBundleStore::open(&store_root).unwrap();
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-store-1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc AAA=".to_string(),
                user: Some("alice".to_string()),
            }),
        };
        let context = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-upstream-1".to_string()],
            now_ms: 1_700_000_000_001,
        };
        let agent_id = AgentId("whisker-a".to_string());

        let persisted = service
            .process_event_with_store(
                &detector,
                &substrate,
                &store,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
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

        let response_receipt_id = persisted
            .record
            .response_receipt_id
            .clone()
            .expect("response receipt id");
        let loaded = service
            .load_persisted_bundle_by_receipt_id(&store, &response_receipt_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.record.bundle_id, persisted.record.bundle_id);

        let preview = service.replay_preview(&loaded.bundle);
        assert_eq!(preview.bundle_id, persisted.record.bundle_id);
        assert!(
            preview
                .note
                .contains("no live response action was re-executed")
        );

        let _ = std::fs::remove_dir_all(store_root);
    }

    #[tokio::test]
    async fn operator_status_reports_metrics_and_recent_decisions() {
        let service = runtime_service();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let store_root = std::env::temp_dir().join("swarm-runtime-operator-store");
        let _ = std::fs::remove_dir_all(&store_root);
        let store = FileReplayBundleStore::open(&store_root).unwrap();
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-status-1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc AAA=".to_string(),
                user: Some("alice".to_string()),
            }),
        };
        let context = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-upstream-2".to_string()],
            now_ms: 1_700_000_000_002,
        };
        let agent_id = AgentId("whisker-a".to_string());

        let _ = service
            .process_event_with_store(
                &detector,
                &substrate,
                &store,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
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

        let status = service
            .operator_status(&detector, &substrate, &store)
            .await
            .unwrap();
        assert_eq!(status.mode, RuntimeMode::LiveResponse);
        assert_eq!(
            status.detector.details,
            "strategy `suspicious_process_tree`"
        );
        assert_eq!(status.replay_store.durable, Some(true));
        assert_eq!(status.recent_decisions.len(), 1);
        assert_eq!(status.metrics.detect.successes, 1);
        assert_eq!(status.metrics.policy.successes, 1);
        assert_eq!(status.metrics.persist.successes, 1);
        assert_eq!(status.metrics.response.successes, 1);
        assert!(status.warnings.is_empty());

        let recent = store.recent(1).unwrap();
        assert_eq!(recent.len(), 1);

        let _ = std::fs::remove_dir_all(store_root);
    }

    #[tokio::test]
    async fn process_event_with_investigation_stays_nonblocking_and_persists_bundle() {
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.investigation = InvestigationConfig {
            enabled: true,
            worker_count: 1,
            max_pending_jobs: 2,
            time_budget_ms: 250,
            bundle_store: BundleStoreConfig::Memory,
        };
        let service = RuntimeService::new(
            config.clone(),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let replay_store_root =
            std::env::temp_dir().join("swarm-runtime-investigation-replay-store");
        let _ = std::fs::remove_dir_all(&replay_store_root);
        let replay_store = FileReplayBundleStore::open(&replay_store_root).unwrap();
        let investigation_store = MemoryInvestigationBundleStore::default();
        let coordinator = crate::investigation::InvestigationCoordinator::new(
            config.investigation.clone(),
            SlowInvestigator { delay_ms: 75 },
            investigation_store.clone(),
        );
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-investigation-1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc AAA=".to_string(),
                user: Some("alice".to_string()),
            }),
        };
        let context = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-upstream-3".to_string()],
            now_ms: 1_700_000_000_003,
        };
        let agent_id = AgentId("whisker-a".to_string());

        let started = std::time::Instant::now();
        let persisted = service
            .process_event_with_store_and_investigation(
                &detector,
                &substrate,
                &replay_store,
                &coordinator,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
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
        let elapsed = started.elapsed();

        assert!(elapsed < std::time::Duration::from_millis(40));
        let investigation = persisted.investigation.expect("queued investigation");
        assert_eq!(
            investigation.status,
            swarm_spine::InvestigationStatus::Queued
        );

        tokio::time::sleep(std::time::Duration::from_millis(125)).await;

        let by_hunt = service
            .load_persisted_investigation_by_hunt_id(&investigation_store, "evt-investigation-1")
            .unwrap()
            .unwrap();
        assert_eq!(
            by_hunt.bundle.status,
            swarm_spine::InvestigationStatus::Completed
        );

        let receipt_id = persisted
            .replay
            .record
            .response_receipt_id
            .clone()
            .expect("response receipt id");
        let by_receipt = service
            .load_persisted_investigation_by_receipt_id(&investigation_store, &receipt_id)
            .unwrap()
            .unwrap();
        assert_eq!(by_receipt.bundle.hunt_id, "evt-investigation-1");
        assert!(coordinator.snapshot().completed_jobs >= 1);

        let _ = std::fs::remove_dir_all(replay_store_root);
    }
}
