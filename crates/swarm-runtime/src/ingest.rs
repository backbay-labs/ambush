use crate::bridge_runtime::{SharedBridgeHealth, bridge_health_report};
use crate::config::{
    CURRENT_SCHEMA_VERSION, RuntimeConfigError, load_config_unresolved,
    resolve_outbound_secrets, resolve_secret_dir_path,
};
use crate::control::{ControlError, SupportedDetector, supported_detector};
use crate::correlation::CorrelationEngine;
use crate::detection::metrics::{CriticalPathMetrics, encode_metrics};
use crate::dispatcher::AgentHealthEntry;
use crate::investigation::{InvestigationCoordinator, SummaryInvestigator};
use crate::service::{ConfiguredRuntimeStack, ServiceError};
use arc_swap::ArcSwap;
use axum::extract::{Json, State, rejection::JsonRejection};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, response::Json as ResponseJson};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use swarm_core::config::{ResponseAdapterConfig, RuntimeMode, SwarmConfig};
use swarm_core::types::AgentId;
use swarm_pheromone::PheromoneSubstrate;
use swarm_policy::ApprovalContext;
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_response::DispatchingExecutor;
use swarm_spine::{
    ConfiguredIncidentStore, ConfiguredInvestigationBundleStore, ConfiguredReplayBundleStore,
    ReplayBundleStore,
};
use swarm_whisker::{DetectionStrategy, TelemetryEvent};
use sysinfo::{ProcessesToUpdate, System, get_current_pid};
use tracing::Instrument;
use uuid::Uuid;

type IngestRuntimeStack =
    ConfiguredRuntimeStack<StaticApprovalGate, DispatchingExecutor, SummaryInvestigator>;

type HeapSnapshotProvider = Arc<dyn Fn() -> Option<HeapPressureSnapshot> + Send + Sync>;

#[derive(Debug, Clone, PartialEq)]
struct HeapPressureSnapshot {
    bytes: u64,
    limit_bytes: u64,
    pressure_ratio: f64,
}

#[derive(Debug, Default)]
struct IngestLifecycleState {
    draining: AtomicBool,
    active_requests: AtomicUsize,
    notify: tokio::sync::Notify,
}

impl IngestLifecycleState {
    fn begin_drain(&self) -> bool {
        !self.draining.swap(true, Ordering::SeqCst)
    }

    fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    fn active_requests(&self) -> usize {
        self.active_requests.load(Ordering::SeqCst)
    }

    fn try_begin_request(self: &Arc<Self>) -> Result<IngestRequestGuard, ()> {
        if self.is_draining() {
            return Err(());
        }
        self.active_requests.fetch_add(1, Ordering::SeqCst);
        if self.is_draining() {
            self.finish_request();
            return Err(());
        }
        Ok(IngestRequestGuard {
            lifecycle: Arc::clone(self),
        })
    }

    fn finish_request(&self) {
        if self.active_requests.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.notify.notify_waiters();
        }
    }

    async fn wait_for_zero(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.active_requests() == 0 {
                return true;
            }
            let notified = self.notify.notified();
            tokio::pin!(notified);
            if tokio::time::timeout_at(deadline, &mut notified)
                .await
                .is_err()
            {
                return self.active_requests() == 0;
            }
        }
    }
}

struct IngestRequestGuard {
    lifecycle: Arc<IngestLifecycleState>,
}

impl Drop for IngestRequestGuard {
    fn drop(&mut self) {
        self.lifecycle.finish_request();
    }
}

#[derive(Debug, Clone)]
struct DetectorRuntimeStatus {
    ready: bool,
    strategy: String,
    details: String,
}

impl DetectorRuntimeStatus {
    fn loaded(strategy: String) -> Self {
        Self {
            ready: true,
            strategy,
            details: "detector loaded".to_string(),
        }
    }

    fn reload_failed(strategy: String, error: impl ToString) -> Self {
        Self {
            ready: false,
            strategy,
            details: format!("last reload failed: {}", error.to_string()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IngestBuildError {
    #[error(transparent)]
    Control(#[from] ControlError),

    #[error(transparent)]
    Service(#[from] ServiceError),

    #[error(transparent)]
    Config(#[from] RuntimeConfigError),
}

#[derive(Clone)]
pub struct IngestState {
    stack: Arc<ArcSwap<IngestRuntimeStack>>,
    detector: Arc<ArcSwap<SupportedDetector>>,
    detector_status: Arc<ArcSwap<DetectorRuntimeStatus>>,
    config_path: Arc<PathBuf>,
    /// The config template before `@secret:` references are resolved.
    /// Stored so that [`Self::reload_secrets_only`] can re-resolve secrets
    /// from disk without re-reading or re-parsing the YAML config file.
    config_template: Arc<ArcSwap<SwarmConfig>>,
    lifecycle: Arc<IngestLifecycleState>,
    telemetry_tx: Option<tokio::sync::mpsc::Sender<TelemetryEvent>>,
    agent_dispatcher_health: Option<Arc<ArcSwap<Vec<AgentHealthEntry>>>>,
    bridge_health: Option<SharedBridgeHealth>,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    heap_snapshot_provider: HeapSnapshotProvider,
    signing_key: ed25519_dalek::SigningKey,
}

impl IngestState {
    fn build_runtime(
        config: SwarmConfig,
    ) -> Result<(Arc<IngestRuntimeStack>, Arc<SupportedDetector>), IngestBuildError> {
        let detector = Arc::new(supported_detector(&config.detection)?);
        let stack = Arc::new(ConfiguredRuntimeStack::from_config(
            config,
            SummaryInvestigator,
        )?);
        Ok((stack, detector))
    }

    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
    ) -> Result<Self, IngestBuildError> {
        let config_path = config_path.into();
        // Store the raw config before secret resolution as the template
        // so that reload_secrets_only can re-resolve from disk later.
        let template = config.clone();
        let resolved = resolve_outbound_secrets(config, Some(&config_path)).map_err(|source| {
            RuntimeConfigError::Validation {
                source_name: config_path.display().to_string(),
                source,
            }
        })?;
        let (stack, detector) = Self::build_runtime(resolved)?;
        let detector_status = Arc::new(ArcSwap::from(Arc::new(DetectorRuntimeStatus::loaded(
            detector.id().to_string(),
        ))));
        Ok(Self {
            stack: Arc::new(ArcSwap::from(stack)),
            detector: Arc::new(ArcSwap::from(detector)),
            detector_status,
            config_path: Arc::new(config_path),
            config_template: Arc::new(ArcSwap::from(Arc::new(template))),
            lifecycle: Arc::new(IngestLifecycleState::default()),
            telemetry_tx: None,
            agent_dispatcher_health: None,
            bridge_health: None,
            shutdown_tx: None,
            heap_snapshot_provider: Arc::new(sample_heap_pressure),
            signing_key: ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),
        })
    }

    pub fn from_path(config_path: impl Into<PathBuf>) -> Result<Self, IngestBuildError> {
        let config_path = config_path.into();
        let config = load_config_unresolved(&config_path)?;
        Self::from_config(config_path, config)
    }

    pub fn reload(&self, config: SwarmConfig) -> Result<(), IngestBuildError> {
        match Self::build_runtime(config) {
            Ok((stack, detector)) => {
                let strategy = detector.id().to_string();
                self.detector.store(detector);
                self.stack.store(stack);
                self.detector_status
                    .store(Arc::new(DetectorRuntimeStatus::loaded(strategy)));
                Ok(())
            }
            Err(error) => {
                let current = self.detector_status.load_full();
                self.detector_status
                    .store(Arc::new(DetectorRuntimeStatus::reload_failed(
                        current.strategy.clone(),
                        &error,
                    )));
                Err(error)
            }
        }
    }

    /// Re-resolve `@secret:` references from disk and update the active runtime
    /// stack without re-reading or re-parsing the YAML config file. This avoids
    /// the overhead of a full config reload when only secret values have rotated.
    ///
    /// The stored config template (with `@secret:` references intact) is cloned,
    /// passed through [`resolve_outbound_secrets`] to read fresh secret files,
    /// and fed to [`Self::reload`] which rebuilds the runtime stack. Because the
    /// config structure is unchanged (only secret values differ), the detector
    /// rebuild is lightweight -- same strategy, same profiles.
    pub fn reload_secrets_only(&self) -> Result<(), IngestBuildError> {
        // Clone the unresolved template -- no YAML file read, no parsing.
        let template = self.config_template.load_full();
        let config = resolve_outbound_secrets(
            template.as_ref().clone(),
            Some(self.config_path()),
        )
        .map_err(|source| RuntimeConfigError::Validation {
            source_name: self.config_path().display().to_string(),
            source,
        })?;

        self.reload(config)?;

        tracing::info!(
            module = module_path!(),
            "reloaded secrets without full config reload"
        );
        Ok(())
    }

    pub fn reload_from_disk(&self) -> Result<(), IngestBuildError> {
        // Load the unresolved template first so we can store it for
        // future reload_secrets_only calls.
        let template = match load_config_unresolved(self.config_path()) {
            Ok(config) => config,
            Err(error) => {
                let current = self.detector_status.load_full();
                self.detector_status
                    .store(Arc::new(DetectorRuntimeStatus::reload_failed(
                        current.strategy.clone(),
                        &error,
                    )));
                return Err(error.into());
            }
        };
        let resolved = resolve_outbound_secrets(template.clone(), Some(self.config_path()))
            .map_err(|source| RuntimeConfigError::Validation {
                source_name: self.config_path().display().to_string(),
                source,
            })?;
        self.config_template.store(Arc::new(template));
        self.reload(resolved)
    }

    pub fn config_path(&self) -> &Path {
        self.config_path.as_ref().as_path()
    }

    pub fn with_telemetry_channel(mut self, tx: tokio::sync::mpsc::Sender<TelemetryEvent>) -> Self {
        self.telemetry_tx = Some(tx);
        self
    }

    pub fn with_agent_health(mut self, health: Arc<ArcSwap<Vec<AgentHealthEntry>>>) -> Self {
        self.agent_dispatcher_health = Some(health);
        self
    }

    pub fn with_bridge_health(mut self, health: SharedBridgeHealth) -> Self {
        self.bridge_health = Some(health);
        self
    }

    pub fn with_shutdown_channel(mut self, tx: tokio::sync::watch::Sender<bool>) -> Self {
        self.shutdown_tx = Some(tx);
        self
    }

    #[cfg(test)]
    fn with_heap_snapshot_provider<F>(mut self, provider: F) -> Self
    where
        F: Fn() -> Option<HeapPressureSnapshot> + Send + Sync + 'static,
    {
        self.heap_snapshot_provider = Arc::new(provider);
        self
    }

    pub fn current_detector(&self) -> Arc<SupportedDetector> {
        self.detector.load_full()
    }

    pub fn current_substrate(&self) -> swarm_pheromone::ConfiguredPheromoneSubstrate {
        self.stack.load_full().substrate.clone()
    }

    pub fn current_pheromone_config(&self) -> swarm_core::config::PheromoneConfig {
        self.stack.load_full().service.config.pheromone.clone()
    }

    pub fn current_response_adapter_config(&self) -> ResponseAdapterConfig {
        self.stack.load_full().service.config.response_adapter.clone()
    }

    pub fn detector_strategy_name(&self) -> String {
        self.detector.load_full().id().to_string()
    }

    pub fn current_prometheus_metrics(&self) -> Option<CriticalPathMetrics> {
        self.stack.load_full().service.prometheus_metrics().cloned()
    }

    pub fn current_replay_store(&self) -> ConfiguredReplayBundleStore {
        self.stack.load_full().replay_store.clone()
    }

    pub fn current_investigation(
        &self,
    ) -> InvestigationCoordinator<SummaryInvestigator, ConfiguredInvestigationBundleStore> {
        self.stack.load_full().investigation.clone()
    }

    pub fn current_investigation_store(&self) -> ConfiguredInvestigationBundleStore {
        self.stack.load_full().investigation_store.clone()
    }

    pub fn current_correlation_engine(&self) -> CorrelationEngine {
        self.stack.load_full().correlation.clone()
    }

    pub fn current_incident_store(&self) -> ConfiguredIncidentStore {
        self.stack.load_full().incident_store.clone()
    }

    fn detector_status(&self) -> DetectorRuntimeStatus {
        self.detector_status.load_full().as_ref().clone()
    }

    pub fn begin_drain(&self) -> bool {
        self.lifecycle.begin_drain()
    }

    fn is_draining(&self) -> bool {
        self.lifecycle.is_draining()
    }

    pub fn active_requests(&self) -> usize {
        self.lifecycle.active_requests()
    }

    fn try_begin_ingest_request(&self) -> Result<IngestRequestGuard, ()> {
        self.lifecycle.try_begin_request()
    }

    pub fn drain_timeout(&self) -> Duration {
        Duration::from_millis(
            self.stack
                .load_full()
                .service
                .config
                .runtime
                .drain_timeout_ms,
        )
    }

    pub fn secret_dir_path(&self) -> Option<PathBuf> {
        let stack = self.stack.load_full();
        resolve_secret_dir_path(
            stack.service.config.runtime.secret_dir.as_deref(),
            Some(self.config_path()),
        )
    }

    pub async fn wait_for_drain(&self) -> bool {
        self.lifecycle.wait_for_zero(self.drain_timeout()).await
    }

    fn sample_heap_pressure(&self) -> Option<HeapPressureSnapshot> {
        (self.heap_snapshot_provider)()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IngestRequest(pub Vec<Value>);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestEventStatus {
    Accepted,
    Rejected,
    ProcessingError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestEventResult {
    pub event_id: Option<String>,
    pub status: IngestEventStatus,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestResponse {
    pub correlation_id: String,
    pub accepted: Vec<IngestEventResult>,
    pub rejected: Vec<IngestEventResult>,
}

#[derive(Debug, Clone, Serialize)]
struct IngestErrorBody {
    error: String,
    correlation_id: String,
}

pub fn validate_and_parse(value: Value) -> Result<TelemetryEvent, String> {
    serde_json::from_value::<TelemetryEvent>(value).map_err(|error| error.to_string())
}

pub async fn ingest_events_handler(
    State(state): State<IngestState>,
    payload: Result<Json<IngestRequest>, JsonRejection>,
) -> Response {
    let correlation_id = Uuid::new_v4().to_string();
    let request_guard = match state.try_begin_ingest_request() {
        Ok(guard) => guard,
        Err(()) => {
            tracing::warn!(
                correlation_id = %correlation_id,
                module = module_path!(),
                "ingest rejected while runtime is draining"
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                ResponseJson(IngestErrorBody {
                    error: "runtime is draining and not accepting new ingest requests".to_string(),
                    correlation_id,
                }),
            )
                .into_response();
        }
    };
    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(rejection) => {
            tracing::warn!(
                correlation_id = %correlation_id,
                module = module_path!(),
                reason = %rejection.body_text(),
                "invalid ingest payload"
            );
            return (
                StatusCode::BAD_REQUEST,
                ResponseJson(IngestErrorBody {
                    error: rejection.body_text(),
                    correlation_id,
                }),
            )
                .into_response();
        }
    };

    let events = request.0;
    let event_count = events.len();
    let span_correlation_id = correlation_id.clone();
    async move {
        let _request_guard = request_guard;
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        for raw_event in events {
            let event_id = event_id_from_raw(&raw_event);
            match validate_and_parse(raw_event) {
                Ok(event) => {
                    tracing::info!(
                        correlation_id = %correlation_id,
                        event_id = ?event_id,
                        module = module_path!(),
                        "processing ingest event"
                    );
                    let approval = ApprovalContext {
                        live_mode: false,
                        receipt_chain: Vec::new(),
                        correlation_id: Some(correlation_id.clone()),
                        now_ms: event.timestamp,
                    };
                    let agent_id = AgentId("ingest".to_string());
                    let stack = state.stack.load_full();
                    let detector = state.detector.load_full();
                    match stack
                        .process_event(
                            detector.as_ref(),
                            &event,
                            crate::service::EventExecutionContext {
                                agent_id: &agent_id,
                                approval: &approval,
                                signing_key: &state.signing_key,
                            },
                            |_| None,
                        )
                        .await
                    {
                        Ok(_) => {
                            if let Some(tx) = &state.telemetry_tx {
                                match tx.try_send(event.clone()) {
                                    Ok(()) => {}
                                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                        tracing::warn!(
                                            correlation_id = %correlation_id,
                                            event_id = %event.event_id,
                                            module = module_path!(),
                                            "telemetry buffer full; skipping agent dispatch copy"
                                        );
                                    }
                                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                        tracing::warn!(
                                            correlation_id = %correlation_id,
                                            event_id = %event.event_id,
                                            module = module_path!(),
                                            "telemetry buffer closed; skipping agent dispatch copy"
                                        );
                                    }
                                }
                            }
                            tracing::info!(
                                correlation_id = %correlation_id,
                                event_id = ?event_id,
                                module = module_path!(),
                                "event accepted"
                            );
                            accepted.push(IngestEventResult {
                                event_id,
                                status: IngestEventStatus::Accepted,
                                reason: None,
                            });
                        }
                        Err(error) => {
                            tracing::error!(
                                correlation_id = %correlation_id,
                                event_id = ?event_id,
                                reason = %error,
                                module = module_path!(),
                                "event processing error"
                            );
                            rejected.push(IngestEventResult {
                                event_id,
                                status: IngestEventStatus::ProcessingError,
                                reason: Some(error.to_string()),
                            });
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        correlation_id = %correlation_id,
                        event_id = ?event_id,
                        reason = %error,
                        module = module_path!(),
                        "event rejected"
                    );
                    rejected.push(IngestEventResult {
                        event_id,
                        status: IngestEventStatus::Rejected,
                        reason: Some(error),
                    });
                }
            }
        }

        ResponseJson(IngestResponse {
            correlation_id,
            accepted,
            rejected,
        })
        .into_response()
    }
    .instrument(tracing::info_span!(
        "ingest_request",
        correlation_id = %span_correlation_id,
        event_count,
    ))
    .await
}

pub fn ingest_router(state: IngestState) -> Router {
    Router::new()
        .route("/v1/ingest/events", post(ingest_events_handler))
        .with_state(state)
}

pub fn detect_http_router(state: IngestState) -> Router {
    Router::new()
        .route("/startupz", get(startupz_handler))
        .route("/livez", get(livez_handler))
        .route("/readyz", get(readyz_handler))
        .route("/healthz", get(healthz_handler))
        .route("/prestop", get(prestop_handler))
        .route("/metrics", get(metrics_handler))
        .route("/v1/ingest/events", post(ingest_events_handler))
        .with_state(state)
}

async fn startupz_handler(State(state): State<IngestState>) -> impl IntoResponse {
    startup_response(state).await
}

async fn livez_handler(State(state): State<IngestState>) -> impl IntoResponse {
    let stack = state.stack.load_full();
    let detector_status = state.detector_status();

    (
        StatusCode::OK,
        ResponseJson(json!({
            "status": "ok",
            "mode": stack.service.mode(),
            "config_path": state.config_path().display().to_string(),
            "lifecycle": {
                "draining": state.is_draining(),
                "active_requests": state.active_requests(),
            },
            "components": {
                "detector": {
                    "ready": detector_status.ready,
                    "strategy": detector_status.strategy,
                    "details": detector_status.details,
                },
                "response": {
                    "ready": true,
                    "adapter": response_adapter_kind(&stack.service.config.response_adapter),
                }
            }
        })),
    )
}

async fn readyz_handler(State(state): State<IngestState>) -> impl IntoResponse {
    readiness_response(state, false).await
}

async fn healthz_handler(State(state): State<IngestState>) -> impl IntoResponse {
    readiness_response(state, true).await
}

async fn prestop_handler(State(state): State<IngestState>) -> impl IntoResponse {
    let drain_timeout_ms = state.drain_timeout().as_millis() as u64;
    let drain_started = state.begin_drain();
    let drained = state.wait_for_drain().await;
    if let Some(tx) = &state.shutdown_tx {
        let _ = tx.send(true);
    }
    let status = if drained {
        StatusCode::OK
    } else {
        StatusCode::GATEWAY_TIMEOUT
    };
    (
        status,
        ResponseJson(json!({
            "status": if drained { "ok" } else { "timeout" },
            "drain_started": drain_started,
            "draining": true,
            "active_requests": state.active_requests(),
            "drain_timeout_ms": drain_timeout_ms,
            "shutdown_requested": true,
        })),
    )
}

async fn startup_response(state: IngestState) -> (StatusCode, ResponseJson<Value>) {
    let stack = state.stack.load_full();
    let schema_supported = stack.service.config.schema_version <= CURRENT_SCHEMA_VERSION
        && stack.service.config.schema_version > 0;
    let telemetry_sources_configured = !stack.service.config.runtime.telemetry_sources.is_empty();
    let (substrate_ready, substrate_payload) = match stack.substrate.health().await {
        Ok(health) => (
            health.ready,
            json!({
                "ready": health.ready,
                "durable": health.durable,
                "backend": health.backend,
                "details": health.details,
            }),
        ),
        Err(error) => (
            false,
            json!({
                "ready": false,
                "durable": false,
                "backend": "unknown",
                "details": error.to_string(),
            }),
        ),
    };
    let ready = schema_supported && telemetry_sources_configured && substrate_ready;
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        ResponseJson(json!({
            "status": if ready { "ok" } else { "starting" },
            "mode": stack.service.mode(),
            "config_path": state.config_path().display().to_string(),
            "checks": {
                "schema_version": {
                    "ready": schema_supported,
                    "loaded": stack.service.config.schema_version,
                    "compiled_max": CURRENT_SCHEMA_VERSION,
                },
                "substrate": substrate_payload,
                "telemetry_sources": {
                    "ready": telemetry_sources_configured,
                    "configured": stack.service.config.runtime.telemetry_sources.len(),
                }
            }
        })),
    )
}

async fn readiness_response(
    state: IngestState,
    include_agents: bool,
) -> (StatusCode, ResponseJson<Value>) {
    let stack = state.stack.load_full();
    let detector_status = state.detector_status();
    let substrate_health = stack.substrate.health().await;
    let replay_store_health = stack.replay_store.health();
    let require_durable = stack.service.config.runtime.require_durable_live_response
        && stack.service.mode() == RuntimeMode::LiveResponse;
    let draining = state.is_draining();
    let heap_snapshot = state.sample_heap_pressure();
    if let Some(metrics) = stack.service.prometheus_metrics()
        && let Some(snapshot) = &heap_snapshot
    {
        metrics.observe_heap(snapshot.bytes, snapshot.pressure_ratio);
    }

    let (substrate_ready, substrate_payload) = match substrate_health {
        Ok(health) => {
            let ready = health.ready && (!require_durable || health.durable);
            (
                ready,
                json!({
                    "ready": health.ready,
                    "durable": health.durable,
                    "backend": health.backend,
                    "details": health.details,
                    "effective_ready": ready,
                }),
            )
        }
        Err(error) => (
            false,
            json!({
                "ready": false,
                "durable": false,
                "backend": "unknown",
                "details": error.to_string(),
                "effective_ready": false,
            }),
        ),
    };

    let (replay_ready, replay_payload) = match replay_store_health {
        Ok(health) => (
            health.ready,
            json!({
                "ready": health.ready,
                "durable": health.durable,
                "backend": health.backend,
                "details": health.details,
            }),
        ),
        Err(error) => (
            false,
            json!({
                "ready": false,
                "durable": false,
                "backend": "unknown",
                "details": error.to_string(),
            }),
        ),
    };

    let heap_ready = heap_snapshot.as_ref().is_none_or(|snapshot| {
        snapshot.pressure_ratio <= stack.service.config.runtime.max_heap_pressure
    });
    let ready = detector_status.ready && substrate_ready && replay_ready && heap_ready && !draining;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let mut components = json!({
        "detector": {
            "ready": detector_status.ready,
            "strategy": detector_status.strategy,
            "details": detector_status.details,
        },
        "substrate": substrate_payload,
        "replay_store": replay_payload,
        "response": {
            "ready": true,
            "adapter": response_adapter_kind(&stack.service.config.response_adapter),
        },
        "lifecycle": {
            "ready": !draining,
            "draining": draining,
            "active_requests": state.active_requests(),
            "drain_timeout_ms": stack.service.config.runtime.drain_timeout_ms,
        },
        "heap": match &heap_snapshot {
            Some(snapshot) => json!({
                "ready": snapshot.pressure_ratio <= stack.service.config.runtime.max_heap_pressure,
                "bytes": snapshot.bytes,
                "limit_bytes": snapshot.limit_bytes,
                "pressure_ratio": snapshot.pressure_ratio,
                "max_pressure": stack.service.config.runtime.max_heap_pressure,
            }),
            None => json!({
                "ready": true,
                "bytes": null,
                "limit_bytes": null,
                "pressure_ratio": null,
                "max_pressure": stack.service.config.runtime.max_heap_pressure,
                "details": "heap pressure unavailable",
            }),
        }
    });

    if include_agents && let Some(health) = &state.agent_dispatcher_health {
        let entries = health.load_full();
        let degraded = entries
            .iter()
            .any(|entry| !matches!(entry.health, swarm_core::agent::AgentHealth::Healthy));
        let entry_payload = entries
            .iter()
            .map(|entry| {
                json!({
                    "id": entry.id,
                    "role": entry.role,
                    "health": entry.health,
                })
            })
            .collect::<Vec<_>>();
        if let Some(object) = components.as_object_mut() {
            object.insert(
                "agents".to_string(),
                json!({
                    "ready": true,
                    "status": if degraded { "degraded" } else { "ok" },
                    "registered": entry_payload.len(),
                    "entries": entry_payload,
                }),
            );
        }
    }

    if include_agents && let Some(health) = &state.bridge_health {
        let report = bridge_health_report(health);
        let entry_payload = report
            .entries
            .iter()
            .map(|entry| {
                json!({
                    "name": entry.name,
                    "source_id": entry.source_id,
                    "status": entry.status(),
                    "ready": entry.ready,
                    "events_processed": entry.events_processed,
                    "error_count": entry.error_count,
                    "lag_seconds": entry.lag_seconds,
                    "last_error": entry.last_error,
                })
            })
            .collect::<Vec<_>>();
        if let Some(object) = components.as_object_mut() {
            object.insert(
                "bridges".to_string(),
                json!({
                    "ready": !report.has_degraded(),
                    "status": report.status(),
                    "configured": report.configured,
                    "ok": report.ok,
                    "degraded": report.degraded,
                    "idle": report.idle,
                    "entries": entry_payload,
                }),
            );
        }
    }

    (
        status,
        ResponseJson(json!({
            "status": if ready {
                "ok"
            } else if draining {
                "draining"
            } else {
                "degraded"
            },
            "mode": stack.service.mode(),
            "config_path": state.config_path().display().to_string(),
            "components": components
        })),
    )
}

async fn metrics_handler(State(state): State<IngestState>) -> impl IntoResponse {
    let stack = state.stack.load_full();
    match stack.service.prometheus_metrics() {
        Some(metrics) => {
            if let Some(snapshot) = state.sample_heap_pressure() {
                metrics.observe_heap(snapshot.bytes, snapshot.pressure_ratio);
            }
            (
                StatusCode::OK,
                [(
                    header::CONTENT_TYPE,
                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                )],
                encode_metrics(metrics),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "metrics not enabled").into_response(),
    }
}

fn sample_heap_pressure() -> Option<HeapPressureSnapshot> {
    let pid = get_current_pid().ok()?;
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    system.refresh_memory();
    let process = system.process(pid)?;
    let bytes = process.memory();
    let limit_bytes = cgroup_memory_limit_bytes()
        .filter(|limit| *limit > 0)
        .or_else(|| {
            let total = system.total_memory();
            (total > 0).then_some(total)
        })?;
    Some(HeapPressureSnapshot {
        bytes,
        limit_bytes,
        pressure_ratio: if limit_bytes == 0 {
            0.0
        } else {
            bytes as f64 / limit_bytes as f64
        },
    })
}

fn cgroup_memory_limit_bytes() -> Option<u64> {
    const CGROUP_V2: &str = "/sys/fs/cgroup/memory.max";
    const CGROUP_V1: &str = "/sys/fs/cgroup/memory/memory.limit_in_bytes";
    read_cgroup_limit(Path::new(CGROUP_V2)).or_else(|| read_cgroup_limit(Path::new(CGROUP_V1)))
}

fn read_cgroup_limit(path: &Path) -> Option<u64> {
    let raw = std::fs::read_to_string(path).ok()?;
    let value = raw.trim();
    if value.is_empty() || value == "max" {
        return None;
    }
    let parsed = value.parse::<u64>().ok()?;
    (parsed < u64::MAX / 4).then_some(parsed)
}

fn event_id_from_raw(value: &Value) -> Option<String> {
    value
        .get("event_id")
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn response_adapter_kind(config: &ResponseAdapterConfig) -> &'static str {
    match config {
        ResponseAdapterConfig::Sandbox => "sandbox",
        ResponseAdapterConfig::HttpEdr { .. } => "http_edr",
        ResponseAdapterConfig::Webhook { .. } => "webhook",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        HeapPressureSnapshot, IngestRequest, IngestResponse, IngestState, detect_http_router,
        ingest_router, response_adapter_kind, validate_and_parse,
    };
    use crate::bridge_runtime::{BridgeStatusSnapshot, SharedBridgeHealth};
    use crate::config::CURRENT_SCHEMA_VERSION;
    use crate::dispatcher::AgentHealthEntry;
    use arc_swap::ArcSwap;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use serde_json::{Value, json};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use swarm_core::agent::{AgentHealth, AgentRole};
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, CanaryConfig, CircuitBreakerConfig, CorrelationConfig,
        DetectionConfig, DetectorProfilesConfig, HttpEdrConfig, InvestigationConfig,
        OperatorSurfaceConfig, PheromoneBackendConfig, PheromoneConfig, PolicyConfig,
        PromotionConfig, ResponseAdapterConfig, RetryConfig, RuntimeMode, RuntimeSettings,
        SwarmConfig, TelemetrySourceConfig, WebhookConfig,
    };
    use swarm_core::types::Severity;
    use tokio::sync::{mpsc, watch};
    use tower::ServiceExt;

    fn test_config(strategy: &str) -> SwarmConfig {
        SwarmConfig {
            schema_version: 1,
            name: "ingest-test".to_string(),
            description: "ingest test config".to_string(),
            runtime: RuntimeSettings {
                mode: RuntimeMode::DetectOnly,
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
                agent_tick_timeout_ms: 500,
                max_dead_letter_bytes: None,
            },
            detection: DetectionConfig {
                strategy: strategy.to_string(),
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
                recent_decisions_limit: 20,
            },
            investigation: InvestigationConfig::default(),
            correlation: CorrelationConfig::default(),
            canary: CanaryConfig::default(),
            promotion: PromotionConfig::default(),
            operator: OperatorSurfaceConfig::default(),
        }
    }

    fn temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "swarm-runtime-ingest-{label}-{}-{nanos}.yaml",
            std::process::id()
        ))
    }

    fn write_config(path: &Path, strategy: &str) {
        fs::write(path, serde_yaml::to_string(&test_config(strategy)).unwrap()).unwrap();
    }

    fn test_ingest_state() -> IngestState {
        IngestState::from_config(temp_path("inline"), test_config("suspicious_process_tree"))
            .unwrap()
    }

    fn degraded_ingest_state() -> IngestState {
        let state = test_ingest_state();
        state
            .detector_status
            .store(Arc::new(super::DetectorRuntimeStatus::reload_failed(
                "suspicious_process_tree".to_string(),
                "synthetic reload failure",
            )));
        state
    }

    fn bridge_health(entries: Vec<BridgeStatusSnapshot>) -> SharedBridgeHealth {
        Arc::new(std::sync::Mutex::new(entries))
    }

    fn valid_process_event_json() -> Value {
        json!({
            "source": "synthetic",
            "event_id": "evt-ingest-1",
            "timestamp": 1_700_000_000_000i64,
            "host_id": "host-1",
            "payload": {
                "kind": "process_start",
                "parent_process": "WINWORD",
                "process_name": "powershell",
                "command_line": "powershell.exe -enc AAA=",
                "user": "alice"
            }
        })
    }

    fn malformed_event_json() -> Value {
        json!({
            "source": "synthetic",
            "event_id": "evt-ingest-bad",
            "timestamp": 1_700_000_000_000i64,
            "host_id": "host-1"
        })
    }

    async fn parse_response(response: axum::response::Response) -> IngestResponse {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[test]
    fn valid_event_parses_successfully() {
        let event = validate_and_parse(valid_process_event_json()).unwrap();
        assert_eq!(event.event_id, "evt-ingest-1");
        assert_eq!(event.host_id.as_deref(), Some("host-1"));
    }

    #[test]
    fn malformed_event_is_rejected() {
        let error = validate_and_parse(malformed_event_json()).unwrap_err();
        assert!(error.contains("payload"));
    }

    #[test]
    fn completely_invalid_json_is_rejected() {
        let error = validate_and_parse(json!("not-an-object")).unwrap_err();
        assert!(error.contains("invalid type"));
    }

    #[test]
    fn missing_payload_is_rejected() {
        let error = validate_and_parse(json!({
            "source": "synthetic",
            "event_id": "evt-missing-payload",
            "timestamp": 1_700_000_000_000i64,
            "host_id": "host-1"
        }))
        .unwrap_err();
        assert!(error.contains("payload"));
    }

    #[test]
    fn ingest_state_from_config_succeeds() {
        let state = test_ingest_state();
        assert_eq!(state.detector_strategy_name(), "suspicious_process_tree");
        assert!(
            state
                .config_path()
                .display()
                .to_string()
                .contains("swarm-runtime-ingest-inline")
        );
    }

    #[test]
    fn ingest_state_reload_updates_detector() {
        let state = test_ingest_state();
        state.reload(test_config("dns_exfiltration")).unwrap();
        assert_eq!(state.detector_strategy_name(), "dns_exfiltration");
    }

    #[test]
    fn ingest_state_reload_from_missing_path_fails() {
        let config_path = temp_path("missing");
        let state =
            IngestState::from_config(&config_path, test_config("suspicious_process_tree")).unwrap();

        let error = state.reload_from_disk().unwrap_err();
        assert!(error.to_string().contains("failed to read config"));
    }

    #[test]
    fn ingest_state_from_path_loads_written_config() {
        let config_path = temp_path("from-path");
        write_config(&config_path, "suspicious_process_tree");

        let state = IngestState::from_path(&config_path).unwrap();
        assert_eq!(state.detector_strategy_name(), "suspicious_process_tree");

        let _ = fs::remove_file(config_path);
    }

    #[tokio::test]
    async fn handler_accepts_valid_batch() {
        let app = ingest_router(test_ingest_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ingest/events")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&IngestRequest(vec![valid_process_event_json()]))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = parse_response(response).await;
        assert!(!body.correlation_id.is_empty());
        assert_eq!(body.accepted.len(), 1);
        assert!(body.rejected.is_empty());
    }

    #[tokio::test]
    async fn handler_rejects_malformed_batch() {
        let app = ingest_router(test_ingest_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ingest/events")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&IngestRequest(vec![malformed_event_json()]))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = parse_response(response).await;
        assert!(!body.correlation_id.is_empty());
        assert!(body.accepted.is_empty());
        assert_eq!(body.rejected.len(), 1);
        assert_eq!(body.rejected[0].event_id.as_deref(), Some("evt-ingest-bad"));
    }

    #[tokio::test]
    async fn handler_rejects_invalid_json_body() {
        let app = ingest_router(test_ingest_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ingest/events")
                    .header("content-type", "application/json")
                    .body(Body::from("{not-json"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn handler_rejects_invalid_content_type() {
        let app = ingest_router(test_ingest_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ingest/events")
                    .header("content-type", "text/plain")
                    .body(Body::from(
                        serde_json::to_string(&IngestRequest(vec![valid_process_event_json()]))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn handler_handles_empty_batch() {
        let app = ingest_router(test_ingest_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ingest/events")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&IngestRequest(vec![])).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = parse_response(response).await;
        assert!(!body.correlation_id.is_empty());
        assert!(body.accepted.is_empty());
        assert!(body.rejected.is_empty());
    }

    #[tokio::test]
    async fn handler_handles_mixed_batch() {
        let app = ingest_router(test_ingest_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ingest/events")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&IngestRequest(vec![
                            valid_process_event_json(),
                            malformed_event_json(),
                            valid_process_event_json(),
                        ]))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = parse_response(response).await;
        assert!(!body.correlation_id.is_empty());
        assert_eq!(body.accepted.len(), 2);
        assert_eq!(body.rejected.len(), 1);
    }

    #[tokio::test]
    async fn handler_generates_unique_correlation_ids_per_request() {
        let app = ingest_router(test_ingest_state());
        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ingest/events")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&IngestRequest(vec![valid_process_event_json()]))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let second = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ingest/events")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&IngestRequest(vec![valid_process_event_json()]))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let first_body = parse_response(first).await;
        let second_body = parse_response(second).await;
        assert_ne!(first_body.correlation_id, second_body.correlation_id);
    }

    #[tokio::test]
    async fn healthz_returns_ok_with_component_status() {
        let app = detect_http_router(test_ingest_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["components"]["response"]["adapter"], "sandbox");
    }

    #[tokio::test]
    async fn handler_forwards_accepted_events_to_agent_buffer() {
        let (tx, mut rx) = mpsc::channel(4);
        let app = ingest_router(test_ingest_state().with_telemetry_channel(tx));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ingest/events")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&IngestRequest(vec![valid_process_event_json()]))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let forwarded = rx.recv().await.unwrap();
        assert_eq!(forwarded.event_id, "evt-ingest-1");
    }

    #[tokio::test]
    async fn healthz_includes_agent_component_when_available() {
        let health = Arc::new(ArcSwap::from_pointee(vec![AgentHealthEntry {
            id: "whisker-primary".to_string(),
            role: AgentRole::Whisker,
            health: AgentHealth::Healthy,
        }]));
        let app = detect_http_router(test_ingest_state().with_agent_health(health));
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["components"]["agents"]["status"], "ok");
        assert_eq!(
            json["components"]["agents"]["entries"][0]["id"],
            "whisker-primary"
        );
    }

    #[tokio::test]
    async fn healthz_includes_bridge_component_without_failing_core_readiness() {
        let bridges = bridge_health(vec![
            BridgeStatusSnapshot {
                name: "cloudtrail-primary".to_string(),
                source_id: "cloudtrail".to_string(),
                ready: true,
                events_processed: 2,
                error_count: 0,
                lag_seconds: Some(4.0),
                last_error: None,
            },
            BridgeStatusSnapshot {
                name: "tetragon-primary".to_string(),
                source_id: "tetragon".to_string(),
                ready: false,
                events_processed: 5,
                error_count: 1,
                lag_seconds: Some(12.0),
                last_error: Some("stream closed".to_string()),
            },
        ]);
        let app = detect_http_router(test_ingest_state().with_bridge_health(bridges));
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["components"]["bridges"]["status"], "degraded");
        assert_eq!(json["components"]["bridges"]["configured"], 2);
        assert_eq!(json["components"]["bridges"]["degraded"], 1);
        assert_eq!(
            json["components"]["bridges"]["entries"][1]["name"],
            "tetragon-primary"
        );
    }

    #[tokio::test]
    async fn readyz_reports_detector_degradation() {
        let app = detect_http_router(degraded_ingest_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "degraded");
        assert_eq!(json["components"]["detector"]["ready"], false);
    }

    #[tokio::test]
    async fn livez_returns_ok_when_detector_is_degraded() {
        let app = detect_http_router(degraded_ingest_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/livez")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["components"]["detector"]["ready"], false);
    }

    #[tokio::test]
    async fn startupz_returns_ok_for_valid_state() {
        let app = detect_http_router(test_ingest_state());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/startupz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["checks"]["schema_version"]["loaded"], 1);
    }

    #[tokio::test]
    async fn startupz_reports_unsupported_schema_version() {
        let mut config = test_config("suspicious_process_tree");
        config.schema_version = CURRENT_SCHEMA_VERSION + 1;
        let app = detect_http_router(
            IngestState::from_config(temp_path("future-schema"), config).unwrap(),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/startupz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["checks"]["schema_version"]["ready"], false);
    }

    #[tokio::test]
    async fn readyz_reports_draining_state() {
        let state = test_ingest_state();
        state.begin_drain();
        let app = detect_http_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "draining");
        assert_eq!(json["components"]["lifecycle"]["draining"], true);
    }

    #[tokio::test]
    async fn draining_runtime_rejects_new_ingest_requests() {
        let state = test_ingest_state();
        state.begin_drain();
        let app = ingest_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ingest/events")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&IngestRequest(vec![valid_process_event_json()]))
                            .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["error"]
                .as_str()
                .is_some_and(|value| value.contains("draining"))
        );
    }

    #[tokio::test]
    async fn prestop_waits_for_inflight_requests_and_requests_shutdown() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let state = test_ingest_state().with_shutdown_channel(shutdown_tx);
        let guard = state.try_begin_ingest_request().unwrap();
        let app = detect_http_router(state);

        let releaser = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(guard);
        });

        let started = Instant::now();
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/prestop")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        releaser.await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(started.elapsed() >= Duration::from_millis(40));
        shutdown_rx.changed().await.unwrap();
        assert!(*shutdown_rx.borrow());
    }

    #[tokio::test]
    async fn readyz_reports_heap_pressure_degradation() {
        let app = detect_http_router(test_ingest_state().with_heap_snapshot_provider(|| {
            Some(HeapPressureSnapshot {
                bytes: 95,
                limit_bytes: 100,
                pressure_ratio: 0.95,
            })
        }));
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["components"]["heap"]["ready"], false);
        assert_eq!(json["components"]["heap"]["pressure_ratio"], 0.95);
    }

    #[tokio::test]
    async fn metrics_include_heap_gauges() {
        let app = detect_http_router(test_ingest_state().with_heap_snapshot_provider(|| {
            Some(HeapPressureSnapshot {
                bytes: 4_096,
                limit_bytes: 8_192,
                pressure_ratio: 0.5,
            })
        }));
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let metrics = String::from_utf8(body.to_vec()).unwrap();
        assert!(metrics.contains("swarm_heap_bytes 4096"));
        assert!(metrics.contains("swarm_heap_pressure_ratio 0.5"));
    }

    fn test_config_with_secret_token(secret_dir: &Path) -> SwarmConfig {
        use swarm_core::config::{CircuitBreakerConfig, HttpEdrConfig, RetryConfig};
        SwarmConfig {
            response_adapter: ResponseAdapterConfig::HttpEdr {
                config: HttpEdrConfig {
                    endpoint: "https://edr.example".to_string(),
                    auth_token: "@secret:edr-token".to_string(),
                    timeout_ms: 1_000,
                    retry: RetryConfig::default(),
                    circuit_breaker: CircuitBreakerConfig::default(),
                    dead_letter_path: "./dead-letter.jsonl".to_string(),
                },
            },
            runtime: swarm_core::config::RuntimeSettings {
                secret_dir: Some(secret_dir.display().to_string()),
                ..test_config("suspicious_process_tree").runtime
            },
            ..test_config("suspicious_process_tree")
        }
    }

    #[test]
    fn reload_secrets_only_updates_auth_token() {
        let tmp = std::env::temp_dir().join(format!(
            "swarm-secrets-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join("edr-token"), "initial-value\n").unwrap();

        // Pass the unresolved config — from_config resolves internally
        // and stores the template with @secret: references intact.
        let config_path = temp_path("secrets-reload");
        let config = test_config_with_secret_token(&tmp);
        let state = IngestState::from_config(&config_path, config).unwrap();

        // Verify initial value was resolved on construction
        let stack = state.stack.load_full();
        match &stack.service.config.response_adapter {
            ResponseAdapterConfig::HttpEdr { config: edr } => {
                assert_eq!(edr.auth_token, "initial-value");
            }
            other => panic!("expected HttpEdr, got {:?}", other),
        }
        drop(stack);

        // Rotate the secret on disk and reload secrets only
        fs::write(tmp.join("edr-token"), "rotated-value\n").unwrap();
        state.reload_secrets_only().unwrap();

        // Verify the rotated value is visible in the active stack
        let stack = state.stack.load_full();
        match &stack.service.config.response_adapter {
            ResponseAdapterConfig::HttpEdr { config: edr } => {
                assert_eq!(edr.auth_token, "rotated-value");
            }
            other => panic!("expected HttpEdr after reload, got {:?}", other),
        }

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_file(config_path);
    }

    #[test]
    fn reload_secrets_only_preserves_detector_strategy() {
        let tmp = std::env::temp_dir().join(format!(
            "swarm-secrets-strategy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join("edr-token"), "some-token\n").unwrap();

        let config_path = temp_path("secrets-strategy");
        let config = test_config_with_secret_token(&tmp);
        let state = IngestState::from_config(&config_path, config).unwrap();
        let strategy_before = state.detector_strategy_name();

        fs::write(tmp.join("edr-token"), "new-token\n").unwrap();
        state.reload_secrets_only().unwrap();

        let strategy_after = state.detector_strategy_name();
        assert_eq!(
            strategy_before, strategy_after,
            "detector strategy must not change after secrets-only reload"
        );

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_file(config_path);
    }

    #[test]
    fn reload_secrets_only_does_not_read_config_yaml() {
        // Build state with a config path that does NOT exist on disk.
        // reload_secrets_only must succeed because it should NOT try
        // to re-read the YAML file — only re-resolve secrets.
        let tmp = std::env::temp_dir().join(format!(
            "swarm-secrets-nofile-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join("edr-token"), "the-token\n").unwrap();

        // Pass unresolved config — from_config stores the template
        let config_path = temp_path("secrets-nofile");
        let config = test_config_with_secret_token(&tmp);
        let state = IngestState::from_config(&config_path, config).unwrap();

        // The config YAML file was never actually written, so reload_from_disk
        // would fail. reload_secrets_only works because it uses the stored
        // config template — no YAML file is read.
        fs::write(tmp.join("edr-token"), "fresh-token\n").unwrap();
        state.reload_secrets_only().unwrap();

        let stack = state.stack.load_full();
        match &stack.service.config.response_adapter {
            ResponseAdapterConfig::HttpEdr { config: edr } => {
                assert_eq!(edr.auth_token, "fresh-token");
            }
            other => panic!("expected HttpEdr, got {:?}", other),
        }

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn response_adapter_kind_maps_variants() {
        assert_eq!(
            response_adapter_kind(&ResponseAdapterConfig::Sandbox),
            "sandbox"
        );
        assert_eq!(
            response_adapter_kind(&ResponseAdapterConfig::HttpEdr {
                config: HttpEdrConfig {
                    endpoint: "https://edr.example".to_string(),
                    auth_token: "secret".to_string(),
                    timeout_ms: 1_000,
                    retry: RetryConfig::default(),
                    circuit_breaker: CircuitBreakerConfig::default(),
                    dead_letter_path: "./dead-letter.jsonl".to_string(),
                },
            }),
            "http_edr"
        );
        assert_eq!(
            response_adapter_kind(&ResponseAdapterConfig::Webhook {
                config: WebhookConfig {
                    url: "https://hooks.example".to_string(),
                    timeout_ms: 1_000,
                    channel: Some("#alerts".to_string()),
                    auth_token: None,
                    retry: RetryConfig::default(),
                    circuit_breaker: CircuitBreakerConfig::default(),
                    dead_letter_path: "./dead-letter.jsonl".to_string(),
                },
            }),
            "webhook"
        );
    }
}
