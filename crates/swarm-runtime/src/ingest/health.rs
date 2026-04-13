use crate::anti_tamper::AntiTamperReport;
use crate::bridge_runtime::bridge_health_report;
use crate::config::CURRENT_SCHEMA_VERSION;
use crate::detection::metrics::encode_metrics;
use crate::evasion_coverage::publish_snapshot_to_metrics;
use crate::providence::ProvidenceHealthStatus;
use crate::startup_attestation::StartupAttestationReport;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::response::Json as ResponseJson;
use serde_json::{Value, json};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use swarm_core::agent::{AgentHealth, AgentHealthEntry};
use swarm_core::config::{ResponseAdapterConfig, RuntimeMode};
use swarm_pheromone::PheromoneSubstrate;
use swarm_spine::ReplayBundleStore;
use sysinfo::{ProcessesToUpdate, System, get_current_pid};

use super::IngestState;

#[derive(Debug, Clone, PartialEq)]
pub(super) struct HeapPressureSnapshot {
    pub(super) bytes: u64,
    pub(super) limit_bytes: u64,
    pub(super) pressure_ratio: f64,
}

#[derive(Debug, Default)]
pub(super) struct IngestLifecycleState {
    pub(super) draining: AtomicBool,
    pub(super) active_requests: AtomicUsize,
    pub(super) notify: tokio::sync::Notify,
}

impl IngestLifecycleState {
    pub(super) fn begin_drain(&self) -> bool {
        !self.draining.swap(true, Ordering::SeqCst)
    }

    pub(super) fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    pub(super) fn active_requests(&self) -> usize {
        self.active_requests.load(Ordering::SeqCst)
    }

    pub(super) fn try_begin_request(self: &Arc<Self>) -> Result<IngestRequestGuard, ()> {
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

    pub(super) fn finish_request(&self) {
        if self.active_requests.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.notify.notify_waiters();
        }
    }

    pub(super) async fn wait_for_zero(&self, timeout: Duration) -> bool {
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

pub(super) struct IngestRequestGuard {
    pub(super) lifecycle: Arc<IngestLifecycleState>,
}

impl Drop for IngestRequestGuard {
    fn drop(&mut self) {
        self.lifecycle.finish_request();
    }
}

#[derive(Debug, Clone)]
pub(super) struct DetectorRuntimeStatus {
    pub(super) ready: bool,
    pub(super) strategy: String,
    pub(super) details: String,
}

impl DetectorRuntimeStatus {
    pub(super) fn loaded(strategy: String) -> Self {
        Self {
            ready: true,
            strategy,
            details: "detector loaded".to_string(),
        }
    }

    pub(super) fn reload_failed(strategy: String, error: impl ToString) -> Self {
        Self {
            ready: false,
            strategy,
            details: format!("last reload failed: {}", error.to_string()),
        }
    }
}

fn startup_attestation_payload(
    report: Option<&StartupAttestationReport>,
    mode: RuntimeMode,
) -> Value {
    let required = matches!(mode, RuntimeMode::LiveResponse);
    match report {
        Some(report) => json!({
            "ready": report.ready,
            "required": required,
            "effective_ready": report.ready_for_mode(mode),
            "status": report.status(),
            "evaluated_at_ms": report.evaluated_at_ms,
            "binary": report.binary,
            "rulesets": report.rulesets,
        }),
        None => json!({
            "ready": false,
            "required": required,
            "effective_ready": !required,
            "status": "unavailable",
            "details": "startup attestation was not evaluated for this runtime state",
        }),
    }
}

fn anti_tamper_payload(report: &AntiTamperReport) -> Value {
    json!({
        "ready": report.ready,
        "supported": report.supported,
        "required": report.required,
        "effective_ready": report.effective_ready(),
        "enabled": report.enabled,
        "status": report.status,
        "checked_at_ms": report.checked_at_ms,
        "details": report.details,
        "debugger_attached": report.debugger_attached,
        "tracer_pid": report.tracer_pid,
        "unexpected_library_loads": report.unexpected_library_loads,
        "baseline_library_count": report.baseline_library_count,
        "fail_closed_live_response": report.fail_closed_live_response,
    })
}

pub(crate) async fn startupz_handler(State(state): State<IngestState>) -> impl IntoResponse {
    startup_response(state).await
}

pub(crate) async fn livez_handler(State(state): State<IngestState>) -> impl IntoResponse {
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

pub(crate) async fn readyz_handler(State(state): State<IngestState>) -> impl IntoResponse {
    readiness_response(state, false).await
}

pub(crate) async fn healthz_handler(State(state): State<IngestState>) -> impl IntoResponse {
    readiness_response(state, true).await
}

pub(crate) async fn prestop_handler(State(state): State<IngestState>) -> impl IntoResponse {
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

pub(super) async fn startup_response(state: IngestState) -> (StatusCode, ResponseJson<Value>) {
    let stack = state.stack.load_full();
    let startup_attestation = state.current_startup_attestation();
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
    let attestation_ready = startup_attestation
        .as_ref()
        .map(|report| report.ready_for_mode(stack.service.mode()))
        .unwrap_or(!matches!(stack.service.mode(), RuntimeMode::LiveResponse));
    let ready =
        schema_supported && telemetry_sources_configured && substrate_ready && attestation_ready;
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
                },
                "startup_attestation": startup_attestation_payload(
                    startup_attestation.as_ref(),
                    stack.service.mode(),
                ),
            }
        })),
    )
}

pub(super) async fn readiness_response(
    state: IngestState,
    include_agents: bool,
) -> (StatusCode, ResponseJson<Value>) {
    let stack = state.stack.load_full();
    let detector_status = state.detector_status();
    let providence_health = state.current_providence_health().await;
    let substrate_health = stack.substrate.health().await;
    let replay_store_health = stack.replay_store.health();
    let require_durable = stack.service.config.runtime.require_durable_live_response
        && stack.service.mode() == RuntimeMode::LiveResponse;
    let startup_attestation = state.current_startup_attestation();
    let anti_tamper = state.current_anti_tamper_report();
    let draining = state.is_draining();
    let heap_snapshot = state.sample_heap_pressure();
    let telemetry_source_count = stack.service.config.runtime.telemetry_sources.len();
    let subject_source_count = stack
        .service
        .config
        .runtime
        .telemetry_sources
        .iter()
        .filter(|source| !source.subject.trim().is_empty())
        .count();
    let bridge_source_count = stack
        .service
        .config
        .runtime
        .telemetry_sources
        .iter()
        .filter(|source| source.bridge.is_some())
        .count();
    let bridge_report = state.bridge_health.as_ref().map(bridge_health_report);
    let degradation = state.current_runtime_degradation().await;
    if let Some(metrics) = stack.service.prometheus_metrics()
        && let Some(snapshot) = &heap_snapshot
    {
        metrics.observe_heap(snapshot.bytes, snapshot.pressure_ratio);
    }

    let substrate_payload = match substrate_health {
        Ok(health) => {
            let ready = health.ready && (!require_durable || health.durable);
            json!({
                "ready": health.ready,
                "durable": health.durable,
                "backend": health.backend,
                "details": health.details,
                "effective_ready": ready,
            })
        }
        Err(error) => json!({
            "ready": false,
            "durable": false,
            "backend": "unknown",
            "details": error.to_string(),
            "effective_ready": false,
        }),
    };

    let replay_payload = match replay_store_health {
        Ok(health) => json!({
            "ready": health.ready,
            "durable": health.durable,
            "backend": health.backend,
            "details": health.details,
        }),
        Err(error) => json!({
            "ready": false,
            "durable": false,
            "backend": "unknown",
            "details": error.to_string(),
        }),
    };
    let providence_ready = providence_health
        .as_ref()
        .is_none_or(ProvidenceHealthStatus::ready);
    let async_lane_status = state.current_async_lane_status().await;
    let (async_ready, async_payload) = match async_lane_status {
        Ok(status) => {
            let ready = (!status.investigation_enabled || status.investigation_store_ready)
                && (!status.correlation_enabled || status.incident_store_ready);
            (
                ready,
                json!({
                    "ready": ready,
                    "enabled": status.enabled,
                    "status": status.status.as_str(),
                    "investigation_enabled": status.investigation_enabled,
                    "correlation_enabled": status.correlation_enabled,
                    "investigation_strategy": status.investigation_strategy,
                    "investigation_store_ready": status.investigation_store_ready,
                    "incident_store_ready": status.incident_store_ready,
                    "queued_jobs": status.queued_jobs,
                    "running_jobs": status.running_jobs,
                    "queue_budget_remaining": status.queue_budget_remaining,
                    "highest_priority_score_basis_points": status.highest_priority_score_basis_points,
                    "oldest_job_age_ms": status.oldest_job_age_ms,
                    "completed_jobs": status.completed_jobs,
                    "failed_jobs": status.failed_jobs,
                    "timed_out_jobs": status.timed_out_jobs,
                    "budget_evictions": status.budget_evictions,
                    "starvation_preventions": status.starvation_preventions,
                    "recent_investigations": status.recent_investigations,
                    "ambiguous_recent_investigations": status.ambiguous_recent_investigations,
                    "recent_incidents": status.recent_incidents,
                    "latest_investigation_id": status.latest_investigation_id,
                    "latest_incident_id": status.latest_incident_id,
                    "latest_incident_confidence_score": status.latest_incident_confidence_score,
                    "latest_incident_graph_dimensions": status.latest_incident_graph_dimensions,
                    "last_failure_reason": status.last_failure_reason,
                    "warnings": status.warnings,
                }),
            )
        }
        Err(error) => (
            false,
            json!({
                "ready": false,
                "enabled": true,
                "status": "degraded",
                "details": error.to_string(),
            }),
        ),
    };
    let ready = degradation.ready && providence_ready && async_ready;
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
        "startup_attestation": startup_attestation_payload(
            startup_attestation.as_ref(),
            stack.service.mode(),
        ),
        "anti_tamper": anti_tamper_payload(&anti_tamper),
        "telemetry_sources": {
            "ready": telemetry_source_count > 0,
            "status": if telemetry_source_count == 0 {
                "missing"
            } else if bridge_report.as_ref().is_some_and(|report| report.has_degraded()) {
                "degraded"
            } else {
                "configured"
            },
            "configured": telemetry_source_count,
            "subject_backed": subject_source_count,
            "bridge_backed": bridge_source_count,
            "details": if telemetry_source_count == 0 {
                "no telemetry sources are configured".to_string()
            } else if let Some(report) = &bridge_report {
                format!(
                    "{} bridge-backed source(s); bridge status={}",
                    bridge_source_count,
                    report.status()
                )
            } else {
                "telemetry sources are configured; bridge runtime status is unavailable on this surface".to_string()
            },
        },
        "lifecycle": {
            "ready": !draining,
            "draining": draining,
            "active_requests": state.active_requests(),
            "drain_timeout_ms": stack.service.config.runtime.drain_timeout_ms,
        },
        "async_lane": async_payload,
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
        },
        "degradation": json!(degradation),
    });

    if let Some(health) = providence_health
        && let Some(object) = components.as_object_mut()
    {
        object.insert(
            "providence".to_string(),
            json!({
                "ready": health.ready(),
                "configured": health.configured,
                "reachable": health.reachable,
                "authenticated": health.authenticated,
                "accepting_writes": health.accepting_writes,
                "status": health.status,
                "details": health.details,
            }),
        );
    }

    if let Some(governance) = state.current_governance_status()
        && let Some(object) = components.as_object_mut()
    {
        object.insert("governance".to_string(), governance);
    }

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
            } else if degradation.capabilities.drains_ingest {
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

pub(crate) async fn metrics_handler(State(state): State<IngestState>) -> impl IntoResponse {
    let stack = state.stack.load_full();
    match stack.service.prometheus_metrics() {
        Some(metrics) => {
            if let Some(snapshot) = state.sample_heap_pressure() {
                metrics.observe_heap(snapshot.bytes, snapshot.pressure_ratio);
            }
            match state.current_evasion_coverage() {
                Ok(snapshot) => publish_snapshot_to_metrics(metrics, &snapshot),
                Err(error) => {
                    tracing::warn!(reason = %error, "failed to refresh evasion coverage metrics");
                }
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

pub(super) fn sample_heap_pressure() -> Option<HeapPressureSnapshot> {
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

pub(super) fn cgroup_memory_limit_bytes() -> Option<u64> {
    const CGROUP_V2: &str = "/sys/fs/cgroup/memory.max";
    const CGROUP_V1: &str = "/sys/fs/cgroup/memory/memory.limit_in_bytes";
    read_cgroup_limit(Path::new(CGROUP_V2)).or_else(|| read_cgroup_limit(Path::new(CGROUP_V1)))
}

pub(super) fn read_cgroup_limit(path: &Path) -> Option<u64> {
    let raw = std::fs::read_to_string(path).ok()?;
    let value = raw.trim();
    if value.is_empty() || value == "max" {
        return None;
    }
    let parsed = value.parse::<u64>().ok()?;
    (parsed < u64::MAX / 4).then_some(parsed)
}

pub(super) fn active_agent_counts(entries: &[AgentHealthEntry]) -> (usize, usize, usize) {
    let degraded = entries
        .iter()
        .filter(|entry| entry.health == AgentHealth::Degraded)
        .count();
    let failed = entries
        .iter()
        .filter(|entry| entry.health == AgentHealth::Failed)
        .count();
    let active = entries
        .iter()
        .filter(|entry| entry.health != AgentHealth::Failed)
        .count();
    (active, degraded, failed)
}

pub(crate) fn response_adapter_kind(config: &ResponseAdapterConfig) -> &'static str {
    match config {
        ResponseAdapterConfig::Sandbox => "sandbox",
        ResponseAdapterConfig::HttpEdr { .. } => "http_edr",
        ResponseAdapterConfig::Webhook { .. } => "webhook",
    }
}
