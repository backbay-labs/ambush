use crate::detection::metrics::CriticalPathMetrics;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use swarm_core::config::{SwarmConfig, TelemetryBridgeConfig, TetragonBridgeConfig};
use swarm_core::{BridgeHealth, TelemetryBridge, TelemetryEvent};
use swarm_ingest_json::{CloudTrailBridge, GenericJsonBridge, JsonBridgeConfigError};
use swarm_ingest_tetragon::{BridgeConfig as TetragonRuntimeConfig, TetragonBridge};
use tokio::sync::{mpsc, watch};

type BoxedTelemetryBridge = Box<dyn TelemetryBridge>;

const BRIDGE_ERROR_BACKOFF_MS: u64 = 100;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BridgeStatusSnapshot {
    pub name: String,
    pub source_id: String,
    pub ready: bool,
    pub events_processed: u64,
    pub error_count: u64,
    pub lag_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl BridgeStatusSnapshot {
    pub fn from_health(name: impl Into<String>, health: BridgeHealth) -> Self {
        Self {
            name: name.into(),
            source_id: health.source_id,
            ready: health.ready,
            events_processed: health.events_processed,
            error_count: health.error_count,
            lag_seconds: health.lag_seconds,
            last_error: health.last_error,
        }
    }

    pub fn status(&self) -> &'static str {
        if self.ready {
            "ok"
        } else if self.error_count > 0 {
            "degraded"
        } else {
            "idle"
        }
    }

    pub fn is_degraded(&self) -> bool {
        self.status() == "degraded"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BridgeStatusReport {
    pub configured: usize,
    pub ok: usize,
    pub degraded: usize,
    pub idle: usize,
    pub entries: Vec<BridgeStatusSnapshot>,
}

impl BridgeStatusReport {
    pub fn from_entries(mut entries: Vec<BridgeStatusSnapshot>) -> Self {
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        let mut ok = 0usize;
        let mut degraded = 0usize;
        let mut idle = 0usize;
        for entry in &entries {
            match entry.status() {
                "ok" => ok = ok.saturating_add(1),
                "degraded" => degraded = degraded.saturating_add(1),
                _ => idle = idle.saturating_add(1),
            }
        }
        Self {
            configured: entries.len(),
            ok,
            degraded,
            idle,
            entries,
        }
    }

    pub fn status(&self) -> &'static str {
        if self.degraded > 0 {
            "degraded"
        } else if self.ok > 0 {
            "ok"
        } else if self.configured > 0 {
            "idle"
        } else {
            "disabled"
        }
    }

    pub fn has_degraded(&self) -> bool {
        self.degraded > 0
    }
}

pub type SharedBridgeHealth = Arc<Mutex<Vec<BridgeStatusSnapshot>>>;

pub fn bridge_health_report(health: &SharedBridgeHealth) -> BridgeStatusReport {
    let entries = health
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    BridgeStatusReport::from_entries(entries)
}

#[derive(Debug, thiserror::Error)]
pub enum BridgeRuntimeError {
    #[error("failed to build bridge `{name}`: {source}")]
    Build {
        name: String,
        #[source]
        source: JsonBridgeConfigError,
    },
}

struct BridgeWorker {
    name: String,
    bridge: BoxedTelemetryBridge,
}

pub struct BridgeRuntimeRegistry {
    health: SharedBridgeHealth,
    workers: Vec<BridgeWorker>,
}

impl BridgeRuntimeRegistry {
    pub fn from_config(config: &SwarmConfig) -> Result<Self, BridgeRuntimeError> {
        let mut workers = Vec::new();
        let mut snapshots = Vec::new();

        for source in &config.runtime.telemetry_sources {
            let Some(bridge_config) = source.bridge.as_ref() else {
                continue;
            };
            let bridge = build_bridge(source.name.as_str(), bridge_config)?;
            snapshots.push(BridgeStatusSnapshot::from_health(
                source.name.clone(),
                bridge.health(),
            ));
            workers.push(BridgeWorker {
                name: source.name.clone(),
                bridge,
            });
        }

        Ok(Self {
            health: Arc::new(Mutex::new(snapshots)),
            workers,
        })
    }

    pub fn shared_health(&self) -> SharedBridgeHealth {
        Arc::clone(&self.health)
    }

    pub fn spawn(
        self,
        telemetry_tx: mpsc::Sender<TelemetryEvent>,
        shutdown: watch::Receiver<bool>,
        metrics: Option<CriticalPathMetrics>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let health = Arc::clone(&self.health);
        self.workers
            .into_iter()
            .map(|worker| {
                let worker_health = Arc::clone(&health);
                let worker_metrics = metrics.clone();
                let worker_shutdown = shutdown.clone();
                let worker_tx = telemetry_tx.clone();
                tokio::spawn(async move {
                    run_bridge_worker(
                        worker,
                        worker_tx,
                        worker_shutdown,
                        worker_health,
                        worker_metrics,
                    )
                    .await;
                })
            })
            .collect()
    }
}

async fn run_bridge_worker(
    mut worker: BridgeWorker,
    telemetry_tx: mpsc::Sender<TelemetryEvent>,
    mut shutdown: watch::Receiver<bool>,
    health: SharedBridgeHealth,
    metrics: Option<CriticalPathMetrics>,
) {
    publish_snapshot(
        &health,
        &worker.name,
        worker.bridge.health(),
        metrics.as_ref(),
    );

    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            result = worker.bridge.poll() => {
                match result {
                    Ok(events) if events.is_empty() => {
                        publish_snapshot(&health, &worker.name, worker.bridge.health(), metrics.as_ref());
                        tracing::info!(
                            bridge_name = %worker.name,
                            source_id = worker.bridge.source_id(),
                            "bridge exhausted available input and stopped"
                        );
                        return;
                    }
                    Ok(events) => {
                        publish_snapshot(&health, &worker.name, worker.bridge.health(), metrics.as_ref());
                        for event in events {
                            tokio::select! {
                                _ = shutdown.changed() => return,
                                send = telemetry_tx.send(event) => {
                                    if send.is_err() {
                                        let mut bridge_health = worker.bridge.health();
                                        bridge_health.record_error("telemetry channel closed");
                                        publish_snapshot(&health, &worker.name, bridge_health, metrics.as_ref());
                                        tracing::warn!(
                                            bridge_name = %worker.name,
                                            source_id = worker.bridge.source_id(),
                                            "bridge stopping because telemetry channel closed"
                                        );
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    Err(error) => {
                        publish_snapshot(&health, &worker.name, worker.bridge.health(), metrics.as_ref());
                        tracing::warn!(
                            bridge_name = %worker.name,
                            source_id = worker.bridge.source_id(),
                            reason = %error,
                            "bridge poll failed"
                        );
                        tokio::time::sleep(Duration::from_millis(BRIDGE_ERROR_BACKOFF_MS)).await;
                    }
                }
            }
        }
    }
}

fn publish_snapshot(
    health: &SharedBridgeHealth,
    name: &str,
    bridge_health: BridgeHealth,
    metrics: Option<&CriticalPathMetrics>,
) {
    if let Some(metrics) = metrics {
        metrics.observe_bridge_health(
            name,
            &bridge_health.source_id,
            bridge_health.ready,
            bridge_health.events_processed,
            bridge_health.error_count,
            bridge_health.lag_seconds,
        );
    }

    let snapshot = BridgeStatusSnapshot::from_health(name.to_string(), bridge_health);
    let mut guard = health.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some(existing) = guard.iter_mut().find(|entry| entry.name == snapshot.name) {
        *existing = snapshot;
    } else {
        guard.push(snapshot);
    }
}

fn build_bridge(
    name: &str,
    config: &TelemetryBridgeConfig,
) -> Result<BoxedTelemetryBridge, BridgeRuntimeError> {
    match config {
        TelemetryBridgeConfig::Tetragon { config } => Ok(Box::new(TetragonBridge::new(
            tetragon_runtime_config(config),
        ))),
        TelemetryBridgeConfig::CloudTrail { config } => {
            let bridge = CloudTrailBridge::from_config(config).map_err(|source| {
                BridgeRuntimeError::Build {
                    name: name.to_string(),
                    source,
                }
            })?;
            Ok(Box::new(bridge))
        }
        TelemetryBridgeConfig::GenericJson { config } => {
            let bridge = GenericJsonBridge::from_config(config).map_err(|source| {
                BridgeRuntimeError::Build {
                    name: name.to_string(),
                    source,
                }
            })?;
            Ok(Box::new(bridge))
        }
    }
}

fn tetragon_runtime_config(config: &TetragonBridgeConfig) -> TetragonRuntimeConfig {
    TetragonRuntimeConfig {
        endpoint: config.endpoint.clone(),
        reconnect_backoff_ms: config.reconnect_backoff_ms,
        max_reconnect_backoff_ms: config.max_reconnect_backoff_ms,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{BridgeRuntimeRegistry, bridge_health_report};
    use crate::config::load_config;
    use crate::detection::metrics::{CriticalPathMetrics, encode_metrics};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use swarm_core::TelemetryPayload;
    use tokio::sync::{mpsc, watch};

    fn default_config_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/default.yaml")
    }

    fn temp_json_fixture_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "swarm-runtime-bridge-{label}-{}-{nanos}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn registry_only_builds_bridge_backed_sources() {
        let config = load_config(default_config_path()).unwrap();
        let registry = BridgeRuntimeRegistry::from_config(&config).unwrap();
        let report = bridge_health_report(&registry.shared_health());
        assert_eq!(report.configured, 0);
        assert_eq!(report.status(), "disabled");
    }

    #[tokio::test]
    async fn registry_polls_generic_json_bridge_and_updates_metrics() {
        let fixture_path = temp_json_fixture_path("generic-json");
        fs::write(
            &fixture_path,
            serde_json::to_string(&serde_json::json!({
                "meta": {
                    "id": "evt-bridge-1",
                    "timestamp": "2026-04-07T12:00:00Z",
                    "host": "host-bridge-1"
                },
                "proc": {
                    "parent": "winword.exe",
                    "name": "powershell.exe",
                    "cmd": "powershell.exe -enc AAA="
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let mut config = load_config(default_config_path()).unwrap();
        config.runtime.telemetry_sources = vec![swarm_core::config::TelemetrySourceConfig {
            name: "generic-json-primary".to_string(),
            subject: String::new(),
            bridge: Some(swarm_core::config::TelemetryBridgeConfig::GenericJson {
                config: Box::new(swarm_core::config::GenericJsonBridgeConfig {
                    source: swarm_core::config::JsonFileSourceConfig {
                        path: fixture_path.display().to_string(),
                    },
                    mapping: swarm_core::config::FieldMappingConfig {
                        event_id_path: "/meta/id".to_string(),
                        timestamp_path: "/meta/timestamp".to_string(),
                        host_id_path: Some("/meta/host".to_string()),
                        payload:
                            swarm_core::config::GenericJsonPayloadMappingConfig::ProcessStart {
                                parent_process_path: "/proc/parent".to_string(),
                                process_name_path: "/proc/name".to_string(),
                                command_line_path: "/proc/cmd".to_string(),
                                user_path: None,
                            },
                    },
                }),
            }),
        }];

        let registry = BridgeRuntimeRegistry::from_config(&config).unwrap();
        let health = registry.shared_health();
        let metrics = CriticalPathMetrics::new();
        let (tx, mut rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let handles = registry.spawn(tx, shutdown_rx, Some(metrics.clone()));

        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("bridge should deliver an event")
            .expect("event should be present");
        assert_eq!(event.event_id, "evt-bridge-1");
        match event.payload {
            TelemetryPayload::ProcessStart(process) => {
                assert_eq!(process.process_name, "powershell.exe");
            }
            other => panic!("expected process_start payload, got {other:?}"),
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let report = bridge_health_report(&health);
        assert_eq!(report.status(), "ok");
        assert_eq!(report.configured, 1);
        assert_eq!(report.entries[0].events_processed, 1);
        assert_eq!(report.entries[0].source_id, "generic_json");

        let encoded = encode_metrics(&metrics);
        assert!(
            encoded.contains("swarm_bridge_events_processed{bridge=\"generic-json-primary\",source_id=\"generic_json\"} 1")
                || encoded.contains("swarm_bridge_events_processed{source_id=\"generic_json\",bridge=\"generic-json-primary\"} 1")
        );
        assert!(
            encoded.contains(
                "swarm_bridge_ready{bridge=\"generic-json-primary\",source_id=\"generic_json\"} 1"
            ) || encoded.contains(
                "swarm_bridge_ready{source_id=\"generic_json\",bridge=\"generic-json-primary\"} 1"
            )
        );

        let _ = fs::remove_file(fixture_path);
    }
}
