use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use swarm_core::config::{SwarmConfig, TaxiiThreatIntelFeedConfig, ThreatIntelFeedConfig};
use swarm_ingest_taxii::TaxiiPoller;
use swarm_pheromone::PheromoneSubstrate;
use tokio::sync::watch;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatIntelFeedStatusSnapshot {
    pub name: String,
    pub kind: String,
    pub ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_poll_at_ms: Option<i64>,
    pub indicators_ingested: u64,
    pub error_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl ThreatIntelFeedStatusSnapshot {
    fn new(name: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: kind.into(),
            ready: false,
            last_poll_at_ms: None,
            indicators_ingested: 0,
            error_count: 0,
            last_error: None,
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

    fn record_success(&mut self, polled_at_ms: i64, ingested: u64) {
        self.ready = true;
        self.last_poll_at_ms = Some(polled_at_ms);
        self.indicators_ingested = self.indicators_ingested.saturating_add(ingested);
        self.last_error = None;
    }

    fn record_error(&mut self, polled_at_ms: i64, error: impl Into<String>) {
        self.ready = false;
        self.last_poll_at_ms = Some(polled_at_ms);
        self.error_count = self.error_count.saturating_add(1);
        self.last_error = Some(error.into());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ThreatIntelFeedStatusReport {
    pub configured: usize,
    pub ok: usize,
    pub degraded: usize,
    pub idle: usize,
    pub entries: Vec<ThreatIntelFeedStatusSnapshot>,
}

impl ThreatIntelFeedStatusReport {
    pub fn from_entries(mut entries: Vec<ThreatIntelFeedStatusSnapshot>) -> Self {
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

pub type SharedThreatIntelFeedHealth = Arc<Mutex<Vec<ThreatIntelFeedStatusSnapshot>>>;

pub fn threat_intel_feed_health_report(
    health: &SharedThreatIntelFeedHealth,
) -> ThreatIntelFeedStatusReport {
    let entries = health
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    ThreatIntelFeedStatusReport::from_entries(entries)
}

struct ThreatIntelFeedWorker {
    name: String,
    kind: &'static str,
    poll_interval: Duration,
    poller: TaxiiPoller,
}

pub struct ThreatIntelFeedRuntimeRegistry {
    health: SharedThreatIntelFeedHealth,
    workers: Vec<ThreatIntelFeedWorker>,
}

impl ThreatIntelFeedRuntimeRegistry {
    pub fn from_config(config: &SwarmConfig) -> Self {
        let mut workers = Vec::new();
        let mut snapshots = Vec::new();

        for feed in &config.runtime.threat_intel_feeds {
            match feed {
                ThreatIntelFeedConfig::Taxii { config } => {
                    workers.push(ThreatIntelFeedWorker::taxii(config));
                    snapshots.push(ThreatIntelFeedStatusSnapshot::new(
                        config.name.clone(),
                        "taxii",
                    ));
                }
            }
        }

        Self {
            health: Arc::new(Mutex::new(snapshots)),
            workers,
        }
    }

    pub fn shared_health(&self) -> SharedThreatIntelFeedHealth {
        Arc::clone(&self.health)
    }

    pub fn spawn<S>(
        self,
        substrate: S,
        shutdown: watch::Receiver<bool>,
    ) -> Vec<tokio::task::JoinHandle<()>>
    where
        S: PheromoneSubstrate + Clone + 'static,
    {
        let health = Arc::clone(&self.health);
        self.workers
            .into_iter()
            .map(|worker| {
                let worker_health = Arc::clone(&health);
                let worker_substrate = substrate.clone();
                let worker_shutdown = shutdown.clone();
                tokio::spawn(async move {
                    run_feed_worker(worker, worker_substrate, worker_shutdown, worker_health).await;
                })
            })
            .collect()
    }
}

impl ThreatIntelFeedWorker {
    fn taxii(config: &TaxiiThreatIntelFeedConfig) -> Self {
        Self {
            name: config.name.clone(),
            kind: "taxii",
            poll_interval: Duration::from_millis(config.poll_interval_ms),
            poller: TaxiiPoller::from_config(config),
        }
    }
}

async fn run_feed_worker<S>(
    worker: ThreatIntelFeedWorker,
    substrate: S,
    mut shutdown: watch::Receiver<bool>,
    health: SharedThreatIntelFeedHealth,
) where
    S: PheromoneSubstrate + Clone + 'static,
{
    let mut snapshot = ThreatIntelFeedStatusSnapshot::new(worker.name.clone(), worker.kind);
    publish_snapshot(&health, &snapshot);
    let mut first_poll = true;

    loop {
        if !first_poll {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                _ = tokio::time::sleep(worker.poll_interval) => {}
            }
        }
        first_poll = false;

        let polled_at_ms = now_ms();
        // Race the poll against the shutdown receiver so a stalled TAXII
        // endpoint cannot block the runtime drain even when the poll itself
        // honors the per-request timeout.
        let poll_outcome = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
                continue;
            }
            outcome = worker.poller.poll_once() => outcome,
        };
        match poll_outcome {
            Ok(outcome) => {
                let mut stored = 0u64;
                let mut store_error = None;
                for entry in outcome.entries {
                    match substrate.store_threat_intel_entry(entry).await {
                        Ok(()) => stored = stored.saturating_add(1),
                        Err(error) => {
                            store_error = Some(error.to_string());
                            break;
                        }
                    }
                }

                if let Some(error) = store_error {
                    snapshot.record_error(outcome.polled_at_ms, error);
                } else {
                    snapshot.record_success(outcome.polled_at_ms, stored);
                }
            }
            Err(error) => snapshot.record_error(polled_at_ms, error.to_string()),
        }
        publish_snapshot(&health, &snapshot);
    }
}

fn publish_snapshot(
    health: &SharedThreatIntelFeedHealth,
    snapshot: &ThreatIntelFeedStatusSnapshot,
) {
    let mut guard = health.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some(existing) = guard.iter_mut().find(|entry| entry.name == snapshot.name) {
        *existing = snapshot.clone();
    } else {
        guard.push(snapshot.clone());
        guard.sort_by(|left, right| left.name.cmp(&right.name));
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{ThreatIntelFeedRuntimeRegistry, threat_intel_feed_health_report};
    use axum::{Json, Router, routing::get};
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, CorrelationConfig, DetectionConfig, DetectorProfilesConfig,
        EvolutionConfig, IdentityConfig, InvestigationConfig, MemoryConfig,
        NotificationRoutingConfig, PheromoneBackendConfig, PheromoneConfig, PlatformApiConfig,
        PolicyConfig, PromotionConfig, ResponsePlaybookConfig, RuntimeMode, RuntimeSettings,
        SwarmConfig, TaxiiThreatIntelFeedConfig, TelemetrySourceConfig, TemporalEventWindowConfig,
        ThreatIntelFeedConfig,
    };
    use swarm_core::{ThreatIntelIndicatorType, config::RuntimeAntiTamperConfig};
    use swarm_pheromone::{InMemoryPheromoneSubstrate, PheromoneSubstrate};
    use tokio::sync::watch;

    fn registry_config(url: String, poll_interval_ms: u64) -> SwarmConfig {
        SwarmConfig {
            schema_version: 1,
            name: "threat-intel-runtime".to_string(),
            description: "threat intel runtime test".to_string(),
            runtime: RuntimeSettings {
                mode: RuntimeMode::DetectOnly,
                demo_mode: false,
                telemetry_sources: vec![TelemetrySourceConfig {
                    name: "synthetic".to_string(),
                    subject: "telemetry.synthetic.process".to_string(),
                    bridge: None,
                }],
                threat_intel_feeds: vec![ThreatIntelFeedConfig::Taxii {
                    config: Box::new(TaxiiThreatIntelFeedConfig {
                        name: "taxii-primary".to_string(),
                        collection_url: url,
                        poll_interval_ms,
                        default_ttl_secs: 3600,
                    }),
                }],
                max_in_flight_actions: 2,
                drain_timeout_ms: 30_000,
                require_durable_live_response: false,
                max_heap_pressure: 0.90,
                secret_dir: None,
                anti_tamper: RuntimeAntiTamperConfig::default(),
                temporal_event_window: TemporalEventWindowConfig::default(),
                agent_tick_timeout_ms: 500,
                governance_degraded_tick_threshold: 3,
                partition_contingency_lease_ttl_ms: 300_000,
                partition_contingency_blast_radius_cap: 1,
                max_dead_letter_bytes: None,
                containment: Default::default(),
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
                response_playbook: ResponsePlaybookConfig::default(),
                backend: PheromoneBackendConfig::InMemory,
            },
            policy: PolicyConfig::default(),
            response_adapter: Default::default(),
            siem_forward: None,
            notification_channels: Default::default(),
            notification_routing: NotificationRoutingConfig::default(),
            audit: AuditConfig {
                bundle_store: BundleStoreConfig::Memory,
                recent_decisions_limit: 20,
            },
            investigation: InvestigationConfig::default(),
            hypothesis_graph: Default::default(),
            correlation: CorrelationConfig::default(),
            canary: Default::default(),
            promotion: PromotionConfig::default(),
            evolution: EvolutionConfig::default(),
            deception: Default::default(),
            memory: MemoryConfig::default(),
            identity: IdentityConfig::default(),
            platform_api: PlatformApiConfig::default(),
            operator: Default::default(),
            tls: None,
        }
    }

    #[tokio::test]
    async fn feed_registry_polls_and_updates_substrate_health() {
        let hits = Arc::new(AtomicUsize::new(0));
        let app_hits = Arc::clone(&hits);
        let app = Router::new().route(
            "/collection",
            get(move || {
                let app_hits = Arc::clone(&app_hits);
                async move {
                    let hit = app_hits.fetch_add(1, Ordering::SeqCst);
                    if hit == 0 {
                        Json(json!({
                            "objects": [{
                                "type": "indicator",
                                "id": "indicator--domain",
                                "pattern": "[domain-name:value = 'evil.example']",
                                "confidence": 40
                            }]
                        }))
                    } else {
                        Json(json!({
                            "objects": [{
                                "type": "indicator",
                                "id": "indicator--domain",
                                "pattern": "[domain-name:value = 'evil.example']",
                                "confidence": 90
                            }]
                        }))
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let config = registry_config(format!("http://{addr}/collection"), 50);
        let registry = ThreatIntelFeedRuntimeRegistry::from_config(&config);
        let health = registry.shared_health();
        let substrate = InMemoryPheromoneSubstrate::new(config.pheromone.clone());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handles = registry.spawn(substrate.clone(), shutdown_rx);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let maybe_entry = substrate
                .query_threat_intel_entry(
                    &ThreatIntelIndicatorType::Domain,
                    "evil.example",
                    super::now_ms(),
                )
                .await
                .unwrap();
            if maybe_entry.is_some_and(|entry| entry.confidence >= 0.9) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "condition timed out"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let report = threat_intel_feed_health_report(&health);
        assert_eq!(report.configured, 1);
        assert_eq!(report.ok, 1);
        assert!(report.entries[0].last_poll_at_ms.is_some());
        assert!(report.entries[0].indicators_ingested >= 2);

        let _ = shutdown_tx.send(true);
        for handle in handles {
            handle.await.unwrap();
        }
        server.abort();
    }
}
