use axum::{Router, routing::get};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use swarm_core::agent::{SwarmAgent, SwarmEnvironment, SwarmMode};
use swarm_core::config::{
    CloudTrailBridgeConfig, FieldMappingConfig, GenericJsonBridgeConfig,
    GenericJsonPayloadMappingConfig, JsonFileSourceConfig, SentinelBridgeConfig, SwarmConfig,
    TelemetryBridgeConfig, TelemetrySourceConfig,
};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::AgentId;
use swarm_core::{InfrastructureHealthEvent, TelemetryPayload};
use swarm_pheromone::{ConfiguredPheromoneSubstrate, DepositQuery, PheromoneSubstrate};
use swarm_runtime::bridge_runtime::{BridgeRuntimeRegistry, bridge_health_report};
use swarm_runtime::config::load_config;
use swarm_runtime::control::build_composite_detector;
use swarm_runtime::whisker_agent::WhiskerAgent;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

fn default_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/default.yaml")
}

fn temp_fixture_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!(
        "swarm-runtime-bridge-integration-{label}-{}-{nanos}.jsonl",
        std::process::id()
    ))
}

fn whisker_env() -> SwarmEnvironment {
    SwarmEnvironment {
        pheromones: Vec::new(),
        mode: SwarmMode::Normal,
        mode_transition_at: None,
        now: 1_700_000_500,
        peer_findings: Vec::new(),
        agent_health: Vec::new(),
    }
}

fn sentinel_metrics_body() -> String {
    r#"
sentinel_cpu_usage_percent{node="node-a"} 96
sentinel_cpu_temperature_celsius{node="node-a"} 82
sentinel_cpu_throttled{node="node-a"} 1
sentinel_cpu_frequency_mhz{node="node-a"} 3200
sentinel_cpu_load_average{node="node-a",period="1m"} 12
sentinel_cpu_load_average{node="node-a",period="5m"} 8
sentinel_cpu_load_average{node="node-a",period="15m"} 4
sentinel_memory_total_bytes{node="node-a"} 1000
sentinel_memory_available_bytes{node="node-a"} 100
sentinel_memory_usage_percent{node="node-a"} 91
sentinel_memory_oom_kill_total{node="node-a"} 3
sentinel_memory_swap_used_bytes{node="node-a"} 128
sentinel_disk_total_bytes{node="node-a"} 2000
sentinel_disk_used_bytes{node="node-a"} 1900
sentinel_disk_usage_percent{node="node-a"} 95
sentinel_disk_io_latency_ms{node="node-a"} 7
sentinel_network_rx_bytes_total{node="node-a"} 1000
sentinel_network_tx_bytes_total{node="node-a"} 2000
sentinel_network_rx_errors_total{node="node-a"} 2
sentinel_network_tx_errors_total{node="node-a"} 1
sentinel_prediction_failure_probability{node="node-a"} 0.8
sentinel_prediction_confidence{node="node-a"} 0.9
sentinel_prediction_time_to_failure_seconds{node="node-a"} 45
sentinel_collection_duration_ms{node="node-a"} 11
"#
    .to_string()
}

async fn spawn_metrics_server(
    body: String,
) -> (
    String,
    watch::Sender<bool>,
    tokio::task::JoinHandle<Result<(), std::io::Error>>,
) {
    let app = Router::new().route(
        "/metrics",
        get({
            let body = body.clone();
            move || {
                let body = body.clone();
                async move { body }
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.changed().await;
            })
            .await
            .map_err(std::io::Error::other)
    });
    (format!("http://{addr}/metrics"), shutdown_tx, handle)
}

fn config_with_concurrent_bridges(
    cloudtrail_path: &Path,
    generic_json_path: &Path,
) -> Result<SwarmConfig, Box<dyn std::error::Error>> {
    let mut config = load_config(default_config_path())?;
    config.detection.strategy = "credential_access".to_string();
    config.runtime.telemetry_sources = vec![
        TelemetrySourceConfig {
            name: "cloudtrail-primary".to_string(),
            subject: String::new(),
            bridge: Some(TelemetryBridgeConfig::CloudTrail {
                config: Box::new(CloudTrailBridgeConfig {
                    source: JsonFileSourceConfig {
                        path: cloudtrail_path.display().to_string(),
                    },
                }),
            }),
        },
        TelemetrySourceConfig {
            name: "generic-json-primary".to_string(),
            subject: String::new(),
            bridge: Some(TelemetryBridgeConfig::GenericJson {
                config: Box::new(GenericJsonBridgeConfig {
                    source: JsonFileSourceConfig {
                        path: generic_json_path.display().to_string(),
                    },
                    mapping: FieldMappingConfig {
                        event_id_path: "/meta/id".to_string(),
                        timestamp_path: "/meta/timestamp".to_string(),
                        host_id_path: Some("/meta/host".to_string()),
                        payload: GenericJsonPayloadMappingConfig::AuthenticationEvent {
                            auth_type_path: "/auth/type".to_string(),
                            source_host_path: Some("/auth/source".to_string()),
                            target_host_path: Some("/auth/target".to_string()),
                            target_service_path: Some("/auth/service".to_string()),
                            process_name_path: Some("/auth/process".to_string()),
                            success_path: "/auth/success".to_string(),
                            user_path: Some("/auth/user".to_string()),
                        },
                    },
                }),
            }),
        },
    ];
    Ok(config)
}

#[tokio::test]
async fn concurrent_bridge_registry_feeds_shared_whisker_pipeline()
-> Result<(), Box<dyn std::error::Error>> {
    let cloudtrail_path = temp_fixture_path("cloudtrail");
    let generic_json_path = temp_fixture_path("generic");

    fs::write(
        &cloudtrail_path,
        serde_json::to_string(&serde_json::json!({
            "eventID": "evt-cloudtrail-1",
            "eventName": "kerberos_tgs",
            "eventSource": "signin.amazonaws.com",
            "eventTime": "2026-04-07T12:00:00Z",
            "recipientAccountId": "123456789012",
            "sourceIPAddress": "198.51.100.10",
            "userAgent": "powershell.exe",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "alice"
            }
        }))?,
    )?;
    fs::write(
        &generic_json_path,
        serde_json::to_string(&serde_json::json!({
            "meta": {
                "id": "evt-generic-1",
                "timestamp": "2026-04-07T12:00:01Z",
                "host": "host-generic-1"
            },
            "auth": {
                "type": "kerberos_tgs",
                "source": "ws-22",
                "target": "dc-01",
                "service": "MSSQLSvc/sql01",
                "process": "rubeus.exe",
                "success": true,
                "user": "bob"
            }
        }))?,
    )?;

    let config = config_with_concurrent_bridges(&cloudtrail_path, &generic_json_path)?;
    let detector = Arc::new(build_composite_detector(&config.detection)?);
    let substrate = ConfiguredPheromoneSubstrate::from_config(&config.pheromone)?;
    let registry = BridgeRuntimeRegistry::from_config(&config)?;
    let bridge_health = registry.shared_health();
    let (telemetry_tx, telemetry_rx) = mpsc::channel(16);
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let handles = registry.spawn(telemetry_tx, shutdown_rx, None);

    tokio::time::timeout(Duration::from_secs(2), async {
        for handle in handles {
            handle.await.map_err(std::io::Error::other)?;
        }
        Ok::<(), std::io::Error>(())
    })
    .await??;

    let health = bridge_health_report(&bridge_health);
    assert_eq!(health.configured, 2);
    assert_eq!(health.ok, 2);

    let mut agent = WhiskerAgent::new(
        AgentId::new("whisker", "primary"),
        telemetry_rx,
        detector,
        substrate.clone(),
        config.pheromone.clone(),
    );
    let actions = agent
        .tick(&whisker_env())
        .await
        .map_err(std::io::Error::other)?;
    assert_eq!(actions.len(), 2);

    let deposits = substrate.query_deposits(DepositQuery::recent(10)).await?;
    assert_eq!(deposits.len(), 2);
    assert!(
        deposits
            .iter()
            .all(|deposit| deposit.threat_class == ThreatClass::CredentialAccess)
    );

    let sources = deposits
        .iter()
        .filter_map(|deposit| {
            deposit
                .indicator
                .get("source")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        sources,
        BTreeSet::from(["cloudtrail".to_string(), "generic_json".to_string(),])
    );

    let _ = fs::remove_file(cloudtrail_path);
    let _ = fs::remove_file(generic_json_path);
    Ok(())
}

#[tokio::test]
async fn sentinel_bridge_registry_emits_normalized_infrastructure_health_event()
-> Result<(), Box<dyn std::error::Error>> {
    let (endpoint, server_shutdown, server_handle) =
        spawn_metrics_server(sentinel_metrics_body()).await;
    let mut config = load_config(default_config_path())?;
    config.runtime.telemetry_sources = vec![TelemetrySourceConfig {
        name: "sentinel-infra".to_string(),
        subject: String::new(),
        bridge: Some(TelemetryBridgeConfig::Sentinel {
            config: Box::new(SentinelBridgeConfig {
                endpoint,
                scrape_interval_ms: 1,
                scrape_timeout_ms: 1_000,
                thermal_anomaly_threshold_celsius: 60.0,
                memory_exhaustion_threshold_percent: 85.0,
                disk_exhaustion_threshold_percent: 90.0,
                max_consecutive_failures: 3,
            }),
        }),
    }];

    let registry = BridgeRuntimeRegistry::from_config(&config)?;
    let bridge_health = registry.shared_health();
    let (telemetry_tx, mut telemetry_rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handles = registry.spawn(telemetry_tx, shutdown_rx, None);

    let event = tokio::time::timeout(Duration::from_secs(2), telemetry_rx.recv())
        .await?
        .ok_or_else(|| std::io::Error::other("expected sentinel event"))?;
    let TelemetryPayload::InfrastructureHealth(InfrastructureHealthEvent {
        node_name,
        cpu_usage_percent,
        memory_usage_percent,
        disk_usage_percent,
        ..
    }) = event.payload
    else {
        return Err(std::io::Error::other("expected infrastructure health payload").into());
    };
    assert_eq!(event.source, "sentinel");
    assert_eq!(node_name, "node-a");
    assert_eq!(cpu_usage_percent, 96.0);
    assert_eq!(memory_usage_percent, 91.0);
    assert_eq!(disk_usage_percent, 95.0);

    shutdown_tx
        .send(true)
        .map_err(|_| std::io::Error::other("failed to stop sentinel worker"))?;
    for handle in handles {
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .map_err(std::io::Error::other)?
            .map_err(std::io::Error::other)?;
    }

    let report = bridge_health_report(&bridge_health);
    assert_eq!(report.configured, 1);
    assert_eq!(report.ok, 1);
    assert_eq!(report.entries[0].source_id, "sentinel");
    assert_eq!(report.entries[0].events_processed, 4);

    server_shutdown
        .send(true)
        .map_err(|_| std::io::Error::other("failed to stop metrics server"))?;
    tokio::time::timeout(Duration::from_secs(2), server_handle)
        .await
        .map_err(std::io::Error::other)?
        .map_err(std::io::Error::other)??;
    Ok(())
}
