#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::serve;
use reqwest::Client;
use serde_json::{Value, json};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use swarm_core::config::{
    BundleStoreConfig, CorrelationConfig, InvestigationConfig, NotificationRoutingConfig,
    PheromoneBackendConfig, ResponseAdapterConfig, RuntimeMode, SwarmConfig, TelemetrySourceConfig,
};
use swarm_runtime::config::load_config;
use swarm_runtime::ingest::{IngestResponse, IngestState, detect_http_router};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use uuid::Uuid;

fn default_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/default.yaml")
}

#[derive(Clone, Copy, Debug)]
enum BenchBackend {
    LocalJournal,
    JetStream,
}

impl BenchBackend {
    fn from_env() -> Result<Self, Box<dyn Error>> {
        match std::env::var("STS_E2E_BENCH_BACKEND")
            .unwrap_or_else(|_| "local_journal".to_string())
            .as_str()
        {
            "local_journal" => Ok(Self::LocalJournal),
            "jet_stream" => Ok(Self::JetStream),
            other => Err(format!(
                "unsupported STS_E2E_BENCH_BACKEND `{other}`; expected `local_journal` or `jet_stream`"
            )
            .into()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::LocalJournal => "local_journal",
            Self::JetStream => "jet_stream",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct BenchSettings {
    warmup_requests: usize,
    measured_requests: usize,
    batch_size: usize,
}

impl BenchSettings {
    fn from_env() -> Self {
        Self {
            warmup_requests: env_usize("STS_E2E_BENCH_WARMUP_REQUESTS", 25),
            measured_requests: env_usize("STS_E2E_BENCH_REQUESTS", 200),
            batch_size: env_usize("STS_E2E_BENCH_BATCH_SIZE", 25),
        }
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn percentile(sorted_samples: &[f64], percentile: f64) -> f64 {
    let index = ((sorted_samples.len().saturating_sub(1) as f64) * percentile).round() as usize;
    sorted_samples[index]
}

fn benchmark_root() -> PathBuf {
    std::env::temp_dir().join(format!("swarm-runtime-e2e-bench-{}", Uuid::new_v4()))
}

fn build_config(root: &Path, backend: BenchBackend) -> Result<SwarmConfig, Box<dyn Error>> {
    let mut config = load_config(default_config_path())?;
    config.name = format!("swarm-e2e-bench-{}", backend.as_str());
    config.description =
        "Measured HTTP ingest benchmark for the supported detect-only runtime slice".to_string();
    config.runtime.mode = RuntimeMode::DetectOnly;
    config.runtime.demo_mode = false;
    config.runtime.require_durable_live_response = false;
    config.runtime.telemetry_sources = vec![TelemetrySourceConfig {
        name: "synthetic-process".to_string(),
        subject: "telemetry.synthetic.process".to_string(),
        bridge: None,
    }];
    config.detection.strategy = "suspicious_process_tree".to_string();
    config.response_adapter = ResponseAdapterConfig::Sandbox;
    config.siem_forward = None;
    config.notification_channels.clear();
    config.notification_routing = NotificationRoutingConfig::default();
    config.audit.bundle_store = BundleStoreConfig::LocalFiles {
        directory: root.join("replay").display().to_string(),
    };
    config.investigation = InvestigationConfig::default();
    config.correlation = CorrelationConfig::default();
    config.memory.knowledge_graph_results_dir = root.join("memory").display().to_string();
    config.identity.agent_key_dir = root.join("agent-keys").display().to_string();
    config.identity.registry_dir = root.join("agent-identity").display().to_string();
    config.pheromone.backend = match backend {
        BenchBackend::LocalJournal => PheromoneBackendConfig::LocalJournal {
            path: root
                .join("pheromones")
                .join("pheromones.jsonl")
                .display()
                .to_string(),
        },
        BenchBackend::JetStream => PheromoneBackendConfig::JetStream {
            url: std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string()),
            connect_timeout_ms: 5_000,
            gc_page_size: 1_000,
        },
    };
    Ok(config)
}

fn build_request_body(request_index: usize, batch_size: usize) -> Value {
    let events = (0..batch_size)
        .map(|offset| {
            json!({
                "source": "benchmark",
                "event_id": format!("evt-{request_index}-{offset}"),
                "timestamp": 1_700_000_000_000_i64 + request_index as i64,
                "host_id": "bench-host",
                "payload": {
                    "kind": "process_start",
                    "parent_process": "winword",
                    "process_name": "powershell",
                    "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ==",
                    "user": "benchmark"
                }
            })
        })
        .collect::<Vec<_>>();
    Value::Array(events)
}

async fn post_batch(
    client: &Client,
    base_url: &str,
    request_index: usize,
    batch_size: usize,
) -> Result<(), Box<dyn Error>> {
    let response = client
        .post(format!("{base_url}/v1/ingest/events"))
        .json(&build_request_body(request_index, batch_size))
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(format!("ingest returned {}", response.status()).into());
    }
    let payload = response.json::<IngestResponse>().await?;
    if !payload.rejected.is_empty() {
        return Err(format!(
            "ingest rejected {} events during request {request_index}",
            payload.rejected.len()
        )
        .into());
    }
    if payload.accepted.len() != batch_size {
        return Err(format!(
            "ingest accepted {} events during request {request_index}; expected {batch_size}",
            payload.accepted.len()
        )
        .into());
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let backend = BenchBackend::from_env()?;
    let settings = BenchSettings::from_env();
    let root = benchmark_root();
    fs::create_dir_all(&root)?;
    let config = build_config(&root, backend)?;
    let config_path = root.join("runtime.yaml");
    fs::write(&config_path, serde_yaml::to_string(&config)?)?;

    let state = IngestState::from_config(&config_path, config)?;
    let app = detect_http_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let client = Client::builder().build()?;
    let base_url = format!("http://{addr}");

    for request_index in 0..settings.warmup_requests {
        post_batch(&client, &base_url, request_index, settings.batch_size).await?;
    }

    let mut request_latencies_ms = Vec::with_capacity(settings.measured_requests);
    let benchmark_start = Instant::now();
    for request_index in 0..settings.measured_requests {
        let started = Instant::now();
        post_batch(
            &client,
            &base_url,
            settings.warmup_requests + request_index,
            settings.batch_size,
        )
        .await?;
        request_latencies_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
    }
    let elapsed_secs = benchmark_start.elapsed().as_secs_f64();
    request_latencies_ms.sort_by(|left, right| left.total_cmp(right));

    let readyz_response = client.get(format!("{base_url}/readyz")).send().await?;
    let readyz_status = readyz_response.status();
    let readyz_payload = readyz_response.json::<Value>().await?;

    let healthz_response = client.get(format!("{base_url}/healthz")).send().await?;
    let healthz_status = healthz_response.status();
    let healthz_payload = healthz_response.json::<Value>().await?;

    let metrics_response = client.get(format!("{base_url}/metrics")).send().await?;
    let metrics_status = metrics_response.status();
    let metrics_payload = metrics_response.text().await?;

    let _ = shutdown_tx.send(());
    server.await??;

    let p50 = percentile(&request_latencies_ms, 0.50);
    let p95 = percentile(&request_latencies_ms, 0.95);
    let p99 = percentile(&request_latencies_ms, 0.99);
    let throughput_rps = settings.measured_requests as f64 / elapsed_secs;
    let throughput_eps = (settings.measured_requests * settings.batch_size) as f64 / elapsed_secs;
    let heap_pressure_ratio = readyz_payload["components"]["heap"]["pressure_ratio"].as_f64();
    let substrate_backend = healthz_payload["components"]["substrate"]["backend"]
        .as_str()
        .unwrap_or("unknown");

    println!("backend={}", backend.as_str());
    println!("requests={}", settings.measured_requests);
    println!("batch_size={}", settings.batch_size);
    println!(
        "events={}",
        settings.measured_requests * settings.batch_size
    );
    println!("warmup_requests={}", settings.warmup_requests);
    println!("server_addr={addr}");
    println!("p50_request_ms={p50:.2}");
    println!("p95_request_ms={p95:.2}");
    println!("p99_request_ms={p99:.2}");
    println!("throughput_requests_per_sec={throughput_rps:.2}");
    println!("throughput_events_per_sec={throughput_eps:.2}");
    println!("readyz_status={readyz_status}");
    println!("healthz_status={healthz_status}");
    println!("metrics_status={metrics_status}");
    println!("readyz_heap_pressure_ratio={heap_pressure_ratio:?}");
    println!("substrate_backend={substrate_backend}");
    println!(
        "metrics_contains_detect_latency={}",
        metrics_payload.contains("swarm_detect_latency_microseconds")
    );
    println!(
        "metrics_contains_policy_latency={}",
        metrics_payload.contains("swarm_policy_latency_microseconds")
    );
    println!(
        "metrics_contains_heap_pressure={}",
        metrics_payload.contains("swarm_heap_pressure_ratio")
    );
    println!(
        "metrics_contains_ingest_request_latency={}",
        metrics_payload.contains("swarm_ingest_request_latency_microseconds")
    );
    println!(
        "metrics_contains_ingest_events={}",
        metrics_payload.contains("swarm_ingest_events_total")
    );
    println!(
        "note=measures loopback HTTP ingest, JSON validation, detector, policy, replay persistence, readiness, and the configured pheromone substrate"
    );
    println!("benchmark_root={}", root.display());

    Ok(())
}
