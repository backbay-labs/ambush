#![allow(clippy::expect_used, clippy::unwrap_used)]

use axum::serve;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use swarm_core::config::{
    BundleStoreConfig, CorrelationConfig, InvestigationConfig, NotificationRoutingConfig,
    PheromoneBackendConfig, ResponseAdapterConfig, RuntimeMode, SwarmConfig, TelemetrySourceConfig,
};
use swarm_runtime::config::load_config;
use swarm_runtime::ingest::{IngestResponse, IngestState, detect_http_router};
use sysinfo::System;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use uuid::Uuid;

type BenchError = Box<dyn Error + Send + Sync>;

fn default_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/default.yaml")
}

#[derive(Clone, Copy, Debug)]
enum BenchBackend {
    LocalJournal,
    JetStream,
}

impl BenchBackend {
    fn from_env() -> Result<Self, BenchError> {
        match std::env::var("STS_E2E_BENCH_BACKEND")
            .unwrap_or_else(|_| "local_journal".to_string())
            .as_str()
        {
            "local_journal" => Ok(Self::LocalJournal),
            "jet_stream" => Ok(Self::JetStream),
            other => Err(bench_error(format!(
                "unsupported STS_E2E_BENCH_BACKEND `{other}`; expected `local_journal` or `jet_stream`"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::LocalJournal => "local_journal",
            Self::JetStream => "jet_stream",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BenchMode {
    Fixed,
    RampUntilShed,
}

impl BenchMode {
    fn from_env() -> Result<Self, BenchError> {
        match std::env::var("STS_E2E_BENCH_MODE")
            .unwrap_or_else(|_| "fixed".to_string())
            .as_str()
        {
            "fixed" => Ok(Self::Fixed),
            "ramp_until_shed" => Ok(Self::RampUntilShed),
            other => Err(bench_error(format!(
                "unsupported STS_E2E_BENCH_MODE `{other}`; expected `fixed` or `ramp_until_shed`"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::RampUntilShed => "ramp_until_shed",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct BenchSettings {
    mode: BenchMode,
    warmup_requests: usize,
    measured_requests: usize,
    batch_size: usize,
    stage_duration_secs: u64,
    starting_concurrency: usize,
    max_concurrency: usize,
    readyz_poll_ms: u64,
    max_heap_pressure: Option<f64>,
    heap_ballast_mb: usize,
}

impl BenchSettings {
    fn from_env() -> Result<Self, BenchError> {
        let mode = BenchMode::from_env()?;
        let settings = Self {
            mode,
            warmup_requests: env_usize("STS_E2E_BENCH_WARMUP_REQUESTS", 25),
            measured_requests: env_usize("STS_E2E_BENCH_REQUESTS", 200),
            batch_size: env_usize("STS_E2E_BENCH_BATCH_SIZE", 25),
            stage_duration_secs: env_u64("STS_E2E_BENCH_STAGE_DURATION_SECS", 3),
            starting_concurrency: env_usize("STS_E2E_BENCH_START_CONCURRENCY", 1),
            max_concurrency: env_usize("STS_E2E_BENCH_MAX_CONCURRENCY", 64),
            readyz_poll_ms: env_u64("STS_E2E_BENCH_READYZ_POLL_MS", 100),
            max_heap_pressure: env_optional_f64("STS_E2E_BENCH_MAX_HEAP_PRESSURE")?,
            heap_ballast_mb: env_usize("STS_E2E_BENCH_HEAP_BALLAST_MB", 0),
        };
        if settings.starting_concurrency == 0 {
            return Err(bench_error(
                "STS_E2E_BENCH_START_CONCURRENCY must be greater than zero",
            ));
        }
        if settings.max_concurrency < settings.starting_concurrency {
            return Err(bench_error(
                "STS_E2E_BENCH_MAX_CONCURRENCY must be greater than or equal to STS_E2E_BENCH_START_CONCURRENCY",
            ));
        }
        if settings.stage_duration_secs == 0 {
            return Err(bench_error(
                "STS_E2E_BENCH_STAGE_DURATION_SECS must be greater than zero",
            ));
        }
        if settings.readyz_poll_ms == 0 {
            return Err(bench_error(
                "STS_E2E_BENCH_READYZ_POLL_MS must be greater than zero",
            ));
        }
        Ok(settings)
    }
}

#[derive(Debug)]
struct HostProfile {
    os_name: String,
    os_version: String,
    kernel_version: String,
    cpu_cores: usize,
    total_memory_bytes: u64,
}

impl HostProfile {
    fn detect() -> Self {
        let mut system = System::new_all();
        system.refresh_memory();
        Self {
            os_name: System::name().unwrap_or_else(|| "unknown".to_string()),
            os_version: System::os_version().unwrap_or_else(|| "unknown".to_string()),
            kernel_version: System::kernel_version().unwrap_or_else(|| "unknown".to_string()),
            cpu_cores: system.cpus().len(),
            total_memory_bytes: system.total_memory(),
        }
    }

    fn total_memory_gib(&self) -> f64 {
        self.total_memory_bytes as f64 / 1024_f64.powi(3)
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_optional_f64(name: &str) -> Result<Option<f64>, BenchError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value.parse::<f64>().map_err(|error| {
            bench_error(format!("failed to parse {name} as f64: {error}"))
        })?)),
        Err(_) => Ok(None),
    }
}

fn percentile(sorted_samples: &[f64], percentile: f64) -> f64 {
    let index = ((sorted_samples.len().saturating_sub(1) as f64) * percentile).round() as usize;
    sorted_samples[index]
}

fn benchmark_root() -> PathBuf {
    std::env::temp_dir().join(format!("swarm-runtime-e2e-bench-{}", Uuid::new_v4()))
}

fn build_config(
    root: &Path,
    backend: BenchBackend,
    settings: BenchSettings,
) -> Result<SwarmConfig, BenchError> {
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
    if let Some(max_heap_pressure) = settings.max_heap_pressure {
        config.runtime.max_heap_pressure = max_heap_pressure;
    }
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

fn bench_error(message: impl Into<String>) -> BenchError {
    std::io::Error::other(message.into()).into()
}

async fn post_batch(
    client: &Client,
    base_url: &str,
    request_index: usize,
    batch_size: usize,
) -> Result<usize, BenchError> {
    let response = client
        .post(format!("{base_url}/v1/ingest/events"))
        .json(&build_request_body(request_index, batch_size))
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(bench_error(format!(
            "ingest returned {}",
            response.status()
        )));
    }
    let payload = response.json::<IngestResponse>().await?;
    if !payload.rejected.is_empty() {
        return Err(bench_error(format!(
            "ingest rejected {} events during request {request_index}",
            payload.rejected.len()
        )));
    }
    if payload.accepted.len() != batch_size {
        return Err(bench_error(format!(
            "ingest accepted {} events during request {request_index}; expected {batch_size}",
            payload.accepted.len()
        )));
    }
    Ok(payload.accepted.len())
}

fn allocate_heap_ballast(megabytes: usize) -> Vec<u8> {
    let bytes = megabytes.saturating_mul(1024 * 1024);
    let mut ballast = vec![0u8; bytes];
    for byte in ballast.iter_mut().step_by(4096).take(1.max(bytes / 4096)) {
        *byte = byte.saturating_add(1);
    }
    ballast
}

#[derive(Clone, Debug)]
struct HealthSample {
    status: StatusCode,
    pressure_ratio: Option<f64>,
}

async fn fetch_readyz_sample(client: &Client, base_url: &str) -> Result<HealthSample, BenchError> {
    let response = client.get(format!("{base_url}/readyz")).send().await?;
    let status = response.status();
    let payload = response.json::<Value>().await?;
    Ok(HealthSample {
        status,
        pressure_ratio: payload["components"]["heap"]["pressure_ratio"].as_f64(),
    })
}

#[derive(Debug)]
struct PostRunHealth {
    readyz_status: StatusCode,
    readyz_payload: Value,
    healthz_status: StatusCode,
    healthz_payload: Value,
    metrics_status: StatusCode,
    metrics_payload: String,
}

async fn fetch_post_run_health(
    client: &Client,
    base_url: &str,
) -> Result<PostRunHealth, BenchError> {
    let readyz_response = client.get(format!("{base_url}/readyz")).send().await?;
    let readyz_status = readyz_response.status();
    let readyz_payload = readyz_response.json::<Value>().await?;

    let healthz_response = client.get(format!("{base_url}/healthz")).send().await?;
    let healthz_status = healthz_response.status();
    let healthz_payload = healthz_response.json::<Value>().await?;

    let metrics_response = client.get(format!("{base_url}/metrics")).send().await?;
    let metrics_status = metrics_response.status();
    let metrics_payload = metrics_response.text().await?;

    Ok(PostRunHealth {
        readyz_status,
        readyz_payload,
        healthz_status,
        healthz_payload,
        metrics_status,
        metrics_payload,
    })
}

async fn run_warmup(
    client: &Client,
    base_url: &str,
    batch_size: usize,
    warmup_requests: usize,
    next_request_index: &mut usize,
) -> Result<(), BenchError> {
    for _ in 0..warmup_requests {
        post_batch(client, base_url, *next_request_index, batch_size).await?;
        *next_request_index += 1;
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct StageReadinessReport {
    polls: usize,
    shed_observed: bool,
    shed_status: Option<StatusCode>,
    peak_pressure_ratio: Option<f64>,
    last_pressure_ratio: Option<f64>,
    last_status: Option<StatusCode>,
}

#[derive(Debug)]
struct WorkerStageSummary {
    successful_requests: usize,
    accepted_events: usize,
    latencies_ms: Vec<f64>,
}

#[derive(Clone, Debug)]
struct StageSummary {
    concurrency: usize,
    successful_requests: usize,
    accepted_events: usize,
    elapsed_secs: f64,
    throughput_requests_per_sec: f64,
    throughput_events_per_sec: f64,
    p50_request_ms: f64,
    p95_request_ms: f64,
    p99_request_ms: f64,
    readiness: StageReadinessReport,
    next_request_index: usize,
}

fn build_stage_summary(
    concurrency: usize,
    elapsed_secs: f64,
    readiness: StageReadinessReport,
    next_request_index: usize,
    mut latencies_ms: Vec<f64>,
    successful_requests: usize,
    accepted_events: usize,
) -> Result<StageSummary, BenchError> {
    if latencies_ms.is_empty() {
        return Err(bench_error(format!(
            "concurrency stage {concurrency} completed without any successful requests"
        )));
    }
    latencies_ms.sort_by(|left, right| left.total_cmp(right));
    Ok(StageSummary {
        concurrency,
        successful_requests,
        accepted_events,
        elapsed_secs,
        throughput_requests_per_sec: successful_requests as f64 / elapsed_secs,
        throughput_events_per_sec: accepted_events as f64 / elapsed_secs,
        p50_request_ms: percentile(&latencies_ms, 0.50),
        p95_request_ms: percentile(&latencies_ms, 0.95),
        p99_request_ms: percentile(&latencies_ms, 0.99),
        readiness,
        next_request_index,
    })
}

async fn run_concurrency_stage(
    client: &Client,
    base_url: &str,
    batch_size: usize,
    concurrency: usize,
    duration: Duration,
    readyz_poll: Duration,
    request_index_start: usize,
) -> Result<StageSummary, BenchError> {
    let deadline = Instant::now() + duration;
    let should_stop = Arc::new(AtomicBool::new(false));
    let request_counter = Arc::new(AtomicUsize::new(request_index_start));
    let mut workers = JoinSet::new();

    for _ in 0..concurrency {
        let client = client.clone();
        let base_url = base_url.to_string();
        let should_stop = Arc::clone(&should_stop);
        let request_counter = Arc::clone(&request_counter);
        workers.spawn(async move {
            let mut latencies_ms = Vec::new();
            let mut successful_requests = 0usize;
            let mut accepted_events = 0usize;
            while !should_stop.load(Ordering::SeqCst) && Instant::now() < deadline {
                let request_index = request_counter.fetch_add(1, Ordering::SeqCst);
                let started = Instant::now();
                let accepted = post_batch(&client, &base_url, request_index, batch_size).await?;
                successful_requests += 1;
                accepted_events += accepted;
                latencies_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
            }
            Ok::<WorkerStageSummary, BenchError>(WorkerStageSummary {
                successful_requests,
                accepted_events,
                latencies_ms,
            })
        });
    }

    let poll_client = client.clone();
    let poll_base_url = base_url.to_string();
    let poll_stop = Arc::clone(&should_stop);
    let poller = tokio::spawn(async move {
        let mut report = StageReadinessReport::default();
        loop {
            let sample = fetch_readyz_sample(&poll_client, &poll_base_url).await?;
            report.polls += 1;
            report.last_status = Some(sample.status);
            report.last_pressure_ratio = sample.pressure_ratio;
            report.peak_pressure_ratio = match (report.peak_pressure_ratio, sample.pressure_ratio) {
                (Some(current), Some(next)) => Some(current.max(next)),
                (None, next) => next,
                (current, None) => current,
            };
            if !sample.status.is_success() {
                report.shed_observed = true;
                report.shed_status = Some(sample.status);
                poll_stop.store(true, Ordering::SeqCst);
                break;
            }
            if poll_stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(readyz_poll).await;
        }
        Ok::<StageReadinessReport, BenchError>(report)
    });

    let stage_start = Instant::now();
    let mut accepted_events = 0usize;
    let mut successful_requests = 0usize;
    let mut latencies_ms = Vec::new();
    while let Some(result) = workers.join_next().await {
        let summary = result??;
        accepted_events += summary.accepted_events;
        successful_requests += summary.successful_requests;
        latencies_ms.extend(summary.latencies_ms);
    }
    should_stop.store(true, Ordering::SeqCst);
    let readiness = poller.await??;
    let elapsed_secs = stage_start.elapsed().as_secs_f64();
    let next_request_index = request_counter.load(Ordering::SeqCst);
    build_stage_summary(
        concurrency,
        elapsed_secs,
        readiness,
        next_request_index,
        latencies_ms,
        successful_requests,
        accepted_events,
    )
}

#[derive(Debug)]
struct FixedBenchmarkReport {
    successful_requests: usize,
    accepted_events: usize,
    p50_request_ms: f64,
    p95_request_ms: f64,
    p99_request_ms: f64,
    throughput_requests_per_sec: f64,
    throughput_events_per_sec: f64,
}

async fn run_fixed_benchmark(
    client: &Client,
    base_url: &str,
    settings: BenchSettings,
) -> Result<FixedBenchmarkReport, BenchError> {
    let mut next_request_index = 0usize;
    run_warmup(
        client,
        base_url,
        settings.batch_size,
        settings.warmup_requests,
        &mut next_request_index,
    )
    .await?;

    let mut request_latencies_ms = Vec::with_capacity(settings.measured_requests);
    let benchmark_start = Instant::now();
    let mut accepted_events = 0usize;
    for _ in 0..settings.measured_requests {
        let started = Instant::now();
        accepted_events +=
            post_batch(client, base_url, next_request_index, settings.batch_size).await?;
        request_latencies_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
        next_request_index += 1;
    }
    let elapsed_secs = benchmark_start.elapsed().as_secs_f64();
    request_latencies_ms.sort_by(|left, right| left.total_cmp(right));

    Ok(FixedBenchmarkReport {
        successful_requests: settings.measured_requests,
        accepted_events,
        p50_request_ms: percentile(&request_latencies_ms, 0.50),
        p95_request_ms: percentile(&request_latencies_ms, 0.95),
        p99_request_ms: percentile(&request_latencies_ms, 0.99),
        throughput_requests_per_sec: settings.measured_requests as f64 / elapsed_secs,
        throughput_events_per_sec: accepted_events as f64 / elapsed_secs,
    })
}

#[derive(Debug)]
struct RampBenchmarkReport {
    baseline_readyz: HealthSample,
    stages: Vec<StageSummary>,
    highest_stable_stage: Option<StageSummary>,
    first_shedding_stage: Option<StageSummary>,
}

async fn run_ramp_benchmark(
    client: &Client,
    base_url: &str,
    settings: BenchSettings,
) -> Result<RampBenchmarkReport, BenchError> {
    let mut next_request_index = 0usize;
    run_warmup(
        client,
        base_url,
        settings.batch_size,
        settings.warmup_requests,
        &mut next_request_index,
    )
    .await?;
    let baseline_readyz = fetch_readyz_sample(client, base_url).await?;

    let mut stages = Vec::new();
    let mut concurrency = settings.starting_concurrency;
    let stage_duration = Duration::from_secs(settings.stage_duration_secs);
    let readyz_poll = Duration::from_millis(settings.readyz_poll_ms);

    loop {
        let stage = run_concurrency_stage(
            client,
            base_url,
            settings.batch_size,
            concurrency,
            stage_duration,
            readyz_poll,
            next_request_index,
        )
        .await?;
        next_request_index = stage.next_request_index;
        let stage_shed = stage.readiness.shed_observed;
        stages.push(stage);
        if stage_shed || concurrency >= settings.max_concurrency {
            break;
        }
        let next_concurrency = (concurrency.saturating_mul(2)).min(settings.max_concurrency);
        if next_concurrency == concurrency {
            break;
        }
        concurrency = next_concurrency;
    }

    let highest_stable_stage = stages
        .iter()
        .filter(|stage| !stage.readiness.shed_observed)
        .max_by_key(|stage| stage.concurrency)
        .cloned();
    let first_shedding_stage = stages
        .iter()
        .find(|stage| stage.readiness.shed_observed)
        .cloned();

    Ok(RampBenchmarkReport {
        baseline_readyz,
        stages,
        highest_stable_stage,
        first_shedding_stage,
    })
}

fn print_common_report(
    host: &HostProfile,
    settings: BenchSettings,
    backend: BenchBackend,
    configured_max_heap_pressure: f64,
    addr: std::net::SocketAddr,
) {
    println!("mode={}", settings.mode.as_str());
    println!("backend={}", backend.as_str());
    println!("server_addr={addr}");
    println!("host_os_name={}", host.os_name);
    println!("host_os_version={}", host.os_version);
    println!("host_kernel_version={}", host.kernel_version);
    println!("host_cpu_cores={}", host.cpu_cores);
    println!("host_total_memory_gib={:.2}", host.total_memory_gib());
    println!("warmup_requests={}", settings.warmup_requests);
    println!("batch_size={}", settings.batch_size);
    println!("configured_max_heap_pressure={configured_max_heap_pressure:.6}");
    println!("heap_ballast_mb={}", settings.heap_ballast_mb);
}

fn print_fixed_report(report: &FixedBenchmarkReport) {
    println!("requests={}", report.successful_requests);
    println!("events={}", report.accepted_events);
    println!("p50_request_ms={:.2}", report.p50_request_ms);
    println!("p95_request_ms={:.2}", report.p95_request_ms);
    println!("p99_request_ms={:.2}", report.p99_request_ms);
    println!(
        "throughput_requests_per_sec={:.2}",
        report.throughput_requests_per_sec
    );
    println!(
        "throughput_events_per_sec={:.2}",
        report.throughput_events_per_sec
    );
}

fn print_ramp_report(settings: BenchSettings, report: &RampBenchmarkReport) {
    println!("stage_duration_secs={}", settings.stage_duration_secs);
    println!("start_concurrency={}", settings.starting_concurrency);
    println!("max_concurrency={}", settings.max_concurrency);
    println!("readyz_poll_ms={}", settings.readyz_poll_ms);
    println!("baseline_readyz_status={}", report.baseline_readyz.status);
    println!(
        "baseline_readyz_heap_pressure_ratio={:?}",
        report.baseline_readyz.pressure_ratio
    );
    println!("stage_count={}", report.stages.len());
    for (index, stage) in report.stages.iter().enumerate() {
        let stage_number = index + 1;
        println!("stage_{stage_number}_concurrency={}", stage.concurrency);
        println!(
            "stage_{stage_number}_successful_requests={}",
            stage.successful_requests
        );
        println!(
            "stage_{stage_number}_accepted_events={}",
            stage.accepted_events
        );
        println!(
            "stage_{stage_number}_elapsed_secs={:.2}",
            stage.elapsed_secs
        );
        println!(
            "stage_{stage_number}_throughput_events_per_sec={:.2}",
            stage.throughput_events_per_sec
        );
        println!(
            "stage_{stage_number}_throughput_requests_per_sec={:.2}",
            stage.throughput_requests_per_sec
        );
        println!(
            "stage_{stage_number}_p50_request_ms={:.2}",
            stage.p50_request_ms
        );
        println!(
            "stage_{stage_number}_p95_request_ms={:.2}",
            stage.p95_request_ms
        );
        println!(
            "stage_{stage_number}_p99_request_ms={:.2}",
            stage.p99_request_ms
        );
        println!(
            "stage_{stage_number}_peak_heap_pressure_ratio={:?}",
            stage.readiness.peak_pressure_ratio
        );
        println!(
            "stage_{stage_number}_readyz_last_status={}",
            stage
                .readiness
                .last_status
                .map(|status| status.as_u16().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );
        println!(
            "stage_{stage_number}_readyz_polls={}",
            stage.readiness.polls
        );
        println!(
            "stage_{stage_number}_shed={}",
            stage.readiness.shed_observed
        );
        if let Some(status) = stage.readiness.shed_status {
            println!("stage_{stage_number}_shed_status={status}");
        }
    }
    if let Some(stage) = &report.highest_stable_stage {
        println!("shed_observed={}", report.first_shedding_stage.is_some());
        println!("highest_stable_concurrency={}", stage.concurrency);
        println!(
            "highest_stable_throughput_events_per_sec={:.2}",
            stage.throughput_events_per_sec
        );
        println!("highest_stable_p95_request_ms={:.2}", stage.p95_request_ms);
    } else {
        println!("shed_observed={}", report.first_shedding_stage.is_some());
        println!("highest_stable_concurrency=none");
        println!("highest_stable_throughput_events_per_sec=none");
    }
    if let Some(stage) = &report.first_shedding_stage {
        println!("first_shedding_concurrency={}", stage.concurrency);
        println!(
            "first_shedding_throughput_events_per_sec={:.2}",
            stage.throughput_events_per_sec
        );
        println!(
            "first_shedding_peak_heap_pressure_ratio={:?}",
            stage.readiness.peak_pressure_ratio
        );
    } else {
        println!("first_shedding_concurrency=none");
    }
}

fn print_post_run_health(report: &PostRunHealth) {
    let heap_pressure_ratio =
        report.readyz_payload["components"]["heap"]["pressure_ratio"].as_f64();
    let substrate_backend = report.healthz_payload["components"]["substrate"]["backend"]
        .as_str()
        .unwrap_or("unknown");
    println!("readyz_status={}", report.readyz_status);
    println!("healthz_status={}", report.healthz_status);
    println!("metrics_status={}", report.metrics_status);
    println!("readyz_heap_pressure_ratio={heap_pressure_ratio:?}");
    println!("substrate_backend={substrate_backend}");
    println!(
        "metrics_contains_detect_latency={}",
        report
            .metrics_payload
            .contains("swarm_detect_latency_microseconds")
    );
    println!(
        "metrics_contains_policy_latency={}",
        report
            .metrics_payload
            .contains("swarm_policy_latency_microseconds")
    );
    println!(
        "metrics_contains_heap_pressure={}",
        report.metrics_payload.contains("swarm_heap_pressure_ratio")
    );
    println!(
        "metrics_contains_ingest_request_latency={}",
        report
            .metrics_payload
            .contains("swarm_ingest_request_latency_microseconds")
    );
    println!(
        "metrics_contains_ingest_events={}",
        report.metrics_payload.contains("swarm_ingest_events_total")
    );
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), BenchError> {
    let host = HostProfile::detect();
    let backend = BenchBackend::from_env()?;
    let settings = BenchSettings::from_env()?;
    let root = benchmark_root();
    fs::create_dir_all(&root)?;
    let heap_ballast = allocate_heap_ballast(settings.heap_ballast_mb);
    std::hint::black_box(&heap_ballast);
    let config = build_config(&root, backend, settings)?;
    let configured_max_heap_pressure = config.runtime.max_heap_pressure;
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

    print_common_report(&host, settings, backend, configured_max_heap_pressure, addr);
    match settings.mode {
        BenchMode::Fixed => {
            let report = run_fixed_benchmark(&client, &base_url, settings).await?;
            print_fixed_report(&report);
        }
        BenchMode::RampUntilShed => {
            let report = run_ramp_benchmark(&client, &base_url, settings).await?;
            print_ramp_report(settings, &report);
        }
    }
    let post_run_health = fetch_post_run_health(&client, &base_url).await?;

    let _ = shutdown_tx.send(());
    server.await??;
    print_post_run_health(&post_run_health);
    println!(
        "note=measures loopback HTTP ingest, JSON validation, detector, policy, replay persistence, readiness, and the configured pheromone substrate"
    );
    println!("benchmark_root={}", root.display());

    Ok(())
}
