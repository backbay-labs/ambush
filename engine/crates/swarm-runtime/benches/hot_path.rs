use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Once;
use std::time::{Duration, Instant};
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
use swarm_core::types::AgentId;
use swarm_pheromone::ConfiguredPheromoneSubstrate;
use swarm_runtime::detection::pipeline::detect_and_deposit;
use swarm_runtime::escalation::ConcentrationMonitor;
use swarm_whisker::{SuspiciousProcessTreeDetector, TelemetryEvent};
use uuid::Uuid;

const DEFAULT_WARMUP_ITERS: usize = 1_000;
const DEFAULT_MEASURED_ITERS: usize = 20_000;
const BENCHMARK_NOW_SECS: i64 = 1_700_000_000;

#[derive(Clone, Copy, Debug)]
enum BenchBackend {
    InMemory,
    LocalJournal,
}

impl BenchBackend {
    fn from_env() -> Self {
        match std::env::var("STS_HOT_PATH_BACKEND")
            .unwrap_or_else(|_| "in_memory".to_string())
            .as_str()
        {
            "in_memory" => Self::InMemory,
            "local_journal" => Self::LocalJournal,
            other => panic!(
                "unsupported STS_HOT_PATH_BACKEND `{other}`; expected `in_memory` or `local_journal`"
            ),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::InMemory => "in_memory",
            Self::LocalJournal => "local_journal",
        }
    }
}

struct HotPathFixture {
    backend: BenchBackend,
    temp_root: Option<PathBuf>,
    detector: SuspiciousProcessTreeDetector,
    substrate: Arc<ConfiguredPheromoneSubstrate>,
    monitor: ConcentrationMonitor<ConfiguredPheromoneSubstrate>,
    event_json: serde_json::Value,
    agent_id: AgentId,
    signing_key: SigningKey,
}

impl HotPathFixture {
    fn new(backend: BenchBackend) -> Self {
        let temp_root = match backend {
            BenchBackend::InMemory => None,
            BenchBackend::LocalJournal => {
                let root = unique_temp_dir("swarm-runtime-hot-path-bench");
                fs::create_dir_all(&root).expect("local_journal benchmark temp root");
                Some(root)
            }
        };
        let config = pheromone_config(backend, temp_root.as_ref());
        let substrate = Arc::new(
            ConfiguredPheromoneSubstrate::from_config(&config)
                .expect("hot path benchmark substrate config must be valid"),
        );
        let detector = SuspiciousProcessTreeDetector::default();
        let monitor = ConcentrationMonitor::new(config.clone(), Arc::clone(&substrate));
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());

        Self {
            backend,
            temp_root,
            detector,
            substrate,
            monitor,
            event_json: synthetic_event_json(0),
            agent_id,
            signing_key,
        }
    }

    async fn run_once(mut self, event_index: usize) -> Result<HotPathOutcome, Box<dyn Error>> {
        let mut event_json = self.event_json.clone();
        event_json["event_id"] = json!(format!("evt-{event_index}"));
        let event: TelemetryEvent = serde_json::from_value(event_json)?;

        let detection = detect_and_deposit(
            &self.detector,
            self.substrate.as_ref(),
            &event,
            &self.agent_id,
            &pheromone_config(self.backend, self.temp_root.as_ref()),
            &self.signing_key,
        )
        .await?;
        let escalation = self.monitor.evaluate_all(BENCHMARK_NOW_SECS).await?;

        Ok(HotPathOutcome {
            finding_count: detection.findings.len(),
            deposit_count: detection.deposits.len(),
            escalation_count: escalation.events.len(),
        })
    }
}

impl Drop for HotPathFixture {
    fn drop(&mut self) {
        if let Some(root) = &self.temp_root {
            let _ = fs::remove_dir_all(root);
        }
    }
}

#[derive(Debug)]
struct HotPathOutcome {
    finding_count: usize,
    deposit_count: usize,
    escalation_count: usize,
}

fn unique_temp_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{label}-{}", Uuid::new_v4()))
}

fn pheromone_config(backend: BenchBackend, temp_root: Option<&PathBuf>) -> PheromoneConfig {
    PheromoneConfig {
        default_half_life_secs: 3600.0,
        evaporation_threshold: 0.01,
        min_sources_for_escalation: 1,
        alert_threshold: 0.4,
        incident_threshold: 0.8,
        deescalation_cooldown_secs: 300,
        response_playbook: Default::default(),
        backend: match backend {
            BenchBackend::InMemory => PheromoneBackendConfig::InMemory,
            BenchBackend::LocalJournal => {
                let root = temp_root.expect("local_journal backend requires a temp root");
                PheromoneBackendConfig::LocalJournal {
                    path: root.join("pheromones.jsonl").display().to_string(),
                }
            }
        },
    }
}

fn synthetic_event_json(index: usize) -> serde_json::Value {
    json!({
        "source": "benchmark",
        "event_id": format!("evt-{index}"),
        "timestamp": BENCHMARK_NOW_SECS,
        "host_id": "bench-host",
        "payload": {
            "kind": "process_start",
            "parent_process": "winword",
            "process_name": "powershell",
            "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ==",
            "user": "benchmark",
            "executable_path": null,
            "signer": null,
            "signature_valid": null
        }
    })
}

fn percentile(sorted_samples: &[f64], percentile: f64) -> f64 {
    let index = ((sorted_samples.len().saturating_sub(1) as f64) * percentile).round() as usize;
    sorted_samples[index]
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn emit_baseline_report(backend: BenchBackend) {
    static REPORT_ONCE: Once = Once::new();
    REPORT_ONCE.call_once(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("hot path benchmark runtime");
        let warmup = env_usize("STS_HOT_PATH_WARMUP", DEFAULT_WARMUP_ITERS);
        let measured = env_usize("STS_HOT_PATH_ITERS", DEFAULT_MEASURED_ITERS);
        let mut latencies_us = Vec::with_capacity(measured);

        for index in 0..warmup {
            let fixture = HotPathFixture::new(backend);
            let outcome = runtime
                .block_on(fixture.run_once(index))
                .expect("warmup hot path run");
            assert_eq!(outcome.finding_count, 1);
            assert_eq!(outcome.deposit_count, 1);
            assert_eq!(outcome.escalation_count, 1);
        }

        let benchmark_start = Instant::now();
        for index in 0..measured {
            let fixture = HotPathFixture::new(backend);
            let started = Instant::now();
            let outcome = runtime
                .block_on(fixture.run_once(index + warmup))
                .expect("measured hot path run");
            let elapsed_us = started.elapsed().as_secs_f64() * 1_000_000.0;
            assert_eq!(outcome.finding_count, 1);
            assert_eq!(outcome.deposit_count, 1);
            assert_eq!(outcome.escalation_count, 1);
            latencies_us.push(elapsed_us);
        }

        let total_secs = benchmark_start.elapsed().as_secs_f64();
        latencies_us.sort_by(|left, right| left.total_cmp(right));
        eprintln!("hot_path_baseline_backend={}", backend.as_str());
        eprintln!("hot_path_baseline_warmup={warmup}");
        eprintln!("hot_path_baseline_iterations={measured}");
        eprintln!(
            "hot_path_baseline_p50_us={:.2}",
            percentile(&latencies_us, 0.50)
        );
        eprintln!(
            "hot_path_baseline_p95_us={:.2}",
            percentile(&latencies_us, 0.95)
        );
        eprintln!(
            "hot_path_baseline_p99_us={:.2}",
            percentile(&latencies_us, 0.99)
        );
        eprintln!(
            "hot_path_baseline_throughput_eps={:.2}",
            measured as f64 / total_secs
        );
    });
}

fn hot_path_benchmark(c: &mut Criterion) {
    let backend = BenchBackend::from_env();
    emit_baseline_report(backend);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("hot path criterion runtime");
    let mut group = c.benchmark_group("hot_path");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));
    group.bench_function(
        format!("ingest_detect_deposit_escalate/{}", backend.as_str()),
        |b| {
            b.to_async(&runtime).iter_batched(
                || HotPathFixture::new(backend),
                |fixture: HotPathFixture| async move {
                    let outcome = fixture.run_once(0).await.expect("hot path iteration");
                    assert_eq!(outcome.finding_count, 1);
                    assert_eq!(outcome.deposit_count, 1);
                    assert_eq!(outcome.escalation_count, 1);
                    criterion::black_box(outcome);
                },
                BatchSize::SmallInput,
            );
        },
    );
    group.finish();
}

criterion_group!(benches, hot_path_benchmark);
criterion_main!(benches);
