#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Instant;

use ed25519_dalek::SigningKey;
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
use swarm_core::types::AgentId;
use swarm_pheromone::InMemoryPheromoneSubstrate;
use swarm_runtime::detection::pipeline::detect_and_deposit;
use swarm_whisker::{
    ProcessStartEvent, SuspiciousProcessTreeDetector, TelemetryEvent, TelemetryPayload,
};

fn percentile(sorted_samples: &[f64], percentile: f64) -> f64 {
    let index = ((sorted_samples.len().saturating_sub(1) as f64) * percentile).round() as usize;
    sorted_samples[index]
}

fn pheromone_config() -> PheromoneConfig {
    PheromoneConfig {
        default_half_life_secs: 3600.0,
        evaporation_threshold: 0.01,
        min_sources_for_escalation: 2,
        alert_threshold: 2.0,
        incident_threshold: 5.0,
        deescalation_cooldown_secs: 300,
        response_playbook: Default::default(),
        backend: PheromoneBackendConfig::InMemory,
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let iterations = std::env::var("STS_BENCH_ITERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(20_000);
    let warmup = std::env::var("STS_BENCH_WARMUP")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1_000);

    let detector = SuspiciousProcessTreeDetector::default();
    let substrate = InMemoryPheromoneSubstrate::new(pheromone_config());
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());

    let base_event = TelemetryEvent {
        source: "benchmark".to_string(),
        event_id: "evt-0".to_string(),
        timestamp: 1_700_000_000,
        host_id: Some("bench-host".to_string()),
        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: "winword".to_string(),
            process_name: "powershell".to_string(),
            command_line: "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ=="
                .to_string(),
            user: Some("benchmark".to_string()),
            executable_path: None,
            signer: None,
            signature_valid: None,
        }),
    };

    for index in 0..warmup {
        let mut event = base_event.clone();
        event.event_id = format!("warmup-{index}");
        let _ = detect_and_deposit(
            &detector,
            &substrate,
            &event,
            &agent_id,
            &pheromone_config(),
            &signing_key,
        )
        .await
        .unwrap();
    }

    let mut latencies_us = Vec::with_capacity(iterations);
    let total_start = Instant::now();

    for index in 0..iterations {
        let mut event = base_event.clone();
        event.event_id = format!("evt-{index}");

        let started = Instant::now();
        let outcome = detect_and_deposit(
            &detector,
            &substrate,
            &event,
            &agent_id,
            &pheromone_config(),
            &signing_key,
        )
        .await
        .unwrap();
        let elapsed_us = started.elapsed().as_secs_f64() * 1_000_000.0;

        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.deposits.len(), 1);
        latencies_us.push(elapsed_us);
    }

    let total_secs = total_start.elapsed().as_secs_f64();
    latencies_us.sort_by(|left, right| left.total_cmp(right));

    let p50 = percentile(&latencies_us, 0.50);
    let p95 = percentile(&latencies_us, 0.95);
    let p99 = percentile(&latencies_us, 0.99);
    let throughput = iterations as f64 / total_secs;

    println!("iterations={iterations}");
    println!("warmup={warmup}");
    println!("p50_us={p50:.2}");
    println!("p95_us={p95:.2}");
    println!("p99_us={p99:.2}");
    println!("throughput_eps={throughput:.2}");
}
