#![cfg(feature = "nats")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Ignored integration tests for the JetStream-backed pheromone substrate.
//!
//! These require a JetStream-enabled NATS server at `NATS_URL` or
//! `nats://127.0.0.1:4222`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
use swarm_core::types::{AgentId, Severity};
use swarm_pheromone::{JetStreamPheromoneSubstrate, PheromoneSubstrate};

fn nats_url() -> String {
    std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string())
}

fn substrate_config() -> PheromoneConfig {
    PheromoneConfig {
        default_half_life_secs: 3600.0,
        evaporation_threshold: 0.01,
        min_sources_for_escalation: 2,
        alert_threshold: 2.0,
        incident_threshold: 5.0,
        backend: PheromoneBackendConfig::JetStream {
            url: nats_url(),
            connect_timeout_ms: 5_000,
            gc_page_size: 512,
        },
    }
}

async fn wait_until<F, Fut>(mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if condition().await {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition was not satisfied before timeout"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn sample_deposit(agent_id: &str, timestamp: i64, confidence: f64) -> PheromoneDeposit {
    PheromoneDeposit {
        indicator: serde_json::json!({"test": true}),
        threat_class: ThreatClass::Execution,
        severity: Severity::High,
        confidence,
        timestamp,
        decay_half_life: 3600.0,
        agent_id: AgentId(agent_id.to_string()),
        signature: Vec::new(),
        agent_key: Vec::new(),
    }
}

fn unique_bucket(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    format!("swarm-pheromone-{label}-{}-{nanos}", std::process::id())
}

async fn connect_for_test(label: &str) -> Option<(String, JetStreamPheromoneSubstrate)> {
    let bucket = unique_bucket(label);
    let url = nats_url();
    match JetStreamPheromoneSubstrate::connect_with_bucket(
        substrate_config(),
        url.clone(),
        bucket.clone(),
    )
    .await
    {
        Ok(substrate) => Some((bucket, substrate)),
        Err(error) => {
            eprintln!("NATS server not available at {url}, skipping JetStream test: {error}");
            None
        }
    }
}

#[tokio::test]
#[ignore = "requires a JetStream-enabled NATS server"]
async fn deposits_survive_reconnect_with_shared_bucket() {
    let Some((bucket, substrate)) = connect_for_test("restart").await else {
        return;
    };
    substrate
        .deposit(sample_deposit("instance-alpha", 100, 0.9))
        .await
        .unwrap();
    substrate
        .deposit(sample_deposit("instance-beta", 200, 0.8))
        .await
        .unwrap();
    wait_until(|| async { substrate.recent_deposits(10).await.unwrap().len() == 2 }).await;
    drop(substrate);

    let reopened =
        JetStreamPheromoneSubstrate::connect_with_bucket(substrate_config(), nats_url(), bucket)
            .await
            .unwrap();
    let deposits = reopened.recent_deposits(10).await.unwrap();
    assert_eq!(deposits.len(), 2);
    assert_eq!(deposits[0].timestamp, 200);
    assert_eq!(deposits[1].timestamp, 100);

    let health = reopened.health().await.unwrap();
    assert!(health.ready);
    assert!(health.durable);
}

#[tokio::test]
#[ignore = "requires a JetStream-enabled NATS server"]
async fn gc_removes_evaporated_entries_and_preserves_fresh_concentration() {
    let Some((_bucket, substrate)) = connect_for_test("gc").await else {
        return;
    };
    substrate
        .deposit(sample_deposit("instance-alpha", 0, 0.1))
        .await
        .unwrap();
    substrate
        .deposit(sample_deposit("instance-beta", 100_000, 0.9))
        .await
        .unwrap();
    wait_until(|| async { substrate.recent_deposits(10).await.unwrap().len() == 2 }).await;

    assert_eq!(substrate.recent_deposits(10).await.unwrap().len(), 2);

    let concentration = substrate
        .query_concentration(&ThreatClass::Execution, 100_000)
        .await
        .unwrap();
    assert_eq!(concentration.distinct_sources, 1);
    assert!(concentration.total_strength >= 0.9);

    let removed = substrate.gc_evaporated(100_000).await.unwrap();
    assert_eq!(removed, 1);

    let deposits = substrate.recent_deposits(10).await.unwrap();
    assert_eq!(deposits.len(), 1);
    assert_eq!(deposits[0].agent_id.0, "instance-beta");
}
