#![cfg(feature = "nats")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Ignored multi-instance integration tests for the shared JetStream substrate.
//!
//! These require a JetStream-enabled NATS server at `NATS_URL` or
//! `nats://127.0.0.1:4222`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig, ResponsePlaybookConfig};
use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
use swarm_core::types::{AgentId, Severity};
use swarm_pheromone::{DepositQuery, JetStreamPheromoneSubstrate, PheromoneSubstrate};

fn nats_url() -> String {
    std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string())
}

fn test_config() -> PheromoneConfig {
    PheromoneConfig {
        default_half_life_secs: 3600.0,
        evaporation_threshold: 0.01,
        min_sources_for_escalation: 2,
        alert_threshold: 2.0,
        incident_threshold: 5.0,
        deescalation_cooldown_secs: 300,
        response_playbook: ResponsePlaybookConfig::default(),
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

fn test_deposit(agent: &str, ts: i64, confidence: f64) -> PheromoneDeposit {
    PheromoneDeposit {
        indicator: serde_json::json!({"test": true}),
        threat_class: ThreatClass::Execution,
        severity: Severity::High,
        confidence,
        timestamp: ts,
        decay_half_life: 3600.0,
        agent_id: AgentId(agent.to_string()),
        agent_identity: String::new(),
        agent_role: None,
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

fn now_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as i64
}

async fn connect_pair(
    label: &str,
) -> Option<(JetStreamPheromoneSubstrate, JetStreamPheromoneSubstrate)> {
    let bucket = unique_bucket(label);
    let url = nats_url();
    let alpha = JetStreamPheromoneSubstrate::connect_with_bucket(
        test_config(),
        url.clone(),
        bucket.clone(),
    )
    .await;
    let beta =
        JetStreamPheromoneSubstrate::connect_with_bucket(test_config(), url.clone(), bucket).await;

    match (alpha, beta) {
        (Ok(alpha), Ok(beta)) => Some((alpha, beta)),
        (Err(error), _) | (_, Err(error)) => {
            eprintln!("NATS server not available at {url}, skipping multi-instance test: {error}");
            None
        }
    }
}

#[tokio::test]
#[ignore = "requires a JetStream-enabled NATS server"]
async fn cross_instance_deposit_visibility() {
    let Some((alpha, beta)) = connect_pair("visibility").await else {
        return;
    };
    let ts = now_timestamp();
    alpha
        .deposit(test_deposit("instance-alpha", ts, 0.95))
        .await
        .unwrap();
    wait_until(|| async {
        beta.query_concentration(&ThreatClass::Execution, ts + 1)
            .await
            .map(|concentration| concentration.distinct_sources == 1)
            .unwrap_or(false)
    })
    .await;

    let first = beta
        .query_concentration(&ThreatClass::Execution, ts + 1)
        .await
        .unwrap();
    assert_eq!(first.distinct_sources, 1);
    assert!(first.total_strength > 0.0);

    beta.deposit(test_deposit("instance-beta", ts + 1, 0.90))
        .await
        .unwrap();
    wait_until(|| async {
        alpha
            .query_concentration(&ThreatClass::Execution, ts + 2)
            .await
            .map(|concentration| concentration.distinct_sources == 2)
            .unwrap_or(false)
    })
    .await;

    let second = alpha
        .query_concentration(&ThreatClass::Execution, ts + 2)
        .await
        .unwrap();
    assert_eq!(second.distinct_sources, 2);
    assert!(second.total_strength > first.total_strength);
}

#[tokio::test]
#[ignore = "requires a JetStream-enabled NATS server"]
async fn escalation_requires_min_sources() {
    let Some((alpha, beta)) = connect_pair("threshold").await else {
        return;
    };
    let ts = now_timestamp();
    let mut first = test_deposit("instance-alpha", ts, 1.0);
    first.indicator = serde_json::json!({"test": true, "sequence": 1});
    alpha.deposit(first).await.unwrap();

    let mut second = test_deposit("instance-alpha", ts, 1.0);
    second.indicator = serde_json::json!({"test": true, "sequence": 2});
    alpha.deposit(second).await.unwrap();
    wait_until(|| async {
        alpha
            .query_concentration(&ThreatClass::Execution, ts)
            .await
            .map(|concentration| concentration.distinct_sources == 1)
            .unwrap_or(false)
    })
    .await;

    let before = alpha
        .query_concentration(&ThreatClass::Execution, ts)
        .await
        .unwrap();
    assert_eq!(before.distinct_sources, 1);
    assert!(before.total_strength >= test_config().alert_threshold);
    assert!(!before.exceeds_threshold(test_config().alert_threshold, 2));

    beta.deposit(test_deposit("instance-beta", ts, 0.9))
        .await
        .unwrap();
    wait_until(|| async {
        beta.query_concentration(&ThreatClass::Execution, ts)
            .await
            .map(|concentration| concentration.distinct_sources == 2)
            .unwrap_or(false)
    })
    .await;

    let after = beta
        .query_concentration(&ThreatClass::Execution, ts)
        .await
        .unwrap();
    assert_eq!(after.distinct_sources, 2);
    assert!(after.exceeds_threshold(test_config().alert_threshold, 2));
}

#[tokio::test]
#[ignore = "requires a JetStream-enabled NATS server"]
async fn single_instance_no_inflation() {
    let Some((alpha, _beta)) = connect_pair("single-source").await else {
        return;
    };
    let ts = now_timestamp();
    for offset in 0..5 {
        alpha
            .deposit(test_deposit("instance-alpha", ts + offset, 0.9))
            .await
            .unwrap();
    }
    wait_until(|| async {
        alpha
            .query_concentration(&ThreatClass::Execution, ts + 5)
            .await
            .map(|concentration| concentration.distinct_sources == 1)
            .unwrap_or(false)
    })
    .await;

    let concentration = alpha
        .query_concentration(&ThreatClass::Execution, ts + 5)
        .await
        .unwrap();
    assert_eq!(concentration.distinct_sources, 1);
    assert!(concentration.total_strength > test_config().alert_threshold);
    assert!(!concentration.exceeds_threshold(test_config().alert_threshold, 2));
}

#[tokio::test]
#[ignore = "requires a JetStream-enabled NATS server"]
async fn cross_instance_query_deposits() {
    let Some((alpha, beta)) = connect_pair("query").await else {
        return;
    };
    let ts = now_timestamp();
    alpha
        .deposit(test_deposit("instance-alpha", ts, 0.95))
        .await
        .unwrap();
    beta.deposit(test_deposit("instance-beta", ts + 1, 0.85))
        .await
        .unwrap();
    wait_until(|| async {
        alpha
            .query_deposits(DepositQuery::recent(10))
            .await
            .map(|deposits| deposits.len() == 2)
            .unwrap_or(false)
    })
    .await;

    let deposits = alpha
        .query_deposits(DepositQuery::recent(10))
        .await
        .unwrap();
    assert_eq!(deposits.len(), 2);
    assert!(
        deposits
            .iter()
            .any(|deposit| deposit.agent_id.0 == "instance-alpha")
    );
    assert!(
        deposits
            .iter()
            .any(|deposit| deposit.agent_id.0 == "instance-beta")
    );

    let mirrored = beta.query_deposits(DepositQuery::recent(10)).await.unwrap();
    assert_eq!(mirrored.len(), 2);
}
