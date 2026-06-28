#![cfg(feature = "nats")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Ignored multi-instance integration tests for the shared JetStream substrate.
//!
//! Run them through `tools/with-nats-jetstream.sh` so the repo owns the NATS
//! lifecycle instead of relying on a manually started server.
//!
//! Example:
//! `bash tools/with-nats-jetstream.sh cargo test -p swarm-pheromone --test multi_instance cross_instance_deposit_visibility -- --ignored --exact`

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig, ResponsePlaybookConfig};
use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
use swarm_core::types::{AgentId, Severity};
use swarm_pheromone::{
    DepositQuery, DepositSigningPayload, JetStreamPheromoneSubstrate, PheromoneSubstrate,
};

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
    let signing_key = signing_key_for_label(agent);
    let derived_agent_id = agent_id_for_label(agent);
    let mut deposit = PheromoneDeposit {
        schema_version: PheromoneDeposit::current_schema_version(),
        indicator: serde_json::json!({"test": true}),
        threat_class: ThreatClass::Execution,
        severity: Severity::High,
        confidence,
        timestamp: ts,
        decay_half_life: 3600.0,
        agent_id: derived_agent_id.clone(),
        agent_identity: derived_agent_id.0,
        agent_role: None,
        signature: Vec::new(),
        agent_key: Vec::new(),
    };
    sign_deposit(&mut deposit, &signing_key);
    deposit
}

fn strategy_scoped_deposit(
    base_agent: &str,
    scope: &str,
    ts: i64,
    confidence: f64,
) -> PheromoneDeposit {
    let signing_key = signing_key_for_label(base_agent);
    let derived_agent_id = agent_id_for_label(base_agent);
    let mut deposit = PheromoneDeposit {
        schema_version: PheromoneDeposit::current_schema_version(),
        indicator: serde_json::json!({
            "test": true,
            "scope": scope,
        }),
        threat_class: ThreatClass::Execution,
        severity: Severity::High,
        confidence,
        timestamp: ts,
        decay_half_life: 3600.0,
        agent_id: AgentId(format!("{}:{scope}", derived_agent_id.0)),
        agent_identity: derived_agent_id.0,
        agent_role: None,
        signature: Vec::new(),
        agent_key: Vec::new(),
    };
    sign_deposit(&mut deposit, &signing_key);
    deposit
}

fn signing_key_for_label(label: &str) -> SigningKey {
    let digest = Sha256::digest(label.as_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    SigningKey::from_bytes(&seed)
}

fn agent_id_for_label(label: &str) -> AgentId {
    AgentId::from_verifying_key(&signing_key_for_label(label).verifying_key())
}

fn sign_deposit(deposit: &mut PheromoneDeposit, key: &SigningKey) {
    let payload = DepositSigningPayload {
        schema_version: deposit.schema_version,
        indicator: &deposit.indicator,
        threat_class: &deposit.threat_class,
        severity: &deposit.severity,
        confidence: deposit.confidence,
        timestamp: deposit.timestamp,
        decay_half_life: deposit.decay_half_life,
        agent_id: &deposit.agent_id,
        agent_identity: &deposit.agent_identity,
        agent_role: deposit.agent_role,
    };
    let payload_bytes = serde_json::to_vec(&payload).expect("deposit signing payload");
    let signature = key.sign(&payload_bytes);
    deposit.signature = signature.to_bytes().to_vec();
    deposit.agent_key = key.verifying_key().to_bytes().to_vec();
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
#[ignore = "run via tools/with-nats-jetstream.sh"]
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
#[ignore = "run via tools/with-nats-jetstream.sh"]
async fn escalation_requires_min_sources() {
    let Some((alpha, beta)) = connect_pair("threshold").await else {
        return;
    };
    let ts = now_timestamp();
    let mut first = test_deposit("instance-alpha", ts, 1.0);
    first.indicator = serde_json::json!({"test": true, "sequence": 1});
    sign_deposit(&mut first, &signing_key_for_label("instance-alpha"));
    alpha.deposit(first).await.unwrap();

    let mut second = test_deposit("instance-alpha", ts, 1.0);
    second.indicator = serde_json::json!({"test": true, "sequence": 2});
    sign_deposit(&mut second, &signing_key_for_label("instance-alpha"));
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
#[ignore = "run via tools/with-nats-jetstream.sh"]
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
#[ignore = "run via tools/with-nats-jetstream.sh"]
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
            .any(|deposit| deposit.agent_id == agent_id_for_label("instance-alpha"))
    );
    assert!(
        deposits
            .iter()
            .any(|deposit| deposit.agent_id == agent_id_for_label("instance-beta"))
    );

    let mirrored = beta.query_deposits(DepositQuery::recent(10)).await.unwrap();
    assert_eq!(mirrored.len(), 2);
}

#[tokio::test]
#[ignore = "run via tools/with-nats-jetstream.sh"]
async fn strategy_scoped_agent_ids_count_as_distinct_sources_across_instances() {
    let Some((alpha, beta)) = connect_pair("strategy-scope-distinct").await else {
        return;
    };
    let ts = now_timestamp();
    alpha
        .deposit(strategy_scoped_deposit(
            "shared-whisker",
            "suspicious_process_tree",
            ts,
            0.9,
        ))
        .await
        .unwrap();
    beta.deposit(strategy_scoped_deposit(
        "shared-whisker",
        "dns_exfiltration",
        ts + 1,
        0.9,
    ))
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

    let concentration = alpha
        .query_concentration(&ThreatClass::Execution, ts + 2)
        .await
        .unwrap();
    assert_eq!(concentration.distinct_sources, 2);
}

#[tokio::test]
#[ignore = "run via tools/with-nats-jetstream.sh"]
async fn repeated_strategy_scoped_agent_id_collapses_to_one_source() {
    let Some((alpha, _beta)) = connect_pair("strategy-scope-collapsed").await else {
        return;
    };
    let ts = now_timestamp();
    alpha
        .deposit(strategy_scoped_deposit(
            "shared-whisker",
            "behavioral_anomaly",
            ts,
            0.9,
        ))
        .await
        .unwrap();
    alpha
        .deposit(strategy_scoped_deposit(
            "shared-whisker",
            "behavioral_anomaly",
            ts + 1,
            0.8,
        ))
        .await
        .unwrap();
    wait_until(|| async {
        alpha
            .query_concentration(&ThreatClass::Execution, ts + 2)
            .await
            .map(|concentration| concentration.distinct_sources == 1)
            .unwrap_or(false)
    })
    .await;

    let concentration = alpha
        .query_concentration(&ThreatClass::Execution, ts + 2)
        .await
        .unwrap();
    assert_eq!(concentration.distinct_sources, 1);
}
