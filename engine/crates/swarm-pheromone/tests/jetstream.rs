#![cfg(feature = "nats")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Ignored integration tests for the JetStream-backed pheromone substrate.
//!
//! Run them through `tools/with-nats-jetstream.sh` so the repo owns the NATS
//! lifecycle instead of relying on a manually started server.
//!
//! Example:
//! `bash tools/with-nats-jetstream.sh cargo test -p swarm-pheromone --test jetstream deposits_survive_reconnect_with_shared_bucket -- --ignored --exact`

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use swarm_core::agent::{AgentRole, SwarmMode};
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig, ResponsePlaybookConfig};
use swarm_core::pheromone::{
    EscalationRecord, PheromoneDeposit, ThreatClass, ThreatClassConfig, ThreatIntelEntry,
    ThreatIntelIndicatorType,
};
use swarm_core::types::{AgentId, Severity};
use swarm_pheromone::{DepositSigningPayload, JetStreamPheromoneSubstrate, PheromoneSubstrate};

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

fn sample_deposit(agent_id: &str, timestamp: i64, confidence: f64) -> PheromoneDeposit {
    let signing_key = signing_key_for_label(agent_id);
    let derived_agent_id = agent_id_for_label(agent_id);
    let mut deposit = PheromoneDeposit {
        schema_version: PheromoneDeposit::current_schema_version(),
        indicator: serde_json::json!({
            "signal": "process-tree",
            "host_id": "host-1",
        }),
        threat_class: ThreatClass::Execution,
        severity: Severity::High,
        confidence,
        timestamp,
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

fn sample_deposit_with_host(
    agent_id: &str,
    timestamp: i64,
    confidence: f64,
    host_id: &str,
) -> PheromoneDeposit {
    let mut deposit = sample_deposit(agent_id, timestamp, confidence);
    deposit.indicator = serde_json::json!({
        "signal": "process-tree",
        "host_id": host_id,
    });
    sign_deposit(&mut deposit, &signing_key_for_label(agent_id));
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

fn unsigned_deposit() -> PheromoneDeposit {
    PheromoneDeposit {
        schema_version: PheromoneDeposit::current_schema_version(),
        indicator: serde_json::json!({"signal": "process-tree"}),
        threat_class: ThreatClass::Execution,
        severity: Severity::High,
        confidence: 0.9,
        timestamp: 100,
        decay_half_life: 3600.0,
        agent_id: AgentId("test-agent".to_string()),
        agent_identity: String::new(),
        agent_role: None,
        signature: Vec::new(),
        agent_key: Vec::new(),
    }
}

fn sample_escalation(mode: SwarmMode, timestamp: i64) -> EscalationRecord {
    EscalationRecord {
        mode,
        threat_class: ThreatClass::Execution,
        total_strength: 2.4,
        distinct_sources: 2,
        peak_confidence: 0.9,
        timestamp,
    }
}

fn sample_threat_class_config(
    threat_class: ThreatClass,
    half_life_secs: f64,
    alert_threshold: f64,
    incident_threshold: f64,
) -> ThreatClassConfig {
    ThreatClassConfig {
        threat_class,
        half_life_secs,
        evaporation_threshold: 0.05,
        alert_threshold,
        incident_threshold,
    }
}

fn sample_threat_intel_entry(
    indicator_type: ThreatIntelIndicatorType,
    value: &str,
    confidence: f64,
    expires_at: i64,
) -> ThreatIntelEntry {
    ThreatIntelEntry {
        indicator_type,
        value: value.to_string(),
        confidence,
        expires_at,
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
#[ignore = "run via tools/with-nats-jetstream.sh"]
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
#[ignore = "run via tools/with-nats-jetstream.sh"]
async fn recent_deposits_support_replay() {
    let Some((_bucket, substrate)) = connect_for_test("replay").await else {
        return;
    };
    substrate
        .deposit(sample_deposit("replay-alpha", 100, 1.0))
        .await
        .unwrap();
    substrate
        .deposit(sample_deposit("replay-beta", 200, 0.9))
        .await
        .unwrap();
    substrate
        .deposit(sample_deposit("replay-gamma", 300, 0.8))
        .await
        .unwrap();
    wait_until(|| async { substrate.recent_deposits(10).await.unwrap().len() == 3 }).await;

    let deposits = substrate.recent_deposits(2).await.unwrap();
    assert_eq!(deposits.len(), 2);
    assert_eq!(deposits[0].timestamp, 300);
    assert_eq!(deposits[1].timestamp, 200);
}

#[tokio::test]
#[ignore = "run via tools/with-nats-jetstream.sh"]
async fn deposit_round_trip_preserves_all_fields() {
    let Some((_bucket, substrate)) = connect_for_test("deposit-round-trip").await else {
        return;
    };
    let signing_key = signing_key_for_label("round-trip-agent");
    let derived_agent_id = agent_id_for_label("round-trip-agent");
    let mut deposit = PheromoneDeposit {
        schema_version: PheromoneDeposit::current_schema_version(),
        indicator: serde_json::json!({"cmd": "whoami", "host_id": "host-7"}),
        threat_class: ThreatClass::Execution,
        severity: Severity::High,
        confidence: 0.95,
        timestamp: 500,
        decay_half_life: 3600.0,
        agent_id: derived_agent_id.clone(),
        agent_identity: derived_agent_id.0.clone(),
        agent_role: Some(AgentRole::Whisker),
        signature: Vec::new(),
        agent_key: Vec::new(),
    };
    sign_deposit(&mut deposit, &signing_key);
    substrate.deposit(deposit).await.unwrap();
    wait_until(|| async { substrate.recent_deposits(1).await.unwrap().len() == 1 }).await;

    let deposits = substrate.recent_deposits(1).await.unwrap();
    assert_eq!(deposits.len(), 1);
    let stored = &deposits[0];
    assert_eq!(
        stored.indicator,
        serde_json::json!({"cmd": "whoami", "host_id": "host-7"})
    );
    assert_eq!(stored.threat_class, ThreatClass::Execution);
    assert_eq!(stored.severity, Severity::High);
    assert!((stored.confidence - 0.95).abs() < f64::EPSILON);
    assert_eq!(stored.timestamp, 500);
    assert!((stored.decay_half_life - 3600.0).abs() < f64::EPSILON);
    assert_eq!(stored.agent_role, Some(AgentRole::Whisker));
    assert!(!stored.signature.is_empty());
    assert!(!stored.agent_key.is_empty());
}

#[tokio::test]
#[ignore = "run via tools/with-nats-jetstream.sh"]
async fn concentration_decays_with_half_life() {
    let Some((_bucket, substrate)) = connect_for_test("half-life").await else {
        return;
    };
    let mut deposit = sample_deposit("decay-agent", 0, 1.0);
    deposit.decay_half_life = 3600.0;
    sign_deposit(&mut deposit, &signing_key_for_label("decay-agent"));
    substrate.deposit(deposit).await.unwrap();
    wait_until(|| async { substrate.recent_deposits(1).await.unwrap().len() == 1 }).await;

    let c0 = substrate
        .query_concentration(&ThreatClass::Execution, 0)
        .await
        .unwrap();
    assert!((c0.total_strength - 1.0).abs() < 0.01);

    let c1 = substrate
        .query_concentration(&ThreatClass::Execution, 3600)
        .await
        .unwrap();
    assert!(
        (c1.total_strength - 0.5).abs() < 0.01,
        "expected ~0.5 at one half-life, got {}",
        c1.total_strength
    );

    let c2 = substrate
        .query_concentration(&ThreatClass::Execution, 7200)
        .await
        .unwrap();
    assert!(
        (c2.total_strength - 0.25).abs() < 0.01,
        "expected ~0.25 at two half-lives, got {}",
        c2.total_strength
    );
}

#[tokio::test]
#[ignore = "run via tools/with-nats-jetstream.sh"]
async fn query_deposits_filters_by_threat_class_and_time() {
    let Some((_bucket, substrate)) = connect_for_test("query-filter").await else {
        return;
    };
    substrate
        .deposit(sample_deposit("filter-alpha", 100, 1.0))
        .await
        .unwrap();
    let mut second = sample_deposit("filter-beta", 200, 0.9);
    second.threat_class = ThreatClass::DefenseEvasion;
    sign_deposit(&mut second, &signing_key_for_label("filter-beta"));
    substrate.deposit(second).await.unwrap();
    wait_until(|| async { substrate.recent_deposits(10).await.unwrap().len() == 2 }).await;

    let deposits = substrate
        .query_deposits(swarm_pheromone::DepositQuery {
            threat_class: Some(ThreatClass::Execution),
            since_timestamp: Some(50),
            host_id: None,
            limit: 10,
        })
        .await
        .unwrap();
    assert_eq!(deposits.len(), 1);
    assert_eq!(deposits[0].timestamp, 100);
}

#[tokio::test]
#[ignore = "run via tools/with-nats-jetstream.sh"]
async fn query_deposits_filters_by_host_id() {
    let Some((_bucket, substrate)) = connect_for_test("host-filter").await else {
        return;
    };
    substrate
        .deposit(sample_deposit_with_host("host-alpha", 100, 1.0, "host-a"))
        .await
        .unwrap();
    substrate
        .deposit(sample_deposit_with_host("host-beta", 200, 0.9, "host-b"))
        .await
        .unwrap();
    wait_until(|| async { substrate.recent_deposits(10).await.unwrap().len() == 2 }).await;

    let deposits = substrate
        .query_deposits(swarm_pheromone::DepositQuery {
            threat_class: None,
            since_timestamp: None,
            host_id: Some("host-b".to_string()),
            limit: 10,
        })
        .await
        .unwrap();
    assert_eq!(deposits.len(), 1);
    assert_eq!(deposits[0].timestamp, 200);
    assert_eq!(deposits[0].indicator["host_id"], "host-b");
}

#[tokio::test]
#[ignore = "run via tools/with-nats-jetstream.sh"]
async fn query_escalations_returns_chronological_records() {
    let Some((_bucket, substrate)) = connect_for_test("escalation-query").await else {
        return;
    };
    substrate
        .record_escalation(sample_escalation(SwarmMode::Alert, 100))
        .await
        .unwrap();
    substrate
        .record_escalation(sample_escalation(SwarmMode::Incident, 250))
        .await
        .unwrap();
    wait_until(|| async { substrate.query_escalations(0).await.unwrap().len() == 2 }).await;

    let escalations = substrate.query_escalations(0).await.unwrap();
    assert_eq!(escalations.len(), 2);
    assert_eq!(escalations[0].mode, SwarmMode::Alert);
    assert_eq!(escalations[1].mode, SwarmMode::Incident);

    let since = substrate.query_escalations(150).await.unwrap();
    assert_eq!(since.len(), 1);
    assert_eq!(since[0].timestamp, 250);
}

#[tokio::test]
#[ignore = "run via tools/with-nats-jetstream.sh"]
async fn query_threat_class_configs_returns_stored_overrides() {
    let Some((_bucket, substrate)) = connect_for_test("threat-class-configs").await else {
        return;
    };
    substrate
        .store_threat_class_config(sample_threat_class_config(
            ThreatClass::Execution,
            120.0,
            1.2,
            3.0,
        ))
        .await
        .unwrap();
    substrate
        .store_threat_class_config(sample_threat_class_config(
            ThreatClass::DefenseEvasion,
            240.0,
            1.4,
            3.5,
        ))
        .await
        .unwrap();
    wait_until(|| async { substrate.query_threat_class_configs().await.unwrap().len() == 2 }).await;

    let configs = substrate.query_threat_class_configs().await.unwrap();
    assert_eq!(configs.len(), 2);
    assert_eq!(configs[0].threat_class, ThreatClass::DefenseEvasion);
    assert_eq!(configs[1].threat_class, ThreatClass::Execution);
}

#[tokio::test]
#[ignore = "run via tools/with-nats-jetstream.sh"]
async fn threat_class_override_affects_concentration_and_gc() {
    let Some((_bucket, substrate)) = connect_for_test("threat-class-override").await else {
        return;
    };
    substrate
        .store_threat_class_config(sample_threat_class_config(
            ThreatClass::Execution,
            60.0,
            0.4,
            0.8,
        ))
        .await
        .unwrap();
    substrate
        .deposit(sample_deposit("override-alpha", 0, 0.03))
        .await
        .unwrap();
    wait_until(|| async { substrate.recent_deposits(1).await.unwrap().len() == 1 }).await;

    let concentration = substrate
        .query_concentration(&ThreatClass::Execution, 0)
        .await
        .unwrap();
    assert_eq!(concentration.total_strength, 0.0);

    let removed = substrate.gc_evaporated(0).await.unwrap();
    assert_eq!(removed, 1);
}

#[tokio::test]
#[ignore = "run via tools/with-nats-jetstream.sh"]
async fn query_threat_intel_entry_respects_normalization_and_expiration() {
    let Some((_bucket, substrate)) = connect_for_test("threat-intel-normalization").await else {
        return;
    };
    substrate
        .store_threat_intel_entry(sample_threat_intel_entry(
            ThreatIntelIndicatorType::Domain,
            " Example.COM. ",
            0.92,
            1_700_000_000_100,
        ))
        .await
        .unwrap();
    wait_until(|| async {
        substrate
            .query_threat_intel_entry(
                &ThreatIntelIndicatorType::Domain,
                "example.com",
                1_700_000_000_000,
            )
            .await
            .unwrap()
            .is_some()
    })
    .await;

    let stored = substrate
        .query_threat_intel_entry(
            &ThreatIntelIndicatorType::Domain,
            "example.com",
            1_700_000_000_000,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.value, "example.com");
    assert_eq!(stored.confidence, 0.92);

    let expired = substrate
        .query_threat_intel_entry(
            &ThreatIntelIndicatorType::Domain,
            "EXAMPLE.COM.",
            1_700_000_000_100,
        )
        .await
        .unwrap();
    assert!(expired.is_none());
}

#[tokio::test]
#[ignore = "run via tools/with-nats-jetstream.sh"]
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
    assert_eq!(deposits[0].agent_id, agent_id_for_label("instance-beta"));
}

#[tokio::test]
#[ignore = "run via tools/with-nats-jetstream.sh"]
async fn gc_expired_threat_intel_removes_expired_entries() {
    let Some((_bucket, substrate)) = connect_for_test("gc-threat-intel").await else {
        return;
    };
    substrate
        .store_threat_intel_entry(sample_threat_intel_entry(
            ThreatIntelIndicatorType::Domain,
            "expired.example.com",
            0.9,
            500,
        ))
        .await
        .unwrap();
    substrate
        .store_threat_intel_entry(sample_threat_intel_entry(
            ThreatIntelIndicatorType::IpAddress,
            "10.0.0.1",
            0.8,
            2_000,
        ))
        .await
        .unwrap();
    wait_until(|| async {
        substrate
            .query_threat_intel_entry(&ThreatIntelIndicatorType::IpAddress, "10.0.0.1", 0)
            .await
            .unwrap()
            .is_some()
    })
    .await;

    let purged = substrate.gc_expired_threat_intel(1_000).await.unwrap();
    assert_eq!(purged, 1);

    let expired = substrate
        .query_threat_intel_entry(&ThreatIntelIndicatorType::Domain, "expired.example.com", 0)
        .await
        .unwrap();
    assert!(expired.is_none());

    let active = substrate
        .query_threat_intel_entry(&ThreatIntelIndicatorType::IpAddress, "10.0.0.1", 0)
        .await
        .unwrap();
    assert!(active.is_some());
}

#[tokio::test]
#[ignore = "run via tools/with-nats-jetstream.sh"]
async fn jetstream_rejects_unsigned_deposits() {
    let Some((_bucket, substrate)) = connect_for_test("unsigned").await else {
        return;
    };
    let error = substrate.deposit(unsigned_deposit()).await.unwrap_err();
    assert!(error.to_string().contains("empty signature"));
}
