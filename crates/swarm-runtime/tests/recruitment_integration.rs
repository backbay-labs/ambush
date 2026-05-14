#![allow(clippy::unwrap_used)]

use ed25519_dalek::SigningKey;
use serde_json::json;
use std::sync::Arc;
use swarm_core::agent::SwarmMode;
use swarm_core::config::{PheromoneBackendConfig, SwarmConfig};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::{AgentId, Severity};
use swarm_pheromone::{
    InMemoryPheromoneSubstrate, LocalJournalPheromoneSubstrate, PheromoneSubstrate,
};
use swarm_runtime::config::load_config;
use swarm_runtime::control::build_composite_detector;
use swarm_runtime::detection::detect_and_deposit;
use swarm_runtime::escalation::ConcentrationMonitor;
use swarm_whisker::{
    DetectionFinding, DetectionStrategy, NetworkConnectEvent, TelemetryEvent, TelemetryPayload,
};

#[derive(Clone)]
struct StaticDetector {
    strategy_id: String,
    threat_class: ThreatClass,
    confidence: f64,
}

impl DetectionStrategy for StaticDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        &self.strategy_id
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        vec![DetectionFinding {
            finding_id: format!("{}:{}", self.strategy_id, event.event_id),
            event_id: event.event_id.clone(),
            threat_class: self.threat_class.clone(),
            severity: Severity::High,
            confidence: self.confidence,
            evidence: json!({
                "seed_strategy": self.strategy_id,
            }),
            strategy_id: self.strategy_id.clone(),
        }]
    }
}

fn test_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn config_with_network_connect_profile(
    profile: serde_json::Value,
) -> Result<SwarmConfig, Box<dyn std::error::Error>> {
    let mut config = load_config(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rulesets/default.yaml"
    ))?;
    config.detection.strategy = "network_connect".to_string();
    config.detection.profiles.network_connect = Some(profile);
    config.pheromone.min_sources_for_escalation = 2;
    config.pheromone.alert_threshold = 1.5;
    config.pheromone.incident_threshold = 5.0;
    config.pheromone.deescalation_cooldown_secs = 300;
    Ok(config)
}

fn recruitment_profile() -> serde_json::Value {
    json!({
        "suspicious_ports": [],
        "beacon_min_sample_count": 4,
        "beacon_window_ms": 240000,
        "beacon_min_interval_ms": 15000,
        "beacon_max_jitter_ratio": 0.20,
        "recruitment": {
            "enabled": true,
            "activation_strength_ratio": 0.75,
            "min_distinct_sources": 2,
            "reduced_beacon_min_sample_count": 3
        }
    })
}

fn recruitment_benchmark_profile(enabled: bool) -> serde_json::Value {
    json!({
        "suspicious_ports": [],
        "beacon_min_sample_count": 4,
        "beacon_window_ms": 240000,
        "beacon_min_interval_ms": 15000,
        "beacon_max_jitter_ratio": 0.20,
        "recruitment": {
            "enabled": enabled,
            "activation_strength_ratio": 0.75,
            "min_distinct_sources": 2,
            "reduced_beacon_min_sample_count": 3
        }
    })
}

fn network_event(
    event_id: &str,
    timestamp: i64,
    destination_ip: &str,
    destination_port: u16,
) -> TelemetryEvent {
    TelemetryEvent {
        source: "integration".to_string(),
        event_id: event_id.to_string(),
        timestamp,
        host_id: Some("host-network".to_string()),
        payload: TelemetryPayload::NetworkConnect(NetworkConnectEvent {
            process_name: "curl".to_string(),
            destination_ip: destination_ip.to_string(),
            destination_port,
            protocol: "TCP".to_string(),
        }),
    }
}

async fn seed_signed_concentration<S: PheromoneSubstrate>(
    substrate: &S,
    pheromone: &swarm_core::config::PheromoneConfig,
    strategy_id: &str,
    threat_class: ThreatClass,
    key_seed: u8,
    timestamp: i64,
) -> Result<Vec<swarm_core::pheromone::PheromoneDeposit>, Box<dyn std::error::Error>> {
    let signing_key = test_signing_key(key_seed);
    let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
    let detector = StaticDetector {
        strategy_id: strategy_id.to_string(),
        threat_class,
        confidence: 0.9,
    };
    let outcome = detect_and_deposit(
        &detector,
        substrate,
        &network_event(
            &format!("seed-{strategy_id}-{key_seed}"),
            timestamp,
            "198.51.100.25",
            443,
        ),
        &agent_id,
        pheromone,
        &signing_key,
    )
    .await?;
    Ok(outcome.deposits)
}

fn unique_journal_path(label: &str) -> std::path::PathBuf {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("swarm-recruitment-{label}-{suffix}.jsonl"))
}

async fn benchmark_alert_elapsed_secs(
    recruitment_enabled: bool,
) -> Result<(usize, i64), Box<dyn std::error::Error>> {
    let mut config =
        config_with_network_connect_profile(recruitment_benchmark_profile(recruitment_enabled))?;
    config.pheromone.alert_threshold = 2.0;
    let detector = build_composite_detector(&config.detection)?;
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new(config.pheromone.clone()));

    seed_signed_concentration(
        substrate.as_ref(),
        &config.pheromone,
        "seed_c2_a",
        ThreatClass::CommandAndControl,
        81,
        1_700_500_000,
    )
    .await?;
    seed_signed_concentration(
        substrate.as_ref(),
        &config.pheromone,
        "seed_c2_b",
        ThreatClass::CommandAndControl,
        82,
        1_700_500_000,
    )
    .await?;

    let mut monitor = ConcentrationMonitor::new(config.pheromone.clone(), Arc::clone(&substrate));
    let initial = monitor.evaluate_all(1_700_500_000).await?;
    assert_eq!(initial.current_mode, SwarmMode::Normal);

    let start = 1_700_500_000;
    let intervals = [0_i64, 60, 120, 180, 240];
    for (index, offset) in intervals.iter().enumerate() {
        let timestamp = start + offset;
        detect_and_deposit(
            &detector,
            substrate.as_ref(),
            &network_event(
                &format!("benchmark-{recruitment_enabled}-{index}"),
                timestamp,
                "198.51.100.88",
                443,
            ),
            &AgentId::from_verifying_key(&test_signing_key(19).verifying_key()),
            &config.pheromone,
            &test_signing_key(19),
        )
        .await?;
        let escalation = monitor.evaluate_all(timestamp).await?;
        if escalation.current_mode == SwarmMode::Alert {
            return Ok((index + 1, timestamp - start));
        }
    }

    Err("benchmark never reached alert".into())
}

#[tokio::test]
async fn command_and_control_recruitment_lowers_beacon_threshold_from_signed_concentration()
-> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_network_connect_profile(recruitment_profile())?;
    let detector = build_composite_detector(&config.detection)?;
    let substrate = InMemoryPheromoneSubstrate::new(config.pheromone.clone());

    seed_signed_concentration(
        &substrate,
        &config.pheromone,
        "seed_c2_a",
        ThreatClass::CommandAndControl,
        41,
        1_700_100_000,
    )
    .await?;
    seed_signed_concentration(
        &substrate,
        &config.pheromone,
        "seed_c2_b",
        ThreatClass::CommandAndControl,
        42,
        1_700_100_000,
    )
    .await?;

    let timestamps = [1_700_100_000, 1_700_100_060, 1_700_100_120];
    for (index, timestamp) in timestamps.iter().enumerate().take(2) {
        let outcome = detect_and_deposit(
            &detector,
            &substrate,
            &network_event(
                &format!("recruited-warm-{index}"),
                *timestamp,
                "198.51.100.77",
                443,
            ),
            &AgentId::from_verifying_key(&test_signing_key(7).verifying_key()),
            &config.pheromone,
            &test_signing_key(7),
        )
        .await?;
        assert!(outcome.findings.is_empty());
    }

    let outcome = detect_and_deposit(
        &detector,
        &substrate,
        &network_event("recruited-alert", timestamps[2], "198.51.100.77", 443),
        &AgentId::from_verifying_key(&test_signing_key(7).verifying_key()),
        &config.pheromone,
        &test_signing_key(7),
    )
    .await?;

    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(
        outcome.findings[0].evidence["recruitment"]["baseline_beacon_min_sample_count"],
        json!(4)
    );
    assert_eq!(
        outcome.findings[0].evidence["recruitment"]["effective_beacon_min_sample_count"],
        json!(3)
    );
    assert_eq!(
        outcome.findings[0].evidence["recruitment"]["distinct_sources"],
        json!(2)
    );
    assert_eq!(
        outcome.findings[0].evidence["beacon"]["sample_count"],
        json!(3)
    );

    Ok(())
}

#[tokio::test]
async fn unrelated_threat_class_pressure_does_not_recruit_command_and_control_beaconing()
-> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_network_connect_profile(recruitment_profile())?;
    let detector = build_composite_detector(&config.detection)?;
    let substrate = InMemoryPheromoneSubstrate::new(config.pheromone.clone());

    seed_signed_concentration(
        &substrate,
        &config.pheromone,
        "seed_exec_a",
        ThreatClass::Execution,
        51,
        1_700_200_000,
    )
    .await?;
    seed_signed_concentration(
        &substrate,
        &config.pheromone,
        "seed_exec_b",
        ThreatClass::Execution,
        52,
        1_700_200_000,
    )
    .await?;

    let timestamps = [1_700_200_000, 1_700_200_060, 1_700_200_120];
    for (index, timestamp) in timestamps.iter().enumerate() {
        let outcome = detect_and_deposit(
            &detector,
            &substrate,
            &network_event(
                &format!("nonrecruited-{index}"),
                *timestamp,
                "198.51.100.88",
                443,
            ),
            &AgentId::from_verifying_key(&test_signing_key(9).verifying_key()),
            &config.pheromone,
            &test_signing_key(9),
        )
        .await?;
        assert!(
            outcome.findings.is_empty(),
            "unrelated execution concentration must not lower command_and_control beacon thresholds"
        );
    }

    Ok(())
}

#[tokio::test]
async fn invalid_unsigned_deposits_do_not_activate_recruitment()
-> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_network_connect_profile(recruitment_profile())?;
    let detector = build_composite_detector(&config.detection)?;
    let substrate = InMemoryPheromoneSubstrate::new(config.pheromone.clone());

    let deposits = seed_signed_concentration(
        &substrate,
        &config.pheromone,
        "seed_c2_valid",
        ThreatClass::CommandAndControl,
        61,
        1_700_300_000,
    )
    .await?;
    let mut invalid = deposits[0].clone();
    invalid.signature.clear();
    invalid.agent_key.clear();
    assert!(substrate.deposit(invalid).await.is_err());

    let timestamps = [1_700_300_000, 1_700_300_060, 1_700_300_120];
    for (index, timestamp) in timestamps.iter().enumerate() {
        let outcome = detect_and_deposit(
            &detector,
            &substrate,
            &network_event(
                &format!("unsigned-{index}"),
                *timestamp,
                "198.51.100.99",
                443,
            ),
            &AgentId::from_verifying_key(&test_signing_key(11).verifying_key()),
            &config.pheromone,
            &test_signing_key(11),
        )
        .await?;
        assert!(
            outcome.findings.is_empty(),
            "one valid source plus one rejected unsigned deposit must not recruit the threshold"
        );
    }

    Ok(())
}

#[tokio::test]
async fn deescalation_persists_normal_inhibitory_signal_that_survives_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let mut config = config_with_network_connect_profile(recruitment_profile())?;
    let journal_path = unique_journal_path("normal-signal");
    config.pheromone.backend = PheromoneBackendConfig::LocalJournal {
        path: journal_path.display().to_string(),
    };

    {
        let substrate =
            LocalJournalPheromoneSubstrate::open(config.pheromone.clone(), &journal_path)?;
        seed_signed_concentration(
            &substrate,
            &config.pheromone,
            "seed_c2_a",
            ThreatClass::CommandAndControl,
            71,
            1_700_400_000,
        )
        .await?;
        seed_signed_concentration(
            &substrate,
            &config.pheromone,
            "seed_c2_b",
            ThreatClass::CommandAndControl,
            72,
            1_700_400_000,
        )
        .await?;

        let substrate = Arc::new(substrate);
        let mut monitor =
            ConcentrationMonitor::new(config.pheromone.clone(), Arc::clone(&substrate));
        let alert = monitor.evaluate_all(1_700_400_000).await?;
        assert_eq!(alert.current_mode, SwarmMode::Alert);
        assert!(alert.mode_changed);

        let quiet = monitor.evaluate_all(1_700_401_000).await?;
        assert_eq!(quiet.current_mode, SwarmMode::Alert);
        assert!(!quiet.mode_changed);

        let resolved = monitor.evaluate_all(1_700_401_301).await?;
        assert_eq!(resolved.current_mode, SwarmMode::Normal);
        assert!(resolved.mode_changed);

        let records = substrate.query_escalations(0).await?;
        let last = records
            .last()
            .expect("de-escalation must persist a Normal record");
        assert_eq!(last.mode, SwarmMode::Normal);
        assert_eq!(last.threat_class, ThreatClass::CommandAndControl);

        let concentration = substrate
            .query_concentration(&ThreatClass::CommandAndControl, 1_700_401_301)
            .await?;
        assert!(
            concentration.total_strength > config.pheromone.alert_threshold * 0.75,
            "residual concentration should stay above the recruitment activation threshold"
        );
    }

    {
        let detector = build_composite_detector(&config.detection)?;
        let substrate =
            LocalJournalPheromoneSubstrate::open(config.pheromone.clone(), &journal_path)?;
        let timestamps = [1_700_401_301, 1_700_401_361, 1_700_401_421];
        for (index, timestamp) in timestamps.iter().enumerate() {
            let outcome = detect_and_deposit(
                &detector,
                &substrate,
                &network_event(
                    &format!("post-resolution-{index}"),
                    *timestamp,
                    "198.51.100.120",
                    443,
                ),
                &AgentId::from_verifying_key(&test_signing_key(12).verifying_key()),
                &config.pheromone,
                &test_signing_key(12),
            )
            .await?;
            assert!(
                outcome.findings.is_empty(),
                "persisted Normal escalation record must inhibit post-resolution recruitment"
            );
        }

        let baseline = detect_and_deposit(
            &detector,
            &substrate,
            &network_event(
                "post-resolution-baseline",
                1_700_401_481,
                "198.51.100.120",
                443,
            ),
            &AgentId::from_verifying_key(&test_signing_key(12).verifying_key()),
            &config.pheromone,
            &test_signing_key(12),
        )
        .await?;
        assert_eq!(baseline.findings.len(), 1);
        assert!(
            baseline.findings[0].evidence.get("recruitment").is_none(),
            "baseline beacon finding should no longer carry recruitment context after inhibition"
        );
    }

    let _ = std::fs::remove_file(&journal_path);
    let _ = std::fs::remove_file(journal_path.with_extension("escalations.jsonl"));
    let _ = std::fs::remove_file(journal_path.with_extension("threat-class-configs.jsonl"));
    let _ = std::fs::remove_file(journal_path.with_extension("threat-intel.jsonl"));
    let _ = std::fs::remove_file(journal_path.with_extension("behavioral-baselines.jsonl"));
    let _ = std::fs::remove_file(journal_path.with_extension("behavioral-baseline-sequences.json"));

    Ok(())
}

#[tokio::test]
async fn recruitment_kill_chain_replay_reaches_alert_at_least_twenty_percent_faster()
-> Result<(), Box<dyn std::error::Error>> {
    let (baseline_samples, baseline_elapsed_secs) = benchmark_alert_elapsed_secs(false).await?;
    let (recruited_samples, recruited_elapsed_secs) = benchmark_alert_elapsed_secs(true).await?;

    let improvement = 1.0 - (recruited_elapsed_secs as f64 / baseline_elapsed_secs as f64);
    println!(
        "baseline_samples={baseline_samples} baseline_elapsed_secs={baseline_elapsed_secs} recruited_samples={recruited_samples} recruited_elapsed_secs={recruited_elapsed_secs} improvement={improvement:.3}"
    );

    assert_eq!(baseline_samples, 4);
    assert_eq!(recruited_samples, 3);
    assert_eq!(baseline_elapsed_secs, 180);
    assert_eq!(recruited_elapsed_secs, 120);
    assert!(
        improvement >= 0.20,
        "expected at least 20% faster alerting, got {:.1}%",
        improvement * 100.0
    );

    Ok(())
}
