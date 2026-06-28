#![allow(clippy::unwrap_used)]

use ed25519_dalek::SigningKey;
use serde_json::json;
use swarm_core::config::SwarmConfig;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::AgentId;
use swarm_pheromone::substrate::validate_deposit_signature;
use swarm_pheromone::{InMemoryPheromoneSubstrate, PheromoneSubstrate};
use swarm_runtime::config::load_config;
use swarm_runtime::control::build_composite_detector;
use swarm_runtime::detection::detect_and_deposit;
use swarm_whisker::{NetworkConnectEvent, TelemetryEvent, TelemetryPayload};

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
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
    Ok(config)
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

#[tokio::test]
async fn network_connect_strategy_detects_suspicious_port_and_deposits_command_and_control()
-> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_network_connect_profile(json!({
        "suspicious_ports": [4444],
    }))?;
    let detector = build_composite_detector(&config.detection)?;
    let substrate = InMemoryPheromoneSubstrate::new(config.pheromone.clone());
    let outcome = detect_and_deposit(
        &detector,
        &substrate,
        &network_event("network-port-evt", 1_700_000_000_000, "198.51.100.25", 4444),
        &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
        &config.pheromone,
        &test_signing_key(),
    )
    .await?;

    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].strategy_id, "network_connect");
    assert_eq!(
        outcome.findings[0].threat_class,
        ThreatClass::CommandAndControl
    );
    assert_eq!(
        outcome.findings[0].evidence["heuristics"]["suspicious_port"],
        json!(true)
    );
    assert_eq!(outcome.deposits.len(), 1);
    assert_eq!(
        outcome.deposits[0].threat_class,
        ThreatClass::CommandAndControl
    );
    validate_deposit_signature(&outcome.deposits[0])?;
    assert_eq!(substrate.recent_deposits(1).await?.len(), 1);

    Ok(())
}

#[tokio::test]
async fn network_connect_strategy_detects_low_jitter_beacon_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_network_connect_profile(json!({
        "suspicious_ports": [],
        "beacon_min_sample_count": 4,
        "beacon_window_ms": 240000,
        "beacon_min_interval_ms": 15000,
        "beacon_max_jitter_ratio": 0.20,
    }))?;
    let detector = build_composite_detector(&config.detection)?;
    let substrate = InMemoryPheromoneSubstrate::new(config.pheromone.clone());
    let timestamps = [
        1_700_000_100_000,
        1_700_000_130_000,
        1_700_000_160_000,
        1_700_000_190_000,
    ];

    for (index, timestamp) in timestamps.iter().enumerate() {
        let outcome = detect_and_deposit(
            &detector,
            &substrate,
            &network_event(
                &format!("network-beacon-{index}"),
                *timestamp,
                "198.51.100.77",
                443,
            ),
            &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
            &config.pheromone,
            &test_signing_key(),
        )
        .await?;

        if index < timestamps.len() - 1 {
            assert!(
                outcome.findings.is_empty(),
                "event {index} should be warm-up only"
            );
            assert!(
                outcome.deposits.is_empty(),
                "event {index} should not deposit"
            );
            continue;
        }

        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.findings[0].strategy_id, "network_connect");
        assert_eq!(
            outcome.findings[0].threat_class,
            ThreatClass::CommandAndControl
        );
        assert_eq!(
            outcome.findings[0].evidence["heuristics"]["beaconing"],
            json!(true)
        );
        assert_eq!(outcome.deposits.len(), 1);
        validate_deposit_signature(&outcome.deposits[0])?;
    }

    assert_eq!(substrate.recent_deposits(10).await?.len(), 1);

    Ok(())
}
