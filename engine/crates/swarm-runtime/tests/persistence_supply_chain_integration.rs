#![allow(clippy::unwrap_used)]

use ed25519_dalek::SigningKey;
use swarm_core::config::SwarmConfig;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::AgentId;
use swarm_pheromone::{InMemoryPheromoneSubstrate, PheromoneSubstrate};
use swarm_runtime::config::load_config;
use swarm_runtime::control::build_composite_detector;
use swarm_runtime::detection::detect_and_deposit;
use swarm_whisker::{
    ProcessStartEvent, RegistryPersistenceEvent, TelemetryEvent, TelemetryPayload,
};

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn config_with_strategy(strategy: &str) -> Result<SwarmConfig, Box<dyn std::error::Error>> {
    let mut config = load_config(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rulesets/default.yaml"
    ))?;
    config.detection.strategy = strategy.to_string();
    Ok(config)
}

fn persistence_event() -> TelemetryEvent {
    TelemetryEvent {
        source: "integration".to_string(),
        event_id: "persist-evt".to_string(),
        timestamp: 1_700_000_200,
        host_id: Some("host-persist".to_string()),
        payload: TelemetryPayload::RegistryPersistence(RegistryPersistenceEvent {
            process_name: "powershell.exe".to_string(),
            registry_path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            value_name: Some("Updater".to_string()),
            value_data: Some("C:\\Users\\alice\\AppData\\Roaming\\updater.exe".to_string()),
            access_type: "write".to_string(),
        }),
    }
}

fn supply_chain_event() -> TelemetryEvent {
    TelemetryEvent {
        source: "integration".to_string(),
        event_id: "supply-evt".to_string(),
        timestamp: 1_700_000_201,
        host_id: Some("host-supply".to_string()),
        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: "services.exe".to_string(),
            process_name: "svchost.exe".to_string(),
            command_line: "svchost.exe -k netsvcs".to_string(),
            user: Some("SYSTEM".to_string()),
            executable_path: Some("C:\\Windows\\System32\\svchost.exe".to_string()),
            signer: Some("Unknown Labs".to_string()),
            signature_valid: Some(false),
        }),
    }
}

#[tokio::test]
async fn persistence_strategy_detects_registry_run_key_and_deposits()
-> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_strategy("persistence")?;
    let detector = build_composite_detector(&config.detection)?;
    let substrate = InMemoryPheromoneSubstrate::new(config.pheromone.clone());
    let outcome = detect_and_deposit(
        &detector,
        &substrate,
        &persistence_event(),
        &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
        &config.pheromone,
        &test_signing_key(),
    )
    .await?;

    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].strategy_id, "persistence");
    assert_eq!(outcome.findings[0].threat_class, ThreatClass::Persistence);
    assert_eq!(
        outcome.findings[0].evidence["mitre_technique_id"],
        "T1547.001"
    );
    assert_eq!(outcome.deposits.len(), 1);
    assert_eq!(outcome.deposits[0].threat_class, ThreatClass::Persistence);
    assert!(outcome.deposits[0].confidence > 0.0);
    assert_eq!(substrate.recent_deposits(1).await?.len(), 1);

    Ok(())
}

#[tokio::test]
async fn supply_chain_strategy_detects_unsigned_trusted_path_execution_and_deposits()
-> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_strategy("supply_chain")?;
    let detector = build_composite_detector(&config.detection)?;
    let substrate = InMemoryPheromoneSubstrate::new(config.pheromone.clone());
    let outcome = detect_and_deposit(
        &detector,
        &substrate,
        &supply_chain_event(),
        &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
        &config.pheromone,
        &test_signing_key(),
    )
    .await?;

    assert_eq!(outcome.findings.len(), 1);
    assert_eq!(outcome.findings[0].strategy_id, "supply_chain");
    assert_eq!(outcome.findings[0].threat_class, ThreatClass::SupplyChain);
    assert_eq!(
        outcome.findings[0].evidence["mitre_technique_id"],
        "T1553.002"
    );
    assert_eq!(outcome.deposits.len(), 1);
    assert_eq!(outcome.deposits[0].threat_class, ThreatClass::SupplyChain);
    assert!(outcome.deposits[0].confidence > 0.0);
    assert_eq!(substrate.recent_deposits(1).await?.len(), 1);

    Ok(())
}
