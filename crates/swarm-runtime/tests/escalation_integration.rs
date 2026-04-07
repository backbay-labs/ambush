#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use swarm_core::agent::{AgentFinding, SwarmEnvironment, SwarmMode};
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
use swarm_core::pheromone::{
    PheromoneDeposit, ThreatClass, ThreatClassConfig, ThreatIntelEntry, ThreatIntelIndicatorType,
};
use swarm_core::telemetry::{DnsQueryEvent, TelemetryEvent, TelemetryPayload};
use swarm_core::types::{AgentId, EscalationEvent, Severity};
use swarm_pheromone::{InMemoryPheromoneSubstrate, PheromoneSubstrate};
use swarm_runtime::detection::detect_and_deposit;
use swarm_runtime::escalation::ConcentrationMonitor;
use swarm_whisker::DnsExfiltrationDetector;

fn test_config() -> PheromoneConfig {
    PheromoneConfig {
        default_half_life_secs: 3600.0,
        evaporation_threshold: 0.01,
        min_sources_for_escalation: 2,
        alert_threshold: 2.0,
        incident_threshold: 5.0,
        backend: PheromoneBackendConfig::InMemory,
    }
}

fn make_deposit(
    agent_id: &str,
    threat_class: ThreatClass,
    confidence: f64,
    timestamp: i64,
) -> PheromoneDeposit {
    PheromoneDeposit {
        indicator: serde_json::json!({"signal": "execution"}),
        threat_class,
        severity: Severity::High,
        confidence,
        timestamp,
        decay_half_life: 3600.0,
        agent_id: AgentId(agent_id.to_string()),
        signature: Vec::new(),
        agent_key: Vec::new(),
    }
}

fn threat_intel_alert_config() -> PheromoneConfig {
    PheromoneConfig {
        default_half_life_secs: 3600.0,
        evaporation_threshold: 0.01,
        min_sources_for_escalation: 1,
        alert_threshold: 0.9,
        incident_threshold: 1.5,
        backend: PheromoneBackendConfig::InMemory,
    }
}

#[tokio::test]
async fn below_threshold_no_escalation() {
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new(test_config()));
    substrate
        .deposit(make_deposit(
            "agent-a",
            ThreatClass::Execution,
            0.3,
            1_700_000_000,
        ))
        .await
        .unwrap();
    substrate
        .deposit(make_deposit(
            "agent-b",
            ThreatClass::Execution,
            0.3,
            1_700_000_000,
        ))
        .await
        .unwrap();

    let mut monitor = ConcentrationMonitor::new(test_config(), Arc::clone(&substrate));
    let outcome = monitor.evaluate_all(1_700_000_000).await.unwrap();
    assert!(outcome.events.is_empty());
    assert!(!outcome.mode_changed);
    assert_eq!(outcome.current_mode, SwarmMode::Normal);
}

#[tokio::test]
async fn single_source_above_threshold_no_escalation() {
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new(test_config()));
    for _ in 0..3 {
        substrate
            .deposit(make_deposit(
                "agent-a",
                ThreatClass::Execution,
                0.9,
                1_700_000_000,
            ))
            .await
            .unwrap();
    }

    let mut monitor = ConcentrationMonitor::new(test_config(), Arc::clone(&substrate));
    let outcome = monitor.evaluate_all(1_700_000_000).await.unwrap();
    assert!(outcome.events.is_empty());
    assert_eq!(outcome.current_mode, SwarmMode::Normal);
}

#[tokio::test]
async fn dual_source_above_alert_threshold() {
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new(test_config()));
    for agent in ["agent-a", "agent-b"] {
        substrate
            .deposit(make_deposit(
                agent,
                ThreatClass::Execution,
                0.9,
                1_700_000_000,
            ))
            .await
            .unwrap();
        substrate
            .deposit(make_deposit(
                agent,
                ThreatClass::Execution,
                0.9,
                1_700_000_000,
            ))
            .await
            .unwrap();
    }

    let mut monitor = ConcentrationMonitor::new(test_config(), Arc::clone(&substrate));
    let outcome = monitor.evaluate_all(1_700_000_000).await.unwrap();
    assert_eq!(outcome.events.len(), 1);
    assert!(matches!(
        outcome.events[0],
        EscalationEvent::Alert {
            threat_class: ThreatClass::Execution,
            ..
        }
    ));
    assert!(outcome.mode_changed);
    assert_eq!(outcome.current_mode, SwarmMode::Alert);

    let records = substrate.query_escalations(0).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].mode, SwarmMode::Alert);
    assert_eq!(records[0].timestamp, 1_700_000_000);
}

#[tokio::test]
async fn dual_source_above_incident_threshold() {
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new(test_config()));
    for agent in ["agent-a", "agent-b"] {
        for _ in 0..3 {
            substrate
                .deposit(make_deposit(
                    agent,
                    ThreatClass::Execution,
                    0.9,
                    1_700_000_000,
                ))
                .await
                .unwrap();
        }
    }

    let mut monitor = ConcentrationMonitor::new(test_config(), Arc::clone(&substrate));
    let outcome = monitor.evaluate_all(1_700_000_000).await.unwrap();
    assert_eq!(outcome.events.len(), 1);
    assert!(matches!(
        outcome.events[0],
        EscalationEvent::Incident {
            threat_class: ThreatClass::Execution,
            ..
        }
    ));
    assert!(outcome.mode_changed);
    assert_eq!(outcome.current_mode, SwarmMode::Incident);
}

#[tokio::test]
async fn threat_class_alert_override_applies_without_restart() {
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new(test_config()));
    substrate
        .store_threat_class_config(ThreatClassConfig {
            threat_class: ThreatClass::Execution,
            half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            alert_threshold: 1.5,
            incident_threshold: 5.0,
        })
        .await
        .unwrap();
    for agent in ["agent-a", "agent-b"] {
        substrate
            .deposit(make_deposit(
                agent,
                ThreatClass::Execution,
                0.8,
                1_700_000_000,
            ))
            .await
            .unwrap();
    }

    let mut monitor = ConcentrationMonitor::new(test_config(), Arc::clone(&substrate));
    let outcome = monitor.evaluate_all(1_700_000_000).await.unwrap();
    assert_eq!(outcome.current_mode, SwarmMode::Alert);
    assert!(matches!(
        outcome.events[0],
        EscalationEvent::Alert {
            threat_class: ThreatClass::Execution,
            ..
        }
    ));
}

#[tokio::test]
async fn mode_progression_normal_to_alert_to_incident() {
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new(test_config()));
    let mut monitor = ConcentrationMonitor::new(test_config(), Arc::clone(&substrate));

    for agent in ["agent-a", "agent-b"] {
        substrate
            .deposit(make_deposit(
                agent,
                ThreatClass::Execution,
                1.1,
                1_700_000_000,
            ))
            .await
            .unwrap();
    }
    let alert = monitor.evaluate_all(1_700_000_000).await.unwrap();
    assert_eq!(alert.current_mode, SwarmMode::Alert);

    for agent in ["agent-a", "agent-b"] {
        for _ in 0..3 {
            substrate
                .deposit(make_deposit(
                    agent,
                    ThreatClass::Execution,
                    0.9,
                    1_700_000_010,
                ))
                .await
                .unwrap();
        }
    }
    let incident = monitor.evaluate_all(1_700_000_010).await.unwrap();
    assert_eq!(incident.current_mode, SwarmMode::Incident);

    let records = substrate.query_escalations(0).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].mode, SwarmMode::Alert);
    assert_eq!(records[1].mode, SwarmMode::Incident);

    let env = SwarmEnvironment {
        pheromones: Vec::new(),
        mode: monitor.mode_state().current,
        mode_transition_at: monitor.mode_state().last_transition_at,
        now: 1_700_000_010,
        peer_findings: Vec::<AgentFinding>::new(),
    };
    assert_eq!(env.current_mode(), SwarmMode::Incident);
    assert_eq!(env.mode_transition_at(), Some(1_700_000_010));
}

#[tokio::test]
async fn threat_intel_enriched_dns_detection_triggers_alert_escalation() {
    let config = threat_intel_alert_config();
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new(config.clone()));
    substrate
        .store_threat_intel_entry(ThreatIntelEntry {
            indicator_type: ThreatIntelIndicatorType::Domain,
            value: "evil.com".to_string(),
            confidence: 0.25,
            expires_at: 1_700_000_000_500,
        })
        .await
        .unwrap();

    let detector = DnsExfiltrationDetector::default();
    let event = TelemetryEvent {
        source: "dns".to_string(),
        event_id: "evt-threat-intel".to_string(),
        timestamp: 1_700_000_000,
        host_id: Some("host-a".to_string()),
        payload: TelemetryPayload::DnsQuery(DnsQueryEvent {
            query_name: "abcdefghijklabcdefghijkl.evil.com".to_string(),
            query_type: "A".to_string(),
            source_ip: Some("10.0.0.4".to_string()),
            process_name: Some("powershell".to_string()),
            response_code: Some("NOERROR".to_string()),
        }),
    };

    let outcome = detect_and_deposit(
        &detector,
        substrate.as_ref(),
        &event,
        &AgentId("whisker-dns".to_string()),
        &config,
    )
    .await
    .unwrap();
    assert_eq!(outcome.findings.len(), 1);
    assert!(outcome.findings[0].confidence > config.alert_threshold);
    assert_eq!(
        outcome.findings[0].evidence["threat_intel_matches"][0]["value"],
        "evil.com"
    );

    let mut monitor = ConcentrationMonitor::new(config.clone(), Arc::clone(&substrate));
    let escalation = monitor.evaluate_all(event.timestamp).await.unwrap();
    assert_eq!(escalation.current_mode, SwarmMode::Alert);
    assert!(matches!(
        escalation.events[0],
        EscalationEvent::Alert {
            threat_class: ThreatClass::DataExfiltration,
            ..
        }
    ));

    let records = substrate.query_escalations(0).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].mode, SwarmMode::Alert);
    assert_eq!(records[0].threat_class, ThreatClass::DataExfiltration);
}
