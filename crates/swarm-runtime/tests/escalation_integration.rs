#![allow(clippy::unwrap_used)]

use ed25519_dalek::SigningKey;
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
use swarm_whisker::{DetectionFinding, DetectionStrategy, DnsExfiltrationDetector};

#[derive(Clone)]
struct StaticDetector {
    findings: Vec<DetectionFinding>,
}

impl DetectionStrategy for StaticDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        "static"
    }

    fn evaluate(&self, _event: &TelemetryEvent) -> Vec<DetectionFinding> {
        self.findings.clone()
    }
}

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn test_config() -> PheromoneConfig {
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

fn signing_key_a() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn signing_key_b() -> SigningKey {
    SigningKey::from_bytes(&[43u8; 32])
}

fn make_deposit(
    key: &SigningKey,
    threat_class: ThreatClass,
    confidence: f64,
    timestamp: i64,
) -> PheromoneDeposit {
    let agent_id = AgentId::from_verifying_key(&key.verifying_key());
    let mut deposit = PheromoneDeposit {
        schema_version: PheromoneDeposit::current_schema_version(),
        indicator: serde_json::json!({"signal": "execution"}),
        threat_class,
        severity: Severity::High,
        confidence,
        timestamp,
        decay_half_life: 3600.0,
        agent_id: agent_id.clone(),
        agent_identity: agent_id.0,
        agent_role: None,
        signature: Vec::new(),
        agent_key: Vec::new(),
    };
    let payload = swarm_pheromone::DepositSigningPayload {
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
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let sig = ed25519_dalek::Signer::sign(key, &payload_bytes);
    deposit.signature = sig.to_bytes().to_vec();
    deposit.agent_key = key.verifying_key().to_bytes().to_vec();
    deposit
}

fn threat_intel_alert_config() -> PheromoneConfig {
    PheromoneConfig {
        default_half_life_secs: 3600.0,
        evaporation_threshold: 0.01,
        min_sources_for_escalation: 1,
        alert_threshold: 0.9,
        incident_threshold: 1.5,
        deescalation_cooldown_secs: 300,
        response_playbook: Default::default(),
        backend: PheromoneBackendConfig::InMemory,
    }
}

fn synthetic_event(event_id: &str) -> TelemetryEvent {
    TelemetryEvent {
        source: "synthetic".to_string(),
        event_id: event_id.to_string(),
        timestamp: 1_700_000_000,
        host_id: Some("host-a".to_string()),
        payload: TelemetryPayload::DnsQuery(DnsQueryEvent {
            query_name: "abcdefghijklabcdefghijkl.evil.com".to_string(),
            query_type: "A".to_string(),
            source_ip: Some("10.0.0.4".to_string()),
            process_name: Some("powershell".to_string()),
            response_code: Some("NOERROR".to_string()),
        }),
    }
}

fn finding(strategy_id: &str, finding_id: &str) -> DetectionFinding {
    DetectionFinding {
        finding_id: finding_id.to_string(),
        event_id: "evt-cross-strategy".to_string(),
        threat_class: ThreatClass::Execution,
        severity: Severity::High,
        confidence: 1.0,
        evidence: serde_json::json!({"strategy_id": strategy_id}),
        strategy_id: strategy_id.to_string(),
    }
}

#[tokio::test]
async fn below_threshold_no_escalation() {
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new(test_config()));
    substrate
        .deposit(make_deposit(
            &signing_key_a(),
            ThreatClass::Execution,
            0.3,
            1_700_000_000,
        ))
        .await
        .unwrap();
    substrate
        .deposit(make_deposit(
            &signing_key_b(),
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
    let key = signing_key_a();
    for _ in 0..3 {
        substrate
            .deposit(make_deposit(
                &key,
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
    for key in [&signing_key_a(), &signing_key_b()] {
        substrate
            .deposit(make_deposit(
                key,
                ThreatClass::Execution,
                0.9,
                1_700_000_000,
            ))
            .await
            .unwrap();
        substrate
            .deposit(make_deposit(
                key,
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
    for key in [&signing_key_a(), &signing_key_b()] {
        for _ in 0..3 {
            substrate
                .deposit(make_deposit(
                    key,
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
    for key in [&signing_key_a(), &signing_key_b()] {
        substrate
            .deposit(make_deposit(
                key,
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

    for key in [&signing_key_a(), &signing_key_b()] {
        substrate
            .deposit(make_deposit(
                key,
                ThreatClass::Execution,
                1.1,
                1_700_000_000,
            ))
            .await
            .unwrap();
    }
    let alert = monitor.evaluate_all(1_700_000_000).await.unwrap();
    assert_eq!(alert.current_mode, SwarmMode::Alert);

    for key in [&signing_key_a(), &signing_key_b()] {
        for _ in 0..3 {
            substrate
                .deposit(make_deposit(
                    key,
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
        agent_health: Vec::new(),
    };
    assert_eq!(env.current_mode(), SwarmMode::Incident);
    assert_eq!(env.mode_transition_at(), Some(1_700_000_010));
}

#[tokio::test]
async fn concentration_monitor_deescalates_after_cooldown() {
    let config = test_config();
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new(config.clone()));
    let mut monitor = ConcentrationMonitor::new(config.clone(), Arc::clone(&substrate));
    let start = 1_700_000_000;

    for key in [&signing_key_a(), &signing_key_b()] {
        substrate
            .deposit(make_deposit(key, ThreatClass::Execution, 1.1, start))
            .await
            .unwrap();
    }

    let alert = monitor.evaluate_all(start).await.unwrap();
    assert_eq!(alert.current_mode, SwarmMode::Alert);
    assert!(alert.mode_changed);
    assert_eq!(
        monitor.mode_state().triggering_threat_class,
        Some(ThreatClass::Execution)
    );

    let quiet_start = start + 3_601;
    let first_quiet = monitor.evaluate_all(quiet_start).await.unwrap();
    assert!(first_quiet.events.is_empty());
    assert!(!first_quiet.mode_changed);
    assert_eq!(first_quiet.current_mode, SwarmMode::Alert);
    assert_eq!(monitor.mode_state().current, SwarmMode::Alert);

    let before_cooldown = monitor
        .evaluate_all(quiet_start + config.deescalation_cooldown_secs - 1)
        .await
        .unwrap();
    assert!(before_cooldown.events.is_empty());
    assert!(!before_cooldown.mode_changed);
    assert_eq!(before_cooldown.current_mode, SwarmMode::Alert);

    let deescalated = monitor
        .evaluate_all(quiet_start + config.deescalation_cooldown_secs)
        .await
        .unwrap();
    assert!(deescalated.events.is_empty());
    assert!(deescalated.mode_changed);
    assert_eq!(deescalated.current_mode, SwarmMode::Normal);
    assert_eq!(monitor.mode_state().current, SwarmMode::Normal);
    assert_eq!(monitor.mode_state().triggering_threat_class, None);
    assert_eq!(
        monitor.mode_state().last_transition_at,
        Some(quiet_start + config.deescalation_cooldown_secs)
    );
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
        &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
        &config,
        &test_signing_key(),
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

#[tokio::test]
async fn cross_strategy_findings_from_one_agent_trigger_alert_escalation() {
    let config = test_config();
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new(config.clone()));
    let detector = StaticDetector {
        findings: vec![
            finding("suspicious_process_tree", "finding-1"),
            finding("dns_exfiltration", "finding-2"),
        ],
    };
    let event = synthetic_event("evt-cross-strategy");

    let outcome = detect_and_deposit(
        &detector,
        substrate.as_ref(),
        &event,
        &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
        &config,
        &test_signing_key(),
    )
    .await
    .unwrap();

    assert_eq!(outcome.deposits.len(), 2);
    assert_ne!(outcome.deposits[0].agent_id, outcome.deposits[1].agent_id);

    let mut monitor = ConcentrationMonitor::new(config, Arc::clone(&substrate));
    let escalation = monitor.evaluate_all(event.timestamp).await.unwrap();
    assert_eq!(escalation.current_mode, SwarmMode::Alert);
    assert!(matches!(
        escalation.events[0],
        EscalationEvent::Alert {
            threat_class: ThreatClass::Execution,
            ..
        }
    ));

    let records = substrate.query_escalations(0).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].mode, SwarmMode::Alert);
    assert_eq!(records[0].distinct_sources, 2);
}

#[tokio::test]
async fn repeated_same_strategy_findings_from_one_agent_do_not_trigger_cross_strategy_alert() {
    let config = test_config();
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new(config.clone()));
    let detector = StaticDetector {
        findings: vec![
            finding("suspicious_process_tree", "finding-1"),
            finding("suspicious_process_tree", "finding-2"),
        ],
    };
    let event = synthetic_event("evt-same-strategy");

    let outcome = detect_and_deposit(
        &detector,
        substrate.as_ref(),
        &event,
        &AgentId::from_verifying_key(&test_signing_key().verifying_key()),
        &config,
        &test_signing_key(),
    )
    .await
    .unwrap();

    assert_eq!(outcome.deposits.len(), 2);
    assert_eq!(outcome.deposits[0].agent_id, outcome.deposits[1].agent_id);

    let mut monitor = ConcentrationMonitor::new(config, Arc::clone(&substrate));
    let escalation = monitor.evaluate_all(event.timestamp).await.unwrap();
    assert!(escalation.events.is_empty());
    assert_eq!(escalation.current_mode, SwarmMode::Normal);

    let concentration = substrate
        .query_concentration(&ThreatClass::Execution, event.timestamp)
        .await
        .unwrap();
    assert_eq!(concentration.distinct_sources, 1);
}
