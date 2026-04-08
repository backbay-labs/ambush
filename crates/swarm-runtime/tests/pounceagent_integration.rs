#![allow(clippy::unwrap_used)]

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use swarm_core::agent::{
    AgentFinding, AgentHealth, AgentHealthEntry, AgentRole, SwarmAgent, SwarmEnvironment, SwarmMode,
};
use swarm_core::config::{
    PheromoneBackendConfig, PheromoneConfig, ResponsePlaybookConfig, ResponsePlaybookRule,
};
use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
use swarm_core::types::{AgentId, ResponseAction, Severity, SwarmAction};
use swarm_policy::static_gate::scope_for_response_action;
use swarm_runtime::pounce_agent::PounceAgent;
use swarm_runtime::tom_agent::GovernancePolicy;

fn playbook() -> ResponsePlaybookConfig {
    ResponsePlaybookConfig {
        rules: vec![
            ResponsePlaybookRule {
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                min_confidence: 0.90,
                max_confidence: 1.0,
                actions: vec![ResponseAction::DeployDecoy {
                    decoy_type: "honeypot".to_string(),
                    target_zone: "dmz".to_string(),
                }],
            },
            ResponsePlaybookRule {
                threat_class: ThreatClass::Execution,
                severity: Severity::Medium,
                min_confidence: 0.70,
                max_confidence: 0.89,
                actions: vec![ResponseAction::Escalate {
                    summary: "review medium-confidence execution activity".to_string(),
                    urgency: Severity::Medium,
                }],
            },
            ResponsePlaybookRule {
                threat_class: ThreatClass::CommandAndControl,
                severity: Severity::Critical,
                min_confidence: 0.95,
                max_confidence: 1.0,
                actions: vec![ResponseAction::BlockEgress {
                    target: "203.0.113.10".to_string(),
                }],
            },
        ],
    }
}

fn test_config() -> PheromoneConfig {
    PheromoneConfig {
        default_half_life_secs: 3600.0,
        evaporation_threshold: 0.01,
        min_sources_for_escalation: 2,
        alert_threshold: 2.0,
        incident_threshold: 5.0,
        deescalation_cooldown_secs: 300,
        response_playbook: playbook(),
        backend: PheromoneBackendConfig::InMemory,
    }
}

fn make_deposit(
    event_id: &str,
    threat_class: ThreatClass,
    severity: Severity,
    confidence: f64,
    timestamp: i64,
) -> PheromoneDeposit {
    let key = SigningKey::from_bytes(&[42u8; 32]);
    let mut deposit = PheromoneDeposit {
        indicator: serde_json::json!({
            "event_id": event_id,
            "source": "integration-test",
            "evidence": {
                "event_id": event_id,
                "host_id": "host-1",
                "signal": "integration-test"
            }
        }),
        threat_class,
        severity,
        confidence,
        timestamp,
        decay_half_life: 3600.0,
        agent_id: AgentId("whisker-primary".to_string()),
        signature: Vec::new(),
        agent_key: Vec::new(),
    };
    let payload = swarm_pheromone::DepositSigningPayload {
        indicator: &deposit.indicator,
        threat_class: &deposit.threat_class,
        severity: &deposit.severity,
        confidence: deposit.confidence,
        timestamp: deposit.timestamp,
        decay_half_life: deposit.decay_half_life,
        agent_id: &deposit.agent_id,
    };
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let sig = ed25519_dalek::Signer::sign(&key, &payload_bytes);
    deposit.signature = sig.to_bytes().to_vec();
    deposit.agent_key = key.verifying_key().to_bytes().to_vec();
    deposit
}

fn env(
    mode: SwarmMode,
    mode_transition_at: Option<i64>,
    now: i64,
    pheromones: Vec<PheromoneDeposit>,
    peer_findings: Vec<AgentFinding>,
) -> SwarmEnvironment {
    SwarmEnvironment {
        pheromones,
        mode,
        mode_transition_at,
        now,
        peer_findings,
        agent_health: Vec::new(),
    }
}

fn request_action(actions: &[SwarmAction]) -> &ResponseAction {
    let SwarmAction::RequestResponse { action, .. } = &actions[0] else {
        panic!("expected request_response action, got {:?}", actions);
    };
    action
}

#[tokio::test]
async fn pounceagent_emits_request_response_for_alert_and_incident() {
    let config = test_config();
    let mut agent = PounceAgent::new(AgentId::new("pouncer", "primary"), config.response_playbook);

    let alert_env = env(
        SwarmMode::Alert,
        Some(1_700_000_010),
        1_700_000_020,
        vec![make_deposit(
            "evt-alert",
            ThreatClass::Execution,
            Severity::High,
            0.97,
            1_700_000_015,
        )],
        Vec::new(),
    );

    let first_actions = agent.tick(&alert_env).await.unwrap();
    assert_eq!(first_actions.len(), 1);
    let SwarmAction::RequestResponse {
        hunt_id,
        action,
        evidence,
    } = &first_actions[0]
    else {
        panic!("expected request_response action");
    };
    assert_eq!(hunt_id.0, "evt-alert");
    assert!(matches!(
        action,
        ResponseAction::DeployDecoy { target_zone, .. } if target_zone == "dmz"
    ));
    assert_eq!(
        evidence["lineage"]["event_id"],
        serde_json::json!("evt-alert")
    );

    let repeated_actions = agent.tick(&alert_env).await.unwrap();
    assert!(repeated_actions.is_empty());

    let normal_env = env(
        SwarmMode::Normal,
        None,
        1_700_000_030,
        Vec::new(),
        Vec::new(),
    );
    assert!(agent.tick(&normal_env).await.unwrap().is_empty());

    let incident_env = env(
        SwarmMode::Incident,
        Some(1_700_000_040),
        1_700_000_050,
        vec![make_deposit(
            "evt-incident",
            ThreatClass::CommandAndControl,
            Severity::Critical,
            0.99,
            1_700_000_045,
        )],
        Vec::new(),
    );
    let incident_actions = agent.tick(&incident_env).await.unwrap();
    assert_eq!(incident_actions.len(), 1);
    let SwarmAction::RequestResponse {
        hunt_id, action, ..
    } = &incident_actions[0]
    else {
        panic!("expected request_response action");
    };
    assert_eq!(hunt_id.0, "evt-incident");
    assert!(matches!(
        action,
        ResponseAction::BlockEgress { target } if target == "203.0.113.10"
    ));
}

#[tokio::test]
async fn pounceagent_skips_scope_present_in_peer_findings() {
    let config = test_config();
    let mut agent = PounceAgent::new(AgentId::new("pouncer", "primary"), config.response_playbook);
    let action = ResponseAction::DeployDecoy {
        decoy_type: "honeypot".to_string(),
        target_zone: "dmz".to_string(),
    };
    let scope = scope_for_response_action(&action).unwrap();
    let peer_findings = vec![AgentFinding {
        agent_id: AgentId::new("pouncer", "peer"),
        role: AgentRole::Pouncer,
        kind: "request_response".to_string(),
        summary: format!("scope={scope} action={}", action.kind()),
    }];

    let alert_env = env(
        SwarmMode::Alert,
        Some(1_700_000_010),
        1_700_000_020,
        vec![make_deposit(
            "evt-alert",
            ThreatClass::Execution,
            Severity::High,
            0.97,
            1_700_000_015,
        )],
        peer_findings,
    );

    let actions = agent.tick(&alert_env).await.unwrap();
    assert!(actions.is_empty());
}

#[tokio::test]
async fn response_playbook_selects_actions_by_threat_severity_and_confidence() {
    let config = test_config();
    let mut agent = PounceAgent::new(
        AgentId::new("pouncer", "selector"),
        config.response_playbook.clone(),
    );

    let medium_env = env(
        SwarmMode::Alert,
        Some(1_700_000_010),
        1_700_000_020,
        vec![make_deposit(
            "evt-medium",
            ThreatClass::Execution,
            Severity::Medium,
            0.80,
            1_700_000_015,
        )],
        Vec::new(),
    );
    let medium_actions = agent.tick(&medium_env).await.unwrap();
    assert!(matches!(
        request_action(&medium_actions),
        ResponseAction::Escalate { urgency, .. } if *urgency == Severity::Medium
    ));

    let normal_env = env(
        SwarmMode::Normal,
        None,
        1_700_000_030,
        Vec::new(),
        Vec::new(),
    );
    assert!(agent.tick(&normal_env).await.unwrap().is_empty());

    let high_env = env(
        SwarmMode::Alert,
        Some(1_700_000_040),
        1_700_000_050,
        vec![make_deposit(
            "evt-high",
            ThreatClass::Execution,
            Severity::High,
            0.96,
            1_700_000_045,
        )],
        Vec::new(),
    );
    let high_actions = agent.tick(&high_env).await.unwrap();
    assert!(matches!(
        request_action(&high_actions),
        ResponseAction::DeployDecoy { target_zone, .. } if target_zone == "dmz"
    ));
}

#[tokio::test]
async fn pounceagent_emits_governance_veto_for_destructive_action() {
    let governance_policy = Arc::new(GovernancePolicy::default());
    governance_policy.observe_health(
        &AgentId::new("tom", "primary"),
        &[AgentHealthEntry {
            id: "whisker-primary".to_string(),
            role: AgentRole::Whisker,
            health: AgentHealth::Degraded,
        }],
    );
    let config = test_config();
    let mut agent = PounceAgent::new(AgentId::new("pouncer", "primary"), config.response_playbook)
        .with_governance_policy(Arc::clone(&governance_policy));

    let incident_env = env(
        SwarmMode::Incident,
        Some(1_700_000_040),
        1_700_000_050,
        vec![make_deposit(
            "evt-incident",
            ThreatClass::CommandAndControl,
            Severity::Critical,
            0.99,
            1_700_000_045,
        )],
        Vec::new(),
    );
    let actions = agent.tick(&incident_env).await.unwrap();

    assert!(matches!(
        actions.as_slice(),
        [SwarmAction::GovernanceVeto {
            hunt_id,
            action: ResponseAction::BlockEgress { target },
            governing_agent_id,
            ..
        }] if hunt_id.0 == "evt-incident"
            && target == "203.0.113.10"
            && governing_agent_id == &AgentId::new("tom", "primary")
    ));
}
