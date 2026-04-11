#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::SigningKey;
use serde_json::json;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::agent::{AgentHealth, AgentHealthEntry, AgentRole};
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_runtime::tom_agent::{
    GovernanceDecision, GovernancePolicy, GovernancePolicyConfig, GovernanceRuntimeEvent,
    PartitionState,
};

fn unique_persistence_path() -> std::path::PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("swarm-governance-resilience-{suffix}.json"))
}

#[test]
fn partition_recovery_reconciles_and_persists_partition_activity() {
    let path = unique_persistence_path();
    let config = GovernancePolicyConfig {
        contingency_lease_ttl_ms: 60_000,
        contingency_blast_radius_cap: 1,
    };
    let base_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time should be after unix epoch")
        .as_millis() as i64;

    let policy = GovernancePolicy::with_persistence(config.clone(), &path).unwrap();
    policy.register_governor(
        AgentId::new("tom", "primary"),
        SigningKey::from_bytes(&[31; 32]),
    );
    policy.observe_health(&AgentId::new("tom", "primary"), &[], base_ms);
    policy.observe_health(
        &AgentId::new("tom", "primary"),
        &[AgentHealthEntry {
            id: "tom-primary".to_string(),
            role: AgentRole::Tom,
            health: AgentHealth::Failed,
        }],
        base_ms + 10_000,
    );
    assert_eq!(
        policy.status_report().partition_state,
        PartitionState::Partitioned
    );

    let action = ResponseAction::IsolateHost {
        host_id: "host-77".to_string(),
    };
    let lease = match policy.can_act(&action) {
        GovernanceDecision::Allow {
            contingency_lease: Some(lease),
            ..
        } => lease,
        other => panic!("expected contingency lease, got {other:?}"),
    };

    let authorized_request = swarm_policy::ActionRequest {
        hunt_id: HuntId("hunt-resilience-allow".to_string()),
        requested_by: AgentId::new("pounce", "primary"),
        action: action.clone(),
        severity: Severity::Critical,
        evidence: json!({
            "contingency_lease": lease,
        }),
    };
    policy
        .authorize_partition_request(&authorized_request, base_ms + 10_100)
        .expect("lease-backed request should be authorized");

    let unauthorized_request = swarm_policy::ActionRequest {
        hunt_id: HuntId("hunt-resilience-block".to_string()),
        requested_by: AgentId::new("pounce", "primary"),
        action,
        severity: Severity::Critical,
        evidence: json!({}),
    };
    let error = policy
        .authorize_partition_request(&unauthorized_request, base_ms + 10_200)
        .expect_err("missing lease should fail closed");
    assert!(
        error.contains("missing contingency lease"),
        "unexpected partition denial: {error}"
    );

    policy.observe_health(&AgentId::new("tom", "primary"), &[], base_ms + 20_000);
    let events = policy.drain_runtime_events();
    let reconciliation = events
        .into_iter()
        .find_map(|event| match event {
            GovernanceRuntimeEvent::PartitionReconciliation { report, .. } => Some(report),
            _ => None,
        })
        .expect("expected reconciliation report");
    assert_eq!(reconciliation.authorized_actions.len(), 1);
    assert_eq!(reconciliation.unauthorized_actions.len(), 1);
    assert_eq!(
        policy.status_report().partition_state,
        PartitionState::Healing
    );

    policy.observe_health(&AgentId::new("tom", "primary"), &[], base_ms + 30_000);
    assert_eq!(
        policy.status_report().partition_state,
        PartitionState::Healthy
    );

    let reloaded = GovernancePolicy::with_persistence(config, &path).unwrap();
    reloaded.register_governor(
        AgentId::new("tom", "primary"),
        SigningKey::from_bytes(&[31; 32]),
    );
    let status = reloaded.status_report();
    assert_eq!(status.partition_state, PartitionState::Healthy);
    assert_eq!(status.unauthorized_partition_actions, 0);
    assert!(status.last_reconciliation_report_id.is_some());

    let _ = fs::remove_file(path);
}
