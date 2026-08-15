#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use swarm_agents::tom_agent::{GovernanceDecision, GovernancePolicy, GovernancePolicyConfig};
use swarm_consensus::{
    ConsensusCommit, ConsensusCommittee, ConsensusGovernanceReceipt, ConsensusProposal,
    GovernanceReceiptDecision, commit_hash_for_proposal, proposal_id_for_payload,
};
use swarm_core::agent::{AgentHealth, AgentHealthEntry, AgentRole};
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_policy::governance::GovernanceActionRequestSubjectV1;
use swarm_policy::{ActionRequest, PolicyDecision};

const GOVERNOR_KEY: [u8; 32] = [91; 32];

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after the unix epoch")
        .as_millis() as i64
}

fn request() -> ActionRequest {
    ActionRequest {
        hunt_id: HuntId("hunt-authz".to_string()),
        requested_by: AgentId::new("pounce", "primary"),
        action: ResponseAction::BlockEgress {
            target: "203.0.113.10".to_string(),
        },
        severity: Severity::Critical,
        evidence: serde_json::json!({
            "lineage": {"event_id": "evt-authz"},
            "signal": "command-and-control",
        }),
    }
}

fn policy() -> GovernancePolicy {
    let policy = GovernancePolicy::default();
    policy
        .register_governor(
            AgentId::new("tom", "primary"),
            SigningKey::from_bytes(&GOVERNOR_KEY),
        )
        .expect("fresh policy accepts its governor");
    policy.observe_health(&AgentId::new("tom", "primary"), &[], now_ms());
    policy
}

fn approval(policy: &GovernancePolicy, request: &ActionRequest) -> serde_json::Value {
    let GovernanceDecision::Authorize { receipt, .. } = policy.can_act(request) else {
        panic!("healthy governance must authorize the request");
    };
    serde_json::to_value(receipt).expect("receipt serializes")
}

#[test]
fn authorization_binds_every_request_subject_field_and_is_consumed_once() {
    let policy = policy();
    let base = request();
    let subject = GovernanceActionRequestSubjectV1::from_request(&base);
    assert_eq!(
        subject.domain,
        "swarm.governance.action-request.authorization.v1"
    );
    assert_eq!(subject.schema_version, 1);
    assert_eq!(subject.hunt_id, base.hunt_id);
    assert_eq!(subject.requested_by, base.requested_by);
    assert_eq!(subject.action, base.action);
    assert_eq!(subject.scope.as_deref(), Some("203.0.113.10"));
    assert_eq!(subject.severity, base.severity);
    assert_eq!(subject.evidence, base.evidence);
    let receipt = approval(&policy, &base);
    let issued_at_ms = receipt["payload"]["issued_at_ms"].as_i64().unwrap();

    let mut mutations = Vec::new();
    let mut changed = base.clone();
    changed.hunt_id = HuntId("hunt-other".to_string());
    mutations.push(("hunt_id", changed));
    let mut changed = base.clone();
    changed.requested_by = AgentId::new("pounce", "other");
    mutations.push(("requested_by", changed));
    let mut changed = base.clone();
    changed.action = ResponseAction::SinkholeDns {
        domain: "203.0.113.10".to_string(),
    };
    assert_eq!(
        GovernanceActionRequestSubjectV1::from_request(&base).scope,
        GovernanceActionRequestSubjectV1::from_request(&changed).scope,
        "the full-action differential must hold scope constant"
    );
    mutations.push(("full_action", changed));
    let mut changed = base.clone();
    changed.action = ResponseAction::BlockEgress {
        target: "203.0.113.99".to_string(),
    };
    mutations.push(("target_scope", changed));
    let mut changed = base.clone();
    changed.severity = Severity::High;
    mutations.push(("severity", changed));
    let mut changed = base.clone();
    changed.evidence["signal"] = serde_json::json!("different");
    mutations.push(("evidence", changed));

    for (field, changed) in mutations {
        let error = policy
            .verify_and_consume_action_authorization(&changed, &receipt, issued_at_ms + 1)
            .expect_err("a changed subject must not consume the authorization");
        assert!(
            error.contains("proposal digest") || error.contains("pending authorization"),
            "{field} was not bound: {error}"
        );
    }

    policy
        .verify_and_consume_action_authorization(&base, &receipt, issued_at_ms + 1)
        .expect("the exact request consumes once");
    let replay = policy
        .verify_and_consume_action_authorization(&base, &receipt, issued_at_ms + 2)
        .expect_err("the receipt must not replay");
    assert!(replay.contains("already consumed"));
}

#[test]
fn bearer_fields_are_the_only_evidence_excluded_from_the_subject() {
    let base = request();
    let mut with_bearers = base.clone();
    with_bearers.evidence["governance_receipt"] = serde_json::json!({"bearer": true});
    with_bearers.evidence["contingency_lease"] = serde_json::json!({"bearer": true});
    assert_eq!(
        GovernanceActionRequestSubjectV1::from_request(&base),
        GovernanceActionRequestSubjectV1::from_request(&with_bearers)
    );

    let mut changed = with_bearers;
    changed.evidence["another_field"] = serde_json::json!(true);
    assert_ne!(
        GovernanceActionRequestSubjectV1::from_request(&base),
        GovernanceActionRequestSubjectV1::from_request(&changed)
    );
}

#[test]
fn approval_and_veto_receipts_cannot_swap_routes() {
    let approve_policy = policy();
    let request = request();
    let approve = approval(&approve_policy, &request);
    let approve_time = approve["payload"]["issued_at_ms"].as_i64().unwrap();
    let error = approve_policy
        .verify_and_consume_veto(&request, &approve, approve_time + 1)
        .expect_err("an approval must not route as a veto");
    assert!(error.contains("decision"));
    approve_policy
        .verify_and_consume_action_authorization(&request, &approve, approve_time + 1)
        .expect("the failed route swap must not consume the approval");

    let veto_policy = policy();
    veto_policy.observe_health(
        &AgentId::new("tom", "primary"),
        &[AgentHealthEntry {
            id: "whisker-primary".to_string(),
            role: AgentRole::Whisker,
            health: AgentHealth::Degraded,
        }],
        now_ms(),
    );
    let GovernanceDecision::Veto {
        receipt: Some(veto),
        ..
    } = veto_policy.can_act(&request)
    else {
        panic!("unhealthy governance must issue a veto receipt");
    };
    let veto = serde_json::to_value(veto).unwrap();
    let veto_time = veto["payload"]["issued_at_ms"].as_i64().unwrap();
    let error = veto_policy
        .verify_and_consume_action_authorization(&request, &veto, veto_time + 1)
        .expect_err("a veto must not route as an approval");
    assert!(error.contains("decision"));
    veto_policy
        .verify_and_consume_veto(&request, &veto, veto_time + 1)
        .expect("the failed route swap must not consume the veto");
}

#[test]
fn authorization_receipts_have_bounded_age_and_future_skew() {
    let stale_policy = policy();
    let request = request();
    let stale = approval(&stale_policy, &request);
    let issued_at_ms = stale["payload"]["issued_at_ms"].as_i64().unwrap();
    assert!(
        stale_policy
            .verify_and_consume_action_authorization(&request, &stale, issued_at_ms + 300_001,)
            .expect_err("stale receipt must fail")
            .contains("stale")
    );

    let future_policy = policy();
    let future = approval(&future_policy, &request);
    let issued_at_ms = future["payload"]["issued_at_ms"].as_i64().unwrap();
    assert!(
        future_policy
            .verify_and_consume_action_authorization(&request, &future, issued_at_ms - 30_001,)
            .expect_err("far-future receipt must fail")
            .contains("future")
    );
}

#[test]
fn trusted_key_receipt_not_issued_by_policy_is_refused() {
    let policy = policy();
    let request = request();
    let subject =
        serde_json::to_value(GovernanceActionRequestSubjectV1::from_request(&request)).unwrap();
    let proposal = ConsensusProposal {
        proposal_id: proposal_id_for_payload(&subject).unwrap(),
        payload: subject,
    };
    let key = SigningKey::from_bytes(&GOVERNOR_KEY);
    let member = AgentId::from_verifying_key(&key.verifying_key());
    let committee = ConsensusCommittee::new(vec![member.clone()], 0).unwrap();
    let previous_commit_hash = "forged-outside-policy";
    let commit = ConsensusCommit {
        height: 0,
        round: 0,
        committee_id: committee.committee_id().to_string(),
        proposal: proposal.clone(),
        prevote_tally: 1,
        precommit_tally: 1,
        commit_hash: commit_hash_for_proposal(0, 0, previous_commit_hash, &proposal).unwrap(),
    };
    let forged = ConsensusGovernanceReceipt::issue(
        &commit,
        previous_commit_hash,
        &committee,
        GovernanceReceiptDecision::Approve,
        member,
        &key,
        now_ms(),
    )
    .unwrap();
    let forged = serde_json::to_value(forged).unwrap();

    let error = policy
        .verify_and_consume_action_authorization(&request, &forged, now_ms())
        .expect_err("a trusted signature without policy issuance must fail");
    assert!(error.contains("pending authorization ledger"));
}

fn persistence_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "swarm-governance-authorization-{label}-{}-{}",
        std::process::id(),
        now_ms()
    ))
}

fn initialize_persisted_policy(path: &PathBuf) -> GovernancePolicy {
    GovernancePolicy::initialize_persistence(
        GovernancePolicyConfig::default(),
        path,
        AgentId::new("tom", "primary"),
        SigningKey::from_bytes(&GOVERNOR_KEY),
    )
    .unwrap()
}

fn reload_persisted_policy(path: &PathBuf) -> GovernancePolicy {
    GovernancePolicy::with_persistence(
        GovernancePolicyConfig::default(),
        path,
        AgentId::new("tom", "primary"),
        SigningKey::from_bytes(&GOVERNOR_KEY),
    )
    .unwrap()
}

fn block_next_state_write(path: &Path) -> PathBuf {
    let temp_path = path.with_extension(format!(
        "{}.tmp-{}",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("state"),
        std::process::id()
    ));
    fs::create_dir(&temp_path).unwrap();
    temp_path
}

fn cleanup_persistence(path: &PathBuf) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(GovernancePolicy::persistence_sequence_path(path));
}

#[test]
fn consumed_authorization_stays_consumed_after_restart() {
    let path = persistence_path("restart");
    let request = request();
    let receipt = {
        let policy = initialize_persisted_policy(&path);
        let receipt = approval(&policy, &request);
        let issued_at_ms = receipt["payload"]["issued_at_ms"].as_i64().unwrap();
        policy
            .verify_and_consume_action_authorization(&request, &receipt, issued_at_ms + 1)
            .unwrap();
        receipt
    };
    let reloaded = reload_persisted_policy(&path);
    let issued_at_ms = receipt["payload"]["issued_at_ms"].as_i64().unwrap();
    let error = reloaded
        .verify_and_consume_action_authorization(&request, &receipt, issued_at_ms + 2)
        .expect_err("restart must not make a consumed receipt replayable");
    assert!(error.contains("already consumed"));
    cleanup_persistence(&path);
}

#[test]
fn issuance_and_consumption_refuse_persistence_failures() {
    let path = persistence_path("failure");
    let policy = initialize_persisted_policy(&path);
    let request = request();

    let blocker = block_next_state_write(&path);
    let GovernanceDecision::Veto {
        receipt: None,
        reason,
        ..
    } = policy.can_act(&request)
    else {
        panic!("an issuance persistence failure must veto without a receipt");
    };
    assert!(reason.contains("pending-ledger persistence failed"));

    fs::remove_dir(&blocker).unwrap();
    let receipt = approval(&policy, &request);
    let issued_at_ms = receipt["payload"]["issued_at_ms"].as_i64().unwrap();
    let blocker = block_next_state_write(&path);
    let error = policy
        .verify_and_consume_action_authorization(&request, &receipt, issued_at_ms + 1)
        .expect_err("a consume persistence failure must refuse routing");
    assert!(error.contains("ledger persistence failed"));

    fs::remove_dir(&blocker).unwrap();
    policy
        .verify_and_consume_action_authorization(&request, &receipt, issued_at_ms + 2)
        .expect("failed persistence must roll the pending entry back in memory");
    cleanup_persistence(&path);
}

#[test]
fn state_committed_before_checkpoint_failure_recovers_conservatively_on_restart() {
    let path = persistence_path("checkpoint-failure");
    let policy = initialize_persisted_policy(&path);
    let request = request();
    let receipt = approval(&policy, &request);
    let issued_at_ms = receipt["payload"]["issued_at_ms"].as_i64().unwrap();
    let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
    let blocker = block_next_state_write(&sequence_path);

    let error = policy
        .verify_and_consume_action_authorization(&request, &receipt, issued_at_ms + 1)
        .expect_err("checkpoint failure must refuse routing");
    assert!(error.contains("ledger persistence failed"));
    fs::remove_dir(blocker).unwrap();
    drop(policy);

    let reloaded = reload_persisted_policy(&path);
    let error = reloaded
        .verify_and_consume_action_authorization(&request, &receipt, issued_at_ms + 2)
        .expect_err("the signed state written before the crash window stays consumed");
    assert!(error.contains("already consumed"));
    cleanup_persistence(&path);
}

#[test]
fn human_hold_binding_and_consumption_refuse_persistence_failures() {
    let path = persistence_path("human-failure");
    let policy = initialize_persisted_policy(&path);
    let request = request();
    let receipt = approval(&policy, &request);
    let issued_at_ms = receipt["payload"]["issued_at_ms"].as_i64().unwrap();
    let decision =
        PolicyDecision::require_human_with_rule("test.require-human", "human review is required");

    let blocker = block_next_state_write(&path);
    let error = policy
        .begin_human_authorization_hold(&request, &receipt, &decision, issued_at_ms + 1)
        .expect_err("a hold persistence failure must refuse the hold");
    assert!(error.contains("hold was not created because persistence failed"));

    fs::remove_dir(&blocker).unwrap();
    let hold = policy
        .begin_human_authorization_hold(&request, &receipt, &decision, issued_at_ms + 2)
        .expect("the failed hold persistence must roll back in memory");
    let blocker = block_next_state_write(&path);
    let error = policy
        .bind_human_approval_set(&hold.hold_id, "approval-set:test", "set-digest:test")
        .expect_err("a binding persistence failure must refuse the binding");
    assert!(error.contains("set was not bound because persistence failed"));

    fs::remove_dir(&blocker).unwrap();
    policy
        .bind_human_approval_set(&hold.hold_id, "approval-set:test", "set-digest:test")
        .expect("the failed binding persistence must roll back in memory");
    let blocker = block_next_state_write(&path);
    let error = policy
        .verify_and_consume_human_authorization(
            &hold.hold_id,
            "approval-set:test",
            "set-digest:test",
            issued_at_ms + 3,
        )
        .expect_err("a consume persistence failure must refuse routing");
    assert!(error.contains("were not consumed because persistence failed"));

    fs::remove_dir(&blocker).unwrap();
    assert!(
        policy
            .pending_human_authorization("approval-set:test")
            .is_ok(),
        "failed persistence must leave the exact hold pending"
    );
    policy
        .verify_and_consume_human_authorization(
            &hold.hold_id,
            "approval-set:test",
            "set-digest:test",
            issued_at_ms + 4,
        )
        .expect("failed persistence must roll both approvals back in memory");
    cleanup_persistence(&path);
}
