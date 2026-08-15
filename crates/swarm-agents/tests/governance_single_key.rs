#![allow(clippy::unwrap_used, clippy::expect_used)]
//! BFT-03 / BFT-04: the single-key property, the transport seam, and the
//! receipt wire shape that must not move while they land.
//!
//! Read the header of `crates/swarm-consensus/src/transport.rs` first; it says
//! what shipped and what deliberately did not.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use swarm_agents::tom_agent::{
    GovernanceDecision, GovernanceKeyError, GovernancePolicy, GovernancePolicyConfig,
};
use swarm_consensus::{
    ConsensusCommittee, ConsensusError, ConsensusSignedEnvelope, ConsensusTransport,
};
use swarm_core::agent::AgentHealthEntry;
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_policy::ActionRequest;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn healthy_policy(seed: u8) -> Arc<GovernancePolicy> {
    let policy = Arc::new(GovernancePolicy::new(GovernancePolicyConfig::default()));
    policy
        .register_governor(AgentId::new("tom", "primary"), key(seed))
        .expect("a fresh policy holds no governor key");
    policy.observe_health(
        &AgentId::new("tom", "primary"),
        &[] as &[AgentHealthEntry],
        1_700_000_000_000,
    );
    policy
}

fn block_egress() -> ActionRequest {
    ActionRequest {
        hunt_id: HuntId("hunt-single-key".to_string()),
        requested_by: AgentId::new("pounce", "test"),
        action: ResponseAction::BlockEgress {
            target: "203.0.113.77".to_string(),
        },
        severity: Severity::Critical,
        evidence: serde_json::json!({"signal": "test"}),
    }
}

#[test]
fn a_second_distinct_governor_signing_key_is_refused() {
    // The structural half of BFT-03. Before this, `register_governor` returned
    // `()` and did `state.governors.insert(..)` unconditionally, so a policy
    // could accumulate every governor's private key and
    // `simulate_governance_commit` would then vote as all of them.
    let policy = GovernancePolicy::default();
    policy
        .register_governor(AgentId::new("tom", "primary"), key(3))
        .expect("first key is accepted");

    let error = policy
        .register_governor(AgentId::new("tom", "secondary"), key(4))
        .expect_err("a second, different signing key must be refused");
    let GovernanceKeyError::SecondSigningKey { existing, offered } = error else {
        panic!("expected a second-key error");
    };
    assert_eq!(
        existing,
        AgentId::from_verifying_key(&key(3).verifying_key())
    );
    assert_eq!(
        offered,
        AgentId::from_verifying_key(&key(4).verifying_key())
    );

    // Idempotent for the SAME key: `governance_resilience_integration.rs`
    // re-registers after a persistence reload and must keep working.
    policy
        .register_governor(AgentId::new("tom", "primary"), key(3))
        .expect("re-registering the same key is a no-op, not a conflict");

    policy.observe_health(
        &AgentId::new("tom", "primary"),
        &[] as &[AgentHealthEntry],
        1_700_000_000_000,
    );
    assert_eq!(policy.status_report().total_governors, 1);
}

#[test]
fn the_receipt_names_a_committee_of_one_signed_by_the_local_key() {
    // The observable consequence of the single-key property: the committee this
    // process can speak for is exactly itself. A receipt naming more members
    // than that, issued by a solo process, would be the thing BFT-03 removes.
    let policy = healthy_policy(5);
    let GovernanceDecision::Authorize { receipt, .. } = policy.can_act(&block_egress()) else {
        panic!("a healthy single-governor policy must allow with a receipt");
    };

    let verifying_key = receipt.verify().expect("receipt must verify");
    let local = AgentId::from_verifying_key(&key(5).verifying_key());
    assert_eq!(AgentId::from_verifying_key(&verifying_key), local);
    assert_eq!(receipt.payload.issued_by, local);
    assert_eq!(receipt.payload.committee_members, vec![local]);
    assert_eq!(receipt.payload.threshold, 1);
    assert_eq!(receipt.payload.prevote_tally, 1);
    assert_eq!(receipt.payload.precommit_tally, 1);
}

#[test]
fn admitting_a_peer_governor_without_a_networked_transport_vetoes() {
    // BFT-04's fail-closed edge, and the reason `SoloGovernorTransport` refuses
    // multi-member committees rather than quietly delivering nothing.
    //
    // Before this change the same situation was UNREACHABLE for the wrong
    // reason: a second governor could only be admitted by handing the policy its
    // private key, after which the in-process simulator voted for it and
    // returned Allow with a receipt claiming a 2-of-2 quorum that no second
    // process had taken part in.
    let policy = healthy_policy(6);
    policy
        .register_peer_governor(&key(7).verifying_key())
        .unwrap();

    let decision = policy.can_act(&block_egress());
    let GovernanceDecision::Veto {
        reason, receipt, ..
    } = decision
    else {
        panic!("a 2-member committee with no networked transport must veto, got {decision:?}");
    };
    assert!(receipt.is_none());
    assert!(
        reason.contains("governance round produced no receipt")
            && reason.contains("cannot serve a committee of 2 members"),
        "the veto must name the transport as the cause: {reason}"
    );
}

#[test]
fn the_governance_receipt_wire_shape_is_unchanged() {
    // NOT a feature test, and stated as such. It passes against the pre-BFT-03
    // tree by construction. Its job is to pin the JSON that
    // `crates/swarm-runtime/src/dispatcher.rs` and `crates/swarm-runtime/src/
    // lib.rs` deserialize, so replacing the in-process simulator with a
    // transport-driven round cannot move the wire format underneath them.
    //
    // The value assertions below are the half that is NOT free: a round that
    // silently degenerated to "one node agreed with itself" while a larger
    // committee was configured would keep this field set and still be wrong, so
    // the tallies are checked against the threshold rather than just present.
    let policy = healthy_policy(8);
    let GovernanceDecision::Authorize { receipt, .. } = policy.can_act(&block_egress()) else {
        panic!("expected an allow with a receipt");
    };

    let value = serde_json::to_value(&receipt).unwrap();
    let top_level = value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        top_level,
        vec!["payload".to_string(), "signature".to_string()]
    );

    let payload_keys = value["payload"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let mut expected = vec![
        "schema_version",
        "receipt_id",
        "decision",
        "committee_id",
        "committee_members",
        "threshold",
        "height",
        "round",
        "previous_commit_hash",
        "commit_hash",
        "proposal_id",
        "prevote_tally",
        "precommit_tally",
        "issued_by",
        "issued_at_ms",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    expected.sort();
    let mut observed = payload_keys;
    observed.sort();
    assert_eq!(observed, expected);

    assert!(receipt.payload.prevote_tally >= receipt.payload.threshold);
    assert!(receipt.payload.precommit_tally >= receipt.payload.threshold);
    assert_eq!(
        receipt.payload.committee_members.len(),
        receipt.payload.threshold,
        "a solo committee's threshold is its size; a receipt whose committee is larger than the \
         quorum it claims would mean the round committed without the missing members"
    );
    receipt.verify().unwrap();
}

#[test]
fn receipts_chain_across_calls_so_the_audit_log_is_ordered() {
    // `run_governance_round` advances `previous_commit_hash` exactly once per
    // committed round. If a refactor ever mints a receipt without advancing it
    // -- or advances it without committing -- this breaks.
    let policy = healthy_policy(9);
    let GovernanceDecision::Authorize { receipt: first, .. } = policy.can_act(&block_egress())
    else {
        panic!("expected an allow");
    };
    let GovernanceDecision::Authorize {
        receipt: second, ..
    } = policy.can_act(&block_egress())
    else {
        panic!("expected an allow");
    };

    assert_eq!(
        second.payload.previous_commit_hash,
        first.payload.commit_hash
    );
    assert_ne!(second.payload.commit_hash, first.payload.commit_hash);
    assert_ne!(second.payload.receipt_id, first.payload.receipt_id);
}

#[test]
fn admitted_peer_governors_survive_a_persistence_reload() {
    // Forgetting the peer set across a restart is a FAIL-OPEN, and it is not a
    // hypothetical one: a policy that knows about a peer refuses every
    // destructive action (the shipped solo transport cannot serve a two-member
    // committee), and a policy that has forgotten it is back to a committee of
    // one and starts authorizing again. Same failure family as b4bf119's:
    // governance state that survives a restart deciding differently from the
    // state that wrote it.
    let path = std::env::temp_dir().join(format!(
        "swarm-governance-peer-reload-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock is after the unix epoch")
            .as_nanos(),
    ));
    let _ = std::fs::remove_file(&path);

    let policy = GovernancePolicy::initialize_persistence(
        GovernancePolicyConfig::default(),
        &path,
        AgentId::new("tom", "primary"),
        key(21),
    )
    .expect("a fresh persistence path initializes");
    policy
        .register_peer_governor(&key(22).verifying_key())
        .unwrap();
    policy.observe_health(
        &AgentId::new("tom", "primary"),
        &[] as &[AgentHealthEntry],
        1_700_000_000_000,
    );
    assert!(matches!(
        policy.can_act(&block_egress()),
        GovernanceDecision::Veto { .. }
    ));
    drop(policy);

    let reloaded = GovernancePolicy::with_persistence(
        GovernancePolicyConfig::default(),
        &path,
        AgentId::new("tom", "primary"),
        key(21),
    )
    .expect("the persisted state reloads");
    reloaded.observe_health(
        &AgentId::new("tom", "primary"),
        &[] as &[AgentHealthEntry],
        1_700_000_000_000,
    );

    let decision = reloaded.can_act(&block_egress());
    assert!(
        matches!(decision, GovernanceDecision::Veto { .. }),
        "a reloaded policy must still know about its peer governor, got {decision:?}"
    );

    drop(reloaded);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(GovernancePolicy::persistence_sequence_path(&path));
    let _ = std::fs::remove_file(GovernancePolicy::persistence_lock_path(&path));
}

/// Records everything a round publishes. Accepts any committee, which is
/// exactly what `SoloGovernorTransport` refuses to do -- it lives here, in a
/// test, and not in the library, so nothing shippable can be wired to it.
#[derive(Debug, Default)]
struct RecordingTransport {
    accepted: std::sync::Mutex<Vec<usize>>,
    published: std::sync::Mutex<Vec<ConsensusSignedEnvelope>>,
}

impl ConsensusTransport for RecordingTransport {
    fn accept_committee(&self, committee: &ConsensusCommittee) -> Result<(), ConsensusError> {
        self.accepted
            .lock()
            .unwrap()
            .push(committee.members().len());
        Ok(())
    }

    fn publish(&self, envelope: &ConsensusSignedEnvelope) -> Result<(), ConsensusError> {
        self.published.lock().unwrap().push(envelope.clone());
        Ok(())
    }

    fn drain(&self) -> Result<Vec<ConsensusSignedEnvelope>, ConsensusError> {
        Ok(Vec::new())
    }
}

#[test]
fn can_act_publishes_its_round_through_the_policys_transport_and_signs_only_locally() {
    // BFT-04's positive claim, and the one that separates "drives a round through
    // a transport" from "calls a function that happens to be named that way":
    // the policy's OWN transport is asked to accept the committee and is handed
    // every envelope, and every envelope verifies to the LOCAL key. Under the
    // deleted `simulate_governance_commit` there was no transport to hand
    // anything to -- envelopes lived and died inside a local `VecDeque` -- and
    // envelopes signed by peer keys were exactly what it produced.
    let transport = Arc::new(RecordingTransport::default());
    let policy = Arc::new(
        GovernancePolicy::new(GovernancePolicyConfig::default())
            .with_transport(Arc::clone(&transport) as Arc<dyn ConsensusTransport>),
    );
    policy
        .register_governor(AgentId::new("tom", "primary"), key(31))
        .expect("a fresh policy holds no governor key");
    policy.observe_health(
        &AgentId::new("tom", "primary"),
        &[] as &[AgentHealthEntry],
        1_700_000_000_000,
    );

    let published_before = transport.published.lock().unwrap().len();
    assert!(
        published_before > 0,
        "observe_health issues contingency leases through the same transport; if this is zero \
         the lease path has stopped running rounds"
    );

    let decision = policy.can_act(&block_egress());
    assert!(matches!(decision, GovernanceDecision::Authorize { .. }));

    let accepted = transport.accepted.lock().unwrap().clone();
    assert!(
        accepted.iter().all(|size| *size == 1),
        "every round must present a one-member committee: {accepted:?}"
    );
    let published = transport.published.lock().unwrap().clone();
    assert!(
        published.len() > published_before,
        "can_act must publish through the policy's transport, not an internal queue"
    );
    let local = AgentId::from_verifying_key(&key(31).verifying_key());
    for envelope in published {
        let verifying_key = envelope.verify().expect("every envelope must verify");
        assert_eq!(
            AgentId::from_verifying_key(&verifying_key),
            local,
            "no envelope may be signed by anything but the one local key"
        );
    }
}
