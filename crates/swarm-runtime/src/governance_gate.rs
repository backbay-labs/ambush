//! The pre-routing governance gate, as one public module, so the autonomous
//! path (`dispatcher.rs`) and the human path (`perch_ops::holds::decide_hold`)
//! cannot drift (bill item B2g).
//!
//! # What a cleared receipt does and does not establish
//!
//! `ConsensusGovernanceReceipt::verify()` checks a signature and that
//! `issued_by` derives from the signing key. IT DOES NOT CHECK THAT THE SIGNER
//! IS A GOVERNOR, and it cannot from here: the governor keys live inside the
//! concrete governance agent's state, not in anything a receipt carries. So
//! [`GovernanceClearance`] is named for what RAN, and no variant of it is
//! called `Verified`. A one-member committee that signed its own approval
//! clears this gate, and a test asserts exactly that limitation so
//! strengthening the gate has to change the test and the console's limit
//! sentence in the same commit.
//!
//! # Why re-authorization happens at decision time
//!
//! A hold can sit for an hour. The receipt that justified it may have been
//! vetoed, aged out, or never have been self-consistent. Checking at hold time
//! would authorize an action against facts that no longer hold when it runs,
//! so the decide path calls [`reauthorize`] with the decision instant.

use std::sync::Arc;

use swarm_consensus::{ConsensusGovernanceReceipt, GovernanceReceiptDecision};
use swarm_core::types::ResponseAction;
use swarm_policy::ActionRequest;
use swarm_policy::governance::GovernanceAuthority;

pub use crate::held_action::GovernanceClearance;

/// The twelve response actions that require a governance receipt.
///
/// Moved verbatim from `dispatcher.rs` so the autonomous path and the human
/// path read one list. Adding a destructive action means adding it here.
pub fn response_action_requires_governance_receipt(action: &ResponseAction) -> bool {
    matches!(
        action,
        ResponseAction::BlockEgress { .. }
            | ResponseAction::IsolateHost { .. }
            | ResponseAction::RevokeCredential { .. }
            | ResponseAction::SinkholeDns { .. }
            | ResponseAction::TerminateUserSession { .. }
            | ResponseAction::InjectFirewallRule { .. }
            | ResponseAction::QuarantineFile { .. }
            | ResponseAction::KillProcess { .. }
            | ResponseAction::SuspendProcess { .. }
            | ResponseAction::DisableUserAccount { .. }
            | ResponseAction::ForcePasswordReset { .. }
            | ResponseAction::RemoveScheduledTask { .. }
    )
}

/// `Some(reason)` when the request cannot proceed on receipt grounds.
///
/// A verbatim move of the dispatcher's G0 so the autonomous path stays
/// byte-identical: this task lifts the gate, it does not make the dispatcher
/// stricter.
pub fn missing_governance_receipt_reason(request: &ActionRequest) -> Option<String> {
    if !response_action_requires_governance_receipt(&request.action) {
        return None;
    }
    let Some(receipt_value) = request.evidence.get("governance_receipt").cloned() else {
        return Some("missing governance receipt".to_string());
    };
    let receipt: ConsensusGovernanceReceipt = match serde_json::from_value(receipt_value) {
        Ok(receipt) => receipt,
        Err(error) => return Some(format!("invalid governance receipt: {error}")),
    };
    receipt
        .verify()
        .map(|_| ())
        .map_err(|error| format!("invalid governance receipt signature: {error}"))
        .err()
}

/// Freshness window for a receipt, from `runtime.response`.
#[derive(Debug, Clone, Copy)]
pub struct GovernanceReceiptBounds {
    /// The hold's `held_at_ms`. A receipt issued AFTER this was minted to
    /// order for an action that was already pending.
    pub subject_captured_at_ms: i64,
    /// Older than this at decision time is `governance.receipt_stale`.
    pub max_age_ms: u64,
}

/// A typed refusal. `rule` is one of the `governance.*` rows of
/// `12-BACKEND-BILL-API.md` §4.6, rendered verbatim by the console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceRefusal {
    /// The refusing rule's stable name.
    pub rule: &'static str,
    /// The refusing layer's own words.
    pub reason: String,
}

fn refusal(rule: &'static str, reason: impl Into<String>) -> GovernanceRefusal {
    GovernanceRefusal {
        rule,
        reason: reason.into(),
    }
}

/// The whole pre-routing gate as one call, evaluated at `now_ms`.
///
/// Partition authorization comes first and SKIPS the receipt check, exactly as
/// the dispatcher's `!partition_authorized &&` does; then G0 (the shipped
/// signature check), G1 (the attested decision), G2 (both freshness bounds)
/// and G3 (committee self-consistency). G4 — binding the receipt to this
/// request's subject — needs the producer-side change B2g-s and is unreachable
/// until it lands, which is why the success arm returns `ReceiptSignatureOk`
/// and never `ReceiptSubjectBound`.
pub fn reauthorize(
    authority: Option<&Arc<dyn GovernanceAuthority>>,
    request: &ActionRequest,
    now_ms: i64,
    bounds: GovernanceReceiptBounds,
) -> Result<GovernanceClearance, GovernanceRefusal> {
    if let Some(authority) = authority {
        match authority.authorize_partition_request(request, now_ms) {
            Ok(true) => return Ok(GovernanceClearance::PartitionAuthorized),
            Ok(false) => {}
            Err(reason) => return Err(refusal("governance.partition_rejected", reason)),
        }
    }
    if !response_action_requires_governance_receipt(&request.action) {
        return Ok(GovernanceClearance::NotRequired);
    }
    // G0 — the shipped gate: the receipt exists, parses, and its signature
    // matches the key its own `issued_by` names.
    let Some(receipt_value) = request.evidence.get("governance_receipt").cloned() else {
        return Err(refusal(
            "governance.missing_receipt",
            "missing governance receipt",
        ));
    };
    let receipt: ConsensusGovernanceReceipt =
        serde_json::from_value(receipt_value).map_err(|error| {
            refusal(
                "governance.invalid_receipt",
                format!("invalid governance receipt: {error}"),
            )
        })?;
    receipt.verify().map_err(|error| {
        refusal(
            "governance.invalid_receipt",
            format!("invalid governance receipt signature: {error}"),
        )
    })?;
    let payload = &receipt.payload;
    // G1 — the field `verify()` never reads. A vetoed receipt is a valid
    // signature over a refusal, and the shipped gate would have let it pass.
    if payload.decision != GovernanceReceiptDecision::Approve {
        return Err(refusal(
            "governance.receipt_veto",
            "the attested decision is a veto",
        ));
    }
    // G2 — freshness, BOTH bounds. The upper bound is the load-bearing half: a
    // receipt issued after the action was held was minted to order for
    // something already pending.
    if payload.issued_at_ms > bounds.subject_captured_at_ms {
        return Err(refusal(
            "governance.receipt_stale",
            format!(
                "receipt issued at {} after the action was held at {}",
                payload.issued_at_ms, bounds.subject_captured_at_ms
            ),
        ));
    }
    if now_ms.saturating_sub(payload.issued_at_ms) > bounds.max_age_ms as i64 {
        return Err(refusal(
            "governance.receipt_stale",
            format!(
                "receipt issued at {} is older than {} ms",
                payload.issued_at_ms, bounds.max_age_ms
            ),
        ));
    }
    // G3 — self-consistency, not authority. These catch a HAND-BUILT payload:
    // `ConsensusCommittee::new` can never produce a zero threshold, so a
    // receipt that carries one was assembled and signed by hand.
    if payload.threshold == 0 {
        return Err(refusal(
            "governance.receipt_committee_inconsistent",
            "threshold is zero",
        ));
    }
    if !payload.committee_members.contains(&payload.issued_by) {
        return Err(refusal(
            "governance.receipt_committee_inconsistent",
            "issued_by is not a committee member",
        ));
    }
    if payload.prevote_tally < payload.threshold || payload.precommit_tally < payload.threshold {
        return Err(refusal(
            "governance.receipt_committee_inconsistent",
            "a tally is below the threshold",
        ));
    }
    // G4 is unreachable until B2g-s writes evidence["governance_proposal"].
    Ok(GovernanceClearance::ReceiptSignatureOk)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use swarm_consensus::{
        ConsensusCommit, ConsensusCommittee, ConsensusGovernanceReceipt,
        ConsensusGovernanceReceiptPayload, ConsensusProposal, GovernanceReceiptDecision,
    };
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_crypto::{DetachedSignature, canonical_json_bytes, sha256, sha256_hex};
    use swarm_policy::ActionRequest;

    const HELD_AT: i64 = 1_773_739_200_000;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[17; 32])
    }

    /// A receipt issued the honest way, through `ConsensusGovernanceReceipt::issue`.
    fn receipt(
        decision: GovernanceReceiptDecision,
        issued_at_ms: i64,
        signer_in_committee: bool,
    ) -> serde_json::Value {
        let key = signing_key();
        let issued_by = AgentId::from_verifying_key(&key.verifying_key());
        let member = if signer_in_committee {
            issued_by.clone()
        } else {
            AgentId::new("tom", "other")
        };
        // `new`'s second argument is max_faulty; threshold is 2f+1, so 0 gives 1.
        let committee = ConsensusCommittee::new(vec![member], 0).unwrap();
        let proposal_payload = json!({ "decision": decision });
        let commit = ConsensusCommit {
            height: 1,
            round: 0,
            committee_id: committee.committee_id().to_string(),
            proposal: ConsensusProposal {
                proposal_id: sha256_hex(&canonical_json_bytes(&proposal_payload).unwrap()),
                payload: proposal_payload,
            },
            prevote_tally: 1,
            precommit_tally: 1,
            commit_hash: "commit".to_string(),
        };
        serde_json::to_value(
            ConsensusGovernanceReceipt::issue(
                &commit,
                "prev",
                &committee,
                decision,
                issued_by,
                &key,
                issued_at_ms,
            )
            .unwrap(),
        )
        .unwrap()
    }

    /// A receipt assembled field by field and signed by hand.
    ///
    /// This is the adversary G3 exists for. `ConsensusCommittee::new` computes
    /// `threshold = 2 * max_faulty + 1` and refuses an empty member list, so a
    /// zero threshold or a below-threshold tally is UNREACHABLE through the
    /// honest constructor — the only way to produce one is to build the payload
    /// yourself, which anyone holding a key can do. Such a receipt passes
    /// `verify()` (the signature is real and `issued_by` derives from the key);
    /// only G3 catches it.
    fn forged_receipt(
        mutate: impl FnOnce(&mut ConsensusGovernanceReceiptPayload),
    ) -> serde_json::Value {
        let key = signing_key();
        let issued_by = AgentId::from_verifying_key(&key.verifying_key());
        let mut payload = ConsensusGovernanceReceiptPayload {
            schema_version: 1,
            receipt_id: "receipt-forged".to_string(),
            decision: GovernanceReceiptDecision::Approve,
            committee_id: "committee-forged".to_string(),
            committee_members: vec![issued_by.clone()],
            threshold: 1,
            height: 1,
            round: 0,
            previous_commit_hash: "prev".to_string(),
            commit_hash: "commit".to_string(),
            proposal_id: "proposal".to_string(),
            prevote_tally: 1,
            precommit_tally: 1,
            issued_by,
            issued_at_ms: HELD_AT - 1,
        };
        mutate(&mut payload);
        let payload_bytes = canonical_json_bytes(&payload).unwrap();
        let signature = key.sign(&payload_bytes);
        let verifying_key = key.verifying_key();
        let receipt = ConsensusGovernanceReceipt {
            payload,
            signature: DetachedSignature {
                algorithm: "ed25519".to_string(),
                key_id: sha256(verifying_key.as_bytes()).to_hex(),
                public_key_hex: hex::encode(verifying_key.to_bytes()),
                signature_hex: hex::encode(signature.to_bytes()),
            },
        };
        // The forgery is well-formed by construction: only G3 may reject it.
        receipt.verify().expect("a forged receipt still verifies");
        serde_json::to_value(receipt).unwrap()
    }

    fn request_with(receipt: Option<serde_json::Value>) -> ActionRequest {
        let mut evidence = json!({ "escalation": { "threat_class": "execution" } });
        if let Some(receipt) = receipt {
            evidence["governance_receipt"] = receipt;
        }
        ActionRequest {
            hunt_id: HuntId("hunt-evt-1".into()),
            requested_by: AgentId::from_public_key_hex(&"18".repeat(32)),
            action: ResponseAction::IsolateHost {
                host_id: "host-ops-1".into(),
            },
            severity: Severity::Critical,
            evidence,
        }
    }

    fn bounds() -> GovernanceReceiptBounds {
        GovernanceReceiptBounds {
            subject_captured_at_ms: HELD_AT,
            max_age_ms: 86_400_000,
        }
    }

    #[test]
    fn a_veto_receipt_is_refused() {
        let request = request_with(Some(receipt(
            GovernanceReceiptDecision::Veto,
            HELD_AT - 1,
            true,
        )));
        let refusal = reauthorize(None, &request, HELD_AT + 10, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.receipt_veto");
        // And the shipped gate would have passed it: the signature is valid.
        assert!(missing_governance_receipt_reason(&request).is_none());
    }

    #[test]
    fn a_receipt_issued_after_the_hold_is_refused() {
        let request = request_with(Some(receipt(
            GovernanceReceiptDecision::Approve,
            HELD_AT + 1,
            true,
        )));
        let refusal = reauthorize(None, &request, HELD_AT + 10, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.receipt_stale");
        assert!(refusal.reason.contains("after the action was held"));
    }

    #[test]
    fn a_receipt_older_than_max_age_is_refused() {
        let request = request_with(Some(receipt(
            GovernanceReceiptDecision::Approve,
            HELD_AT - 86_400_001,
            true,
        )));
        let refusal = reauthorize(None, &request, HELD_AT + 10, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.receipt_stale");
        assert!(refusal.reason.contains("older than"));
    }

    #[test]
    fn a_receipt_whose_signer_is_not_in_its_own_committee_is_refused() {
        let request = request_with(Some(receipt(
            GovernanceReceiptDecision::Approve,
            HELD_AT - 1,
            false,
        )));
        let refusal = reauthorize(None, &request, HELD_AT + 10, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.receipt_committee_inconsistent");
    }

    #[test]
    fn a_zero_threshold_receipt_is_refused() {
        let request = request_with(Some(forged_receipt(|payload| {
            payload.threshold = 0;
        })));
        let refusal = reauthorize(None, &request, HELD_AT + 10, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.receipt_committee_inconsistent");
        assert_eq!(refusal.reason, "threshold is zero");
    }

    #[test]
    fn a_receipt_whose_tallies_are_below_its_own_threshold_is_refused() {
        let request = request_with(Some(forged_receipt(|payload| {
            payload.threshold = 3;
            payload.prevote_tally = 3;
            payload.precommit_tally = 1;
        })));
        let refusal = reauthorize(None, &request, HELD_AT + 10, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.receipt_committee_inconsistent");
        assert_eq!(refusal.reason, "a tally is below the threshold");
    }

    #[test]
    fn a_self_signed_one_member_approve_receipt_is_accepted_and_clears_only_to_receipt_signature_ok()
     {
        // Asserts a LIMITATION. Strengthening the gate must fail this test and
        // force the console's limit sentence to change in the same commit.
        let request = request_with(Some(receipt(
            GovernanceReceiptDecision::Approve,
            HELD_AT - 1,
            true,
        )));
        let clearance = reauthorize(None, &request, HELD_AT + 10, bounds()).unwrap();
        assert_eq!(clearance, GovernanceClearance::ReceiptSignatureOk);
        assert_ne!(clearance, GovernanceClearance::ReceiptSubjectBound);
    }

    #[test]
    fn a_missing_receipt_on_a_gated_action_is_refused_and_a_non_gated_action_needs_none() {
        let refusal = reauthorize(None, &request_with(None), HELD_AT, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.missing_receipt");
        let mut scan = request_with(None);
        scan.action = ResponseAction::TriggerEdrScan {
            host_id: "h".into(),
            scan_profile: "quick".into(),
        };
        assert_eq!(
            reauthorize(None, &scan, HELD_AT, bounds()).unwrap(),
            GovernanceClearance::NotRequired
        );
    }

    #[test]
    fn a_malformed_receipt_is_an_invalid_receipt_not_a_missing_one() {
        let mut request = request_with(None);
        request.evidence["governance_receipt"] = json!({ "not": "a receipt" });
        let refusal = reauthorize(None, &request, HELD_AT, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.invalid_receipt");
    }

    /// A partition authorization SKIPS the receipt checks entirely, exactly as
    /// the dispatcher does, and a partition rejection is its own rule.
    ///
    /// Driven through the REAL `GovernancePolicy`: `GovernanceAuthority` is a
    /// sealed trait, deliberately, so that the set of types which can authorize
    /// a destructive action during a partition stays enumerable. A test double
    /// here would have had to break that seal, which is a worse trade than
    /// standing up the real policy.
    #[test]
    fn a_partition_authorization_short_circuits_and_a_rejection_is_its_own_rule() {
        use ed25519_dalek::SigningKey as GovernorKey;
        use swarm_agents::tom_agent::{
            GovernanceDecision, GovernancePolicy, GovernancePolicyConfig,
        };
        use swarm_core::agent::{AgentHealth, AgentHealthEntry, AgentRole};

        // Contingency leases are PRE-STAGED while the quorum is healthy and
        // redeemed against the WALL CLOCK during the partition, so this setup
        // is anchored to real time rather than to `HELD_AT`. A fixture instant
        // six months in the past stages a lease that has already expired, and
        // the partition arm then vetoes for the wrong reason.
        let base = crate::runtime_events::now_ms();

        let policy = |partitioned: bool| -> Arc<GovernancePolicy> {
            let policy = Arc::new(GovernancePolicy::new(GovernancePolicyConfig {
                contingency_lease_ttl_ms: 60_000,
                contingency_blast_radius_cap: 1,
            }));
            let governor = AgentId::new("tom", "primary");
            policy
                .register_governor(governor.clone(), GovernorKey::from_bytes(&[23; 32]))
                .expect("the policy holds no other governor key");
            // Healthy first: this is the observation that stages the leases.
            policy.observe_health(&governor, &[], base);
            if partitioned {
                // The only governor goes unhealthy: quorum is lost.
                policy.observe_health(
                    &governor,
                    &[AgentHealthEntry {
                        id: "tom-primary".to_string(),
                        role: AgentRole::Tom,
                        health: AgentHealth::Failed,
                    }],
                    base + 1_000,
                );
            }
            policy
        };

        // Healthy quorum: `Ok(false)` means no partition authorization was
        // needed, so the receipt checks still run and a missing receipt is
        // still a refusal.
        let healthy = policy(false);
        let authority: Arc<dyn GovernanceAuthority> = healthy;
        let refusal =
            reauthorize(Some(&authority), &request_with(None), base, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.missing_receipt");

        // Partitioned, destructive, no contingency lease in EVIDENCE: rejected
        // outright, under its own rule rather than as a missing receipt.
        let partitioned = policy(true);
        let request = request_with(None);
        let staged = partitioned.can_act(&request.action);
        let authority: Arc<dyn GovernanceAuthority> = partitioned;
        let refusal = reauthorize(Some(&authority), &request, base + 2_000, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.partition_rejected");
        assert!(
            refusal.reason.contains("contingency lease"),
            "{}",
            refusal.reason
        );

        // The same partitioned policy, now carrying the lease it staged: the
        // receipt checks are SKIPPED entirely and the clearance says which
        // authority admitted the act.
        let GovernanceDecision::Allow {
            contingency_lease: Some(lease),
            ..
        } = staged
        else {
            panic!("a partitioned policy should stage a contingency lease: {staged:?}");
        };
        let mut leased = request_with(None);
        leased.evidence["contingency_lease"] = serde_json::to_value(&lease).unwrap();
        assert!(
            leased.evidence.get("governance_receipt").is_none(),
            "the point of this arm is that no receipt is consulted"
        );
        assert_eq!(
            reauthorize(Some(&authority), &leased, base + 2_000, bounds()).unwrap(),
            GovernanceClearance::PartitionAuthorized
        );
    }
}
