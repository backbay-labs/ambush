//! `swarm:rollback:v1` — the card that says a containment was undone.
//!
//! Published by the BRIDGE for both release triggers now that B1c exists, so
//! the operator key still publishes exactly one marker.
//!
//! Nothing here reads a clock or a store: every field comes from the
//! `ContainmentReleased` event, which the sweep built from the receipt it
//! actually got back. A card assembled from anything else would be the bridge
//! asserting an outcome it did not witness.

use serde_json::{Value, json};
use swarm_core::types::Severity;
use swarm_policy::governance::PartitionState;
use swarm_response::rollback::{RollbackReceipt, RollbackTrigger};

/// The `ContainmentReleased` variant's fields, destructured once at the seam.
#[derive(Debug, Clone)]
pub struct ContainmentReleasedFields {
    pub emitted_at_ms: i64,
    pub lease_id: String,
    pub trigger: RollbackTrigger,
    pub receipt: RollbackReceipt,
    pub lease_closed: bool,
    pub attestation_verified: bool,
    pub attestation_error: Option<String>,
    pub partition_state_at_execution: Option<PartitionState>,
}

/// The `swarm.perch.rollback.v1` fact.
///
/// `release_response` rides only on a MANUAL release. An expiry comes from the
/// sweep with no HTTP request behind it, so there is no response to report, and
/// a card that invented one would be describing a request nobody made.
#[must_use]
pub fn rollback_card_body(
    event: &ContainmentReleasedFields,
    case_channel: uuid::Uuid,
    lease_card_id: &str,
) -> Value {
    let mut fact = json!({
        "schema": "swarm.perch.rollback.v1",
        "issuer": {
            "swarm_agent_id": "containment-sweep",
            "role": Value::Null,
            "nostr_pubkey": Value::Null,
        },
        "emitted_at_ms": event.emitted_at_ms,
        "locator": {
            "rollback_id": event.receipt.rollback_id,
            "lease_id": event.lease_id,
            "case_channel": case_channel.to_string(),
            "lease_card_id": lease_card_id,
        },
        "rollback_receipt": event.receipt,
        "partition_state_at_execution": event.partition_state_at_execution,
    });
    if event.trigger == RollbackTrigger::Manual {
        fact["release_response"] = json!({
            "lease_closed": event.lease_closed,
            "fully_reversed": event.receipt.fully_reversed(),
            "attestation_verified": event.attestation_verified,
            "attestation_error": event.attestation_error,
        });
    }
    fact
}

/// The closed tag budget for a rollback card.
///
/// `h` (the case), exactly one `e` (the lease card, as a NIP-10 reply), `t`,
/// `l`, `k`. Never a `p`: a kind:9 card addresses a channel, and a `p` tag
/// would make it a notice to a person.
#[must_use]
pub fn rollback_tags(
    case_channel: uuid::Uuid,
    lease_card_id: &str,
    severity: Severity,
    threat_class_slug: &str,
) -> Vec<Vec<String>> {
    vec![
        vec!["h".to_string(), case_channel.to_string()],
        vec![
            "e".to_string(),
            lease_card_id.to_string(),
            String::new(),
            "reply".to_string(),
        ],
        vec!["t".to_string(), threat_class_slug.to_string()],
        vec![
            "l".to_string(),
            serde_json::to_value(severity)
                .ok()
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_default(),
        ],
        vec!["k".to_string(), "rollback".to_string()],
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use swarm_response::{ExecutionMode, ResponseStatus};

    fn fields(trigger: RollbackTrigger) -> ContainmentReleasedFields {
        ContainmentReleasedFields {
            emitted_at_ms: 1_773_739_125_000,
            lease_id: "cl_a".to_string(),
            trigger,
            receipt: RollbackReceipt {
                rollback_id: "rb_a".to_string(),
                lease_id: "cl_a".to_string(),
                origin_receipt_id: "resp:cl_a".to_string(),
                governance_receipt_id: None,
                trigger,
                mode: ExecutionMode::Enforced,
                status: ResponseStatus::Executed,
                steps: Vec::new(),
                completed_at_ms: 1_773_739_125_000,
                summary: "0 of 0 steps reversed".to_string(),
                governance_attestation: None,
            },
            lease_closed: true,
            attestation_verified: false,
            attestation_error: Some("unattested".to_string()),
            partition_state_at_execution: Some(PartitionState::Healing),
        }
    }

    const CASE: &str = "27799e23-ab25-4659-b381-3de47ea7ca4d";

    /// A manual release has a request behind it; an expiry does not.
    ///
    /// A `release_response` on an expiry card would describe a request nobody
    /// made, which is the kind of invented detail an operator cannot audit.
    #[test]
    fn release_response_rides_only_on_a_manual_release() {
        let case = uuid::Uuid::parse_str(CASE).unwrap();
        let manual = rollback_card_body(&fields(RollbackTrigger::Manual), case, "0xcard");
        assert_eq!(manual["release_response"]["lease_closed"], true);
        // Deliberately false: this receipt reversed NO steps, and
        // `fully_reversed` is stricter than "nothing errored" because an
        // operator reading it acts on it. "We undid it" and "we went through
        // the motions" must not render the same.
        assert_eq!(manual["release_response"]["fully_reversed"], false);
        assert_eq!(manual["release_response"]["attestation_verified"], false);
        assert_eq!(
            manual["release_response"]["attestation_error"],
            "unattested"
        );

        let expiry = rollback_card_body(&fields(RollbackTrigger::Expiry), case, "0xcard");
        assert!(
            expiry.get("release_response").is_none(),
            "an expiry has no request to report"
        );
    }

    /// The card reports a real restoration as one.
    #[test]
    fn a_receipt_that_restored_every_step_reports_fully_reversed() {
        use swarm_core::types::ResponseRollbackStepKind;
        use swarm_response::rollback::{RollbackStepOutcome, RollbackStepStatus};

        let case = uuid::Uuid::parse_str(CASE).unwrap();
        let mut event = fields(RollbackTrigger::Manual);
        event.receipt.steps = vec![RollbackStepOutcome {
            kind: ResponseRollbackStepKind::RestoreHostConnectivity,
            status: RollbackStepStatus::Reversed,
            detail: "restored host-1".to_string(),
        }];
        let body = rollback_card_body(&event, case, "0xcard");
        assert_eq!(body["release_response"]["fully_reversed"], true);

        // A simulated step did not restore anything, and says so.
        event.receipt.steps[0].status = RollbackStepStatus::Simulated;
        let rehearsed = rollback_card_body(&event, case, "0xcard");
        assert_eq!(rehearsed["release_response"]["fully_reversed"], false);
    }

    /// Every field is the event's. The card asserts nothing the sweep did not
    /// witness.
    #[test]
    fn the_card_carries_the_receipt_and_the_partition_verbatim() {
        let case = uuid::Uuid::parse_str(CASE).unwrap();
        let event = fields(RollbackTrigger::Expiry);
        let body = rollback_card_body(&event, case, "0xcard");
        assert_eq!(body["schema"], "swarm.perch.rollback.v1");
        assert_eq!(body["emitted_at_ms"], event.emitted_at_ms);
        assert_eq!(body["locator"]["rollback_id"], "rb_a");
        assert_eq!(body["locator"]["lease_id"], "cl_a");
        assert_eq!(body["locator"]["case_channel"], CASE);
        assert_eq!(body["locator"]["lease_card_id"], "0xcard");
        assert_eq!(body["partition_state_at_execution"], "healing");
        assert_eq!(
            body["rollback_receipt"],
            serde_json::to_value(&event.receipt).unwrap()
        );
    }

    /// An unestablished partition is null, never `healthy`.
    #[test]
    fn an_unknown_partition_is_null_not_healthy() {
        let case = uuid::Uuid::parse_str(CASE).unwrap();
        let mut event = fields(RollbackTrigger::Expiry);
        event.partition_state_at_execution = None;
        let body = rollback_card_body(&event, case, "0xcard");
        assert!(body["partition_state_at_execution"].is_null());
    }

    /// The tag budget is closed: one `e`, and never a `p`.
    #[test]
    fn the_tag_budget_is_closed_and_carries_no_p() {
        let case = uuid::Uuid::parse_str(CASE).unwrap();
        let tags = rollback_tags(case, "0xcard", Severity::Critical, "execution");
        let names: Vec<&str> = tags
            .iter()
            .filter_map(|tag| tag.first())
            .map(String::as_str)
            .collect();
        assert_eq!(names, vec!["h", "e", "t", "l", "k"]);
        assert!(!names.contains(&"p"), "a kind:9 card never carries a p tag");
        assert_eq!(tags[1][1], "0xcard");
        assert_eq!(tags[1][3], "reply", "the lease card is the NIP-10 parent");
        assert_eq!(tags[3][1], "CRITICAL");
        assert_eq!(tags[4][1], "rollback");
    }
}
