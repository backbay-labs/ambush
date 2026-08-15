//! Shared governance request, hold, event, and health-report value types.
//!
//! The authority capability and concrete policy live in `swarm-governance`.
//! This lower policy crate owns only the serializable values used across that
//! boundary; it exposes no governance backend or authorization extension point.

use serde::{Deserialize, Serialize};
use swarm_core::agent::AgentRole;
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};

use crate::{ActionRequest, PolicyDecision, static_gate::scope_for_response_action};

pub const GOVERNANCE_ACTION_REQUEST_SUBJECT_SCHEMA_VERSION: u32 = 1;
pub const GOVERNANCE_ACTION_REQUEST_SUBJECT_DOMAIN: &str =
    "swarm.governance.action-request.authorization.v1";
pub const GOVERNED_HUMAN_APPROVAL_EVIDENCE_PREFIX: &str =
    "swarm.governance.human-authorization.v1:";

/// Canonical subject governed for one response request.
///
/// The two bearer artifacts are deliberately not part of the subject: the receipt
/// cannot hash itself, and the partition lease is verified through its own path.
/// Every other evidence field is retained. The domain and schema prevent this digest
/// from being confused with a release attestation, contingency lease, or later schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernanceActionRequestSubjectV1 {
    pub domain: String,
    pub schema_version: u32,
    pub hunt_id: HuntId,
    pub requested_by: AgentId,
    pub action: ResponseAction,
    pub scope: Option<String>,
    pub severity: Severity,
    pub evidence: serde_json::Value,
}

impl GovernanceActionRequestSubjectV1 {
    pub fn from_request(request: &ActionRequest) -> Self {
        let mut evidence = request.evidence.clone();
        if let Some(object) = evidence.as_object_mut() {
            object.remove("governance_receipt");
            object.remove("contingency_lease");
        }
        Self {
            domain: GOVERNANCE_ACTION_REQUEST_SUBJECT_DOMAIN.to_string(),
            schema_version: GOVERNANCE_ACTION_REQUEST_SUBJECT_SCHEMA_VERSION,
            hunt_id: request.hunt_id.clone(),
            requested_by: request.requested_by.clone(),
            action: request.action.clone(),
            scope: scope_for_response_action(&request.action),
            severity: request.severity,
            evidence,
        }
    }
}

/// Durable composition point between a pending governance authorization and an
/// ordinary policy decision that requires a human.
///
/// This record is data, not an execution capability. The configured governance
/// authority persists and consumes it, and the dispatcher can mint an execution
/// admission only from the consumed form returned by that authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernedHumanAuthorizationHold {
    pub hold_id: String,
    pub request: ActionRequest,
    pub policy_decision: PolicyDecision,
    pub governance_receipt: serde_json::Value,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_set_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_set_digest: Option<String>,
}

impl GovernedHumanAuthorizationHold {
    pub fn approval_evidence_ref(&self) -> String {
        format!("{GOVERNED_HUMAN_APPROVAL_EVIDENCE_PREFIX}{}", self.hold_id)
    }
}

/// Result of atomically consuming both a human hold and its still-pending
/// governance authorization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsumedGovernedHumanAuthorization {
    pub hold: GovernedHumanAuthorizationHold,
    pub verified_governance_receipt: serde_json::Value,
}

/// One governance-originated runtime event, flattened to what the dispatcher publishes.
///
/// The concrete event enum stays private to the governance agent. Everything the
/// dispatcher ever read out of it -- the governing agent, the action-kind label, and
/// the serialized body -- is carried here, so the agent owns the mapping and the
/// dispatcher owns only the publishing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernanceRuntimeEventRecord {
    /// Identifier of the governor that emitted the event.
    pub governing_agent_id: String,
    /// Role to attribute the event to on the runtime event bus.
    pub role: AgentRole,
    /// Stable action-kind label for the emitted runtime event.
    pub action_kind: String,
    /// Serialized event body.
    pub details: serde_json::Value,
}

/// Where the governance quorum currently sits on the partition/heal path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionState {
    Healthy,
    Degraded,
    Partitioned,
    Healing,
}

/// The governance policy's own account of itself, as operators read it.
///
/// Kept in this lower value-type crate so the ingest health surface can render
/// these eight fields into `/healthz` without depending on governance internals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceStatusReport {
    pub partition_state: PartitionState,
    pub total_governors: usize,
    pub healthy_governors: usize,
    pub quorum_threshold: usize,
    pub active_contingency_leases: usize,
    pub unauthorized_partition_actions: usize,
    pub last_transition_at_ms: Option<i64>,
    pub last_reconciliation_report_id: Option<String>,
}
