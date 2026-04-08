//! Deterministic approval gate for live response actions.
//!
//! This crate is the Rust-first replacement for the earlier Python
//! governance path. It is intentionally narrow:
//! - define the request shape for live response actions
//! - evaluate those requests against a static policy gate
//! - mint short-lived capability leases for authorized execution

pub mod configurable_gate;
pub mod static_gate;

use serde::{Deserialize, Serialize};
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};

/// A response request emitted by the detection runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    /// Investigation or correlation context.
    pub hunt_id: HuntId,
    /// Agent or service requesting the action.
    pub requested_by: AgentId,
    /// Action to authorize.
    pub action: ResponseAction,
    /// Current threat severity driving the request.
    pub severity: Severity,
    /// Evidence bundle carried with the request.
    pub evidence: serde_json::Value,
}

/// Runtime context passed into the approval gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalContext {
    /// Whether the runtime may issue live actions or only dry-run them.
    pub live_mode: bool,
    /// Receipt or checkpoint identifiers already associated with the request.
    pub receipt_chain: Vec<String>,
    /// Optional request correlation ID for structured logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Wall-clock timestamp in unix milliseconds.
    pub now_ms: i64,
}

/// The outcome of evaluating a live response request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Deterministic policy verdict.
    pub verdict: PolicyVerdict,
    /// Stable rule identifier responsible for the final verdict.
    pub rule_name: String,
    /// Human-readable explanation for audit logs and operators.
    pub reason: String,
}

/// Deterministic policy verdicts for a response request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyVerdict {
    Deny,
    Allow,
    RequireHuman,
}

impl PolicyDecision {
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::deny_with_rule("policy.unknown", reason)
    }

    pub fn deny_with_rule(rule_name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            verdict: PolicyVerdict::Deny,
            rule_name: rule_name.into(),
            reason: reason.into(),
        }
    }

    pub fn allow(reason: impl Into<String>) -> Self {
        Self::allow_with_rule("policy.unknown", reason)
    }

    pub fn allow_with_rule(rule_name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            verdict: PolicyVerdict::Allow,
            rule_name: rule_name.into(),
            reason: reason.into(),
        }
    }

    pub fn require_human(reason: impl Into<String>) -> Self {
        Self::require_human_with_rule("policy.unknown", reason)
    }

    pub fn require_human_with_rule(
        rule_name: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            verdict: PolicyVerdict::RequireHuman,
            rule_name: rule_name.into(),
            reason: reason.into(),
        }
    }
}

/// A short-lived authorization lease attached to a live response request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityLease {
    /// Opaque capability identifier.
    pub capability_id: String,
    /// Expiration time for the lease in unix milliseconds.
    pub expires_at_ms: i64,
    /// Response action authorized by the lease.
    pub action: String,
    /// Optional target scope, such as a host or network segment.
    pub scope: Option<String>,
}

/// Policy evaluation errors.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    #[error("policy denied action: {0}")]
    Denied(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

/// Deterministic approval gate for live response execution.
pub trait ApprovalGate: Send + Sync {
    /// Evaluate a response request under the supplied runtime context.
    fn evaluate(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<PolicyDecision, ApprovalError>;

    /// Mint a short-lived capability lease for an authorized request.
    fn issue_lease(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<CapabilityLease, ApprovalError>;
}
