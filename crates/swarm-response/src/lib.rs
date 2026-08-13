//! Execution layer for live response actions.
//!
//! The first milestone is intentionally small: expose a single trait for
//! adapters that execute capability-scoped actions and emit signed receipts.
//!
//! ## Owns
//!
//! - Performing the action: the adapter trait and its implementations
//!   ([`adapters`], [`http_edr`], [`crowdstrike_rtr`], [`webhook`]) and the
//!   dispatch path that drives them ([`dispatch`]).
//! - Undoing the action: containment leases, their expiry, and the inverse
//!   plans that reverse them ([`containment`], [`rollback`]).
//! - The receipt for what was attempted, including failure and simulated
//!   outcomes, plus the outbound resilience around a live effect
//!   ([`resilience`], [`dead_letter`]).
//! - Fan-out of finished findings to operators and SIEMs ([`notification`],
//!   [`siem`], [`splunk_hec`]).
//!
//! ## Does not own
//!
//! - Deciding whether the action is allowed. Every adapter is handed a
//!   [`CapabilityLease`] minted by `swarm-policy`; this crate never re-decides
//!   and never fabricates one.
//! - Detection, correlation, or scoring.
//! - The audit chain. It emits receipts; `swarm-spine` chains and signs them.
//! - The advisory lane. `swarm-runtime`'s correlation and memory modules must
//!   never reach the dispatch path, so what gets executed never depends on how
//!   much optional context happened to be available (TCBOUND-04), and that ban
//!   covers dev-dependencies too.
//!
//! NOT in the trusted computing base, deliberately. This crate declares
//! `reqwest` because a live-response adapter has to talk to an EDR, and that is
//! precisely why the *decision* lives one crate down in `swarm-policy` where no
//! transport is reachable. The one consequence worth stating: `swarm-spine`
//! declares this crate, so `reqwest` and `hyper` are reachable from the TCB
//! through it — see this crate's entry in ADR 0009.
//!
//! The advisory-lane ban is enforced by `tools/check-workspace-layering.sh`,
//! which runs in CI and carries a fixture proving it fails when it is broken.

pub mod adapters;
pub mod config;
pub mod containment;
pub mod crowdstrike_rtr;
pub mod dead_letter;
pub mod dispatch;
pub mod http_edr;
pub mod notification;
pub mod resilience;
pub mod rollback;
pub mod siem;
pub mod splunk_hec;
pub mod webhook;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use swarm_core::types::AgentId;
use swarm_policy::{ActionRequest, CapabilityLease, PolicyVerdict};

pub use config::{
    CircuitBreakerConfig, CrowdStrikeRtrConfig, HttpEdrConfig, NotificationChannelConfig,
    NotificationRateLimitConfig, NotificationRoutingConfig, QuietHoursConfig,
    ResponseAdapterConfig, RetryConfig, RoutingRule, SiemForwardConfig, WebhookConfig,
};
pub use containment::{
    CONTAINMENT_LEASE_SCHEMA_VERSION, ContainmentLease, ContainmentLeaseError,
    ContainmentLeaseStore, ContainmentStoreError, ContainmentTtl, FileContainmentLeaseStore,
    MemoryContainmentLeaseStore,
};
pub use crowdstrike_rtr::CrowdStrikeRtrAdapter;
pub use dead_letter::{DeadLetterEntry, DeadLetterJournal};
pub use dispatch::DispatchingExecutor;
pub use http_edr::{HttpEdrAdapter, HttpEdrRollbackExecutor};
pub use notification::{NotificationError, NotificationReplayResult, NotificationRouter};
pub use resilience::{CircuitBreakerState, ResilientExecutor};
pub use rollback::{
    ContainmentInverse, InverseGap, RollbackExecutor, RollbackReceipt, RollbackStepOutcome,
    RollbackStepStatus, RollbackTrigger, SandboxRollbackExecutor, plan_is_reversible,
    resolve_inverse,
};
pub use siem::{SiemFindingForwarder, SiemForwardAdapter, SwarmFindingEnvelope};
pub use splunk_hec::{SplunkHecAdapter, SwarmFindingBatchEnvelope};
pub use webhook::WebhookAdapter;

/// Whether a response adapter should act or simulate execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    /// Log intent and return a synthetic receipt without changing the world.
    DryRun,
    /// Perform the external side effect.
    Enforced,
}

/// Receipt emitted by a response adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseReceipt {
    /// Stable receipt identifier for audit reconstruction.
    pub receipt_id: String,
    /// Stable action name for audit and replay.
    pub action: String,
    /// Whether the adapter simulated or executed the action.
    pub mode: ExecutionMode,
    /// Normalized result status.
    pub status: ResponseStatus,
    /// Human-readable outcome summary.
    pub summary: String,
    /// Adapter-specific evidence, status, or metadata.
    pub details: serde_json::Value,
    /// Runtime-owned audit metadata layered on top of adapter output.
    #[serde(default)]
    pub audit: ResponseReceiptAudit,
}

/// Runtime-owned audit metadata attached to successful response receipts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseReceiptAudit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<ResponsePolicyAudit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance: Option<ResponseGovernanceAudit>,
}

/// Policy attribution captured on a successful response receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePolicyAudit {
    pub verdict: PolicyVerdict,
    pub rule_name: String,
    pub reason: String,
}

/// Governance attribution captured on response receipts and synthetic veto receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseGovernanceAudit {
    pub governing_agent_id: AgentId,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<serde_json::Value>,
}

/// Normalized response status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Simulated,
    Executed,
    Timeout,
    Failed,
}

/// Normalized failure record for response execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseFailure {
    pub receipt_id: String,
    pub action: String,
    pub mode: ExecutionMode,
    pub message: String,
    pub details: serde_json::Value,
}

/// Errors surfaced by live response adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseError {
    pub failure: ResponseFailure,
}

impl std::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.failure.message)
    }
}

impl std::error::Error for ResponseError {}

impl ResponseError {
    pub fn unavailable(
        action: impl Into<String>,
        mode: ExecutionMode,
        message: impl Into<String>,
    ) -> Self {
        let action = action.into();
        Self {
            failure: ResponseFailure {
                receipt_id: format!("resp-failure:{action}"),
                action,
                mode,
                message: message.into(),
                details: serde_json::json!({}),
            },
        }
    }

    pub fn execution_failed(
        receipt_id: impl Into<String>,
        action: impl Into<String>,
        mode: ExecutionMode,
        message: impl Into<String>,
        details: serde_json::Value,
    ) -> Self {
        Self {
            failure: ResponseFailure {
                receipt_id: receipt_id.into(),
                action: action.into(),
                mode,
                message: message.into(),
                details,
            },
        }
    }
}

impl ResponseStatus {
    pub fn indicates_success(self) -> bool {
        matches!(self, Self::Simulated | Self::Executed)
    }
}

impl ResponseReceipt {
    pub fn with_policy_audit(
        mut self,
        verdict: PolicyVerdict,
        rule_name: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        self.audit.policy = Some(ResponsePolicyAudit {
            verdict,
            rule_name: rule_name.into(),
            reason: reason.into(),
        });
        self
    }

    pub fn with_governance_audit(
        mut self,
        governing_agent_id: AgentId,
        reason: impl Into<String>,
        receipt: Option<serde_json::Value>,
    ) -> Self {
        self.audit.governance = Some(ResponseGovernanceAudit {
            governing_agent_id,
            reason: reason.into(),
            receipt,
        });
        self
    }

    pub fn into_failure(self) -> ResponseFailure {
        ResponseFailure {
            receipt_id: self.receipt_id,
            action: self.action,
            mode: self.mode,
            message: self.summary,
            details: serde_json::json!({
                "status": self.status,
                "details": self.details,
                "audit": self.audit,
            }),
        }
    }
}

/// Capability-scoped executor for live response actions.
#[async_trait]
pub trait ResponseExecutor: Send + Sync {
    /// Execute or simulate an action under the supplied lease.
    async fn execute(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError>;
}
