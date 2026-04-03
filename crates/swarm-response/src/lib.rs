//! Execution layer for live response actions.
//!
//! The first milestone is intentionally small: expose a single trait for
//! adapters that execute capability-scoped actions and emit signed receipts.

pub mod adapters;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use swarm_policy::{ActionRequest, CapabilityLease};

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
}

/// Normalized successful response status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Simulated,
    Executed,
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
