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
    /// Human-readable outcome summary.
    pub summary: String,
    /// Adapter-specific evidence, status, or metadata.
    pub details: serde_json::Value,
}

/// Errors surfaced by live response adapters.
#[derive(Debug, thiserror::Error)]
pub enum ResponseError {
    #[error("response adapter unavailable: {0}")]
    Unavailable(String),

    #[error("execution failed: {0}")]
    ExecutionFailed(String),
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
