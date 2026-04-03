//! Typed audit and replay records for the v1 runtime slice.
//!
//! The first milestone does not need the full upstream envelope or
//! checkpoint machinery. It needs a small, serializable record format
//! that captures what happened in the critical lane and can be replayed.

pub mod store;

use serde::{Deserialize, Serialize};
use swarm_core::pheromone::PheromoneDeposit;
use swarm_policy::{ActionRequest, CapabilityLease, PolicyVerdict};
use swarm_response::{ResponseFailure, ResponseReceipt};
use swarm_whisker::{DetectionFinding, TelemetryEvent};

pub use store::{
    ConfiguredReplayBundleStore, FileReplayBundleStore, MemoryReplayBundleStore,
    ReplayBundleLookup, ReplayBundleRecord, ReplayBundleStore, ReplayPreview, ReplayStoreError,
    ReplayStoreHealth,
};

/// Policy step captured in an audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub verdict: PolicyVerdict,
    pub reason: String,
    pub lease: Option<CapabilityLease>,
}

/// Response step captured in an audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditResponseRecord {
    Success(ResponseReceipt),
    Failure(ResponseFailure),
    Skipped { reason: String },
}

/// Minimal auditable trail for one handled event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrail {
    pub trail_id: String,
    pub hunt_id: String,
    pub related_receipt_ids: Vec<String>,
    pub detection: DetectionFinding,
    pub policy: PolicyRecord,
    pub response: AuditResponseRecord,
    pub created_at_ms: i64,
}

/// File-backed bundle that can replay the critical path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBundle {
    pub bundle_id: String,
    pub event: TelemetryEvent,
    pub findings: Vec<DetectionFinding>,
    pub deposits: Vec<PheromoneDeposit>,
    pub action_request: ActionRequest,
    pub audit: AuditTrail,
}

impl AuditTrail {
    pub fn response_receipt_id(&self) -> Option<&str> {
        match &self.response {
            AuditResponseRecord::Success(receipt) => Some(&receipt.receipt_id),
            AuditResponseRecord::Failure(failure) => Some(&failure.receipt_id),
            AuditResponseRecord::Skipped { .. } => None,
        }
    }

    pub fn response_kind(&self) -> &'static str {
        match &self.response {
            AuditResponseRecord::Success(_) => "success",
            AuditResponseRecord::Failure(_) => "failure",
            AuditResponseRecord::Skipped { .. } => "skipped",
        }
    }

    pub fn all_receipt_ids(&self) -> Vec<String> {
        let mut receipt_ids = self.related_receipt_ids.clone();
        if let Some(receipt_id) = self.response_receipt_id()
            && !receipt_ids.iter().any(|existing| existing == receipt_id)
        {
            receipt_ids.push(receipt_id.to_string());
        }
        receipt_ids
    }
}

impl ReplayBundle {
    pub fn action_kind(&self) -> &'static str {
        self.action_request.action.kind()
    }
}
