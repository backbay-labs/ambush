//! Typed audit and replay records for the v1 runtime slice.
//!
//! The first milestone does not need the full upstream envelope or
//! checkpoint machinery. It needs a small, serializable record format
//! that captures what happened in the critical lane and can be replayed.

use serde::{Deserialize, Serialize};
use swarm_core::pheromone::PheromoneDeposit;
use swarm_policy::{ActionRequest, CapabilityLease, PolicyVerdict};
use swarm_response::{ResponseFailure, ResponseReceipt};
use swarm_whisker::{DetectionFinding, TelemetryEvent};

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
