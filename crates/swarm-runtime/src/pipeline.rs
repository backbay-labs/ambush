use serde::{Deserialize, Serialize};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;

/// Normalized event entering the runtime pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    pub source: String,
    pub event_type: String,
    pub threat_class: ThreatClass,
    pub severity: Severity,
    pub payload: serde_json::Value,
}

/// Summary emitted when the critical lane decides a response should be considered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionProposal {
    pub proposal_id: String,
    pub event: DetectionEvent,
    pub evidence: serde_json::Value,
}
