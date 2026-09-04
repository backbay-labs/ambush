//! Hot-path detection submodule.
//!
//! External consumers should import through `crate::detection::*`.

pub mod metrics;
pub mod pipeline;

pub use metrics::{CriticalPathMetrics, encode_metrics};
pub use pipeline::{DetectionPipelineOutcome, PipelineError, detect_and_deposit};

/// Test-only mirror of the ingest crate's `routed_detection_from_request`, so
/// the hold store's tests can build a [`swarm_whisker::DetectionFinding`]
/// without linking `swarm-ingest-runtime` (which depends on this crate, so a
/// non-dev dependency the other way is a Cargo cycle).
#[cfg(test)]
pub fn routed_detection_for_test(
    request: &swarm_policy::ActionRequest,
) -> swarm_whisker::DetectionFinding {
    swarm_whisker::DetectionFinding {
        finding_id: format!("finding:{}", request.hunt_id.0),
        event_id: request.hunt_id.0.clone(),
        strategy_id: "test".to_string(),
        threat_class: swarm_core::pheromone::ThreatClass::Execution,
        severity: request.severity,
        confidence: 1.0,
        evidence: request.evidence.clone(),
    }
}
