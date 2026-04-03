//! Detection strategies that Whiskers execute on each telemetry event.

use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;

/// A detection match produced by a Whisker's analysis.
#[derive(Debug, Clone)]
pub struct DetectionMatch {
    /// What threat class was detected.
    pub threat_class: ThreatClass,
    /// Severity assessment.
    pub severity: Severity,
    /// Confidence score (0.0–1.0).
    pub confidence: f64,
    /// Raw indicator data for the pheromone deposit.
    pub indicator: serde_json::Value,
    /// Which detection strategy produced this match.
    pub strategy_id: String,
}

/// Trait for pluggable detection strategies.
///
/// Strategies are evolved by Kitten agents and verified by Z3
/// before deployment. They must be fast — microsecond budget per event.
pub trait DetectionStrategy: Send + Sync {
    /// Strategy identifier.
    fn id(&self) -> &str;

    /// Evaluate a single telemetry event. Returns matches (possibly empty).
    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionMatch>;
}

/// A telemetry event from the environment (eBPF, network, tool invocation, etc).
#[derive(Debug, Clone)]
pub struct TelemetryEvent {
    /// Event source (e.g., "tetragon", "hubble", "guard_pipeline").
    pub source: String,
    /// Event type within the source.
    pub event_type: String,
    /// Timestamp (unix seconds).
    pub timestamp: i64,
    /// Event payload.
    pub payload: serde_json::Value,
}
