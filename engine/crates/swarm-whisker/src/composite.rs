use crate::{DetectionFinding, DetectionStrategy, TelemetryEvent};
use std::any::Any;

/// Detector that evaluates all configured strategies for a single event.
pub struct CompositeDetector {
    strategies: Vec<Box<dyn DetectionStrategy>>,
}

impl CompositeDetector {
    pub fn new(strategies: Vec<Box<dyn DetectionStrategy>>) -> Self {
        Self { strategies }
    }

    pub fn strategies(&self) -> impl Iterator<Item = &dyn DetectionStrategy> {
        self.strategies.iter().map(|strategy| strategy.as_ref())
    }
}

impl DetectionStrategy for CompositeDetector {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn id(&self) -> &str {
        "composite"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        let trace_id =
            swarm_core::observability::current_trace_id().unwrap_or_else(|| "unknown".to_string());
        let span = tracing::debug_span!(
            "whisker.composite.evaluate",
            trace_id = %trace_id,
            event_id = %event.event_id,
            host_id = ?event.host_id,
            strategy_count = self.strategies.len()
        );
        let _guard = span.enter();

        self.strategies
            .iter()
            .flat_map(|strategy| strategy.evaluate(event))
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::CompositeDetector;
    use crate::{
        DetectionFinding, DetectionStrategy, ProcessStartEvent, TelemetryEvent, TelemetryPayload,
    };
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::Severity;

    struct MockStrategy {
        findings: Vec<DetectionFinding>,
    }

    impl DetectionStrategy for MockStrategy {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn id(&self) -> &str {
            "mock"
        }

        fn evaluate(&self, _event: &TelemetryEvent) -> Vec<DetectionFinding> {
            self.findings.clone()
        }
    }

    fn event() -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    fn finding(finding_id: &str, strategy_id: &str) -> DetectionFinding {
        DetectionFinding {
            finding_id: finding_id.to_string(),
            event_id: "evt-1".to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.8,
            evidence: serde_json::json!({ "strategy_id": strategy_id }),
            strategy_id: strategy_id.to_string(),
        }
    }

    #[test]
    fn id_is_composite() {
        let detector = CompositeDetector::new(Vec::new());

        assert_eq!(detector.id(), "composite");
    }

    #[test]
    fn evaluate_returns_empty_for_zero_strategies() {
        let detector = CompositeDetector::new(Vec::new());

        assert!(detector.evaluate(&event()).is_empty());
    }

    #[test]
    fn evaluate_merges_findings_from_all_strategies() {
        let detector = CompositeDetector::new(vec![
            Box::new(MockStrategy {
                findings: vec![finding("finding-1", "first")],
            }),
            Box::new(MockStrategy {
                findings: vec![finding("finding-2", "second")],
            }),
        ]);

        let findings = detector.evaluate(&event());

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].finding_id, "finding-1");
        assert_eq!(findings[1].finding_id, "finding-2");
    }
}
