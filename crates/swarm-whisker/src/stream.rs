//! Stream processing runtime for Whisker agents.
//!
//! The first slice is intentionally small: evaluate a normalized event
//! through a concrete detector and materialize resulting pheromone deposits.

use crate::detector::{DetectionFinding, DetectionStrategy, TelemetryEvent};
use swarm_core::config::PheromoneConfig;
use swarm_core::pheromone::PheromoneDeposit;
use swarm_core::types::AgentId;

/// Evaluate one telemetry event with a detector and return structured findings.
pub fn evaluate_event<D>(detector: &D, event: &TelemetryEvent) -> Vec<DetectionFinding>
where
    D: DetectionStrategy,
{
    detector.evaluate(event)
}

/// Convert detector findings into pheromone deposits for the substrate layer.
pub fn findings_to_deposits(
    findings: &[DetectionFinding],
    event: &TelemetryEvent,
    agent_id: &AgentId,
    pheromone: &PheromoneConfig,
) -> Vec<PheromoneDeposit> {
    findings
        .iter()
        .map(|finding| PheromoneDeposit {
            indicator: serde_json::json!({
                "event_id": finding.event_id,
                "source": event.source,
                "evidence": finding.evidence.clone(),
            }),
            threat_class: finding.threat_class.clone(),
            severity: finding.severity,
            confidence: finding.confidence,
            timestamp: event.timestamp,
            decay_half_life: pheromone.default_half_life_secs,
            agent_id: agent_id.clone(),
            signature: Vec::new(),
            agent_key: Vec::new(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{evaluate_event, findings_to_deposits};
    use crate::detector::{
        ProcessStartEvent, SuspiciousProcessTreeDetector, TelemetryEvent, TelemetryPayload,
    };
    use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
    use swarm_core::types::AgentId;

    #[test]
    fn findings_convert_to_deposits() {
        let detector = SuspiciousProcessTreeDetector::default();
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc AAA=".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };

        let findings = evaluate_event(&detector, &event);
        let deposits = findings_to_deposits(
            &findings,
            &event,
            &AgentId("whisker-a".to_string()),
            &PheromoneConfig {
                default_half_life_secs: 3600.0,
                evaporation_threshold: 0.01,
                min_sources_for_escalation: 2,
                alert_threshold: 2.0,
                incident_threshold: 5.0,
                backend: PheromoneBackendConfig::InMemory,
            },
        );

        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].agent_id.0, "whisker-a");
    }
}
