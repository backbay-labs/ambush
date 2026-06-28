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

/// Derive a pheromone source identity scoped to one detector strategy.
pub fn strategy_scoped_agent_id(base: &AgentId, strategy_id: &str) -> AgentId {
    AgentId(format!("{}:{strategy_id}", base.0))
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
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::json!({
                "event_id": finding.event_id,
                "host_id": event.host_id,
                "source": event.source,
                "evidence": finding.evidence.clone(),
            }),
            threat_class: finding.threat_class.clone(),
            severity: finding.severity,
            confidence: finding.confidence,
            timestamp: event.timestamp,
            decay_half_life: pheromone.default_half_life_secs,
            agent_id: strategy_scoped_agent_id(agent_id, &finding.strategy_id),
            agent_identity: String::new(),
            agent_role: None,
            signature: Vec::new(),
            agent_key: Vec::new(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{evaluate_event, findings_to_deposits, strategy_scoped_agent_id};
    use crate::detector::{
        DetectionFinding, ProcessStartEvent, SuspiciousProcessTreeDetector, TelemetryEvent,
        TelemetryPayload,
    };
    use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig, ResponsePlaybookConfig};
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::{AgentId, Severity};

    fn pheromone_config() -> PheromoneConfig {
        PheromoneConfig {
            default_half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
            deescalation_cooldown_secs: 300,
            response_playbook: ResponsePlaybookConfig::default(),
            backend: PheromoneBackendConfig::InMemory,
        }
    }

    fn finding(strategy_id: &str, finding_id: &str) -> DetectionFinding {
        DetectionFinding {
            finding_id: finding_id.to_string(),
            event_id: "evt-1".to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::Critical,
            confidence: 0.9,
            evidence: serde_json::json!({"strategy_id": strategy_id}),
            strategy_id: strategy_id.to_string(),
        }
    }

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
            &pheromone_config(),
        );

        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].agent_id.0, "whisker-a:suspicious_process_tree");
        assert_eq!(
            deposits[0].indicator["host_id"],
            serde_json::json!("host-1")
        );
    }

    #[test]
    fn repeated_same_strategy_findings_share_one_scoped_agent_id() {
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
        let findings = vec![
            finding("suspicious_process_tree", "finding-1"),
            finding("suspicious_process_tree", "finding-2"),
        ];

        let deposits = findings_to_deposits(
            &findings,
            &event,
            &AgentId("whisker-a".to_string()),
            &pheromone_config(),
        );

        assert_eq!(deposits.len(), 2);
        assert_eq!(
            deposits[0].agent_id,
            AgentId("whisker-a:suspicious_process_tree".to_string())
        );
        assert_eq!(deposits[0].agent_id, deposits[1].agent_id);
    }

    #[test]
    fn different_strategies_produce_different_scoped_agent_ids() {
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
        let findings = vec![
            finding("suspicious_process_tree", "finding-1"),
            finding("dns_exfiltration", "finding-2"),
        ];

        let deposits = findings_to_deposits(
            &findings,
            &event,
            &AgentId("whisker-a".to_string()),
            &pheromone_config(),
        );

        assert_eq!(deposits.len(), 2);
        assert_ne!(deposits[0].agent_id, deposits[1].agent_id);
        assert_eq!(deposits[0].agent_id.0, "whisker-a:suspicious_process_tree");
        assert_eq!(deposits[1].agent_id.0, "whisker-a:dns_exfiltration");
    }

    #[test]
    fn helper_appends_strategy_suffix() {
        assert_eq!(
            strategy_scoped_agent_id(&AgentId("whisker-a".to_string()), "suspicious_process_tree"),
            AgentId("whisker-a:suspicious_process_tree".to_string())
        );
    }
}
