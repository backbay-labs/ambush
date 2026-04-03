use swarm_core::config::PheromoneConfig;
use swarm_core::pheromone::PheromoneDeposit;
use swarm_core::types::AgentId;
use swarm_pheromone::{PheromoneSubstrate, SubstrateError};
use swarm_whisker::stream::{evaluate_event, findings_to_deposits};
use swarm_whisker::{DetectionFinding, DetectionStrategy, TelemetryEvent};

/// Output of the fast detection lane for a single event.
#[derive(Debug, Clone)]
pub struct DetectionPipelineOutcome {
    pub event: TelemetryEvent,
    pub findings: Vec<DetectionFinding>,
    pub deposits: Vec<PheromoneDeposit>,
}

/// Errors raised while executing the fast detection lane.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error(transparent)]
    Substrate(#[from] SubstrateError),
}

/// Evaluate one telemetry event and persist any resulting pheromone deposits.
pub async fn detect_and_deposit<D, S>(
    detector: &D,
    substrate: &S,
    event: &TelemetryEvent,
    agent_id: &AgentId,
    pheromone: &PheromoneConfig,
) -> Result<DetectionPipelineOutcome, PipelineError>
where
    D: DetectionStrategy,
    S: PheromoneSubstrate,
{
    let findings = evaluate_event(detector, event);
    let deposits = findings_to_deposits(&findings, event, agent_id, pheromone);

    for deposit in &deposits {
        substrate.deposit(deposit.clone()).await?;
    }

    Ok(DetectionPipelineOutcome {
        event: event.clone(),
        findings,
        deposits,
    })
}

#[cfg(test)]
mod tests {
    use super::detect_and_deposit;
    use swarm_core::config::PheromoneConfig;
    use swarm_core::types::AgentId;
    use swarm_pheromone::{InMemoryPheromoneSubstrate, PheromoneSubstrate};
    use swarm_whisker::{
        ProcessStartEvent, SuspiciousProcessTreeDetector, TelemetryEvent, TelemetryPayload,
    };

    fn pheromone_config() -> PheromoneConfig {
        PheromoneConfig {
            default_half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
        }
    }

    #[tokio::test]
    async fn detector_findings_are_deposited_into_substrate() {
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(pheromone_config());
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
            }),
        };

        let outcome = detect_and_deposit(
            &detector,
            &substrate,
            &event,
            &AgentId("whisker-a".to_string()),
            &pheromone_config(),
        )
        .await
        .unwrap();

        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.deposits.len(), 1);
        assert_eq!(substrate.recent_deposits(1).await.unwrap().len(), 1);
    }
}
