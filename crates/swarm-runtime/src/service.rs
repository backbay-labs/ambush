use crate::config::RuntimeSettings;
use crate::pipeline::{detect_and_deposit, DetectionPipelineOutcome, PipelineError};
use crate::{RuntimeError, RuntimeMode, SwarmRuntime};
use std::fs;
use std::path::Path;
use swarm_policy::ApprovalGate;
use swarm_policy::{ActionRequest, ApprovalContext};
use swarm_response::ResponseExecutor;
use swarm_spine::ReplayBundle;
use swarm_whisker::{DetectionFinding, DetectionStrategy, TelemetryEvent};
use swarm_pheromone::PheromoneSubstrate;
use swarm_core::config::PheromoneConfig;
use swarm_core::types::{AgentId, ResponseAction};

/// Errors raised by the runtime service wrapper.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error(transparent)]
    Pipeline(#[from] PipelineError),

    #[error(transparent)]
    Runtime(#[from] RuntimeError),

    #[error("failed to write replay bundle `{path}`: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read replay bundle `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to serialize replay bundle: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Inputs that stay constant while processing one event through the critical lane.
pub struct EventExecutionContext<'a> {
    pub agent_id: &'a AgentId,
    pub pheromone: &'a PheromoneConfig,
    pub approval: &'a ApprovalContext,
}

/// Thin service wrapper around the first Rust-only runtime slice.
pub struct RuntimeService<P, E> {
    pub config: RuntimeSettings,
    pub runtime: SwarmRuntime<P, E>,
}

impl<P, E> RuntimeService<P, E>
where
    P: ApprovalGate,
    E: ResponseExecutor,
{
    pub fn new(config: RuntimeSettings, runtime: SwarmRuntime<P, E>) -> Self {
        Self { config, runtime }
    }

    pub fn mode(&self) -> RuntimeMode {
        self.runtime.mode()
    }

    /// Run the full critical lane for one event and build a replay bundle.
    pub async fn process_event<D, S, F>(
        &self,
        detector: &D,
        substrate: &S,
        event: &TelemetryEvent,
        execution: EventExecutionContext<'_>,
        request_builder: F,
    ) -> Result<Option<ReplayBundle>, ServiceError>
    where
        D: DetectionStrategy,
        S: PheromoneSubstrate,
        F: Fn(&DetectionFinding) -> Option<ResponseAction>,
    {
        let DetectionPipelineOutcome {
            event,
            findings,
            deposits,
        } = detect_and_deposit(
            detector,
            substrate,
            event,
            execution.agent_id,
            execution.pheromone,
        )
        .await?;

        let Some(primary_finding) = findings.first().cloned() else {
            tracing::info!("no findings emitted for event");
            return Ok(None);
        };

        let Some(action) = request_builder(&primary_finding) else {
            tracing::info!(event_id = %primary_finding.event_id, "no action proposed for finding");
            return Ok(None);
        };

        let request = ActionRequest {
            hunt_id: swarm_core::types::HuntId(primary_finding.event_id.clone()),
            requested_by: execution.agent_id.clone(),
            action,
            severity: primary_finding.severity,
            evidence: primary_finding.evidence.clone(),
        };
        let audit = self
            .runtime
            .audit_authorize_and_execute(&primary_finding, &request, execution.approval)
            .await?;

        Ok(Some(ReplayBundle {
            bundle_id: format!(
                "bundle:{}:{}",
                request.hunt_id.0, execution.approval.now_ms
            ),
            event,
            findings,
            deposits,
            action_request: request,
            audit,
        }))
    }

    pub fn save_replay_bundle(
        &self,
        bundle: &ReplayBundle,
        path: impl AsRef<Path>,
    ) -> Result<(), ServiceError> {
        let path = path.as_ref();
        let serialized = serde_json::to_string_pretty(bundle)?;
        fs::write(path, serialized).map_err(|source| ServiceError::Write {
            path: path.display().to_string(),
            source,
        })
    }

    pub fn load_replay_bundle(&self, path: impl AsRef<Path>) -> Result<ReplayBundle, ServiceError> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(|source| ServiceError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Ok(serde_json::from_str(&raw)?)
    }
}

#[cfg(test)]
mod tests {
    use super::{EventExecutionContext, RuntimeService};
    use crate::{SwarmRuntime, RuntimeMode};
    use swarm_core::config::{PheromoneConfig, RuntimeSettings, TelemetrySourceConfig};
    use swarm_core::types::AgentId;
    use swarm_pheromone::InMemoryPheromoneSubstrate;
    use swarm_policy::static_gate::StaticApprovalGate;
    use swarm_policy::ApprovalContext;
    use swarm_response::adapters::SandboxExecutor;
    use swarm_response::ResponseStatus;
    use swarm_spine::AuditResponseRecord;
    use swarm_whisker::{
        ProcessStartEvent, SuspiciousProcessTreeDetector, TelemetryEvent, TelemetryPayload,
    };

    fn runtime_service() -> RuntimeService<StaticApprovalGate, SandboxExecutor> {
        RuntimeService::new(
            RuntimeSettings {
                mode: RuntimeMode::LiveResponse,
                telemetry_sources: vec![TelemetrySourceConfig {
                    name: "synthetic".to_string(),
                    subject: "telemetry.synthetic.process".to_string(),
                }],
                max_in_flight_actions: 4,
            },
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        )
    }

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
    async fn process_event_creates_and_replays_bundle() {
        let service = runtime_service();
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
        let context = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-1".to_string()],
            now_ms: 1_700_000_000_000,
        };
        let agent_id = AgentId("whisker-a".to_string());
        let pheromone = pheromone_config();

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    pheromone: &pheromone,
                    approval: &context,
                },
                |_finding| {
                    Some(swarm_core::types::ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        match &bundle.audit.response {
            AuditResponseRecord::Success(receipt) => {
                assert_eq!(receipt.status, ResponseStatus::Executed);
            }
            other => panic!("expected successful response record, got {other:?}"),
        }

        let path = std::env::temp_dir().join("swarm-runtime-replay-bundle.json");
        service.save_replay_bundle(&bundle, &path).unwrap();
        let replayed = service.load_replay_bundle(&path).unwrap();

        assert_eq!(replayed.audit.trail_id, bundle.audit.trail_id);
        assert_eq!(replayed.findings.len(), 1);
        let _ = std::fs::remove_file(path);
    }
}
