use crate::replay::{
    LoadedReplayScenario, ReplayHarnessError, ReplayScenarioClass, ReplayScenarioInput,
    load_replay_suite_manifest, load_scenario_manifest, resolve_manifest_relative_path,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;
use swarm_whisker::TelemetryEvent;

/// Runtime-owned context for deterministic adversarial corpus generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatContext {
    pub suite_path: PathBuf,
    pub requested_at_ms: i64,
    pub sequence_id: String,
    #[serde(default)]
    pub include_benign_controls: bool,
}

impl ThreatContext {
    pub fn new(
        suite_path: impl Into<PathBuf>,
        requested_at_ms: i64,
        sequence_id: impl Into<String>,
    ) -> Self {
        Self {
            suite_path: suite_path.into(),
            requested_at_ms,
            sequence_id: sequence_id.into(),
            include_benign_controls: false,
        }
    }
}

/// Materialized adversarial sequence artifact ready for later fitness scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversarialSequenceArtifact {
    pub sequence_id: String,
    pub suite_name: String,
    pub suite_path: String,
    pub corpus_version: String,
    pub generated_at_ms: i64,
    pub campaign: Option<String>,
    pub techniques: Vec<String>,
    pub tags: Vec<String>,
    pub scenario_names: Vec<String>,
    pub benign_control_scenarios: Vec<String>,
    pub events: Vec<TelemetryEvent>,
}

/// Errors surfaced by runtime-owned adversarial corpus generation.
#[derive(Debug, thiserror::Error)]
pub enum RedSwarmError {
    #[error(transparent)]
    Replay(#[from] ReplayHarnessError),

    #[error("invalid threat context field `{field}`: {reason}")]
    InvalidContext { field: &'static str, reason: String },

    #[error(
        "scenario `{scenario}` uses replay bundles; red-swarm corpus generation currently requires event-backed scenarios"
    )]
    UnsupportedScenarioInput { scenario: String },

    #[error("suite `{suite}` did not contain any matching scenarios for red-swarm generation")]
    NoMatchingScenarios { suite: String },
}

/// Deterministic seam for generating adversarial telemetry without the historical Python runtime.
#[async_trait]
pub trait RedSwarmAdapter: Send + Sync {
    async fn generate_adversarial_sequence(
        &self,
        context: &ThreatContext,
    ) -> Result<Vec<TelemetryEvent>, RedSwarmError>;
}

/// Default Rust-native adapter backed by tracked replay suite manifests.
#[derive(Debug, Clone, Default)]
pub struct SuiteRedSwarmAdapter;

impl SuiteRedSwarmAdapter {
    pub async fn generate_sequence_artifact(
        &self,
        context: &ThreatContext,
    ) -> Result<AdversarialSequenceArtifact, RedSwarmError> {
        validate_context(context)?;

        let suite_path = context.suite_path.clone();
        let suite = load_replay_suite_manifest(&suite_path)?;
        let mut selected_scenarios = Vec::new();
        let mut benign_control_scenarios = Vec::new();

        for scenario_ref in &suite.scenarios {
            let scenario_path = resolve_manifest_relative_path(&suite_path, scenario_ref);
            let loaded = load_scenario_manifest(&scenario_path)?;
            if matches!(loaded.manifest.metadata.class, ReplayScenarioClass::Benign)
                && !context.include_benign_controls
            {
                benign_control_scenarios.push(loaded.manifest.name.clone());
                continue;
            }
            selected_scenarios.push(loaded);
        }

        if selected_scenarios.is_empty() {
            return Err(RedSwarmError::NoMatchingScenarios {
                suite: suite.name.clone(),
            });
        }

        let min_timestamp = selected_scenarios
            .iter()
            .flat_map(scenario_event_timestamps)
            .min()
            .unwrap_or(context.requested_at_ms);

        let scenario_names = selected_scenarios
            .iter()
            .map(|scenario| scenario.manifest.name.clone())
            .collect::<Vec<_>>();

        let mut techniques = BTreeSet::new();
        techniques.extend(suite.metadata.techniques.iter().cloned());
        let mut tags = BTreeSet::new();
        tags.extend(suite.metadata.tags.iter().cloned());
        let campaign = suite.metadata.campaign.clone().or_else(|| {
            selected_scenarios
                .iter()
                .find_map(|scenario| scenario.manifest.metadata.campaign.clone())
        });

        let mut events = Vec::new();
        for scenario in &selected_scenarios {
            techniques.extend(scenario.manifest.metadata.techniques.iter().cloned());
            tags.extend(scenario.manifest.metadata.tags.iter().cloned());
            match &scenario.manifest.input {
                ReplayScenarioInput::Events { events: steps } => {
                    for step in steps {
                        events.push(parameterize_event(
                            &step.event,
                            context,
                            &scenario.manifest.name,
                            min_timestamp,
                        ));
                    }
                }
                ReplayScenarioInput::ReplayBundles { .. } => {
                    return Err(RedSwarmError::UnsupportedScenarioInput {
                        scenario: scenario.manifest.name.clone(),
                    });
                }
            }
        }
        events.sort_by(|left, right| {
            left.timestamp
                .cmp(&right.timestamp)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });

        Ok(AdversarialSequenceArtifact {
            sequence_id: sanitize_identifier(&context.sequence_id),
            suite_name: suite.name,
            suite_path: suite_path.display().to_string(),
            corpus_version: suite.corpus_version,
            generated_at_ms: context.requested_at_ms,
            campaign,
            techniques: techniques.into_iter().collect(),
            tags: tags.into_iter().collect(),
            scenario_names,
            benign_control_scenarios,
            events,
        })
    }
}

#[async_trait]
impl RedSwarmAdapter for SuiteRedSwarmAdapter {
    async fn generate_adversarial_sequence(
        &self,
        context: &ThreatContext,
    ) -> Result<Vec<TelemetryEvent>, RedSwarmError> {
        Ok(self.generate_sequence_artifact(context).await?.events)
    }
}

/// Deterministic test double for later fitness integration and episode logging.
#[derive(Debug, Clone, Default)]
pub struct MockRedSwarm {
    events: Vec<TelemetryEvent>,
}

impl MockRedSwarm {
    pub fn new(events: Vec<TelemetryEvent>) -> Self {
        Self { events }
    }
}

#[async_trait]
impl RedSwarmAdapter for MockRedSwarm {
    async fn generate_adversarial_sequence(
        &self,
        _context: &ThreatContext,
    ) -> Result<Vec<TelemetryEvent>, RedSwarmError> {
        Ok(self.events.clone())
    }
}

fn validate_context(context: &ThreatContext) -> Result<(), RedSwarmError> {
    if context.requested_at_ms <= 0 {
        return Err(RedSwarmError::InvalidContext {
            field: "requested_at_ms",
            reason: "must be greater than zero".to_string(),
        });
    }
    if context.sequence_id.trim().is_empty() {
        return Err(RedSwarmError::InvalidContext {
            field: "sequence_id",
            reason: "must not be empty".to_string(),
        });
    }
    Ok(())
}

fn scenario_event_timestamps(scenario: &LoadedReplayScenario) -> Vec<i64> {
    match &scenario.manifest.input {
        ReplayScenarioInput::Events { events } => {
            events.iter().map(|step| step.event.timestamp).collect()
        }
        ReplayScenarioInput::ReplayBundles { .. } => Vec::new(),
    }
}

fn parameterize_event(
    event: &TelemetryEvent,
    context: &ThreatContext,
    scenario_name: &str,
    min_timestamp: i64,
) -> TelemetryEvent {
    let mut parameterized = event.clone();
    let offset = event.timestamp.saturating_sub(min_timestamp);
    parameterized.timestamp = context.requested_at_ms.saturating_add(offset);
    parameterized.event_id = format!(
        "{}:{}:{}",
        sanitize_identifier(&context.sequence_id),
        sanitize_identifier(scenario_name),
        event.event_id
    );
    parameterized.source = format!(
        "red_swarm::{}::{}",
        sanitize_identifier(&context.sequence_id),
        sanitize_identifier(&event.source)
    );
    parameterized
}

fn sanitize_identifier(raw: &str) -> String {
    let mut sanitized = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_lowercase());
        } else {
            sanitized.push('_');
        }
    }
    while sanitized.contains("__") {
        sanitized = sanitized.replace("__", "_");
    }
    sanitized.trim_matches('_').to_string()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{MockRedSwarm, RedSwarmAdapter, SuiteRedSwarmAdapter, ThreatContext};
    use std::path::PathBuf;
    use swarm_whisker::{ProcessStartEvent, TelemetryEvent, TelemetryPayload};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn suite_path() -> PathBuf {
        repo_root().join("scenario-suites/hellcat-office-v1.yaml")
    }

    fn event_fingerprint(events: &[TelemetryEvent]) -> Vec<(String, i64, Option<String>, String)> {
        events
            .iter()
            .map(|event| {
                (
                    event.event_id.clone(),
                    event.timestamp,
                    event.host_id.clone(),
                    serde_json::to_string(&event.payload).expect("payload should encode"),
                )
            })
            .collect()
    }

    fn mock_event(event_id: &str, timestamp: i64) -> TelemetryEvent {
        TelemetryEvent {
            source: "mock".to_string(),
            event_id: event_id.to_string(),
            timestamp,
            host_id: Some("host-mock".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "WINWORD".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc AAA=".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    #[tokio::test]
    async fn suite_red_swarm_adapter_materializes_deterministic_hellcat_sequence() {
        let adapter = SuiteRedSwarmAdapter;
        let context = ThreatContext::new(suite_path(), 1_900_000_000_000, "Gen 7");

        let artifact = adapter
            .generate_sequence_artifact(&context)
            .await
            .expect("suite-backed generation should succeed");
        let generated = adapter
            .generate_adversarial_sequence(&context)
            .await
            .expect("trait generation should succeed");

        assert_eq!(artifact.suite_name, "hellcat_office_v1");
        assert_eq!(artifact.corpus_version, "2026-04-03");
        assert_eq!(
            artifact.scenario_names,
            vec![
                "office_dropper_correlation".to_string(),
                "pdf_lolbin_execution".to_string(),
            ]
        );
        assert_eq!(
            artifact.benign_control_scenarios,
            vec![
                "benign_baseline".to_string(),
                "python_maintenance_benign".to_string(),
            ]
        );
        assert_eq!(artifact.events.len(), 3);
        assert_eq!(artifact.events[0].timestamp, 1_900_000_000_000);
        assert_eq!(artifact.events[1].timestamp, 1_900_000_001_000);
        assert_eq!(artifact.events[2].timestamp, 1_900_000_003_000);
        assert_eq!(
            artifact.events[0].event_id,
            "gen_7:office_dropper_correlation:hunt-evt-1"
        );
        assert_eq!(
            artifact.events[2].event_id,
            "gen_7:pdf_lolbin_execution:hunt-pdf-1"
        );
        assert_eq!(
            event_fingerprint(&artifact.events),
            event_fingerprint(&generated)
        );
        assert!(artifact.techniques.contains(&"T1204.002".to_string()));
        assert!(artifact.techniques.contains(&"T1059.001".to_string()));
        assert!(artifact.tags.contains(&"office".to_string()));
        assert_eq!(artifact.campaign.as_deref(), Some("hellcat.office_loader"));
    }

    #[tokio::test]
    async fn mock_red_swarm_returns_static_deterministic_sequence() {
        let expected = vec![mock_event("mock-evt-1", 1_900_000_100_000)];
        let adapter = MockRedSwarm::new(expected.clone());
        let context = ThreatContext::new(PathBuf::from("scenario-suites/mock.yaml"), 1, "mock");

        let generated = adapter
            .generate_adversarial_sequence(&context)
            .await
            .expect("mock generation should succeed");

        assert_eq!(event_fingerprint(&generated), event_fingerprint(&expected));
    }
}
