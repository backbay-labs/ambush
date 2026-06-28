use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::evolution_status::EvolutionStatusReport;
use serde::{Deserialize, Serialize};
use swarm_core::agent::{AgentHealth, AgentRole, SwarmMode};
use swarm_core::pheromone::{PheromoneConcentration, ThreatClass};
use swarm_policy::PolicyVerdict;
use swarm_response::SwarmFindingEnvelope;
use swarm_spine::IncidentGraphDimension;
use tokio::sync::broadcast;

pub const DEFAULT_RUNTIME_EVENT_CAPACITY: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsyncLaneStatusLevel {
    Disabled,
    Ok,
    Degraded,
}

impl AsyncLaneStatusLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Ok => "ok",
            Self::Degraded => "degraded",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AsyncLaneStatusSnapshot {
    pub enabled: bool,
    pub investigation_enabled: bool,
    pub correlation_enabled: bool,
    pub status: AsyncLaneStatusLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub investigation_strategy: Option<String>,
    pub investigation_store_ready: bool,
    pub incident_store_ready: bool,
    pub queued_jobs: usize,
    pub running_jobs: usize,
    pub queue_budget_remaining: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_priority_score_basis_points: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_job_age_ms: Option<u64>,
    pub completed_jobs: u64,
    pub failed_jobs: u64,
    pub timed_out_jobs: u64,
    pub budget_evictions: u64,
    pub starvation_preventions: u64,
    pub recent_investigations: usize,
    pub ambiguous_recent_investigations: usize,
    pub recent_incidents: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_investigation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_incident_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_incident_confidence_score: Option<f64>,
    #[serde(default)]
    pub latest_incident_graph_dimensions: Vec<IncidentGraphDimension>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure_reason: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl AsyncLaneStatusSnapshot {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            investigation_enabled: false,
            correlation_enabled: false,
            status: AsyncLaneStatusLevel::Disabled,
            investigation_strategy: None,
            investigation_store_ready: true,
            incident_store_ready: true,
            queued_jobs: 0,
            running_jobs: 0,
            queue_budget_remaining: 0,
            highest_priority_score_basis_points: None,
            oldest_job_age_ms: None,
            completed_jobs: 0,
            failed_jobs: 0,
            timed_out_jobs: 0,
            budget_evictions: 0,
            starvation_preventions: 0,
            recent_investigations: 0,
            ambiguous_recent_investigations: 0,
            recent_incidents: 0,
            latest_investigation_id: None,
            latest_incident_id: None,
            latest_incident_confidence_score: None,
            latest_incident_graph_dimensions: Vec::new(),
            last_failure_reason: None,
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeEventBroadcaster {
    tx: broadcast::Sender<RuntimeEvent>,
}

impl RuntimeEventBroadcaster {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn publish(&self, event: RuntimeEvent) {
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RuntimeEvent> {
        self.tx.subscribe()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEventKind {
    Ingest,
    Finding,
    Replay,
    AgentAction,
    TamperAlert,
    EvolutionStatus,
    ResponseExecution,
    AgentHealth,
    ConcentrationSnapshot,
    Escalation,
    ModeTransition,
}

impl RuntimeEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ingest => "ingest",
            Self::Finding => "finding",
            Self::Replay => "replay",
            Self::AgentAction => "agent_action",
            Self::TamperAlert => "tamper_alert",
            Self::EvolutionStatus => "evolution_status",
            Self::ResponseExecution => "response_execution",
            Self::AgentHealth => "agent_health",
            Self::ConcentrationSnapshot => "concentration_snapshot",
            Self::Escalation => "escalation",
            Self::ModeTransition => "mode_transition",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "ingest" => Some(Self::Ingest),
            "finding" => Some(Self::Finding),
            "replay" => Some(Self::Replay),
            "agent_action" => Some(Self::AgentAction),
            "tamper_alert" => Some(Self::TamperAlert),
            "evolution_status" => Some(Self::EvolutionStatus),
            "response_execution" => Some(Self::ResponseExecution),
            "agent_health" => Some(Self::AgentHealth),
            "concentration_snapshot" => Some(Self::ConcentrationSnapshot),
            "escalation" => Some(Self::Escalation),
            "mode_transition" => Some(Self::ModeTransition),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayEventPhase {
    Started,
    Step,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationLevel {
    Alert,
    Incident,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeThreatConcentration {
    pub threat_class: ThreatClass,
    pub total_strength: f64,
    pub distinct_sources: usize,
    pub peak_confidence: f64,
}

impl From<&PheromoneConcentration> for RuntimeThreatConcentration {
    fn from(value: &PheromoneConcentration) -> Self {
        Self {
            threat_class: value.threat_class.clone(),
            total_strength: value.total_strength,
            distinct_sources: value.distinct_sources,
            peak_confidence: value.peak_confidence,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum RuntimeEvent {
    Ingest {
        emitted_at_ms: i64,
        correlation_id: String,
        event_id: String,
        source: String,
        host_id: Option<String>,
        accepted: bool,
        reason: Option<String>,
    },
    Finding {
        emitted_at_ms: i64,
        host_id: Option<String>,
        finding: SwarmFindingEnvelope,
    },
    Replay {
        emitted_at_ms: i64,
        run_id: String,
        scenario_name: String,
        scenario_path: String,
        requested_by: String,
        phase: ReplayEventPhase,
        pace_ms: u64,
        total_steps: usize,
        step_index: Option<usize>,
        event_id: Option<String>,
        reason: Option<String>,
    },
    AgentAction {
        emitted_at_ms: i64,
        agent_id: String,
        role: AgentRole,
        action_kind: String,
        hunt_id: Option<String>,
        details: serde_json::Value,
    },
    TamperAlert {
        emitted_at_ms: i64,
        debugger_attached: bool,
        tracer_pid: Option<u32>,
        unexpected_library_loads: Vec<String>,
        fail_closed: bool,
        details: String,
    },
    EvolutionStatus {
        emitted_at_ms: i64,
        source: String,
        status: EvolutionStatusReport,
    },
    ResponseExecution {
        emitted_at_ms: i64,
        agent_id: String,
        hunt_id: String,
        action_kind: String,
        response_kind: String,
        policy_verdict: PolicyVerdict,
        rule_name: String,
        reason: String,
        receipt_id: Option<String>,
        governing_agent_id: Option<String>,
        error: Option<String>,
    },
    AgentHealth {
        emitted_at_ms: i64,
        agent_id: String,
        role: AgentRole,
        from: Option<AgentHealth>,
        to: AgentHealth,
    },
    ConcentrationSnapshot {
        emitted_at_ms: i64,
        current_mode: SwarmMode,
        concentrations: Vec<RuntimeThreatConcentration>,
    },
    Escalation {
        emitted_at_ms: i64,
        threat_class: ThreatClass,
        level: EscalationLevel,
        total_strength: f64,
        distinct_sources: usize,
        peak_confidence: f64,
        mode_changed: bool,
        current_mode: SwarmMode,
    },
    ModeTransition {
        emitted_at_ms: i64,
        from: SwarmMode,
        to: SwarmMode,
        triggering_threat_class: Option<ThreatClass>,
        reason: String,
    },
}

impl RuntimeEvent {
    pub fn emitted_at_ms(&self) -> i64 {
        match self {
            Self::Ingest { emitted_at_ms, .. }
            | Self::Finding { emitted_at_ms, .. }
            | Self::Replay { emitted_at_ms, .. }
            | Self::AgentAction { emitted_at_ms, .. }
            | Self::TamperAlert { emitted_at_ms, .. }
            | Self::EvolutionStatus { emitted_at_ms, .. }
            | Self::ResponseExecution { emitted_at_ms, .. }
            | Self::AgentHealth { emitted_at_ms, .. }
            | Self::ConcentrationSnapshot { emitted_at_ms, .. }
            | Self::Escalation { emitted_at_ms, .. }
            | Self::ModeTransition { emitted_at_ms, .. } => *emitted_at_ms,
        }
    }

    pub fn kind(&self) -> RuntimeEventKind {
        match self {
            Self::Ingest { .. } => RuntimeEventKind::Ingest,
            Self::Finding { .. } => RuntimeEventKind::Finding,
            Self::Replay { .. } => RuntimeEventKind::Replay,
            Self::AgentAction { .. } => RuntimeEventKind::AgentAction,
            Self::TamperAlert { .. } => RuntimeEventKind::TamperAlert,
            Self::EvolutionStatus { .. } => RuntimeEventKind::EvolutionStatus,
            Self::ResponseExecution { .. } => RuntimeEventKind::ResponseExecution,
            Self::AgentHealth { .. } => RuntimeEventKind::AgentHealth,
            Self::ConcentrationSnapshot { .. } => RuntimeEventKind::ConcentrationSnapshot,
            Self::Escalation { .. } => RuntimeEventKind::Escalation,
            Self::ModeTransition { .. } => RuntimeEventKind::ModeTransition,
        }
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

pub fn parse_runtime_event_filter(
    raw: Option<&str>,
) -> Result<Option<HashSet<RuntimeEventKind>>, String> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    let mut kinds = HashSet::new();
    for value in raw.split(',') {
        let Some(kind) = RuntimeEventKind::parse(value) else {
            return Err(format!("unknown runtime event type `{}`", value.trim()));
        };
        kinds.insert(kind);
    }

    Ok(Some(kinds))
}

#[cfg(test)]
mod tests {
    use super::{RuntimeEventKind, parse_runtime_event_filter};

    #[test]
    fn runtime_event_filter_parses_comma_separated_kinds() {
        let filter = parse_runtime_event_filter(Some(
            "agent_action,response_execution,concentration_snapshot,finding",
        ))
        .unwrap()
        .unwrap();

        assert!(filter.contains(&RuntimeEventKind::AgentAction));
        assert!(filter.contains(&RuntimeEventKind::ResponseExecution));
        assert!(filter.contains(&RuntimeEventKind::ConcentrationSnapshot));
        assert!(filter.contains(&RuntimeEventKind::Finding));
    }

    #[test]
    fn runtime_event_filter_rejects_unknown_kind() {
        let error = parse_runtime_event_filter(Some("mystery")).unwrap_err();
        assert!(error.contains("unknown runtime event type"));
    }

    #[test]
    fn runtime_event_filter_parses_evolution_status() {
        let filter = parse_runtime_event_filter(Some("evolution_status"))
            .unwrap()
            .unwrap();
        assert!(filter.contains(&RuntimeEventKind::EvolutionStatus));
    }
}
