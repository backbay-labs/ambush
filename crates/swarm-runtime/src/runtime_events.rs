use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::evolution_status::EvolutionStatusReport;
use serde::{Deserialize, Serialize};
use swarm_core::agent::{AgentHealth, AgentRole, SwarmMode};
use swarm_core::pheromone::{PheromoneConcentration, ThreatClass};
use swarm_core::types::Severity;
use swarm_policy::PolicyVerdict;
use swarm_policy::governance::PartitionState;
use swarm_response::SwarmFindingEnvelope;
use swarm_response::rollback::{RollbackReceipt, RollbackTrigger};
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
    /// A finding was promoted to a case (12-PLAN-FIRST-CARD.md Task 11, B1d).
    CasePromoted,
    /// A destructive action was held for a human decision (13-PLAN-THE-HOLD.md, B1).
    ResponseHeld,
    /// A containment lease was released and its rollback ran (B1c).
    ContainmentReleased,
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
            Self::CasePromoted => "case_promoted",
            Self::ResponseHeld => "response_held",
            Self::ContainmentReleased => "containment_released",
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
            "case_promoted" => Some(Self::CasePromoted),
            "response_held" => Some(Self::ResponseHeld),
            "containment_released" => Some(Self::ContainmentReleased),
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

/// Which ADR 0018 promotion clause turned a finding into a case.
///
/// Only `Manual` — the operator's `E` key through `POST /v1/operator/incidents`
/// — is produced by the first build; the other two are the clauses the hold
/// path and the correlation engine raise once they promote (00-DECISIONS W3-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CasePromotionClause {
    /// A response was held for a human decision; the hold is itself a promotion.
    HeldAction,
    /// The correlation engine assembled a multi-finding incident.
    CorrelatedIncident,
    /// An operator promoted the finding explicitly.
    Manual,
}

impl CasePromotionClause {
    /// The snake_case name the wire and the logs use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeldAction => "held_action",
            Self::CorrelatedIncident => "correlated_incident",
            Self::Manual => "manual",
        }
    }
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
    /// A finding became a case. Published AFTER the incident record commits, so
    /// the bridge creates the case channel — whose UUID is `case_id`, minted by
    /// the daemon (00-DECISIONS W3-14) — for a record that already exists.
    CasePromoted {
        /// When the promotion was recorded (unix ms).
        emitted_at_ms: i64,
        /// The hunt the promoted finding belongs to.
        hunt_id: String,
        /// The case channel UUID the daemon minted.
        case_id: String,
        /// Which promotion clause fired.
        clause: CasePromotionClause,
        /// `incident:perch-case:{case_id}` — the incident record's id.
        incident_id: String,
        /// The finding that was promoted.
        finding_id: String,
        /// The finding's threat class.
        threat_class: ThreatClass,
        /// The finding's severity.
        severity: Severity,
        /// The one-line summary the case channel is named after.
        summary: String,
    },
    /// A destructive action held for a human (bill item B1). Seven fields and
    /// no more: the bridge maps this onto the community-global `26006` frame
    /// and drops `hunt_id`, which is a join key into detection data.
    ResponseHeld {
        /// When the transition was published (unix ms).
        emitted_at_ms: i64,
        /// The hold's opaque id.
        hold_id: String,
        /// The hunt the held action belongs to. Daemon-side consumers only.
        hunt_id: String,
        /// `ResponseAction::kind()` for the held action.
        action_kind: String,
        /// The severity the requesting agent claimed.
        severity: Severity,
        /// When the hold stops being decidable (unix ms).
        expires_at_ms: i64,
        /// The state this event announces.
        state: crate::held_action::HoldState,
    },
    /// B1c. A containment lease was released and its rollback ran.
    ///
    /// Every field the console needs to say what actually happened, because a
    /// release that CLAIMS to have undone something is exactly the claim an
    /// operator cannot take on trust. `lease_closed` is re-listed after the
    /// release rather than assumed from a successful call, and a failed
    /// attestation is carried as a reason rather than swallowed.
    ContainmentReleased {
        /// When the release was published (unix ms).
        emitted_at_ms: i64,
        /// The lease that was released.
        lease_id: String,
        /// Whether a human asked or the lease simply expired.
        trigger: RollbackTrigger,
        /// The rollback's own record: its steps, status and summary.
        receipt: RollbackReceipt,
        /// Re-listed after the release. Never inferred from the call returning.
        lease_closed: bool,
        /// Whether the governance attestation on the receipt verified.
        attestation_verified: bool,
        /// Why it did not, when it did not.
        attestation_error: Option<String>,
        /// The partition the daemon was in when the rollback ran.
        partition_state_at_execution: Option<PartitionState>,
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
            | Self::ModeTransition { emitted_at_ms, .. }
            | Self::CasePromoted { emitted_at_ms, .. }
            | Self::ResponseHeld { emitted_at_ms, .. }
            | Self::ContainmentReleased { emitted_at_ms, .. } => *emitted_at_ms,
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
            Self::CasePromoted { .. } => RuntimeEventKind::CasePromoted,
            Self::ResponseHeld { .. } => RuntimeEventKind::ResponseHeld,
            Self::ContainmentReleased { .. } => RuntimeEventKind::ContainmentReleased,
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{CasePromotionClause, RuntimeEvent, RuntimeEventKind, parse_runtime_event_filter};
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::Severity;

    #[test]
    fn case_promoted_round_trips_and_is_the_twelfth_kind() {
        let event = RuntimeEvent::CasePromoted {
            emitted_at_ms: 7,
            hunt_id: "hunt-1".into(),
            case_id: "9499a6e2-8872-453b-80d9-dafc6fc7fc69".into(),
            clause: CasePromotionClause::Manual,
            incident_id: "incident:perch-case:9499a6e2-8872-453b-80d9-dafc6fc7fc69".into(),
            finding_id: "f-1".into(),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            summary: "promoted".into(),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["event_type"], "case_promoted");
        assert_eq!(json["clause"], "manual");
        assert_eq!(json["threat_class"], "execution");
        assert_eq!(json["severity"], "HIGH");
        assert_eq!(event.kind(), RuntimeEventKind::CasePromoted);
        assert_eq!(event.emitted_at_ms(), 7);
        assert_eq!(
            RuntimeEventKind::parse("case_promoted"),
            Some(RuntimeEventKind::CasePromoted)
        );
        assert_eq!(RuntimeEventKind::CasePromoted.as_str(), "case_promoted");
        let back: RuntimeEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back.kind(), RuntimeEventKind::CasePromoted);
        for (clause, name) in [
            (CasePromotionClause::HeldAction, "held_action"),
            (
                CasePromotionClause::CorrelatedIncident,
                "correlated_incident",
            ),
            (CasePromotionClause::Manual, "manual"),
        ] {
            assert_eq!(clause.as_str(), name);
            assert_eq!(serde_json::to_value(clause).unwrap(), name);
        }
    }

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

    #[test]
    fn response_held_round_trips_through_kind_parse_and_serde() {
        assert_eq!(
            RuntimeEventKind::parse("response_held"),
            Some(RuntimeEventKind::ResponseHeld)
        );
        assert_eq!(RuntimeEventKind::ResponseHeld.as_str(), "response_held");
        let event = RuntimeEvent::ResponseHeld {
            emitted_at_ms: 1_773_739_200_000,
            hold_id: "hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13".to_string(),
            hunt_id: "hunt-evt-1".to_string(),
            action_kind: "isolate_host".to_string(),
            severity: Severity::Critical,
            expires_at_ms: 1_773_742_800_000,
            state: crate::held_action::HoldState::Created,
        };
        assert_eq!(event.kind(), RuntimeEventKind::ResponseHeld);
        assert_eq!(event.emitted_at_ms(), 1_773_739_200_000);
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["event_type"], "response_held");
        assert_eq!(value["state"], "created");
        assert_eq!(
            value.as_object().unwrap().len(),
            8,
            "seven fields plus the tag, and no more"
        );
        let back: RuntimeEvent = serde_json::from_value(value).unwrap();
        assert_eq!(back.kind(), RuntimeEventKind::ResponseHeld);
    }

    #[test]
    fn response_held_is_the_thirteenth_kind_and_every_kind_round_trips_its_name() {
        let kinds = [
            RuntimeEventKind::Ingest,
            RuntimeEventKind::Finding,
            RuntimeEventKind::Replay,
            RuntimeEventKind::AgentAction,
            RuntimeEventKind::TamperAlert,
            RuntimeEventKind::EvolutionStatus,
            RuntimeEventKind::ResponseExecution,
            RuntimeEventKind::AgentHealth,
            RuntimeEventKind::ConcentrationSnapshot,
            RuntimeEventKind::Escalation,
            RuntimeEventKind::ModeTransition,
            RuntimeEventKind::CasePromoted,
            RuntimeEventKind::ResponseHeld,
        ];
        assert_eq!(kinds.len(), 13);
        for kind in kinds {
            assert_eq!(RuntimeEventKind::parse(kind.as_str()), Some(kind));
        }
    }

    /// The wire spelling is the filter grammar. A variant whose `event_type`
    /// and whose `parse` disagree is a stream nobody can subscribe to.
    #[test]
    fn containment_released_kind_round_trips_through_the_filter_grammar() {
        assert_eq!(
            RuntimeEventKind::ContainmentReleased.as_str(),
            "containment_released"
        );
        assert_eq!(
            RuntimeEventKind::parse("containment_released"),
            Some(RuntimeEventKind::ContainmentReleased)
        );
        let receipt = swarm_response::rollback::RollbackReceipt {
            rollback_id: "rb_test".into(),
            lease_id: "cl_test".into(),
            origin_receipt_id: "resp_test".into(),
            governance_receipt_id: None,
            trigger: swarm_response::rollback::RollbackTrigger::Expiry,
            mode: swarm_response::ExecutionMode::Enforced,
            status: swarm_response::ResponseStatus::Executed,
            steps: Vec::new(),
            completed_at_ms: 7,
            summary: "0 of 0 steps reversed".into(),
            governance_attestation: None,
        };
        let event = RuntimeEvent::ContainmentReleased {
            emitted_at_ms: 7,
            lease_id: "cl_test".into(),
            trigger: swarm_response::rollback::RollbackTrigger::Expiry,
            receipt,
            lease_closed: true,
            attestation_verified: false,
            attestation_error: Some("unattested".into()),
            partition_state_at_execution: Some(swarm_policy::governance::PartitionState::Healthy),
        };
        assert_eq!(event.emitted_at_ms(), 7);
        assert_eq!(event.kind(), RuntimeEventKind::ContainmentReleased);
        let json = serde_json::to_value(&event).expect("the event serialises");
        assert_eq!(json["event_type"], "containment_released");
        assert_eq!(json["trigger"], "expiry");
        assert_eq!(json["partition_state_at_execution"], "healthy");
    }
}
