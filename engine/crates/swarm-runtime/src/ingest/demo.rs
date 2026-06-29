use crate::approval::{
    ApprovalError, ApprovalReceiptPackReport, ApprovalVerdictStatus, verify_receipt_pack,
};
use crate::providence::ProvidenceContextScope;
use crate::replay::{
    ReplayHarnessError, ReplayScenarioInput, ReplayScenarioStep, load_scenario_manifest,
};
use crate::runtime_events::{ReplayEventPhase, RuntimeEvent, now_ms, parse_runtime_event_filter};
use axum::extract::{Json, Query, State, rejection::JsonRejection};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Json as ResponseJson;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::time::Duration;
use swarm_core::ThreatClass;
use swarm_core::agent::SwarmModeState;
use swarm_core::config::RuntimeMode;
use swarm_core::pheromone::EscalationRecord;
use swarm_core::types::{AgentId, ResponseAction};
use swarm_crypto::Ed25519Signer;
use swarm_crypto::{MerkleProof, MerkleTree, canonical_json_bytes};
use swarm_pheromone::PheromoneSubstrate;
use swarm_policy::{ActionRequest, ApprovalContext};
use swarm_spine::{AuditTrail, CorrelatedIncident};
use swarm_whisker::{DetectionFinding, TelemetryEvent};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use super::IngestState;
use crate::escalation::standard_threat_classes;
use crate::runtime_events::RuntimeThreatConcentration;
use swarm_core::agent::AgentHealthEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoTimelineEntry {
    pub occurred_at_ms: i64,
    pub stage: String,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DemoApprovalDecisionRecord {
    pub(super) approval_set_id: String,
    pub(super) approval_ledger_id: String,
    pub(super) step_index: usize,
    pub(super) action_kind: String,
    pub(super) initial_audit: AuditTrail,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) receipt_pack: Option<ApprovalReceiptPackReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) resumed_audit: Option<AuditTrail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DemoRunState {
    pub(super) run_id: String,
    pub(super) scenario_name: String,
    pub(super) scenario_path: String,
    pub(super) requested_by: String,
    pub(super) pace_ms: u64,
    pub(super) total_steps: usize,
    pub(super) created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) completed_at_ms: Option<i64>,
    pub(super) timeline: Vec<DemoTimelineEntry>,
    pub(super) approvals: Vec<DemoApprovalDecisionRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) final_incident: Option<CorrelatedIncident>,
}

#[derive(Debug, Clone)]
pub(super) struct PendingDemoApproval {
    pub(super) run_id: String,
    pub(super) approval_set_id: String,
    pub(super) approval_ledger_id: String,
    pub(super) request: ActionRequest,
    pub(super) detection: DetectionFinding,
}

#[derive(Debug, Default)]
pub(super) struct DemoRunRegistry {
    pub(super) runs: BTreeMap<String, DemoRunState>,
    pub(super) pending_approvals: BTreeMap<String, PendingDemoApproval>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemoReplayRequest {
    pub scenario_path: String,
    #[serde(default)]
    pub pace_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemoReplayResponse {
    pub run_id: String,
    pub scenario_name: String,
    pub scenario_path: String,
    pub requested_by: String,
    pub pace_ms: u64,
    pub injected_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemoApprovalResumeRequest {
    pub receipt_pack: ApprovalReceiptPackReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemoApprovalResumeResponse {
    pub approval_set_id: String,
    pub receipt_pack_id: String,
    pub response_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_receipt_id: Option<String>,
    pub audit: AuditTrail,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemoProofQuery {
    pub run_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoProofLeaf {
    pub label: String,
    pub payload: Value,
    pub proof: MerkleProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoProofPackage {
    pub run_id: String,
    pub scenario_name: String,
    pub scenario_path: String,
    pub requested_by: String,
    pub created_at_ms: i64,
    pub completed_at_ms: i64,
    pub signed_receipts: Vec<ApprovalReceiptPackReport>,
    pub final_incident: CorrelatedIncident,
    pub decision_timeline: Vec<DemoTimelineEntry>,
    pub merkle_root: String,
    pub merkle_leaves: Vec<DemoProofLeaf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoRunApprovalReport {
    pub approval_set_id: String,
    pub approval_ledger_id: String,
    pub step_index: usize,
    pub action_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_pack_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoRunReport {
    pub run_id: String,
    pub scenario_name: String,
    pub scenario_path: String,
    pub requested_by: String,
    pub pace_ms: u64,
    pub total_steps: usize,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at_ms: Option<i64>,
    pub timeline: Vec<DemoTimelineEntry>,
    pub approvals: Vec<DemoRunApprovalReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_incident: Option<CorrelatedIncident>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirstRunWizardStatus {
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirstRunWizardStep {
    pub name: String,
    pub status: String,
    pub details: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FirstRunWizardArtifacts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_set_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_ledger_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_pack_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_merkle_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstRunWizardRequest {
    #[serde(default)]
    pub scenario_path: Option<String>,
    #[serde(default)]
    pub pace_ms: u64,
    pub voter_signing_key_env: String,
    pub evidence_signer_id: String,
    pub evidence_signing_key_env: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirstRunWizardReport {
    pub status: FirstRunWizardStatus,
    pub scenario_name: String,
    pub scenario_path: String,
    pub requested_by: String,
    pub run_id: String,
    pub injected_events: usize,
    pub steps: Vec<FirstRunWizardStep>,
    pub artifacts: FirstRunWizardArtifacts,
    pub run: DemoRunReport,
    pub proof: DemoProofPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemoDashboardSnapshot {
    pub captured_at_ms: i64,
    pub mode_state: SwarmModeState,
    pub agent_health: Vec<AgentHealthEntry>,
    pub concentrations: Vec<RuntimeThreatConcentration>,
    pub recent_escalations: Vec<EscalationRecord>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DemoScopeQuery {
    #[serde(default)]
    pub(super) context_token: Option<String>,
    #[serde(default)]
    pub(super) incident_id: Option<String>,
    #[serde(default)]
    pub(super) hunt_id: Option<String>,
    #[serde(default)]
    pub(super) finding_id: Option<String>,
    #[serde(default)]
    pub(super) strategy_id: Option<String>,
    #[serde(default)]
    pub(super) threat_class: Option<ThreatClass>,
}

impl DemoScopeQuery {
    pub(super) fn raw_scope(&self) -> ProvidenceContextScope {
        ProvidenceContextScope {
            incident_id: self.incident_id.clone(),
            hunt_id: self.hunt_id.clone(),
            finding_id: self.finding_id.clone(),
            strategy_id: self.strategy_id.clone(),
            threat_class: self.threat_class.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DemoDashboardQuery {
    #[serde(flatten)]
    pub(super) scope: DemoScopeQuery,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DemoWidgetQuery {
    #[serde(flatten)]
    pub(super) scope: DemoScopeQuery,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeEventStreamQuery {
    #[serde(default)]
    pub(super) types: Option<String>,
    #[serde(flatten)]
    pub(super) scope: DemoScopeQuery,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct DemoReplayErrorBody {
    pub(super) error: String,
}

#[derive(Debug, thiserror::Error)]
pub enum FirstRunWizardError {
    #[error("demo mode is disabled for the first-run wizard")]
    DemoModeDisabled,

    #[error("approval harness is not configured for the first-run wizard")]
    ApprovalHarnessNotConfigured,

    #[error(transparent)]
    Approval(#[from] ApprovalError),

    #[error(transparent)]
    InvalidEvent(#[from] super::IngestRequestError),

    #[error("approval voter signing key env `{env_name}` is missing or empty")]
    MissingVoterSigningKey { env_name: String },

    #[error("first-run scenario `{path}` could not be loaded: {source}")]
    ScenarioLoad {
        path: String,
        #[source]
        source: ReplayHarnessError,
    },

    #[error("first-run wizard only supports event-backed scenarios")]
    UnsupportedScenarioInput,

    #[error("first-run replay failed at step {step_index}: {reason}")]
    ReplayFailed { step_index: usize, reason: String },

    #[error("first-run wizard did not create an approval decision for run `{run_id}`")]
    MissingApproval { run_id: String },

    #[error("approval set `{approval_set_id}` does not have a ledger")]
    MissingApprovalLedger { approval_set_id: String },

    #[error("demo run `{run_id}` was not found")]
    DemoRunNotFound { run_id: String },

    #[error("demo run `{run_id}` did not produce a correlated incident")]
    MissingIncident { run_id: String },

    #[error("demo proof for run `{run_id}` could not be built: {reason}")]
    ProofUnavailable { run_id: String, reason: String },
}

#[derive(Debug, Clone)]
struct PreparedFirstRunScenario {
    scenario_name: String,
    scenario_path: String,
    requested_by: String,
    events: Vec<ReplayScenarioStep>,
}

pub(super) fn with_demo_cors(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn demo_run_report(run: DemoRunState) -> DemoRunReport {
    DemoRunReport {
        run_id: run.run_id,
        scenario_name: run.scenario_name,
        scenario_path: run.scenario_path,
        requested_by: run.requested_by,
        pace_ms: run.pace_ms,
        total_steps: run.total_steps,
        created_at_ms: run.created_at_ms,
        completed_at_ms: run.completed_at_ms,
        timeline: run.timeline,
        approvals: run
            .approvals
            .into_iter()
            .map(|approval| DemoRunApprovalReport {
                approval_set_id: approval.approval_set_id,
                approval_ledger_id: approval.approval_ledger_id,
                step_index: approval.step_index,
                action_kind: approval.action_kind,
                receipt_pack_id: approval
                    .receipt_pack
                    .as_ref()
                    .map(|pack| pack.pack_id.clone()),
                verdict_id: approval
                    .receipt_pack
                    .as_ref()
                    .map(|pack| pack.verdict.verdict_id.clone()),
            })
            .collect(),
        final_incident: run.final_incident,
    }
}

fn demo_proof_package(state: &IngestState, run_id: &str) -> Result<DemoProofPackage, String> {
    let Some(run) = state.load_demo_run(run_id) else {
        return Err(format!("demo run `{run_id}` was not found"));
    };
    let Some(completed_at_ms) = run.completed_at_ms else {
        return Err("demo run has not completed yet".to_string());
    };
    let Some(final_incident) = run.final_incident.clone() else {
        return Err("demo run does not have a correlated incident yet".to_string());
    };
    if run
        .approvals
        .iter()
        .any(|approval| approval.receipt_pack.is_none() || approval.resumed_audit.is_none())
    {
        return Err("demo run still has unresolved approval decisions".to_string());
    }

    let mut leaves = Vec::new();
    let mut leaf_specs = Vec::new();
    for approval in &run.approvals {
        let paused_payload = serde_json::to_value(&approval.initial_audit).unwrap_or(Value::Null);
        leaf_specs.push(("paused_audit".to_string(), paused_payload.clone()));
        leaves.push(canonical_json_bytes(&paused_payload).unwrap_or_default());

        let Some(pack) = approval.receipt_pack.as_ref() else {
            return Err("demo run still has unresolved approval decisions".to_string());
        };
        let pack_payload = serde_json::to_value(pack).unwrap_or(Value::Null);
        leaf_specs.push(("approval_receipt_pack".to_string(), pack_payload.clone()));
        leaves.push(canonical_json_bytes(&pack_payload).unwrap_or_default());

        let Some(resumed) = approval.resumed_audit.as_ref() else {
            return Err("demo run still has unresolved approval decisions".to_string());
        };
        let resumed_payload = serde_json::to_value(resumed).unwrap_or(Value::Null);
        leaf_specs.push(("resumed_audit".to_string(), resumed_payload.clone()));
        leaves.push(canonical_json_bytes(&resumed_payload).unwrap_or_default());
    }

    let incident_payload = serde_json::to_value(&final_incident).unwrap_or(Value::Null);
    leaf_specs.push(("final_incident".to_string(), incident_payload.clone()));
    leaves.push(canonical_json_bytes(&incident_payload).unwrap_or_default());

    let timeline_payload = serde_json::to_value(&run.timeline).unwrap_or(Value::Null);
    leaf_specs.push(("decision_timeline".to_string(), timeline_payload.clone()));
    leaves.push(canonical_json_bytes(&timeline_payload).unwrap_or_default());

    let tree = MerkleTree::from_leaves(&leaves).map_err(|error| error.to_string())?;
    let merkle_leaves = leaf_specs
        .into_iter()
        .enumerate()
        .filter_map(|(index, (label, payload))| {
            tree.inclusion_proof(index).ok().map(|proof| DemoProofLeaf {
                label,
                payload,
                proof,
            })
        })
        .collect::<Vec<_>>();

    Ok(DemoProofPackage {
        run_id: run.run_id,
        scenario_name: run.scenario_name,
        scenario_path: run.scenario_path,
        requested_by: run.requested_by,
        created_at_ms: run.created_at_ms,
        completed_at_ms,
        signed_receipts: run
            .approvals
            .iter()
            .filter_map(|approval| approval.receipt_pack.clone())
            .collect(),
        final_incident,
        decision_timeline: run.timeline,
        merkle_root: tree.root().to_hex_prefixed(),
        merkle_leaves,
    })
}

fn built_in_first_run_event() -> Result<TelemetryEvent, FirstRunWizardError> {
    Ok(super::validate_and_parse(json!({
        "source": "synthetic",
        "event_id": "evt-first-run-1",
        "timestamp": 1_700_000_000_000i64,
        "host_id": "host-first-run",
        "payload": {
            "kind": "process_start",
            "parent_process": "WINWORD",
            "process_name": "powershell",
            "command_line": "powershell.exe -enc AAA=",
            "user": "alice"
        }
    }))?)
}

fn built_in_first_run_scenario() -> Result<PreparedFirstRunScenario, FirstRunWizardError> {
    Ok(PreparedFirstRunScenario {
        scenario_name: "guided first-run".to_string(),
        scenario_path: "builtin://first-run-guided-detection".to_string(),
        requested_by: "swarmctl-first-run".to_string(),
        events: vec![ReplayScenarioStep {
            action: ResponseAction::IsolateHost {
                host_id: "host-first-run".to_string(),
            },
            event: built_in_first_run_event()?,
        }],
    })
}

fn load_first_run_scenario(
    scenario_path: Option<&str>,
) -> Result<PreparedFirstRunScenario, FirstRunWizardError> {
    match scenario_path {
        Some(path) => {
            let loaded = load_scenario_manifest(path).map_err(|source| {
                FirstRunWizardError::ScenarioLoad {
                    path: path.to_string(),
                    source,
                }
            })?;
            let ReplayScenarioInput::Events { events } = loaded.manifest.input.clone() else {
                return Err(FirstRunWizardError::UnsupportedScenarioInput);
            };
            Ok(PreparedFirstRunScenario {
                scenario_name: loaded.manifest.name,
                scenario_path: loaded.path.display().to_string(),
                requested_by: loaded.manifest.requested_by,
                events,
            })
        }
        None => built_in_first_run_scenario(),
    }
}

fn load_demo_run_report(
    state: &IngestState,
    run_id: &str,
) -> Result<DemoRunReport, FirstRunWizardError> {
    state
        .load_demo_run(run_id)
        .map(demo_run_report)
        .ok_or_else(|| FirstRunWizardError::DemoRunNotFound {
            run_id: run_id.to_string(),
        })
}

pub async fn run_first_run_wizard(
    state: IngestState,
    request: FirstRunWizardRequest,
) -> Result<FirstRunWizardReport, FirstRunWizardError> {
    if !state.demo_mode_enabled() {
        return Err(FirstRunWizardError::DemoModeDisabled);
    }

    let scenario = load_first_run_scenario(request.scenario_path.as_deref())?;
    let requested_by = AgentId(scenario.requested_by.clone());
    let run_id = format!("demo_replay:{}", uuid::Uuid::new_v4());
    let total_steps = scenario.events.len();

    state.begin_demo_run(
        &run_id,
        &scenario.scenario_name,
        &scenario.scenario_path,
        &scenario.requested_by,
        request.pace_ms,
        total_steps,
    );
    state.publish_runtime_event(RuntimeEvent::Replay {
        emitted_at_ms: now_ms(),
        run_id: run_id.clone(),
        scenario_name: scenario.scenario_name.clone(),
        scenario_path: scenario.scenario_path.clone(),
        requested_by: scenario.requested_by.clone(),
        phase: ReplayEventPhase::Started,
        pace_ms: request.pace_ms,
        total_steps,
        step_index: None,
        event_id: None,
        reason: None,
    });

    for (index, step) in scenario.events.into_iter().enumerate() {
        let event_id = step.event.event_id.clone();
        state.publish_runtime_event(RuntimeEvent::Replay {
            emitted_at_ms: now_ms(),
            run_id: run_id.clone(),
            scenario_name: scenario.scenario_name.clone(),
            scenario_path: scenario.scenario_path.clone(),
            requested_by: scenario.requested_by.clone(),
            phase: ReplayEventPhase::Step,
            pace_ms: request.pace_ms,
            total_steps,
            step_index: Some(index),
            event_id: Some(event_id.clone()),
            reason: None,
        });
        state.append_demo_timeline(
            &run_id,
            "replay_step_started",
            json!({
                "step_index": index,
                "event_id": event_id,
                "action_kind": step.action.kind(),
            }),
            now_ms(),
        );
        if let Err(error) =
            super::process_demo_replay_step(&state, &run_id, &requested_by, index, step).await
        {
            let reason = error.to_string();
            state.publish_runtime_event(RuntimeEvent::Replay {
                emitted_at_ms: now_ms(),
                run_id: run_id.clone(),
                scenario_name: scenario.scenario_name.clone(),
                scenario_path: scenario.scenario_path.clone(),
                requested_by: scenario.requested_by.clone(),
                phase: ReplayEventPhase::Failed,
                pace_ms: request.pace_ms,
                total_steps,
                step_index: Some(index),
                event_id: Some(event_id.clone()),
                reason: Some(reason.clone()),
            });
            state.append_demo_timeline(
                &run_id,
                "replay_failed",
                json!({
                    "step_index": index,
                    "event_id": event_id,
                    "reason": reason.clone(),
                }),
                now_ms(),
            );
            return Err(FirstRunWizardError::ReplayFailed {
                step_index: index,
                reason,
            });
        }
        if request.pace_ms > 0 && index + 1 < total_steps {
            tokio::time::sleep(Duration::from_millis(request.pace_ms)).await;
        }
    }

    state.publish_runtime_event(RuntimeEvent::Replay {
        emitted_at_ms: now_ms(),
        run_id: run_id.clone(),
        scenario_name: scenario.scenario_name.clone(),
        scenario_path: scenario.scenario_path.clone(),
        requested_by: scenario.requested_by.clone(),
        phase: ReplayEventPhase::Completed,
        pace_ms: request.pace_ms,
        total_steps,
        step_index: None,
        event_id: None,
        reason: None,
    });
    state.append_demo_timeline(
        &run_id,
        "replay_completed",
        json!({
            "scenario_name": scenario.scenario_name,
            "total_steps": total_steps,
        }),
        now_ms(),
    );
    state.mark_demo_completed(&run_id);

    let run = load_demo_run_report(&state, &run_id)?;
    let approval =
        run.approvals
            .first()
            .cloned()
            .ok_or_else(|| FirstRunWizardError::MissingApproval {
                run_id: run_id.clone(),
            })?;
    let harness = state
        .approval_harness
        .as_ref()
        .cloned()
        .ok_or(FirstRunWizardError::ApprovalHarnessNotConfigured)?;
    let voter_secret = std::env::var(&request.voter_signing_key_env)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| FirstRunWizardError::MissingVoterSigningKey {
            env_name: request.voter_signing_key_env.clone(),
        })?;
    let voter = Ed25519Signer::from_secret_material(&voter_secret);
    harness.append_vote(&approval.approval_set_id, &state.operator_id(), &voter)?;

    let approval_ledger_id = harness
        .list_ledgers(Some(&approval.approval_set_id))?
        .ledgers
        .into_iter()
        .next()
        .map(|ledger| ledger.ledger_id)
        .ok_or_else(|| FirstRunWizardError::MissingApprovalLedger {
            approval_set_id: approval.approval_set_id.clone(),
        })?;
    let verdict = harness.create_verdict(&approval.approval_set_id, &approval_ledger_id)?;
    let receipt_pack = harness.export_receipt_pack(
        &verdict.report.verdict_id,
        &request.evidence_signer_id,
        &request.evidence_signing_key_env,
    )?;

    let context = ApprovalContext {
        live_mode: state.stack.load_full().service.runtime.mode() == RuntimeMode::LiveResponse,
        receipt_chain: vec![receipt_pack.report.pack_id.clone()],
        correlation_id: Some(run_id.clone()),
        now_ms: now_ms(),
    };
    let pending = state
        .take_pending_demo_approval(&approval.approval_set_id)
        .ok_or_else(|| FirstRunWizardError::MissingApproval {
            run_id: run_id.clone(),
        })?;
    let stack = state.stack.load_full();
    let execution = stack
        .service
        .runtime
        .audit_authorize_and_execute_human_approved_instrumented(
            &pending.detection,
            &pending.request,
            &context,
        )
        .await
        .map_err(|error| FirstRunWizardError::ReplayFailed {
            step_index: approval.step_index,
            reason: error.to_string(),
        })?;
    let audit = execution.audit.clone();
    if let Err(error) = state.complete_demo_approval(&pending, receipt_pack.report.clone(), audit) {
        return Err(FirstRunWizardError::ReplayFailed {
            step_index: approval.step_index,
            reason: error.to_string(),
        });
    }
    if let Ok(Some(outcome)) = stack.correlate_hunt(&pending.request.hunt_id.0) {
        state.update_demo_incident(&pending.run_id, outcome.incident);
    }

    let run = load_demo_run_report(&state, &run_id)?;
    let incident_id = run
        .final_incident
        .as_ref()
        .map(|incident| incident.incident_id.clone())
        .ok_or_else(|| FirstRunWizardError::MissingIncident {
            run_id: run_id.clone(),
        })?;
    let proof = demo_proof_package(&state, &run_id).map_err(|reason| {
        FirstRunWizardError::ProofUnavailable {
            run_id: run_id.clone(),
            reason,
        }
    })?;

    Ok(FirstRunWizardReport {
        status: FirstRunWizardStatus::Completed,
        scenario_name: run.scenario_name.clone(),
        scenario_path: run.scenario_path.clone(),
        requested_by: run.requested_by.clone(),
        run_id,
        injected_events: total_steps,
        steps: vec![
            FirstRunWizardStep {
                name: "readiness".to_string(),
                status: "passed".to_string(),
                details: "configuration passed the repo-owned first-run readiness gate".to_string(),
            },
            FirstRunWizardStep {
                name: "synthetic_detection".to_string(),
                status: "completed".to_string(),
                details: format!(
                    "replayed {} synthetic event(s) through scenario `{}`",
                    total_steps, run.scenario_name
                ),
            },
            FirstRunWizardStep {
                name: "approval".to_string(),
                status: "completed".to_string(),
                details: format!(
                    "created approval set `{}` and exported receipt pack `{}`",
                    approval.approval_set_id, receipt_pack.report.pack_id
                ),
            },
            FirstRunWizardStep {
                name: "proof_export".to_string(),
                status: "completed".to_string(),
                details: format!(
                    "exported proof for incident `{incident_id}` with Merkle root `{}`",
                    proof.merkle_root
                ),
            },
        ],
        artifacts: FirstRunWizardArtifacts {
            approval_set_id: Some(approval.approval_set_id),
            approval_ledger_id: Some(approval_ledger_id),
            verdict_id: Some(verdict.report.verdict_id),
            receipt_pack_id: Some(receipt_pack.report.pack_id),
            incident_id: Some(incident_id),
            proof_merkle_root: Some(proof.merkle_root.clone()),
        },
        run,
        proof,
    })
}

pub(super) fn render_demo_widget_html(
    runtime_base_url: &str,
    scope: &ProvidenceContextScope,
    raw_token: Option<&str>,
) -> String {
    let runtime_base_url_json =
        serde_json::to_string(runtime_base_url).unwrap_or_else(|_| "\"\"".to_string());
    let token_json = serde_json::to_string(&raw_token.unwrap_or_default())
        .unwrap_or_else(|_| "\"\"".to_string());
    let incident_id_json =
        serde_json::to_string(&scope.incident_id).unwrap_or_else(|_| "null".to_string());
    let hunt_id_json = serde_json::to_string(&scope.hunt_id).unwrap_or_else(|_| "null".to_string());
    let finding_id_json =
        serde_json::to_string(&scope.finding_id).unwrap_or_else(|_| "null".to_string());
    let strategy_id_json =
        serde_json::to_string(&scope.strategy_id).unwrap_or_else(|_| "null".to_string());
    let threat_class_json = serde_json::to_string(&super::widget_threat_class_slug(scope))
        .unwrap_or_else(|_| "null".to_string());
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Swarm Widget</title>
<style>
body{{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0b1220;color:#e6edf7;}}
.shell{{padding:16px;display:grid;gap:12px;background:radial-gradient(circle at top right,#13325a 0,#0b1220 55%);min-height:100vh;box-sizing:border-box;}}
.header{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;}}
.eyebrow{{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:#8fb5ff;margin:0 0 6px 0;}}
h1{{font-size:18px;margin:0 0 4px 0;}}
.muted{{color:#9bb0cf;font-size:13px;}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;}}
.card{{background:rgba(9,16,31,.72);border:1px solid rgba(151,181,255,.18);border-radius:14px;padding:12px;backdrop-filter:blur(8px);}}
.card h2{{margin:0 0 8px 0;font-size:13px;color:#bfd2ff;text-transform:uppercase;letter-spacing:.08em;}}
.kpi{{font-size:24px;font-weight:700;}}
ul{{list-style:none;padding:0;margin:0;display:grid;gap:8px;}}
li{{padding:8px 10px;border-radius:10px;background:rgba(255,255,255,.04);font-size:13px;}}
.pill{{display:inline-flex;align-items:center;border-radius:999px;padding:4px 8px;background:#143050;color:#bfd2ff;font-size:12px;gap:6px;}}
.empty{{color:#7f93b5;font-style:italic;}}
</style>
</head>
<body>
<main class="shell">
  <section class="header">
    <div>
      <p class="eyebrow">Ambush Engine</p>
      <h1>Providence Context Widget</h1>
      <div class="muted" id="scope-label">Loading scoped context…</div>
    </div>
    <div class="pill" id="connection-state">Connecting</div>
  </section>
  <section class="grid">
    <article class="card"><h2>Mode</h2><div class="kpi" id="mode-value">--</div></article>
    <article class="card"><h2>Context</h2><div class="muted" id="context-value">Awaiting token scope</div></article>
  </section>
  <section class="grid">
    <article class="card"><h2>Concentrations</h2><ul id="concentration-list"><li class="empty">Waiting for snapshot</li></ul></article>
    <article class="card"><h2>Agent Activity</h2><ul id="activity-list"><li class="empty">Waiting for scoped events</li></ul></article>
    <article class="card"><h2>Escalation Timeline</h2><ul id="timeline-list"><li class="empty">Waiting for scoped events</li></ul></article>
  </section>
</main>
<script>
const runtimeBaseUrl = {runtime_base_url_json};
const widgetScope = {{
  token: {token_json},
  incidentId: {incident_id_json},
  huntId: {hunt_id_json},
  findingId: {finding_id_json},
  strategyId: {strategy_id_json},
  threatClass: {threat_class_json}
}};

const modeValue = document.getElementById("mode-value");
const scopeLabel = document.getElementById("scope-label");
const contextValue = document.getElementById("context-value");
const connectionState = document.getElementById("connection-state");
const concentrationList = document.getElementById("concentration-list");
const activityList = document.getElementById("activity-list");
const timelineList = document.getElementById("timeline-list");

function scopedParams(includeTypes) {{
  const params = new URLSearchParams();
  if (includeTypes) {{
    params.set("types", "agent_action,response_execution,concentration_snapshot,escalation,mode_transition,finding");
  }}
  if (widgetScope.token) params.set("context_token", widgetScope.token);
  if (widgetScope.incidentId) params.set("incident_id", widgetScope.incidentId);
  if (widgetScope.huntId) params.set("hunt_id", widgetScope.huntId);
  if (widgetScope.findingId) params.set("finding_id", widgetScope.findingId);
  if (widgetScope.strategyId) params.set("strategy_id", widgetScope.strategyId);
  if (widgetScope.threatClass) params.set("threat_class", widgetScope.threatClass);
  return params;
}}

function summarizeScope() {{
  const bits = [];
  if (widgetScope.incidentId) bits.push(`incident=${{widgetScope.incidentId}}`);
  if (widgetScope.huntId) bits.push(`hunt=${{widgetScope.huntId}}`);
  if (widgetScope.findingId) bits.push(`finding=${{widgetScope.findingId}}`);
  if (widgetScope.strategyId) bits.push(`strategy=${{widgetScope.strategyId}}`);
  if (widgetScope.threatClass) bits.push(`threat=${{widgetScope.threatClass}}`);
  scopeLabel.textContent = bits.length ? bits.join(" · ") : "Live swarm context";
  contextValue.textContent = bits.length ? bits.join(" | ") : "No scoped context supplied";
}}

function renderList(target, entries, formatter) {{
  if (!entries.length) {{
    target.innerHTML = '<li class="empty">No scoped events yet</li>';
    return;
  }}
  target.innerHTML = entries.slice(0, 10).map(formatter).join("");
}}

function renderConcentrations(snapshot) {{
  const entries = (snapshot.concentrations || []).map((entry) => {{
    return {{
      label: entry.threat_class,
      detail: `strength ${{entry.total_strength.toFixed(2)}} · sources ${{entry.distinct_sources}} · peak ${{entry.peak_confidence.toFixed(2)}}`
    }};
  }});
  renderList(concentrationList, entries, (entry) => `<li><strong>${{entry.label}}</strong><div class="muted">${{entry.detail}}</div></li>`);
}}

const activity = [];
const timeline = [];

function pushLimited(target, list, entry) {{
  list.unshift(entry);
  if (list.length > 10) list.length = 10;
  renderList(target, list, (item) => `<li><strong>${{item.title}}</strong><div class="muted">${{item.detail}}</div></li>`);
}}

function connect() {{
  summarizeScope();
  fetch(runtimeBaseUrl.replace(/\/$/, "") + "/v1/demo/dashboard?" + scopedParams(false).toString())
    .then((response) => response.json())
    .then((snapshot) => {{
      modeValue.textContent = snapshot.mode_state?.current || "--";
      renderConcentrations(snapshot);
    }})
    .catch((error) => {{
      concentrationList.innerHTML = `<li class="empty">${{error.message}}</li>`;
    }});

  const source = new EventSource(
    runtimeBaseUrl.replace(/\/$/, "") + "/v1/events/stream?" + scopedParams(true).toString()
  );
  source.onopen = () => {{
    connectionState.textContent = "Live";
  }};
  source.onerror = () => {{
    connectionState.textContent = "Reconnecting";
  }};
  source.onmessage = (event) => {{
    const payload = JSON.parse(event.data);
    if (payload.event_type === "finding") {{
      pushLimited(activityList, activity, {{
        title: payload.finding.strategy_id,
        detail: `${{payload.finding.threat_class}} · confidence ${{payload.finding.confidence.toFixed(2)}}`
      }});
    }} else if (payload.event_type === "agent_action") {{
      pushLimited(activityList, activity, {{
        title: payload.role,
        detail: payload.action_kind + (payload.hunt_id ? ` · ${{payload.hunt_id}}` : "")
      }});
    }} else if (payload.event_type === "response_execution") {{
      pushLimited(timelineList, timeline, {{
        title: payload.response_kind,
        detail: `${{payload.action_kind}} · hunt ${{payload.hunt_id}}`
      }});
    }} else if (payload.event_type === "escalation") {{
      pushLimited(timelineList, timeline, {{
        title: payload.level,
        detail: `${{payload.threat_class}} · strength ${{payload.total_strength.toFixed(2)}}`
      }});
    }} else if (payload.event_type === "mode_transition") {{
      modeValue.textContent = payload.to;
      pushLimited(timelineList, timeline, {{
        title: `${{payload.from}} → ${{payload.to}}`,
        detail: payload.reason
      }});
    }} else if (payload.event_type === "concentration_snapshot") {{
      renderConcentrations(payload);
    }}
  }};
}}

connect();
</script>
</body>
</html>"#
    )
}

// --- Handlers ---

pub(crate) async fn demo_replay_handler(
    State(state): State<IngestState>,
    payload: Result<Json<DemoReplayRequest>, JsonRejection>,
) -> Response {
    if !state.demo_mode_enabled() {
        return (
            StatusCode::FORBIDDEN,
            ResponseJson(DemoReplayErrorBody {
                error: "demo mode is disabled".to_string(),
            }),
        )
            .into_response();
    }

    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(rejection) => {
            return (
                StatusCode::BAD_REQUEST,
                ResponseJson(DemoReplayErrorBody {
                    error: rejection.body_text(),
                }),
            )
                .into_response();
        }
    };

    let loaded = match load_scenario_manifest(&request.scenario_path) {
        Ok(loaded) => loaded,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                ResponseJson(DemoReplayErrorBody {
                    error: error.to_string(),
                }),
            )
                .into_response();
        }
    };

    let ReplayScenarioInput::Events { events } = loaded.manifest.input.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            ResponseJson(DemoReplayErrorBody {
                error: "demo replay only supports event-backed scenarios".to_string(),
            }),
        )
            .into_response();
    };

    let run_id = format!("demo_replay:{}", uuid::Uuid::new_v4());
    let requested_by = AgentId(loaded.manifest.requested_by.clone());
    let total_steps = events.len();
    state.begin_demo_run(
        &run_id,
        &loaded.manifest.name,
        &loaded.path.display().to_string(),
        &loaded.manifest.requested_by,
        request.pace_ms,
        total_steps,
    );

    state.publish_runtime_event(RuntimeEvent::Replay {
        emitted_at_ms: now_ms(),
        run_id: run_id.clone(),
        scenario_name: loaded.manifest.name.clone(),
        scenario_path: loaded.path.display().to_string(),
        requested_by: loaded.manifest.requested_by.clone(),
        phase: ReplayEventPhase::Started,
        pace_ms: request.pace_ms,
        total_steps,
        step_index: None,
        event_id: None,
        reason: None,
    });

    for (index, step) in events.into_iter().enumerate() {
        let event_id = step.event.event_id.clone();
        state.publish_runtime_event(RuntimeEvent::Replay {
            emitted_at_ms: now_ms(),
            run_id: run_id.clone(),
            scenario_name: loaded.manifest.name.clone(),
            scenario_path: loaded.path.display().to_string(),
            requested_by: loaded.manifest.requested_by.clone(),
            phase: ReplayEventPhase::Step,
            pace_ms: request.pace_ms,
            total_steps,
            step_index: Some(index),
            event_id: Some(event_id.clone()),
            reason: None,
        });
        state.append_demo_timeline(
            &run_id,
            "replay_step_started",
            json!({
                "step_index": index,
                "event_id": event_id,
                "action_kind": step.action.kind(),
            }),
            now_ms(),
        );

        if let Err(error) =
            super::process_demo_replay_step(&state, &run_id, &requested_by, index, step).await
        {
            let error_body = error.to_string();
            state.publish_runtime_event(RuntimeEvent::Replay {
                emitted_at_ms: now_ms(),
                run_id: run_id.clone(),
                scenario_name: loaded.manifest.name.clone(),
                scenario_path: loaded.path.display().to_string(),
                requested_by: loaded.manifest.requested_by.clone(),
                phase: ReplayEventPhase::Failed,
                pace_ms: request.pace_ms,
                total_steps,
                step_index: Some(index),
                event_id: Some(event_id.clone()),
                reason: Some(error_body.clone()),
            });
            state.append_demo_timeline(
                &run_id,
                "replay_failed",
                json!({
                    "step_index": index,
                    "event_id": event_id,
                    "reason": error_body,
                }),
                now_ms(),
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseJson(DemoReplayErrorBody { error: error_body }),
            )
                .into_response();
        }

        if request.pace_ms > 0 && index + 1 < total_steps {
            tokio::time::sleep(Duration::from_millis(request.pace_ms)).await;
        }
    }

    state.publish_runtime_event(RuntimeEvent::Replay {
        emitted_at_ms: now_ms(),
        run_id: run_id.clone(),
        scenario_name: loaded.manifest.name.clone(),
        scenario_path: loaded.path.display().to_string(),
        requested_by: loaded.manifest.requested_by.clone(),
        phase: ReplayEventPhase::Completed,
        pace_ms: request.pace_ms,
        total_steps,
        step_index: None,
        event_id: None,
        reason: None,
    });
    state.append_demo_timeline(
        &run_id,
        "replay_completed",
        json!({
            "scenario_name": loaded.manifest.name,
            "total_steps": total_steps,
        }),
        now_ms(),
    );
    state.mark_demo_completed(&run_id);

    (
        StatusCode::OK,
        ResponseJson(DemoReplayResponse {
            run_id,
            scenario_name: loaded.manifest.name,
            scenario_path: loaded.path.display().to_string(),
            requested_by: loaded.manifest.requested_by,
            pace_ms: request.pace_ms,
            injected_events: total_steps,
        }),
    )
        .into_response()
}

pub(crate) async fn demo_dashboard_snapshot_handler(
    State(state): State<IngestState>,
    Query(query): Query<DemoDashboardQuery>,
) -> Response {
    if !state.demo_mode_enabled() {
        return with_demo_cors(
            (
                StatusCode::FORBIDDEN,
                ResponseJson(DemoReplayErrorBody {
                    error: "demo mode is disabled".to_string(),
                }),
            )
                .into_response(),
        );
    }
    let operator = state.stack.load_full().service.config.operator.clone();
    let scope = match super::resolve_demo_scope(&operator, &query.scope) {
        Ok(scope) => scope,
        Err(error) => {
            return with_demo_cors(
                (
                    StatusCode::UNAUTHORIZED,
                    ResponseJson(DemoReplayErrorBody {
                        error: error.to_string(),
                    }),
                )
                    .into_response(),
            );
        }
    };

    let substrate = state.current_substrate();
    let now = super::unix_timestamp_secs();
    let mut concentrations = Vec::with_capacity(standard_threat_classes().len());
    for threat_class in standard_threat_classes() {
        let concentration = match substrate.query_concentration(&threat_class, now).await {
            Ok(concentration) => concentration,
            Err(error) => {
                return with_demo_cors(
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ResponseJson(DemoReplayErrorBody {
                            error: error.to_string(),
                        }),
                    )
                        .into_response(),
                );
            }
        };
        concentrations.push(RuntimeThreatConcentration::from(&concentration));
    }

    let mut recent_escalations = match substrate.query_escalations(0).await {
        Ok(records) => records,
        Err(error) => {
            return with_demo_cors(
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ResponseJson(DemoReplayErrorBody {
                        error: error.to_string(),
                    }),
                )
                    .into_response(),
            );
        }
    };
    recent_escalations.sort_by(|left, right| {
        right
            .timestamp
            .cmp(&left.timestamp)
            .then_with(|| right.mode.cmp(&left.mode))
    });
    recent_escalations.truncate(20);
    let concentrations = super::filter_concentrations_for_scope(concentrations, &scope);
    let recent_escalations = super::filter_escalations_for_scope(recent_escalations, &scope);

    with_demo_cors(
        (
            StatusCode::OK,
            ResponseJson(DemoDashboardSnapshot {
                captured_at_ms: now_ms(),
                mode_state: state.current_mode_state(),
                agent_health: state.current_agent_health(),
                concentrations,
                recent_escalations,
            }),
        )
            .into_response(),
    )
}

pub(crate) async fn demo_approval_resume_handler(
    State(state): State<IngestState>,
    axum::extract::Path(approval_set_id): axum::extract::Path<String>,
    payload: Result<Json<DemoApprovalResumeRequest>, JsonRejection>,
) -> Response {
    if !state.demo_mode_enabled() {
        return with_demo_cors(
            (
                StatusCode::FORBIDDEN,
                ResponseJson(DemoReplayErrorBody {
                    error: "demo mode is disabled".to_string(),
                }),
            )
                .into_response(),
        );
    }

    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(rejection) => {
            return with_demo_cors(
                (
                    StatusCode::BAD_REQUEST,
                    ResponseJson(DemoReplayErrorBody {
                        error: rejection.body_text(),
                    }),
                )
                    .into_response(),
            );
        }
    };

    if request.receipt_pack.approval_set.set_id != approval_set_id {
        return with_demo_cors(
            (
                StatusCode::BAD_REQUEST,
                ResponseJson(DemoReplayErrorBody {
                    error: "approval set id does not match receipt pack".to_string(),
                }),
            )
                .into_response(),
        );
    }
    if !matches!(
        request.receipt_pack.verdict.status,
        ApprovalVerdictStatus::Approved
    ) {
        return with_demo_cors(
            (
                StatusCode::CONFLICT,
                ResponseJson(DemoReplayErrorBody {
                    error: "approval receipt pack does not carry an approved verdict".to_string(),
                }),
            )
                .into_response(),
        );
    }
    if let Err(error) = verify_receipt_pack(&request.receipt_pack) {
        return with_demo_cors(
            (
                StatusCode::BAD_REQUEST,
                ResponseJson(DemoReplayErrorBody {
                    error: error.to_string(),
                }),
            )
                .into_response(),
        );
    }

    let Some(pending) = state.take_pending_demo_approval(&approval_set_id) else {
        return with_demo_cors(
            (
                StatusCode::NOT_FOUND,
                ResponseJson(DemoReplayErrorBody {
                    error: format!("pending demo approval `{approval_set_id}` was not found"),
                }),
            )
                .into_response(),
        );
    };

    let context = ApprovalContext {
        live_mode: state.stack.load_full().service.runtime.mode() == RuntimeMode::LiveResponse,
        receipt_chain: vec![request.receipt_pack.pack_id.clone()],
        correlation_id: Some(pending.run_id.clone()),
        now_ms: now_ms(),
    };
    let stack = state.stack.load_full();
    let execution = match stack
        .service
        .runtime
        .audit_authorize_and_execute_human_approved_instrumented(
            &pending.detection,
            &pending.request,
            &context,
        )
        .await
    {
        Ok(report) => report,
        Err(error) => {
            return with_demo_cors(
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ResponseJson(DemoReplayErrorBody {
                        error: error.to_string(),
                    }),
                )
                    .into_response(),
            );
        }
    };

    let audit = execution.audit.clone();
    let (receipt_id, response_error) = super::response_receipt_details(&audit);
    state.publish_runtime_event(RuntimeEvent::ResponseExecution {
        emitted_at_ms: now_ms(),
        agent_id: pending.request.requested_by.to_string(),
        hunt_id: audit.hunt_id.clone(),
        action_kind: pending.request.action.kind().to_string(),
        response_kind: audit.response_kind().to_string(),
        policy_verdict: audit.policy.verdict,
        rule_name: audit.policy.rule_name.clone(),
        reason: audit.policy.reason.clone(),
        receipt_id: receipt_id.clone(),
        governing_agent_id: None,
        error: response_error,
    });

    if let Err(error) =
        state.complete_demo_approval(&pending, request.receipt_pack.clone(), audit.clone())
    {
        return with_demo_cors(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseJson(DemoReplayErrorBody {
                    error: error.to_string(),
                }),
            )
                .into_response(),
        );
    }

    if let Ok(Some(outcome)) = stack.correlate_hunt(&pending.request.hunt_id.0) {
        state.update_demo_incident(&pending.run_id, outcome.incident);
    }

    with_demo_cors(
        (
            StatusCode::OK,
            ResponseJson(DemoApprovalResumeResponse {
                approval_set_id,
                receipt_pack_id: request.receipt_pack.pack_id,
                response_kind: audit.response_kind().to_string(),
                response_receipt_id: receipt_id,
                audit,
            }),
        )
            .into_response(),
    )
}

pub(crate) async fn demo_proof_handler(
    State(state): State<IngestState>,
    Query(query): Query<DemoProofQuery>,
) -> Response {
    if !state.demo_mode_enabled() {
        return with_demo_cors(
            (
                StatusCode::FORBIDDEN,
                ResponseJson(DemoReplayErrorBody {
                    error: "demo mode is disabled".to_string(),
                }),
            )
                .into_response(),
        );
    }

    let Some(run) = state.load_demo_run(&query.run_id) else {
        return with_demo_cors(
            (
                StatusCode::NOT_FOUND,
                ResponseJson(DemoReplayErrorBody {
                    error: format!("demo run `{}` was not found", query.run_id),
                }),
            )
                .into_response(),
        );
    };
    let Some(completed_at_ms) = run.completed_at_ms else {
        return with_demo_cors(
            (
                StatusCode::CONFLICT,
                ResponseJson(DemoReplayErrorBody {
                    error: "demo run has not completed yet".to_string(),
                }),
            )
                .into_response(),
        );
    };
    let Some(final_incident) = run.final_incident.clone() else {
        return with_demo_cors(
            (
                StatusCode::CONFLICT,
                ResponseJson(DemoReplayErrorBody {
                    error: "demo run does not have a correlated incident yet".to_string(),
                }),
            )
                .into_response(),
        );
    };
    if run
        .approvals
        .iter()
        .any(|approval| approval.receipt_pack.is_none() || approval.resumed_audit.is_none())
    {
        return with_demo_cors(
            (
                StatusCode::CONFLICT,
                ResponseJson(DemoReplayErrorBody {
                    error: "demo run still has unresolved approval decisions".to_string(),
                }),
            )
                .into_response(),
        );
    }

    let mut leaves = Vec::new();
    let mut leaf_specs = Vec::new();
    for approval in &run.approvals {
        let paused_payload = serde_json::to_value(&approval.initial_audit).unwrap_or(Value::Null);
        leaf_specs.push(("paused_audit".to_string(), paused_payload.clone()));
        leaves.push(canonical_json_bytes(&paused_payload).unwrap_or_default());

        let Some(pack) = approval.receipt_pack.as_ref() else {
            return with_demo_cors(
                (
                    StatusCode::CONFLICT,
                    ResponseJson(DemoReplayErrorBody {
                        error: "demo run still has unresolved approval decisions".to_string(),
                    }),
                )
                    .into_response(),
            );
        };
        let pack_payload = serde_json::to_value(pack).unwrap_or(Value::Null);
        leaf_specs.push(("approval_receipt_pack".to_string(), pack_payload.clone()));
        leaves.push(canonical_json_bytes(&pack_payload).unwrap_or_default());

        let Some(resumed) = approval.resumed_audit.as_ref() else {
            return with_demo_cors(
                (
                    StatusCode::CONFLICT,
                    ResponseJson(DemoReplayErrorBody {
                        error: "demo run still has unresolved approval decisions".to_string(),
                    }),
                )
                    .into_response(),
            );
        };
        let resumed_payload = serde_json::to_value(resumed).unwrap_or(Value::Null);
        leaf_specs.push(("resumed_audit".to_string(), resumed_payload.clone()));
        leaves.push(canonical_json_bytes(&resumed_payload).unwrap_or_default());
    }

    let incident_payload = serde_json::to_value(&final_incident).unwrap_or(Value::Null);
    leaf_specs.push(("final_incident".to_string(), incident_payload.clone()));
    leaves.push(canonical_json_bytes(&incident_payload).unwrap_or_default());

    let timeline_payload = serde_json::to_value(&run.timeline).unwrap_or(Value::Null);
    leaf_specs.push(("decision_timeline".to_string(), timeline_payload.clone()));
    leaves.push(canonical_json_bytes(&timeline_payload).unwrap_or_default());

    let tree = match MerkleTree::from_leaves(&leaves) {
        Ok(tree) => tree,
        Err(error) => {
            return with_demo_cors(
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ResponseJson(DemoReplayErrorBody {
                        error: error.to_string(),
                    }),
                )
                    .into_response(),
            );
        }
    };
    let merkle_leaves = leaf_specs
        .into_iter()
        .enumerate()
        .filter_map(|(index, (label, payload))| {
            tree.inclusion_proof(index).ok().map(|proof| DemoProofLeaf {
                label,
                payload,
                proof,
            })
        })
        .collect::<Vec<_>>();

    with_demo_cors(
        (
            StatusCode::OK,
            ResponseJson(DemoProofPackage {
                run_id: run.run_id,
                scenario_name: run.scenario_name,
                scenario_path: run.scenario_path,
                requested_by: run.requested_by,
                created_at_ms: run.created_at_ms,
                completed_at_ms,
                signed_receipts: run
                    .approvals
                    .iter()
                    .filter_map(|approval| approval.receipt_pack.clone())
                    .collect(),
                final_incident,
                decision_timeline: run.timeline,
                merkle_root: tree.root().to_hex_prefixed(),
                merkle_leaves,
            }),
        )
            .into_response(),
    )
}

pub(crate) async fn demo_widget_handler(
    State(state): State<IngestState>,
    Query(query): Query<DemoWidgetQuery>,
) -> Response {
    if !state.demo_mode_enabled() {
        return with_demo_cors(
            (
                StatusCode::FORBIDDEN,
                ResponseJson(DemoReplayErrorBody {
                    error: "demo mode is disabled".to_string(),
                }),
            )
                .into_response(),
        );
    }
    let operator = state.stack.load_full().service.config.operator.clone();
    let scope = match super::resolve_demo_scope(&operator, &query.scope) {
        Ok(scope) => scope,
        Err(error) => {
            return super::with_widget_headers(
                (
                    StatusCode::UNAUTHORIZED,
                    Html(format!(
                        "<!DOCTYPE html><html><body>{}</body></html>",
                        error
                    )),
                )
                    .into_response(),
                &operator,
            );
        }
    };
    super::with_widget_headers(
        Html(render_demo_widget_html(
            &operator.runtime_base_url,
            &scope,
            query.scope.context_token.as_deref(),
        ))
        .into_response(),
        &operator,
    )
}

pub(crate) async fn runtime_events_handler(
    State(state): State<IngestState>,
    Query(query): Query<RuntimeEventStreamQuery>,
) -> Response {
    let operator = state.stack.load_full().service.config.operator.clone();
    let scope = match super::resolve_demo_scope(&operator, &query.scope) {
        Ok(scope) => scope,
        Err(error) => {
            return with_demo_cors(
                (
                    StatusCode::UNAUTHORIZED,
                    ResponseJson(DemoReplayErrorBody {
                        error: error.to_string(),
                    }),
                )
                    .into_response(),
            );
        }
    };
    let filter = match parse_runtime_event_filter(query.types.as_deref()) {
        Ok(filter) => filter,
        Err(error) => {
            return with_demo_cors(
                (
                    StatusCode::BAD_REQUEST,
                    ResponseJson(DemoReplayErrorBody { error }),
                )
                    .into_response(),
            );
        }
    };

    let Some(receiver) = state.subscribe_runtime_events() else {
        return with_demo_cors(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                ResponseJson(DemoReplayErrorBody {
                    error: "runtime event stream is not configured".to_string(),
                }),
            )
                .into_response(),
        );
    };

    let stream = BroadcastStream::new(receiver).filter_map(move |result| {
        let Ok(event) = result else {
            return None;
        };
        if filter
            .as_ref()
            .is_some_and(|kinds| !kinds.contains(&event.kind()))
        {
            return None;
        }
        let event = super::filter_runtime_event_for_scope(event, &scope)?;

        Some(Ok::<SseEvent, Infallible>(
            SseEvent::default()
                .event(event.kind().as_str())
                .id(event.emitted_at_ms().to_string())
                .data(serde_json::to_string(&event).unwrap_or_else(|error| {
                    json!({
                        "event_type": "serialization_error",
                        "reason": error.to_string(),
                    })
                    .to_string()
                })),
        ))
    });

    let response = Sse::new(stream)
        .keep_alive(KeepAlive::default().interval(Duration::from_secs(15)))
        .into_response();
    with_demo_cors(response)
}
