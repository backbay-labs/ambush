//! Fixtures shared by the `perch_ops` test modules: a runtime state with a live
//! `RuntimeEventBroadcaster`, and a hand-built single-member incident.

use super::super::IngestState;
use super::super::tests::test_config;
use super::mint::IncidentMintRequest;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use swarm_core::ThreatClass;
use swarm_core::types::Severity;
use swarm_runtime::runtime_events::{DEFAULT_RUNTIME_EVENT_CAPACITY, RuntimeEventBroadcaster};
use swarm_spine::{CorrelatedIncident, IncidentMemberDecision};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A per-call temp path for the state's config path, so every repo-relative
/// store a feedback write opens (`data/evolution-population`, ...) lands under
/// the OS temp dir rather than the checked-out crate root.
fn temp_config_path() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "swarm-perch-ops-{}-{nanos}-{counter}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("temp root");
    root.join("inline")
}

/// An `IngestState` over the `suspicious_process_tree` test config with an
/// in-memory incident store and a subscribable runtime-event broadcaster.
pub(super) fn test_state() -> IngestState {
    IngestState::from_config(temp_config_path(), test_config("suspicious_process_tree"))
        .expect("ingest state")
        .with_runtime_events(RuntimeEventBroadcaster::new(DEFAULT_RUNTIME_EVENT_CAPACITY))
}

/// A `CorrelatedIncident` with exactly one included member for `finding_id`,
/// carrying a `host:host-ops-1` correlation key and a real strategy id.
pub(super) fn perch_incident(
    hunt_id: &str,
    finding_id: &str,
    created_at_ms: i64,
) -> CorrelatedIncident {
    CorrelatedIncident {
        incident_id: format!("incident:{hunt_id}:{created_at_ms}"),
        summary: format!("test incident for {finding_id}"),
        created_at_ms,
        window_start_ms: created_at_ms,
        window_end_ms: created_at_ms,
        correlation_keys: vec!["host:host-ops-1".to_string()],
        related_receipt_ids: Vec::new(),
        included_members: vec![IncidentMemberDecision {
            investigation_id: format!("investigation:{finding_id}"),
            hunt_id: hunt_id.to_string(),
            finding_id: finding_id.to_string(),
            reason: "seed".to_string(),
            shared_keys: Vec::new(),
            evidence_links: Vec::new(),
            confidence_score: 1.0,
        }],
        rejected_members: Vec::new(),
        graph_dimensions: Vec::new(),
        confidence_score: 1.0,
        trigger_event_id: Some(hunt_id.to_string()),
        trigger_finding_id: Some(finding_id.to_string()),
        trigger_strategy_id: Some("suspicious_process_tree".to_string()),
        threat_class: Some(ThreatClass::Execution),
        severity: Some(Severity::High),
        external_references: Vec::new(),
        providence_reconciliation: None,
        providence_callback_audit_entries: Vec::new(),
        feedback_audit_entries: Vec::new(),
        false_positive_measurements: Vec::new(),
    }
}

/// A B3i body for `finding` on hunt `hunt-evt-1`, with or without a host.
pub(super) fn mint_request(finding: &str, host: Option<&str>) -> IncidentMintRequest {
    IncidentMintRequest {
        finding_id: finding.into(),
        hunt_id: "hunt-evt-1".into(),
        event_id: "hunt-evt-1".into(),
        strategy_id: "suspicious_process_tree".into(),
        threat_class: ThreatClass::Execution,
        severity: Severity::High,
        created_at_ms: 1_700_000_000_000,
        summary: "Office-spawned encoded PowerShell".into(),
        host_id: host.map(str::to_string),
        correlation_keys: vec![],
    }
}

/// Persist a replay bundle for `hunt_id` so `investigate` feedback — which
/// re-queues the hunt's bundle — has something to load.
pub(super) fn seed_replay_bundle(
    state: &IngestState,
    hunt_id: &str,
    finding_id: &str,
    host_id: &str,
) {
    use swarm_core::types::{AgentId, HuntId, ResponseAction};
    use swarm_spine::{
        AuditResponseRecord, AuditTrail, PolicyRecord, ReplayBundle, ReplayBundleStore,
    };
    use swarm_whisker::{DetectionFinding, ProcessStartEvent, TelemetryEvent, TelemetryPayload};

    let event = TelemetryEvent {
        source: "synthetic".to_string(),
        event_id: hunt_id.to_string(),
        timestamp: 1_700_000_000,
        host_id: Some(host_id.to_string()),
        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: "winword".to_string(),
            process_name: "powershell".to_string(),
            command_line: "powershell -enc AAAA".to_string(),
            user: Some("alice".to_string()),
            executable_path: None,
            signer: None,
            signature_valid: None,
        }),
    };
    let finding = DetectionFinding {
        finding_id: finding_id.to_string(),
        event_id: hunt_id.to_string(),
        threat_class: ThreatClass::Execution,
        severity: Severity::High,
        confidence: 0.98,
        evidence: serde_json::json!({ "host_id": host_id, "event_id": hunt_id }),
        strategy_id: "suspicious_process_tree".to_string(),
    };
    let bundle = ReplayBundle {
        bundle_id: format!("bundle-{hunt_id}"),
        event,
        findings: vec![finding.clone()],
        deposits: Vec::new(),
        action_request: swarm_policy::ActionRequest {
            hunt_id: HuntId(hunt_id.to_string()),
            requested_by: AgentId::new("whisker", "primary"),
            action: ResponseAction::Escalate {
                summary: format!("escalate {hunt_id}"),
                urgency: Severity::High,
            },
            severity: Severity::High,
            evidence: serde_json::json!(swarm_response::SwarmFindingEnvelope::from(&finding)),
        },
        rehearsal: None,
        audit: AuditTrail {
            trail_id: format!("trail-{hunt_id}"),
            hunt_id: hunt_id.to_string(),
            related_receipt_ids: Vec::new(),
            detection: finding,
            policy: PolicyRecord {
                verdict: swarm_policy::PolicyVerdict::Allow,
                rule_name: "perch-ops-test.allow".to_string(),
                reason: "perch ops test fixture".to_string(),
                lease: None,
            },
            response: AuditResponseRecord::Skipped {
                reason: "perch ops fixture skips response execution".to_string(),
            },
            created_at_ms: 1_700_000_000_000,
        },
    };
    state
        .current_replay_store()
        .persist(&bundle)
        .expect("replay bundle");
}
