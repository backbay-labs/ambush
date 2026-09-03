//! B3i — the engine half of `POST /v1/operator/incidents`.
//!
//! Builds a single-member `CorrelatedIncident` for a finding an operator promoted
//! and persists it through the ONE incident store the tuning report reads. The
//! minting contract is enforced, not documented (12-BACKEND-BILL-API.md §9.3):
//! an empty `strategy_id` is refused because `None` would become the literal
//! `"unknown"` downstream and collapse every hand-promoted finding into one fake
//! detector bucket; a missing `host_id` is accepted and NAMED in `degraded`,
//! because a finding with no host is a legitimate object.
//!
//! The daemon mints `case_id` (00-DECISIONS W3-14): the request carries none,
//! and `RuntimeEvent::CasePromoted` goes out AFTER the record commits so the
//! bridge creates the case channel for a record that already exists.

use super::super::{IngestState, sanitize_id};
use super::PerchOpsError;
use serde::{Deserialize, Serialize};
use swarm_core::ThreatClass;
use swarm_core::types::Severity;
use swarm_runtime::runtime_events::{CasePromotionClause, RuntimeEvent};
use swarm_spine::{CorrelatedIncident, IncidentMemberDecision, IncidentRecord, IncidentStore};

/// Prefix of every incident this route mints: `incident:perch-case:{case_id}`.
///
/// The second segment is the literal `perch-case`, so the id cannot collide with
/// the correlation engine's `incident:{hunt_id}:{created_at_ms}`.
pub const PERCH_CASE_INCIDENT_PREFIX: &str = "incident:perch-case:";

/// The tuning capability a mint without a `host:` key cannot support.
pub const DEGRADED_HOST_EXCLUSION_UNREACHABLE: &str = "host_exclusion_unreachable";

/// Body of `POST /v1/operator/incidents`. Deliberately has no `case_id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentMintRequest {
    /// The finding being promoted; becomes the single included member.
    pub finding_id: String,
    /// The hunt the finding belongs to.
    pub hunt_id: String,
    /// The telemetry event the finding was raised on; becomes `trigger_event_id`.
    pub event_id: String,
    /// The detector that raised the finding; refused when empty.
    pub strategy_id: String,
    /// The finding's threat class.
    pub threat_class: ThreatClass,
    /// The finding's severity.
    pub severity: Severity,
    /// The finding's own instant; used for `created_at_ms` and both window bounds.
    pub created_at_ms: i64,
    /// One human sentence; becomes the incident summary.
    pub summary: String,
    /// When present, written as a `host:{host_id}` correlation key so
    /// `HostExclusionReview` can reach this finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    /// Additional correlation keys, copied verbatim.
    #[serde(default)]
    pub correlation_keys: Vec<String>,
}

/// Response of `POST /v1/operator/incidents`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentMintResponse {
    /// Response schema version; `1`.
    pub schema_version: u32,
    /// `incident:perch-case:{case_id}`.
    pub incident_id: String,
    /// The case channel UUID the daemon minted.
    pub case_id: String,
    /// False on a replay: an incident this route already minted for the finding.
    pub created: bool,
    /// Named tuning capabilities this incident cannot support; empty when none.
    pub degraded: Vec<String>,
    /// The record as persisted.
    pub record: IncidentRecord,
}

/// Mint (or replay) the single-member incident for a promoted finding.
///
/// Idempotent on `finding_id`: a second call for a finding this route already
/// promoted returns the original `case_id` with `created: false` and publishes
/// nothing. The replay scan is bounded by the same window B3r reads.
pub fn mint_incident(
    state: &IngestState,
    request: IncidentMintRequest,
    now_ms: i64,
) -> Result<IncidentMintResponse, PerchOpsError> {
    if request.strategy_id.trim().is_empty() {
        return Err(PerchOpsError::BadRequest(
            "strategy_id must be non-empty; `unknown` would collapse the tuning bucket".into(),
        ));
    }
    for (name, value) in [
        ("finding_id", &request.finding_id),
        ("hunt_id", &request.hunt_id),
        ("event_id", &request.event_id),
    ] {
        if value.trim().is_empty() {
            return Err(PerchOpsError::BadRequest(format!(
                "{name} must be non-empty"
            )));
        }
    }
    let store = state.current_incident_store();
    // Idempotency on the finding: the console supplies no case_id (W3-14), so a
    // replay is "an incident this route already minted for this finding".
    let window = {
        let stack = state.stack.load_full();
        stack.service.config.audit.recent_decisions_limit.max(200)
    };
    if let Some(existing) = store.recent(window)?.into_iter().find(|record| {
        record.incident_id.starts_with(PERCH_CASE_INCIDENT_PREFIX)
            && record.trigger_finding_id.as_deref() == Some(request.finding_id.as_str())
    }) {
        let case_id = existing.incident_id[PERCH_CASE_INCIDENT_PREFIX.len()..].to_string();
        let degraded = degraded_for(&existing.correlation_keys);
        return Ok(IncidentMintResponse {
            schema_version: 1,
            incident_id: existing.incident_id.clone(),
            case_id,
            created: false,
            degraded,
            record: existing,
        });
    }

    let case_id = uuid::Uuid::new_v4().to_string();
    let incident_id = format!("{PERCH_CASE_INCIDENT_PREFIX}{case_id}");
    let mut correlation_keys = request.correlation_keys.clone();
    if let Some(host) = request
        .host_id
        .as_deref()
        .map(str::trim)
        .filter(|host| !host.is_empty())
    {
        correlation_keys.push(format!("host:{host}"));
    }
    let strategy_id = request.strategy_id.trim().to_string();
    // The seed member mirrors `CorrelationEngine::assemble_incident_at`'s, with
    // an honest reason: nothing was inferred, an operator said so.
    let member = IncidentMemberDecision {
        investigation_id: format!("perch-promotion:{}", sanitize_id(&request.finding_id)),
        hunt_id: request.hunt_id.clone(),
        finding_id: request.finding_id.clone(),
        reason: "promoted by operator".into(),
        shared_keys: correlation_keys.clone(),
        evidence_links: Vec::new(),
        confidence_score: 1.0,
    };
    let incident = CorrelatedIncident {
        incident_id: incident_id.clone(),
        summary: request.summary.clone(),
        created_at_ms: request.created_at_ms,
        window_start_ms: request.created_at_ms,
        window_end_ms: request.created_at_ms,
        correlation_keys: correlation_keys.clone(),
        related_receipt_ids: Vec::new(),
        included_members: vec![member],
        rejected_members: Vec::new(),
        graph_dimensions: Vec::new(),
        confidence_score: 1.0,
        trigger_event_id: Some(request.event_id.clone()),
        trigger_finding_id: Some(request.finding_id.clone()),
        trigger_strategy_id: Some(strategy_id),
        threat_class: Some(request.threat_class.clone()),
        severity: Some(request.severity),
        external_references: Vec::new(),
        providence_reconciliation: None,
        providence_callback_audit_entries: Vec::new(),
        feedback_audit_entries: Vec::new(),
        false_positive_measurements: Vec::new(),
    };
    let record = store.persist(&incident)?;
    // The event goes out AFTER the record commits: the bridge creates the
    // channel the record already names.
    state.publish_runtime_event(RuntimeEvent::CasePromoted {
        emitted_at_ms: now_ms,
        hunt_id: request.hunt_id,
        case_id: case_id.clone(),
        clause: CasePromotionClause::Manual,
        incident_id: incident_id.clone(),
        finding_id: request.finding_id,
        threat_class: request.threat_class,
        severity: request.severity,
        summary: request.summary,
    });
    Ok(IncidentMintResponse {
        schema_version: 1,
        incident_id,
        case_id,
        created: true,
        degraded: degraded_for(&correlation_keys),
        record,
    })
}

/// `host_exclusion_unreachable` when no `host:` key reaches the feedback target.
fn degraded_for(keys: &[String]) -> Vec<String> {
    if keys.iter().any(|key| key.starts_with("host:")) {
        Vec::new()
    } else {
        vec![DEGRADED_HOST_EXCLUSION_UNREACHABLE.to_string()]
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::PerchOpsError;
    use super::super::test_support::{mint_request as request, test_state};
    use super::{IncidentMintRequest, PERCH_CASE_INCIDENT_PREFIX, mint_incident};
    use swarm_core::ThreatClass;
    use swarm_core::types::Severity;
    use swarm_runtime::runtime_events::{CasePromotionClause, RuntimeEvent};
    use swarm_spine::IncidentStore;

    #[test]
    fn a_mint_satisfies_the_feedback_target_contract_and_emits_case_promoted() {
        let state = test_state();
        let mut rx = state.subscribe_runtime_events().unwrap();
        let out = mint_incident(
            &state,
            request("f-1", Some("host-ops-1")),
            1_700_000_001_000,
        )
        .unwrap();
        assert!(out.created);
        assert_eq!(out.schema_version, 1);
        assert!(out.incident_id.starts_with(PERCH_CASE_INCIDENT_PREFIX));
        assert_eq!(
            out.incident_id,
            format!("{PERCH_CASE_INCIDENT_PREFIX}{}", out.case_id)
        );
        assert!(uuid::Uuid::parse_str(&out.case_id).is_ok());
        assert!(out.degraded.is_empty());
        assert_eq!(out.record.incident_id, out.incident_id);
        assert_eq!(
            out.record.trigger_strategy_id.as_deref(),
            Some("suspicious_process_tree")
        );
        assert_eq!(out.record.included_hunt_ids, vec!["hunt-evt-1".to_string()]);

        let lookup = state
            .current_incident_store()
            .load_by_incident_id(&out.incident_id)
            .unwrap()
            .unwrap();
        let target =
            swarm_runtime::providence::resolve_feedback_target(&lookup, Some("f-1")).unwrap();
        assert_eq!(
            target.strategy_id.as_deref(),
            Some("suspicious_process_tree")
        );
        assert_eq!(target.host_id.as_deref(), Some("host-ops-1"));
        assert_eq!(target.threat_class, ThreatClass::Execution);
        assert_eq!(target.severity, Severity::High);
        assert_eq!(target.event_id, "hunt-evt-1");
        assert_eq!(lookup.incident.included_members.len(), 1);
        assert_eq!(
            lookup.incident.included_members[0].reason,
            "promoted by operator"
        );
        assert_eq!(lookup.incident.window_start_ms, 1_700_000_000_000);
        assert_eq!(lookup.incident.window_end_ms, 1_700_000_000_000);

        match rx.try_recv().unwrap() {
            RuntimeEvent::CasePromoted {
                emitted_at_ms,
                hunt_id,
                case_id,
                clause,
                incident_id,
                finding_id,
                threat_class,
                severity,
                summary,
            } => {
                assert_eq!(emitted_at_ms, 1_700_000_001_000);
                assert_eq!(hunt_id, "hunt-evt-1");
                assert_eq!(case_id, out.case_id);
                assert_eq!(clause, CasePromotionClause::Manual);
                assert_eq!(incident_id, out.incident_id);
                assert_eq!(finding_id, "f-1");
                assert_eq!(threat_class, ThreatClass::Execution);
                assert_eq!(severity, Severity::High);
                assert_eq!(summary, "Office-spawned encoded PowerShell");
            }
            other => panic!("expected CasePromoted, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "exactly one event per mint");
    }

    #[test]
    fn a_second_mint_for_the_same_finding_replays_and_emits_nothing() {
        let state = test_state();
        let first = mint_incident(&state, request("f-1", Some("h")), 1).unwrap();
        let mut rx = state.subscribe_runtime_events().unwrap();
        let second = mint_incident(&state, request("f-1", Some("h")), 2).unwrap();
        assert!(!second.created);
        assert_eq!(second.case_id, first.case_id);
        assert_eq!(second.incident_id, first.incident_id);
        assert!(second.degraded.is_empty());
        assert!(rx.try_recv().is_err(), "a replay must not re-promote");
        assert_eq!(
            state.current_incident_store().recent(10).unwrap().len(),
            1,
            "a replay persists nothing new"
        );

        // A different finding on the same hunt is a different case.
        let third = mint_incident(&state, request("f-2", Some("h")), 3).unwrap();
        assert!(third.created);
        assert_ne!(third.case_id, first.case_id);
    }

    #[test]
    fn an_empty_strategy_id_is_refused_and_a_missing_host_is_named_as_degraded() {
        let state = test_state();
        let mut rx = state.subscribe_runtime_events().unwrap();
        let mut bad = request("f-2", Some("h"));
        bad.strategy_id = "  ".into();
        assert!(matches!(
            mint_incident(&state, bad, 1).unwrap_err(),
            PerchOpsError::BadRequest(_)
        ));
        for field in ["finding_id", "hunt_id", "event_id"] {
            let mut bad = request("f-2", Some("h"));
            match field {
                "finding_id" => bad.finding_id = String::new(),
                "hunt_id" => bad.hunt_id = " ".into(),
                _ => bad.event_id = String::new(),
            }
            let error = mint_incident(&state, bad, 1).unwrap_err();
            assert!(
                matches!(&error, PerchOpsError::BadRequest(message) if message.contains(field)),
                "{field}: {error}"
            );
        }
        assert!(rx.try_recv().is_err(), "a refused mint emits nothing");
        assert!(
            state
                .current_incident_store()
                .recent(10)
                .unwrap()
                .is_empty(),
            "a refused mint persists nothing"
        );

        let out = mint_incident(&state, request("f-3", None), 1).unwrap();
        assert_eq!(out.degraded, vec!["host_exclusion_unreachable".to_string()]);
        let blank_host = mint_incident(
            &state,
            {
                let mut r = request("f-4", Some("   "));
                r.correlation_keys = vec!["user:alice".into()];
                r
            },
            1,
        )
        .unwrap();
        assert_eq!(
            blank_host.degraded,
            vec!["host_exclusion_unreachable".to_string()],
            "a blank host id is no host id"
        );
        assert_eq!(
            blank_host.record.correlation_keys,
            vec!["user:alice".to_string()]
        );
    }

    #[test]
    fn a_host_reaches_the_feedback_target_through_the_correlation_key() {
        let state = test_state();
        let out = mint_incident(&state, request("f-5", Some("host-9")), 1).unwrap();
        assert!(
            out.record
                .correlation_keys
                .contains(&"host:host-9".to_string())
        );
        let lookup = state
            .current_incident_store()
            .load_by_incident_id(&out.incident_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            lookup.incident.included_members[0].shared_keys,
            vec!["host:host-9".to_string()]
        );
    }

    #[test]
    fn the_minted_id_cannot_collide_with_the_correlation_engines_scheme() {
        // correlation.rs mints `incident:{hunt_id}:{created_at_ms}`; the second
        // segment here is the literal `perch-case`, which no hunt id is.
        assert!(!"incident:perch-case:x".starts_with("incident:hunt"));
        let id = format!("{PERCH_CASE_INCIDENT_PREFIX}{}", uuid::Uuid::nil());
        assert_eq!(id.split(':').nth(1), Some("perch-case"));
        assert_eq!(id.split(':').count(), 3);
    }

    #[test]
    fn the_request_body_carries_no_case_id() {
        // W3-14: the daemon mints case_id; the console never supplies one.
        let mut value = serde_json::to_value(request("f-1", Some("h"))).unwrap();
        assert!(serde_json::from_value::<IncidentMintRequest>(value.clone()).is_ok());
        value["case_id"] = serde_json::json!("9499a6e2-8872-453b-80d9-dafc6fc7fc69");
        assert!(serde_json::from_value::<IncidentMintRequest>(value).is_err());
    }
}
