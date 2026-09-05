//! The read behind the case canvas's kill-chain figure and the tuning bench's
//! provenance: one correlated incident, with the members the correlation
//! joined, the members it refused with their reasons, the evidence links
//! between them, and every false-positive measurement recorded against it.
//!
//! `GET /v2/api/incidents` serves a summary with none of that (W3-42, W3-43);
//! this is the read the console needs, on the operator surface it already
//! authenticates to.

use serde::Serialize;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;
use swarm_spine::{IncidentGraphDimension, IncidentLookup, IncidentMemberDecision, IncidentStore};

use super::PerchOpsError;
use super::mint::PERCH_CASE_INCIDENT_PREFIX;
use crate::ingest::IngestState;

/// One evidence link a member decision rests on.
#[derive(Debug, Clone, Serialize)]
pub struct PerchIncidentEvidenceLink {
    pub dimension: IncidentGraphDimension,
    pub explanation: String,
    pub shared_values: Vec<String>,
    pub weight: usize,
}

/// One member decision — included or rejected — as the figure draws it.
#[derive(Debug, Clone, Serialize)]
pub struct PerchIncidentMember {
    pub finding_id: String,
    pub hunt_id: String,
    pub investigation_id: String,
    /// The correlation's own words for why this member was joined or refused.
    pub reason: String,
    pub confidence_score: f64,
    /// From the member's shared keys (`host:…`), else the record's correlation
    /// keys — the same derivation the feedback target uses. `None` when
    /// neither names a host.
    pub host_id: Option<String>,
    /// The incident's trigger strategy, which is what the feedback target
    /// reports for every member; per-member strategies are not recorded.
    pub strategy_id: Option<String>,
    pub shared_keys: Vec<String>,
    pub evidence_links: Vec<PerchIncidentEvidenceLink>,
}

/// The whole read.
#[derive(Debug, Clone, Serialize)]
pub struct PerchIncidentRead {
    pub schema_version: u32,
    pub incident_id: String,
    /// The case channel this incident was minted for, when it was (`incident:perch-case:<case>`).
    pub case_id: Option<String>,
    pub summary: String,
    pub created_at_ms: i64,
    pub window_start_ms: i64,
    pub window_end_ms: i64,
    pub trigger_finding_id: Option<String>,
    pub trigger_strategy_id: Option<String>,
    pub threat_class: Option<ThreatClass>,
    pub severity: Option<Severity>,
    pub confidence_score: f64,
    pub graph_dimensions: Vec<IncidentGraphDimension>,
    pub correlation_keys: Vec<String>,
    pub included_members: Vec<PerchIncidentMember>,
    pub rejected_members: Vec<PerchIncidentMember>,
    /// Every measurement recorded against this incident, as persisted.
    pub false_positive_measurements: Vec<serde_json::Value>,
}

fn host_from_keys(keys: &[String]) -> Option<String> {
    keys.iter()
        .find_map(|key| key.strip_prefix("host:").map(ToString::to_string))
}

fn member_view(member: &IncidentMemberDecision, lookup: &IncidentLookup) -> PerchIncidentMember {
    PerchIncidentMember {
        finding_id: member.finding_id.clone(),
        hunt_id: member.hunt_id.clone(),
        investigation_id: member.investigation_id.clone(),
        reason: member.reason.clone(),
        confidence_score: member.confidence_score,
        host_id: host_from_keys(&member.shared_keys)
            .or_else(|| host_from_keys(&lookup.record.correlation_keys)),
        strategy_id: lookup.record.trigger_strategy_id.clone(),
        shared_keys: member.shared_keys.clone(),
        evidence_links: member
            .evidence_links
            .iter()
            .map(|link| PerchIncidentEvidenceLink {
                dimension: link.dimension.clone(),
                explanation: link.explanation.clone(),
                shared_values: link.shared_values.clone(),
                weight: link.weight,
            })
            .collect(),
    }
}

/// `Ok(None)` when the store has no such incident; a bad id is a `BadRequest`.
pub fn read_incident(
    state: &IngestState,
    incident_id: &str,
) -> Result<Option<PerchIncidentRead>, PerchOpsError> {
    if incident_id.is_empty() || incident_id.contains(['/', '?', '#']) {
        return Err(PerchOpsError::BadRequest(
            "incident_id must be a bare incident id".to_string(),
        ));
    }
    let Some(lookup) = state
        .current_incident_store()
        .load_by_incident_id(incident_id)
        .map_err(|error| PerchOpsError::Internal(error.to_string()))?
    else {
        return Ok(None);
    };
    let incident = &lookup.incident;
    let record = &lookup.record;
    Ok(Some(PerchIncidentRead {
        schema_version: 1,
        incident_id: record.incident_id.clone(),
        case_id: record
            .incident_id
            .strip_prefix(PERCH_CASE_INCIDENT_PREFIX)
            .map(ToString::to_string),
        summary: record.summary.clone(),
        created_at_ms: record.created_at_ms,
        window_start_ms: incident.window_start_ms,
        window_end_ms: incident.window_end_ms,
        trigger_finding_id: record.trigger_finding_id.clone(),
        trigger_strategy_id: record.trigger_strategy_id.clone(),
        threat_class: record.threat_class.clone(),
        severity: record.severity,
        confidence_score: incident.confidence_score,
        graph_dimensions: incident.graph_dimensions.clone(),
        correlation_keys: record.correlation_keys.clone(),
        included_members: incident
            .included_members
            .iter()
            .map(|member| member_view(member, &lookup))
            .collect(),
        rejected_members: incident
            .rejected_members
            .iter()
            .map(|member| member_view(member, &lookup))
            .collect(),
        false_positive_measurements: record
            .false_positive_measurements
            .iter()
            .filter_map(|measurement| serde_json::to_value(measurement).ok())
            .collect(),
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::mint::mint_incident;
    use super::super::test_support::{mint_request, test_state};
    use super::{PerchOpsError, read_incident};

    #[test]
    fn a_minted_incident_reads_back_with_its_members_and_their_host() {
        let state = test_state();
        let out = mint_incident(
            &state,
            mint_request("f-1", Some("host-ops-1")),
            1_700_000_001_000,
        )
        .unwrap();
        let read = read_incident(&state, &out.incident_id)
            .unwrap()
            .expect("the incident just minted");
        assert_eq!(read.incident_id, out.incident_id);
        assert_eq!(read.case_id.as_deref(), Some(out.case_id.as_str()));
        assert_eq!(
            read.trigger_strategy_id.as_deref(),
            Some("suspicious_process_tree")
        );
        assert!(
            !read.included_members.is_empty(),
            "the trigger finding is a member"
        );
        let member = &read.included_members[0];
        assert_eq!(member.finding_id, "f-1");
        assert_eq!(member.host_id.as_deref(), Some("host-ops-1"));
        assert_eq!(
            member.strategy_id.as_deref(),
            Some("suspicious_process_tree")
        );
        assert!(
            !member.reason.is_empty(),
            "a member carries the correlation's reason"
        );
        // The rejected half is a list, never an absence: an empty list means
        // the correlation refused nothing, which is a fact about this incident.
        assert!(read.rejected_members.is_empty());
    }

    #[test]
    fn an_unknown_incident_is_none_and_a_bad_id_is_refused() {
        let state = test_state();
        assert!(
            read_incident(&state, "incident:perch-case:nope")
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            read_incident(&state, "a/b"),
            Err(PerchOpsError::BadRequest(_))
        ));
        assert!(matches!(
            read_incident(&state, ""),
            Err(PerchOpsError::BadRequest(_))
        ));
    }
}
