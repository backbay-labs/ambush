use std::time::{SystemTime, UNIX_EPOCH};

use swarm_core::config::CorrelationConfig;
use swarm_spine::{
    CorrelatedIncident, IncidentLookup, IncidentMemberDecision, IncidentRecord, IncidentStore,
    IncidentStoreError, InvestigationBundle, InvestigationBundleStore, InvestigationStatus,
    InvestigationStoreError,
};

/// Errors raised while assembling or loading incidents.
#[derive(Debug, thiserror::Error)]
pub enum CorrelationError {
    #[error(transparent)]
    InvestigationStore(#[from] InvestigationStoreError),

    #[error(transparent)]
    IncidentStore(#[from] IncidentStoreError),
}

/// Persisted outcome of one incident-assembly run.
#[derive(Debug, Clone)]
pub struct CorrelationOutcome {
    pub record: IncidentRecord,
    pub incident: CorrelatedIncident,
}

/// Deterministic rule-based correlation engine for phase 9.
#[derive(Debug, Clone)]
pub struct CorrelationEngine {
    config: CorrelationConfig,
}

impl CorrelationEngine {
    pub fn new(config: CorrelationConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &CorrelationConfig {
        &self.config
    }

    pub fn correlate_hunt<Investigations, Incidents>(
        &self,
        investigations: &Investigations,
        incidents: &Incidents,
        hunt_id: &str,
    ) -> Result<Option<CorrelationOutcome>, CorrelationError>
    where
        Investigations: InvestigationBundleStore,
        Incidents: IncidentStore,
    {
        if !self.config.enabled {
            return Ok(None);
        }

        let Some(seed_lookup) = investigations.load_by_hunt_id(hunt_id)? else {
            return Ok(None);
        };
        let recent_records = investigations.recent(self.config.candidate_limit)?;
        let mut candidates = Vec::new();
        for record in recent_records {
            let Some(lookup) = investigations.load_by_investigation_id(&record.investigation_id)?
            else {
                continue;
            };
            candidates.push(lookup.bundle);
        }

        let incident = self.assemble_incident(&seed_lookup.bundle, &candidates);
        let record = incidents.persist(&incident)?;
        Ok(Some(CorrelationOutcome { record, incident }))
    }

    pub fn load_incident_by_hunt_id<Incidents>(
        &self,
        incidents: &Incidents,
        hunt_id: &str,
    ) -> Result<Option<IncidentLookup>, CorrelationError>
    where
        Incidents: IncidentStore,
    {
        Ok(incidents.load_by_hunt_id(hunt_id)?)
    }

    fn assemble_incident(
        &self,
        seed: &InvestigationBundle,
        candidates: &[InvestigationBundle],
    ) -> CorrelatedIncident {
        let mut included = vec![IncidentMemberDecision {
            investigation_id: seed.investigation_id.clone(),
            hunt_id: seed.hunt_id.clone(),
            finding_id: seed.finding_id.clone(),
            reason: "seed investigation".to_string(),
            shared_keys: seed.correlation_keys.clone(),
        }];
        let mut rejected = Vec::new();
        let mut related_receipt_ids = seed.related_receipt_ids.clone();
        let mut correlation_keys = seed.correlation_keys.clone();
        let mut window_start_ms = seed.queued_at_ms;
        let mut window_end_ms = seed.last_updated_ms();

        for candidate in candidates {
            if candidate.investigation_id == seed.investigation_id {
                continue;
            }

            let shared_keys = shared_keys(seed, candidate);
            let time_delta_ms = (candidate.last_updated_ms() - seed.last_updated_ms()).abs();

            let decision = if candidate.status != InvestigationStatus::Completed {
                Err("investigation not completed".to_string())
            } else if shared_keys.len() < self.config.min_shared_keys {
                Err("insufficient shared correlation keys".to_string())
            } else if time_delta_ms > self.config.time_window_ms {
                Err("outside correlation time window".to_string())
            } else {
                Ok(format!(
                    "shared {} within correlation window",
                    shared_keys.join(", ")
                ))
            };

            match decision {
                Ok(reason) => {
                    window_start_ms = window_start_ms.min(candidate.queued_at_ms);
                    window_end_ms = window_end_ms.max(candidate.last_updated_ms());
                    let new_correlation_keys = shared_keys
                        .iter()
                        .filter(|key| !correlation_keys.iter().any(|existing| existing == *key))
                        .cloned()
                        .collect::<Vec<_>>();
                    correlation_keys.extend(new_correlation_keys);
                    let new_receipt_ids = candidate
                        .related_receipt_ids
                        .iter()
                        .filter(|id| !related_receipt_ids.iter().any(|existing| existing == *id))
                        .cloned()
                        .collect::<Vec<_>>();
                    related_receipt_ids.extend(new_receipt_ids);
                    included.push(IncidentMemberDecision {
                        investigation_id: candidate.investigation_id.clone(),
                        hunt_id: candidate.hunt_id.clone(),
                        finding_id: candidate.finding_id.clone(),
                        reason,
                        shared_keys,
                    });
                }
                Err(reason) => rejected.push(IncidentMemberDecision {
                    investigation_id: candidate.investigation_id.clone(),
                    hunt_id: candidate.hunt_id.clone(),
                    finding_id: candidate.finding_id.clone(),
                    reason,
                    shared_keys,
                }),
            }
        }

        let created_at_ms = now_ms();
        let summary = summarize_incident(seed, &included, &correlation_keys);

        CorrelatedIncident {
            incident_id: format!("incident:{}:{created_at_ms}", seed.hunt_id),
            summary,
            created_at_ms,
            window_start_ms,
            window_end_ms,
            correlation_keys,
            related_receipt_ids,
            included_members: included,
            rejected_members: rejected,
        }
    }
}

fn shared_keys(seed: &InvestigationBundle, candidate: &InvestigationBundle) -> Vec<String> {
    let mut shared = seed
        .correlation_keys
        .iter()
        .filter(|key| {
            candidate
                .correlation_keys
                .iter()
                .any(|candidate_key| candidate_key == *key)
        })
        .cloned()
        .collect::<Vec<_>>();
    shared.sort();
    shared.dedup();
    shared
}

fn summarize_incident(
    seed: &InvestigationBundle,
    included: &[IncidentMemberDecision],
    correlation_keys: &[String],
) -> String {
    let key_summary = if correlation_keys.is_empty() {
        "no shared keys".to_string()
    } else {
        correlation_keys
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "incident seeded from {} grouped {} investigation(s) via {}",
        seed.hunt_id,
        included.len(),
        key_summary
    )
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::CorrelationEngine;
    use swarm_core::config::{BundleStoreConfig, CorrelationConfig};
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::Severity;
    use swarm_spine::{
        IncidentStore, InvestigationBundle, InvestigationBundleStore, InvestigationStatus,
        MemoryIncidentStore, MemoryInvestigationBundleStore,
    };

    fn config() -> CorrelationConfig {
        CorrelationConfig {
            enabled: true,
            time_window_ms: 5_000,
            min_shared_keys: 1,
            candidate_limit: 16,
            incident_store: BundleStoreConfig::Memory,
        }
    }

    fn investigation(
        investigation_id: &str,
        hunt_id: &str,
        queued_at_ms: i64,
        correlation_keys: &[&str],
        status: InvestigationStatus,
    ) -> InvestigationBundle {
        InvestigationBundle {
            investigation_id: investigation_id.to_string(),
            source_bundle_id: format!("bundle:{hunt_id}:1"),
            hunt_id: hunt_id.to_string(),
            trail_id: format!("trail:{hunt_id}:1"),
            event_id: format!("evt:{hunt_id}"),
            finding_id: format!("finding:{hunt_id}"),
            threat_class: ThreatClass::Execution,
            severity: Severity::Critical,
            strategy_id: "summary_investigator".to_string(),
            response_kind: "success".to_string(),
            related_receipt_ids: vec![format!("receipt:{hunt_id}")],
            host_id: Some("host-1".to_string()),
            user: Some("alice".to_string()),
            process_name: Some("powershell".to_string()),
            queued_at_ms,
            started_at_ms: Some(queued_at_ms + 10),
            completed_at_ms: Some(queued_at_ms + 100),
            status,
            summary: Some(format!("summary for {hunt_id}")),
            evidence_points: vec!["host_id=host-1".to_string()],
            correlation_keys: correlation_keys.iter().map(|key| key.to_string()).collect(),
            failure_reason: None,
        }
    }

    #[test]
    fn correlate_hunt_includes_matching_candidates_and_rejects_others() {
        let investigations = MemoryInvestigationBundleStore::default();
        let incidents = MemoryIncidentStore::default();
        let engine = CorrelationEngine::new(config());

        let seed = investigation(
            "investigation:hunt-1:1",
            "hunt-1",
            1_700_000_000_000,
            &["host:host-1", "user:alice", "strategy:summary"],
            InvestigationStatus::Completed,
        );
        let related = investigation(
            "investigation:hunt-2:1",
            "hunt-2",
            1_700_000_003_000,
            &["host:host-1", "user:alice"],
            InvestigationStatus::Completed,
        );
        let outside_window = investigation(
            "investigation:hunt-3:1",
            "hunt-3",
            1_700_000_010_500,
            &["host:host-1"],
            InvestigationStatus::Completed,
        );

        investigations.persist(&seed).unwrap();
        investigations.persist(&related).unwrap();
        investigations.persist(&outside_window).unwrap();

        let outcome = engine
            .correlate_hunt(&investigations, &incidents, "hunt-1")
            .unwrap()
            .unwrap();

        assert_eq!(outcome.incident.included_members.len(), 2);
        assert_eq!(outcome.incident.rejected_members.len(), 1);
        assert!(
            outcome
                .incident
                .rejected_members
                .first()
                .unwrap()
                .reason
                .contains("outside correlation time window")
        );

        let loaded = incidents.load_by_hunt_id("hunt-2").unwrap().unwrap();
        assert_eq!(loaded.incident.incident_id, outcome.incident.incident_id);
    }
}
