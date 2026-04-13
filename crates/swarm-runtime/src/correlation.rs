use std::time::{SystemTime, UNIX_EPOCH};

use swarm_core::config::CorrelationConfig;
use swarm_spine::{
    CorrelatedIncident, IncidentEvidenceLink, IncidentGraphDimension, IncidentLookup,
    IncidentMemberDecision, IncidentRecord, IncidentStore, IncidentStoreError, InvestigationBundle,
    InvestigationBundleStore, InvestigationStatus, InvestigationStoreError,
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

const STRATEGY_KEY_PREFIX: &str = "strategy:";

#[derive(Debug, Clone, PartialEq)]
struct CandidatePairScore {
    shared_keys: Vec<String>,
    cross_strategy: bool,
    weighted_score: usize,
    evidence_links: Vec<IncidentEvidenceLink>,
    confidence_score: f64,
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
        self.correlate_hunt_at(investigations, incidents, hunt_id, now_ms())
    }

    pub fn correlate_hunt_at<Investigations, Incidents>(
        &self,
        investigations: &Investigations,
        incidents: &Incidents,
        hunt_id: &str,
        created_at_ms: i64,
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

        let incident = self.assemble_incident_at(&seed_lookup.bundle, &candidates, created_at_ms);
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

    fn assemble_incident_at(
        &self,
        seed: &InvestigationBundle,
        candidates: &[InvestigationBundle],
        created_at_ms: i64,
    ) -> CorrelatedIncident {
        let mut included = vec![IncidentMemberDecision {
            investigation_id: seed.investigation_id.clone(),
            hunt_id: seed.hunt_id.clone(),
            finding_id: seed.finding_id.clone(),
            reason: "seed investigation".to_string(),
            shared_keys: seed.correlation_keys.clone(),
            evidence_links: Vec::new(),
            confidence_score: 1.0,
        }];
        let mut rejected = Vec::new();
        let mut related_receipt_ids = seed.related_receipt_ids.clone();
        let mut correlation_keys = seed.correlation_keys.clone();
        let mut window_start_ms = seed.queued_at_ms;
        let mut window_end_ms = seed.last_updated_ms();
        let mut graph_dimensions = Vec::new();
        let mut confidence_total = 0.35_f64;

        for candidate in candidates {
            if candidate.investigation_id == seed.investigation_id {
                continue;
            }

            let time_delta_ms = (candidate.last_updated_ms() - seed.last_updated_ms()).abs();
            let pair_score =
                weighted_score(seed, candidate, self.config.time_window_ms, time_delta_ms);

            let decision = if candidate.status != InvestigationStatus::Completed {
                Err("investigation not completed".to_string())
            } else if time_delta_ms > self.config.time_window_ms {
                Err("outside correlation time window".to_string())
            } else if supporting_weight(&pair_score) == 0 {
                Err(no_supporting_evidence_reason(&pair_score))
            } else if pair_score.weighted_score < self.config.min_shared_keys {
                Err(insufficient_weighted_score_reason(
                    &pair_score,
                    self.config.min_shared_keys,
                ))
            } else {
                Ok(included_reason(&pair_score))
            };

            match decision {
                Ok(reason) => {
                    window_start_ms = window_start_ms.min(candidate.queued_at_ms);
                    window_end_ms = window_end_ms.max(candidate.last_updated_ms());
                    let new_correlation_keys = pair_score
                        .shared_keys
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
                    let new_dimensions = pair_score
                        .evidence_links
                        .iter()
                        .map(|link| link.dimension.clone())
                        .filter(|dimension| !graph_dimensions.contains(dimension))
                        .collect::<Vec<_>>();
                    graph_dimensions.extend(new_dimensions);
                    confidence_total += pair_score.confidence_score;
                    included.push(IncidentMemberDecision {
                        investigation_id: candidate.investigation_id.clone(),
                        hunt_id: candidate.hunt_id.clone(),
                        finding_id: candidate.finding_id.clone(),
                        reason,
                        shared_keys: pair_score.shared_keys,
                        evidence_links: pair_score.evidence_links,
                        confidence_score: pair_score.confidence_score,
                    });
                }
                Err(reason) => rejected.push(IncidentMemberDecision {
                    investigation_id: candidate.investigation_id.clone(),
                    hunt_id: candidate.hunt_id.clone(),
                    finding_id: candidate.finding_id.clone(),
                    reason,
                    shared_keys: pair_score.shared_keys,
                    evidence_links: pair_score.evidence_links,
                    confidence_score: pair_score.confidence_score,
                }),
            }
        }

        graph_dimensions.sort();
        graph_dimensions.dedup();
        let confidence_score = (confidence_total / included.len() as f64).clamp(0.0, 1.0);
        let summary = summarize_incident(seed, &included, &correlation_keys, &graph_dimensions);

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
            graph_dimensions,
            confidence_score,
            trigger_event_id: Some(seed.event_id.clone()),
            trigger_finding_id: Some(seed.finding_id.clone()),
            trigger_strategy_id: Some(seed.strategy_id.clone()),
            threat_class: Some(seed.threat_class.clone()),
            severity: Some(seed.severity),
            external_references: Vec::new(),
            providence_reconciliation: None,
            providence_callback_audit_entries: Vec::new(),
            feedback_audit_entries: Vec::new(),
            false_positive_measurements: Vec::new(),
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

fn weighted_score(
    seed: &InvestigationBundle,
    candidate: &InvestigationBundle,
    time_window_ms: i64,
    time_delta_ms: i64,
) -> CandidatePairScore {
    let shared_keys = shared_keys(seed, candidate);
    let cross_strategy = seed.strategy_id != candidate.strategy_id;
    let mut evidence_links = Vec::new();

    let entity_keys = shared_keys
        .iter()
        .filter(|key| is_entity_key(key))
        .cloned()
        .collect::<Vec<_>>();
    if !entity_keys.is_empty() {
        evidence_links.push(IncidentEvidenceLink {
            dimension: IncidentGraphDimension::Entity,
            explanation: format!(
                "shared entity context via {}",
                shared_keys_summary(&entity_keys)
            ),
            shared_values: entity_keys.clone(),
            weight: entity_keys.len(),
        });
    }

    let mut causal_values = shared_receipts(seed, candidate);
    if seed.trail_id == candidate.trail_id {
        causal_values.push(format!("trail:{}", seed.trail_id));
    }
    causal_values.sort();
    causal_values.dedup();
    if !causal_values.is_empty() {
        evidence_links.push(IncidentEvidenceLink {
            dimension: IncidentGraphDimension::Causal,
            explanation: format!(
                "shared causal lineage through {}",
                shared_keys_summary(&causal_values)
            ),
            shared_values: causal_values.clone(),
            weight: causal_values.len(),
        });
    }

    let semantic_values = semantic_values(seed, candidate, cross_strategy);
    if !semantic_values.is_empty() {
        evidence_links.push(IncidentEvidenceLink {
            dimension: IncidentGraphDimension::Semantic,
            explanation: format!(
                "shared semantic context through {}",
                shared_keys_summary(&semantic_values)
            ),
            shared_values: semantic_values.clone(),
            weight: semantic_values.len(),
        });
    }

    if time_delta_ms <= time_window_ms {
        evidence_links.push(IncidentEvidenceLink {
            dimension: IncidentGraphDimension::Temporal,
            explanation: format!(
                "completed {} ms apart within the {} ms correlation window",
                time_delta_ms, time_window_ms
            ),
            shared_values: vec![format!("delta_ms:{time_delta_ms}")],
            weight: 1,
        });
    }

    let weighted_score = evidence_links.iter().map(|link| link.weight).sum::<usize>();
    let non_temporal_links = evidence_links
        .iter()
        .filter(|link| link.dimension != IncidentGraphDimension::Temporal)
        .count();
    let confidence_score = if non_temporal_links == 0 {
        0.0
    } else {
        (0.35 + (evidence_links.len() as f64 * 0.15) + (shared_keys.len() as f64 * 0.05)).min(0.99)
    };

    CandidatePairScore {
        shared_keys,
        cross_strategy,
        weighted_score,
        evidence_links,
        confidence_score,
    }
}

fn shared_receipts(seed: &InvestigationBundle, candidate: &InvestigationBundle) -> Vec<String> {
    let mut shared = seed
        .related_receipt_ids
        .iter()
        .filter(|id| {
            candidate
                .related_receipt_ids
                .iter()
                .any(|candidate_id| candidate_id == *id)
        })
        .cloned()
        .collect::<Vec<_>>();
    shared.sort();
    shared.dedup();
    shared
}

fn semantic_values(
    seed: &InvestigationBundle,
    candidate: &InvestigationBundle,
    cross_strategy: bool,
) -> Vec<String> {
    let mut values = Vec::new();
    if seed.threat_class == candidate.threat_class {
        values.push(format!("threat:{:?}", seed.threat_class).to_ascii_lowercase());
    }
    if seed.process_name == candidate.process_name
        && let Some(process_name) = &seed.process_name
    {
        values.push(format!("process:{process_name}"));
    }
    if seed.response_kind == candidate.response_kind {
        values.push(format!("response:{}", seed.response_kind));
    }
    let summary_terms = shared_summary_terms(seed.summary.as_deref(), candidate.summary.as_deref());
    values.extend(
        summary_terms
            .into_iter()
            .map(|term| format!("summary:{term}")),
    );
    if cross_strategy {
        values.push(format!(
            "cross_strategy:{}->{}",
            seed.strategy_id, candidate.strategy_id
        ));
    }
    values.sort();
    values.dedup();
    values
}

fn shared_summary_terms(seed: Option<&str>, candidate: Option<&str>) -> Vec<String> {
    let Some(seed) = seed else {
        return Vec::new();
    };
    let Some(candidate) = candidate else {
        return Vec::new();
    };
    let seed_terms = tokenize_summary(seed);
    let mut shared = tokenize_summary(candidate)
        .into_iter()
        .filter(|term| seed_terms.contains(term))
        .collect::<Vec<_>>();
    shared.sort();
    shared.dedup();
    shared.into_iter().take(3).collect()
}

fn tokenize_summary(summary: &str) -> Vec<String> {
    let mut tokens = summary
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|term| term.len() >= 4)
        .map(|term| term.to_ascii_lowercase())
        .collect::<Vec<_>>();
    tokens.sort();
    tokens.dedup();
    tokens
}

fn is_entity_key(key: &str) -> bool {
    !key.starts_with(STRATEGY_KEY_PREFIX)
        && (key.starts_with("host:")
            || key.starts_with("user:")
            || key.starts_with("process:")
            || key.starts_with("ip:")
            || key.starts_with("domain:")
            || key.starts_with("identity:")
            || key.starts_with("peer_group:"))
}

fn supporting_weight(score: &CandidatePairScore) -> usize {
    score
        .evidence_links
        .iter()
        .filter(|link| {
            matches!(
                link.dimension,
                IncidentGraphDimension::Entity | IncidentGraphDimension::Causal
            )
        })
        .map(|link| link.weight)
        .sum()
}

fn shared_keys_summary(shared_keys: &[String]) -> String {
    if shared_keys.is_empty() {
        "no shared keys".to_string()
    } else {
        shared_keys.join(", ")
    }
}

fn score_breakdown(score: &CandidatePairScore) -> String {
    let breakdown = score
        .evidence_links
        .iter()
        .map(|link| format!("{:?}={}", link.dimension, link.weight).to_ascii_lowercase())
        .collect::<Vec<_>>();
    if breakdown.is_empty() {
        "no graph evidence".to_string()
    } else {
        breakdown.join(", ")
    }
}

fn no_supporting_evidence_reason(score: &CandidatePairScore) -> String {
    if score.cross_strategy {
        format!(
            "requires at least one entity or causal link before semantic evidence can reinforce correlation; {}",
            score_breakdown(score)
        )
    } else {
        format!(
            "requires at least one entity or causal link before semantic evidence can reinforce correlation; shared {}",
            shared_keys_summary(&score.shared_keys)
        )
    }
}

fn insufficient_weighted_score_reason(
    score: &CandidatePairScore,
    min_shared_keys: usize,
) -> String {
    format!(
        "weighted_score={} below threshold {} from shared {} ({})",
        score.weighted_score,
        min_shared_keys,
        shared_keys_summary(&score.shared_keys),
        score_breakdown(score)
    )
}

fn included_reason(score: &CandidatePairScore) -> String {
    let dimensions = score
        .evidence_links
        .iter()
        .map(|link| format!("{:?}", link.dimension).to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "shared {} with weighted_score={} across [{}] ({})",
        shared_keys_summary(&score.shared_keys),
        score.weighted_score,
        dimensions,
        score_breakdown(score)
    )
}

fn summarize_incident(
    seed: &InvestigationBundle,
    included: &[IncidentMemberDecision],
    correlation_keys: &[String],
    graph_dimensions: &[IncidentGraphDimension],
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
    let dimension_summary = if graph_dimensions.is_empty() {
        "seed-only evidence".to_string()
    } else {
        graph_dimensions
            .iter()
            .map(|dimension| format!("{dimension:?}").to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "incident seeded from {} grouped {} investigation(s) via {} across {}",
        seed.hunt_id,
        included.len(),
        key_summary,
        dimension_summary
    )
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
        config_with_min_shared_keys(1)
    }

    fn config_with_min_shared_keys(min_shared_keys: usize) -> CorrelationConfig {
        CorrelationConfig {
            enabled: true,
            time_window_ms: 5_000,
            min_shared_keys,
            candidate_limit: 16,
            incident_store: BundleStoreConfig::Memory,
        }
    }

    fn investigation(
        investigation_id: &str,
        hunt_id: &str,
        queued_at_ms: i64,
        strategy_id: &str,
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
            strategy_id: strategy_id.to_string(),
            response_kind: "success".to_string(),
            related_receipt_ids: vec![format!("receipt:{hunt_id}")],
            host_id: Some("host-1".to_string()),
            user: Some("alice".to_string()),
            process_name: Some("powershell".to_string()),
            queued_at_ms,
            started_at_ms: Some(queued_at_ms + 10),
            completed_at_ms: Some(queued_at_ms + 100),
            status,
            priority: swarm_spine::InvestigationPriority::default(),
            summary: Some(format!("summary for {hunt_id}")),
            evidence_points: vec!["host_id=host-1".to_string()],
            correlation_keys: correlation_keys.iter().map(|key| key.to_string()).collect(),
            candidate_interpretations: Vec::new(),
            vote_lineage: Vec::new(),
            decision: swarm_spine::InvestigationDecision::default(),
            failure_reason: None,
        }
    }

    fn default_investigation(
        investigation_id: &str,
        hunt_id: &str,
        queued_at_ms: i64,
        correlation_keys: &[&str],
        status: InvestigationStatus,
    ) -> InvestigationBundle {
        investigation(
            investigation_id,
            hunt_id,
            queued_at_ms,
            "summary_investigator",
            correlation_keys,
            status,
        )
    }

    #[test]
    fn correlate_hunt_includes_matching_candidates_and_rejects_others() {
        let investigations = MemoryInvestigationBundleStore::default();
        let incidents = MemoryIncidentStore::default();
        let engine = CorrelationEngine::new(config());

        let seed = default_investigation(
            "investigation:hunt-1:1",
            "hunt-1",
            1_700_000_000_000,
            &["host:host-1", "user:alice", "strategy:summary"],
            InvestigationStatus::Completed,
        );
        let related = default_investigation(
            "investigation:hunt-2:1",
            "hunt-2",
            1_700_000_003_000,
            &["host:host-1", "user:alice"],
            InvestigationStatus::Completed,
        );
        let incomplete = default_investigation(
            "investigation:hunt-3:1",
            "hunt-3",
            1_700_000_003_500,
            &["host:host-1", "user:alice"],
            InvestigationStatus::Running,
        );
        let outside_window = default_investigation(
            "investigation:hunt-4:1",
            "hunt-4",
            1_700_000_010_500,
            &["host:host-1"],
            InvestigationStatus::Completed,
        );

        investigations.persist(&seed).unwrap();
        investigations.persist(&related).unwrap();
        investigations.persist(&incomplete).unwrap();
        investigations.persist(&outside_window).unwrap();

        let outcome = engine
            .correlate_hunt(&investigations, &incidents, "hunt-1")
            .unwrap()
            .unwrap();

        assert_eq!(outcome.incident.included_members.len(), 2);
        assert_eq!(outcome.incident.rejected_members.len(), 2);
        assert!(
            outcome
                .incident
                .graph_dimensions
                .contains(&swarm_spine::IncidentGraphDimension::Entity)
        );
        assert!(outcome.incident.confidence_score >= 0.5);
        assert!(
            outcome
                .incident
                .rejected_members
                .iter()
                .find(|member| member.hunt_id == "hunt-4")
                .unwrap()
                .reason
                .contains("outside correlation time window")
        );
        assert_eq!(
            outcome
                .incident
                .rejected_members
                .iter()
                .find(|member| member.hunt_id == "hunt-3")
                .unwrap()
                .reason,
            "investigation not completed"
        );

        let loaded = incidents.load_by_hunt_id("hunt-2").unwrap().unwrap();
        assert_eq!(loaded.incident.incident_id, outcome.incident.incident_id);
    }

    #[test]
    fn cross_strategy_bonus_allows_one_real_overlap_to_meet_threshold() {
        let investigations = MemoryInvestigationBundleStore::default();
        let incidents = MemoryIncidentStore::default();
        let engine = CorrelationEngine::new(config_with_min_shared_keys(2));

        let seed = investigation(
            "investigation:hunt-1:1",
            "hunt-1",
            1_700_000_000_000,
            "summary_investigator",
            &["host:host-1", "strategy:summary_investigator"],
            InvestigationStatus::Completed,
        );
        let related = investigation(
            "investigation:hunt-2:1",
            "hunt-2",
            1_700_000_001_000,
            "dns_exfiltration",
            &["host:host-1", "strategy:dns_exfiltration"],
            InvestigationStatus::Completed,
        );

        investigations.persist(&seed).unwrap();
        investigations.persist(&related).unwrap();

        let outcome = engine
            .correlate_hunt(&investigations, &incidents, "hunt-1")
            .unwrap()
            .unwrap();

        let included = outcome
            .incident
            .included_members
            .iter()
            .find(|member| member.hunt_id == "hunt-2")
            .unwrap();

        assert_eq!(included.shared_keys, vec!["host:host-1".to_string()]);
        assert!(included.reason.contains("weighted_score="));
        assert!(included.reason.contains("semantic="));
        assert!(
            included
                .evidence_links
                .iter()
                .any(|link| link.dimension == swarm_spine::IncidentGraphDimension::Semantic)
        );
        assert!(included.confidence_score > 0.5);
    }

    #[test]
    fn cross_strategy_bonus_is_rejected_without_real_overlap() {
        let investigations = MemoryInvestigationBundleStore::default();
        let incidents = MemoryIncidentStore::default();
        let engine = CorrelationEngine::new(config_with_min_shared_keys(2));

        let seed = investigation(
            "investigation:hunt-1:1",
            "hunt-1",
            1_700_000_000_000,
            "summary_investigator",
            &["host:host-1", "strategy:summary_investigator"],
            InvestigationStatus::Completed,
        );
        let related = investigation(
            "investigation:hunt-2:1",
            "hunt-2",
            1_700_000_001_000,
            "dns_exfiltration",
            &["user:bob", "strategy:dns_exfiltration"],
            InvestigationStatus::Completed,
        );

        investigations.persist(&seed).unwrap();
        investigations.persist(&related).unwrap();

        let outcome = engine
            .correlate_hunt(&investigations, &incidents, "hunt-1")
            .unwrap()
            .unwrap();

        let rejected = outcome
            .incident
            .rejected_members
            .iter()
            .find(|member| member.hunt_id == "hunt-2")
            .unwrap();

        assert!(rejected.shared_keys.is_empty());
        assert!(
            rejected
                .reason
                .contains("requires at least one entity or causal link")
        );
        assert!(rejected.reason.contains("semantic="));
    }

    #[test]
    fn same_strategy_strategy_only_overlap_is_rejected() {
        let investigations = MemoryInvestigationBundleStore::default();
        let incidents = MemoryIncidentStore::default();
        let engine = CorrelationEngine::new(config_with_min_shared_keys(1));

        let seed = investigation(
            "investigation:hunt-1:1",
            "hunt-1",
            1_700_000_000_000,
            "summary_investigator",
            &["host:host-1", "strategy:summary_investigator"],
            InvestigationStatus::Completed,
        );
        let related = investigation(
            "investigation:hunt-2:1",
            "hunt-2",
            1_700_000_001_000,
            "summary_investigator",
            &["user:bob", "strategy:summary_investigator"],
            InvestigationStatus::Completed,
        );

        investigations.persist(&seed).unwrap();
        investigations.persist(&related).unwrap();

        let outcome = engine
            .correlate_hunt(&investigations, &incidents, "hunt-1")
            .unwrap()
            .unwrap();

        let rejected = outcome
            .incident
            .rejected_members
            .iter()
            .find(|member| member.hunt_id == "hunt-2")
            .unwrap();

        assert_eq!(
            rejected.shared_keys,
            vec!["strategy:summary_investigator".to_string()]
        );
        assert!(
            rejected
                .reason
                .contains("requires at least one entity or causal link")
        );
        assert!(rejected.reason.contains("strategy:summary_investigator"));
    }
}
