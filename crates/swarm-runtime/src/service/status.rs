use super::*;

pub(super) fn component_status_from_substrate(health: &SubstrateHealth) -> ComponentStatus {
    ComponentStatus {
        ready: health.ready,
        durable: Some(health.durable),
        details: format!("{} ({})", health.backend, health.details),
    }
}

pub(super) fn component_status_from_replay_store(health: &ReplayStoreHealth) -> ComponentStatus {
    ComponentStatus {
        ready: health.ready,
        durable: Some(health.durable),
        details: format!("{} ({})", health.backend, health.details),
    }
}

pub(super) fn component_status_from_investigation_store(
    health: &InvestigationStoreHealth,
) -> ComponentStatus {
    ComponentStatus {
        ready: health.ready,
        durable: Some(health.durable),
        details: format!("{} ({})", health.backend, health.details),
    }
}

pub(super) fn component_status_from_incident_store(
    health: &IncidentStoreHealth,
) -> ComponentStatus {
    ComponentStatus {
        ready: health.ready,
        durable: Some(health.durable),
        details: format!("{} ({})", health.backend, health.details),
    }
}

pub(super) fn summarize_async_lane_status(
    config: &SwarmConfig,
    investigation_strategy: &str,
    queue: &InvestigationQueueSnapshot,
    investigation_store_health: &InvestigationStoreHealth,
    incident_store_health: &IncidentStoreHealth,
    recent_investigations: &[InvestigationBundleRecord],
    recent_incidents: &[IncidentRecord],
) -> AsyncLaneStatusSnapshot {
    let investigation_enabled = config.investigation.enabled;
    let correlation_enabled = config.correlation.enabled;
    let enabled = investigation_enabled || correlation_enabled;
    if !enabled {
        return AsyncLaneStatusSnapshot::disabled();
    }

    let mut warnings = Vec::new();
    if investigation_enabled && !investigation_store_health.ready {
        warnings.push("durable investigation store is not ready".to_string());
    }
    if correlation_enabled && !incident_store_health.ready {
        warnings.push("durable incident store is not ready".to_string());
    }
    if let Some(reason) = &queue.last_failure_reason {
        warnings.push(format!("recent investigation failure: {reason}"));
    }
    if queue.timed_out_jobs > 0 {
        warnings.push(format!(
            "{} investigation job(s) timed out",
            queue.timed_out_jobs
        ));
    }
    if queue.queue_budget_remaining == 0 && queue.max_pending_jobs > 0 {
        warnings.push("investigation queue budget is exhausted".to_string());
    } else if queue.budget_evictions > 0 {
        warnings.push(format!(
            "investigation queue evicted {} job(s) under pressure",
            queue.budget_evictions
        ));
    }

    let latest_incident = recent_incidents.first();
    AsyncLaneStatusSnapshot {
        enabled,
        investigation_enabled,
        correlation_enabled,
        status: if warnings.is_empty() {
            AsyncLaneStatusLevel::Ok
        } else {
            AsyncLaneStatusLevel::Degraded
        },
        investigation_strategy: Some(investigation_strategy.to_string()),
        investigation_store_ready: !investigation_enabled || investigation_store_health.ready,
        incident_store_ready: !correlation_enabled || incident_store_health.ready,
        queued_jobs: queue.queued_jobs,
        running_jobs: queue.running_jobs,
        queue_budget_remaining: queue.queue_budget_remaining,
        highest_priority_score_basis_points: queue.highest_priority_score_basis_points,
        oldest_job_age_ms: queue.oldest_job_age_ms,
        completed_jobs: queue.completed_jobs,
        failed_jobs: queue.failed_jobs,
        timed_out_jobs: queue.timed_out_jobs,
        budget_evictions: queue.budget_evictions,
        starvation_preventions: queue.starvation_preventions,
        recent_investigations: recent_investigations.len(),
        ambiguous_recent_investigations: recent_investigations
            .iter()
            .filter(|record| record.ambiguous)
            .count(),
        recent_incidents: recent_incidents.len(),
        latest_investigation_id: recent_investigations
            .first()
            .map(|record| record.investigation_id.clone()),
        latest_incident_id: latest_incident.map(|record| record.incident_id.clone()),
        latest_incident_confidence_score: latest_incident.map(|record| record.confidence_score),
        latest_incident_graph_dimensions: latest_incident
            .map(|record| record.graph_dimensions.clone())
            .unwrap_or_default(),
        last_failure_reason: queue.last_failure_reason.clone(),
        warnings,
    }
}

pub(super) fn extend_unique_warnings(target: &mut Vec<String>, new_warnings: Vec<String>) {
    for warning in new_warnings {
        if !target.iter().any(|existing| existing == &warning) {
            target.push(warning);
        }
    }
}
