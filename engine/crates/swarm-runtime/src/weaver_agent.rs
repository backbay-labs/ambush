use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::collections::HashSet;
use swarm_core::agent::{
    AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError, SwarmEvent,
};
use swarm_core::types::{AgentId, HuntId, SwarmAction};
use swarm_spine::{ConfiguredIncidentStore, ConfiguredInvestigationBundleStore};

use crate::correlation::CorrelationEngine;

pub struct WeaverAgent {
    id: AgentId,
    _signing_key: SigningKey,
    verifying_key: VerifyingKey,
    correlation: CorrelationEngine,
    investigation_store: ConfiguredInvestigationBundleStore,
    incident_store: ConfiguredIncidentStore,
    correlated_hunts: HashSet<String>,
    role: AgentRole,
    health: AgentHealth,
}

impl WeaverAgent {
    pub fn new(
        id: AgentId,
        correlation: CorrelationEngine,
        investigation_store: ConfiguredInvestigationBundleStore,
        incident_store: ConfiguredIncidentStore,
    ) -> Self {
        Self::new_with_signing_key(
            id,
            SigningKey::generate(&mut OsRng),
            correlation,
            investigation_store,
            incident_store,
        )
    }

    pub fn new_with_signing_key(
        id: AgentId,
        signing_key: SigningKey,
        correlation: CorrelationEngine,
        investigation_store: ConfiguredInvestigationBundleStore,
        incident_store: ConfiguredIncidentStore,
    ) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            id,
            _signing_key: signing_key,
            verifying_key,
            correlation,
            investigation_store,
            incident_store,
            correlated_hunts: HashSet::new(),
            role: AgentRole::Weaver,
            health: AgentHealth::Healthy,
        }
    }
}

#[async_trait]
impl SwarmAgent for WeaverAgent {
    fn identity(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    fn id(&self) -> &AgentId {
        &self.id
    }

    fn role(&self) -> AgentRole {
        self.role
    }

    fn observe_event(&mut self, event: &SwarmEvent) -> Result<(), SwarmError> {
        match event {
            SwarmEvent::RoleShift {
                agent_id, new_role, ..
            } if agent_id == &self.id => {
                self.role = *new_role;
            }
            _ => {}
        }
        Ok(())
    }

    async fn tick(&mut self, env: &SwarmEnvironment) -> Result<Vec<SwarmAction>, SwarmError> {
        let mut actions = Vec::new();

        for hunt_id in investigation_hunts(&env.pheromones) {
            if self.correlated_hunts.contains(&hunt_id) {
                continue;
            }

            let outcome = self
                .correlation
                .correlate_hunt(&self.investigation_store, &self.incident_store, &hunt_id)
                .map_err(internal_error)?;
            let Some(outcome) = outcome else {
                continue;
            };
            self.correlated_hunts.insert(hunt_id.clone());
            actions.push(SwarmAction::PublishFindings {
                hunt_id: HuntId(hunt_id),
                findings: serde_json::json!({
                    "incident_id": outcome.incident.incident_id,
                    "summary": outcome.incident.summary,
                    "included_hunts": outcome.incident.included_hunt_ids(),
                    "correlation_confidence": outcome.incident.confidence_score,
                    "graph_dimensions": outcome.incident.graph_dimensions,
                    "included_members": outcome.incident.included_members,
                }),
                confidence: 1.0,
            });
        }

        Ok(actions)
    }

    fn health(&self) -> AgentHealth {
        self.health
    }
}

fn investigation_hunts(pheromones: &[swarm_core::pheromone::PheromoneDeposit]) -> Vec<String> {
    let mut hunts = Vec::new();
    for deposit in pheromones {
        let from_stalker = matches!(deposit.agent_role, Some(AgentRole::Stalker))
            || deposit.agent_id.0.starts_with("stalker-");
        if !from_stalker {
            continue;
        }
        let Some(hunt_id) = deposit
            .indicator
            .get("hunt_id")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        if hunts.iter().any(|existing| existing == hunt_id) {
            continue;
        }
        hunts.push(hunt_id.to_string());
    }
    hunts
}

fn internal_error(error: impl std::error::Error) -> SwarmError {
    SwarmError::Internal(std::io::Error::other(error.to_string()).into())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::WeaverAgent;
    use crate::correlation::CorrelationEngine;
    use swarm_core::agent::{AgentRole, SwarmAgent, SwarmEnvironment, SwarmMode};
    use swarm_core::config::{BundleStoreConfig, CorrelationConfig};
    use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
    use swarm_core::types::{AgentId, Severity, SwarmAction};
    use swarm_spine::{
        ConfiguredIncidentStore, ConfiguredInvestigationBundleStore, InvestigationBundle,
        InvestigationBundleStore, InvestigationStatus,
    };

    fn investigation_store() -> ConfiguredInvestigationBundleStore {
        ConfiguredInvestigationBundleStore::from_config(&BundleStoreConfig::Memory).unwrap()
    }

    fn incident_store() -> ConfiguredIncidentStore {
        ConfiguredIncidentStore::from_config(&BundleStoreConfig::Memory).unwrap()
    }

    fn correlation() -> CorrelationEngine {
        CorrelationEngine::new(CorrelationConfig {
            enabled: true,
            time_window_ms: 300_000,
            min_shared_keys: 1,
            candidate_limit: 32,
            incident_store: BundleStoreConfig::Memory,
        })
    }

    fn completed_investigation(hunt_id: &str) -> InvestigationBundle {
        InvestigationBundle {
            investigation_id: format!("investigation:{hunt_id}"),
            source_bundle_id: format!("bundle:{hunt_id}"),
            hunt_id: hunt_id.to_string(),
            trail_id: format!("trail:{hunt_id}"),
            event_id: hunt_id.to_string(),
            finding_id: format!("finding:{hunt_id}"),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            strategy_id: "suspicious_process_tree".to_string(),
            response_kind: "success".to_string(),
            related_receipt_ids: vec![format!("receipt:{hunt_id}")],
            host_id: Some("host-1".to_string()),
            user: Some("alice".to_string()),
            process_name: Some("powershell".to_string()),
            queued_at_ms: 1_700_000_000_000,
            started_at_ms: Some(1_700_000_000_010),
            completed_at_ms: Some(1_700_000_000_020),
            status: InvestigationStatus::Completed,
            priority: swarm_spine::InvestigationPriority::default(),
            summary: Some("completed investigation".to_string()),
            evidence_points: vec!["host_id=host-1".to_string()],
            correlation_keys: vec!["host:host-1".to_string()],
            candidate_interpretations: Vec::new(),
            vote_lineage: Vec::new(),
            decision: swarm_spine::InvestigationDecision::default(),
            failure_reason: None,
        }
    }

    fn env(hunt_id: &str) -> SwarmEnvironment {
        SwarmEnvironment {
            pheromones: vec![PheromoneDeposit {
                schema_version: PheromoneDeposit::current_schema_version(),
                indicator: serde_json::json!({"hunt_id": hunt_id}),
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                confidence: 0.9,
                timestamp: 1_700_000_000,
                decay_half_life: 3600.0,
                agent_id: AgentId::new("stalker", "primary"),
                agent_identity: String::new(),
                agent_role: None,
                signature: Vec::new(),
                agent_key: Vec::new(),
            }],
            mode: SwarmMode::Incident,
            mode_transition_at: Some(1_700_000_050),
            now: 1_700_000_100,
            peer_findings: Vec::new(),
            agent_health: Vec::new(),
        }
    }

    #[test]
    fn weaver_agent_reports_role() {
        let agent = WeaverAgent::new(
            AgentId::new("weaver", "primary"),
            correlation(),
            investigation_store(),
            incident_store(),
        );

        assert_eq!(agent.role(), AgentRole::Weaver);
    }

    #[tokio::test]
    async fn weaver_agent_correlates_completed_investigations() {
        let investigation_store = investigation_store();
        investigation_store
            .persist(&completed_investigation("hunt-1"))
            .unwrap();
        let mut agent = WeaverAgent::new(
            AgentId::new("weaver", "primary"),
            correlation(),
            investigation_store.clone(),
            incident_store(),
        );

        let actions = agent.tick(&env("hunt-1")).await.unwrap();
        let findings = actions
            .iter()
            .find_map(|action| match action {
                SwarmAction::PublishFindings { findings, .. } => Some(findings),
                _ => None,
            })
            .expect("publish findings action");
        assert!(findings.get("correlation_confidence").is_some());
        assert!(findings.get("graph_dimensions").is_some());
    }
}
