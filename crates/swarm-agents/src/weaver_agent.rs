use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::collections::HashSet;
use swarm_core::agent::{
    AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError, SwarmEvent,
};
use swarm_core::types::{AgentId, HuntId, SwarmAction};
use swarm_spine::{
    ConfiguredIncidentStore, ConfiguredInvestigationBundleStore, InvestigationBundleStore,
    InvestigationStatus,
};

use swarm_runtime::correlation::CorrelationEngine;
use swarm_runtime::hypothesis_graph::{GraphServiceError, GraphWorkerAdapter};

pub struct WeaverAgent {
    id: AgentId,
    _signing_key: SigningKey,
    verifying_key: VerifyingKey,
    correlation: CorrelationEngine,
    investigation_store: ConfiguredInvestigationBundleStore,
    incident_store: ConfiguredIncidentStore,
    correlated_hunts: HashSet<String>,
    hypothesis_graph: Option<GraphWorkerAdapter>,
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
            hypothesis_graph: None,
            role: AgentRole::Weaver,
            health: AgentHealth::Healthy,
        }
    }

    /// Install the Challenger capability for the durable collective graph.
    pub fn with_hypothesis_graph(
        mut self,
        worker: GraphWorkerAdapter,
    ) -> Result<Self, GraphServiceError> {
        if worker.claimant() != &self.id {
            return Err(GraphServiceError::WorkerIdentityMismatch {
                expected: self.id.clone(),
                observed: worker.claimant().clone(),
            });
        }
        self.hypothesis_graph = Some(worker);
        Ok(self)
    }

    fn tick_hypothesis_graph(
        &mut self,
        env: &SwarmEnvironment,
        graph: &GraphWorkerAdapter,
    ) -> Result<Vec<SwarmAction>, SwarmError> {
        let now =
            swarm_core::hypothesis_graph::GraphLogicalTime::new(env.now.saturating_mul(1_000));
        let Some(context) = graph.next_challenge_context(now).map_err(internal_error)? else {
            return Ok(Vec::new());
        };
        let Some(investigation) = self
            .investigation_store
            .load_by_hunt_id(&context.hunt_id)
            .map_err(internal_error)?
        else {
            return Ok(Vec::new());
        };
        match investigation.bundle.status {
            InvestigationStatus::Queued | InvestigationStatus::Running => {
                return Ok(Vec::new());
            }
            InvestigationStatus::Failed | InvestigationStatus::TimedOut => {
                let terminal_at = investigation
                    .bundle
                    .completed_at_ms
                    .map(swarm_core::hypothesis_graph::GraphLogicalTime::new)
                    .unwrap_or(now);
                if !graph
                    .complete_challenge_no_finding(&context.task_id, terminal_at)
                    .map_err(internal_error)?
                {
                    return Ok(Vec::new());
                }
                return Ok(vec![SwarmAction::PublishFindings {
                    hunt_id: HuntId(context.hunt_id),
                    findings: serde_json::json!({
                        "graph_id": graph.graph_id(),
                        "graph_task_id": context.task_id,
                        "evidence_ids": context.evidence_ids,
                        "investigation_status": investigation.bundle.status,
                        "failure_reason": investigation.bundle.failure_reason,
                        "challenge_no_finding": true,
                    }),
                    confidence: 0.0,
                }]);
            }
            InvestigationStatus::Completed => {}
        }
        let outcome = self
            .correlation
            .correlate_hunt(
                &self.investigation_store,
                &self.incident_store,
                &context.hunt_id,
            )
            .map_err(internal_error)?;
        let Some(outcome) = outcome else {
            return Ok(Vec::new());
        };
        if !graph
            .complete_challenge(&context.task_id, now)
            .map_err(internal_error)?
        {
            return Ok(Vec::new());
        }
        Ok(vec![SwarmAction::PublishFindings {
            hunt_id: HuntId(context.hunt_id),
            findings: serde_json::json!({
                "incident_id": outcome.incident.incident_id,
                "summary": outcome.incident.summary,
                "graph_id": graph.graph_id(),
                "graph_task_id": context.task_id,
                "evidence_ids": context.evidence_ids,
                "correlation_confidence": outcome.incident.confidence_score,
            }),
            confidence: 1.0,
        }])
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
        if let Some(graph) = self.hypothesis_graph.clone() {
            return self.tick_hypothesis_graph(env, &graph);
        }
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
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;
    use swarm_core::agent::{AgentRole, SwarmAgent, SwarmEnvironment, SwarmMode};
    use swarm_core::config::{BundleStoreConfig, CorrelationConfig, HypothesisGraphConfig};
    use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity, SwarmAction};
    use swarm_crypto::Keypair;
    use swarm_policy::{ActionRequest, PolicyVerdict};
    use swarm_runtime::correlation::CorrelationEngine;
    use swarm_runtime::hypothesis_graph::CollectiveHypothesisService;
    use swarm_spine::{
        AuditResponseRecord, AuditTrail, ConfiguredIncidentStore,
        ConfiguredInvestigationBundleStore, InvestigationBundle, InvestigationBundleStore,
        InvestigationStatus, PolicyRecord, ReplayBundle,
    };
    use swarm_whisker::{DetectionFinding, ProcessStartEvent, TelemetryEvent, TelemetryPayload};

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

    fn replay_bundle(hunt_id: &str) -> ReplayBundle {
        let finding = DetectionFinding {
            finding_id: format!("finding:{hunt_id}"),
            event_id: hunt_id.to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.95,
            evidence: serde_json::json!({"event_id": hunt_id}),
            strategy_id: "suspicious_process_tree".to_string(),
        };
        ReplayBundle {
            bundle_id: format!("bundle:{hunt_id}"),
            event: TelemetryEvent {
                source: "synthetic".to_string(),
                event_id: hunt_id.to_string(),
                timestamp: 1_700_000_000,
                host_id: Some("host-1".to_string()),
                payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                    parent_process: "winword".to_string(),
                    process_name: "powershell".to_string(),
                    command_line: "powershell.exe -enc AAA=".to_string(),
                    user: Some("alice".to_string()),
                    executable_path: None,
                    signer: None,
                    signature_valid: None,
                }),
            },
            findings: vec![finding.clone()],
            deposits: Vec::new(),
            action_request: ActionRequest {
                hunt_id: HuntId(hunt_id.to_string()),
                requested_by: AgentId("whisker:graph".to_string()),
                action: ResponseAction::Escalate {
                    summary: "correlate graph evidence".to_string(),
                    urgency: Severity::High,
                },
                severity: Severity::High,
                evidence: serde_json::json!({"event_id": hunt_id}),
            },
            rehearsal: None,
            audit: AuditTrail {
                trail_id: format!("trail:{hunt_id}"),
                hunt_id: hunt_id.to_string(),
                related_receipt_ids: Vec::new(),
                detection: finding,
                policy: PolicyRecord {
                    verdict: PolicyVerdict::Allow,
                    rule_name: "test.allow".to_string(),
                    reason: "weaver graph fixture".to_string(),
                    lease: None,
                },
                response: AuditResponseRecord::Skipped {
                    reason: "graph reasoning is advisory".to_string(),
                },
                created_at_ms: 1_700_000_000_000,
            },
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

    #[tokio::test]
    async fn weaver_agent_correlates_then_completes_durable_challenge() {
        let hunt_id = "hunt-graph-weaver";
        let investigation_store = investigation_store();
        investigation_store
            .persist(&completed_investigation(hunt_id))
            .unwrap();
        let graph_config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 32,
            max_claims_per_tick: 16,
            ..HypothesisGraphConfig::default()
        };
        let graph = Arc::new(
            CollectiveHypothesisService::new(&graph_config, Keypair::from_seed(&[118; 32]), None)
                .unwrap(),
        );
        let weaver_seed = [121; 32];
        let weaver_signing_key = SigningKey::from_bytes(&weaver_seed);
        let weaver_id = AgentId::from_verifying_key(&weaver_signing_key.verifying_key());
        let _stalker_worker = graph
            .worker(
                [
                    swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                    swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
                ],
                Keypair::from_seed(&[122; 32]),
            )
            .unwrap();
        let weaver_worker = graph
            .worker(
                [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
                Keypair::from_seed(&weaver_seed),
            )
            .unwrap();
        graph.submit_replay(&replay_bundle(hunt_id)).unwrap();
        let mut agent = WeaverAgent::new_with_signing_key(
            weaver_id,
            weaver_signing_key,
            correlation(),
            investigation_store,
            incident_store(),
        )
        .with_hypothesis_graph(weaver_worker)
        .unwrap();

        let actions = agent.tick(&env(hunt_id)).await.unwrap();
        let findings = actions
            .iter()
            .find_map(|action| match action {
                SwarmAction::PublishFindings { findings, .. } => Some(findings),
                _ => None,
            })
            .unwrap();
        assert_eq!(findings["graph_id"], graph.graph_id().as_str());
        assert!(findings.get("graph_task_id").is_some());
        let projection = graph.operator_projection().unwrap();
        assert_eq!(projection.metrics.completed_challenges, 1);
        assert_eq!(
            projection
                .tasks
                .iter()
                .filter(|task| task.state == swarm_core::hypothesis_graph::TaskState::Completed)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn weaver_keeps_inflight_challenge_open_then_closes_terminal_failure() {
        let hunt_id = "hunt-graph-weaver-failure";
        let investigation_store = investigation_store();
        let mut queued = completed_investigation(hunt_id);
        queued.status = InvestigationStatus::Queued;
        queued.started_at_ms = None;
        queued.completed_at_ms = None;
        queued.summary = None;
        investigation_store.persist(&queued).unwrap();
        let graph_config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 32,
            max_claims_per_tick: 16,
            ..HypothesisGraphConfig::default()
        };
        let graph = Arc::new(
            CollectiveHypothesisService::new(&graph_config, Keypair::from_seed(&[123; 32]), None)
                .unwrap(),
        );
        graph
            .worker(
                [
                    swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                    swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
                ],
                Keypair::from_seed(&[124; 32]),
            )
            .unwrap();
        let weaver_seed = [125; 32];
        let signing_key = SigningKey::from_bytes(&weaver_seed);
        let worker = graph
            .worker(
                [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
                Keypair::from_seed(&weaver_seed),
            )
            .unwrap();
        graph.submit_replay(&replay_bundle(hunt_id)).unwrap();
        let mut agent = WeaverAgent::new_with_signing_key(
            AgentId::from_verifying_key(&signing_key.verifying_key()),
            signing_key,
            correlation(),
            investigation_store.clone(),
            incident_store(),
        )
        .with_hypothesis_graph(worker)
        .unwrap();

        assert!(agent.tick(&env(hunt_id)).await.unwrap().is_empty());
        assert_eq!(graph.summary().unwrap().completed_task_count, 0);

        let failed = queued.with_failure(
            InvestigationStatus::Failed,
            "investigator exhausted its retry budget".to_string(),
            1_700_000_000_030,
        );
        investigation_store.persist(&failed).unwrap();
        let actions = agent.tick(&env(hunt_id)).await.unwrap();
        let findings = actions
            .iter()
            .find_map(|action| match action {
                SwarmAction::PublishFindings { findings, .. } => Some(findings),
                _ => None,
            })
            .unwrap();
        assert_eq!(findings["investigation_status"], "failed");
        assert_eq!(findings["challenge_no_finding"], true);
        assert_eq!(graph.summary().unwrap().completed_task_count, 1);
        assert!(agent.tick(&env(hunt_id)).await.unwrap().is_empty());
    }
}
