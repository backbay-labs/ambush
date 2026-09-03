use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::collections::HashSet;
use swarm_core::agent::{
    AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError, SwarmEvent,
};
use swarm_core::config::PheromoneConfig;
use swarm_core::pheromone::PheromoneDeposit;
use swarm_core::types::{AgentId, HuntId, SwarmAction};
use swarm_crypto::sha256_hex;
use swarm_pheromone::{
    ConfiguredPheromoneSubstrate, DepositSigningPayload, PheromoneSubstrate, SubstrateError,
};
use swarm_spine::{
    ConfiguredReplayBundleStore, InvestigationStatus, ReplayBundleStore, ReplayStoreError,
};

use swarm_core::agent::{AgentTickBoundaryError, AgentTickError};
use swarm_runtime::hypothesis_graph::{GraphServiceError, GraphWorkerAdapter};
use swarm_runtime::investigation::InvestigationError;
use swarm_runtime::investigation::{InvestigationCoordinator, SummaryInvestigator};
use swarm_spine::ConfiguredInvestigationBundleStore;

pub struct StalkerAgent {
    id: AgentId,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    replay_store: ConfiguredReplayBundleStore,
    investigation:
        InvestigationCoordinator<SummaryInvestigator, ConfiguredInvestigationBundleStore>,
    substrate: ConfiguredPheromoneSubstrate,
    pheromone_config: PheromoneConfig,
    queued_hunts: HashSet<String>,
    published_hunts: HashSet<String>,
    pending_graph_publication_acks: HashSet<String>,
    hypothesis_graph: Option<GraphWorkerAdapter>,
    role: AgentRole,
    health: AgentHealth,
}

#[derive(Debug, thiserror::Error)]
pub enum StalkerAgentTickError {
    #[error(transparent)]
    ReplayStore(#[from] ReplayStoreError),

    #[error(transparent)]
    Investigation(#[from] InvestigationError),

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    #[error(transparent)]
    Substrate(#[from] SubstrateError),

    #[error(transparent)]
    HypothesisGraph(#[from] GraphServiceError),
}

// `AgentTickError` is sealed so the set of types that can emit an `error_boundary`
// telemetry label stays enumerable. See `swarm_core::agent::AgentTickError`.
impl swarm_core::agent::sealed::SealedAgentTickError for StalkerAgentTickError {}

impl AgentTickError for StalkerAgentTickError {
    fn boundary(&self) -> &'static str {
        match self {
            Self::ReplayStore(_) => "replay_store",
            Self::Investigation(_) => "investigation",
            Self::Serialization(_) => "serialization",
            Self::Substrate(_) => "substrate",
            Self::HypothesisGraph(_) => "hypothesis_graph",
        }
    }

    fn role(&self) -> AgentRole {
        AgentRole::Stalker
    }
}

impl StalkerAgent {
    pub fn new(
        id: AgentId,
        replay_store: ConfiguredReplayBundleStore,
        investigation: InvestigationCoordinator<
            SummaryInvestigator,
            ConfiguredInvestigationBundleStore,
        >,
        substrate: ConfiguredPheromoneSubstrate,
        pheromone_config: PheromoneConfig,
    ) -> Self {
        Self::new_with_signing_key(
            id,
            SigningKey::generate(&mut OsRng),
            replay_store,
            investigation,
            substrate,
            pheromone_config,
        )
    }

    pub fn new_with_signing_key(
        id: AgentId,
        signing_key: SigningKey,
        replay_store: ConfiguredReplayBundleStore,
        investigation: InvestigationCoordinator<
            SummaryInvestigator,
            ConfiguredInvestigationBundleStore,
        >,
        substrate: ConfiguredPheromoneSubstrate,
        pheromone_config: PheromoneConfig,
    ) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            id,
            signing_key,
            verifying_key,
            replay_store,
            investigation,
            substrate,
            pheromone_config,
            queued_hunts: HashSet::new(),
            published_hunts: HashSet::new(),
            pending_graph_publication_acks: HashSet::new(),
            hypothesis_graph: None,
            role: AgentRole::Stalker,
            health: AgentHealth::Healthy,
        }
    }

    /// Install the key-bound collective graph worker. Its presence selects
    /// the durable graph path; the legacy hash-set path remains untouched for
    /// disabled configurations.
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

    async fn tick_hypothesis_graph(
        &mut self,
        env: &SwarmEnvironment,
        graph: GraphWorkerAdapter,
    ) -> Result<Vec<SwarmAction>, SwarmError> {
        let mut actions = Vec::new();
        let mut first_error = None;
        // A prior tick's actions have passed through the dispatcher's
        // synchronous apply phase before this tick can begin. Persist the
        // acknowledgement now, one tick after emission. A crash before this
        // point deliberately leaves the durable graph terminal pending so the
        // replacement Stalker replays it at least once.
        for hunt_id in self
            .pending_graph_publication_acks
            .iter()
            .cloned()
            .collect::<Vec<_>>()
        {
            match self.investigation.acknowledge_graph_findings(&hunt_id) {
                Ok(Some(_)) => match graph.acknowledge_stalker_publication(&hunt_id) {
                    Ok(()) => {
                        self.pending_graph_publication_acks.remove(&hunt_id);
                    }
                    Err(error) => {
                        if first_error.is_none() {
                            first_error = Some(agent_tick_error(error));
                        }
                    }
                },
                Ok(None) => {}
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(agent_tick_error(error));
                    }
                }
            }
        }
        let mut hunts = detection_hunts(&env.pheromones);
        for hunt_id in graph
            .outstanding_stalker_hunts_at(swarm_core::hypothesis_graph::GraphLogicalTime::new(
                env.now.saturating_mul(1_000),
            ))
            .map_err(agent_tick_error)?
        {
            if !self.published_hunts.contains(&hunt_id) && !hunts.contains(&hunt_id) {
                hunts.push(hunt_id);
            }
        }
        for hunt_id in hunts {
            match self.tick_hypothesis_hunt(env, &graph, &hunt_id) {
                Ok(hunt_actions) => actions.extend(hunt_actions),
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        // Actions are an ephemeral delivery surface layered over durable graph
        // terminals. Returning a later hunt's error here would discard actions
        // already produced for earlier hunts; those terminals are idempotent on
        // retry, so the lost actions could never be reconstructed. Surface the
        // first error only when this tick has no useful actions to deliver.
        if actions.is_empty()
            && let Some(error) = first_error
        {
            return Err(error);
        }
        Ok(actions)
    }

    fn tick_hypothesis_hunt(
        &mut self,
        env: &SwarmEnvironment,
        graph: &GraphWorkerAdapter,
        hunt_id: &str,
    ) -> Result<Vec<SwarmAction>, SwarmError> {
        let mut actions = Vec::new();
        let replay = self
            .replay_store
            .load_by_hunt_id(hunt_id)
            .map_err(agent_tick_error)?;
        if let Some(replay) = &replay {
            graph
                .ensure_replay_admitted(&replay.bundle)
                .map_err(agent_tick_error)?;
        }
        let existing = self
            .investigation
            .load_by_hunt_id(hunt_id)
            .map_err(agent_tick_error)?;
        let mut investigation = match existing {
            Some(existing) => existing,
            None => {
                let Some(replay) = replay else {
                    return Ok(actions);
                };
                self.investigation
                    .submit(&replay.bundle)
                    .map_err(agent_tick_error)?;
                actions.push(SwarmAction::ClaimInvestigation {
                    hunt_id: HuntId(hunt_id.to_string()),
                    lead: replay.bundle.audit.detection.strategy_id.clone(),
                });
                return Ok(actions);
            }
        };
        if investigation.bundle.graph_findings_published || self.published_hunts.contains(hunt_id) {
            if investigation.bundle.graph_findings_published {
                graph
                    .acknowledge_stalker_publication(hunt_id)
                    .map_err(agent_tick_error)?;
            }
            self.published_hunts.insert(hunt_id.to_string());
            return Ok(actions);
        }
        if matches!(
            investigation.bundle.status,
            InvestigationStatus::Queued | InvestigationStatus::Running
        ) {
            let Some(replay) = replay else {
                return Ok(actions);
            };
            self.investigation
                .resume_unfinished(&replay.bundle, &investigation.bundle)
                .map_err(agent_tick_error)?;
            let Some(recovered) = self
                .investigation
                .load_by_hunt_id(hunt_id)
                .map_err(agent_tick_error)?
            else {
                return Ok(actions);
            };
            investigation = recovered;
            if matches!(
                investigation.bundle.status,
                InvestigationStatus::Queued | InvestigationStatus::Running
            ) {
                return Ok(actions);
            }
        }
        let investigation_completed_at_ms = investigation.bundle.completed_at_ms;
        let worker_now =
            swarm_core::hypothesis_graph::GraphLogicalTime::new(env.now.saturating_mul(1_000));
        if matches!(
            investigation.bundle.status,
            InvestigationStatus::Failed | InvestigationStatus::TimedOut
        ) {
            // Outstanding work prevents campaign rotation before this point.
            // Capture the campaign identity before the terminal commit so a
            // concurrent post-commit rotation cannot relabel the publication.
            let failure_summary_digest = sha256_hex(
                format!(
                    "{:?}\0{}",
                    investigation.bundle.status,
                    investigation.bundle.failure_reason.as_deref().unwrap_or("")
                )
                .as_bytes(),
            );
            graph
                .close_failed_stalker_hunt(hunt_id, worker_now, &failure_summary_digest)
                .map_err(agent_tick_error)?;
            let Some(publication) = graph
                .committed_stalker_publication(hunt_id)
                .map_err(agent_tick_error)?
            else {
                return Ok(actions);
            };
            let graph_id = publication.graph_id;
            let completion = publication.completion;
            let failure_summaries = publication.failure_summaries;
            let publication_id = format!(
                "stalker-findings:{}:{}:{}",
                graph_id, hunt_id, investigation.bundle.investigation_id
            );
            self.published_hunts.insert(hunt_id.to_string());
            self.pending_graph_publication_acks
                .insert(hunt_id.to_string());
            actions.push(SwarmAction::PublishFindings {
                hunt_id: HuntId(hunt_id.to_string()),
                findings: serde_json::json!({
                    "hunt_id": hunt_id,
                    "investigation_id": investigation.bundle.investigation_id,
                    "investigation_completed_at_ms": investigation_completed_at_ms,
                    "investigation_status": investigation.bundle.status,
                    "failure_reason": investigation.bundle.failure_reason,
                    "graph_id": graph_id,
                    "publication_id": publication_id,
                    "acquisition_failures": completion.acquisition_failures,
                    "falsification_failures": completion.falsification_failures,
                    "task_failure_summaries": failure_summaries,
                    "memory_records_projected": completion.memory_records_projected,
                }),
                confidence: 0.0,
            });
            return Ok(actions);
        }
        graph
            .complete_stalker_hunt(
                hunt_id,
                worker_now,
                investigation.bundle.decision.final_confidence_basis_points,
                investigation.bundle.decision.ambiguous,
                investigation
                    .bundle
                    .decision
                    .selected_interpretation_id
                    .as_deref()
                    .is_some_and(|selected| selected.starts_with("malicious_")),
            )
            .map_err(agent_tick_error)?;
        let Some(publication) = graph
            .committed_stalker_publication(hunt_id)
            .map_err(agent_tick_error)?
        else {
            return Ok(actions);
        };
        let graph_id = publication.graph_id;
        let completion = publication.completion;
        let publication_id = format!(
            "stalker-findings:{}:{}:{}",
            graph_id, hunt_id, investigation.bundle.investigation_id
        );
        self.published_hunts.insert(hunt_id.to_string());
        self.pending_graph_publication_acks
            .insert(hunt_id.to_string());
        actions.push(SwarmAction::PublishFindings {
            hunt_id: HuntId(hunt_id.to_string()),
            findings: serde_json::json!({
                "hunt_id": hunt_id,
                "investigation_id": investigation.bundle.investigation_id,
                "investigation_completed_at_ms": investigation_completed_at_ms,
                "graph_id": graph_id,
                "publication_id": publication_id,
                "acquisitions_completed": completion.acquisitions,
                "acquisition_no_findings": completion.acquisition_no_findings,
                "falsifications_completed": completion.falsifications,
                "falsification_no_findings": completion.falsification_no_findings,
                "memory_records_projected": completion.memory_records_projected,
            }),
            confidence: (f64::from(investigation.bundle.decision.final_confidence_basis_points)
                / 10_000.0)
                .clamp(0.0, 1.0),
        });
        Ok(actions)
    }
}

#[async_trait]
impl SwarmAgent for StalkerAgent {
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
            return self.tick_hypothesis_graph(env, graph).await;
        }
        let mut actions = Vec::new();

        for hunt_id in detection_hunts(&env.pheromones) {
            if !self.queued_hunts.contains(&hunt_id) {
                let replay = self
                    .replay_store
                    .load_by_hunt_id(&hunt_id)
                    .map_err(agent_tick_error)?;
                let Some(replay) = replay else {
                    continue;
                };
                self.investigation
                    .submit(&replay.bundle)
                    .map_err(agent_tick_error)?;
                self.queued_hunts.insert(hunt_id.clone());
                actions.push(SwarmAction::ClaimInvestigation {
                    hunt_id: HuntId(hunt_id.clone()),
                    lead: replay.bundle.audit.detection.strategy_id.clone(),
                });
            }

            if self.published_hunts.contains(&hunt_id) {
                continue;
            }

            let investigation = self
                .investigation
                .load_by_hunt_id(&hunt_id)
                .map_err(agent_tick_error)?;
            let Some(investigation) = investigation else {
                continue;
            };
            if investigation.bundle.status != swarm_spine::InvestigationStatus::Completed {
                continue;
            }

            let confidence = if investigation.bundle.decision.final_confidence_basis_points == 0 {
                0.9_f64
            } else {
                (f64::from(investigation.bundle.decision.final_confidence_basis_points) / 10_000.0)
                    .clamp(0.55, 0.99)
            };
            let indicator = serde_json::json!({
                "hunt_id": hunt_id,
                "investigation_id": investigation.bundle.investigation_id,
                "host_id": investigation.bundle.host_id,
                "correlation_keys": investigation.bundle.correlation_keys,
                "summary": investigation.bundle.summary,
                "priority_class": investigation.bundle.priority.class,
                "priority_score_basis_points": investigation.bundle.priority.total_basis_points,
                "selected_interpretation_id": investigation.bundle.decision.selected_interpretation_id,
                "final_confidence_basis_points": investigation.bundle.decision.final_confidence_basis_points,
                "ambiguous": investigation.bundle.decision.ambiguous,
            });
            let threat_class_config = self
                .substrate
                .query_threat_class_config(&investigation.bundle.threat_class)
                .await
                .map_err(agent_tick_error)?;
            let policy = self
                .pheromone_config
                .resolve_threat_class_policy(threat_class_config.as_ref());
            let derived_identity = AgentId::from_verifying_key(&self.verifying_key);
            let mut deposit = PheromoneDeposit {
                schema_version: PheromoneDeposit::current_schema_version(),
                indicator: indicator.clone(),
                threat_class: investigation.bundle.threat_class.clone(),
                severity: investigation.bundle.severity,
                confidence,
                timestamp: env.now,
                decay_half_life: policy.half_life_secs,
                agent_id: AgentId(format!("{}:{}", derived_identity.0, self.id.0)),
                agent_identity: derived_identity.0,
                agent_role: Some(AgentRole::Stalker),
                signature: Vec::new(),
                agent_key: Vec::new(),
            };
            let signing_payload = DepositSigningPayload {
                schema_version: deposit.schema_version,
                indicator: &deposit.indicator,
                threat_class: &deposit.threat_class,
                severity: &deposit.severity,
                confidence: deposit.confidence,
                timestamp: deposit.timestamp,
                decay_half_life: deposit.decay_half_life,
                agent_id: &deposit.agent_id,
                agent_identity: &deposit.agent_identity,
                agent_role: deposit.agent_role,
            };
            let payload_bytes = serde_json::to_vec(&signing_payload).map_err(agent_tick_error)?;
            let sig = self.signing_key.sign(&payload_bytes);
            deposit.signature = sig.to_bytes().to_vec();
            deposit.agent_key = self.signing_key.verifying_key().to_bytes().to_vec();
            self.substrate
                .deposit(deposit)
                .await
                .map_err(agent_tick_error)?;
            self.published_hunts.insert(hunt_id.clone());

            actions.push(SwarmAction::PublishFindings {
                hunt_id: HuntId(hunt_id.clone()),
                findings: indicator.clone(),
                confidence,
            });
            actions.push(SwarmAction::DepositPheromone {
                threat_class: threat_class_name(&investigation.bundle.threat_class),
                severity: investigation.bundle.severity,
                indicator,
                confidence,
            });
        }

        Ok(actions)
    }

    fn health(&self) -> AgentHealth {
        self.health
    }
}

fn detection_hunts(pheromones: &[PheromoneDeposit]) -> Vec<String> {
    let mut hunts = Vec::new();
    for deposit in pheromones {
        let from_whisker = matches!(deposit.agent_role, Some(AgentRole::Whisker))
            || deposit.agent_id.0.starts_with("whisker-");
        if !from_whisker {
            continue;
        }
        let Some(hunt_id) = deposit
            .indicator
            .get("event_id")
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

fn threat_class_name(threat_class: &swarm_core::pheromone::ThreatClass) -> String {
    match threat_class {
        swarm_core::pheromone::ThreatClass::LateralMovement => "lateral_movement".to_string(),
        swarm_core::pheromone::ThreatClass::DataExfiltration => "data_exfiltration".to_string(),
        swarm_core::pheromone::ThreatClass::PrivilegeEscalation => {
            "privilege_escalation".to_string()
        }
        swarm_core::pheromone::ThreatClass::CommandAndControl => "command_and_control".to_string(),
        swarm_core::pheromone::ThreatClass::InitialAccess => "initial_access".to_string(),
        swarm_core::pheromone::ThreatClass::Persistence => "persistence".to_string(),
        swarm_core::pheromone::ThreatClass::SupplyChain => "supply_chain".to_string(),
        swarm_core::pheromone::ThreatClass::DefenseEvasion => "defense_evasion".to_string(),
        swarm_core::pheromone::ThreatClass::CredentialAccess => "credential_access".to_string(),
        swarm_core::pheromone::ThreatClass::Discovery => "discovery".to_string(),
        swarm_core::pheromone::ThreatClass::Execution => "execution".to_string(),
        swarm_core::pheromone::ThreatClass::Impact => "impact".to_string(),
        swarm_core::pheromone::ThreatClass::Custom(value) => value.clone(),
    }
}

fn agent_tick_error(error: impl Into<StalkerAgentTickError>) -> SwarmError {
    let error: StalkerAgentTickError = error.into();
    SwarmError::Internal(AgentTickBoundaryError::agent(error).into())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::StalkerAgent;
    use ed25519_dalek::SigningKey;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::agent::AgentTickBoundaryError;
    use swarm_core::agent::{AgentRole, SwarmAgent, SwarmEnvironment, SwarmError, SwarmMode};
    use swarm_core::config::{
        BundleStoreConfig, HypothesisGraphConfig, InvestigationConfig, PheromoneBackendConfig,
        PheromoneConfig,
    };
    use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
    use swarm_core::types::{AgentId, Severity, SwarmAction};
    use swarm_crypto::Keypair;
    use swarm_pheromone::{
        ConfiguredPheromoneSubstrate, InMemoryPheromoneSubstrate, PheromoneSubstrate,
    };
    use swarm_policy::{ActionRequest, CapabilityLease, PolicyVerdict};
    use swarm_response::{ExecutionMode, ResponseReceipt, ResponseStatus};
    use swarm_runtime::hypothesis_graph::CollectiveHypothesisService;
    use swarm_runtime::investigation::{InvestigationCoordinator, SummaryInvestigator};
    use swarm_spine::{AuditResponseRecord, AuditTrail, PolicyRecord};
    use swarm_spine::{
        ConfiguredInvestigationBundleStore, ConfiguredReplayBundleStore, InvestigationBundle,
        InvestigationBundleStore, InvestigationDecision, InvestigationStatus, ReplayBundle,
        ReplayBundleStore,
    };
    use swarm_whisker::{DetectionFinding, ProcessStartEvent, TelemetryEvent, TelemetryPayload};

    fn pheromone_config() -> PheromoneConfig {
        PheromoneConfig {
            default_half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
            deescalation_cooldown_secs: 300,
            response_playbook: Default::default(),
            backend: PheromoneBackendConfig::InMemory,
        }
    }

    fn substrate(config: &PheromoneConfig) -> ConfiguredPheromoneSubstrate {
        ConfiguredPheromoneSubstrate::InMemory(InMemoryPheromoneSubstrate::new_for_replay(
            config.clone(),
        ))
    }

    fn temp_root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-stalker-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn replay_store() -> ConfiguredReplayBundleStore {
        ConfiguredReplayBundleStore::from_config(&BundleStoreConfig::Memory).unwrap()
    }

    fn investigation()
    -> InvestigationCoordinator<SummaryInvestigator, ConfiguredInvestigationBundleStore> {
        InvestigationCoordinator::new(
            InvestigationConfig {
                enabled: true,
                worker_count: 1,
                max_pending_jobs: 8,
                time_budget_ms: 250,
                bundle_store: BundleStoreConfig::Memory,
                ..InvestigationConfig::default()
            },
            SummaryInvestigator,
            ConfiguredInvestigationBundleStore::from_config(&BundleStoreConfig::Memory).unwrap(),
        )
    }

    fn replay_bundle(hunt_id: &str) -> ReplayBundle {
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: hunt_id.to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                // Agent-loop tests exercise one graph challenge at a time.
                // Parent/correlation fan-out is covered by the runtime's
                // production-adapter integration tests.
                parent_process: "<none>".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc AAA=".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        ReplayBundle {
            bundle_id: format!("bundle:{hunt_id}"),
            event: event.clone(),
            findings: vec![DetectionFinding {
                finding_id: format!("finding:{hunt_id}"),
                event_id: hunt_id.to_string(),
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                confidence: 0.97,
                evidence: serde_json::json!({"command_line": "powershell.exe -enc AAA=", "user": "alice"}),
                strategy_id: "suspicious_process_tree".to_string(),
            }],
            deposits: Vec::new(),
            action_request: ActionRequest {
                hunt_id: swarm_core::types::HuntId(hunt_id.to_string()),
                requested_by: AgentId("swarm-detect".to_string()),
                action: swarm_core::types::ResponseAction::DeployDecoy {
                    decoy_type: "honeypot".to_string(),
                    target_zone: "dmz".to_string(),
                },
                severity: Severity::High,
                evidence: serde_json::json!({"signal": "test"}),
            },
            rehearsal: None,
            audit: AuditTrail {
                trail_id: format!("trail:{hunt_id}"),
                hunt_id: hunt_id.to_string(),
                related_receipt_ids: Vec::new(),
                detection: DetectionFinding {
                    finding_id: format!("finding:{hunt_id}"),
                    event_id: hunt_id.to_string(),
                    threat_class: ThreatClass::Execution,
                    severity: Severity::High,
                    confidence: 0.97,
                    evidence: serde_json::json!({"command_line": "powershell.exe -enc AAA=", "user": "alice"}),
                    strategy_id: "suspicious_process_tree".to_string(),
                },
                policy: PolicyRecord {
                    verdict: PolicyVerdict::Allow,
                    rule_name: "test.allow".to_string(),
                    reason: "test".to_string(),
                    lease: Some(CapabilityLease {
                        capability_id: "lease:test".to_string(),
                        action: "deploy_decoy".to_string(),
                        expires_at_ms: 1_700_000_100_000,
                        scope: Some("test".to_string()),
                    }),
                },
                response: AuditResponseRecord::Success(ResponseReceipt {
                    receipt_id: format!("receipt:{hunt_id}"),
                    action: "deploy_decoy".to_string(),
                    mode: ExecutionMode::DryRun,
                    status: ResponseStatus::Simulated,
                    summary: "simulated".to_string(),
                    details: serde_json::json!({"status": "simulated"}),
                    audit: Default::default(),
                }),
                created_at_ms: 1_700_000_000_100,
            },
        }
    }

    fn completed_investigation_bundle(
        replay: &ReplayBundle,
        completed_at_ms: i64,
    ) -> InvestigationBundle {
        InvestigationBundle::queued_from_bundle(
            replay,
            format!("investigation:{}", replay.audit.hunt_id),
            completed_at_ms.saturating_sub(20),
            Default::default(),
        )
        .with_summary(
            "completed graph investigation".to_string(),
            vec!["event reviewed".to_string()],
            vec!["host:host-1".to_string()],
            Vec::new(),
            Vec::new(),
            InvestigationDecision::default(),
            completed_at_ms,
        )
    }

    fn env(hunt_id: &str) -> SwarmEnvironment {
        SwarmEnvironment {
            pheromones: vec![PheromoneDeposit {
                schema_version: PheromoneDeposit::current_schema_version(),
                indicator: serde_json::json!({"event_id": hunt_id}),
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                confidence: 0.95,
                timestamp: 1_700_000_000,
                decay_half_life: 3600.0,
                agent_id: AgentId::new("whisker", "primary"),
                agent_identity: String::new(),
                agent_role: None,
                signature: Vec::new(),
                agent_key: Vec::new(),
            }],
            mode: SwarmMode::Alert,
            mode_transition_at: Some(1_700_000_050),
            now: 1_700_000_100,
            peer_findings: Vec::new(),
            agent_health: Vec::new(),
        }
    }

    #[tokio::test]
    async fn stalker_agent_reports_role() {
        let config = pheromone_config();
        let agent = StalkerAgent::new(
            AgentId::new("stalker", "primary"),
            replay_store(),
            investigation(),
            substrate(&config),
            config,
        );

        assert_eq!(agent.role(), AgentRole::Stalker);
    }

    #[tokio::test]
    async fn stalker_agent_submits_and_publishes_completed_investigations() {
        let config = pheromone_config();
        let replay_store = replay_store();
        replay_store.persist(&replay_bundle("hunt-1")).unwrap();
        let investigation = investigation();
        let substrate = substrate(&config);
        let mut agent = StalkerAgent::new(
            AgentId::new("stalker", "primary"),
            replay_store,
            investigation.clone(),
            substrate.clone(),
            config,
        );

        let first_actions = agent.tick(&env("hunt-1")).await.unwrap();
        assert!(
            first_actions
                .iter()
                .any(|action| matches!(action, SwarmAction::ClaimInvestigation { .. }))
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let lookup = investigation.load_by_hunt_id("hunt-1").unwrap();
                if lookup
                    .as_ref()
                    .map(|lookup| {
                        lookup.bundle.status == swarm_spine::InvestigationStatus::Completed
                    })
                    .unwrap_or(false)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let second_actions = agent.tick(&env("hunt-1")).await.unwrap();
        assert!(
            second_actions
                .iter()
                .any(|action| matches!(action, SwarmAction::PublishFindings { .. }))
        );
        assert!(
            second_actions
                .iter()
                .any(|action| matches!(action, SwarmAction::DepositPheromone { .. }))
        );
        assert!(
            substrate
                .recent_deposits(10)
                .await
                .unwrap()
                .iter()
                .any(|deposit| {
                    deposit.agent_id.0.ends_with(":stalker-primary")
                        && deposit.agent_role == Some(AgentRole::Stalker)
                        && deposit.agent_identity.starts_with("swarm:ed25519:")
                })
        );
    }

    #[tokio::test]
    async fn stalker_agent_completes_durable_graph_work_without_legacy_side_effects() {
        let pheromone = pheromone_config();
        let replay_store = replay_store();
        let replay = replay_bundle("hunt-graph-stalker");
        replay_store.persist(&replay).unwrap();
        let graph_config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 32,
            max_claims_per_tick: 16,
            ..HypothesisGraphConfig::default()
        };
        let graph = Arc::new(
            CollectiveHypothesisService::new(&graph_config, Keypair::from_seed(&[117; 32]), None)
                .unwrap(),
        );
        let stalker_seed = [119; 32];
        let stalker_signing_key = SigningKey::from_bytes(&stalker_seed);
        let stalker_id = AgentId::from_verifying_key(&stalker_signing_key.verifying_key());
        let stalker_worker = graph
            .worker(
                [
                    swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                    swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
                ],
                Keypair::from_seed(&stalker_seed),
            )
            .unwrap();
        let _weaver_worker = graph
            .worker(
                [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
                Keypair::from_seed(&[120; 32]),
            )
            .unwrap();
        graph.submit_replay(&replay).unwrap();
        let investigation = investigation();
        let substrate = substrate(&pheromone);
        let mut agent = StalkerAgent::new_with_signing_key(
            stalker_id,
            stalker_signing_key,
            replay_store,
            investigation.clone(),
            substrate.clone(),
            pheromone,
        )
        .with_hypothesis_graph(stalker_worker)
        .unwrap();

        let mut recovered_env = env("hunt-graph-stalker");
        recovered_env.pheromones.clear();

        let first_actions = agent.tick(&recovered_env).await.unwrap();
        assert!(
            first_actions
                .iter()
                .any(|action| matches!(action, SwarmAction::ClaimInvestigation { .. }))
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if investigation
                    .load_by_hunt_id("hunt-graph-stalker")
                    .unwrap()
                    .is_some_and(|lookup| {
                        lookup.bundle.status == swarm_spine::InvestigationStatus::Completed
                    })
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let second_actions = agent.tick(&recovered_env).await.unwrap();
        let findings = second_actions
            .iter()
            .find_map(|action| match action {
                SwarmAction::PublishFindings { findings, .. } => Some(findings),
                _ => None,
            })
            .unwrap();
        assert_eq!(findings["graph_id"], graph.graph_id().as_str());
        assert_eq!(findings["acquisitions_completed"], 1);
        assert_eq!(findings["falsifications_completed"], 1);
        assert_eq!(findings["falsification_no_findings"], 1);
        assert_eq!(findings["memory_records_projected"], 1);
        assert!(
            !second_actions
                .iter()
                .any(|action| matches!(action, SwarmAction::DepositPheromone { .. }))
        );
        assert!(substrate.recent_deposits(10).await.unwrap().is_empty());
        assert_eq!(graph.summary().unwrap().completed_task_count, 3);
    }

    #[tokio::test]
    async fn stalker_replays_committed_graph_publication_after_crash_then_durably_acks() {
        let hunt_id = "hunt-graph-publication-crash";
        let pheromone = pheromone_config();
        let replay_store = replay_store();
        let replay = replay_bundle(hunt_id);
        replay_store.persist(&replay).unwrap();
        let graph_config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 32,
            max_claims_per_tick: 16,
            ..HypothesisGraphConfig::default()
        };
        let graph = Arc::new(
            CollectiveHypothesisService::new(&graph_config, Keypair::from_seed(&[142; 32]), None)
                .unwrap(),
        );
        let stalker_seed = [143; 32];
        let signing_key = SigningKey::from_bytes(&stalker_seed);
        let stalker_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        graph
            .worker(
                [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
                Keypair::from_seed(&[144; 32]),
            )
            .unwrap();
        let investigation = investigation();
        let substrate = substrate(&pheromone);
        let worker = graph
            .worker(
                [
                    swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                    swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
                ],
                Keypair::from_seed(&stalker_seed),
            )
            .unwrap();
        graph.submit_replay(&replay).unwrap();
        let mut agent = StalkerAgent::new_with_signing_key(
            stalker_id.clone(),
            signing_key.clone(),
            replay_store.clone(),
            investigation.clone(),
            substrate.clone(),
            pheromone.clone(),
        )
        .with_hypothesis_graph(worker)
        .unwrap();
        let mut recovered_env = env(hunt_id);
        recovered_env.pheromones.clear();

        assert!(
            agent
                .tick(&recovered_env)
                .await
                .unwrap()
                .iter()
                .any(|action| matches!(action, SwarmAction::ClaimInvestigation { .. }))
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if investigation
                    .load_by_hunt_id(hunt_id)
                    .unwrap()
                    .is_some_and(|lookup| lookup.bundle.status == InvestigationStatus::Completed)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let first_publication = agent
            .tick(&recovered_env)
            .await
            .unwrap()
            .into_iter()
            .find_map(|action| match action {
                SwarmAction::PublishFindings { findings, .. } => {
                    findings["publication_id"].as_str().map(ToString::to_string)
                }
                _ => None,
            })
            .unwrap();
        assert!(
            !investigation
                .load_by_hunt_id(hunt_id)
                .unwrap()
                .unwrap()
                .bundle
                .graph_findings_published
        );
        drop(agent);

        let replacement_worker = graph
            .worker(
                [
                    swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                    swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
                ],
                Keypair::from_seed(&stalker_seed),
            )
            .unwrap();
        let mut replacement = StalkerAgent::new_with_signing_key(
            stalker_id.clone(),
            signing_key.clone(),
            replay_store.clone(),
            investigation.clone(),
            substrate.clone(),
            pheromone.clone(),
        )
        .with_hypothesis_graph(replacement_worker)
        .unwrap();
        let replayed_publication = replacement
            .tick(&recovered_env)
            .await
            .unwrap()
            .into_iter()
            .find_map(|action| match action {
                SwarmAction::PublishFindings { findings, .. } => {
                    findings["publication_id"].as_str().map(ToString::to_string)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(replayed_publication, first_publication);

        assert!(replacement.tick(&recovered_env).await.unwrap().is_empty());
        assert!(
            investigation
                .load_by_hunt_id(hunt_id)
                .unwrap()
                .unwrap()
                .bundle
                .graph_findings_published
        );
        drop(replacement);

        let final_worker = graph
            .worker(
                [
                    swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                    swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
                ],
                Keypair::from_seed(&stalker_seed),
            )
            .unwrap();
        let mut final_agent = StalkerAgent::new_with_signing_key(
            stalker_id,
            signing_key,
            replay_store,
            investigation,
            substrate,
            pheromone,
        )
        .with_hypothesis_graph(final_worker)
        .unwrap();
        assert!(final_agent.tick(&recovered_env).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn stalker_reconciles_a_persisted_replay_before_claiming_investigation() {
        let pheromone = pheromone_config();
        let replay_store = replay_store();
        replay_store
            .persist(&replay_bundle("hunt-graph-reconcile"))
            .unwrap();
        let graph_config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 32,
            max_claims_per_tick: 16,
            ..HypothesisGraphConfig::default()
        };
        let graph = Arc::new(
            CollectiveHypothesisService::new(&graph_config, Keypair::from_seed(&[130; 32]), None)
                .unwrap(),
        );
        let stalker_seed = [131; 32];
        let stalker_signing_key = SigningKey::from_bytes(&stalker_seed);
        let stalker_worker = graph
            .worker(
                [
                    swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                    swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
                ],
                Keypair::from_seed(&stalker_seed),
            )
            .unwrap();
        graph
            .worker(
                [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
                Keypair::from_seed(&[132; 32]),
            )
            .unwrap();
        assert_eq!(graph.summary().unwrap().evidence_count, 0);
        let mut agent = StalkerAgent::new_with_signing_key(
            AgentId::from_verifying_key(&stalker_signing_key.verifying_key()),
            stalker_signing_key,
            replay_store,
            investigation(),
            substrate(&pheromone),
            pheromone,
        )
        .with_hypothesis_graph(stalker_worker)
        .unwrap();

        let actions = agent.tick(&env("hunt-graph-reconcile")).await.unwrap();
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, SwarmAction::ClaimInvestigation { .. }))
        );
        let summary = graph.summary().unwrap();
        assert_eq!(summary.evidence_count, 1);
        assert_eq!(summary.hypothesis_count, 2);
        assert_eq!(summary.pending_task_count, 4);
    }

    #[tokio::test]
    async fn stalker_resumes_a_queued_investigation_after_coordinator_restart() {
        let hunt_id = "hunt-graph-restart-resume";
        let pheromone = pheromone_config();
        let replay_store = replay_store();
        let replay = replay_bundle(hunt_id);
        replay_store.persist(&replay).unwrap();
        let graph_config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 32,
            max_claims_per_tick: 16,
            ..HypothesisGraphConfig::default()
        };
        let graph = Arc::new(
            CollectiveHypothesisService::new(&graph_config, Keypair::from_seed(&[139; 32]), None)
                .unwrap(),
        );
        let stalker_seed = [140; 32];
        let signing_key = SigningKey::from_bytes(&stalker_seed);
        let stalker_worker = graph
            .worker(
                [
                    swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                    swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
                ],
                Keypair::from_seed(&stalker_seed),
            )
            .unwrap();
        graph
            .worker(
                [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
                Keypair::from_seed(&[141; 32]),
            )
            .unwrap();
        graph.submit_replay(&replay).unwrap();

        let investigation_store =
            ConfiguredInvestigationBundleStore::from_config(&BundleStoreConfig::Memory).unwrap();
        let original_id = format!("investigation:{hunt_id}:before-restart");
        let original_queued_at_ms = 1_700_000_000_050;
        investigation_store
            .persist(&InvestigationBundle::queued_from_bundle(
                &replay,
                original_id.clone(),
                original_queued_at_ms,
                Default::default(),
            ))
            .unwrap();
        let coordinator = InvestigationCoordinator::new(
            InvestigationConfig {
                enabled: true,
                worker_count: 1,
                max_pending_jobs: 8,
                time_budget_ms: 250,
                bundle_store: BundleStoreConfig::Memory,
                ..InvestigationConfig::default()
            },
            SummaryInvestigator,
            investigation_store,
        );
        let mut agent = StalkerAgent::new_with_signing_key(
            AgentId::from_verifying_key(&signing_key.verifying_key()),
            signing_key,
            replay_store,
            coordinator.clone(),
            substrate(&pheromone),
            pheromone,
        )
        .with_hypothesis_graph(stalker_worker)
        .unwrap();
        let mut recovered_env = env(hunt_id);
        recovered_env.pheromones.clear();

        assert!(agent.tick(&recovered_env).await.unwrap().is_empty());
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if coordinator
                    .load_by_hunt_id(hunt_id)
                    .unwrap()
                    .is_some_and(|lookup| lookup.bundle.status == InvestigationStatus::Completed)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let completed = coordinator.load_by_hunt_id(hunt_id).unwrap().unwrap();
        assert_eq!(completed.bundle.investigation_id, original_id);
        assert_eq!(completed.bundle.queued_at_ms, original_queued_at_ms);
        let actions = agent.tick(&recovered_env).await.unwrap();
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, SwarmAction::PublishFindings { .. }))
        );
        assert_eq!(graph.summary().unwrap().completed_task_count, 3);
    }

    #[tokio::test]
    async fn stalker_closes_failed_investigation_work_once_as_failure() {
        let hunt_id = "hunt-graph-stalker-failure";
        let pheromone = pheromone_config();
        let replay_store = replay_store();
        let replay = replay_bundle(hunt_id);
        replay_store.persist(&replay).unwrap();
        let graph_config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 32,
            max_claims_per_tick: 16,
            ..HypothesisGraphConfig::default()
        };
        let graph = Arc::new(
            CollectiveHypothesisService::new(&graph_config, Keypair::from_seed(&[133; 32]), None)
                .unwrap(),
        );
        let stalker_seed = [134; 32];
        let signing_key = SigningKey::from_bytes(&stalker_seed);
        let stalker_worker = graph
            .worker(
                [
                    swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                    swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
                ],
                Keypair::from_seed(&stalker_seed),
            )
            .unwrap();
        graph
            .worker(
                [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
                Keypair::from_seed(&[135; 32]),
            )
            .unwrap();
        graph.submit_replay(&replay).unwrap();

        let investigation_store =
            ConfiguredInvestigationBundleStore::from_config(&BundleStoreConfig::Memory).unwrap();
        let failed = InvestigationBundle::queued_from_bundle(
            &replay,
            format!("investigation:{hunt_id}"),
            1_700_000_000_000,
            Default::default(),
        )
        .with_failure(
            InvestigationStatus::TimedOut,
            "investigation exceeded its budget".to_string(),
            1_700_000_000_100,
        );
        investigation_store.persist(&failed).unwrap();
        let coordinator = InvestigationCoordinator::new(
            InvestigationConfig {
                enabled: true,
                worker_count: 1,
                max_pending_jobs: 8,
                time_budget_ms: 250,
                bundle_store: BundleStoreConfig::Memory,
                ..InvestigationConfig::default()
            },
            SummaryInvestigator,
            investigation_store,
        );
        let mut agent = StalkerAgent::new_with_signing_key(
            AgentId::from_verifying_key(&signing_key.verifying_key()),
            signing_key,
            replay_store,
            coordinator,
            substrate(&pheromone),
            pheromone,
        )
        .with_hypothesis_graph(stalker_worker)
        .unwrap();

        let actions = agent.tick(&env(hunt_id)).await.unwrap();
        let findings = actions
            .iter()
            .find_map(|action| match action {
                SwarmAction::PublishFindings { findings, .. } => Some(findings),
                _ => None,
            })
            .unwrap();
        assert_eq!(findings["investigation_status"], "timed_out");
        assert_eq!(findings["acquisition_failures"], 1);
        assert_eq!(findings["falsification_failures"], 2);
        assert_eq!(
            findings["task_failure_summaries"].as_array().map(Vec::len),
            Some(1)
        );
        let summary = graph.summary().unwrap();
        assert_eq!(summary.completed_task_count, 0);
        assert_eq!(summary.failed_task_count, 3);
        assert_eq!(summary.pending_task_count, 1);
        assert_eq!(summary.metrics.failed_acquisitions, 1);
        assert_eq!(summary.metrics.failed_falsifications, 2);
        assert!(agent.tick(&env(hunt_id)).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn stalker_reclaims_expired_task_at_current_tick_not_investigation_time() {
        let hunt_id = "hunt-graph-expired-lease";
        let pheromone = pheromone_config();
        let replay_store = replay_store();
        let replay = replay_bundle(hunt_id);
        replay_store.persist(&replay).unwrap();
        let graph_config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 32,
            max_claims_per_tick: 16,
            ..HypothesisGraphConfig::default()
        };
        let graph = Arc::new(
            CollectiveHypothesisService::new(&graph_config, Keypair::from_seed(&[136; 32]), None)
                .unwrap(),
        );
        let stalker_seed = [137; 32];
        let signing_key = SigningKey::from_bytes(&stalker_seed);
        let stalker_worker = graph
            .worker(
                [
                    swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                    swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
                ],
                Keypair::from_seed(&stalker_seed),
            )
            .unwrap();
        graph
            .worker(
                [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
                Keypair::from_seed(&[138; 32]),
            )
            .unwrap();
        graph.submit_replay(&replay).unwrap();
        let claimed = stalker_worker
            .claim_next(swarm_core::hypothesis_graph::GraphLogicalTime::new(
                1_700_000_000_100,
            ))
            .unwrap()
            .expect("one stalker task should be claimed before the simulated crash");

        let investigation_store =
            ConfiguredInvestigationBundleStore::from_config(&BundleStoreConfig::Memory).unwrap();
        investigation_store
            .persist(&completed_investigation_bundle(&replay, 1_700_000_000_020))
            .unwrap();
        let coordinator = InvestigationCoordinator::new(
            InvestigationConfig {
                enabled: true,
                worker_count: 1,
                max_pending_jobs: 8,
                time_budget_ms: 250,
                bundle_store: BundleStoreConfig::Memory,
                ..InvestigationConfig::default()
            },
            SummaryInvestigator,
            investigation_store,
        );
        let mut agent = StalkerAgent::new_with_signing_key(
            AgentId::from_verifying_key(&signing_key.verifying_key()),
            signing_key,
            replay_store,
            coordinator,
            substrate(&pheromone),
            pheromone,
        )
        .with_hypothesis_graph(stalker_worker)
        .unwrap();

        let actions = agent.tick(&env(hunt_id)).await.unwrap();
        assert!(actions.iter().any(|action| matches!(
            action,
            SwarmAction::PublishFindings { findings, .. }
                if findings["investigation_completed_at_ms"] == 1_700_000_000_020_i64
        )));
        assert_eq!(graph.summary().unwrap().completed_task_count, 3);
        assert!(matches!(
            claimed.request.kind,
            swarm_core::hypothesis_graph::TaskKind::AcquireEvidence
                | swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis
        ));
    }

    #[tokio::test]
    async fn stalker_preserves_completed_actions_when_a_later_hunt_errors() {
        let first_hunt = "hunt-graph-first-action";
        let blocked_hunt = "hunt-graph-blocked-admission";
        let pheromone = pheromone_config();
        let replay_store = replay_store();
        let first_replay = replay_bundle(first_hunt);
        let blocked_replay = replay_bundle(blocked_hunt);
        replay_store.persist(&first_replay).unwrap();
        replay_store.persist(&blocked_replay).unwrap();
        let graph_config = HypothesisGraphConfig {
            enabled: true,
            max_tasks: 5,
            max_work_units_per_tick: 32,
            max_claims_per_tick: 16,
            ..HypothesisGraphConfig::default()
        };
        let graph = Arc::new(
            CollectiveHypothesisService::new(&graph_config, Keypair::from_seed(&[139; 32]), None)
                .unwrap(),
        );
        let stalker_seed = [140; 32];
        let signing_key = SigningKey::from_bytes(&stalker_seed);
        let stalker_worker = graph
            .worker(
                [
                    swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                    swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
                ],
                Keypair::from_seed(&stalker_seed),
            )
            .unwrap();
        graph
            .worker(
                [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
                Keypair::from_seed(&[141; 32]),
            )
            .unwrap();
        graph.submit_replay(&first_replay).unwrap();

        let investigation_store =
            ConfiguredInvestigationBundleStore::from_config(&BundleStoreConfig::Memory).unwrap();
        investigation_store
            .persist(&completed_investigation_bundle(
                &first_replay,
                1_700_000_000_020,
            ))
            .unwrap();
        let coordinator = InvestigationCoordinator::new(
            InvestigationConfig {
                enabled: true,
                worker_count: 1,
                max_pending_jobs: 8,
                time_budget_ms: 250,
                bundle_store: BundleStoreConfig::Memory,
                ..InvestigationConfig::default()
            },
            SummaryInvestigator,
            investigation_store,
        );
        let mut agent = StalkerAgent::new_with_signing_key(
            AgentId::from_verifying_key(&signing_key.verifying_key()),
            signing_key,
            replay_store,
            coordinator,
            substrate(&pheromone),
            pheromone,
        )
        .with_hypothesis_graph(stalker_worker)
        .unwrap();
        let mut multi_hunt_env = env(first_hunt);
        let mut blocked_deposit = multi_hunt_env.pheromones[0].clone();
        blocked_deposit.indicator = serde_json::json!({"event_id": blocked_hunt});
        multi_hunt_env.pheromones.push(blocked_deposit);

        let actions = agent.tick(&multi_hunt_env).await.unwrap();
        assert!(actions.iter().any(|action| matches!(
            action,
            SwarmAction::PublishFindings { hunt_id, .. } if hunt_id.0 == first_hunt
        )));
        assert_eq!(graph.summary().unwrap().completed_task_count, 3);
        assert!(agent.tick(&multi_hunt_env).await.is_err());
    }

    #[tokio::test]
    async fn stalker_agent_surfaces_replay_store_failures_with_typed_boundary() {
        let config = pheromone_config();
        let root = temp_root("replay-store-failure");
        let replay_store =
            ConfiguredReplayBundleStore::from_config(&BundleStoreConfig::LocalFiles {
                directory: root.display().to_string(),
            })
            .unwrap();
        replay_store.persist(&replay_bundle("hunt-1")).unwrap();
        fs::remove_dir_all(root.join("bundles")).unwrap();
        let mut agent = StalkerAgent::new(
            AgentId::new("stalker", "primary"),
            replay_store,
            investigation(),
            substrate(&config),
            config,
        );

        let error = agent.tick(&env("hunt-1")).await.unwrap_err();
        let boundary = match &error {
            SwarmError::Internal(error) => error
                .downcast_ref::<AgentTickBoundaryError>()
                .expect("stalker agent should preserve typed boundary error"),
            other => panic!("expected internal boundary error, got {other:?}"),
        };

        assert!(matches!(boundary, AgentTickBoundaryError::Agent(_)));
        assert_eq!(boundary.role(), AgentRole::Stalker);
        assert_eq!(boundary.boundary(), "replay_store");

        let _ = fs::remove_dir_all(root);
    }
}
