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
use swarm_pheromone::{
    ConfiguredPheromoneSubstrate, DepositSigningPayload, PheromoneSubstrate, SubstrateError,
};
use swarm_spine::{ConfiguredReplayBundleStore, ReplayBundleStore, ReplayStoreError};

use crate::AgentTickBoundaryError;
use crate::investigation::InvestigationError;
use crate::investigation::{InvestigationCoordinator, SummaryInvestigator};
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
}

impl StalkerAgentTickError {
    pub fn boundary(&self) -> &'static str {
        match self {
            Self::ReplayStore(_) => "replay_store",
            Self::Investigation(_) => "investigation",
            Self::Serialization(_) => "serialization",
            Self::Substrate(_) => "substrate",
        }
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
            role: AgentRole::Stalker,
            health: AgentHealth::Healthy,
        }
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
    SwarmError::Internal(AgentTickBoundaryError::from(error.into()).into())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{StalkerAgent, StalkerAgentTickError};
    use crate::AgentTickBoundaryError;
    use crate::investigation::{InvestigationCoordinator, SummaryInvestigator};
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::agent::{AgentRole, SwarmAgent, SwarmEnvironment, SwarmError, SwarmMode};
    use swarm_core::config::{
        BundleStoreConfig, InvestigationConfig, PheromoneBackendConfig, PheromoneConfig,
    };
    use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
    use swarm_core::types::{AgentId, Severity, SwarmAction};
    use swarm_pheromone::{
        ConfiguredPheromoneSubstrate, InMemoryPheromoneSubstrate, PheromoneSubstrate,
    };
    use swarm_policy::{ActionRequest, CapabilityLease, PolicyVerdict};
    use swarm_response::{ExecutionMode, ResponseReceipt, ResponseStatus};
    use swarm_spine::{AuditResponseRecord, AuditTrail, PolicyRecord};
    use swarm_spine::{
        ConfiguredInvestigationBundleStore, ConfiguredReplayBundleStore, ReplayBundle,
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
        ConfiguredPheromoneSubstrate::InMemory(InMemoryPheromoneSubstrate::new(config.clone()))
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
                parent_process: "winword".to_string(),
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

        assert!(matches!(
            boundary,
            AgentTickBoundaryError::Stalker(StalkerAgentTickError::ReplayStore(_))
        ));
        assert_eq!(boundary.boundary(), "replay_store");

        let _ = fs::remove_dir_all(root);
    }
}
