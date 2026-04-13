use crate::detection::pipeline::detect_and_deposit_with_role;
use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::sync::Arc;
use swarm_core::agent::{
    AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError, SwarmEvent,
};
use swarm_core::config::PheromoneConfig;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::{AgentId, SwarmAction};
use swarm_pheromone::ConfiguredPheromoneSubstrate;
use swarm_whisker::{CompositeDetector, TelemetryEvent};
use tokio::sync::Mutex;
use tokio::sync::mpsc;

pub type SharedTelemetryReceiver = Arc<Mutex<mpsc::Receiver<TelemetryEvent>>>;

pub struct WhiskerAgent {
    id: AgentId,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    event_rx: SharedTelemetryReceiver,
    detector: Arc<CompositeDetector>,
    substrate: ConfiguredPheromoneSubstrate,
    pheromone_config: PheromoneConfig,
    role: AgentRole,
    health: AgentHealth,
}

impl WhiskerAgent {
    pub fn shared_receiver(event_rx: mpsc::Receiver<TelemetryEvent>) -> SharedTelemetryReceiver {
        Arc::new(Mutex::new(event_rx))
    }

    pub fn new(
        id: AgentId,
        event_rx: mpsc::Receiver<TelemetryEvent>,
        detector: Arc<CompositeDetector>,
        substrate: ConfiguredPheromoneSubstrate,
        pheromone_config: PheromoneConfig,
    ) -> Self {
        Self::new_with_signing_key(
            id,
            SigningKey::generate(&mut OsRng),
            event_rx,
            detector,
            substrate,
            pheromone_config,
        )
    }

    pub fn new_with_signing_key(
        id: AgentId,
        signing_key: SigningKey,
        event_rx: mpsc::Receiver<TelemetryEvent>,
        detector: Arc<CompositeDetector>,
        substrate: ConfiguredPheromoneSubstrate,
        pheromone_config: PheromoneConfig,
    ) -> Self {
        Self::new_with_shared_receiver_and_signing_key(
            id,
            signing_key,
            Self::shared_receiver(event_rx),
            detector,
            substrate,
            pheromone_config,
        )
    }

    pub fn new_with_shared_receiver(
        id: AgentId,
        event_rx: SharedTelemetryReceiver,
        detector: Arc<CompositeDetector>,
        substrate: ConfiguredPheromoneSubstrate,
        pheromone_config: PheromoneConfig,
    ) -> Self {
        Self::new_with_shared_receiver_and_signing_key(
            id,
            SigningKey::generate(&mut OsRng),
            event_rx,
            detector,
            substrate,
            pheromone_config,
        )
    }

    pub fn new_with_shared_receiver_and_signing_key(
        id: AgentId,
        signing_key: SigningKey,
        event_rx: SharedTelemetryReceiver,
        detector: Arc<CompositeDetector>,
        substrate: ConfiguredPheromoneSubstrate,
        pheromone_config: PheromoneConfig,
    ) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            id,
            signing_key,
            verifying_key,
            event_rx,
            detector,
            substrate,
            pheromone_config,
            role: AgentRole::Whisker,
            health: AgentHealth::Healthy,
        }
    }
}

#[async_trait]
impl SwarmAgent for WhiskerAgent {
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

    async fn tick(&mut self, _env: &SwarmEnvironment) -> Result<Vec<SwarmAction>, SwarmError> {
        let mut events = Vec::new();
        {
            let mut rx = self.event_rx.lock().await;
            while let Ok(event) = rx.try_recv() {
                events.push(event);
            }
        }

        let mut actions = Vec::new();
        for event in events {
            let derived_identity = AgentId::from_verifying_key(&self.signing_key.verifying_key());
            let scoped_agent_id = AgentId(format!("{}:{}", derived_identity.0, self.id.0));
            match detect_and_deposit_with_role(
                self.detector.as_ref(),
                &self.substrate,
                &event,
                &scoped_agent_id,
                Some(AgentRole::Whisker),
                &self.pheromone_config,
                &self.signing_key,
            )
            .await
            {
                Ok(outcome) => {
                    actions.extend(outcome.deposits.into_iter().map(|deposit| {
                        SwarmAction::DepositPheromone {
                            threat_class: threat_class_name(&deposit.threat_class),
                            severity: deposit.severity,
                            indicator: deposit.indicator,
                            confidence: deposit.confidence,
                        }
                    }));
                }
                Err(error) => {
                    tracing::warn!(
                        agent_id = %self.id,
                        event_id = %event.event_id,
                        reason = %error,
                        module = module_path!(),
                        "whisker agent failed to process buffered telemetry"
                    );
                    self.health = AgentHealth::Degraded;
                }
            }
        }

        Ok(actions)
    }

    fn health(&self) -> AgentHealth {
        self.health
    }
}

fn threat_class_name(threat_class: &ThreatClass) -> String {
    match threat_class {
        ThreatClass::LateralMovement => "lateral_movement".to_string(),
        ThreatClass::DataExfiltration => "data_exfiltration".to_string(),
        ThreatClass::PrivilegeEscalation => "privilege_escalation".to_string(),
        ThreatClass::CommandAndControl => "command_and_control".to_string(),
        ThreatClass::InitialAccess => "initial_access".to_string(),
        ThreatClass::Persistence => "persistence".to_string(),
        ThreatClass::SupplyChain => "supply_chain".to_string(),
        ThreatClass::DefenseEvasion => "defense_evasion".to_string(),
        ThreatClass::CredentialAccess => "credential_access".to_string(),
        ThreatClass::Discovery => "discovery".to_string(),
        ThreatClass::Execution => "execution".to_string(),
        ThreatClass::Impact => "impact".to_string(),
        ThreatClass::Custom(value) => value.clone(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::WhiskerAgent;
    use std::sync::Arc;
    use swarm_core::agent::{
        AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmEvent, SwarmMode,
    };
    use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
    use swarm_core::types::{AgentId, SwarmAction};
    use swarm_pheromone::{
        ConfiguredPheromoneSubstrate, InMemoryPheromoneSubstrate, PheromoneSubstrate,
    };
    use swarm_whisker::{
        CompositeDetector, ProcessStartEvent, SuspiciousProcessTreeDetector, TelemetryEvent,
        TelemetryPayload,
    };
    use tokio::sync::mpsc;

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

    fn event() -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-1".to_string(),
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
        }
    }

    fn env() -> SwarmEnvironment {
        SwarmEnvironment {
            pheromones: Vec::new(),
            mode: SwarmMode::Normal,
            mode_transition_at: None,
            now: 1_700_000_000,
            peer_findings: Vec::new(),
            agent_health: Vec::new(),
        }
    }

    fn detector() -> Arc<CompositeDetector> {
        Arc::new(CompositeDetector::new(vec![Box::new(
            SuspiciousProcessTreeDetector::default(),
        )]))
    }

    #[tokio::test]
    async fn whisker_agent_reports_role_and_health() {
        let config = pheromone_config();
        let (tx, rx) = mpsc::channel(4);
        drop(tx);
        let agent = WhiskerAgent::new(
            AgentId::new("whisker", "primary"),
            rx,
            detector(),
            substrate(&config),
            config,
        );

        assert_eq!(agent.role(), AgentRole::Whisker);
        assert_eq!(agent.health(), AgentHealth::Healthy);
        assert_eq!(agent.id().to_string(), "whisker-primary");
    }

    #[tokio::test]
    async fn whisker_agent_updates_role_when_role_shift_event_targets_self() {
        let config = pheromone_config();
        let (_tx, rx) = mpsc::channel(4);
        let mut agent = WhiskerAgent::new(
            AgentId::new("whisker", "primary"),
            rx,
            detector(),
            substrate(&config),
            config,
        );

        agent
            .observe_event(&SwarmEvent::RoleShift {
                agent_id: AgentId::new("whisker", "primary"),
                new_role: AgentRole::Tom,
                observed_at: 1_700_000_000,
            })
            .unwrap();

        assert_eq!(agent.role(), AgentRole::Tom);
    }

    #[tokio::test]
    async fn whisker_agent_returns_no_actions_with_empty_buffer() {
        let config = pheromone_config();
        let (_tx, rx) = mpsc::channel(4);
        let mut agent = WhiskerAgent::new(
            AgentId::new("whisker", "primary"),
            rx,
            detector(),
            substrate(&config),
            config,
        );

        let actions = agent.tick(&env()).await.unwrap();
        assert!(actions.is_empty());
    }

    #[tokio::test]
    async fn whisker_agent_drains_buffer_and_deposits_pheromones() {
        let config = pheromone_config();
        let substrate = substrate(&config);
        let detector = detector();
        let (tx, rx) = mpsc::channel(4);
        tx.send(event()).await.unwrap();
        drop(tx);
        let mut agent = WhiskerAgent::new(
            AgentId::new("whisker", "primary"),
            rx,
            detector,
            substrate.clone(),
            config,
        );

        let actions = agent.tick(&env()).await.unwrap();
        assert!(!actions.is_empty());
        assert!(matches!(actions[0], SwarmAction::DepositPheromone { .. }));
        let deposits = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].agent_role, Some(AgentRole::Whisker));
        assert!(deposits[0].agent_identity.starts_with("swarm:ed25519:"));
    }
}
