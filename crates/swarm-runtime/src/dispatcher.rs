use crate::detection::metrics::CriticalPathMetrics;
use arc_swap::ArcSwap;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use swarm_core::agent::{
    AgentFinding, AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmEvent, SwarmModeState,
};
use swarm_core::types::{AgentId, SwarmAction};
use swarm_pheromone::{ConfiguredPheromoneSubstrate, PheromoneSubstrate};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AgentHealthEntry {
    pub id: String,
    pub role: AgentRole,
    pub health: AgentHealth,
}

#[derive(Debug, Clone)]
pub struct AgentDispatcherConfig {
    pub tick_interval_ms: u64,
    pub max_agents: usize,
    pub enabled: bool,
    pub agent_tick_timeout_ms: u64,
}

impl Default for AgentDispatcherConfig {
    fn default() -> Self {
        Self {
            tick_interval_ms: 100,
            max_agents: 16,
            enabled: true,
            agent_tick_timeout_ms: 500,
        }
    }
}

pub struct AgentRegistry {
    agents: BTreeMap<AgentId, Box<dyn SwarmAgent>>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self {
            agents: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.agents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    pub fn register(&mut self, agent: Box<dyn SwarmAgent>) -> Result<(), &'static str> {
        let agent_id = agent.id().clone();
        if self.agents.contains_key(&agent_id) {
            return Err("agent registry already contains that id");
        }
        self.agents.insert(agent_id, agent);
        Ok(())
    }

    pub fn deregister(&mut self, agent_id: &AgentId) -> bool {
        self.agents.remove(agent_id).is_some()
    }

    fn iter(&self) -> impl Iterator<Item = (&AgentId, &Box<dyn SwarmAgent>)> {
        self.agents.iter()
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = (&AgentId, &mut Box<dyn SwarmAgent>)> {
        self.agents.iter_mut()
    }

    fn get(&self, agent_id: &AgentId) -> Option<&dyn SwarmAgent> {
        self.agents.get(agent_id).map(Box::as_ref)
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

struct CompletedAgentTick {
    agent_id: AgentId,
    role: AgentRole,
    actions: Vec<SwarmAction>,
}

struct PendingRoleShift {
    agent_id: AgentId,
    from_role: AgentRole,
    to_role: AgentRole,
}

pub struct AgentDispatcher {
    registry: AgentRegistry,
    health_overrides: HashMap<AgentId, AgentHealth>,
    config: AgentDispatcherConfig,
    shutdown: watch::Receiver<bool>,
    substrate: ConfiguredPheromoneSubstrate,
    health_state: Arc<ArcSwap<Vec<AgentHealthEntry>>>,
    mode_state: Arc<ArcSwap<SwarmModeState>>,
    recent_findings: HashMap<AgentId, AgentFinding>,
    metrics: Option<CriticalPathMetrics>,
}

impl AgentDispatcher {
    pub fn new(
        config: AgentDispatcherConfig,
        shutdown: watch::Receiver<bool>,
        substrate: ConfiguredPheromoneSubstrate,
        health_state: Arc<ArcSwap<Vec<AgentHealthEntry>>>,
    ) -> Self {
        Self {
            registry: AgentRegistry::new(),
            health_overrides: HashMap::new(),
            config,
            shutdown,
            substrate,
            health_state,
            mode_state: Arc::new(ArcSwap::from_pointee(SwarmModeState::new())),
            recent_findings: HashMap::new(),
            metrics: None,
        }
    }

    pub fn with_mode_state(mut self, mode_state: Arc<ArcSwap<SwarmModeState>>) -> Self {
        self.mode_state = mode_state;
        self
    }

    pub fn with_metrics(mut self, metrics: CriticalPathMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn register(&mut self, agent: Box<dyn SwarmAgent>) -> Result<(), &'static str> {
        if self.registry.len() >= self.config.max_agents {
            return Err("agent dispatcher is at capacity");
        }

        let agent_id = agent.id().clone();
        let role = agent.role();
        let health = self.effective_health(&agent_id, agent.health());
        self.registry.register(agent)?;
        tracing::info!(
            agent_id = %agent_id,
            role = agent_role_label(role),
            module = module_path!(),
            "agent registered"
        );
        self.health_overrides.insert(agent_id.clone(), health);
        self.health_overrides.remove(&agent_id);
        self.refresh_health_snapshot();
        Ok(())
    }

    pub fn deregister(&mut self, agent_id: &AgentId) -> bool {
        let removed = self.registry.deregister(agent_id);
        if removed {
            self.health_overrides.remove(agent_id);
            self.recent_findings.remove(agent_id);
            tracing::info!(
                agent_id = %agent_id,
                module = module_path!(),
                "agent deregistered"
            );
            self.refresh_health_snapshot();
        }
        removed
    }

    pub fn agent_health_summary(&self) -> Vec<AgentHealthEntry> {
        self.registry
            .iter()
            .map(|(_, agent)| AgentHealthEntry {
                id: agent.id().to_string(),
                role: agent.role(),
                health: self.effective_health(agent.id(), agent.health()),
            })
            .collect()
    }

    pub async fn run(&mut self) {
        self.refresh_health_snapshot();
        if !self.config.enabled {
            return;
        }

        let mut interval =
            tokio::time::interval(Duration::from_millis(self.config.tick_interval_ms));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                changed = self.shutdown.changed() => {
                    if changed.is_err() || *self.shutdown.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    if *self.shutdown.borrow() {
                        break;
                    }
                    self.tick_agents().await;
                }
            }
        }

        self.refresh_health_snapshot();
    }

    async fn tick_agents(&mut self) {
        let before_health = self.current_health_map();
        let now = unix_timestamp_secs();
        let pheromones = self.load_recent_pheromones().await;
        let mode_state = self.mode_state.load();
        let mode = mode_state.current;
        let mode_transition_at = mode_state.last_transition_at;
        let peer_findings_snapshot = self.recent_findings.values().cloned().collect::<Vec<_>>();
        let mut completed_ticks = Vec::new();

        for (agent_id, agent) in self.registry.iter_mut() {
            let env = SwarmEnvironment {
                pheromones: pheromones.clone(),
                mode,
                mode_transition_at,
                now,
                peer_findings: peer_findings_snapshot
                    .iter()
                    .filter(|finding| finding.agent_id != *agent_id)
                    .cloned()
                    .collect(),
            };
            let tick_role = agent.role();
            let tick_timeout = Duration::from_millis(self.config.agent_tick_timeout_ms);
            match tokio::time::timeout(tick_timeout, agent.tick(&env)).await {
                Ok(Ok(actions)) => {
                    self.health_overrides.remove(agent_id);
                    tracing::info!(
                        agent_id = %agent_id,
                        role = agent_role_label(tick_role),
                        action_count = actions.len(),
                        module = module_path!(),
                        "agent tick completed"
                    );
                    completed_ticks.push(CompletedAgentTick {
                        agent_id: agent_id.clone(),
                        role: tick_role,
                        actions,
                    });
                }
                Ok(Err(error)) => {
                    tracing::warn!(
                        agent_id = %agent_id,
                        role = agent_role_label(tick_role),
                        reason = %error,
                        module = module_path!(),
                        "agent tick failed"
                    );
                    self.health_overrides
                        .insert(agent_id.clone(), AgentHealth::Degraded);
                }
                Err(_elapsed) => {
                    tracing::warn!(
                        agent_id = %agent_id,
                        role = agent_role_label(tick_role),
                        timeout_ms = self.config.agent_tick_timeout_ms,
                        module = module_path!(),
                        "agent tick timed out, marking degraded"
                    );
                    self.health_overrides
                        .insert(agent_id.clone(), AgentHealth::Degraded);
                }
            }

            if let Some(metrics) = &self.metrics {
                metrics.observe_agent_tick(agent_role_label(tick_role));
            }
        }

        self.apply_actions(completed_ticks, now);
        self.log_health_transitions(before_health);
        self.refresh_health_snapshot();
    }

    fn apply_actions(&mut self, completed_ticks: Vec<CompletedAgentTick>, now: i64) {
        let mut pending_role_shifts = Vec::new();

        for completed in completed_ticks {
            let mut latest_finding = None;
            for action in completed.actions {
                if let Some(finding) =
                    agent_finding_from_action(&completed.agent_id, completed.role, &action)
                {
                    latest_finding = Some(finding);
                }

                match action {
                    SwarmAction::RoleShift { new_role } => {
                        pending_role_shifts.push(PendingRoleShift {
                            agent_id: completed.agent_id.clone(),
                            from_role: completed.role,
                            to_role: new_role,
                        })
                    }
                    SwarmAction::HealthReport { status } => {
                        self.health_overrides
                            .insert(completed.agent_id.clone(), status);
                    }
                    _ => {}
                }
            }

            if let Some(finding) = latest_finding {
                self.recent_findings
                    .insert(completed.agent_id.clone(), finding);
            }
        }

        for role_shift in pending_role_shifts {
            self.broadcast_role_shift(role_shift, now);
        }
    }

    fn broadcast_role_shift(&mut self, role_shift: PendingRoleShift, now: i64) {
        let event = SwarmEvent::RoleShift {
            agent_id: role_shift.agent_id.clone(),
            new_role: role_shift.to_role,
            observed_at: now,
        };

        for (agent_id, agent) in self.registry.iter_mut() {
            if let Err(error) = agent.observe_event(&event) {
                tracing::warn!(
                    agent_id = %agent_id,
                    event = "role_shift",
                    reason = %error,
                    module = module_path!(),
                    "agent failed to observe broadcast event"
                );
            }
        }

        tracing::info!(
            agent_id = %role_shift.agent_id,
            from_role = agent_role_label(role_shift.from_role),
            to_role = agent_role_label(role_shift.to_role),
            module = module_path!(),
            "agent role shift broadcast"
        );
        if let Some(metrics) = &self.metrics {
            metrics.observe_agent_role_shift(agent_role_label(role_shift.to_role));
        }
    }

    fn log_health_transitions(&self, before_health: HashMap<AgentId, AgentHealth>) {
        for (agent_id, current_health) in self.current_health_map() {
            let previous_health = before_health.get(&agent_id).copied();
            if previous_health == Some(current_health) {
                continue;
            }

            if let Some(role) = self.registry.get(&agent_id).map(SwarmAgent::role) {
                tracing::info!(
                    agent_id = %agent_id,
                    role = agent_role_label(role),
                    from = previous_health
                        .map(agent_health_label)
                        .unwrap_or("unknown"),
                    to = agent_health_label(current_health),
                    module = module_path!(),
                    "agent health transitioned"
                );
                if let Some(metrics) = &self.metrics {
                    metrics.observe_agent_health_transition(agent_role_label(role));
                }
            }
        }
    }

    async fn load_recent_pheromones(&self) -> Vec<swarm_core::pheromone::PheromoneDeposit> {
        match self.substrate.recent_deposits(100).await {
            Ok(pheromones) => pheromones,
            Err(error) => {
                tracing::warn!(
                    reason = %error,
                    module = module_path!(),
                    "failed to load recent pheromones for agent tick"
                );
                Vec::new()
            }
        }
    }

    fn current_health_map(&self) -> HashMap<AgentId, AgentHealth> {
        self.registry
            .iter()
            .map(|(_, agent)| {
                (
                    agent.id().clone(),
                    self.effective_health(agent.id(), agent.health()),
                )
            })
            .collect()
    }

    fn effective_health(&self, agent_id: &AgentId, intrinsic: AgentHealth) -> AgentHealth {
        worse_health(intrinsic, self.health_overrides.get(agent_id).copied())
    }

    fn refresh_health_snapshot(&self) {
        self.health_state
            .store(Arc::new(self.agent_health_summary()));
    }
}

fn agent_finding_from_action(
    agent_id: &AgentId,
    role: AgentRole,
    action: &SwarmAction,
) -> Option<AgentFinding> {
    match action {
        SwarmAction::DepositPheromone {
            threat_class,
            severity,
            confidence,
            ..
        } => Some(AgentFinding {
            agent_id: agent_id.clone(),
            role,
            kind: "deposit_pheromone".to_string(),
            summary: format!(
                "threat_class={threat_class} severity={severity:?} confidence={confidence:.2}"
            ),
        }),
        SwarmAction::ClaimInvestigation { hunt_id, lead } => Some(AgentFinding {
            agent_id: agent_id.clone(),
            role,
            kind: "claim_investigation".to_string(),
            summary: format!("hunt_id={} lead={lead}", hunt_id.0),
        }),
        SwarmAction::PublishFindings {
            hunt_id,
            findings,
            confidence,
        } => Some(AgentFinding {
            agent_id: agent_id.clone(),
            role,
            kind: "publish_findings".to_string(),
            summary: format!(
                "hunt_id={} confidence={confidence:.2} findings={}",
                hunt_id.0, findings
            ),
        }),
        SwarmAction::RequestResponse {
            hunt_id, action, ..
        } => Some(AgentFinding {
            agent_id: agent_id.clone(),
            role,
            kind: "request_response".to_string(),
            summary: format!("hunt_id={} action={}", hunt_id.0, action.kind()),
        }),
        _ => None,
    }
}

fn agent_role_label(role: AgentRole) -> &'static str {
    match role {
        AgentRole::Whisker => "whisker",
        AgentRole::Stalker => "stalker",
        AgentRole::Weaver => "weaver",
        AgentRole::Pouncer => "pouncer",
        AgentRole::Tom => "tom",
        AgentRole::Kitten => "kitten",
        AgentRole::Sphinx => "sphinx",
        AgentRole::Calico => "calico",
    }
}

fn agent_health_label(health: AgentHealth) -> &'static str {
    match health {
        AgentHealth::Healthy => "healthy",
        AgentHealth::Degraded => "degraded",
        AgentHealth::Failed => "failed",
    }
}

fn worse_health(current: AgentHealth, override_status: Option<AgentHealth>) -> AgentHealth {
    match (current, override_status) {
        (AgentHealth::Failed, _) | (_, Some(AgentHealth::Failed)) => AgentHealth::Failed,
        (AgentHealth::Degraded, _) | (_, Some(AgentHealth::Degraded)) => AgentHealth::Degraded,
        _ => AgentHealth::Healthy,
    }
}

fn unix_timestamp_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{AgentDispatcher, AgentDispatcherConfig, AgentHealthEntry, agent_role_label};
    use crate::detection::metrics::{CriticalPathMetrics, encode_metrics};
    use arc_swap::ArcSwap;
    use async_trait::async_trait;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use swarm_core::agent::{
        AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError, SwarmEvent,
    };
    use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
    use swarm_core::types::{AgentId, SwarmAction};
    use swarm_pheromone::{ConfiguredPheromoneSubstrate, InMemoryPheromoneSubstrate};
    use tokio::sync::watch;

    struct MockAgent {
        id: AgentId,
        verifying_key: VerifyingKey,
        role: AgentRole,
        health: AgentHealth,
        ticks: Arc<AtomicUsize>,
        fail: bool,
        planned_actions: VecDeque<Vec<SwarmAction>>,
        observed_events: Arc<std::sync::Mutex<Vec<SwarmEvent>>>,
        last_peer_findings_len: Arc<AtomicUsize>,
    }

    impl MockAgent {
        fn new(
            id: &str,
            role: AgentRole,
            health: AgentHealth,
            ticks: Arc<AtomicUsize>,
            fail: bool,
        ) -> Self {
            let signing_key = SigningKey::from_bytes(&[7; 32]);
            Self {
                id: AgentId(id.to_string()),
                verifying_key: signing_key.verifying_key(),
                role,
                health,
                ticks,
                fail,
                planned_actions: VecDeque::new(),
                observed_events: Arc::new(std::sync::Mutex::new(Vec::new())),
                last_peer_findings_len: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn with_actions(mut self, planned_actions: Vec<Vec<SwarmAction>>) -> Self {
            self.planned_actions = planned_actions.into();
            self
        }

        fn with_event_log(
            mut self,
            observed_events: Arc<std::sync::Mutex<Vec<SwarmEvent>>>,
        ) -> Self {
            self.observed_events = observed_events;
            self
        }

        fn with_peer_finding_counter(mut self, counter: Arc<AtomicUsize>) -> Self {
            self.last_peer_findings_len = counter;
            self
        }
    }

    #[async_trait]
    impl SwarmAgent for MockAgent {
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
            self.observed_events.lock().unwrap().push(event.clone());
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
            self.ticks.fetch_add(1, Ordering::SeqCst);
            self.last_peer_findings_len
                .store(env.peer_findings.len(), Ordering::SeqCst);
            if self.fail {
                Err(SwarmError::SubstrateUnavailable("boom".to_string()))
            } else {
                Ok(self.planned_actions.pop_front().unwrap_or_default())
            }
        }

        fn health(&self) -> AgentHealth {
            self.health
        }
    }

    fn pheromone_config() -> PheromoneConfig {
        PheromoneConfig {
            default_half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
            backend: PheromoneBackendConfig::InMemory,
        }
    }

    fn substrate() -> ConfiguredPheromoneSubstrate {
        ConfiguredPheromoneSubstrate::InMemory(InMemoryPheromoneSubstrate::new(pheromone_config()))
    }

    fn empty_health_state() -> Arc<ArcSwap<Vec<AgentHealthEntry>>> {
        Arc::new(ArcSwap::from_pointee(Vec::new()))
    }

    #[tokio::test]
    async fn dispatcher_with_zero_agents_runs_and_shuts_down_cleanly() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let health_state = empty_health_state();
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig {
                tick_interval_ms: 5,
                ..AgentDispatcherConfig::default()
            },
            shutdown_rx,
            substrate(),
            Arc::clone(&health_state),
        );

        let handle = tokio::spawn(async move {
            dispatcher.run().await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();

        assert!(health_state.load_full().is_empty());
    }

    #[tokio::test]
    async fn dispatcher_ticks_registered_agents() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let health_state = empty_health_state();
        let ticks = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig {
                tick_interval_ms: 5,
                ..AgentDispatcherConfig::default()
            },
            shutdown_rx,
            substrate(),
            Arc::clone(&health_state),
        );
        dispatcher
            .register(Box::new(MockAgent::new(
                "whisker-primary",
                AgentRole::Whisker,
                AgentHealth::Healthy,
                Arc::clone(&ticks),
                false,
            )))
            .unwrap();

        let handle = tokio::spawn(async move {
            dispatcher.run().await;
        });
        tokio::time::sleep(Duration::from_millis(25)).await;
        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();

        assert!(ticks.load(Ordering::SeqCst) > 0);
        assert_eq!(health_state.load_full()[0].id, "whisker-primary");
    }

    #[test]
    fn dispatcher_reports_agent_health_summary() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig::default(),
            shutdown_rx,
            substrate(),
            empty_health_state(),
        );
        dispatcher
            .register(Box::new(MockAgent::new(
                "whisker-primary",
                AgentRole::Whisker,
                AgentHealth::Healthy,
                Arc::new(AtomicUsize::new(0)),
                false,
            )))
            .unwrap();
        dispatcher
            .register(Box::new(MockAgent::new(
                "stalker-primary",
                AgentRole::Stalker,
                AgentHealth::Degraded,
                Arc::new(AtomicUsize::new(0)),
                false,
            )))
            .unwrap();

        let summary = dispatcher.agent_health_summary();
        assert_eq!(summary.len(), 2);
        assert_eq!(summary[0].health, AgentHealth::Degraded);
        assert_eq!(summary[1].health, AgentHealth::Healthy);
    }

    #[tokio::test]
    async fn dispatcher_marks_failing_agents_degraded() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let health_state = empty_health_state();
        let ticks = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig {
                tick_interval_ms: 5,
                ..AgentDispatcherConfig::default()
            },
            shutdown_rx,
            substrate(),
            Arc::clone(&health_state),
        );
        dispatcher
            .register(Box::new(MockAgent::new(
                "whisker-primary",
                AgentRole::Whisker,
                AgentHealth::Healthy,
                Arc::clone(&ticks),
                true,
            )))
            .unwrap();

        let handle = tokio::spawn(async move {
            dispatcher.run().await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();

        assert!(ticks.load(Ordering::SeqCst) > 0);
        assert_eq!(health_state.load_full()[0].health, AgentHealth::Degraded);
    }

    #[test]
    fn dispatcher_can_deregister_agents_from_registry() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig::default(),
            shutdown_rx,
            substrate(),
            empty_health_state(),
        );
        let agent_id = AgentId::new("whisker", "primary");
        dispatcher
            .register(Box::new(MockAgent::new(
                &agent_id.to_string(),
                AgentRole::Whisker,
                AgentHealth::Healthy,
                Arc::new(AtomicUsize::new(0)),
                false,
            )))
            .unwrap();

        assert!(dispatcher.deregister(&agent_id));
        assert!(dispatcher.agent_health_summary().is_empty());
    }

    #[tokio::test]
    async fn dispatcher_broadcasts_role_shift_events_and_updates_roles() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let observer_events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig::default(),
            shutdown_rx,
            substrate(),
            empty_health_state(),
        );
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "whisker-primary",
                    AgentRole::Whisker,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )
                .with_actions(vec![vec![SwarmAction::RoleShift {
                    new_role: AgentRole::Tom,
                }]]),
            ))
            .unwrap();
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "stalker-primary",
                    AgentRole::Stalker,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )
                .with_event_log(Arc::clone(&observer_events)),
            ))
            .unwrap();

        dispatcher.tick_agents().await;

        let summary = dispatcher.agent_health_summary();
        assert_eq!(summary[1].role, AgentRole::Tom);
        let events = observer_events.lock().unwrap();
        assert!(events.iter().any(|event| matches!(
            event,
            SwarmEvent::RoleShift {
                agent_id,
                new_role: AgentRole::Tom,
                ..
            } if agent_id.0 == "whisker-primary"
        )));
    }

    #[tokio::test]
    async fn dispatcher_exposes_peer_findings_on_subsequent_ticks() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let stalker_peer_findings = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig::default(),
            shutdown_rx,
            substrate(),
            empty_health_state(),
        );
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "whisker-primary",
                    AgentRole::Whisker,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )
                .with_actions(vec![
                    vec![SwarmAction::DepositPheromone {
                        threat_class: "execution".to_string(),
                        severity: swarm_core::types::Severity::High,
                        indicator: serde_json::json!({"event_id": "evt-1"}),
                        confidence: 0.95,
                    }],
                    Vec::new(),
                ]),
            ))
            .unwrap();
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "stalker-primary",
                    AgentRole::Stalker,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )
                .with_peer_finding_counter(Arc::clone(&stalker_peer_findings)),
            ))
            .unwrap();

        dispatcher.tick_agents().await;
        assert_eq!(stalker_peer_findings.load(Ordering::SeqCst), 0);
        dispatcher.tick_agents().await;
        assert_eq!(stalker_peer_findings.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dispatcher_records_agent_metrics_on_shared_registry() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let metrics = CriticalPathMetrics::new();
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig::default(),
            shutdown_rx,
            substrate(),
            empty_health_state(),
        )
        .with_metrics(metrics.clone());
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "whisker-primary",
                    AgentRole::Whisker,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )
                .with_actions(vec![vec![
                    SwarmAction::RoleShift {
                        new_role: AgentRole::Stalker,
                    },
                    SwarmAction::HealthReport {
                        status: AgentHealth::Degraded,
                    },
                ]]),
            ))
            .unwrap();

        dispatcher.tick_agents().await;

        let encoded = encode_metrics(&metrics);
        assert!(encoded.contains(&format!(
            "swarm_agent_ticks_total{{role=\"{}\"}} 1",
            agent_role_label(AgentRole::Whisker)
        )));
        assert!(encoded.contains("swarm_agent_role_shifts_total{role=\"stalker\"} 1"));
        assert!(encoded.contains("swarm_agent_health_transitions_total{role=\"stalker\"} 1"));
    }

    struct SlowMockAgent {
        id: AgentId,
        verifying_key: VerifyingKey,
        delay: Duration,
    }

    impl SlowMockAgent {
        fn new(id: &str, delay: Duration) -> Self {
            let signing_key = SigningKey::from_bytes(&[9; 32]);
            Self {
                id: AgentId(id.to_string()),
                verifying_key: signing_key.verifying_key(),
                delay,
            }
        }
    }

    #[async_trait]
    impl SwarmAgent for SlowMockAgent {
        fn identity(&self) -> &VerifyingKey {
            &self.verifying_key
        }

        fn id(&self) -> &AgentId {
            &self.id
        }

        fn role(&self) -> AgentRole {
            AgentRole::Whisker
        }

        async fn tick(&mut self, _env: &SwarmEnvironment) -> Result<Vec<SwarmAction>, SwarmError> {
            tokio::time::sleep(self.delay).await;
            Ok(vec![])
        }

        fn health(&self) -> AgentHealth {
            AgentHealth::Healthy
        }
    }

    #[tokio::test]
    async fn dispatcher_marks_slow_agent_degraded_on_tick_timeout() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let health_state = empty_health_state();
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig {
                tick_interval_ms: 5,
                agent_tick_timeout_ms: 50,
                ..AgentDispatcherConfig::default()
            },
            shutdown_rx,
            substrate(),
            Arc::clone(&health_state),
        );
        dispatcher
            .register(Box::new(SlowMockAgent::new(
                "slow-whisker",
                Duration::from_millis(200),
            )))
            .unwrap();

        dispatcher.tick_agents().await;

        let snapshot = health_state.load_full();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].health, AgentHealth::Degraded);
    }

    #[tokio::test]
    async fn dispatcher_keeps_fast_agent_healthy_within_tick_timeout() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let health_state = empty_health_state();
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig {
                tick_interval_ms: 5,
                agent_tick_timeout_ms: 500,
                ..AgentDispatcherConfig::default()
            },
            shutdown_rx,
            substrate(),
            Arc::clone(&health_state),
        );
        dispatcher
            .register(Box::new(SlowMockAgent::new(
                "fast-whisker",
                Duration::from_millis(5),
            )))
            .unwrap();

        dispatcher.tick_agents().await;

        let snapshot = health_state.load_full();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].health, AgentHealth::Healthy);
    }

    #[tokio::test]
    async fn dispatcher_discards_actions_from_timed_out_agent() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let health_state = empty_health_state();
        let ticks = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig {
                tick_interval_ms: 5,
                agent_tick_timeout_ms: 50,
                ..AgentDispatcherConfig::default()
            },
            shutdown_rx,
            substrate(),
            Arc::clone(&health_state),
        );

        // Register a slow agent -- its tick will time out so any actions would be discarded
        dispatcher
            .register(Box::new(SlowMockAgent::new(
                "slow-whisker",
                Duration::from_millis(200),
            )))
            .unwrap();

        // Register a normal agent that emits a RoleShift -- should NOT see role shift broadcast
        // from the slow agent (because slow agent's result is discarded)
        let observer_events = Arc::new(std::sync::Mutex::new(Vec::new()));
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "normal-whisker",
                    AgentRole::Whisker,
                    AgentHealth::Healthy,
                    Arc::clone(&ticks),
                    false,
                )
                .with_event_log(Arc::clone(&observer_events)),
            ))
            .unwrap();

        dispatcher.tick_agents().await;

        // The slow agent should be degraded
        let snapshot = health_state.load_full();
        let slow_entry = snapshot.iter().find(|e| e.id == "slow-whisker").unwrap();
        assert_eq!(slow_entry.health, AgentHealth::Degraded);
    }

    #[test]
    fn default_agent_tick_timeout_is_500() {
        let config = AgentDispatcherConfig::default();
        assert_eq!(config.agent_tick_timeout_ms, 500);
    }
}
