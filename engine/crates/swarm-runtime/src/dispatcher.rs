use crate::detection::metrics::CriticalPathMetrics;
use crate::runtime_events::{RuntimeEvent, RuntimeEventBroadcaster, now_ms};
use crate::tom_agent::{GovernancePolicy, GovernanceRuntimeEvent};
use crate::{
    RuntimeError, StrategyProposalRouteError, agent_tick_error_boundary, agent_tick_panic_error,
};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use futures_util::FutureExt;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use swarm_consensus::ConsensusGovernanceReceipt;
use swarm_core::agent::{
    AgentFinding, AgentHealth, AgentHealthEntry, AgentRole, SwarmAgent, SwarmEnvironment,
    SwarmEvent, SwarmModeState,
};
use swarm_core::types::{AgentId, ResponseAction, Severity, SwarmAction};
use swarm_pheromone::{ConfiguredPheromoneSubstrate, PheromoneSubstrate};
use swarm_policy::static_gate::scope_for_response_action;
use swarm_policy::{ActionRequest, ApprovalContext};
use swarm_spine::AuditTrail;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

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

    pub fn replace(&mut self, agent: Box<dyn SwarmAgent>) -> Result<(), &'static str> {
        let agent_id = agent.id().clone();
        if !self.agents.contains_key(&agent_id) {
            return Err("agent registry does not contain that id");
        }
        self.agents.insert(agent_id, agent);
        Ok(())
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
    requested_by: AgentId,
    agent_id: AgentId,
    from_role: AgentRole,
    to_role: AgentRole,
}

#[derive(Debug, Clone)]
pub struct GovernanceVetoRoute {
    pub request: ActionRequest,
    pub governing_agent_id: AgentId,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct StrategyProposalRoute {
    pub proposed_by: AgentId,
    pub strategy_id: String,
    pub strategy: Value,
    pub fitness: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrategyProposalOutcome {
    Accepted,
    Blocked,
    Rejected,
}

#[derive(Debug, Clone)]
pub struct StrategyProposalRouteReport {
    pub strategy_id: String,
    pub outcome: StrategyProposalOutcome,
    pub selection_id: Option<String>,
    pub bridge_id: Option<String>,
    pub handoff_id: Option<String>,
    pub canary_run_id: Option<String>,
}

#[async_trait]
pub trait RequestResponseRouter: Send + Sync {
    async fn route_request(&self, request: ActionRequest) -> Result<AuditTrail, RuntimeError>;

    async fn route_governance_veto(
        &self,
        veto: GovernanceVetoRoute,
    ) -> Result<AuditTrail, RuntimeError>;
}

#[async_trait]
pub trait StrategyProposalRouter: Send + Sync {
    async fn route_proposal(
        &self,
        proposal: StrategyProposalRoute,
    ) -> Result<StrategyProposalRouteReport, StrategyProposalRouteError>;
}

pub struct AgentDispatcher {
    registry: AgentRegistry,
    restart_factories: HashMap<AgentId, AgentRestartFactory>,
    health_overrides: HashMap<AgentId, AgentHealth>,
    admitted_identities: Option<HashSet<AgentId>>,
    config: AgentDispatcherConfig,
    shutdown: watch::Receiver<bool>,
    substrate: ConfiguredPheromoneSubstrate,
    health_state: Arc<ArcSwap<Vec<AgentHealthEntry>>>,
    mode_state: Arc<ArcSwap<SwarmModeState>>,
    recent_findings: HashMap<AgentId, AgentFinding>,
    metrics: Option<CriticalPathMetrics>,
    request_response_router: Option<Arc<dyn RequestResponseRouter>>,
    strategy_proposal_router: Option<Arc<dyn StrategyProposalRouter>>,
    runtime_events: Option<RuntimeEventBroadcaster>,
    governance_policy: Option<Arc<GovernancePolicy>>,
}

pub type AgentRestartFactory = Arc<dyn Fn() -> Result<Box<dyn SwarmAgent>, String> + Send + Sync>;

impl AgentDispatcher {
    pub fn new(
        config: AgentDispatcherConfig,
        shutdown: watch::Receiver<bool>,
        substrate: ConfiguredPheromoneSubstrate,
        health_state: Arc<ArcSwap<Vec<AgentHealthEntry>>>,
    ) -> Self {
        Self {
            registry: AgentRegistry::new(),
            restart_factories: HashMap::new(),
            health_overrides: HashMap::new(),
            admitted_identities: None,
            config,
            shutdown,
            substrate,
            health_state,
            mode_state: Arc::new(ArcSwap::from_pointee(SwarmModeState::new())),
            recent_findings: HashMap::new(),
            metrics: None,
            request_response_router: None,
            strategy_proposal_router: None,
            runtime_events: None,
            governance_policy: None,
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

    pub fn with_request_response_router(mut self, router: Arc<dyn RequestResponseRouter>) -> Self {
        self.request_response_router = Some(router);
        self
    }

    pub fn with_strategy_proposal_router(
        mut self,
        router: Arc<dyn StrategyProposalRouter>,
    ) -> Self {
        self.strategy_proposal_router = Some(router);
        self
    }

    pub fn with_runtime_events(mut self, runtime_events: RuntimeEventBroadcaster) -> Self {
        self.runtime_events = Some(runtime_events);
        self
    }

    pub fn with_governance_policy(mut self, governance_policy: Arc<GovernancePolicy>) -> Self {
        self.governance_policy = Some(governance_policy);
        self
    }

    pub fn set_admitted_identities(
        &mut self,
        identities: impl IntoIterator<Item = AgentId>,
    ) -> &mut Self {
        let identities = identities.into_iter().collect::<Vec<_>>();
        self.admitted_identities = Some(identities.iter().cloned().collect());
        if let Err(error) = self.substrate.set_admitted_identities(identities) {
            tracing::warn!(
                reason = %error,
                module = module_path!(),
                "failed to propagate admitted identities to pheromone substrate"
            );
        }
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

    pub fn register_restartable(
        &mut self,
        agent: Box<dyn SwarmAgent>,
        restart_factory: AgentRestartFactory,
    ) -> Result<(), &'static str> {
        let agent_id = agent.id().clone();
        self.register(agent)?;
        self.restart_factories.insert(agent_id, restart_factory);
        Ok(())
    }

    pub fn deregister(&mut self, agent_id: &AgentId) -> bool {
        let removed = self.registry.deregister(agent_id);
        if removed {
            self.restart_factories.remove(agent_id);
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

    pub async fn tick_once(&mut self) {
        self.tick_agents().await;
    }

    async fn tick_agents(&mut self) {
        let before_health = self.current_health_map();
        let now = unix_timestamp_secs();
        let pheromones = self.load_recent_pheromones().await;
        let mode_state = self.mode_state.load();
        let mode = mode_state.current;
        let mode_transition_at = mode_state.last_transition_at;
        let peer_findings_snapshot = self.recent_findings.values().cloned().collect::<Vec<_>>();
        let agent_health_snapshot = self.agent_health_summary();
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
                agent_health: agent_health_snapshot.clone(),
            };
            let tick_role = agent.role();
            let tick_timeout = Duration::from_millis(self.config.agent_tick_timeout_ms);
            let tick_future = AssertUnwindSafe(agent.tick(&env)).catch_unwind();
            match tokio::time::timeout(tick_timeout, tick_future).await {
                Ok(Ok(Ok(actions))) => {
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
                Ok(Ok(Err(error))) => {
                    let error_boundary = agent_tick_error_boundary(&error).unwrap_or("swarm");
                    tracing::warn!(
                        agent_id = %agent_id,
                        role = agent_role_label(tick_role),
                        boundary = error_boundary,
                        reason = %error,
                        module = module_path!(),
                        "agent tick failed"
                    );
                    self.health_overrides
                        .insert(agent_id.clone(), AgentHealth::Degraded);
                }
                Ok(Err(panic_payload)) => {
                    let error = agent_tick_panic_error(agent_id, tick_role, panic_payload);
                    let error_boundary = agent_tick_error_boundary(&error).unwrap_or("swarm");
                    tracing::warn!(
                        agent_id = %agent_id,
                        role = agent_role_label(tick_role),
                        boundary = error_boundary,
                        reason = %error,
                        module = module_path!(),
                        "agent tick panicked"
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

        self.apply_actions(completed_ticks, now).await;
        self.restart_failed_agents();
        self.publish_governance_events();
        self.log_health_transitions(before_health);
        self.refresh_health_snapshot();
    }

    async fn apply_actions(&mut self, completed_ticks: Vec<CompletedAgentTick>, now: i64) {
        let mut pending_role_shifts = Vec::new();

        for completed in completed_ticks {
            let mut latest_finding = None;
            for action in completed.actions {
                if governance_action_requires_admission(&action)
                    && !self.is_governance_identity_admitted(&completed.agent_id)
                {
                    tracing::warn!(
                        agent_id = %completed.agent_id,
                        role = agent_role_label(completed.role),
                        action = swarm_action_kind(&action),
                        module = module_path!(),
                        "blocked governance action from unadmitted identity"
                    );
                    continue;
                }

                if let Some(finding) =
                    agent_finding_from_action(&completed.agent_id, completed.role, &action)
                {
                    latest_finding = Some(finding);
                }

                self.publish_agent_action(&completed.agent_id, completed.role, &action);

                match action {
                    SwarmAction::RoleShift {
                        target_agent_id,
                        new_role,
                    } => {
                        let Some(from_role) =
                            self.registry.get(&target_agent_id).map(SwarmAgent::role)
                        else {
                            tracing::warn!(
                                requested_by = %completed.agent_id,
                                target_agent_id = %target_agent_id,
                                new_role = agent_role_label(new_role),
                                module = module_path!(),
                                "role shift targeted an unknown agent"
                            );
                            continue;
                        };
                        pending_role_shifts.push(PendingRoleShift {
                            requested_by: completed.agent_id.clone(),
                            agent_id: target_agent_id,
                            from_role,
                            to_role: new_role,
                        })
                    }
                    SwarmAction::HealthReport {
                        target_agent_id,
                        status,
                    } => {
                        if self.registry.get(&target_agent_id).is_none() {
                            tracing::warn!(
                                requested_by = %completed.agent_id,
                                target_agent_id = %target_agent_id,
                                status = agent_health_label(status),
                                module = module_path!(),
                                "health report targeted an unknown agent"
                            );
                            continue;
                        }
                        self.health_overrides.insert(target_agent_id, status);
                    }
                    // Agent-direct: deposits are submitted to the substrate by the
                    // agent itself during tick(). The action is recorded as an
                    // AgentFinding for peer visibility but requires no dispatcher routing.
                    SwarmAction::DepositPheromone { .. } => {}
                    SwarmAction::RequestResponse {
                        hunt_id,
                        action,
                        evidence,
                    } => {
                        let hunt_id_value = hunt_id.0.clone();
                        let action_kind = action.kind().to_string();
                        let Some(router) = self.request_response_router.as_ref() else {
                            tracing::warn!(
                                agent_id = %completed.agent_id,
                                hunt_id = %hunt_id_value,
                                action = %action_kind,
                                module = module_path!(),
                                "request_response action dropped because no router is configured"
                            );
                            continue;
                        };

                        let Some(request) =
                            request_from_action(&completed.agent_id, hunt_id, action, evidence)
                        else {
                            tracing::warn!(
                                agent_id = %completed.agent_id,
                                hunt_id = %hunt_id_value,
                                action = %action_kind,
                                module = module_path!(),
                                "request_response action missing routable severity metadata"
                            );
                            continue;
                        };
                        let partition_authorized = match self.authorize_partition_request(&request)
                        {
                            Ok(authorized) => authorized,
                            Err(reason) => {
                                tracing::warn!(
                                    agent_id = %completed.agent_id,
                                    hunt_id = %request.hunt_id.0,
                                    action = %action_kind,
                                    reason = %reason,
                                    module = module_path!(),
                                    "request_response action rejected during partition authorization"
                                );
                                continue;
                            }
                        };
                        if !partition_authorized
                            && let Some(reason) = missing_governance_receipt_reason(&request)
                        {
                            tracing::warn!(
                                agent_id = %completed.agent_id,
                                hunt_id = %request.hunt_id.0,
                                action = %action_kind,
                                reason = %reason,
                                module = module_path!(),
                                "request_response action rejected before runtime routing"
                            );
                            continue;
                        }

                        match router.route_request(request).await {
                            Ok(audit) => {
                                self.publish_routed_response(
                                    &completed.agent_id,
                                    &audit,
                                    &action_kind,
                                    None,
                                    None,
                                );
                                tracing::info!(
                                    agent_id = %completed.agent_id,
                                    hunt_id = %audit.hunt_id,
                                    response_kind = audit.response_kind(),
                                    module = module_path!(),
                                    "request_response action routed through runtime"
                                );
                            }
                            Err(error) => {
                                self.publish_routed_response_error(
                                    &completed.agent_id,
                                    &hunt_id_value,
                                    &action_kind,
                                    None,
                                    error.to_string(),
                                );
                                tracing::warn!(
                                    agent_id = %completed.agent_id,
                                    hunt_id = %hunt_id_value,
                                    action = %action_kind,
                                    reason = %error,
                                    module = module_path!(),
                                    "request_response action failed during runtime routing"
                                );
                            }
                        }
                    }
                    SwarmAction::GovernanceVeto {
                        hunt_id,
                        action,
                        evidence,
                        governing_agent_id,
                        reason,
                    } => {
                        let hunt_id_value = hunt_id.0.clone();
                        let action_kind = action.kind().to_string();
                        let Some(router) = self.request_response_router.as_ref() else {
                            tracing::warn!(
                                agent_id = %completed.agent_id,
                                hunt_id = %hunt_id_value,
                                action = %action_kind,
                                governing_agent_id = %governing_agent_id,
                                module = module_path!(),
                                "governance veto dropped because no router is configured"
                            );
                            continue;
                        };

                        let Some(request) =
                            request_from_action(&completed.agent_id, hunt_id, action, evidence)
                        else {
                            tracing::warn!(
                                agent_id = %completed.agent_id,
                                hunt_id = %hunt_id_value,
                                action = %action_kind,
                                governing_agent_id = %governing_agent_id,
                                module = module_path!(),
                                "governance veto missing routable severity metadata"
                            );
                            continue;
                        };
                        if self
                            .governance_policy
                            .as_ref()
                            .is_some_and(|policy| policy.is_partitioned())
                        {
                            if let Some(policy) = &self.governance_policy {
                                policy.note_partition_veto(
                                    &request,
                                    &reason,
                                    unix_timestamp_millis(),
                                );
                            }
                        } else if let Some(reason) = missing_governance_receipt_reason(&request) {
                            tracing::warn!(
                                agent_id = %completed.agent_id,
                                hunt_id = %request.hunt_id.0,
                                action = %action_kind,
                                governing_agent_id = %governing_agent_id,
                                reason = %reason,
                                module = module_path!(),
                                "governance veto rejected before runtime routing"
                            );
                            continue;
                        }

                        match router
                            .route_governance_veto(GovernanceVetoRoute {
                                request,
                                governing_agent_id: governing_agent_id.clone(),
                                reason: reason.clone(),
                            })
                            .await
                        {
                            Ok(audit) => {
                                self.publish_routed_response(
                                    &completed.agent_id,
                                    &audit,
                                    &action_kind,
                                    Some(governing_agent_id.to_string()),
                                    None,
                                );
                                tracing::info!(
                                    agent_id = %completed.agent_id,
                                    hunt_id = %audit.hunt_id,
                                    response_kind = audit.response_kind(),
                                    governing_agent_id = %governing_agent_id,
                                    module = module_path!(),
                                    "governance veto routed through runtime"
                                );
                            }
                            Err(error) => {
                                self.publish_routed_response_error(
                                    &completed.agent_id,
                                    &hunt_id_value,
                                    &action_kind,
                                    Some(governing_agent_id.to_string()),
                                    error.to_string(),
                                );
                                tracing::warn!(
                                    agent_id = %completed.agent_id,
                                    hunt_id = %hunt_id_value,
                                    action = %action_kind,
                                    governing_agent_id = %governing_agent_id,
                                    reason = %error,
                                    module = module_path!(),
                                    "governance veto failed during runtime routing"
                                );
                            }
                        }
                    }
                    // Agent-direct: the stalker agent manages investigation state
                    // internally. These exist in SwarmAction so they can be recorded
                    // as AgentFindings for peer visibility.
                    SwarmAction::ClaimInvestigation { hunt_id, lead } => {
                        tracing::debug!(
                            agent_id = %completed.agent_id,
                            hunt_id = %hunt_id.0,
                            lead = %lead,
                            module = module_path!(),
                            "agent-direct action: claim_investigation (not dispatcher-routed)"
                        );
                    }
                    SwarmAction::PublishFindings {
                        hunt_id,
                        confidence,
                        ..
                    } => {
                        tracing::debug!(
                            agent_id = %completed.agent_id,
                            hunt_id = %hunt_id.0,
                            confidence = %confidence,
                            module = module_path!(),
                            "agent-direct action: publish_findings (not dispatcher-routed)"
                        );
                    }
                    SwarmAction::FeedbackSignal { signal } => {
                        tracing::debug!(
                            agent_id = %completed.agent_id,
                            incident_id = %signal.incident_id,
                            finding_id = ?signal.finding_id,
                            strategy_id = ?signal.strategy_id,
                            module = module_path!(),
                            "agent-direct action: feedback_signal (not dispatcher-routed)"
                        );
                    }
                    SwarmAction::ProposeStrategy {
                        strategy_id,
                        fitness,
                        strategy,
                    } => {
                        let Some(router) = self.strategy_proposal_router.as_ref() else {
                            tracing::warn!(
                                agent_id = %completed.agent_id,
                                action = "propose_strategy",
                                strategy_id = %strategy_id,
                                fitness = %fitness,
                                module = module_path!(),
                                "strategy proposal dropped because no router is configured"
                            );
                            continue;
                        };
                        let router = Arc::clone(router);
                        let proposed_by = completed.agent_id.clone();
                        tokio::spawn(async move {
                            match router
                                .route_proposal(StrategyProposalRoute {
                                    proposed_by: proposed_by.clone(),
                                    strategy_id: strategy_id.clone(),
                                    strategy,
                                    fitness,
                                })
                                .await
                            {
                                Ok(report) => {
                                    tracing::info!(
                                        agent_id = %proposed_by,
                                        strategy_id = %report.strategy_id,
                                        outcome = ?report.outcome,
                                        selection_id = report.selection_id.as_deref().unwrap_or("none"),
                                        bridge_id = report.bridge_id.as_deref().unwrap_or("none"),
                                        handoff_id = report.handoff_id.as_deref().unwrap_or("none"),
                                        canary_run_id = report.canary_run_id.as_deref().unwrap_or("none"),
                                        module = module_path!(),
                                        "strategy proposal routed through the formal safety and canary lane"
                                    );
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        agent_id = %proposed_by,
                                        strategy_id = %strategy_id,
                                        fitness = %fitness,
                                        boundary = error.boundary(),
                                        reason = %error,
                                        module = module_path!(),
                                        "strategy proposal failed during runtime routing"
                                    );
                                }
                            }
                        });
                    }
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

    fn is_governance_identity_admitted(&self, agent_id: &AgentId) -> bool {
        self.admitted_identities
            .as_ref()
            .is_none_or(|identities| identities.contains(agent_id))
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
            requested_by = %role_shift.requested_by,
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
                if let Some(runtime_events) = &self.runtime_events {
                    runtime_events.publish(RuntimeEvent::AgentHealth {
                        emitted_at_ms: now_ms(),
                        agent_id: agent_id.to_string(),
                        role,
                        from: previous_health,
                        to: current_health,
                    });
                }
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

    fn publish_agent_action(&self, agent_id: &AgentId, role: AgentRole, action: &SwarmAction) {
        let Some(runtime_events) = &self.runtime_events else {
            return;
        };

        runtime_events.publish(RuntimeEvent::AgentAction {
            emitted_at_ms: now_ms(),
            agent_id: agent_id.to_string(),
            role,
            action_kind: swarm_action_kind(action).to_string(),
            hunt_id: swarm_action_hunt_id(action).map(ToString::to_string),
            details: serde_json::to_value(action).unwrap_or_else(|error| {
                json!({
                    "type": "serialization_error",
                    "reason": error.to_string(),
                })
            }),
        });
    }

    fn publish_routed_response(
        &self,
        agent_id: &AgentId,
        audit: &AuditTrail,
        action_kind: &str,
        governing_agent_id: Option<String>,
        error: Option<String>,
    ) {
        let Some(runtime_events) = &self.runtime_events else {
            return;
        };

        runtime_events.publish(RuntimeEvent::ResponseExecution {
            emitted_at_ms: now_ms(),
            agent_id: agent_id.to_string(),
            hunt_id: audit.hunt_id.clone(),
            action_kind: action_kind.to_string(),
            response_kind: audit.response_kind().to_string(),
            policy_verdict: audit.policy.verdict,
            rule_name: audit.policy.rule_name.clone(),
            reason: audit.policy.reason.clone(),
            receipt_id: audit.response_receipt_id().map(ToString::to_string),
            governing_agent_id,
            error,
        });
    }

    fn publish_routed_response_error(
        &self,
        agent_id: &AgentId,
        hunt_id: &str,
        action_kind: &str,
        governing_agent_id: Option<String>,
        error: String,
    ) {
        let Some(runtime_events) = &self.runtime_events else {
            return;
        };

        runtime_events.publish(RuntimeEvent::ResponseExecution {
            emitted_at_ms: now_ms(),
            agent_id: agent_id.to_string(),
            hunt_id: hunt_id.to_string(),
            action_kind: action_kind.to_string(),
            response_kind: "routing_error".to_string(),
            policy_verdict: swarm_policy::PolicyVerdict::Deny,
            rule_name: "runtime.routing".to_string(),
            reason: error.clone(),
            receipt_id: None,
            governing_agent_id,
            error: Some(error),
        });
    }

    fn authorize_partition_request(&self, request: &ActionRequest) -> Result<bool, String> {
        let Some(governance_policy) = &self.governance_policy else {
            return Ok(false);
        };
        governance_policy
            .authorize_partition_request(request, unix_timestamp_millis())
            .map(|lease| lease.is_some())
    }

    fn publish_governance_events(&self) {
        let Some(governance_policy) = &self.governance_policy else {
            return;
        };
        let events = governance_policy.drain_runtime_events();
        if events.is_empty() {
            return;
        }
        let Some(runtime_events) = &self.runtime_events else {
            return;
        };

        for event in events {
            let (agent_id, action_kind) = match &event {
                GovernanceRuntimeEvent::PartitionStateTransition {
                    governing_agent_id, ..
                } => (governing_agent_id.to_string(), "partition_state_transition"),
                GovernanceRuntimeEvent::PartitionReconciliation {
                    governing_agent_id, ..
                } => (governing_agent_id.to_string(), "partition_reconciliation"),
            };
            runtime_events.publish(RuntimeEvent::AgentAction {
                emitted_at_ms: now_ms(),
                agent_id,
                role: AgentRole::Tom,
                action_kind: action_kind.to_string(),
                hunt_id: None,
                details: serde_json::to_value(&event).unwrap_or_else(|error| {
                    json!({
                        "type": "serialization_error",
                        "reason": error.to_string(),
                    })
                }),
            });
        }
    }

    fn restart_failed_agents(&mut self) {
        let failed_agents = self
            .current_health_map()
            .into_iter()
            .filter_map(|(agent_id, health)| (health == AgentHealth::Failed).then_some(agent_id))
            .collect::<Vec<_>>();

        for agent_id in failed_agents {
            let Some(current_role) = self.registry.get(&agent_id).map(SwarmAgent::role) else {
                continue;
            };
            let Some(restart_factory) = self.restart_factories.get(&agent_id).cloned() else {
                tracing::warn!(
                    agent_id = %agent_id,
                    role = agent_role_label(current_role),
                    module = module_path!(),
                    "agent reached failed health without a configured restart factory"
                );
                continue;
            };

            match (restart_factory.as_ref())() {
                Ok(agent) => {
                    if agent.id() != &agent_id {
                        tracing::warn!(
                            agent_id = %agent_id,
                            role = agent_role_label(current_role),
                            rebuilt_agent_id = %agent.id(),
                            module = module_path!(),
                            "agent restart factory returned a mismatched identity"
                        );
                        self.publish_agent_restart(
                            &agent_id,
                            current_role,
                            "failed",
                            Some("restart factory returned mismatched identity".to_string()),
                        );
                        continue;
                    }

                    let restarted_role = agent.role();
                    if let Err(error) = self.registry.replace(agent) {
                        tracing::warn!(
                            agent_id = %agent_id,
                            role = agent_role_label(current_role),
                            reason = error,
                            module = module_path!(),
                            "failed to replace agent during targeted restart"
                        );
                        self.publish_agent_restart(
                            &agent_id,
                            current_role,
                            "failed",
                            Some(error.to_string()),
                        );
                        continue;
                    }

                    self.health_overrides
                        .insert(agent_id.clone(), AgentHealth::Degraded);
                    tracing::info!(
                        agent_id = %agent_id,
                        previous_role = agent_role_label(current_role),
                        restarted_role = agent_role_label(restarted_role),
                        module = module_path!(),
                        "agent restarted after crossing failed health boundary"
                    );
                    self.publish_agent_restart(&agent_id, restarted_role, "succeeded", None);
                }
                Err(error) => {
                    tracing::warn!(
                        agent_id = %agent_id,
                        role = agent_role_label(current_role),
                        reason = %error,
                        module = module_path!(),
                        "agent restart failed after crossing failed health boundary"
                    );
                    self.publish_agent_restart(&agent_id, current_role, "failed", Some(error));
                }
            }
        }
    }

    fn publish_agent_restart(
        &self,
        agent_id: &AgentId,
        role: AgentRole,
        outcome: &str,
        reason: Option<String>,
    ) {
        let Some(runtime_events) = &self.runtime_events else {
            return;
        };

        runtime_events.publish(RuntimeEvent::AgentAction {
            emitted_at_ms: now_ms(),
            agent_id: agent_id.to_string(),
            role,
            action_kind: "agent_restart".to_string(),
            hunt_id: None,
            details: json!({
                "agent_id": agent_id,
                "role": role,
                "trigger_health": "failed",
                "outcome": outcome,
                "reason": reason,
            }),
        });
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
            summary: format!(
                "hunt_id={} action={}{}",
                hunt_id.0,
                action.kind(),
                scope_for_response_action(action)
                    .map(|scope| format!(" scope={scope}"))
                    .unwrap_or_default()
            ),
        }),
        SwarmAction::GovernanceVeto {
            hunt_id,
            action,
            governing_agent_id,
            ..
        } => Some(AgentFinding {
            agent_id: agent_id.clone(),
            role,
            kind: "governance_veto".to_string(),
            summary: format!(
                "hunt_id={} action={} governing_agent_id={}",
                hunt_id.0,
                action.kind(),
                governing_agent_id
            ),
        }),
        SwarmAction::ProposeStrategy {
            strategy_id,
            fitness,
            ..
        } => Some(AgentFinding {
            agent_id: agent_id.clone(),
            role,
            kind: "propose_strategy".to_string(),
            summary: format!("strategy_id={strategy_id} fitness={fitness:.3}"),
        }),
        SwarmAction::FeedbackSignal { signal } => Some(AgentFinding {
            agent_id: agent_id.clone(),
            role,
            kind: "feedback_signal".to_string(),
            summary: format!(
                "action={:?} incident_id={} finding_id={} strategy_id={}",
                signal.action,
                signal.incident_id,
                signal.finding_id.as_deref().unwrap_or("n/a"),
                signal.strategy_id.as_deref().unwrap_or("n/a")
            ),
        }),
        _ => None,
    }
}

fn swarm_action_kind(action: &SwarmAction) -> &'static str {
    match action {
        SwarmAction::DepositPheromone { .. } => "deposit_pheromone",
        SwarmAction::ClaimInvestigation { .. } => "claim_investigation",
        SwarmAction::PublishFindings { .. } => "publish_findings",
        SwarmAction::RequestResponse { .. } => "request_response",
        SwarmAction::ProposeStrategy { .. } => "propose_strategy",
        SwarmAction::FeedbackSignal { .. } => "feedback_signal",
        SwarmAction::RoleShift { .. } => "role_shift",
        SwarmAction::HealthReport { .. } => "health_report",
        SwarmAction::GovernanceVeto { .. } => "governance_veto",
    }
}

fn governance_action_requires_admission(action: &SwarmAction) -> bool {
    matches!(
        action,
        SwarmAction::RoleShift { .. }
            | SwarmAction::HealthReport { .. }
            | SwarmAction::RequestResponse { .. }
            | SwarmAction::GovernanceVeto { .. }
            | SwarmAction::ProposeStrategy { .. }
    )
}

fn response_action_requires_governance_receipt(action: &ResponseAction) -> bool {
    matches!(
        action,
        ResponseAction::BlockEgress { .. }
            | ResponseAction::IsolateHost { .. }
            | ResponseAction::RevokeCredential { .. }
            | ResponseAction::SinkholeDns { .. }
            | ResponseAction::TerminateUserSession { .. }
            | ResponseAction::InjectFirewallRule { .. }
            | ResponseAction::QuarantineFile { .. }
            | ResponseAction::KillProcess { .. }
            | ResponseAction::SuspendProcess { .. }
            | ResponseAction::DisableUserAccount { .. }
            | ResponseAction::ForcePasswordReset { .. }
            | ResponseAction::RemoveScheduledTask { .. }
    )
}

fn missing_governance_receipt_reason(request: &ActionRequest) -> Option<String> {
    if !response_action_requires_governance_receipt(&request.action) {
        return None;
    }
    let Some(receipt_value) = request.evidence.get("governance_receipt").cloned() else {
        return Some("missing governance receipt".to_string());
    };
    let receipt: ConsensusGovernanceReceipt = match serde_json::from_value(receipt_value) {
        Ok(receipt) => receipt,
        Err(error) => return Some(format!("invalid governance receipt: {error}")),
    };
    receipt
        .verify()
        .map(|_| ())
        .map_err(|error| format!("invalid governance receipt signature: {error}"))
        .err()
}

fn swarm_action_hunt_id(action: &SwarmAction) -> Option<&swarm_core::types::HuntId> {
    match action {
        SwarmAction::ClaimInvestigation { hunt_id, .. }
        | SwarmAction::PublishFindings { hunt_id, .. }
        | SwarmAction::RequestResponse { hunt_id, .. }
        | SwarmAction::GovernanceVeto { hunt_id, .. } => Some(hunt_id),
        SwarmAction::DepositPheromone { .. }
        | SwarmAction::ProposeStrategy { .. }
        | SwarmAction::FeedbackSignal { .. }
        | SwarmAction::RoleShift { .. }
        | SwarmAction::HealthReport { .. } => None,
    }
}

fn request_from_action(
    agent_id: &AgentId,
    hunt_id: swarm_core::types::HuntId,
    action: swarm_core::types::ResponseAction,
    evidence: serde_json::Value,
) -> Option<ActionRequest> {
    let severity = evidence
        .get("escalation")
        .and_then(|value| value.get("severity"))
        .cloned()
        .and_then(|value| serde_json::from_value::<Severity>(value).ok())?;

    Some(ActionRequest {
        hunt_id,
        requested_by: agent_id.clone(),
        action,
        severity,
        evidence,
    })
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

pub(crate) fn approval_context_now(live_mode: bool) -> ApprovalContext {
    ApprovalContext {
        live_mode,
        receipt_chain: Vec::new(),
        correlation_id: None,
        now_ms: unix_timestamp_millis(),
    }
}

fn unix_timestamp_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{
        AgentDispatcher, AgentDispatcherConfig, AgentRestartFactory, StrategyProposalOutcome,
        StrategyProposalRoute, StrategyProposalRouteReport, StrategyProposalRouter,
        agent_role_label,
    };
    use crate::detection::metrics::{CriticalPathMetrics, encode_metrics};
    use crate::runtime_events::{RuntimeEvent, RuntimeEventBroadcaster};
    use crate::tom_agent::{GovernancePolicy, GovernancePolicyConfig, TomAgent};
    use crate::{
        StrategyProposalRouteError, agent_tick_error_boundary, agent_tick_error_role,
        agent_tick_panic_error,
    };
    use arc_swap::ArcSwap;
    use async_trait::async_trait;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use swarm_core::agent::{
        AgentHealth, AgentHealthEntry, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError,
        SwarmEvent,
    };
    use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
    use swarm_core::types::{AgentId, HuntId, SwarmAction};
    use swarm_pheromone::{ConfiguredPheromoneSubstrate, InMemoryPheromoneSubstrate};
    use tokio::sync::{mpsc, watch};

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

    struct MockStrategyProposalRouter {
        tx: mpsc::UnboundedSender<StrategyProposalRoute>,
        result: std::sync::Mutex<
            Option<Result<StrategyProposalRouteReport, StrategyProposalRouteError>>,
        >,
    }

    #[async_trait]
    impl StrategyProposalRouter for MockStrategyProposalRouter {
        async fn route_proposal(
            &self,
            proposal: StrategyProposalRoute,
        ) -> Result<StrategyProposalRouteReport, StrategyProposalRouteError> {
            let _ = self.tx.send(proposal);
            self.result
                .lock()
                .expect("mock strategy proposal router mutex poisoned")
                .take()
                .expect("mock strategy proposal router result missing")
        }
    }

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
    async fn dispatcher_publishes_partition_state_transitions_to_runtime_events() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let health_state = empty_health_state();
        let governance_policy = Arc::new(GovernancePolicy::new(GovernancePolicyConfig {
            contingency_lease_ttl_ms: 60_000,
            contingency_blast_radius_cap: 1,
        }));
        governance_policy.register_governor(
            AgentId::new("tom", "primary"),
            SigningKey::from_bytes(&[31; 32]),
        );
        governance_policy.observe_health(
            &AgentId::new("tom", "primary"),
            &[AgentHealthEntry {
                id: "tom-primary".to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Failed,
            }],
            1_700_000_000_000,
        );

        let broadcaster = RuntimeEventBroadcaster::new(8);
        let mut receiver = broadcaster.subscribe();
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig::default(),
            shutdown_rx,
            substrate(),
            health_state,
        )
        .with_governance_policy(governance_policy)
        .with_runtime_events(broadcaster);

        dispatcher.tick_once().await;

        let event = receiver.recv().await.unwrap();
        match event {
            RuntimeEvent::AgentAction {
                action_kind,
                details,
                ..
            } => {
                assert_eq!(action_kind, "partition_state_transition");
                assert_eq!(details["kind"], "partition_state_transition");
                assert_eq!(details["to"], "partitioned");
            }
            other => panic!("expected agent_action runtime event, got {other:?}"),
        }
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
    async fn dispatcher_applies_targeted_role_shift_from_tom_agent() {
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
                    "tom-primary",
                    AgentRole::Tom,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )
                .with_actions(vec![vec![SwarmAction::RoleShift {
                    target_agent_id: AgentId::new("whisker", "primary"),
                    new_role: AgentRole::Tom,
                }]]),
            ))
            .unwrap();
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "whisker-primary",
                    AgentRole::Whisker,
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
    async fn dispatcher_rejects_governance_actions_from_unadmitted_identities() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let observer_events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig::default(),
            shutdown_rx,
            substrate(),
            empty_health_state(),
        );
        dispatcher.set_admitted_identities([AgentId::new("whisker", "primary")]);
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "tom-primary",
                    AgentRole::Tom,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )
                .with_actions(vec![vec![SwarmAction::RoleShift {
                    target_agent_id: AgentId::new("whisker", "primary"),
                    new_role: AgentRole::Tom,
                }]]),
            ))
            .unwrap();
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "whisker-primary",
                    AgentRole::Whisker,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )
                .with_event_log(Arc::clone(&observer_events)),
            ))
            .unwrap();

        dispatcher.tick_agents().await;

        let summary = dispatcher.agent_health_summary();
        assert_eq!(summary[1].role, AgentRole::Whisker);
        assert!(observer_events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dispatcher_applies_targeted_failed_health_report_from_tom_agent() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let health_state = empty_health_state();
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig::default(),
            shutdown_rx,
            substrate(),
            Arc::clone(&health_state),
        );
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "tom-primary",
                    AgentRole::Tom,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )
                .with_actions(vec![vec![SwarmAction::HealthReport {
                    target_agent_id: AgentId::new("whisker", "primary"),
                    status: AgentHealth::Failed,
                }]]),
            ))
            .unwrap();
        dispatcher
            .register(Box::new(MockAgent::new(
                "whisker-primary",
                AgentRole::Whisker,
                AgentHealth::Healthy,
                Arc::new(AtomicUsize::new(0)),
                false,
            )))
            .unwrap();

        dispatcher.tick_agents().await;

        let summary = health_state.load_full();
        assert!(
            summary.iter().any(|entry| {
                entry.id == "whisker-primary" && entry.health == AgentHealth::Failed
            })
        );
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
                        target_agent_id: AgentId::new("whisker", "primary"),
                        new_role: AgentRole::Stalker,
                    },
                    SwarmAction::HealthReport {
                        target_agent_id: AgentId::new("whisker", "primary"),
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

    struct PanicMockAgent {
        id: AgentId,
        verifying_key: VerifyingKey,
        role: AgentRole,
        ticks: Arc<AtomicUsize>,
        message: &'static str,
    }

    impl PanicMockAgent {
        fn new(id: &str, role: AgentRole, ticks: Arc<AtomicUsize>, message: &'static str) -> Self {
            let signing_key = SigningKey::from_bytes(&[11; 32]);
            Self {
                id: AgentId(id.to_string()),
                verifying_key: signing_key.verifying_key(),
                role,
                ticks,
                message,
            }
        }
    }

    #[async_trait]
    impl SwarmAgent for PanicMockAgent {
        fn identity(&self) -> &VerifyingKey {
            &self.verifying_key
        }

        fn id(&self) -> &AgentId {
            &self.id
        }

        fn role(&self) -> AgentRole {
            self.role
        }

        async fn tick(&mut self, _env: &SwarmEnvironment) -> Result<Vec<SwarmAction>, SwarmError> {
            self.ticks.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            panic!("{}", self.message);
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
    fn agent_tick_panic_error_preserves_boundary_and_role() {
        let error = agent_tick_panic_error(
            &AgentId::new("kitten", "evolver"),
            AgentRole::Kitten,
            Box::new("kitten exploded"),
        );

        assert_eq!(agent_tick_error_boundary(&error), Some("panic"));
        assert_eq!(agent_tick_error_role(&error), Some(AgentRole::Kitten));
        assert!(error.to_string().contains("kitten-evolver"));
        assert!(error.to_string().contains("kitten exploded"));
    }

    #[tokio::test]
    async fn dispatcher_isolates_panicking_agent_and_keeps_run_loop_alive() {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let health_state = empty_health_state();
        let panic_ticks = Arc::new(AtomicUsize::new(0));
        let healthy_ticks = Arc::new(AtomicUsize::new(0));
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
            .register(Box::new(PanicMockAgent::new(
                "kitten-evolver",
                AgentRole::Kitten,
                Arc::clone(&panic_ticks),
                "kitten panic",
            )))
            .unwrap();
        dispatcher
            .register(Box::new(MockAgent::new(
                "whisker-primary",
                AgentRole::Whisker,
                AgentHealth::Healthy,
                Arc::clone(&healthy_ticks),
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

        assert!(panic_ticks.load(Ordering::SeqCst) > 0);
        assert!(healthy_ticks.load(Ordering::SeqCst) > 0);

        let snapshot = health_state.load_full();
        let panicking = snapshot
            .iter()
            .find(|entry| entry.id == "kitten-evolver")
            .unwrap();
        let healthy = snapshot
            .iter()
            .find(|entry| entry.id == "whisker-primary")
            .unwrap();
        assert_eq!(panicking.health, AgentHealth::Degraded);
        assert_eq!(healthy.health, AgentHealth::Healthy);
    }

    #[tokio::test]
    async fn dispatcher_restarts_failed_agent_after_tom_failure_boundary() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let health_state = empty_health_state();
        let governance_policy = Arc::new(GovernancePolicy::new(GovernancePolicyConfig::default()));
        let restart_builds = Arc::new(AtomicUsize::new(0));
        let restarted_agent_ticks = Arc::new(AtomicUsize::new(0));
        let healthy_peer_ticks = Arc::new(AtomicUsize::new(0));
        let restart_factory: AgentRestartFactory = Arc::new({
            let restart_builds = Arc::clone(&restart_builds);
            let restarted_agent_ticks = Arc::clone(&restarted_agent_ticks);
            move || {
                let build_index = restart_builds.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(MockAgent::new(
                    "whisker-primary",
                    AgentRole::Whisker,
                    AgentHealth::Healthy,
                    Arc::clone(&restarted_agent_ticks),
                    build_index == 0,
                )) as Box<dyn SwarmAgent>)
            }
        });
        let initial_agent = (restart_factory.as_ref())().unwrap();
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig::default(),
            shutdown_rx,
            substrate(),
            Arc::clone(&health_state),
        )
        .with_governance_policy(Arc::clone(&governance_policy));
        dispatcher
            .register_restartable(initial_agent, Arc::clone(&restart_factory))
            .unwrap();
        dispatcher
            .register(Box::new(TomAgent::new_with_signing_key(
                AgentId::new("tom", "primary"),
                SigningKey::from_bytes(&[17; 32]),
                1,
                Arc::clone(&governance_policy),
            )))
            .unwrap();
        dispatcher
            .register(Box::new(MockAgent::new(
                "observer-whisker",
                AgentRole::Whisker,
                AgentHealth::Healthy,
                Arc::clone(&healthy_peer_ticks),
                false,
            )))
            .unwrap();

        dispatcher.tick_agents().await;
        let snapshot = health_state.load_full();
        assert_eq!(
            snapshot
                .iter()
                .find(|entry| entry.id == "whisker-primary")
                .unwrap()
                .health,
            AgentHealth::Degraded
        );

        dispatcher.tick_agents().await;
        let snapshot = health_state.load_full();
        assert_eq!(restart_builds.load(Ordering::SeqCst), 2);
        assert_eq!(
            snapshot
                .iter()
                .find(|entry| entry.id == "whisker-primary")
                .unwrap()
                .health,
            AgentHealth::Degraded
        );

        dispatcher.tick_agents().await;
        let snapshot = health_state.load_full();
        assert_eq!(
            snapshot
                .iter()
                .find(|entry| entry.id == "whisker-primary")
                .unwrap()
                .health,
            AgentHealth::Healthy
        );
        assert!(healthy_peer_ticks.load(Ordering::SeqCst) > 0);
        assert!(restarted_agent_ticks.load(Ordering::SeqCst) >= 3);
    }

    #[tokio::test]
    async fn dispatcher_leaves_agent_failed_when_restart_factory_errors() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let health_state = empty_health_state();
        let restart_attempts = Arc::new(AtomicUsize::new(0));
        let restart_factory: AgentRestartFactory = Arc::new({
            let restart_attempts = Arc::clone(&restart_attempts);
            move || {
                restart_attempts.fetch_add(1, Ordering::SeqCst);
                Err("restart build failed".to_string())
            }
        });
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig::default(),
            shutdown_rx,
            substrate(),
            Arc::clone(&health_state),
        );
        dispatcher
            .register_restartable(
                Box::new(MockAgent::new(
                    "whisker-primary",
                    AgentRole::Whisker,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )),
                restart_factory,
            )
            .unwrap();
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "tom-primary",
                    AgentRole::Tom,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )
                .with_actions(vec![vec![SwarmAction::HealthReport {
                    target_agent_id: AgentId::new("whisker", "primary"),
                    status: AgentHealth::Failed,
                }]]),
            ))
            .unwrap();

        dispatcher.tick_agents().await;

        let snapshot = health_state.load_full();
        assert_eq!(restart_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            snapshot
                .iter()
                .find(|entry| entry.id == "whisker-primary")
                .unwrap()
                .health,
            AgentHealth::Failed
        );
    }

    #[test]
    fn default_agent_tick_timeout_is_500() {
        let config = AgentDispatcherConfig::default();
        assert_eq!(config.agent_tick_timeout_ms, 500);
    }

    #[tokio::test]
    async fn dispatcher_logs_warning_for_unhandled_propose_strategy_action() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
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
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "kitten-evolver",
                    AgentRole::Kitten,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )
                .with_actions(vec![vec![SwarmAction::ProposeStrategy {
                    strategy_id: "strategy-1".to_string(),
                    strategy: serde_json::json!({"kind": "evolved"}),
                    fitness: 0.87,
                }]]),
            ))
            .unwrap();

        // Tick should not panic; the agent should remain healthy
        dispatcher.tick_agents().await;

        let snapshot = health_state.load_full();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].health, AgentHealth::Healthy);
    }

    #[tokio::test]
    async fn dispatcher_routes_kitten_strategy_proposals_through_configured_router() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig {
                tick_interval_ms: 5,
                ..AgentDispatcherConfig::default()
            },
            shutdown_rx,
            substrate(),
            empty_health_state(),
        )
        .with_strategy_proposal_router(Arc::new(MockStrategyProposalRouter {
            tx,
            result: std::sync::Mutex::new(Some(Ok(StrategyProposalRouteReport {
                strategy_id: "strategy-1".to_string(),
                outcome: StrategyProposalOutcome::Accepted,
                selection_id: Some("selection-1".to_string()),
                bridge_id: Some("bridge-1".to_string()),
                handoff_id: Some("handoff-1".to_string()),
                canary_run_id: Some("canary-1".to_string()),
            }))),
        }));
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "kitten-evolver",
                    AgentRole::Kitten,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )
                .with_actions(vec![vec![SwarmAction::ProposeStrategy {
                    strategy_id: "strategy-1".to_string(),
                    strategy: serde_json::json!({
                        "source": "kitten_population_candidate",
                        "ranking_id": "ranking-1",
                        "validation_bundle_id": "validation-1",
                        "materialization_id": "materialization-1",
                        "experiment_path": "experiments/strategy-1.yaml"
                    }),
                    fitness: 0.87,
                }]]),
            ))
            .unwrap();

        dispatcher.tick_agents().await;

        let routed = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(routed.strategy_id, "strategy-1");
        assert_eq!(routed.proposed_by.0, "kitten-evolver");
        assert_eq!(
            routed
                .strategy
                .get("source")
                .and_then(serde_json::Value::as_str),
            Some("kitten_population_candidate")
        );
    }

    #[tokio::test]
    async fn dispatcher_records_kitten_strategy_proposals_for_peer_visibility() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let peer_findings_seen = Arc::new(AtomicUsize::new(0));
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig::default(),
            shutdown_rx,
            substrate(),
            empty_health_state(),
        );
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "kitten-evolver",
                    AgentRole::Kitten,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )
                .with_actions(vec![vec![SwarmAction::ProposeStrategy {
                    strategy_id: "strategy-1".to_string(),
                    strategy: serde_json::json!({"kind": "evolved"}),
                    fitness: 0.87,
                }]]),
            ))
            .unwrap();
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "observer-whisker",
                    AgentRole::Whisker,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )
                .with_peer_finding_counter(Arc::clone(&peer_findings_seen)),
            ))
            .unwrap();

        dispatcher.tick_agents().await;
        dispatcher.tick_agents().await;

        assert_eq!(peer_findings_seen.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dispatcher_handles_claim_investigation_and_publish_findings_without_panic() {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
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
        dispatcher
            .register(Box::new(
                MockAgent::new(
                    "stalker-primary",
                    AgentRole::Stalker,
                    AgentHealth::Healthy,
                    Arc::new(AtomicUsize::new(0)),
                    false,
                )
                .with_actions(vec![vec![
                    SwarmAction::ClaimInvestigation {
                        hunt_id: HuntId("hunt-1".to_string()),
                        lead: "suspicious lateral movement".to_string(),
                    },
                    SwarmAction::PublishFindings {
                        hunt_id: HuntId("hunt-1".to_string()),
                        findings: serde_json::json!({"confirmed": true}),
                        confidence: 0.92,
                    },
                ]]),
            ))
            .unwrap();

        // Tick should not panic; agent stays healthy; actions are acknowledged
        dispatcher.tick_agents().await;

        let snapshot = health_state.load_full();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].health, AgentHealth::Healthy);
    }
}
