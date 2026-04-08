//! The `SwarmAgent` trait and agent role definitions.

use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::pheromone::{PheromoneDeposit, ThreatClass};
use crate::types::{AgentId, SwarmAction};

/// The behavioral mode an agent currently occupies.
/// Roles are fluid — agents shift based on swarm needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    /// Sensor/detection — deposits pheromones on anomaly detection.
    Whisker,
    /// Investigation — follows leads, reconstructs timelines.
    Stalker,
    /// Correlation — connects signals into attack narratives.
    Weaver,
    /// Response — executes actions after consensus approval.
    Pouncer,
    /// Governance — enforces policy, manages lifecycle.
    Tom,
    /// Evolution — mutates detection strategies.
    Kitten,
    /// Memory — maintains long-term threat knowledge.
    Sphinx,
    /// Deception — deploys honeypots and canary tokens.
    Calico,
}

/// Agent health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealth {
    /// Agent is operational and processing.
    Healthy,
    /// Agent is alive but degraded (e.g., high load, stale data).
    Degraded,
    /// Agent has failed and needs restart.
    Failed,
}

/// Read-only view of a recent agent finding or action outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentFinding {
    pub agent_id: AgentId,
    pub role: AgentRole,
    pub kind: String,
    pub summary: String,
}

/// Read-only health summary for one registered agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHealthEntry {
    pub id: String,
    pub role: AgentRole,
    pub health: AgentHealth,
}

/// Broadcast event emitted inside the swarm runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SwarmEvent {
    RoleShift {
        agent_id: AgentId,
        new_role: AgentRole,
        observed_at: i64,
    },
}

/// A snapshot of the swarm environment visible to an agent during a tick.
pub struct SwarmEnvironment {
    /// Recent pheromone deposits relevant to this agent.
    pub pheromones: Vec<PheromoneDeposit>,
    /// Current swarm mode (normal, alert, incident).
    pub mode: SwarmMode,
    /// Last time the runtime transitioned upward into the current or a higher mode.
    pub mode_transition_at: Option<i64>,
    /// Wall-clock timestamp (unix seconds).
    pub now: i64,
    /// Read-only view of recent findings emitted by peer agents.
    pub peer_findings: Vec<AgentFinding>,
    /// Read-only health summary for registered agents visible this tick.
    pub agent_health: Vec<AgentHealthEntry>,
}

impl SwarmEnvironment {
    /// Current swarm mode visible to the agent for this tick.
    pub fn current_mode(&self) -> SwarmMode {
        self.mode
    }

    /// Timestamp of the most recent upward swarm-mode transition.
    pub fn mode_transition_at(&self) -> Option<i64> {
        self.mode_transition_at
    }

    /// Agent-health summary visible to this agent for the current tick.
    pub fn agent_health_summary(&self) -> &[AgentHealthEntry] {
        &self.agent_health
    }
}

/// Swarm-wide operating mode, driven by quorum sensing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmMode {
    /// Routine patrol. Whiskers on standard sampling.
    Normal,
    /// Elevated threat signals. Increased sampling, more Stalkers.
    Alert,
    /// Active threat confirmed. All agents focused, Pouncers unlocked.
    Incident,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmModeState {
    pub current: SwarmMode,
    pub last_transition_at: Option<i64>,
    pub triggering_threat_class: Option<ThreatClass>,
}

impl SwarmModeState {
    pub fn new() -> Self {
        Self {
            current: SwarmMode::Normal,
            last_transition_at: None,
            triggering_threat_class: None,
        }
    }

    pub fn transition_to(&mut self, mode: SwarmMode, threat_class: ThreatClass, now: i64) -> bool {
        if mode <= self.current {
            return false;
        }

        self.current = mode;
        self.last_transition_at = Some(now);
        self.triggering_threat_class = Some(threat_class);
        true
    }

    pub fn transition_down(&mut self, mode: SwarmMode, now: i64) -> bool {
        if mode >= self.current {
            return false;
        }

        self.current = mode;
        self.last_transition_at = Some(now);
        self.triggering_threat_class = None;
        true
    }
}

impl Default for SwarmModeState {
    fn default() -> Self {
        Self::new()
    }
}

/// The core trait every swarm agent implements.
#[async_trait]
pub trait SwarmAgent: Send + Sync {
    /// Agent's cryptographic identity.
    fn identity(&self) -> &VerifyingKey;

    /// Unique agent identifier.
    fn id(&self) -> &AgentId;

    /// Current behavioral role (may change over time).
    fn role(&self) -> AgentRole;

    /// Observe a swarm-runtime event broadcast by the dispatcher.
    fn observe_event(&mut self, _event: &SwarmEvent) -> Result<(), SwarmError> {
        Ok(())
    }

    /// Process one tick of the agent's event loop.
    /// Returns zero or more actions to emit.
    async fn tick(&mut self, env: &SwarmEnvironment) -> Result<Vec<SwarmAction>, SwarmError>;

    /// Agent's current health status.
    fn health(&self) -> AgentHealth;
}

/// Errors that can occur during agent execution.
#[derive(Debug, thiserror::Error)]
pub enum SwarmError {
    #[error("pheromone substrate unavailable: {0}")]
    SubstrateUnavailable(String),

    #[error("consensus failed: {0}")]
    ConsensusFailed(String),

    #[error("guard denied action: {0}")]
    GuardDenied(String),

    #[error("agent timeout after {0}ms")]
    Timeout(u64),

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::{AgentFinding, SwarmEnvironment, SwarmMode, SwarmModeState};
    use crate::pheromone::ThreatClass;

    #[test]
    fn mode_state_starts_in_normal_mode() {
        let state = SwarmModeState::new();
        assert_eq!(state.current, SwarmMode::Normal);
        assert_eq!(state.last_transition_at, None);
        assert_eq!(state.triggering_threat_class, None);
    }

    #[test]
    fn mode_state_escalates_monotonically() {
        let mut state = SwarmModeState::new();
        assert!(state.transition_to(SwarmMode::Alert, ThreatClass::Execution, 1_700_000_000));
        assert_eq!(state.current, SwarmMode::Alert);
        assert_eq!(state.last_transition_at, Some(1_700_000_000));
        assert_eq!(state.triggering_threat_class, Some(ThreatClass::Execution));

        assert!(state.transition_to(
            SwarmMode::Incident,
            ThreatClass::CredentialAccess,
            1_700_000_100
        ));
        assert_eq!(state.current, SwarmMode::Incident);
        assert_eq!(state.last_transition_at, Some(1_700_000_100));
        assert_eq!(
            state.triggering_threat_class,
            Some(ThreatClass::CredentialAccess)
        );
    }

    #[test]
    fn mode_state_rejects_noops_and_deescalation() {
        let mut state = SwarmModeState::new();
        assert!(!state.transition_to(SwarmMode::Normal, ThreatClass::Execution, 1_700_000_000));
        assert!(state.transition_to(SwarmMode::Alert, ThreatClass::Execution, 1_700_000_001));
        assert!(!state.transition_to(SwarmMode::Alert, ThreatClass::Execution, 1_700_000_002));
        assert!(!state.transition_to(SwarmMode::Normal, ThreatClass::Execution, 1_700_000_003));
    }

    #[test]
    fn mode_state_transition_down_clears_triggering_threat_class() {
        let mut state = SwarmModeState::new();
        assert!(state.transition_to(SwarmMode::Alert, ThreatClass::Execution, 1_700_000_001));

        assert!(state.transition_down(SwarmMode::Normal, 1_700_000_050));
        assert_eq!(state.current, SwarmMode::Normal);
        assert_eq!(state.last_transition_at, Some(1_700_000_050));
        assert_eq!(state.triggering_threat_class, None);

        assert!(!state.transition_down(SwarmMode::Normal, 1_700_000_060));
        assert!(!state.transition_down(SwarmMode::Incident, 1_700_000_070));
    }

    #[test]
    fn environment_exposes_mode_helpers() {
        let env = SwarmEnvironment {
            pheromones: Vec::new(),
            mode: SwarmMode::Alert,
            mode_transition_at: Some(1_700_000_100),
            now: 1_700_000_200,
            peer_findings: Vec::<AgentFinding>::new(),
            agent_health: Vec::new(),
        };

        assert_eq!(env.current_mode(), SwarmMode::Alert);
        assert_eq!(env.mode_transition_at(), Some(1_700_000_100));
        assert!(env.agent_health_summary().is_empty());
    }
}
