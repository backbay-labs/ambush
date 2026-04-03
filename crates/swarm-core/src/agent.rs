//! The `SwarmAgent` trait and agent role definitions.

use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::pheromone::PheromoneDeposit;
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

/// A snapshot of the swarm environment visible to an agent during a tick.
pub struct SwarmEnvironment {
    /// Recent pheromone deposits relevant to this agent.
    pub pheromones: Vec<PheromoneDeposit>,
    /// Current swarm mode (normal, alert, incident).
    pub mode: SwarmMode,
    /// Wall-clock timestamp (unix seconds).
    pub now: i64,
}

/// Swarm-wide operating mode, driven by quorum sensing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmMode {
    /// Routine patrol. Whiskers on standard sampling.
    Normal,
    /// Elevated threat signals. Increased sampling, more Stalkers.
    Alert,
    /// Active threat confirmed. All agents focused, Pouncers unlocked.
    Incident,
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
