//! The `SwarmAgent` trait, agent role definitions, and the typed tick-failure
//! boundary the runtime observes agents through.

use async_trait::async_trait;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fmt;

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

/// Not public API. Seals [`AgentTickError`]; see the note on that trait.
#[doc(hidden)]
pub mod sealed {
    /// Supertrait of [`super::AgentTickError`], carrying no contract of its own.
    ///
    /// Its only job is to make implementing `AgentTickError` require naming a
    /// `#[doc(hidden)]` item, so the set of types that can emit an `error_boundary`
    /// telemetry label stays enumerable and every addition is explicit.
    pub trait SealedAgentTickError {}
}

/// A typed tick failure owned by an agent implementation.
///
/// # Why this exists (SPLIT-03, phase 282)
///
/// `AgentTickBoundaryError` used to be an enum in `swarm-runtime`'s lib.rs with one
/// variant per concrete agent error type (`Sphinx(SphinxAgentTickError)`,
/// `Stalker(StalkerAgentTickError)`). That made the composition root name concrete
/// agent types while the agent files imported back into config, correlation,
/// investigation, replay and the evolution cluster. The coupling was BIDIRECTIONAL,
/// so no extraction order fixed it -- whichever crate was cut first would need the
/// other. The root had to stop naming agents at all.
///
/// It now names this trait instead. An agent crate implements `AgentTickError` for
/// its own error type and depends on `swarm-core`; the runtime observes the failure
/// through `boundary()` and `role()` and depends on `swarm-core`. Neither depends on
/// the other, so the edge that was a cycle is now two edges into a shared leaf.
///
/// The two methods are the entire contract the runtime ever used, and they are the
/// contract it still uses: `boundary()` feeds the `error_boundary` label on restart
/// and health telemetry, `role()` attributes the failure to an agent role.
///
/// # What the trait widened, and why it is sealed
///
/// Replacing a closed enum with a `pub` trait opens an extension point that did not
/// exist before. The `error_boundary` telemetry label is derived from `boundary()`
/// (see the `agent tick failed` / `agent tick panicked` sites in the dispatcher), and
/// its value domain used to be fixed by the crate that owned the enum: the three
/// strings `SphinxAgentTickError` returns, the four `StalkerAgentTickError` returns,
/// and `"panic"`. An arbitrary implementation can return any `&'static str`, so the
/// label domain would otherwise be unbounded and the set of label sources would grow
/// silently with any crate that imports `swarm-core`.
///
/// The trait is therefore sealed: it requires [`sealed::SealedAgentTickError`], which
/// lives in a `#[doc(hidden)]` module and is not part of the documented API. An
/// implementer must write that impl too, so every source of a boundary label stays
/// enumerable with `grep -rn SealedAgentTickError`, and adding one is a deliberate,
/// reviewable act rather than a side effect of depending on this crate.
///
/// The seal is a deliberate-act barrier, not a capability boundary. Rust cannot
/// restrict an impl to a named set of crates, and this trait must stay implementable
/// from whichever crate the agents are extracted into (that is the entire point of
/// SPLIT-03), so a determined downstream crate can still name the hidden module. What
/// the seal buys is that it cannot happen by accident or unnoticed.
pub trait AgentTickError:
    sealed::SealedAgentTickError + std::error::Error + Send + Sync + 'static
{
    /// Stable identifier for the subsystem boundary this failure crossed.
    ///
    /// Used as a telemetry label, so the returned strings are part of the observable
    /// contract and must stay stable across refactors.
    fn boundary(&self) -> &'static str;

    /// Role of the agent that raised the failure.
    fn role(&self) -> AgentRole;
}

/// Typed boundary errors surfaced from runtime-owned agent ticks.
#[derive(Debug)]
pub enum AgentTickBoundaryError {
    /// An agent panicked and the dispatcher caught it at the tick boundary.
    Panic(AgentPanicBoundaryError),
    /// An agent returned a typed failure of its own. See [`AgentTickError`].
    Agent(Box<dyn AgentTickError>),
}

impl AgentTickBoundaryError {
    /// Wrap an agent-owned typed tick failure.
    pub fn agent(error: impl AgentTickError) -> Self {
        Self::Agent(Box::new(error))
    }

    pub fn boundary(&self) -> &'static str {
        match self {
            Self::Panic(_) => "panic",
            Self::Agent(error) => error.boundary(),
        }
    }

    pub fn role(&self) -> AgentRole {
        match self {
            Self::Panic(error) => error.role,
            Self::Agent(error) => error.role(),
        }
    }
}

impl From<AgentPanicBoundaryError> for AgentTickBoundaryError {
    fn from(error: AgentPanicBoundaryError) -> Self {
        Self::Panic(error)
    }
}

// `#[derive(thiserror::Error)]` with `#[error(transparent)]` cannot express this
// enum: the `Agent` variant holds a `Box<dyn AgentTickError>`, and a boxed trait
// object does not implement `std::error::Error` (the std impl is
// `impl<T: Error> Error for Box<T>`, which requires `T: Sized`). The two impls below
// reproduce `transparent` exactly, so the Display text and the `source()` chain are
// unchanged from the derived version this replaced: Display forwards to the inner
// error, and `source()` returns the inner error's SOURCE, not the inner error.
impl fmt::Display for AgentTickBoundaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Panic(error) => fmt::Display::fmt(error, f),
            Self::Agent(error) => fmt::Display::fmt(&**error, f),
        }
    }
}

impl std::error::Error for AgentTickBoundaryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Panic(error) => std::error::Error::source(error),
            Self::Agent(error) => std::error::Error::source(&**error),
        }
    }
}

pub fn agent_tick_error_boundary(error: &SwarmError) -> Option<&'static str> {
    match error {
        SwarmError::Internal(error) => error
            .downcast_ref::<AgentTickBoundaryError>()
            .map(AgentTickBoundaryError::boundary),
        _ => None,
    }
}

pub fn agent_tick_error_role(error: &SwarmError) -> Option<AgentRole> {
    match error {
        SwarmError::Internal(error) => error
            .downcast_ref::<AgentTickBoundaryError>()
            .map(AgentTickBoundaryError::role),
        _ => None,
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("agent `{agent_id}` ({role:?}) panicked during tick: {message}")]
pub struct AgentPanicBoundaryError {
    pub agent_id: AgentId,
    pub role: AgentRole,
    pub message: String,
}

impl AgentPanicBoundaryError {
    pub fn new(agent_id: AgentId, role: AgentRole, payload: Box<dyn Any + Send>) -> Self {
        Self {
            agent_id,
            role,
            message: panic_payload_message(payload.as_ref()),
        }
    }
}

fn panic_payload_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        return (*message).to_string();
    }
    "non-string panic payload".to_string()
}

pub fn agent_tick_panic_error(
    agent_id: &AgentId,
    role: AgentRole,
    payload: Box<dyn Any + Send>,
) -> SwarmError {
    SwarmError::Internal(
        AgentTickBoundaryError::from(AgentPanicBoundaryError::new(
            agent_id.clone(),
            role,
            payload,
        ))
        .into(),
    )
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
