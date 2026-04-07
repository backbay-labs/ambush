//! Core types, traits, and primitives for Swarm Team Six.
//!
//! This crate defines the fundamental abstractions:
//! - `SwarmAgent` trait — the interface every agent archetype implements
//! - `Pheromone` — signed threat indicators deposited into the shared substrate
//! - `AgentRole` — the behavioral mode an agent currently occupies
//! - `SwarmAction` — actions an agent can emit from its tick loop
//! - `Verdict` — aggregated swarm decision on a threat

pub mod agent;
pub mod config;
pub mod pheromone;
pub mod telemetry;
pub mod types;
pub mod verdict;

pub use agent::{
    AgentFinding, AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmEvent, SwarmMode,
    SwarmModeState,
};
pub use pheromone::{
    EscalationRecord, Pheromone, PheromoneDeposit, ThreatClass, ThreatClassConfig,
    ThreatClassPolicy, ThreatIntelEntry, ThreatIntelIndicatorType,
};
pub use telemetry::{
    AuthenticationEventData, BridgeHealth, DnsQueryEvent, FilePersistenceEvent,
    NetworkConnectEvent, ProcessStartEvent, RegistryAccessEvent, RegistryPersistenceEvent,
    TelemetryBridge, TelemetryBridgeError, TelemetryBridgeResult, TelemetryEvent, TelemetryPayload,
};
pub use types::{AgentId, EscalationEvent, HuntId, SwarmAction};
pub use verdict::{ConsensusResult, ThreatVerdict};
