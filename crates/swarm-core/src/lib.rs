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
pub mod observability;
pub mod pheromone;
pub mod telemetry;
pub mod types;
pub mod verdict;

pub use agent::{
    AgentFinding, AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmEvent, SwarmMode,
    SwarmModeState,
};
pub use pheromone::{
    BehavioralBaselineSnapshot, BehavioralFrequencyEntry, BehavioralHostBaseline,
    BehavioralOnlineDistributionSnapshot, BehavioralRoleToolFrequencyEntry,
    BehavioralTelemetryFamilyBaseline, EscalationRecord, Pheromone, PheromoneDeposit, ThreatClass,
    ThreatClassConfig, ThreatClassPolicy, ThreatIntelEntry, ThreatIntelIndicatorType,
};
pub use telemetry::{
    AuthenticationEventData, BridgeHealth, DnsQueryEvent, ExhaustedResource, FilePersistenceEvent,
    InfrastructureHealthEvent, NetworkConnectEvent, ProcessMemoryAccessEvent, ProcessStartEvent,
    RegistryAccessEvent, RegistryPersistenceEvent, ResourceExhaustionEvent, TelemetryBridge,
    TelemetryBridgeError, TelemetryBridgeResult, TelemetryEvent, TelemetryPayload,
    ThermalAnomalyEvent, ThermalSeverity,
};
pub use types::{
    AgentId, EscalationEvent, HuntId, ProvidenceCallbackAuditEntry, ProvidenceCallbackEvent,
    ProvidenceCreateIncidentBody, ProvidenceFeedbackEvidence, ProvidenceIncidentReconciliation,
    ProvidenceIncidentStatus, ProvidenceReconciliationOutcome, SwarmAction,
    SwarmProvidenceAggregateContext, SwarmProvidenceCallbackRequest, SwarmProvidenceFindingContext,
    SwarmProvidenceLinks, SwarmProvidenceRuntimeBridgeHealth, SwarmProvidenceRuntimeContext,
    SwarmProvidenceWebhookContract,
};
pub use verdict::{ConsensusResult, ThreatVerdict};
