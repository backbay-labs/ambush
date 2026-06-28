//! Pheromone substrate — the swarm's stigmergic communication layer.
//!
//! Backed by NATS JetStream KV for persistence and replay.
//! Deposit keys are segmented primarily by threat class
//! (`exp.<gc_page>.<threat_class>...` for deposits,
//! `esc.<timestamp>.<mode>.<threat_class>...` for escalations).
//!
//! Responsibilities:
//! - Deposit signed pheromones
//! - Query concentration by threat class / region / time window
//! - Garbage-collect evaporated pheromones
//! - Enforce source diversity (one agent can't flood)

pub mod jetstream;
pub mod substrate;

pub use jetstream::JetStreamPheromoneSubstrate;
pub use substrate::{
    ConfiguredPheromoneSubstrate, DepositQuery, DepositSigningPayload, InMemoryPheromoneSubstrate,
    LocalJournalPheromoneSubstrate, PheromoneSubstrate, SubstrateError, SubstrateHealth,
};
