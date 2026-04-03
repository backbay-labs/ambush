//! Pheromone substrate — the swarm's stigmergic communication layer.
//!
//! Backed by NATS JetStream for persistence and replay.
//! Subject hierarchy: `swarm.pheromone.{threat_class}.{severity}`
//!
//! Responsibilities:
//! - Deposit signed pheromones
//! - Query concentration by threat class / region / time window
//! - Garbage-collect evaporated pheromones
//! - Enforce source diversity (one agent can't flood)

pub mod substrate;

pub use substrate::{InMemoryPheromoneSubstrate, PheromoneSubstrate, SubstrateError};
