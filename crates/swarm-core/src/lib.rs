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
pub mod types;
pub mod verdict;

pub use agent::{AgentHealth, AgentRole, SwarmAgent};
pub use pheromone::{Pheromone, PheromoneDeposit, ThreatClass};
pub use types::{AgentId, HuntId, SwarmAction};
pub use verdict::{ConsensusResult, ThreatVerdict};
