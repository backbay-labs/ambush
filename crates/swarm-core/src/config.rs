//! Swarm configuration types — hunt missions defined in YAML/TOML.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::agent::AgentRole;
use crate::verdict::AutonomyTier;

/// Top-level swarm mission configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmConfig {
    /// Mission name.
    pub name: String,
    /// Mission description.
    pub description: String,
    /// Agent population — how many of each archetype to spawn.
    pub population: HashMap<AgentRole, PopulationConfig>,
    /// Pheromone substrate settings.
    pub pheromone: PheromoneConfig,
    /// Consensus settings.
    pub consensus: ConsensusConfig,
    /// Autonomy tier boundaries.
    pub autonomy: AutonomyConfig,
    /// NATS connection settings.
    pub nats: NatsConfig,
}

/// Configuration for an agent archetype's population.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopulationConfig {
    /// Number of agents to spawn.
    pub count: u32,
    /// Maximum allowed (for auto-scaling).
    pub max_count: u32,
    /// Autonomy tier this archetype operates at.
    pub tier: AutonomyTier,
}

/// Pheromone substrate tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PheromoneConfig {
    /// Default half-life for pheromone decay (seconds).
    pub default_half_life_secs: f64,
    /// Strength below which pheromones are garbage-collected.
    pub evaporation_threshold: f64,
    /// Minimum distinct sources for concentration escalation.
    pub min_sources_for_escalation: usize,
    /// Strength threshold for alert mode transition.
    pub alert_threshold: f64,
    /// Strength threshold for incident mode transition.
    pub incident_threshold: f64,
}

/// BFT consensus settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Maximum Byzantine faults tolerated (f in 3f+1).
    pub max_byzantine_faults: u32,
    /// Timeout for consensus rounds (milliseconds).
    pub round_timeout_ms: u64,
    /// How often to rotate committee membership.
    pub committee_rotation_interval_secs: u64,
}

/// Autonomy tier boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomyConfig {
    /// Confidence threshold for Tier 1 (fully autonomous).
    pub tier1_confidence: f64,
    /// Confidence threshold for Tier 2 (autonomous + report).
    pub tier2_confidence: f64,
    /// Everything below tier2 requires human approval (Tier 3).
    pub require_human_above_severity: String,
}

/// NATS connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsConfig {
    /// NATS server URLs.
    pub servers: Vec<String>,
    /// Subject prefix for all swarm messages.
    pub subject_prefix: String,
    /// JetStream stream name for pheromone persistence.
    pub pheromone_stream: String,
}

impl Default for PheromoneConfig {
    fn default() -> Self {
        Self {
            default_half_life_secs: 3600.0, // 1 hour
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
        }
    }
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            max_byzantine_faults: 1,
            round_timeout_ms: 5000,
            committee_rotation_interval_secs: 3600,
        }
    }
}
