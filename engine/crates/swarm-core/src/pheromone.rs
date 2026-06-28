//! Pheromone types — signed threat indicators deposited into the shared substrate.
//!
//! Pheromones are the swarm's stigmergic communication primitive.
//! Agents deposit them when they detect anomalies; other agents
//! sense concentration and adjust behavior accordingly.

use serde::{Deserialize, Serialize};

use crate::agent::{AgentRole, SwarmMode};
use crate::config::PheromoneConfig;
use crate::types::{AgentId, Severity};

/// Classification of threat indicators.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatClass {
    LateralMovement,
    DataExfiltration,
    PrivilegeEscalation,
    CommandAndControl,
    InitialAccess,
    Persistence,
    SupplyChain,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    Execution,
    Impact,
    /// Custom threat class not in the standard taxonomy.
    Custom(String),
}

/// Durable per-threat-class pheromone overrides stored in the substrate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatClassConfig {
    /// Threat class the override applies to.
    pub threat_class: ThreatClass,
    /// Half-life used for deposits of this threat class.
    pub half_life_secs: f64,
    /// Effective-strength floor used for evaporation checks.
    pub evaporation_threshold: f64,
    /// Concentration threshold for alert mode.
    pub alert_threshold: f64,
    /// Concentration threshold for incident mode.
    pub incident_threshold: f64,
}

/// Supported threat-intel indicator families.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatIntelIndicatorType {
    IpAddress,
    Domain,
    FileHash,
}

/// Durable operator-seeded threat-intel record stored in the substrate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatIntelEntry {
    /// Indicator family used for exact lookup.
    pub indicator_type: ThreatIntelIndicatorType,
    /// Normalized indicator value.
    pub value: String,
    /// Confidence contribution applied when a detector matches this indicator.
    pub confidence: f64,
    /// When the indicator expires (unix timestamp milliseconds).
    pub expires_at: i64,
}

/// Durable restart-safe behavioral baseline snapshot stored in the substrate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralBaselineSnapshot {
    /// Strategy family that owns the snapshot.
    pub strategy_id: String,
    /// When the snapshot was captured (unix timestamp seconds).
    pub captured_at: i64,
    /// Host-scoped baseline states tracked by the detector.
    #[serde(default)]
    pub hosts: Vec<BehavioralHostBaseline>,
    /// Identity-scoped baseline states tracked by the detector.
    #[serde(default)]
    pub identities: Vec<BehavioralIdentityBaseline>,
    /// Peer-group-scoped baseline states tracked by the detector.
    #[serde(default)]
    pub peer_groups: Vec<BehavioralPeerGroupBaseline>,
}

/// Durable restart-safe online distribution state for one behavioral scope.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BehavioralOnlineDistributionSnapshot {
    /// Number of samples incorporated into the online distribution.
    pub sample_count: u64,
    /// Running mean maintained by the online learner.
    pub mean: f64,
    /// Running second central moment maintained by the online learner.
    pub m2: f64,
}

/// One restart-safe learned baseline for a non-process telemetry family.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralTelemetryFamilyBaseline {
    /// Telemetry family identifier such as `network_connect` or `dns_query`.
    pub family: String,
    /// Number of observations incorporated for this family within the scope.
    pub observation_count: u64,
    /// Restart-safe online novelty distribution for this family within the scope.
    #[serde(default)]
    pub novelty_distribution: BehavioralOnlineDistributionSnapshot,
    /// Decayed learned feature observations for this family within the scope.
    #[serde(default)]
    pub features: Vec<BehavioralFrequencyEntry>,
}

/// Behavioral baseline state for one host.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralHostBaseline {
    pub host_id: String,
    pub observation_count: u64,
    #[serde(default)]
    pub novelty_distribution: BehavioralOnlineDistributionSnapshot,
    #[serde(default)]
    pub telemetry_families: Vec<BehavioralTelemetryFamilyBaseline>,
    pub parent_child_pairs: Vec<BehavioralFrequencyEntry>,
    pub binaries: Vec<BehavioralFrequencyEntry>,
    pub role_tools: Vec<BehavioralRoleToolFrequencyEntry>,
}

/// Behavioral baseline state for one identity principal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralIdentityBaseline {
    pub identity_id: String,
    pub observation_count: u64,
    #[serde(default)]
    pub novelty_distribution: BehavioralOnlineDistributionSnapshot,
    #[serde(default)]
    pub telemetry_families: Vec<BehavioralTelemetryFamilyBaseline>,
    pub parent_child_pairs: Vec<BehavioralFrequencyEntry>,
    pub binaries: Vec<BehavioralFrequencyEntry>,
    pub role_tools: Vec<BehavioralRoleToolFrequencyEntry>,
}

/// Behavioral baseline state for one peer-group scope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralPeerGroupBaseline {
    pub peer_group_id: String,
    pub observation_count: u64,
    #[serde(default)]
    pub novelty_distribution: BehavioralOnlineDistributionSnapshot,
    #[serde(default)]
    pub telemetry_families: Vec<BehavioralTelemetryFamilyBaseline>,
    pub parent_child_pairs: Vec<BehavioralFrequencyEntry>,
    pub binaries: Vec<BehavioralFrequencyEntry>,
    pub role_tools: Vec<BehavioralRoleToolFrequencyEntry>,
}

/// One decayed-frequency baseline observation keyed by a string value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralFrequencyEntry {
    pub key: String,
    pub weight: f64,
    pub last_seen_at: i64,
}

/// One decayed-frequency baseline observation keyed by user role plus tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehavioralRoleToolFrequencyEntry {
    pub user_role: String,
    pub tool: String,
    pub weight: f64,
    pub last_seen_at: i64,
}

/// Effective pheromone policy after base config plus threat-class override resolution.
#[derive(Debug, Clone, PartialEq)]
pub struct ThreatClassPolicy {
    pub half_life_secs: f64,
    pub evaporation_threshold: f64,
    pub min_sources_for_escalation: usize,
    pub alert_threshold: f64,
    pub incident_threshold: f64,
}

pub const PHEROMONE_DEPOSIT_PREVIOUS_SCHEMA_VERSION: u32 = 1;
pub const PHEROMONE_DEPOSIT_CURRENT_SCHEMA_VERSION: u32 = 2;

fn default_pheromone_deposit_schema_version() -> u32 {
    PHEROMONE_DEPOSIT_PREVIOUS_SCHEMA_VERSION
}

/// A pheromone deposit — a signed threat indicator in the substrate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PheromoneDeposit {
    /// Explicit wire-format schema version for the serialized deposit payload.
    ///
    /// Missing values deserialize as the previous supported schema version so
    /// legacy stored deposits can still be migrated through the bounded
    /// current-plus-previous compatibility path.
    #[serde(default = "default_pheromone_deposit_schema_version")]
    pub schema_version: u32,
    /// What was observed.
    pub indicator: serde_json::Value,
    /// Classification of the threat.
    pub threat_class: ThreatClass,
    /// Severity assessment.
    pub severity: Severity,
    /// Agent's confidence in this signal (0.0–1.0).
    pub confidence: f64,
    /// When deposited (unix timestamp seconds).
    pub timestamp: i64,
    /// Half-life in seconds — controls evaporation rate.
    pub decay_half_life: f64,
    /// Who deposited it.
    pub agent_id: AgentId,
    /// Stable cryptographic identity derived from the depositing public key.
    #[serde(default)]
    pub agent_identity: String,
    /// Depositing agent role at the time the pheromone was emitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_role: Option<AgentRole>,
    /// Ed25519 signature over the canonical deposit content.
    pub signature: Vec<u8>,
    /// Public key of the depositing agent.
    pub agent_key: Vec<u8>,
}

/// A durable record of a swarm-mode escalation transition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscalationRecord {
    /// The new swarm mode entered by the runtime.
    pub mode: SwarmMode,
    /// Threat class that triggered the transition.
    pub threat_class: ThreatClass,
    /// Total pheromone strength observed at transition time.
    pub total_strength: f64,
    /// Number of distinct sources contributing to the transition.
    pub distinct_sources: usize,
    /// Highest individual confidence contributing to the transition.
    pub peak_confidence: f64,
    /// When the transition was recorded (unix timestamp seconds).
    pub timestamp: i64,
}

/// A pheromone with computed effective strength (after decay).
#[derive(Debug, Clone)]
pub struct Pheromone {
    pub deposit: PheromoneDeposit,
    /// Effective strength at query time, accounting for decay.
    pub effective_strength: f64,
}

impl PheromoneDeposit {
    pub const fn current_schema_version() -> u32 {
        PHEROMONE_DEPOSIT_CURRENT_SCHEMA_VERSION
    }

    pub const fn previous_schema_version() -> u32 {
        PHEROMONE_DEPOSIT_PREVIOUS_SCHEMA_VERSION
    }

    pub const fn supports_schema_version(schema_version: u32) -> bool {
        matches!(
            schema_version,
            PHEROMONE_DEPOSIT_PREVIOUS_SCHEMA_VERSION | PHEROMONE_DEPOSIT_CURRENT_SCHEMA_VERSION
        )
    }

    /// Compute effective strength at a given time, accounting for exponential decay.
    ///
    /// `strength(t) = confidence * 0.5^((t - timestamp) / half_life)`
    pub fn strength_at(&self, now: i64) -> f64 {
        if now <= self.timestamp {
            return self.confidence;
        }
        let elapsed = (now - self.timestamp) as f64;
        self.confidence * (0.5_f64).powf(elapsed / self.decay_half_life)
    }

    /// Check if this pheromone has effectively evaporated (strength < threshold).
    pub fn is_evaporated(&self, now: i64, threshold: f64) -> bool {
        self.strength_at(now) < threshold
    }
}

impl PheromoneConfig {
    /// Resolve the effective pheromone policy for one threat class.
    pub fn resolve_threat_class_policy(
        &self,
        override_config: Option<&ThreatClassConfig>,
    ) -> ThreatClassPolicy {
        ThreatClassPolicy {
            half_life_secs: override_config
                .map(|config| config.half_life_secs)
                .unwrap_or(self.default_half_life_secs),
            evaporation_threshold: override_config
                .map(|config| config.evaporation_threshold)
                .unwrap_or(self.evaporation_threshold),
            min_sources_for_escalation: self.min_sources_for_escalation,
            alert_threshold: override_config
                .map(|config| config.alert_threshold)
                .unwrap_or(self.alert_threshold),
            incident_threshold: override_config
                .map(|config| config.incident_threshold)
                .unwrap_or(self.incident_threshold),
        }
    }
}

/// Aggregated pheromone concentration for a threat class in a region.
#[derive(Debug, Clone)]
pub struct PheromoneConcentration {
    pub threat_class: ThreatClass,
    /// Sum of effective strengths from distinct agents.
    pub total_strength: f64,
    /// Number of distinct agents contributing.
    pub distinct_sources: usize,
    /// Highest individual confidence.
    pub peak_confidence: f64,
}

impl PheromoneConcentration {
    /// Whether concentration exceeds a threshold for escalation.
    /// Requires both strength AND source diversity to prevent single-agent flooding.
    pub fn exceeds_threshold(&self, strength_threshold: f64, min_sources: usize) -> bool {
        self.total_strength >= strength_threshold && self.distinct_sources >= min_sources
    }
}
