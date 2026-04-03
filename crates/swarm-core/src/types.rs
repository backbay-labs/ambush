//! Fundamental types used across the swarm.

use serde::{Deserialize, Serialize};

/// Unique identifier for a swarm agent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

impl AgentId {
    pub fn new(role: &str, short_id: &str) -> Self {
        Self(format!("{role}-{short_id}"))
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a hunt investigation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HuntId(pub String);

impl std::fmt::Display for HuntId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Actions an agent can emit from its tick loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SwarmAction {
    /// Deposit a pheromone into the substrate.
    DepositPheromone {
        threat_class: String,
        severity: Severity,
        indicator: serde_json::Value,
        confidence: f64,
    },

    /// Claim an investigation (prevents duplication).
    ClaimInvestigation { hunt_id: HuntId, lead: String },

    /// Publish investigation findings.
    PublishFindings {
        hunt_id: HuntId,
        findings: serde_json::Value,
        confidence: f64,
    },

    /// Request a response action (requires consensus).
    RequestResponse {
        hunt_id: HuntId,
        action: ResponseAction,
        evidence: serde_json::Value,
    },

    /// Propose an evolved detection strategy.
    ProposeStrategy {
        strategy_id: String,
        strategy: serde_json::Value,
        fitness: f64,
    },

    /// Shift to a different agent role.
    RoleShift { new_role: super::agent::AgentRole },

    /// Report health status change.
    HealthReport { status: super::agent::AgentHealth },
}

/// Severity levels for threat indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Response actions that Pouncers can execute (after consensus).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseAction {
    /// Block network egress to a target.
    BlockEgress { target: String },
    /// Isolate a host from the network.
    IsolateHost { host_id: String },
    /// Revoke a credential or capability.
    RevokeCredential { credential_id: String },
    /// Deploy a deception asset.
    DeployDecoy {
        decoy_type: String,
        target_zone: String,
    },
    /// Escalate to human operator.
    Escalate { summary: String, urgency: Severity },
}

impl ResponseAction {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::BlockEgress { .. } => "block_egress",
            Self::IsolateHost { .. } => "isolate_host",
            Self::RevokeCredential { .. } => "revoke_credential",
            Self::DeployDecoy { .. } => "deploy_decoy",
            Self::Escalate { .. } => "escalate",
        }
    }
}
