//! Swarm-level threat verdicts and consensus results.

use serde::{Deserialize, Serialize};

use crate::types::{HuntId, Severity};

/// The swarm's collective verdict on a threat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatVerdict {
    pub hunt_id: HuntId,
    /// Overall threat assessment.
    pub assessment: ThreatAssessment,
    /// Confidence in the verdict (0.0–1.0).
    pub confidence: f64,
    /// Severity if confirmed.
    pub severity: Severity,
    /// MITRE ATT&CK technique IDs, if mapped.
    pub mitre_techniques: Vec<String>,
    /// Summary of evidence chain.
    pub evidence_summary: String,
    /// Recommended response tier.
    pub recommended_tier: AutonomyTier,
}

/// Threat assessment levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatAssessment {
    /// No threat detected.
    Benign,
    /// Suspicious but insufficient evidence.
    Suspicious,
    /// Likely threat, investigation recommended.
    Likely,
    /// Confirmed threat, response authorized.
    Confirmed,
    /// Active exploitation in progress.
    Active,
}

/// Autonomy tiers governing what the swarm can do without human approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyTier {
    /// Fully autonomous: routine hunting, known-bad detection, IOC matching.
    Tier1,
    /// Autonomous with reporting: novel detections, hypothesis generation.
    /// Runs autonomously but reports for human validation before escalation.
    Tier2,
    /// Human-approved: response actions, policy changes, new detection deployment.
    Tier3,
}

/// Result of a BFT consensus vote among Tom agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResult {
    pub hunt_id: HuntId,
    /// Whether consensus was reached.
    pub reached: bool,
    /// Votes in favor.
    pub approve_count: u32,
    /// Votes against.
    pub deny_count: u32,
    /// Total eligible voters.
    pub total_voters: u32,
    /// Required threshold (2f+1 for BFT).
    pub threshold: u32,
}

impl ConsensusResult {
    /// Check if BFT consensus was achieved (2f+1 out of 3f+1).
    pub fn is_bft_consensus(&self) -> bool {
        self.reached && self.approve_count >= self.threshold
    }
}
