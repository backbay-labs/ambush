//! Fundamental types used across the swarm.

use crate::pheromone::ThreatClass;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// Unique identifier for a swarm agent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AgentId(pub String);

impl AgentId {
    pub fn new(role: &str, short_id: &str) -> Self {
        Self(format!("{role}-{short_id}"))
    }

    pub fn from_public_key_hex(public_key_hex: &str) -> Self {
        Self(format!("swarm:ed25519:{public_key_hex}"))
    }

    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        Self::from_public_key_hex(&hex::encode(key.to_bytes()))
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

pub const SPHINX_MEMORY_PHEROMONE_SCHEMA_VERSION: u32 = 1;
pub const SPHINX_MEMORY_THREAT_CLASS: &str = "sphinx_memory";
pub const SWARM_PROVIDENCE_WEBHOOK_SCHEMA: &str = "swarm_providence_webhook";
pub const SWARM_PROVIDENCE_WEBHOOK_SCHEMA_VERSION: u32 = 1;
pub const SWARM_PROVIDENCE_FEEDBACK_SCHEMA: &str = "swarm_providence_feedback";
pub const SWARM_PROVIDENCE_FEEDBACK_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SphinxMemoryPayloadKind {
    Query,
    Answer,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SphinxMemoryQuery {
    pub schema_version: u32,
    pub kind: SphinxMemoryPayloadKind,
    pub query_id: String,
    pub requested_by_agent_id: String,
    pub strategy_id: String,
    pub selection_source: String,
    pub observation_count: usize,
    pub base_fitness: f64,
    pub requested_at_ms: i64,
    pub threat_classes: Vec<String>,
    pub attack_technique_ids: Vec<String>,
    pub entity_values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SphinxMemoryContribution {
    pub engagement_id: String,
    pub threat_class: String,
    pub observed_at_ms: i64,
    pub matched_technique_ids: Vec<String>,
    pub matched_entity_values: Vec<String>,
    pub relevance: f64,
    pub outcome_reward: f64,
    pub recency_decay: f64,
    pub q_value: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analyst_disposition: Option<ProvidenceFeedbackAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analyst_note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SphinxMemoryAnswer {
    pub schema_version: u32,
    pub kind: SphinxMemoryPayloadKind,
    pub query_id: String,
    pub strategy_id: String,
    pub answered_by_agent_id: String,
    pub answered_at_ms: i64,
    pub matching_engagement_count: usize,
    pub retrieval_score: f64,
    pub sparse: bool,
    pub contributions: Vec<SphinxMemoryContribution>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvidenceIncidentStatus {
    Open,
    Investigating,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvidenceFeedbackAction {
    Confirm,
    Dismiss,
    Investigate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoarSourceSystem {
    SplunkSoar,
    SentinelSoar,
    ChronicleSoar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvidenceCallbackEvent {
    Created,
    Updated,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvidenceReconciliationOutcome {
    InSync,
    SwarmAhead,
    ProvidenceAhead,
    Mismatch,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmProvidenceFeedbackRequest {
    pub action: ProvidenceFeedbackAction,
    pub incident_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    pub analyst_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmSoarVerdictRequest {
    pub source_system: SoarSourceSystem,
    pub source_verdict_id: String,
    pub verdict_at_ms: i64,
    pub action: ProvidenceFeedbackAction,
    pub incident_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    pub analyst_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_case_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_case_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SoarVerdictLineage {
    pub source_system: SoarSourceSystem,
    pub source_verdict_id: String,
    pub verdict_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_case_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_case_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvidenceFeedbackEvidence {
    pub schema: String,
    pub schema_version: u32,
    pub threat_class: ThreatClass,
    pub agent_id: String,
    pub signed_at_ms: i64,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmProvidenceCallbackRequest {
    pub event: ProvidenceCallbackEvent,
    pub incident_key: String,
    pub remote_incident_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_incident_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<String>,
    pub status: ProvidenceIncidentStatus,
    pub severity: Severity,
    pub updated_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmFeedbackSignal {
    pub action: ProvidenceFeedbackAction,
    pub incident_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_class: Option<ThreatClass>,
    pub analyst_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub recorded_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvidenceCreateIncidentBody {
    pub title: String,
    pub severity: Severity,
    pub status: ProvidenceIncidentStatus,
    pub source: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmProvidenceFindingContext {
    pub schema: String,
    pub finding_id: String,
    pub event_id: String,
    pub strategy_id: String,
    pub threat_class: ThreatClass,
    pub severity: Severity,
    pub confidence: f64,
    pub evidence: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmProvidenceAggregateContext {
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmProvidenceRuntimeBridgeHealth {
    pub status: String,
    pub configured: usize,
    pub ok: usize,
    pub degraded: usize,
    pub idle: usize,
    pub entries: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmProvidenceRuntimeContext {
    pub mode: super::agent::SwarmMode,
    pub registered_agent_count: usize,
    pub active_agent_count: usize,
    pub degraded_agent_count: usize,
    pub failed_agent_count: usize,
    pub bridge_health: SwarmProvidenceRuntimeBridgeHealth,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmProvidenceLinks {
    pub dashboard: String,
    pub event_stream: String,
    pub finding_drilldown: String,
    pub replay_bundle: String,
    pub audit_trail: String,
    pub incident: String,
    pub review_home: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvidenceIncidentReconciliation {
    pub incident_key: String,
    pub remote_incident_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_incident_url: Option<String>,
    pub remote_status: ProvidenceIncidentStatus,
    pub remote_severity: Severity,
    pub swarm_status: ProvidenceIncidentStatus,
    pub swarm_severity: Severity,
    pub remote_updated_at_ms: i64,
    pub reconciled_at_ms: i64,
    pub outcome: ProvidenceReconciliationOutcome,
    pub needs_review: bool,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvidenceCallbackAuditEntry {
    pub callback_id: String,
    pub received_at_ms: i64,
    pub event: ProvidenceCallbackEvent,
    pub incident_key: String,
    pub remote_incident_id: String,
    pub request_signature: String,
    pub payload: serde_json::Value,
    pub reconciliation: ProvidenceIncidentReconciliation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmProvidenceWebhookContract {
    pub schema: String,
    pub schema_version: u32,
    pub channel: String,
    pub incident_key: String,
    pub create_incident: ProvidenceCreateIncidentBody,
    pub finding: SwarmProvidenceFindingContext,
    pub aggregate: SwarmProvidenceAggregateContext,
    pub runtime: SwarmProvidenceRuntimeContext,
    pub links: SwarmProvidenceLinks,
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

    /// Deliver analyst feedback into the evolution loop.
    FeedbackSignal { signal: SwarmFeedbackSignal },

    /// Shift to a different agent role.
    RoleShift {
        target_agent_id: AgentId,
        new_role: super::agent::AgentRole,
    },

    /// Report health status change.
    HealthReport {
        target_agent_id: AgentId,
        status: super::agent::AgentHealth,
    },

    /// Record a governance veto over a destructive autonomous response.
    GovernanceVeto {
        hunt_id: HuntId,
        action: ResponseAction,
        evidence: serde_json::Value,
        governing_agent_id: AgentId,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EscalationEvent {
    Alert {
        threat_class: ThreatClass,
        total_strength: f64,
        distinct_sources: usize,
        peak_confidence: f64,
        timestamp: i64,
    },
    Incident {
        threat_class: ThreatClass,
        total_strength: f64,
        distinct_sources: usize,
        peak_confidence: f64,
        timestamp: i64,
    },
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseAction {
    /// Block network egress to a target.
    BlockEgress { target: String },
    /// Isolate a host from the network.
    IsolateHost { host_id: String },
    /// Revoke a credential or capability.
    RevokeCredential { credential_id: String },
    /// Redirect one domain or DNS name to a defensive sinkhole.
    SinkholeDns { domain: String },
    /// Terminate one scoped user session on one host.
    TerminateUserSession { host_id: String, session_id: String },
    /// Trigger an EDR scan on one host with one named profile.
    TriggerEdrScan {
        host_id: String,
        scan_profile: String,
    },
    /// Inject one firewall rule on one host.
    InjectFirewallRule {
        host_id: String,
        rule_name: String,
        direction: String,
        cidr: String,
        port: Option<u16>,
    },
    /// Quarantine one file on one host.
    QuarantineFile { host_id: String, file_path: String },
    /// Terminate one process on one host.
    KillProcess {
        host_id: String,
        process_name: String,
    },
    /// Suspend one process on one host.
    SuspendProcess {
        host_id: String,
        process_name: String,
    },
    /// Disable one user account.
    DisableUserAccount { user_id: String },
    /// Force a password reset for one user account.
    ForcePasswordReset { user_id: String },
    /// Remove one scheduled task on one host.
    RemoveScheduledTask { host_id: String, task_name: String },
    /// Deploy a deception asset.
    DeployDecoy {
        decoy_type: String,
        target_zone: String,
    },
    /// Escalate to human operator.
    Escalate { summary: String, urgency: Severity },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseRehearsalScopeKind {
    NetworkTarget,
    Host,
    Credential,
    UserSession,
    File,
    Process,
    UserAccount,
    ScheduledTask,
    Zone,
    OperatorQueue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBlastRadiusImpact {
    NetworkEgressBlocked,
    HostConnectivityIsolated,
    CredentialAccessRevoked,
    DnsResolutionSinkholed,
    UserSessionTerminated,
    HostScanTriggered,
    HostFirewallPolicyChanged,
    FileQuarantined,
    ProcessTerminated,
    ProcessSuspended,
    UserAccountDisabled,
    PasswordResetEnforced,
    ScheduledTaskRemoved,
    DeceptionCoverageChanged,
    OperatorEscalationOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseBlastRadiusPreview {
    pub scope_kind: ResponseRehearsalScopeKind,
    pub scope_value: String,
    pub impact: ResponseBlastRadiusImpact,
    pub max_affected_scopes: usize,
    pub affected_capabilities: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseRollbackStepKind {
    RemoveNetworkBlock,
    RestoreHostConnectivity,
    RestoreCredential,
    RemoveDnsSinkhole,
    ReauthenticateUserSession,
    CancelHostScan,
    RemoveFirewallRule,
    ReleaseQuarantinedFile,
    RestartProcess,
    ResumeProcess,
    ReenableUserAccount,
    ClearPasswordResetRequirement,
    RestoreScheduledTask,
    WithdrawDecoy,
    CloseEscalation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseRollbackStep {
    pub kind: ResponseRollbackStepKind,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseRollbackPreview {
    pub required: bool,
    pub summary: String,
    pub steps: Vec<ResponseRollbackStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseRehearsalPreview {
    pub rehearsal_id: String,
    pub source_bundle_id: String,
    pub prepared_at_ms: i64,
    pub simulated_only: bool,
    pub blast_radius: ResponseBlastRadiusPreview,
    pub rollback: ResponseRollbackPreview,
}

impl ResponseAction {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::BlockEgress { .. } => "block_egress",
            Self::IsolateHost { .. } => "isolate_host",
            Self::RevokeCredential { .. } => "revoke_credential",
            Self::SinkholeDns { .. } => "sinkhole_dns",
            Self::TerminateUserSession { .. } => "terminate_user_session",
            Self::TriggerEdrScan { .. } => "trigger_edr_scan",
            Self::InjectFirewallRule { .. } => "inject_firewall_rule",
            Self::QuarantineFile { .. } => "quarantine_file",
            Self::KillProcess { .. } => "kill_process",
            Self::SuspendProcess { .. } => "suspend_process",
            Self::DisableUserAccount { .. } => "disable_user_account",
            Self::ForcePasswordReset { .. } => "force_password_reset",
            Self::RemoveScheduledTask { .. } => "remove_scheduled_task",
            Self::DeployDecoy { .. } => "deploy_decoy",
            Self::Escalate { .. } => "escalate",
        }
    }

    /// Whether enforced execution requires a one-time governance authorization.
    ///
    /// This is the canonical classification used by governance issuance, dispatcher
    /// admission, raw-runtime refusal, and direct-ingest filtering. Keep the match
    /// exhaustive so adding a response variant forces an explicit security decision.
    pub fn requires_governance_receipt(&self) -> bool {
        match self {
            Self::BlockEgress { .. }
            | Self::IsolateHost { .. }
            | Self::RevokeCredential { .. }
            | Self::SinkholeDns { .. }
            | Self::TerminateUserSession { .. }
            | Self::InjectFirewallRule { .. }
            | Self::QuarantineFile { .. }
            | Self::KillProcess { .. }
            | Self::SuspendProcess { .. }
            | Self::DisableUserAccount { .. }
            | Self::ForcePasswordReset { .. }
            | Self::RemoveScheduledTask { .. } => true,
            Self::TriggerEdrScan { .. } | Self::DeployDecoy { .. } | Self::Escalate { .. } => false,
        }
    }

    /// Stable governed action kinds used when pre-staging unscoped contingency
    /// leases. Kept beside the canonical classifier so no downstream crate owns a
    /// competing destructive-action list.
    pub const fn governed_action_kinds() -> [&'static str; 12] {
        [
            "block_egress",
            "isolate_host",
            "revoke_credential",
            "sinkhole_dns",
            "terminate_user_session",
            "inject_firewall_rule",
            "quarantine_file",
            "kill_process",
            "suspend_process",
            "disable_user_account",
            "force_password_reset",
            "remove_scheduled_task",
        ]
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::{ResponseAction, Severity};

    #[test]
    fn governance_receipt_classification_covers_every_response_action() {
        let cases = [
            (
                ResponseAction::BlockEgress {
                    target: "net".into(),
                },
                true,
            ),
            (
                ResponseAction::IsolateHost {
                    host_id: "host".into(),
                },
                true,
            ),
            (
                ResponseAction::RevokeCredential {
                    credential_id: "credential".into(),
                },
                true,
            ),
            (
                ResponseAction::SinkholeDns {
                    domain: "bad.test".into(),
                },
                true,
            ),
            (
                ResponseAction::TerminateUserSession {
                    host_id: "host".into(),
                    session_id: "session".into(),
                },
                true,
            ),
            (
                ResponseAction::TriggerEdrScan {
                    host_id: "host".into(),
                    scan_profile: "quick".into(),
                },
                false,
            ),
            (
                ResponseAction::InjectFirewallRule {
                    host_id: "host".into(),
                    rule_name: "deny".into(),
                    direction: "egress".into(),
                    cidr: "203.0.113.0/24".into(),
                    port: Some(443),
                },
                true,
            ),
            (
                ResponseAction::QuarantineFile {
                    host_id: "host".into(),
                    file_path: "/tmp/a".into(),
                },
                true,
            ),
            (
                ResponseAction::KillProcess {
                    host_id: "host".into(),
                    process_name: "bad".into(),
                },
                true,
            ),
            (
                ResponseAction::SuspendProcess {
                    host_id: "host".into(),
                    process_name: "suspect".into(),
                },
                true,
            ),
            (
                ResponseAction::DisableUserAccount {
                    user_id: "user".into(),
                },
                true,
            ),
            (
                ResponseAction::ForcePasswordReset {
                    user_id: "user".into(),
                },
                true,
            ),
            (
                ResponseAction::RemoveScheduledTask {
                    host_id: "host".into(),
                    task_name: "task".into(),
                },
                true,
            ),
            (
                ResponseAction::DeployDecoy {
                    decoy_type: "token".into(),
                    target_zone: "dmz".into(),
                },
                false,
            ),
            (
                ResponseAction::Escalate {
                    summary: "review".into(),
                    urgency: Severity::High,
                },
                false,
            ),
        ];

        for (action, expected) in cases {
            assert_eq!(
                action.requires_governance_receipt(),
                expected,
                "classification drifted for {}",
                action.kind()
            );
            assert_eq!(
                ResponseAction::governed_action_kinds().contains(&action.kind()),
                expected,
                "governed kind list drifted for {}",
                action.kind()
            );
        }
    }
}
