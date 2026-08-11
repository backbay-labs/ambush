use super::*;

/// Deterministic policy settings for live response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Severity at or above which destructive actions require human approval.
    pub human_gate_severity: Severity,
    /// Capability lease lifetime.
    pub lease_ttl_ms: i64,
    /// Maximum number of actions a single scope may receive inside one minute
    /// before the static fallback gate denies additional requests.
    #[serde(default = "default_max_actions_per_scope_per_minute")]
    pub max_actions_per_scope_per_minute: usize,
    /// Ordered configurable policy rules evaluated before static fallback.
    #[serde(default)]
    pub rules: Vec<PolicyRuleConfig>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            human_gate_severity: Severity::High,
            lease_ttl_ms: 60_000,
            max_actions_per_scope_per_minute: default_max_actions_per_scope_per_minute(),
            rules: Vec::new(),
        }
    }
}

/// One ordered configurable policy rule loaded from repository YAML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRuleConfig {
    /// Stable rule identifier emitted into logs and audit records.
    pub name: String,
    /// Final verdict emitted when this rule matches and its constraints pass.
    pub decision: PolicyRuleDecision,
    /// Threat class selector for the rule.
    pub threat_class: ThreatClass,
    /// Optional action selector list. Empty means all actions for the threat class.
    #[serde(default)]
    pub actions: Vec<PolicyActionSelector>,
    /// Inclusive lower severity bound for the rule.
    #[serde(default = "default_policy_rule_min_severity")]
    pub min_severity: Severity,
    /// Inclusive upper severity bound for the rule.
    #[serde(default = "default_policy_rule_max_severity")]
    pub max_severity: Severity,
    /// Optional UTC hour window. Requests outside the window are denied by the rule.
    #[serde(default)]
    pub time_window_utc: Option<PolicyTimeWindowConfig>,
    /// Optional per-agent one-minute burst limit scoped to this rule.
    #[serde(default)]
    pub max_actions_per_agent_per_minute: Option<usize>,
    /// Optional human-readable rationale attached to the rule verdict.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Final verdict supported by repository-owned policy rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRuleDecision {
    Allow,
    Deny,
}

/// Action selector used by configurable policy rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyActionSelector {
    BlockEgress,
    IsolateHost,
    RevokeCredential,
    SinkholeDns,
    TerminateUserSession,
    TriggerEdrScan,
    InjectFirewallRule,
    QuarantineFile,
    KillProcess,
    SuspendProcess,
    DisableUserAccount,
    ForcePasswordReset,
    RemoveScheduledTask,
    DeployDecoy,
    Escalate,
}

impl PolicyActionSelector {
    pub fn matches(self, action: &ResponseAction) -> bool {
        matches!(
            (self, action),
            (Self::BlockEgress, ResponseAction::BlockEgress { .. })
                | (Self::IsolateHost, ResponseAction::IsolateHost { .. })
                | (
                    Self::RevokeCredential,
                    ResponseAction::RevokeCredential { .. }
                )
                | (Self::SinkholeDns, ResponseAction::SinkholeDns { .. })
                | (
                    Self::TerminateUserSession,
                    ResponseAction::TerminateUserSession { .. }
                )
                | (Self::TriggerEdrScan, ResponseAction::TriggerEdrScan { .. })
                | (
                    Self::InjectFirewallRule,
                    ResponseAction::InjectFirewallRule { .. }
                )
                | (Self::QuarantineFile, ResponseAction::QuarantineFile { .. })
                | (Self::KillProcess, ResponseAction::KillProcess { .. })
                | (Self::SuspendProcess, ResponseAction::SuspendProcess { .. })
                | (
                    Self::DisableUserAccount,
                    ResponseAction::DisableUserAccount { .. }
                )
                | (
                    Self::ForcePasswordReset,
                    ResponseAction::ForcePasswordReset { .. }
                )
                | (
                    Self::RemoveScheduledTask,
                    ResponseAction::RemoveScheduledTask { .. }
                )
                | (Self::DeployDecoy, ResponseAction::DeployDecoy { .. })
                | (Self::Escalate, ResponseAction::Escalate { .. })
        )
    }
}

/// Optional UTC hour restriction for one configurable policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTimeWindowConfig {
    /// Inclusive start hour in UTC.
    pub start_hour_utc: u8,
    /// Exclusive end hour in UTC.
    pub end_hour_utc: u8,
}

impl PolicyTimeWindowConfig {
    pub fn contains_hour(self, hour_utc: u8) -> bool {
        if self.start_hour_utc < self.end_hour_utc {
            hour_utc >= self.start_hour_utc && hour_utc < self.end_hour_utc
        } else {
            hour_utc >= self.start_hour_utc || hour_utc < self.end_hour_utc
        }
    }
}

impl PolicyRuleConfig {
    pub(super) fn validate(&self, index: usize) -> Result<(), ConfigValidationError> {
        if self.name.trim().is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "policy.rules",
                reason: format!("rule {index} name must not be empty"),
            });
        }
        if self.max_severity < self.min_severity {
            return Err(ConfigValidationError::InvalidField {
                field: "policy.rules",
                reason: format!(
                    "rule {index} max_severity must be greater than or equal to min_severity"
                ),
            });
        }
        if let Some(limit) = self.max_actions_per_agent_per_minute
            && limit == 0
        {
            return Err(ConfigValidationError::InvalidField {
                field: "policy.rules",
                reason: format!(
                    "rule {index} max_actions_per_agent_per_minute must be greater than zero"
                ),
            });
        }
        if let Some(window) = self.time_window_utc {
            if window.start_hour_utc > 23 {
                return Err(ConfigValidationError::InvalidField {
                    field: "policy.rules",
                    reason: format!("rule {index} start_hour_utc must be between 0 and 23"),
                });
            }
            if window.end_hour_utc == 0 || window.end_hour_utc > 24 {
                return Err(ConfigValidationError::InvalidField {
                    field: "policy.rules",
                    reason: format!("rule {index} end_hour_utc must be between 1 and 24"),
                });
            }
            if window.start_hour_utc == window.end_hour_utc {
                return Err(ConfigValidationError::InvalidField {
                    field: "policy.rules",
                    reason: format!("rule {index} time_window_utc must span at least one UTC hour"),
                });
            }
        }
        Ok(())
    }
}
