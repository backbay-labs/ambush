//! Negative falsifiability tests for the `swarm-policy` rows of
//! `docs/assurance/MAPPING.md` (FALSIFY-02).
//!
//! # What a test in this file has to do, and why
//!
//! A positive test proves that the gate denies. It does NOT prove that the
//! guard named in MAPPING.md is what denied: the same assertion passes if some
//! unrelated arm happens to refuse the probe first, and it keeps passing after
//! the guard is deleted. `.planning/STATE.md` catalogues twelve shipped defects
//! of exactly that shape.
//!
//! So each test here carries a MIRROR of the enforcing function, and runs three
//! things over one probe input:
//!
//!   1. the REAL function, which must deny;
//!   2. the mirror with NO mutation, which must reproduce the real verdict --
//!      this is the anti-vacuity control, and without it a difference under
//!      mutation could just as easily be a sloppy rewrite;
//!   3. the mirror with ONE guard removed, which must PERMIT.
//!
//! Step 2 is the part that is easy to leave out and is the part that makes
//! step 3 mean anything.
//!
//! # Why a mirror rather than a feature flag in production code
//!
//! Because a `#[cfg(...)]`-selectable hole in `swarm-policy` is a hole in the
//! trusted computing base (ADR 0009) that a build flag can open. The mirror
//! lives in the test binary and cannot be linked into anything that ships.
//!
//! The mirror's fidelity is guarded by the control in step 2 and by review; the
//! registry entry in `docs/assurance/negative-registry.toml` names it so a
//! reviewer can diff it against the function it copies.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../../../tests/negative_protocol.rs"]
mod negative_protocol;

use serde_json::json;
use std::collections::{HashMap, VecDeque};
use swarm_core::config::{
    PolicyConfig, PolicyRuleConfig, PolicyRuleDecision, PolicyTimeWindowConfig,
};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_policy::configurable_gate::ConfigurableApprovalGate;
use swarm_policy::static_gate::{StaticApprovalGate, scope_for_response_action};
use swarm_policy::{
    ActionRequest, ApprovalContext, ApprovalError, ApprovalGate, PolicyDecision, PolicyVerdict,
};

// ---------------------------------------------------------------------------
// Probe inputs
// ---------------------------------------------------------------------------

fn context(now_ms: i64) -> ApprovalContext {
    ApprovalContext {
        live_mode: true,
        receipt_chain: vec!["receipt-1".to_string()],
        correlation_id: None,
        now_ms,
    }
}

fn request(
    action: ResponseAction,
    severity: Severity,
    evidence: serde_json::Value,
) -> ActionRequest {
    ActionRequest {
        hunt_id: HuntId("hunt-negative".to_string()),
        requested_by: AgentId("pounce-1".to_string()),
        action,
        severity,
        evidence,
    }
}

fn isolate_host() -> ResponseAction {
    ResponseAction::IsolateHost {
        host_id: "host-1".to_string(),
    }
}

fn escalation_evidence(severity: Severity) -> serde_json::Value {
    json!({
        "escalation": {
            "threat_class": ThreatClass::Execution,
            "severity": severity,
        }
    })
}

// ---------------------------------------------------------------------------
// The mirror of `StaticApprovalGate::validate_request` + `::evaluate`
// ---------------------------------------------------------------------------

/// Which single guard the mirror below has had removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaticMutation {
    /// No mutation. The control: must reproduce the real gate exactly.
    None,
    /// `validate_request`'s `evidence.is_null()` arm deleted.
    SkipNullEvidence,
    /// `validate_request`'s action-target match deleted.
    SkipActionTarget,
    /// `evaluate`'s `static.minimum_severity` arm deleted.
    SkipMinimumSeverity,
    /// `evaluate`'s `static.human_gate` arm deleted.
    SkipHumanGate,
    /// `evaluate`'s deploy-decoy minimum-severity arm deleted.
    SkipDeployDecoyMinimum,
    /// `scope_rate_limit_decision`'s over-budget arm deleted.
    SkipScopeRateLimit,
}

/// Mirror of `swarm_policy::static_gate::StaticApprovalGate`, copied from
/// `crates/swarm-policy/src/static_gate.rs` with one guard removable.
///
struct MirroredStaticGate {
    human_gate_severity: Severity,
    max_actions_per_scope_per_minute: usize,
    mutation: StaticMutation,
    scope_windows: HashMap<String, VecDeque<i64>>,
}

impl MirroredStaticGate {
    fn from_config(config: &PolicyConfig, mutation: StaticMutation) -> Self {
        Self {
            human_gate_severity: config.human_gate_severity,
            max_actions_per_scope_per_minute: config.max_actions_per_scope_per_minute,
            mutation,
            scope_windows: HashMap::new(),
        }
    }

    fn destructive_action(request: &ActionRequest) -> bool {
        matches!(
            request.action,
            ResponseAction::BlockEgress { .. }
                | ResponseAction::IsolateHost { .. }
                | ResponseAction::RevokeCredential { .. }
                | ResponseAction::SinkholeDns { .. }
                | ResponseAction::TerminateUserSession { .. }
                | ResponseAction::InjectFirewallRule { .. }
                | ResponseAction::QuarantineFile { .. }
                | ResponseAction::KillProcess { .. }
                | ResponseAction::SuspendProcess { .. }
                | ResponseAction::DisableUserAccount { .. }
                | ResponseAction::ForcePasswordReset { .. }
                | ResponseAction::RemoveScheduledTask { .. }
        )
    }

    fn validate_request(&self, request: &ActionRequest) -> Result<(), ApprovalError> {
        if self.mutation != StaticMutation::SkipNullEvidence && request.evidence.is_null() {
            return Err(ApprovalError::InvalidRequest(
                "evidence bundle must not be null".to_string(),
            ));
        }
        let invalid_target = match &request.action {
            ResponseAction::BlockEgress { target } if target.trim().is_empty() => {
                Some("block target must not be empty")
            }
            ResponseAction::IsolateHost { host_id } if host_id.trim().is_empty() => {
                Some("host_id must not be empty")
            }
            ResponseAction::RevokeCredential { credential_id }
                if credential_id.trim().is_empty() =>
            {
                Some("credential_id must not be empty")
            }
            ResponseAction::SinkholeDns { domain } if domain.trim().is_empty() => {
                Some("domain must not be empty")
            }
            ResponseAction::TerminateUserSession {
                host_id,
                session_id,
            } if host_id.trim().is_empty() || session_id.trim().is_empty() => {
                Some("host_id and session_id must not be empty")
            }
            ResponseAction::TriggerEdrScan {
                host_id,
                scan_profile,
            } if host_id.trim().is_empty() || scan_profile.trim().is_empty() => {
                Some("host_id and scan_profile must not be empty")
            }
            ResponseAction::InjectFirewallRule {
                host_id,
                rule_name,
                direction,
                cidr,
                ..
            } if host_id.trim().is_empty()
                || rule_name.trim().is_empty()
                || direction.trim().is_empty()
                || cidr.trim().is_empty() =>
            {
                Some("host_id, rule_name, direction, and cidr must not be empty")
            }
            ResponseAction::QuarantineFile { host_id, file_path }
                if host_id.trim().is_empty() || file_path.trim().is_empty() =>
            {
                Some("host_id and file_path must not be empty")
            }
            ResponseAction::KillProcess {
                host_id,
                process_name,
            }
            | ResponseAction::SuspendProcess {
                host_id,
                process_name,
            } if host_id.trim().is_empty() || process_name.trim().is_empty() => {
                Some("host_id and process_name must not be empty")
            }
            ResponseAction::DisableUserAccount { user_id }
            | ResponseAction::ForcePasswordReset { user_id }
                if user_id.trim().is_empty() =>
            {
                Some("user_id must not be empty")
            }
            ResponseAction::RemoveScheduledTask { host_id, task_name }
                if host_id.trim().is_empty() || task_name.trim().is_empty() =>
            {
                Some("host_id and task_name must not be empty")
            }
            ResponseAction::DeployDecoy {
                decoy_type,
                target_zone,
            } if decoy_type.trim().is_empty() || target_zone.trim().is_empty() => {
                Some("decoy_type and target_zone must not be empty")
            }
            ResponseAction::Escalate { summary, .. } if summary.trim().is_empty() => {
                Some("summary must not be empty")
            }
            _ => None,
        };
        if self.mutation != StaticMutation::SkipActionTarget
            && let Some(reason) = invalid_target
        {
            return Err(ApprovalError::InvalidRequest(reason.to_string()));
        }
        Ok(())
    }

    fn prune_window(window: &mut VecDeque<i64>, now_ms: i64) {
        while window
            .front()
            .is_some_and(|timestamp| *timestamp <= now_ms.saturating_sub(60_000))
        {
            window.pop_front();
        }
    }

    fn scope_rate_limit_decision(
        &mut self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Option<PolicyDecision> {
        let scope = scope_for_response_action(&request.action)
            .unwrap_or_else(|| format!("unscoped:{}", request.action.kind()));
        let limit = self.max_actions_per_scope_per_minute;
        let mutation = self.mutation;
        let window = self.scope_windows.entry(scope.clone()).or_default();
        Self::prune_window(window, context.now_ms);
        if mutation != StaticMutation::SkipScopeRateLimit && window.len() >= limit {
            return Some(PolicyDecision::deny_with_rule(
                "static.scope_rate_limit",
                format!("scope `{scope}` exceeded {limit} actions per minute"),
            ));
        }
        window.push_back(context.now_ms);
        None
    }

    fn evaluate(
        &mut self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<PolicyDecision, ApprovalError> {
        self.validate_request(request)?;

        if self.mutation != StaticMutation::SkipMinimumSeverity
            && Self::destructive_action(request)
            && request.severity == Severity::Low
        {
            return Ok(PolicyDecision::deny_with_rule(
                "static.minimum_severity",
                "destructive actions require at least medium severity",
            ));
        }

        if self.mutation != StaticMutation::SkipDeployDecoyMinimum
            && matches!(request.action, ResponseAction::DeployDecoy { .. })
            && request.severity == Severity::Low
        {
            return Ok(PolicyDecision::deny_with_rule(
                "static.deploy_decoy_min_severity",
                "deploy_decoy requires at least medium severity",
            ));
        }

        if let Some(decision) = self.scope_rate_limit_decision(request, context) {
            return Ok(decision);
        }

        if self.mutation != StaticMutation::SkipHumanGate
            && Self::destructive_action(request)
            && request.severity >= self.human_gate_severity
        {
            return Ok(PolicyDecision::require_human_with_rule(
                "static.human_gate",
                "authorized but held for human approval",
            ));
        }

        Ok(PolicyDecision::allow_with_rule(
            "static.default_allow",
            "authorized for immediate execution",
        ))
    }
}

// ---------------------------------------------------------------------------
// POLICY-ACTION-TARGETS-NONEMPTY
// ---------------------------------------------------------------------------

#[test]
fn broken_action_target_validation_permits_empty_fields_across_all_action_variants() {
    let config = PolicyConfig::default();
    let context = context(1_700_000_000_000);
    let blank = || "   ".to_string();
    let value = |text: &str| text.to_string();
    let probes = vec![
        (
            "block.target",
            ResponseAction::BlockEgress { target: blank() },
        ),
        (
            "isolate.host",
            ResponseAction::IsolateHost { host_id: blank() },
        ),
        (
            "revoke.credential",
            ResponseAction::RevokeCredential {
                credential_id: blank(),
            },
        ),
        (
            "sinkhole.domain",
            ResponseAction::SinkholeDns { domain: blank() },
        ),
        (
            "session.host",
            ResponseAction::TerminateUserSession {
                host_id: blank(),
                session_id: value("s-1"),
            },
        ),
        (
            "session.id",
            ResponseAction::TerminateUserSession {
                host_id: value("host-1"),
                session_id: blank(),
            },
        ),
        (
            "scan.host",
            ResponseAction::TriggerEdrScan {
                host_id: blank(),
                scan_profile: value("full"),
            },
        ),
        (
            "scan.profile",
            ResponseAction::TriggerEdrScan {
                host_id: value("host-1"),
                scan_profile: blank(),
            },
        ),
        (
            "firewall.host",
            ResponseAction::InjectFirewallRule {
                host_id: blank(),
                rule_name: value("deny"),
                direction: value("out"),
                cidr: value("192.0.2.0/24"),
                port: None,
            },
        ),
        (
            "firewall.name",
            ResponseAction::InjectFirewallRule {
                host_id: value("host-1"),
                rule_name: blank(),
                direction: value("out"),
                cidr: value("192.0.2.0/24"),
                port: None,
            },
        ),
        (
            "firewall.direction",
            ResponseAction::InjectFirewallRule {
                host_id: value("host-1"),
                rule_name: value("deny"),
                direction: blank(),
                cidr: value("192.0.2.0/24"),
                port: None,
            },
        ),
        (
            "firewall.cidr",
            ResponseAction::InjectFirewallRule {
                host_id: value("host-1"),
                rule_name: value("deny"),
                direction: value("out"),
                cidr: blank(),
                port: None,
            },
        ),
        (
            "quarantine.host",
            ResponseAction::QuarantineFile {
                host_id: blank(),
                file_path: value("/tmp/e"),
            },
        ),
        (
            "quarantine.path",
            ResponseAction::QuarantineFile {
                host_id: value("host-1"),
                file_path: blank(),
            },
        ),
        (
            "kill.host",
            ResponseAction::KillProcess {
                host_id: blank(),
                process_name: value("bad"),
            },
        ),
        (
            "kill.process",
            ResponseAction::KillProcess {
                host_id: value("host-1"),
                process_name: blank(),
            },
        ),
        (
            "suspend.host",
            ResponseAction::SuspendProcess {
                host_id: blank(),
                process_name: value("bad"),
            },
        ),
        (
            "suspend.process",
            ResponseAction::SuspendProcess {
                host_id: value("host-1"),
                process_name: blank(),
            },
        ),
        (
            "disable.user",
            ResponseAction::DisableUserAccount { user_id: blank() },
        ),
        (
            "reset.user",
            ResponseAction::ForcePasswordReset { user_id: blank() },
        ),
        (
            "task.host",
            ResponseAction::RemoveScheduledTask {
                host_id: blank(),
                task_name: value("evil"),
            },
        ),
        (
            "task.name",
            ResponseAction::RemoveScheduledTask {
                host_id: value("host-1"),
                task_name: blank(),
            },
        ),
        (
            "decoy.type",
            ResponseAction::DeployDecoy {
                decoy_type: blank(),
                target_zone: value("dmz"),
            },
        ),
        (
            "decoy.zone",
            ResponseAction::DeployDecoy {
                decoy_type: value("honeytoken"),
                target_zone: blank(),
            },
        ),
        (
            "escalate.summary",
            ResponseAction::Escalate {
                summary: blank(),
                urgency: Severity::Medium,
            },
        ),
    ];

    let probes: Vec<(&'static str, ActionRequest)> = probes
        .into_iter()
        .map(|(label, action)| {
            (
                label,
                request(
                    action,
                    Severity::Medium,
                    escalation_evidence(Severity::Medium),
                ),
            )
        })
        .collect();
    negative_protocol::assert_registered_negative_case! {
        case: POLICY_ACTION_TARGETS_NONEMPTY,
        mutation: StaticMutation,
        control: StaticMutation::None,
        broken: StaticMutation::SkipActionTarget,
        state: {
            config: PolicyConfig = config,
            context: ApprovalContext = context,
        },
        probe: Vec<(&'static str, ActionRequest)> = probes,
        outcome: Vec<(&'static str, String)>,
        real_probe: probe,
        production_each: swarm_policy::static_gate::StaticApprovalGate::evaluate,
        arguments_each: (
            &StaticApprovalGate::from_config(config),
            &item.1,
            context,
        ),
        items: item in probe.iter(),
        normalize_each: |production_result, item| (item.0, outcome(&production_result)),
        mirror: |_state, probe, mutation| {
            probe.iter().map(|(label, request)| {
                (*label, outcome(&MirroredStaticGate::from_config(config, mutation).evaluate(request, context)))
            }).collect()
        },
        denied: |outcomes| outcomes.iter().all(|(_, value)| value.starts_with("Err/")),
        permitted: |outcomes| outcomes.iter().all(|(_, value)| value == "Allow/static.default_allow"),
    }
}

// ---------------------------------------------------------------------------
// POLICY-DEPLOY-DECOY-MIN-SEVERITY
// ---------------------------------------------------------------------------

#[test]
fn broken_deploy_decoy_minimum_permits_a_low_severity_deployment() {
    let config = PolicyConfig::default();
    let probe = request(
        ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        },
        Severity::Low,
        escalation_evidence(Severity::Low),
    );
    let context = context(1_700_000_000_000);
    negative_protocol::assert_registered_negative_case! {
        case: POLICY_DEPLOY_DECOY_MIN_SEVERITY,
        mutation: StaticMutation,
        control: StaticMutation::None,
        broken: StaticMutation::SkipDeployDecoyMinimum,
        state: {
            config: PolicyConfig = config,
            context: ApprovalContext = context,
        },
        probe: ActionRequest = probe,
        outcome: String,
        real_probe: probe,
        production: swarm_policy::static_gate::StaticApprovalGate::evaluate,
        arguments: (
            &StaticApprovalGate::from_config(config), probe, context,
        ),
        call: sync,
        normalize: |production_result| outcome(&production_result),
        mirror: |_state, probe, mutation| outcome(&MirroredStaticGate::from_config(config, mutation).evaluate(probe, context)),
        denied: |value| value == "Deny/static.deploy_decoy_min_severity",
        permitted: |value| value == "Allow/static.default_allow",
    }
}

/// Verdict, or the error kind, flattened so the control can compare the real
/// gate against the unmutated mirror in one assertion.
fn outcome(result: &Result<PolicyDecision, ApprovalError>) -> String {
    match result {
        Ok(decision) => format!("{:?}/{}", decision.verdict, decision.rule_name),
        Err(error) => format!("Err/{error}"),
    }
}

// ---------------------------------------------------------------------------
// POLICY-NULL-EVIDENCE-REFUSED
// ---------------------------------------------------------------------------

#[test]
fn broken_validate_request_permits_the_null_evidence_request_the_real_gate_refuses() {
    let config = PolicyConfig::default();
    let real = StaticApprovalGate::from_config(&config);
    let probe = request(isolate_host(), Severity::High, serde_json::Value::Null);
    let context = context(1_700_000_000_000);

    negative_protocol::assert_registered_negative_case! {
        case: POLICY_NULL_EVIDENCE_REFUSED,
        mutation: StaticMutation,
        control: StaticMutation::None,
        broken: StaticMutation::SkipNullEvidence,
        state: {
            config: PolicyConfig = config,
            real: StaticApprovalGate = real,
            context: ApprovalContext = context,
        },
        probe: ActionRequest = probe,
        outcome: String,
        real_probe: probe,
        production: swarm_policy::static_gate::StaticApprovalGate::evaluate,
        arguments: (&*real, probe, context),
        call: sync,
        normalize: |production_result| outcome(&production_result),
        mirror: |_state, probe, mutation| outcome(&MirroredStaticGate::from_config(config, mutation).evaluate(probe, context)),
        denied: |value| value.starts_with("Err/"),
        permitted: |value| value == "RequireHuman/static.human_gate",
    }
}

// ---------------------------------------------------------------------------
// POLICY-DESTRUCTIVE-MIN-SEVERITY
// ---------------------------------------------------------------------------

#[test]
fn broken_minimum_severity_permits_the_low_severity_destructive_action_the_real_gate_denies() {
    let config = PolicyConfig::default();
    let real = StaticApprovalGate::from_config(&config);
    let probe = request(
        isolate_host(),
        Severity::Low,
        escalation_evidence(Severity::Low),
    );
    let context = context(1_700_000_000_000);

    negative_protocol::assert_registered_negative_case! {
        case: POLICY_DESTRUCTIVE_MIN_SEVERITY,
        mutation: StaticMutation,
        control: StaticMutation::None,
        broken: StaticMutation::SkipMinimumSeverity,
        state: {
            config: PolicyConfig = config,
            real: StaticApprovalGate = real,
            context: ApprovalContext = context,
        },
        probe: ActionRequest = probe,
        outcome: String,
        real_probe: probe,
        production: swarm_policy::static_gate::StaticApprovalGate::evaluate,
        arguments: (&*real, probe, context),
        call: sync,
        normalize: |production_result| outcome(&production_result),
        mirror: |_state, probe, mutation| outcome(&MirroredStaticGate::from_config(config, mutation).evaluate(probe, context)),
        denied: |value| value == "Deny/static.minimum_severity",
        permitted: |value| value == "Allow/static.default_allow",
    }
}

// ---------------------------------------------------------------------------
// POLICY-DESTRUCTIVE-HUMAN-GATE
// ---------------------------------------------------------------------------

#[test]
fn broken_human_gate_permits_immediate_execution_of_what_the_real_gate_holds() {
    let config = PolicyConfig::default();
    assert_eq!(
        config.human_gate_severity,
        Severity::High,
        "the probe below is chosen against PolicyConfig::default()"
    );
    let real = StaticApprovalGate::from_config(&config);
    let probe = request(
        isolate_host(),
        Severity::Critical,
        escalation_evidence(Severity::Critical),
    );
    let context = context(1_700_000_000_000);

    negative_protocol::assert_registered_negative_case! {
        case: POLICY_DESTRUCTIVE_HUMAN_GATE,
        mutation: StaticMutation,
        control: StaticMutation::None,
        broken: StaticMutation::SkipHumanGate,
        state: {
            config: PolicyConfig = config,
            real: StaticApprovalGate = real,
            context: ApprovalContext = context,
        },
        probe: ActionRequest = probe,
        outcome: String,
        real_probe: probe,
        production: swarm_policy::static_gate::StaticApprovalGate::evaluate,
        arguments: (&*real, probe, context),
        call: sync,
        normalize: |production_result| outcome(&production_result),
        mirror: |_state, probe, mutation| outcome(&MirroredStaticGate::from_config(config, mutation).evaluate(probe, context)),
        denied: |value| value == "RequireHuman/static.human_gate",
        permitted: |value| value == "Allow/static.default_allow",
    }
}

// ---------------------------------------------------------------------------
// POLICY-SCOPE-RATE-LIMIT
// ---------------------------------------------------------------------------

#[test]
fn broken_scope_rate_limit_permits_the_over_budget_action_the_real_gate_denies() {
    let config = PolicyConfig::default();
    assert_eq!(
        config.max_actions_per_scope_per_minute, 5,
        "the burst below is sized against PolicyConfig::default()"
    );
    // Medium keeps the verdict below `human_gate_severity` so the rate limit is
    // the only arm that can deny; at Critical the human gate would answer first
    // and this test would pass for the wrong reason.
    let probe = request(
        isolate_host(),
        Severity::Medium,
        escalation_evidence(Severity::Medium),
    );
    let context = context(1_700_000_000_000);
    let real = StaticApprovalGate::from_config(&config);
    for _ in 0..config.max_actions_per_scope_per_minute {
        let _ = real.evaluate(&probe, &context);
    }

    negative_protocol::assert_registered_negative_case! {
        case: POLICY_SCOPE_RATE_LIMIT,
        mutation: StaticMutation,
        control: StaticMutation::None,
        broken: StaticMutation::SkipScopeRateLimit,
        state: {
            config: PolicyConfig = config,
            real: StaticApprovalGate = real,
            context: ApprovalContext = context,
        },
        probe: ActionRequest = probe,
        outcome: String,
        real_probe: probe,
        production: swarm_policy::static_gate::StaticApprovalGate::evaluate,
        arguments: (&*real, probe, context),
        call: sync,
        normalize: |production_result| outcome(&production_result),
        mirror: |_state, probe, mutation| {
            let mut gate = MirroredStaticGate::from_config(config, mutation);
            for _ in 0..config.max_actions_per_scope_per_minute {
                let _ = gate.evaluate(probe, context);
            }
            outcome(&gate.evaluate(probe, context))
        },
        denied: |value| value == "Deny/static.scope_rate_limit",
        permitted: |value| value == "Allow/static.default_allow",
    }
}

// ---------------------------------------------------------------------------
// POLICY-EMPTY-RULESET-DENIES
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigurableMutation {
    None,
    SkipEmptyRuleset,
    SkipTimeWindow,
    SkipAgentRateLimit,
    FlipDenyToAllow,
}

/// Mirror of `ConfigurableApprovalGate::evaluate`'s empty-ruleset ordering,
/// with that fail-closed arm selectively removable.
///
/// The shipped function's remaining body is "match a rule, else delegate to the
/// static gate"; with no rules loaded there is nothing to match, so the mirror
/// is exactly that delegation. That is the fall-open this arm exists to stop,
/// and it is what a reviewer should check this against.
struct MirroredConfigurableGate {
    config: PolicyConfig,
    mutation: ConfigurableMutation,
    agent_windows: HashMap<String, VecDeque<i64>>,
}

impl MirroredConfigurableGate {
    fn new(config: &PolicyConfig, mutation: ConfigurableMutation) -> Self {
        Self {
            config: config.clone(),
            mutation,
            agent_windows: HashMap::new(),
        }
    }

    fn evaluate(
        &mut self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<PolicyDecision, ApprovalError> {
        if self.mutation != ConfigurableMutation::SkipEmptyRuleset && self.config.rules.is_empty() {
            return Ok(PolicyDecision::deny_with_rule(
                "configurable.fail_closed.empty_ruleset",
                "no configurable policy rules loaded; failing closed",
            ));
        }

        let threat_class = request
            .evidence
            .get("escalation")
            .and_then(|value| value.get("threat_class"))
            .cloned()
            .or_else(|| request.evidence.get("threat_class").cloned())
            .and_then(|value| serde_json::from_value::<ThreatClass>(value).ok());
        if let Some(threat_class) = threat_class {
            for rule in &self.config.rules {
                if rule.threat_class != threat_class
                    || request.severity < rule.min_severity
                    || request.severity > rule.max_severity
                    || (!rule.actions.is_empty()
                        && !rule
                            .actions
                            .iter()
                            .any(|action| action.matches(&request.action)))
                {
                    continue;
                }
                if self.mutation != ConfigurableMutation::SkipTimeWindow
                    && let Some(window) = rule.time_window_utc
                {
                    let hour = context
                        .now_ms
                        .div_euclid(1_000)
                        .div_euclid(3_600)
                        .rem_euclid(24) as u8;
                    if !window.contains_hour(hour) {
                        return Ok(PolicyDecision::deny_with_rule(
                            rule.name.clone(),
                            format!("rule `{}` is inactive at {hour:02}:00 UTC", rule.name),
                        ));
                    }
                }
                if let Some(limit) = rule.max_actions_per_agent_per_minute {
                    let key = format!("{}:{}", rule.name, request.requested_by.0);
                    let window = self.agent_windows.entry(key).or_default();
                    MirroredStaticGate::prune_window(window, context.now_ms);
                    if self.mutation != ConfigurableMutation::SkipAgentRateLimit
                        && window.len() >= limit
                    {
                        return Ok(PolicyDecision::deny_with_rule(
                            rule.name.clone(),
                            "agent exceeded rule limit",
                        ));
                    }
                    window.push_back(context.now_ms);
                }
                return Ok(match rule.decision {
                    PolicyRuleDecision::Allow => {
                        PolicyDecision::allow_with_rule(rule.name.clone(), "allowed by rule")
                    }
                    PolicyRuleDecision::Deny
                        if self.mutation != ConfigurableMutation::FlipDenyToAllow =>
                    {
                        PolicyDecision::deny_with_rule(rule.name.clone(), "denied by rule")
                    }
                    PolicyRuleDecision::Deny => {
                        PolicyDecision::allow_with_rule(rule.name.clone(), "mutated to allow")
                    }
                });
            }
        }
        StaticApprovalGate::from_config(&self.config).evaluate(request, context)
    }
}

#[test]
fn broken_empty_ruleset_arm_permits_the_action_the_real_gate_fails_closed_on() {
    let config = PolicyConfig::default();
    assert!(
        config.rules.is_empty(),
        "the in-memory PolicyConfig::default() constructor carries no rules; \
         rulesets/default.yaml is configured and is not this probe"
    );
    // Medium: below the human gate and a class the static fallback would allow.
    // If the probe were Low or Critical the static gate would deny or hold on
    // its own and the difference below would not be attributable to this arm.
    let probe = request(
        isolate_host(),
        Severity::Medium,
        escalation_evidence(Severity::Medium),
    );
    let context = context(1_700_000_000_000);

    negative_protocol::assert_registered_negative_case! {
        case: POLICY_EMPTY_RULESET_DENIES,
        mutation: ConfigurableMutation,
        control: ConfigurableMutation::None,
        broken: ConfigurableMutation::SkipEmptyRuleset,
        state: {
            config: PolicyConfig = config.clone(),
            context: ApprovalContext = context.clone(),
        },
        probe: ActionRequest = probe.clone(),
        outcome: String,
        real_probe: probe,
        production: swarm_policy::configurable_gate::ConfigurableApprovalGate::evaluate,
        arguments: (
            &ConfigurableApprovalGate::from_config(config), probe, context,
        ),
        call: sync,
        normalize: |production_result| outcome(&production_result),
        mirror: |_state, probe, mutation| outcome(&MirroredConfigurableGate::new(config, mutation).evaluate(probe, context)),
        denied: |value| value == "Deny/configurable.fail_closed.empty_ruleset",
        permitted: |value| value == "Allow/static.default_allow",
    }

    // The control for this row is the OTHER direction: with a rule loaded, the
    // real gate must reach the rule rather than the fail-closed arm. Without
    // this, `evaluate` could deny everything unconditionally and still pass the
    // assertions above.
    let mut configured = config.clone();
    configured.rules.push(PolicyRuleConfig {
        name: "execution-allow".to_string(),
        decision: PolicyRuleDecision::Allow,
        threat_class: ThreatClass::Execution,
        actions: Vec::new(),
        min_severity: Severity::Low,
        max_severity: Severity::Critical,
        time_window_utc: None,
        max_actions_per_agent_per_minute: None,
        reason: None,
    });
    let with_rules = ConfigurableApprovalGate::from_config(&configured);
    let decision = with_rules.evaluate(&probe, &context).expect("a decision");
    assert_eq!(decision.verdict, PolicyVerdict::Allow);
    assert_eq!(decision.rule_name, "execution-allow");
}

fn configured_rule(decision: PolicyRuleDecision) -> PolicyRuleConfig {
    PolicyRuleConfig {
        name: "execution-rule".to_string(),
        decision,
        threat_class: ThreatClass::Execution,
        actions: Vec::new(),
        min_severity: Severity::Low,
        max_severity: Severity::Critical,
        time_window_utc: None,
        max_actions_per_agent_per_minute: None,
        reason: None,
    }
}

#[test]
fn broken_time_window_admits_a_request_outside_the_configured_window() {
    let mut config = PolicyConfig::default();
    let mut rule = configured_rule(PolicyRuleDecision::Allow);
    rule.time_window_utc = Some(PolicyTimeWindowConfig {
        start_hour_utc: 1,
        end_hour_utc: 2,
    });
    config.rules.push(rule);
    let probe = request(
        isolate_host(),
        Severity::Medium,
        escalation_evidence(Severity::Medium),
    );
    let context = context(12 * 3_600_000);
    negative_protocol::assert_registered_negative_case! {
        case: POLICY_RULE_TIME_WINDOW,
        mutation: ConfigurableMutation,
        control: ConfigurableMutation::None,
        broken: ConfigurableMutation::SkipTimeWindow,
        state: {
            config: PolicyConfig = config,
            context: ApprovalContext = context,
        },
        probe: ActionRequest = probe,
        outcome: String,
        real_probe: probe,
        production: swarm_policy::configurable_gate::ConfigurableApprovalGate::evaluate,
        arguments: (
            &ConfigurableApprovalGate::from_config(config), probe, context,
        ),
        call: sync,
        normalize: |production_result| outcome(&production_result),
        mirror: |_state, probe, mutation| outcome(&MirroredConfigurableGate::new(config, mutation).evaluate(probe, context)),
        denied: |value| value == "Deny/execution-rule",
        permitted: |value| value == "Allow/execution-rule",
    }
}

#[test]
fn broken_agent_rate_limit_admits_the_over_budget_request() {
    let mut config = PolicyConfig::default();
    let mut rule = configured_rule(PolicyRuleDecision::Allow);
    rule.max_actions_per_agent_per_minute = Some(1);
    config.rules.push(rule);
    let probe = request(
        isolate_host(),
        Severity::Medium,
        escalation_evidence(Severity::Medium),
    );
    let context = context(1_700_000_000_000);
    let real = ConfigurableApprovalGate::from_config(&config);
    let _ = real.evaluate(&probe, &context);
    negative_protocol::assert_registered_negative_case! {
        case: POLICY_RULE_AGENT_RATE_LIMIT,
        mutation: ConfigurableMutation,
        control: ConfigurableMutation::None,
        broken: ConfigurableMutation::SkipAgentRateLimit,
        state: {
            config: PolicyConfig = config,
            real: ConfigurableApprovalGate = real,
            context: ApprovalContext = context,
        },
        probe: ActionRequest = probe,
        outcome: String,
        real_probe: probe,
        production: swarm_policy::configurable_gate::ConfigurableApprovalGate::evaluate,
        arguments: (&*real, probe, context),
        call: sync,
        normalize: |production_result| outcome(&production_result),
        mirror: |_state, probe, mutation| {
            let mut gate = MirroredConfigurableGate::new(config, mutation);
            let _ = gate.evaluate(probe, context);
            outcome(&gate.evaluate(probe, context))
        },
        denied: |value| value == "Deny/execution-rule",
        permitted: |value| value == "Allow/execution-rule",
    }
}

#[test]
fn broken_configured_deny_rule_turns_an_explicit_denial_into_allow() {
    let mut config = PolicyConfig::default();
    config.rules.push(configured_rule(PolicyRuleDecision::Deny));
    let probe = request(
        isolate_host(),
        Severity::Medium,
        escalation_evidence(Severity::Medium),
    );
    let context = context(1_700_000_000_000);
    negative_protocol::assert_registered_negative_case! {
        case: POLICY_CONFIGURED_DENY_RULE,
        mutation: ConfigurableMutation,
        control: ConfigurableMutation::None,
        broken: ConfigurableMutation::FlipDenyToAllow,
        state: {
            config: PolicyConfig = config,
            context: ApprovalContext = context,
        },
        probe: ActionRequest = probe,
        outcome: String,
        real_probe: probe,
        production: swarm_policy::configurable_gate::ConfigurableApprovalGate::evaluate,
        arguments: (
            &ConfigurableApprovalGate::from_config(config), probe, context,
        ),
        call: sync,
        normalize: |production_result| outcome(&production_result),
        mirror: |_state, probe, mutation| outcome(&MirroredConfigurableGate::new(config, mutation).evaluate(probe, context)),
        denied: |value| value == "Deny/execution-rule",
        permitted: |value| value == "Allow/execution-rule",
    }
}
