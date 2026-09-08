//! Pure, IO-free decision core for the policy gates.
//!
//! `static_gate` and `configurable_gate` each hold a rate-limit window
//! (`Arc<Mutex<HashMap<String, VecDeque<i64>>>>`) keyed by scope or by
//! agent, and both prune-then-check-then-record that window against a
//! configured per-minute budget before they build a [`PolicyDecision`]. That
//! prune/check/record algorithm is byte-identical in the two gates today; it
//! is lifted here once, as a total function over values, so it can be
//! proven about directly (Kani, phase 293) without needing a clock, a lock,
//! or the filesystem to run.
//!
//! Every function in this module is **pure and total**: no [`std::sync::Mutex`],
//! no `std::fs`, no clock read (`SystemTime::now`, `Instant::now`, or an
//! internal `now_ms()`), no network, no `panic!`, no unbounded recursion.
//! `now_ms` is always a plain parameter supplied by the caller. The gate
//! structs keep the `Mutex` at the edge: under the lock, they read the
//! stored window, hand it to [`evaluate_rate_limit`] by value, and write the
//! returned window back in its place. No verdict changes for any input --
//! this module is an extraction of existing logic, not a new decision.
//!
//! ## Governance predicates (DCORE-02)
//!
//! The same discipline is applied to the governance authorization predicates
//! that used to live in `swarm-agents` (`GovernancePolicy::can_act`'s
//! partition branch, `ContingencyLease::{verify, can_redeem, redeem}`, and
//! `governance_quorum_threshold`). Their pure decision logic is lifted here as
//! total functions over plain values: a lease is decided from its scope,
//! blast-radius cap, expiry and already-redeemed scopes (a [`LeaseTerms`]
//! view) plus the action and a caller-supplied `now_ms`, never from the
//! cryptographic `ConsensusGovernanceReceipt` it also carries. That receipt --
//! and the `swarm-consensus` crate that defines it -- sits ABOVE this crate in
//! the dependency graph, so it is deliberately kept out of the decision core:
//! the redemption verdict is a scope/expiry/blast-radius decision over plain
//! values, provable (phase 293) without it. `swarm-agents` keeps the
//! receipt-bearing `ContingencyLease` type and the cryptographic half of
//! `verify`; it calls these functions with the clock supplied explicitly at
//! the call site, so no verdict changes for any input.
//!
//! ## Severity gating predicates (DCORE-05, SC1)
//!
//! The same discipline is applied to `static_gate::evaluate`'s three severity
//! decisions -- the `static.minimum_severity` and
//! `static.deploy_decoy_min_severity` floors and the `static.human_gate` hold.
//! Their pure logic is lifted here as [`severity_floor_denial`] and
//! [`human_gate_decision`], together with the [`destructive_action`] classifier
//! they both read, so the human gate that carries the
//! `PolicyHumanGateOnDestructiveAction` invariant now lives on a pure surface
//! phase 293's Kani harness can prove about directly. `static_gate::evaluate`
//! calls these in the identical order it applied the inline checks in, so no
//! verdict changes for any input.
//!
//! [`PolicyDecision`]: crate::PolicyDecision

use crate::PolicyDecision;
use crate::static_gate::scope_for_response_action;
use std::collections::VecDeque;
use swarm_core::types::{ResponseAction, Severity};

/// The trailing window a rate-limit budget is measured over, in
/// milliseconds. Matches the prune threshold `static_gate` and
/// `configurable_gate` already used before this extraction.
const RATE_LIMIT_WINDOW_MS: i64 = 60_000;

/// The result of checking one action against a rate-limit window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitOutcome {
    /// The action fit inside the budget. The window returned alongside this
    /// outcome already records the action's timestamp.
    Allowed,
    /// The action would exceed the budget. The window returned alongside
    /// this outcome is pruned but does NOT record the action -- a denied
    /// action never consumes budget.
    Denied,
}

/// Drop every timestamp in `window` that fell outside the trailing
/// [`RATE_LIMIT_WINDOW_MS`] as of `now_ms`. Pure: mutates only the `window`
/// value the caller passed in and reads only its `now_ms` parameter for the
/// current time.
fn prune_stale_window(window: &mut VecDeque<i64>, now_ms: i64) {
    while window
        .front()
        .is_some_and(|timestamp| *timestamp <= now_ms.saturating_sub(RATE_LIMIT_WINDOW_MS))
    {
        window.pop_front();
    }
}

// INVARIANT: PolicyScopeRateLimitDeniesBurst
/// Prune `window` to the trailing 60-second budget as of `now_ms`, then
/// decide whether one more action at `now_ms` still fits inside `limit`
/// actions. Total and pure: takes the window and the clock as plain values
/// and returns both the [`RateLimitOutcome`] and the window exactly as the
/// caller should store it back -- an allowed action's timestamp is recorded,
/// a denied action's is not.
///
/// This is the shared enforcing logic behind both
/// `StaticApprovalGate`'s per-scope budget (`max_actions_per_scope_per_minute`)
/// and `ConfigurableApprovalGate`'s per-agent budget
/// (`max_actions_per_agent_per_minute`): the callers differ only in what key
/// they store the window under and how they phrase the denial reason, never
/// in this decision.
pub fn evaluate_rate_limit(
    mut window: VecDeque<i64>,
    now_ms: i64,
    limit: usize,
) -> (RateLimitOutcome, VecDeque<i64>) {
    prune_stale_window(&mut window, now_ms);
    if window.len() >= limit {
        return (RateLimitOutcome::Denied, window);
    }
    window.push_back(now_ms);
    (RateLimitOutcome::Allowed, window)
}

// ---------------------------------------------------------------------------
// Governance predicates (DCORE-02)
// ---------------------------------------------------------------------------

/// The Byzantine quorum threshold for a committee of `total_governors`, given
/// that committee's recommended fault tolerance `max_faulty` (a `3f + 1`
/// committee tolerates `f` faults and commits at `2f + 1` votes).
///
/// `max_faulty` is supplied by the caller rather than derived here on purpose:
/// the `3f + 1` fault model lives in `swarm-consensus`
/// (`recommended_max_faulty`), which sits above this crate, so the caller
/// passes the value in and this function stays a pure arithmetic total over
/// plain integers. The empty committee is special-cased to a threshold of `0`
/// (no governors, no quorum to reach) rather than `2 * 0 + 1 = 1`, preserving
/// the pre-extraction behaviour exactly. Saturating arithmetic keeps it total
/// for any `usize`.
pub fn governance_quorum_threshold(total_governors: usize, max_faulty: usize) -> usize {
    if total_governors == 0 {
        0
    } else {
        max_faulty.saturating_mul(2).saturating_add(1)
    }
}

/// The plain, receipt-free view of a contingency lease that the redemption
/// predicates read.
///
/// A lease also carries a cryptographic `ConsensusGovernanceReceipt`; it is
/// deliberately absent here. Redemption is a scope/expiry/blast-radius
/// decision over plain values, so it is decided in this pure core without the
/// receipt or the `swarm-consensus` crate that defines it (which sits above
/// `swarm-policy` in the dependency graph). Borrowed, so the caller keeps
/// ownership of the lease.
#[derive(Debug, Clone, Copy)]
pub struct LeaseTerms<'a> {
    /// The lease identifier, read only to phrase [`lease_redeem`] error text.
    pub lease_id: &'a str,
    /// The action kind this lease authorizes (`ResponseAction::kind`).
    pub action_kind: &'a str,
    /// The scope this lease is pinned to, if any. `None` covers every scope of
    /// the matching action kind.
    pub scope: Option<&'a str>,
    /// How many distinct scopes this lease may be redeemed across.
    pub blast_radius_cap: usize,
    /// Wall-clock expiry in milliseconds, compared against the caller-supplied
    /// `now_ms`.
    pub expires_at_ms: i64,
    /// Scopes already redeemed under this lease.
    pub redeemed_scopes: &'a [String],
}

/// The result of a successful [`lease_redeem`] check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseRedeemOutcome {
    /// The action's scope was already redeemed under this lease; redeeming it
    /// again is a no-op and nothing is recorded.
    AlreadyRedeemed,
    /// The action's scope is newly redeemed. The caller records the returned
    /// scope against the lease's `redeemed_scopes`.
    Recorded(String),
}

/// Whether `action` falls under `terms`: the same action kind, and -- when the
/// lease pins a scope -- the action's scope equals it. A scope-less lease
/// covers every scope of the matching kind. Pure and total.
pub fn lease_matches_action(terms: &LeaseTerms<'_>, action: &ResponseAction) -> bool {
    terms.action_kind == action.kind()
        && terms
            .scope
            .is_none_or(|scope| scope_for_response_action(action).as_deref() == Some(scope))
}

/// The key an action is redeemed under: its policy scope, or a synthetic
/// `unscoped:<kind>` key when the action has no scope. Pure and total.
pub fn action_scope_key(action: &ResponseAction) -> String {
    scope_for_response_action(action).unwrap_or_else(|| format!("unscoped:{}", action.kind()))
}

/// Whether `action` may be redeemed against `terms` as of `now_ms`: the action
/// must match, the lease must not have expired, and either its scope is
/// already redeemed (a re-redemption) or the lease still has blast-radius
/// budget for a new scope. Pure and total; the clock is the `now_ms`
/// parameter, never read here.
pub fn lease_can_redeem(terms: &LeaseTerms<'_>, action: &ResponseAction, now_ms: i64) -> bool {
    if !lease_matches_action(terms, action) || terms.expires_at_ms <= now_ms {
        return false;
    }
    let scope = action_scope_key(action);
    terms
        .redeemed_scopes
        .iter()
        .any(|existing| existing == &scope)
        || terms.redeemed_scopes.len() < terms.blast_radius_cap
}

/// Decide whether `action` may be redeemed against `terms` as of `now_ms`,
/// returning what the caller must record. Fails closed with the same error
/// text the method form produced: a non-matching action, an expired lease, or
/// a lease already at its blast-radius cap for a new scope. On success it
/// returns [`LeaseRedeemOutcome::AlreadyRedeemed`] (scope already present, no
/// change) or [`LeaseRedeemOutcome::Recorded`] with the scope the caller
/// appends. Pure and total: it never mutates `terms` and reads the clock only
/// through `now_ms`.
pub fn lease_redeem(
    terms: &LeaseTerms<'_>,
    action: &ResponseAction,
    now_ms: i64,
) -> Result<LeaseRedeemOutcome, String> {
    if !lease_matches_action(terms, action) {
        return Err(format!(
            "contingency lease `{}` does not cover action `{}`",
            terms.lease_id,
            action.kind()
        ));
    }
    if terms.expires_at_ms <= now_ms {
        return Err("contingency lease expired".to_string());
    }
    let scope = action_scope_key(action);
    if terms
        .redeemed_scopes
        .iter()
        .any(|existing| existing == &scope)
    {
        return Ok(LeaseRedeemOutcome::AlreadyRedeemed);
    }
    if terms.redeemed_scopes.len() >= terms.blast_radius_cap {
        return Err(format!(
            "contingency lease `{}` exceeded blast radius cap {}",
            terms.lease_id, terms.blast_radius_cap
        ));
    }
    Ok(LeaseRedeemOutcome::Recorded(scope))
}

/// The structural, clock-free half of contingency-lease verification: the
/// schema version matches `expected_schema_version`, the blast-radius cap is
/// positive, the declared duration is positive, and expiry is strictly after
/// issuance. Pure and total, and returns the same error text the method form
/// produced in the same order.
///
/// The cryptographic half of `ContingencyLease::verify` -- verifying the
/// `ConsensusGovernanceReceipt`'s signature, requiring an `Approve` decision,
/// and rebuilding the proposal hash -- stays in `swarm-agents` with the
/// receipt type; it is receipt-bound, not part of this IO-free decision core.
pub fn validate_lease_terms(
    schema_version: u32,
    expected_schema_version: u32,
    blast_radius_cap: usize,
    max_duration_ms: i64,
    issued_at_ms: i64,
    expires_at_ms: i64,
) -> Result<(), String> {
    if schema_version != expected_schema_version {
        return Err(format!(
            "unsupported contingency lease schema_version `{schema_version}`"
        ));
    }
    if blast_radius_cap == 0 {
        return Err("contingency lease blast radius cap must be positive".to_string());
    }
    if max_duration_ms <= 0 {
        return Err("contingency lease duration must be positive".to_string());
    }
    if expires_at_ms <= issued_at_ms {
        return Err("contingency lease expiry must be after issuance".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Severity gating predicates (DCORE-05, SC1)
// ---------------------------------------------------------------------------

/// Whether `action` is one of the twelve destructive/containment-class response
/// actions the severity floor and the human gate reason about. Pure, total
/// classification of the `ResponseAction` variant -- no clock, no lock, no IO.
///
/// Moved here from `static_gate` so the human gate that depends on it lives on
/// a provable surface (phase 293). Kept in step with
/// [`crate::static_gate::destructive_action_kinds`] by a test.
pub fn destructive_action(action: &ResponseAction) -> bool {
    matches!(
        action,
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

/// The severity-floor denials, in the EXACT order `static_gate::evaluate`
/// applied them: a destructive action at `Severity::Low` is denied under
/// `static.minimum_severity` first, and only if that did not fire, a
/// `DeployDecoy` at `Severity::Low` is denied under
/// `static.deploy_decoy_min_severity`. Returns `None` when neither floor is
/// tripped, so evaluation falls through to the rate-limit and human-gate
/// checks. Pure and total; the observable order and the rule names match the
/// pre-extraction behaviour byte-for-byte.
pub fn severity_floor_denial(
    action: &ResponseAction,
    severity: Severity,
) -> Option<PolicyDecision> {
    if destructive_action(action) && severity == Severity::Low {
        return Some(PolicyDecision::deny_with_rule(
            "static.minimum_severity",
            "destructive actions require at least medium severity",
        ));
    }

    if matches!(action, ResponseAction::DeployDecoy { .. }) && severity == Severity::Low {
        return Some(PolicyDecision::deny_with_rule(
            "static.deploy_decoy_min_severity",
            "deploy_decoy requires at least medium severity",
        ));
    }

    None
}

// INVARIANT: PolicyHumanGateOnDestructiveAction
/// Hold a destructive action at or above `human_gate_severity` for human
/// approval: returns `RequireHuman` under `static.human_gate` rather than
/// letting it auto-execute. Returns `None` when the action is not destructive
/// or its severity is below the gate, so evaluation falls through to the
/// default allow. Pure and total; the gate severity is a caller-supplied
/// parameter, never read from configuration or a clock here.
pub fn human_gate_decision(
    action: &ResponseAction,
    severity: Severity,
    human_gate_severity: Severity,
) -> Option<PolicyDecision> {
    if destructive_action(action) && severity >= human_gate_severity {
        return Some(PolicyDecision::require_human_with_rule(
            "static.human_gate",
            "authorized but held for human approval",
        ));
    }

    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        LeaseRedeemOutcome, LeaseTerms, RateLimitOutcome, action_scope_key, destructive_action,
        evaluate_rate_limit, governance_quorum_threshold, human_gate_decision, lease_can_redeem,
        lease_matches_action, lease_redeem, severity_floor_denial, validate_lease_terms,
    };
    use crate::PolicyVerdict;
    use std::collections::VecDeque;
    use swarm_core::types::{ResponseAction, Severity};

    fn block_egress(target: &str) -> ResponseAction {
        ResponseAction::BlockEgress {
            target: target.to_string(),
        }
    }

    #[test]
    fn empty_window_under_limit_is_allowed_and_records_the_timestamp() {
        let (outcome, window) = evaluate_rate_limit(VecDeque::new(), 1_000, 1);
        assert_eq!(outcome, RateLimitOutcome::Allowed);
        assert_eq!(window, VecDeque::from([1_000]));
    }

    #[test]
    fn second_action_at_limit_is_denied_and_does_not_record() {
        let (first, window) = evaluate_rate_limit(VecDeque::new(), 1_000, 1);
        assert_eq!(first, RateLimitOutcome::Allowed);

        let (second, window) = evaluate_rate_limit(window, 1_100, 1);
        assert_eq!(second, RateLimitOutcome::Denied);
        // The denied action's timestamp (1_100) must not appear: a denied
        // action never consumes budget.
        assert_eq!(window, VecDeque::from([1_000]));
    }

    #[test]
    fn action_outside_the_trailing_window_is_pruned_before_the_check() {
        let (first, window) = evaluate_rate_limit(VecDeque::new(), 1_700_000_000_000, 1);
        assert_eq!(first, RateLimitOutcome::Allowed);

        // 60_001ms later the first timestamp is outside the trailing 60s
        // window, so it is pruned and the budget is available again.
        let (second, window) = evaluate_rate_limit(window, 1_700_000_060_001, 1);
        assert_eq!(second, RateLimitOutcome::Allowed);
        assert_eq!(window, VecDeque::from([1_700_000_060_001]));
    }

    #[test]
    fn exactly_at_the_trailing_edge_is_still_pruned() {
        // A timestamp exactly `RATE_LIMIT_WINDOW_MS` behind `now_ms` is
        // pruned (the boundary is `<=`, matching the pre-extraction
        // behaviour byte-for-byte).
        let mut window = VecDeque::new();
        window.push_back(1_700_000_000_000);

        let (outcome, window) = evaluate_rate_limit(window, 1_700_000_060_000, 1);
        assert_eq!(outcome, RateLimitOutcome::Allowed);
        assert_eq!(window, VecDeque::from([1_700_000_060_000]));
    }

    #[test]
    fn zero_limit_denies_even_an_empty_window() {
        let (outcome, window) = evaluate_rate_limit(VecDeque::new(), 1_000, 0);
        assert_eq!(outcome, RateLimitOutcome::Denied);
        assert!(window.is_empty());
    }

    #[test]
    fn function_is_total_over_a_larger_window_at_a_higher_budget() {
        let seeded: VecDeque<i64> = (0..5).map(|i| 1_000 + i * 10).collect();
        let (outcome, window) = evaluate_rate_limit(seeded, 1_050, 10);
        assert_eq!(outcome, RateLimitOutcome::Allowed);
        // Five seeded timestamps plus the one just recorded.
        assert_eq!(window.len(), 6);
        assert_eq!(window.back().copied(), Some(1_050));
    }

    #[test]
    fn governance_quorum_threshold_is_zero_for_an_empty_committee() {
        // No governors, no quorum to reach -- the empty committee is 0, not the
        // `2 * 0 + 1 = 1` a naive formula would give.
        assert_eq!(governance_quorum_threshold(0, 0), 0);
        assert_eq!(governance_quorum_threshold(0, 5), 0);
    }

    #[test]
    fn governance_quorum_threshold_is_two_f_plus_one_for_a_populated_committee() {
        // f from `recommended_max_faulty`: committee 4 -> f 1 -> threshold 3;
        // committee 13 -> f 4 -> threshold 9; a solo committee -> f 0 -> 1.
        assert_eq!(governance_quorum_threshold(1, 0), 1);
        assert_eq!(governance_quorum_threshold(4, 1), 3);
        assert_eq!(governance_quorum_threshold(13, 4), 9);
    }

    fn lease_terms<'a>(
        blast_radius_cap: usize,
        expires_at_ms: i64,
        redeemed_scopes: &'a [String],
    ) -> LeaseTerms<'a> {
        LeaseTerms {
            lease_id: "lease-1",
            action_kind: "block_egress",
            scope: None,
            blast_radius_cap,
            expires_at_ms,
            redeemed_scopes,
        }
    }

    #[test]
    fn lease_matches_action_requires_the_same_kind() {
        let empty: Vec<String> = Vec::new();
        let terms = lease_terms(1, 10_000, &empty);
        assert!(lease_matches_action(&terms, &block_egress("10.0.0.1")));
        assert!(!lease_matches_action(
            &terms,
            &ResponseAction::IsolateHost {
                host_id: "h1".to_string(),
            }
        ));
    }

    #[test]
    fn lease_matches_action_honours_a_pinned_scope() {
        let empty: Vec<String> = Vec::new();
        let mut terms = lease_terms(1, 10_000, &empty);
        terms.scope = Some("10.0.0.1");
        assert!(lease_matches_action(&terms, &block_egress("10.0.0.1")));
        assert!(!lease_matches_action(&terms, &block_egress("10.0.0.2")));
    }

    #[test]
    fn action_scope_key_is_the_scope_or_an_unscoped_fallback() {
        assert_eq!(action_scope_key(&block_egress("10.0.0.1")), "10.0.0.1");
        assert_eq!(
            action_scope_key(&ResponseAction::Escalate {
                summary: "n/a".to_string(),
                urgency: Severity::Low,
            }),
            "unscoped:escalate"
        );
    }

    #[test]
    fn lease_can_redeem_denies_an_expired_lease() {
        let empty: Vec<String> = Vec::new();
        let terms = lease_terms(1, 1_000, &empty);
        // Expiry is `<= now_ms`: exactly-at-expiry is already dead.
        assert!(!lease_can_redeem(&terms, &block_egress("10.0.0.1"), 1_000));
        assert!(lease_can_redeem(&terms, &block_egress("10.0.0.1"), 999));
    }

    #[test]
    fn lease_can_redeem_respects_the_blast_radius_cap() {
        let one_scope = vec!["10.0.0.1".to_string()];
        let terms = lease_terms(1, 10_000, &one_scope);
        // A new scope is over the cap of 1...
        assert!(!lease_can_redeem(&terms, &block_egress("10.0.0.2"), 500));
        // ...but the already-redeemed scope may be redeemed again.
        assert!(lease_can_redeem(&terms, &block_egress("10.0.0.1"), 500));
    }

    #[test]
    fn lease_redeem_records_a_new_scope_within_budget() {
        let empty: Vec<String> = Vec::new();
        let terms = lease_terms(2, 10_000, &empty);
        assert_eq!(
            lease_redeem(&terms, &block_egress("10.0.0.1"), 500),
            Ok(LeaseRedeemOutcome::Recorded("10.0.0.1".to_string()))
        );
    }

    #[test]
    fn lease_redeem_is_a_noop_for_an_already_redeemed_scope() {
        let one_scope = vec!["10.0.0.1".to_string()];
        let terms = lease_terms(1, 10_000, &one_scope);
        assert_eq!(
            lease_redeem(&terms, &block_egress("10.0.0.1"), 500),
            Ok(LeaseRedeemOutcome::AlreadyRedeemed)
        );
    }

    #[test]
    fn lease_redeem_fails_closed_on_mismatch_expiry_and_cap() {
        let one_scope = vec!["10.0.0.1".to_string()];
        let terms = lease_terms(1, 10_000, &one_scope);
        assert_eq!(
            lease_redeem(
                &terms,
                &ResponseAction::IsolateHost {
                    host_id: "h1".to_string(),
                },
                500,
            ),
            Err("contingency lease `lease-1` does not cover action `isolate_host`".to_string())
        );
        assert_eq!(
            lease_redeem(&terms, &block_egress("10.0.0.1"), 20_000),
            Err("contingency lease expired".to_string())
        );
        // A different scope with the cap already full fails closed.
        assert_eq!(
            lease_redeem(&terms, &block_egress("10.0.0.2"), 500),
            Err("contingency lease `lease-1` exceeded blast radius cap 1".to_string())
        );
    }

    #[test]
    fn validate_lease_terms_accepts_well_formed_terms_and_rejects_each_defect() {
        assert_eq!(validate_lease_terms(1, 1, 1, 1_000, 100, 1_100), Ok(()));
        assert_eq!(
            validate_lease_terms(2, 1, 1, 1_000, 100, 1_100),
            Err("unsupported contingency lease schema_version `2`".to_string())
        );
        assert_eq!(
            validate_lease_terms(1, 1, 0, 1_000, 100, 1_100),
            Err("contingency lease blast radius cap must be positive".to_string())
        );
        assert_eq!(
            validate_lease_terms(1, 1, 1, 0, 100, 1_100),
            Err("contingency lease duration must be positive".to_string())
        );
        assert_eq!(
            validate_lease_terms(1, 1, 1, 1_000, 1_100, 1_100),
            Err("contingency lease expiry must be after issuance".to_string())
        );
    }

    #[test]
    fn destructive_action_classifies_the_twelve_containment_actions() {
        assert!(destructive_action(&block_egress("10.0.0.1")));
        assert!(destructive_action(&ResponseAction::IsolateHost {
            host_id: "h1".to_string(),
        }));
        // Neither a decoy nor an escalation is destructive.
        assert!(!destructive_action(&ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        }));
        assert!(!destructive_action(&ResponseAction::Escalate {
            summary: "review".to_string(),
            urgency: Severity::High,
        }));
    }

    #[test]
    fn severity_floor_denies_a_low_severity_destructive_action() {
        let decision = severity_floor_denial(&block_egress("10.0.0.1"), Severity::Low)
            .expect("a Low destructive action is denied by the minimum-severity floor");
        assert_eq!(decision.verdict, PolicyVerdict::Deny);
        assert_eq!(decision.rule_name, "static.minimum_severity");
    }

    #[test]
    fn severity_floor_denies_a_low_severity_deploy_decoy() {
        // DeployDecoy is not destructive, so it falls through the first floor
        // to the deploy-decoy-specific one.
        let decoy = ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        };
        let decision = severity_floor_denial(&decoy, Severity::Low)
            .expect("a Low deploy_decoy is denied by its own severity floor");
        assert_eq!(decision.verdict, PolicyVerdict::Deny);
        assert_eq!(decision.rule_name, "static.deploy_decoy_min_severity");
    }

    #[test]
    fn severity_floor_passes_a_medium_destructive_action_through() {
        assert!(severity_floor_denial(&block_egress("10.0.0.1"), Severity::Medium).is_none());
    }

    #[test]
    fn human_gate_holds_a_destructive_action_at_the_boundary() {
        // Exactly at the gate severity -> held for a human.
        let at_gate =
            human_gate_decision(&block_egress("10.0.0.1"), Severity::High, Severity::High)
                .expect("a destructive action exactly at the gate severity is held");
        assert_eq!(at_gate.verdict, PolicyVerdict::RequireHuman);
        assert_eq!(at_gate.rule_name, "static.human_gate");

        // Above the gate severity -> also held.
        let above = human_gate_decision(
            &block_egress("10.0.0.1"),
            Severity::Critical,
            Severity::High,
        )
        .expect("a destructive action above the gate severity is held");
        assert_eq!(above.verdict, PolicyVerdict::RequireHuman);
    }

    #[test]
    fn human_gate_lets_a_destructive_action_just_below_the_boundary_through() {
        // Just below the gate severity -> not held here.
        assert!(
            human_gate_decision(&block_egress("10.0.0.1"), Severity::Medium, Severity::High)
                .is_none()
        );
    }

    #[test]
    fn human_gate_ignores_a_non_destructive_action() {
        // An escalation at or above the gate severity is never held: only
        // destructive actions trip the human gate.
        let escalate = ResponseAction::Escalate {
            summary: "review".to_string(),
            urgency: Severity::Critical,
        };
        assert!(human_gate_decision(&escalate, Severity::Critical, Severity::High).is_none());
    }
}
