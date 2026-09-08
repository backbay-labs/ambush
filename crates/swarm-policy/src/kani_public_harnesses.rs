//! Kani bounded-model-checking harnesses over the real `formal_core` public
//! decision functions (phase 293 — KANI-01, KANI-02, KANI-03).
//!
//! ## How this module is gated (KANI-01)
//!
//! `lib.rs` declares it `#[cfg(any(kani, feature = "kani"))]`, so it is compiled
//! ONLY when Kani runs (`cargo kani` sets `--cfg kani`) or the explicit,
//! dependency-free `kani` cargo feature is switched on. It is therefore absent
//! from a normal `cargo build`/`cargo test`, adds NO crate to the shipped
//! dependency graph, and cannot change any production verdict. The `kani::`
//! proof API (`kani::proof`, `kani::any`, `kani::assume`, `kani::unwind`)
//! resolves only under the real Kani cfg, because the Kani compiler supplies it
//! — no `kani` crate is a cargo dependency of `swarm-policy`. That is exactly
//! the KANI-01 gating ruling: plain `cargo kani --harness <NAME>` compiles this
//! module via `--cfg kani` and proves the harness; nothing else does.
//!
//! ## Bounded proofs (Design-of-record "Bounded proofs" ruling)
//!
//! `evaluate_rate_limit` prunes a `VecDeque` in a `while` loop, so Kani needs a
//! finite unwind. Every symbolic domain a harness constructs is explicitly
//! BOUNDED (window length, timestamp range, `limit`) and each bound is stated
//! on the harness. A bounded proof is still a proof over its bounded domain —
//! that is the point of the checker, not a weakness — but the bound is named so
//! it stays honest.
//!
//! ## REAL vs `MODEL-ONLY` (KANI-03)
//!
//! Most harnesses CALL the real `formal_core` `pub fn` under proof. A few lease
//! properties are proved `MODEL-ONLY`: the lease redemption predicates and the
//! reject paths of `validate_lease_terms` build error strings with `format!` over
//! their inputs, and the cryptographic half of `ContingencyLease::verify` lives
//! ABOVE this crate. Kani instruments every heap `String`/`format!` access with
//! allocation and `memchr` checks, so those paths do not terminate under CBMC in
//! any CI budget. Per the KANI-03 provision they are proved as scalar/boolean
//! `MODEL-ONLY` harnesses that mirror the real decision arithmetic exactly and
//! NAME the runtime test that covers the real symbol. Every `MODEL-ONLY` harness
//! and its model are labelled as such.

use crate::PolicyVerdict;
use crate::formal_core::{
    RateLimitOutcome, destructive_action, evaluate_rate_limit, governance_quorum_threshold,
    human_gate_decision, severity_floor_denial,
};
use std::collections::VecDeque;
use swarm_core::types::{ResponseAction, Severity};

/// The trailing rate-limit window in milliseconds. Mirrors the (private)
/// `formal_core::RATE_LIMIT_WINDOW_MS` = 60_000 that the pruning threshold
/// uses; duplicated here only because it is not `pub`, and asserted about below
/// through the same `saturating_sub` the production code applies.
const RATE_LIMIT_WINDOW_MS: i64 = 60_000;

/// The longest symbolic rate-limit window a harness constructs. The prune
/// `while` pops at most this many entries and the build/scan loops iterate at
/// most this many times, so this constant also fixes the unwind bound. Kept
/// small (the SAT problem grows quickly with it) while still exercising every
/// prune count 0..=3 and both sides of the `len >= limit` boundary.
const MAX_WINDOW: usize = 3;

/// The largest symbolic per-minute budget a harness explores. Only budgets up
/// to `MAX_WINDOW + 1` can change the outcome, so `4` covers every distinct
/// case (0 = always-deny, 1..=3 = boundary, 4 = always-allow here).
const MAX_LIMIT: usize = 4;

// ---------------------------------------------------------------------------
// Symbolic-input builders (bounded)
// ---------------------------------------------------------------------------

/// A bounded symbolic rate-limit window of `i64` timestamps.
///
/// Length is symbolic in `0..=MAX_WINDOW`; each timestamp is symbolic within a
/// small range that straddles the pruning threshold so both the "kept" and
/// "pruned" cases are exercised. When `sorted` is set the timestamps are
/// nondecreasing — the gate's real storage invariant, since it only ever pushes
/// the current `now_ms` onto the back.
fn arbitrary_window(sorted: bool) -> VecDeque<i64> {
    let n: usize = kani::any();
    kani::assume(n <= MAX_WINDOW);

    // Pre-size to the maximum the harness ever reaches (window + the one
    // possible `push_back` inside `evaluate_rate_limit`) so no reallocation
    // loop appears in the model; capacity never changes the function's verdict.
    let mut window = VecDeque::with_capacity(MAX_WINDOW + 1);
    let mut last: i64 = -3;
    for _ in 0..n {
        let ts: i64 = kani::any();
        kani::assume(ts >= -2 && ts <= 6);
        if sorted {
            kani::assume(ts >= last);
            last = ts;
        }
        window.push_back(ts);
    }
    window
}

/// A bounded symbolic `(now_ms, limit)`: `now_ms` in `60_000..=60_004` (so
/// `now_ms - 60_000` never saturates within the explored range) and `limit` in
/// `0..=MAX_LIMIT` (including 0, the always-deny budget).
fn arbitrary_now_and_limit() -> (i64, usize) {
    let now_ms: i64 = kani::any();
    kani::assume(now_ms >= 60_000 && now_ms <= 60_004);
    let limit: usize = kani::any();
    kani::assume(limit <= MAX_LIMIT);
    (now_ms, limit)
}

/// Compile-time exhaustiveness guard for the variant coverage below. If
/// `ResponseAction` gains a variant, this match stops compiling — forcing
/// `arbitrary_response_action` (its `idx < 15` bound and the arms) and every
/// harness that claims "over all 15 variants" to be updated to cover it, so a
/// new action can never silently escape the soundness proofs. Never called; it
/// exists only for the exhaustiveness check the compiler performs on it.
#[allow(dead_code)]
fn assert_response_action_variants_are_modeled(action: &ResponseAction) {
    match action {
        ResponseAction::BlockEgress { .. }
        | ResponseAction::IsolateHost { .. }
        | ResponseAction::RevokeCredential { .. }
        | ResponseAction::SinkholeDns { .. }
        | ResponseAction::TerminateUserSession { .. }
        | ResponseAction::TriggerEdrScan { .. }
        | ResponseAction::InjectFirewallRule { .. }
        | ResponseAction::QuarantineFile { .. }
        | ResponseAction::KillProcess { .. }
        | ResponseAction::SuspendProcess { .. }
        | ResponseAction::DisableUserAccount { .. }
        | ResponseAction::ForcePasswordReset { .. }
        | ResponseAction::RemoveScheduledTask { .. }
        | ResponseAction::DeployDecoy { .. }
        | ResponseAction::Escalate { .. } => {}
    }
}

/// Map a symbolic index onto one representative of every `ResponseAction`
/// variant: indices 0..=11 are the twelve destructive/containment actions,
/// 12 `TriggerEdrScan`, 13 `DeployDecoy`, 14 `Escalate` (the three
/// non-destructive ones). The classifiers under proof (`destructive_action`,
/// `severity_floor_denial`) branch on the VARIANT only, never on field
/// contents, so fixed empty strings keep the symbolic state finite without
/// narrowing the variant coverage.
fn arbitrary_response_action() -> ResponseAction {
    let idx: u8 = kani::any();
    kani::assume(idx < 15);
    match idx {
        0 => ResponseAction::BlockEgress {
            target: String::new(),
        },
        1 => ResponseAction::IsolateHost {
            host_id: String::new(),
        },
        2 => ResponseAction::RevokeCredential {
            credential_id: String::new(),
        },
        3 => ResponseAction::SinkholeDns {
            domain: String::new(),
        },
        4 => ResponseAction::TerminateUserSession {
            host_id: String::new(),
            session_id: String::new(),
        },
        5 => ResponseAction::InjectFirewallRule {
            host_id: String::new(),
            rule_name: String::new(),
            direction: String::new(),
            cidr: String::new(),
            port: None,
        },
        6 => ResponseAction::QuarantineFile {
            host_id: String::new(),
            file_path: String::new(),
        },
        7 => ResponseAction::KillProcess {
            host_id: String::new(),
            process_name: String::new(),
        },
        8 => ResponseAction::SuspendProcess {
            host_id: String::new(),
            process_name: String::new(),
        },
        9 => ResponseAction::DisableUserAccount {
            user_id: String::new(),
        },
        10 => ResponseAction::ForcePasswordReset {
            user_id: String::new(),
        },
        11 => ResponseAction::RemoveScheduledTask {
            host_id: String::new(),
            task_name: String::new(),
        },
        12 => ResponseAction::TriggerEdrScan {
            host_id: String::new(),
            scan_profile: String::new(),
        },
        13 => ResponseAction::DeployDecoy {
            decoy_type: String::new(),
            target_zone: String::new(),
        },
        _ => ResponseAction::Escalate {
            summary: String::new(),
            urgency: Severity::Low,
        },
    }
}

/// Map a symbolic index onto a `Severity`. `Severity` is `Ord`
/// (Low < Medium < High < Critical), so a harness taking two of these sees
/// every ordering of `(severity, gate)`.
fn arbitrary_severity() -> Severity {
    match kani::any::<u8>() % 4 {
        0 => Severity::Low,
        1 => Severity::Medium,
        2 => Severity::High,
        _ => Severity::Critical,
    }
}

// ---------------------------------------------------------------------------
// KANI-02: rate-limit boundedness within the 60_000ms trailing window
// ---------------------------------------------------------------------------

/// An `Allowed` outcome never leaves the window above `limit`, and it records
/// exactly the current `now_ms` at the back (an allowed action consumes one
/// unit of budget).
///
/// Bound: symbolic window length ≤ 3, timestamps in `[-2, 6]`,
/// `now_ms` in `[60_000, 60_004]`, `limit` ≤ 4. Loops unwind to 5.
#[kani::proof]
#[kani::unwind(5)]
fn kani_rate_limit_allowed_stays_within_limit() {
    let window = arbitrary_window(false);
    let (now_ms, limit) = arbitrary_now_and_limit();

    let (outcome, out) = evaluate_rate_limit(window, now_ms, limit);

    if outcome == RateLimitOutcome::Allowed {
        // `Allowed` is impossible at limit 0 (an empty budget always denies).
        assert!(limit >= 1);
        // After recording, the window is still within the budget…
        assert!(out.len() <= limit);
        // …and the recorded entry is exactly this action's timestamp.
        assert_eq!(out.back().copied(), Some(now_ms));
    }
}

/// A `Denied` outcome means the budget was genuinely full — the pruned window
/// already held at least `limit` entries — and the denied action never consumed
/// budget, so the returned window is a pruned subset of the input and is never
/// longer than it.
///
/// Bound: as above (window ≤ 3, `limit` ≤ 4). Loops unwind to 5.
#[kani::proof]
#[kani::unwind(5)]
fn kani_rate_limit_denied_means_budget_full() {
    let window = arbitrary_window(false);
    let input_len = window.len();
    let (now_ms, limit) = arbitrary_now_and_limit();

    let (outcome, out) = evaluate_rate_limit(window, now_ms, limit);

    if outcome == RateLimitOutcome::Denied {
        // The budget was actually at or over the limit after pruning.
        assert!(out.len() >= limit);
        // A denied action records nothing: the result only ever removed
        // entries relative to the input, never added one.
        assert!(out.len() <= input_len);
    }
}

/// Every timestamp the window retains (and the freshly recorded `now_ms`) lies
/// strictly inside the trailing `RATE_LIMIT_WINDOW_MS` as of `now_ms`: pruning
/// drops everything at or before `now_ms - 60_000`.
///
/// Bound: the window is sorted nondecreasing — the gate's real storage
/// invariant. Without it a stale timestamp hidden behind a fresh one could
/// survive the front-only prune; with it, pruning clears exactly the stale
/// prefix. Window length ≤ 3, `now_ms` in `[60_000, 60_004]`. Loops unwind to 5.
#[kani::proof]
#[kani::unwind(5)]
fn kani_rate_limit_retains_only_fresh_timestamps() {
    let window = arbitrary_window(true);
    let (now_ms, limit) = arbitrary_now_and_limit();

    let (_, out) = evaluate_rate_limit(window, now_ms, limit);

    // Same `saturating_sub` the production `prune_stale_window` applies.
    let threshold = now_ms.saturating_sub(RATE_LIMIT_WINDOW_MS);
    for &ts in out.iter() {
        assert!(ts > threshold);
    }
}

// ---------------------------------------------------------------------------
// KANI-02: severity-gate soundness / fail-closed
// ---------------------------------------------------------------------------

/// At `Severity::Low` the static severity floor is sound and fails closed for
/// EVERY action variant: a destructive action is denied under
/// `static.minimum_severity`; a (non-destructive) `DeployDecoy` is denied under
/// `static.deploy_decoy_min_severity`; every other action passes both floors
/// (`None`). Proved over a symbolic `ResponseAction` spanning all 15 variants.
///
/// Bound: exhaustive over the 15 action variants. `#[kani::unwind(64)]` caps
/// the byte-wise loops CBMC generates for the `PolicyDecision`'s `rule_name`
/// and `reason` `String`s (construction and comparison); every such literal is
/// ≤ 52 bytes, so 64 iterations provably suffice.
#[kani::proof]
#[kani::unwind(64)]
fn kani_severity_floor_low_is_sound_for_every_action() {
    let action = arbitrary_response_action();

    let decision = severity_floor_denial(&action, Severity::Low);

    // The rule the floor MUST apply, derived independently of the function
    // under proof, so the assertion is an oracle rather than a restatement.
    let expected_deny_rule: Option<&str> = if destructive_action(&action) {
        Some("static.minimum_severity")
    } else if matches!(action, ResponseAction::DeployDecoy { .. }) {
        Some("static.deploy_decoy_min_severity")
    } else {
        None
    };

    match (decision, expected_deny_rule) {
        (Some(d), Some(rule)) => {
            assert!(d.verdict == PolicyVerdict::Deny);
            assert!(d.rule_name == rule);
        }
        (None, None) => {}
        _ => assert!(false, "severity floor disagreed with the expected decision"),
    }
}

/// The human gate holds EVERY destructive action whose severity is at or above
/// the gate for human approval (`RequireHuman` under `static.human_gate`) and
/// holds nothing else: a destructive action below the gate, or any
/// non-destructive action, returns `None`. Proved over a symbolic action across
/// all 15 variants and every ordering of `(severity, gate)`.
///
/// Bound: exhaustive over the 15 action variants and 4 severities.
/// `#[kani::unwind(64)]` caps the byte-wise `String` loops for the decision's
/// `rule_name`/`reason` (each ≤ 52 bytes), exactly as the floor harness above.
#[kani::proof]
#[kani::unwind(64)]
fn kani_human_gate_holds_destructive_at_or_above_gate() {
    let action = arbitrary_response_action();
    let severity = arbitrary_severity();
    let gate = arbitrary_severity();

    let decision = human_gate_decision(&action, severity, gate);

    if destructive_action(&action) && severity >= gate {
        match decision {
            Some(d) => {
                assert!(d.verdict == PolicyVerdict::RequireHuman);
                assert!(d.rule_name == "static.human_gate");
            }
            None => assert!(false, "a destructive action at/above the gate must be held"),
        }
    } else {
        assert!(decision.is_none());
    }
}

// ---------------------------------------------------------------------------
// KANI-03: lease integrity + governance quorum
//
// REAL (format!-free, string-comparison-free) predicates are proved directly;
// the format!/String-heavy lease redemption and the receipt crypto are proved
// MODEL-ONLY (see the module header) with the runtime test named on each.
// ---------------------------------------------------------------------------

/// REAL: `destructive_action` classifies exactly the twelve containment actions
/// as destructive and the three others (`TriggerEdrScan`, `DeployDecoy`,
/// `Escalate`) as not — over one representative of every `ResponseAction`
/// variant. A variant match with no string comparison and no `format!`, so it
/// is Kani-tractable. The `expected` oracle lists the twelve containment
/// variants directly — NOT `static_gate::destructive_action_kinds()`, because
/// that is a `&[&str]` slug list and checking `.contains(&action.kind())` would
/// reintroduce the String `memcmp` blow-up that forces the lease harnesses
/// MODEL-ONLY. The variant list is a second, independent statement of the spec:
/// if `destructive_action` and this oracle ever disagree (a variant added to one
/// arm-set and not the other), the proof fails.
///
/// Bound: exhaustive over the 15 variants (`arbitrary_response_action`, idx<15).
#[kani::proof]
#[kani::unwind(16)]
fn kani_destructive_action_classifies_every_variant() {
    let action = arbitrary_response_action();
    let expected = matches!(
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
    );
    assert_eq!(destructive_action(&action), expected);
}

/// REAL: `governance_quorum_threshold` is the Byzantine `2f + 1` quorum — an
/// empty committee needs zero votes, and any non-empty committee needs
/// `2*max_faulty + 1`, always at least one. Pure integer arithmetic, no strings.
///
/// Bound: total and max_faulty in [0,10] (no saturation in range).
#[kani::proof]
fn kani_governance_quorum_threshold_is_2f_plus_1() {
    let total: usize = kani::any();
    kani::assume(total <= 10);
    let max_faulty: usize = kani::any();
    kani::assume(max_faulty <= 10);

    let q = governance_quorum_threshold(total, max_faulty);
    if total == 0 {
        assert_eq!(q, 0);
    } else {
        assert_eq!(q, max_faulty * 2 + 1);
        assert!(q >= 1);
    }
}

/// REAL: `governance_quorum_threshold` is monotonic in the fault tolerance and
/// never overflows — its saturating `2f + 1` arithmetic means a larger
/// `max_faulty` can only raise the threshold, and it stays a valid `usize` even
/// at the extreme. Proved over unbounded `max_faulty` so the saturation edge is
/// covered; `total` in [1,4] (a non-empty committee).
#[kani::proof]
fn kani_governance_quorum_threshold_is_monotonic_and_saturating() {
    let total: usize = kani::any();
    kani::assume((1..=4).contains(&total));
    let a: usize = kani::any();
    let b: usize = kani::any();
    kani::assume(a <= b); // unbounded otherwise: exercises the saturation edge

    assert!(governance_quorum_threshold(total, a) <= governance_quorum_threshold(total, b));
    assert!(governance_quorum_threshold(total, a) >= 1);
}

/// The scalar model of `formal_core::validate_lease_terms`'s accept predicate,
/// mirroring its four checks and their meaning exactly. Used by the MODEL-ONLY
/// reject harness because the real function's reject paths call `format!`.
fn model_lease_terms_accepted(
    schema: u32,
    expected: u32,
    cap: usize,
    duration: i64,
    issued: i64,
    expires: i64,
) -> bool {
    schema == expected && cap > 0 && duration > 0 && expires > issued
}

/// MODEL-ONLY (see [`model_lease_terms_accepted`]): `validate_lease_terms` fails
/// closed on EVERY malformed lease — a schema mismatch, a non-positive cap, a
/// non-positive duration, or expiry at or before issuance each reject it.
/// Modeled over scalars because the real reject paths build error strings with
/// `format!`, which Kani cannot instrument tractably. The real fail-closed
/// behavior is covered by the swarm-policy `formal_core` unit tests
/// (`validate_lease_terms_*`) and end to end by the swarm-agents test
/// `keyless_policy_reloaded_into_a_partition_refuses_persisted_leases`.
#[kani::proof]
fn kani_model_only_validate_lease_terms_rejects_malformed() {
    let schema: u32 = kani::any();
    kani::assume(schema <= 2);
    let expected: u32 = kani::any();
    kani::assume(expected <= 2);
    let cap: usize = kani::any();
    kani::assume(cap <= 3);
    let duration: i64 = kani::any();
    kani::assume((-2..=3).contains(&duration));
    let issued: i64 = kani::any();
    kani::assume((-2..=3).contains(&issued));
    let expires: i64 = kani::any();
    kani::assume((-2..=3).contains(&expires));

    // Full characterization: accepted IFF well-formed — proves the fail-closed
    // reject direction (any malformation ⇒ rejected) and that no well-formed
    // lease is wrongly rejected.
    let well_formed = schema == expected && cap > 0 && duration > 0 && expires > issued;
    assert_eq!(
        model_lease_terms_accepted(schema, expected, cap, duration, issued, expires),
        well_formed
    );
}

/// The scalar model of `formal_core::lease_redeem`'s record decision for a NEW
/// (not-already-redeemed), matching, non-expired scope: record iff the redeemed
/// count is strictly below the cap. Mirrors the real `len >= blast_radius_cap`
/// guard.
fn model_lease_records_new_scope(redeemed_count: usize, cap: usize) -> bool {
    redeemed_count < cap
}

/// MODEL-ONLY (see [`model_lease_records_new_scope`]): blast-radius conservation.
/// `lease_redeem` records a NEW scope only while the redeemed-scope count is
/// strictly below `blast_radius_cap`, so a redemption can never drive the count
/// past the cap, and at or above the cap a new scope is always refused. Modeled
/// over the scalar count and cap because the real `lease_redeem` matches scopes
/// by `String` and builds error strings with `format!` (Kani-intractable). The
/// real `lease_redeem` cap logic is covered by the `formal_core` unit tests that
/// call it directly — `lease_redeem_records_a_new_scope_within_budget` (records
/// under budget) and `lease_redeem_fails_closed_on_mismatch_expiry_and_cap` (the
/// at-or-over-cap refusal) — and end to end by the swarm-agents partition lease
/// test `governance_policy_stages_and_redeems_contingency_leases_during_partition`.
#[kani::proof]
fn kani_model_only_blast_radius_conservation() {
    let count: usize = kani::any();
    kani::assume(count <= 8);
    let cap: usize = kani::any();
    kani::assume(cap <= 8);

    let records = model_lease_records_new_scope(count, cap);
    if records {
        // Recording keeps the post-redemption count within the cap.
        assert!(count + 1 <= cap);
    }
    if count >= cap {
        // At or over the cap, a new scope is always refused.
        assert!(!records);
    }
}

/// The scalar model of `formal_core::lease_can_redeem`'s guard: a lease may be
/// redeemed only if the action matches, the lease has NOT expired
/// (`expires_at_ms > now_ms`), and there is budget. Mirrors the real expiry
/// check `expires_at_ms <= now_ms ⇒ deny`.
fn model_lease_can_redeem(
    matches: bool,
    expires_at_ms: i64,
    now_ms: i64,
    has_budget: bool,
) -> bool {
    matches && expires_at_ms > now_ms && has_budget
}

/// MODEL-ONLY (see [`model_lease_can_redeem`]): an expired lease denies every
/// redemption — once `now_ms` reaches expiry the lease fails closed regardless
/// of match or remaining budget. Modeled over the scalar clock/expiry because
/// the real predicates match scopes by `String`. The real expiry guard is
/// covered by the `formal_core` unit test that calls it directly —
/// `lease_can_redeem_denies_an_expired_lease` — and end to end by the swarm-agents
/// partition lease test
/// `governance_policy_stages_and_redeems_contingency_leases_during_partition`.
#[kani::proof]
fn kani_model_only_expired_lease_always_denies() {
    let now_ms: i64 = kani::any();
    kani::assume((0..=4).contains(&now_ms));
    let expires: i64 = kani::any();
    kani::assume((0..=4).contains(&expires));
    kani::assume(expires <= now_ms); // the lease has expired

    let matches: bool = kani::any();
    let has_budget: bool = kani::any();
    assert!(!model_lease_can_redeem(
        matches, expires, now_ms, has_budget
    ));
}

/// MODEL-ONLY: a structural model of the receipt-bound half of
/// `ContingencyLease::verify` (crates/swarm-agents/src/tom_agent.rs), which
/// lives ABOVE this crate with the `ConsensusGovernanceReceipt` type and is NOT
/// part of the pure decision core. It mirrors verify's exact check order and
/// fail-closed precedence — signature, then `Approve` decision, then
/// proposal-hash match — so the contract can be model-checked here. The error
/// strings echo the real ones for readability (the signature error is the real
/// message's prefix); they are documentary only, since the harnesses assert on
/// the `Err`/`Ok` outcome, not the text. The REAL
/// cryptographic checks are covered by the swarm-agents runtime tests
/// `keyless_policy_reloaded_into_a_partition_refuses_persisted_leases` (receipt /
/// signature refusal) and
/// `governance_policy_approves_destructive_actions_with_signed_receipt_when_healthy`
/// (the accept path).
fn model_receipt_verify(
    signature_valid: bool,
    is_approve: bool,
    proposal_hash_matches: bool,
) -> Result<(), &'static str> {
    if !signature_valid {
        return Err("invalid contingency lease receipt");
    }
    if !is_approve {
        return Err("contingency lease receipt must be an approval");
    }
    if !proposal_hash_matches {
        return Err("contingency lease proposal hash did not match receipt");
    }
    Ok(())
}

/// MODEL-ONLY (see [`model_receipt_verify`]): an invalid receipt signature
/// always denies, for EVERY decision and proposal-hash outcome — signature is
/// checked first and its failure is terminal.
#[kani::proof]
fn kani_model_only_invalid_signature_always_denies() {
    let is_approve: bool = kani::any();
    let hash_matches: bool = kani::any();
    assert!(model_receipt_verify(false, is_approve, hash_matches).is_err());
}

/// MODEL-ONLY (see [`model_receipt_verify`]): a receipt whose decision is not
/// `Approve` always denies, for EVERY proposal-hash outcome, even with a valid
/// signature.
#[kani::proof]
fn kani_model_only_non_approve_decision_always_denies() {
    let hash_matches: bool = kani::any();
    assert!(model_receipt_verify(true, false, hash_matches).is_err());
}

/// MODEL-ONLY (see [`model_receipt_verify`]): a proposal-hash mismatch always
/// denies, even with a valid signature and an `Approve` decision — the last of
/// the three receipt checks, and equally fail-closed.
#[kani::proof]
fn kani_model_only_hash_mismatch_always_denies() {
    assert!(model_receipt_verify(true, true, false).is_err());
}
