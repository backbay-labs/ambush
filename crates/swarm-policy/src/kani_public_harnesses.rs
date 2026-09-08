//! Kani bounded-model-checking harnesses over the real `formal_core` public
//! decision functions (phase 293 — KANI-01, KANI-02).
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
//! Every harness here CALLS the real `formal_core` `pub fn` under proof; there
//! are no `MODEL-ONLY` harnesses in this task.

use crate::PolicyVerdict;
use crate::formal_core::{
    RateLimitOutcome, destructive_action, evaluate_rate_limit, human_gate_decision,
    severity_floor_denial,
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
