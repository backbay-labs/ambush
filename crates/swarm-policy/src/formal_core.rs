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
//! [`PolicyDecision`]: crate::PolicyDecision

use std::collections::VecDeque;

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{RateLimitOutcome, evaluate_rate_limit};
    use std::collections::VecDeque;

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
}
