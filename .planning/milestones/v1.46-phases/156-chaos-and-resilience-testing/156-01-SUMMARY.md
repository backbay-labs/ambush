# Phase 156 Plan 01 Summary

## Delivered

- Extended `crates/swarm-consensus/src/lib.rs` with a deterministic Byzantine regression that injects both invalid signatures and equivocation into the consensus message path and proves the validator emits signed exclusion receipts without producing an unauthorized commit.
- Kept the timeout and sequential-commit proof live in the same consensus crate so Phase 156 closes on both safety and recovery: malicious envelopes are rejected, and round timeout still advances to the next proposer on the nominal protocol path.
- Added an expired-lease routing regression in `crates/swarm-runtime/tests/dispatch_integration.rs` that stages a real contingency lease, lets it expire, and proves the dispatcher blocks destructive execution before the runtime gate or executor can run.
- Added `crates/swarm-runtime/tests/governance_resilience_integration.rs` to prove partition recovery and restart semantics: one authorized partition-era action and one unauthorized one reconcile into a durable report, and the healed governance state reloads from persistence with the reconciliation marker intact.

## Notes

- Phase 156 was verification-heavy rather than feature-heavy. The runtime surface from Phases 153 through 155 stayed intact; the main new work is deterministic chaos coverage that pins the intended safety behavior.
- The only debug correction during this phase was in the new persistence test: unauthorized partition actions are expected to move out of the live pending counter once reconciliation completes, because they are preserved in the reconciliation report instead of remaining pending activity.
