---
phase: 77-human-gate-and-promotion-integration
plan: 01
subsystem: runtime
tags: [promotion, human-gate, severity, governance]
requirements-completed: [GOV-07]
one-liner: "Critical-severity promotions now enter an explicit human-approval-pending state with persisted review context and approval metadata slots."
completed: 2026-04-05
---

# Phase 77 Plan 01: Human Gate And Promotion Integration Summary

**Critical-severity promotions now enter an explicit human-approval-pending state with persisted review context and approval metadata slots.**

## Accomplishments

- Added `HumanApprovalPending` promotion status and `PendingHumanApproval` recommendation to the production-promotion model.
- Extended promotion reports with pending-review packets, approval-vote references, optional consensus receipts, persisted approval severity, and persisted quorum-gate configuration.
- Added severity-aware promotion start logic so critical findings route into the human gate while non-critical promotions continue through the existing active observation path.
- Kept fail-closed semantics for pending promotions: event ingestion is blocked until explicit approval, but operators can still halt or roll back a pending promotion.
- Added promotion tests covering critical gating, non-critical pass-through, pending-state persistence, approval transition behavior, and halt/rollback behavior for pending promotions.

## Files Created Or Modified

- `crates/swarm-runtime/src/promotion.rs` - added the pending state, review packet, approval metadata fields, severity gate logic, render updates, and tests.
- `crates/swarm-runtime/src/evidence.rs` - updated promotion report fixtures for the expanded promotion report schema.
- `crates/swarm-runtime/src/strategy.rs` - updated promotion report fixtures for the expanded promotion report schema.

## Key Decisions

- Human gating is triggered from severity on the existing promotion artifact instead of creating a second promotion pipeline.
- Pending promotions keep the existing durable artifact shape and render path, which lets existing CLI and operator read surfaces show the new fields without a parallel storage model.
- Approval metadata fields ship before real multi-node trust boundaries so later governance work can activate the gate without redesigning the promotion report schema again.

## Verification

- `cargo fmt --all -- --check`
- `cargo build --workspace --all-targets`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo test -p swarm-runtime --lib promotion::tests -- --nocapture`

