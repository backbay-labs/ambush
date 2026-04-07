---
phase: 77-human-gate-and-promotion-integration
plan: 02
subsystem: runtime
tags: [promotion, quorum, signatures, swarmctl]
requirements-completed: [GOV-01, GOV-02]
one-liner: "Pending promotions now require structurally validated approval votes, optional signed consensus receipts, and explicit swarmctl approval commands before activation."
completed: 2026-04-05
---

# Phase 77 Plan 02: Quorum Gate Validation And CLI Summary

**Pending promotions now require structurally validated approval votes, optional signed consensus receipts, and explicit `swarmctl` approval commands before activation.**

## Accomplishments

- Added structural quorum-gate validation to the promotion path, including threshold checks, required-voter checks, persisted gate configuration, and explicit `QuorumNotMet` failure reporting.
- Added vote-signature and consensus-receipt-signature verification helpers so pending-promotion approval fails closed on invalid signed artifacts.
- Extended `approve_pending_run` to enforce pending-state checks, quorum validation, vote verification, optional receipt verification, and durable persistence of approval votes plus consensus receipts.
- Added `swarmctl promotion approve` and `swarmctl promotion pending` commands so operators can sign local approval votes and inspect pending promotions directly from the CLI.
- Added focused promotion tests covering quorum enforcement, vote-signature verification, receipt-signature verification, persisted approval metadata, and persisted quorum-gate configuration.

## Files Created Or Modified

- `crates/swarm-runtime/src/promotion.rs` - added quorum validation, signature verification, approval transition checks, render updates, and tests.
- `crates/swarm-runtime/src/bin/swarmctl.rs` - added promotion approval and pending-promotion commands plus signing payload construction.

## Key Decisions

- Quorum configuration is persisted on the promotion report even though the current default is advisory-only; that preserves audit meaning at approval time and keeps future activation additive.
- CLI approval signs a canonical vote payload locally using the existing Ed25519 signer instead of inventing a promotion-only signature path.
- Consensus receipts are optional at approval time so the human gate can still operate locally while receipt-pack workflows mature separately.

## Verification

- `cargo fmt --all -- --check`
- `cargo build --workspace --all-targets`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo test -p swarm-runtime --lib promotion::tests -- --nocapture`

