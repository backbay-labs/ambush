---
phase: 75-approval-set-definition-and-signed-ledgers
plan: 01
subsystem: runtime
tags: [approval-ledger, governance, swarmctl, operator-http]
requirements-completed: [GOV-03, GOV-04]
one-liner: "Approval sets, signed approval ledgers, swarmctl approval commands, and operator HTTP approval routes now exist as durable local governance artifacts."
completed: 2026-04-05
---

# Phase 75: Approval Set Definition And Signed Ledgers Summary

**Approval sets, signed approval ledgers, swarmctl approval commands, and operator HTTP approval routes now exist as durable local governance artifacts.**

## Accomplishments

- Added a new `approval` runtime module with durable approval-set and approval-ledger reports, file-backed stores, stable IDs, quorum-state computation, and a harness that auto-creates a ledger for each approval set.
- Implemented signed vote append flow using canonical JSON payloads, Ed25519 detached signatures, and signed spine envelopes so each ledger entry preserves voter identity, signature metadata, timestamp, and lineage hash.
- Wired approval workflows into both `swarmctl` and the authenticated operator HTTP surface for approval-set creation, approval-set lookup, approval-ledger lookup, approval-ledger listing, and vote append.
- Added focused unit and persistence tests covering threshold rules, quorum-state math, valid vote append, duplicate-voter rejection, ineligible-voter rejection, invalid-signature rejection, and harness round-trips.

## Files Created Or Modified

- `crates/swarm-runtime/src/approval.rs` - added the approval-set and ledger domain model, stores, harness, render helpers, and tests.
- `crates/swarm-runtime/src/lib.rs` - exported the new approval module.
- `crates/swarm-runtime/src/bin/swarmctl.rs` - added approval-set and approval-ledger commands plus CLI path configuration.
- `crates/swarm-runtime/src/operator_http.rs` - added approval-set and approval-ledger operator routes plus approval store wiring.

## Key Decisions

- Approval sets automatically create their companion ledger so later CLI and HTTP flows can stay keyed by the stable approval-set ID.
- Threshold handling was generalized from a fixed count into `AtLeast`, `Majority`, and `Unanimous` so the same core type can support later verdict work without a second model rewrite.
- Vote entries are signed twice in different layers on purpose: detached signatures prove the vote payload, and spine envelopes preserve append-only lineage.

## Verification

- `cargo fmt --all -- --check`
- `cargo build --workspace --all-targets`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo test -p swarm-runtime --lib approval -- --nocapture`

## Notes

- No atomic task commits were created in this autonomous run; the phase remains represented by the workspace changes and the summary plus verification artifacts.
- Operator HTTP coverage for approval artifacts was implemented directly in the existing authenticated surface instead of introducing a second approval-specific service.

