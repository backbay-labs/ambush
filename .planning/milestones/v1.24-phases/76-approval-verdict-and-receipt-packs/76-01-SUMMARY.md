---
phase: 76-approval-verdict-and-receipt-packs
plan: 01
subsystem: runtime
tags: [approval-verdict, receipt-pack, governance, swarmctl]
requirements-completed: [GOV-05, GOV-06]
one-liner: "Deterministic approval verdicts and signed portable receipt packs now extend the approval ledger lane through the runtime harness and swarmctl."
completed: 2026-04-05
---

# Phase 76: Approval Verdict And Receipt Packs Summary

**Deterministic approval verdicts and signed portable receipt packs now extend the approval ledger lane through the runtime harness and `swarmctl`.**

## Accomplishments

- Extended the approval module with deterministic verdict evaluation that counts approve and reject entries against `AtLeast`, `Majority`, and `Unanimous` threshold rules without depending on local clock or store state.
- Added portable approval receipt-pack artifacts that bundle the approval set, approval ledger, verdict, audit references, content hash, and detached Ed25519 signature for later independent verification.
- Added file-backed verdict and receipt-pack stores plus harness methods for verdict creation, verdict listing, receipt-pack export, receipt-pack loading, and receipt-pack verification.
- Wired new `swarmctl` commands for verdict create/read/list and receipt-pack export/read/list/verify using the same approval harness.
- Added deterministic and tamper-detection tests covering verdict stability, threshold outcomes, store round-trips, receipt-pack signing, and receipt-pack verification failure on content mutation.

## Files Created Or Modified

- `crates/swarm-runtime/src/approval.rs` - added verdict types, receipt-pack types, pure evaluation logic, stores, harness methods, render helpers, and tests.
- `crates/swarm-runtime/src/bin/swarmctl.rs` - added verdict and receipt-pack commands and approval artifact path configuration.

## Key Decisions

- Verdict generation stays pure and deterministic so the same approval-set and ledger state always yields the same verdict report.
- Receipt packs are signed over canonical JSON of the bundled content instead of a store-local wrapper so verification works without access to the local runtime directories.
- The approval harness keeps verdict and receipt-pack stores optional so the lighter Phase 75 HTTP wiring can still construct a reduced harness without backfilling new directories.

## Verification

- `cargo fmt --all -- --check`
- `cargo build --workspace --all-targets`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo test -p swarm-runtime --lib approval -- --nocapture`

## Notes

- No new HTTP endpoints were required in this phase; the scope stayed on deterministic artifact creation, persistence, and CLI access.
- Receipt-pack verification is fail-closed on both content-hash drift and detached-signature mismatch.

