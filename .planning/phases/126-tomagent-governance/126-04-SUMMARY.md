---
phase: 126-tomagent-governance
plan: 04
subsystem: veto-audit
tags: [runtime, audit, receipts, dispatch, governance]
provides:
  - runtime-backed governance-veto routing through the dispatcher seam
  - synthetic failure receipts with governance provenance
  - dispatch integration proof that veto receipts persist without executor calls
affects:
  - operator receipt lookup surfaces
  - phase 126 verification
key-files:
  created:
    - .planning/phases/126-tomagent-governance/126-04-SUMMARY.md
  modified:
    - crates/swarm-response/src/lib.rs
    - crates/swarm-runtime/src/dispatcher.rs
    - crates/swarm-runtime/src/ingest.rs
    - crates/swarm-runtime/src/lib.rs
    - crates/swarm-runtime/tests/dispatch_integration.rs
requirements-completed: [TOM-02]
completed: 2026-04-08
---

# Phase 126 Plan 04 Summary

**Governance vetoes now leave receipt-id-bearing audit artifacts instead of disappearing into dispatcher logs**

## Accomplishments

- Added `GovernanceVetoRoute` and extended the dispatcher router seam so governance vetoes route through the same runtime-backed integration point as autonomous response requests.
- Added a synthetic veto receipt path in `SwarmRuntime` that produces failure-shaped audit artifacts with `governance.veto` policy attribution and typed governance audit metadata.
- Extended `ResponseReceiptAudit` with a dedicated governance section so veto provenance is additive and typed, not buried in adapter-specific details.
- Added dispatch integration coverage proving governance vetoes preserve receipt ids and governance provenance while leaving the response executor untouched.

## Task Commits

No task commit was created for this plan.

## Verification Notes

- `cargo test -p swarm-runtime --test dispatch_integration governance_veto_records_failure_receipt_without_execution -- --exact` passed
- `cargo test -p swarm-runtime --test dispatch_integration` passed

## Deviations From Plan

### External Verification Blocker

- The package-wide `cargo test -p swarm-core -p swarm-policy -p swarm-runtime` sweep is currently red in pre-existing `drafting`, `evolution`, `mutation`, `portfolio`, `replay`, and `selection` fixture paths that were already dirty in the worktree and are outside the Phase 126 write set. Phase-specific runtime and integration coverage stayed green.
