---
phase: 40-queue-reconciliation-and-handoff-readiness
plan: 01
subsystem: evolution-drafting
tags:
  - evolution
  - queue
  - runtime
  - cli
one-liner: Added in-place queue reconciliation so refreshed draft evidence can reuse the existing handoff lane.
requires:
  - 39-validation-bundle-refresh
provides:
  - file-backed reconciliation storage rooted under `data/evolution-reconciliations/`
  - in-place queue proposal reconciliation keyed by the original draft-promotion artifact
  - stable-ID reload through `swarmctl evolution-queue-reconciliation-result`
affects:
  - evolution queue readiness
  - handoff continuity
tech-stack:
  added:
    - reconciliation reports and index files
  patterns:
    - reconciliation updates existing reviewed queue state instead of cloning proposal history
    - handoff readiness remains separate from explicit `accept-for-canary` review
key-files:
  modified:
    - crates/swarm-runtime/src/drafting.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Reconcile the original queue proposal in place so rollout identity stays unambiguous."
  - "Preserve deferred review state when evidence is refreshed successfully; otherwise mark the proposal blocked."
  - "Expose handoff readiness as durable reconciliation output rather than launching rollout automatically."
patterns-established:
  - "Reviewed draft proposals can now rejoin the verified rollout ladder without duplicating queue state."
requirements-completed:
  - RECN-01
  - RECN-02
duration: 28min
completed: 2026-04-03
---

# Phase 40: Queue Reconciliation And Handoff Readiness Summary

**The runtime now reconciles refreshed draft evidence back into the original reviewed queue proposal and marks when the existing handoff path is ready after operator acceptance.**

## Accomplishments

- Added `EvolutionQueueReconciliationReport`, `EvolutionQueueReconciliationRecord`, and `FileEvolutionQueueReconciliationStore`.
- Implemented `DefaultEvolutionDraftingHarness::reconcile_queue_proposal`.
- Added `swarmctl evolution-queue-reconcile` and `evolution-queue-reconciliation-result`.
- Verified that a reconciled and accepted proposal can feed the existing handoff path without duplicate proposal state.
