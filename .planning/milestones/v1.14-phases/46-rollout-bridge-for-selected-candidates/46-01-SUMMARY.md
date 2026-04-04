---
phase: 46-rollout-bridge-for-selected-candidates
plan: 01
subsystem: evolution-selection
tags:
  - evolution
  - selection
  - rollout
  - cli
one-liner: Added a fail-closed bridge from accepted ranked-candidate selections back into the existing handoff and canary lane.
requires:
  - 45-ranked-candidate-review-decisions
provides:
  - file-backed bridge artifacts under `data/evolution-selection-bridges/`
  - bridge creation from accepted selections through `swarmctl`
  - reuse of existing queue, handoff, and canary safety boundaries
affects: []
tech-stack:
  added: []
  patterns:
    - bridge artifacts fail closed on stale manifests, blocked selections, or missing rollout evidence
key-files:
  modified:
    - crates/swarm-runtime/src/selection.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
    - .gitignore
key-decisions:
  - "Bridge accepted selections by creating a new queue proposal that preserves existing evidence references instead of regenerating evaluation artifacts."
  - "Hash long upstream IDs into shorter deterministic selection and bridge IDs so persisted file paths stay filesystem-safe."
  - "Verify manifest and lineage digests at bridge time so stale selections fail closed before entering handoff."
patterns-established:
  - "Ranked candidate review can now re-enter the rollout ladder through a durable bridge artifact instead of manual evidence translation."
requirements-completed:
  - EVOL-21
  - EVOL-22
duration: 29min
completed: 2026-04-04
---

# Phase 46: Rollout Bridge For Selected Candidates Summary

**Accepted ranked-candidate selections can now create a durable bridge artifact that feeds the existing queue, handoff, and bounded canary path without re-materializing evidence.**

## Accomplishments

- Added ranked-candidate bridge report, record, store, and bridge harness logic to `crates/swarm-runtime/src/selection.rs`.
- Revalidated preserved experiment manifest and lineage digests before minting a queue-ready bridge result.
- Added `swarmctl evolution-selection-bridge` and `evolution-selection-bridge-result`.
- Updated `docs/CONFIGURATION.md` with the ranked-candidate selection and bridge workflow.
- Verified both the blocked fail-closed branch and the successful bridge -> handoff -> canary operator flow.
