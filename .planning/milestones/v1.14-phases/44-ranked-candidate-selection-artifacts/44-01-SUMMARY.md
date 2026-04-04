---
phase: 44-ranked-candidate-selection-artifacts
plan: 01
subsystem: evolution-selection
tags:
  - evolution
  - selection
  - runtime
  - cli
one-liner: Added durable ranked-candidate selection artifacts above shortlist review packets.
requires:
  - 43-candidate-ranking-and-review-packets
provides:
  - file-backed ranked-candidate selections under `data/evolution-selections/`
  - stable selection creation from ranking packets through `swarmctl`
  - preserved ranking, validation, advisory, and parent-queue lineage
affects: []
tech-stack:
  added:
    - serde-backed selection reports and index files
  patterns:
    - selected ranked candidates remain operator-controlled and advisory until explicitly bridged
key-files:
  modified:
    - crates/swarm-runtime/src/selection.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - .gitignore
key-decisions:
  - "Create one durable selection artifact from one ranking packet instead of rewriting queue or rollout state immediately."
  - "Carry validation, proof, advisory, and parent queue lineage directly onto the selection record."
  - "Persist blocked selections for later review rather than treating them as transient command failures."
patterns-established:
  - "Ranked candidate work now moves from advisory packets into durable operator review artifacts."
requirements-completed:
  - EVOL-17
  - EVOL-18
duration: 34min
completed: 2026-04-04
---

# Phase 44: Ranked Candidate Selection Artifacts Summary

**The runtime now persists one ranked-candidate selection artifact from one shortlist review packet without re-materializing the candidate manifest.**

## Accomplishments

- Added ranked-candidate selection report, record, index, and harness types to `crates/swarm-runtime/src/selection.rs`.
- Preserved ranking packet, materialization, validation bundle, proof, advisory, shadow, and parent queue lineage in one durable selection record.
- Added `swarmctl evolution-selection-create` and `evolution-selection-result`.
- Added test coverage for ready and blocked selection creation, including fixture path normalization and deterministic artifact IDs.
