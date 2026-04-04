---
phase: 45-ranked-candidate-review-decisions
plan: 01
subsystem: evolution-selection
tags:
  - evolution
  - selection
  - review
  - cli
one-liner: Added durable review decisions and stable-ID listing for ranked-candidate selections.
requires:
  - 44-ranked-candidate-selection-artifacts
provides:
  - selection listing and stable-ID inspection through `swarmctl`
  - accepted, deferred, and rejected review decisions with operator reasons
  - immutable selection evidence with append-only decision history
affects: []
tech-stack:
  added: []
  patterns:
    - review state remains explicit and operator-authored before rollout bridging
key-files:
  modified:
    - crates/swarm-runtime/src/selection.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
key-decisions:
  - "Reuse the existing evolution review-state model instead of inventing a second state machine for ranked selections."
  - "Keep selection evidence immutable and append review decisions as durable history."
  - "Allow selection filtering by strategy and review state through the CLI."
patterns-established:
  - "Ranked candidate review now mirrors earlier queue review while remaining separate from queue mutation."
requirements-completed:
  - EVOL-19
  - EVOL-20
duration: 18min
completed: 2026-04-04
---

# Phase 45: Ranked Candidate Review Decisions Summary

**Operators can now inspect ranked-candidate selections by stable ID, list them by review state, and record explicit review decisions without rewriting the underlying ranking evidence.**

## Accomplishments

- Added selection listing, review-state filtering, and decision-history persistence to `crates/swarm-runtime/src/selection.rs`.
- Reused the existing evolution review-state and decision-action model for selection review.
- Added `swarmctl evolution-selection-list` and `evolution-selection-decision`.
- Verified accepted review transitions and listing filters with runtime tests and the end-to-end CLI flow.
