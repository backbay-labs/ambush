---
phase: 31-operator-queue-review-and-decisions
plan: 01
subsystem: evolution-operator-review
tags:
  - evolution
  - cli
  - operator
  - docs
one-liner: Added CLI-backed proof and queue review commands plus durable operator decisions for accepted, deferred, or rejected proposals.
requires:
  - 29-evolution-queue-and-proposal-artifacts
  - 30-proof-backed-admission-gate
provides:
  - `swarmctl` proof creation and reload commands
  - `swarmctl` queue creation, result, list, and decision commands
  - persisted decision history with a fail-closed review-state machine
affects: []
tech-stack:
  added:
    - clap value-enum parsing for queue review filters and decisions
  patterns:
    - review decisions persist as durable state transitions instead of transient CLI actions
    - operator docs describe proof and queue workflows alongside artifact directories
key-files:
  modified:
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
    - crates/swarm-runtime/src/evolution.rs
key-decisions:
  - "Expose proof creation through the same repo-owned CLI as the rest of the rollout ladder."
  - "Allow `accept_for_canary` only for unblocked, proved proposals; blocked proposals may only be rejected."
  - "Keep queue decisions review-only so they never mutate canary or production state directly."
patterns-established:
  - "The operator review ladder now includes durable queue decisions: proof -> proposal -> review -> accept/defer/reject."
requirements-completed:
  - EVOL-05
  - EVOL-06
  - EVOL-07
duration: 35min
completed: 2026-04-03
---

# Phase 31: Operator Queue Review And Decisions Summary

**Operators can now create proof artifacts, inspect queue entries by stable ID or review state, and record explicit accept, defer, or reject decisions through `swarmctl`.**

## Performance

- **Duration:** 35 min
- **Completed:** 2026-04-03T22:31:19Z
- **Tasks:** 4
- **Files modified:** 3

## Accomplishments

- Added `swarmctl evolution-proof-create`, `evolution-proof-result`, `evolution-queue-create`, `evolution-queue-result`, `evolution-queue-list`, and `evolution-queue-decision`.
- Implemented a durable review-state machine with persisted `decision_history` and explicit restrictions on terminal or blocked states.
- Added operator-facing renderers for proof artifacts, queue artifacts, and filtered queue listings.
- Documented proof and queue directories plus the full CLI workflow in `docs/CONFIGURATION.md`.

## Decisions Made

- Queue review remains CLI-first and artifact-driven.
- Accept-for-canary is explicit review state only; it does not launch a canary automatically.
- Blocked proposals remain visible so operators can inspect why they failed admission.

## Deviations from Plan

The first operator surface stays entirely inside `swarmctl` and text renderers. No HTTP or TUI work was added because the roadmap still prefers repo-owned CLI workflows over richer surfaces.

## Issues Encountered

`clippy -D warnings` forced the proposal-construction API to collapse into an owned request struct, which improved the CLI integration and test ergonomics.

## User Setup Required

Inspect the shipped queue and proof commands:

```bash
sed -n '508,575p' docs/CONFIGURATION.md
```

## Next Phase Readiness

The next milestone can now bridge accepted proposals into later rollout workflows without requiring manual artifact translation.

---
*Phase: 31-operator-queue-review-and-decisions*
*Completed: 2026-04-03*
