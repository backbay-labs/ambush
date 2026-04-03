---
phase: 19-promotion-review-packets
plan: 01
subsystem: promotion-review
tags:
  - review
  - verification
  - shadow
  - cli
one-liner: Promotion review packets now tie candidate lineage, verification evidence, and shadow evidence together as a durable operator handoff artifact.
requires:
  - 18-verification-gate-and-shadow-runner
provides:
  - persisted promotion review packets with stable IDs
  - CLI create and reload commands for review packets
  - blocking-reason summaries derived from verification and shadow artifacts
affects: []
tech-stack:
  added: []
  patterns:
    - review packets reference stable evidence IDs instead of duplicating execution
    - manual-review readiness remains explicit and non-automating
    - promotion evidence persists under a dedicated local store
key-files:
  created: []
  modified:
    - .gitignore
    - crates/swarm-runtime/src/replay.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Keep the promotion packet thin and reference-oriented instead of embedding full nested reports again."
  - "Manual review is the terminal state for this milestone; no automatic deployment or approval machinery was added."
  - "Blocking reasons are derived directly from failed invariants and failed shadow gates."
patterns-established:
  - "Promotion evidence artifacts compose previous offline artifacts by stable ID."
requirements-completed:
  - VER-02
  - PRM-01
  - PRM-02
duration: 35min
completed: 2026-04-03
---

# Phase 19: Promotion Review Packets Summary

**Swarm Team Six now produces a durable promotion review packet that references the stable verification and shadow artifacts for a candidate detector and tells the operator whether the evidence is ready for manual review or blocked.**

## Performance

- **Duration:** 35 min
- **Completed:** 2026-04-03T17:32:57Z
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments

- Added promotion review packet types, blocking-reason summaries, and a dedicated local store in `crates/swarm-runtime/src/replay.rs`.
- Added `swarmctl promotion-review-create` and `swarmctl promotion-review-result`.
- Added a replay test proving packet creation and reload from stored verification and shadow IDs.
- Updated `.gitignore` and `docs/CONFIGURATION.md` for `data/promotion-reviews/`.

## Decisions Made

- The packet stays reference-oriented: it stores stable verification and shadow IDs plus the operator-relevant summary fields.
- Recommendation remains binary and explicit for now: `ready_for_manual_review` or `blocked`.
- Packet creation validates that the verification and shadow evidence belong to the same experiment before persisting anything.

## Deviations from Plan

No material deviation. The implementation stayed thin and reused the evidence artifacts from Phase 18 instead of recomputing them.

## Issues Encountered

The first CLI verification of `promotion-review-result` failed because I launched packet creation and reload in parallel, so the reload raced the store write. Running the reload after creation completed resolved it.

## User Setup Required

Create a review packet from the control candidate:

```bash
cargo run -p swarm-runtime --bin swarmctl -- promotion-review-create --experiment experiments/office-baseline-control.yaml --verification-id verification:office_baseline_control:office_baseline_control:office_detector_safety_v1 --shadow-id shadow:office_baseline_control:office_baseline_control:2026-04-03
```

Reload it later by stable ID:

```bash
cargo run -p swarm-runtime --bin swarmctl -- promotion-review-result --review-id promotion_review:office_baseline_control:office_baseline_control:2026-04-03
```

## Next Phase Readiness

`v1.5` now has the full offline promotion-readiness chain: experiment -> verification -> shadow -> promotion review packet. The milestone is ready for audit and archival after state cleanup.

---
*Phase: 19-promotion-review-packets*
*Completed: 2026-04-03*
