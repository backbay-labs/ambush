---
phase: 24-production-observation-window-and-metrics
plan: 01
subsystem: production-observation
tags:
  - promotion
  - metrics
  - rollback
  - runtime
one-liner: The runtime now observes a promoted detector over a bounded production window, records divergence and latency metrics, and automatically rolls back on threshold failure.
requires:
  - 23-production-promotion-and-baseline-rotation
provides:
  - live production-window event ingestion for promoted detectors
  - persisted post-promotion metrics and threshold results
  - automatic rollback on divergence, latency, or detection-budget failure
affects: []
tech-stack:
  added: []
  patterns:
    - promoted detector remains observable against the retained fallback baseline
    - production observation stays deterministic and auditable
    - automatic rollback uses the same durable artifact as operator review
key-files:
  created:
    - crates/swarm-runtime/src/promotion.rs
  modified:
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Use an event-count production observation window first, matching the deterministic canary model."
  - "Track promoted-only divergence, fallback recovery, latency, and detection volume as the first production metrics."
  - "Keep fallback comparison local to the promotion harness rather than mutating the baseline runtime pipeline."
patterns-established:
  - "Post-promotion observation now follows the same stable-ID store pattern as replay, shadow, canary, and promotion review."
requirements-completed:
  - PROD-03
  - PROD-04
duration: 40min
completed: 2026-04-03
---

# Phase 24: Production Observation Window And Metrics Summary

**The runtime now watches a promoted detector under a bounded production window, compares it continuously to the retained fallback baseline, and rolls back automatically when the promoted detector diverges beyond configured bounds.**

## Performance

- **Duration:** 40 min
- **Completed:** 2026-04-03T21:12:35Z
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments

- Added production-window metrics for fallback and promoted detections, divergence, latency, and promoted deposit volume.
- Added event ingestion and threshold evaluation to `DefaultProductionPromotionHarness`.
- Added automatic rollback on threshold or budget failure with explicit rollback triggers.
- Verified a clean completion path and an automatic rollback path in runtime tests.

## Decisions Made

- The promoted detector becomes authoritative inside the promotion harness, but the fallback baseline continues to run as a comparator during the observation window.
- Observation completion is event-count based for the first implementation.
- Promoted deposit volume is tracked as the first production budget metric even before richer CPU or memory accounting exists.

## Deviations from Plan

Resource metrics started with detect latency and detection-volume budgets rather than full process or host resource accounting. That keeps the first production-promotion slice aligned with the current detector-centered runtime evidence model.

## Issues Encountered

The new promotion module needed a full `rustfmt` pass after the first implementation. No behavioral changes were required after formatting.

## User Setup Required

Drive the production observation window with fixture events:

```bash
cargo run -p swarm-runtime --bin swarmctl -- promotion-event --promotion-id YOUR_PROMOTION_ID --event fixtures/canary/word-powershell.yaml
```

## Next Phase Readiness

Phase 25 can now turn the production observation artifact into the durable operator record: manual halt or rollback, stable-ID reload, and end-to-end docs.

---
*Phase: 24-production-observation-window-and-metrics*
*Completed: 2026-04-03*
