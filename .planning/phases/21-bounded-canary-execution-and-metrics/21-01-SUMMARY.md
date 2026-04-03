---
phase: 21-bounded-canary-execution-and-metrics
plan: 01
subsystem: canary-observation
tags:
  - canary
  - metrics
  - runtime
  - fixtures
one-liner: The runtime now executes a bounded canary lane that compares baseline and candidate detector behavior, records observation metrics, and exposes the run through `swarmctl`.
requires:
  - 20-canary-slot-and-strategy-assignment
provides:
  - live canary event ingestion with baseline and candidate comparison
  - persisted metrics and threshold results over a configured observation window
  - CLI reload and fixture-driven verification for canary observation
affects: []
tech-stack:
  added: []
  patterns:
    - canary observation stays local and does not mutate the production pheromone substrate
    - metrics record both shared and divergent detector behavior
    - readiness for promotion depends on the bounded observation window completing cleanly
key-files:
  created:
    - fixtures/canary/word-powershell.yaml
    - fixtures/canary/outlook-cmd.yaml
    - fixtures/canary/python-curl.yaml
  modified:
    - crates/swarm-runtime/src/canary.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Keep canary observation substrate-free so one candidate run cannot drive fleet-wide escalation semantics."
  - "Track candidate-only rate, baseline miss rate, latency, and deposit count as the first bounded canary metrics."
  - "Use tracked YAML fixtures to exercise the first canary flow outside unit tests."
patterns-established:
  - "Live rollout steps stay replayable and inspectable through the same CLI used for offline promotion evidence."
requirements-completed:
  - CAN-02
  - CAN-03
duration: 40min
completed: 2026-04-03
---

# Phase 21: Bounded Canary Execution And Metrics Summary

**The runtime now runs a candidate detector beside the production baseline inside a bounded canary lane, records their deltas and latencies over a configurable window, and surfaces the result through stable canary artifacts.**

## Performance

- **Duration:** 40 min
- **Completed:** 2026-04-03T20:03:20Z
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments

- Added live canary event ingestion and event-path loading in `DefaultCanaryHarness`.
- Recorded per-run metrics for total events, shared findings, candidate-only and baseline-only detections, latency, and candidate deposit counts.
- Added threshold evaluation and recommendation updates on every canary event.
- Added fixture events and documented the end-to-end `canary-start -> canary-event -> canary-result` flow.

## Decisions Made

- The first canary lane compares baseline and candidate locally instead of writing canary findings into the shared pheromone substrate.
- The observation window is event-count based for the first implementation; that keeps the lane deterministic and easy to test.
- Candidate deposit volume is tracked as a budget metric even though canary findings do not enter the production substrate.

## Deviations from Plan

Resource metrics started with detection latency and candidate deposit volume rather than full CPU or memory accounting. That keeps the first lane aligned with the runtime’s existing detector-focused evidence model.

## Issues Encountered

`cargo fmt --check` initially flagged style diffs in the new `canary.rs` module after the implementation settled. Running `cargo fmt --all` resolved them cleanly.

## User Setup Required

Run the documented happy-path canary flow:

```bash
cargo run -p swarm-runtime --bin swarmctl -- canary-start --experiment experiments/office-baseline-control.yaml --verification-id verification:office_baseline_control:office_baseline_control:office_detector_safety_v1 --shadow-id shadow:office_baseline_control:office_baseline_control:2026-04-03
```

## Next Phase Readiness

Phase 22 can now turn threshold failures and operator actions into durable rollback history and one review surface that links verification, shadow, and canary evidence together.

---
*Phase: 21-bounded-canary-execution-and-metrics*
*Completed: 2026-04-03*
