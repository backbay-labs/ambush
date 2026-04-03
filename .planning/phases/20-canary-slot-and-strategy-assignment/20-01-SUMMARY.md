---
phase: 20-canary-slot-and-strategy-assignment
plan: 01
subsystem: canary-assignment
tags:
  - canary
  - config
  - runtime
  - cli
one-liner: Verified candidate detectors can now be bound to a repo-owned canary slot through deterministic config, stable run IDs, and persisted assignment metadata.
requires:
  - 19-promotion-review-packets
provides:
  - validated canary slot config in the shared Rust config model
  - fail-closed canary start that cross-checks experiment, verification, and shadow evidence
  - persisted assignment artifacts keyed by stable canary run ID
affects: []
tech-stack:
  added: []
  patterns:
    - one active canary run per slot
    - canary start remains metadata-driven and does not mutate the production baseline detector
    - candidate deployment stays gated by passing verification and shadow evidence
key-files:
  created:
    - crates/swarm-runtime/src/canary.rs
  modified:
    - crates/swarm-core/src/config.rs
    - crates/swarm-runtime/src/config.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - rulesets/default.yaml
    - docs/CONFIGURATION.md
key-decisions:
  - "Represent canary configuration in `SwarmConfig` instead of inventing a separate sidecar manifest."
  - "Make `canary-start` fail closed on missing, failing, or mismatched verification and shadow artifacts."
  - "Preserve baseline strategy identity in the canary assignment instead of mutating runtime detector config."
patterns-established:
  - "Candidate deployment continues to progress by durable IDs: experiment -> verification -> shadow -> canary."
requirements-completed:
  - CAN-01
duration: 35min
completed: 2026-04-03
---

# Phase 20: Canary Slot And Strategy Assignment Summary

**The runtime now has a first-class canary assignment contract: one repo-owned slot, one active run per slot, and a deterministic start path that only accepts candidates already cleared by verification and shadow.**

## Performance

- **Duration:** 35 min
- **Completed:** 2026-04-03T20:03:20Z
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments

- Added `CanaryConfig` to the shared Rust config model and validated it during repo config loading.
- Added a persisted canary store and `DefaultCanaryHarness::start_run` to materialize a bounded canary assignment from an experiment manifest plus verification and shadow IDs.
- Enforced fail-closed start behavior for missing, failing, or experiment-mismatched artifacts.
- Added `swarmctl canary-start` and documented the canary config block plus operator flow.

## Decisions Made

- The first canary lane is a single named slot, not a generalized fleet scheduler.
- Canary assignment reuses the existing experiment lineage and stable artifact IDs instead of inventing a parallel approval model.
- Assignment artifacts store both the baseline and candidate detector identity so rollback remains explicit later.

## Deviations from Plan

The first implementation starts canaries from experiment manifests plus stable verification and shadow IDs rather than adding a separate canary manifest type. That kept the promotion ladder linear and avoided duplicating lineage data.

## Issues Encountered

The runtime test helpers in `control.rs` and `service.rs` needed small config updates after `SwarmConfig` gained the new `canary` block.

## User Setup Required

Inspect the shipped canary config defaults:

```bash
sed -n '52,80p' rulesets/default.yaml
```

## Next Phase Readiness

Phase 21 can now ingest live fixture events through the bounded canary lane and measure candidate-vs-baseline behavior over a controlled observation window.

---
*Phase: 20-canary-slot-and-strategy-assignment*
*Completed: 2026-04-03*
