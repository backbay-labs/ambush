---
phase: 09-correlation-and-incident-assembly
plan: 01
subsystem: correlation
tags:
  - incidents
  - correlation
  - review
  - durability
one-liner: The runtime can now assemble and persist deterministic incidents from durable investigation bundles, with explicit inclusion and rejection reasons.
requires:
  - 08-async-investigation-pipeline
provides:
  - Repository-owned correlation configuration
  - Durable incident artifact storage
  - Deterministic incident assembly with explicit rejection reasons
affects: []
tech-stack:
  added: []
  patterns:
    - seeded incident assembly from persisted investigation bundles
    - explainable inclusion and rejection decisions
key-files:
  created:
    - crates/swarm-spine/src/incident.rs
    - crates/swarm-runtime/src/correlation.rs
  modified:
    - crates/swarm-core/src/config.rs
    - crates/swarm-runtime/src/config.rs
    - crates/swarm-runtime/src/lib.rs
    - crates/swarm-runtime/src/service.rs
    - crates/swarm-spine/src/lib.rs
    - rulesets/default.yaml
key-decisions:
  - "Correlation stays rule-based and operator-facing for the first incident layer."
  - "Every rejected candidate is persisted as part of the incident artifact rather than discarded."
patterns-established:
  - "swarm-spine now owns replay, investigation, and incident artifact families."
  - "Runtime service helpers can materialize higher-order artifacts from durable lower-order ones."
requirements-completed:
  - COR-01
  - COR-02
duration: 55min
completed: 2026-04-03
---

# Phase 9: Correlation And Incident Assembly Summary

**The runtime now assembles durable incidents from persisted investigation bundles and records both included and rejected candidates with stable reasons.**

## Performance

- **Duration:** 55 min
- **Started:** 2026-04-03T13:50:00Z
- **Completed:** 2026-04-03T14:45:25Z
- **Tasks:** 3
- **Files modified:** 6
- **Files created:** 2

## Accomplishments
- Added repository-owned `correlation` config for time windows, shared-key thresholds, candidate limits, and incident-store selection.
- Added durable incident types and memory or file-backed incident stores in `swarm-spine`.
- Added a deterministic correlation engine that assembles incidents from persisted investigation bundles.
- Persisted inclusion and rejection reasoning directly in incident artifacts.
- Added runtime helpers and tests proving that correlated incidents can be assembled and loaded by included hunt ID.

## Decisions Made

- The first incident model is seeded from one hunt and explains every candidate against that seed.
- Correlation uses stable shared keys and time windows only; no scoring model or graph dependency was introduced.

## Deviations from Plan

None.

## Issues Encountered

The first engine pass hit a couple of borrow-checker conflicts while extending shared-key and receipt vectors. Collecting the new values first kept the implementation simple and explicit.

## User Setup Required

If incident durability is enabled with `local_files`, the configured incident-store directory must be writable by the runtime process.

## Next Phase Readiness

The operator report can now surface queued investigations, recent investigation bundles, and correlated incidents from durable stores without redesigning the underlying artifact formats.

---
*Phase: 09-correlation-and-incident-assembly*
*Completed: 2026-04-03*
