---
phase: 06-persistent-audit-and-replay
plan: 01
subsystem: audit
tags:
  - replay
  - persistence
  - receipts
  - indexing
one-liner: Replay bundles now persist to configurable stores and can be reloaded by hunt or receipt ID without re-executing actions.
requires:
  - 05-durable-substrate
provides:
  - Replay bundle store abstraction with memory and local-file backends
  - Persisted bundle lookup by hunt ID and receipt ID
  - Side-effect-free replay previews
affects:
  - operator-visibility
tech-stack:
  added: []
  patterns:
    - durable bundle index
    - receipt-chain correlation
key-files:
  created:
    - crates/swarm-spine/src/store.rs
  modified:
    - crates/swarm-core/src/types.rs
    - crates/swarm-runtime/src/lib.rs
    - crates/swarm-runtime/src/service.rs
    - crates/swarm-spine/src/lib.rs
key-decisions:
  - "Replay persistence lives in `swarm-spine`, not inside ad hoc runtime file helpers."
  - "Stored records index by stable IDs so operator and replay surfaces can share the same metadata."
patterns-established:
  - "Replay inspection is explicitly read-only and described as such in the preview object."
requirements-completed:
  - AUD-03
  - AUD-04
  - AUD-05
duration: 30min
completed: 2026-04-03
---

# Phase 6: Persistent Audit And Replay Summary

**Replay bundles now persist through a configurable store abstraction and can be recovered by hunt or receipt identifiers after restart without re-running the original action.**

## Performance

- **Duration:** 30 min
- **Started:** 2026-04-03T05:25:00Z
- **Completed:** 2026-04-03T05:55:00Z
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments
- Added `swarm-spine` replay stores with in-memory and local-file backends plus recent-decision health summaries.
- Enriched audit trails with upstream receipt IDs so persisted records can correlate bundle, hunt, trail, and receipt identifiers.
- Added runtime helpers to persist bundles, reload them by stable IDs, and generate replay previews that explicitly avoid action re-execution.

## Decisions Made

- Replay persistence belongs in `swarm-spine` because it is audit-domain logic, not runtime orchestration glue.
- File-backed replay storage is sufficient for the single-node operator milestone and easy to inspect manually.

## Deviations from Plan

None.

## Issues Encountered

The audit trail initially lacked the upstream receipt chain needed for useful lookup by prior IDs. The runtime now carries those IDs into the persisted record set.

## User Setup Required

Provide a writable directory when using the local-file replay store backend.

## Next Phase Readiness

Phase 7 can build operator status directly on the replay store’s recent-decision summaries and stable correlation metadata.

---
*Phase: 06-persistent-audit-and-replay*
*Completed: 2026-04-03*
