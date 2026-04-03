---
phase: 33-queue-to-canary-admission-gate
plan: 01
subsystem: evolution-handoff-gate
tags:
  - evolution
  - handoff
  - gate
  - runtime
one-liner: Added fail-closed handoff admission checks for accepted proposal state, proof status, verification linkage, and shadow evidence.
requires:
  - 32-queue-handoff-artifacts
provides:
  - handoff blocking reasons persisted on invalid queue-to-canary packets
  - fail-closed admission checks across proposal, proof, verification, and shadow artifacts
  - blocked handoff packets that remain auditable through the CLI
affects: []
tech-stack:
  added: []
  patterns:
    - handoff admission records denial reasons instead of silently discarding invalid launch requests
    - queue-to-canary checks remain off the hot path and separate from canary execution
key-files:
  modified:
    - crates/swarm-runtime/src/evolution.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Require `accepted_for_canary` plus proved proposal state before any handoff can become launchable."
  - "Treat missing or mismatched shadow evidence as a blocked handoff artifact rather than an opaque CLI error."
  - "Preserve blocked handoff packets so operators can inspect why launch prep failed."
patterns-established:
  - "The queue bridge now has its own safety floor: accepted proposal + proved evidence + passed shadow -> launchable handoff."
requirements-completed:
  - HAND-03
duration: 20min
completed: 2026-04-03
---

# Phase 33: Queue-To-Canary Admission Gate Summary

**Handoff creation now fails closed unless the proposal is accepted for canary, the queue evidence is proved and unblocked, and the supplied shadow artifact matches and passes.**

## Performance

- **Duration:** 20 min
- **Completed:** 2026-04-03T22:42:24Z
- **Tasks:** 4
- **Files modified:** 2

## Accomplishments

- Added handoff blocking checks for proposal review state, proof status, prior proposal blocking reasons, verification status, experiment path, and shadow consistency.
- Persisted blocking reasons directly on handoff artifacts.
- Wired `evolution-handoff-create` to exit nonzero when the handoff is blocked.
- Covered invalid handoff creation with runtime tests and CLI verification.

## Decisions Made

- Handoff creation is allowed to persist blocked artifacts for review instead of failing invisibly.
- Proposal acceptance and handoff launch readiness are distinct states.
- Shadow evidence must match both experiment and strategy before the handoff can become launchable.

## Deviations from Plan

The initial gate relies on the existing queue proof and verification summaries rather than reloading every upstream artifact again. That keeps the handoff lane aligned with the reviewed proposal state while still checking shadow compatibility directly.

## Issues Encountered

The queue bridge needed to reject pre-acceptance proposals cleanly; otherwise operators could create rollout handoffs from proposals that had never been reviewed.

## User Setup Required

Inspect the shipped blocked-handoff behavior:

```bash
sed -n '600,613p' docs/CONFIGURATION.md
```

## Next Phase Readiness

Phase 34 can now launch canary from handoff packets because launchable handoffs have a bounded and explicit admission rule.

---
*Phase: 33-queue-to-canary-admission-gate*
*Completed: 2026-04-03*
