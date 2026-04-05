---
gsd_state_version: 1.0
milestone: v1.27
milestone_name: Live Response Adapters And Deployment
status: ready-to-plan
last_updated: "2026-04-05T00:00:00Z"
progress:
  total_phases: 2
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-05)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** Phase 84 - Real Response Adapters

## Current Position

Phase: 84 of 85 (Real Response Adapters)
Plan: --
Status: Ready to plan
Last activity: 2026-04-05 -- Roadmap created for v1.27

Progress: [░░░░░░░░░░] 0%

## Memory

- `v1.26` shipped 5 detectors, HTTP ingest, and Tetragon bridge. 275 tests passing.
- Only SandboxExecutor exists for response -- no real side effects yet.
- No Dockerfile, docker-compose, or deployment infrastructure.
- reqwest not yet in workspace deps -- needed for HTTP response adapters.
- Guard pipeline and policy gate already protect response path (v1.23).
- axum server in swarm-detect already serves /metrics and /v1/ingest/events.
- v1.28 (durable substrate + multi-instance) is queued after this.

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
No new decisions yet for v1.27.

### Blockers/Concerns

None yet.

## Session Continuity

Last session: 2026-04-05
Stopped at: Roadmap created, ready to plan Phase 84
Resume file: None
