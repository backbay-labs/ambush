---
gsd_state_version: 1.0
milestone: v1.27
milestone_name: Live Response Adapters And Deployment
status: defining-requirements
last_updated: "2026-04-05T00:00:00Z"
progress:
  total_phases: 0
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-05)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** v1.27 Live Response Adapters And Deployment

## Current Position

Phase: Not started (defining requirements)
Plan: --
Status: Defining requirements
Last activity: 2026-04-05 -- Milestone v1.27 started

## Memory

- `v1.26` shipped 5 detectors, HTTP ingest, and Tetragon bridge. 275 tests passing.
- Only SandboxExecutor exists for response — no real side effects.
- No Dockerfile, docker-compose, or deployment infrastructure.
- reqwest not yet in workspace deps — needed for HTTP response adapters.
- Guard pipeline and policy gate already protect response path (v1.23).
- axum server in swarm-detect already serves /metrics and /v1/ingest/events.
- v1.28 (durable substrate + multi-instance) is queued after this.

## Next Command

Define requirements, then create roadmap.
