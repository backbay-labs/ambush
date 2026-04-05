---
gsd_state_version: 1.0
milestone: v1.26
milestone_name: Detection Breadth And Telemetry Ingestion
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
**Current focus:** v1.26 Detection Breadth And Telemetry Ingestion

## Current Position

Phase: Not started (defining requirements)
Plan: --
Status: Defining requirements
Last activity: 2026-04-05 -- Milestone v1.26 started

## Memory

- `v1.25` shipped standalone binary, metrics, integration tests, clippy enforcement.
- Only one detector exists (SuspiciousProcessTreeDetector). Need 3-4 more for real coverage.
- Only synthetic telemetry ingestion (function calls). Need HTTP/gRPC ingest server.
- Tetragon bridge pattern exists in vendor/reference/ but is not active code.
- reqwest not yet in workspace deps — needed for outbound HTTP.
- v1.27 (response adapters + deployment) and v1.28 (durable substrate + multi-instance) are queued.

## Next Command

Define requirements, then create roadmap.
