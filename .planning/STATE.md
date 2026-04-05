---
gsd_state_version: 1.0
milestone: v1.25
milestone_name: Operational Hardening And Service Extraction
status: ready-to-plan
last_updated: "2026-04-04T00:00:00Z"
progress:
  total_phases: 3
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-05)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** Phase 78 - Service Extraction And Detection Binary

## Current Position

Phase: 78 of 80 (Service Extraction And Detection Binary)
Plan: --
Status: Ready to plan
Last activity: 2026-04-04 -- Roadmap created for v1.25

Progress: [░░░░░░░░░░] 0%

## Memory

- `v1.24` shipped approval ledgers, signed verdicts, receipt packs, and human-gate promotion integration.
- `v1.25` extracts the detection hot path, adds metrics, integration tests, and lint enforcement.
- swarmctl (3K+ lines) is the only binary today; swarm-detect will be the second.
- rulesets/default.yaml and scenarios/*.yaml exist but are not wired into detection config.
- No Prometheus dependency exists yet -- needs library selection (prometheus-client crate recommended).
- 1,386 unwrap/expect violations across the workspace -- Phase 80 is substantial refactoring.
- axum is already a workspace dependency for the HTTP surface.
- Phase 80 is independent of 78/79 and can run in parallel.

## Next Command

Plan Phase 78: `/gsd:plan-phase 78`
