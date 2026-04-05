---
gsd_state_version: 1.0
milestone: v1.25
milestone_name: Operational Hardening And Service Extraction
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
**Current focus:** v1.25 Operational Hardening And Service Extraction

## Current Position

Phase: Not started (defining requirements)
Plan: --
Status: Defining requirements
Last activity: 2026-04-05 -- Milestone v1.25 started

## Memory

- `v1.23` shipped crypto foundation, guard pipeline, spine signing, and CI gates.
- `v1.24` shipped approval ledgers, signed verdicts, receipt packs, and human-gate promotion integration.
- `v1.25` extracts the detection hot path, adds metrics, integration tests, and lint enforcement.
- The runtime is ~45K lines across 20+ modules — monolithic. Service extraction is structural investment.
- 1,386 unwrap/expect violations exist in the codebase — Phase 80 requires substantial refactoring.
- No Prometheus dependency exists yet — Phase 79 adds it.
- swarmctl is the only binary; swarm-detect will be the second.
- Queued plan at .planning/queued/v1.25-PLAN.md has phase structure and success criteria.

## Next Command

Define requirements, then create roadmap.
