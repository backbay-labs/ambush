---
gsd_state_version: 1.0
milestone: v1.29
milestone_name: Runtime Decomposition And Test Coverage
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
**Current focus:** v1.29 Runtime Decomposition And Test Coverage

## Current Position

Phase: Not started (defining requirements)
Plan: --
Status: Defining requirements
Last activity: 2026-04-05 -- Milestone v1.29 started

## Memory

- `v1.28` shipped JetStream substrate, multi-instance coordination, legacy cleanup. 310 tests.
- swarm-runtime is 49K lines with 114 tests (0.23% coverage).
- operator_http.rs is 5.4K lines. review_workbench.rs is 3.8K with 0 tests. replay.rs is 5.3K.
- swarmctl.rs has 3.5K lines of CLI logic in a binary (untestable).
- approval.rs and promotion.rs are the model (0.5% coverage each).
- v1.30 (observability + resilience) and v1.31 (agent dispatcher) are queued.

## Next Command

Define requirements, then create roadmap.
