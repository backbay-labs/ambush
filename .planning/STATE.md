---
gsd_state_version: 1.0
milestone: v1.5
milestone_name: formal-verification-and-shadow-readiness
status: ready
last_updated: "2026-04-03T16:45:00Z"
progress:
  total_phases: 3
  completed_phases: 0
  total_plans: 3
  completed_plans: 0
  percent: 0
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-03)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** Defining and executing v1.5 formal verification and shadow-readiness work

## Memory

- This is a brownfield repository with a Rust-first runtime and Python retained as reference-only material.
- `v1.0` shipped the first trusted vertical slice: config loading, detection, in-memory substrate, deterministic policy, sandboxed response, and replayable audit artifacts.
- `v1.1` shipped the operational hardening slice: local durable substrate, persistent replay storage, and operator status or metrics surfaces.
- `v1.2` shipped async investigation, explainable incident assembly, one operator review report, and config-backed async stack composition.
- `v1.3` shipped the repo-owned operator CLI, deterministic offline replay, and replay regression gates over a tracked scenario corpus.
- `v1.4` is complete: named suites, candidate experiments, persisted reports, and offline gates all shipped.
- `v1.5` is derived directly from `docs/EVOLUTION.md`: verification gate first, then shadow readiness, with canary and consensus still deferred.
- The repo now has enough offline bench infrastructure to build promotion-readiness artifacts without widening live autonomy.
- The runtime remains single-node and self-contained; distributed governance and gossip remain deferred.
- Additional milestone research was skipped because the canonical docs already make the next track explicit.

## Next Command

`$gsd-plan-phase 17`
