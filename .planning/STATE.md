---
gsd_state_version: 1.0
milestone: v1.2
milestone_name: async-investigation-and-correlation
status: planning
last_updated: "2026-04-03T05:22:05Z"
progress:
  total_phases: 0
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-03)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** Defining milestone v1.2 requirements and roadmap

## Memory

- This is a brownfield repository with a Rust-first runtime and Python retained as reference-only material.
- `v1.0` shipped the first trusted vertical slice: config loading, detection, in-memory substrate, deterministic policy, sandboxed response, and replayable audit artifacts.
- `v1.1` shipped the operational hardening slice: local durable substrate, persistent replay storage, and operator status/metrics surfaces.
- `v1.2` is intended to add async investigation and incident correlation without weakening the hot path.
- The runtime remains single-node and self-contained; distributed governance and gossip remain deferred.

## Next Command

`$gsd-new-milestone` in progress
