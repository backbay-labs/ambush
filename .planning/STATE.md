---
gsd_state_version: 1.0
milestone: v1.2
milestone_name: async-investigation-and-correlation
status: ready
last_updated: "2026-04-03T14:50:46Z"
progress:
  total_phases: 3
  completed_phases: 3
  total_plans: 3
  completed_plans: 3
  percent: 100
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-03)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** Milestone v1.2 complete and archived; ready for next milestone

## Memory

- This is a brownfield repository with a Rust-first runtime and Python retained as reference-only material.
- `v1.0` shipped the first trusted vertical slice: config loading, detection, in-memory substrate, deterministic policy, sandboxed response, and replayable audit artifacts.
- `v1.1` shipped the operational hardening slice: local durable substrate, persistent replay storage, and operator status/metrics surfaces.
- `v1.2` now has Phase 8 complete: persisted replay bundles can seed an async investigation queue with durable queued/completed/failed outcomes.
- `v1.2` now has Phase 9 complete: correlation can assemble durable incidents with explicit inclusion and rejection reasons.
- `v1.2` now has Phase 10 complete: one operator review report combines hot-path decisions, async investigation state, incidents, and freshness markers.
- The runtime remains single-node and self-contained; distributed governance and gossip remain deferred.
- `v1.2` audit passed with full requirement coverage, config-backed async stack composition, and green workspace tests plus clippy.

## Next Command

`$gsd-new-milestone`
