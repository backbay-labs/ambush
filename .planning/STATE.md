---
gsd_state_version: 1.0
milestone: v1.3
milestone_name: operator-control-and-replay-evaluation
status: ready
last_updated: "2026-04-03T15:53:22Z"
progress:
  total_phases: 3
  completed_phases: 2
  total_plans: 3
  completed_plans: 2
  percent: 67
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-03)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** Phase 12 complete; Phase 13 is next

## Memory

- This is a brownfield repository with a Rust-first runtime and Python retained as reference-only material.
- `v1.0` shipped the first trusted vertical slice: config loading, detection, in-memory substrate, deterministic policy, sandboxed response, and replayable audit artifacts.
- `v1.1` shipped the operational hardening slice: local durable substrate, persistent replay storage, and operator status or metrics surfaces.
- `v1.2` shipped async investigation, explainable incident assembly, one operator review report, and config-backed async stack composition.
- `v1.3` is scoped around a repo-owned operator CLI, deterministic offline replay, and regression evaluation over the existing durable artifact model.
- Phase 11 is complete: `swarmctl` now exposes runtime status plus stable-ID lookup for replay bundles, investigation bundles, and incidents.
- Phase 12 is complete: `swarmctl` can now run offline replay from tracked scenarios or replay-bundle fixtures and persist durable replay-run bundles under `data/replay-runs/`.
- The runtime remains single-node and self-contained; distributed governance and gossip remain deferred.
- Research was intentionally skipped for this milestone because the existing docs and archived roadmap already identified the next scope clearly.

## Next Command

`$gsd-plan-phase 13`
