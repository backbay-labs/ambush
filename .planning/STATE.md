---
gsd_state_version: 1.0
milestone: v1.4
milestone_name: adversarial-replay-and-strategy-bench
status: milestone-complete
last_updated: "2026-04-03T16:30:26Z"
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
**Current focus:** `v1.4` is complete and archived; waiting for the next milestone

## Memory

- This is a brownfield repository with a Rust-first runtime and Python retained as reference-only material.
- `v1.0` shipped the first trusted vertical slice: config loading, detection, in-memory substrate, deterministic policy, sandboxed response, and replayable audit artifacts.
- `v1.1` shipped the operational hardening slice: local durable substrate, persistent replay storage, and operator status or metrics surfaces.
- `v1.2` shipped async investigation, explainable incident assembly, one operator review report, and config-backed async stack composition.
- `v1.3` shipped the repo-owned operator CLI, deterministic offline replay, and replay regression gates over a tracked scenario corpus.
- `v1.4` is complete: named suites, candidate experiments, persisted reports, and offline gates all shipped.
- The repo now has an offline adversarial bench that future promotion or verification work can build on.
- The runtime remains single-node and self-contained; distributed governance and gossip remain deferred.
- No new milestone has been opened yet.

## Next Command

`$gsd-new-milestone`
