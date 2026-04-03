---
gsd_state_version: 1.0
milestone: v1.4
milestone_name: adversarial-replay-and-strategy-bench
status: ready
last_updated: "2026-04-03T16:00:00Z"
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
**Current focus:** Defining and executing v1.4 adversarial replay and strategy bench work

## Memory

- This is a brownfield repository with a Rust-first runtime and Python retained as reference-only material.
- `v1.0` shipped the first trusted vertical slice: config loading, detection, in-memory substrate, deterministic policy, sandboxed response, and replayable audit artifacts.
- `v1.1` shipped the operational hardening slice: local durable substrate, persistent replay storage, and operator status or metrics surfaces.
- `v1.2` shipped async investigation, explainable incident assembly, one operator review report, and config-backed async stack composition.
- `v1.3` shipped the repo-owned operator CLI, deterministic offline replay, and replay regression gates over a tracked scenario corpus.
- `v1.4` is derived from the deferred Phase 7 work in `docs/ROADMAP.md` plus the offline bench semantics in `docs/EVOLUTION.md`.
- This milestone stays offline-only: adversarial suites and candidate strategy experiments are allowed, but live promotion, canary rollout, and governance changes remain deferred.
- The runtime remains single-node and self-contained; distributed governance and gossip remain deferred.
- Separate milestone research was skipped because the canonical docs already specify the next track clearly.

## Next Command

`$gsd-plan-phase 14`
