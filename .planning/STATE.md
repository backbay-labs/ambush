---
gsd_state_version: 1.0
milestone: v1.7
milestone_name: controlled-production-promotion
status: roadmap-defined
last_updated: "2026-04-03T20:15:34Z"
progress:
  total_phases: 3
  completed_phases: 0
  total_plans: 3
  completed_plans: 0
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-03)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** `v1.7 Controlled Production Promotion` is defined and ready to begin at Phase 23.

## Memory

- This is a brownfield repository with a Rust-first runtime and Python retained as reference-only material.
- `v1.0` shipped the first trusted vertical slice: config loading, detection, in-memory substrate, deterministic policy, sandboxed response, and replayable audit artifacts.
- `v1.1` shipped the operational hardening slice: local durable substrate, persistent replay storage, and operator status or metrics surfaces.
- `v1.2` shipped async investigation, explainable incident assembly, one operator review report, and config-backed async stack composition.
- `v1.3` shipped the repo-owned operator CLI, deterministic offline replay, and replay regression gates over a tracked scenario corpus.
- `v1.4` is complete: named suites, candidate experiments, persisted reports, and offline gates all shipped.
- `v1.5` is complete: repo-owned verification corpora, invariant verdicts, shadow comparisons, and promotion review packets now ship through `swarmctl`.
- `v1.6` is complete: bounded canary assignment, live observation metrics, automatic rollback, manual halt or rollback, and durable canary review artifacts now ship through `swarmctl`.
- The runtime remains single-node and self-contained; distributed governance and gossip remain deferred.
- The repo now has enough promotion-readiness infrastructure to promote from canary into the production detector role without inventing a new evidence model.
- `v1.7` follows the staged deployment path documented in `docs/EVOLUTION.md` and `docs/INTEGRATION.md`: after shadow and canary, the next bounded step is production promotion with observation-window rollback.
- Consensus, MemRL-based automatic selection, and richer operator surfaces remain future work.

## Next Command

`$gsd-plan-phase 23`
