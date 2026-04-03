---
gsd_state_version: 1.0
milestone: v1.6
milestone_name: bounded-canary-and-rollback
status: roadmap-defined
last_updated: "2026-04-03T19:26:46Z"
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
**Current focus:** `v1.6 Bounded Canary And Rollback` is defined and ready to begin at Phase 20.

## Memory

- This is a brownfield repository with a Rust-first runtime and Python retained as reference-only material.
- `v1.0` shipped the first trusted vertical slice: config loading, detection, in-memory substrate, deterministic policy, sandboxed response, and replayable audit artifacts.
- `v1.1` shipped the operational hardening slice: local durable substrate, persistent replay storage, and operator status or metrics surfaces.
- `v1.2` shipped async investigation, explainable incident assembly, one operator review report, and config-backed async stack composition.
- `v1.3` shipped the repo-owned operator CLI, deterministic offline replay, and replay regression gates over a tracked scenario corpus.
- `v1.4` is complete: named suites, candidate experiments, persisted reports, and offline gates all shipped.
- `v1.5` is complete: repo-owned verification corpora, invariant verdicts, shadow comparisons, and promotion review packets now ship through `swarmctl`.
- The repo now has enough offline bench infrastructure to support a bounded live canary lane for verified candidate detectors.
- The runtime remains single-node and self-contained; distributed governance and gossip remain deferred.
- `v1.6` follows the staged deployment path already documented in `docs/EVOLUTION.md` and `docs/INTEGRATION.md`: shadow is complete, so canary is the next bounded step.
- This milestone deliberately stops at canary, rollback, and canary review artifacts; fleet-wide promotion and consensus remain future work.

## Next Command

`$gsd-plan-phase 20`
