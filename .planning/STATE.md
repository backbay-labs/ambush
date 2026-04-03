---
gsd_state_version: 1.0
milestone: v1.9
milestone_name: verified-evolution-queue
status: ready-to-plan
last_updated: "2026-04-03T22:05:16Z"
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
**Current focus:** `v1.9 Verified Evolution Queue` is active. Phase 29 is next.

## Memory

- This is a brownfield repository with a Rust-first runtime and Python retained as reference-only material.
- `v1.0` shipped the first trusted vertical slice: config loading, detection, in-memory substrate, deterministic policy, sandboxed response, and replayable audit artifacts.
- `v1.1` shipped the operational hardening slice: local durable substrate, persistent replay storage, and operator status or metrics surfaces.
- `v1.2` shipped async investigation, explainable incident assembly, one operator review report, and config-backed async stack composition.
- `v1.3` shipped the repo-owned operator CLI, deterministic offline replay, and replay regression gates over a tracked scenario corpus.
- `v1.4` is complete: named suites, candidate experiments, persisted reports, and offline gates all shipped.
- `v1.5` is complete: repo-owned verification corpora, invariant verdicts, shadow comparisons, and promotion review packets now ship through `swarmctl`.
- `v1.6` is complete: bounded canary assignment, live observation metrics, automatic rollback, manual halt or rollback, and durable canary review artifacts now ship through `swarmctl`.
- `v1.7` is complete: production promotion start, bounded production observation, automatic rollback to the retained baseline, and durable promotion records now ship through `swarmctl`.
- `v1.8` is complete: durable strategy-memory records, advisory utility scoring, and baseline-vs-candidate scorecards now ship through `swarmctl`.
- The runtime remains single-node and self-contained; distributed governance and gossip remain deferred.
- The repo now has a full evidence ladder from replay and verification through production promotion plus one advisory memory layer above it.
- `v1.9` focuses on turning that advisory layer into a proof-backed detector proposal queue with durable review state.
- Phase 29 will establish stable evolution proposal artifacts before proof admission or operator decision workflows are added.
- Consensus, automatic strategy selection, and richer operator surfaces remain future work.

## Next Command

`$gsd-plan-phase 29`
