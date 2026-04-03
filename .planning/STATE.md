---
gsd_state_version: 1.0
milestone: v1.10
milestone_name: queue-handoff-and-canary-launch
status: ready-to-plan
last_updated: "2026-04-03T22:31:19Z"
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
**Current focus:** `v1.10 Queue Handoff And Canary Launch` is active. Phase 32 is next.

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
- `v1.9` is complete: proof-backed detector proposal queue artifacts, fail-closed admission, and CLI-backed review decisions now ship through `swarmctl`.
- The runtime now needs to bridge accepted proposals into the existing canary lane without forcing operators to hand-translate experiment, verification, and proof metadata.
- `v1.10` focuses on durable handoff packets plus operator-launched canary entry from accepted proposals.
- Phase 32 will establish stable queue-to-canary handoff artifacts before handoff admission checks or launch commands are added.
- Consensus, automatic strategy selection, and richer operator surfaces remain future work.

## Next Command

`$gsd-plan-phase 32`
