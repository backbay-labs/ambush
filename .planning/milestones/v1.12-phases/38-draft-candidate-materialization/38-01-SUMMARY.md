---
phase: 38-draft-candidate-materialization
plan: 01
subsystem: evolution-drafting
tags:
  - evolution
  - drafting
  - runtime
  - cli
one-liner: Added durable draft materialization artifacts that generate repo-owned experiment manifests from stable drafts.
requires:
  - 37-draft-review-and-queue-promotion
provides:
  - file-backed materialization storage rooted under `data/evolution-materializations/`
  - materialized experiment manifests written beside the chosen base experiment
  - stable-ID reload through `swarmctl evolution-materialization-result`
affects: []
tech-stack:
  added:
    - serde-backed materialization reports and index files
  patterns:
    - draft materialization stays operator-triggered and off the hot path
    - materialized candidates reuse the existing experiment manifest type
key-files:
  modified:
    - crates/swarm-runtime/src/drafting.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Reuse the current suspicious process-tree experiment manifest instead of creating a separate draft-only candidate schema."
  - "Write materialized manifests next to the selected base experiment so existing relative corpus references remain valid."
  - "Keep profile changes explicit through CLI override flags rather than auto-mutating draft hints."
patterns-established:
  - "The evolution lane now preserves a concrete bridge from reviewed draft to repo-owned candidate manifest."
requirements-completed:
  - MTRL-01
  - MTRL-02
duration: 31min
completed: 2026-04-03
---

# Phase 38: Draft Candidate Materialization Summary

**The runtime now materializes reviewed draft proposals into concrete repo-owned detector experiment manifests with stable artifact IDs and preserved lineage.**

## Accomplishments

- Added `EvolutionMaterializationReport`, `EvolutionMaterializationRecord`, and `FileEvolutionMaterializationStore`.
- Implemented `DefaultEvolutionDraftingHarness::materialize_draft`.
- Added `swarmctl evolution-materialize` and `evolution-materialization-result`.
- Preserved source experiment, draft lineage, manifest digests, and applied profile changes in durable artifacts.
