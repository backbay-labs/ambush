---
phase: 43-candidate-ranking-and-review-packets
plan: 01
subsystem: evolution-mutation
tags:
  - evolution
  - mutation
  - runtime
  - cli
one-liner: Added deterministic candidate ranking and durable review packets above mutation validation batches.
requires:
  - 42-batch-candidate-materialization-and-validation
provides:
  - file-backed ranking artifacts under `data/evolution-rankings/`
  - deterministic scoring from validation, proof, advisory, and reviewed-queue state
  - durable review packets preserving materialization and validation refs
affects: []
tech-stack:
  added:
    - serde-backed ranking reports and index files
  patterns:
    - ranking remains advisory and does not auto-enqueue rollout work
    - review packets preserve upstream queue references instead of rewriting evidence
key-files:
  modified:
    - crates/swarm-runtime/src/mutation.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
    - .gitignore
key-decisions:
  - "Score candidates from persisted validation evidence and reviewed queue state instead of re-running evaluation."
  - "Emit review packets for the shortlisted candidates only, but keep the full ordered ranking in the durable report."
  - "Keep ranking deterministic and advisory rather than connecting it directly to queue or rollout mutation."
patterns-established:
  - "The mutation lane now ends in a durable operator review packet rather than a loose list of candidate IDs."
requirements-completed:
  - EVOL-15
  - EVOL-16
duration: 24min
completed: 2026-04-03
---

# Phase 43: Candidate Ranking And Review Packets Summary

**The runtime now scores validated mutation candidates deterministically and emits durable review packets that preserve materialization, validation, and reviewed-queue references.**

## Accomplishments

- Added ranking report, review packet, and ranking store types to `crates/swarm-runtime/src/mutation.rs`.
- Added `swarmctl evolution-rank-candidates` and `evolution-ranking-result`.
- Ranked candidates from validation status, proof status, advisory score deltas, blocking reasons, and reviewed queue state when present.
- Added runtime coverage proving that a ready control-preserving branch outranks a blocked broadened branch and that the shortlist packet keeps the parent queue reference.
