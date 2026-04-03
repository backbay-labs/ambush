# Milestone v1.8: Production Memory And Strategy Scoring

**Status:** NOT STARTED
**Date:** 2026-04-03
**Milestone Goal:** Add durable strategy-memory records, context-aware utility scoring, and operator advisory scorecards from real rollout history without introducing automatic promotion or quorum governance.

## Overview

This milestone turns the completed rollout ladder into a memory source. The runtime already persists experiment, verification, shadow, canary, and production-promotion artifacts; the next useful step is to derive durable per-strategy memories from that evidence and use them to score verified detectors with real deployment history.

The milestone stays deliberately narrow. It does not add distributed governance, automatic promotion, or multi-user control surfaces. The goal is to make detector choice more informed and explainable while keeping the runtime single-node, CLI-first, and operator-controlled.

## Phase Plan

### Phase 26: Strategy Outcome Memory

**Goal:** Turn completed canary and production-promotion artifacts into durable strategy-memory records with stable history lookup.

**Requirements:** MEM-01, MEM-02

**Depends on:** Phase 22, Phase 25

**Plans:** 0/1 plans complete

**Success Criteria:**
- Completed canary and production-promotion artifacts can be converted into strategy-memory records without rerunning detector workflows.
- Strategy-memory records persist stable IDs plus strategy lineage and source-artifact references.
- Operators can reload strategy-memory history by memory ID or strategy ID through `swarmctl`.
- Memory extraction remains deterministic and reuses persisted rollout artifacts only.

### Phase 27: Context-Aware Utility Scoring

**Goal:** Compute deterministic advisory utility scores from strategy memories with replay-fitness fallback and explicit score explanations.

**Requirements:** MEM-03, MEM-04, MEM-05

**Depends on:** Phase 26

**Plans:** 0/1 plans complete

**Success Criteria:**
- Utility scoring works when live history is sparse by falling back to replay fitness instead of failing open.
- Score computation uses explicit outcome weighting, recency decay, and context matching over persisted memories.
- Score output preserves the evidence and weighting that produced the final ranking.
- Memory-backed scores remain advisory and cannot by themselves mutate or promote production detector configuration.

### Phase 28: Strategy Review And Advisory Selection

**Goal:** Surface strategy memory histories and scorecards through `swarmctl` for operator review of the production baseline versus verified candidates.

**Requirements:** MEM-06, MEM-07

**Depends on:** Phase 27

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can assemble a strategy scorecard that compares the current production baseline and verified candidates from stable IDs.
- Scorecards link memory summaries, rollout lineage, and current promotion state in one durable artifact.
- `swarmctl` can reload memory-backed recommendations and score breakdowns by stable ID or strategy ID.
- Documentation explains how advisory scoring fits the rollout ladder without widening governance boundaries.

## Traceability

| Requirement | Phase |
|-------------|-------|
| MEM-01 | Phase 26 |
| MEM-02 | Phase 26 |
| MEM-03 | Phase 27 |
| MEM-04 | Phase 27 |
| MEM-05 | Phase 27 |
| MEM-06 | Phase 28 |
| MEM-07 | Phase 28 |

## Deferred Work

- Quorum-based promotion approval and signed consensus receipts remain deferred until independent trust boundaries exist.
- Multi-node or partial-fleet production rollout remains out of scope while the runtime is still single-node.
- Authenticated HTTP or TUI operator surfaces remain secondary to the repo-owned CLI and durable artifact flow.
- Proof-backed evolution queues and autonomous detector mutation remain future work after advisory scoring proves useful.

## Next Step

`$gsd-plan-phase 26`

---
*Roadmap created: 2026-04-03*
*Last updated: 2026-04-03 after milestone v1.8 initialization*
