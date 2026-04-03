# Milestone v1.6: Bounded Canary And Rollback

**Status:** READY
**Date:** 2026-04-03
**Milestone Goal:** Add a bounded live canary lane for verified candidate detectors with live observation metrics, rollback, and canary review artifacts, without introducing fleet-wide promotion or quorum governance.

## Overview

This milestone extends the staged deployment pipeline from offline shadow into bounded live exposure. It introduces a scoped canary slot for verified candidate detectors, records live canary metrics over a controlled observation window, and makes rollback a first-class behavior instead of a future assumption.

The milestone stays narrow by design. It does not attempt fleet-wide production promotion, distributed approvals, or adaptive strategy selection in the hot path. The goal is to prove that candidate detectors can be exercised in a bounded live lane with clear rollback semantics and inspectable evidence.

## Phase Plan

### Phase 20: Canary Slot And Strategy Assignment

**Goal:** Define how a verified candidate detector is registered, scoped, and attached to a bounded canary slot without replacing the production baseline.

**Requirements:** CAN-01

**Depends on:** Phase 17, Phase 18, Phase 19

**Plans:** 0/1 plans complete

**Success Criteria:**
- Verified candidate detectors can be referenced as deployable canary inputs by stable ID or manifest.
- The runtime can attach one candidate detector to a bounded canary slot while preserving the baseline detector as production.
- Canary slot configuration is explicit, repo-owned, and reloadable after restart.
- Documentation and tests show that canary assignment does not mutate fleet-wide production configuration.

### Phase 21: Bounded Canary Execution And Metrics

**Goal:** Run the assigned candidate detector in a live but scoped canary lane and persist observation metrics over the canary window.

**Requirements:** CAN-02, CAN-03

**Depends on:** Phase 20

**Plans:** 0/1 plans complete

**Success Criteria:**
- Canary execution emits live detections only from the scoped canary lane.
- Source-diversity and escalation semantics prevent a single canary from driving fleet-wide mode transitions on its own.
- The runtime records detection, false-positive, latency, and resource metrics for the canary window.
- Operator CLI can inspect current canary metrics without reading raw storage files.

### Phase 22: Rollback And Canary Review

**Goal:** Turn rollback and canary review into durable operator workflows with stable artifacts and explicit recommendations.

**Requirements:** RLB-01, RLB-02, PRM-03, PRM-04

**Depends on:** Phase 21

**Plans:** 0/1 plans complete

**Success Criteria:**
- Canary runs automatically roll back when configured thresholds or budgets are violated.
- Operators can manually halt or roll back a canary and inspect the precise reason and reverted baseline.
- Canary review artifacts persist verification, shadow, and canary evidence into one recommendation surface.
- Operator CLI can reload active or completed canary runs, rollback history, and canary review packets by stable ID.

## Traceability

| Requirement | Phase |
|-------------|-------|
| CAN-01 | Phase 20 |
| CAN-02 | Phase 21 |
| CAN-03 | Phase 21 |
| RLB-01 | Phase 22 |
| RLB-02 | Phase 22 |
| PRM-03 | Phase 22 |
| PRM-04 | Phase 22 |

## Deferred Work

- Fleet-wide production promotion remains out of scope for this milestone.
- Quorum-based or BFT promotion approval remains deferred until real independent trust boundaries exist.
- Adaptive MemRL-based strategy selection remains future work after bounded canary execution is real.
- Multi-user control planes and authenticated operator surfaces remain secondary to canary safety and rollback.

## Next Step

`$gsd-plan-phase 20`

---
*Roadmap created: 2026-04-03*
*Last updated: 2026-04-03 for milestone v1.6*
