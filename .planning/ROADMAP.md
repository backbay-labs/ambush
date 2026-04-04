# Milestone v1.15: Cross-Batch Portfolio And Governance Prep

**Status:** READY FOR PLANNING
**Date:** 2026-04-04
**Milestone Goal:** Turn single-ranked-candidate re-entry into cross-batch portfolio review and governance-ready packet preparation without implementing distributed governance.

## Overview

`v1.14` closed the continuity gap from one ranked review packet back into the existing queue, handoff, and canary path. The runtime can now select one ranked candidate, review it explicitly, and bridge it back into rollout without re-materializing evidence.

The next useful step is to widen that review seam without widening autonomy. `v1.15` focuses on portfolio-level comparison across multiple ranked batches or cohorts, explicit operator curation over that portfolio, and governance-ready packet generation that preserves evidence for a future trust-boundary lane. This milestone stays CLI-first, artifact-first, and fail-closed.

## Phase Plan

### Phase 47: Cross-Batch Portfolio Assembly

**Status:** READY

**Goal:** Assemble durable portfolio artifacts from ranked selections spanning multiple mutation batches or campaign cohorts.

**Requirements:** EVOL-24, EVOL-25

**Depends on:** Phase 46

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can create one durable portfolio artifact from multiple ranked selections through `swarmctl`.
- Portfolio entries preserve source ranking, selection, batch, and cohort references in one stable record.
- Portfolio assembly remains operator-triggered and does not mutate queue, canary, or production state.
- Portfolio artifacts are reloadable later without reading raw storage files.

### Phase 48: Portfolio Review And Curation

**Status:** READY

**Goal:** Add explicit operator curation decisions over portfolio entries while preserving immutable upstream evidence.

**Requirements:** EVOL-26, EVOL-27

**Depends on:** Phase 47

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can list and inspect portfolio artifacts and their entries by stable ID through `swarmctl`.
- Operators can record include, defer, or drop decisions for individual portfolio candidates without rewriting selection or ranking evidence.
- Portfolio review artifacts preserve operator reason, source lineage, and current curation state in one durable record.
- Curation remains advisory until a later governance-prep packet is explicitly created.

### Phase 49: Governance-Ready Review Packets

**Status:** READY

**Goal:** Generate governance-ready review packets from curated portfolio entries using preserved evidence references instead of re-encoding artifacts.

**Requirements:** EVOL-23, EVOL-28, EVOL-29

**Depends on:** Phase 48

**Plans:** 0/1 plans complete

**Success Criteria:**
- Curated portfolio entries can create durable governance-ready review packets through `swarmctl`.
- Review packets preserve ranking, selection, portfolio, experiment, validation, proof, advisory, and rollout-lineage references for future trust-boundary work.
- Stale, blocked, or inconsistent portfolio entries fail closed and persist inspectable blocked packet artifacts.
- Documentation explains how governance-ready packets prepare later trust-boundary work without implementing quorum or multi-node rollout in this cycle.

## Traceability

| Requirement | Phase |
|-------------|-------|
| EVOL-24 | Phase 47 |
| EVOL-25 | Phase 47 |
| EVOL-26 | Phase 48 |
| EVOL-27 | Phase 48 |
| EVOL-23 | Phase 49 |
| EVOL-28 | Phase 49 |
| EVOL-29 | Phase 49 |

## Deferred Work

- Quorum-based approval, signed votes, and durable consensus receipts remain deferred until independent trust boundaries exist.
- Multi-node rollout execution remains out of scope while the runtime stays single-node and repo-owned.
- Automatic portfolio curation, automatic promotion, and automatic rollout remain out of scope for this cycle.
- Authenticated HTTP or TUI operator surfaces remain secondary to the repo-owned CLI and durable artifact flow.

## Next Step

`$gsd-plan-phase 47`

---
*Roadmap created: 2026-04-04*
*Last updated: 2026-04-04 after milestone v1.15 definition*
