# Milestone v1.11: Proposal Drafting And Selection Pressure

**Status:** NOT STARTED
**Date:** 2026-04-03
**Milestone Goal:** Derive proposal drafts from replay regressions, verification drift, and strategy-memory evidence, then let operators promote those drafts into the reviewed queue without introducing automatic enqueue or launch.

## Overview

This milestone turns the now-complete queue and handoff ladder back upstream. The runtime already persists replay regressions, verification artifacts, rollout memories, reviewed proposals, handoff packets, and canary runs; the next useful step is to derive durable draft proposals from the evidence that currently only operators synthesize manually.

The milestone stays deliberately narrow. It does not add automatic mutation, automatic queue promotion, automatic canary launch, quorum approval, or richer HTTP or TUI operator surfaces. The goal is to make proposal drafting evidence-driven while keeping enqueue and rollout decisions explicit and operator-controlled.

## Phase Plan

### Phase 35: Selection Pressure Signals

**Goal:** Derive durable selection-pressure reports from replay regressions, verification drift, and strategy-memory gaps.

**Requirements:** DRAFT-01, DRAFT-02

**Depends on:** Phase 34

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can materialize a durable pressure report from existing replay, verification, or memory artifacts.
- Pressure reports preserve stable IDs, source evidence references, and explicit rationale for why new detector work is warranted.
- Pressure analysis remains off the hot path and operator-inspectable.
- The pressure lane stays repo-owned and CLI-first.

### Phase 36: Proposal Draft Artifacts

**Goal:** Persist draft proposal artifacts derived from selection-pressure reports without auto-enqueuing them.

**Requirements:** DRAFT-03

**Depends on:** Phase 35

**Plans:** 0/1 plans complete

**Success Criteria:**
- Draft proposal artifacts preserve stable IDs, pressure-report references, rationale, and candidate lineage hints.
- Draft creation does not create a reviewed queue proposal automatically.
- Operators can reload draft artifacts later without reading raw store files.
- Draft packaging remains deterministic and auditable.

### Phase 37: Draft Review And Queue Promotion

**Goal:** Let operators inspect one draft and promote it into the reviewed evolution queue through `swarmctl`.

**Requirements:** DRAFT-04, DRAFT-05

**Depends on:** Phase 36

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can reload draft artifacts by stable ID and explicitly promote one into the reviewed queue.
- Draft promotion preserves the originating pressure-report reference, operator reason, and resulting queue proposal reference in one durable record.
- Draft promotion remains operator-triggered and does not auto-launch handoff or canary.
- Documentation explains how draft generation fits ahead of reviewed queue entry.

## Traceability

| Requirement | Phase |
|-------------|-------|
| DRAFT-01 | Phase 35 |
| DRAFT-02 | Phase 35 |
| DRAFT-03 | Phase 36 |
| DRAFT-04 | Phase 37 |
| DRAFT-05 | Phase 37 |

## Deferred Work

- Quorum-based approval and signed governance receipts remain deferred until independent trust boundaries exist.
- Multi-node or partial-fleet rollout remains out of scope while the runtime is still single-node.
- Authenticated HTTP or TUI operator surfaces remain secondary to the repo-owned CLI and durable artifact flow.
- Automatic mutation, automatic draft enqueue, and automatic launch remain future work after draft generation proves useful.

## Next Step

`$gsd-plan-phase 35`

---
*Roadmap created: 2026-04-03*
*Last updated: 2026-04-03 after milestone v1.11 creation*
