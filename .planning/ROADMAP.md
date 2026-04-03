# Milestone v1.9: Verified Evolution Queue

**Status:** COMPLETE
**Date:** 2026-04-03
**Milestone Goal:** Add a proof-backed, operator-controlled evolution queue for detector proposals so verified candidate strategies can be reviewed, deferred, or prepared for later rollout without introducing automatic promotion or quorum governance.

## Overview

This milestone turns the new advisory scoring layer into a durable proposal workflow. The runtime already persists experiment, verification, shadow, canary, production-promotion, strategy-memory, and advisory scorecard artifacts; the next useful step is to assemble those into repo-owned evolution proposals that carry proof-backed safety evidence and explicit review state.

The milestone stays deliberately narrow. It does not add autonomous mutation, quorum approval, or richer HTTP or TUI operator surfaces. The goal is to make candidate detector updates reviewable and durable while keeping deployment decisions explicit and operator-controlled.

## Phase Plan

### Phase 29: Evolution Queue And Proposal Artifacts

**Goal:** Persist repo-owned evolution proposals with stable IDs, lineage, evidence references, and durable review state.

**Requirements:** EVOL-02, EVOL-04

**Depends on:** Phase 28

**Plans:** 1/1 plans complete

**Success Criteria:**
- Verified detector proposals can be written to a durable evolution queue without mutating production detector configuration.
- Queue records persist stable proposal IDs, lineage, verification evidence, and advisory scorecard references in one artifact.
- Operators can reload queued proposal artifacts later without reading raw store files.
- Queue state remains deterministic and repo-owned.

### Phase 30: Proof-Backed Admission Gate

**Goal:** Attach proof-backed safety artifacts to queued proposals and fail closed when required evidence is missing or inconsistent.

**Requirements:** EVOL-01, EVOL-03

**Depends on:** Phase 29

**Plans:** 1/1 plans complete

**Success Criteria:**
- Proposal admission requires proof-backed safety artifacts rather than heuristic summaries alone.
- Queue admission rejects proposals with missing or inconsistent proof, verification, or lineage metadata.
- Blocked proposals preserve explicit denial reasons for later operator review.
- Proof-backed proposal checks remain off the hot path and auditable.

### Phase 31: Operator Queue Review And Decisions

**Goal:** Surface queued proposals, proof status, advisory ranking, and operator decisions through `swarmctl`.

**Requirements:** EVOL-05, EVOL-06, EVOL-07

**Depends on:** Phase 30

**Plans:** 1/1 plans complete

**Success Criteria:**
- Operators can list and reload queued proposals by stable ID, strategy ID, or review state.
- Operators can record explicit queue decisions such as accept for canary, defer, or reject without mutating production detector config directly.
- Queue review output explains proof status, evidence references, and advisory ranking in one operator-readable surface.
- Documentation explains how the evolution queue fits between advisory scoring and any future governance-backed rollout path.

## Traceability

| Requirement | Phase |
|-------------|-------|
| EVOL-01 | Phase 30 |
| EVOL-02 | Phase 29 |
| EVOL-03 | Phase 30 |
| EVOL-04 | Phase 29 |
| EVOL-05 | Phase 31 |
| EVOL-06 | Phase 31 |
| EVOL-07 | Phase 31 |

## Deferred Work

- Quorum-based approval and signed governance receipts remain deferred until independent trust boundaries exist.
- Multi-node or partial-fleet rollout remains out of scope while the runtime is still single-node.
- Authenticated HTTP or TUI operator surfaces remain secondary to the repo-owned CLI and durable artifact flow.
- Automatic mutation, automatic selection, and automatic promotion remain future work after a verified queue proves useful.

## Next Step

`$gsd-new-milestone`

---
*Roadmap created: 2026-04-03*
*Last updated: 2026-04-03 after milestone v1.9 completion*
