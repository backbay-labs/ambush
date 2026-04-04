# Milestone v1.12: Draft Materialization And Validation Bundles

**Status:** NOT STARTED
**Date:** 2026-04-03
**Milestone Goal:** Turn reviewed draft proposals into materialized candidate artifacts plus refreshed validation bundles, then reconnect them to the existing verified rollout ladder without hand-editing or duplicate queue state.

## Overview

This milestone closes the gap exposed by `v1.11`. The runtime can already derive pressure, package drafts, promote drafts into the reviewed queue, and run proof-backed rollout flows for verified candidates, but the draft-backed queue entries still stop short of materialized experiment and evidence artifacts. The next useful step is to make that bridge repo-owned and durable.

The milestone stays deliberately narrow. It does not add automatic mutation, automatic validation refresh, automatic canary launch, quorum approval, or richer HTTP or TUI operator surfaces. The goal is to remove manual artifact translation between draft review and the verified rollout ladder while keeping every stage explicit and operator-controlled.

## Phase Plan

### Phase 38: Draft Candidate Materialization

**Goal:** Materialize durable candidate experiment artifacts from one stable draft without hand-editing repo manifests.

**Requirements:** MTRL-01, MTRL-02

**Depends on:** Phase 37

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can materialize a repo-owned detector experiment manifest from one draft artifact through `swarmctl`.
- Materialized candidate artifacts preserve draft ID, pressure ID, lineage, strategy hint, and rationale in one durable record.
- Operators can reload materialized candidate artifacts later without reading raw store files.
- Candidate materialization remains off the hot path and CLI-first.

### Phase 39: Validation Bundle Refresh

**Goal:** Refresh experiment evaluation, verification, proof, and shadow artifacts from one materialized candidate.

**Requirements:** VALD-01, VALD-02

**Depends on:** Phase 38

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can run one repo-owned CLI flow that refreshes experiment, verification, proof, and shadow artifacts from a materialized candidate.
- Validation refresh preserves stable IDs linking the materialized candidate to all refreshed evidence artifacts.
- Refresh fails closed when lineage, manifest digests, or refreshed evidence become inconsistent.
- Refreshed evidence remains auditable and separate from live rollout mutation.

### Phase 40: Queue Reconciliation And Handoff Readiness

**Goal:** Reconcile draft-backed queue entries with materialized candidate and refreshed evidence so the existing handoff and canary path can use them.

**Requirements:** RECN-01, RECN-02

**Depends on:** Phase 39

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can reconcile one draft-backed queue entry with its materialized experiment and refreshed evidence without ambiguous duplicate rollout state.
- Reconciliation preserves draft-promotion lineage, operator intent, and refreshed evidence references in one durable record.
- Reconciled queue entries become eligible for the existing handoff and canary path only when refreshed evidence passes.
- Documentation explains how draft materialization reconnects to the verified queue and rollout ladder.

## Traceability

| Requirement | Phase |
|-------------|-------|
| MTRL-01 | Phase 38 |
| MTRL-02 | Phase 38 |
| VALD-01 | Phase 39 |
| VALD-02 | Phase 39 |
| RECN-01 | Phase 40 |
| RECN-02 | Phase 40 |

## Deferred Work

- Quorum-based approval and signed governance receipts remain deferred until independent trust boundaries exist.
- Authenticated HTTP or TUI operator surfaces remain secondary to the repo-owned CLI and durable artifact flow.
- Automatic detector mutation, automatic draft promotion, and automatic rollout remain future work after draft materialization proves useful.
- Multi-node or partial-fleet rollout remains out of scope while the runtime is still single-node.

## Next Step

`$gsd-plan-phase 38`

---
*Roadmap created: 2026-04-03*
*Last updated: 2026-04-03 after milestone v1.12 creation*
