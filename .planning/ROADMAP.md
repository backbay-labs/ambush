# Roadmap: Swarm Team Six

**Created:** 2026-04-03
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## Milestone v1.1: Durability And Operators

**Milestone Goal:** Make the shipped single-node Rust lane durable and operator-usable without expanding the architecture prematurely.

## Summary

**3 phases** | **11 v1.1 requirements mapped** | All covered ✓

| # | Phase | Goal | Requirements | Success Criteria | Status |
|---|-------|------|--------------|------------------|--------|
| 5 | Durable Substrate | Add persistent substrate selection, recovery, and durability gating without changing hot-path contracts | CFG-04, DUR-01, DUR-02, DUR-03, DUR-04 | 4 | Planned |
| 6 | Persistent Audit And Replay | Persist decision artifacts and support offline retrieval and replay by stable identifiers | AUD-03, AUD-04, AUD-05 | 4 | Planned |
| 7 | Operator Visibility | Expose runtime health, metrics, and cross-artifact correlation for operators | OPS-03, OPS-04, OPS-05 | 4 | Planned |

## Phase Details

### Phase 5: Durable Substrate

**Goal:** Add persistent substrate selection, recovery, and durability gating without changing the hot-path contract.
**Status:** Planned

**Requirements:** CFG-04, DUR-01, DUR-02, DUR-03, DUR-04

**Success criteria:**
1. Runtime can load durable substrate configuration and select in-memory or JetStream-backed substrate at startup.
2. Detector and policy code continue to depend only on the substrate trait while deposits land in the configured backend.
3. Restarting the runtime in durable mode preserves recent pheromone state and supports query by threat class and recency.
4. `live_response` fails closed when durable substrate readiness is required but unavailable.

### Phase 6: Persistent Audit And Replay

**Goal:** Persist decision artifacts and support offline retrieval and replay without re-running live actions.
**Status:** Planned

**Requirements:** AUD-03, AUD-04, AUD-05

**Success criteria:**
1. Detect -> authorize -> execute writes receipt and replay artifacts to a configured durable store.
2. Operators can retrieve persisted bundles by hunt ID or receipt ID after restart.
3. Replay tooling can reconstruct a saved decision flow without re-executing the original live response.
4. Persisted artifacts preserve stable identifiers linking receipt chain, findings, and execution records.

### Phase 7: Operator Visibility

**Goal:** Give operators usable health, performance, and correlation visibility for the durable runtime.
**Status:** Planned

**Requirements:** OPS-03, OPS-04, OPS-05

**Success criteria:**
1. One operator-facing status surface reports runtime mode plus detector, substrate, policy, and response readiness.
2. Metrics expose counters and latency distributions for detect, policy, persist, and response stages.
3. Runtime traces and logs share stable hunt and receipt identifiers with stored artifacts for correlation.
4. Operator workflows document how to inspect status, recent persisted decisions, and degraded durability modes.

## Deferred Work

These remain intentionally outside this milestone:

- async investigation and correlation on the hot path
- distributed governance / quorum approvals
- gossip / CRDT membership
- Python runtime or PyO3 expansion
- offline evolution and adversarial evaluation loops

## Sequencing Rationale

- Phase 5 hardens the substrate boundary before broader persistence work depends on it.
- Phase 6 makes the audit path durable once the underlying storage posture is real.
- Phase 7 turns the durable runtime into something operators can inspect and trust day to day.

---
*Roadmap created: 2026-04-03*
*Last updated: 2026-04-03 after initializing milestone v1.1*
