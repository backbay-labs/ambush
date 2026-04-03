# Roadmap: Swarm Team Six

**Created:** 2026-04-03
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## Milestone v1.2: Async Investigation And Correlation

**Milestone Goal:** Add async investigation and incident correlation on top of the durable runtime without weakening the hot path or over-expanding the architecture.

## Summary

**3 phases** | **7 v1.2 requirements mapped** | All covered ✓

- [x] **Phase 8: Async Investigation Pipeline** (completed 2026-04-03)
- [x] **Phase 9: Correlation And Incident Assembly** (completed 2026-04-03)
- [ ] **Phase 10: Operator Review Surfaces**

| # | Phase | Goal | Requirements | Success Criteria | Status |
|---|-------|------|--------------|------------------|--------|
| 8 | Async Investigation Pipeline | Add a background investigation lane that enriches prior findings without delaying the original decision path | INV-01, INV-02, INV-03 | 4 | Complete (2026-04-03) |
| 9 | Correlation And Incident Assembly | Group related findings and investigation bundles into reviewable incidents with explainable inclusion logic | COR-01, COR-02 | 4 | Complete (2026-04-03) |
| 10 | Operator Review Surfaces | Expose investigation and incident context in one operator-facing surface with clear hot-path versus async boundaries | REV-01, REV-02 | 4 | Planned |

## Phase Details

### Phase 8: Async Investigation Pipeline

**Goal:** Add a background investigation lane that enriches prior findings without delaying the original decision path.
**Status:** Complete (2026-04-03)

**Requirements:** INV-01, INV-02, INV-03

**Success criteria:**
1. Detect-only and live-response flows can emit an investigation request and complete the original decision path without waiting for enrichment.
2. Operators can configure investigation enablement, worker count, concurrency, and time budgets through repository-owned config.
3. Investigation outputs persist as durable bundles linked to the originating hunt ID and receipt IDs.
4. Tests prove that investigation failure or timeout degrades to visible async status rather than blocking the hot path.

### Phase 9: Correlation And Incident Assembly

**Goal:** Group related findings and investigation bundles into reviewable incidents with explainable inclusion logic.
**Status:** Complete (2026-04-03)

**Requirements:** COR-01, COR-02

**Success criteria:**
1. Runtime can assemble a correlated incident record from multiple findings and investigation bundles using stable identifiers, time windows, and shared evidence.
2. Correlation output records which inputs were included, which were rejected, and why.
3. Incident records persist across restart and remain linked to the underlying hunts, receipts, and investigation bundles.
4. Tests cover both successful grouping and rejection cases so false merges are visible and bounded.

### Phase 10: Operator Review Surfaces

**Goal:** Expose investigation and incident context in one operator-facing surface with clear hot-path versus async boundaries.
**Status:** Planned

**Requirements:** REV-01, REV-02

**Success criteria:**
1. One operator-facing surface reports investigation queue state, recent job status, summaries, and failure reasons without requiring raw file inspection.
2. Operators can inspect correlated incidents, underlying findings, and linked evidence from that same surface.
3. Hot-path decisions and later async enrichment show distinct timestamps and freshness markers so operators can see what is authoritative versus newly attached context.
4. Operator documentation covers how to review enriched findings, interpret incident membership, and handle degraded investigation states.

## Deferred Work

These remain intentionally outside this milestone:

- async investigation on the hot path
- correlation directly changing automated response policy
- distributed governance / quorum approvals
- gossip / CRDT membership
- Python runtime or PyO3 expansion
- offline evolution and adversarial evaluation loops

## Sequencing Rationale

- Phase 8 creates the async job and bundle model before any higher-level correlation logic depends on it.
- Phase 9 assembles incidents only after the runtime can produce durable investigation outputs.
- Phase 10 turns the new enrichment and incident layers into something operators can review without ambiguity.

---
*Roadmap created: 2026-04-03*
*Last updated: 2026-04-03 for milestone v1.2 initialization*
