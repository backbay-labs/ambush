# Roadmap: Swarm Team Six

**Created:** 2026-04-02
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## Summary

**4 phases** | **20 v1 requirements mapped** | All v1 requirements covered ✓

| # | Phase | Goal | Requirements | Success Criteria | Status |
|---|-------|------|--------------|------------------|--------|
| 1 | Baseline Contracts | Lock configuration and runtime contracts so the core lane can be built without churn | CFG-01, CFG-02, CFG-03 | 3 | Complete (2026-04-03) |
| 2 | Fast Detection Lane | Ship one benchmarked Rust detector and in-memory pheromone substrate | DET-01, DET-02, DET-03, DET-04, SUB-01, SUB-02, SUB-03 | 4 | In progress |
| 3 | Safe Live Response | Add deterministic policy, scoped capability leases, and sandboxed response execution | POL-01, POL-02, POL-03, RSP-01, RSP-02, RSP-03 | 4 | Planned |
| 4 | Audit And Hardening | Make the critical path observable, testable, and replayable | AUD-01, AUD-02, OPS-01, OPS-02 | 4 | Planned |

## Phase Details

### Phase 1: Baseline Contracts

**Goal:** Replace doc-only assumptions with strict configuration and runtime-owned contracts.
**Status:** Complete (2026-04-03)

**Requirements:** CFG-01, CFG-02, CFG-03

**Success criteria:**
1. Runtime can load repository-owned config files into typed Rust structures.
2. Invalid or unknown config fields fail at load time with actionable errors.
3. Runtime mode is explicit and test-covered for `detect_only` and `live_response`.

### Phase 2: Fast Detection Lane

**Goal:** Ship a real Rust detector path that turns telemetry into pheromone deposits with published measurements.

**Requirements:** DET-01, DET-02, DET-03, DET-04, SUB-01, SUB-02, SUB-03

**Success criteria:**
1. A normalized telemetry event can enter the Rust runtime and be evaluated by a concrete detector.
2. Detector output includes threat class, severity, confidence, and evidence.
3. Findings can be deposited into and queried from an in-memory pheromone substrate with decay and source-diversity semantics.
4. Benchmark artifacts publish p50, p95, p99, and throughput numbers for the detector path.

### Phase 3: Safe Live Response

**Goal:** Prove a narrow live-response path without requiring distributed governance.

**Requirements:** POL-01, POL-02, POL-03, RSP-01, RSP-02, RSP-03

**Success criteria:**
1. Response proposals are evaluated through a deterministic Rust policy gate.
2. Policy results can deny, authorize, or require human approval based on action and severity.
3. Authorized actions receive scoped capability leases before execution.
4. The runtime supports dry-run and at least one sandboxed enforced response adapter with normalized receipts.

### Phase 4: Audit And Hardening

**Goal:** Make the critical path trustworthy through observability, replay, and end-to-end verification.

**Requirements:** AUD-01, AUD-02, OPS-01, OPS-02

**Success criteria:**
1. The system records an auditable receipt trail spanning detection, policy, and response.
2. Operators can replay a detect -> authorize -> execute flow from saved artifacts.
3. Structured traces or logs make latency and decision paths inspectable.
4. Integration tests cover the critical path from telemetry ingest to receipt creation.

## Deferred Work

These are intentionally excluded from the first roadmap:

- investigation and correlation on the hot path
- JetStream-backed durability as a prerequisite for Phase 1
- BFT / VRF governance
- gossip / CRDT membership
- live co-evolution and broader red-team runtime loops

## Sequencing Rationale

- Phase 1 removes contract churn risk before detector work begins.
- Phase 2 proves the product’s first non-negotiable claim: fast detection.
- Phase 3 adds controlled live response only after findings are real.
- Phase 4 hardens observability and replay so the system can be trusted operationally.

---
*Roadmap created: 2026-04-02*
*Last updated: 2026-04-03 after Phase 1 completion*
