# Phase 2: Fast Detection Lane - Context

**Gathered:** 2026-04-02
**Status:** Ready for planning

<domain>
## Phase Boundary

Ship one concrete detector, a normalized Rust telemetry input, and an in-memory pheromone substrate with measurable performance.

</domain>

<decisions>
## Implementation Decisions

### Detector Shape
- Implement one concrete detector only for v1.
- Normalize telemetry at the Rust runtime boundary before evaluation.
- Emit structured findings with typed threat class, severity, confidence, and evidence.

### Substrate Shape
- Build an in-memory substrate first.
- Preserve decay and source-diversity semantics in the substrate contract.
- Retain recent deposits so the runtime can replay or inspect them without JetStream.

### Claude's Discretion
Exact detector heuristic and benchmark implementation are flexible as long as the critical path stays single-process and Rust-only.

</decisions>

<specifics>
## Specific Ideas

Fast detection matters more than cleverness. One reliable detector and measurable latency numbers are enough for this phase.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Product Direction
- `.planning/ROADMAP.md` - Phase 2 goal and success criteria.
- `.planning/REQUIREMENTS.md` - Detection and substrate requirement IDs.
- `docs/ARCHITECTURE.md` - Critical lane boundaries.

### Existing Code
- `crates/swarm-whisker/src/detector.rs` - Existing telemetry and match types to harden.
- `crates/swarm-whisker/src/stream.rs` - Stream runtime stub.
- `crates/swarm-pheromone/src/substrate.rs` - Substrate stub.
- `crates/swarm-core/src/pheromone.rs` - Decay and concentration primitives.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-core/src/pheromone.rs` - Already contains decay math and concentration semantics.
- `crates/swarm-whisker/src/detector.rs` - Already defines telemetry and finding shapes.

### Established Patterns
- The runtime uses narrow typed structs and local unit tests with synthetic payloads.
- Hot-path crates are intentionally free of Python or network dependencies.

### Integration Points
- `swarm-whisker` should output findings that map directly into pheromone deposits.
- `swarm-runtime` will later compose detector and substrate behavior into one service.

</code_context>

<deferred>
## Deferred Ideas

JetStream-backed durability is deferred until the in-memory contract is stable.

</deferred>

---
*Phase: 02-fast-detection-lane*
*Context gathered: 2026-04-02*
