# Phase 3: Safe Live Response - Context

**Gathered:** 2026-04-02
**Status:** Ready for planning

<domain>
## Phase Boundary

Prove one narrow live-response path with deterministic policy, scoped capability leases, and sandboxed execution.

</domain>

<decisions>
## Implementation Decisions

### Policy
- Keep policy single-node and deterministic for v1.
- Policy must be able to deny, authorize, or require human approval.
- Capability leases are short-lived and scoped to the requested action target.

### Response
- Support both dry-run and enforced sandbox execution.
- Normalize response receipts so audit code can consume them without adapter-specific parsing.
- Fail closed when the request is malformed or incompatible with the current runtime mode.

### Claude's Discretion
Exact denial heuristics are flexible as long as they are deterministic and test-covered.

</decisions>

<specifics>
## Specific Ideas

This phase should stay narrow: one trustworthy policy path and one safe adapter matter more than broad action coverage.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Product Direction
- `.planning/ROADMAP.md` - Phase 3 goal and success criteria.
- `.planning/REQUIREMENTS.md` - Policy and response requirement IDs.
- `docs/ARCHITECTURE.md` - Deterministic policy and response lane.

### Existing Code
- `crates/swarm-policy/src/lib.rs` - Existing request, decision, and lease scaffolding.
- `crates/swarm-policy/src/static_gate.rs` - Minimal gate to harden.
- `crates/swarm-response/src/lib.rs` - Executor and receipt contracts.
- `crates/swarm-response/src/adapters.rs` - Sandbox adapter scaffold.
- `crates/swarm-runtime/src/lib.rs` - Authorization and execution flow to harden.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-policy/src/static_gate.rs` - Already models a severity-based human gate.
- `crates/swarm-response/src/adapters.rs` - Already provides a basic sandbox executor.

### Established Patterns
- Policy and response crates already prefer typed structs over free-form maps.
- Runtime tests already exercise dry-run and denied live behavior.

### Integration Points
- `swarm-runtime` is the place where policy decisions turn into executor calls.
- The policy lease contract must flow cleanly into response execution and later audit records.

</code_context>

<deferred>
## Deferred Ideas

BFT or replicated policy authorities are deferred until after the single-node path is proven.

</deferred>

---
*Phase: 03-safe-live-response*
*Context gathered: 2026-04-02*
