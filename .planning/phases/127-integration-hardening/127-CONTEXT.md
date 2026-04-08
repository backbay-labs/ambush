# Phase 127: Integration Hardening - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 127 is the milestone closeout proof phase for v1.39. It does not add new autonomous-response features; it proves that the Phase 124-126 seams work together under dispatcher-backed execution, policy gating, governance veto, de-escalation cooldown, and durable audit output. The owned deliverable is deterministic integration coverage for the seven correctness pitfalls called out in the roadmap, plus green workspace test and clippy validation after all v1.39 changes land.

</domain>

<decisions>
## Implementation Decisions

### End-To-End Proof Strategy
- Phase-owned proof should be centralized in a dedicated v1.39 integration surface under `crates/swarm-runtime/tests/`, not scattered across unrelated unit files.
- The integration harness should exercise the real `AgentDispatcher::tick_once()` plus runtime-backed routing wherever the pitfall is about ordering across dispatcher, policy, governance, and receipts.
- Each pitfall needs an exact-test proof point with a stable, grep-able name so future regressions can target one behavior without rerunning the full suite.
- Workspace verification is part of the phase contract, not cleanup after the fact: `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` are required closeout gates.

### Reuse Over New Seams
- Reuse the existing counting approval/executor/router patterns from `dispatch_integration.rs` and the deposit/playbook fixtures from `pounceagent_integration.rs` instead of adding production-only testing seams.
- Existing lower-level phase tests stay in place as local guards; Phase 127 adds combined proofs that show the seams compose correctly across Phases 124-126.
- Minor test-helper extraction is acceptable if it reduces duplication, but the phase should stay test-focused and avoid widening runtime API surface unless a real integration gap forces it.
- Deterministic timestamps, in-memory substrate state, and repo-owned config fixtures should drive the new proofs; no network-only or timing-fragile validation should be introduced.

### Pitfall Coverage
- The seven milestone pitfalls to prove together are: no double-trigger, synchronous governance veto, fail-closed policy rules, TOCTOU-safe lease expiry, flap-resistant de-escalation, dry-run parity, and audit lineage preservation.
- No-double-trigger must be proven at the routed execution layer by counting runtime routing or executor calls, not only by asserting that agent-local action vectors are empty on a second tick.
- Dry-run parity and audit lineage should be proven through the same routed runtime path that live execution uses, so receipt/audit fields and execution mode stay coupled in the proof.
- Fail-closed policy should use the real configurable gate path with an empty ruleset or equivalent repo-owned config, not a mocked `PolicyDecision`.

### Claude's Discretion
- Whether the new proofs live in one dedicated `integration_hardening` file or a small pair of closely related integration files, as long as the phase-owned coverage is centralized and obvious.
- Whether the reusable counting helpers remain local to the new suite or move into test support, as long as the resulting tests stay readable and exact-test-friendly.
- The exact latency headroom of the repo-owned `office_detector_safety_v1` verification corpus, as long as it stays aligned with the current debug-test runtime envelope and does not spuriously block proof-backed workflow artifacts.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-runtime/tests/dispatch_integration.rs` already contains runtime-backed router, counting approval gate, counting executor, and dispatcher-driven request/veto helpers that can be reused for full-path pitfall proofs.
- `crates/swarm-runtime/tests/pounceagent_integration.rs` already contains deterministic `PheromoneDeposit` builders, playbook fixtures, and PounceAgent-oriented escalation scenarios.
- `crates/swarm-runtime/tests/escalation_integration.rs` already proves cooldown-driven de-escalation and provides the existing integration home for concentration-monitor behavior.
- `crates/swarm-runtime/src/dispatcher.rs` exposes `tick_once()` and the request/veto routing seam, which is the cleanest entry point for end-to-end v1.39 tests.

### Established Patterns
- Phase-level proof files use exact integration-test names to pin one observable truth per risk area, while lower-level unit tests stay in their owning modules.
- Test harnesses prefer in-memory substrate/config state plus repo-owned YAML fixtures over bespoke mocks when the behavior depends on serialized config or canonical runtime construction.
- Dispatcher tests and integration tests already count runtime calls directly with `AtomicUsize`, which is the right proof style for double-trigger and veto assertions.
- Audit correctness is already asserted through typed `AuditTrail` and `ResponseReceipt.audit` fields rather than string matching log output.

### Integration Points
- `crates/swarm-runtime/tests/dispatch_integration.rs` is the natural source of routing helpers and receipt/audit assertions.
- `crates/swarm-runtime/tests/pounceagent_integration.rs` is the natural source of escalation deposits, playbook selection inputs, and same-session PounceAgent behavior.
- `crates/swarm-runtime/tests/escalation_integration.rs` or a new phase-owned suite must cover the burst-decay-burst de-escalation pitfall without duplicating unrelated escalation proofs.
- `verifications/office-detector-safety-v1.yaml` remains part of the milestone validation surface because proof-backed evolution and queue flows depend on that canonical verification artifact staying green.

</code_context>

<specifics>
## Specific Ideas

- Prefer one phase-owned integration suite that names the v1.39 pitfalls explicitly rather than extending unrelated files with opaque test names.
- Keep the dry-run parity and audit-lineage proof close together because both depend on the same routed request evidence and receipt path.
- Use a real PounceAgent plus dispatcher tick cycle for the no-double-trigger proof so the test validates the phase goal, not just internal helper behavior.
- Treat the `office_detector_safety_v1` latency-budget alignment as part of milestone hardening, not a detached fixture tweak, because it directly affects proof-backed workflow stability.

</specifics>

<deferred>
## Deferred Ideas

- Demo/operator-surface visualization of the new pitfall proofs belongs to v1.40, not this milestone closeout phase.
- Any new policy semantics, expanded governance logic, or adaptive playbook behavior remain out of scope; Phase 127 verifies existing behavior rather than widening it.
- Distributed or multi-node validation remains deferred until the roadmap reaches real quorum/governance work.

</deferred>
