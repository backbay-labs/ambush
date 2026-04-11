# Phase 156: Chaos And Resilience Testing - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 156 validates the distributed-governance stack under adversarial conditions. The work spans Byzantine message injection, partition simulation, lease-expiry proof, and cascading-failure replay against the multi-instance governance path that Phases 153 through 155 just established.

</domain>

<decisions>
## Implementation Decisions

- Reuse the in-process consensus and runtime harnesses from Phases 153 through 155 instead of creating a second chaos-only protocol model.
- Keep the phase verification-heavy: add only the minimum harness seams needed to inject Byzantine or partition behavior and prove safety properties on the existing runtime path.
- Prefer deterministic replay and persisted runtime artifacts over probabilistic soak tests so the milestone can be rerun reliably in CI and milestone closeout.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-consensus/src/lib.rs` already has the three-node harness and signed-message validation seams needed for equivocation, delay, and invalid-signature injection.
- `crates/swarm-runtime/src/tom_agent.rs` and `crates/swarm-runtime/src/dispatcher.rs` now own the partition state machine, contingency lease issuance, redemption, and reconciliation, so partition chaos should target those seams directly instead of mocking authority outside the runtime.
- `crates/swarm-runtime/tests/dispatch_integration.rs` already proves partition fail-closed routing and valid lease redemption, which is the right starting point for expiry and multi-step healing scenarios.
- The existing runtime integration suites already exercise end-to-end agent and response flows, so cascading-failure proof should build on those deterministic seams rather than inventing a parallel test runtime.

</code_context>

<deferred>
## Deferred Ideas

- Cross-region consensus transport tuning and large-cluster performance are not Phase 156 work.
- The next milestone still owns deception and detection-breadth expansion; this phase stays focused on governance correctness and resilience.

</deferred>
