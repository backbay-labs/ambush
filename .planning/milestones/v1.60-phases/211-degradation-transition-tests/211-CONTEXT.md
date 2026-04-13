# Phase 211: Degradation Transition Tests - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 211 proves the Phase 210 degradation ladder under bounded failure
scenarios. The goal is scenario-driven verification of the shipped state machine
 rather than widening the degradation contract itself.

</domain>

<decisions>
## Implementation Decisions

- Reuse repo-owned runtime harnesses and health surfaces instead of adding a new
  shadow test controller for degradation behavior.
- Prove each required transition through bounded failure injection at the
  existing seams: substrate unavailable, replay-store write-path failure, and
  heap-pressure drain.
- Assert degradation outcomes through operator-visible health or status
  contracts, not through private helper output alone.

</decisions>

<code_context>
## Existing Code Insights

- Phase 210 added a shared `RuntimeDegradationStatus` contract plus live
  evaluation in `IngestState`, so the remaining work is scenario proof rather
  than new state-machine design.
- `crates/swarm-runtime/src/ingest/tests.rs` already owns repo-local health and
  ingest harnesses that can force detector, attestation, anti-tamper, and heap
  conditions without standing up the full runtime process.
- The repo already ships real substrate harness work from v1.55, which gives
  Phase 211 a natural path for a bounded NATS-unreachable proof without
  inventing a second infrastructure story.

</code_context>

<deferred>
## Deferred Ideas

- Automatic hysteresis or cooldown for degradation recovery remains later work
  once the failure-transition proof is stable.
- Broader response-path behavior changes under degraded levels remain outside
  this phase unless required by the end-to-end proofs.

</deferred>
