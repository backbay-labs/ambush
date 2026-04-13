# Phase 210: Degradation Mode State Machine - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 210 turns the isolated failure and restart work from Phases 208-209 into a
runtime-wide operating model. Swarm needs explicit degradation levels that say
what the runtime may still do when dependencies or health signals degrade, and
those transitions must stay bounded, observable, and fail closed.

</domain>

<decisions>
## Implementation Decisions

- Build degradation behavior around repo-owned runtime and health surfaces
  instead of inventing a parallel lifecycle controller outside the ingest and
  control seams.
- Reuse existing health signals such as agent health, heap pressure,
  anti-tamper, substrate readiness, and response-path readiness before adding
  any new runtime-wide trigger source.
- Keep Phase 210 focused on the state machine, transition rules, and operator
  visibility; end-to-end failure-scenario proof remains Phase 211 work.

</decisions>

<code_context>
## Existing Code Insights

- Phase 208 now isolates panics per agent tick, and Phase 209 restarts only the
  failed agent, but the runtime still exposes one broad runtime mode without a
  bounded degraded-state ladder.
- `crates/swarm-runtime/src/ingest/health.rs` and `crates/swarm-runtime/src/control.rs`
  already surface readiness and runtime status, which gives Phase 210 a natural
  place to publish degradation level and transition reason.
- `IngestState` already owns runtime health inputs such as startup attestation,
  anti-tamper, async lane status, detector status, bridge health, and current
  mode state, so the degradation evaluator can stay runtime-owned instead of
  scattering logic through individual agents.
- `swarm-core` config already models runtime mode and related safety toggles,
  making it the right seam for any explicit degradation-level contract or
  transition policy knobs that Phase 210 needs.

</code_context>

<deferred>
## Deferred Ideas

- Scenario-driven proof for NATS-down, disk-full, and heap-pressure transitions
  remains Phase 211 work.
- Broader response-path behavior under the new degradation levels remains later
  milestone work once the state machine itself is stable.

</deferred>
