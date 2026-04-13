# Phase 209: Agent Health-Driven Restart - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 209 turns the new per-agent panic boundary into a real lifecycle action:
when one runtime agent repeatedly fails or remains failed, Swarm should restart
only that agent without restarting the dispatcher task or the whole process.
The restart path must preserve the rest of the swarm and keep health reporting
honest for operators.

</domain>

<decisions>
## Implementation Decisions

- Build restart behavior around the dispatcher-owned registry and health state
  rather than introducing a second lifecycle loop beside the dispatcher.
- Reuse the existing startup registration contract in `swarm_detect` so
  restarted agents are recreated with the same persisted identities and role-
  specific dependencies they use at process start.
- Keep restart scope bounded to individual agents; runtime-wide degradation
  transitions remain Phase 210 work.

</decisions>

<code_context>
## Existing Code Insights

- Phase 208 now catches agent panics inside `AgentDispatcher::tick_agents` and
  marks only the crashing agent degraded, but there is no restart path yet.
- `AgentDispatcher` already owns registration, deregistration, and effective
  health overrides for each `AgentId`, which gives Phase 209 the natural seam
  for targeted restart.
- `swarm_detect` still constructs every agent inline at startup with role-
  specific dependencies and persisted identities, so Phase 209 needs a
  reusable construction path instead of duplicating agent wiring logic in two
  places.
- Health surfaces already distinguish `healthy`, `degraded`, and `failed`
  counts from the dispatcher snapshot, so restart activity can build on that
  existing operator-facing contract.

</code_context>

<deferred>
## Deferred Ideas

- Global degradation mode transitions remain Phase 210 work.
- End-to-end degradation scenario proof remains Phase 211 work.

</deferred>
