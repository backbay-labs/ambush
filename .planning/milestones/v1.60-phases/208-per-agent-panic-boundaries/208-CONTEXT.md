# Phase 208: Per-Agent Panic Boundaries - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 208 contains agent panics to the specific agent boundary. A panic in
Kitten, Tom, Pounce, Calico, or any other registered agent must not terminate
the shared dispatcher task or take the runtime process down with it; the
runtime should degrade only that agent and preserve attributable failure
context for later restart and degradation-mode work.

</domain>

<decisions>
## Implementation Decisions

- Add panic containment at the dispatcher-owned tick boundary instead of
  relying on each agent implementation to remember its own wrapper.
- Preserve the existing typed `AgentTickBoundaryError` contract and extend it
  with panic-owned classification that identifies the crashing agent boundary.
- Defer restart policy and global degradation transitions to Phases 209 and
  210; this phase guarantees containment and attribution only.

</decisions>

<code_context>
## Existing Code Insights

- `AgentDispatcher::tick_agents` currently wraps each agent tick with a
  timeout, but it still awaits `agent.tick(&env)` directly, so a panic inside
  any agent can unwind through the shared dispatcher task.
- `AgentTickBoundaryError` currently covers only typed `Sphinx` and `Stalker`
  failures; the other runtime agents still rely on raw `SwarmError` or panic
  behavior.
- `swarm_detect` runs the dispatcher as a long-lived background task, so
  per-agent isolation has to happen before a tick future can unwind out of
  that task.

</code_context>

<deferred>
## Deferred Ideas

- Individual agent restart loops remain Phase 209 work.
- Runtime-wide mode transitions such as detect-only or emergency-drain remain
  Phase 210 work.

</deferred>
