# Phase 94: Agent Registry And Role Shift Runtime

## Vision

The runtime stops being a single hard-coded agent loop and becomes a reusable multi-agent foundation. The dispatcher owns a keyed registry instead of a positional vector, agents can signal and observe role shifts through a runtime event bus, and each tick sees a richer swarm snapshot that includes current mode, recent pheromones, and recent peer findings.

## Decisions

- `AgentRegistry` lives in `swarm-runtime` alongside the dispatcher because it owns trait objects and runtime lifecycle concerns, not shared core semantics
- Role-shift propagation uses a lightweight runtime event type in `swarm-core` so every `SwarmAgent` can observe swarm-wide changes without the dispatcher knowing concrete agent internals
- `SwarmEnvironment` grows a read-only `peer_findings` view built from recent `SwarmAction` outputs rather than exposing mutable agent state directly
- Peer finding snapshots are intentionally compact summaries derived from agent actions; the dispatcher tracks the latest finding per agent and refreshes the environment once per tick
- Agent lifecycle counters reuse the existing Prometheus registry from `CriticalPathMetrics` so `/metrics` exposes one runtime surface instead of a second disconnected registry
- This phase makes the registry reload-ready in-process; the concrete Stalker/Weaver agent implementations and full multi-agent pipeline land in Phase 95

## Deferred Ideas

- Full config-driven agent factories for every role
- Durable persistence of peer finding snapshots across restarts
- Richer event-bus history beyond role-shift propagation
- Cross-process registry synchronization
- Investigation and correlation agent behavior (Phase 95)

## Claude's Discretion

- Exact shape of the role-shift event payload
- How much action detail to preserve in peer-finding summaries
- Counter label dimensions for lifecycle metrics as long as they remain partitioned by role
- Whether registry iteration order is insertion-based or key-sorted
