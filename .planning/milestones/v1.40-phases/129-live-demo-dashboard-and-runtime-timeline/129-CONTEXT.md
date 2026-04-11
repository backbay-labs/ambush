# Phase 129: Live Demo Dashboard And Runtime Timeline - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Expose a demo-focused live runtime dashboard inside the authenticated operator review surface by bootstrapping from a runtime-owned snapshot endpoint and staying current from the Phase 128 runtime event stream.

</domain>

<decisions>
## Implementation Decisions

### Runtime Snapshot Contract
- Add a runtime-owned demo dashboard snapshot endpoint on the `swarm-detect` HTTP surface instead of trying to reconstruct live state from operator-local stores.
- Gate the snapshot endpoint behind `runtime.demo_mode`, matching the replay injector and event stream intent for the v1.40 demo slice.
- Return current swarm mode, agent health, per-threat-class concentrations, and recent escalation records so the UI can render immediately before SSE events arrive.

### Operator Dashboard Wiring
- Keep the dashboard on the existing `/v1/operator/review` home page so the demo stays on the authenticated operator surface instead of adding a second UI entry point.
- Add a repo-owned `operator_surface.runtime_base_url` setting so the review UI can call the runtime snapshot and SSE endpoints directly even though they run on a different local port.
- Use one initial `fetch()` for the snapshot and one `EventSource` subscription for live updates rather than polling storage or logs.

### Live Event Model
- Extend the runtime event bus with a concentration snapshot event emitted by the concentration monitor on every evaluation cycle.
- Use streamed runtime events to maintain the scrolling timeline, with escalations and mode transitions emphasized but other runtime events still visible for drilldown context.
- Add permissive GET CORS headers on the runtime demo snapshot and SSE endpoints so the operator UI can consume them cross-origin during local demo runs.

### Claude's Discretion
Minor markup, styling, and JavaScript structure on the review home page can stay flexible as long as the dashboard clearly shows swarm mode, agent health, concentrations, and a live timeline.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-runtime/src/runtime_events.rs` already defines the typed runtime event bus and filter parsing used by `/v1/events/stream`.
- `crates/swarm-runtime/src/ingest.rs` already owns the demo replay endpoint and the shared `IngestState`, which is the correct place to expose runtime snapshot state.
- `crates/swarm-runtime/src/http/core.inc` already renders the authenticated review home page and carries repo-owned operator config into `OperatorHttpState`.

### Established Patterns
- Demo-only runtime features are gated through `runtime.demo_mode`.
- The runtime server publishes JSON APIs plus SSE directly from Axum handlers without extra service layers.
- The operator review UI is server-rendered HTML with inline CSS and JavaScript in the existing review layout.

### Integration Points
- `crates/swarm-core/src/config.rs` for `operator_surface.runtime_base_url`.
- `crates/swarm-runtime/src/bin/swarm_detect.rs` and `crates/swarm-runtime/src/ingest.rs` for passing live mode state into `IngestState` and exposing the new snapshot endpoint.
- `crates/swarm-runtime/src/escalation.rs` and `crates/swarm-runtime/src/runtime_events.rs` for concentration snapshot emission.
- `crates/swarm-runtime/src/http/core.inc` for the dashboard markup and runtime stream bootstrap wiring.

</code_context>

<specifics>
## Specific Ideas

Use the review home page as a single-screen demo cockpit: top-level live mode card, per-agent health board, threat concentration grid, and a scrolling runtime timeline fed by SSE.

</specifics>

<deferred>
## Deferred Ideas

Providence webhook drilldowns, signed proof export UX, and approval-in-the-loop controls belong to later v1.40 phases.

</deferred>
