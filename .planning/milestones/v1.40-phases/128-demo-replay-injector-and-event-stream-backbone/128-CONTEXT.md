# Phase 128: Demo Replay Injector And Event Stream Backbone - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 128 creates the operator-facing runtime lane for the v1.40 demo story. The owned deliverable is not a dashboard yet; it is the shared runtime backbone that can both drive the live swarm from repo-owned replay scenarios and expose typed real-time events to downstream demo surfaces. The phase must stay inside two requirement boundaries: `demo_mode`-gated replay injection against the real telemetry lane, and a typed SSE stream with event-type filtering.

</domain>

<decisions>
## Implementation Decisions

### Use The Existing Runtime Hot Path
- Replay injection should reuse the repo-owned `ReplayScenarioManifest` format that `swarm_detect` already consumes rather than introducing a second demo-only manifest schema.
- Injected events must flow through the same ingest/runtime path the live server already uses so the demo can exercise real replay persistence, investigation queueing, correlation, escalation, and routed response handling.
- The clean seam for this is `IngestState`, because it already owns the configured runtime stack, detector, telemetry fan-out channel, and the public HTTP router.

### One Shared Event Backbone
- The event stream should be backed by a single shared broadcaster stored in runtime state, not by ad hoc per-endpoint state or log scraping.
- Event production belongs at the natural convergence points: ingest submission, dispatcher action routing, and concentration-monitor mode transitions.
- The backbone should emit typed structured events that are stable enough for later demo UI work, with query-time filtering by event type for selective subscribers.

### Keep Phase 128 Focused
- The stream only needs to provide the typed backbone for the future dashboard and proof/export flows; building the live dashboard itself remains Phase 129.
- Replay injection should support pacing controls and scenario-path loading, but not add a separate offline orchestration subsystem.
- The phase should avoid refactoring the operator surface in `http/core.inc`; the new demo endpoints belong on the existing runtime HTTP surface in `ingest.rs`.

### Claude's Discretion
- Whether replay injection runs inline in the request task or spawns a background task, as long as the accepted response is deterministic and the injected events enter the real runtime lane.
- The exact typed event taxonomy, as long as it clearly covers replay lifecycle, agent actions, escalation transitions, and routed response/audit outcomes needed by later demo phases.
- The shape of event filtering parameters, as long as downstream consumers can subscribe selectively by event type without parsing every event client-side.

</decisions>

<code_context>
## Existing Code Insights

### Runtime Seams Already In Place
- `crates/swarm-runtime/src/ingest.rs` already owns the shared serve-mode state, the ingest handler, the detector/runtime stack, and the Axum router used by `swarm_detect --serve`.
- `crates/swarm-runtime/src/bin/swarm_detect.rs` wires together `IngestState`, the telemetry channel, `AgentDispatcher`, `ConcentrationMonitor`, bridge runtime tasks, and the HTTP server. This is the right place to instantiate one shared event broadcaster and pass it to all producers.
- `crates/swarm-runtime/src/dispatcher.rs` is the single point where all `SwarmAction` variants converge, so it is the clean place to emit typed action and routed-request events.
- `crates/swarm-runtime/src/escalation.rs` is the canonical producer for swarm mode transitions and escalation threshold crossings.

### Reusable Assets
- `crates/swarm-runtime/src/replay/core.inc` already defines `ReplayScenarioManifest`, `ReplayScenarioInput::Events`, and `load_scenario_manifest`, so the demo injector can stay aligned with the existing repo-owned scenario corpus.
- `crates/swarm-runtime/src/service.rs` and `ConfiguredRuntimeStack::process_event()` already represent the full runtime critical path that persists replay bundles and queues investigations.
- `crates/swarm-runtime/src/ingest.rs` already has direct Axum endpoint tests with `tower::ServiceExt`, making it the right file to add replay and SSE HTTP verification.

### Constraints From Current Workspace State
- The worktree is already dirty in unrelated files, including formatting churn and an approval-signature change in `crates/swarm-runtime/src/http/core.inc`; Phase 128 should not revert or rewrite that work.
- `crates/swarm-core/src/config.rs` is already dirty, but the overlap is acceptable because `RuntimeSettings` must grow a repo-owned `demo_mode` gate and its tests will need updating.
- Future dashboard and Providence work depends on the new event backbone, so the event model should be extensible without overfitting to just one endpoint test.

</code_context>

<specifics>
## Specific Ideas

- Add a small `runtime_events` module in `swarm-runtime` so the event taxonomy is explicit and not buried in `ingest.rs`.
- Reuse the existing ingest processing helper for both `/v1/ingest/events` and `/v1/demo/replay` so injected demo events and live ingest events share the same runtime behavior and event emission.
- Emit typed SSE `event:` names that mirror the internal event kind values; this keeps filtering and future UI subscriptions simple.
- Include replay metadata such as scenario path, run id, pacing, and per-step index in the replay lifecycle events so later demo proof/export work has stable lineage.

</specifics>

<deferred>
## Deferred Ideas

- The real-time dashboard UI, timeline rendering, and concentration snapshots remain Phase 129.
- Approval pause/resume and signed proof packaging remain Phase 130.
- Providence webhook shaping and drilldown-link generation remain Phase 131.

</deferred>
