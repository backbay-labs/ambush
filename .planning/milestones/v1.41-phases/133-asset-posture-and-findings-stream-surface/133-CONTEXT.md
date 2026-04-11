# Phase 133: Asset Posture And Findings Stream Surface - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 133 turns the new `/v2/api/*` surface into something an operator or downstream consumer can use continuously. The owned outcome is one host posture endpoint plus one authenticated live findings SSE endpoint. This phase does not own Helm, CLI flows, bearer auth, or TLS.

</domain>

<decisions>
## Implementation Decisions

### Add Host Filtering At The Substrate Query Seam
- The roadmap explicitly allows either a new host-filtered substrate query method or a host filter on `query_deposits()`.
- Extending `DepositQuery` with `host_id` is the smallest change because it preserves the existing substrate interface and lets the detect server compute host posture from the same durable deposit history already used for escalation.
- Detection deposits should start carrying `host_id` in their `indicator` payload so new runtime data is immediately filterable, while the filter should also tolerate older artifacts by checking the enriched evidence metadata path when present.

### Keep Host Posture As A Platform-Shaped Read Model In `ingest.rs`
- `IngestState` already owns the live substrate, replay store, investigation store, incident store, mode state, and runtime-event broadcaster.
- The new posture endpoint should stay in `crates/swarm-runtime/src/ingest.rs` beside the Phase 132 platform handlers instead of creating a second read-model service.
- Return the posture payload through the same `{ data, cursor }` contract introduced in Phase 132, with a single posture object in `data` and `cursor: null`.

### Derive Posture From Durable Runtime Artifacts, Not New Caches
- Per-threat-class concentrations should come from host-filtered substrate deposits.
- Active investigations already exist as `InvestigationBundleRecord` values with `host_id` and `status`, so the posture endpoint should filter those records rather than inventing a parallel queue view.
- Recent findings already exist in persisted replay bundles and the Phase 132 finding summary shape can be reused for the posture payload.

### Reuse The Existing Runtime Event Broadcaster By Adding A First-Class `finding` Event
- The live runtime already has `RuntimeEventBroadcaster` and `/v1/events/stream?types=...`.
- Add a `finding` runtime event kind that carries a `SwarmFindingEnvelope` plus optional `host_id`, publish it when ingest or demo replay produces findings, and let `/v2/api/stream/findings` subscribe to the same broadcaster with finding-only filtering.
- The platform stream should serialize the `SwarmFindingEnvelope` itself as SSE data so downstream consumers receive the canonical finding schema rather than a platform-specific wrapper.

</decisions>

<code_context>
## Existing Code Insights

### Phase 132 Already Established The Router And Auth Shape
- `platform_api_router(...)` in `crates/swarm-runtime/src/ingest.rs` already owns `/v2/api/findings`, `/v2/api/incidents`, and `/v2/api/runtime/status`, all behind `require_platform_api_key_auth`.
- Phase 133 can extend that same nested router with `/assets/{host_id}/posture` and `/stream/findings` without reopening the auth design.

### Findings Already Flow Through Persisted Replay Bundles
- `ConfiguredRuntimeStack::process_event(...)` returns `PersistedReplayBundleWithInvestigation`, which gives `ingest.rs` access to the exact enriched findings that were just produced.
- That makes `process_runtime_event(...)` and `process_demo_replay_step(...)` the right publication seams for new runtime finding events.

### Store Shapes Already Cover The Needed Supporting Fields
- `InvestigationBundleRecord` already exposes `host_id`, `status`, summary preview, and correlation keys.
- `ReplayBundleLookup` exposes the original event host and full `DetectionFinding`, which is enough to reuse `PlatformFindingSummary` inside host posture.
- `RuntimeEventBroadcaster` already supports broadcast subscription and SSE conversion through `BroadcastStream`, so the new stream handler can mirror the existing `/v1/events/stream` structure.

</code_context>

<specifics>
## Specific Ideas

- Add `GET /v2/api/assets/{host_id}/posture`.
- Add `GET /v2/api/stream/findings`.
- Add a `RuntimeEvent::Finding` variant and publish it from both ingest and demo replay execution paths.
- Add focused tests for:
  - host-filtered substrate deposit queries
  - host posture envelope shape and filtered contents
  - platform findings SSE output
  - finding runtime event publication from the ingest path

</specifics>

<deferred>
## Deferred Ideas

- Bearer auth and TLS on `/v2/api/*` remain Phase 135 work.
- Multi-tenant asset inventory, historical posture pagination, and incident-by-host endpoints are out of scope here.
- Evolution and memory surfaces remain later milestone work.

</deferred>
