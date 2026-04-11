# Phase 132: Platform API Envelope And Auth Surface - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 132 adds the first versioned platform read surface on the detect server. The owned outcome is a repo-owned `/v2/api/*` group for findings, incidents, and runtime status with one stable pagination envelope and one scoped API-key auth path. This phase does not own host posture, findings SSE, bearer auth, or TLS. Those belong to later roadmap phases.

</domain>

<decisions>
## Implementation Decisions

### Keep The New API On The Detect Server
- `detect_http_router(...)` already owns health probes, ingest, demo snapshot APIs, runtime event streaming, and the live `IngestState` handles for replay, investigation, incident, and substrate data.
- Phase 132 should extend that detect router in place rather than proxying through the operator surface or adding a second HTTP service.
- `/v1/operator/*`, `/v1/ingest/events`, demo routes, and health probes stay structurally separate from the `/v2/api/*` route group so the new auth gate only wraps the versioned platform routes.

### Back Findings And Incidents With Existing Durable Artifacts
- Recent findings already survive in persisted replay bundles. The most direct read model is a platform-facing summary derived from `ReplayBundle` plus its embedded `DetectionFinding`.
- Recent incidents already survive as `IncidentRecord` values in `ConfiguredIncidentStore`; Phase 132 should expose those records directly through a platform-shaped envelope instead of inventing a second incident cache.
- This keeps the first platform read API grounded in the same persisted artifacts the runtime already uses for replay and review.

### Use One Simple Cursor Contract Across Endpoints
- The roadmap fixes the response contract at `{ data: [...], cursor: Option<String> }`, so the platform API should use one shared envelope type for findings, incidents, and runtime status.
- Use query-string pagination with `page_size`, default `50`, maximum `200`, and a stable opaque-enough cursor derived from the sort key `{created_at_ms}:{stable_id}`.
- Filters should stay repo-owned and minimal for the first slice: findings filter by identifiers and core detection fields (`hunt_id`, `finding_id`, `strategy_id`, `threat_class`, `severity`, `host_id`); incidents filter by `incident_id`, `hunt_id`, `receipt_id`, and `correlation_key`.

### Add A Separate Platform API Key Config And Middleware Path
- The operator surface already has bearer auth, but Phase 132 explicitly wants scoped platform API keys, not a reuse of the operator bearer token path.
- Add a new `platform_api` config section on `SwarmConfig` that owns hashed keys and scope metadata. The runtime should compare the inbound key after SHA-256 hashing, resolve the configured `read` scope, and reject missing or mismatched keys.
- The middleware should insert an authenticated principal into request extensions so downstream handlers can include the identity in structured logs without coupling the endpoint payloads to auth internals.

</decisions>

<code_context>
## Existing Code Insights

### Detect Server Already Owns Runtime Read State
- `crates/swarm-runtime/src/ingest.rs` already exposes `current_mode_state()`, `current_agent_health()`, `current_replay_store()`, `current_investigation_store()`, `current_incident_store()`, and `current_substrate()`.
- `detect_http_router(...)` already separates public health and ingest routes from optional demo and SSE routes, which is the right seam for nesting `/v2/api/*`.

### Existing Stores Already Provide The Needed Read Models
- `crates/swarm-spine/src/store.rs` exposes `ConfiguredReplayBundleStore::recent(...)` plus full bundle lookup by stable IDs, which is enough to derive platform finding summaries.
- `crates/swarm-spine/src/incident.rs` exposes `ConfiguredIncidentStore::recent(...)` with `IncidentRecord`, which is already a stable metadata shape for list reads.
- `crates/swarm-spine/src/investigation.rs` captures host and summary fields that Phase 133 can reuse for posture, but Phase 132 does not need a new host-specific store query yet.

### Operator Auth Shows The Middleware Pattern To Follow
- `crates/swarm-runtime/src/http/core.inc` already uses `middleware::from_fn_with_state(...)` plus a dedicated auth state struct for `/v1/operator/*`.
- Phase 132 should mirror that shape on the detect server, but with a separate platform principal type and API-key validation path so the route groups remain independently evolvable.

### Current Runtime Events And Demo Snapshot Cover Future Phases
- `RuntimeEventBroadcaster` and `/v1/events/stream` already exist in `ingest.rs`; Phase 133 can reuse them for `/v2/api/stream/findings`.
- The demo dashboard snapshot already computes concentrations and mode state, which means runtime status can stay lightweight in Phase 132 and host posture can build on the same primitives in Phase 133.

</code_context>

<specifics>
## Specific Ideas

- Add `GET /v2/api/findings`, `GET /v2/api/incidents`, and `GET /v2/api/runtime/status`.
- Introduce a shared `PlatformEnvelope<T>` plus endpoint-specific summary structs instead of reusing operator envelopes.
- Use focused HTTP tests in `crates/swarm-runtime/src/ingest.rs` to prove:
  - `/v2/api/*` rejects missing or invalid keys
  - `/v1/ingest/events` and health probes remain unauthenticated
  - findings and incidents paginate and filter correctly
  - runtime status returns the platform envelope with live state

</specifics>

<deferred>
## Deferred Ideas

- Host posture and live findings SSE are Phase 133 work.
- Bearer auth and TLS on `/v2/api/*` are Phase 135 work.
- Write-side platform endpoints, key management APIs, and multi-scope auth beyond `read` are out of scope for Phase 132.

</deferred>
