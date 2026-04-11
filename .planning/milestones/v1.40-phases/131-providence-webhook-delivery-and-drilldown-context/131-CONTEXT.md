# Phase 131: Providence Webhook Delivery And Drilldown Context - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 131 closes the v1.40 demo story by pushing live Swarm findings into Providence with enough context for an external operator to understand the incident and click back into Swarm-owned drilldown surfaces. The owned outcome is not a generic notification rewrite. It is one repo-owned Providence webhook path that reuses the existing finding-notification lane, maps Swarm severity and threat class into Providence-oriented incident fields, and carries stable links plus runtime status context for the demo.

</domain>

<decisions>
## Implementation Decisions

### Reuse The Existing Notification Router
- `NotificationRouter` already deduplicates findings, applies quiet hours and rate limits, persists dead letters, and handles replay. Phase 131 should extend that router with channel-specific payload shaping instead of introducing a second outbound delivery path.
- The Providence-specific payload should be selected by the repo-owned `providence_webhook` channel name so existing notification channels keep the generic `swarm_notification` schema unchanged.
- Dead-letter replay must resend the exact Providence-shaped payload, not a rebuilt approximation, so the notification router remains the correct serialization boundary.

### Let The Runtime Supply Live Context
- Providence payloads need current swarm mode, active agent count, bridge health, and absolute drilldown URLs. That context lives in the runtime serve path, not in the `swarm-response` crate.
- The clean seam is a runtime-installed payload builder on `NotificationRouter`. `swarm-response` stays transport-focused while `IngestState` injects the live state provider needed by the demo runtime.
- This preserves crate boundaries: `swarm-response` owns delivery, while `swarm-runtime` owns runtime-state enrichment and link construction.

### Add One Explicit Public Operator Base URL
- `operator.runtime_base_url` is for runtime snapshot and SSE reads. Providence drilldown links need absolute URLs to the authenticated operator surface.
- Add `operator.public_base_url` as a repo-owned config field used only for outward-facing drilldown links.
- Keep the field simple: validate it as an HTTP(S) base URL and use it to build stable absolute links for replay, investigation, incident, and review surfaces.

### Prefer Stable Hunt-Based Links
- Notification routing happens before response execution finishes, so response receipt IDs are not reliably available at delivery time.
- Stable links should therefore key off the finding event/hunt identifier that already exists on `SwarmFindingEnvelope`.
- The replay, investigation, and incident operator routes already support `hunt_id` selectors, so the Providence payload can point to real existing surfaces without inventing new lookup routes.

</decisions>

<code_context>
## Existing Code Insights

### Notification Delivery Already Exists
- `crates/swarm-response/src/notification.rs` builds one `AggregatedNotification` per deduped finding group and already handles channel matching, rate limiting, quiet hours, dead-letter persistence, and replay.
- `crates/swarm-runtime/src/service.rs` routes findings into that notification path before action execution, which is why stable hunt-based links are safer than receipt-based links here.
- `crates/swarm-runtime/src/control.rs` already exposes dead-letter list and replay behavior through the operator surface; the Providence path should keep using that same operational tooling.

### Runtime State And URLs Are Available In Serve Mode
- `crates/swarm-runtime/src/ingest.rs` already exposes `current_mode_state()`, `current_agent_health()`, and optional bridge health via `bridge_health_report(...)`.
- `crates/swarm-runtime/src/http/core.inc` already has operator routes for replay, investigation, incident, review evidence, and verification pages, plus runtime demo endpoints on `runtime_base_url`.
- `crates/swarm-core/src/config.rs` already validates `operator.runtime_base_url`; it is the right place to add and validate `operator.public_base_url`.

### Stable Drilldown Paths Already Exist
- `/v1/operator/replay?hunt_id=...`
- `/v1/operator/investigation?hunt_id=...`
- `/v1/operator/incident?hunt_id=...`
- `/v1/operator/review`
- These are sufficient for the external Providence payload. No new HTTP routes are required for Phase 131.

</code_context>

<specifics>
## Specific Ideas

- Model the Providence payload as one envelope containing:
  - the canonical `SwarmFindingEnvelope`
  - Providence incident fields derived from threat class and severity
  - aggregate counters and timestamps
  - runtime status context
  - absolute drilldown links
- Install the payload builder from `IngestState` and refresh it when runtime state handles are attached or the runtime reloads.
- Add an end-to-end ingest test that posts a real event, captures the outbound Providence webhook, and asserts severity mapping, threat-class mapping, operator links, and runtime status context.

</specifics>

<deferred>
## Deferred Ideas

- General-purpose channel typing beyond the repo-owned `providence_webhook` path is out of scope.
- Providence acknowledgement, retry semantics beyond the existing notification dead-letter/replay flow, and inbound webhook callbacks are out of scope.
- Rich Providence-specific operator pages are out of scope; Phase 131 only needs outbound payloads that point back to existing Swarm surfaces.

</deferred>
