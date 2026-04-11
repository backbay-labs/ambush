# Phase 151: Analyst Feedback Loop - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 151 adds the inbound Providence feedback seam: signed feedback intake, substrate side effects for confirm / dismiss / investigate, and propagation of false-positive dismissals into Kitten fitness or pending storage.

</domain>

<decisions>
## Implementation Decisions

- Reuse Phase 149 request-signing semantics for Providence inbound verification instead of inventing a second auth scheme.
- Build feedback persistence on top of the existing audit / spine path so analyst actions become durable runtime evidence, not transient HTTP side effects.
- Keep the Kitten integration best-effort and fail closed to durable pending storage when the evolution lane is not active.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/providence.rs` now owns outbound Providence lifecycle and already provides the stable incident key / external reference seam Phase 151 should reuse.
- `crates/swarm-runtime/src/ingest.rs` is the right inbound HTTP integration point because it already owns HMAC-bearing Providence config, runtime state, and readiness surfaces.
- `crates/swarm-runtime/src/kitten_agent.rs` and the durable evolution artifacts already provide a landing zone for negative feedback signals once the HTTP feedback endpoint is translated into runtime actions.

</code_context>

<deferred>
## Deferred Ideas

- Full bidirectional incident-state reconciliation remains out of scope; Phase 151 should focus on explicit analyst actions only.
- Embeddable dashboard/widget work and context tokens remain Phase 152.

</deferred>
