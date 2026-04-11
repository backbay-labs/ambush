# Phase 152: Embeddable Dashboard Widget And Context Tokens - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 152 adds the Providence-facing presentation and deep-link seam: a minimal embeddable widget, scoped runtime reads, and short-lived signed context tokens for read-only drilldown.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing demo snapshot and runtime SSE surfaces instead of introducing a second dashboard data path.
- Scope the widget and drilldowns through one shared `ProvidenceContextScope` contract so Providence links, widget fetches, SSE filters, and platform API reads all enforce the same boundary.
- Treat context tokens as a narrow read-only alternative to bearer plus API-key auth for a small subset of `GET /v2/api/*` routes rather than as a general auth mechanism.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/ingest.rs` already owns the demo dashboard and SSE endpoints, which makes it the correct place to add the widget HTML and scoped filtering.
- `crates/swarm-runtime/src/providence.rs` already owns Providence link generation, so token minting and scoped URL construction should live there.
- `crates/swarm-core/src/config.rs` already owns operator-surface config validation and is the right place for embed-origin and token-TTL policy.

</code_context>

<deferred>
## Deferred Ideas

- Full browser UI beyond the minimal widget remains out of scope.
- Context tokens remain read-only and scoped to findings/incidents status links only; they do not widen write access or general operator-surface auth.

</deferred>
