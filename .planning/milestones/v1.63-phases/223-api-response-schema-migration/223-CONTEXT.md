# Phase 223: API Response Schema Migration - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 223 adds explicit schema versions and bounded negotiation to
operator-facing API response envelopes so future breaking shape changes do not
arrive as silent drift. The phase is limited to response envelopes and
compatibility handling; it does not reopen pheromone wire-format work or
redesign the operator data model itself.

</domain>

<decisions>
## Implementation Decisions

- Add schema version metadata at the shared API envelope boundary rather than as
  one-off fields on individual response payloads.
- Keep negotiation bounded to one current compatibility path so existing
  operator and CLI consumers keep working while later breaking changes can roll
  forward explicitly.
- Reuse the current runtime-owned HTTP and control surfaces instead of creating
  a parallel versioned API stack.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/control.rs` and
  `crates/swarm-runtime/src/ingest/platform_api.rs` currently serialize
  operator-facing JSON shapes directly, so schema drift would land implicitly
  unless the envelope contract is centralized.
- `crates/swarm-runtime/src/http/core.inc` wires the operator review surface and
  HTTP handlers that will need one bounded negotiation seam instead of
  per-endpoint ad hoc branching.
- `crates/swarm-cli/src/core.inc` consumes current JSON output from repo-owned
  control commands, so the compatibility path must keep the existing CLI lane
  working while version metadata is introduced.

</code_context>

<deferred>
## Deferred Ideas

- This phase does not introduce a broad OpenAPI or codegen pipeline.
- Request-body versioning is out of scope unless one existing endpoint requires
  it to keep response negotiation coherent.
- Long-tail multi-version support beyond the bounded current compatibility path
  remains future work.

</deferred>
