# Phase 185: Ingest And Service Panic-Free Conversion - Context

**Gathered:** 2026-04-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 185 converts the string-only and ad hoc error propagation seams in the
ingest, service, and HTTP entrypoints into typed runtime errors. Phase 184
already proved the entrypoint tranche has zero live non-test `unwrap()` and
`expect()` sites, so this phase is about making malformed input and store
failures propagate through explicit `Result` contracts instead of `String`
reason plumbing and `error.to_string()` mapping.

</domain>

<decisions>
## Implementation Decisions

- Start with the request-facing seams that still return `Result<_, String>` in
  `ingest/mod.rs` and the operator-surface handlers that collapse typed errors
  into `OperatorApiError::internal(error.to_string())`.
- Preserve the existing HTTP response shape where possible; change the internal
  propagation contract first, then widen or refine response payloads only when
  needed to keep the surface stable.
- Reuse existing `thiserror` enums and add focused typed boundary enums rather
  than inventing one catch-all runtime error.
- Leave agent, replay, and evolution module cleanup to Phase 186, which now
  owns the non-entrypoint pass according to the Phase 184 audit.

</decisions>

<code_context>
## Existing Code Insights

- [184-RUNTIME-PANIC-AUDIT.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/.planning/phases/184-runtime-unwrap-audit-and-error-types/184-RUNTIME-PANIC-AUDIT.md)
  confirmed zero live non-test `unwrap()` and `expect()` sites across
  `swarm-runtime` entrypoints, so Phase 185 should target typed propagation
  debt, not repeat the panic-site grep.
- [mod.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/mod.rs)
  still contains multiple `Result<_, String>` helpers such as
  `validate_and_parse`, Providence context-token helpers, and operator-secret
  material resolution.
- [core.inc](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/http/core.inc)
  still maps many typed failures into `OperatorApiError::internal(error.to_string())`
  and `OperatorReviewError::internal(error.to_string())`, which hides boundary
  structure even though the surface no longer panics.
- [service.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/service.rs)
  already has `ServiceError`, but some adjacent seams still trade in string
  reasons that should become typed errors or typed conversions.
- [serve.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/serve.rs)
  now uses `ServeError`, which is the boundary pattern this phase should extend
  into ingest and request-facing service composition.

</code_context>

<deferred>
## Deferred Ideas

- Agent, replay, workbench, and evolution-specific error propagation cleanup
  remains Phase 186 work.
- Repo or CI enforcement against new `unwrap()` and `expect()` use remains Phase
  187 work.

</deferred>
