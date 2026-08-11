# Phase 239: HTTP Rate Limiting - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase adds per-source rate limiting to the shipped authenticated HTTP
surfaces: the local operator API and the `/v2/api/*` platform API. It is
limited to repo-owned rate-limit config, bounded in-memory enforcement,
fail-closed response behavior, and operator-visible audit/status context.

</domain>

<decisions>
## Implementation Decisions

### Chosen Approach
- Add one shared repo-owned `HttpRateLimitConfig` and attach it separately to
  `operator_surface` and `platform_api` so the thresholds can evolve
  independently while using the same runtime implementation.
- Implement one reusable in-memory limiter in `swarm-runtime` that tracks burst
  and sustained sliding windows per request source, keeps recent violations in a
  bounded audit queue, and exposes status snapshots for operator visibility.
- Identify the request source from request metadata in this order:
  `x-forwarded-for`, `x-real-ip`, `forwarded`, then `unknown`. This keeps the
  limiter testable on `Router::oneshot` while still working behind a proxy.

### Constraint To Acknowledge
- This limiter is intentionally per-process and in-memory for the current
  milestone. It does not coordinate budgets across multiple runtime replicas.

### Deferred To Later Phases
- Cross-node or distributed rate limiting is out of scope.
- Richer source attribution from trusted proxy config or socket metadata is
  future work if the deployment model needs it.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- [crates/swarm-core/src/config/operator.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-core/src/config/operator.rs) already owns the repo-owned operator and platform HTTP config boundary.
- [crates/swarm-runtime/src/http/core.inc](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/http/core.inc) and [crates/swarm-runtime/src/ingest/platform_api.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/platform_api.rs) already centralize protected-route middleware.
- [crates/swarm-runtime/src/service/types.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/service/types.rs) and the platform runtime status payload already carry operator-visible runtime status.

### Established Patterns
- Protected-request failures return structured JSON errors rather than raw text.
- Operator-visible runtime state is surfaced through `/v1/operator/status`,
  `/v2/api/runtime/status`, and `swarmctl control status`.
- Config validation rejects nonsensical zero or empty thresholds before runtime
  startup.

### Integration Points
- `crates/swarm-core/src/config/defaults.rs`
- `crates/swarm-core/src/config/operator.rs`
- `crates/swarm-core/src/config/validation.rs`
- `crates/swarm-runtime/src/http/rate_limit.rs`
- `crates/swarm-runtime/src/http/core.inc`
- `crates/swarm-runtime/src/ingest/platform_api.rs`
- `crates/swarm-runtime/src/control.rs`
- `crates/swarm-runtime/src/ingest/tests.rs`

</code_context>

<specifics>
## Specific Ideas

- Return `429 Too Many Requests` with a `Retry-After` header and a bounded error
  message that includes the exceeded threshold, request path, and source.
- Keep a bounded recent-violations list in runtime status so operators can see
  which sources tripped the limiter most recently.
- Add focused tests for operator burst allowance plus recovery, and for platform
  sustained-threshold rejection with audit visibility.

</specifics>

<deferred>
## Deferred Ideas

- No durable violation journal in this milestone.
- No per-principal or per-API-key quotas separate from source-based budgets.

</deferred>
