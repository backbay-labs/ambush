# Phase 186: Agent Tick And Evolution Error Boundaries - Context

**Gathered:** 2026-04-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 186 extends the panic-free error-contract pass from request entrypoints into
the runtime-owned agent tick and evolution composition paths. Phase 185 closed
the ingest, service, and HTTP seams, but the runtime still has evolution- and
agent-adjacent paths that flatten failures into strings once work leaves the
request boundary.

</domain>

<decisions>
## Implementation Decisions

- Start with the runtime-owned orchestration seams in `swarm-runtime`, especially
  agent tick paths and the ingest strategy-proposal router that still carries
  evolution-specific `String` propagation.
- Reuse the Phase 185 pattern: add focused local typed enums at each boundary,
  then map those typed errors only at the final surface that still needs a
  string response or trait-compatible payload.
- Preserve current runtime status, events, and operator-facing behavior while
  improving the internal classification and fail-closed behavior.
- Leave repo-wide enforcement and malformed-input CI policy to Phase 187.

</decisions>

<code_context>
## Existing Code Insights

- [mod.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/mod.rs)
  now has typed request and processing errors for the request-facing ingest
  paths, but the strategy proposal router still returns `Result<_, String>` and
  carries many evolution-specific `error.to_string()` adapters.
- [service.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/service.rs)
  now models rehearsal preview and readiness failures explicitly, which is the
  pattern to extend into agent tick and cross-crate runtime orchestration.
- [core.inc](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/http/core.inc)
  now maps typed runtime errors through explicit adapter functions instead of
  inline blanket string flattening.
- The next unresolved runtime tranche sits in agent runtime code such as
  `lib.rs`, `sphinx_agent.rs`, `stalker_agent.rs`, and evolution-facing calls
  that currently hide failure class after the request boundary.

</code_context>

<deferred>
## Deferred Ideas

- CI or repo-owned enforcement against new `unwrap()` / `expect()` and new
  malformed-input panic regressions remains Phase 187 work.

</deferred>
