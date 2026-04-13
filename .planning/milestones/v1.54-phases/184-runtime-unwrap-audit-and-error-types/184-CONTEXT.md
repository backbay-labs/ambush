# Phase 184: Runtime Unwrap Audit And Error Types - Context

**Gathered:** 2026-04-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 184 starts the `v1.54` panic-eradication milestone by auditing non-test
`unwrap()` and `expect()` use across `swarm-runtime` and defining the typed
error boundaries needed to remove those panic sites in follow-on phases. The
goal is an actionable runtime debt map plus foundational error enums and
conversions, not yet a full crate-wide panic purge.

</domain>

<decisions>
## Implementation Decisions

- Exclude test-only `unwrap()` and `expect()` usage from the requirement scope;
  this phase is about live runtime code paths and crate boundaries.
- Reuse the repo's existing `thiserror`-based error style instead of collapsing
  runtime failures into one catch-all error type.
- Start from the runtime entrypoints and shared module seams (`lib.rs`,
  `service.rs`, `ingest`, `http`, `serve`) so later conversion phases can
  propagate errors outward instead of adding more local ad hoc wrappers.
- Record deferred panic sites explicitly when they belong to later conversion
  phases rather than trying to hide them inside an incomplete first pass.

</decisions>

<code_context>
## Existing Code Insights

- A repo-wide search shows many `unwrap()` and `expect()` calls under
  `crates/swarm-runtime/src`, but a large share live inside inline `#[cfg(test)]`
  modules; the live runtime sites cluster around bootstrap, serve wiring, and a
  few persistence or serialization helpers.
- [lib.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/lib.rs),
  [service.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/service.rs),
  [config.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/config.rs),
  [mod.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/mod.rs),
  and [core.inc](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/http/core.inc)
  already define typed error enums, but the boundary map is uneven and some
  runtime call sites still bypass those enums with panic-driven control flow.
- [serve.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/serve.rs)
  and [sphinx_agent.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/sphinx_agent.rs)
  are likely hotspots for later conversion work once the boundary inventory is
  recorded.
- Phase 183 just tightened operator attribution and config validation, so the
  next milestone can focus on error propagation without reopening the freshly
  shipped production-access contract.

</code_context>

<deferred>
## Deferred Ideas

- Full ingest, service, and HTTP panic-site conversion belongs to Phase 185 once
  the boundary inventory is explicit.
- Agent tick, Sphinx, replay, and evolution panic-site cleanup belongs to Phase
  186.
- CI or lint enforcement for new runtime `unwrap()` and `expect()` usage belongs
  to Phase 187.

</deferred>
