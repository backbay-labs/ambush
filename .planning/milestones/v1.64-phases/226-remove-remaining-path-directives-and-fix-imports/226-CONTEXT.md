# Phase 226: Remove Remaining Path Directives And Fix Imports - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 226 verifies and normalizes the workspace after the Phase 225 source move:
all remaining `#[path]` bridge directives must be gone, and the runtime and
compatibility crate surfaces must compile through ordinary Rust module paths.

</domain>

<decisions>
## Implementation Decisions

- Treat the `swarm-runtime` source move as the last structural change.
- Use this phase to prove there are no surviving `#[path]` bridges and that the
  updated runtime/evolution imports compile cleanly.

</decisions>
