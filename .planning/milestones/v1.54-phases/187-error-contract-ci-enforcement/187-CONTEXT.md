# Phase 187: Error Contract CI Enforcement - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 187 closes `v1.54` by turning the panic-free runtime contract into a
repo-owned enforcement rule. Phases 184 through 186 removed the live non-test
runtime `unwrap()` and `expect()` debt and replaced the main request, agent,
and evolution seams with typed boundaries, but CI still treats that contract as
convention instead of a hard gate.

</domain>

<decisions>
## Implementation Decisions

- Add one repo-owned panic-contract check that scans non-test runtime code for
  new `unwrap()` or `expect()` sites and allows only explicitly justified
  exceptions.
- Wire that check into the existing GitHub Actions workflow instead of relying
  on local discipline or review memory.
- Add representative malformed-input or failing-fixture integration coverage so
  the repo proves the runtime returns errors instead of panicking across a few
  concrete ingress or routing paths.
- Keep the enforcement scope centered on `swarm-runtime` for this milestone; a
  broader workspace rule can come later if the contract expands.

</decisions>

<code_context>
## Existing Code Insights

- [184-RUNTIME-PANIC-AUDIT.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/.planning/phases/184-runtime-unwrap-audit-and-error-types/184-RUNTIME-PANIC-AUDIT.md)
  already documents the current non-test runtime baseline and is the source of
  truth for what the CI rule must preserve.
- [ci.yml](/Users/connor/Medica/backbay/standalone/swarm-team-six/.github/workflows/ci.yml)
  currently runs formatting, clippy, build, tests, and `cargo deny`, but it
  does not include a dedicated panic-contract gate.
- [ingest_integration.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/tests/ingest_integration.rs)
  and [critical_path_integration.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/tests/critical_path_integration.rs)
  are the most natural existing homes for broader malformed-input and
  fail-closed runtime assertions.
- Phase 186 introduced typed runtime-owned agent and strategy-routing
  boundaries, so Phase 187 can focus on enforcement and representative
  integration proof instead of more internal refactoring.

</code_context>

<deferred>
## Deferred Ideas

- Expanding the panic-contract scan to other crates is out of scope for
  `v1.54`; the milestone contract names runtime code specifically.

</deferred>
