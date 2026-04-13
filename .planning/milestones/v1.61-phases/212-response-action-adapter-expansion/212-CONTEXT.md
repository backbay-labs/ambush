# Phase 212: Response Action Adapter Expansion - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 212 starts `v1.61` by widening the response adapter library from the
small current set into a materially broader operator-usable action catalog.

</domain>

<decisions>
## Implementation Decisions

- Build on the existing typed `ResponseAction` and adapter seams rather than
  inventing a second playbook-only action representation.
- Keep Phase 212 focused on expanding concrete action support and adapter
  routing; blast-radius modeling and rollback stay in Phase 213.
- Preserve fail-closed behavior so unsupported or partially wired actions are
  rejected explicitly instead of silently degrading into no-op execution.

</decisions>

<code_context>
## Existing Code Insights

- `swarm-core` already owns typed response actions, and `swarm-runtime` plus
  `swarm-response` already route a smaller supported adapter set through the
  normal approval and execution lane.
- The current response path already supports rehearsal and proof export, so
  broader action coverage should reuse the same execution and evidence seams.
- Later v1.61 work depends on typed action coverage being in place before
  blast-radius and playbook composition can become operator-meaningful.

</code_context>

<deferred>
## Deferred Ideas

- Typed blast-radius and rollback metadata remain Phase 213 work.
- Multi-step playbook YAML and preview flows remain Phases 214-215.

</deferred>
