# Phase 179: Rehearsal Review Surface And Providence Handoff - Context

**Gathered:** 2026-04-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 179 needs to surface the new rehearsal artifacts together with Providence reconciliation on the bounded local review and Providence handoff paths. The codebase already persists rehearsal metadata on replay bundles and already exposes reconciliation on incidents, but the handoff links and local review entry points still treat those two records separately.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing replay bundle, platform API, operator review, and evidence-export surfaces instead of creating a second Providence-only review path.
- Keep Providence drilldown links scoped by the existing context-token contract and enrich them with rehearsal and reconciliation lookup context rather than broader operator capabilities.
- Reuse the existing replay-bundle evidence export contract for signed rehearsal proof packages so signed proof remains one operator-owned format.

</decisions>

<code_context>
## Existing Code Insights

- [service.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/service.rs) now persists `ReplayBundle` artifacts with optional `rehearsal` proof carrying typed blast-radius and rollback preview data.
- [platform_api.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/platform_api.rs) already surfaces replay-backed finding summaries and incident reconciliation summaries, but it does not yet join those views or expose rehearsal-specific metadata.
- [providence.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/providence.rs) already mints scoped Providence context tokens and drilldown links, but `review_home` is still generic and `replay_bundle` only scopes by hunt.
- [http/core.inc](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/http/core.inc) already hosts the local operator review home plus replay and evidence pages, and the operator surface paths already carry an evidence signer id plus signing-key env for signed proof export.
- [evidence.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-evolution/src/evidence.rs) already exports signed `EvidenceSubjectKind::ReplayBundle` proof bundles when given a stable bundle id and local signing material.

</code_context>

<deferred>
## Deferred Ideas

- Rich Providence-side rendering or embedded replay visualizations remain outside this phase.
- Multi-bundle rehearsal comparison and operator-authored playbook packs remain later response UX work.

</deferred>
