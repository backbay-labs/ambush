# Phase 164: Canonical Capability Matrix And Source-Of-Truth Reset - Context

**Gathered:** 2026-04-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 164 is documentation and contract work only. It aligns the canonical docs, planning docs, and repo-owned config examples around the runtime that already exists, without reopening implementation behavior.

</domain>

<decisions>
## Implementation Decisions

- Treat the runtime, config, and planning artifacts as the source of truth over historical reference docs.
- Split active and historical material explicitly instead of trying to preserve one blended narrative.
- Publish one capability matrix covering critical lane, async lane, governance, evolution, and operator surfaces before any deeper product or ops milestone begins.

</decisions>

<code_context>
## Existing Code Insights

- `.planning/PROJECT.md`, `.planning/ROADMAP.md`, and `.planning/REQUIREMENTS.md` already reflect the shipped runtime more accurately than several older canonical docs.
- `docs/ARCHITECTURE.md`, `docs/AGENTS.md`, `docs/CONSENSUS.md`, `docs/EVOLUTION.md`, and `docs/INTEGRATION.md` still contain active-vs-historical drift.
- `rulesets/default.yaml` and `docs/CONFIGURATION.md` expose the currently shipped config surface and should anchor the capability matrix.

</code_context>

<deferred>
## Deferred Ideas

- Packaging, RBAC, and broader operator-access work belong to later milestones once the contract is stable.
- No runtime code changes are in scope for this phase unless a doc contract cannot be stated without a tiny naming cleanup.

</deferred>
