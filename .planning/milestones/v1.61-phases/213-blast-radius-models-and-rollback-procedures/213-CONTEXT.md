# Phase 213: Blast-Radius Models And Rollback Procedures - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 213 turns the broadened Phase 212 response catalog into an operator-usable
typed contract by attaching explicit blast-radius and rollback semantics to each
supported action.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing `ResponseRehearsalPreview`, blast-radius, and rollback
  model in `swarm-core` and `swarm-runtime` instead of inventing a second
  preview-specific schema.
- Keep the support matrix explicit: action metadata should be defined once and
  shared by rehearsal, preview, and later playbook composition work.
- Preserve Phase 212's fail-closed behavior by converting the temporary
  `UnsupportedAction` preview responses for the new actions into typed metadata
  rather than widening any adapter semantics.

</decisions>

<code_context>
## Existing Code Insights

- `ResponseAction` now covers fifteen concrete actions, but the new actions
  still return `RehearsalPreviewError::UnsupportedAction` during preview
  construction.
- `swarm-runtime/src/service.rs` already owns the typed preview builder for the
  original five actions, so Phase 213 can extend one existing contract instead
  of scattering action metadata across adapters or HTTP surfaces.
- Later v1.61 work depends on this typed metadata: Phase 214 needs reusable
  action semantics for YAML playbook composition, and Phase 215 needs the same
  metadata for dry-run preview.

</code_context>

<deferred>
## Deferred Ideas

- Multi-step YAML playbooks remain Phase 214 work.
- Operator-facing dry-run and approval preview across composed playbooks remains
  Phase 215 work.

</deferred>
