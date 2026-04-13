# Phase 214: Composable Playbook YAML Schema - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 214 turns the now-complete typed response action catalog into a
repo-owned playbook language so operators can declare bounded multi-step
response sequences in YAML instead of hard-coding them in Rust.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing `ResponseAction` catalog and the Phase 213 typed
  blast-radius and rollback metadata instead of inventing a second playbook
  action schema.
- Extend the current `ResponsePlaybookConfig` surface in `swarm-core` rather
  than introducing an external parser or a free-form scripting DSL.
- Keep execution deterministic and approval-aware: composed playbooks should
  still route through the existing PounceAgent and runtime action seams rather
  than bypassing policy or governance.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-core/src/config.rs` already defines `ResponsePlaybookConfig`
  and `ResponsePlaybookRule`, but today each rule only maps directly to an
  ordered flat `Vec<ResponseAction>`.
- `crates/swarm-runtime/src/pounce_agent.rs` already matches findings against
  that repo-owned playbook and emits the configured actions through the normal
  approval and execution path, so Phase 214 can extend one existing control
  point instead of adding another response orchestrator.
- Phase 213 now guarantees every response action carries typed rehearsal
  metadata, which gives Phase 215 one shared semantic surface for previewing
  composed playbooks.

</code_context>

<deferred>
## Deferred Ideas

- Operator-facing dry-run preview for full playbooks remains Phase 215 work.
- Any UI or operator-surface presentation of composed playbooks remains later
  work; this phase is about the repo-owned YAML schema and runtime execution
  wiring.

</deferred>
