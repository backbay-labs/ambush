# Phase 215: Playbook Dry-Run And Preview - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 215 turns the new repo-owned playbook composition schema into an
operator-visible dry-run preview so one matched playbook can show projected
blast radius, rollback expectations, and approval requirements before any live
execution happens.

</domain>

<decisions>
## Implementation Decisions

- Reuse the Phase 213 typed rehearsal metadata and the Phase 214 branch-aware
  playbook selection semantics instead of inventing a second preview-only
  action description.
- Keep the preview side-effect free: preview must not hit live executors,
  create governance receipts, or perform real response actions.
- Start with the repo-owned operator surfaces already in tree, rather than
  adding a new UI-only preview workflow.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/service.rs` already builds typed per-action
  rehearsal preview metadata, so Phase 215 can compose one playbook preview
  from the same scope, blast-radius, and rollback contract already used by the
  rehearsal lane.
- `crates/swarm-runtime/src/pounce_agent.rs` now evaluates ordered branch-aware
  playbooks and records matched branch metadata in request evidence, which
  gives preview a deterministic explanation surface for why one branch was
  chosen.
- `crates/swarm-runtime/src/control.rs` and `crates/swarm-cli/src/core.inc`
  already expose bounded operator-visible reports such as readiness, first-run,
  and runtime status, which is the natural entrypoint for a repo-owned preview
  command.

</code_context>

<deferred>
## Deferred Ideas

- UI workbench or Providence-facing playbook preview remains later work.
- Editing playbooks interactively or accepting arbitrary operator-authored
  playbooks outside the checked-in repo config remains out of scope.

</deferred>
