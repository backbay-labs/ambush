# Phase 215 Plan 01 Summary

## Delivered

- Added shared playbook-resolution helpers in
  `crates/swarm-core/src/config.rs` so both preview and live routing now use
  the same deterministic rule-plus-branch selection contract. `PounceAgent`
  was updated in `crates/swarm-runtime/src/pounce_agent.rs` to consume that
  shared resolution path instead of maintaining duplicate branch-selection
  logic.
- Added `RuntimeService::playbook_preview` plus typed preview report structs in
  `crates/swarm-runtime/src/service.rs`. The preview now resolves one
  repo-owned playbook match from `(threat_class, severity, confidence, mode)`,
  reuses the Phase 213 typed rehearsal blast-radius and rollback metadata for
  each ordered action, and evaluates approval requirements through a fresh
  `ConfigurableApprovalGate` without touching live executors or durable
  governance state.
- Exposed that dry-run report through the repo-owned operator surfaces in
  `crates/swarm-runtime/src/control.rs` and `crates/swarm-cli/src/core.inc`.
  `swarmctl playbook-preview` now emits one bounded `playbook_preview` report
  in either text or JSON and carries matched rule, matched branch or fallback,
  per-action policy verdicts, approval-summary counts, and typed rollback or
  blast-radius metadata.
- Documented the operator-facing contract in `docs/CONFIGURATION.md`,
  including one canonical CLI example and the guarantee that preview remains
  side-effect free while evaluating the checked-in
  `pheromone.response_playbook` config.

## Notes

- Phase 215 intentionally previews only the checked-in repo config. It does
  not add an operator-authored ad hoc playbook upload or editing surface.
- The preview contract remains bounded to policy plus rehearsal projection. It
  does not mint synthetic governance receipts or simulate committee quorum.
