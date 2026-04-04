---
gsd_state_version: 1.0
milestone: none
milestone_name: none
status: milestone-complete
last_updated: "2026-04-04T03:10:00Z"
progress:
  total_phases: 0
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-03)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** No active milestone. `v1.12 Draft Materialization And Validation Bundles` shipped and is archived.

## Memory

- The runtime remains Rust-first, single-node, and operator-controlled.
- The evidence ladder now reaches from replay and verification through production promotion, advisory memory, draft packaging, materialized candidate generation, refreshed validation, and reconciled reviewed queue state.
- `swarmctl` now closes the draft continuity gap with `evolution-materialize`, `evolution-validation-refresh`, and `evolution-queue-reconcile`.
- Reconciled proposals still require explicit `accept-for-canary` review before the existing handoff and canary path can be used.
- Governance, richer operator surfaces, and automatic strategy mutation remain future work.

## Next Command

`$gsd-new-milestone`
