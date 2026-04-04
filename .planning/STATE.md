---
gsd_state_version: 1.0
milestone: v1.15
milestone_name: cross-batch-portfolio-and-governance-prep
status: milestone-complete
last_updated: "2026-04-04T05:09:49Z"
progress:
  total_phases: 3
  completed_phases: 3
  total_plans: 3
  completed_plans: 3
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-04)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** No active milestone. `v1.15 Cross-Batch Portfolio And Governance Prep` is archived.

## Memory

- `v1.15` widened the offline evolution lane from one ranked selection to a durable cross-batch portfolio artifact.
- Portfolio entries now preserve ranking, selection, mutation-batch, validation-batch, cohort, validation, proof, advisory, shadow, and parent-queue lineage in one operator review record.
- Operators can now record include, defer, or drop decisions on portfolio entries without mutating queue, canary, or production state.
- Governance-ready review packets now reuse preserved portfolio evidence and fail closed on stale, blocked, or drifted state while still persisting inspectable blocked packets.
- The planner is idle until the next milestone is created from the docs and roadmap.

## Next Command

`$gsd-new-milestone`
