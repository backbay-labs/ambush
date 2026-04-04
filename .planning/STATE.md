---
gsd_state_version: 1.0
milestone: v1.16
milestone_name: governance-packet-sets-and-portfolio-history
status: ready-to-plan
last_updated: "2026-04-04T05:21:04Z"
progress:
  total_phases: 3
  completed_phases: 0
  total_plans: 3
  completed_plans: 0
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-04)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** `v1.16 Governance Packet Sets And Portfolio History` is active. Phase 50 is next.

## Memory

- `v1.15` widened the offline evolution lane from one ranked selection to a durable cross-batch portfolio artifact.
- Portfolio entries now preserve ranking, selection, mutation-batch, validation-batch, cohort, validation, proof, advisory, shadow, and parent-queue lineage in one operator review record.
- Operators can now record include, defer, or drop decisions on portfolio entries without mutating queue, canary, or production state.
- Governance-ready review packets now reuse preserved portfolio evidence and fail closed on stale, blocked, or drifted state while still persisting inspectable blocked packets.
- The next missing seam is durable packet grouping and outcome history above the governance-prep lane, not quorum voting or a richer HTTP/TUI operator surface yet.

## Next Command

`$gsd-plan-phase 50`
