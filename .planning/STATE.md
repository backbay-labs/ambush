---
gsd_state_version: 1.0
milestone: v1.16
milestone_name: governance-packet-sets-and-portfolio-history
status: milestone-complete
last_updated: "2026-04-04T10:15:00Z"
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
**Current focus:** no active milestone. `v1.16 Governance Packet Sets And Portfolio History` is archived.

## Memory

- `v1.16` added durable packet-set artifacts above governance-ready review packets.
- Packet sets now preserve source packet, portfolio, cohort, ranking, validation, proof, advisory, and rollout-lineage references in one stable record.
- Operators can now split packet sets into child subsets with preserved parent lineage and source packet-set entry references.
- Portfolio history snapshots now derive cross-cohort survival, rollout outcomes, and review debt from existing strategy memories instead of duplicating rollout state.
- Packet-set and portfolio-history review surfaces now ship through `swarmctl` with stable-ID reload and cohort filtering.

## Next Command

`$gsd-new-milestone`
