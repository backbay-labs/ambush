---
gsd_state_version: 1.0
milestone: v1.18
milestone_name: signed-evidence-and-external-verification
status: planning
last_updated: "2026-04-04T15:10:00Z"
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
**Current focus:** `v1.18 Signed Evidence And External Verification` is active and Phase 56 is next.

## Memory

- `v1.16` added durable packet-set artifacts above governance-ready review packets.
- Packet sets now preserve source packet, portfolio, cohort, ranking, validation, proof, advisory, and rollout-lineage references in one stable record.
- Operators can now split packet sets into child subsets with preserved parent lineage and source packet-set entry references.
- Portfolio history snapshots now derive cross-cohort survival, rollout outcomes, and review debt from existing strategy memories instead of duplicating rollout state.
- Packet-set and portfolio-history review surfaces now ship through `swarmctl` with stable-ID reload and cohort filtering.
- `v1.17` extended those repo-owned review flows into an authenticated local operator surface instead of jumping early into quorum governance.
- Phase 53 shipped the local operator-surface config contract, bearer-token auth boundary, and protected `/v1/operator/status` route through `swarmctl serve`.
- Phase 54 extended that surface with authenticated runtime artifact, portfolio, governance-packet, packet-set, and portfolio-history read endpoints.
- Phase 55 added bounded authenticated maintenance actions plus durable stable-ID audit records for applied and blocked attempts.
- `v1.17` is archived with a passing milestone audit and a clean worktree.
- `v1.18` will focus on signed evidence bundle export, local verification, and advisory promotion evidence packets instead of jumping directly to quorum governance.

## Next Command

`$gsd-plan-phase 56`
