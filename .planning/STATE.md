---
gsd_state_version: 1.0
milestone: v1.18
milestone_name: signed-evidence-and-external-verification
status: milestone-complete
last_updated: "2026-04-04T21:21:29Z"
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
**Current focus:** no active milestone. `v1.18 Signed Evidence And External Verification` is archived.

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
- `v1.18` added signed evidence bundle export, local verification records, authenticated evidence read endpoints, and advisory promotion evidence packets.
- Signed evidence now covers replay, investigation, incident, maintenance, canary, promotion, verification, shadow, and promotion-review artifacts through one repo-owned contract.
- `v1.18` is now archived with a passing milestone audit and no active follow-on milestone yet.

## Next Command

`$gsd-new-milestone`
