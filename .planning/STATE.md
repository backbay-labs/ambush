---
gsd_state_version: 1.0
milestone: v1.14
milestone_name: ranked-candidate-rollout-bridge
status: milestone-complete
last_updated: "2026-04-04T09:35:00Z"
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
**Current focus:** No active milestone. `v1.14 Ranked Candidate Rollout Bridge` is archived.

## Memory

- `v1.14` closed the continuity gap from ranked review packets back into the existing handoff and bounded canary lane.
- Ranked-candidate selections now preserve ranking, validation, proof, advisory, shadow, and parent queue lineage in one durable operator artifact.
- Review decisions over ranked selections remain explicit and operator-authored until a bridge artifact is created.
- Ranked-candidate bridges now fail closed on blocked state, stale manifests, or lineage drift while still persisting inspectable blocked records.
- The planner is idle until the next milestone is created from the docs and roadmap.

## Next Command

`$gsd-new-milestone`
