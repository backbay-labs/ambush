---
gsd_state_version: 1.0
milestone: v1.14
milestone_name: ranked-candidate-rollout-bridge
status: ready-to-plan
last_updated: "2026-04-04T04:15:00Z"
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
**Current focus:** `v1.14 Ranked Candidate Rollout Bridge` is active. Phase 44 is next.

## Memory

- `v1.12` closed the single-candidate continuity gap from reviewed drafts back into the verified rollout ladder.
- `v1.13` widened that continuity path into a multi-candidate offline bench with mutation specs, materialization batches, validation batches, and ranking packets.
- The runtime now supports pressure -> draft -> reviewed queue -> mutation spec -> materialization batch -> validation batch -> ranking packet.
- Ranked batches remain advisory and do not mutate queue, canary, or production lanes automatically.
- `v1.14` focuses on turning one selected ranked candidate back into a rollout-ready review artifact using the existing handoff and canary path.
- Governance remains deferred because the runtime still lacks independent trust boundaries.
- Phase 44 will define durable ranked-candidate selection artifacts before review decisions or rollout bridging are added.

## Next Command

`$gsd-plan-phase 44`
