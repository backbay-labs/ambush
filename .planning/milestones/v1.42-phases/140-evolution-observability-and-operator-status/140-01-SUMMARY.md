# Phase 140 Plan 01 Summary

## Delivered

- Added a durable evolution-status surface in `crates/swarm-runtime/src/evolution_status.rs` that reads the shipped population, ranking, selection, canary, and Kitten runtime-status artifacts instead of inventing a second observability cache.
- Persisted `KittenAgent` state into the existing evolution artifact tree so operators can see the current drift-cycle phase, latest observation window, degraded ratio, and proposal candidate without inspecting in-memory state.
- Extended `RuntimeEvent` with a stable `evolution_status` event and published it from the routed admission lane so `/v1/events/stream` now carries evolution metrics over the existing SSE broadcaster.
- Wired the operator control surface to attach evolution status to `swarmctl status`, keeping the main runtime status output aligned with the same durable evolution data used by the admission lane.
- Added `swarmctl evolution status` through the extracted CLI surface so operators can query generation count, population metrics, verification pass rate, canary admission rate, and Kitten drift state directly.
- Added focused regression coverage for the durable status summary, SSE event filtering, the new runtime-event kind parser, and the CLI command parser, while re-verifying the existing routed canary-admission path from Phase 139.

## Notes

- The new observability surface is intentionally artifact-derived: rankings define generation count and verification pass rate, selections define admission rate, canaries define rollout state, and the persisted Kitten status file defines current drift-cycle state.
- This phase keeps the existing crate-graph seam intact. The runtime owns the status module for now, while the extracted CLI reuses it through the same transitional bridge as the other evolution surfaces.
