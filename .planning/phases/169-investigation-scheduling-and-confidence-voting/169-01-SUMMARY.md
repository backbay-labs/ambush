# Phase 169 Plan 01 Summary

## Delivered

- Added repo-owned investigation scheduling controls in `crates/swarm-core/src/config.rs`, including starvation boost, maximum starvation boost, and ambiguity-margin bounds.
- Extended `crates/swarm-spine/src/investigation.rs` so durable investigation artifacts now preserve priority, competing interpretations, vote lineage, and final decision metadata.
- Replaced FIFO-only queue behavior in `crates/swarm-runtime/src/investigation.rs` with a bounded priority scheduler that accounts for queue budget, aging, starvation boost, and deterministic eviction pressure.
- Updated `crates/swarm-runtime/src/stalker_agent.rs` so ambiguous hunts can emit multiple candidate interpretations plus decision confidence instead of collapsing directly to one opaque result.
- Surfaced bounded scheduling state through the existing runtime lane, including queue-budget snapshots and recent decision metadata used by later operator-facing async status work.

## Notes

- Phase 169 stayed focused on queue selection and confidence lineage rather than adding a second operator surface.
- The async lane is still bounded by explicit queue budgets and starvation rules, which keeps the new scheduling behavior testable and predictable.
