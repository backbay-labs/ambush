# Phase 155 Plan 01 Summary

## Delivered

- Extended `GovernancePolicy` in `crates/swarm-runtime/src/tom_agent.rs` from simple healthy versus unhealthy veto logic into an explicit partition-authority state machine with `healthy`, `degraded`, `partitioned`, and `healing` states, durable JSON persistence, staged contingency leases, partition activity records, and reconciliation reports.
- Reused the Phase 154 receipt path instead of inventing an emergency side channel: contingency leases are signed consensus-issued artifacts tied to destructive action kinds, scope, TTL, and blast-radius caps, and the same governance seam now previews those leases during partition and validates redemption during dispatcher routing.
- Wired `AgentDispatcher` to fail closed on destructive partition-era requests unless a valid `contingency_lease` accompanies the existing `governance_receipt`, while still publishing structured partition transition and reconciliation runtime events for downstream SSE and audit consumers.
- Updated `PounceAgent` to attach both `governance_receipt` and `contingency_lease` evidence on partition-authorized destructive actions so downstream routing, persistence, and replay all see the same canonical authority payload.
- Surfaced the shared governance state on the serve surface by plumbing the policy through `swarm_detect` and `IngestState`, then exposing a `governance` component on `/healthz` and `/readyz` with partition status, quorum counts, active leases, unauthorized partition actions, and reconciliation markers.
- Added repo-owned runtime knobs for contingency lease TTL and blast-radius caps in `SwarmConfig.runtime`, shipped defaults in `rulesets/default.yaml`, and documented the new settings plus persisted governance state location in `docs/CONFIGURATION.md`.

## Notes

- The persistence path for partition authority is derived from the config location and currently resolves to `data/governance-partition-state.json`; it is runtime-owned behavior, not a separate YAML knob.
- Phase 155 deliberately stops at bounded partition authority. Byzantine fault injection, simulated partitions, and cascading-failure replay remain Phase 156 work.
