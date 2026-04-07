---
phase: 87-multi-instance-coordination-and-cleanup
plan: 01
subsystem: pheromone
tags: [pheromone, jetstream, multi-instance, coordination, tests]
requirements-completed: [SUB-02, SUB-03]
one-liner: "ignored multi-instance integration coverage now proves cross-instance visibility, distinct-source aggregation, and min-sources escalation behavior against a shared JetStream bucket."
completed: 2026-04-05
---

# Phase 87 Plan 01 Summary

**ignored multi-instance integration coverage now proves cross-instance visibility, distinct-source aggregation, and min-sources escalation behavior against a shared JetStream bucket.**

## Accomplishments

- Added `crates/swarm-pheromone/tests/multi_instance.rs` with four ignored live-NATS integration tests covering cross-instance visibility, shared deposit queries, min-source gating, and repeated single-instance deposits.
- Verified that two substrate instances pointed at the same JetStream bucket observe each other's deposits through the public `PheromoneSubstrate` interface.
- Proved `distinct_sources` is still keyed by unique `agent_id` values instead of raw deposit count, so escalation only fires after enough independent instances contribute.
- Strengthened JetStream key generation to preserve repeated deposits from the same instance as distinct records while keeping the threat/timestamp/agent prefix needed for bucket scans.

## Files Created Or Modified

- `crates/swarm-pheromone/src/jetstream.rs`
- `crates/swarm-pheromone/tests/multi_instance.rs`

## Verification

- `cargo test -p swarm-pheromone --test multi_instance --no-run`
- `NATS_URL=nats://127.0.0.1:4223 cargo test -p swarm-pheromone --test multi_instance -- --ignored --nocapture`

## Notes

- The repo `docker-compose` NATS profile intentionally stays internal-only, so live host verification used a temporary JetStream container published on `127.0.0.1:4223`.
