---
gsd_state_version: 1.0
milestone: v1.28
milestone_name: Durable Substrate And Multi-Instance Coordination
status: ready-to-plan
last_updated: "2026-04-05T00:00:00Z"
progress:
  total_phases: 2
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-05)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** Phase 86 -- NATS JetStream Pheromone Backend

## Current Position

Phase: 86 of 87 (NATS JetStream Pheromone Backend)
Plan: --
Status: Ready to plan
Last activity: 2026-04-05 -- v1.28 roadmap created (2 phases, 4 requirements)

Progress: [░░░░░░░░░░] 0%

## Memory

- `v1.27` shipped HTTP EDR + webhook response adapters, Dockerfile, docker-compose, healthz, graceful shutdown, policy reload. 293 tests.
- docker-compose already includes optional NATS sidecar (profiles: nats).
- async-nats not yet in workspace deps -- needed for JetStream substrate.
- PheromoneSubstrate trait in swarm-pheromone has InMemory and LocalJournal backends.
- ConfiguredPheromoneSubstrate enum selects backend via config.
- swarm-bridge is a dead PyO3 shim -- safe to remove.
- kernel/ directory contains legacy Python stubs -- reference only.
- min_sources_for_escalation is already in config but only works within single instance.

## Next Command

Plan phase 86.
