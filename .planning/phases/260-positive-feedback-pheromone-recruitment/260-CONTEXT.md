# Phase 260 Context

## Goal

Lower matching detector thresholds when trusted pheromone concentration proves a threat class is already recruiting corroboration.

## Repo State

- `v1.72` closed with a machine-readable platform contract and a bounded inbound SOAR verdict loop.
- The runtime already persists signed learned-state artifacts and exposes threat concentration across the substrate and platform surfaces.
- Recruitment and baseline-resistance work is the next active milestone and has not yet landed on the live runtime path.

## Phase Focus

- Define a bounded recruitment mechanism driven by trusted pheromone concentration for one matching threat class.
- Reuse the existing signed-state and substrate seams instead of creating a parallel mutable threshold store.
- Keep the recruited-threshold state explainable enough for later operator and benchmark proof.

## Verification Target

- Repo-owned tests showing recruited pheromone pressure can lower the matching threshold without widening unrelated detector lanes.
- Persistence or signing proof that the recruitment state is derived from trusted state rather than unsourced mutable counters.
