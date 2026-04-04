# Phase 51 Context

## Goal

Persist portfolio history that measures cross-cohort survival, rollout outcomes, and review debt over time.

## Inputs

- Packet sets now provide one durable grouping layer above governance-ready packets.
- Strategy memories already persist durable rollout outcomes from completed canary and production-promotion artifacts.
- Operators needed historical views that reuse those rollout outcomes rather than copying canary or promotion state into a second store.

## Constraints

- Derive history from existing strategy memories instead of duplicating rollout state.
- Fail closed when a supposedly ready governance packet carries inconsistent proof, validation, shadow, or blocking state.
- Preserve review debt for unobserved packet-set entries so cohorts stay inspectable over time.
