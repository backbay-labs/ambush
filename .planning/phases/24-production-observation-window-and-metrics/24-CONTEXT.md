# Phase 24 Context

## Goal

Observe the promoted production detector over a bounded window and enforce automatic rollback when post-promotion metrics diverge.

## Current Reality

- Canary already records divergence, latency, and budget metrics over a bounded event window.
- Production promotion will need similar metrics, but the promoted detector now acts as production and the previous baseline becomes the rollback comparator.
- No production observation window or automatic rollback exists today.

## Constraints

- Reuse existing detector comparison patterns where practical.
- Keep the observation model deterministic and auditable.
- Avoid hidden runtime mutation; persist the observation state explicitly.

## Likely Implementation Shape

- Record promoted-vs-rollback-target metrics on each ingested event.
- Reuse event-count observation windows first, matching the canary milestone’s deterministic approach.
- Trigger automatic rollback when divergence, latency, or detection-volume budgets fail.

## Success Checks

- Promotion records post-promotion metrics over a bounded window.
- Observation can complete cleanly when metrics remain within bounds.
- Divergent promoted behavior causes automatic rollback with durable reasoning.
