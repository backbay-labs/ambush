# Phase 47 Context

## Goal

Assemble durable portfolio artifacts from ranked selections spanning multiple mutation batches or campaign cohorts.

## Inputs

- `v1.14` already persists durable ranked-candidate selections under `data/evolution-selections/`.
- Each selection already preserves ranking, validation, proof, advisory, shadow, and queue-lineage references.
- Operators needed one stable artifact that groups multiple ranked selections into one curated review surface without reopening the rollout lanes.

## Constraints

- Keep portfolio assembly operator-triggered and non-mutating for queue, canary, and production state.
- Reuse ranked selection and ranking artifacts instead of regenerating experiment evidence.
- Preserve blocked upstream state instead of silently filtering it out of the assembled portfolio.
