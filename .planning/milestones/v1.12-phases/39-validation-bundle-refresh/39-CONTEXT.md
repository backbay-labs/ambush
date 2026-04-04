# Phase 39 Context

## Goal

Refresh experiment evaluation, verification, proof, and shadow artifacts from one materialized candidate.

## Inputs

- Phase 38 now produces concrete experiment manifests from drafts.
- The repo already had experiment, verification, proof, shadow, and advisory scorecard workflows.
- Validation needed to preserve one durable artifact chain and fail closed on drift.

## Constraints

- Reuse existing evaluation lanes instead of duplicating logic.
- Persist blocked validation bundles for review instead of silently failing.
- Detect manifest and lineage drift before queue reconciliation.
