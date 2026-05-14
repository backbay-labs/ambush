# Phase 234 Context

Date: 2026-04-13
Requirement: `STATESIG-03`

## Goal

Sign evolution population and episode artifacts before persistence and verify them on restore.

## Scope

- Sign `state.json` for the durable evolution population store.
- Sign per-episode reports in the evolution episode store.
- Thread runtime signing identity through `DefaultEvolutionMutationHarness`, `KittenAgent`, and ingest feedback paths.

## Key Decisions

- Population state uses a single signed stream keyed as `population`.
- Episode reports use one signed stream per `episode_id`.
- Restore paths verify the trusted signer identity before rehydrating proposal-ready population state.
