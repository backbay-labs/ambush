# Phase 232 Context

Date: 2026-04-13
Requirement: `STATESIG-01`

## Goal

Sign behavioral baseline snapshots before persistence and verify them on restore with fail-closed semantics.

## Scope

- Add a shared signed learned-state envelope in `swarm-core`.
- Sign behavioral baseline snapshots in the local-journal and JetStream substrate paths.
- Thread the runtime signing identity through detector persistence and restore.

## Key Decisions

- The shared signed statement stores `payload_json` as the exact serialized payload string so float-heavy learned state round-trips without signature drift.
- Restore paths verify the signed envelope before decoding the typed payload.
- Baseline stores keep a sidecar sequence ledger so later phases can reject replayed older snapshots.
