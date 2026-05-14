# Phase 235 Context

Date: 2026-04-13
Requirement: `STATESIG-04`

## Goal

Add monotonic sequence numbers across all signed learned-state artifacts and reject replay of older persisted state.

## Scope

- Carry a sequence number inside every signed learned-state statement.
- Persist the newest accepted sequence beside each signed behavioral baseline, Sphinx graph snapshot, population state, and episode report.
- Reject replayed older artifacts once a newer sequence has been accepted for the same state stream.

## Key Decisions

- Replay detection is enforced centrally in `swarm_core::signed_state::SignedStateExpectation`.
- Each store owns a minimal sidecar sequence ledger so replay prevention stays explicit and inspectable.
- Store-level tests prove replay rejection on the three learned-state surfaces instead of relying only on the shared unit test.
