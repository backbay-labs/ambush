# Phase 40 Verification

## Checks

- `cargo test -p swarm-runtime drafting --quiet`
- Real CLI flow: `verification -> scorecard -> pressure -> draft -> draft promote -> materialize -> validation refresh -> queue reconcile -> accept-for-canary -> handoff create`

## Evidence

- Reconciliation records reload by stable ID through `load_queue_reconciliation` and `swarmctl evolution-queue-reconciliation-result`.
- The accepted reconciled proposal feeds the existing `evolution-handoff-create` path without restating experiment or proof metadata by hand.
- A blocked materialized candidate remains blocked through reconciliation and does not become handoff-ready.

## Verdict

Phase 40 passed.
