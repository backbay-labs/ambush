---
phase: 286-collective-hypothesis-graph
plan: 03B
wave: 7
status: complete
requirements-completed: [COG-03, COG-07, COG-08]
---

# Phase 286 Plan 03B: spine boundary and logical-time memory summary

Implemented the additive spine adapter on committed Plan 01C `b26e2af`. The
historical `HypothesisGraphStore::{snapshot, compare_and_swap}` protocol is
unchanged; no runtime coordinator, second task ledger, decision history, or
terminal outbox was added.

## Delivered

- Memory and file graph CAS now reject a candidate whose logical-time
  high-water regresses and carry a higher accepted high-water into the
  published state. Existing graph/task/tombstone/fence checks remain at the
  same CAS seam.
- `validate_task_terminal_envelope` delegates durable admission to core
  `TaskTerminalEnvelope::validate_for_task(task, limits.max_task_lease_ms,
  limits.max_task_retries)`, which in turn applies
  `TaskCapabilityProof::validate_for_claim` and exact task, idempotency, active
  lease, fence, completion, producer, and lineage checks.
  The spine only checks the supplied capability is the envelope capability
  and that persisted decision lineage targets the task target. It does not
  pretend to re-derive a logical `TaskId` without a seed; the additive
  `validate_task_logical_identity(graph_id, task, seed_digest)` helper requires
  that seed explicitly.
- Strategy-memory append-at-time paths persist a signed core
  `StrategyMemoryExpiryEnvelope` sidecar keyed by the unchanged memory ID.
  The envelope binds memory digest, `created_at`, and `expires_at`, uses the
  validated deployment `max_memory_ttl_ticks` through `new_with_limit`, and is
  checked with `is_applicable_at_with_limit` on state load/retrieval. Missing
  sidecars remain legacy/quarantined and are excluded from logical retrieval;
  applicability is exactly
  `created_at <= now < expires_at` with injected `GraphLogicalTime`.
- Config-bound constructors/open paths persist and enforce the deployment TTL
  ceiling for both memory and file stores. A lower-ceiling append is rejected
  without mutation, and reopening a file store under a lower ceiling fails
  closed. `append_at` on an identical legacy sidecarless record is also an
  explicit quarantine error rather than a silent idempotent success.
- Legacy signed Plan 03 state is authenticated using its exact old canonical
  shape before any new fields are materialized. Empty sidecars and absent TTL
  metadata are skipped during serialization, and a true signed legacy file
  fixture reopens with byte-identical `state.json`.
- Memory and file stores expose matching `append_at`/`retrieve_at` behavior,
  including restart parity and canonical state-digest parity. The existing
  legacy `append`/`retrieve` surface remains available without a host clock;
  records created there have no expiry proof and are therefore not returned by
  logical-time retrieval.
- Added `reasoning_state_contract.rs` covering CAS high-water mutation,
  durable terminal admission/fence mutation, config-bound scheduler ordering/
  budget rejection, memory/file expiry boundary and restart parity, lower TTL
  mutation, and legacy sidecar quarantine.

## Verification evidence

- `cargo test -p swarm-spine --test reasoning_state_contract --no-default-features
  --locked --offline`: **5 passed, 0 failed**.
- `cargo test -p swarm-spine --lib --no-default-features --locked --offline
  strategy_memory::tests::`: **13 passed, 0 failed** before the new legacy
  fixture; the focused legacy fixture then passed **1 passed, 0 failed**.
- `cargo check -p swarm-spine --tests --no-default-features --locked --offline`:
  passed after the live core scheduler/terminal signature update.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.

The final all-target spine test/clippy run is intentionally left for the root
agent on the combined concurrent tree.

## P0/P1/P2 review

- P0: none found.
- P1: final combined all-target spine/clippy gates remain to be run by the
  root agent after concurrent core/runtime edits settle; no owned-slice failure
  is currently observed.
- P2: none found. Legacy sidecarless records are an intentional quarantined
  compatibility path, not an expiry admission bypass.

No commit was created by this execution.
