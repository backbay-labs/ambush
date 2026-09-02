---
phase: 286-collective-hypothesis-graph
plan: 01C
wave: 6
status: complete
---

# Phase 286 Plan 01C: post-Plan-03 reasoning contracts

Implemented the additive contracts required after the historical Plan 03
store boundary. Existing `TaskCompletion`, `StrategyMemory`, and
`GraphSchedulerKey` wire fields remain unchanged.

## Delivered

- `derive_logical_task_id` derives a claimant-independent canonical task ID
  from graph, typed target, task kind, and a strict lowercase SHA-256 seed digest. Claimant-scoped
  `IdempotencyKey` derivation remains in `TaskClaimRequest`.
- `TaskDecisionLink`, `TaskCapabilityProof`, and `TaskTerminalEnvelope` bind
  challenge/falsification terminals to typed targets, evidence, decisions,
  claimant identity, signed scope, canonical claim digest, completion kind,
  lease ID, and fencing token.
- `validate_completion_kind` closes the task/completion vocabulary.
- Every new durable record has `deny_unknown_fields` wire decoding followed by
  semantic validation; capability and expiry signatures verify canonical
  bytes before admission.
- `GraphSchedulerKey` now orders by logical ready time ascending, priority
  descending, explicit closed task-kind rank, and task ID ascending. This is
  the `BTreeSet::pop_first` dispatch order consumed by runtime scheduling.
- `SchedulerBudget` persists its logical tick and usage counters, performs
  atomic per-tick work/claim admission, rejects stale ticks, and cannot be
  reset through restart or serialization.
- `GraphPolicyMode` is a closed, behavior-bearing enum with evidence-first,
  contradiction-challenge, and conservative-reversible-containment signals.
- `StrategyMemoryExpiryEnvelope` signs memory ID/digest and logical creation/
  expiry times, rejects zero/overflow/over-limit TTLs, treats exact expiry as
  inactive, and exposes `validate_for` for store-level memory binding.
- Added serde-defaulted `max_memory_ttl_ticks`,
  `max_work_units_per_tick`, and `max_claims_per_tick` config limits. Top-level
  config validation rejects zero or over-bound values without changing the
  signed default ruleset.

## Verification and mutation coverage

Passed:

```text
cargo test -p swarm-core config::tests::hypothesis_graph --lib --locked --offline
  5 passed
cargo test -p swarm-core hypothesis_graph --lib --locked --offline -- --test-threads=1
  23 passed
cargo clippy -p swarm-core --all-targets --locked --offline -- -D warnings
  passed
cargo fmt --all -- --check
  passed
git diff --check
  passed
```

The focused tests exercise deterministic logical identity, malformed/varied
seed digests, claimant/key/signed-scope binding, producer/completion binding,
wrong completion kind,
challenge/falsification evidence and decision lineage, priority inversion,
budget overrun/restart persistence/stale-tick refusal, logical exact-expiry,
expiry digest tampering, unknown
expiry schema, config default migration, and config limit mutations.

No P0, P1, or P2 issue was identified in this slice. The only non-owned file
touch is the minimal existing `SwarmConfig::validate` seam required to enforce
the three new config bounds at top-level admission; the signed ruleset was not
modified.
