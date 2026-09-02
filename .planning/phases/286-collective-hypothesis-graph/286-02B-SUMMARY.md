---
phase: 286-collective-hypothesis-graph
plan: 02B
wave: 7
status: complete
requirements-completed: [COG-01, COG-03, COG-04, COG-08]
---

# Phase 286 Plan 02B: runtime admission and logical-time hardening

Implemented the additive runtime hardening pass on top of committed 01C
`b26e2af`. No second normalizer, scheduler, or witness registry was added.

## Delivered

- `EvidenceRegistry` now keeps an explicit constructor-time key-derived
  allowlist snapshot for all admission decisions. The historical
  `witness_admission_mut()` compatibility view is inert and cannot grant a
  capability after construction.
- `KeypairGraphRecordSigner::new` remains constructible only as an unadmitted
  signer; signing and verification fail closed until `with_admission` binds the
  key-derived base `AgentId`. Scoped role aliases never substitute for that
  identity.
- Added transactional failure-spy coverage proving unadmitted witnesses,
  role/scope mutations, and allowlist mutations leave registry and graph bytes
  unchanged.
- Kept one source-record-bound `EventNode::new` normalization path, with a
  bounded non-empty source/source-record projection at the shared event-node
  boundary. Same-kind/same-time records with different source IDs remain
  distinct, while exact retries remain idempotent.
- Preserved the existing CloudTrail adapter and added named coverage for
  event-scoped unknown principal/account digests and lower-priority principal
  field mutation.
- Added direct typed-payload deserialization validation and graph-version
  overflow rollback probes.
- Kept `DeterministicScheduler::pop_ready` logical-time-only: future work is
  inspected before the consuming primitive and remains in ordered/contains/
  length/tombstone state until its declared ready time.
- Corrected the scheduler ordering contract documentation to state the exact
  comparator: ready time ascending, priority descending, task-kind dispatch
  rank, then task ID.
- `HypothesisGraphRuntime::with_limits` now rejects registry/scheduler
  `GraphResourceLimits` mismatches before constructing scheduler state. The
  failure path is covered by a byte-identical registry-state spy.
- Added `with_config`/`with_config_at` (and `new_with_config` aliases) as
  additive config-bound constructors. Enabled configurations retain a private
  validated `HypothesisGraphConfig` alongside one `SchedulerBudget`; every
  scheduler admission and budgeted logical-time pop passes that config back to
  core `SchedulerBudget::admit_at`.
- Added transactional budgeted pop/admission coverage, including future-task
  preservation, work/claim ceilings, disabled/default compatibility, and a
  serde-mutated budget whose self-declared ceiling exceeds the active config.

## Verification

Passed for the owned runtime targets on the combined checkout:

```text
cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline
  32 passed, 0 failed
cargo test -p swarm-runtime hypothesis_graph::normalize --lib --locked --offline
  4 passed, 0 failed
cargo test -p swarm-runtime hypothesis_graph::clock --lib --locked --offline
  7 passed, 0 failed
cargo test -p swarm-runtime --locked --offline
  413 library tests passed; compile-fail admission test, all runtime
  integration targets, and doctests passed; 0 failures
```

The eleven exact 02B probes also passed:

```text
unadmitted_graph_signer_is_rejected
role_scope_mutation_invalidates_witness
event_node_same_time_different_source_records_are_distinct
cloudtrail_unknown_identity_is_event_scoped
typed_evidence_payload_direct_deserialize_is_validated
graph_version_overflow_is_fail_closed
future_task_is_not_consumed_before_ready_time
runtime_with_limits_rejects_registry_scheduler_mismatch_without_mutation
config_bound_runtime_budget_gates_logical_pop_and_admission
serde_mutated_budget_above_active_config_is_rejected_without_pop
disabled_config_and_legacy_runtime_keep_unbudgeted_scheduler_behavior
```

Owned-file `rustfmt --edition 2024 --check` and `git diff --check` passed.
`cargo fmt --all -- --check` passed. Both
`cargo clippy -p swarm-runtime --all-targets --no-deps --locked --offline --
-D warnings` and the dependency-complete
`cargo clippy -p swarm-runtime --all-targets --locked --offline -- -D warnings`
passed.

## P0/P1/P2 review

- P0: none found.
- P1: none found in the owned runtime slice or the requested runtime gates.
- P2: none found.

No commit was created by this execution.
