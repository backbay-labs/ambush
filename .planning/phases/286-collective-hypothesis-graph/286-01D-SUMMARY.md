---
phase: 286-collective-hypothesis-graph
plan: 01D
status: complete
---

# Phase 286 Plan 01D Summary

Implemented the adversarial core regressions on top of committed Plan 01C
(`b26e2af`) without adding replacement identity, witness, payload, or version
APIs. The owned changes are limited to `swarm-core` and its configuration
tests.

## Required regressions

- `event_node_same_time_different_source_records_are_distinct` proves that
  same-kind events at one logical time remain distinct by source-record ID,
  while an exact source-record retry remains idempotent.
- `unsigned_witness_is_untrusted` proves unsigned witness metadata cannot be
  admitted and leaves canonical graph bytes unchanged.
- `typed_evidence_payload_direct_deserialize_is_validated` proves direct
  deserialization still applies semantic entity, digest, family, confidence,
  and logical-expiry validation.
- `graph_version_overflow_is_fail_closed` proves `u64::MAX` admission is
  rejected atomically without changing canonical bytes.

## Review fixes

- Added canonical `TaskClaimRequest::canonical_digest` and exact
  `TaskCapabilityProof::validate_for_claim` binding.
- Added signed terminal witnesses and durable
  `TaskTerminalEnvelope::validate_for_task`, binding the exact claim,
  idempotency key, active lease, fencing token, holder, completion, lineage,
  capability, producer, and terminal scope. `new` remains structurally valid
  but untrusted; `signed_with` is required for durable admission.
- Added config-bound `SchedulerBudget::new_with_config` and bounded validation,
  config-bound `admit`/`admit_at`, restart deserialization, and expiry
  construction/applicability with deployment TTL limits. Global/self-declared
  scheduler admission paths were removed; callers must provide the validated
  active configuration.
- `TaskTerminalEnvelope::validate_for_task` now validates the complete
  `TaskRecord` with explicit lease/retry bounds and requires decision lineage
  to target the exact claimed task target. Mutations of attempts, generation,
  and decision target are rejected.
- Replaced direct `HypothesisGraphConfig` deserialization with a validated wire
  boundary: unknown, zero, over-limit, and contradictory resource/reasoning
  limits now fail before a config object can be used.
- Added validated, canonical, digested `GraphPolicyContract`; mode and
  behavior mutations change the digest and unknown modes fail closed.
- Added signed default-ruleset hash and detached-signature verification in the
  configuration test suite.

## Verification evidence

- `cargo test -p swarm-core --lib --locked --offline -- --test-threads=1`: **119
  passed, 0 failed, 0 ignored**.
- Named event identity regression: **1 passed, 117 filtered**.
- Named unsigned witness regression: **1 passed, 117 filtered**.
- Named typed-payload regression: **1 passed, 117 filtered**.
- Named graph-overflow regression: **1 passed, 117 filtered**.
- `cargo test -p swarm-core config::tests::hypothesis_graph --lib --locked
  --offline`: **7 passed, 0 failed**.
- Config-bound scheduler/expiry restart and mutation regressions passed in the
  full core suite, including rejection of serialized budgets and expiry
  envelopes under narrower deployment limits.
- Direct `HypothesisGraphConfig` serde mutation regression: **1 passed**.
- `cargo clippy -p swarm-core --all-targets --locked --offline -- -D
  warnings`: passed.
- Targeted owned-file `rustfmt --edition 2024 --check`: passed.
- `cargo fmt --all -- --check`: blocked only by concurrent unowned
  `swarm-spine` formatting changes; no owned-file formatting differences remain.
- `git diff --check`: passed.

## Integration note

The owned core slice has no P0, P1, or P2 findings. The concurrent spine tree
requires follow-up call-site updates for the newly fail-closed APIs
(`validate_for_task` now takes explicit retry limits, scheduler admission now
requires `HypothesisGraphConfig`, and expiry applicability now requires the
active config); its test also still calls `.unwrap()` on the live direct-value
`MemoryProvenance::new(...)` constructor. These are outside this ownership
boundary. No spine or runtime files were changed to work around them.
