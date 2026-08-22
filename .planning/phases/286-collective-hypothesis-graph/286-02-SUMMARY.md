---
phase: 286-collective-hypothesis-graph
plan: 02
subsystem: runtime-normalization
tags: [collective-reasoning, graph-clock, scheduler, evidence, witness, conflicts]
requirements-completed: [COG-04]
one-liner: "Runtime now exposes an injected GraphClock seam, source-scoped canonical event identity, bounded six-family evidence normalization, admitted-key signing, and visible conflicts."
completed: 2026-08-21
---

# Phase 286 Plan 02 Summary

The stable runtime slice now consumes existing typed telemetry and threat-intel
records and emits signed `swarm_core::hypothesis_graph::EvidenceEnvelope`
values.  No vendor JSON parser was added and no second logical-time type was
introduced.

## Accomplishments

- Added `swarm_runtime::hypothesis_graph::clock::GraphClock` with
  `FixedGraphClock::new(GraphLogicalTime)` and a separate host-clock
  observation wrapper.  `DeterministicScheduler` orders only the core
  `GraphSchedulerKey` fields, exposes readiness-gated `pop_ready(now)`,
  retains popped-task tombstones, and rejects non-idempotent task-ID
  rescheduling.  Tokio-yield, insertion-order, and host-clock perturbations
  produce the same queue.
- Event-node IDs now bind a bounded digest of source ID plus source-record ID
  in addition to event kind and observed time.  Equal vendor record IDs no
  longer alias graph entities, while the registry still treats same-source
  adapter aliases as one conflict stream.
- Added strict adapters for process, identity, Kubernetes audit, CloudTrail,
  network/DNS, and threat-intelligence records.  Adapters preserve source
  lineage, observed versus injected ingest time, precision/uncertainty, and
  unknown ordering while hashing bounded command lines, request/response
  objects, annotations, indicators, registry value name/data fields, and
  other raw projections.  Explicit source timestamp units are available while
  the legacy wrapper remains documented compatibility behavior.
- Extended typed CloudTrail metadata/entity references and typed threat-intel
  expiry with exact-boundary active/expired validation.  Account, actor, and
  event semantics never use legacy `host_id`; Tetragon `<none>` parents remain
  explicitly absent.
- Added base key-derived witness admission plus the `GraphRecordSigner` seam
  for signed/verified edges and decisions.  Scoped role labels are metadata,
  not independent identities.  `KeypairGraphRecordSigner::with_admission`
  snapshots the allowlist capability; an unadmitted signer cannot sign or
  verify.  Evidence, edge, and decision witness signatures bind canonical
  record bytes, producer identity/role, and scoped agent ID.  Exact envelopes are idempotent;
  malformed or tampered canonical bytes, unadmitted keys, and same-ID content
  changes fail closed.  Ingestion time is operationally signed but excluded
  from evidence identity/conflict facts.
- `EventNode` identity now includes stable source-record identity.  Core graph
  version mutations use one checked bump helper, including conflict removal;
  exhausted `u64::MAX` graphs fail before any mutation.  Direct
  `TypedEvidencePayload` deserialization goes through a validated wire enum,
  so malformed JSON cannot bypass typed semantic checks.
- Added a bounded `EvidenceRegistry` with aggregate evidence/byte/witness,
  per-source-record, and conflict limits enforced before cloning.  Source keys
  bind family/source/record identity while intentionally excluding adapter
  aliases; adjacent conflict indexing avoids all-prior conflict amplification,
  and `admit_into_graph` transactionally synchronizes additions and replaced
  conflicts into a candidate core graph.
- CloudTrail principal/account projections are event-scoped when identities
  are absent, and all supplied principal fields participate in the digest;
  account IDs never become hosts.  The behavior target covers missing-identity
  non-aliasing and lower-priority principal-field mutation.
- Bound scheduler ready entries, active task IDs, and lifetime tombstones by
  `GraphResourceLimits.max_tasks`, with the default policy and explicit custom
  limits threaded through `HypothesisGraphRuntime` construction.  Exact
  tombstone retries remain idempotent while new IDs fail closed at the cap.
- Tetragon process records with no source start timestamp retain detection
  telemetry but receive a deterministic fallback-origin event-ID marker.  The
  graph normalizer rejects that marker (and the equivalent source marker)
  before timestamp conversion, so host-clock perturbations cannot become
  causal IDs or conflicts.
- Renamed the signer integration target to
  `graph_record_signer_binds_edge_and_decision` and verified signed edge and
  decision tampering, including decision-rationale mutation.
- Added the separate `collective_hypothesis_graph.rs` behavior target covering
  all six source families, corroborating/conflicting records, source-time
  conflicts, same-record fact changes, cross-source IDs, adapter variation,
  role aliases, tampering, expiry/DNS/CloudTrail semantics, host-clock drift,
  scheduler perturbation, raw size/depth/node/list caps, resource limits,
  transactional rollback, and nested raw-secret exclusion.  The sealed
  `collective_hypothesis_oracle.rs` and all planning files were left untouched
  by this implementation.

## Verification

- `cargo check -p swarm-runtime --lib` — passed on the current combined tree.
- `cargo test -p swarm-core --lib` — 105 passed, 0 failed.
- `cargo test -p swarm-runtime --lib` — 409 passed, 0 failed.
- `cargo test -p swarm-ingest-tetragon --lib` — 16 passed, 0 failed (mapper focus: 8 passed).
- `cargo test -p swarm-runtime hypothesis_graph::clock --lib` — 7 passed.
- `cargo test -p swarm-runtime hypothesis_graph::normalize --lib` — 4 passed.
- `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact graph_record_signer_binds_edge_and_decision --nocapture` — 1 passed (1 test executed).
- `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --nocapture` — 14 passed.
- `cargo clippy -p swarm-core --lib -- -D warnings` — passed.
- `cargo clippy -p swarm-core --all-targets -- -D warnings` — passed.
- `cargo clippy -p swarm-runtime --lib --no-deps -- -D warnings` — passed.
- `cargo clippy -p swarm-runtime --test collective_hypothesis_graph --no-deps -- -D warnings` — passed.
- `cargo clippy -p swarm-runtime --all-targets -- -D warnings` — passed.
- `cargo clippy -p swarm-ingest-tetragon --lib --no-deps -- -D warnings` — passed.
- `cargo clippy -p swarm-ingest-tetragon --all-targets -- -D warnings` — passed.
- `rustfmt --edition 2024 --check` on all owned Rust files — passed.
- `cargo fmt --all -- --check` — passed on the current combined tree.
- `git diff --check` plus the owned-file whitespace audit — passed.

## Boundary

This plan does not add durable spine stores, hypothesis adjudication,
containment planning, benchmark logic, or the post-Plan-06B compile contract.
No response/policy/receipt/lease/executor authority is imported.
