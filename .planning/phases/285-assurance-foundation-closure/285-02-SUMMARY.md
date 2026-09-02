---
phase: 285-assurance-foundation-closure
plan: "02"
subsystem: governance
tags: [witness-store, revision-cas, reference-model, typed-proxy, mutation-testing]
requires:
  - phase: 285-assurance-foundation-closure
    provides: accepted Plan 01 response and candidate-verifier checkpoint f29f283
provides:
  - revision-CAS witness-store contract with authenticated current-state validation
  - independent deterministic in-memory reference oracle and differential fault matrix
  - typed proxy with static readiness, exact backend call ordering, and ambiguous-outcome refusal
  - exact 20-case materialized witness conformance inventory over the frozen 58-row registry
affects: [285-03A, witness-transport, jetstream-store, phase285-closure]
tech-stack:
  added: []
  patterns: [independent semantic oracle, authenticated read-before-CAS, immutable-tree hostile review]
key-files:
  created:
    - crates/swarm-governance/src/witness_engine/store.rs
    - crates/swarm-governance/src/witness_engine/store/in_memory.rs
    - crates/swarm-governance/src/witness_engine/store/proxy.rs
    - crates/swarm-governance/src/witness_engine/store/tests.rs
  modified:
    - crates/swarm-governance/src/witness_engine.rs
    - crates/swarm-governance/tests/phase285_witness_conformance.rs
    - tools/check-phase285-witness-conformance.sh
key-decisions:
  - "Reference validation independently reconstructs production semantics instead of calling production validators."
  - "InspectReady performs exactly one authenticated read per sorted admitted stream and derives no trust from unsigned backend summaries."
  - "Ambiguous CAS outcomes remain closed unless an authenticated diagnostic read proves exact non-application; they are never retried or upgraded to success."
patterns-established:
  - "Every coherent differential mutant is rebuilt, re-digested, and re-signed so the intended semantic predicate—not an earlier signature check—kills it."
  - "Static Ready metadata is separated from authenticated per-stream revision and digest evidence."
requirements-completed: [ASSURE-04, ASSURE-06]
duration: 1h55m
completed: 2026-08-25
---

# Phase 285 Plan 02: revision-CAS store, reference model, and typed proxy summary

**Accepted an authenticated revision-CAS witness-store boundary, independent semantic oracle, and fail-closed typed proxy on one immutable production tree.**

## Performance

- **Duration:** 1h 55m
- **Completed:** 2026-08-25
- **Tasks:** 3
- **Files modified:** 7

## Accepted objects

- **Production commit:** `ff762236a216f44d26da90d7b3fe7eeecc3d178d`
- **Direct parent:** `f29f28324d9c9c00ac1fd429c27a54147aad1b17`
- **Reviewed tree:** `5a206ebfe472d370e7eb1326b70c91b0c5e91d91`
- **Plan SHA-256:** `a1c0babc48de3e383a5f0767bc367eb4609999aecaae36f95b73e3e4852e6c1f`
- **Remote refs:** `work/v179-phase285-plan02-r2` and `checkpoint/v179-phase285-plan02`
- **Independent review:** P0/P1/P2 = `0/0/0`, confidence high

## Delivered

- Added typed store requests, responses, logical revisions, compare-and-swap outcomes, authenticated readiness state, and exact static configuration validation without exposing transport capabilities to governance.
- Added a deterministic in-memory store and independently implemented reference state machine covering Ready validation, four exact transitions, conflicts, ambiguity, fault preservation, and byte-identical refusal behavior.
- Added a typed proxy that canonicalizes and authenticates before backend access, performs exact read/CAS/confirmation ordering, rejects coordinated unsigned substitutions, and never retries ambiguous mutation.
- Extended the frozen witness registry to 20 materialized cases while preserving its exact 58-row digest and keeping all future selectors fail-closed.

## Verification evidence

- Exact selectors: `response-failure-wire` 4/4, `candidate-verifier` 3/3, `protocol-checkpoint` 3/3, `atomic-store-contract` 3/3, `in-memory-differential` 4/4, and `typed-proxy` 3/3. Every exact case reported 19 filtered tests and every selector killed eight checker mutations.
- `swarm-governance`: 133 library tests and 20 Phase 285 conformance tests passed with zero failures or ignored cases.
- Strict all-target/all-feature clippy with `-D warnings`, workspace formatting, shellcheck, and diff checks passed.
- `transport-layering`, `jetstream-cas`, `jetstream-checkpoint`, `public-dispatcher`, `full-service-path`, and `service-checkpoint` remained deliberately red because later plans do not yet exist on this lineage.

## Deviations from plan

- The original Plan 02 implementation was quarantined after the first two-hour window failed convergence. The plan was redesigned around static/dynamic readiness separation, a complete independent oracle, and executable coherent mutants before this clean re-execution began.
- Three immutable review rounds rejected incomplete reference-oracle parity. Bounded repairs added complete nested Ready validation, unconditional genesis-abort namespace binding, exact bucket-prefix and derived-subject rules, NUL rejection, and coherent rebuilt controls. The final frozen tree passed at `0/0/0` before commit.
- The production slice used one atomic commit rather than one commit per task because the governing convergence objective required one reviewed tree and one banked checkpoint.
- No Plan 03A-07B, dirty integration-tree, or Phase 286-289 files were changed.

## Next-plan readiness

Plan 03A may now add only the transport-library boundary and its dependency/negative controls on top of `ff762236`. Its plan must first be audited against this exact accepted tree. JetStream mutation, restart, and checkpoint behavior remains exclusively Plan 03B scope.

---
*Phase: 285-assurance-foundation-closure*
*Completed: 2026-08-25*
