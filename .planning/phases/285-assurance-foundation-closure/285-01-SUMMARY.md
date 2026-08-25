---
phase: 285-assurance-foundation-closure
plan: "01"
subsystem: governance
tags: [witness, signed-failure, candidate-verification, conformance, mutation-testing]
requires:
  - phase: 285-assurance-foundation-closure
    provides: accepted witness request, session-fence, envelope, and service-wire checkpoints through a9837f2
provides:
  - closed signed witness response and failure contracts
  - independent candidate admission and post-genesis-abort Prepare verification
  - exact 58-row Phase 285 witness conformance registry with mutation-sensitive self-tests
  - fail-closed Phase 285 checker, schema, and initial CI wiring surface
affects: [285-02, witness-store, witness-proxy, phase285-closure]
tech-stack:
  added: []
  patterns: [opaque verified admission values, exact tuple registries, immutable-tree hostile review]
key-files:
  created:
    - crates/swarm-governance/src/witness_candidate_verifier.rs
    - crates/swarm-governance/tests/phase285_witness_conformance.rs
    - tools/check-phase285-witness-conformance.sh
  modified:
    - crates/swarm-governance/src/witness_service.rs
    - .github/workflows/ci.yml
    - tools/check-gates-wired.sh
key-decisions:
  - "Positive absent-stream issuance remains unavailable until Plan 02 supplies authenticated InspectReady evidence."
  - "A post-genesis-abort Prepare requires an opaque verified abort outcome and retains the abort receipt inside the prepared record."
  - "The exact selector, package, target, command, and case registry is frozen by an independent literal SHA-256 contract."
patterns-established:
  - "Every accepted slice is reviewed against an immutable Git tree before its production commit is created."
  - "Every exact selector proves nonzero execution and rejects omission, addition, duplication, target, command, and substring mutations."
requirements-completed: [ASSURE-04, ASSURE-06]
duration: 1h37m
completed: 2026-08-24
---

# Phase 285 Plan 01: signed witness response and candidate admission summary

**Closed signed witness failures, independent candidate admission, and a 58-row mutation-sensitive conformance surface were accepted on one immutable production tree.**

## Performance

- **Duration:** 1h 37m
- **Completed:** 2026-08-24
- **Tasks:** 3
- **Files modified:** 11

## Accepted objects

- **Production commit:** `f29f28324d9c9c00ac1fd429c27a54147aad1b17`
- **Direct parent:** `a9837f210b50bb391e6902e1e24ef84e4a8da4dc`
- **Reviewed tree:** `c53c6c7e9d48be3c2b8e09404d4e5eb9102814aa`
- **Remote refs:** `work/v179-phase285-plan01` and `checkpoint/v179-phase285-plan01`
- **Independent review:** P0/P1/P2/P3 = `0/0/0/0`, confidence high

## Delivered

- Added closed operation-specific witness responses and signed, matchable failures bound to the exact request, admission, witness, and present-store digest.
- Added independent, non-forgeable candidate admission with exact authority, binding, session, payload, predecessor, bound, and post-genesis-abort checks before a pure Prepare transition.
- Added the complete 58-tuple selector/package/target/command/case registry. Twelve selector self-tests produced 96 deliberate failures through the real registry validator.
- Added fail-closed Phase 285 witness, deployment, closure, evidence, and plan-schema checkers, the nested plan schema, initial CI registration, and gate-wiring controls.

## Verification evidence

- Exact selectors: `response-failure-wire` 4/4, `candidate-verifier` 3/3, and `protocol-checkpoint` 3/3. Every case ran exactly once with zero failed or ignored cases.
- `swarm-governance`: 133 unit tests, 10 integration tests, and one compile-fail doctest passed.
- Strict all-target/all-feature clippy with `-D warnings`, workspace formatting, cached diff checks, shellcheck, and actionlint passed.
- Plan-schema mutation self-test passed; the separately frozen draft corpus validated 13/13 while the production no-argument invocation failed as required.

## Deviations from plan

- The production slice used one atomic commit rather than one commit per task because the explicit convergence goal required one frozen, independently reviewed tree and one banked checkpoint.
- The first frozen tree was rejected at P0/P1/P2=`0/2/1`. One bounded repair added exact post-genesis-abort Prepare handling, replaced the circular registry check with a frozen exact tuple contract, and added self-consistent re-signed foreign candidates. The repaired tree passed at `0/0/0`.
- No Phase 02-07B implementation or planning files were added to the production commit.

## Next-plan readiness

Plan 02 may now define the revision-CAS store, deterministic reference model, authenticated `InspectReady` result, and typed proxy on top of `f29f283`. Plan 02 still requires an isolated plan audit against that exact accepted tree before execution.

---
*Phase: 285-assurance-foundation-closure*
*Completed: 2026-08-24*
