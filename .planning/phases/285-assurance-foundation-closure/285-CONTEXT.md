# Phase 285 Context: Assurance Foundation Closure

## Decision

Phase 285 is reopened. The 2026-08-21 verification closed the original assurance-evidence scope, but it did not cover the subsequently reopened governance/detector integration gate. Phase 285 may return to `passed` only after that gate is implemented and one immutable combined tree satisfies the full local, adversarial, independent-review, hosted, and closure contract.

Provenance-distinct external GitHub App and repository protected-required-check enforcement remain explicitly deferred. The reopened work must not represent either as wired, executed, passed, or protected-required.

## Accepted frozen basis

The following immutable checkpoints are banked inputs, not evidence that the phase is complete:

| Slice | Commit | Acceptance state |
|---|---|---|
| Approval and voter hardening | `f2eb791d` | Accepted checkpoint |
| Persistence architecture | `5be011a0` | Independent architecture review: P0=0, P1=0, P2=0 |
| Authenticated persistence protocol model | `27b64174` | Accepted production/model checkpoint |
| Exact witness-adapter contract | `eacadf6b` | Independent contract review: P0=0, P1=0, P2=0 |
| Bounded witness session fence | `3a584882` | Accepted checkpoint |
| Authenticated witness-envelope model | `296bb983` | Accepted checkpoint |
| Witness request/service wire | `a9837f21` | Independent implementation review: P0=0, P1=0, P2=0 |

The separately accepted Phase 286 Plan 04 checkpoint `1408620e` remains parked. It is not Phase 285 acceptance and cannot justify Phase 286 advancement.

## Locked contracts

- `285-WITNESS-ADAPTER-CONTRACT.md` is the normative wire, canonicalization, authentication, error-mapping, and boundedness contract.
- Persistence semantics are fixed by commit `5be011a0` at `.planning/phases/285-assurance-foundation-closure/285-GOVERNANCE-PERSISTENCE-PROTOCOL.md`.
- Ordinary enforced governance has no local-only, optional-witness, pathname-derived, unbounded-retention, or best-effort cleanup fallback.
- A green isolated package suite proves only its frozen slice. Every later edit invalidates evidence for the final combined tree until the exact new commit is rerun and reviewed.

## Remaining implementation scope

1. Complete witness failure-code and signed-attestation handling without collapsing authenticated protocol states into transport strings.
2. Implement the candidate verifier against exact canonical bytes, digest derivations, bounds, predecessor/head transitions, authority identity, and role distinctness.
3. Implement one production durability-witness adapter with typed compare-and-set semantics and a bounded durable backing service. Enforced persistence must refuse when it is absent, stale, conflicting, unauthenticated, or uncertain.
4. Expose the witness through the public governance service/binary and deployment/init path without sharing the local governance filesystem authority domain.
5. Finish fixed authenticated publication lanes, recovery, abort/commit resolution, retention, maintenance, reinitialization, and cleanup-pool exhaustion semantics from the reviewed protocol.
6. Inject enforced governance through the real runtime construction path; remove any optional or silently downgraded production route.
7. Integrate the detector selector guard and bounded cleanup handoff without fallback names, lost cleanup errors, or pathname identity assumptions.
8. Form one frozen combined Phase 285 commit and run the complete acceptance matrix, including hostile mutation and independent P0/P1/P2 review.
9. Obtain fresh hosted Linux evidence for that exact commit and update the closure ledger truthfully.

## Preserved assurance scope

- Preserve the parsed assumption registry, exact invariant mappings, negative-registry entries, fixture-freshness controls, and locked supply-chain/SBOM evidence.
- Bind SBOM components and dependency edges to locked `cargo metadata` resolution and retain graph/schema mutation controls.
- Require fresh, credential-free hosted Linux evidence with commit-bound machine-readable results and exact runner, toolchain, and input identity.
- Report `wired`, `executed`, `passed`, and `protected-required` as separate states.
- Leave no unresolved P0, P1, or P2 finding in the exact combined-tree review packet.

## Acceptance boundary

Phase 285 closes only when all of the following refer to the same immutable commit and tree:

- workspace tests and all Phase 285 focused suites pass;
- strict all-target/all-feature clippy and formatting pass;
- repository diff and assurance gates pass;
- non-vacuous mutation, differential, crash/recovery, race, replay, exhaustion, and negative controls pass;
- detector/governance integration tests traverse the production construction path;
- an independent hostile review reports zero P0, P1, and P2 findings;
- hosted Linux reruns the declared gates on a fresh credential-free checkout and publishes commit-bound evidence.

## Explicit non-claims

The phase does not claim a protected GitHub App check, protected-branch enforcement, distributed failover beyond the implemented witness contract, or release authorization. Local scripts, local services, workflow wiring, and isolated checkpoint reviews are useful evidence but are not provenance-distinct repository protection or final combined-tree acceptance.

## Sequencing

Phases 286-289 remain blocked. Do not resume Phase 286, publish Plan 04 as phase completion, or execute parked Phase 287-289 plans until Phase 285 has the exact combined-tree and hosted closure evidence above.
