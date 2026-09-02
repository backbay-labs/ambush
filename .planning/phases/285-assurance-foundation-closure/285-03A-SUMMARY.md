---
phase: 285-assurance-foundation-closure
plan: "03A"
subsystem: governance-witness-transport
tags: [cargo-boundary, dependency-closure, ci-wiring, mutation-testing, fail-closed]
requires:
  - phase: 285-assurance-foundation-closure
    provides: accepted Plan 02 revision-CAS store/reference/proxy checkpoint ff762236
provides:
  - library-only downstream witness transport package with exact declared and resolved dependency boundaries
  - package-ID and target-aware closure checker with exact-subject mutation controls
  - six-row transport layering executor over the frozen 58-row witness registry
  - exact Phase 285 CI wiring and immutable-base global-wiring no-regression differential
affects: [285-03B, jetstream-store, witness-service, phase285-closure]
tech-stack:
  added: [async-nats transport crate]
  patterns: [exact package-ID closure, same-engine mutation controls, immutable-base wiring differential]
key-files:
  created:
    - crates/swarm-governance-witness/Cargo.toml
    - crates/swarm-governance-witness/src/lib.rs
    - tools/check-witness-dependency-closure.sh
    - tools/fixtures/phase285-layering/README.md
  modified:
    - Cargo.toml
    - Cargo.lock
    - .github/workflows/ci.yml
    - tools/check-workspace-layering.sh
    - tools/check-single-governor-key.sh
    - tools/check-negative-registry.sh
    - tools/check-phase285-witness-conformance.sh
    - tools/check-gates-wired.sh
key-decisions:
  - "The transport crate depends downstream on governance and owns async-nats; governance cannot import transport."
  - "Normal, dev-root, combined dev, and build closures are computed independently from locked metadata and cross-checked against exact Cargo-tree package IDs."
  - "Global authority and negative-registry inventories remain pending their one-time final refresh in Plan 07B; this slice runs only scoped transport controls."
  - "The parked Phase 286 checker remains the exact accepted-base global wiring singleton and is neither wired nor exempted by Phase 285 Plan 03A."
patterns-established:
  - "Mutation fixtures project the actual workspace subject independently of the policy under test and verify byte identity before mutation."
  - "All scratch writers reject repository and Git-boundary overlap before their first content write and prove cleanup under hostile TMPDIR."
requirements-completed: [ASSURE-02, ASSURE-06]
duration: 2h38m
completed: 2026-08-25
---

# Phase 285 Plan 03A: downstream transport and dependency-boundary summary

**Accepted a library-only witness transport package, exact locked dependency boundary, and non-vacuous CI/registry wiring without adding JetStream code, service binaries, or a Phase 286 execution claim.**

## Performance

- **Duration:** 2h 38m
- **Completed:** 2026-08-25
- **Tasks:** 1 with two mandatory internal checkpoints
- **Files modified:** 12

## Accepted objects

- **Production commit:** `cf0ad8b287a23fd1a4b57c922c8318b77c2cea81`
- **Direct parent:** `ff762236a216f44d26da90d7b3fe7eeecc3d178d`
- **Reviewed tree:** `69f369942c366595cb893e151aa89a4acb12cd20`
- **Intermediate package/closure tree:** `f7ee9528a1b9310c0053566b6b799550b5dcd118`
- **Accepted plan checkpoint:** `21bb9680eb59814e0770a66ff87e45d309cb94d0`
- **Plan SHA-256:** `ba4d4ed6fc8e0be18eceaab7dfee6e8fa35795cbe81a7e765552326e45eb777d`
- **Remote refs:** `work/v179-phase285-plan03a` and `checkpoint/v179-phase285-plan03a`
- **Independent final review:** P0/P1/P2 = `0/0/0`, confidence high

## Delivered

- Added the library-only `swarm-governance-witness` crate with an exact 11-normal/one-dev/zero-build direct dependency contract, one exact library target, and no premature binaries.
- Added a closure checker that retains exact locked package identities, canonical workspace paths, declared dependency kinds, independent normal/dev-root/dev/build traversal, Cargo-tree parity, and future target-aware compilation.
- Added a 16-control exact-subject mutation corpus. Every case copies all 22 metadata-derived workspace package roots, verifies 352 byte identities and target configuration, confines scratch state, and proves cleanup.
- Materialized the six shell-only `transport-layering` rows without changing the frozen 58-row registry digest. The live executor and omission/zero controls use the same actual-result ledger validator.
- Added the exact seven materialized witness selectors plus library-only closure to CI. One structural workflow parser serves normal, self-test, and differential modes and kills workflow, checker, and base/candidate mutations.

## Verification evidence

- Locked `cargo check` for library and tests passed. Strict all-target/all-feature clippy, workspace formatting, shellcheck, actionlint, and diff checks passed.
- Dependency closure passed with one library, zero binaries, declared dependencies 11/1/0, resolved normal/dev/build/dev-root counts 165/165/171/37, six exact internal package identities, four Cargo-tree ID comparisons, and zero forbidden packages.
- Closure self-test: 16/16 targeted mutations passed; the future all-target mode remained deliberately red for the three absent Plan 04 binaries.
- Transport selector: 6/6 actual commands passed with six actual mutation failures. Registry self-test retained 12 selectors, 58 exact rows, digest `a3a3ec459600ac3163a9b66aa40aa39e9387c50cc75b1e765d9f0693ddb8983b`, and 96 mutation failures.
- Prior selectors remained green: response 4/4, candidate 3/3, protocol 3/3, atomic 3/3, differential 4/4, and proxy 3/3.
- Workflow self-test rejected 32/32 invocation mutations and six checker substitutions. Immutable-base differential rejected 20/20 mutations with zero subject writes and preserved exact base/candidate unwired counts of one.
- Workspace-layering real-tree validation and 11 fixture cases passed. Five later witness selectors remained deliberately red.

## Deviations from plan

- Stage one required four rejected immutable audits before the independent package projection, package-ID traversal, Cargo-tree parity, dev-root proof, target compilation, and scratch confinement all became non-vacuous. Its final intermediate tree passed `0/0/0` before stage two began.
- The first two-hour Plan 03A window stopped uncommitted because the original automated command demanded global gates already red on accepted base. The plan was redesigned and independently reaccepted rather than wiring Phase 286 or refreshing global assurance inventories prematurely.
- Plan 07B remains the sole owner of the final single-governor and negative-registry inventory refresh after all Phase 285 bytes freeze. Their normal modes are intentionally not claimed green here.
- Normal global gate wiring still reports exactly the accepted parked `tools/check-collective-hypothesis-graph.sh` singleton. The Plan 03A differential proves this slice introduced no new unwired gate; it does not claim global wiring closure.
- No JetStream implementation, integration test target, service binary, hosted evidence, external App enforcement, or Phase 286 advancement was added.

## Next-plan readiness

Plan 03B may now implement the pinned NATS 2.11.17 raw projection, leader-mediated revision CAS, restart controls, and non-skipping JetStream harness on top of `cf0ad8b`. It must first be audited against this exact accepted tree. Service binaries and public/private runtime paths remain Plan 04 scope.

---
*Phase: 285-assurance-foundation-closure*
*Completed: 2026-08-25*
