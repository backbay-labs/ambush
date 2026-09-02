---
phase: 285-assurance-foundation-closure
plan: "03B"
subsystem: governance-witness-jetstream
tags: [nats-2.11.17, jetstream-cas, restart-recovery, integrity-boundary, mutation-testing]
requires:
  - phase: 285-assurance-foundation-closure
    provides: accepted Plan 03A transport and dependency-boundary checkpoint cf0ad8b
provides:
  - closed pinned-NATS raw configuration and Stream.Info evidence before client normalization
  - fixed-subject leader-mediated JetStream read and confirmed revision-CAS repository
  - same-volume post-ack SIGKILL/restart proof for five authenticated witness states
  - root-pinned launcher and manifest integrity boundary for exact CAS and checkpoint selectors
affects: [285-04, witness-service, governance-persistence, phase285-closure]
tech-stack:
  added: []
  patterns: [closed raw DTO, stable-vs-complete snapshot evidence, non-lossy differential records, root-pinned local integrity]
key-files:
  created:
    - crates/swarm-governance-witness/src/jetstream_store.rs
    - crates/swarm-governance-witness/src/nats_config.rs
    - crates/swarm-governance-witness/src/raw_config.rs
    - crates/swarm-governance-witness/tests/jetstream_cas.rs
    - crates/swarm-governance-witness/tests/jetstream_checkpoint.rs
    - tools/check-phase285-witness-integrity.sh
    - tools/fixtures/phase285-witness-integrity.json
  modified:
    - crates/swarm-governance-witness/src/lib.rs
    - crates/swarm-governance/src/witness_engine/store.rs
    - docker-compose.yml
    - tools/check-negative-registry.sh
    - tools/check-phase285-witness-conformance.sh
    - tools/with-nats-jetstream.sh
key-decisions:
  - "Raw NATS evidence is decoded through an exact 2.11.17 DTO and retains complete per-read response bytes while stable Ready equality excludes mutable response ts."
  - "A publish acknowledgement is never Applied authority without exact nonduplicate increasing-sequence predicates and a leader-mediated authenticated confirming read."
  - "The integrity launcher is a local frozen-tree/root-integrator boundary; it does not claim resistance to coordinated repository mutation or external GitHub App enforcement."
  - "Checkpoint tests use fresh tree-bound invocation tokens and exact-package-only serial execution; selector case overrides remain command-scoped and authoritative."
patterns-established:
  - "Physical backend acknowledgement and authenticated diagnostic evidence remain separate closed observations in normalized ambiguity records."
  - "Restart, release-probe, iterator, and cumulative ledgers bind actual runtime evidence and reject stale, partial, cross-run, and forged-counter substitutions."
requirements-completed: [ASSURE-04, ASSURE-06]
duration: 17h03m
completed: 2026-08-26
---

# Phase 285 Plan 03B: pinned JetStream CAS and restart summary

**Accepted a closed NATS 2.11.17 evidence boundary, leader-confirmed revision CAS, and same-volume restart checkpoint on one immutable production tree without adding service binaries or claiming Phase 285 closure.**

## Performance

- **Duration:** 17h 03m from accepted parent commit to final production commit
- **Completed:** 2026-08-26
- **Tasks:** 3 with mandatory A, B, and C internal freeze/review boundaries
- **Files modified:** 13

## Accepted objects

- **Production commit:** `8abe28dbc42c444643ea473614bee7a8cf912b8b`
- **Direct parent:** `cf0ad8b287a23fd1a4b57c922c8318b77c2cea81`
- **Reviewed tree:** `7ce5ed8e7ae305153170ff92b71f79dc218ae1cf`
- **Accepted planning commit/tree:** `7880321235e12c8ebc1ed2f969f5182207b42f69` / `7a9fd4983998b69963a2fb12ca4cb34e825afb83`
- **Plan SHA-256/blob:** `acfd0f905fe66093553fa4a7f087be5412f58d6b459a8b9746e11a20e3996ab6` / `905fc3ffbc0ffced59e5f8765bd80d0dd4ae9f5a`
- **Remote refs:** `origin/work/v179-phase285-plan03b` and `origin/checkpoint/v179-phase285-plan03b-production`
- **Independent whole-plan review:** P0/P1/P2 = `0/0/0`, confidence high

## Delivered

- Added a closed, deny-unknown NATS 2.11.17 raw configuration and Stream.Info projection. It independently binds semantic bucket configuration to the epoch and raw configuration to the anchor while retaining complete initial and final response evidence, including their independently mutable response timestamps.
- Added the fixed-subject `NatsWitnessStore`. `InspectReady` bounds and validates the exact manifest/admission iterator before a fresh stable snapshot and authenticated entry reads; CAS validates before publish, checks the exact acknowledgement tuple, and confirms exact bytes, digest, revision, subject, and permitted headers through the leader before returning Applied.
- Reused public typed governance validators without importing transport authority into governance. The accepted 19-scenario corpus produces non-lossy direct, reference, typed-proxy, and JetStream records with separate backend-reported and authenticated-diagnostic ambiguity observations.
- Added a pinned two-account Compose harness with fixed image identity, account isolation, same named volume, explicit unavailability controls, exact package-run serialization, fresh tree-bound tokens, scratch confinement, cleanup enforcement, and mutation-sensitive transcript validation.
- Added five authenticated post-ack/pre-confirmation crash states. Each original call remains Ambiguous without retry or upgrade, then exact raw message evidence, Ready bindings, leader identity, container/project/service/image/volume identity, and store/global revision relations are revalidated after SIGKILL and same-volume restart.
- Added the root-pinned integrity launcher and canonical manifest. The launcher authenticates the exact checker before CAS/checkpoint execution under a deliberately local frozen-tree/root-integrator trust model.

## Verification evidence

- The frozen 58-row registry retained digest `a3a3ec459600ac3163a9b66aa40aa39e9387c50cc75b1e765d9f0693ddb8983b`. `jetstream-cas` executed 5/5 exact cases and `jetstream-checkpoint` executed 4/4 exact cases with zero failed or ignored tests.
- The launcher-bound final checkpoint evidence recorded five positive families, four checkpoint cases, eight checkpoint rows, five positive envelopes, six iterator rows, one release row, 140 controls, and 35 cumulative mutations. Its exact cumulative digest is `a023ecfddee58c87896c87c62180d7956647c33e4a11ae2c285e172fcf58a009`.
- The independent checkpoint oracle killed 30 coherent crypto/nested/provenance/relation controls; the dynamic ledger killed 74 controls; release caller evidence killed 8; iterator ledger and source guards killed 10 each; selector materialization killed 8; and the final harness killed 7 environment, 3 binding, 9 exact-command matcher, and 11 unique source-wiring mutations.
- The exact full witness package passed 14 library, 5 JetStream CAS, and 4 JetStream checkpoint tests. Governance and witness package suites, strict all-target/all-feature clippy, workspace formatting, shellcheck, actionlint, dependency closure, and diff checks passed on the reviewed tree.
- Both production refs resolve to the exact accepted commit. The final integrity launcher invocation bound the reviewed production tree and the planning-object-pinned launcher/manifest identities before executing the evidence-producing selectors.

## Deviations from plan

- The three planned internal checkpoints were further decomposed into bounded A, B1/B2/B3, C1a/C1b, C2a/C2b/C2c, and C3 freezes when hostile reviews found lossy differential metadata, circular release evidence, incomplete runtime bindings, and iterator/final-snapshot gaps. No rejected intermediate tree was promoted.
- The first restart design incorrectly compared complete Stream.Info responses even though NATS refreshes top-level `ts`. The corrected contract preserves each complete response independently and compares only the normative stable projection.
- Release-probe integrity required a separate root-pinned launcher/manifest boundary after in-checker source/body guards proved circular. Its stated guarantee is intentionally limited to local frozen-tree/root-integrator integrity.
- The exact full-package gate exposed absent checkpoint tokens and possible intra-binary restart concurrency after selector-only validation was already green. The harness now supplies a fresh package token and exact staged tree, serializes only the exact full-package command, and mutation-protects the complete command matcher without altering selector overrides.
- Production remained one atomic 13-path child of accepted Plan 03A. No service binary, Plan 04-07B implementation, hosted evidence, combined-tree acceptance, protected-check requirement, external App enforcement, or Phase 286 advancement was added.

## Next-plan readiness

Plan 04 is the only authorized next slice. It may add the public dispatcher, full request/reply service path, and service checkpoint on top of `8abe28d`. Phase 285 remains open through Plans 04-07B and still requires the frozen combined production tree, hosted evidence, final independent review/attestation, and closure artifact. External provenance-distinct GitHub App enforcement remains deferred.

---
*Phase: 285-assurance-foundation-closure*
*Completed: 2026-08-26*
