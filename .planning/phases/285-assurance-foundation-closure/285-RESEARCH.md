---
phase: 285
slug: assurance-foundation-closure
status: complete
researched: 2026-08-24
baseline_commit: a9837f210b50bb391e6902e1e24ef84e4a8da4dc
requirements:
  - ASSURE-01
  - ASSURE-02
  - ASSURE-03
  - ASSURE-04
  - ASSURE-05
  - ASSURE-06
---

# Phase 285 Research — Assurance Foundation Closure

## Research verdict

Phase 285 has a sound, independently reviewed protocol basis but not a production durability path. The accepted tree contains the pure protocol model, bounded session fence, signed witness-store envelope, reference transition validator, and canonical public request wire. It does not contain a durable CAS repository, public witness dispatcher, signed failure/response wire, independent candidate-verifier entry point, NATS service binaries, deployment isolation, witness-backed local publication coordinator, or enforced detector construction path.

The correct execution strategy is to preserve the accepted checkpoint chain and implement the remaining contract in serial, independently reviewable slices. Reopening filesystem or transport architecture inside implementation would repeat the failed 64,000-line integration-tree experiment.

Confidence: high. This conclusion is based on the exact tree at `a9837f210b50bb391e6902e1e24ef84e4a8da4dc`, the reviewed protocol at `5be011a07690a63a297d5bba8fbf740bb659c19d`, the complete witness adapter contract, current crate manifests, current production construction in `swarm_detect.rs`, and current CI/gate scripts.

## Sources of truth

1. `.planning/phases/285-assurance-foundation-closure/285-CONTEXT.md` — reopened scope, accepted checkpoints, remaining work, and immutable-tree acceptance rule.
2. `.planning/phases/285-assurance-foundation-closure/285-WITNESS-ADAPTER-CONTRACT.md` — normative witness wire, store, transport, bounds, isolation, and conformance contract.
3. Commit `5be011a07690a63a297d5bba8fbf740bb659c19d`, file `.planning/phases/285-assurance-foundation-closure/285-GOVERNANCE-PERSISTENCE-PROTOCOL.md` — normative local publication, recovery, retention, maintenance, and reinitialization state machine.
4. `crates/swarm-governance/src/persistence_protocol.rs` — accepted pure types and validation model.
5. `crates/swarm-governance/src/witness_engine.rs` — accepted bounded signed store envelope and one-step transition validator.
6. `crates/swarm-governance/src/witness_service.rs` — accepted canonical nine-operation request envelope only.
7. `crates/swarm-governance/src/lib.rs` — current local governance policy and filesystem persistence implementation.
8. `crates/swarm-runtime-http/src/bin/swarm_detect.rs` — shipped governance bootstrap, reinitialization, and trust-consumer composition.
9. `deploy/helm/swarm-team-six/**`, `.github/workflows/ci.yml`, and `tools/check-*.sh` — current production and acceptance surfaces.

## Accepted implementation inventory

### Protocol and local transaction model

`persistence_protocol.rs` already provides:

- canonical decoding/encoding and length-delimited domain hashing through `canonical_wire_bytes`, `decode_canonical`, and `digest_domain`;
- checked epoch, sequence, intent, session, journal, and size arithmetic;
- exact artifact, authority-pair, publication-role, mapping, binding, candidate, transaction, head, session, discovery, outcome, journal, and recovery types;
- `GovernanceDurabilityWitness` as the required external durability boundary;
- `TransactionRecordV1`, `GovernanceJournalRecordV1`, `validate_recovery_pair`, `select_recovery_record`, and `validate_reinitialization_epoch`.

This module is a model and validation library. It is not yet the filesystem transaction coordinator used by `GovernancePolicy`.

### Witness store model

`witness_engine.rs` already provides:

- `WitnessStoreEnvelopeV1`, `WitnessStoredCandidateV1`, and `WitnessStoredPreparedV1`;
- namespace expectations through `WitnessStoreExpectationV1`;
- exact one-step classification through `WitnessStoreTransitionV1` and `validate_store_transition`;
- fixed stream-key derivation through `witness_stream_key`;
- bounded current/predecessor/prepared/session/last-outcome cardinality.

It deliberately owns no transport or storage handle. The current tree therefore cannot durably linearize a witness mutation.

### Public request wire

`witness_service.rs` already provides:

- the exact nine operations `Fence`, `Establish`, `Discover`, `Prepare`, `Commit`, `Abort`, `ReadPrepared`, `ReadHead`, and `FetchPayload`;
- operation/body equality, canonical request digest, null authorization for fence/rotation, and exact session authorization for the six session-bound operations;
- nested request, challenge, head, candidate, digest, and namespace validation.

It deliberately owns no response, transport, admission lookup, candidate admission, store access, service dispatch, or failure attestation.

### Slice-level acceptance already banked

The immutable chain through `a9837f21` has independent zero-P0/P1/P2 evidence for the reviewed architecture, witness contract, and witness-service request wire. Those reviews remain valid for those commit objects. They do not cover later integration.

## Exact gaps in the accepted tree

### 1. No signed service response or typed failure contract

`witness_service.rs` stops at `WitnessServiceRequestV1`. The adapter contract requires bounded canonical success and failure responses signed only after a confirmed durable transition. There is no public failure-code enum, retryability contract, operation/request digest binding, failure attestation verifier, or response decoder.

Required result: versioned `WitnessServiceResponseV1` and `WitnessServiceFailureV1` types whose signed preimages bind operation, request digest, admission, witness identity/key, exact typed outcome or typed failure, store revision/transition evidence where applicable, and bounded retry metadata. Transport strings must never determine protocol state.

### 2. No independent candidate verifier

The request wire calls candidate canonical validation, and the pure engine validates stored transitions, but the service lacks the contract-mandated `WitnessCandidateVerifier` entry point. Prepare must independently reconstruct and verify state/checkpoint signatures, admitted signer, binding, lengths/digests, candidate/txid derivation, predecessor/data-head transition, epoch/sequence/intent, authority, mapping, role distinctness, and all resource bounds.

Required result: a verifier API that takes admitted stream state plus a request candidate and returns a verified, non-forgeable admission value consumed by the prepare transition. Tests must mutate every independently checked field and prove the store is unchanged.

### 3. No atomic store or CAS proxy

There is no store trait, in-memory fault-injection repository, typed proxy request/response, JetStream KV repository, or exact header/acknowledgement validation in the accepted tree. `crates/swarm-governance/Cargo.toml` has no `async-nats` dependency. The only existing JetStream precedent is `swarm-pheromone`; it may create a missing bucket and its ordinary ignored tests can skip when NATS is absent, both forbidden for the witness acceptance lane.

Required result: a separate downstream witness transport package or equivalent non-cyclic boundary that depends on `swarm-governance`, owns `async-nats`, and exposes distinct runtime-client, public-witness, store-proxy, and one-shot-init binaries or targets. `swarm-governance` must remain the authority/protocol layer and must not depend back on the transport package.

The store API must be revision-CAS, not last-write-wins. A successful proxy mutation requires all of:

- exact configured stream and subject;
- non-deduplicated publish acknowledgement;
- new revision strictly greater than observed revision;
- confirming read with exact raw message sequence, byte-identical value, and expected-subject-sequence header equal to the observed revision;
- signed proposed envelope and typed proxy request validated independently before mutation.

### 4. No public witness dispatcher or binaries

No production dispatcher maps the nine request operations to fence/session/store transitions. There is no service loop, no private typed proxy, no one-shot bucket initializer, and no production client implementing `GovernanceDurabilityWitness`.

Required result: explicit operation handlers with one durable transition per mutation, exact-retry behavior, commit/abort CAS race resolution, signed read/absence responses, contention exhaustion, and no response signature before confirmed durability.

The current `GovernanceDurabilityWitness` associated error type complicates type erasure at the `GovernancePolicy` boundary. Planning must choose one concrete, matchable client error or add a sealed erased adapter in `swarm-governance`; it must not make `GovernancePolicy` generic throughout the runtime or collapse failures into `String`.

### 5. Local persistence is not wired to the reviewed protocol

`crates/swarm-governance/src/lib.rs` still owns `GovernancePersistence` and the shipped `GovernancePolicy::{initialize_persistence,with_persistence,reinitialize_persistence}` entry points. It does not construct a `GovernanceDurabilityWitness` or route every publication through the accepted transaction and recovery records.

Required result: a witness-backed coordinator that:

- holds the selector/authority/state/pool guards across construction or refusal;
- authenticates the fixed namespace and within-role inode pairs;
- prepares externally before local publication;
- uses the exact staged/exchanged/journaled state machine;
- resolves lost prepare/commit/abort responses only through signed discovery;
- treats uncertain mappings, responses, fsync failures, unknown entries, and exhaustion as typed refusal;
- has no optional witness or local success fallback in enforced production mode.

### 6. Fixed-lane filesystem operations remain an integration gap

The pure protocol defines mappings and journal semantics but does not perform descriptor-relative fixed-lane exchange, fsync, seam revalidation, escrow repair, or within-pair recovery in production. The reviewed architecture forbids counter-, process-, timestamp-, transaction-, or random-derived ordinary publication paths.

Required result: small filesystem modules for held directory/file descriptors, authenticated fixed namespace enumeration, exact role identity, within-pair exchange, durable alternating journals, and escrow-backed repair. Unsafe code remains forbidden in the crate; any OS primitive requiring a wrapper must use an already accepted safe dependency or a narrowly reviewed platform abstraction outside the authority module.

### 7. Retention and offline maintenance are not accepted as the reviewed state machine

The old dirty-tree reviews repeatedly found premature `Retained`, foreign canonical restoration, unverifiable journal chains, unbounded or replaceable pools, and no supported exhaustion recovery. None of that WIP is an accepted input.

Required result: fixed authenticated cleanup slots with `Reserved -> SourceBound -> CandidateCopied -> QuarantineMoved -> ReadyToRetain -> Retained`, post-commit `Uncertain` precedence, exact slot-name and held-inode checks, typed exhaustion, and no best-effort error discard. Offline drain/reset/rebind is explicit, quiescence-guarded, journaled, preservation-only, and never runs during ordinary startup.

### 8. Shipped detector construction does not inject the witness

`swarm_detect.rs:333-350` selects `GovernancePolicy::initialize_persistence` or `with_persistence` from the local agent-key status. `swarm_detect.rs:360-381` then shares the resulting local authority among ingest, dispatcher, and containment. `--reinitialize-governance-state` calls local `GovernancePolicy::reinitialize_persistence`.

Required result: production configuration must construct a transport-authenticated witness client first and transfer it, plus the detector selector/authority guard, into initialization/load/recovery. Enforced startup refuses before minting `ShippedGovernanceWiring` if witness configuration, admission, fence, store, or head verification fails. Reinitialization becomes an explicit witness-backed epoch transition, not local archive-and-reset.

Tests must prove the same injected authority identity reaches ingest, dispatcher, containment, human resume, health, and recovery; removing the witness or swapping the selector/authority guard must fail before any governed action or local mutation.

### 9. Deployment and init authority are absent

The current Helm chart has one application deployment and a generic NATS subchart. It does not render the contract’s public-witness, private-store-proxy, one-shot-init identities, three NATS accounts, disjoint credentials, sealed external epoch/anchor, or init-authority revocation.

Required result: bootstrap and accepted-serving renders are separate evidence subjects. Serving workloads cannot mount init credentials or the runtime state PVC across the witness boundary. The init Job alone creates the exact predeclared bucket and is absent, disabled, and credential-revoked in the accepted serving render. Production services refuse bucket creation or drift.

### 10. Final combined-tree evidence does not exist

Existing focused tests and checkpoint reviews apply to their exact objects only. ASSURE-01..06 require regeneration and review on the final immutable commit. The current CI JetStream lane covers pheromone, not the witness path.

## Recommended implementation sequence

The planner should produce bounded plans with serial ownership. Each plan starts from the last independently accepted object and ends in a commit before the next plan begins.

### Slice A — response, failure, and candidate-verifier contract

Own only protocol/service modules and tests. Add canonical signed response/failure types, typed matchable errors, verified candidate admission, and red-first mutations. No transport or filesystem changes.

Checkpoint gate: governance package tests, exact named mutations with nonzero execution counts, strict package clippy, format, diff, independent P0/P1/P2 review.

### Slice B — atomic store abstraction and in-memory conformance

Add the revision-CAS store/proxy wire, deterministic in-memory store, fault injection, reference transition model comparison, initialization manifest/admission records, and exact boundedness. Do not add JetStream until the store contract passes independent review.

Checkpoint gate: same conformance suite against direct in-memory store and typed proxy; crash/ambiguity/contention/capacity mutations; independent review.

### Slice C — JetStream repository and non-skipping harness

Create the downstream transport package and implement exact-header CAS against the pinned NATS version. Extend `tools/with-nats-jetstream.sh` or add a dedicated checked wrapper that proves the named witness tests execute and fails on unavailable NATS, zero tests, skips, or ignored results.

Checkpoint gate: in-memory/proxy/JetStream differential equality, restart durability, header and ack mutations, locked dependency update, supply-chain and layering gates, independent review.

### Slice D — public witness, proxy, init, and runtime client

Implement the nine-operation dispatcher, three serving/init binaries, exact retry/session rotation, signed durable responses, client-side attestation verification, and the concrete `GovernanceDurabilityWitness` adapter.

Checkpoint gate: full request/reply path through separate NATS accounts; unauthorized/wildcard/credential-swap mutations; kill/restart recovery; no signer or raw-KV capability in the wrong process; independent review.

### Slice E — witness-backed local publication and recovery

Integrate the accepted transaction records with `GovernancePolicy` using fixed authenticated lanes, held descriptors, alternating journals, escrow repair, explicit abort/commit resolution, and enforced witness injection. Keep retention/maintenance in the next slice unless a shared atomic primitive requires serial introduction.

Checkpoint gate: crash at every phase, seam replacement, hard-link/cross-role alias, same-inode mutation, fsync failure, replay against newer head, lost response, recovery-session rotation, overflow, and no-witness mutations; independent review.

### Slice F — retention, maintenance, reinitialization, and detector handoff

Implement the exact cleanup state machine, bounded authenticated pool, explicit offline maintenance, witness-backed epoch transition, selector guard transfer, and shipped `swarm-detect` construction/configuration. Delete or make unreachable every local-only enforced route.

Checkpoint gate: pool exhaustion/retry, namespace replacement/restart, pre/post-retain barriers, maintenance crash/resume, archive collision, selector mismatch, production-construction witness removal, and detector cleanup handoff; independent review.

### Slice G — deployment, frozen combined tree, and closure

Render and test the four identities, accounts, secret mounts, init lifecycle, pinned NATS image/configuration, external epoch/anchor, and network isolation. Then freeze one commit and run all local, adversarial, workspace, exact-head hosted, and independent review gates. Update the ledger only after exact-head evidence exists.

## File and ownership guidance

- Preserve `persistence_protocol.rs`, `witness_engine.rs`, and `witness_service.rs` as focused modules; do not move their accepted code back into `lib.rs`.
- Split new service/store/client code into small modules. No new production file should become another multi-thousand-line mixed implementation/test unit.
- A downstream witness transport crate may depend on `swarm-governance`; `swarm-governance` must not depend on it. Runtime composition may depend on both and inject the implementation through the protocol trait.
- Update `tools/check-workspace-layering.sh`, `tools/check-single-governor-key.sh`, `tools/check-negative-registry.sh`, and their fixtures deliberately when a new crate or manifest changes the authority inventory. Hash/baseline edits without failing mutations are not acceptance.
- `crates/swarm-runtime-http/src/bin/swarm_detect.rs` has one serial owner for detector integration. No parallel task may edit it while another plan changes governance construction.
- Helm templates, values, and evidence checker have one serial deployment owner. Transport service code and Helm code may proceed only when their DTO/config boundary is frozen.
- Never import dirty files from `integrate/v179-phase285` wholesale. Any useful WIP must be re-derived against the reviewed contracts and landed as a bounded diff with red-first evidence.

## Risks and required controls

| Risk | Required control |
|---|---|
| Valid request mistaken for accepted operation | Response signatures exist only after confirmed durable CAS; request digest is never success evidence |
| Client validates its own candidate | Separate service-side verifier with field-by-field mutations and unchanged-store assertions |
| Lost response causes local downgrade | Signed discovery is the only resolver; no local success fallback |
| CAS acknowledgement is weaker than durability | Exact stream, revision, non-duplicate ack, confirming byte-identical read, and expected-subject-sequence checks |
| Missing NATS silently skips tests | Dedicated wrapper asserts named test counts and fails on missing server/skip/ignore/zero |
| Bucket recreation replays signed old bytes | External bucket epoch, sealed anchor, exact server creation time, and no serving create credential |
| Same process holds conflicting authorities | Separate runtime, witness, proxy, and init credentials/pods; negative mount/account/network checks |
| Local pathname race authorizes mutation | Held descriptor identity, complete namespace enumeration, immediate seam pre/post checks, no-replace operations |
| Retention commits before final validation | `ReadyToRetain` then final validation then `Retained`, followed by post-commit barrier and `Uncertain` precedence |
| Fixed pool exhausts silently | Typed pre-mutation exhaustion; explicit offline preservation-only maintenance; no discarded cleanup errors |
| Old local entry points bypass witness | Production construction mutation removes witness and must fail before authority mint or local mutation |
| Passing slice reported as phase completion | Exact commit/tree ledger plus final combined-tree and hosted evidence parser |

## Validation Architecture

### Test layers

1. **Pure protocol layer** — deterministic unit tests for canonical bytes, bounds, identifiers, signatures, candidate transitions, sessions, outcomes, journal selection, and error mapping.
2. **Reference-model layer** — every accepted/rejected store operation compared byte-for-byte with a small deterministic transition model.
3. **In-memory atomic-store layer** — deterministic revision conflicts, ambiguous responses, retries, crash points, capacity exhaustion, and exact store immutability on refusal.
4. **Typed proxy layer** — the same conformance suite through canonical signed proxy request/response DTOs; mismatched body/signature/header mutations fail.
5. **JetStream layer** — the same named conformance cases under a pinned NATS image, with non-skipping execution-count enforcement and restart durability.
6. **Full service layer** — runtime client -> public witness -> private proxy -> JetStream, with account, subject, credential, timeout, replay, and process-restart controls.
7. **Local persistence layer** — descriptor, exchange, journal, witness, recovery, retention, maintenance, and epoch-transition fault matrices.
8. **Production construction layer** — `swarm-detect` enforced startup/load/recovery/reinitialize and all governance trust consumers use the same witness-backed authority.
9. **Deployment layer** — Helm render and live harness verify identities, mounts, accounts, network reachability, init removal, bucket configuration, image digest, epoch/anchor, and restart behavior.
10. **Final assurance layer** — complete repository gates, workspace tests, strict clippy/fmt, clean-tree checks, exact-head hosted run, and independent hostile review.

### Sampling rules

- After each task: run the narrowest exact test target and assert at least one test executed.
- After each plan: run the complete affected package suite, strict affected-package all-target clippy, format, diff check, and the plan’s mutation controls.
- Before a checkpoint is accepted: commit the exact tree, rerun its declared gates on that commit, then obtain an independent zero-P0/P1/P2 review.
- After any review-driven edit: previous test and review evidence is stale; rerun against the new hash.
- Before Phase 285 closure: run the final matrix on one immutable commit locally and in hosted Linux.

### Required commands and gates

Existing commands that remain mandatory:

```text
cargo test -p swarm-governance --lib --locked --offline
cargo test -p swarm-runtime-http --bin swarm-detect --locked --offline
cargo test --workspace --exclude swarm-runtime --exclude swarm-ingest-runtime --locked --offline
cargo test -p swarm-runtime -p swarm-ingest-runtime --locked --offline -- --test-threads=1
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo fmt --all -- --check
bash tools/check-mapping.sh
bash tools/check-negative-registry.sh
bash tools/check-fixture-freshness.sh
bash tools/check-supply-chain.sh
bash tools/check-single-governor-key.sh
bash tools/check-workspace-layering.sh
bash tools/check-gates-wired.sh
bash tools/check-worktree-clean.sh "the Phase 285 final run"
git diff --check
```

New commands the plans must create:

- a focused witness conformance gate that runs pure/in-memory/proxy named cases and rejects zero execution;
- a JetStream witness gate under `tools/with-nats-jetstream.sh` or a stricter dedicated wrapper that rejects unavailable, skipped, ignored, or zero-test execution;
- a deployment render/isolation checker with deliberate bad-mount, bad-account, bad-image, bad-bucket, recreated-init, and missing-anchor fixtures;
- a Phase 285 exact-head evidence checker that binds commit, tree, test identities/counts, mutation results, hosted run, reviewer identity, and zero P0/P1/P2 verdict.

### Mandatory mutation families

- remove or bypass the witness;
- accept a local fallback;
- weaken canonical decoding, signature, signer, admission, role-distinctness, or identifier derivation;
- skip an fsync or confirming store read;
- accept duplicate/zero/wrong-stream/wrong-revision acknowledgements;
- accept stale session, stale intent, reused abort, conflicting prepare, or losing commit/abort result;
- select the highest local sequence without witness authority;
- replace parent, pool, binding, lock, slot, canonical, staging, journal, proxy response, or deployment credential at the last seam;
- permit pool eviction, unbounded retention, fallback names, silent cleanup errors, or ordinary startup maintenance;
- start enforced `swarm-detect` without a verified witness dependency;
- recreate init authority or permit a serving workload to create/purge/delete the bucket;
- report an earlier checkpoint or hosted run as evidence for a different final commit.

### Nyquist conclusion

Existing infrastructure covers unit/package/workspace testing, formatting, clippy, repository assurance, Helm, and JetStream process startup. Wave 0 must add non-skipping witness conformance, deployment-isolation, and exact-head evidence checkers before implementation plans can claim their corresponding acceptance rows. All phase behaviors except external hosted execution are automatable. Hosted execution is mechanically verified by the exact-head evidence checker rather than accepted by manual inspection.

## Planning constraints

- All six requirement IDs `ASSURE-01` through `ASSURE-06` must appear in plan frontmatter and task coverage.
- No plan may claim Phase 285 completion from a slice-level checkpoint.
- No plan may execute Phase 286-289 work.
- No plan may make external GitHub App or repository protected-required enforcement an acceptance dependency or a passed claim.
- Every task must name exact files/symbols, red-first controls, non-vacuous commands, and objective acceptance criteria.
- Parallelism is limited to disjoint pure-code/test or render/checker work after the shared contract is frozen. `lib.rs`, `swarm_detect.rs`, workspace manifests/gates, and Helm evidence each have one serial owner.
