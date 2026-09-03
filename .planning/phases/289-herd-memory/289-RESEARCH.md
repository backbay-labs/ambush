# Phase 289: Herd Memory - Research

**Researched:** 2026-08-21
**Domain:** Privacy-minimized, content-addressed, signed memory transfer between Ambush swarms
**Confidence:** HIGH for repository seams and security boundaries; MEDIUM for new wire types and benchmark APIs because Phase 289 has no implementation

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

The context file has no heading named Decisions. Its operative scope is copied verbatim below.

#### Objective

Transfer learned attack abstractions between swarms without sharing raw telemetry or creating a single publisher whose memory can authorize local action. Memory should improve the next investigation while preserving local corroboration and revocation control.

#### Required shape

- Export typed attack abstractions, causal motifs, detector/response outcomes, and strategy utility only. Raw telemetry, secrets, host identifiers, and operator credentials are prohibited by schema and export tests.
- Every record carries version, signer/provenance lineage, source-corpus digest, confidence, expiry, and transformation history. Import rejects tampered, replayed, stale, schema-invalid, or privacy-violating records with a durable refusal reason.
- A receiving swarm requires independent local corroboration before peer memory affects prioritization. Conflicting memories remain visible as contradictions; no single publisher raises confidence or authorizes containment.
- Retrieval changes task ordering only when the memory context matches the current graph and evidence. It cannot bypass hypothesis adjudication, policy, receipts, approval, or response adapters.
- Retention, expiry, revocation, poisoning quarantine, and operator deletion are restart-safe. Garbage collection removes expired payloads and dependent indexes without actionable orphan state.

#### Measurement contract

Compare memory-enabled, single-agent, and no-memory controls on hypothesis time, chain recall, false causal edges, duplicate work, and evidence coverage. Plan 00 freezes checked-integer basis-point formulas: pass with time improvement `>= 2,000 bp` OR chain-recall improvement `>= 1,000 bp`, false edges `<= 1,000 bp`, duplicate work `<= 500 bp`, at least one previously unseen evasion across the withheld corpus, and withheld-campaign relative gap `<= 500 bp` versus in-sample. No float or wall-clock-only comparison is acceptance evidence.

### Claude's Discretion

The context file has no Claude's Discretion heading. Recommendations below stay within the objective and required shape.

### Deferred Ideas (OUT OF SCOPE)

The context file has no Deferred Ideas heading. Raw-telemetry export, peer-authorized containment, and retrieval that bypasses corroboration, adjudication, policy, receipts, approval, or response adapters are out of scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| HERDMEM-01 | Investigations export typed attack abstractions, causal motifs, detector/response outcomes, and strategy utility without raw telemetry, secrets, host identifiers, or operator credentials. The export schema is versioned and rejects unredacted fields. | Add a separate typed allowlist projection; never serialize ReplayBundle, InvestigationBundle, Sphinx EntityNode/contributions, incidents, or generic evidence views. Use Serde unknown-field rejection and keyed opaque refs. |
| HERDMEM-02 | Every memory record carries signer/provenance lineage, source-corpus digest, confidence, expiry, and transformation history. Import rejects tampered, replayed, stale, schema-invalid, or privacy-violating records and records the refusal reason. | Put registry-anchored envelope, strict chain/nonce/expiry verification, and durable refusal state in swarm-spine. |
| HERDMEM-03 | A receiving swarm requires independent local corroboration before using a peer memory for prioritization. No single publisher can raise confidence or authorize containment; conflicting memories remain visible as contradictions. | Tag imported origin separately, join only with local evidence, retain contradiction sets, and keep memory above the policy/response TCB boundary. |
| HERDMEM-04 | Retrieved memory changes the next investigation's task ordering only when its context matches the current graph and source evidence. The benchmark compares memory-enabled, single-agent, and no-memory controls on hypothesis time, chain recall, false causal edges, duplicate work, and evidence coverage. | Adapt Sphinx/strategy retrieval to a corroboration-gated priority delta; drive all three arms through Phase 288's Arena-owned `Phase287ArenaSynthesisAdapter` and real Phase 287 Blue bridge, consuming only Runtime-owned `ArenaSynthesisInput`/`ArenaSourceRef` lineage. `DefaultReplayHarness` or a generic replay substitute is not evidence. |
| HERDMEM-05 | Memory retention, expiry, revocation, poisoning quarantine, and operator deletion are durable and restart-safe. Garbage collection removes expired payloads and dependent indexes without leaving actionable orphan state. | Use a tombstone-first lifecycle ledger, atomic committed generations, restart recovery, registry revocation, and complete dependent-index GC. |
| HERDMEM-06 | Herd-memory acceptance requires checked-integer time improvement `>= 2,000 bp` or chain-recall improvement `>= 1,000 bp` versus the single-agent control, false-edge `<= 1,000 bp`, duplicate-work `<= 500 bp`, at least one previously unseen evasion across the withheld corpus, and withheld-campaign relative gap `<= 500 bp` versus in-sample. | Add deterministic event/virtual-clock metrics, unseen-evasion accounting, and an evaluator-only held-out corpus digest. |
</phase_requirements>

## Summary

The repository has useful cryptographic precedents but not a safe cross-swarm memory protocol. swarm-spine envelope signs canonical JSON and chain checks issuer, sequence, and previous hash; swarm-core SignedStateEnvelope checks one local signer and a sequence. Neither provides a locally trusted issuer registry, tenant/swarm/epoch binding, expiry, nonce uniqueness, durable fork/equivocation retention, or a strict persisted head. The generic spine verifier also derives a public key from the envelope issuer, which proves self-consistency, not federation trust.

The current producers are too rich to export directly. ReplayBundle, InvestigationBundle, CorrelatedIncident, Sphinx EntityNode, SphinxMemoryContribution, and generic evidence views can contain host IDs, users, process names, IPs, raw indicators, receipt references, secrets, or operator notes. Sphinx extract_entities explicitly collects host, user, process, and IP values, and evidence export serializes complete views. Phase 289 needs a dedicated allowlist projection before signing/hashing.

Place typed envelope, registry, chain, refusal, tombstone, and lifecycle primitives in swarm-spine (TCB), and projection, import/quarantine, corroboration, graph matching, task ordering, and benchmark integration in swarm-runtime. Imported memory may only contribute a bounded task-ordering hint. It must never count as local source diversity, authorize confidence, create a receipt, reach policy/response, or bypass approval.

**Primary recommendation:** Build a versioned HerdMemoryEnvelope around a privacy-minimized HerdMemoryBody, verify it against a locally configured and rotatable TrustedHerdIssuerRegistry plus a durable per-stream head/nonce ledger, retain every refusal and contradiction, and expose imports only through corroboration-gated advisory priority.

**Upstream Phase 288 contract (authoritative for this phase):** Phase 289 does not own or recreate
the bridge. `crates/swarm-arena/src/synthesis_adapter.rs` owns
`Phase287ArenaSynthesisAdapter`, which runs the real `BlueRuntimeAdapter` and emits the pure
Runtime DTO `ArenaSynthesisInput` from `crates/swarm-runtime/src/synthesis/arena_input.rs`.
Every `ArenaSourceRef` carries the closed `ArenaSourceRole` (`BlueOutcome`, `ArenaIngestResult`,
`Phase286InvestigationCapture`, `ArenaArtifactStore`, `PairReport`, or
`SignedBlueLearnedState`), schema version, canonical ID, content digest, payload digest, and
partition digest. The adapter preserves the full signed learned-state envelope and Phase 286
capture/artifact/pair evidence. Runtime consumes the DTO but never imports `swarm-arena`; any
benchmark, evaluator, or herd-memory projection must validate these refs against the pinned
Phase 288 adapter/closure evidence and the Phase 287 exact tuple
`tactic_id|technique_id|fixture_primitive|order_relation|timing_bucket`. A generic replay harness,
static fixture, detector-only seam, or second Runtime adapter is not an acceptable upstream
contract.

## Phase 289 repair contract (2026-08-23)

The upstream closure dependency is executable and external to implementation.
Before any Phase 289 fixture, compilation, benchmark, or lifecycle operation,
`tools/check-herd-memory-upstreams.sh --run -- <command>` must be the first
operation; its internal first step is
`--require-accepted --locked-tree` and it must
resolve the exact closure sets:

| upstream | closure summary | independent records | retained canonical evidence |
|---|---|---|---|
| Phase 286 | `.planning/phases/286-collective-hypothesis-graph/286-07B-SUMMARY.md` | `286-P0-P2-REVIEW.md`, `286-VERIFICATION.md` | `artifacts/phase286/collective-report-one.json` plus its recomputed digest |
| Phase 287 | `.planning/phases/287-adversarial-co-evolution-arena/287-06-SUMMARY.md` | `287-P0-P2-REVIEW.md`, `287-VERIFICATION.md`, `287-VALIDATION.md` | `artifacts/phase287/final-gate/arena-report.json`, `arena-lineage.json`, and `final-gate-evidence.json`, with the recomputed report/newline/lineage digest |
| Phase 288 | `.planning/phases/288-autonomous-detector-response-synthesis/288-07-SUMMARY.md` | `288-P0-P2-REVIEW.md`, `288-VERIFICATION.md`, `288-VALIDATION.md` | `artifacts/synthesis/run-1/manifest.json`, `arena-report.signed.json`, `synthesis-packet.signed.json`, `controls.json`, and `pair-report-view.json`, with its `phase287_evidence_digest`/frozen-tree digest |

The gate requires regular non-symlink files, complete status, exact one-to-one
task/requirement/artifact rows, exactly one anchored zero for each P0/P1/P2,
distinct reviewer/implementer, reviewed `HEAD` and `HEAD^{tree}`, and
recomputed canonical SHA-256 evidence. The Phase 286 validation ledger by
itself is explicitly insufficient. Missing, partial, path-only, planned,
pending, substituted, stale, dirty, or untracked evidence fails closed. Once
the gate passes it resolves the actual Phase 287 adapter/runtime DTO/Cargo
membership/corpus and Phase 288 runtime-contract/source/tree/evidence digests;
Phase 289 may not guess paths or precompute placeholder hashes.
The accepted result is retained only at
`artifacts/phase289/upstream-prerequisite-gate.json`; later plans must consume
that record and re-run the executable gate, never infer acceptance from the
pin file or a path-only summary.

The detached lineage contract is typed and complete. `ArenaLineage` contains
adapter artifact, Runtime DTO, Cargo membership, corpus, detached source digest,
six source-role refs (each with role/schema/canonical-ID/content/payload/
partition digests), plus a selected source ref and detached aggregate source
digest, capture, receipt, preview, rollback, and
`SignedStateExpectation`. The latter
contains kind, signer, stream, sequence, generation, predecessor, fence,
schema, signature, payload, content, capture, receipt, preview, and rollback.
Each role/schema/canonical ID/content/payload/partition, the selected source and
aggregate source digest, and each signed-state field is independently mutated
and rejected before projection/export/import or
evaluator scoring. Raw telemetry, host IDs, secrets, and withheld cases cannot
be represented in this detached manifest.

Import and export use one atomic lifecycle coordinator under
`lifecycle OS lock -> registry lock`. The import API verifies and imports in
one CAS with registry generation/epoch/nonce/head revalidation. The export API
is `prepare_export`/`commit_export` and persists generation, predecessor, source
high-water, nonce, fence, and digest-only crash journal; recovery turns an
orphan reservation into durable refusal/retry state. Memory and file backends
must have identical canonical operation-log state. The durable lifecycle
snapshot authenticates schema, domain, trusted issuer root anchor, registry
generation, epoch, predecessor, source high-water, nonce ledger, fence, state
digest, and signature. Root-anchor custody/provisioning is owner-only,
create-new, no-follow, fsync/rename/parent-sync, and mutations of scope,
schema, domain, epoch, rotation, revocation, replacement, and forgery fail.

The issuer root is independently authenticated by an external root public-key
digest and out-of-band custody. Its canonical subject excludes self digest and
signature fields, and root-signed anchor/rotation/revocation statements form a
generation chain; a self-carried legacy self-key signature cannot authenticate
itself. Export signing is a separate config-bound `HerdMemoryExportSigner`
private-key custody, distinct from the HMAC `FileOpaqueKeyProvider`; callers
cannot supply a signer or raw key, and root/scope/domain/schema/epoch/rotation/
revocation are rechecked at commit.

The public byte boundary is bounded `deserialize_and_import(&[u8])`; it checks
size before parse, rejects duplicate/unknown/noncanonical/trailing data, uses
typed deny-unknown decoding, and persists refusal without exposing a typed
envelope bypass. `TaskOrderHint` uses `BTreeSet<Digest64>` and `Digest64`, never
String or generic maps.

The evaluator corpus/resolver is physically isolated in a separate
`tools/herd-memory-evaluator` process mounted from a CI secret. Candidate code
receives only a public corpus version/digest and an opaque one-shot handle; the
separately signed/pinned evaluator bundle and root live outside the candidate
tree. Authenticated IPC request/response messages and a typed
`SignedFreezeReceipt` bind evaluator root, artifact digest, process nonce,
issuance/freeze/lineage, export generation, and expiry. The process protocol
returns only issuance ID, aggregate result digest, unseen count, and withheld
gap. Fresh per-process issuance IDs and signed freeze receipts prevent
reuse/replay and tests assert no path/content/key/FD/env/log leakage. The typed control table runs all three arms through the real Phase 288
candidate/`empty_frozen` path with identical campaign/fixture/partition/source/
clock/scheduler inputs, distinct arm provenance, measurable imported advisory
effect, and no scorer-only or duplicate replay.

Final review assignment/provenance is root-signed and out-of-band; the
implementer cannot author reviewer results or root evidence. Final review
freezes an explicit allowlist and canonical sorted
`path\0blob_sha256\0mode\n` tree manifest, binds `HEAD^{tree}` and rejects
dirty/untracked/out-of-allowlist files. The sole root helper
`tools/sha256-root.sh` emits unprefixed lowercase 64-hex output and has a
format test. A parser recomputes severity and requires exactly one structured
row for every task, HERDMEM requirement, `must_haves` artifact, upstream pin,
arm, and control; missing/duplicate/mismatched rows and implementer-authored
reviewer results fail closed.

## Standard Stack

### Core

| Crate | Version at checkout | Purpose | Why standard |
|---------|---------|---------|--------------|
| swarm-spine | 0.1.0 workspace | TCB envelope, registry, chain, refusal, tombstone, lifecycle primitives | It already owns signed envelopes, chain heads, checkpoints, and proof/audit boundaries. |
| swarm-crypto | 0.1.0 workspace | Canonical JSON, SHA-256, HMAC-SHA-256, Ed25519 | It is the deepest crypto crate and centralizes protocol bytes and verification. |
| swarm-core | 0.1.0 workspace | Shared schema/config and MemoryConfig extension | Core is neutral and cannot depend on advisory runtime code. |
| swarm-runtime | 0.1.0 workspace | Sphinx projection/import, corroboration, retrieval, strategy adapter, benchmark | Existing memory, strategy, investigation, and replay integration lives here. |

### Supporting

| Library | Locked version | Purpose | When to use |
|---------|---------|---------|-------------|
| serde | 1.0.228 | Typed wire records and deny-unknown-fields | Every body, envelope, registry, refusal, tombstone, and manifest. |
| serde_json | 1.0.149 | Decode/encode before canonicalization | Persistence only after typed schema validation. |
| ed25519-dalek | 2.2.0 | Existing runtime identity rotation pattern | Reuse runtime precedent; prefer swarm-crypto in spine. |
| sha2 | 0.10.9 | Hash implementation behind swarm-crypto | Do not duplicate hashing wrappers. |
| hex | 0.4.3 | Key/digest encoding | Use established lower-case formats. |
| chrono | 0.4.44 | Timestamp parsing and bounded freshness | Issued/expiry validation and one clock-skew policy. |
| tokio | 1.52.3 | Existing async orchestration | Bounded import/GC work outside hot response path. |
| thiserror | 2.0.18 | Stable typed refusal/store errors | Persist named refusal reasons, not log-only strings. |
| serde_yaml | 0.9.34+deprecated | Existing replay manifests | Hash normalized in-sample and withheld selection separately. |

**Installation:** No new dependency is needed. Reuse workspace dependencies and Cargo.lock.

**Version verification:** These versions are from Cargo.lock on 2026-08-21. Run <code>cargo metadata --locked --offline --format-version 1 --no-deps</code> before implementation and preserve the checked-in resolution unless a deliberate protocol review changes it.

## Architecture Patterns

### Recommended project structure

~~~
crates/swarm-core/src/config/state.rs       # Herd scope/epoch/TTL/registry config
crates/swarm-spine/src/herd_memory.rs       # Typed body/envelope/registry/chain/lifecycle
crates/swarm-spine/tests/herd_memory_negative.rs
crates/swarm-runtime/src/herd_memory.rs    # Projection/import/corroboration/advisory adapter
crates/swarm-runtime/src/synthesis/arena_input.rs # Runtime-owned pure ArenaSynthesisInput DTO
crates/swarm-arena/src/synthesis_adapter.rs # Phase287ArenaSynthesisAdapter; sole concrete bridge producer
crates/swarm-runtime/src/sphinx_agent.rs    # Call safe projection; never export raw graph nodes
crates/swarm-runtime/src/strategy.rs       # Imported origin and context-gated score adapter
crates/swarm-runtime/tests/herd_memory_integration.rs
crates/swarm-runtime/tests/herd_memory_benchmark.rs
~~~

### Exact Rust seams

| Concern | Existing seam | Required change |
|---------|---------------|-----------------|
| Generic signed envelope | swarm-spine/src/envelope.rs:38-155 | Add typed/domain-separated herd envelope; do not use self-carried issuer key as trust. |
| Chain linkage | swarm-spine/src/chain.rs:9-183; negative_envelope_and_chain.rs | Persist one head per tenant/source-swarm/issuer/epoch; strict head plus durable fork/equivocation records. |
| Identity admission/rotation | swarm-runtime/src/agent_identity.rs:129-177, 516-690, 717-857 | Reuse continuity-proof shape with federation scope, validity, revocation; never admit from peer bytes. |
| Sphinx store | swarm-runtime/src/sphinx_agent.rs:1231-1373 | Keep graph local; derive a safe projection before export. Existing writes are not one atomic herd lifecycle. |
| Raw entities | swarm-runtime/src/sphinx_agent.rs:1591-1641 | Treat all extracted values as prohibited; HMAC them into opaque refs before construction. |
| Sphinx answers | SphinxAgent::matching_contributions, answer_memory_query, deposit_memory_answer | Existing entity_values and substrate answers are not cross-swarm records; add import adapter. |
| Investigation source | swarm-spine/src/investigation.rs:76-183 and swarm-spine/src/lib.rs:124-180 | Project only typed abstractions, motifs, outcomes, utility, digests, transformations, opaque refs. |
| Strategy memory | swarm-runtime/src/strategy.rs:29-36, 114-138, 1122-1274 | Add Local/Imported origin and corroboration; imports cannot satisfy MIN_LIVE_MEMORIES. |
| Generic evidence | swarm-evolution/src/evidence.rs:231-242, 1319-1559, 1759-1845 | Do not reuse whole-view export; make herd export a separate allowlist. |
| Config | swarm-core/src/config/state.rs:85-128 | Add explicit tenant, swarm, epoch, registry, key epoch, TTL/skew, retention, import root. |
| Benchmark | swarm-runtime/src/replay/harness.rs:90-173, 733-753 and replay types | Reuse scenario execution; add three-arm report and evaluator-only held-out digest. |

### Pattern 1: Explicit privacy allowlist

Build HerdMemoryBody from completed local graph/investigation summaries, not arbitrary JSON. Use fixed kinds for attack abstractions, causal motifs, detector outcomes, response outcomes, and strategy utility. Every nested struct uses deny_unknown_fields. Source evidence is a digest or typed ID; transformation history contains transform IDs and input digests; raw telemetry maps, host/user/process/IP values, secrets, credentials, receipt/action requests, URLs, and operator notes do not appear.

Use OpaqueEntityRef with kind, HMAC digest, and key epoch. A plain hash of a host or user is not private enough for low-entropy dictionary attacks.

### Pattern 2: Registry-anchored strict envelope

Verify in this order: exact schema and bounds; tenant, source swarm, receiver swarm, and epoch; trusted registry entry and key validity; issued/expiry window; canonical body hash/content ID; domain-separated signature with the registry key; nonce uniqueness; strict head sequence and previous hash. Persist envelope, head, nonce, and status atomically.

Envelope fields should include schema_version, memory_id, tenant_id, source_swarm_id, receiver_swarm_id, epoch, issuer_id, issuer_key_id, sequence, previous_envelope_hash, nonce, issued_at_ms, expires_at_ms, source_corpus_digest, confidence, transformation_history, body, body_hash, and signature. The receiver's configured scope is authoritative.

Registry entries need active/retired/revoked state, tenant/source-swarm/schema/domain, validity interval, epoch, and continuity proof. The old key signs a canonical rotation payload linking old/new key IDs, following FileAgentIdentityRegistry::rotate_identity. Persist the registry snapshot atomically at the configured `HerdMemoryConfig.issuer_registry_path`, including generation, active entries, rotation history, and revocation/retirement history; reopen must reproduce the same trust state. A revoked key cannot create new actionable imports. Unknown keys are never admitted from envelopes.

Require exact head plus one and exact predecessor. A second valid record at an already-seen sequence with a different hash is equivocation: retain both in a contradiction set and quarantine the stream. HashMismatch or SequenceMismatch returned only in memory is not durable detection.

### Pattern 3: Corroboration-gated advisory retrieval

Imported records have origin Imported and status Accepted only after verification. Retrieval requires graph topology/stage/technique/source-digest context plus independent local evidence. It may add a bounded learned-value basis-point delta to task ordering only.

Imported records never count as independent sources, local corroboration, graph confidence, MIN_LIVE_MEMORIES, policy evidence, approval, receipt, capability, or response authority. A single publisher cannot manufacture diversity by emitting multiple records. Contradictory memories remain visible as a typed set.

### Pattern 4: Tombstone-first restart-safe lifecycle

Accepted payload, indexes, per-stream head, nonce ledger, refusal report, quarantine state, and tombstone form one durable state machine. Write a complete temporary generation, sync it, rename atomically, and sync the parent directory. Write a tombstone before deleting payload. GC removes payload and every dependent retrieval index but retains a non-actionable tombstone/refusal/equivocation record plus per-stream head, nonce, and replay tombstones at the current epoch, so restart cannot resurrect it or permit sequence reset/replay. Clearing a stream replay fence requires an explicit trusted epoch transition.

### Pattern 5: Deterministic three-arm/withheld evaluation

Run memory-enabled, single-agent, and no-memory arms through the same Phase 287 Blue bridge by invoking Phase 288's Arena-owned `Phase287ArenaSynthesisAdapter`, then pass the resulting Runtime-owned `ArenaSynthesisInput` to the benchmark scorer. Preserve identical seeded campaigns, scheduler, virtual clock, in-sample corpus, source refs, and signed-state lineage; no `DefaultReplayHarness`, generic replay, detector-only shortcut, or Runtime-to-Arena dependency may stand in for the bridge. Use event count or virtual time for hypothesis time. Persist seed, corpus digests, memory-set digest, scheduler, and gate inputs. Load held-out scenarios only in the evaluator after export/calibration and reject contamination. Keep wall-clock observations non-gating, as existing ReplayEvaluationObservation does.

### Anti-patterns to avoid

- Directly serialize ReplayBundle, InvestigationBundle, incidents, Sphinx nodes/contributions, or evidence views.
- Treat an envelope's public key as a trust anchor.
- Use sequence greater-than-or-equal or an in-memory head as replay protection.
- Latest-wins merge contradictory peer records.
- Count imported records as corroborators or source diversity.
- Let memory produce an action, receipt, approval, or dispatcher admission.
- Delete payload without a durable tombstone.
- Gate acceptance on wall-clock latency or a single benchmark run.

## Don't Hand-Roll

| Problem | Do not build | Use instead | Why |
|---------|--------------|-------------|-----|
| Canonical signing | Per-module JSON sorting or signing serde_json text | swarm_crypto::canonical_json_bytes | One protocol byte representation. |
| Content ID | Caller IDs or pretty-printed hashes | SHA-256 over canonical allowlisted body | Hash identifies exactly signed bytes. |
| Opaque entity ref | Plain SHA-256 of local identifiers or caller-provided secret bytes | `OpaqueKeyResolver` with `swarm_crypto::hmac_sha256_hex` over tenant/export namespace/key epoch | Prevents offline dictionary recovery, cross-scope correlation, and cross-tenant key lookup; resolver controls rotation/retirement. |
| Signature verification | New wrapper or trust from public_key_hex | swarm-crypto primitives after registry lookup | Signature integrity and trust admission stay separate. |
| Chain validation | Sequence-only counter | Extend swarm-spine chain with durable head, nonce, predecessor, equivocation | Existing negative tests enumerate failure classes. |
| Key rotation | First-seen key acceptance | Agent identity continuity-proof pattern plus registry/revocation | Rotation requires trusted continuity. |
| Schema rejection | Broad Value filter/redaction | Typed structs plus deny_unknown_fields and negative fixtures | New fields fail closed. |
| Cleanup | remove_file plus index rewrite | Tombstone-first atomic generation/recovery | Prevents orphan/resurrection state. |
| Corroboration | Count signatures/records | Independent local evidence producer set | Same publisher is not independent evidence. |
| Benchmark | Synthetic score or one arm | Phase288 Arena-owned `Phase287ArenaSynthesisAdapter` -> real Phase287 Blue bridge -> Runtime `ArenaSynthesisInput`, with three arms and held-out digest | Tests the production bridge, typed lineage, and generalization. |

## Common Pitfalls

### Raw telemetry crosses the projection

Existing Sphinx extraction recognizes host, user, process, and IP fields; generic evidence exports whole views. Direct serialization or post-hoc redaction leaks new nested fields. Use explicit constructors and nested privacy fixtures. Warning sign: Value, flatten, TelemetryEvent, ReplayBundle, or raw entity value in the exported API.

### Signature is mistaken for trust

The generic spine verifier derives a key from issuer. An attacker can self-sign a valid body. Registry lookup must precede verification and bind key to tenant, source swarm, schema/domain, epoch, and validity. Never auto-admit unknown keys.

### Replay/fork state is only in memory

SignedStateEnvelope permits an equal sequence under its accepted-sequence rule; Sphinx writes payload/index/sequence separately; chain verdicts are not persisted. Persist nonce/head/hash together, require head plus one, retain same-sequence forks, and restart between transitions.

### Scope or epoch is decorative

Bind tenant, receiver swarm, source swarm, and epoch into canonical signed bytes and registry lookup. Include key epoch in opaque refs. Do not check scope after persistence.

### Stale/revoked/quarantined data remains actionable

Query only Accepted, unexpired, non-revoked, non-quarantined, non-tombstoned records. Rebuild indexes from authoritative lifecycle state at startup. Revocation must also remove records from retrieval.

### Imported provenance manufactures corroboration

Existing strategy scoring counts matching memories. Add origin and independent local evidence IDs; imported records cannot satisfy live-memory or source thresholds. Retain conflicts instead of increasing confidence.

### Retrieval becomes response authority

The memory lane is async enrichment. Return only priority/order metadata; keep memory types out of policy/response and add a negative route test for imported recommendations.

### Conflicts disappear through deduplication

One file per stable ID/latest-wins is unsuitable. Content-address each record and retain all source digests, issuers, confidence, and statuses under a context/motif contradiction key.

### Deletion/restart is under-tested

Test accepted, expiry, revocation, quarantine, deletion, GC, and reimport across process restart. A tombstone and committed generation are required, not only filesystem absence.

### Context match is too permissive

Technique-label-only matching can create false edges. Require typed graph topology, stage/technique, source digest, schema, and local evidence intersection; return zero ordering delta otherwise.

### Withheld corpus is contaminated

One suite path or display-only corpus_version can make held-out results in-sample. Keep evaluator-only manifest/digest and reject any held-out digest in export/calibration/memory lineage.

### Wall-clock timing gates acceptance

Existing replay code correctly stores wall-clock latency as non-gating observations. Use deterministic event/virtual time for Phase 289 gates and retain host timing only as advisory.

## Code Examples

### Explicit export body

~~~rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueEntityRef {
    pub kind: OpaqueEntityKind,
    pub ref_digest: Digest64,
    pub key_epoch: u64,
    pub tenant_scope_digest: Digest64,
    pub export_namespace_digest: Digest64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HerdMemoryBody {
    pub schema_version: u32,
    pub attack_abstractions: Vec<AttackAbstraction>,
    pub causal_motifs: Vec<CausalMotif>,
    pub detector_outcome: Option<DetectorOutcomeSummary>,
    pub response_outcome: Option<ResponseOutcomeSummary>,
    pub strategy_utility: Option<StrategyUtilitySummary>,
}
~~~

Do not add a catch-all map or a raw evidence field for forward compatibility.

### Content address and opaque reference

~~~rust
use swarm_crypto::{canonical_json_bytes, hmac_sha256_hex, sha256_hex};

fn body_id(body: &HerdMemoryBody) -> Result<String, swarm_crypto::CryptoError> {
    Ok(sha256_hex(&canonical_json_bytes(body)?))
}

fn opaque_ref(
    resolver: &dyn OpaqueKeyResolver,
    key_ref: &str,
    tenant: &str,
    export_namespace: &str,
    epoch: u64,
    kind: &str,
    normalized: &str,
) -> Result<String, OpaqueKeyError> {
    let key = resolver.resolve(key_ref, tenant, export_namespace, epoch, KeyPurpose::HerdEntity)?;
    let material = format!("ambush.herd.entity-ref.v2:{tenant}:{export_namespace}:{epoch}:{kind}:{normalized}");
    Ok(key.hmac_sha256_hex(material.as_bytes()))
}
~~~

Construct the wire reference before dropping normalized; raw normalized values must never be serialized.

### Verification order

~~~rust
fn verify_import_locked(
    envelope: &HerdMemoryEnvelope,
    scope: &ReceiverScope,
    registry: &TrustedHerdIssuerRegistry,
    state: &mut HerdMemoryState,
    now_ms: i64,
) -> Result<HerdMemoryImportTicket, HerdMemoryRefusal> {
    envelope.validate_schema_and_bounds()?;
    scope.check(envelope.tenant_id, envelope.receiver_swarm_id, envelope.epoch)?;
    let issuer = registry.active_key(
        envelope.issuer_key_id,
        envelope.tenant_id,
        envelope.source_swarm_id,
    ).ok_or(HerdMemoryRefusal::UnknownIssuer)?;
    issuer.check_validity_and_revocation(envelope.issued_at_ms, envelope.epoch)?;
    envelope.check_time_window(now_ms, scope.max_clock_skew_ms)?;
    let body = canonical_body_bytes(&envelope.body)?;
    if sha256_hex(&body) != envelope.body_hash
        || envelope.memory_id != sha256_hex(&body)
    {
        return Err(HerdMemoryRefusal::ContentHashMismatch);
    }
    if !issuer.public_key.verify(&envelope.signing_bytes()?, &envelope.signature) {
        return Err(HerdMemoryRefusal::InvalidSignature);
    }
    if state.nonce_seen(envelope.issuer_key_id, envelope.nonce) {
        return Err(HerdMemoryRefusal::Replay);
    }
    let reservation = state.reserve_nonce_and_head(envelope)?;
    let ticket = HerdMemoryImportTicket::new(envelope, reservation)?;
    // The caller keeps the same lifecycle lock while re-reading all anchors.
    state.revalidate_generation_epoch_nonce_and_head(&ticket)?;
    state.commit_verify_and_import(ticket)
}
~~~

`HerdMemoryImportTicket` is private, non-serializable, non-debug, non-cloneable,
and single-use. The coordinator consumes it in the same locked CAS that writes
accepted payload/status/head/nonce/index state; a generation, epoch, revocation,
nonce, or head change returns a durable typed refusal and commits no payload.
Signature success is not authorization; refusal and accepted state must be
persisted.

### Corroboration-gated ordering

~~~rust
fn learned_priority_delta(
    memory: &ImportedMemory,
    graph: &HypothesisGraph,
    local: &LocalEvidenceIndex,
) -> u16 {
    if memory.status != ImportStatus::Accepted
        || !memory.context_matches(graph)
        || !local.has_independent_corroboration(memory.context_key())
        || memory.contradicted()
    {
        return 0;
    }
    memory.bounded_utility_basis_points()
}
~~~

The returned value is a task ordering hint, never a policy verdict or permit.

## Historical Plan-Sized Work Decomposition (non-authoritative)

The decomposition below is retained as the initial research sketch only. Its
wave labels and prose are not executable ownership or dependency instructions;
the current `*-PLAN.md` files, `289-VALIDATION.md`, and the accepted Wave 0
gate are authoritative. Do not copy commands, paths, or implementation
boundaries from this historical section into closure evidence.

### Wave 0: Contract and fixtures

- Extend MemoryConfig with tenant, local swarm, accepted source swarms, epoch, registry path, import root, TTL/skew, retention, and opaque-key epoch; validate fail-closed.
- Define allowlist/prohibited-field fixtures, including nested raw telemetry, secrets, host/user/process/IP, credentials, receipts, actions, and notes.
- Define separate in-sample and evaluator-only withheld replay manifests/digests, seed, scheduler, and virtual-clock contract.

### Wave 1: TCB envelope, registry, and chain

- Add typed body/envelope, domain-separated canonical signing subject, trusted issuer registry, continuity-proof rotation, revocation, refusal, nonce/head, contradiction/equivocation records in swarm-spine.
- Verify scope, registry key, body/content hash, signature, time window, nonce, strict head plus one, and exact predecessor before atomic commit.
- Add negative controls for unknown fields/privacy, tamper, unknown issuer, cross-scope splice, stale/expiry, replay, gaps, regression, wrong predecessor, fork, equivocation, rotation, and revocation.

### Wave 2: Projection and lifecycle

- Project completed Phase 286 investigations/graphs/strategy outcomes through an explicit allowlist; never serialize rich source structs.
- Add accepted/quarantined/refused/expired/revoked/tombstoned import store with durable refusal reasons and contradiction retention.
- Add local corroboration only from independent local evidence, then restart tests for import, quarantine, revoke, delete, GC, and reimport.

### Wave 3: Advisory retrieval boundary

- Adapt Sphinx and strategy memory with Imported origin, context matching, local corroboration, and bounded task priority.
- Ensure imports cannot satisfy MIN_LIVE_MEMORIES, source diversity, confidence authority, policy, receipts, approval, dispatch, or response adapters.
- Add dependency and runtime negative tests for authority leakage.

### Wave 4: Evaluation and acceptance

- Run memory-enabled, single-agent, and no-memory arms through the Phase 288 Arena-owned `Phase287ArenaSynthesisAdapter` and real Phase 287 Blue bridge, with fixed seeds, typed `ArenaSynthesisInput` lineage, and in-sample digest.
- Report hypothesis time, chain recall, false edges, duplicate work, evidence coverage, unseen evasion, and input digests.
- Evaluate held-out only after export/calibration; enforce the HERDMEM-06 thresholds and preserve machine-readable evidence.

## State of the Art

| Current approach | Phase 289 approach | Impact |
|---------|---------|---------|
| Generic envelope/self-carried issuer | Registry-anchored typed herd envelope | Integrity and trust admission become separate checks. |
| Local snapshot sequence | Durable scoped head, nonce, predecessor, expiry, equivocation | Restart-safe replay/fork resistance. |
| Raw Sphinx entities and whole evidence views | Allowlisted abstractions and HMAC refs | No raw telemetry transfer. |
| Local strategy memory count | Origin-aware corroboration-gated ordering | Imported memory cannot manufacture authority. |
| File cleanup/index rewrite | Tombstone-first atomic generations | No actionable orphan or resurrection. |
| Wall-clock observations | Deterministic virtual/event metrics | Benchmark acceptance is reproducible. |
| One replay suite | Three arms plus evaluator-only withheld corpus | Transfer and generalization are measurable. |

**Deprecated/outdated:** direct rich-struct serialization, issuer-key self-trust, sequence-only replay checks, imported source diversity, memory-to-response shortcuts, tombstone-free deletion, and wall-clock acceptance gates.

## Open Questions

1. **Initial trusted issuer source:** No federation registry exists. Require an explicitly configured or locally signed bootstrap registry; never admit a peer key from an envelope.
2. **Federation allowlist:** Bind tenant, receiver swarm, source swarm, and epoch; make accepted source swarms explicit rather than default-all.
3. **Corroboration threshold:** Define a typed policy requiring at least one independent local producer/evidence digest by default; test zero, one, and conflict cases.
4. **TTL/skew/revocation history:** Configure bounded values; revoked historical records may remain review-only but never retrieval-actionable.
5. **Contradiction key:** Use canonical graph context plus motif and source-corpus digest; retain every content-addressed body below it.
6. **Opaque-key rotation:** Scope HMAC to tenant/export namespace and key epoch; new exports use only the configured current epoch, same-scope retired epochs are verification-only, and missing/retired/revoked/rotated keys fail closed with no raw, environment, test, or process-local fallback.
7. **Withheld corpus location:** Add a separate evaluator-owned manifest/digest; no Phase 289 benchmark manifest currently exists.

## Validation Architecture

> **Historical, non-authoritative examples.** The commands and file-existence
> rows in this research section describe the initial research state only; they
> are not execution gates and may contain pre-repair broad filters or stale
> paths. The authoritative commands are the `<automated>` fields in the
> Phase 289 plans and `289-VALIDATION.md`, all of which use the Wave 0 upstream
> prerequisite gate plus `--locked --offline` and exact filters where required.

### Research update graph and authority

This research document is a historical input, not an executable source of
truth. The authoritative update graph is:

```text
289-00W-PLAN.md (gate + --run wrapper + root helper)
        -> 289-00-PLAN.md (public truth, immutable allowlist, exact matrix)
        -> 289-01..289-06-PLAN.md (typed implementation contracts/tests)
        -> 289-07-PLAN.md + 289-VALIDATION.md + 289-P0-P2-REVIEW.md + 289-VERIFICATION.md
```

The pre-repair Test Framework, Existing controls, Phase Requirements to Test
Map, Sampling Rate, and Wave 0 Gaps sections below are historical examples;
their commands, paths, filters, and File Exists values must never be copied
into execution or closure evidence. When they disagree with a plan, the
plan's `<automated>` command wins; when a plan disagrees with current upstream
closure, the accepted Wave 0 gate and typed pins win. Update this graph only by
editing plan/validation artifacts, never by silently reinterpreting stale
research commands.

### Current resolved planning table (authoritative)

The following table resolves the research sketch into the current plan-owned
contracts. It is the only research summary that may be used to reconcile plan
ownership; the historical tables below remain explicitly non-authoritative and
retain truthful `No — Wave 0`/pending existence cells.

| owner | resolved contract and handoff | exact proof or gate |
|---|---|---|
| `289-00W` | Tools-only prerequisite: execute the external closure gate first, retain `artifacts/phase289/upstream-prerequisite-gate.json`, and own the sole root SHA-256 helper. It resolves actual Phase 286 07B, Phase 287 06, and Phase 288 07 closure/review/validation/tree/evidence records before any fixture or implementation work. | `bash tools/check-herd-memory-upstreams.sh --require-accepted --locked-tree`; all later commands use `bash tools/check-herd-memory-upstreams.sh --run -- ...`; missing/partial/path-only evidence fails closed. |
| `289-00` | Plan-owned public truth: immutable frozen-tree allowlist, typed `ArenaLineage`/`SignedStateExpectation` with six unique roles and complete signed-state fields, `ArenaContractPins`, canonical `Digest64`/typed IDs, three-arm truth, exact eight-file Phase 287 corpus inventory plus `oracle-registry.json` cardinality/aggregate manifest digest, and `herd-memory-metrics-v1` names/formula IDs. It consumes resolved pins and never invents upstream or withheld values. | `allowlist_oracle_rejects_nested_privacy_fields`; `phase287_corpus_inventory_is_exactly_eight_files`; `sha256_root_output_is_unprefixed_lowercase_64_hex`; all lineage/digest/self-field mutations fail before scoring. |
| `289-01`, `289-01B`, `289-01C` | Config, privacy body, and config-bound opaque reference provider. Raw telemetry/host IDs/secrets/credentials/authority fields are schema-prohibited; HMAC entity references are not signing authority. | `herd_memory_config_contract`; `typed_body_rejects_unknown_and_prohibited_fields`; `file_provider_bootstrap_requires_secure_root`; `factory_requires_config_bound_file_provider`. |
| `289-02` | TCB trust: resolver-only private `ExternalRootKeyPin`/`ResolvedExternalRootKey`, bytes-only `NeutralSignatureBytes`, explicit externally keyed `verify(subject, signature)`, opaque config-bound `HerdMemoryRootVerifier` facade, root-signed issuer/rotation/revocation, strict scope/epoch/nonce/head, and private raw-byte decode token. No embedded/self-key verifier can authenticate itself. | `registry_rotation_requires_continuity_and_scope`; `registry_restart_preserves_rotation_and_revocation_history`; root subject/key/path/custody/replacement and unknown/duplicate/noncanonical/oversize mutations fail closed. |
| `289-03` | One config-owned lifecycle handle/store/clock/lock authority. Import is one verify-and-import CAS; export is `prepare_export`/`commit_export` with root-signed `ExportSignerAnchor` and a distinct self-field-excluded lifecycle export subject, generation/predecessor/source-highwater/nonce/fence journal, recovery, crash/concurrency/revocation races, and memory/file parity. | `export_signer_requires_config_bound_custody`; `export_anchor_root_subject_excludes_anchor_self_fields`; `lifecycle_export_subject_excludes_snapshot_self_fields`; `verify_and_import_rejects_crash_revocation_epoch_and_concurrent_same_head`; no public store, clock, candidate, token, signer, or verified-value bypass. |
| `289-04` | Runtime allowlist projection consumes only the Arena-owned Phase 287 adapter and Runtime-owned Phase 288 `ArenaSynthesisInput`; Runtime has no CampaignStage conversion, tuple constructor, or fingerprint type. Its Arena-side contract is owned by 289-06 in the existing adapter seam, with literal five-scalar bytes, Phase 287 golden-vector equality, per-tuple digests, sorted `phase_287_known_evasion_set_sha256`, and derived attribution outside the tuple digest but inside authenticated ArenaLineage. Export routes only to the lifecycle reservation pair. | `arena_synthesis_input_accepts_phase287_lineage_and_phase288_adapter_evidence`; `projection_serialization_rejects_authority_and_raw_fields`. |
| `289-05` | Runtime importer exposes only bounded `deserialize_and_import(&[u8])`, forwards to the handle, and gates advisory ordering on graph/source match plus independent local corroboration. Withheld records, candidate envelopes/tokens, stores, and clocks are not public injection seams. | `restart_revocation_and_quarantine_remove_actionable_memory`; `imported_memory_cannot_reach_response_authority`; poisoning/quarantine/contradiction/revocation/delete/restart mutations retain only typed durable review state. |
| `289-06` | Deterministic real-bridge three-arm table: `memory_enabled`, `single_agent`, and `no_memory` share candidate/`empty_frozen`, inputs, scheduler, source lineage, and clock but have distinct provenance; imported advisory effect is measurable. The existing Arena adapter seam owns exhaustive CampaignStage conversion, exact literal bytes/golden vector, per-tuple digest, sorted known-set aggregate, and derived authenticated attribution; a separate evaluator process owns private tuple/record/aggregate/fingerprint types and emits only signed aggregate results. One canonical authenticated IPC schema carries signed wire `issuance_id` copies while the private capability remains non-serializable. | `three_arms_use_real_blue_bridge_and_preserve_typed_lineage`; `phase287_campaign_stage_conversion_is_exhaustive`; `phase287_tuple_golden_vector_matches_upstream`; `phase287_known_set_aggregate_digest_is_sorted_and_pinned`; `phase287_attribution_is_derived_from_authenticated_source`; `three_arms_emit_identical_input_digests`; `evidence_coverage_formula_zero_and_rounding_are_exact`; canonical metric names and `evidence_coverage_formula_id` are parser-enforced. |
| `289-07` plus review/verification | Two-scope/two-freeze closure: candidate/public Scope A emits a root-signed `CandidateFreezeReceipt` binding the one lineage/tree/allowlist/export-anchor/generation digest set; evaluator Scope B then receives a fresh authenticated capability, and independent root-signed reviewer assignment/provenance follows. `ReviewRootArtifactKind` and private authenticated `VerifiedReviewProvenance` distinguish assignment/result records. Review parser recomputes severity and requires one row for every task, requirement, artifact, upstream pin, arm, and control; root/validation/bridge subjects are structured catalog entries within the 84 rows. | `independent_closure_artifact_mutations_fail_closed`, exact CI wiring, frozen `HEAD^{tree}`/dirty/untracked checks, and 84-row/cardinality/arithmetic validation. |

All current plan commands are `--locked --offline` (except native rustfmt's
flagless `cargo fmt -- --check`) and all non-Wave-0 task commands begin with the
mandatory wrapper. This table describes planned contracts only: it does not
turn any future file into an existing artifact or change the validation
document's pre-execution false cells.

The project config explicitly sets workflow.nyquist_validation to true, so validation planning is required.

### Historical Test Framework (non-authoritative)

| Property | Value |
|----------|-------|
| Framework | Rust built-in test harness with test and tokio::test |
| Config file | Cargo.toml workspace; no separate runner |
| Quick run command | <code>cargo test -p swarm-spine --lib herd_memory --locked --offline</code> or <code>cargo test -p swarm-runtime --lib herd_memory --locked --offline</code> |
| Full suite command | <code>cargo test --workspace --locked --offline</code> |

### Historical Existing Controls (non-authoritative)

- <code>cargo test -p swarm-spine --lib envelope::tests --locked --offline</code> covers generic envelope roundtrip and tampered fact rejection.
- <code>cargo test -p swarm-spine --test negative_envelope_and_chain --locked --offline</code> covers missing issuer/signature/hash, forged issuer, malformed key/signature, replay, fork, sequence, predecessor, and cross-issuer splice mutations.
- Sphinx restart/tamper/replay tests in swarm-runtime preserve local snapshot behavior but do not prove peer registry/nonce/expiry/tombstone safety.
- Strategy sparse-memory and latency-invariance tests preserve the advisory/deterministic score boundary.
- Generic evidence verification tests must remain separate from herd privacy export.

### Historical Phase Requirements to Test Map (non-authoritative)

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|-------------|----------|-----------|-------------------|--------------|
| HERDMEM-01 | Allowlist exports only typed abstractions/motifs/outcomes/utility; prohibited and unknown fields fail, including nested values | unit + negative serialization | <code>cargo test -p swarm-spine --lib herd_memory_export_rejects_privacy_violation --locked --offline</code> | No — Wave 0, new herd_memory module |
| HERDMEM-02 | Registry signature/content/provenance/scope/time/nonce/strict chain checks; tamper/replay/stale/schema/privacy refusal persists | unit + integration | <code>cargo test -p swarm-spine --test herd_memory_negative --locked --offline</code> | No — Wave 0, new integration test |
| HERDMEM-03 | Imported memory cannot count as corroboration/diversity or authorize; context and local evidence gate ordering; conflicts remain visible | integration + authority negative | <code>cargo test -p swarm-runtime --test herd_memory_integration corroboration_and_conflicts --locked --offline</code> | No — Wave 0 |
| HERDMEM-04 | Matching graph/source evidence alone changes ordering; three arms report all required metrics | deterministic integration/benchmark | <code>cargo test -p swarm-runtime --test herd_memory_benchmark ordering_requires_context --locked --offline</code> | No — Wave 0 |
| HERDMEM-05 | Expiry, rotation, revocation, quarantine, tombstone/delete, GC, indexes, and restart recover without actionable orphan | restart/fault integration | <code>cargo test -p swarm-runtime --test herd_memory_integration lifecycle_survives_restart --locked --offline</code> | No — Wave 0 |
| HERDMEM-06 | Checked-integer `>=2,000 bp` time OR `>=1,000 bp` recall; false-edge `<=1,000 bp`; duplicate-work `<=500 bp`; unseen evasion; withheld relative gap `<=500 bp` | benchmark gate | <code>cargo test -p swarm-runtime --test herd_memory_benchmark acceptance_gate --locked --offline</code> | No — Wave 0 |

### Historical Sampling Rate (non-authoritative)

- Per task commit: focused spine/runtime herd tests plus the relevant existing negative control.
- Per wave merge: <code>cargo test -p swarm-spine --lib --locked --offline && cargo test -p swarm-runtime --lib herd_memory --locked --offline && cargo test -p swarm-runtime --test herd_memory_integration --locked --offline</code>.
- Phase gate: full workspace suite, deterministic three-arm benchmark, and held-out evaluator green before verification.

### Historical Wave 0 Gaps (non-authoritative)

- New swarm-spine herd_memory module with body/envelope/registry/head/nonce/refusal/tombstone and unit tests.
- New swarm-spine herd_memory_negative integration test.
- New swarm-runtime herd_memory adapter and integration tests.
- New three-arm benchmark test and separate held-out corpus manifest/digest.
- MemoryConfig schema/fixture coverage for scope, registry, epoch, TTL/skew, retention, and opaque key epoch.
- Atomic-generation interruption/recovery fixture.

## Sources

### Primary (HIGH confidence)

- CLAUDE.md — Rust-first crate ownership, fail-closed runtime, audit, and workspace commands.
- docs/AGENTS.md, docs/ARCHITECTURE.md, docs/CONSENSUS.md — Sphinx enrichment boundary, async/critical/governance lanes, and the rule that signatures do not alone confer authority.
- docs/decisions/0009-trusted-computing-base-boundary.md — policy/response cannot depend on the runtime memory host.
- docs/decisions/0011-governance-receipts-need-a-trust-anchor.md — self-consistent chain linkage is not a durable trust anchor.
- .planning/phases/289-herd-memory/289-CONTEXT.md and .planning/REQUIREMENTS.md:860-867 — locked scope and exact HERDMEM requirements.
- crates/swarm-spine/src/envelope.rs and src/chain.rs — canonical envelope and current chain seams.
- crates/swarm-spine/tests/negative_envelope_and_chain.rs — mutation controls for envelope/chain failure classes.
- crates/swarm-core/src/signed_state.rs — local snapshot limitation.
- crates/swarm-runtime/src/agent_identity.rs — registry admission, continuity rotation, and atomic file precedent.
- crates/swarm-runtime/src/sphinx_agent.rs — rich local graph, raw extraction, restart, tamper, replay, and retention seams.
- crates/swarm-spine/src/investigation.rs and src/lib.rs — rich local source structures to project, not export.
- crates/swarm-runtime/src/strategy.rs — local memory count/context/recency/advisory scoring.
- crates/swarm-evolution/src/evidence.rs — broad generic evidence export and verification boundary.
- crates/swarm-runtime/src/replay/harness.rs and src/replay/types.rs — replay suite and gating-versus-observation separation.
- crates/swarm-crypto/src/hashing.rs and src/lib.rs — canonical JSON, SHA-256, HMAC, and Ed25519 helpers.
- Cargo.toml and Cargo.lock — dependency layering and versions.

### Official documentation (HIGH confidence)

- <https://serde.rs/attributes.html> — deny_unknown_fields and Serde attributes.
- <https://serde.rs/derive.html> — typed Serde derive.
- <https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.SigningKey.html> — Ed25519 signing/verification API.
- <https://doc.rust-lang.org/std/fs/fn.rename.html> — rename semantics for atomic commits.
- <https://doc.rust-lang.org/stable/std/fs/struct.File.html> — File::sync_all durability primitive.
- <https://doc.rust-lang.org/std/fs/index.html> — filesystem atomicity and TOCTOU guidance.

### Secondary (MEDIUM confidence)

- Phase 286, 287, and 288 context/plan/validation files — upstream graph, adversarial, and synthesis contracts consumed by Phase 289, including the Arena-owned adapter and Runtime-owned DTO paths above.

### Tertiary (LOW confidence)

- None used for normative claims.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — workspace manifests and lockfile directly verify versions and dependency direction.
- Architecture: HIGH for layering/existing seams; MEDIUM for exact new module and wire-field names.
- Privacy boundary: HIGH — current Sphinx/source types explicitly expose prohibited values.
- Envelope/lifecycle: HIGH for required invariants and existing precedents; MEDIUM for final recovery-journal layout.
- Benchmark: MEDIUM — replay infrastructure exists, but Phase 286 metrics and Phase 289 withheld manifest remain to be implemented.
- Pitfalls: HIGH — existing negative tests and ADRs directly demonstrate failure classes.

**Research date:** 2026-08-21
**Valid until:** 2026-09-20 for stable seams; re-check lockfile, upstream phase implementation, and corpus identity if they change.
