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

Compare memory-enabled, single-agent, and no-memory controls on hypothesis time, chain recall, false causal edges, duplicate work, and evidence coverage. Pass with at least 20% lower median time to correct hypothesis or +10 percentage points chain recall, no breach of Phase 286 false-edge/duplicate ceilings, at least one previously unseen evasion across the withheld corpus, and withheld-campaign performance within 5% of in-sample score.

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
| HERDMEM-04 | Retrieved memory changes the next investigation's task ordering only when its context matches the current graph and source evidence. The benchmark compares memory-enabled, single-agent, and no-memory controls on hypothesis time, chain recall, false causal edges, duplicate work, and evidence coverage. | Adapt Sphinx/strategy retrieval to a corroboration-gated priority delta and reuse the deterministic replay harness for three isolated arms. |
| HERDMEM-05 | Memory retention, expiry, revocation, poisoning quarantine, and operator deletion are durable and restart-safe. Garbage collection removes expired payloads and dependent indexes without leaving actionable orphan state. | Use a tombstone-first lifecycle ledger, atomic committed generations, restart recovery, registry revocation, and complete dependent-index GC. |
| HERDMEM-06 | Herd-memory acceptance requires at least 20% lower median time to correct hypothesis or 10 percentage-point higher chain recall versus the single-agent control, no increase above the Phase 286 false-edge/duplicate-work ceilings, discovery of at least one previously unseen evasion across the withheld corpus, and withheld-campaign generalization within 5% of the in-sample score. | Add deterministic event/virtual-clock metrics, unseen-evasion accounting, and an evaluator-only held-out corpus digest. |
</phase_requirements>

## Summary

The repository has useful cryptographic precedents but not a safe cross-swarm memory protocol. swarm-spine envelope signs canonical JSON and chain checks issuer, sequence, and previous hash; swarm-core SignedStateEnvelope checks one local signer and a sequence. Neither provides a locally trusted issuer registry, tenant/swarm/epoch binding, expiry, nonce uniqueness, durable fork/equivocation retention, or a strict persisted head. The generic spine verifier also derives a public key from the envelope issuer, which proves self-consistency, not federation trust.

The current producers are too rich to export directly. ReplayBundle, InvestigationBundle, CorrelatedIncident, Sphinx EntityNode, SphinxMemoryContribution, and generic evidence views can contain host IDs, users, process names, IPs, raw indicators, receipt references, secrets, or operator notes. Sphinx extract_entities explicitly collects host, user, process, and IP values, and evidence export serializes complete views. Phase 289 needs a dedicated allowlist projection before signing/hashing.

Place typed envelope, registry, chain, refusal, tombstone, and lifecycle primitives in swarm-spine (TCB), and projection, import/quarantine, corroboration, graph matching, task ordering, and benchmark integration in swarm-runtime. Imported memory may only contribute a bounded task-ordering hint. It must never count as local source diversity, authorize confidence, create a receipt, reach policy/response, or bypass approval.

**Primary recommendation:** Build a versioned HerdMemoryEnvelope around a privacy-minimized HerdMemoryBody, verify it against a locally configured and rotatable TrustedHerdIssuerRegistry plus a durable per-stream head/nonce ledger, retain every refusal and contradiction, and expose imports only through corroboration-gated advisory priority.

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

**Version verification:** These versions are from Cargo.lock on 2026-08-21. Run <code>cargo metadata --locked --format-version 1 --no-deps</code> before implementation and preserve the checked-in resolution unless a deliberate protocol review changes it.

## Architecture Patterns

### Recommended project structure

~~~
crates/swarm-core/src/config/state.rs       # Herd scope/epoch/TTL/registry config
crates/swarm-spine/src/herd_memory.rs       # Typed body/envelope/registry/chain/lifecycle
crates/swarm-spine/tests/herd_memory_negative.rs
crates/swarm-runtime/src/herd_memory.rs    # Projection/import/corroboration/advisory adapter
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

Registry entries need active/retired/revoked state, tenant/source-swarm/schema/domain, validity interval, epoch, and continuity proof. The old key signs a canonical rotation payload linking old/new key IDs, following FileAgentIdentityRegistry::rotate_identity. A revoked key cannot create new actionable imports. Unknown keys are never admitted from envelopes.

Require exact head plus one and exact predecessor. A second valid record at an already-seen sequence with a different hash is equivocation: retain both in a contradiction set and quarantine the stream. HashMismatch or SequenceMismatch returned only in memory is not durable detection.

### Pattern 3: Corroboration-gated advisory retrieval

Imported records have origin Imported and status Accepted only after verification. Retrieval requires graph topology/stage/technique/source-digest context plus independent local evidence. It may add a bounded learned-value basis-point delta to task ordering only.

Imported records never count as independent sources, local corroboration, graph confidence, MIN_LIVE_MEMORIES, policy evidence, approval, receipt, capability, or response authority. A single publisher cannot manufacture diversity by emitting multiple records. Contradictory memories remain visible as a typed set.

### Pattern 4: Tombstone-first restart-safe lifecycle

Accepted payload, indexes, head, nonce ledger, refusal report, quarantine state, and tombstone form one durable state machine. Write a complete temporary generation, sync it, rename atomically, and sync the parent directory. Write a tombstone before deleting payload. GC removes payload and every dependent index but retains a non-actionable tombstone/refusal/equivocation record so restart cannot resurrect it.

### Pattern 5: Deterministic three-arm/withheld evaluation

Run memory-enabled, single-agent, and no-memory arms through the same seeded replay/investigation path, scheduler, virtual clock, and in-sample corpus. Use event count or virtual time for hypothesis time. Persist seed, corpus digests, memory-set digest, scheduler, and gate inputs. Load held-out scenarios only in the evaluator after export/calibration and reject contamination. Keep wall-clock observations non-gating, as existing ReplayEvaluationObservation does.

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
| Opaque entity ref | Plain SHA-256 of local identifiers | swarm_crypto::hmac_sha256_hex with tenant/key-epoch key | Prevents offline dictionary recovery and cross-scope correlation. |
| Signature verification | New wrapper or trust from public_key_hex | swarm-crypto primitives after registry lookup | Signature integrity and trust admission stay separate. |
| Chain validation | Sequence-only counter | Extend swarm-spine chain with durable head, nonce, predecessor, equivocation | Existing negative tests enumerate failure classes. |
| Key rotation | First-seen key acceptance | Agent identity continuity-proof pattern plus registry/revocation | Rotation requires trusted continuity. |
| Schema rejection | Broad Value filter/redaction | Typed structs plus deny_unknown_fields and negative fixtures | New fields fail closed. |
| Cleanup | remove_file plus index rewrite | Tombstone-first atomic generation/recovery | Prevents orphan/resurrection state. |
| Corroboration | Count signatures/records | Independent local evidence producer set | Same publisher is not independent evidence. |
| Benchmark | Synthetic score or one arm | Existing replay harness with three arms and held-out digest | Tests production path and generalization. |

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
    pub ref_digest: String,
    pub key_epoch: u64,
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

fn opaque_ref(key: &[u8], epoch: u64, kind: &str, normalized: &str) -> String {
    let material = format!("ambush.herd.entity-ref.v1:{epoch}:{kind}:{normalized}");
    hmac_sha256_hex(key, material.as_bytes())
}
~~~

Construct the wire reference before dropping normalized; raw normalized values must never be serialized.

### Verification order

~~~rust
fn verify_import(
    envelope: &HerdMemoryEnvelope,
    scope: &ReceiverScope,
    registry: &TrustedHerdIssuerRegistry,
    state: &HerdMemoryState,
    now_ms: i64,
) -> Result<VerifiedHerdMemory, HerdMemoryRefusal> {
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
    state.verify_strict_head(envelope)?;
    Ok(VerifiedHerdMemory::from(envelope.clone()))
}
~~~

Signature success is not authorization; refusal and accepted state must be persisted.

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

## Plan-Sized Work Decomposition

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

- Run memory-enabled, single-agent, and no-memory arms through the production replay/investigation path with fixed seeds and in-sample digest.
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
6. **Opaque-key rotation:** Scope HMAC to tenant/export namespace and key epoch; allow only bounded dual-key reads during planned rotation, never raw fallback.
7. **Withheld corpus location:** Add a separate evaluator-owned manifest/digest; no Phase 289 benchmark manifest currently exists.

## Validation Architecture

The project config explicitly sets workflow.nyquist_validation to true, so validation planning is required.

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in test harness with test and tokio::test |
| Config file | Cargo.toml workspace; no separate runner |
| Quick run command | <code>cargo test -p swarm-spine --lib herd_memory</code> or <code>cargo test -p swarm-runtime --lib herd_memory</code> |
| Full suite command | <code>cargo test --workspace</code> |

### Existing controls

- <code>cargo test -p swarm-spine --lib envelope::tests</code> covers generic envelope roundtrip and tampered fact rejection.
- <code>cargo test -p swarm-spine --test negative_envelope_and_chain</code> covers missing issuer/signature/hash, forged issuer, malformed key/signature, replay, fork, sequence, predecessor, and cross-issuer splice mutations.
- Sphinx restart/tamper/replay tests in swarm-runtime preserve local snapshot behavior but do not prove peer registry/nonce/expiry/tombstone safety.
- Strategy sparse-memory and latency-invariance tests preserve the advisory/deterministic score boundary.
- Generic evidence verification tests must remain separate from herd privacy export.

### Phase Requirements to Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|-------------|----------|-----------|-------------------|--------------|
| HERDMEM-01 | Allowlist exports only typed abstractions/motifs/outcomes/utility; prohibited and unknown fields fail, including nested values | unit + negative serialization | <code>cargo test -p swarm-spine --lib herd_memory_export_rejects_privacy_violation</code> | No — Wave 0, new herd_memory module |
| HERDMEM-02 | Registry signature/content/provenance/scope/time/nonce/strict chain checks; tamper/replay/stale/schema/privacy refusal persists | unit + integration | <code>cargo test -p swarm-spine --test herd_memory_negative</code> | No — Wave 0, new integration test |
| HERDMEM-03 | Imported memory cannot count as corroboration/diversity or authorize; context and local evidence gate ordering; conflicts remain visible | integration + authority negative | <code>cargo test -p swarm-runtime --test herd_memory_integration corroboration_and_conflicts</code> | No — Wave 0 |
| HERDMEM-04 | Matching graph/source evidence alone changes ordering; three arms report all required metrics | deterministic integration/benchmark | <code>cargo test -p swarm-runtime --test herd_memory_benchmark ordering_requires_context</code> | No — Wave 0 |
| HERDMEM-05 | Expiry, rotation, revocation, quarantine, tombstone/delete, GC, indexes, and restart recover without actionable orphan | restart/fault integration | <code>cargo test -p swarm-runtime --test herd_memory_integration lifecycle_survives_restart</code> | No — Wave 0 |
| HERDMEM-06 | Either 20% time or +10pp recall; Phase 286 ceilings; unseen evasion; within 5% withheld score | benchmark gate | <code>cargo test -p swarm-runtime --test herd_memory_benchmark acceptance_gate</code> | No — Wave 0 |

### Sampling Rate

- Per task commit: focused spine/runtime herd tests plus the relevant existing negative control.
- Per wave merge: <code>cargo test -p swarm-spine --lib && cargo test -p swarm-runtime --lib herd_memory && cargo test -p swarm-runtime --test herd_memory_integration</code>.
- Phase gate: full workspace suite, deterministic three-arm benchmark, and held-out evaluator green before verification.

### Wave 0 Gaps

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

- Phase 286, 287, and 288 context files — upstream graph, adversarial, synthesis, replay, and withheld contracts consumed by Phase 289.

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
