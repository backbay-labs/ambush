# Phase 285 Governance Persistence Protocol

status: architecture-reviewed
reviewed_at: 2026-08-24T06:53:23Z
architecture_review: P0=0, P1=0, P2=0
implementation_status: not implemented

## Purpose

This contract replaces the failed pathname-cleanup and counter-derived temporary-file approach used during the reopened Phase 285 governance/detector integration gate. It defines the persistence, publication, retention, recovery, reinitialization, and external-witness invariants that implementation must satisfy before Phase 285 can close again.

The protocol is deliberately fail-closed. A crash, conflicting writer, replaced inode, malformed fixed lane, unavailable witness, or ambiguous recovery state may deny service. It must not authorize action, overwrite a foreign artifact, delete uncertain bytes, silently rebind an authority namespace, or report a committed state that cannot be recovered.

## Scope and non-claims

The protocol protects the shipped governance stream against:

- cooperating writers serialized by the selector, state, authority-pair, and cleanup-pool locks;
- noncooperating local writers that race governance pathnames or mutate governance file contents;
- symlink, hard-link alias, parent-directory replacement, pool replacement, slot replacement, and final-seam inode substitution;
- torn writes and crashes at every publication, witness, retention, maintenance, and recovery phase;
- local replay of signed governance files when the external durability witness retains a newer head.

The protocol does not claim post-return filesystem immutability. Final verification establishes a linearization point. A same-UID writer may mutate local bytes after that point; the next operation or restart must detect the mutation and fail closed or repair from external escrow.

The protocol does not claim that local files alone prevent coordinated replay. That guarantee is impossible when an adversary may replay every locally signed anchor. Persistent enforced governance therefore requires the external durability witness defined below. There is no local-file or optional production fallback.

Durability is scoped to successful file and directory `fsync` and the external witness's documented durable-linearizable contract.

## Required authority lifetime

The current and legacy governance authority sidecars must be hard links to one regular-file inode. Path selection acquires the selector lock and this authority pair, validates both names against the held identity, and transfers an opaque guard through bootstrap, initialization, reinitialization, or recovery.

Construction must not drop the guard and reacquire either authority pathname. The guard remains live until construction commits or refuses. A direct initializer through an alternate path cannot establish a second authority stream.

External witness sessions are bound to:

- the governance stream identifier;
- the exact transferred authority-pair identity;
- the admitted governance signing key;
- the publication-binding generation;
- the witness service identity;
- the committed witness head;
- a random 256-bit session commitment retained only by the opaque guard.

## Fixed authenticated namespace

The signed cleanup-pool binding declares one fixed namespace. Ordinary operation allocates no publication or retention pathname.

The binding includes:

- schema and domain versions;
- a random namespace generation;
- parent-directory, pool-directory, pool-lock, and binding-file identities;
- the exact fixed cleanup-slot names and count;
- one state staging lane;
- one checkpoint staging lane;
- two alternating transaction-journal lanes;
- every allowed inode identity for those roles;
- configured byte and record limits;
- the external witness identity and stream binding.

The canonical state and checkpoint files and every staging, journal, lock, binding, archive, and cleanup-slot role must be pairwise inode-distinct. Cross-role hard links are invalid even when names differ.

Ordinary startup, save, retention, and recovery enumerate the complete pool namespace. An unknown entry, missing fixed entry, malformed fixed slot, unexpected file type, role alias, name-to-inode mismatch, or binding disagreement returns a typed refusal before mutation.

## Canonical wire and identifier derivation

All signed structures use versioned structs with fixed field order, unknown-field rejection, canonical JSON, bounded strings and collections, and checked size arithmetic.

`CandidatePreimageV1` contains:

- complete signed state and checkpoint bytes;
- the byte lengths and SHA-256 digests of both payloads;
- stream identifier and predecessor committed head;
- publication binding and binding generation;
- authority-pair identity;
- epoch, sequence, and witness intent counter.

It excludes transaction identifier, candidate digest, witness receipts, session credentials, and all other derived fields.

The candidate digest is:

```text
SHA256(domain_candidate_v1 || u64_be(canonical_length) || canonical_candidate_preimage)
```

`TxidPreimageV1` is a separate canonical struct containing the domain version, stream identifier, predecessor-head digest, candidate digest, binding generation, epoch, sequence, intent counter, and authority-pair identity.

The transaction identifier is:

```text
SHA256(domain_tx_v1 || u64_be(canonical_length) || canonical_txid_preimage)
```

Every domain-separated digest uses an explicit version and length-delimited canonical bytes. Raw tuple concatenation is forbidden.

Epoch, sequence, intent counter, session generation, journal generation, and size arithmetic are checked and non-wrapping. Exhaustion is permanent and typed; no identifier derivation or mutation proceeds after overflow.

## External durability witness

Persistent enforced governance requires an injected `GovernanceDurabilityWitness`. The witness is durable, linearizable, replay-resistant, outside the local governance filesystem authority domain, and transport-authenticated. It stores immutable candidate payloads and independently validates them.

Required operations are conceptually:

```text
discover_stream(recovery_challenge)
prepare_successor(session, expected_head, candidate)
read_prepared_for_stream(stream_id)
commit_prepared(session, txid)
abort_prepared(session, txid)
read_head(stream_id)
fetch_payload(head_or_txid)
```

The witness permits at most one live prepared successor per stream. Calls are idempotent by transaction identifier and candidate digest.

Before returning `Prepared`, the witness independently verifies:

- canonical state and checkpoint serialization;
- exact stream, signing domain, signer, and authority-pair binding;
- state/checkpoint publication-binding equality;
- payload digests and configured size limits;
- predecessor committed head;
- epoch, sequence, and intent transition;
- pairwise-distinct publication roles;
- candidate-digest and transaction-identifier derivation.

The committed witness head contains the committed transaction identifier, candidate digest, epoch, sequence, intent counter, binding generation, authority-pair identity, and both payload digests and sizes.

The witness retains the current committed payload, its predecessor, and one live prepared payload. Resource limits bound each payload and total retained bytes per stream.

### Session-independent recovery discovery

After a crash, the prior ephemeral witness session may be unavailable. `discover_stream` therefore does not require that session. It requires a transport-authenticated challenge signed by the admitted governance key over the stream, exact locally held authority-pair identity, nonce, and witness identity.

The signed witness response returns the exact committed head, the optional unique prepared record, and a fresh recovery-session challenge. Completing the challenge rotates the witness session and revokes the lost session. Mutation operations still require the opaque session; transaction-identifier knowledge is not authority.

### Intent counter and aborts

The witness head has a monotonic intent counter. Prepare reserves exactly `committed_counter + 1`. Commit advances the data head and intent counter. Abort leaves the data epoch, sequence, and payload digests unchanged but advances the intent counter and records the aborted transaction digest as the last intent outcome.

Any operation whose intent counter is not the unique next value is stale. An aborted transaction identifier cannot revive. Retrying the same payload after abort creates a new intent counter and a new transaction identifier without accumulating tombstones.

Commit and abort form one linearizable transition. If commit wins, abort returns `Committed`; if abort wins, commit permanently returns `Aborted` for that intent.

## Bootstrap state machine

Bootstrap runs under the selector, authority-pair, state, and pool guards.

1. Require the canonical stream and fixed namespace to be absent or to match one recognized incomplete-bootstrap state.
2. Create every fixed entry with descriptor-relative no-replace operations and capture pairwise-distinct identities.
3. Construct and sign the binding and complete epoch-0, sequence-0 state/checkpoint payloads.
4. Prepare the full initial candidate against an absent external head. The witness escrows the bytes before returning.
5. Write a durable local `WitnessPrepared` journal record.
6. Populate and fsync the fixed canonical and staging entries through held descriptors; reread exact bytes, signatures, digests, and identities; fsync pool and parent directories.
7. Write and fsync `ReadyForWitnessCommit`.
8. Revalidate the entire namespace and both canonical payloads.
9. Commit the external prepared candidate, resolving a lost response through discovery.
10. Write and fsync local `Committed`, then revalidate before returning.

A crash before the local prepared journal remains discoverable from the witness's unique prepared record and deterministic transaction identifier. A crash after external commit is recoverable from immutable witness escrow. An incomplete bootstrap never silently becomes an ordinary initialized stream.

## Ordinary publication state machine

One state staging inode and one checkpoint staging inode are sufficient because the state lock serializes transactions and lane reuse is forbidden while recovery depends on prior bytes.

1. Validate local signed state/checkpoint, external head, authority-pair guard, binding, complete namespace, pairwise role identities, canonical/staging mappings, and the latest journal record.
2. Build complete next state/checkpoint bytes and the canonical candidate/transaction identifiers.
3. Prepare the successor externally. Resolve a lost response with `read_prepared_for_stream` and exact candidate equality.
4. Durably journal `WitnessPrepared` with the witness receipt, predecessor, candidate, and complete before/after mappings.
5. Rewrite only an inactive staging inode whose current name, identity, signed bytes, and journal role prove it is the governed predecessor and no recovery phase needs it. Write through the held descriptor, fsync, and reread exact bytes.
6. Stage and verify both payloads, then journal `PayloadsStaged`.
7. Immediately precheck the state canonical and staging identities. Atomically exchange their names through held parent/pool descriptors. Postcheck both identities and exact bytes; fsync both directories; journal `StateExchanged`.
8. Perform the same transition for the checkpoint and journal `CheckpointExchanged`.
9. Write and fsync `ReadyForWitnessCommit`, containing complete immutable recovery provenance.
10. Immediately revalidate state/checkpoint bytes, signatures, digests, mappings, parent/pool/lock/binding namespace, journal, and external prepared record.
11. Commit the witness transaction. Resolve an ambiguous response through discovery.
12. Write and fsync `Committed`. Revalidate the external head, both canonicals, both inactive lanes, journal, authority pair, and complete namespace before returning success.

Each exchange is detection, not expected-inode compare-and-swap. It includes immediate prechecks, syscall, postchecks, and directory fsync. If a foreign entry won the seam, reversal is attempted only after exact pre-reversal identity checks and is followed by exact post-reversal checks. Any ambiguity returns `Uncertain`; a successful exchange syscall alone is never semantic success.

## Crash and recovery rules

Recovery uses the external committed/prepared record, local journal phases, and exact canonical/staging mappings. It never selects a candidate by highest sequence alone.

- Before external prepare: canonical predecessor remains authoritative.
- Prepared externally but no local journal: discover the unique prepared record and deterministic transaction identifier; resume or explicitly abort.
- `WitnessPrepared` or `PayloadsStaged`: resume only when the complete before/after bytes and mappings match; otherwise `Uncertain`.
- Exchange completed but phase record absent: infer completion only from the exact prepared payload, predecessor payload, and expected swapped identities; otherwise `Uncertain`.
- `ReadyForWitnessCommit` with witness still prepared: revalidate and commit or abort through the explicit protocol.
- Witness committed but local `Committed` absent: external escrow is authoritative; finish the local journal.
- Witness committed but local bytes are missing, replaced, or corrupt: fetch immutable payloads, preserve conflicting local entries through offline no-replace archive/rebind, reconstruct only into verified fixed lanes, and keep ordinary startup `Uncertain` until repair completes.
- Witness aborted but local journal lags: discover the exact abort outcome, durably write `Aborted`, and require local data digests to match the witness data head before another prepare.
- Equal journal generations, forks, two invalid journal lanes, unknown mappings, or content disagreement return `Uncertain`.

Journal records are self-contained, signed, predecessor-linked, and alternate between two fixed distinct lanes. The previous valid lane remains authoritative while the other is rewritten and fsynced. A lane is never reused while a live transaction or recovery phase depends on it.

## Cleanup retention commit protocol

Every `AuthorityCleanupRetirement` retains its fixed slot name, held slot descriptor, slot identity, pool/lock/parent identities, target component, and signed record-chain head.

Before every record append, content move, recovery decision, and API return, the implementation revalidates the fixed slot name against the held identity and the complete pool binding.

`Retained` is not written immediately after a move. The phases are:

```text
Reserved -> SourceBound -> CandidateCopied -> QuarantineMoved -> ReadyToRetain -> Retained
```

After `ReadyToRetain`, the implementation performs the exact final slot-binding, source-content, canonical-absence, and parent/pool validation. `Retained` is the commit record. Recovery treats it as authoritative only if those invariants still hold.

An exact post-commit test barrier and linearization check follows. If the canonical name or slot binding changed, the implementation appends durable `Uncertain`; recovery gives `Uncertain` precedence over the older `Retained` record. It does not rewrite the terminal claim as `ForeignPreserved`.

No code claims that the canonical name remains absent after the verified linearization point.

## Offline maintenance and reinitialization

Normal startup never drains, resets, silently migrates, or rebinds the fixed pool.

Offline maintenance requires the selector-held quiescence guard and acquires state, authority-pair, and pool locks in the documented nonblocking order. It validates all signed anchors and the exact namespace before mutation.

The maintenance journal binds every selected slot's name, inode identity, content digest, byte length, record-chain head, source identity, destination identity, parent identity, pool identity, archive identity, and before/after mapping.

Every archive move uses held directory descriptors and no-replace operations. Source, destination, pool-name, archive-name, and parent identities are revalidated immediately before and after the move. Source-absent/archive-present resume is accepted only when the authenticated journal proves the exact destination identity and content digest.

Reinitialization is an epoch transition, not a sequence reset. The witness accepts only `epoch + 1` with an authenticated retirement digest of the old head, the quiescence and authority-pair proof, the new binding, and the preserved legacy payload digest. Arbitrary epoch jumps refuse.

Legacy streams without the fixed binding and external witness head refuse ordinary load. Explicit offline migration authenticates the legacy state/checkpoint bytes before normalization and establishes the first witness-backed epoch transition.

A torn, malformed, replaced, or unknown inactive lane is never overwritten by ordinary flow. Offline maintenance archives its bytes and performs a signed witness-backed rebind. This is an intentional fail-closed availability tradeoff.

## Boundedness

Automatic operation uses a constant set of names:

- canonical state and checkpoint names;
- one state staging lane;
- one checkpoint staging lane;
- two journal lanes;
- the fixed cleanup-pool binding and lock;
- the configured fixed cleanup-slot set.

Counter-, process-, timestamp-, transaction-, or random-derived filesystem names are forbidden in ordinary publication and retention.

The witness retains a bounded record count and enforces configured maximum state, checkpoint, binding, and total retained bytes. The fixed cleanup pool has typed exhaustion. A full or uncertain pool refuses before moving a new source.

Operator-owned offline archives have an explicit lifecycle and are not represented as automatically bounded. The runtime creates no fallback archive names after exhaustion.

## Required typed failures

Implementation must expose matchable failures for at least:

- authority-pair or selector-guard mismatch;
- publication namespace changed;
- role identity alias;
- cleanup slot name changed;
- malformed or uncertain lane;
- journal fork or phase ambiguity;
- external witness unavailable, identity mismatch, conflict, prepared, committed, or aborted;
- witness/local head mismatch;
- payload escrow digest mismatch;
- maintenance busy or archive conflict;
- cleanup pool exhausted;
- sequence, epoch, intent, session, journal, or size exhaustion.

Errors that occur after a durable state exchange must distinguish committed, checkpoint-lagging, recoverable-prepared, and uncertain outcomes. Cleanup errors must never be discarded by best-effort wrappers when they affect authority or retained evidence.

## Mandatory adversarial verification

Implementation acceptance requires non-vacuous controls for:

1. parent, pool, pool-lock, binding, slot, canonical, staging, and journal name replacement at every final seam;
2. cross-role hard links and same-inode aliases;
3. same-inode content mutation, signed old-byte replay, partial writes, truncation, and digest change;
4. exchange precheck, postcheck, reversal precheck, reversal postcheck, and directory-fsync failure;
5. crash at every journal, staging, exchange, witness-prepare, witness-commit, abort, and local-commit boundary;
6. lost prepare and commit responses, witness restart/outage, conflicting transaction identifiers, commit/abort races, and recovery-session rotation;
7. external escrow reconstruction after hostile local replacement;
8. bootstrap crash before local journal and after witness commit;
9. epoch transition, arbitrary epoch jump, legacy migration, and coordinated local replay against a newer witness head;
10. fixed pool exhaustion and repeated retries with exact source and namespace preservation;
11. fixed publication-lane reuse over many transactions with a constant name set;
12. maintenance source/archive replacement, source-absent resume, partial move, and unknown namespace entries;
13. exact `ReadyToRetain` and post-`Retained` canonical recreation barriers;
14. every configured byte and counter limit, including permanent checked overflow;
15. mutations that remove the witness, use a local fallback, weaken role distinctness, skip an fsync, select highest sequence alone, or treat an exchange syscall as success.

The final acceptance gate is one frozen commit object: full workspace tests, strict all-target/all-feature clippy, formatting, diff checks, repository assurance gates, mutation controls, detector integration tests, and an independent zero-P0/P1/P2 review of the exact commit and tree.

## Implementation sequencing

1. Remove the counter-derived exchange experiment from the acceptance candidate while retaining its WIP commit for forensic comparison.
2. Implement the versioned protocol types and pure validation/state-transition model with exhaustive transition and mutation tests.
3. Implement the witness trait, adversarial conformance harness, and one production durability-witness adapter. Enforced persistence must refuse without it.
4. Implement fixed-lane descriptor primitives and ordinary publication/recovery.
5. Convert retention to `ReadyToRetain`/`Uncertain` precedence and exact slot-name binding.
6. Convert offline maintenance and reinitialization to witness-backed epochs and authenticated move proofs.
7. Wire the detector selector guard and bounded cleanup handoff without introducing fallback names.
8. Freeze, verify, audit, commit, push, and obtain hosted exact-head evidence before closing Phase 285 or resuming Phase 286.

Phases 287-289 remain parked. The separately reviewed Phase 286 Plan 04 checkpoint remains banked but is not phase advancement.
