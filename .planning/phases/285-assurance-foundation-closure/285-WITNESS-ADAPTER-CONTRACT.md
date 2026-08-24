# Phase 285 External Governance Witness Contract

status: architecture-reviewed
contract_version: 1
protocol_architecture_commit: 5be011a07690a63a297d5bba8fbf740bb659c19d
protocol_code_commit: 27b64174e2c7ceef7c203f357f543e4950e4c27c
implementation_status: not implemented
reviewed_at: 2026-08-24T16:06:22Z
reviewed_content_sha256: f9b7dee9872d566878ad3db89333d9236182d2defb65f7e6c0f5b7fdf3b6d43a
review_verdict: P0=0 P1=0 P2=0

## Decision

The production `GovernanceDurabilityWitness` is a separate
`swarm-governance-witness` process. It owns the witness signing key, validates
governance requests, and signs protocol attestations, but it has no raw
JetStream credential. It reaches a smaller
`swarm-governance-witness-store` process through a private, typed, bounded CAS
service. Only the store process holds the online credential that can publish to
the fixed witness KV subjects, and it has no witness signing key. A separate,
offline init identity may create and freeze the bucket and initialize its fixed
key set but cannot serve either service. The governance runtime reaches only
the public witness process through bounded NATS request/reply messages.

The runtime must not:

- hold the witness signing key;
- receive credentials for the witness-store JetStream account;
- open the witness KV bucket directly;
- manufacture a witness attestation from a KV acknowledgement;
- fall back to a local file, memory store, unsigned response, or permissive
  witness when the service or JetStream is unavailable.

The witness service and JetStream volume are outside the governance runtime's
local filesystem authority. A same-UID process in the runtime pod cannot mount
the NATS volume or read the witness key. The witness is fail-closed, not highly
available by assertion: an unavailable single-replica JetStream installation
denies governed persistence until it recovers.

The trusted computing base is explicit. It includes the exact witness and
store-proxy binaries, the witness signing key, the store proxy's raw KV
credential, authenticated NATS TLS/account/service-import enforcement,
JetStream consensus and file-storage durability, and the deployment authority
that supplies the external epoch and seals the anchor. The contract detects
attacks from the governance runtime, malformed or replayed protocol traffic,
ordinary stream recreation, unsigned KV replacement, and lifecycle drift. It
does not detect a bit-for-bit rollback of the trusted JetStream volume to an earlier valid state
with the same stream creation identity, or a coordinated rollback of both that
volume and the external Kubernetes objects by the deployment authority. Such a
restore is a TCB violation and requires an explicit offline epoch transition;
no in-scope component may present it as ordinary recovery. Per-mutation
rollback detection would require an independent non-rollbackable external
head, which is deliberately deferred with external App enforcement.

## Blocking protocol correction

The accepted protocol-code checkpoint cannot be connected to a production
adapter unchanged. `RecoveryChallengeV1` has a governance-signed random nonce,
but no monotonic session generation or witness-issued state fence. After a
later session rotation, replaying an older valid challenge can rotate authority
back to the older ephemeral session unless the service stores every historical
nonce. An unbounded nonce set violates the retention contract.

Implementation must first add a bounded two-round rotation fence:

```text
governance                        witness
    |                                |
    |-- signed fence request ------->|
    |<-- signed current-state fence--|
    |                                |
    |-- signed recovery challenge -->|  CAS exact fenced state -> new session
    |<-- signed session/discovery ---|
```

The first request is signed by the admitted governance key and contains the
complete admitted namespace plus a fresh requester nonce. The witness response
is signed by the pinned witness key and binds:

- the exact fence request;
- the current witness-store state digest;
- the optional current session generation and session digest;
- the optional current data-head digest and prepared-record digest;
- a fresh witness nonce;
- the witness identity and admission digest.

`RecoveryChallengeV1` must contain that complete verified fence and bind it in
its governance signature together with the new ephemeral key ID and secret
commitment. A first-time establishment or discovery may rotate only when the
current store state exactly equals the fence. It advances the checked session
generation by one in the same CAS that stores the new session.

The store retains one `WitnessSessionRotationReceiptV1`: the digest of the
complete accepted service request and recovery challenge, the resulting
session, the response kind, and the exact unsigned session/discovery response
snapshot at the rotation linearization point. The service-request digest binds
`expected_head` for establishment. This receipt is replaced, not appended, at
the next rotation. An exact retry is recognized before fence-state comparison
by both digests and the matching current session. The witness recreates the
same deterministic signed response from the retained snapshot even if a
prepare, commit, or abort changed the data head after rotation. A different
request or challenge against the consumed fence is stale. Once another
rotation commits, every older challenge is stale.

If a live prepared record exists, the rotation CAS reissues its
`session_generation` to the checked new session generation before constructing
the retained discovery snapshot. Candidate, transaction, predecessor, and
payload fields do not change. This keeps session-independent recovery compatible
with the protocol invariant that a discovered prepared record and recovery
session have the same generation.

No timestamp, process-local cache, TTL, random-nonce history, or transport
connection identity substitutes for the durable generation fence and single
bounded rotation receipt.

The witness trait therefore gains one read-only operation conceptually named
`issue_session_fence`. The conformance harness must prove that two and one
hundred intervening rotations both reject replay of the first challenge, while
an exact retry of the immediately committed rotation returns the same response
before and after a later data-head mutation.

## Authority topology

Production uses three NATS accounts:

| Account | Principal | Permitted authority |
|---|---|---|
| runtime | `swarm-detect` | publish imported witness request subjects, receive replies, and use only runtime-owned JetStream subjects such as pheromone state |
| witness | `swarm-governance-witness` | subscribe to public witness subjects, import/call only the typed store service, and sign protocol/store values; no raw JetStream subjects or management API |
| witness-store | `swarm-governance-witness-store` | subscribe to the private typed store subjects, inspect the fixed bucket, and issue header-fixed nonzero-revision PUT CAS for admitted keys; no witness signing key or public witness subjects |
| witness-store | one-shot init identity | create and freeze the exact witness stream, revision-zero initialize the fixed manifest/key set, emit the external anchor with one-shot signer access, and serve no request subjects |

The witness account exports only the public request/reply service, which the
runtime account imports. The witness-store account exports only the private
typed store service, which only the witness account imports. Raw JetStream API
and `$KV` subjects are never exported. JetStream API subjects are account-
scoped: the runtime credential may use `$JS.API.>` for the runtime account's
Pheromone KV bucket, but the witness bucket and underlying stream exist only in
the witness-store account. Runtime access to Pheromone must continue to pass
while raw witness-bucket access through either runtime or public-witness
credentials fails. A public-witness or store-proxy credential cannot publish
telemetry or call runtime control subjects.

The rendered NATS configuration contains explicit `runtime`, `witness`, and
`witness-store` accounts; distinct users/credentials; two one-way service
exports and their single authorized imports; account-local JetStream limits;
and deny-by-default publish/subscribe permissions. A shared account with
subject-only conventions does not satisfy this contract.

The generated per-user allowlists are exact:

- runtime publishes only the nine imported public request subjects and its
  runtime-owned telemetry/JetStream subjects, subscribes only to its inbox and
  runtime-owned subjects, and has no import from `witness-store`;
- public witness subscribes only to the nine public service subjects and its
  private-store reply inbox, publishes only the three imported typed-store
  subjects, and uses bounded NATS `allow_responses` for replies to requests it
  actually received; `$KV.>` and `$JS.API.>` are explicitly denied;
- online store proxy subscribes only to the three private store subjects and
  its JetStream reply inbox, publishes only the admission-derived exact
  `$KV.<bucket>.s.<digest>` subjects plus the exact stream-info/raw-get API
  requests, and uses bounded `allow_responses`; it cannot publish the manifest
  subject or any stream create/update/delete/purge API;
- init publishes only the exact stream create/update/info/raw-get requests and
  exact manifest/admitted-key subjects required by init, subscribes only to its
  reply inbox, has no `allow_responses`, and cannot publish or subscribe to
  either request service.

No witness-side user receives a `$KV.>` or `$JS.API.>` wildcard. All dynamic
reply permission is server-issued, single-response, and deadline-bounded after
receipt of an allowed request; a client-supplied reply subject does not widen
ordinary publish authority.

Every production NATS connection uses `tls://`, validates a mounted pinned CA
and exact server name, and rejects plaintext, an untrusted chain, an expired
certificate, name mismatch, and any insecure-skip-verification option. Client
credentials remain account-specific. Plaintext loopback is allowed only inside
the isolated local conformance harness and cannot satisfy deployment
acceptance.

The Helm deployment creates separate public-witness and store-proxy
`Deployment`/`ServiceAccount` pairs, disjoint secret mounts, and container
security contexts. Neither mounts the runtime state PVC. The runtime deployment
does not mount any witness secret. The public witness mounts the signing key and
private-store client credential but no raw KV credential. The store proxy
mounts the raw KV credential and pinned witness public key but no signing key.
All may connect to the same NATS server because account isolation, not the
server pathname, is the security boundary.

Bucket identity is anchored outside JetStream. Before one-time init, the
operator supplies a read-only canonical `WitnessBucketEpochV1` with a random
256-bit generation; its `nats_account` is exactly `witness-store`. After the
Ready CAS, init emits a signed `WitnessBucketAnchorV1`; the operator seals that
exact object in a separate
read-only Kubernetes Secret before enabling either serving Deployment. Neither
epoch nor anchor is stored only in, or writable through, the witness-store NATS
account. Both serving containers mount them read-only and have
`automountServiceAccountToken: false`; neither mounts an init credential.

The init Job is the only pod that temporarily mounts both the witness signing
key and the init NATS credential. It also sets
`automountServiceAccountToken: false`; its ServiceAccount cannot read or mutate
Kubernetes Secrets, call either request service, or launch workloads. The init
NATS user cannot subscribe to public/private service subjects. The public
witness and store-proxy Deployments remain scaled to zero until the Ready state
and byte-exact anchor are sealed. Before either Deployment is enabled, the init
Job must be gone, its NATS user disabled, its credential Secret deleted, and a
cluster query must prove that no live pod mounts that credential. A failed init
or lost pre-seal anchor leaves the credential enabled only for the explicit
retry window; it never starts serving. Later reinitialization requires an
audited offline transition that stops both serving Deployments and deliberately
issues a new short-lived init credential.

Deployment is two-stage. The bootstrap render contains the disabled serving
workloads, init user/Secret/Job, and no unsealed anchor. The accepted serving
render contains the sealed anchor and serving users, removes the init user from
the reloaded NATS account configuration, and contains no init Secret or Job.
Ordinary Helm reconciliation uses only the serving render, so it cannot
recreate init authority. Both rendered digests and the transition evidence are
retained.

Each binary mode has a closed, deny-unknown-fields configuration variant. It
requires every applicable item below and rejects credentials or key paths owned
by another mode; a combined superset configuration is invalid. Production
startup refuses unless the role-appropriate values are explicit:

- witness identity;
- witness public key ID;
- role-specific witness signing-key, pinned public-key, external epoch/anchor,
  public-service, private-store-client, raw-store, and init credential paths;
- governance admission-manifest path;
- role-specific `tls://` NATS URL, credentials path, pinned CA path, and exact
  TLS server name;
- public and private service subject prefixes;
- KV bucket name;
- maximum admitted streams;
- state, checkpoint, binding, request, response, per-stream retained, KV value,
  store-proxy request/response, and bucket byte limits;
- CAS retry limit and request deadline;
- required KV history, storage class, and replica count;
- subscription, client-command, initial read-buffer, ingress-queue, and maximum
  in-flight request capacities;
- NATS server `max_payload`, fixed NATS header-overhead budget, and fixed
  JetStream entry-overhead budget.
- exact supported NATS server semantic version and OCI image-index digest;
  neither a floating tag nor a version range is accepted.

There are no production defaults for an identity, key path, credential path,
bucket, or admission manifest.

## Admission contract

The service loads a bounded `WitnessAdmissionSetV1` before subscribing. Each
entry contains:

- stream ID;
- governance signer public key and derived key ID;
- witness identity and pinned witness key ID;
- publication-binding generation and digest;
- authority-pair identity;
- maximum state, checkpoint, binding, request, response, and retained bytes;
- permitted initial epoch, sequence, and intent counter;
- an optional predecessor admission digest for an offline epoch transition.

The deployment authority supplies the same admission set through read-only
configuration mounts to the public witness, store proxy, and init Job. Each
checks canonical encoding, duplicate stream IDs, duplicate active authority
bindings, key-ID derivation, and all bounds. The public witness and init mode
also check the mounted signing key against the witness identity/key; the store
proxy has only the pinned public key and independently verifies every signed
request and proposed store envelope.

An arbitrary valid Ed25519 key cannot self-register a stream. The first fence,
session establishment, discovery, and initial prepare all have to match one
admission entry exactly. Changing the signer, witness, binding generation,
binding digest, authority pair, or stream requires the explicit offline epoch
transition protocol; it is never inferred from a client request.

## Wire and transport

All request and response DTOs are versioned structs with
`#[serde(deny_unknown_fields)]`. Encoding uses `canonical_wire_bytes`; decoding
must reproduce the exact input bytes. Every string, collection, and aggregate
size is checked before allocation or business validation.

The session-fence repair freezes these concrete wire values:

Unless an optional/container/type is written explicitly below,
`schema_version` is `u32`, generations/revisions/counters are `u64`,
`retryable` is `bool`, protocol object fields use the named `...V1` type,
`signature` is `DetachedSignature`, and identifiers/digests/nonces are bounded
canonical `String` values. `stream_keys` is `Vec<String>` and every displayed
map is a `BTreeMap<String, T>`. `nats_stream_created_at` is a canonical UTC
RFC3339 string with exactly nine fractional-second digits and `Z`; decoding and
re-encoding must preserve its exact bytes.

`bucket_generation` is the sole exception to the generic generation rule. It
is a canonical `String` containing exactly 64 lowercase hexadecimal characters
that encode 32 independently random bytes. It is not a `u64`, decimal string,
UUID, truncated digest, or server revision.

```text
WitnessSessionFenceRequestV1 {
  schema_version,
  stream_id,
  authority_pair,
  binding_generation,
  binding_digest,
  signer_key_id,
  witness_key_id,
  witness_identity,
  requester_nonce,
  signature
}

WitnessSessionStateFenceV1 {
  schema_version,
  request,
  admission_digest,
  bucket_epoch_digest,
  bucket_anchor_digest,
  ready_manifest_digest,
  store_state_digest,
  current_session_generation: Option<u64>,
  current_session_digest: Option<String>,
  current_head_digest: Option<String>,
  current_prepared_digest: Option<String>,
  witness_nonce,
  witness_identity,
  witness_key_id,
  signature
}

WitnessSessionRotationReceiptV1 {
  schema_version,
  accepted_request_digest,
  accepted_challenge_digest,
  response_kind: WitnessSessionRotationResponseKindV1,
  session,
  establish_snapshot: Option<WitnessEstablishSnapshotV1>,
  discovery_snapshot: Option<WitnessDiscoveryV1>
}

WitnessEstablishSnapshotV1 {
  schema_version,
  committed_head: Option<WitnessHeadV1>,
  external_marker
}

WitnessSessionRotationResponseKindV1 = Establish | Discover

WitnessBucketManifestV1 {
  schema_version,
  bucket_epoch_digest,
  bucket_configuration_digest,
  admission_set_digest,
  stream_keys,
  initialized_streams: BTreeMap<key, WitnessStreamInitializationRecordV1>,
  phase: Initializing | Ready,
  witness_identity,
  witness_key_id,
  signature
}

WitnessStreamInitializationRecordV1 {
  schema_version,
  stream_initialization_digest,
  empty_envelope_digest
}

WitnessStreamInitializationV1 {
  schema_version,
  bucket_epoch_digest,
  admission_digest,
  stream_id,
  witness_identity,
  witness_key_id
}

WitnessBucketConfigurationV1 {
  schema_version: u32,
  nats_server_version: String,
  nats_server_image_index_digest: String,
  stream_name: String,
  description: String,
  subjects: Vec<String>,
  retention: WitnessRetentionPolicyV1,
  discard: WitnessDiscardPolicyV1,
  discard_new_per_subject: bool,
  storage: WitnessStorageTypeV1,
  max_messages: i64,
  max_bytes: i64,
  max_messages_per_subject: i64,
  max_age_nanos: u64,
  max_consumers: i32,
  max_message_size: i32,
  num_replicas: u32,
  no_ack: bool,
  duplicate_window_nanos: u64,
  persistence_semantics: WitnessPersistenceSemanticsV1,
  persist_mode_wire_key_present: bool,
  sealed: bool,
  allow_rollup: bool,
  deny_delete: bool,
  deny_purge: bool,
  allow_direct: bool,
  mirror_direct: bool,
  allow_message_ttl: bool,
  allow_atomic_publish: bool,
  allow_message_schedules: bool,
  allow_message_counter: bool,
  template_owner: String,
  application_metadata: BTreeMap<String, String>,
  server_metadata: BTreeMap<String, String>,
  republish_present: bool,
  mirror_present: bool,
  sources_count: u64,
  subject_transform_present: bool,
  compression: WitnessCompressionV1,
  consumer_limits_present: bool,
  first_sequence: Option<u64>,
  placement_present: bool,
  pause_until: Option<String>,
  subject_delete_marker_ttl_nanos: Option<u64>
}

WitnessRetentionPolicyV1 = Limits | Interest | WorkQueue
WitnessDiscardPolicyV1 = Old | New
WitnessStorageTypeV1 = File | Memory
WitnessPersistenceSemanticsV1 = Nats21117SynchronousOnly
WitnessCompressionV1 = Disabled | S2

WitnessBucketEpochV1 {
  schema_version,
  bucket_generation,
  nats_account,
  stream_name,
  bucket_configuration_digest,
  admission_set_digest,
  witness_identity,
  witness_key_id
}

WitnessBucketAnchorV1 {
  schema_version,
  epoch,
  nats_stream_created_at,
  raw_stream_configuration_digest,
  ready_manifest_digest,
  witness_key_id,
  signature
}

RecoveryChallengeV1 {
  schema_version,
  stream_id,
  authority_pair,
  binding_generation,
  binding_digest,
  signer_key_id,
  witness_key_id,
  witness_identity,
  state_fence,
  ephemeral_key_id,
  nonce,
  session_commitment,
  signature
}

WitnessServiceRequestV1 {
  schema_version,
  operation: WitnessServiceOperationV1,
  request_nonce,
  admission_digest,
  body: WitnessServiceRequestBodyV1,
  request_digest,
  authorization: Option<WitnessSessionAuthorizationV1>
}

WitnessServiceRequestBodyV1 =
  Fence { request }
  | Establish { challenge, expected_head }
  | Discover { challenge }
  | Prepare { session, expected_head, candidate }
  | Commit { session, txid }
  | Abort { session, txid }
  | ReadPrepared { session, target_txid }
  | ReadHead { session, target_txid }
  | FetchPayload { session, txid }

WitnessServiceFailureAttestationV1 {
  schema_version,
  operation,
  request_digest,
  stream_id,
  admission_digest,
  witness_identity,
  witness_key_id,
  store_state_digest: Option<String>,
  failure_code: WitnessServiceFailureCodeV1,
  retryable,
  signature
}

WitnessStoreProxyOperationV1 = InspectReady | ReadEntry | CompareAndSwap

WitnessStoreProxyRequestV1 {
  schema_version,
  operation: WitnessStoreProxyOperationV1,
  request_nonce,
  admission_digest,
  bucket_epoch_digest,
  bucket_anchor_digest,
  body: WitnessStoreProxyRequestBodyV1,
  request_digest,
  witness_key_id,
  signature
}

WitnessStoreProxyRequestBodyV1 =
  InspectReady
  | ReadEntry { stream_id }
  | CompareAndSwap {
      stream_id,
      expected_revision: u64,
      expected_store_state_digest,
      proposed_envelope: WitnessStoreEnvelopeV1
    }

WitnessStoreProxyResponseV1 {
  schema_version,
  operation: WitnessStoreProxyOperationV1,
  request_digest,
  body: WitnessStoreProxyResponseBodyV1
}

WitnessStoreProxyResponseBodyV1 =
  Ready {
    nats_stream_created_at,
    bucket_configuration_digest,
    ready_manifest: WitnessBucketManifestV1,
    validated_streams:
      BTreeMap<stream_id, WitnessStoreProxyValidatedEntryV1>
  }
  | Entry {
      stream_id,
      revision: u64,
      envelope: WitnessStoreEnvelopeV1
    }
  | CasApplied {
      stream_id,
      previous_revision: u64,
      new_revision: u64,
      acknowledged_value_digest
    }
  | Conflict {
      stream_id,
      observed_revision: u64,
      observed_envelope: WitnessStoreEnvelopeV1
    }
  | Refused {
      failure_code: WitnessStoreProxyFailureCodeV1,
      observed_revision: Option<u64>,
      observed_value_digest: Option<String>
    }

WitnessStoreProxyValidatedEntryV1 {
  schema_version,
  revision: u64,
  store_state_digest,
  stream_initialization_digest
}
```

Exactly one response snapshot matches `response_kind`. The receipt is inside
the signed store envelope and has no independent signature. Optional values are
encoded by canonical JSON as the literal `null`; there are no magic zero,
empty-string, or all-zero-digest sentinels.

For `Establish`, `establish_snapshot` is present and `discovery_snapshot` is
null. For `Discover`, the inverse holds and
`discovery_snapshot.recovery_session == session`. A store with no current
session fences both session fields as null and rotates to generation 1.
Generation 0 is the durable absent-session baseline and is never emitted as a
live session. A present generation `g` rotates only to
`checked_next_session(g)`.

Signing preimages contain every field above in declaration order except the
outer `signature`. New fence-request, state-fence, store-envelope,
bucket-manifest, bucket-anchor, store-proxy-request, and service-failure
signatures sign
`domain || u64_be(canonical_preimage_length) || canonical_preimage` under their
fixed domain below. The repaired `RecoveryChallengeV1` uses the rotation-
challenge domain. The fence request is signed by `signer_key_id`; the state
fence, bucket anchor, store-proxy request, and every public witness response are
signed by `witness_key_id`. Store-proxy responses are not governance
attestations and rely on the authenticated private service import. The
bucket epoch is canonical operator input mounted outside NATS; its digest, not a
self-contained KV value, is the bootstrap authority. All nested signatures and
key-ID derivations are verified before a digest is accepted.

`WitnessServiceOperationV1` has exactly the nine fixed subject operations. The
request body variant must match it. `request_digest` covers a canonical preimage
containing schema version, operation, request nonce, admission digest, and body;
it excludes `request_digest` and `authorization`. Fence, establish, and
discover require `authorization = null`; every other variant requires one
authorization whose operation, stream, txid, and request digest match the body.
Failure codes are a closed enum corresponding to the typed failures in this
contract. `retryable` is derived from the code, not accepted as independent
client input.

`WitnessStoreProxyOperationV1` has exactly the three variants above, and its
body must match the operation. The proxy request digest covers every field
except `request_digest` and `signature`; the public witness signs the complete
request digest under the store-proxy-request domain. The proxy verifies that
signature, the pinned witness key, external epoch/anchor, admission, fixed
stream-to-key mapping, and all sizes before touching JetStream. There is no
wire field for a NATS subject, header, KV operation marker, raw key, or revision
zero. `CompareAndSwap.expected_revision` must be nonzero. The proxy response is
transport-authenticated by pinned TLS and the private account import, binds the request digest,
and confers no governance authority; the public witness still validates the
acknowledged revision/value through a subsequent proxy read before signing an
external attestation. `WitnessStoreProxyFailureCodeV1` is a closed enum for the
missing/corrupt/header/configuration/admission/signature/bounds/conflict and
internal-unavailable cases in this contract; the response body is never a
client-chosen error string.

The fixed domain constants are:

```text
swarm.governance.witness-fence-request.v1
swarm.governance.witness-state-fence.v1
swarm.governance.witness-session-state.v1
swarm.governance.witness-prepared-state.v1
swarm.governance.witness-rotation-challenge.v1
swarm.governance.witness-rotation-receipt.v1
swarm.governance.witness-external-marker.v1
swarm.governance.witness-store.v1
swarm.governance.witness-store-signed.v1
swarm.governance.witness-bucket-manifest.v1
swarm.governance.witness-bucket-epoch.v1
swarm.governance.witness-bucket-anchor.v1
swarm.governance.witness-stream-initialization.v1
swarm.governance.witness-admission.v1
swarm.governance.witness-service-request.v1
swarm.governance.witness-service-failure.v1
swarm.governance.witness-store-proxy-request.v1
```

Each digest is `digest_domain(domain, canonical_bytes)`. Fence-request and
state-fence digests cover the complete signed value, including its detached
signature. `accepted_challenge_digest` covers the complete validated
`RecoveryChallengeV1`, including its nested state fence and both signatures.
`store_state_digest` covers the `WitnessStoreEnvelopeV1` signing preimage and
therefore excludes only the outer store signature. The optional session digest
covers canonical `WitnessSessionV1`; the optional prepared digest covers
canonical `WitnessPreparedV1`; the head uses its existing `head_digest`.
`WitnessEstablishSnapshotV1.external_marker` is the digest of a canonical
preimage containing the accepted challenge digest, resulting session digest,
and `Establish` response kind under the external-marker domain. It is computed
before CAS, retained in the receipt, and signed only after CAS acknowledgement;
it does not contain the KV revision or its own digest.

`bucket_epoch_digest` covers the complete canonical `WitnessBucketEpochV1`.
`ready_manifest_digest` covers the complete signed Ready manifest.
`bucket_anchor_digest` covers the complete signed `WitnessBucketAnchorV1`.
Every fence requires `bucket_epoch_digest` to match both the external epoch and
the stream envelope, `ready_manifest_digest` to match both the Ready manifest
and external anchor, and `bucket_anchor_digest` to match the external anchor.
The anchor's `nats_stream_created_at` must equal the current server-reported
stream creation time. A recreated stream therefore cannot accept a replayed
old manifest/envelope set under the old external anchor.

`stream_initialization_digest` covers canonical
`WitnessStreamInitializationV1`. `empty_envelope_digest` uses the store-signed
domain over the complete validated signed empty envelope. The ordinary
`store_state_digest` continues to use the store domain over the signing
preimage, excluding only the outer store signature.

`RecoveryChallengeV1` and its signing preimage use the exact declaration order
above. Fence-free bytes are rejected as a missing required field; there is no
legacy dual decoder because the accepted checkpoint has not shipped a witness
adapter.

The exact trait addition is:

```text
async fn issue_session_fence(
    &self,
    request: WitnessSessionFenceRequestV1,
) -> Result<WitnessSessionStateFenceV1, Self::Error>;
```

`WitnessSessionAuthorizationV1` gains a public server-side
`verify_for_session_record` validator taking the stored `WitnessSessionV1`,
operation, txid, and request digest. Service code must not reproduce those
comparisons ad hoc.

The subject set is fixed and contains no raw user string:

```text
swarm.governance.witness.v1.fence
swarm.governance.witness.v1.establish
swarm.governance.witness.v1.discover
swarm.governance.witness.v1.prepare
swarm.governance.witness.v1.commit
swarm.governance.witness.v1.abort
swarm.governance.witness.v1.read_prepared
swarm.governance.witness.v1.read_head
swarm.governance.witness.v1.fetch_payload

swarm.governance.witness.store.v1.inspect_ready
swarm.governance.witness.store.v1.read_entry
swarm.governance.witness.store.v1.compare_and_swap
```

The first nine subjects are exported only from `witness` to `runtime`. The last
three are exported only from `witness-store` to `witness`. The stream ID is
inside the signed canonical request, not interpolated into a subject. Each
process uses queue subscriptions for its exact subjects and rejects wildcard
operation dispatch. A runtime credential cannot address the private store
subjects, and a public-witness credential cannot address raw `$KV` or JetStream
API subjects.

Both NATS clients set explicit bounded subscription, command, and read-buffer
capacities. Each service admits work through its own fixed semaphore and
bounded queue. A full public queue returns overload without spawning a task or
calling the store proxy; a full private queue returns an internal unavailable
result without opening the KV store. Request size is checked from the NATS
payload length before JSON decoding. No request path creates an unbounded
channel, task set, retry set, response map, or per-stream mutex map.

Each message contains exactly one operation-specific body and a common envelope
with schema version, operation, request nonce, request digest, and admission
digest. `request_digest` is the domain-separated digest of the canonical body
excluding itself and the NATS reply subject. Mutation and session-bound read
bodies include the public `WitnessSessionV1` plus the exact
`WitnessSessionAuthorizationV1`. The service validates the authorization
against the stored current session and recomputes the request digest before any
read or state transition.

Every successful response is one of the signed protocol attestations already
validated by the governance crate. Every decoded, admission-bound application
rejection is a signed, canonical `WitnessServiceFailureAttestationV1` bound to
the request digest, operation, stream, admission, witness key, and current
store-state digest. Oversize, framing, pre-admission overload, transport, and
timeout failures remain adapter errors and confer no authority; the server may
drop them without producing a witness signature.

The client uses one bounded deadline for request publication and response. A
timeout is `OutcomeUnknown`, never success. The caller resolves mutation
ambiguity through the fenced discovery/read protocol. The adapter does not
retry a mutation under a new request digest or session automatically.

NATS `max_payload` must exceed the largest public envelope, private store-proxy
envelope, or KV publish including its fixed headers. Configuration arithmetic
is checked and non-wrapping. Both services refuse when the server or bucket
limits are smaller than the admitted protocol limits.

The concrete configuration conversion rules are:

```text
max_kv_value_bytes = max(max_store_envelope_bytes, max_manifest_bytes)
max_kv_value_bytes <= i32::MAX

jetstream_entry_overhead_budget_bytes = 65_536
nats_header_overhead_budget_bytes = 4_096
required_bucket_bytes =
    2 * (max_manifest_bytes + jetstream_entry_overhead_budget_bytes)
    + maximum_admitted_streams
      * 2 * (max_store_envelope_bytes + jetstream_entry_overhead_budget_bytes)
required_bucket_bytes <= i64::MAX

nats_max_payload_bytes >= max(
    max_public_request_bytes,
    max_public_response_bytes,
    max_store_proxy_request_bytes,
    max_store_proxy_response_bytes,
    max_store_envelope_bytes + nats_header_overhead_budget_bytes,
    max_manifest_bytes + nats_header_overhead_budget_bytes
)
```

`WitnessBucketConfigurationV1` is the single canonical digest preimage for the
bucket configuration. The epoch's `bucket_configuration_digest` is the
domain-separated SHA-256 of its canonical bytes. Init constructs the
underlying `async_nats::jetstream::stream::Config` only from this object; init,
the online proxy, and `InspectReady` decode the raw authoritative server JSON
through a 2.11.17-specific, deny-unknown-fields DTO and project it into this
object. They require the resulting canonical bytes to equal the epoch-bound
object before using any entry. The projection covers every raw field, including
false, zero, empty, and absent values. It does not rely on async-nats silently
discarding unknown response fields. A newly introduced server field or client
mapping is a refusal until the supported-version projection is deliberately
updated and independently reviewed.

Contract version 1 has this exact semantic configuration:

```text
nats_server_version = "2.11.17"
nats_server_image_index_digest =
  "sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00"
stream_name = "KV_" + bucket_name
description = "Phase 285 external governance witness"
subjects = ["$KV." + bucket_name + ".>"]
retention = Limits
discard = New
discard_new_per_subject = false
storage = File
max_messages = -1
max_bytes = required_bucket_bytes
max_messages_per_subject = 1
max_age_nanos = 0
max_consumers = -1
max_message_size = max_kv_value_bytes
num_replicas = configured_replica_count
no_ack = false
duplicate_window_nanos = 120_000_000_000
persistence_semantics = Nats21117SynchronousOnly
persist_mode_wire_key_present = false
sealed = false
allow_rollup = false
deny_delete = true
deny_purge = true
allow_direct = false
mirror_direct = false
allow_message_ttl = false
allow_atomic_publish = false
allow_message_schedules = false
allow_message_counter = false
template_owner = ""
application_metadata = {}
server_metadata = {
  "_nats.level": "1",
  "_nats.req.level": "0",
  "_nats.ver": "2.11.17"
}
republish_present = false
mirror_present = false
sources_count = 0
subject_transform_present = false
compression = Disabled
consumer_limits_present = false
first_sequence = None
placement_present = false
pause_until = None
subject_delete_marker_ttl_nanos = None
```

The normalization table for the exact pinned server is closed:

- raw `persist_mode` must be absent in both the init request and every raw
  create/info response; its semantic projection is
  `Nats21117SynchronousOnly`;
- raw `compression: "none"` projects to `Disabled`;
- the raw metadata map must contain exactly the three `server_metadata` entries
  and values above; they are not application metadata and no other `_nats.*`
  or application key is ignored;
- fields introduced by NATS 2.12 are accepted only when their 2.11.17 response
  representation is absent and project to the explicit false/`None` values
  above; a present unknown raw key refuses.

The allowed raw response `config` key set is also exact: `name`, `description`,
`subjects`, `retention`, `max_consumers`, `max_msgs`, `max_bytes`, `max_age`,
`max_msgs_per_subject`, `max_msg_size`, `discard`, `storage`, `num_replicas`,
`duplicate_window`, `compression`, `allow_direct`, `mirror_direct`, `sealed`,
`deny_delete`, `deny_purge`, `allow_rollup_hdrs`, `consumer_limits`,
`allow_msg_ttl`, and `metadata`. The first create response and every later info
response must contain exactly that set for this configuration.
`consumer_limits` must be the empty object and projects to
`consumer_limits_present = false`. Raw fields whose false/empty value is
omitted by the 2.11.17 schema (`no_ack`, `discard_new_per_subject`,
`template_owner`, `placement`, `mirror`, `sources`, `first_seq`,
`subject_transform`, `republish`, and `subject_delete_marker_ttl`) must remain
absent and project to their explicit semantic false/empty/`None` value. The
canonical raw-config bytes and their domain-separated digest are retained in
the sealed anchor as `raw_stream_configuration_digest`; startup recomputes that
digest before semantic projection. Thus a normalizer bug cannot make two
different observable raw configurations share one accepted anchor.

This is a version property, not a generic interpretation of an omitted field.
NATS 2.11.17's `StreamConfig` schema has no persistence-mode field and its file
store acknowledges under the synchronous default; even a raw request carrying
`persist_mode: "async"` is ignored and omitted from the response. The init
request therefore omits that unsupported key, the byte-exact request builder
accepts no caller-supplied extra field, and no serving identity has stream
update authority. A server version that implements asynchronous persistence is
outside contract version 1 and fails the exact version/image gate. Changing the
pinned binary or granting a management principal after init is a TCB violation,
not configuration drift this server can report. `no_ack = true`, non-`Limits`
retention, or any other normalized-field mismatch remains a permanent refusal.
Creating a KV bucket and checking only the KV-level history/storage/TTL facade
is insufficient.

All repository harnesses and production manifests use exactly
`docker.io/library/nats:2.11.17-alpine@sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00`.
The client compares `Client::server_info().version` byte-for-byte with
`2.11.17` before init or either serving process may inspect the stream. The
Helm/render checker and container harness independently inspect the resolved
OCI image ID and require the index digest above. A tag without a digest,
`2.11`, `2-alpine`, a later patch/minor, or a reported-version/image-digest
mismatch refuses acceptance. This pin deliberately excludes NATS 2.12.0,
whose server-side expected-last-subject-sequence implementation regressed to a
global stream-sequence comparison. An upgrade is a reviewed contract change
with the complete conformance lane rerun, not an automatic tag refresh.

All additions, multiplications, and conversions are checked through `u64`
before converting to async-nats' `i32` `max_value_size`, `i64` `max_bytes`,
`usize` channel capacities, or `u16` initial read-buffer capacity. Every queue
capacity and maximum in-flight value is nonzero and at most `u32::MAX` before
`usize` conversion. The factor of two reserves the old and proposed value
during a revision update; `history = 1` still makes only the new value durable
after acknowledgement. The 4,096-byte NATS header budget covers the fixed
`KV-Operation: PUT`, expected-stream, expected-last-subject-sequence, and
protocol headers. The
65,536-byte per-entry budget covers subject, headers, and JetStream storage
metadata. Integration tests measure both the maximum wire message and actual
stream bytes at the maximum configured value and prove neither reserved bound
is exceeded. A platform that needs a larger measured overhead must increase the
explicit budget and bucket size; it cannot reduce payload retention.

## Stored state

Each admitted stream maps to one KV key:

```text
s.<lowercase SHA-256 of domain || canonical stream ID>
```

No client controls a key token. The KV value is one canonical,
witness-signed `WitnessStoreEnvelopeV1` containing:

```text
schema_version
admission_digest
bucket_epoch_digest
stream_initialization_digest
stream_id
witness_identity
witness_key_id
session: optional WitnessSessionV1
last_session_rotation: optional WitnessSessionRotationReceiptV1
current: optional { complete CandidatePreimageV1, settled WitnessHeadV1 }
predecessor: optional { complete CandidatePreimageV1, settled WitnessHeadV1 }
prepared: optional { complete CandidatePreimageV1, WitnessPreparedV1 }
genesis_abort: optional WitnessGenesisAbortedV1
store_generation
signature
```

The envelope validator recomputes every payload digest, candidate digest,
transaction ID, head digest, data-head digest, namespace field, publication
mapping, size, and transition relation. It proves these cardinality rules:

- zero or one current committed payload;
- zero or one predecessor committed payload;
- zero or one live prepared payload;
- predecessor is the immediate payload predecessor of current;
- prepared is the unique immediate successor of current, or the valid genesis
  successor when current is absent;
- genesis abort is present only when current, predecessor, and prepared are
  absent;
- the stored session and last rotation receipt are singular and bounded;
- no terminal-history or nonce collection exists.

Every initialization, rotation, prepare, commit, abort, and read requires the
envelope `bucket_epoch_digest` to equal the external epoch and anchor. It also
requires `stream_initialization_digest` to match the key's immutable Ready-
manifest record. Every proposed transition preserves both exactly. The Ready
manifest record additionally retains the exact full signed empty-envelope
digest used during init. Later envelope generations are linked by the preserved
initialization digest, witness signature, monotonic store generation, and
revision CAS; they are not written back into the immutable manifest.

`store_generation` is checked and monotonic but is not the JetStream CAS token.
The typed proxy request carries the KV entry `revision` as the expected-last-
revision value. `store_generation` advances by exactly one. The acknowledged
JetStream revision must equal the raw stored message sequence returned by the
CAS and be strictly greater than the observed revision; it need not equal
`observed_revision + 1` because writes to other stream keys share the global
sequence. Neither value is an external high-water mark: rolling the trusted
JetStream volume back to an earlier internally consistent snapshot rolls both
back and is outside the guarantee as stated in the TCB boundary above.

The public witness never opens a KV handle. The store proxy reads with one
private `read_put_entry` primitive over the leader-mediated
`Stream::get_last_raw_message_by_subject` API and exposes only `InspectReady`,
`ReadEntry`, and `CompareAndSwap`. For CAS it requires a nonzero observed
revision, rereads and
fully validates the current signed envelope, verifies the signed proxy request
and complete proposed one-step transition, then calls one private
`publish_put_cas` primitive. That primitive derives the fixed subject itself and
sets exactly `KV-Operation: PUT`, `Nats-Expected-Stream: KV_<bucket>`, and
`Nats-Expected-Last-Subject-Sequence: <observed_revision>`; callers cannot pass
subjects or headers. `read_put_entry` requires the exact fixed subject and
stream, one exact `KV-Operation: PUT`, one parseable expected-subject-sequence
header smaller than the raw message sequence, no rollup/TTL/message-ID header,
canonical bytes, and the witness signature; absent, DEL, PURGE,
unknown, duplicate, or conflicting operation headers are permanent typed
refusals. Plain `Store::create`, `Store::put`,
`Store::delete`, `Store::purge`, rollup, watch-derived authority, revision zero,
and last-write-wins retry are absent from the online proxy API and binary.

NATS subject ACLs cannot distinguish PUT from DEL headers on the same `$KV`
subject. The raw store-proxy credential and proxy binary are therefore an
explicit small TCB, not a falsely claimed header-level ACL. The public witness
credential cannot publish any raw KV message. The online store-proxy NATS user
can publish only the exact admitted stream-key subjects, not the manifest or a
wildcard, and the proxy accepts only witness-signed typed requests. A raw
store-proxy-credential compromise cannot forge new witness signatures, but it
can delete or replay an older signed value and therefore can violate
availability or rollback integrity. That credential and the small proxy binary
are full TCB components; the security gain is that neither the network-facing
public witness nor the governance runtime holds them.

The bucket has `allow_direct = false`. `async-nats` 0.47 creates KV streams with
direct reads enabled by default; that default is not acceptable because a
replica may serve a stale value that the witness would then sign as current.
After initialization and on every startup, only the leader-mediated raw-message
path above may supply authority. A stream handle whose cached configuration
still enables direct reads is rejected before serving. `Store::entry` is not an
authority primitive because async-nats maps an unknown KV operation header to
`Put`.

On a wrong-revision result, the public service asks the proxy to reload, fully
validates, and reevaluates the original request. It may return the matching idempotent outcome,
a typed conflict/stale result, or attempt another exact CAS. The retry count is
fixed. Exhaustion returns signed `Contention`; it never reports the proposed
state as durable.

The production store proxy opens an existing bucket and verifies its full
stream configuration. It does not silently create or repair it. A separate
`swarm-governance-witness-store init` command, using the one-shot initialization
credential and signer access described above, creates the bucket once with:

- the complete canonical `WitnessBucketConfigurationV1` above, including file
  storage, `history = 1`, `retention = Limits`, `discard = New`,
  `no_ack = false`, `Nats21117SynchronousOnly`, and an absent raw
  `persist_mode` key;
- `allow_direct = false`, `deny_delete = true`, `deny_purge = true`, and
  `allow_rollup = false`, applied to and reread from the underlying stream
  after KV creation;
- no additional raw KV writer principal and no delete, purge, rollup, generic
  put, or create call in the online proxy binary;
- exact `max_value_size` and `max_bytes`;
- no TTL;
- exact configured replica count;
- no mirror, sources, republish, or placement drift.

After freezing the stream configuration, init creates a fixed
`__witness_bucket_manifest` key containing a canonical, witness-signed
`WitnessBucketManifestV1` with the init-only form of `publish_put_cas`, setting
exactly `KV-Operation: PUT` and expected-last-subject-sequence zero. The
manifest binds the external bucket-epoch digest, bucket configuration,
admission set, sorted exact stream-key set, an initially empty per-key progress
map, and phase `Initializing`. `Store::create` is forbidden even in init because
async-nats 0.47 deliberately recreates Delete/Purge tombstones.

For each sorted stream key, init computes the deterministic empty envelope,
stream-initialization digest, and full signed empty-envelope digest. It then:

1. requires every key already listed in manifest progress to be an exact
   explicit-PUT entry whose bytes and both digests match exactly;
2. for an unlisted key, accepts only `None` or the exact expected Put bytes from
   a crash between key CAS and manifest CAS; Delete, Purge, different bytes, or
   any unexpected key refuses the entire init;
3. creates a truly absent key only with the same explicit-PUT, expected-
   revision-zero primitive, so any intervening history/tombstone makes the CAS
   fail;
4. revision-CASes the manifest to add that key's
   `WitnessStreamInitializationRecordV1` before continuing.

After rereading and validating the complete exact key set and progress map,
init revision-CASes the manifest to `Ready`. It queries the authoritative NATS
stream information through the closed raw 2.11.17 DTO, constructs the anchor
with the server-reported creation time, raw-stream-configuration digest, and
complete signed Ready-manifest digest, signs it, and emits it for the operator
to seal outside NATS. Anchor construction contains no fresh nonce or wall-clock
input, so Ed25519 signing of the same canonical Ready state produces the same
anchor bytes.

An interrupted init may resume only from a valid `Initializing` manifest under
the exact external epoch and rules above. If the Ready CAS committed but the
process died before publishing the anchor, an init invocation against the
complete exact `Ready` manifest may perform no KV mutation and only revalidate
the stream configuration, creation time, key set, and manifest before emitting
the byte-identical anchor again. A `Ready` manifest makes the key set and
initialization records immutable. Init and serving both refuse a missing,
deleted, purged, extra, or malformed stream key and never recreate it. An
existing bucket without its manifest is not an uninitialized bucket.

Store-proxy startup requires all of the following before it subscribes: a valid
external epoch and sealed anchor, exact server-reported stream creation time,
exact pinned server version, exact canonical bucket-configuration projection,
exact anchor-bound raw-stream-configuration digest, exact
configuration/admission/Ready-manifest digests, `manifest.phase ==
Ready`, complete key/progress equality, no init credential, and the serving raw
credential restricted to exact admitted stream-key publish subjects plus
required read APIs but no manifest publish or stream-management API. `Initializing` is
an unconditional refusal even when all stream keys happen to exist. The public
witness starts only after a signed `InspectReady` request obtains a matching
private response and independently verifies its Ready manifest and every
reported entry. The Helm lifecycle enables neither serving Deployment until
init has exited, the anchor Secret is sealed, and init authority is revoked.

`InspectReady` enumerates the exact `$KV.<bucket>.>` subject set through
`Stream::info_with_subjects`, not a watch or consumer. It rejects before
collection when the iterator's public initial
`info.state.subjects_count` exceeds one manifest plus the maximum admitted
streams. It snapshots that initial subject count, message count, first/last
sequence, creation time, raw-configuration digest, and complete projected
configuration; bounds each
yield and the cumulative item count to the same limit; rejects duplicate
subjects; and requires the yielded item count to equal the initial advertised
subject count. Every yielded count must be exactly one and the complete set
must equal the manifest key plus admission-derived stream keys. After iterator
exhaustion it performs a fresh leader-mediated `Stream::get_info` and requires
the subject count, message count, first/last sequence, creation time, and
complete raw-configuration digest and projected configuration to equal the
initial snapshot and sealed anchor before it
raw-reads and validates each entry. A short iterator, duplicate, changed
snapshot, extra subject, wildcard, cumulative overflow, or pagination error is
a startup refusal.

This check intentionally does not claim access to the private
`async_nats::jetstream::stream::PagedInfo.total` field: async-nats 0.47 uses it
internally but does not expose it. Completeness is instead established with the
public initial advertised count, a bounded/deduplicated yielded set, and an
unchanged authoritative post-enumeration snapshot. The conformance lane must
mutate each of those checks independently.

The init command, store proxy, and public witness are different binary modes or
processes with disjoint runtime credentials. Any configuration or lifecycle
mismatch is a refusal. A recreated bucket has a different server-reported
creation time and remains permanently
refused under the old external anchor. Recreating or rebinding the bucket
requires an explicit offline operator epoch transition and a separately audited
state migration; replaying an old signed manifest and envelopes cannot perform
that transition.

## Session and authorization semantics

Fence issuance is read-only and governance-signer authenticated. It does not
create a session and cannot authorize mutation.

Session establishment and discovery:

1. validate the admission, both nested signatures, both nonces, namespace, and
   every bound digest;
2. load and validate the signed store envelope;
3. compute the complete service-request and accepted-challenge digests and first
   compare both with the stored last rotation receipt;
4. when both digests, response kind, and current session match, regenerate the
   exact signed response from the retained snapshot without comparing the old
   fence to the now-current data head; a changed establishment `expected_head`
   necessarily has a different service-request digest;
5. otherwise require exact equality with the witness-issued state fence;
6. derive `checked_next_session(current_generation)`;
7. reissue any live prepared record to that exact session generation without
   changing candidate semantics;
8. construct the new `WitnessSessionV1`, exact response snapshot, and
   `WitnessSessionRotationReceiptV1`, then store them in one revision CAS;
9. sign the response only from the CAS-confirmed receipt and state.

An exact retry after a lost response therefore returns the same attestation for
the already current session even when a subsequent prepare, commit, or abort
changed the data head. A different challenge against the same consumed fence is
stale. A challenge from any earlier generation is stale even if every signature
is valid. Session generation exhaustion is permanent and causes no prepared
record or store mutation.

Every session-bound operation requires all of:

- exact stored session generation and commitment;
- exact ephemeral public key ID;
- a valid `WitnessSessionAuthorizationV1` signature;
- matching operation, stream, binding digest, txid, and request digest;
- current admission and witness identity.

Discovery rotates and revokes the prior session. Reads do not rotate. A signed
attestation, request digest, transaction ID, NATS credential, or witness reply
subject is not a mutation capability.

## Candidate validation and transitions

The service reuses the pure governance protocol validators but owns a separate
`WitnessCandidateVerifier` entry point. It must not call a client-provided
boolean or trust fields merely because the client already constructed
`CandidateV1`.

Before `Prepared`, the service independently verifies:

- canonical complete state and checkpoint bytes;
- state and checkpoint detached signatures and admitted signer key;
- exact publication-binding equality and binding digest;
- state/checkpoint lengths and SHA-256 digests;
- candidate and transaction identifier derivation;
- exact predecessor head and data-head digest;
- epoch, sequence, intent, binding, authority, and mapping transition;
- pairwise-distinct publication roles;
- all admission and retained-byte bounds;
- current session authorization and unique next intent.

Prepare stores the complete candidate payload before returning `Prepared`. The
same txid and candidate digest is idempotent. A different live successor is
`Conflict`. An old or skipped intent is `StaleIntent`.

Commit and abort are one revision-CAS race:

- commit moves prepared to current, current to predecessor, discards the older
  predecessor, clears prepared, and writes the committed last-intent outcome;
- abort clears prepared, preserves current and predecessor payloads, advances
  the intent counter, and writes the aborted last-intent outcome;
- a genesis abort retains the bounded genesis-abort receipt and no payload;
- the losing operation returns the authenticated winning outcome when it is
  still the current last intent;
- a retry older than the bounded last outcome returns `StaleIntent`, not a
  fabricated terminal receipt.

The public witness signs a protocol response only after the proxy verifies that
the publish acknowledgement names the exact configured stream, is not a
deduplicate acknowledgement, and returns a new revision greater than the
observed revision, then a confirming proxy read returns that exact raw message
sequence, byte-identical value, and expected-subject-sequence header equal to
the observed revision. The proposed store
envelope and typed proxy request are necessarily signed before CAS, but neither
is an external success attestation. A publish future, proposed envelope, proxy
request signature, or raw acknowledgement is not durability.

Reads return only current, predecessor, or live prepared escrow. Fetching an
older transaction returns a signed absence. The service never consults local
governance files.

## Retention and resource bounds

For each stream, automatic retention is exactly:

- one current committed candidate payload;
- one immediate predecessor candidate payload;
- one live prepared candidate payload;
- one current session and one bounded rotation receipt containing a single
  accepted-request digest, accepted-challenge digest, and response snapshot;
- one bounded last-intent outcome embedded in the current head, or one genesis
  abort receipt.

There are no vectors for sessions, nonces, terminal outcomes, attempts,
requests, failures, or audit logs in the authoritative value. Operational logs
must be size- and retention-managed by the platform and are not recovery
authority.

The public witness and store proxy independently validate the serialized
proposed envelope before CAS and refuse before mutation if any individual or
aggregate limit is exceeded. The KV bucket
`max_bytes` is derived from checked multiplication of maximum admitted streams,
per-stream value bytes, and required history. Capacity exhaustion is a typed
failure. It cannot evict an authoritative key because the bucket uses discard
new semantics.

## Failure model

Matchable failures include:

- unavailable, timeout, no responder, disconnected, and protocol framing;
- noncanonical, unsupported version, unknown operation, and bounds;
- admission missing/mismatch and signer/witness identity mismatch;
- invalid governance, ephemeral-session, witness, or store signature;
- stale rotation fence, stale session, stale intent, and checked exhaustion;
- expected-head, prepared, commit/abort, and CAS conflict;
- corrupt, unsigned, oversized, missing, deleted, or purged store entry;
- invalid store-proxy signature/body pairing, zero revision, non-PUT or
  conflicting lifecycle header, and private-service authentication failure;
- KV bucket absent or configuration drift;
- durability acknowledgement mismatch and contention exhaustion.

After an unavailable or ambiguous mutation, no caller may downgrade to a local
success path. The only recovery is a new fenced discovery followed by exact
attestation verification and the local transaction resolver.

A trusted-volume snapshot rollback is not a matchable runtime failure because
the rolled-back bytes remain internally valid. Operations and evidence must not
classify it as detected; it is prevented operationally by the explicit TCB and
offline epoch-transition boundary.

## Adversarial conformance harness

The harness is generic over an atomic store and transport. The same suite runs
against:

1. an in-memory revision-CAS store with deterministic fault injection;
2. the typed store proxy over that in-memory store;
3. the typed store proxy and JetStream under `tools/with-nats-jetstream.sh`;
4. the complete runtime-client, public-witness, private-store-proxy, and
   JetStream request/reply path.

The JetStream lane is explicitly ignored in ordinary unit execution only so it
can be selected by the wrapper. The acceptance command must prove every named
test executed at least once; a missing server, zero-test filter, skip, or
ignored result fails the lane.

Required controls include:

1. one-time manifest and per-admission empty-envelope initialization, interrupted
   init resume, and refusal to initialize or serve a ready bucket with a missing
   key;
2. startup during `Initializing` refuses; listed progress with a missing or
   changed key refuses; unlisted DEL/PURGE/unknown-operation headers refuse; the
   explicit-PUT revision-zero initializer cannot resurrect a tombstone;
3. crash after the Ready CAS but before anchor publication, and after anchor
   publication but before sealing, permits only byte-identical mutation-free
   anchor re-emission from the exact Ready state;
4. a recreated bucket populated with an old signed manifest and old signed
   envelopes is rejected by external epoch/anchor and stream-creation binding;
   a one-field mutation of every `WitnessBucketConfigurationV1` field changes
   its digest and makes init/startup refuse;
5. the acceptance artifact states that a bit-for-bit trusted-volume rollback or
   coordinated external-anchor rollback is outside the guarantee, and a claim
   mutation asserting such detection makes the truthfulness checker fail;
6. init is the only identity that can create/manage the stream and the only pod
   that temporarily mounts signer plus init credential; it cannot call either
   service, no serving pod mounts its credential, and serving remains disabled
   until the Job is gone, its NATS user disabled, and its Secret deleted;
7. runtime credentials retain Pheromone JetStream read/write while runtime and
   public-witness credentials cannot see or publish to the raw witness
   bucket/API; only the public witness can call the private typed store import;
   plaintext, wrong-CA, wrong-name, expired, and skip-verification connections
   fail before either service subscribes;
8. proxy DTOs reject a raw subject, header, operation marker, wildcard key, or
   revision zero, and an exact request-body/operation/signature mutation is
   rejected before a JetStream read;
9. an exact 2.11.17 raw create/info golden fixture proves the closed projection:
   `retention = Limits`, `no_ack = false`, synchronous-only version semantics,
   absent `persist_mode`, raw `compression: "none"`, exact three-entry reserved
   metadata, `allow_rollup = false`, `deny_delete = true`, and
   `deny_purge = true`; a response containing `persist_mode`, an unknown field,
   changed reserved metadata, or any isolated configuration mutation refuses
   before service subscription; a request-body mutant adding
   `persist_mode: "async"` is rejected locally even though the pinned server's
   permissive decoder would ignore it; isolated writers publishing DEL, PURGE,
   an unknown operation, missing PUT, wrong expected stream/revision, a message
   ID, or plain put through the raw proxy credential never produce a signed
   success and make `read_put_entry` refuse the fixture;
10. two concurrent prepares for one predecessor;
11. commit/commit, abort/abort, and commit/abort races with one linearizable
   winner;
12. lost response before send, after service decision, between proxy CAS and
   confirming proxy read, after KV acknowledgement, and after response
   publication;
13. public-witness and store-proxy restart before and after each CAS;
14. JetStream restart with current, predecessor, prepared, abort, and genesis
   abort states; for each state, kill NATS immediately after the publish
   acknowledgement and before the proxy's confirming read, restart the exact
   pinned image, and require the acknowledged raw sequence and bytes to remain
   authoritative; a truthfulness mutant claiming that 2.11.17 reports or
   supports a selectable async persistence mode must fail acceptance;
15. wrong KV revision and bounded CAS exhaustion; cross-key interleaving proves
    the acknowledged global revision may jump while the per-envelope
    `store_generation` advances exactly one; on the exact pinned NATS image,
    create key A, perform at least ten A updates, create key B, and then update
    B with expected-last-subject-sequence equal to B's first global sequence;
    the B update must succeed and a server implementation that compares that
    header to the global stream tail must fail the lane;
16. direct-read configuration enabled at initialization or startup is rejected,
   and a stale-replica read cannot produce a signed response;
17. current, predecessor, and prepared payload corruption;
18. signer, witness key, admission, binding, authority pair, mapping, head,
   digest, size, epoch, sequence, intent, and txid mutation;
19. unsigned direct KV replacement detected by the store-envelope signature;
20. a forced missing, DEL, PURGE, unknown-operation, or malformed key and
    full-stream-purge-then-restart are detected and never recreated by init,
    proxy, or public witness;
    subject enumeration independently rejects an understated initial
    `subjects_count`, a short iterator, a cross-page duplicate, cumulative
    overflow, and any initial/final subject-count, message-count, sequence,
    creation-time, or configuration change without consulting private paged
    totals;
21. current-session authorization replayed after one and one hundred rotations;
22. first recovery challenge replayed after one and one hundred rotations;
23. exact rotation retry after lost response remains byte-identical before and
    after a later prepare, commit, and abort; a different nonce/signature against
    the same fence is stale;
24. an establish retry changing only `expected_head` is stale and cannot receive
    the retained response for the original request;
25. concurrent exact and conflicting challenges against one fence produce one
    session, exact retry, and stale conflict without nonce retention;
26. fence issued before a head, prepared, session, manifest, epoch, or anchor
    change becomes stale;
27. prepare at generation N, lose the session, rotate to N+1, discover the
    reissued prepared record, then commit and abort in separate controls;
28. stale generation/commitment and session-generation `u64::MAX` rotation are
    rejected with byte-identical store state;
29. challenge signed by an unadmitted but cryptographically valid key rejected;
30. old binding generation and arbitrary epoch jump rejected;
31. reads for current, predecessor, prepared, aborted, and evicted txids;
32. every byte, collection, counter, stream-count, KV-value, bucket, NATS
    overhead budget, async-nats integer conversion, queue capacity, and NATS
    payload boundary at maximum and maximum plus one;
33. more transactions than the retention window with constant key count and
    bounded value size;
34. either service absent, NATS absent, wrong credentials, wrong account,
    unauthenticated transport, and misconfigured bucket all refuse without
    local fallback; the container lane also rejects a floating image tag, an
    OCI digest other than the contract digest, a server version other than
    exact `2.11.17`, or a version/digest mismatch;
35. mutations removing witness/proxy-request verification, replacing the typed
    CAS with plain put or `Store::create`, changing any fixed CAS header,
    retaining nonce history, signing before the confirming proxy read,
    accepting raw KV acknowledgements, or giving runtime/public-witness
    credentials direct bucket access.

The harness must compare the implementation against a small deterministic
reference transition model. Mutation controls have to demonstrate red-first
failure against the weakened implementation and green behavior after repair.

## Deployment acceptance

The deployment checkpoint is incomplete until it proves:

- Helm renders distinct runtime, public-witness, store-proxy, and one-shot-init
  identities with disjoint secret mounts and three NATS accounts;
- both serving pods mount the exact external bucket epoch and sealed anchor
  read-only, have no init credential or Kubernetes API token, and refuse an
  `Initializing` manifest;
- the runtime pod has no witness key or witness-account credentials;
- the public-witness pod has the signer and private-store client credential but
  no raw KV credential; the store-proxy pod has the raw KV credential and
  pinned public key but no signer; neither has the runtime state PVC;
- runtime cannot address the private typed store service or witness KV/API;
  public witness can address only the typed store import, never raw KV/API;
- the init Job alone temporarily mounts signer plus init credential, cannot call
  either service, and no serving workload starts until the Job is gone, its
  NATS user is disabled, its credential Secret is deleted, and live-pod mount
  inspection is empty;
- the bootstrap render contains init authority and disabled serving workloads,
  while the accepted serving render contains the sealed anchor and no init
  user, Secret, or Job; reconciling the accepted release cannot recreate init
  authority;
- both imported request services work end to end and no unauthorized import or
  wildcard subject works;
- rendered production clients require `tls://`, the mounted pinned CA, and the
  exact server name; plaintext and insecure verification settings fail the
  rendered-manifest and live negative controls;
- production refuses an absent or drifted bucket instead of creating it;
- every NATS manifest and harness resolves exact
  `docker.io/library/nats:2.11.17-alpine@sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00`,
  runtime server INFO reports exact `2.11.17`, and no `2-alpine`, `2.11-alpine`,
  version range, or tag-only image remains in an acceptance path;
- the explicit init Job creates and rereads the complete canonical
  `WitnessBucketConfigurationV1`, including `retention = Limits`,
  `no_ack = false`, `Nats21117SynchronousOnly`, absent raw `persist_mode`,
  `allow_direct = false`, `allow_rollup = false`, `deny_delete = true`, and
  `deny_purge = true`;
- a recreated stream with replayed old signed KV contents fails the external
  epoch/anchor and server-reported creation-time check;
- the evidence statement and machine checker explicitly scope trusted-volume
  or coordinated external-anchor rollback outside the guarantee, and no normal
  restore automation can roll the NATS volume backward without the audited
  offline epoch-transition procedure;
- killing/restarting the public witness, store proxy, and NATS processes
  preserves the accepted current/predecessor/prepared states;
- enforced governance startup and mutation refuse when the witness dependency
  is absent, untrusted, or unavailable.

The final proof records the exact image reference and independently inspected
resolved index digest, NATS server version, canonical bucket-configuration
bytes and digest, canonical raw server-configuration bytes and anchor-bound
digest, bootstrap- and serving-render digests, transition evidence, admission
digest, witness public-key ID, test identities, commit, and tree.
Secrets and credentials are never included.

## Checkpoint sequence

No checkpoint mixes with the dirty integration tree. Each starts from the last
accepted immutable object and is independently audited before the next begins:

1. session-fence protocol repair and red-first replay controls;
2. pure witness engine, signed store envelope, reference model, and in-memory
   conformance harness;
3. typed CAS proxy, header-exact JetStream repository, and non-skipping
   persistence conformance;
4. public NATS request/reply adapter and witness service binary;
5. three-account isolation, Helm witness/proxy deployment, one-shot bucket init,
   init-authority revocation, and deployment controls;
6. enforced governance injection with no local fallback;
7. frozen combined Phase 285 validation and hostile exact-object review.

Phase 286 remains banked but blocked. Phases 287-289 remain parked until the
frozen combined Phase 285 gate is accepted.
