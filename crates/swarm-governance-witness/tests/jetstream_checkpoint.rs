use async_nats::header::{NATS_EXPECTED_LAST_SUBJECT_SEQUENCE, NATS_EXPECTED_STREAM};
use async_nats::jetstream::response::Response;
use async_nats::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::{env, error::Error, io};
use swarm_crypto::{DetachedSignature, Ed25519Signer, sha256_hex};
use swarm_governance::persistence_protocol::*;
use swarm_governance::witness_engine::store::{
    WitnessAdmissionEntryV1, WitnessAdmissionSetV1, WitnessAtomicStore, WitnessBucketAnchorV1,
    WitnessBucketConfigurationV1, WitnessBucketEpochV1, WitnessBucketManifestPhaseV1,
    WitnessBucketManifestV1, WitnessCompressionV1, WitnessDiscardPolicyV1,
    WitnessPersistenceSemanticsV1, WitnessRetentionPolicyV1, WitnessStorageTypeV1,
    WitnessStoreCasResultV1, WitnessStoreDeploymentInputsV1, WitnessStoreErrorV1,
    WitnessStreamInitializationRecordV1, WitnessStreamInitializationV1, validate_read_entry,
};
use swarm_governance::witness_engine::{
    WitnessStoreEnvelopeV1, WitnessStoreExpectationV1, WitnessStoreTransitionV1,
    WitnessStoredCandidateV1, WitnessStoredPreparedV1, validate_store_transition,
    witness_stream_key,
};
use swarm_governance::witness_service::WitnessAdmissionRecordV1;
use swarm_governance_witness::NatsWitnessStore;
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn fixture_protocol<T, E: std::fmt::Debug>(
    step: &'static str,
    result: Result<T, E>,
) -> Result<T, io::Error> {
    result.map_err(|error| io::Error::other(format!("{step}: {error:?}")))
}

const NATS_VERSION: &str = "2.11.17";
const NATS_IMAGE: &str = "sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00";
const NATS_PINNED_IMAGE: &str = "docker.io/library/nats:2.11.17-alpine@sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00";
const RAW_CONFIG_DOMAIN: &[u8] = b"swarm.governance.nats-2.11.17-raw-stream-configuration.v1";
const MANIFEST_KEY: &str = "__witness_bucket_manifest";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawConfigDigestFixture {
    name: Value,
    description: Value,
    subjects: Value,
    retention: Value,
    max_consumers: Value,
    max_msgs: Value,
    max_bytes: Value,
    max_age: Value,
    max_msgs_per_subject: Value,
    max_msg_size: Value,
    discard: Value,
    storage: Value,
    num_replicas: Value,
    duplicate_window: Value,
    compression: Value,
    allow_direct: Value,
    mirror_direct: Value,
    sealed: Value,
    deny_delete: Value,
    deny_purge: Value,
    allow_rollup_hdrs: Value,
    consumer_limits: Value,
    allow_msg_ttl: Value,
    metadata: Value,
}

#[derive(Clone, Copy)]
enum InitialHeader {
    Put,
}

struct LiveFixture {
    context: async_nats::jetstream::Context,
    ready: swarm_governance::witness_engine::store::WitnessStoreReadyResultV1,
    stream_id: String,
    current: WitnessStoreEnvelopeV1,
    proposed: WitnessStoreEnvelopeV1,
    initial_revision: u64,
    subject: String,
}

fn roles() -> PublicationRoleIdentitiesV1 {
    PublicationRoleIdentitiesV1 {
        state_canonical: ArtifactIdentityV1 {
            device: 2,
            inode: 1,
        },
        state_staging: ArtifactIdentityV1 {
            device: 2,
            inode: 2,
        },
        checkpoint_canonical: ArtifactIdentityV1 {
            device: 2,
            inode: 3,
        },
        checkpoint_staging: ArtifactIdentityV1 {
            device: 2,
            inode: 4,
        },
        journal_primary: ArtifactIdentityV1 {
            device: 2,
            inode: 5,
        },
        journal_secondary: ArtifactIdentityV1 {
            device: 2,
            inode: 6,
        },
    }
}

fn binding(
    governance: &Ed25519Signer,
    witness: &Ed25519Signer,
    stream_id: &str,
) -> ProtocolResult<PublicationBindingV1> {
    let mut value = PublicationBindingV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: stream_id.to_string(),
        generation: "9".repeat(64),
        parent_directory: ArtifactIdentityV1 {
            device: 2,
            inode: 7,
        },
        pool_directory: ArtifactIdentityV1 {
            device: 2,
            inode: 8,
        },
        pool_lock: ArtifactIdentityV1 {
            device: 2,
            inode: 9,
        },
        binding_file: ArtifactIdentityV1 {
            device: 2,
            inode: 10,
        },
        authority_pair: AuthorityPairIdentityV1 {
            current: ArtifactIdentityV1 {
                device: 1,
                inode: 1,
            },
            legacy: ArtifactIdentityV1 {
                device: 1,
                inode: 1,
            },
        },
        publication_roles: roles(),
        cleanup_slot_count: FIXED_CLEANUP_SLOT_COUNT as u32,
        cleanup_slot_names: (0..FIXED_CLEANUP_SLOT_COUNT)
            .map(|index| format!("slot-{index:02}"))
            .collect(),
        cleanup_slot_identities: (11..(11 + FIXED_CLEANUP_SLOT_COUNT as u64))
            .map(|inode| ArtifactIdentityV1 { device: 2, inode })
            .collect(),
        limits: ProtocolLimitsV1::default(),
        signer_key_id: governance.key_id().to_string(),
        witness_key_id: witness.key_id().to_string(),
        witness_identity: "phase285-witness".to_string(),
        binding_digest: "0".repeat(64),
        binding_signature: governance.sign(&[]),
    };
    let signing_bytes = value.signing_bytes()?;
    value.binding_digest = value.computed_digest()?;
    value.binding_signature = governance.sign(&signing_bytes);
    value.validate()?;
    Ok(value)
}

fn initial_mapping(roles: PublicationRoleIdentitiesV1) -> PublicationMappingV1 {
    PublicationMappingV1 {
        state_canonical: roles.state_canonical,
        state_staging: roles.state_staging,
        checkpoint_canonical: roles.checkpoint_canonical,
        checkpoint_staging: roles.checkpoint_staging,
        journal_primary: roles.journal_primary,
        journal_secondary: roles.journal_secondary,
    }
}

fn sign_payload(
    signer: &Ed25519Signer,
    domain: &str,
    binding: &PublicationBindingV1,
    payload: Vec<u8>,
    digest: String,
) -> ProtocolResult<DetachedSignature> {
    let preimage = SignedPayloadPreimageV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        domain: domain.to_string(),
        stream_id: binding.stream_id.clone(),
        binding_generation: binding.generation.clone(),
        binding_digest: binding.binding_digest.clone(),
        authority_pair: binding.authority_pair,
        byte_len: payload.len() as u64,
        digest,
        payload,
    };
    Ok(signer.sign(&preimage.canonical_bytes()?))
}

fn checkpoint_candidate(
    governance: &Ed25519Signer,
    binding: &PublicationBindingV1,
    predecessor: Option<&WitnessHeadV1>,
) -> ProtocolResult<CandidatePreimageV1> {
    let publication_mapping_before = predecessor.map_or_else(
        || initial_mapping(binding.publication_roles),
        |head| head.publication_mapping,
    );
    let (predecessor_head_digest, predecessor_data_head_digest, epoch, sequence, intent_counter) =
        if let Some(head) = predecessor {
            (
                head.head_digest()?,
                head.data_head_digest()?,
                head.epoch,
                head.sequence
                    .checked_add(1)
                    .ok_or(ProtocolError::Overflow {
                        counter: "checkpoint_sequence",
                    })?,
                head.intent_counter
                    .checked_add(1)
                    .ok_or(ProtocolError::Overflow {
                        counter: "checkpoint_intent",
                    })?,
            )
        } else {
            let genesis = GenesisPredecessorV1::for_binding(binding);
            (genesis.digest()?, genesis.data_head_digest()?, 0, 0, 1)
        };
    let state_payload = serde_json::to_vec(&json!({"state": intent_counter}))
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
    let checkpoint_payload = serde_json::to_vec(&json!({"checkpoint": intent_counter}))
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
    let state_digest = sha256_hex(&state_payload);
    let checkpoint_digest = sha256_hex(&checkpoint_payload);
    let value = CandidatePreimageV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: binding.stream_id.clone(),
        predecessor_head: predecessor.cloned(),
        predecessor_head_digest,
        predecessor_data_head_digest,
        state_payload: state_payload.clone(),
        state_byte_len: state_payload.len() as u64,
        state_digest: state_digest.clone(),
        state_attestation: sign_payload(
            governance,
            STATE_PAYLOAD_DOMAIN_V1,
            binding,
            state_payload,
            state_digest,
        )?,
        checkpoint_payload: checkpoint_payload.clone(),
        checkpoint_byte_len: checkpoint_payload.len() as u64,
        checkpoint_digest: checkpoint_digest.clone(),
        checkpoint_attestation: sign_payload(
            governance,
            CHECKPOINT_PAYLOAD_DOMAIN_V1,
            binding,
            checkpoint_payload,
            checkpoint_digest,
        )?,
        publication_binding: binding.clone(),
        publication_mapping_before,
        publication_mapping_after: PublicationMappingV1 {
            state_canonical: publication_mapping_before.state_staging,
            state_staging: publication_mapping_before.state_canonical,
            checkpoint_canonical: publication_mapping_before.checkpoint_staging,
            checkpoint_staging: publication_mapping_before.checkpoint_canonical,
            journal_primary: publication_mapping_before.journal_primary,
            journal_secondary: publication_mapping_before.journal_secondary,
        },
        epoch,
        sequence,
        intent_counter,
    };
    value.validate()?;
    Ok(value)
}

fn sign_envelope(
    mut envelope: WitnessStoreEnvelopeV1,
    witness: &Ed25519Signer,
) -> ProtocolResult<WitnessStoreEnvelopeV1> {
    envelope.signature = witness.sign(&envelope.signing_bytes()?);
    envelope.validate()?;
    Ok(envelope)
}

fn prepared_envelope(
    previous: &WitnessStoreEnvelopeV1,
    candidate: CandidatePreimageV1,
    witness: &Ed25519Signer,
) -> ProtocolResult<WitnessStoreEnvelopeV1> {
    let session_generation = previous
        .session
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .session_generation;
    let built = candidate.build()?;
    let prepared = WitnessPreparedV1::from_candidate(
        &built,
        previous.current.as_ref().map(|value| value.head.clone()),
        session_generation,
    )?;
    let mut proposed = previous.clone();
    proposed.prepared = Some(WitnessStoredPreparedV1 {
        candidate,
        prepared,
    });
    proposed.genesis_abort = None;
    proposed.store_generation =
        previous
            .store_generation
            .checked_add(1)
            .ok_or(ProtocolError::Overflow {
                counter: "checkpoint_store_generation",
            })?;
    sign_envelope(proposed, witness)
}

fn committed_envelope(
    previous: &WitnessStoreEnvelopeV1,
    witness: &Ed25519Signer,
) -> ProtocolResult<WitnessStoreEnvelopeV1> {
    let prepared = previous
        .prepared
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    let built = prepared.candidate.build()?;
    let mut proposed = previous.clone();
    proposed.predecessor = previous.current.clone();
    proposed.current = Some(WitnessStoredCandidateV1 {
        candidate: prepared.candidate.clone(),
        head: WitnessHeadV1::committed_from_candidate(&built)?,
    });
    proposed.prepared = None;
    proposed.store_generation =
        previous
            .store_generation
            .checked_add(1)
            .ok_or(ProtocolError::Overflow {
                counter: "checkpoint_store_generation",
            })?;
    sign_envelope(proposed, witness)
}

fn aborted_envelope(
    previous: &WitnessStoreEnvelopeV1,
    witness: &Ed25519Signer,
) -> ProtocolResult<WitnessStoreEnvelopeV1> {
    let prepared = previous
        .prepared
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    let mut proposed = previous.clone();
    proposed.prepared = None;
    if let Some(current) = &previous.current {
        let mut head = current.head.clone();
        head.intent_counter = prepared.prepared.head.intent_counter;
        head.last_intent_outcome = Some(WitnessIntentOutcomeV1::Aborted(Box::new(
            WitnessAbortSummaryV1 {
                txid: prepared.prepared.head.txid.clone(),
                candidate_digest: prepared.prepared.head.candidate_digest.clone(),
                predecessor_head_digest: prepared.prepared.predecessor_head_digest.clone(),
                epoch: prepared.prepared.head.epoch,
                sequence: prepared.prepared.head.sequence,
                intent_counter: prepared.prepared.head.intent_counter,
                binding_generation: prepared.prepared.head.binding_generation.clone(),
                binding_digest: prepared.prepared.head.binding_digest.clone(),
                signer_key_id: prepared.prepared.head.signer_key_id.clone(),
                witness_key_id: prepared.prepared.head.witness_key_id.clone(),
                authority_pair: prepared.prepared.head.authority_pair,
                publication_mapping: prepared.prepared.predecessor_publication_mapping,
                resulting_data_head_digest: current.head.data_head_digest()?,
            },
        )));
        proposed.current = Some(WitnessStoredCandidateV1 {
            candidate: current.candidate.clone(),
            head,
        });
        proposed.genesis_abort = None;
    } else {
        proposed.genesis_abort = Some(WitnessGenesisAbortedV1::from_prepared(
            &prepared.prepared,
            "phase285-checkpoint-genesis-abort".to_string(),
        )?);
    }
    proposed.store_generation =
        previous
            .store_generation
            .checked_add(1)
            .ok_or(ProtocolError::Overflow {
                counter: "checkpoint_store_generation",
            })?;
    sign_envelope(proposed, witness)
}

fn session_rotation(
    governance: &Ed25519Signer,
    witness: &Ed25519Signer,
    binding: &PublicationBindingV1,
    envelope: &WitnessStoreEnvelopeV1,
) -> ProtocolResult<WitnessStoreEnvelopeV1> {
    let mut fence_request = WitnessSessionFenceRequestV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: binding.stream_id.clone(),
        authority_pair: binding.authority_pair,
        binding_generation: binding.generation.clone(),
        binding_digest: binding.binding_digest.clone(),
        signer_key_id: binding.signer_key_id.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        witness_identity: binding.witness_identity.clone(),
        requester_nonce: "3".repeat(64),
        signature: governance.sign(&[]),
    };
    fence_request.signature = governance.sign(&fence_request.signing_bytes()?);
    let mut fence = WitnessSessionStateFenceV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        request: fence_request,
        admission_digest: envelope.admission_digest.clone(),
        bucket_epoch_digest: envelope.bucket_epoch_digest.clone(),
        bucket_anchor_digest: "4".repeat(64),
        ready_manifest_digest: "5".repeat(64),
        store_state_digest: envelope.store_state_digest()?,
        current_session_generation: envelope
            .session
            .as_ref()
            .map(|session| session.session_generation),
        current_session_digest: envelope
            .session
            .as_ref()
            .map(|session| {
                digest_domain(
                    WITNESS_SESSION_STATE_DOMAIN_V1,
                    &canonical_wire_bytes(session)?,
                )
            })
            .transpose()?,
        current_head_digest: envelope
            .current
            .as_ref()
            .map(|current| current.head.head_digest())
            .transpose()?,
        current_prepared_digest: envelope
            .prepared
            .as_ref()
            .map(|prepared| {
                digest_domain(
                    WITNESS_PREPARED_STATE_DOMAIN_V1,
                    &canonical_wire_bytes(&prepared.prepared)?,
                )
            })
            .transpose()?,
        witness_nonce: "6".repeat(64),
        witness_identity: binding.witness_identity.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        signature: witness.sign(&[]),
    };
    fence.signature = witness.sign(&fence.signing_bytes()?);
    fence.validate()?;
    let ephemeral = Ed25519Signer::from_secret_material("phase285-plan03b-ephemeral");
    let mut challenge = RecoveryChallengeV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: binding.stream_id.clone(),
        authority_pair: binding.authority_pair,
        binding_generation: binding.generation.clone(),
        binding_digest: binding.binding_digest.clone(),
        signer_key_id: binding.signer_key_id.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        witness_identity: binding.witness_identity.clone(),
        state_fence: fence.clone(),
        ephemeral_key_id: ephemeral.key_id().to_string(),
        nonce: "7".repeat(64),
        session_commitment: "8".repeat(64),
        signature: governance.sign(&[]),
    };
    challenge.signature = governance.sign(&challenge.signing_bytes()?);
    challenge.validate()?;
    let session_generation = envelope
        .session
        .as_ref()
        .map_or(0, |session| session.session_generation)
        .checked_add(1)
        .ok_or(ProtocolError::Overflow {
            counter: "checkpoint_session_generation",
        })?;
    let session = WitnessSessionV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: binding.stream_id.clone(),
        authority_pair: binding.authority_pair,
        binding_generation: binding.generation.clone(),
        binding_digest: binding.binding_digest.clone(),
        signer_key_id: binding.signer_key_id.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        ephemeral_key_id: ephemeral.key_id().to_string(),
        witness_identity: binding.witness_identity.clone(),
        session_generation,
        session_commitment: challenge.session_commitment.clone(),
    };
    session.validate()?;
    let mut rotated_prepared = envelope.prepared.clone();
    if let Some(prepared) = &mut rotated_prepared {
        prepared.prepared.session_generation = session_generation;
    }
    let discovery = WitnessDiscoveryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: envelope
            .current
            .as_ref()
            .map(|current| current.head.clone()),
        prepared: rotated_prepared
            .as_ref()
            .map(|prepared| prepared.prepared.clone()),
        genesis_abort: envelope.genesis_abort.clone(),
        recovery_session: session.clone(),
    };
    let receipt = WitnessSessionRotationReceiptV1::for_discovery(
        fence.request.request_digest()?,
        &challenge,
        discovery,
    )?;
    let mut proposed = envelope.clone();
    proposed.session = Some(session);
    proposed.last_session_rotation = Some(receipt);
    proposed.prepared = rotated_prepared;
    proposed.store_generation =
        envelope
            .store_generation
            .checked_add(1)
            .ok_or(ProtocolError::Overflow {
                counter: "checkpoint_store_generation",
            })?;
    proposed.signature = witness.sign(&proposed.signing_bytes()?);
    proposed.validate()?;
    Ok(proposed)
}

fn checkpoint_state_pair(
    state: &str,
    empty: &WitnessStoreEnvelopeV1,
    governance: &Ed25519Signer,
    witness: &Ed25519Signer,
    binding: &PublicationBindingV1,
) -> ProtocolResult<(WitnessStoreEnvelopeV1, WitnessStoreEnvelopeV1)> {
    let session = session_rotation(governance, witness, binding, empty)?;
    let genesis_prepared = prepared_envelope(
        &session,
        checkpoint_candidate(governance, binding, None)?,
        witness,
    )?;
    let genesis_committed = committed_envelope(&genesis_prepared, witness)?;
    let successor_prepared = prepared_envelope(
        &genesis_committed,
        checkpoint_candidate(
            governance,
            binding,
            genesis_committed
                .current
                .as_ref()
                .map(|current| &current.head),
        )?,
        witness,
    )?;
    let target = match state {
        "current" => genesis_committed,
        "predecessor" => committed_envelope(&successor_prepared, witness)?,
        "prepared" => genesis_prepared,
        "abort" => aborted_envelope(&successor_prepared, witness)?,
        "genesis_abort" => aborted_envelope(&genesis_prepared, witness)?,
        _ => return Err(ProtocolError::WitnessOutcomeMismatch),
    };
    let proposed = session_rotation(governance, witness, binding, &target)?;
    let transition = validate_store_transition(
        &target,
        &proposed,
        WitnessStoreExpectationV1 {
            admission_digest: &target.admission_digest,
            bucket_epoch_digest: &target.bucket_epoch_digest,
            stream_initialization_digest: &target.stream_initialization_digest,
            stream_id: &target.stream_id,
            witness_identity: &target.witness_identity,
            witness_key_id: &target.witness_key_id,
            authority_pair: binding.authority_pair,
            binding_generation: &binding.generation,
            binding_digest: &binding.binding_digest,
            signer_key_id: &binding.signer_key_id,
        },
    )?;
    if transition != WitnessStoreTransitionV1::RotateSession {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    Ok((target, proposed))
}

fn bucket_configuration(
    bucket: &str,
    max_value_bytes: u64,
    max_bucket_bytes: u64,
) -> ProtocolResult<WitnessBucketConfigurationV1> {
    Ok(WitnessBucketConfigurationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        nats_server_version: NATS_VERSION.to_string(),
        nats_server_image_index_digest: NATS_IMAGE.to_string(),
        stream_name: format!("KV_{bucket}"),
        description: "Phase 285 external governance witness".to_string(),
        subjects: vec![format!("$KV.{bucket}.>")],
        retention: WitnessRetentionPolicyV1::Limits,
        discard: WitnessDiscardPolicyV1::New,
        discard_new_per_subject: false,
        storage: WitnessStorageTypeV1::File,
        max_messages: -1,
        max_bytes: i64::try_from(max_bucket_bytes)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?,
        max_messages_per_subject: 1,
        max_age_nanos: 0,
        max_consumers: -1,
        max_message_size: i32::try_from(max_value_bytes)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?,
        num_replicas: 1,
        no_ack: false,
        duplicate_window_nanos: 120_000_000_000,
        persistence_semantics: WitnessPersistenceSemanticsV1::Nats21117SynchronousOnly,
        persist_mode_wire_key_present: false,
        sealed: false,
        allow_rollup: false,
        deny_delete: true,
        deny_purge: true,
        allow_direct: false,
        mirror_direct: false,
        allow_message_ttl: false,
        allow_atomic_publish: false,
        allow_message_schedules: false,
        allow_message_counter: false,
        template_owner: String::new(),
        application_metadata: BTreeMap::new(),
        server_metadata: BTreeMap::from([
            ("_nats.level".to_string(), "1".to_string()),
            ("_nats.req.level".to_string(), "0".to_string()),
            ("_nats.ver".to_string(), NATS_VERSION.to_string()),
        ]),
        republish_present: false,
        mirror_present: false,
        sources_count: 0,
        subject_transform_present: false,
        compression: WitnessCompressionV1::Disabled,
        consumer_limits_present: false,
        first_sequence: None,
        placement_present: false,
        pause_until: None,
        subject_delete_marker_ttl_nanos: None,
    })
}

fn raw_configuration(bucket: &str, max_value: u64, max_bytes: u64) -> Value {
    json!({
        "name": format!("KV_{bucket}"),
        "description": "Phase 285 external governance witness",
        "subjects": [format!("$KV.{bucket}.>")],
        "retention": "limits",
        "max_consumers": -1,
        "max_msgs": -1,
        "max_bytes": max_bytes,
        "max_age": 0,
        "max_msgs_per_subject": 1,
        "max_msg_size": max_value,
        "discard": "new",
        "storage": "file",
        "num_replicas": 1,
        "duplicate_window": 120000000000_u64,
        "compression": "none",
        "allow_direct": false,
        "mirror_direct": false,
        "sealed": false,
        "deny_delete": true,
        "deny_purge": true,
        "allow_rollup_hdrs": false,
        "consumer_limits": {},
        "allow_msg_ttl": false,
        "metadata": {"_nats.level":"1","_nats.req.level":"0","_nats.ver":NATS_VERSION}
    })
}

async fn request_value(
    context: &async_nats::jetstream::Context,
    subject: String,
    payload: &Value,
) -> TestResult {
    let response: Response<Value> = context.request(subject, payload).await?;
    match response {
        Response::Ok(value) => {
            if value.is_null() {
                Err(io::Error::other("NATS returned a null response").into())
            } else {
                Ok(())
            }
        }
        Response::Err { error } => Err(io::Error::other(error.to_string()).into()),
    }
}

async fn raw_info(
    context: &async_nats::jetstream::Context,
    stream_name: &str,
) -> Result<Value, Box<dyn Error>> {
    let response: Response<Value> = context
        .request(format!("STREAM.INFO.{stream_name}"), &json!({}))
        .await?;
    match response {
        Response::Ok(value) => Ok(value),
        Response::Err { error } => Err(io::Error::other(error.to_string()).into()),
    }
}

fn raw_configuration_digest(raw_info: &Value) -> Result<String, Box<dyn Error>> {
    let config: RawConfigDigestFixture = serde_json::from_value(
        raw_info
            .get("config")
            .cloned()
            .ok_or_else(|| io::Error::other("raw info omitted config"))?,
    )?;
    let canonical = serde_json::to_vec(&config)?;
    let mut digest = Sha256::new();
    digest.update(RAW_CONFIG_DOMAIN);
    digest.update(u64::try_from(canonical.len())?.to_be_bytes());
    digest.update(canonical);
    Ok(hex::encode(digest.finalize()))
}

fn canonical_fixture_created_at(raw: &str) -> Result<String, io::Error> {
    let without_z = raw
        .strip_suffix('Z')
        .ok_or_else(|| io::Error::other("NATS created time is not UTC"))?;
    let (base, fraction) = without_z
        .split_once('.')
        .map_or((without_z, ""), |parts| parts);
    if base.len() != 19 || fraction.len() > 9 || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(io::Error::other(
            "NATS created time is not the pinned RFC3339Nano form",
        ));
    }
    Ok(format!("{base}.{fraction:0<9}Z"))
}

fn exact_put_headers(stream_name: &str, revision: u64, operation: InitialHeader) -> HeaderMap {
    let mut headers = HeaderMap::new();
    assert!(matches!(operation, InitialHeader::Put));
    headers.insert("KV-Operation", "PUT");
    headers.insert(NATS_EXPECTED_STREAM, HeaderValue::from(stream_name));
    headers.insert(
        NATS_EXPECTED_LAST_SUBJECT_SEQUENCE,
        HeaderValue::from(revision),
    );
    headers
}

async fn publish_initial(
    context: &async_nats::jetstream::Context,
    subject: String,
    stream_name: &str,
    payload: Vec<u8>,
    operation: InitialHeader,
) -> Result<u64, Box<dyn Error>> {
    let ack = context
        .publish_with_headers(
            subject,
            exact_put_headers(stream_name, 0, operation),
            payload.into(),
        )
        .await?
        .await?;
    Ok(ack.sequence)
}

async fn live_fixture(
    bucket: &str,
    operation: InitialHeader,
) -> Result<LiveFixture, Box<dyn Error>> {
    let server = current_server()?;
    live_fixture_at(bucket, operation, &server, None).await
}

fn current_server() -> TestResult<String> {
    if let Some(path) = env::var_os("SWARM_NATS_CURRENT_PORT_FILE") {
        let port = std::fs::read_to_string(path)?;
        let port = port.trim();
        if port.bytes().all(|byte| byte.is_ascii_digit()) && !port.is_empty() {
            return Ok(format!("nats://127.0.0.1:{port}"));
        }
        return Err(io::Error::other("harness current client port is malformed").into());
    }
    let nats_url = env::var("NATS_URL")?;
    nats_url
        .rsplit_once('@')
        .map(|(_, server)| format!("nats://{server}"))
        .ok_or_else(|| io::Error::other("NATS_URL omitted fixed harness credentials").into())
}

async fn live_fixture_at(
    bucket: &str,
    operation: InitialHeader,
    server: &str,
    checkpoint_state: Option<&str>,
) -> Result<LiveFixture, Box<dyn Error>> {
    let client = async_nats::ConnectOptions::new()
        .user_and_password(
            "phase285_expected".to_string(),
            "phase285_expected_fixed_password".to_string(),
        )
        .connect(server)
        .await
        .map_err(|error| io::Error::other(format!("connect expected account: {error}")))?;
    let context = async_nats::jetstream::new(client);
    let stream_id = format!("stream-{bucket}");
    let governance_secret = format!("{bucket}-governance");
    let witness_secret = format!("{bucket}-witness");
    let governance = Ed25519Signer::from_secret_material(&governance_secret);
    let witness = Ed25519Signer::from_secret_material(&witness_secret);
    let binding = fixture_protocol(
        "construct publication binding",
        binding(&governance, &witness, &stream_id),
    )?;
    let max_retained_bytes = 1_000_000_u64;
    let max_manifest_bytes = 1_000_000_u64;
    let required_bucket_bytes =
        2 * (max_manifest_bytes + 65_536) + 2 * (max_retained_bytes + 65_536);
    let configuration = fixture_protocol(
        "construct bucket configuration",
        bucket_configuration(
            bucket,
            max_retained_bytes.max(max_manifest_bytes),
            required_bucket_bytes,
        ),
    )?;
    fixture_protocol("validate bucket configuration", configuration.validate())?;
    request_value(
        &context,
        format!("STREAM.CREATE.{}", configuration.stream_name),
        &raw_configuration(bucket, max_retained_bytes, required_bucket_bytes),
    )
    .await
    .map_err(|error| io::Error::other(format!("open confirmed store: {error:?}")))?;
    let server_info = raw_info(&context, &configuration.stream_name).await?;
    let raw_created_at = server_info
        .get("created")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("raw info omitted created"))?
        .to_string();
    let created_at = canonical_fixture_created_at(&raw_created_at)?;

    let mut admission = WitnessAdmissionRecordV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: binding.stream_id.clone(),
        signer_key_id: binding.signer_key_id.clone(),
        witness_identity: binding.witness_identity.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        binding_generation: binding.generation.clone(),
        binding_digest: binding.binding_digest.clone(),
        authority_pair: binding.authority_pair,
        publication_roles: binding.publication_roles,
        limits: binding.limits,
        max_retained_bytes,
        initial_epoch: 0,
        initial_sequence: 0,
        initial_intent_counter: 1,
        admission_digest: "0".repeat(64),
    };
    admission.admission_digest =
        fixture_protocol("compute admission digest", admission.computed_digest())?;
    fixture_protocol("validate admission", admission.validate())?;
    let admission_entry = WitnessAdmissionEntryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        admission: admission.clone(),
        governance_signer_public_key_hex: governance.public_key_hex().to_string(),
        max_state_bytes: admission.limits.max_payload_bytes,
        max_checkpoint_bytes: admission.limits.max_payload_bytes,
        max_binding_bytes: admission.limits.max_record_bytes,
        max_request_bytes: admission.limits.max_record_bytes,
        max_response_bytes: admission.limits.max_record_bytes,
        predecessor_admission_digest: None,
    };
    let mut admission_set = WitnessAdmissionSetV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        entries: vec![admission_entry],
        admission_set_digest: "0".repeat(64),
    };
    admission_set.admission_set_digest = fixture_protocol(
        "compute admission-set digest",
        admission_set.computed_digest(),
    )?;
    fixture_protocol("validate admission set", admission_set.validate())?;
    let configuration_digest = fixture_protocol(
        "compute bucket configuration digest",
        configuration.digest(),
    )?;
    let epoch = WitnessBucketEpochV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        bucket_generation: "a".repeat(64),
        nats_account: "PHASE285_EXPECTED".to_string(),
        stream_name: configuration.stream_name.clone(),
        bucket_configuration_digest: configuration_digest.clone(),
        admission_set_digest: admission_set.admission_set_digest.clone(),
        witness_identity: admission.witness_identity.clone(),
        witness_key_id: admission.witness_key_id.clone(),
    };
    let epoch_digest = fixture_protocol("compute bucket epoch digest", epoch.digest())?;
    let initialization_digest = WitnessStreamInitializationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        bucket_epoch_digest: epoch_digest.clone(),
        admission_digest: admission.admission_digest.clone(),
        stream_id: stream_id.clone(),
        witness_identity: admission.witness_identity.clone(),
        witness_key_id: admission.witness_key_id.clone(),
    }
    .digest()
    .map_err(|error| {
        io::Error::other(format!("compute stream initialization digest: {error:?}"))
    })?;
    let mut current = WitnessStoreEnvelopeV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        admission_digest: admission.admission_digest.clone(),
        bucket_epoch_digest: epoch_digest.clone(),
        stream_initialization_digest: initialization_digest.clone(),
        stream_id: stream_id.clone(),
        witness_identity: admission.witness_identity.clone(),
        witness_key_id: admission.witness_key_id.clone(),
        session: None,
        last_session_rotation: None,
        current: None,
        predecessor: None,
        prepared: None,
        genesis_abort: None,
        store_generation: 0,
        signature: witness.sign(&[]),
    };
    current.signature = witness.sign(&fixture_protocol(
        "encode empty envelope signing bytes",
        current.signing_bytes(),
    )?);
    fixture_protocol("validate empty envelope", current.validate())?;
    let empty = current.clone();
    let (current, proposed) = if let Some(state) = checkpoint_state {
        fixture_protocol(
            "construct checkpoint state pair",
            checkpoint_state_pair(state, &empty, &governance, &witness, &binding),
        )?
    } else {
        (
            empty.clone(),
            fixture_protocol(
                "construct session rotation",
                session_rotation(&governance, &witness, &binding, &empty),
            )?,
        )
    };
    let stream_key = fixture_protocol("derive witness stream key", witness_stream_key(&stream_id))?;
    let mut manifest = WitnessBucketManifestV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        bucket_epoch_digest: epoch_digest,
        bucket_configuration_digest: configuration_digest,
        admission_set_digest: admission_set.admission_set_digest.clone(),
        stream_keys: vec![stream_key.clone()],
        initialized_streams: BTreeMap::from([(
            stream_key.clone(),
            WitnessStreamInitializationRecordV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                stream_initialization_digest: initialization_digest,
                empty_envelope_digest: fixture_protocol(
                    "compute empty-envelope digest",
                    empty.signed_envelope_digest(),
                )?,
            },
        )]),
        phase: WitnessBucketManifestPhaseV1::Ready,
        witness_identity: admission.witness_identity.clone(),
        witness_key_id: admission.witness_key_id.clone(),
        signature: witness.sign(&[]),
    };
    manifest.signature = witness.sign(&fixture_protocol(
        "encode ready-manifest signing bytes",
        manifest.signing_bytes(),
    )?);
    let mut anchor = WitnessBucketAnchorV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        epoch: epoch.clone(),
        nats_stream_created_at: created_at.clone(),
        raw_stream_configuration_digest: raw_configuration_digest(&server_info)?,
        ready_manifest_digest: fixture_protocol(
            "compute ready-manifest digest",
            manifest.digest(),
        )?,
        witness_key_id: admission.witness_key_id.clone(),
        signature: witness.sign(&[]),
    };
    anchor.signature = witness.sign(&fixture_protocol(
        "encode bucket-anchor signing bytes",
        anchor.signing_bytes(),
    )?);
    let deployment_inputs = WitnessStoreDeploymentInputsV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        max_manifest_bytes,
        maximum_admitted_streams: 1,
        configured_replica_count: 1,
    };
    let ready = fixture_protocol(
        "construct ready result",
        swarm_governance::witness_engine::store::WitnessStoreReadyResultV1::new(
            created_at,
            configuration,
            epoch,
            anchor,
            admission_set,
            manifest.clone(),
            deployment_inputs,
        ),
    )?;
    let manifest_sequence = publish_initial(
        &context,
        format!("$KV.{bucket}.{MANIFEST_KEY}"),
        &ready.bucket_configuration.stream_name,
        canonical_wire_bytes(&manifest)?,
        InitialHeader::Put,
    )
    .await?;
    assert_eq!(manifest_sequence, 1);
    let subject = format!("$KV.{bucket}.{stream_key}");
    let initial_revision = publish_initial(
        &context,
        subject.clone(),
        &ready.bucket_configuration.stream_name,
        current.canonical_bytes()?,
        operation,
    )
    .await?;
    assert_eq!(initial_revision, 2);
    Ok(LiveFixture {
        context,
        ready,
        stream_id,
        current,
        proposed,
        initial_revision,
        subject,
    })
}

const CHECKPOINT_LEDGER_PATH_ENV: &str = "PHASE285_CHECKPOINT_LEDGER";
const CHECKPOINT_LEDGER_REQUIRED_ENV: &str = "PHASE285_CHECKPOINT_LEDGER_REQUIRED";
const CHECKPOINT_INVOCATION_TOKEN_ENV: &str = "PHASE285_CHECKPOINT_INVOCATION_TOKEN";
const CHECKPOINT_TREE_ENV: &str = "PHASE285_CHECKPOINT_TREE";
const CHECKPOINT_LEDGER_DOMAIN: &[u8] = b"swarm.phase285.checkpoint-dynamic-ledger-row.v1";
const CHECKPOINT_GENESIS_COMPONENT_DOMAIN: &[u8] =
    b"swarm.phase285.checkpoint-genesis-abort-component.v1";

struct CheckpointLedger {
    case_name: &'static str,
    invocation_token: String,
    harness_token: String,
    accepted_tree: String,
    rows: Vec<BTreeMap<String, Value>>,
}

impl CheckpointLedger {
    fn new(case_name: &'static str) -> Result<Self, io::Error> {
        let invocation_token = env::var(CHECKPOINT_INVOCATION_TOKEN_ENV)
            .map_err(|_| io::Error::other("checkpoint invocation token absent"))?;
        let harness_token = env::var("SWARM_NATS_CHECKPOINT_TOKEN")
            .map_err(|_| io::Error::other("checkpoint harness token absent"))?;
        let accepted_tree = env::var(CHECKPOINT_TREE_ENV)
            .map_err(|_| io::Error::other("checkpoint accepted tree absent"))?;
        for token in [&invocation_token, &harness_token] {
            if token.len() > 512
                || !token.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_uppercase()
                        || byte.is_ascii_digit()
                        || b"._-".contains(&byte)
                })
            {
                return Err(io::Error::other("checkpoint ledger token malformed"));
            }
        }
        if accepted_tree.len() != 40
            || !accepted_tree
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(io::Error::other("checkpoint accepted tree malformed"));
        }
        Ok(Self {
            case_name,
            invocation_token,
            harness_token,
            accepted_tree,
            rows: Vec::new(),
        })
    }

    fn record(
        &mut self,
        kind: &'static str,
        state_id: Option<&str>,
        evidence: Value,
    ) -> Result<(), io::Error> {
        if kind.is_empty()
            || !kind.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
            || state_id.is_some_and(|state| {
                state.is_empty()
                    || !state.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
                    })
            })
            || !evidence.is_object()
            || self.rows.iter().any(|row| {
                row.get("kind") == Some(&Value::String(kind.to_string()))
                    && row.get("state_id")
                        == Some(&state_id.map_or(Value::Null, |value| Value::String(value.into())))
            })
        {
            return Err(io::Error::other("invalid checkpoint ledger row"));
        }
        let mut preimage = BTreeMap::from([
            (
                "accepted_tree".to_string(),
                Value::String(self.accepted_tree.clone()),
            ),
            (
                "case".to_string(),
                Value::String(self.case_name.to_string()),
            ),
            ("evidence".to_string(), evidence),
            (
                "harness_token".to_string(),
                Value::String(self.harness_token.clone()),
            ),
            (
                "invocation_token".to_string(),
                Value::String(self.invocation_token.clone()),
            ),
            ("kind".to_string(), Value::String(kind.to_string())),
            ("schema_version".to_string(), Value::from(1_u64)),
            (
                "state_id".to_string(),
                state_id.map_or(Value::Null, |value| Value::String(value.into())),
            ),
            ("status".to_string(), Value::String("passed".to_string())),
        ]);
        let canonical = serde_json::to_vec(&preimage).map_err(io::Error::other)?;
        if canonical.len() > 2_000_000 {
            return Err(io::Error::other("checkpoint ledger row exceeds bound"));
        }
        let mut digest = Sha256::new();
        digest.update(CHECKPOINT_LEDGER_DOMAIN);
        digest.update(
            u64::try_from(canonical.len())
                .map_err(io::Error::other)?
                .to_be_bytes(),
        );
        digest.update(&canonical);
        preimage.insert(
            "row_digest".to_string(),
            Value::String(hex::encode(digest.finalize())),
        );
        self.rows.push(preimage);
        Ok(())
    }

    fn finish(self) -> Result<(), io::Error> {
        let required = env::var(CHECKPOINT_LEDGER_REQUIRED_ENV).as_deref() == Ok("1");
        let path = match env::var_os(CHECKPOINT_LEDGER_PATH_ENV) {
            Some(value) => std::path::PathBuf::from(value),
            None if required => return Err(io::Error::other("required checkpoint ledger absent")),
            None => return Ok(()),
        };
        if !path.is_absolute()
            || path.exists()
            || !path.parent().is_some_and(std::path::Path::is_dir)
        {
            return Err(io::Error::other(
                "checkpoint ledger path is not fresh and confined",
            ));
        }
        let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
        if self.rows.is_empty() {
            return Err(io::Error::other("checkpoint ledger is empty"));
        }
        for row in self.rows {
            serde_json::to_writer(&mut output, &row).map_err(io::Error::other)?;
            output.write_all(b"\n")?;
        }
        output.flush()?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapturedAckEvent {
    stream: String,
    sequence: u64,
    duplicate: bool,
    proposed_digest: String,
    token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredOutcomeFingerprint {
    Absent,
    Committed,
    Aborted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckpointSemanticFingerprint {
    current: StoredOutcomeFingerprint,
    predecessor: StoredOutcomeFingerprint,
    prepared: bool,
    genesis_abort: bool,
    current_binds_predecessor: bool,
    prepared_binds_current: bool,
}

fn stored_outcome(value: Option<&WitnessStoredCandidateV1>) -> StoredOutcomeFingerprint {
    match value.and_then(|stored| stored.head.last_intent_outcome.as_ref()) {
        None => StoredOutcomeFingerprint::Absent,
        Some(WitnessIntentOutcomeV1::Committed { .. }) => StoredOutcomeFingerprint::Committed,
        Some(WitnessIntentOutcomeV1::Aborted(_)) => StoredOutcomeFingerprint::Aborted,
    }
}

fn semantic_fingerprint(
    envelope: &WitnessStoreEnvelopeV1,
) -> TestResult<CheckpointSemanticFingerprint> {
    envelope.validate()?;
    let current_binds_predecessor = match (&envelope.current, &envelope.predecessor) {
        (Some(current), Some(predecessor)) => {
            current.candidate.predecessor_head_digest == predecessor.head.head_digest()?
                && current.candidate.predecessor_data_head_digest
                    == predecessor.head.data_head_digest()?
        }
        (Some(current), None) => current.candidate.predecessor_head.is_none(),
        (None, None) => true,
        (None, Some(_)) => false,
    };
    let prepared_binds_current = match (&envelope.prepared, &envelope.current) {
        (Some(prepared), Some(current)) => {
            prepared.prepared.predecessor_head_digest == current.head.head_digest()?
                && prepared.prepared.predecessor_data_head_digest
                    == current.head.data_head_digest()?
        }
        (Some(prepared), None) => prepared.prepared.predecessor_head.is_none(),
        (None, _) => true,
    };
    Ok(CheckpointSemanticFingerprint {
        current: stored_outcome(envelope.current.as_ref()),
        predecessor: stored_outcome(envelope.predecessor.as_ref()),
        prepared: envelope.prepared.is_some(),
        genesis_abort: envelope.genesis_abort.is_some(),
        current_binds_predecessor,
        prepared_binds_current,
    })
}

fn expected_semantic_fingerprint(state: &str) -> TestResult<CheckpointSemanticFingerprint> {
    let fingerprint = match state {
        "current" => CheckpointSemanticFingerprint {
            current: StoredOutcomeFingerprint::Committed,
            predecessor: StoredOutcomeFingerprint::Absent,
            prepared: false,
            genesis_abort: false,
            current_binds_predecessor: true,
            prepared_binds_current: true,
        },
        "predecessor" => CheckpointSemanticFingerprint {
            current: StoredOutcomeFingerprint::Committed,
            predecessor: StoredOutcomeFingerprint::Committed,
            prepared: false,
            genesis_abort: false,
            current_binds_predecessor: true,
            prepared_binds_current: true,
        },
        "prepared" => CheckpointSemanticFingerprint {
            current: StoredOutcomeFingerprint::Absent,
            predecessor: StoredOutcomeFingerprint::Absent,
            prepared: true,
            genesis_abort: false,
            current_binds_predecessor: true,
            prepared_binds_current: true,
        },
        "abort" => CheckpointSemanticFingerprint {
            current: StoredOutcomeFingerprint::Aborted,
            predecessor: StoredOutcomeFingerprint::Absent,
            prepared: false,
            genesis_abort: false,
            current_binds_predecessor: true,
            prepared_binds_current: true,
        },
        "genesis_abort" => CheckpointSemanticFingerprint {
            current: StoredOutcomeFingerprint::Absent,
            predecessor: StoredOutcomeFingerprint::Absent,
            prepared: false,
            genesis_abort: true,
            current_binds_predecessor: true,
            prepared_binds_current: true,
        },
        _ => return Err(io::Error::other("unknown checkpoint semantic state").into()),
    };
    Ok(fingerprint)
}

fn component_frame<T: Serialize>(domain: &[u8], value: Option<&T>) -> TestResult<Value> {
    value.map_or_else(
        || Ok(Value::Null),
        |component| {
            let canonical = canonical_wire_bytes(component)?;
            Ok(json!({
                "canonical_hex": hex::encode(&canonical),
                "digest": digest_domain(domain, &canonical)?,
            }))
        },
    )
}

fn authenticated_component_frames(envelope: &WitnessStoreEnvelopeV1) -> TestResult<Value> {
    Ok(json!({
        "current_candidate": component_frame(
            CANDIDATE_DOMAIN_V1,
            envelope.current.as_ref().map(|stored| &stored.candidate),
        )?,
        "current_head": component_frame(
            WITNESS_HEAD_DOMAIN_V1,
            envelope.current.as_ref().map(|stored| &stored.head),
        )?,
        "predecessor_candidate": component_frame(
            CANDIDATE_DOMAIN_V1,
            envelope.predecessor.as_ref().map(|stored| &stored.candidate),
        )?,
        "predecessor_head": component_frame(
            WITNESS_HEAD_DOMAIN_V1,
            envelope.predecessor.as_ref().map(|stored| &stored.head),
        )?,
        "prepared_candidate": component_frame(
            CANDIDATE_DOMAIN_V1,
            envelope.prepared.as_ref().map(|stored| &stored.candidate),
        )?,
        "prepared_state": component_frame(
            WITNESS_PREPARED_STATE_DOMAIN_V1,
            envelope.prepared.as_ref().map(|stored| &stored.prepared),
        )?,
        "genesis_abort": component_frame(
            CHECKPOINT_GENESIS_COMPONENT_DOMAIN,
            envelope.genesis_abort.as_ref(),
        )?,
    }))
}

fn checkpoint_control_paths(
    label: &str,
) -> TestResult<(
    String,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
)> {
    let token = env::var("SWARM_NATS_CHECKPOINT_TOKEN")?;
    let root = std::path::PathBuf::from(env::var("SWARM_NATS_HARNESS_SCRATCH")?);
    if !root.is_absolute() || !root.is_dir() {
        return Err(io::Error::other("checkpoint harness scratch unavailable").into());
    }
    Ok((
        token,
        root.join(format!("{label}.ack.json")),
        root.join(format!("{label}.release")),
        root.join(format!("{label}.done")),
        root.join(format!("{label}.restart")),
    ))
}

async fn connect_expected(server: &str) -> TestResult<async_nats::jetstream::Context> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match async_nats::ConnectOptions::new()
            .user_and_password(
                "phase285_expected".to_string(),
                "phase285_expected_fixed_password".to_string(),
            )
            .connect(server)
            .await
        {
            Ok(client) => return Ok(async_nats::jetstream::new(client)),
            Err(error) if tokio::time::Instant::now() < deadline => {
                let _ = error;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn crash_after_ack_and_verify(label: &str, server: &str) -> TestResult<(String, Value)> {
    let bucket = format!("phase285_c_{}", label.replace('_', ""));
    let fixture = live_fixture_at(&bucket, InitialHeader::Put, server, Some(label)).await?;
    let intended_fingerprint = semantic_fingerprint(&fixture.proposed)?;
    assert_eq!(intended_fingerprint, expected_semantic_fingerprint(label)?);
    for other in [
        "current",
        "predecessor",
        "prepared",
        "abort",
        "genesis_abort",
    ] {
        if other != label {
            assert_ne!(intended_fingerprint, expected_semantic_fingerprint(other)?);
        }
    }
    let (token, ack_path, release_path, done_path, observation_path) =
        checkpoint_control_paths(label)?;
    let event_trace_path =
        std::path::PathBuf::from(format!("{}.events", observation_path.display()));
    for path in [
        &ack_path,
        &release_path,
        &done_path,
        &observation_path,
        &event_trace_path,
    ] {
        assert!(
            !path.exists(),
            "checkpoint control path was not fresh: {path:?}"
        );
    }
    let store = NatsWitnessStore::open_with_post_ack_barrier(
        fixture.context.clone(),
        fixture.ready.clone(),
        NATS_VERSION,
        NATS_IMAGE,
        token.clone(),
        ack_path.clone(),
        release_path.clone(),
    )
    .await?;
    let bucket_name = fixture
        .ready
        .bucket_configuration
        .stream_name
        .strip_prefix("KV_")
        .ok_or_else(|| io::Error::other("checkpoint stream name omitted KV prefix"))?;
    let manifest_subject = format!("$KV.{bucket_name}.{MANIFEST_KEY}");
    let manifest_bytes = canonical_wire_bytes(&fixture.ready.ready_manifest)?;
    let mut manifest_revision = 1;
    for _ in 0..10 {
        let acknowledgement = fixture
            .context
            .publish_with_headers(
                manifest_subject.clone(),
                exact_put_headers(
                    &fixture.ready.bucket_configuration.stream_name,
                    manifest_revision,
                    InitialHeader::Put,
                ),
                manifest_bytes.clone().into(),
            )
            .await?
            .await?;
        assert!(acknowledgement.sequence > manifest_revision);
        manifest_revision = acknowledgement.sequence;
    }
    let harness =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/with-nats-jetstream.sh");
    let mut control = std::process::Command::new("bash")
        .arg(harness)
        .arg("--checkpoint-control")
        .arg(&token)
        .arg(&ack_path)
        .arg(&release_path)
        .arg(&done_path)
        .arg(&observation_path)
        .spawn()?;
    let result = store
        .compare_and_swap(
            &fixture.stream_id,
            fixture.initial_revision,
            &fixture.current.store_state_digest()?,
            &fixture.proposed,
        )
        .await;
    let mut done = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&done_path)?;
    writeln!(done, "{token}")?;
    done.flush()?;
    let status = control.wait()?;
    assert!(
        status.success(),
        "checkpoint control did not restart NATS; CAS result={result:?}"
    );
    assert!(matches!(result?, WitnessStoreCasResultV1::Ambiguous { .. }));

    let ack: CapturedAckEvent = serde_json::from_slice(&std::fs::read(&ack_path)?)?;
    assert_eq!(ack.token, token);
    assert_eq!(ack.stream, fixture.ready.bucket_configuration.stream_name);
    assert!(!ack.duplicate);
    assert!(ack.sequence > fixture.initial_revision);
    assert!(ack.sequence > manifest_revision);
    assert_eq!(
        ack.proposed_digest,
        fixture.proposed.signed_envelope_digest()?
    );
    assert_eq!(
        std::fs::read_to_string(&release_path)?,
        format!("{token}\n")
    );
    let observation = std::fs::read_to_string(observation_path)?;
    let event_trace = std::fs::read_to_string(event_trace_path)?;
    let expected_events = [
        format!("1\tack_observed\t{token}"),
        format!("2\trelease_written\t{token}"),
        format!("3\tdone_observed\t{token}"),
        format!("4\trestart_observed\t{token}"),
    ];
    assert_eq!(event_trace.lines().collect::<Vec<_>>(), expected_events);
    for exact in ["service=nats", "status=restarted"] {
        assert_eq!(observation.lines().filter(|line| *line == exact).count(), 1);
    }
    let live_leader = observation
        .lines()
        .find_map(|line| line.strip_prefix("leader="))
        .ok_or_else(|| io::Error::other("restart observation omitted live leader"))?;
    assert!(!live_leader.is_empty());
    let project = observation
        .lines()
        .find_map(|line| line.strip_prefix("project="))
        .ok_or_else(|| io::Error::other("restart observation omitted project"))?;
    let service = observation
        .lines()
        .find_map(|line| line.strip_prefix("service="))
        .ok_or_else(|| io::Error::other("restart observation omitted service"))?;
    let image_before = observation
        .lines()
        .find_map(|line| line.strip_prefix("image_before="))
        .ok_or_else(|| io::Error::other("restart observation omitted image_before"))?;
    let image_after = observation
        .lines()
        .find_map(|line| line.strip_prefix("image_after="))
        .ok_or_else(|| io::Error::other("restart observation omitted image_after"))?;
    let volume_before = observation
        .lines()
        .find_map(|line| line.strip_prefix("volume_before="))
        .ok_or_else(|| io::Error::other("restart observation omitted volume_before"))?;
    let volume_after = observation
        .lines()
        .find_map(|line| line.strip_prefix("volume_after="))
        .ok_or_else(|| io::Error::other("restart observation omitted volume_after"))?;
    let container_before = observation
        .lines()
        .find_map(|line| line.strip_prefix("container_before="))
        .ok_or_else(|| io::Error::other("restart observation omitted container_before"))?;
    let container_after = observation
        .lines()
        .find_map(|line| line.strip_prefix("container_after="))
        .ok_or_else(|| io::Error::other("restart observation omitted container_after"))?;
    let client_port = observation
        .lines()
        .find_map(|line| line.strip_prefix("client_port="))
        .ok_or_else(|| io::Error::other("restart observation omitted client_port"))?;
    let restarted_server = format!("nats://127.0.0.1:{client_port}");
    assert_eq!(image_before, NATS_PINNED_IMAGE);
    assert_eq!(image_after, image_before);
    assert_eq!(volume_after, volume_before);
    assert_eq!(container_after, container_before);
    assert_eq!(service, "nats");

    let independent = connect_expected(&restarted_server)
        .await
        .map_err(|error| io::Error::other(format!("post-restart connect: {error:?}")))?;
    let stream = independent
        .get_stream_no_info(&fixture.ready.bucket_configuration.stream_name)
        .await
        .map_err(|error| io::Error::other(format!("post-restart stream lookup: {error:?}")))?;
    let raw = stream
        .get_last_raw_message_by_subject(&fixture.subject)
        .await
        .map_err(|error| io::Error::other(format!("post-restart raw read: {error:?}")))?;
    assert_eq!(raw.sequence, ack.sequence);
    assert_eq!(raw.subject.as_ref(), fixture.subject);
    assert_eq!(raw.payload.as_ref(), fixture.proposed.canonical_bytes()?);
    assert_eq!(raw.headers.len(), 3);
    assert_eq!(
        raw.headers.get("KV-Operation").map(HeaderValue::as_str),
        Some("PUT")
    );
    assert_eq!(
        raw.headers
            .get(NATS_EXPECTED_STREAM)
            .map(HeaderValue::as_str),
        Some(fixture.ready.bucket_configuration.stream_name.as_str())
    );
    let expected_previous_revision = fixture.initial_revision.to_string();
    assert_eq!(
        raw.headers
            .get(NATS_EXPECTED_LAST_SUBJECT_SEQUENCE)
            .map(HeaderValue::as_str),
        Some(expected_previous_revision.as_str())
    );
    let authenticated = WitnessStoreEnvelopeV1::decode(raw.payload.as_ref())?;
    validate_read_entry(
        &fixture.ready,
        &fixture.stream_id,
        raw.sequence,
        &authenticated,
    )?;
    assert_eq!(authenticated, fixture.proposed);
    let actual_fingerprint = semantic_fingerprint(&authenticated)?;
    assert_eq!(actual_fingerprint, intended_fingerprint);
    for other in [
        "current",
        "predecessor",
        "prepared",
        "abort",
        "genesis_abort",
    ] {
        if other != label {
            assert_ne!(actual_fingerprint, expected_semantic_fingerprint(other)?);
        }
    }
    assert_eq!(authenticated.signed_envelope_digest()?, ack.proposed_digest);
    assert_eq!(
        fixture.proposed.store_generation,
        fixture.current.store_generation + 1
    );
    assert_ne!(raw.sequence, fixture.proposed.store_generation);
    assert_eq!(
        fixture.ready.bucket_epoch.digest()?,
        fixture.proposed.bucket_epoch_digest
    );
    assert_eq!(
        fixture.ready.bucket_anchor.epoch.digest()?,
        fixture.proposed.bucket_epoch_digest
    );
    let stream_key = witness_stream_key(&fixture.stream_id)?;
    assert_eq!(
        fixture
            .ready
            .ready_manifest
            .initialized_streams
            .get(&stream_key)
            .ok_or_else(|| io::Error::other("ready initialization missing"))?
            .stream_initialization_digest,
        fixture.proposed.stream_initialization_digest
    );
    let restarted_info = raw_info(
        &independent,
        &fixture.ready.bucket_configuration.stream_name,
    )
    .await?;
    let restarted_created = canonical_fixture_created_at(
        restarted_info
            .get("created")
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other("restarted stream omitted created"))?,
    )?;
    assert_eq!(restarted_created, fixture.ready.nats_stream_created_at);
    assert_eq!(
        raw_configuration_digest(&restarted_info)?,
        fixture.ready.bucket_anchor.raw_stream_configuration_digest
    );
    let reopened =
        NatsWitnessStore::open(independent, fixture.ready.clone(), NATS_VERSION, NATS_IMAGE)
            .await?;
    let reopened_ready = reopened.inspect_ready().await?;
    assert_eq!(reopened_ready, fixture.ready);
    let post_restart_read = reopened.read_entry(&fixture.stream_id).await?;
    let (read_stream_id, read_revision, read_envelope) = post_restart_read.parts();
    assert_eq!(read_stream_id, fixture.stream_id);
    assert_eq!(read_revision, ack.sequence);
    let raw_bytes = raw.payload.to_vec();
    assert_eq!(read_envelope.canonical_bytes()?, raw_bytes);
    let ready_epoch_digest = fixture.ready.bucket_epoch.digest()?;
    let ready_manifest_digest = fixture.ready.ready_manifest.digest()?;
    let stream_initialization_digest = fixture
        .ready
        .ready_manifest
        .initialized_streams
        .get(&stream_key)
        .ok_or_else(|| io::Error::other("ready initialization missing"))?
        .stream_initialization_digest
        .clone();
    let admitted = fixture
        .ready
        .admission_set
        .entries
        .iter()
        .find(|entry| entry.stream_id == fixture.stream_id)
        .ok_or_else(|| io::Error::other("Ready admission omitted checkpoint stream"))?;
    let reopened_admitted = reopened_ready
        .admission_set
        .entries
        .iter()
        .find(|entry| entry.stream_id == fixture.stream_id)
        .ok_or_else(|| io::Error::other("reopened Ready omitted checkpoint stream"))?;
    let reopened_stream_key = witness_stream_key(&reopened_admitted.stream_id)?;
    assert_eq!(admitted.witness_identity, fixture.proposed.witness_identity);
    assert_eq!(admitted.witness_key_id, fixture.proposed.witness_key_id);
    assert_eq!(admitted.admission_digest, fixture.proposed.admission_digest);
    let component_frames = authenticated_component_frames(&authenticated)?;
    let fingerprint_value = |fingerprint: CheckpointSemanticFingerprint| {
        let outcome = |value| match value {
            StoredOutcomeFingerprint::Absent => "absent",
            StoredOutcomeFingerprint::Committed => "committed",
            StoredOutcomeFingerprint::Aborted => "aborted",
        };
        json!({
            "current": outcome(fingerprint.current),
            "predecessor": outcome(fingerprint.predecessor),
            "prepared": fingerprint.prepared,
            "genesis_abort": fingerprint.genesis_abort,
            "current_binds_predecessor": fingerprint.current_binds_predecessor,
            "prepared_binds_current": fingerprint.prepared_binds_current,
        })
    };
    let evidence = json!({
        "semantic": fingerprint_value(actual_fingerprint),
        "ack": {
            "stream": ack.stream,
            "sequence": ack.sequence,
            "duplicate": ack.duplicate,
            "proposed_digest": ack.proposed_digest,
            "token": ack.token,
        },
        "relations": {
            "initial_revision": fixture.initial_revision,
            "manifest_tail_sequence": manifest_revision,
            "current_store_generation": fixture.current.store_generation,
            "proposed_store_generation": fixture.proposed.store_generation,
        },
        "barrier": {
            "ack_lines": std::fs::read_to_string(&ack_path)?.lines().count(),
            "release_lines": std::fs::read_to_string(&release_path)?.lines().count(),
            "done_lines": std::fs::read_to_string(&done_path)?.lines().count(),
            "ack_token": token,
            "release_token": std::fs::read_to_string(&release_path)?.trim(),
            "done_token": std::fs::read_to_string(&done_path)?.trim(),
            "event_trace": event_trace.lines().collect::<Vec<_>>(),
        },
        "raw": {
            "subject": raw.subject.as_ref(),
            "sequence": raw.sequence,
            "bytes_hex": hex::encode(&raw_bytes),
            "signed_digest": authenticated.signed_envelope_digest()?,
            "headers": {
                "KV-Operation": raw.headers.get("KV-Operation").map(HeaderValue::as_str),
                "Nats-Expected-Stream": raw.headers.get(NATS_EXPECTED_STREAM).map(HeaderValue::as_str),
                "Nats-Expected-Last-Subject-Sequence": raw.headers.get(NATS_EXPECTED_LAST_SUBJECT_SEQUENCE).map(HeaderValue::as_str),
            },
        },
        "ready_identity": {
            "stream_name": fixture.ready.bucket_configuration.stream_name,
            "bucket_name": bucket_name,
            "admitted_stream_id": admitted.stream_id,
            "admitted_stream_key": stream_key,
            "subject": fixture.subject,
            "witness_identity": admitted.witness_identity,
            "witness_key_id": admitted.witness_key_id,
            "admission_digest": admitted.admission_digest,
            "bucket_epoch_digest": ready_epoch_digest,
            "stream_initialization_digest": stream_initialization_digest,
            "reopened_stream_name": reopened_ready.bucket_configuration.stream_name,
            "reopened_admitted_stream_id": reopened_admitted.stream_id,
            "reopened_admitted_stream_key": reopened_stream_key,
            "reopened_subject": format!("$KV.{bucket_name}.{reopened_stream_key}"),
        },
        "decoded": {
            "store_state_digest": authenticated.store_state_digest()?,
            "components": component_frames,
        },
        "restart": {
            "project": project,
            "service": service,
            "image_before": image_before,
            "image_after": image_after,
            "volume_before": volume_before,
            "volume_after": volume_after,
            "container_before": container_before,
            "container_after": container_after,
            "leader": live_leader,
        },
        "bindings": {
            "ready_created_at": fixture.ready.nats_stream_created_at,
            "restarted_created_at": restarted_created,
            "ready_raw_config_digest": fixture.ready.bucket_anchor.raw_stream_configuration_digest,
            "restarted_raw_config_digest": raw_configuration_digest(&restarted_info)?,
            "ready_epoch_digest": ready_epoch_digest,
            "anchor_epoch_digest": fixture.ready.bucket_anchor.epoch.digest()?,
            "envelope_epoch_digest": fixture.proposed.bucket_epoch_digest,
            "ready_initialization_digest": stream_initialization_digest,
            "envelope_initialization_digest": fixture.proposed.stream_initialization_digest,
            "ready_manifest_digest": ready_manifest_digest,
            "reopened_manifest_digest": reopened_ready.ready_manifest.digest()?,
            "reopened_read_stream_id": read_stream_id,
            "reopened_read_revision": read_revision,
            "reopened_read_digest": read_envelope.signed_envelope_digest()?,
        },
    });
    Ok((restarted_server, evidence))
}

#[tokio::test]
async fn jetstream_checkpoint_survives_restart_for_current_predecessor_prepared_abort_and_genesis()
-> TestResult {
    let case =
        "jetstream_checkpoint_survives_restart_for_current_predecessor_prepared_abort_and_genesis";
    let mut ledger = CheckpointLedger::new(case)?;
    let mut server = current_server()?;
    for state in [
        "current",
        "predecessor",
        "prepared",
        "abort",
        "genesis_abort",
    ] {
        let (restarted_server, evidence) = crash_after_ack_and_verify(state, &server)
            .await
            .map_err(|error| io::Error::other(format!("checkpoint state {state}: {error:?}")))?;
        server = restarted_server;
        ledger.record("restart_state", Some(state), evidence)?;
    }
    ledger.finish()?;
    Ok(())
}

#[tokio::test]
async fn jetstream_checkpoint_rejects_rolled_back_anchor_or_recreated_stream() -> TestResult {
    let mut ledger = CheckpointLedger::new(
        "jetstream_checkpoint_rejects_rolled_back_anchor_or_recreated_stream",
    )?;
    let fixture = live_fixture("phase285_c_anchor", InitialHeader::Put).await?;
    let before_created = fixture.ready.nats_stream_created_at.clone();
    let before_raw_config_digest = fixture
        .ready
        .bucket_anchor
        .raw_stream_configuration_digest
        .clone();
    let mut stale = fixture.ready.clone();
    stale.bucket_anchor.nats_stream_created_at = "2026-08-24T00:00:00.000000000Z".to_string();
    let witness = Ed25519Signer::from_secret_material("phase285_c_anchor-witness");
    stale.bucket_anchor.signature = witness.sign(&stale.bucket_anchor.signing_bytes()?);
    stale.bucket_anchor.validate()?;
    let stale_result = match NatsWitnessStore::open(
        fixture.context.clone(),
        stale,
        NATS_VERSION,
        NATS_IMAGE,
    )
    .await
    {
        Err(WitnessStoreErrorV1::Configuration) => {
            json!({"result": "err", "error": "configuration"})
        }
        other => {
            return Err(
                io::Error::other(format!("stale anchor result differed: {other:?}")).into(),
            );
        }
    };
    let stream_name = fixture.ready.bucket_configuration.stream_name.clone();
    assert!(fixture.context.delete_stream(&stream_name).await?.success);
    let max_value = 1_000_000_u64;
    let required_bucket_bytes = 4 * (max_value + 65_536);
    request_value(
        &fixture.context,
        format!("STREAM.CREATE.{stream_name}"),
        &raw_configuration("phase285_c_anchor", max_value, required_bucket_bytes),
    )
    .await?;
    let recreated_info = raw_info(&fixture.context, &stream_name).await?;
    let after_created = canonical_fixture_created_at(
        recreated_info
            .get("created")
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other("recreated stream omitted created"))?,
    )?;
    let after_raw_config_digest = raw_configuration_digest(&recreated_info)?;
    let recreated_result = match NatsWitnessStore::open(
        fixture.context.clone(),
        fixture.ready.clone(),
        NATS_VERSION,
        NATS_IMAGE,
    )
    .await
    {
        Err(WitnessStoreErrorV1::Configuration) => {
            json!({"result": "err", "error": "configuration"})
        }
        other => {
            return Err(
                io::Error::other(format!("recreated stream result differed: {other:?}")).into(),
            );
        }
    };
    let stream_key = witness_stream_key(&fixture.stream_id)?;
    ledger.record(
        "anchor_recreation",
        None,
        json!({
            "stream_name": stream_name,
            "bucket_name": "phase285_c_anchor",
            "before_created": before_created,
            "before_anchor_created": fixture.ready.bucket_anchor.nats_stream_created_at,
            "stale_created": "2026-08-24T00:00:00.000000000Z",
            "after_created": after_created,
            "before_raw_config_digest": before_raw_config_digest,
            "after_raw_config_digest": after_raw_config_digest,
            "stale_result": stale_result,
            "recreated_result": recreated_result,
            "ready_epoch_digest": fixture.ready.bucket_epoch.digest()?,
            "anchor_epoch_digest": fixture.ready.bucket_anchor.epoch.digest()?,
            "manifest_initialization_digest": fixture.ready.ready_manifest.initialized_streams
                .get(&stream_key)
                .ok_or_else(|| io::Error::other("ready initialization missing"))?
                .stream_initialization_digest,
            "envelope_initialization_digest": fixture.current.stream_initialization_digest,
            "ready_manifest_digest": fixture.ready.ready_manifest.digest()?,
            "anchor_manifest_digest": fixture.ready.bucket_anchor.ready_manifest_digest,
        }),
    )?;
    ledger.finish()?;
    Ok(())
}

#[tokio::test]
async fn jetstream_checkpoint_rejects_unavailable_server_instead_of_skipping() -> TestResult {
    let mut ledger = CheckpointLedger::new(
        "jetstream_checkpoint_rejects_unavailable_server_instead_of_skipping",
    )?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        async_nats::connect("nats://127.0.0.1:9"),
    )
    .await;
    assert!(result.is_err() || result.is_ok_and(|connection| connection.is_err()));
    let fixture = live_fixture("phase285_c_account", InitialHeader::Put).await?;
    let foreign_client = async_nats::ConnectOptions::new()
        .user_and_password(
            "phase285_foreign".to_string(),
            "phase285_foreign_fixed_password".to_string(),
        )
        .connect(current_server()?)
        .await?;
    let foreign = async_nats::jetstream::new(foreign_client);
    let foreign_view: Response<Value> = foreign
        .request(
            format!(
                "STREAM.INFO.{}",
                fixture.ready.bucket_configuration.stream_name
            ),
            &json!({}),
        )
        .await?;
    let foreign_result = match foreign_view {
        Response::Err { error } => json!({
            "result": "refused",
            "http_code": error.code(),
            "error_code": serde_json::to_value(error.error_code())?,
            "description": error.to_string(),
        }),
        Response::Ok(_) => {
            return Err(io::Error::other("foreign account observed expected stream").into());
        }
    };
    let context = fixture.context.clone();
    let store = NatsWitnessStore::open(
        context.clone(),
        fixture.ready.clone(),
        NATS_VERSION,
        NATS_IMAGE,
    )
    .await?;
    assert_eq!(store.inspect_ready().await?, fixture.ready);
    let rogue_ack = context
        .publish_with_headers(
            "$KV.phase285_c_account.unadmitted".to_string(),
            exact_put_headers(
                &fixture.ready.bucket_configuration.stream_name,
                0,
                InitialHeader::Put,
            ),
            b"unadmitted".as_slice().into(),
        )
        .await?
        .await?;
    assert!(rogue_ack.sequence > 0);
    let iterator_result = match store.inspect_ready().await {
        Err(WitnessStoreErrorV1::Bounds) => json!({"result": "err", "error": "bounds"}),
        other => {
            return Err(io::Error::other(format!("iterator result differed: {other:?}")).into());
        }
    };
    let harness =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/with-nats-jetstream.sh");
    let token = env::var("SWARM_NATS_CHECKPOINT_TOKEN")?;
    let stop = std::process::Command::new("bash")
        .arg(&harness)
        .arg("--checkpoint-unavailable")
        .arg("stop")
        .arg(&token)
        .status()?;
    assert!(stop.success());
    let inspect_unavailable =
        tokio::time::timeout(std::time::Duration::from_secs(8), store.inspect_ready()).await;
    let read_unavailable = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        store.read_entry(&fixture.stream_id),
    )
    .await;
    let cas_unavailable = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        store.compare_and_swap(
            &fixture.stream_id,
            fixture.initial_revision,
            &fixture.current.store_state_digest()?,
            &fixture.proposed,
        ),
    )
    .await;
    let start = std::process::Command::new("bash")
        .arg(&harness)
        .arg("--checkpoint-unavailable")
        .arg("start")
        .arg(&token)
        .status()?;
    assert!(start.success());
    let inspect_result = match inspect_unavailable {
        Ok(Err(WitnessStoreErrorV1::Unavailable)) => {
            json!({"result": "err", "error": "unavailable"})
        }
        other => {
            return Err(io::Error::other(format!("inspect result differed: {other:?}")).into());
        }
    };
    let read_result = match read_unavailable {
        Ok(Err(WitnessStoreErrorV1::Unavailable)) => {
            json!({"result": "err", "error": "unavailable"})
        }
        other => return Err(io::Error::other(format!("read result differed: {other:?}")).into()),
    };
    let cas_result = match cas_unavailable {
        Ok(Err(WitnessStoreErrorV1::Unavailable)) => {
            json!({"result": "err", "error": "unavailable"})
        }
        other => return Err(io::Error::other(format!("CAS result differed: {other:?}")).into()),
    };
    ledger.record(
        "unavailable_account_iterator",
        None,
        json!({
            "stream_name": fixture.ready.bucket_configuration.stream_name,
            "bucket_name": "phase285_c_account",
            "stream_id": fixture.stream_id,
            "foreign_result": foreign_result,
            "rogue_sequence": rogue_ack.sequence,
            "iterator_result": iterator_result,
            "inspect_result": inspect_result,
            "read_result": read_result,
            "cas_result": cas_result,
        }),
    )?;
    ledger.finish()?;
    Ok(())
}

#[tokio::test]
async fn jetstream_checkpoint_uses_global_revision_not_store_generation() -> TestResult {
    let mut ledger =
        CheckpointLedger::new("jetstream_checkpoint_uses_global_revision_not_store_generation")?;
    let fixture = live_fixture("phase285_c_global", InitialHeader::Put).await?;
    let store = NatsWitnessStore::open(
        fixture.context.clone(),
        fixture.ready.clone(),
        NATS_VERSION,
        NATS_IMAGE,
    )
    .await?;
    let noise_subject = "$KV.phase285_c_global.noise".to_string();
    let mut previous = 0;
    let mut noise_sequences = Vec::new();
    for index in 0..10_u8 {
        let ack = fixture
            .context
            .publish_with_headers(
                noise_subject.clone(),
                exact_put_headers(
                    &fixture.ready.bucket_configuration.stream_name,
                    previous,
                    InitialHeader::Put,
                ),
                vec![index].into(),
            )
            .await?
            .await?;
        previous = ack.sequence;
        noise_sequences.push(ack.sequence);
    }
    let result = store
        .compare_and_swap(
            &fixture.stream_id,
            fixture.initial_revision,
            &fixture.current.store_state_digest()?,
            &fixture.proposed,
        )
        .await?;
    let WitnessStoreCasResultV1::Applied {
        stream_id,
        expected_previous_revision,
        previous_revision,
        new_revision,
        acknowledged_value_digest,
        duplicate,
    } = result
    else {
        return Err(io::Error::other("cross-key CAS was not applied").into());
    };
    assert!(new_revision > previous);
    assert_eq!(fixture.proposed.store_generation, 1);
    assert_ne!(new_revision, fixture.proposed.store_generation);
    assert_ne!(new_revision, fixture.initial_revision + 1);
    let final_read = store.read_entry(&fixture.stream_id).await?;
    let (final_stream_id, final_revision, final_envelope) = final_read.parts();
    assert_eq!(final_stream_id, fixture.stream_id);
    assert_eq!(final_revision, new_revision);
    assert_eq!(final_envelope, &fixture.proposed);
    ledger.record(
        "global_revision",
        None,
        json!({
            "stream_id": stream_id,
            "initial_revision": fixture.initial_revision,
            "noise_sequences": noise_sequences,
            "noise_last_sequence": previous,
            "expected_previous_revision": expected_previous_revision,
            "previous_revision": previous_revision,
            "new_revision": new_revision,
            "acknowledged_digest": acknowledged_value_digest,
            "proposed_digest": fixture.proposed.signed_envelope_digest()?,
            "duplicate": duplicate,
            "store_generation": fixture.proposed.store_generation,
            "initial_plus_one": fixture.initial_revision + 1,
            "final_read_revision": final_revision,
            "final_read_digest": final_envelope.signed_envelope_digest()?,
        }),
    )?;
    ledger.finish()?;
    Ok(())
}
