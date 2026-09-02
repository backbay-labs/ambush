use super::*;
use crate::persistence_protocol::*;
use swarm_crypto::{DetachedSignature, Ed25519Signer, sha256_hex};

#[test]
fn signed_empty_envelope_binds_namespace_and_generation() -> ProtocolResult<()> {
    let envelope = signed_empty_envelope(0)?;
    envelope.validate()?;

    let digest = envelope.store_state_digest()?;
    let mut changed = envelope.clone();
    changed.bucket_epoch_digest = "9".repeat(64);
    assert_ne!(changed.store_state_digest()?, digest);
    assert!(changed.validate().is_err());

    let mut changed = envelope.clone();
    changed.store_generation = 1;
    assert!(changed.validate().is_err());
    Ok(())
}

#[test]
fn stream_key_is_fixed_domain_hash_not_a_client_token() -> ProtocolResult<()> {
    let first = witness_stream_key("tom-primary")?;
    let mut expected_material = WITNESS_STORE_DOMAIN_V1.to_vec();
    expected_material.extend_from_slice(b"tom-primary");
    assert_eq!(first, format!("s.{}", sha256_hex(&expected_material)));
    assert_eq!(first, witness_stream_key("tom-primary")?);
    assert!(first.starts_with("s."));
    assert_eq!(first.len(), 66);
    assert!(!first.contains("tom-primary"));
    assert_ne!(first, witness_stream_key("tom-secondary")?);
    assert!(witness_stream_key("").is_err());
    Ok(())
}

#[test]
fn genesis_abort_is_singular_and_can_authorize_exact_next_prepare() -> ProtocolResult<()> {
    let established = rotate_session(&signed_empty_envelope(0)?, false)?;
    let prepared = prepare(&established, candidate_after(None, 1)?)?;
    let aborted = abort(&prepared)?;
    assert_eq!(
        validate_transition(&prepared, &aborted)?,
        WitnessStoreTransitionV1::Abort
    );
    assert!(aborted.current.is_none());
    assert!(aborted.predecessor.is_none());
    assert!(aborted.genesis_abort.is_some());

    let prepared_after_abort = prepare_after_genesis_abort(&aborted, 2)?;
    assert_eq!(
        validate_transition(&aborted, &prepared_after_abort)?,
        WitnessStoreTransitionV1::Prepare
    );
    assert!(prepared_after_abort.genesis_abort.is_none());
    let committed = commit(&prepared_after_abort)?;
    assert_eq!(
        validate_transition(&prepared_after_abort, &committed)?,
        WitnessStoreTransitionV1::Commit
    );
    committed.validate()?;
    Ok(())
}

#[test]
fn retained_abort_summary_recomputes_transaction_identity_and_successor_coordinates()
-> ProtocolResult<()> {
    let established = rotate_session(&signed_empty_envelope(0)?, false)?;
    let prepared = prepare(&established, candidate_after(None, 1)?)?;
    let committed = commit(&prepared)?;
    let successor = candidate_after(
        Some(
            committed
                .current
                .as_ref()
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                .head
                .clone(),
        ),
        2,
    )?;
    let aborted = abort(&prepare(&committed, successor)?)?;

    for mutation in 0..5 {
        let mut changed = aborted.clone();
        let summary = match changed
            .current
            .as_mut()
            .and_then(|current| current.head.last_intent_outcome.as_mut())
        {
            Some(WitnessIntentOutcomeV1::Aborted(summary)) => summary,
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        };
        match mutation {
            0 => summary.txid = "0".repeat(64),
            1 => summary.candidate_digest = "1".repeat(64),
            2 => summary.predecessor_head_digest = "2".repeat(64),
            3 => summary.epoch = summary.epoch.saturating_add(1),
            4 => summary.sequence = summary.sequence.saturating_add(1),
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        }
        assert!(resign(changed).is_err(), "mutation {mutation} survived");
    }
    Ok(())
}

#[test]
fn genesis_abort_identity_is_recomputed_before_retention_or_reuse() -> ProtocolResult<()> {
    let established = rotate_session(&signed_empty_envelope(0)?, false)?;
    let prepared = prepare(&established, candidate_after(None, 1)?)?;
    let aborted = abort(&prepared)?;

    for mutation in 0..2 {
        let mut changed = aborted.clone();
        let receipt = changed
            .genesis_abort
            .as_mut()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        if mutation == 0 {
            receipt.txid = "0".repeat(64);
        } else {
            receipt.candidate_digest = "1".repeat(64);
        }
        assert!(resign(changed).is_err(), "top-level mutation survived");
    }

    let prepared_after_abort = prepare_after_genesis_abort(&aborted, 2)?;
    for mutation in 0..2 {
        let mut changed = prepared_after_abort.clone();
        let receipt = changed
            .prepared
            .as_mut()
            .and_then(|prepared| prepared.prepared.genesis_abort.as_mut())
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        if mutation == 0 {
            receipt.txid = "0".repeat(64);
        } else {
            receipt.candidate_digest = "1".repeat(64);
        }
        assert!(resign(changed).is_err(), "nested mutation survived");
    }
    Ok(())
}

#[test]
fn no_op_and_generation_skip_are_not_store_transitions() -> ProtocolResult<()> {
    let previous = signed_empty_envelope(0)?;
    let established = rotate_session(&previous, false)?;

    let mut proposed = established.clone();
    proposed.store_generation += 1;
    let proposed = resign(proposed)?;
    assert!(validate_transition(&established, &proposed).is_err());

    let mut skipped = established.clone();
    skipped.store_generation += 2;
    let skipped = resign(skipped)?;
    assert!(validate_transition(&established, &skipped).is_err());
    Ok(())
}

#[test]
fn generation_zero_is_the_exact_empty_initialization_state() -> ProtocolResult<()> {
    let initialized = signed_empty_envelope(0)?;
    initialized.validate()?;

    let established = rotate_session(&initialized, false)?;
    let mut forged_zero = established;
    forged_zero.store_generation = 0;
    assert!(resign(forged_zero).is_err());
    Ok(())
}

#[test]
fn store_and_session_generation_overflow_fail_closed() -> ProtocolResult<()> {
    let established = rotate_session(&signed_empty_envelope(0)?, false)?;

    let mut exhausted_store = established.clone();
    exhausted_store.store_generation = u64::MAX;
    let exhausted_store = resign(exhausted_store)?;
    let mut proposed_store = established.clone();
    proposed_store.store_generation = 1;
    let proposed_store = resign(proposed_store)?;
    assert!(matches!(
        validate_transition(&exhausted_store, &proposed_store),
        Err(ProtocolError::Overflow {
            counter: "store_generation"
        })
    ));

    let mut exhausted_session = established.clone();
    exhausted_session
        .session
        .as_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .session_generation = u64::MAX;
    let mut proposed_session = established;
    proposed_session
        .session
        .as_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .session_generation = 1;
    assert!(matches!(
        is_session_rotation(&exhausted_session, &proposed_session),
        Err(ProtocolError::Overflow {
            counter: "session_generation"
        })
    ));
    Ok(())
}

#[test]
fn reference_lifecycle_accepts_only_exact_single_step_transitions() -> ProtocolResult<()> {
    let empty = signed_empty_envelope(0)?;
    let established = rotate_session(&empty, false)?;
    assert_eq!(
        validate_transition(&empty, &established)?,
        WitnessStoreTransitionV1::RotateSession
    );

    let genesis = candidate_after(None, 1)?;
    let prepared = prepare(&established, genesis)?;
    assert_eq!(
        validate_transition(&established, &prepared)?,
        WitnessStoreTransitionV1::Prepare
    );

    let committed = commit(&prepared)?;
    assert_eq!(
        validate_transition(&prepared, &committed)?,
        WitnessStoreTransitionV1::Commit
    );

    let successor = candidate_after(
        Some(
            committed
                .current
                .as_ref()
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                .head
                .clone(),
        ),
        2,
    )?;
    let prepared_successor = prepare(&committed, successor)?;
    let rotated_prepared = rotate_session(&prepared_successor, true)?;
    assert_eq!(
        validate_transition(&prepared_successor, &rotated_prepared)?,
        WitnessStoreTransitionV1::RotateSession
    );
    let aborted = abort(&rotated_prepared)?;
    assert_eq!(
        validate_transition(&rotated_prepared, &aborted)?,
        WitnessStoreTransitionV1::Abort
    );
    aborted.validate()?;
    Ok(())
}

#[test]
fn envelope_rejects_payload_predecessor_and_namespace_substitution() -> ProtocolResult<()> {
    let established = rotate_session(&signed_empty_envelope(0)?, false)?;
    let prepared = prepare(&established, candidate_after(None, 1)?)?;
    let committed = commit(&prepared)?;

    let mut changed = committed.clone();
    changed
        .current
        .as_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .candidate
        .state_payload = br#"{"state":99}"#.to_vec();
    assert!(resign(changed).is_err());

    let successor = candidate_after(
        Some(
            committed
                .current
                .as_ref()
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                .head
                .clone(),
        ),
        2,
    )?;
    let prepared_successor = prepare(&committed, successor)?;

    let mut removed_current = prepared_successor.clone();
    removed_current.current = None;
    assert!(resign(removed_current).is_err());

    let mut changed_namespace = prepared_successor.clone();
    changed_namespace.admission_digest = "8".repeat(64);
    let changed_namespace = resign(changed_namespace)?;
    assert!(validate_transition(&committed, &changed_namespace).is_err());
    Ok(())
}

#[test]
fn transition_rejects_combined_rotation_prepare_and_forged_rotation_snapshot() -> ProtocolResult<()>
{
    let empty = signed_empty_envelope(0)?;
    let established = rotate_session(&empty, false)?;
    let prepared = prepare(&established, candidate_after(None, 1)?)?;

    let rotated = rotate_session(&empty, false)?;
    let candidate = candidate_after(None, 1)?;
    let built = candidate.build()?;
    let session = rotated
        .session
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    let mut combined = rotated.clone();
    combined.prepared = Some(WitnessStoredPreparedV1 {
        prepared: WitnessPreparedV1::from_candidate(&built, None, session.session_generation)?,
        candidate,
    });
    combined.store_generation = 1;
    let combined = resign(combined)?;
    assert!(validate_transition(&empty, &combined).is_err());

    let mut bad_snapshot = rotate_session(&prepared, true)?;
    bad_snapshot
        .last_session_rotation
        .as_mut()
        .and_then(|receipt| receipt.discovery_snapshot.as_mut())
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .prepared = None;
    let bad_snapshot = resign(bad_snapshot)?;
    assert!(validate_transition(&prepared, &bad_snapshot).is_err());
    Ok(())
}

#[test]
fn signed_wire_round_trip_rejects_unknown_fields_and_wrong_expectation() -> ProtocolResult<()> {
    let envelope = signed_empty_envelope(0)?;
    let admitted = binding()?;
    let bytes = envelope.canonical_bytes()?;
    assert_eq!(WitnessStoreEnvelopeV1::decode(&bytes)?, envelope);

    let mut value = serde_json::to_value(&envelope)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    value
        .as_object_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .insert("terminal_history".to_string(), serde_json::json!([]));
    assert!(WitnessStoreEnvelopeV1::decode(&canonical_wire_bytes(&value)?).is_err());

    assert!(
        envelope
            .validate_for(WitnessStoreExpectationV1 {
                admission_digest: &"9".repeat(64),
                bucket_epoch_digest: &envelope.bucket_epoch_digest,
                stream_initialization_digest: &envelope.stream_initialization_digest,
                stream_id: &envelope.stream_id,
                witness_identity: &envelope.witness_identity,
                witness_key_id: &envelope.witness_key_id,
                authority_pair: admitted.authority_pair,
                binding_generation: &admitted.generation,
                binding_digest: &admitted.binding_digest,
                signer_key_id: &admitted.signer_key_id,
            })
            .is_err()
    );

    let established = rotate_session(&envelope, false)?;
    let mut wrong_authority = admitted.authority_pair;
    wrong_authority.current.inode += 100;
    wrong_authority.legacy.inode += 100;
    assert!(
        established
            .validate_for(WitnessStoreExpectationV1 {
                admission_digest: &established.admission_digest,
                bucket_epoch_digest: &established.bucket_epoch_digest,
                stream_initialization_digest: &established.stream_initialization_digest,
                stream_id: &established.stream_id,
                witness_identity: &established.witness_identity,
                witness_key_id: &established.witness_key_id,
                authority_pair: wrong_authority,
                binding_generation: &admitted.generation,
                binding_digest: &admitted.binding_digest,
                signer_key_id: &admitted.signer_key_id,
            })
            .is_err()
    );
    Ok(())
}

fn witness_signer() -> Ed25519Signer {
    Ed25519Signer::from_secret_material("phase-285-witness-store-envelope")
}

fn validate_transition(
    previous: &WitnessStoreEnvelopeV1,
    proposed: &WitnessStoreEnvelopeV1,
) -> ProtocolResult<WitnessStoreTransitionV1> {
    let admitted = binding()?;
    validate_store_transition(
        previous,
        proposed,
        WitnessStoreExpectationV1 {
            admission_digest: &previous.admission_digest,
            bucket_epoch_digest: &previous.bucket_epoch_digest,
            stream_initialization_digest: &previous.stream_initialization_digest,
            stream_id: &previous.stream_id,
            witness_identity: &previous.witness_identity,
            witness_key_id: &previous.witness_key_id,
            authority_pair: admitted.authority_pair,
            binding_generation: &admitted.generation,
            binding_digest: &admitted.binding_digest,
            signer_key_id: &admitted.signer_key_id,
        },
    )
}

fn placeholder_signature() -> swarm_crypto::DetachedSignature {
    witness_signer().sign(&[])
}

fn signed_empty_envelope(generation: u64) -> ProtocolResult<WitnessStoreEnvelopeV1> {
    let signer = witness_signer();
    let envelope = WitnessStoreEnvelopeV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        admission_digest: "1".repeat(64),
        bucket_epoch_digest: "2".repeat(64),
        stream_initialization_digest: "3".repeat(64),
        stream_id: "tom-primary".to_string(),
        witness_identity: "witness-1".to_string(),
        witness_key_id: signer.key_id().to_string(),
        session: None,
        last_session_rotation: None,
        current: None,
        predecessor: None,
        prepared: None,
        genesis_abort: None,
        store_generation: generation,
        signature: placeholder_signature(),
    };
    let signature = signer.sign(&envelope.signing_bytes()?);
    envelope.seal_with_signature(signature)
}

fn resign(mut envelope: WitnessStoreEnvelopeV1) -> ProtocolResult<WitnessStoreEnvelopeV1> {
    let signer = witness_signer();
    envelope.signature = signer.sign(&envelope.signing_bytes()?);
    envelope.validate()?;
    Ok(envelope)
}

fn governance_signer() -> Ed25519Signer {
    Ed25519Signer::from_secret_material("phase-285-witness-store-governance")
}

fn authority() -> AuthorityPairIdentityV1 {
    AuthorityPairIdentityV1 {
        current: ArtifactIdentityV1 {
            device: 1,
            inode: 1,
        },
        legacy: ArtifactIdentityV1 {
            device: 1,
            inode: 1,
        },
    }
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

fn initial_mapping() -> PublicationMappingV1 {
    let roles = roles();
    PublicationMappingV1 {
        state_canonical: roles.state_canonical,
        state_staging: roles.state_staging,
        checkpoint_canonical: roles.checkpoint_canonical,
        checkpoint_staging: roles.checkpoint_staging,
        journal_primary: roles.journal_primary,
        journal_secondary: roles.journal_secondary,
    }
}

fn successor_mapping(before: PublicationMappingV1) -> PublicationMappingV1 {
    PublicationMappingV1 {
        state_canonical: before.state_staging,
        state_staging: before.state_canonical,
        checkpoint_canonical: before.checkpoint_staging,
        checkpoint_staging: before.checkpoint_canonical,
        journal_primary: before.journal_primary,
        journal_secondary: before.journal_secondary,
    }
}

fn binding() -> ProtocolResult<PublicationBindingV1> {
    let signer = governance_signer();
    let cleanup_slot_names = (0..FIXED_CLEANUP_SLOT_COUNT)
        .map(|index| format!("slot-{index:02}"))
        .collect::<Vec<_>>();
    let cleanup_slot_identities = (11..(11 + FIXED_CLEANUP_SLOT_COUNT as u64))
        .map(|inode| ArtifactIdentityV1 { device: 2, inode })
        .collect::<Vec<_>>();
    let mut binding = PublicationBindingV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: "tom-primary".to_string(),
        generation: "b".repeat(64),
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
        authority_pair: authority(),
        publication_roles: roles(),
        cleanup_slot_count: FIXED_CLEANUP_SLOT_COUNT as u32,
        cleanup_slot_names,
        cleanup_slot_identities,
        limits: ProtocolLimitsV1::default(),
        signer_key_id: signer.key_id().to_string(),
        witness_key_id: witness_signer().key_id().to_string(),
        witness_identity: "witness-1".to_string(),
        binding_digest: "0".repeat(64),
        binding_signature: signer.sign(&[]),
    };
    let signing_bytes = binding.signing_bytes()?;
    binding.binding_digest = binding.computed_digest()?;
    binding.binding_signature = signer.sign(&signing_bytes);
    binding.validate()?;
    Ok(binding)
}

fn sign_payload(
    signer: &Ed25519Signer,
    domain: &str,
    binding: &PublicationBindingV1,
    payload: Vec<u8>,
    digest: String,
) -> DetachedSignature {
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
    signer.sign(&preimage.canonical_bytes().unwrap_or_default())
}

fn candidate_after(
    predecessor: Option<WitnessHeadV1>,
    payload_version: u64,
) -> ProtocolResult<CandidatePreimageV1> {
    let binding = binding()?;
    let before = predecessor
        .as_ref()
        .map_or_else(initial_mapping, |head| head.publication_mapping);
    let after = successor_mapping(before);
    let (predecessor_head_digest, predecessor_data_head_digest, epoch, sequence, intent) =
        match &predecessor {
            Some(head) => (
                head.head_digest()?,
                head.data_head_digest()?,
                head.epoch,
                head.sequence
                    .checked_add(1)
                    .ok_or(ProtocolError::Overflow {
                        counter: "test_sequence",
                    })?,
                head.intent_counter
                    .checked_add(1)
                    .ok_or(ProtocolError::Overflow {
                        counter: "test_intent",
                    })?,
            ),
            None => {
                let genesis = GenesisPredecessorV1::for_binding(&binding);
                (genesis.digest()?, genesis.data_head_digest()?, 0, 0, 1)
            }
        };
    let state_payload = format!("{{\"state\":{payload_version}}}").into_bytes();
    let checkpoint_payload = format!("{{\"checkpoint\":{payload_version}}}").into_bytes();
    let state_digest = sha256_hex(&state_payload);
    let checkpoint_digest = sha256_hex(&checkpoint_payload);
    let signer = governance_signer();
    let candidate = CandidatePreimageV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: binding.stream_id.clone(),
        predecessor_head: predecessor,
        predecessor_head_digest,
        predecessor_data_head_digest,
        state_payload: state_payload.clone(),
        state_byte_len: state_payload.len() as u64,
        state_digest: state_digest.clone(),
        state_attestation: sign_payload(
            &signer,
            STATE_PAYLOAD_DOMAIN_V1,
            &binding,
            state_payload,
            state_digest,
        ),
        checkpoint_payload: checkpoint_payload.clone(),
        checkpoint_byte_len: checkpoint_payload.len() as u64,
        checkpoint_digest: checkpoint_digest.clone(),
        checkpoint_attestation: sign_payload(
            &signer,
            CHECKPOINT_PAYLOAD_DOMAIN_V1,
            &binding,
            checkpoint_payload,
            checkpoint_digest,
        ),
        publication_binding: binding,
        publication_mapping_before: before,
        publication_mapping_after: after,
        epoch,
        sequence,
        intent_counter: intent,
    };
    candidate.validate()?;
    Ok(candidate)
}

fn prepare(
    previous: &WitnessStoreEnvelopeV1,
    candidate: CandidatePreimageV1,
) -> ProtocolResult<WitnessStoreEnvelopeV1> {
    let built = candidate.build()?;
    let session_generation = previous
        .session
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .session_generation;
    let prepared = WitnessPreparedV1::from_candidate(
        &built,
        previous
            .current
            .as_ref()
            .map(|current| current.head.clone()),
        session_generation,
    )?;
    let mut proposed = previous.clone();
    proposed.prepared = Some(WitnessStoredPreparedV1 {
        candidate,
        prepared,
    });
    proposed.genesis_abort = None;
    proposed.store_generation += 1;
    resign(proposed)
}

fn prepare_after_genesis_abort(
    previous: &WitnessStoreEnvelopeV1,
    payload_version: u64,
) -> ProtocolResult<WitnessStoreEnvelopeV1> {
    let aborted = previous
        .genesis_abort
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    let mut candidate = candidate_after(None, payload_version)?;
    candidate.intent_counter =
        aborted
            .intent_counter
            .checked_add(1)
            .ok_or(ProtocolError::Overflow {
                counter: "test_intent",
            })?;
    candidate.validate()?;
    let built = candidate.build()?;
    let session_generation = previous
        .session
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .session_generation;
    let prepared = WitnessPreparedV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        predecessor_head: None,
        head: WitnessHeadV1::from_candidate(&built)?,
        predecessor_head_digest: candidate.predecessor_head_digest.clone(),
        predecessor_data_head_digest: candidate.predecessor_data_head_digest.clone(),
        binding_digest: candidate.publication_binding.binding_digest.clone(),
        predecessor_publication_mapping: candidate.publication_mapping_before,
        session_generation,
        genesis_abort: Some(aborted.clone()),
    };
    prepared.validate()?;
    let mut proposed = previous.clone();
    proposed.prepared = Some(WitnessStoredPreparedV1 {
        candidate,
        prepared,
    });
    proposed.genesis_abort = None;
    proposed.store_generation += 1;
    resign(proposed)
}

fn commit(previous: &WitnessStoreEnvelopeV1) -> ProtocolResult<WitnessStoreEnvelopeV1> {
    let prepared = previous
        .prepared
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    let current = WitnessStoredCandidateV1 {
        candidate: prepared.candidate.clone(),
        head: WitnessHeadV1::committed_from_candidate(&prepared.candidate.build()?)?,
    };
    let mut proposed = previous.clone();
    proposed.predecessor = previous.current.clone();
    proposed.current = Some(current);
    proposed.prepared = None;
    proposed.store_generation += 1;
    resign(proposed)
}

fn abort(previous: &WitnessStoreEnvelopeV1) -> ProtocolResult<WitnessStoreEnvelopeV1> {
    let prepared = previous
        .prepared
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    let mut proposed = previous.clone();
    proposed.prepared = None;
    match &previous.current {
        Some(current) => {
            let head = &prepared.prepared.head;
            let mut resulting_head = current.head.clone();
            resulting_head.intent_counter = head.intent_counter;
            resulting_head.last_intent_outcome = Some(WitnessIntentOutcomeV1::Aborted(Box::new(
                WitnessAbortSummaryV1 {
                    txid: head.txid.clone(),
                    candidate_digest: head.candidate_digest.clone(),
                    predecessor_head_digest: prepared.prepared.predecessor_head_digest.clone(),
                    epoch: head.epoch,
                    sequence: head.sequence,
                    intent_counter: head.intent_counter,
                    binding_generation: head.binding_generation.clone(),
                    binding_digest: head.binding_digest.clone(),
                    signer_key_id: head.signer_key_id.clone(),
                    witness_key_id: head.witness_key_id.clone(),
                    authority_pair: head.authority_pair,
                    publication_mapping: prepared.prepared.predecessor_publication_mapping,
                    resulting_data_head_digest: current.head.data_head_digest()?,
                },
            )));
            resulting_head.validate_settled()?;
            proposed.current = Some(WitnessStoredCandidateV1 {
                candidate: current.candidate.clone(),
                head: resulting_head,
            });
        }
        None => {
            proposed.genesis_abort = Some(WitnessGenesisAbortedV1::from_prepared(
                &prepared.prepared,
                "test abort".to_string(),
            )?);
        }
    }
    proposed.store_generation += 1;
    resign(proposed)
}

fn rotate_session(
    previous: &WitnessStoreEnvelopeV1,
    discover: bool,
) -> ProtocolResult<WitnessStoreEnvelopeV1> {
    let binding = binding()?;
    let governance = governance_signer();
    let witness = witness_signer();
    let mut fence_request = WitnessSessionFenceRequestV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: binding.stream_id.clone(),
        authority_pair: binding.authority_pair,
        binding_generation: binding.generation.clone(),
        binding_digest: binding.binding_digest.clone(),
        signer_key_id: binding.signer_key_id.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        witness_identity: binding.witness_identity.clone(),
        requester_nonce: "4".repeat(64),
        signature: governance.sign(&[]),
    };
    fence_request.signature = governance.sign(&fence_request.signing_bytes()?);

    let snapshot = WitnessSessionStateSnapshotV1 {
        admission_digest: previous.admission_digest.clone(),
        bucket_epoch_digest: previous.bucket_epoch_digest.clone(),
        bucket_anchor_digest: "5".repeat(64),
        ready_manifest_digest: "6".repeat(64),
        store_state_digest: previous.store_state_digest()?,
        current_session: previous.session.clone(),
        current_head: previous
            .current
            .as_ref()
            .map(|current| current.head.clone()),
        current_prepared: previous
            .prepared
            .as_ref()
            .map(|prepared| prepared.prepared.clone()),
    };
    snapshot.validate()?;
    let current_session_digest = snapshot
        .current_session
        .as_ref()
        .map(|session| {
            digest_domain(
                WITNESS_SESSION_STATE_DOMAIN_V1,
                &canonical_wire_bytes(session)?,
            )
        })
        .transpose()?;
    let current_prepared_digest = snapshot
        .current_prepared
        .as_ref()
        .map(|prepared| {
            digest_domain(
                WITNESS_PREPARED_STATE_DOMAIN_V1,
                &canonical_wire_bytes(prepared)?,
            )
        })
        .transpose()?;
    let mut fence = WitnessSessionStateFenceV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        request: fence_request.clone(),
        admission_digest: snapshot.admission_digest.clone(),
        bucket_epoch_digest: snapshot.bucket_epoch_digest.clone(),
        bucket_anchor_digest: snapshot.bucket_anchor_digest.clone(),
        ready_manifest_digest: snapshot.ready_manifest_digest.clone(),
        store_state_digest: snapshot.store_state_digest.clone(),
        current_session_generation: snapshot
            .current_session
            .as_ref()
            .map(|session| session.session_generation),
        current_session_digest,
        current_head_digest: snapshot
            .current_head
            .as_ref()
            .map(WitnessHeadV1::head_digest)
            .transpose()?,
        current_prepared_digest,
        witness_nonce: "7".repeat(64),
        witness_identity: binding.witness_identity.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        signature: witness.sign(&[]),
    };
    fence.signature = witness.sign(&fence.signing_bytes()?);
    fence.verify_for_snapshot(&snapshot)?;

    let generation = fence.expected_session_generation()?;
    let mut challenge = RecoveryChallengeV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: binding.stream_id.clone(),
        authority_pair: binding.authority_pair,
        binding_generation: binding.generation.clone(),
        binding_digest: binding.binding_digest.clone(),
        signer_key_id: binding.signer_key_id.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        witness_identity: binding.witness_identity.clone(),
        state_fence: fence,
        ephemeral_key_id: "8".repeat(64),
        nonce: "9".repeat(64),
        session_commitment: "a".repeat(64),
        signature: governance.sign(&[]),
    };
    challenge.signature = governance.sign(&challenge.signing_bytes()?);
    challenge.validate()?;

    let session = WitnessSessionV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: binding.stream_id.clone(),
        authority_pair: binding.authority_pair,
        binding_generation: binding.generation.clone(),
        binding_digest: binding.binding_digest.clone(),
        signer_key_id: binding.signer_key_id.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        ephemeral_key_id: challenge.ephemeral_key_id.clone(),
        witness_identity: binding.witness_identity,
        session_generation: generation,
        session_commitment: challenge.session_commitment.clone(),
    };

    let mut proposed = previous.clone();
    proposed.session = Some(session.clone());
    if let Some(prepared) = &mut proposed.prepared {
        prepared.prepared.session_generation = generation;
    }
    let request_digest = fence_request.request_digest()?;
    proposed.last_session_rotation = Some(if discover {
        WitnessSessionRotationReceiptV1::for_discovery(
            request_digest,
            &challenge,
            WitnessDiscoveryV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                head: proposed
                    .current
                    .as_ref()
                    .map(|current| current.head.clone()),
                prepared: proposed
                    .prepared
                    .as_ref()
                    .map(|prepared| prepared.prepared.clone()),
                genesis_abort: proposed.genesis_abort.clone(),
                recovery_session: session,
            },
        )?
    } else {
        WitnessSessionRotationReceiptV1::for_establish(
            request_digest,
            &challenge,
            session,
            proposed
                .current
                .as_ref()
                .map(|current| current.head.clone()),
        )?
    });
    proposed.store_generation += 1;
    resign(proposed)
}
