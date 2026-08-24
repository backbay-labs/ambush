use super::*;
use std::collections::BTreeMap;
use swarm_crypto::Ed25519Signer;

#[test]
fn candidate_digest_is_canonical_and_domain_separated() -> ProtocolResult<()> {
    let candidate = sample_candidate();
    candidate.validate()?;
    let first = candidate.candidate_digest()?;
    assert_eq!(first, candidate.candidate_digest()?);
    let mut changed = candidate.clone();
    changed.stream_id.push_str("-changed");
    changed.publication_binding.stream_id = changed.stream_id.clone();
    assert!(changed.candidate_digest().is_err());
    assert_ne!(
        first,
        digest_domain(CANDIDATE_DOMAIN_V1_ALT, &candidate.canonical_bytes()?)?
    );
    Ok(())
}

#[test]
fn candidate_embeds_complete_settled_predecessor_and_rejects_digest_only_mutations()
-> ProtocolResult<()> {
    let candidate = sample_candidate();
    let predecessor = candidate
        .predecessor_head
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    predecessor.validate_settled()?;

    let mut changed_head = candidate.clone();
    changed_head
        .predecessor_head
        .as_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .txid = "f".repeat(64);
    assert!(changed_head.validate().is_err());

    let mut changed_data = candidate.clone();
    changed_data
        .predecessor_head
        .as_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .state_digest = "f".repeat(64);
    assert!(changed_data.validate().is_err());

    let built = candidate.build()?;
    assert!(WitnessPreparedV1::from_candidate(&built, None, 0).is_err());
    assert!(WitnessPreparedV1::from_candidate(&built, Some(predecessor.clone()), 0).is_ok());
    Ok(())
}

#[test]
fn canonical_map_order_and_unknown_fields_are_stable_or_rejected() -> ProtocolResult<()> {
    let mut first = BTreeMap::new();
    first.insert("b", 2_u64);
    first.insert("a", 1_u64);
    let mut second = BTreeMap::new();
    second.insert("a", 1_u64);
    second.insert("b", 2_u64);
    assert_eq!(
        canonical_wire_bytes(&first)?,
        canonical_wire_bytes(&second)?
    );

    let candidate = sample_candidate();
    let mut bytes = candidate.canonical_bytes()?;
    bytes.truncate(bytes.len() - 1);
    bytes.extend_from_slice(b",\"unknown\":true}");
    assert!(decode_canonical::<CandidatePreimageV1>(&bytes).is_err());
    Ok(())
}

#[test]
fn payload_length_and_digest_mutations_are_rejected() {
    let mut candidate = sample_candidate();
    candidate.state_payload = br#"{"state":2}"#.to_vec();
    assert!(candidate.validate().is_err());
    let mut candidate = sample_candidate();
    candidate.checkpoint_byte_len += 1;
    assert!(candidate.validate().is_err());
}

#[test]
fn txid_is_non_circular_and_length_delimited() -> ProtocolResult<()> {
    let candidate = sample_candidate();
    let digest = candidate.candidate_digest()?;
    let txid = candidate.txid(&digest)?;
    assert_eq!(txid, candidate.txid(&digest)?);
    assert_ne!(txid, digest);
    assert_ne!(
        digest_domain(b"domain", b"ab")?,
        digest_domain(b"domain", b"a")?
    );
    assert!(candidate.txid(&"f".repeat(64)).is_err());
    Ok(())
}

#[test]
fn role_aliases_and_authority_aliases_refuse() {
    let mut roles = sample_roles();
    roles.state_staging = roles.state_canonical;
    assert!(matches!(
        roles.validate(),
        Err(ProtocolError::RoleIdentityAlias { .. })
    ));
    let mut authority = sample_authority();
    assert!(authority.validate().is_ok());
    authority.legacy = ArtifactIdentityV1 {
        device: 1,
        inode: 2,
    };
    assert!(matches!(
        authority.validate(),
        Err(ProtocolError::AuthorityPairMismatch)
    ));
}

#[test]
fn checked_counters_and_sizes_fail_closed_at_maximum() {
    assert!(checked_next_epoch(u64::MAX).is_err());
    assert!(checked_next_sequence(u64::MAX).is_err());
    assert!(checked_next_intent(u64::MAX).is_err());
    assert!(checked_next_session(u64::MAX).is_err());
    assert!(checked_next_journal_generation(u64::MAX).is_err());
    assert!(checked_add_size(u64::MAX, 1).is_err());
    assert!(validate_next_intent(9, 9).is_err());
    assert!(validate_next_intent(9, 10).is_ok());
}

#[test]
fn transaction_transitions_and_intent_abort_are_explicit() -> ProtocolResult<()> {
    let candidate = sample_candidate().build()?;
    let record = TransactionRecordV1::intent(TransactionIntentV1::from_candidate(&candidate)?)?;
    let prepared = record.resolve_verified_prepare(&sample_verified_prepare(&record)?)?;
    let staged = prepared.transition(TransactionPhaseV1::PayloadsStaged)?;
    let staged_abort = staged.begin_abort()?;
    assert_eq!(staged_abort.phase, TransactionPhaseV1::AbortPending);
    assert_eq!(staged_abort.intent_counter, record.intent_counter);
    assert_eq!(
        select_recovery_record(
            &[observed_journal(&record)?, observed_journal(&prepared)?,],
            &sample_candidate().publication_binding,
        )?,
        prepared
    );
    assert!(staged.transition(TransactionPhaseV1::Intent).is_err());
    assert!(record.transition(TransactionPhaseV1::Aborted).is_err());
    let pending = record.abort_intent()?;
    assert_eq!(pending.phase, TransactionPhaseV1::AbortPending);
    assert_eq!(pending.intent_counter, record.intent_counter);
    assert!(pending.transition(TransactionPhaseV1::Aborted).is_err());
    assert_eq!(pending.sequence, record.sequence);
    assert!(
        record
            .transition(TransactionPhaseV1::CheckpointExchanged)
            .is_err()
    );
    let ready = staged
        .transition(TransactionPhaseV1::StateExchanged)?
        .transition(TransactionPhaseV1::CheckpointExchanged)?
        .transition(TransactionPhaseV1::ReadyForWitnessCommit)?;
    let verified_commit = sample_verified_commit(&staged)?;
    let committed = ready.resolve_verified_commit(&verified_commit)?;
    assert!(committed.transition(TransactionPhaseV1::Aborted).is_err());
    Ok(())
}

#[test]
fn raw_intent_to_prepared_transition_is_not_authority() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    assert!(
        record
            .transition(TransactionPhaseV1::WitnessPrepared)
            .is_err()
    );
    let committed = WitnessCommittedV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: sample_witness_head(&record, record.publication_mapping_after),
    };
    assert!(
        record
            .resolve_commit_outcome(&WitnessCommitOutcomeV1::Committed(committed.clone()))
            .is_err()
    );
    let aborted = sample_witness_abort(&record)?;
    assert!(
        record
            .resolve_abort_outcome(&WitnessAbortOutcomeV1::Aborted(aborted))
            .is_err()
    );
    let discovery = WitnessDiscoveryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: Some(committed.head),
        prepared: None,
        genesis_abort: None,
        recovery_session: sample_session(&record),
    };
    assert!(record.resolve_discovery(&discovery).is_err());

    let accepted = record.resolve_verified_prepare(&sample_verified_prepare(&record)?)?;
    assert_eq!(accepted.phase, TransactionPhaseV1::WitnessPrepared);
    assert!(accepted.witness_prepared_attestation.is_some());
    Ok(())
}

#[test]
fn signed_prepare_conflict_cannot_survive_journal_selection() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let conflict = sample_verified_outcome(
        &record,
        WitnessOperationV1::Prepare,
        WitnessOperationOutcomeV1::Prepare(Box::new(WitnessPrepareOutcomeV1::Conflict)),
    )?;
    assert_prepared_attestation_not_recoverable(&record, conflict.attestation().clone())
}

#[test]
fn signed_prepare_predecessor_head_mapping_and_head_mismatches_cannot_survive_recovery()
-> ProtocolResult<()> {
    let record = sample_transaction_record()?;

    let mut changed_predecessor = sample_witness_prepared(&record)?;
    let predecessor = changed_predecessor
        .predecessor_head
        .as_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    predecessor.state_digest = "f".repeat(64);
    changed_predecessor.predecessor_head_digest = predecessor.head_digest()?;
    changed_predecessor.predecessor_data_head_digest = predecessor.data_head_digest()?;
    changed_predecessor.validate()?;
    let changed_predecessor_attestation = sample_verified_outcome(
        &record,
        WitnessOperationV1::Prepare,
        WitnessOperationOutcomeV1::Prepare(Box::new(WitnessPrepareOutcomeV1::Prepared(
            changed_predecessor,
        ))),
    )?;
    assert_prepared_attestation_not_recoverable(
        &record,
        changed_predecessor_attestation.attestation().clone(),
    )?;

    let mut changed_head = sample_witness_prepared(&record)?;
    changed_head.head.state_digest = "e".repeat(64);
    changed_head.validate()?;
    let changed_head_attestation = sample_verified_outcome(
        &record,
        WitnessOperationV1::Prepare,
        WitnessOperationOutcomeV1::Prepare(Box::new(WitnessPrepareOutcomeV1::Prepared(
            changed_head,
        ))),
    )?;
    assert_prepared_attestation_not_recoverable(
        &record,
        changed_head_attestation.attestation().clone(),
    )?;

    let mut changed_mapping = sample_witness_prepared(&record)?;
    let alternate_predecessor_mapping = sample_mapping_after();
    let alternate_successor_mapping = sample_mapping_before();
    let predecessor = changed_mapping
        .predecessor_head
        .as_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    predecessor.publication_mapping = alternate_predecessor_mapping;
    changed_mapping.predecessor_publication_mapping = alternate_predecessor_mapping;
    changed_mapping.head.publication_mapping = alternate_successor_mapping;
    changed_mapping.predecessor_head_digest = predecessor.head_digest()?;
    changed_mapping.predecessor_data_head_digest = predecessor.data_head_digest()?;
    changed_mapping.validate()?;
    let changed_mapping_attestation = sample_verified_outcome(
        &record,
        WitnessOperationV1::Prepare,
        WitnessOperationOutcomeV1::Prepare(Box::new(WitnessPrepareOutcomeV1::Prepared(
            changed_mapping,
        ))),
    )?;
    assert_prepared_attestation_not_recoverable(
        &record,
        changed_mapping_attestation.attestation().clone(),
    )?;
    Ok(())
}

#[test]
fn signed_journal_envelope_rejects_tamper_wrong_signer_and_namespace_replay() -> ProtocolResult<()>
{
    let record = sample_transaction_record()?;
    let prepared = record.resolve_verified_prepare(&sample_verified_prepare(&record)?)?;
    let envelope = signed_journal(&prepared)?;

    let mut tampered = envelope.clone();
    tampered.record.sequence = checked_next_sequence(tampered.record.sequence)?;
    assert!(tampered.validate_structure().is_err());

    let mut wrong_signer = envelope.clone();
    wrong_signer.signature = sample_witness_signer().sign(&wrong_signer.signing_bytes()?);
    assert!(wrong_signer.validate_structure().is_err());

    let mut foreign = envelope;
    foreign.stream_id.push_str("-foreign");
    foreign.signature = sample_signer().sign(&foreign.signing_bytes()?);
    assert!(foreign.validate_structure().is_err());
    Ok(())
}

#[test]
fn journal_validation_requires_the_current_verified_publication_binding() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let binding = sample_candidate().publication_binding;
    let envelope = signed_journal(&record)?;
    assert!(envelope.validate_against_binding(&binding).is_ok());

    let signer = sample_signer();
    let mut foreign_binding = binding.clone();
    foreign_binding.generation = "f".repeat(64);
    foreign_binding.binding_digest = foreign_binding.computed_digest()?;
    foreign_binding.binding_signature = signer.sign(&foreign_binding.signing_bytes()?);
    foreign_binding.validate()?;
    assert!(envelope.validate_against_binding(&foreign_binding).is_err());

    let first = observed_journal(&record)?;
    let second =
        observed_journal(&record.resolve_verified_prepare(&sample_verified_prepare(&record)?)?)?;
    assert!(validate_recovery_pair(&first, &second, &binding).is_ok());
    assert!(select_recovery_record(&[first, second], &binding).is_ok());
    Ok(())
}

#[test]
fn recovery_requires_exact_two_distinct_anchored_lane_observations() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let binding = sample_candidate().publication_binding;
    let prepared = record.resolve_verified_prepare(&sample_verified_prepare(&record)?)?;
    let first = observed_journal(&record)?;
    let second = observed_journal(&prepared)?;
    assert!(select_recovery_record(std::slice::from_ref(&first), &binding,).is_err());

    let mut duplicate_lane = second.clone();
    duplicate_lane.observed_lane = first.observed_lane;
    assert!(select_recovery_record(&[first.clone(), duplicate_lane], &binding).is_err());

    let mut non_root = first.envelope.record.clone();
    non_root.phase = TransactionPhaseV1::WitnessPrepared;
    non_root.journal_generation = 1;
    non_root.previous_record_digest = Some(first.envelope.record_digest.clone());
    non_root.witness_prepared_attestation =
        second.envelope.record.witness_prepared_attestation.clone();
    non_root.journal_lane = second.envelope.journal_lane;
    non_root.validate()?;
    let non_root = observed_journal(&non_root)?;
    assert!(select_recovery_record(&[non_root.clone(), second], &binding).is_err());
    Ok(())
}

#[test]
fn prepared_head_digest_is_not_committed_successor_digest() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let prepared = sample_witness_prepared(&record)?;
    assert_ne!(
        record.witness_successor_head_digest,
        prepared.head.head_digest()?
    );
    Ok(())
}

#[test]
fn prepared_validation_rejects_unsettled_predecessor_and_mixed_genesis_receipt()
-> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let prepared = sample_witness_prepared(&record)?;

    let mut unsettled = prepared.clone();
    let predecessor = unsettled
        .predecessor_head
        .as_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    predecessor.last_intent_outcome = None;
    unsettled.predecessor_head_digest = predecessor.head_digest()?;
    unsettled.predecessor_data_head_digest = predecessor.data_head_digest()?;
    assert!(unsettled.validate().is_err());

    let mut genesis_preimage = sample_candidate();
    let genesis = GenesisPredecessorV1::for_binding(&genesis_preimage.publication_binding);
    genesis_preimage.predecessor_head = None;
    genesis_preimage.predecessor_head_digest = genesis.digest()?;
    genesis_preimage.predecessor_data_head_digest = genesis.data_head_digest()?;
    genesis_preimage.epoch = 0;
    genesis_preimage.sequence = 0;
    genesis_preimage.intent_counter = 1;
    let genesis_candidate = genesis_preimage.build()?;
    let genesis_prepared = WitnessPreparedV1::from_candidate(&genesis_candidate, None, 0)?;
    let genesis_abort =
        WitnessGenesisAbortedV1::from_prepared(&genesis_prepared, "test".to_string())?;

    let mut mixed = prepared;
    mixed.genesis_abort = Some(genesis_abort);
    assert!(mixed.validate().is_err());
    Ok(())
}

#[test]
fn verified_prepare_binds_expected_predecessor_data_identity() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let verified = sample_verified_prepare(&record)?;
    let mut forged = record;
    forged.expected_predecessor_data_head_digest = "f".repeat(64);
    refresh_intent_root(&mut forged)?;
    assert!(forged.validate().is_err());
    assert!(forged.resolve_verified_prepare(&verified).is_err());
    Ok(())
}

#[test]
fn recovery_requires_both_anchored_journal_lanes() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    assert!(
        select_recovery_record(
            &[observed_journal(&record)?],
            &sample_candidate().publication_binding,
        )
        .is_err()
    );

    let mut high = record.resolve_verified_prepare(&sample_verified_prepare(&record)?)?;
    high.journal_generation = 9;
    assert!(
        select_recovery_record(
            &[observed_journal(&record)?, observed_journal(&high)?,],
            &sample_candidate().publication_binding,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn recovery_accepts_latest_adjacent_lanes_after_ready_and_terminal_phases() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let ready = record
        .resolve_verified_prepare(&sample_verified_prepare(&record)?)?
        .transition(TransactionPhaseV1::PayloadsStaged)?
        .transition(TransactionPhaseV1::StateExchanged)?
        .transition(TransactionPhaseV1::CheckpointExchanged)?
        .transition(TransactionPhaseV1::ReadyForWitnessCommit)?;
    let committed = ready.resolve_verified_commit(&sample_verified_commit(&ready)?)?;
    assert_eq!(
        select_recovery_record(
            &[observed_journal(&ready)?, observed_journal(&committed)?,],
            &sample_candidate().publication_binding,
        )?,
        committed
    );

    let pending = ready.begin_abort()?;
    let aborted = pending.resolve_verified_abort(&sample_verified_outcome(
        &pending,
        WitnessOperationV1::Abort,
        WitnessOperationOutcomeV1::Abort(Box::new(WitnessAbortOutcomeV1::Aborted(
            sample_witness_abort(&pending)?,
        ))),
    )?)?;
    assert_eq!(
        select_recovery_record(
            &[observed_journal(&pending)?, observed_journal(&aborted)?,],
            &sample_candidate().publication_binding,
        )?,
        aborted
    );
    Ok(())
}

#[test]
fn equal_generation_fork_and_highest_sequence_shortcut_fail() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let mut fork = record.clone();
    fork.candidate_digest = "b".repeat(64);
    refresh_intent_root(&mut fork)?;
    assert!(
        validate_recovery_pair(
            &observed_journal(&record)?,
            &observed_journal(&fork)?,
            &sample_candidate().publication_binding,
        )
        .is_err()
    );
    assert!(
        select_recovery_record(
            &[observed_journal(&record)?, observed_journal(&fork)?,],
            &sample_candidate().publication_binding,
        )
        .is_err()
    );
    let mut later = record.resolve_verified_prepare(&sample_verified_prepare(&record)?)?;
    later.journal_generation = 9;
    assert!(
        select_recovery_record(
            &[observed_journal(&record)?, observed_journal(&later)?,],
            &sample_candidate().publication_binding,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn reinitialization_requires_exact_epoch_successor() {
    assert!(validate_reinitialization_epoch(4, 5).is_ok());
    assert!(validate_reinitialization_epoch(4, 6).is_err());
    assert!(validate_reinitialization_epoch(u64::MAX, 0).is_err());
}

#[test]
fn genesis_predecessor_is_explicit_and_bound() -> ProtocolResult<()> {
    let mut preimage = sample_candidate();
    preimage.predecessor_head_digest =
        GenesisPredecessorV1::for_binding(&preimage.publication_binding).digest()?;
    preimage.predecessor_data_head_digest =
        GenesisPredecessorV1::for_binding(&preimage.publication_binding).data_head_digest()?;
    preimage.predecessor_head = None;
    preimage.epoch = 0;
    preimage.sequence = 0;
    preimage.intent_counter = 1;
    let candidate = preimage.build()?;
    let prepared = WitnessPreparedV1::from_candidate(&candidate, None, 0)?;
    assert!(prepared.predecessor_head.is_none());
    let mut malformed = candidate;
    malformed.preimage.predecessor_head_digest = "f".repeat(64);
    assert!(WitnessPreparedV1::from_candidate(&malformed, None, 0).is_err());
    Ok(())
}

#[test]
fn genesis_abort_preserves_absent_data_head_advances_intent_and_refuses_replay()
-> ProtocolResult<()> {
    let mut preimage = sample_candidate();
    let genesis = GenesisPredecessorV1::for_binding(&preimage.publication_binding);
    preimage.predecessor_head_digest = genesis.digest()?;
    preimage.predecessor_data_head_digest = genesis.data_head_digest()?;
    preimage.predecessor_head = None;
    preimage.epoch = 0;
    preimage.sequence = 0;
    preimage.intent_counter = 1;
    let candidate = preimage.build()?;
    let prepared = WitnessPreparedV1::from_candidate(&candidate, None, 0)?;
    let aborted = WitnessGenesisAbortedV1::from_prepared(&prepared, "bootstrap-abort".to_string())?;
    assert!(aborted.resulting_data_head_digest == genesis.data_head_digest()?);
    assert!(
        WitnessAbortOutcomeV1::GenesisAborted(aborted.clone())
            .validate_against_prepared(&prepared)
            .is_ok()
    );

    let record = TransactionRecordV1::intent(TransactionIntentV1::from_candidate(&candidate)?)?;
    let verified_abort = sample_verified_outcome(
        &record,
        WitnessOperationV1::Abort,
        WitnessOperationOutcomeV1::Abort(Box::new(WitnessAbortOutcomeV1::GenesisAborted(
            aborted.clone(),
        ))),
    )?;
    let verified_commit = sample_verified_outcome(
        &record,
        WitnessOperationV1::Commit,
        WitnessOperationOutcomeV1::Commit(Box::new(WitnessCommitOutcomeV1::GenesisAborted(
            Box::new(aborted.clone()),
        ))),
    )?;
    let discovery = WitnessDiscoveryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: None,
        prepared: None,
        genesis_abort: Some(aborted.clone()),
        recovery_session: sample_session(&record),
    };
    let pending = record.begin_abort()?;
    let attestation = sample_signed_discovery_attestation(&pending, discovery.clone())?;
    let verified = attestation.verify_authority(
        &sample_challenge(&pending, "a".repeat(64), [7_u8; 32]),
        &sample_candidate().publication_binding,
        None,
    )?;
    assert!(record.resolve_verified_discovery(&verified).is_err());
    let recovered = pending.resolve_verified_discovery(&verified)?;
    assert_eq!(recovered.phase, TransactionPhaseV1::Aborted);
    let binding = sample_candidate().publication_binding;
    let first = observed_journal(&pending)?;
    let second = observed_journal(&recovered)?;
    assert!(validate_recovery_pair(&first, &second, &binding).is_ok());
    assert_eq!(
        select_recovery_record(&[first.clone(), second.clone()], &binding)?,
        recovered
    );

    let mut missing_discovery = recovered.clone();
    missing_discovery.witness_terminal_discovery_attestation = None;
    assert!(observed_journal(&missing_discovery).is_err());

    let mut changed_discovery = recovered.clone();
    changed_discovery
        .witness_terminal_discovery_attestation
        .as_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .signature
        .signature_hex = "0".repeat(128);
    assert!(observed_journal(&changed_discovery).is_err());

    let mut foreign_binding = binding.clone();
    foreign_binding.generation = "e".repeat(64);
    foreign_binding.binding_digest = foreign_binding.computed_digest()?;
    foreign_binding.binding_signature = sample_signer().sign(&foreign_binding.signing_bytes()?);
    foreign_binding.validate()?;
    assert!(validate_recovery_pair(&first, &second, &foreign_binding).is_err());
    assert!(record.resolve_discovery(&discovery).is_err());

    let replay_record = sample_transaction_record()?;
    let replay_prepare = sample_verified_prepare(&replay_record)?;
    assert!(recovered.resolve_verified_prepare(&replay_prepare).is_err());

    let mut next = preimage;
    next.intent_counter = checked_next_intent(aborted.intent_counter)?;
    let next_candidate = next.build()?;
    let next_preimage_bytes = next_candidate.preimage.canonical_bytes()?;
    assert!(
        !next_preimage_bytes
            .windows(b"genesis_abort".len())
            .any(|window| window == b"genesis_abort")
    );
    let mut unknown_value = serde_json::from_slice::<serde_json::Value>(&next_preimage_bytes)
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
    unknown_value
        .as_object_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .insert("genesis_abort".to_string(), serde_json::Value::Null);
    let unknown_field = canonical_wire_bytes(&unknown_value)?;
    assert!(CandidatePreimageV1::decode(&unknown_field).is_err());
    assert!(TransactionIntentV1::from_candidate(&next_candidate).is_ok());

    // A structurally valid counter-two candidate is still only a request;
    // the raw receipt above cannot authorize its prepared witness state.
    assert!(WitnessPreparedV1::from_candidate(&next_candidate, None, 0).is_err());
    let next_prepared =
        WitnessPreparedV1::from_candidate_after_genesis_abort(&next_candidate, &verified_abort, 0)?;
    let next_prepared_from_commit = WitnessPreparedV1::from_candidate_after_genesis_abort(
        &next_candidate,
        &verified_commit,
        0,
    )?;
    assert_eq!(next_prepared, next_prepared_from_commit);
    assert_eq!(next_prepared.head.intent_counter, 2);
    assert_eq!(next_prepared.genesis_abort, Some(aborted.clone()));

    let mut wrong_counter_preimage = next_candidate.preimage.clone();
    wrong_counter_preimage.intent_counter = 3;
    let wrong_counter_candidate = wrong_counter_preimage.build()?;
    assert!(
        WitnessPreparedV1::from_candidate_after_genesis_abort(
            &wrong_counter_candidate,
            &verified_abort,
            0,
        )
        .is_err()
    );

    let mut wrong_binding_candidate = next_candidate.clone();
    wrong_binding_candidate
        .preimage
        .publication_binding
        .generation = "c".repeat(64);
    assert!(
        WitnessPreparedV1::from_candidate_after_genesis_abort(
            &wrong_binding_candidate,
            &verified_abort,
            0,
        )
        .is_err()
    );

    let wrong_operation_record = sample_transaction_record()?;
    let wrong_operation = sample_verified_prepare(&wrong_operation_record)?;
    assert!(
        WitnessPreparedV1::from_candidate_after_genesis_abort(
            &next_candidate,
            &wrong_operation,
            0,
        )
        .is_err()
    );
    let wrong_outcome = sample_verified_commit(&wrong_operation_record)?;
    assert!(
        WitnessPreparedV1::from_candidate_after_genesis_abort(&next_candidate, &wrong_outcome, 0,)
            .is_err()
    );

    let mut forged = aborted;
    forged.resulting_data_head_digest = "f".repeat(64);
    assert!(forged.validate().is_err());
    Ok(())
}

#[test]
fn witness_heads_and_abort_outcomes_preserve_data_head() -> ProtocolResult<()> {
    let candidate = sample_candidate().build()?;
    let head = WitnessHeadV1::committed_from_candidate(&candidate)?;
    let aborted = WitnessAbortedV1::intent_only(
        &head,
        "c".repeat(64),
        "d".repeat(64),
        "operator-cancelled".to_string(),
    )?;
    validate_intent_abort(&head, &aborted)?;
    assert_eq!(aborted.predecessor_head_digest, head.head_digest()?);
    assert_ne!(aborted.predecessor_head_digest, head.candidate_digest);
    assert_eq!(aborted.epoch, head.epoch);
    assert_eq!(aborted.sequence, head.sequence);
    assert_eq!(aborted.intent_counter, head.intent_counter + 1);
    assert_eq!(
        aborted.resulting_head.data_head_digest()?,
        head.data_head_digest()?
    );
    let mut reused = aborted.clone();
    reused.intent_counter += 1;
    assert!(validate_intent_abort(&head, &reused).is_err());
    assert!(WitnessAbortOutcomeV1::Aborted(aborted).validate().is_ok());
    Ok(())
}

#[test]
fn intent_only_abort_rejects_prepared_head_and_preserves_reserved_counter() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let prepared = sample_witness_prepared(&record)?;
    let prepared_abort = sample_witness_abort(&record)?;
    assert!(validate_intent_abort(&prepared.head, &prepared_abort).is_err());
    assert!(
        WitnessAbortedV1::intent_only(
            &prepared.head,
            prepared.head.txid.clone(),
            prepared.head.candidate_digest.clone(),
            "prepared-must-use-authenticated-abort".to_string(),
        )
        .is_err()
    );

    let authenticated = sample_witness_abort(&record)?;
    assert_eq!(authenticated.intent_counter, prepared.head.intent_counter);
    assert!(
        WitnessAbortOutcomeV1::Aborted(authenticated)
            .validate_against_prepared(&prepared)
            .is_ok()
    );
    Ok(())
}

#[test]
fn intent_cannot_resolve_commit_aborted_without_abort_pending() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let aborted = sample_witness_abort(&record)?;
    let verified = sample_verified_outcome(
        &record,
        WitnessOperationV1::Commit,
        WitnessOperationOutcomeV1::Commit(Box::new(WitnessCommitOutcomeV1::Aborted(Box::new(
            aborted,
        )))),
    )?;

    assert!(record.resolve_verified_commit(&verified).is_err());
    Ok(())
}

#[test]
fn witness_commit_abort_outcomes_and_discovery_are_bound() -> ProtocolResult<()> {
    let candidate = sample_candidate().build()?;
    let head = WitnessHeadV1::committed_from_candidate(&candidate)?;
    let session = WitnessSessionV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: head.stream_id.clone(),
        authority_pair: head.authority_pair,
        binding_generation: head.binding_generation.clone(),
        binding_digest: head.binding_digest.clone(),
        signer_key_id: head.signer_key_id.clone(),
        witness_key_id: head.witness_key_id.clone(),
        ephemeral_key_id: sample_ephemeral_key_id(),
        witness_identity: "witness-1".to_string(),
        session_generation: 0,
        session_commitment: "e".repeat(64),
    };
    let committed = WitnessCommittedV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: head.clone(),
    };
    let discovery = WitnessDiscoveryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: Some(head.clone()),
        prepared: None,
        genesis_abort: None,
        recovery_session: session,
    };
    discovery.validate()?;
    let mut candidate_shaped = discovery.clone();
    let Some(candidate_head) = candidate_shaped.head.as_mut() else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    candidate_head.last_intent_outcome = None;
    assert!(candidate_shaped.validate().is_err());
    WitnessCommitOutcomeV1::Committed(committed.clone()).validate()?;
    WitnessCommitOutcomeV1::AlreadyCommitted(committed).validate()?;
    WitnessAbortOutcomeV1::Committed(WitnessCommittedV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head,
    })
    .validate()?;
    assert!(WitnessPrepareOutcomeV1::Conflict.validate().is_ok());
    Ok(())
}

#[test]
fn abort_pending_requires_witness_and_lost_commit_resolution() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let ready = record
        .resolve_verified_prepare(&sample_verified_prepare(&record)?)?
        .transition(TransactionPhaseV1::PayloadsStaged)?
        .transition(TransactionPhaseV1::StateExchanged)?
        .transition(TransactionPhaseV1::CheckpointExchanged)?
        .transition(TransactionPhaseV1::ReadyForWitnessCommit)?;
    let pending = ready.begin_abort()?;
    assert_eq!(pending.phase, TransactionPhaseV1::AbortPending);
    assert!(pending.transition(TransactionPhaseV1::Aborted).is_err());

    let aborted = sample_witness_abort(&pending)?;
    let mut wrong = aborted.clone();
    wrong.intent_counter = checked_next_intent(pending.intent_counter)?;
    assert!(
        sample_verified_outcome(
            &pending,
            WitnessOperationV1::Abort,
            WitnessOperationOutcomeV1::Abort(Box::new(WitnessAbortOutcomeV1::Aborted(wrong))),
        )
        .is_err()
    );
    let abort_receipt = sample_verified_outcome(
        &pending,
        WitnessOperationV1::Commit,
        WitnessOperationOutcomeV1::Commit(Box::new(WitnessCommitOutcomeV1::Aborted(Box::new(
            aborted.clone(),
        )))),
    )?;
    assert!(ready.resolve_verified_commit(&abort_receipt).is_err());
    let abort_wins = pending.resolve_verified_commit(&abort_receipt)?;
    assert_eq!(abort_wins.phase, TransactionPhaseV1::Aborted);
    let abort_pending = ready.begin_abort()?;
    let committed_head = sample_witness_head(&record, record.publication_mapping_after);
    let commit_wins = abort_pending.resolve_verified_abort(&sample_verified_outcome(
        &abort_pending,
        WitnessOperationV1::Abort,
        WitnessOperationOutcomeV1::Abort(Box::new(WitnessAbortOutcomeV1::Committed(
            WitnessCommittedV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                head: committed_head.clone(),
            },
        ))),
    )?)?;
    assert_eq!(commit_wins.phase, TransactionPhaseV1::Committed);

    let session = sample_session(&record);
    let discovery = WitnessDiscoveryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: Some(committed_head),
        prepared: None,
        genesis_abort: None,
        recovery_session: session,
    };
    let discovery_attestation = sample_signed_discovery_attestation(&ready, discovery)?;
    let recovered = ready.resolve_verified_discovery(&discovery_attestation.verify_authority(
        &sample_challenge(&ready, "a".repeat(64), [7_u8; 32]),
        &sample_candidate().publication_binding,
        None,
    )?)?;
    assert_eq!(recovered.phase, TransactionPhaseV1::Committed);

    let aborted_discovery = WitnessDiscoveryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: Some(aborted.resulting_head),
        prepared: None,
        genesis_abort: None,
        recovery_session: sample_session(&pending),
    };
    let aborted_attestation = sample_signed_discovery_attestation(&pending, aborted_discovery)?;
    let aborted_verified = aborted_attestation.verify_authority(
        &sample_challenge(&pending, "a".repeat(64), [7_u8; 32]),
        &sample_candidate().publication_binding,
        None,
    )?;
    assert!(ready.resolve_verified_discovery(&aborted_verified).is_err());
    assert_eq!(
        pending.resolve_verified_discovery(&aborted_verified)?.phase,
        TransactionPhaseV1::Aborted
    );
    Ok(())
}

#[test]
fn abort_from_unprepared_intent_retains_signed_predecessor_data_identity() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let pending = record.begin_abort()?;
    assert!(pending.witness_prepared_attestation.is_none());
    let aborted = pending.resolve_verified_abort(&sample_verified_outcome(
        &pending,
        WitnessOperationV1::Abort,
        WitnessOperationOutcomeV1::Abort(Box::new(WitnessAbortOutcomeV1::Aborted(
            sample_witness_abort(&pending)?,
        ))),
    )?)?;
    assert_eq!(aborted.phase, TransactionPhaseV1::Aborted);
    assert!(aborted.witness_prepared_attestation.is_none());
    assert!(aborted.witness_outcome_attestation.is_some());
    aborted.validate()
}

#[test]
fn abort_receipt_must_preserve_predecessor_data_identity() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let ready = record
        .resolve_verified_prepare(&sample_verified_prepare(&record)?)?
        .transition(TransactionPhaseV1::PayloadsStaged)?
        .transition(TransactionPhaseV1::StateExchanged)?
        .transition(TransactionPhaseV1::CheckpointExchanged)?
        .transition(TransactionPhaseV1::ReadyForWitnessCommit)?;
    let pending = ready.begin_abort()?;
    let mut aborted = sample_witness_abort(&pending)?;
    let replacement = br#"{"state":2}"#;
    aborted.resulting_head.state_digest = swarm_crypto::sha256_hex(replacement);
    aborted.resulting_head.state_byte_len = replacement.len() as u64;
    let replacement_data_head = aborted.resulting_head.data_head_digest()?;
    let Some(WitnessIntentOutcomeV1::Aborted(summary)) =
        aborted.resulting_head.last_intent_outcome.as_mut()
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    summary.resulting_data_head_digest = replacement_data_head;
    assert!(
        pending
            .resolve_verified_abort(&sample_verified_outcome(
                &pending,
                WitnessOperationV1::Abort,
                WitnessOperationOutcomeV1::Abort(Box::new(WitnessAbortOutcomeV1::Aborted(aborted))),
            )?)
            .is_err()
    );
    Ok(())
}

#[test]
fn terminal_record_requires_authenticated_witness_receipt() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let ready = record
        .resolve_verified_prepare(&sample_verified_prepare(&record)?)?
        .transition(TransactionPhaseV1::PayloadsStaged)?
        .transition(TransactionPhaseV1::StateExchanged)?
        .transition(TransactionPhaseV1::CheckpointExchanged)?
        .transition(TransactionPhaseV1::ReadyForWitnessCommit)?;
    let committed = ready.resolve_verified_commit(&sample_verified_commit(&ready)?)?;
    assert!(committed.witness_outcome.is_some());
    committed.validate()?;

    let mut missing = committed.clone();
    missing.witness_outcome = None;
    assert!(matches!(
        missing.validate(),
        Err(ProtocolError::WitnessOutcomeMismatch)
    ));

    let mut forged = committed;
    forged.witness_outcome = Some(WitnessTerminalOutcomeV1::Committed(Box::new(
        WitnessCommittedV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            head: sample_witness_head(&record, record.publication_mapping_before),
        },
    )));
    assert!(matches!(
        forged.validate(),
        Err(ProtocolError::WitnessOutcomeMismatch)
    ));
    Ok(())
}

#[test]
fn aborted_discovery_binds_last_outcome_to_prepared_transaction() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let prepared = sample_witness_prepared(&record)?;
    let aborted = sample_witness_abort(&record)?;
    assert!(
        WitnessAbortOutcomeV1::Aborted(aborted.clone())
            .validate_against_prepared(&prepared)
            .is_ok()
    );

    let mut wrong = aborted.clone();
    wrong.txid = "f".repeat(64);
    assert!(
        WitnessAbortOutcomeV1::Aborted(wrong)
            .validate_against_prepared(&prepared)
            .is_err()
    );

    let mut changed_resulting_txid = aborted.clone();
    changed_resulting_txid.resulting_head.txid = "f".repeat(64);
    assert!(
        WitnessAbortOutcomeV1::Aborted(changed_resulting_txid)
            .validate_against_prepared(&prepared)
            .is_err()
    );
    let mut changed_resulting_candidate = aborted.clone();
    changed_resulting_candidate.resulting_head.candidate_digest = "e".repeat(64);
    assert!(
        WitnessAbortOutcomeV1::Aborted(changed_resulting_candidate)
            .validate_against_prepared(&prepared)
            .is_err()
    );
    let mut changed_prior_metadata = aborted.clone();
    let Some(WitnessIntentOutcomeV1::Aborted(summary)) = changed_prior_metadata
        .resulting_head
        .last_intent_outcome
        .as_mut()
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    summary.predecessor_head_digest = "a".repeat(64);
    assert!(
        WitnessAbortOutcomeV1::Aborted(changed_prior_metadata)
            .validate_against_prepared(&prepared)
            .is_err()
    );

    let discovery = WitnessDiscoveryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: Some(aborted.resulting_head.clone()),
        prepared: None,
        genesis_abort: None,
        recovery_session: sample_session(&record),
    };
    discovery.validate()?;
    Ok(())
}

#[test]
fn verified_discovery_recovers_prepared_from_intent_and_rejects_absent_or_foreign()
-> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let prepared = sample_witness_prepared(&record)?;
    let predecessor = prepared
        .predecessor_head
        .clone()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    let discovery = WitnessDiscoveryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: Some(predecessor.clone()),
        prepared: Some(prepared.clone()),
        genesis_abort: None,
        recovery_session: sample_session(&record),
    };
    let attestation = sample_signed_discovery_attestation(&record, discovery.clone())?;
    let verified = attestation.verify_authority(
        &sample_challenge(&record, "a".repeat(64), [7_u8; 32]),
        &sample_candidate().publication_binding,
        Some(&predecessor),
    )?;
    let recovered = record.resolve_verified_discovery(&verified)?;
    assert_eq!(recovered.phase, TransactionPhaseV1::WitnessPrepared);
    assert!(recovered.witness_prepared_attestation.is_none());
    assert!(recovered.witness_prepared_discovery_attestation.is_some());

    let absent = WitnessDiscoveryV1 {
        prepared: None,
        ..discovery.clone()
    };
    let absent_attestation = sample_signed_discovery_attestation(&record, absent)?;
    let absent_verified = absent_attestation.verify_authority(
        &sample_challenge(&record, "a".repeat(64), [7_u8; 32]),
        &sample_candidate().publication_binding,
        Some(&predecessor),
    )?;
    assert!(record.resolve_verified_discovery(&absent_verified).is_err());

    let mut foreign_preimage = sample_candidate();
    foreign_preimage.state_payload = br#"{"state":2}"#.to_vec();
    foreign_preimage.state_byte_len = foreign_preimage.state_payload.len() as u64;
    foreign_preimage.state_digest = swarm_crypto::sha256_hex(&foreign_preimage.state_payload);
    foreign_preimage.state_attestation = sign_payload(
        &sample_signer(),
        STATE_PAYLOAD_DOMAIN_V1,
        &foreign_preimage.stream_id,
        &foreign_preimage.publication_binding,
        foreign_preimage.state_payload.clone(),
        foreign_preimage.state_digest.clone(),
    );
    let foreign_candidate = foreign_preimage.build()?;
    let foreign_prepared =
        WitnessPreparedV1::from_candidate(&foreign_candidate, Some(predecessor.clone()), 0)?;
    let foreign = WitnessDiscoveryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: Some(predecessor.clone()),
        prepared: Some(foreign_prepared),
        genesis_abort: None,
        recovery_session: sample_session(&record),
    };
    let foreign_attestation = sample_signed_discovery_attestation(&record, foreign)?;
    let foreign_verified = foreign_attestation.verify_authority(
        &sample_challenge(&record, "a".repeat(64), [7_u8; 32]),
        &sample_candidate().publication_binding,
        Some(&predecessor),
    )?;
    assert!(
        record
            .resolve_verified_discovery(&foreign_verified)
            .is_err()
    );
    Ok(())
}

#[test]
fn recovery_accepts_signed_discovery_prepared_successor_and_rejects_mutations() -> ProtocolResult<()>
{
    let record = sample_transaction_record()?;
    let prepared = sample_witness_prepared(&record)?;
    let predecessor = prepared
        .predecessor_head
        .clone()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    let discovery = WitnessDiscoveryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: Some(predecessor.clone()),
        prepared: Some(prepared),
        genesis_abort: None,
        recovery_session: sample_session(&record),
    };
    let attestation = sample_signed_discovery_attestation(&record, discovery.clone())?;
    let verified = attestation.verify_authority(
        &sample_challenge(&record, "a".repeat(64), [7_u8; 32]),
        &sample_candidate().publication_binding,
        Some(&predecessor),
    )?;
    let recovered = record.resolve_verified_discovery(&verified)?;
    assert_eq!(recovered.phase, TransactionPhaseV1::WitnessPrepared);
    assert!(recovered.witness_prepared_attestation.is_none());
    assert!(recovered.witness_prepared_discovery_attestation.is_some());

    let binding = sample_candidate().publication_binding;
    let first = observed_journal(&record)?;
    let second = observed_journal(&recovered)?;
    assert!(validate_recovery_pair(&first, &second, &binding).is_ok());
    assert_eq!(
        select_recovery_record(&[first.clone(), second.clone()], &binding)?,
        recovered
    );

    let mut missing_discovery = recovered.clone();
    missing_discovery.witness_prepared_discovery_attestation = None;
    assert!(observed_journal(&missing_discovery).is_err());

    let mut changed_discovery = recovered.clone();
    changed_discovery
        .witness_prepared_discovery_attestation
        .as_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .signature
        .signature_hex = "0".repeat(128);
    assert!(observed_journal(&changed_discovery).is_err());

    let mut foreign_binding = binding.clone();
    foreign_binding.generation = "f".repeat(64);
    foreign_binding.binding_digest = foreign_binding.computed_digest()?;
    foreign_binding.binding_signature = sample_signer().sign(&foreign_binding.signing_bytes()?);
    foreign_binding.validate()?;
    assert!(validate_recovery_pair(&first, &second, &foreign_binding).is_err());

    assert!(record.resolve_discovery(&discovery).is_err());
    assert!(
        record
            .transition(TransactionPhaseV1::WitnessPrepared)
            .is_err()
    );
    Ok(())
}

#[test]
fn prepared_discovery_evidence_survives_full_commit_chain_and_adjacent_recovery()
-> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let prepared = sample_witness_prepared(&record)?;
    let predecessor = prepared
        .predecessor_head
        .clone()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    let discovery = WitnessDiscoveryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: Some(predecessor),
        prepared: Some(prepared),
        genesis_abort: None,
        recovery_session: sample_session(&record),
    };
    let attestation = sample_signed_discovery_attestation(&record, discovery)?;
    let mut current = record.resolve_verified_discovery(&attestation.verify_authority(
        &sample_challenge(&record, "a".repeat(64), [7_u8; 32]),
        &sample_candidate().publication_binding,
        None,
    )?)?;
    assert!(current.witness_prepared_discovery_attestation.is_some());
    assert!(current.witness_terminal_discovery_attestation.is_none());

    let binding = sample_candidate().publication_binding;
    assert_eq!(
        select_recovery_record(
            &[observed_journal(&record)?, observed_journal(&current)?],
            &binding,
        )?,
        current
    );
    for phase in [
        TransactionPhaseV1::PayloadsStaged,
        TransactionPhaseV1::StateExchanged,
        TransactionPhaseV1::CheckpointExchanged,
        TransactionPhaseV1::ReadyForWitnessCommit,
    ] {
        let next = current.transition(phase)?;
        assert_eq!(
            select_recovery_record(
                &[observed_journal(&current)?, observed_journal(&next)?],
                &binding,
            )?,
            next
        );
        current = next;
    }
    let committed = current.resolve_verified_commit(&sample_verified_commit(&current)?)?;
    assert!(committed.witness_prepared_discovery_attestation.is_some());
    assert!(committed.witness_terminal_discovery_attestation.is_none());
    assert!(committed.witness_outcome_attestation.is_some());
    assert_eq!(
        select_recovery_record(
            &[observed_journal(&current)?, observed_journal(&committed)?],
            &binding,
        )?,
        committed
    );
    Ok(())
}

#[test]
fn direct_committed_head_discovery_from_intent_is_rejected() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let discovery = WitnessDiscoveryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: Some(sample_witness_head(
            &record,
            record.publication_mapping_after,
        )),
        prepared: None,
        genesis_abort: None,
        recovery_session: sample_session(&record),
    };
    let attestation = sample_signed_discovery_attestation(&record, discovery)?;
    let verified = attestation.verify_authority(
        &sample_challenge(&record, "a".repeat(64), [7_u8; 32]),
        &sample_candidate().publication_binding,
        None,
    )?;
    assert!(record.resolve_verified_discovery(&verified).is_err());
    Ok(())
}

#[test]
fn recovery_rejects_witness_namespace_replay() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let mut successor = record.resolve_verified_prepare(&sample_verified_prepare(&record)?)?;
    successor.witness_successor_head_digest = "e".repeat(64);
    refresh_intent_root(&mut successor)?;
    successor.previous_record_digest = Some(record.record_digest()?);
    assert!(matches!(
        validate_recovery_pair(
            &observed_journal(&record)?,
            &observed_journal(&successor)?,
            &sample_candidate().publication_binding,
        ),
        Err(ProtocolError::RecoveryFork { .. })
    ));

    let mut terminal = record
        .resolve_verified_prepare(&sample_verified_prepare(&record)?)?
        .transition(TransactionPhaseV1::PayloadsStaged)?
        .transition(TransactionPhaseV1::StateExchanged)?
        .transition(TransactionPhaseV1::CheckpointExchanged)?
        .transition(TransactionPhaseV1::ReadyForWitnessCommit)?
        .resolve_verified_commit(&sample_verified_commit(&record)?)?;
    let original = terminal.witness_successor_head_digest.clone();
    terminal.witness_successor_head_digest = "d".repeat(64);
    assert_ne!(terminal.witness_successor_head_digest, original);
    assert!(terminal.validate().is_err());
    Ok(())
}

#[test]
fn witness_session_capability_is_head_bound_and_not_wire_attestation() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let head = sample_witness_head(&record, record.publication_mapping_after);
    let candidate = sample_candidate().build()?;
    let binding = &candidate.preimage.publication_binding;
    let secret = [7_u8; 32];
    let challenge = sample_challenge(&record, "a".repeat(64), secret);
    let mut session = sample_session(&record);
    session.session_commitment = challenge.session_commitment.clone();
    let request = GovernanceWitnessSessionRequest::from_secret(challenge.clone(), secret)?;
    let signer = sample_witness_signer();
    let mut attestation = WitnessSessionAttestationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        challenge: challenge.clone(),
        session: session.clone(),
        committed_head: Some(head.clone()),
        external_marker: "f".repeat(64),
        witness_key_id: signer.key_id().to_string(),
        signature: signer.sign(&[]),
    };
    attestation.signature = signer.sign(&attestation.signing_bytes()?);
    let capability = GovernanceWitnessSession::from_verified_attestation(
        request,
        attestation.clone(),
        Some(&head),
        binding,
    )?;
    assert_eq!(capability.attestation(), &session);
    assert_eq!(capability.committed_head(), Some(&head));
    assert_eq!(capability.external_marker(), "f".repeat(64));

    let mut response = WitnessOutcomeAttestationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        operation: WitnessOperationV1::Commit,
        stream_id: record.stream_id.clone(),
        binding_generation: record.binding_generation.clone(),
        binding_digest: record.binding_digest.clone(),
        signer_key_id: record.signer_key_id.clone(),
        authority_pair: record.authority_pair,
        txid: record.txid.clone(),
        candidate_digest: record.candidate_digest.clone(),
        session_generation: session.session_generation,
        session_commitment: session.session_commitment.clone(),
        witness_key_id: session.witness_key_id.clone(),
        outcome: WitnessOperationOutcomeV1::Commit(Box::new(WitnessCommitOutcomeV1::Committed(
            WitnessCommittedV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                head: head.clone(),
            },
        ))),
        signature: signer.sign(&[]),
    };
    response.signature = signer.sign(&response.signing_bytes()?);
    assert!(matches!(
        response.verify_for(
            &capability,
            WitnessOperationV1::Commit,
            &record.txid,
            &record.candidate_digest,
        )?,
        WitnessOperationOutcomeV1::Commit(_)
    ));
    let mut forged_response = response.clone();
    forged_response.txid = "b".repeat(64);
    assert!(forged_response.validate().is_err());
    let authorization = capability.authorize(
        WitnessOperationV1::Commit,
        &record.txid,
        &record.candidate_digest,
    )?;
    capability.verify_authorization(
        &authorization,
        WitnessOperationV1::Commit,
        &record.txid,
        &record.candidate_digest,
    )?;
    let cross_operation_authorization = authorization.clone();
    let mut forged_authorization = authorization;
    forged_authorization.request_digest = "c".repeat(64);
    assert!(
        capability
            .verify_authorization(
                &forged_authorization,
                WitnessOperationV1::Commit,
                &record.txid,
                &record.candidate_digest,
            )
            .is_err()
    );
    assert!(
        capability
            .verify_authorization(
                &cross_operation_authorization,
                WitnessOperationV1::ReadHead,
                &record.txid,
                &record.candidate_digest,
            )
            .is_err()
    );
    let mut wrong_ephemeral = cross_operation_authorization;
    wrong_ephemeral.ephemeral_key_id = "f".repeat(64);
    assert!(wrong_ephemeral.validate().is_err());

    let mut read_head = WitnessReadAttestationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        operation: WitnessOperationV1::ReadHead,
        stream_id: record.stream_id.clone(),
        binding_generation: record.binding_generation.clone(),
        binding_digest: record.binding_digest.clone(),
        signer_key_id: record.signer_key_id.clone(),
        authority_pair: record.authority_pair,
        target_txid: record.txid.clone(),
        request_digest: record.candidate_digest.clone(),
        session_generation: session.session_generation,
        session_commitment: session.session_commitment.clone(),
        witness_key_id: session.witness_key_id.clone(),
        response: WitnessReadResponseV1::Head(Box::new(Some(head.clone()))),
        signature: signer.sign(&[]),
    };
    read_head.signature = signer.sign(&read_head.signing_bytes()?);
    assert_eq!(
        read_head.verify_for(
            &capability,
            WitnessOperationV1::ReadHead,
            &record.txid,
            &record.candidate_digest,
        )?,
        WitnessReadResponseV1::Head(Box::new(Some(head.clone())))
    );

    let mut read_none = read_head.clone();
    read_none.response = WitnessReadResponseV1::Head(Box::new(None));
    read_none.signature = signer.sign(&read_none.signing_bytes()?);
    assert_eq!(
        read_none.verify_for(
            &capability,
            WitnessOperationV1::ReadHead,
            &record.txid,
            &record.candidate_digest,
        )?,
        WitnessReadResponseV1::Head(Box::new(None))
    );

    let mut cross_operation = read_head.clone();
    cross_operation.operation = WitnessOperationV1::ReadPrepared;
    cross_operation.signature = signer.sign(&cross_operation.signing_bytes()?);
    assert!(cross_operation.validate().is_err());

    let mut cross_namespace = read_head.clone();
    let WitnessReadResponseV1::Head(foreign_head) = &mut cross_namespace.response else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    let Some(foreign_head) = foreign_head.as_mut().as_mut() else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    foreign_head.signer_key_id = "f".repeat(64);
    cross_namespace.signature = signer.sign(&cross_namespace.signing_bytes()?);
    assert!(cross_namespace.validate().is_err());

    let mut foreign_binding = read_head;
    foreign_binding.binding_generation = "f".repeat(64);
    foreign_binding.signature = signer.sign(&foreign_binding.signing_bytes()?);
    assert!(foreign_binding.validate().is_err());

    let mut wrong_challenge = challenge.clone();
    wrong_challenge.nonce = "b".repeat(64);
    assert!(GovernanceWitnessSessionRequest::from_secret(wrong_challenge, secret).is_err());
    assert!(GovernanceWitnessSessionRequest::from_secret(challenge.clone(), [8_u8; 32]).is_err());
    let mut wrong_attestation = attestation.clone();
    wrong_attestation.challenge.nonce = "b".repeat(64);
    assert!(
        GovernanceWitnessSession::from_verified_attestation(
            GovernanceWitnessSessionRequest::from_secret(challenge.clone(), secret)?,
            wrong_attestation,
            Some(&head),
            binding,
        )
        .is_err()
    );
    let mut wrong_head = head;
    wrong_head.stream_id.push_str("-foreign");
    assert!(
        GovernanceWitnessSession::from_verified_attestation(
            GovernanceWitnessSessionRequest::from_secret(challenge, secret)?,
            attestation,
            Some(&wrong_head),
            binding,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn signed_discovery_rotation_requires_secret_namespace_and_expected_head() -> ProtocolResult<()> {
    let record = sample_transaction_record()?;
    let binding = sample_candidate().publication_binding;
    let head = sample_witness_head(&record, record.publication_mapping_after);
    let discovery = WitnessDiscoveryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: Some(head.clone()),
        prepared: None,
        genesis_abort: None,
        recovery_session: sample_session(&record),
    };
    let attestation = sample_signed_discovery_attestation(&record, discovery)?;
    let request =
        GovernanceWitnessSessionRequest::from_secret(attestation.challenge.clone(), [7_u8; 32])?;
    let (verified, session) = GovernanceWitnessSession::from_verified_discovery(
        request,
        attestation.clone(),
        &binding,
        Some(&head),
    )?;
    assert_eq!(verified.discovery().head.as_ref(), Some(&head));
    assert_eq!(session.committed_head(), Some(&head));

    // The public wire verifier yields only a non-authority wrapper; a caller
    // must still provide the one-time secret-backed request to obtain a
    // mutation session.
    assert!(
        attestation
            .verify_authority(&attestation.challenge, &binding, Some(&head))
            .is_ok()
    );
    assert!(
        GovernanceWitnessSessionRequest::from_secret(attestation.challenge.clone(), [8_u8; 32],)
            .is_err()
    );

    let mut wrong_namespace = attestation.clone();
    wrong_namespace.challenge.stream_id.push_str("-foreign");
    assert!(
        wrong_namespace
            .verify_authority(&wrong_namespace.challenge, &binding, Some(&head))
            .is_err()
    );

    let mut wrong_head = head.clone();
    wrong_head.sequence = checked_next_sequence(wrong_head.sequence)?;
    assert!(
        attestation
            .verify_authority(&attestation.challenge, &binding, Some(&wrong_head))
            .is_err()
    );
    Ok(())
}

#[test]
fn resource_bounds_refuse_unbounded_wire_values() {
    let mut candidate = sample_candidate();
    candidate.stream_id = "x".repeat(MAX_PROTOCOL_STRING_BYTES + 1);
    candidate.publication_binding.stream_id = candidate.stream_id.clone();
    assert!(candidate.validate().is_err());
    let mut candidate = sample_candidate();
    candidate.state_payload = vec![0; MAX_PROTOCOL_PAYLOAD_BYTES + 1];
    assert!(candidate.validate().is_err());
}

#[test]
fn binding_has_fixed_bounded_slots_and_canonical_payloads() -> ProtocolResult<()> {
    let candidate = sample_candidate();
    candidate.publication_binding.validate()?;
    candidate
        .publication_mapping_before
        .validate_against(&candidate.publication_binding.publication_roles)?;
    candidate
        .publication_mapping_after
        .validate_against(&candidate.publication_binding.publication_roles)?;
    assert_eq!(
        candidate.publication_binding.cleanup_slot_count as usize,
        FIXED_CLEANUP_SLOT_COUNT
    );
    assert_eq!(
        candidate.publication_binding.cleanup_slot_names.len(),
        FIXED_CLEANUP_SLOT_COUNT
    );
    let mut changed = candidate.clone();
    changed.state_payload = br#"{ "state": 1 }"#.to_vec();
    assert!(changed.validate().is_err());
    let mut changed = candidate;
    changed.publication_binding.cleanup_slot_names[1] =
        changed.publication_binding.cleanup_slot_names[0].clone();
    assert!(changed.validate().is_err());
    let mut changed = sample_candidate();
    changed.publication_mapping_after.state_canonical = ArtifactIdentityV1 {
        device: 99,
        inode: 99,
    };
    assert!(changed.validate().is_err());
    let mut cross_pair = sample_candidate();
    std::mem::swap(
        &mut cross_pair.publication_mapping_after.state_canonical,
        &mut cross_pair.publication_mapping_after.checkpoint_canonical,
    );
    assert!(cross_pair.validate().is_err());
    let mut same_set_wrong_assignment = sample_candidate();
    same_set_wrong_assignment.publication_mapping_after =
        same_set_wrong_assignment.publication_mapping_before;
    assert!(same_set_wrong_assignment.validate().is_err());
    Ok(())
}

#[test]
fn publication_binding_signature_covers_complete_binding() -> ProtocolResult<()> {
    let candidate = sample_candidate();
    candidate.publication_binding.validate()?;

    let mut stale = candidate.publication_binding.clone();
    stale.parent_directory.inode += 100;
    assert!(stale.validate().is_err());

    let signer = sample_signer();
    let stale_bytes = stale.signing_bytes()?;
    stale.binding_digest = digest_domain(BINDING_DOMAIN_V1, &stale_bytes)?;
    stale.binding_signature = signer.sign(&stale_bytes);
    assert!(stale.validate().is_ok());

    let mut candidate_with_resigned_binding = candidate;
    candidate_with_resigned_binding.publication_binding = stale;
    assert!(candidate_with_resigned_binding.validate().is_err());
    Ok(())
}

fn sample_authority() -> AuthorityPairIdentityV1 {
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

fn sample_signer() -> Ed25519Signer {
    Ed25519Signer::from_secret_material("phase-285-protocol-test-signer")
}

fn sample_witness_signer() -> Ed25519Signer {
    Ed25519Signer::from_secret_material("phase-285-protocol-test-witness")
}

fn sign_payload(
    signer: &Ed25519Signer,
    domain: &str,
    stream_id: &str,
    binding: &PublicationBindingV1,
    payload: Vec<u8>,
    digest: String,
) -> swarm_crypto::DetachedSignature {
    let preimage = SignedPayloadPreimageV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        domain: domain.to_string(),
        stream_id: stream_id.to_string(),
        binding_generation: binding.generation.clone(),
        binding_digest: binding.binding_digest.clone(),
        authority_pair: binding.authority_pair,
        byte_len: payload.len() as u64,
        digest,
        payload,
    };
    signer.sign(&preimage.canonical_bytes().unwrap_or_default())
}

fn sample_predecessor_head(
    stream_id: &str,
    binding: &PublicationBindingV1,
    publication_mapping: PublicationMappingV1,
    state_digest: &str,
    state_byte_len: u64,
    checkpoint_digest: &str,
    checkpoint_byte_len: u64,
) -> WitnessHeadV1 {
    WitnessHeadV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: stream_id.to_string(),
        txid: "c".repeat(64),
        candidate_digest: "d".repeat(64),
        epoch: 0,
        sequence: 0,
        intent_counter: 0,
        binding_generation: binding.generation.clone(),
        binding_digest: binding.binding_digest.clone(),
        signer_key_id: binding.signer_key_id.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        authority_pair: binding.authority_pair,
        state_digest: state_digest.to_string(),
        state_byte_len,
        checkpoint_digest: checkpoint_digest.to_string(),
        checkpoint_byte_len,
        publication_mapping,
        last_intent_outcome: Some(WitnessIntentOutcomeV1::Committed {
            txid: "c".repeat(64),
            candidate_digest: "d".repeat(64),
            predecessor_head_digest: "e".repeat(64),
            intent_counter: 0,
        }),
    }
}

fn sample_roles() -> PublicationRoleIdentitiesV1 {
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

fn sample_candidate() -> CandidatePreimageV1 {
    let authority = sample_authority();
    let roles = sample_roles();
    let stream_id = "tom-primary".to_string();
    let state_payload = br#"{"state":1}"#.to_vec();
    let checkpoint_payload = br#"{"checkpoint":1}"#.to_vec();
    let state_digest = swarm_crypto::sha256_hex(&state_payload);
    let checkpoint_digest = swarm_crypto::sha256_hex(&checkpoint_payload);
    let publication_mapping_before = sample_mapping_before();
    let publication_mapping_after = sample_mapping_after();
    let cleanup_slot_names = (0..FIXED_CLEANUP_SLOT_COUNT)
        .map(|index| format!("slot-{index:02}"))
        .collect::<Vec<_>>();
    let cleanup_slot_identities = (11..(11 + FIXED_CLEANUP_SLOT_COUNT as u64))
        .map(|inode| ArtifactIdentityV1 { device: 2, inode })
        .collect::<Vec<_>>();
    let signer = sample_signer();
    let mut publication_binding = PublicationBindingV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: stream_id.clone(),
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
        authority_pair: authority,
        publication_roles: roles,
        cleanup_slot_count: FIXED_CLEANUP_SLOT_COUNT as u32,
        cleanup_slot_names,
        cleanup_slot_identities,
        limits: ProtocolLimitsV1::default(),
        signer_key_id: signer.key_id().to_string(),
        witness_key_id: sample_witness_signer().key_id().to_string(),
        witness_identity: "witness-1".to_string(),
        binding_digest: "0".repeat(64),
        binding_signature: signer.sign(&[]),
    };
    let binding_bytes = publication_binding.signing_bytes().unwrap_or_default();
    publication_binding.binding_digest =
        digest_domain(BINDING_DOMAIN_V1, &binding_bytes).unwrap_or_else(|_| "0".repeat(64));
    publication_binding.binding_signature = signer.sign(&binding_bytes);
    let predecessor_head = sample_predecessor_head(
        &stream_id,
        &publication_binding,
        publication_mapping_before,
        &state_digest,
        state_payload.len() as u64,
        &checkpoint_digest,
        checkpoint_payload.len() as u64,
    );
    CandidatePreimageV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id,
        predecessor_head: Some(predecessor_head.clone()),
        predecessor_head_digest: predecessor_head
            .head_digest()
            .unwrap_or_else(|error| panic!("predecessor head: {error:?}")),
        predecessor_data_head_digest: predecessor_head
            .data_head_digest()
            .unwrap_or_else(|error| panic!("predecessor data head: {error:?}")),
        state_payload: state_payload.clone(),
        state_byte_len: state_payload.len() as u64,
        state_digest: state_digest.clone(),
        state_attestation: sign_payload(
            &signer,
            STATE_PAYLOAD_DOMAIN_V1,
            "tom-primary",
            &publication_binding,
            state_payload,
            state_digest,
        ),
        checkpoint_payload: checkpoint_payload.clone(),
        checkpoint_byte_len: checkpoint_payload.len() as u64,
        checkpoint_digest: checkpoint_digest.clone(),
        checkpoint_attestation: sign_payload(
            &signer,
            CHECKPOINT_PAYLOAD_DOMAIN_V1,
            "tom-primary",
            &publication_binding,
            checkpoint_payload,
            checkpoint_digest,
        ),
        publication_binding,
        publication_mapping_before,
        publication_mapping_after,
        epoch: 0,
        sequence: 1,
        intent_counter: 1,
    }
}

fn sample_mapping_before() -> PublicationMappingV1 {
    let roles = sample_roles();
    PublicationMappingV1 {
        state_canonical: roles.state_canonical,
        state_staging: roles.state_staging,
        checkpoint_canonical: roles.checkpoint_canonical,
        checkpoint_staging: roles.checkpoint_staging,
        journal_primary: roles.journal_primary,
        journal_secondary: roles.journal_secondary,
    }
}

fn sample_mapping_after() -> PublicationMappingV1 {
    let before = sample_mapping_before();
    PublicationMappingV1 {
        state_canonical: before.state_staging,
        state_staging: before.state_canonical,
        checkpoint_canonical: before.checkpoint_staging,
        checkpoint_staging: before.checkpoint_canonical,
        journal_primary: before.journal_primary,
        journal_secondary: before.journal_secondary,
    }
}

fn sample_transaction_record() -> ProtocolResult<TransactionRecordV1> {
    let candidate = sample_candidate().build()?;
    TransactionRecordV1::intent(TransactionIntentV1::from_candidate(&candidate)?)
}

fn refresh_intent_root(record: &mut TransactionRecordV1) -> ProtocolResult<()> {
    let intent = TransactionIntentV1 {
        schema_version: record.schema_version,
        stream_id: record.stream_id.clone(),
        txid: record.txid.clone(),
        candidate_digest: record.candidate_digest.clone(),
        intent_root_digest: "0".repeat(64),
        predecessor_head: record.predecessor_head.clone(),
        predecessor_head_digest: record.predecessor_head_digest.clone(),
        expected_predecessor_data_head_digest: record.expected_predecessor_data_head_digest.clone(),
        epoch: record.epoch,
        sequence: record.sequence,
        intent_counter: record.intent_counter,
        binding_generation: record.binding_generation.clone(),
        binding_digest: record.binding_digest.clone(),
        signer_key_id: record.signer_key_id.clone(),
        witness_key_id: record.witness_key_id.clone(),
        authority_pair: record.authority_pair,
        witness_predecessor_head_digest: record.witness_predecessor_head_digest.clone(),
        witness_prepared_head_digest: record.witness_prepared_head_digest.clone(),
        witness_successor_head_digest: record.witness_successor_head_digest.clone(),
        journal_lane: record.publication_mapping_before.journal_primary,
        publication_mapping_before: record.publication_mapping_before,
        publication_mapping_after: record.publication_mapping_after,
    };
    record.intent_root_digest = intent.computed_root_digest()?;
    Ok(())
}

fn sample_capability(
    record: &TransactionRecordV1,
    expected_head: Option<&WitnessHeadV1>,
) -> ProtocolResult<GovernanceWitnessSession> {
    let secret = [7_u8; 32];
    let challenge = sample_challenge(record, "a".repeat(64), secret);
    let mut session = sample_session(record);
    session.session_commitment = challenge.session_commitment.clone();
    let signer = sample_witness_signer();
    let mut attestation = WitnessSessionAttestationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        challenge: challenge.clone(),
        session,
        committed_head: expected_head.cloned(),
        external_marker: "f".repeat(64),
        witness_key_id: signer.key_id().to_string(),
        signature: signer.sign(&[]),
    };
    attestation.signature = signer.sign(&attestation.signing_bytes()?);
    GovernanceWitnessSession::from_verified_attestation(
        GovernanceWitnessSessionRequest::from_secret(challenge, secret)?,
        attestation,
        expected_head,
        &sample_candidate().publication_binding,
    )
}

fn sample_verified_outcome(
    record: &TransactionRecordV1,
    operation: WitnessOperationV1,
    outcome: WitnessOperationOutcomeV1,
) -> ProtocolResult<VerifiedWitnessOutcomeV1> {
    let session = sample_capability(record, None)?;
    let mut attestation = WitnessOutcomeAttestationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        operation,
        stream_id: record.stream_id.clone(),
        binding_generation: record.binding_generation.clone(),
        binding_digest: record.binding_digest.clone(),
        signer_key_id: record.signer_key_id.clone(),
        authority_pair: record.authority_pair,
        txid: record.txid.clone(),
        candidate_digest: record.candidate_digest.clone(),
        session_generation: session.attestation().session_generation,
        session_commitment: session.attestation().session_commitment.clone(),
        witness_key_id: session.attestation().witness_key_id.clone(),
        outcome,
        signature: sample_witness_signer().sign(&[]),
    };
    attestation.signature = sample_witness_signer().sign(&attestation.signing_bytes()?);
    VerifiedWitnessOutcomeV1::from_attestation(
        attestation,
        &session,
        operation,
        &record.txid,
        &record.candidate_digest,
    )
}

fn sample_verified_prepare(
    record: &TransactionRecordV1,
) -> ProtocolResult<VerifiedWitnessOutcomeV1> {
    let prepared = sample_witness_prepared(record)?;
    sample_verified_outcome(
        record,
        WitnessOperationV1::Prepare,
        WitnessOperationOutcomeV1::Prepare(Box::new(WitnessPrepareOutcomeV1::Prepared(prepared))),
    )
}

fn assert_prepared_attestation_not_recoverable(
    record: &TransactionRecordV1,
    attestation: WitnessOutcomeAttestationV1,
) -> ProtocolResult<()> {
    let mut current = record.resolve_verified_prepare(&sample_verified_prepare(record)?)?;
    for phase in [
        TransactionPhaseV1::PayloadsStaged,
        TransactionPhaseV1::StateExchanged,
        TransactionPhaseV1::CheckpointExchanged,
        TransactionPhaseV1::ReadyForWitnessCommit,
    ] {
        current = current.transition(phase)?;
    }
    let committed = current.resolve_verified_commit(&sample_verified_commit(&current)?)?;

    let mut invalid_current = current.clone();
    invalid_current.witness_prepared_attestation = Some(attestation.clone());
    let invalid_current_digest = invalid_current
        .record_digest()
        .unwrap_or(current.record_digest()?);

    let mut invalid_committed = committed;
    invalid_committed.witness_prepared_attestation = Some(attestation);
    invalid_committed.previous_record_digest = Some(invalid_current_digest);

    let first = observed_journal(&invalid_current);
    let second = observed_journal(&invalid_committed);
    match (first, second) {
        (Ok(first), Ok(second)) => {
            assert!(
                select_recovery_record(&[first, second], &sample_candidate().publication_binding,)
                    .is_err()
            );
        }
        (Err(_), _) | (_, Err(_)) => {}
    }
    Ok(())
}

fn sample_verified_commit(
    record: &TransactionRecordV1,
) -> ProtocolResult<VerifiedWitnessOutcomeV1> {
    let committed = WitnessCommittedV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        head: sample_witness_head(record, record.publication_mapping_after),
    };
    sample_verified_outcome(
        record,
        WitnessOperationV1::Commit,
        WitnessOperationOutcomeV1::Commit(Box::new(WitnessCommitOutcomeV1::Committed(committed))),
    )
}

fn sample_signed_discovery_attestation(
    record: &TransactionRecordV1,
    discovery: WitnessDiscoveryV1,
) -> ProtocolResult<WitnessDiscoveryAttestationV1> {
    let challenge = sample_challenge(record, "a".repeat(64), [7_u8; 32]);
    let signer = sample_witness_signer();
    let mut attestation = WitnessDiscoveryAttestationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        challenge,
        discovery,
        witness_key_id: signer.key_id().to_string(),
        signature: signer.sign(&[]),
    };
    attestation.signature = signer.sign(&attestation.signing_bytes()?);
    attestation.validate()?;
    Ok(attestation)
}

fn signed_journal(record: &TransactionRecordV1) -> ProtocolResult<GovernanceJournalRecordV1> {
    let signer = sample_signer();
    let mut envelope = GovernanceJournalRecordV1::unsigned(record.clone())?;
    envelope.signature = signer.sign(&envelope.signing_bytes()?);
    envelope.validate_against_binding(&sample_candidate().publication_binding)?;
    Ok(envelope)
}

fn observed_journal(
    record: &TransactionRecordV1,
) -> ProtocolResult<GovernanceJournalLaneObservationV1> {
    let envelope = signed_journal(record)?;
    Ok(GovernanceJournalLaneObservationV1 {
        observed_lane: envelope.journal_lane,
        envelope,
    })
}

fn sample_witness_head(
    record: &TransactionRecordV1,
    publication_mapping: PublicationMappingV1,
) -> WitnessHeadV1 {
    WitnessHeadV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: record.stream_id.clone(),
        txid: record.txid.clone(),
        candidate_digest: record.candidate_digest.clone(),
        epoch: record.epoch,
        sequence: record.sequence,
        intent_counter: record.intent_counter,
        binding_generation: record.binding_generation.clone(),
        binding_digest: record.binding_digest.clone(),
        signer_key_id: record.signer_key_id.clone(),
        witness_key_id: record.witness_key_id.clone(),
        authority_pair: record.authority_pair,
        state_digest: swarm_crypto::sha256_hex(br#"{"state":1}"#),
        state_byte_len: br#"{"state":1}"#.len() as u64,
        checkpoint_digest: swarm_crypto::sha256_hex(br#"{"checkpoint":1}"#),
        checkpoint_byte_len: br#"{"checkpoint":1}"#.len() as u64,
        publication_mapping,
        last_intent_outcome: Some(WitnessIntentOutcomeV1::Committed {
            txid: record.txid.clone(),
            candidate_digest: record.candidate_digest.clone(),
            predecessor_head_digest: record.witness_predecessor_head_digest.clone(),
            intent_counter: record.intent_counter,
        }),
    }
}

fn sample_witness_abort(record: &TransactionRecordV1) -> ProtocolResult<WitnessAbortedV1> {
    let aborted = WitnessAbortedV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: record.stream_id.clone(),
        txid: record.txid.clone(),
        candidate_digest: record.candidate_digest.clone(),
        predecessor_head_digest: record.predecessor_head_digest.clone(),
        epoch: record.epoch,
        sequence: record.sequence,
        intent_counter: record.intent_counter,
        binding_generation: record.binding_generation.clone(),
        binding_digest: record.binding_digest.clone(),
        signer_key_id: record.signer_key_id.clone(),
        witness_key_id: record.witness_key_id.clone(),
        authority_pair: record.authority_pair,
        publication_mapping: record.publication_mapping_before,
        resulting_head: {
            let candidate = sample_candidate();
            let mut head = sample_predecessor_head(
                &record.stream_id,
                &candidate.publication_binding,
                record.publication_mapping_before,
                &candidate.state_digest,
                candidate.state_byte_len,
                &candidate.checkpoint_digest,
                candidate.checkpoint_byte_len,
            );
            head.intent_counter = record.intent_counter;
            head.last_intent_outcome = Some(WitnessIntentOutcomeV1::Aborted(Box::new(
                WitnessAbortSummaryV1 {
                    txid: record.txid.clone(),
                    candidate_digest: record.candidate_digest.clone(),
                    predecessor_head_digest: record.witness_predecessor_head_digest.clone(),
                    epoch: record.epoch,
                    sequence: record.sequence,
                    intent_counter: record.intent_counter,
                    binding_generation: record.binding_generation.clone(),
                    binding_digest: record.binding_digest.clone(),
                    signer_key_id: record.signer_key_id.clone(),
                    witness_key_id: record.witness_key_id.clone(),
                    authority_pair: record.authority_pair,
                    publication_mapping: record.publication_mapping_before,
                    resulting_data_head_digest: head.data_head_digest()?,
                },
            )));
            head
        },
        reason: "operator-cancelled".to_string(),
    };
    Ok(aborted)
}

fn sample_witness_prepared(record: &TransactionRecordV1) -> ProtocolResult<WitnessPreparedV1> {
    let candidate = sample_candidate().build()?;
    let predecessor = sample_predecessor_head(
        &record.stream_id,
        &candidate.preimage.publication_binding,
        record.publication_mapping_before,
        &candidate.preimage.state_digest,
        candidate.preimage.state_byte_len,
        &candidate.preimage.checkpoint_digest,
        candidate.preimage.checkpoint_byte_len,
    );
    WitnessPreparedV1::from_candidate(&candidate, Some(predecessor), 0)
}

fn sample_session(record: &TransactionRecordV1) -> WitnessSessionV1 {
    let secret = [7_u8; 32];
    let ephemeral = swarm_crypto::Keypair::from_seed(&secret).public_key();
    WitnessSessionV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: record.stream_id.clone(),
        authority_pair: record.authority_pair,
        binding_generation: record.binding_generation.clone(),
        binding_digest: record.binding_digest.clone(),
        signer_key_id: record.signer_key_id.clone(),
        witness_key_id: record.witness_key_id.clone(),
        ephemeral_key_id: swarm_crypto::sha256_hex(ephemeral.as_bytes()),
        witness_identity: "witness-1".to_string(),
        session_generation: 0,
        session_commitment: swarm_crypto::sha256_hex(&secret),
    }
}

fn sample_ephemeral_key_id() -> String {
    let secret = [7_u8; 32];
    let ephemeral = swarm_crypto::Keypair::from_seed(&secret).public_key();
    swarm_crypto::sha256_hex(ephemeral.as_bytes())
}

fn sample_challenge(
    record: &TransactionRecordV1,
    nonce: String,
    secret: [u8; 32],
) -> RecoveryChallengeV1 {
    let signer = sample_signer();
    let ephemeral = swarm_crypto::Keypair::from_seed(&secret).public_key();
    let mut challenge = RecoveryChallengeV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: record.stream_id.clone(),
        authority_pair: record.authority_pair,
        binding_generation: record.binding_generation.clone(),
        binding_digest: record.binding_digest.clone(),
        signer_key_id: record.signer_key_id.clone(),
        witness_key_id: record.witness_key_id.clone(),
        ephemeral_key_id: swarm_crypto::sha256_hex(ephemeral.as_bytes()),
        witness_identity: "witness-1".to_string(),
        nonce,
        session_commitment: swarm_crypto::sha256_hex(&secret),
        signature: signer.sign(&[]),
    };
    challenge.signature = signer.sign(&challenge.signing_bytes().unwrap_or_default());
    challenge
}
