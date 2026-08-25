//! Phase 285 Plan 01 witness-service conformance target.

use serde::Serialize;
use swarm_crypto::{DetachedSignature, Ed25519Signer, sha256_hex};
use swarm_governance::persistence_protocol::*;
use swarm_governance::witness_engine::{WitnessStoreEnvelopeV1, validate_store_transition};
use swarm_governance::witness_service::*;

#[test]
fn response_failure_wire_binds_operation_and_request_digest() -> ProtocolResult<()> {
    let fixture = Fixture::new(4_096)?;
    let request = fixture.fence_service_request()?;
    let response = WitnessServiceResponseV1::Fence(fixture.fence.clone());
    response.validate_for_request(&request, None)?;

    let discover_request = fixture.discover_service_request()?;
    WitnessServiceResponseV1::Discover(fixture.discovery_attestation()?)
        .validate_for_request(&discover_request, None)?;

    let establish_request = fixture.establish_service_request()?;
    WitnessServiceResponseV1::Establish(fixture.establish_attestation()?)
        .validate_for_request(&establish_request, None)?;

    let prepare_request = fixture.session_service_request(WitnessServiceOperationV1::Prepare)?;
    WitnessServiceResponseV1::Outcome(fixture.prepare_outcome_attestation()?)
        .validate_for_request(&prepare_request, None)?;

    for operation in [
        WitnessServiceOperationV1::Commit,
        WitnessServiceOperationV1::Abort,
    ] {
        let terminal_request = fixture.session_service_request(operation)?;
        assert!(
            WitnessServiceResponseV1::Outcome(fixture.prepare_outcome_attestation()?)
                .validate_for_request(&terminal_request, None)
                .is_err()
        );
    }

    for operation in [
        WitnessServiceOperationV1::ReadPrepared,
        WitnessServiceOperationV1::ReadHead,
        WitnessServiceOperationV1::FetchPayload,
    ] {
        let read_request = fixture.session_service_request(operation)?;
        WitnessServiceResponseV1::Read(
            fixture.empty_read_attestation(operation, &read_request.request_digest)?,
        )
        .validate_for_request(&read_request, None)?;
    }

    let proof = VerifiedWitnessStoreStateV1::from_present(&fixture.envelope)?;
    let failure = fixture.signed_failure(&request, Some(fixture.envelope.store_state_digest()?))?;
    WitnessServiceResponseV1::Failure(failure.clone())
        .validate_for_request(&request, Some(&proof))?;

    let mut changed_request = request.clone();
    changed_request.request_nonce = "d".repeat(64);
    changed_request.request_digest = changed_request.computed_digest()?;
    assert!(
        WitnessServiceResponseV1::Failure(failure)
            .validate_for_request(&changed_request, Some(&proof))
            .is_err()
    );
    assert!(
        WitnessServiceResponseV1::Discover(fixture.discovery_attestation()?)
            .validate_for_request(&request, None)
            .is_err()
    );
    Ok(())
}

#[test]
fn failure_retryability_is_derived_from_code() -> ProtocolResult<()> {
    for code in [
        WitnessServiceFailureCodeV1::NonCanonical,
        WitnessServiceFailureCodeV1::AdmissionMismatch,
        WitnessServiceFailureCodeV1::StaleSession,
        WitnessServiceFailureCodeV1::Conflict,
        WitnessServiceFailureCodeV1::Contention,
        WitnessServiceFailureCodeV1::CapacityExhausted,
        WitnessServiceFailureCodeV1::InternalUnavailable,
    ] {
        let failure = WitnessServiceFailureV1::new(code);
        failure.validate()?;
        assert_eq!(failure.retryable, code.retryable());
        let mut forged = failure;
        forged.retryable = !forged.retryable;
        assert!(forged.validate().is_err());
    }
    Ok(())
}

#[test]
fn response_decoder_rejects_unknown_fields_or_unsigned_success() -> ProtocolResult<()> {
    let fixture = Fixture::new(4_096)?;
    let request = fixture.fence_service_request()?;
    let response = WitnessServiceResponseV1::Fence(fixture.fence.clone());
    let bytes = response.canonical_bytes()?;
    assert_eq!(
        WitnessServiceResponseV1::decode_for_request(&bytes, &request, None)?,
        response
    );

    let mut unsigned = serde_json::to_value(&response)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    unsigned
        .get_mut("Fence")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .remove("signature");
    let unsigned = serde_json::to_vec(&unsigned)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    assert!(WitnessServiceResponseV1::decode_for_request(&unsigned, &request, None).is_err());

    let unknown = br#"{"Success":{"request_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#;
    assert!(WitnessServiceResponseV1::decode_for_request(unknown, &request, None).is_err());
    Ok(())
}

#[test]
fn failure_store_state_digest_binds_current_snapshot_and_rejects_unproved_absence()
-> ProtocolResult<()> {
    let fixture = Fixture::new(4_096)?;
    let request = fixture.fence_service_request()?;
    let proof = VerifiedWitnessStoreStateV1::from_present(&fixture.envelope)?;
    let digest = fixture.envelope.store_state_digest()?;
    let valid = fixture.signed_failure(&request, Some(digest))?;
    WitnessServiceResponseV1::Failure(valid.clone())
        .validate_for_request(&request, Some(&proof))?;

    let unproved_absence = fixture.signed_failure(&request, None)?;
    assert!(
        WitnessServiceResponseV1::Failure(unproved_absence)
            .validate_for_request(&request, Some(&proof))
            .is_err()
    );

    for bad_digest in [
        Some("A".repeat(64)),
        Some("0".repeat(63)),
        Some("0".repeat(64)),
    ] {
        let changed = fixture.signed_failure(&request, bad_digest)?;
        assert!(
            WitnessServiceResponseV1::Failure(changed)
                .validate_for_request(&request, Some(&proof))
                .is_err()
        );
    }
    assert!(
        WitnessServiceResponseV1::Failure(valid)
            .validate_for_request(&request, None)
            .is_err()
    );
    Ok(())
}

#[test]
fn candidate_verifier_accepts_exact_candidate_without_mutation() -> ProtocolResult<()> {
    let fixture = Fixture::new(4_096)?;
    let before = fixture.envelope.canonical_bytes()?;
    let verified = fixture.verify(&fixture.candidate, &fixture.admission)?;
    assert_eq!(verified.candidate(), &fixture.candidate);
    assert_eq!(verified.session(), &fixture.session);
    assert_eq!(fixture.envelope.canonical_bytes()?, before);
    Ok(())
}

#[test]
fn candidate_verifier_rejects_each_field_mutation_without_store_change() -> ProtocolResult<()> {
    let fixture = Fixture::new(4_096)?;
    let before = fixture.envelope.canonical_bytes()?;

    // These are not broken wire objects. Each foreign candidate is rebuilt
    // through the canonical constructor after its binding and both payload
    // attestations are re-signed. They therefore pass CandidateV1 validation
    // and can only be refused by the service-side admission comparisons.
    let governance = Ed25519Signer::from_secret_material("phase285-plan01-governance");
    let foreign_governance =
        Ed25519Signer::from_secret_material("phase285-plan01-foreign-governance");
    let foreign_witness = Ed25519Signer::from_secret_material("phase285-plan01-foreign-witness");
    let mut admitted_foreign_candidates = Vec::new();

    let foreign_signer_binding = binding(&foreign_governance, &fixture.witness)?;
    admitted_foreign_candidates.push(candidate_with_payloads(
        &foreign_governance,
        &foreign_signer_binding,
        br#"{"state":"foreign-signer"}"#,
        br#"{"checkpoint":"foreign-signer"}"#,
    )?);

    let foreign_witness_binding = binding(&governance, &foreign_witness)?;
    admitted_foreign_candidates.push(candidate(&governance, &foreign_witness_binding)?.build()?);

    let mut foreign_identity_binding = fixture.binding.clone();
    foreign_identity_binding.witness_identity = "witness-foreign".to_string();
    admitted_foreign_candidates.push(
        candidate(
            &governance,
            &resign_binding(foreign_identity_binding, &governance)?,
        )?
        .build()?,
    );

    let mut foreign_generation_binding = fixture.binding.clone();
    foreign_generation_binding.generation = "b".repeat(64);
    admitted_foreign_candidates.push(
        candidate(
            &governance,
            &resign_binding(foreign_generation_binding, &governance)?,
        )?
        .build()?,
    );

    let mut foreign_authority_binding = fixture.binding.clone();
    let foreign_authority = ArtifactIdentityV1 {
        device: 1,
        inode: 101,
    };
    foreign_authority_binding.authority_pair = AuthorityPairIdentityV1 {
        current: foreign_authority,
        legacy: foreign_authority,
    };
    admitted_foreign_candidates.push(
        candidate(
            &governance,
            &resign_binding(foreign_authority_binding, &governance)?,
        )?
        .build()?,
    );

    let mut foreign_roles_binding = fixture.binding.clone();
    foreign_roles_binding.publication_roles = offset_roles(200);
    admitted_foreign_candidates.push(
        candidate(
            &governance,
            &resign_binding(foreign_roles_binding, &governance)?,
        )?
        .build()?,
    );

    for (index, candidate) in admitted_foreign_candidates.iter().enumerate() {
        candidate.validate()?;
        assert_ne!(
            candidate.candidate_digest,
            fixture.candidate.candidate_digest
        );
        assert_ne!(candidate.txid, fixture.candidate.txid);
        assert!(
            fixture.verify(candidate, &fixture.admission).is_err(),
            "self-consistent foreign candidate {index} survived admission"
        );
        assert_eq!(fixture.envelope.canonical_bytes()?, before);
    }

    let mut mutations = Vec::new();
    macro_rules! changed {
        ($body:expr) => {{
            let mut value = fixture.candidate.clone();
            $body(&mut value);
            mutations.push(value);
        }};
    }
    changed!(
        |value: &mut CandidateV1| value.preimage.publication_binding.signer_key_id = "1".repeat(64)
    );
    changed!(
        |value: &mut CandidateV1| value.preimage.publication_binding.witness_key_id =
            "2".repeat(64)
    );
    changed!(|value: &mut CandidateV1| value
        .preimage
        .publication_binding
        .witness_identity
        .push_str("-foreign"));
    changed!(
        |value: &mut CandidateV1| value.preimage.publication_binding.binding_digest =
            "3".repeat(64)
    );
    changed!(
        |value: &mut CandidateV1| value.preimage.publication_binding.generation = "b".repeat(64)
    );
    changed!(|value: &mut CandidateV1| value
        .preimage
        .publication_binding
        .authority_pair
        .current
        .inode += 1);
    changed!(|value: &mut CandidateV1| value
        .preimage
        .publication_binding
        .publication_roles
        .state_staging = value
        .preimage
        .publication_binding
        .publication_roles
        .state_canonical);
    changed!(|value: &mut CandidateV1| value.preimage.predecessor_head_digest = "4".repeat(64));
    changed!(
        |value: &mut CandidateV1| value.preimage.predecessor_data_head_digest = "5".repeat(64)
    );
    changed!(|value: &mut CandidateV1| value.preimage.state_payload = br#"{"state":9}"#.to_vec());
    changed!(|value: &mut CandidateV1| value.preimage.state_byte_len += 1);
    changed!(|value: &mut CandidateV1| value.preimage.state_digest = "6".repeat(64));
    changed!(
        |value: &mut CandidateV1| value.preimage.checkpoint_payload =
            br#"{"checkpoint":9}"#.to_vec()
    );
    changed!(|value: &mut CandidateV1| value.preimage.checkpoint_byte_len += 1);
    changed!(|value: &mut CandidateV1| value.preimage.checkpoint_digest = "a".repeat(64));
    changed!(|value: &mut CandidateV1| value.preimage.epoch += 1);
    changed!(|value: &mut CandidateV1| value.preimage.sequence += 1);
    changed!(|value: &mut CandidateV1| value.preimage.intent_counter += 1);
    changed!(|value: &mut CandidateV1| value.candidate_digest = "7".repeat(64));
    changed!(|value: &mut CandidateV1| value.txid = "8".repeat(64));

    for (index, candidate) in mutations.iter().enumerate() {
        assert!(
            fixture.verify(candidate, &fixture.admission).is_err(),
            "candidate mutation {index} survived"
        );
        assert_eq!(fixture.envelope.canonical_bytes()?, before);
    }

    let mut admission = fixture.admission.clone();
    admission.witness_identity.push_str("-foreign");
    admission.admission_digest = admission.computed_digest()?;
    assert!(fixture.verify(&fixture.candidate, &admission).is_err());
    assert_eq!(fixture.envelope.canonical_bytes()?, before);
    Ok(())
}

#[test]
fn candidate_verifier_rejects_stale_session_authorization_and_bounds_without_store_change()
-> ProtocolResult<()> {
    let fixture = Fixture::new(4_096)?;
    let before = fixture.envelope.canonical_bytes()?;
    let mut stale = fixture.session.clone();
    stale.session_generation += 1;
    assert!(
        WitnessCandidateVerifier::verify_prepare(
            &fixture.admission,
            &fixture.envelope,
            &stale,
            &fixture.authorization,
            None,
            &fixture.candidate,
            &fixture.request_digest,
            None,
        )
        .is_err()
    );

    let mut wrong_authorization = fixture.authorization.clone();
    wrong_authorization.signature.signature_hex = "00".repeat(64);
    assert!(
        WitnessCandidateVerifier::verify_prepare(
            &fixture.admission,
            &fixture.envelope,
            &fixture.session,
            &wrong_authorization,
            None,
            &fixture.candidate,
            &fixture.request_digest,
            None,
        )
        .is_err()
    );
    assert_eq!(fixture.envelope.canonical_bytes()?, before);

    let bounded = Fixture::new(1)?;
    let bounded_before = bounded.envelope.canonical_bytes()?;
    assert!(
        bounded
            .verify(&bounded.candidate, &bounded.admission)
            .is_err()
    );
    assert_eq!(bounded.envelope.canonical_bytes()?, bounded_before);
    Ok(())
}

#[test]
fn protocol_checkpoint_rejects_unverified_prepare_and_accepts_only_one_step_transition()
-> ProtocolResult<()> {
    let fixture = Fixture::new(4_096)?;
    let verified = fixture.verify(&fixture.candidate, &fixture.admission)?;
    let transition = prepare_verified_candidate(&fixture.envelope, verified)?;
    let signature = fixture.witness.sign(&transition.signing_bytes()?);
    let proposed = transition.seal(signature)?;
    assert!(proposed.prepared.is_some());
    assert_eq!(
        proposed.store_generation,
        fixture.envelope.store_generation + 1
    );

    let mut skipped = proposed;
    skipped.store_generation += 1;
    skipped.signature = fixture.witness.sign(&skipped.signing_bytes()?);
    assert!(
        validate_store_transition(&fixture.envelope, &skipped, fixture.store_expectation())
            .is_err()
    );

    let genesis_prepared = WitnessPreparedV1::from_candidate(
        &fixture.candidate,
        None,
        fixture.session.session_generation,
    )?;
    let genesis_abort = WitnessGenesisAbortedV1::from_prepared(
        &genesis_prepared,
        "phase285-plan01-bootstrap-abort".to_string(),
    )?;
    let verified_abort = verified_genesis_abort(&fixture, genesis_abort.clone())?;
    let mut aborted_envelope = fixture.envelope.clone();
    aborted_envelope.genesis_abort = Some(genesis_abort.clone());
    aborted_envelope.store_generation += 1;
    aborted_envelope.signature = fixture.witness.sign(&aborted_envelope.signing_bytes()?);
    aborted_envelope.validate()?;

    let governance = Ed25519Signer::from_secret_material("phase285-plan01-governance");
    let mut successor_preimage = candidate(&governance, &fixture.binding)?;
    successor_preimage.intent_counter = 2;
    let successor = successor_preimage.build()?;
    let successor_authorization = authorization(
        &Ed25519Signer::from_secret_material("phase285-plan01-ephemeral"),
        &fixture.session,
        WitnessOperationV1::Prepare,
        &successor.txid,
        &fixture.request_digest,
    )?;
    assert!(
        WitnessCandidateVerifier::verify_prepare(
            &fixture.admission,
            &aborted_envelope,
            &fixture.session,
            &successor_authorization,
            None,
            &successor,
            &fixture.request_digest,
            None,
        )
        .is_err(),
        "an unauthenticated absent-head counter-two candidate must fail closed"
    );
    let verified_successor = WitnessCandidateVerifier::verify_prepare(
        &fixture.admission,
        &aborted_envelope,
        &fixture.session,
        &successor_authorization,
        None,
        &successor,
        &fixture.request_digest,
        Some(&verified_abort),
    )?;
    let transition = prepare_verified_candidate(&aborted_envelope, verified_successor)?;
    let successor_signature = fixture.witness.sign(&transition.signing_bytes()?);
    let successor_envelope = transition.seal(successor_signature)?;
    assert!(successor_envelope.genesis_abort.is_none());
    assert_eq!(
        successor_envelope
            .prepared
            .as_ref()
            .and_then(|stored| stored.prepared.genesis_abort.as_ref()),
        Some(&genesis_abort)
    );
    assert_eq!(
        validate_store_transition(
            &aborted_envelope,
            &successor_envelope,
            fixture.store_expectation(),
        )?,
        swarm_governance::witness_engine::WitnessStoreTransitionV1::Prepare
    );
    Ok(())
}

#[test]
fn response_failure_maps_each_matchable_protocol_error() {
    let service_cases = [
        (
            WitnessServiceProtocolFailureV1::Canonical,
            WitnessServiceFailureCodeV1::NonCanonical,
        ),
        (
            WitnessServiceProtocolFailureV1::Admission,
            WitnessServiceFailureCodeV1::AdmissionMismatch,
        ),
        (
            WitnessServiceProtocolFailureV1::Signature,
            WitnessServiceFailureCodeV1::InvalidSignature,
        ),
        (
            WitnessServiceProtocolFailureV1::Bounds,
            WitnessServiceFailureCodeV1::BoundsExceeded,
        ),
        (
            WitnessServiceProtocolFailureV1::StaleSession,
            WitnessServiceFailureCodeV1::StaleSession,
        ),
        (
            WitnessServiceProtocolFailureV1::StaleIntent,
            WitnessServiceFailureCodeV1::StaleIntent,
        ),
        (
            WitnessServiceProtocolFailureV1::Conflict,
            WitnessServiceFailureCodeV1::Conflict,
        ),
        (
            WitnessServiceProtocolFailureV1::StoreTransition,
            WitnessServiceFailureCodeV1::StoreTransitionRefused,
        ),
    ];
    for (error, code) in service_cases {
        assert_eq!(
            WitnessServiceFailureV1::from_service_failure(error).failure_code,
            code
        );
    }

    let cases = [
        (
            ProtocolError::NonCanonicalEncoding,
            WitnessServiceFailureCodeV1::NonCanonical,
        ),
        (
            ProtocolError::Bounds {
                field: "payload".to_string(),
                observed: 2,
                maximum: 1,
            },
            WitnessServiceFailureCodeV1::BoundsExceeded,
        ),
        (
            ProtocolError::StaleIntent {
                expected: 2,
                observed: 1,
            },
            WitnessServiceFailureCodeV1::StaleIntent,
        ),
        (
            ProtocolError::WitnessOutcomeMismatch,
            WitnessServiceFailureCodeV1::InvalidSignature,
        ),
        (
            ProtocolError::AuthorityPairMismatch,
            WitnessServiceFailureCodeV1::AdmissionMismatch,
        ),
        (
            ProtocolError::RecoveryAmbiguous,
            WitnessServiceFailureCodeV1::StoreTransitionRefused,
        ),
    ];
    for (error, code) in cases {
        assert_eq!(
            WitnessServiceFailureV1::from_protocol_error(&error).failure_code,
            code
        );
    }
}

#[test]
fn canonical_response_round_trip_preserves_signing_preimage() -> ProtocolResult<()> {
    let fixture = Fixture::new(4_096)?;
    let request = fixture.fence_service_request()?;
    let proof = VerifiedWitnessStoreStateV1::from_present(&fixture.envelope)?;
    let failure = fixture.signed_failure(&request, Some(fixture.envelope.store_state_digest()?))?;
    let before = failure.signing_bytes()?;
    let response = WitnessServiceResponseV1::Failure(failure.clone());
    let bytes = response.canonical_bytes()?;
    let decoded = WitnessServiceResponseV1::decode_for_request(&bytes, &request, Some(&proof))?;
    let WitnessServiceResponseV1::Failure(decoded_failure) = decoded else {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    };
    assert_eq!(decoded_failure.signing_bytes()?, before);
    assert_eq!(decoded_failure, failure);
    Ok(())
}

struct Fixture {
    witness: Ed25519Signer,
    binding: PublicationBindingV1,
    admission: WitnessAdmissionRecordV1,
    fence: WitnessSessionStateFenceV1,
    challenge: RecoveryChallengeV1,
    session: WitnessSessionV1,
    envelope: WitnessStoreEnvelopeV1,
    candidate: CandidateV1,
    request_digest: String,
    authorization: WitnessSessionAuthorizationV1,
}

impl Fixture {
    fn new(max_retained_bytes: u64) -> ProtocolResult<Self> {
        let governance = Ed25519Signer::from_secret_material("phase285-plan01-governance");
        let witness = Ed25519Signer::from_secret_material("phase285-plan01-witness");
        let binding = binding(&governance, &witness)?;
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
        admission.admission_digest = admission.computed_digest()?;
        admission.validate()?;

        let empty = signed_empty_envelope(&witness, &admission)?;
        let (fence, challenge, session) =
            session_rotation(&governance, &witness, &binding, &empty)?;
        let receipt = WitnessSessionRotationReceiptV1::for_establish(
            fence.request.request_digest()?,
            &challenge,
            session.clone(),
            None,
        )?;
        let mut envelope = empty;
        envelope.session = Some(session.clone());
        envelope.last_session_rotation = Some(receipt);
        envelope.store_generation = 1;
        envelope.signature = witness.sign(&envelope.signing_bytes()?);
        envelope.validate()?;

        let candidate = candidate(&governance, &binding)?.build()?;
        let request_digest = "c".repeat(64);
        let authorization = authorization(
            &Ed25519Signer::from_secret_material("phase285-plan01-ephemeral"),
            &session,
            WitnessOperationV1::Prepare,
            &candidate.txid,
            &request_digest,
        )?;
        Ok(Self {
            witness,
            binding,
            admission,
            fence,
            challenge,
            session,
            envelope,
            candidate,
            request_digest,
            authorization,
        })
    }

    fn verify(
        &self,
        candidate: &CandidateV1,
        admission: &WitnessAdmissionRecordV1,
    ) -> ProtocolResult<VerifiedCandidateAdmissionV1> {
        WitnessCandidateVerifier::verify_prepare(
            admission,
            &self.envelope,
            &self.session,
            &self.authorization,
            None,
            candidate,
            &self.request_digest,
            None,
        )
    }

    fn fence_service_request(&self) -> ProtocolResult<WitnessServiceRequestV1> {
        let mut request = WitnessServiceRequestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: WitnessServiceOperationV1::Fence,
            request_nonce: "e".repeat(64),
            admission_digest: self.admission.admission_digest.clone(),
            body: WitnessServiceRequestBodyV1::Fence {
                request: Box::new(self.fence.request.clone()),
            },
            request_digest: "0".repeat(64),
            authorization: None,
        };
        request.request_digest = request.computed_digest()?;
        request.validate()?;
        Ok(request)
    }

    fn discover_service_request(&self) -> ProtocolResult<WitnessServiceRequestV1> {
        let mut request = WitnessServiceRequestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: WitnessServiceOperationV1::Discover,
            request_nonce: "f".repeat(64),
            admission_digest: self.admission.admission_digest.clone(),
            body: WitnessServiceRequestBodyV1::Discover {
                challenge: Box::new(self.challenge.clone()),
            },
            request_digest: "0".repeat(64),
            authorization: None,
        };
        request.request_digest = request.computed_digest()?;
        request.validate()?;
        Ok(request)
    }

    fn establish_service_request(&self) -> ProtocolResult<WitnessServiceRequestV1> {
        let mut request = WitnessServiceRequestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: WitnessServiceOperationV1::Establish,
            request_nonce: "a".repeat(64),
            admission_digest: self.admission.admission_digest.clone(),
            body: WitnessServiceRequestBodyV1::Establish {
                challenge: Box::new(self.challenge.clone()),
                expected_head: None,
            },
            request_digest: "0".repeat(64),
            authorization: None,
        };
        request.request_digest = request.computed_digest()?;
        request.validate()?;
        Ok(request)
    }

    fn session_service_request(
        &self,
        operation: WitnessServiceOperationV1,
    ) -> ProtocolResult<WitnessServiceRequestV1> {
        let (body, protocol_operation) = match operation {
            WitnessServiceOperationV1::Prepare => (
                WitnessServiceRequestBodyV1::Prepare {
                    session: Box::new(self.session.clone()),
                    expected_head: None,
                    candidate: Box::new(self.candidate.clone()),
                },
                WitnessOperationV1::Prepare,
            ),
            WitnessServiceOperationV1::Commit => (
                WitnessServiceRequestBodyV1::Commit {
                    session: Box::new(self.session.clone()),
                    txid: self.candidate.txid.clone(),
                },
                WitnessOperationV1::Commit,
            ),
            WitnessServiceOperationV1::Abort => (
                WitnessServiceRequestBodyV1::Abort {
                    session: Box::new(self.session.clone()),
                    txid: self.candidate.txid.clone(),
                },
                WitnessOperationV1::Abort,
            ),
            WitnessServiceOperationV1::ReadPrepared => (
                WitnessServiceRequestBodyV1::ReadPrepared {
                    session: Box::new(self.session.clone()),
                    target_txid: self.candidate.txid.clone(),
                },
                WitnessOperationV1::ReadPrepared,
            ),
            WitnessServiceOperationV1::ReadHead => (
                WitnessServiceRequestBodyV1::ReadHead {
                    session: Box::new(self.session.clone()),
                    target_txid: self.candidate.txid.clone(),
                },
                WitnessOperationV1::ReadHead,
            ),
            WitnessServiceOperationV1::FetchPayload => (
                WitnessServiceRequestBodyV1::FetchPayload {
                    session: Box::new(self.session.clone()),
                    txid: self.candidate.txid.clone(),
                },
                WitnessOperationV1::FetchPayload,
            ),
            _ => {
                return Err(ProtocolError::InvalidField {
                    field: "operation".to_string(),
                    reason: "fixture supports Prepare and read operations only".to_string(),
                });
            }
        };
        let mut request = WitnessServiceRequestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation,
            request_nonce: "b".repeat(64),
            admission_digest: self.admission.admission_digest.clone(),
            body,
            request_digest: "0".repeat(64),
            authorization: None,
        };
        request.request_digest = request.computed_digest()?;
        request.authorization = Some(authorization(
            &Ed25519Signer::from_secret_material("phase285-plan01-ephemeral"),
            &self.session,
            protocol_operation,
            &self.candidate.txid,
            &request.request_digest,
        )?);
        request.validate()?;
        Ok(request)
    }

    fn signed_failure(
        &self,
        request: &WitnessServiceRequestV1,
        store_state_digest: Option<String>,
    ) -> ProtocolResult<WitnessServiceFailureAttestationV1> {
        let mut failure = WitnessServiceFailureAttestationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            stream_id: self.binding.stream_id.clone(),
            admission_digest: request.admission_digest.clone(),
            witness_identity: self.binding.witness_identity.clone(),
            witness_key_id: self.binding.witness_key_id.clone(),
            store_state_digest,
            failure_code: WitnessServiceFailureCodeV1::Conflict,
            retryable: WitnessServiceFailureCodeV1::Conflict.retryable(),
            signature: self.witness.sign(&[]),
        };
        failure.signature = self.witness.sign(&failure.signing_bytes()?);
        Ok(failure)
    }

    fn discovery_attestation(&self) -> ProtocolResult<WitnessDiscoveryAttestationV1> {
        let discovery = WitnessDiscoveryV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            head: None,
            prepared: None,
            genesis_abort: None,
            recovery_session: self.session.clone(),
        };
        let mut attestation = WitnessDiscoveryAttestationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            challenge: self.challenge.clone(),
            discovery,
            witness_key_id: self.witness.key_id().to_string(),
            signature: self.witness.sign(&[]),
        };
        attestation.signature = self.witness.sign(&attestation.signing_bytes()?);
        Ok(attestation)
    }

    fn establish_attestation(&self) -> ProtocolResult<WitnessSessionAttestationV1> {
        let session_digest = digest_domain(
            WITNESS_SESSION_STATE_DOMAIN_V1,
            &canonical_wire_bytes(&self.session)?,
        )?;
        let external_marker = digest_domain(
            WITNESS_EXTERNAL_MARKER_DOMAIN_V1,
            &canonical_wire_bytes(&ExternalMarkerPreimage {
                accepted_challenge_digest: &self.challenge.challenge_digest()?,
                resulting_session_digest: &session_digest,
                response_kind: WitnessSessionRotationResponseKindV1::Establish,
            })?,
        )?;
        let mut attestation = WitnessSessionAttestationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            challenge: self.challenge.clone(),
            session: self.session.clone(),
            committed_head: None,
            external_marker,
            witness_key_id: self.binding.witness_key_id.clone(),
            signature: self.witness.sign(&[]),
        };
        attestation.signature = self.witness.sign(&attestation.signing_bytes()?);
        attestation.validate()?;
        Ok(attestation)
    }

    fn prepare_outcome_attestation(&self) -> ProtocolResult<WitnessOutcomeAttestationV1> {
        let prepared = WitnessPreparedV1::from_candidate(
            &self.candidate,
            None,
            self.session.session_generation,
        )?;
        let mut attestation = WitnessOutcomeAttestationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: WitnessOperationV1::Prepare,
            stream_id: self.binding.stream_id.clone(),
            binding_generation: self.binding.generation.clone(),
            binding_digest: self.binding.binding_digest.clone(),
            signer_key_id: self.binding.signer_key_id.clone(),
            authority_pair: self.binding.authority_pair,
            txid: self.candidate.txid.clone(),
            candidate_digest: self.candidate.candidate_digest.clone(),
            session_generation: self.session.session_generation,
            session_commitment: self.session.session_commitment.clone(),
            witness_key_id: self.binding.witness_key_id.clone(),
            outcome: WitnessOperationOutcomeV1::Prepare(Box::new(
                WitnessPrepareOutcomeV1::Prepared(prepared),
            )),
            signature: self.witness.sign(&[]),
        };
        attestation.signature = self.witness.sign(&attestation.signing_bytes()?);
        attestation.validate()?;
        Ok(attestation)
    }

    fn empty_read_attestation(
        &self,
        operation: WitnessServiceOperationV1,
        request_digest: &str,
    ) -> ProtocolResult<WitnessReadAttestationV1> {
        let (protocol_operation, response) = match operation {
            WitnessServiceOperationV1::ReadPrepared => (
                WitnessOperationV1::ReadPrepared,
                WitnessReadResponseV1::Prepared(Box::new(None)),
            ),
            WitnessServiceOperationV1::ReadHead => (
                WitnessOperationV1::ReadHead,
                WitnessReadResponseV1::Head(Box::new(None)),
            ),
            WitnessServiceOperationV1::FetchPayload => (
                WitnessOperationV1::FetchPayload,
                WitnessReadResponseV1::Payload(Box::new(None)),
            ),
            _ => {
                return Err(ProtocolError::InvalidField {
                    field: "operation".to_string(),
                    reason: "fixture requires a read operation".to_string(),
                });
            }
        };
        let mut attestation = WitnessReadAttestationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: protocol_operation,
            stream_id: self.binding.stream_id.clone(),
            binding_generation: self.binding.generation.clone(),
            binding_digest: self.binding.binding_digest.clone(),
            signer_key_id: self.binding.signer_key_id.clone(),
            authority_pair: self.binding.authority_pair,
            target_txid: self.candidate.txid.clone(),
            request_digest: request_digest.to_string(),
            session_generation: self.session.session_generation,
            session_commitment: self.session.session_commitment.clone(),
            witness_key_id: self.binding.witness_key_id.clone(),
            response,
            signature: self.witness.sign(&[]),
        };
        attestation.signature = self.witness.sign(&attestation.signing_bytes()?);
        attestation.validate()?;
        Ok(attestation)
    }

    fn store_expectation(&self) -> swarm_governance::witness_engine::WitnessStoreExpectationV1<'_> {
        swarm_governance::witness_engine::WitnessStoreExpectationV1 {
            admission_digest: &self.admission.admission_digest,
            bucket_epoch_digest: &self.envelope.bucket_epoch_digest,
            stream_initialization_digest: &self.envelope.stream_initialization_digest,
            stream_id: &self.admission.stream_id,
            witness_identity: &self.admission.witness_identity,
            witness_key_id: &self.admission.witness_key_id,
            authority_pair: self.admission.authority_pair,
            binding_generation: &self.admission.binding_generation,
            binding_digest: &self.admission.binding_digest,
            signer_key_id: &self.admission.signer_key_id,
        }
    }
}

fn signed_empty_envelope(
    witness: &Ed25519Signer,
    admission: &WitnessAdmissionRecordV1,
) -> ProtocolResult<WitnessStoreEnvelopeV1> {
    let mut envelope = WitnessStoreEnvelopeV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        admission_digest: admission.admission_digest.clone(),
        bucket_epoch_digest: "1".repeat(64),
        stream_initialization_digest: "2".repeat(64),
        stream_id: admission.stream_id.clone(),
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
    envelope.signature = witness.sign(&envelope.signing_bytes()?);
    envelope.validate()?;
    Ok(envelope)
}

fn session_rotation(
    governance: &Ed25519Signer,
    witness: &Ed25519Signer,
    binding: &PublicationBindingV1,
    envelope: &WitnessStoreEnvelopeV1,
) -> ProtocolResult<(
    WitnessSessionStateFenceV1,
    RecoveryChallengeV1,
    WitnessSessionV1,
)> {
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
        current_session_generation: None,
        current_session_digest: None,
        current_head_digest: None,
        current_prepared_digest: None,
        witness_nonce: "6".repeat(64),
        witness_identity: binding.witness_identity.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        signature: witness.sign(&[]),
    };
    fence.signature = witness.sign(&fence.signing_bytes()?);
    fence.validate()?;

    let ephemeral = Ed25519Signer::from_secret_material("phase285-plan01-ephemeral");
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
        session_generation: 1,
        session_commitment: challenge.session_commitment.clone(),
    };
    session.validate()?;
    Ok((fence, challenge, session))
}

fn verified_genesis_abort(
    fixture: &Fixture,
    genesis_abort: WitnessGenesisAbortedV1,
) -> ProtocolResult<VerifiedWitnessOutcomeV1> {
    let governance = Ed25519Signer::from_secret_material("phase285-plan01-governance");
    let secret = [7_u8; 32];
    let ephemeral = swarm_crypto::Keypair::from_seed(&secret).public_key();
    let mut challenge = fixture.challenge.clone();
    challenge.ephemeral_key_id = sha256_hex(ephemeral.as_bytes());
    challenge.session_commitment = sha256_hex(&secret);
    challenge.signature = governance.sign(&challenge.signing_bytes()?);
    challenge.validate()?;

    let mut session = fixture.session.clone();
    session.ephemeral_key_id = challenge.ephemeral_key_id.clone();
    session.session_commitment = challenge.session_commitment.clone();
    session.validate()?;
    let session_digest = digest_domain(
        WITNESS_SESSION_STATE_DOMAIN_V1,
        &canonical_wire_bytes(&session)?,
    )?;
    let external_marker = digest_domain(
        WITNESS_EXTERNAL_MARKER_DOMAIN_V1,
        &canonical_wire_bytes(&ExternalMarkerPreimage {
            accepted_challenge_digest: &challenge.challenge_digest()?,
            resulting_session_digest: &session_digest,
            response_kind: WitnessSessionRotationResponseKindV1::Establish,
        })?,
    )?;
    let mut session_attestation = WitnessSessionAttestationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        challenge: challenge.clone(),
        session,
        committed_head: None,
        external_marker,
        witness_key_id: fixture.witness.key_id().to_string(),
        signature: fixture.witness.sign(&[]),
    };
    session_attestation.signature = fixture.witness.sign(&session_attestation.signing_bytes()?);
    let governance_session = GovernanceWitnessSession::from_verified_attestation(
        GovernanceWitnessSessionRequest::from_secret(challenge, secret)?,
        session_attestation,
        None,
        &fixture.binding,
    )?;

    let mut outcome_attestation = WitnessOutcomeAttestationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        operation: WitnessOperationV1::Abort,
        stream_id: fixture.binding.stream_id.clone(),
        binding_generation: fixture.binding.generation.clone(),
        binding_digest: fixture.binding.binding_digest.clone(),
        signer_key_id: fixture.binding.signer_key_id.clone(),
        authority_pair: fixture.binding.authority_pair,
        txid: genesis_abort.txid.clone(),
        candidate_digest: genesis_abort.candidate_digest.clone(),
        session_generation: governance_session.attestation().session_generation,
        session_commitment: governance_session.attestation().session_commitment.clone(),
        witness_key_id: fixture.binding.witness_key_id.clone(),
        outcome: WitnessOperationOutcomeV1::Abort(Box::new(WitnessAbortOutcomeV1::GenesisAborted(
            genesis_abort,
        ))),
        signature: fixture.witness.sign(&[]),
    };
    outcome_attestation.signature = fixture.witness.sign(&outcome_attestation.signing_bytes()?);
    let outcome_txid = outcome_attestation.txid.clone();
    let outcome_candidate_digest = outcome_attestation.candidate_digest.clone();
    VerifiedWitnessOutcomeV1::from_attestation(
        outcome_attestation,
        &governance_session,
        WitnessOperationV1::Abort,
        &outcome_txid,
        &outcome_candidate_digest,
    )
}

fn candidate(
    governance: &Ed25519Signer,
    binding: &PublicationBindingV1,
) -> ProtocolResult<CandidatePreimageV1> {
    let before = initial_mapping(binding.publication_roles);
    let genesis = GenesisPredecessorV1::for_binding(binding);
    let state_payload = br#"{"state":1}"#.to_vec();
    let checkpoint_payload = br#"{"checkpoint":1}"#.to_vec();
    let state_digest = sha256_hex(&state_payload);
    let checkpoint_digest = sha256_hex(&checkpoint_payload);
    let value = CandidatePreimageV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: binding.stream_id.clone(),
        predecessor_head: None,
        predecessor_head_digest: genesis.digest()?,
        predecessor_data_head_digest: genesis.data_head_digest()?,
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
        publication_mapping_before: before,
        publication_mapping_after: PublicationMappingV1 {
            state_canonical: before.state_staging,
            state_staging: before.state_canonical,
            checkpoint_canonical: before.checkpoint_staging,
            checkpoint_staging: before.checkpoint_canonical,
            journal_primary: before.journal_primary,
            journal_secondary: before.journal_secondary,
        },
        epoch: 0,
        sequence: 0,
        intent_counter: 1,
    };
    value.validate()?;
    Ok(value)
}

fn candidate_with_payloads(
    governance: &Ed25519Signer,
    binding: &PublicationBindingV1,
    state_payload: &[u8],
    checkpoint_payload: &[u8],
) -> ProtocolResult<CandidateV1> {
    let mut value = candidate(governance, binding)?;
    value.state_payload = state_payload.to_vec();
    value.state_byte_len = value.state_payload.len() as u64;
    value.state_digest = sha256_hex(&value.state_payload);
    value.state_attestation = sign_payload(
        governance,
        STATE_PAYLOAD_DOMAIN_V1,
        binding,
        value.state_payload.clone(),
        value.state_digest.clone(),
    )?;
    value.checkpoint_payload = checkpoint_payload.to_vec();
    value.checkpoint_byte_len = value.checkpoint_payload.len() as u64;
    value.checkpoint_digest = sha256_hex(&value.checkpoint_payload);
    value.checkpoint_attestation = sign_payload(
        governance,
        CHECKPOINT_PAYLOAD_DOMAIN_V1,
        binding,
        value.checkpoint_payload.clone(),
        value.checkpoint_digest.clone(),
    )?;
    value.build()
}

fn resign_binding(
    mut value: PublicationBindingV1,
    governance: &Ed25519Signer,
) -> ProtocolResult<PublicationBindingV1> {
    value.binding_digest = "0".repeat(64);
    value.binding_signature = governance.sign(&[]);
    let signing_bytes = value.signing_bytes()?;
    value.binding_digest = value.computed_digest()?;
    value.binding_signature = governance.sign(&signing_bytes);
    value.validate()?;
    Ok(value)
}

fn binding(
    governance: &Ed25519Signer,
    witness: &Ed25519Signer,
) -> ProtocolResult<PublicationBindingV1> {
    let roles = roles();
    let mut value = PublicationBindingV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: "tom-primary".to_string(),
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
        publication_roles: roles,
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
        witness_identity: "witness-1".to_string(),
        binding_digest: "0".repeat(64),
        binding_signature: governance.sign(&[]),
    };
    let signing_bytes = value.signing_bytes()?;
    value.binding_digest = value.computed_digest()?;
    value.binding_signature = governance.sign(&signing_bytes);
    value.validate()?;
    Ok(value)
}

fn roles() -> PublicationRoleIdentitiesV1 {
    offset_roles(0)
}

fn offset_roles(offset: u64) -> PublicationRoleIdentitiesV1 {
    PublicationRoleIdentitiesV1 {
        state_canonical: ArtifactIdentityV1 {
            device: 2,
            inode: offset + 1,
        },
        state_staging: ArtifactIdentityV1 {
            device: 2,
            inode: offset + 2,
        },
        checkpoint_canonical: ArtifactIdentityV1 {
            device: 2,
            inode: offset + 3,
        },
        checkpoint_staging: ArtifactIdentityV1 {
            device: 2,
            inode: offset + 4,
        },
        journal_primary: ArtifactIdentityV1 {
            device: 2,
            inode: offset + 5,
        },
        journal_secondary: ArtifactIdentityV1 {
            device: 2,
            inode: offset + 6,
        },
    }
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

#[derive(Serialize)]
struct AuthorizationPreimage<'a> {
    schema_version: u32,
    operation: WitnessOperationV1,
    stream_id: &'a str,
    binding_digest: &'a str,
    txid: &'a str,
    request_digest: &'a str,
    session_generation: u64,
    session_commitment: &'a str,
    ephemeral_key_id: &'a str,
}

#[derive(Serialize)]
struct ExternalMarkerPreimage<'a> {
    accepted_challenge_digest: &'a str,
    resulting_session_digest: &'a str,
    response_kind: WitnessSessionRotationResponseKindV1,
}

fn authorization(
    ephemeral: &Ed25519Signer,
    session: &WitnessSessionV1,
    operation: WitnessOperationV1,
    txid: &str,
    request_digest: &str,
) -> ProtocolResult<WitnessSessionAuthorizationV1> {
    let preimage = AuthorizationPreimage {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        operation,
        stream_id: &session.stream_id,
        binding_digest: &session.binding_digest,
        txid,
        request_digest,
        session_generation: session.session_generation,
        session_commitment: &session.session_commitment,
        ephemeral_key_id: &session.ephemeral_key_id,
    };
    Ok(WitnessSessionAuthorizationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        operation,
        stream_id: session.stream_id.clone(),
        binding_digest: session.binding_digest.clone(),
        txid: txid.to_string(),
        request_digest: request_digest.to_string(),
        session_generation: session.session_generation,
        session_commitment: session.session_commitment.clone(),
        ephemeral_key_id: session.ephemeral_key_id.clone(),
        signature: ephemeral.sign(&canonical_wire_bytes(&preimage)?),
    })
}
