//! Phase 285 Plan 01 witness-service conformance target.

use async_trait::async_trait;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use swarm_crypto::{DetachedSignature, Ed25519Signer, sha256_hex};
use swarm_governance::persistence_protocol::*;
use swarm_governance::witness_engine::store::in_memory::{
    InMemoryWitnessStore, ReferenceWitnessStoreModel, WitnessStoreFault,
};
use swarm_governance::witness_engine::store::proxy::WitnessStoreProxy;
use swarm_governance::witness_engine::store::*;
use swarm_governance::witness_engine::{
    WitnessStoreEnvelopeV1, WitnessStoredCandidateV1, validate_store_transition, witness_stream_key,
};
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

#[test]
fn service_request_draft_derives_nonce_operation_target_and_authorization_once()
-> ProtocolResult<()> {
    let fixture = Fixture::new(4_096)?;
    let nonce = witness_service_request_nonce([41; 32]);
    assert_eq!(nonce, sha256_hex(&[41; 32]));

    let fence = WitnessServiceRequestDraftV1::new(
        nonce.clone(),
        fixture.admission.admission_digest.clone(),
        WitnessServiceRequestBodyV1::Fence {
            request: Box::new(fixture.fence.request.clone()),
        },
    )?
    .finalize_without_authorization()?;
    assert_eq!(fence.operation, WitnessServiceOperationV1::Fence);
    assert_eq!(fence.request_nonce, nonce);
    assert!(fence.authorization.is_none());

    let governance_session = fixture.governance_session()?;
    let wire_session = governance_session.attestation().clone();
    let cases = [
        (
            WitnessServiceOperationV1::Prepare,
            WitnessOperationV1::Prepare,
            WitnessServiceRequestBodyV1::Prepare {
                session: Box::new(wire_session.clone()),
                expected_head: None,
                candidate: Box::new(fixture.candidate.clone()),
            },
        ),
        (
            WitnessServiceOperationV1::Commit,
            WitnessOperationV1::Commit,
            WitnessServiceRequestBodyV1::Commit {
                session: Box::new(wire_session.clone()),
                txid: fixture.candidate.txid.clone(),
            },
        ),
        (
            WitnessServiceOperationV1::Abort,
            WitnessOperationV1::Abort,
            WitnessServiceRequestBodyV1::Abort {
                session: Box::new(wire_session.clone()),
                txid: fixture.candidate.txid.clone(),
            },
        ),
        (
            WitnessServiceOperationV1::ReadPrepared,
            WitnessOperationV1::ReadPrepared,
            WitnessServiceRequestBodyV1::ReadPrepared {
                session: Box::new(wire_session.clone()),
                target_txid: fixture.candidate.txid.clone(),
            },
        ),
        (
            WitnessServiceOperationV1::ReadHead,
            WitnessOperationV1::ReadHead,
            WitnessServiceRequestBodyV1::ReadHead {
                session: Box::new(wire_session.clone()),
                target_txid: fixture.candidate.txid.clone(),
            },
        ),
        (
            WitnessServiceOperationV1::FetchPayload,
            WitnessOperationV1::FetchPayload,
            WitnessServiceRequestBodyV1::FetchPayload {
                session: Box::new(wire_session.clone()),
                txid: fixture.candidate.txid.clone(),
            },
        ),
    ];
    for (service_operation, authorization_operation, body) in cases {
        let draft = WitnessServiceRequestDraftV1::new(
            witness_service_request_nonce([service_operation as u8; 32]),
            fixture.admission.admission_digest.clone(),
            body,
        )?;
        let digest = draft.request_digest().to_string();
        let request = draft.finalize_with_session(&governance_session)?;
        assert_eq!(request.operation, service_operation);
        let authorization = request
            .authorization
            .as_ref()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        assert_eq!(authorization.operation, authorization_operation);
        assert_eq!(authorization.txid, fixture.candidate.txid);
        assert_eq!(authorization.request_digest, digest);
    }
    Ok(())
}

#[test]
fn client_failure_decoder_is_request_bound_without_raw_store_proof() -> ProtocolResult<()> {
    let fixture = Fixture::new(4_096)?;
    let request = fixture.fence_service_request()?;
    let failure = fixture.signed_failure(&request, Some(fixture.envelope.store_state_digest()?))?;
    let bytes = WitnessServiceResponseV1::Failure(failure.clone()).canonical_bytes()?;
    assert_eq!(
        WitnessServiceResponseV1::decode_for_client_request(&bytes, &request)?,
        WitnessServiceResponseV1::Failure(failure.clone())
    );
    assert!(
        WitnessServiceResponseV1::decode_for_request(&bytes, &request, None).is_err(),
        "server-side failure validation must retain authenticated store proof"
    );
    let mut changed = request;
    changed.request_nonce = "d".repeat(64);
    changed.request_digest = changed.computed_digest()?;
    assert!(WitnessServiceResponseV1::decode_for_client_request(&bytes, &changed).is_err());
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

    fn governance_session(&self) -> ProtocolResult<GovernanceWitnessSession> {
        let governance = Ed25519Signer::from_secret_material("phase285-plan01-governance");
        let secret = [7_u8; 32];
        let ephemeral = swarm_crypto::Keypair::from_seed(&secret).public_key();
        let mut challenge = self.challenge.clone();
        challenge.ephemeral_key_id = sha256_hex(ephemeral.as_bytes());
        challenge.session_commitment = sha256_hex(&secret);
        challenge.signature = governance.sign(&challenge.signing_bytes()?);
        challenge.validate()?;

        let mut session = self.session.clone();
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
        let mut attestation = WitnessSessionAttestationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            challenge: challenge.clone(),
            session,
            committed_head: None,
            external_marker,
            witness_key_id: self.witness.key_id().to_string(),
            signature: self.witness.sign(&[]),
        };
        attestation.signature = self.witness.sign(&attestation.signing_bytes()?);
        GovernanceWitnessSession::from_verified_attestation(
            GovernanceWitnessSessionRequest::from_secret(challenge, secret)?,
            attestation,
            None,
            &self.binding,
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

type StoreTestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type StoreEntries = BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>;
type ReadyAndEntries = (WitnessStoreReadyResultV1, StoreEntries);
type ReadyEntriesAndEnvelope = (
    WitnessStoreReadyResultV1,
    StoreEntries,
    WitnessStoreEnvelopeV1,
);

fn raw_stream_configuration_digest(
    configuration: &WitnessBucketConfigurationV1,
) -> ProtocolResult<String> {
    let authoritative_raw = serde_json::json!({
        "authoritative_stream_configuration": configuration,
        "source": "nats-2.11.17-stream-info",
    });
    digest_domain(
        b"swarm.governance.witness-store.raw-stream-configuration.v1",
        &canonical_wire_bytes(&authoritative_raw)?,
    )
}

const REFERENCE_ORACLE_FORBIDDEN_TOKENS: &[&str] = &[
    "validate_store_transition",
    "validate_cas_transition",
    "validate_read_entry",
    "validate_admission_bounds",
    "validate_for",
    "validate_signature_before_semantics",
    "store_state_digest",
    "signed_envelope_digest",
    "computed_digest",
    ".digest",
    "WitnessStoreExpectationV1",
    "expectation",
    "committed_from_candidate",
    "validate_against_prepared",
    ".build(",
    ".validate(",
    "WitnessHeadV1 {",
    "CandidateV1 {",
    "WitnessPreparedV1 {",
    "WitnessSessionV1 {",
    "WitnessSessionRotationReceiptV1 {",
    "TxidPreimageV1 {",
    "SignedPayloadPreimageV1 {",
    "GenesisPredecessorV1 {",
    "WitnessAbortSummaryV1 {",
    "WitnessStoredCandidateV1 {",
    "WitnessStoredPreparedV1 {",
    "WitnessDiscoveryV1 {",
    "PublicationBindingV1 {",
    ".canonical_bytes(",
    ".head_digest(",
    ".data_head_digest(",
    ".candidate_digest(",
    ".txid(",
    ".receipt_digest(",
    ".signing_bytes(",
];

fn reference_oracle_is_independent(source: &str) -> bool {
    REFERENCE_ORACLE_FORBIDDEN_TOKENS
        .iter()
        .all(|token| !source.contains(token))
}

#[derive(Clone, Copy)]
struct StoreBounds {
    state: u64,
    checkpoint: u64,
    binding: u64,
    retained: u64,
    request: u64,
    response: u64,
}

struct StoreFixture {
    stream_id: String,
    current: WitnessStoreEnvelopeV1,
    proposed: WitnessStoreEnvelopeV1,
    entries: BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>,
    ready: WitnessStoreReadyResultV1,
    base: Fixture,
}

impl StoreFixture {
    fn new() -> StoreTestResult<Self> {
        let mut fixture = Fixture::new(1_000_000)?;
        let governance = Ed25519Signer::from_secret_material("phase285-plan01-governance");
        let admission_entry = WitnessAdmissionEntryV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            admission: fixture.admission.clone(),
            governance_signer_public_key_hex: governance.public_key_hex().to_string(),
            max_state_bytes: fixture.admission.limits.max_payload_bytes,
            max_checkpoint_bytes: fixture.admission.limits.max_payload_bytes,
            max_binding_bytes: fixture.admission.limits.max_record_bytes,
            max_request_bytes: fixture.admission.limits.max_record_bytes,
            max_response_bytes: fixture.admission.limits.max_record_bytes,
            predecessor_admission_digest: None,
        };
        admission_entry.validate()?;
        let mut admission_set = WitnessAdmissionSetV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            entries: vec![admission_entry],
            admission_set_digest: "0".repeat(64),
        };
        admission_set.admission_set_digest = admission_set.computed_digest()?;
        admission_set.validate()?;

        let deployment_inputs = WitnessStoreDeploymentInputsV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            max_manifest_bytes: 1_000_000,
            maximum_admitted_streams: 3,
            configured_replica_count: 5,
        };
        let max_store = admission_set.entries[0].max_retained_bytes;
        let required_bucket_bytes = 2 * (deployment_inputs.max_manifest_bytes + 65_536)
            + deployment_inputs.maximum_admitted_streams * 2 * (max_store + 65_536);
        let bucket_configuration = store_bucket_configuration(
            max_store.max(deployment_inputs.max_manifest_bytes),
            required_bucket_bytes,
            deployment_inputs.configured_replica_count,
        )?;
        let bucket_configuration_digest = bucket_configuration.digest()?;
        let bucket_epoch = WitnessBucketEpochV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            bucket_generation: "9".repeat(64),
            nats_account: "phase285-account".to_string(),
            stream_name: bucket_configuration.stream_name.clone(),
            bucket_configuration_digest: bucket_configuration_digest.clone(),
            admission_set_digest: admission_set.admission_set_digest.clone(),
            witness_identity: fixture.admission.witness_identity.clone(),
            witness_key_id: fixture.admission.witness_key_id.clone(),
        };
        let bucket_epoch_digest = bucket_epoch.digest()?;
        let initialization_digest = WitnessStreamInitializationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            bucket_epoch_digest: bucket_epoch_digest.clone(),
            admission_digest: fixture.admission.admission_digest.clone(),
            stream_id: fixture.admission.stream_id.clone(),
            witness_identity: fixture.admission.witness_identity.clone(),
            witness_key_id: fixture.admission.witness_key_id.clone(),
        }
        .digest()?;

        fixture.envelope.bucket_epoch_digest = bucket_epoch_digest.clone();
        fixture.envelope.stream_initialization_digest = initialization_digest.clone();
        fixture.envelope.signature = fixture.witness.sign(&fixture.envelope.signing_bytes()?);
        let mut empty = fixture.envelope.clone();
        empty.session = None;
        empty.last_session_rotation = None;
        empty.current = None;
        empty.predecessor = None;
        empty.prepared = None;
        empty.genesis_abort = None;
        empty.store_generation = 0;
        empty.signature = fixture.witness.sign(&empty.signing_bytes()?);

        let stream_key = witness_stream_key(&fixture.admission.stream_id)?;
        let mut ready_manifest = WitnessBucketManifestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            bucket_epoch_digest,
            bucket_configuration_digest: bucket_configuration_digest.clone(),
            admission_set_digest: admission_set.admission_set_digest.clone(),
            stream_keys: vec![stream_key.clone()],
            initialized_streams: BTreeMap::from([(
                stream_key,
                WitnessStreamInitializationRecordV1 {
                    schema_version: PROTOCOL_SCHEMA_VERSION,
                    stream_initialization_digest: initialization_digest,
                    empty_envelope_digest: empty.signed_envelope_digest()?,
                },
            )]),
            phase: WitnessBucketManifestPhaseV1::Ready,
            witness_identity: fixture.admission.witness_identity.clone(),
            witness_key_id: fixture.admission.witness_key_id.clone(),
            signature: fixture.witness.sign(&[]),
        };
        ready_manifest.signature = fixture.witness.sign(&ready_manifest.signing_bytes()?);
        let mut bucket_anchor = WitnessBucketAnchorV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            epoch: bucket_epoch.clone(),
            nats_stream_created_at: "2026-08-25T00:00:00.000000000Z".to_string(),
            raw_stream_configuration_digest: raw_stream_configuration_digest(
                &bucket_configuration,
            )?,
            ready_manifest_digest: ready_manifest.digest()?,
            witness_key_id: fixture.admission.witness_key_id.clone(),
            signature: fixture.witness.sign(&[]),
        };
        bucket_anchor.signature = fixture.witness.sign(&bucket_anchor.signing_bytes()?);

        let verified = fixture.verify(&fixture.candidate, &fixture.admission)?;
        let transition = prepare_verified_candidate(&fixture.envelope, verified)?;
        let transition_signature = fixture.witness.sign(&transition.signing_bytes()?);
        let proposed = transition.seal(transition_signature)?;
        let current = fixture.envelope.clone();
        let entries = BTreeMap::from([(fixture.admission.stream_id.clone(), (7, current.clone()))]);
        let ready = WitnessStoreReadyResultV1::new(
            bucket_anchor.nats_stream_created_at.clone(),
            bucket_configuration,
            bucket_epoch,
            bucket_anchor,
            admission_set,
            ready_manifest,
            deployment_inputs,
        )?;
        Ok(Self {
            stream_id: fixture.admission.stream_id.clone(),
            current,
            proposed,
            entries,
            ready,
            base: fixture,
        })
    }

    fn store(&self, capacity: usize) -> Result<InMemoryWitnessStore, WitnessStoreErrorV1> {
        InMemoryWitnessStore::new(self.ready.clone(), self.entries.clone(), capacity)
    }

    fn commit_envelope(&self) -> ProtocolResult<WitnessStoreEnvelopeV1> {
        let prepared = self
            .proposed
            .prepared
            .as_ref()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        let candidate = prepared.candidate.build()?;
        let mut committed = self.proposed.clone();
        committed.predecessor = self.proposed.current.clone();
        committed.current = Some(WitnessStoredCandidateV1 {
            candidate: prepared.candidate.clone(),
            head: WitnessHeadV1::committed_from_candidate(&candidate)?,
        });
        committed.prepared = None;
        committed.store_generation += 1;
        committed.signature = self.base.witness.sign(&committed.signing_bytes()?);
        Ok(committed)
    }

    fn rebuilt_commit_content_mutant(&self) -> StoreTestResult<WitnessStoreEnvelopeV1> {
        let governance = Ed25519Signer::from_secret_material("phase285-plan01-governance");
        let mut committed = self.commit_envelope()?;
        let stored = committed
            .current
            .as_mut()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        stored.candidate.state_payload = br#"{"state":"well-formed-but-not-sealed"}"#.to_vec();
        stored.candidate.state_byte_len = stored.candidate.state_payload.len() as u64;
        stored.candidate.state_digest = sha256_hex(&stored.candidate.state_payload);
        let binding = &stored.candidate.publication_binding;
        let state_preimage = SignedPayloadPreimageV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            domain: STATE_PAYLOAD_DOMAIN_V1.to_string(),
            stream_id: stored.candidate.stream_id.clone(),
            binding_generation: binding.generation.clone(),
            binding_digest: binding.binding_digest.clone(),
            authority_pair: binding.authority_pair,
            payload: stored.candidate.state_payload.clone(),
            byte_len: stored.candidate.state_byte_len,
            digest: stored.candidate.state_digest.clone(),
        };
        stored.candidate.state_attestation = governance.sign(&state_preimage.canonical_bytes()?);
        let rebuilt = stored.candidate.build()?;
        stored.head = WitnessHeadV1::committed_from_candidate(&rebuilt)?;
        committed.signature = self.base.witness.sign(&committed.signing_bytes()?);
        committed.validate()?;
        Ok(committed)
    }

    fn abort_envelope(&self) -> ProtocolResult<WitnessStoreEnvelopeV1> {
        let prepared = self
            .proposed
            .prepared
            .as_ref()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        let mut aborted = self.proposed.clone();
        aborted.prepared = None;
        aborted.genesis_abort = Some(WitnessGenesisAbortedV1::from_prepared(
            &prepared.prepared,
            "phase285-plan02-independent-abort".to_string(),
        )?);
        aborted.store_generation += 1;
        aborted.signature = self.base.witness.sign(&aborted.signing_bytes()?);
        Ok(aborted)
    }

    fn rebuild_ready_for_epoch(
        &self,
        mut ready: WitnessStoreReadyResultV1,
        epoch: WitnessBucketEpochV1,
        manifest_signer: &Ed25519Signer,
    ) -> StoreTestResult<ReadyAndEntries> {
        let epoch_digest = digest_domain(
            WITNESS_BUCKET_EPOCH_DOMAIN_V1,
            &canonical_wire_bytes(&epoch)?,
        )?;
        let mut entries = BTreeMap::new();
        let mut stream_keys = Vec::new();
        let mut initialized_streams = BTreeMap::new();
        for admission in &ready.admission_set.entries {
            let initialization_digest = WitnessStreamInitializationV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                bucket_epoch_digest: epoch_digest.clone(),
                admission_digest: admission.admission_digest.clone(),
                stream_id: admission.stream_id.clone(),
                witness_identity: admission.witness_identity.clone(),
                witness_key_id: admission.witness_key_id.clone(),
            }
            .digest()?;
            let mut envelope = self.current.clone();
            envelope.stream_id = admission.stream_id.clone();
            envelope.admission_digest = admission.admission_digest.clone();
            envelope.bucket_epoch_digest = epoch_digest.clone();
            envelope.stream_initialization_digest = initialization_digest.clone();
            envelope.witness_identity = admission.witness_identity.clone();
            envelope.witness_key_id = admission.witness_key_id.clone();
            envelope.signature = self.base.witness.sign(&envelope.signing_bytes()?);
            let mut empty = envelope.clone();
            empty.session = None;
            empty.last_session_rotation = None;
            empty.current = None;
            empty.predecessor = None;
            empty.prepared = None;
            empty.genesis_abort = None;
            empty.store_generation = 0;
            empty.signature = self.base.witness.sign(&empty.signing_bytes()?);
            let key = witness_stream_key(&admission.stream_id)?;
            stream_keys.push(key.clone());
            initialized_streams.insert(
                key,
                WitnessStreamInitializationRecordV1 {
                    schema_version: PROTOCOL_SCHEMA_VERSION,
                    stream_initialization_digest: initialization_digest,
                    empty_envelope_digest: empty.signed_envelope_digest()?,
                },
            );
            entries.insert(admission.stream_id.clone(), (7, envelope));
        }
        stream_keys.sort();
        ready.bucket_epoch = epoch.clone();
        ready.ready_manifest.bucket_epoch_digest = epoch_digest;
        ready.ready_manifest.bucket_configuration_digest = digest_domain(
            b"swarm.governance.witness-bucket-configuration.v1",
            &canonical_wire_bytes(&ready.bucket_configuration)?,
        )?;
        ready.ready_manifest.admission_set_digest =
            ready.admission_set.admission_set_digest.clone();
        ready.ready_manifest.stream_keys = stream_keys;
        ready.ready_manifest.initialized_streams = initialized_streams;
        ready.ready_manifest.witness_identity = epoch.witness_identity.clone();
        ready.ready_manifest.witness_key_id = epoch.witness_key_id.clone();
        ready.ready_manifest.signature =
            manifest_signer.sign(&ready.ready_manifest.signing_bytes()?);
        ready.bucket_anchor.epoch = epoch.clone();
        ready.bucket_anchor.ready_manifest_digest = ready.ready_manifest.digest()?;
        ready.bucket_anchor.witness_key_id = epoch.witness_key_id;
        ready.bucket_anchor.signature = manifest_signer.sign(&ready.bucket_anchor.signing_bytes()?);
        Ok((ready, entries))
    }

    fn rebuild_ready_for_configuration(
        &self,
        ready: WitnessStoreReadyResultV1,
    ) -> StoreTestResult<ReadyAndEntries> {
        let mut epoch = ready.bucket_epoch.clone();
        epoch.stream_name = ready.bucket_configuration.stream_name.clone();
        epoch.bucket_configuration_digest = digest_domain(
            b"swarm.governance.witness-bucket-configuration.v1",
            &canonical_wire_bytes(&ready.bucket_configuration)?,
        )?;
        self.rebuild_ready_for_epoch(ready, epoch, &self.base.witness)
    }

    fn sessionless_cross_stream_abort(&self) -> StoreTestResult<WitnessStoreEnvelopeV1> {
        let mut envelope = self.abort_envelope()?;
        envelope.session = None;
        envelope.last_session_rotation = None;
        let aborted = envelope
            .genesis_abort
            .as_mut()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        aborted.stream_id = "cross-stream-abort".to_string();
        let genesis = GenesisPredecessorV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: aborted.stream_id.clone(),
            binding_generation: aborted.binding_generation.clone(),
            binding_digest: aborted.binding_digest.clone(),
            signer_key_id: aborted.signer_key_id.clone(),
            witness_key_id: aborted.witness_key_id.clone(),
            authority_pair: aborted.authority_pair,
            epoch: 0,
            sequence: 0,
            intent_counter: 0,
        };
        aborted.predecessor_head_digest = genesis.digest()?;
        aborted.resulting_data_head_digest = genesis.data_head_digest()?;
        aborted.txid = TxidPreimageV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: aborted.stream_id.clone(),
            predecessor_head_digest: aborted.predecessor_head_digest.clone(),
            candidate_digest: aborted.candidate_digest.clone(),
            binding_generation: aborted.binding_generation.clone(),
            binding_digest: aborted.binding_digest.clone(),
            authority_pair: aborted.authority_pair,
            epoch: aborted.epoch,
            sequence: aborted.sequence,
            intent_counter: aborted.intent_counter,
        }
        .txid()?;
        aborted.validate()?;
        self.unchecked_resign(&mut envelope)?;
        Ok(envelope)
    }

    fn unchecked_resign(&self, envelope: &mut WitnessStoreEnvelopeV1) -> StoreTestResult {
        let mut value = serde_json::to_value(&*envelope)?;
        value
            .as_object_mut()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?
            .remove("signature")
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        let canonical = canonical_wire_bytes(&value)?;
        let mut signing_bytes =
            swarm_governance::witness_engine::WITNESS_STORE_SIGNED_DOMAIN_V1.to_vec();
        signing_bytes.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
        signing_bytes.extend_from_slice(&canonical);
        envelope.signature = self.base.witness.sign(&signing_bytes);
        Ok(())
    }

    fn proxy_request(
        &self,
        operation: WitnessStoreProxyOperationV1,
        body: WitnessStoreProxyRequestBodyV1,
    ) -> StoreTestResult<WitnessStoreProxyRequestV1> {
        let mut request = WitnessStoreProxyRequestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation,
            request_nonce: "b".repeat(64),
            admission_digest: self.current.admission_digest.clone(),
            bucket_epoch_digest: self.ready.bucket_epoch.digest()?,
            bucket_anchor_digest: self.ready.bucket_anchor.digest()?,
            body,
            request_digest: "0".repeat(64),
            witness_key_id: self.current.witness_key_id.clone(),
            signature: self.base.witness.sign(&[]),
        };
        request.request_digest = request.computed_digest()?;
        request.signature = self.base.witness.sign(&request.signing_bytes()?);
        Ok(request)
    }

    fn inspect_request(&self) -> StoreTestResult<WitnessStoreProxyRequestV1> {
        self.proxy_request(
            WitnessStoreProxyOperationV1::InspectReady,
            WitnessStoreProxyRequestBodyV1::InspectReady,
        )
    }

    fn inspect_request_for(
        &self,
        ready: &WitnessStoreReadyResultV1,
    ) -> StoreTestResult<WitnessStoreProxyRequestV1> {
        let mut request = self.inspect_request()?;
        request.admission_digest = ready.admission_set.entries[0].admission_digest.clone();
        request.bucket_epoch_digest = ready.bucket_epoch.digest()?;
        request.bucket_anchor_digest = ready.bucket_anchor.digest()?;
        self.resign_request(&mut request)?;
        Ok(request)
    }

    fn read_request(&self) -> StoreTestResult<WitnessStoreProxyRequestV1> {
        self.proxy_request(
            WitnessStoreProxyOperationV1::ReadEntry,
            WitnessStoreProxyRequestBodyV1::ReadEntry {
                stream_id: self.stream_id.clone(),
            },
        )
    }

    fn cas_request(&self) -> StoreTestResult<WitnessStoreProxyRequestV1> {
        self.proxy_request(
            WitnessStoreProxyOperationV1::CompareAndSwap,
            WitnessStoreProxyRequestBodyV1::CompareAndSwap {
                stream_id: self.stream_id.clone(),
                expected_revision: 7,
                expected_store_state_digest: self.current.store_state_digest()?,
                proposed_envelope: Box::new(self.proposed.clone()),
            },
        )
    }

    fn resign_request(&self, request: &mut WitnessStoreProxyRequestV1) -> StoreTestResult {
        request.request_digest = request.computed_digest()?;
        request.signature = self.base.witness.sign(&request.signing_bytes()?);
        Ok(())
    }

    fn spy_store(&self) -> Result<SpyStore, WitnessStoreErrorV1> {
        Ok(SpyStore {
            inner: self.store(1_000_000)?,
            inspect_calls: AtomicUsize::new(0),
            read_calls: AtomicUsize::new(0),
            cas_calls: AtomicUsize::new(0),
        })
    }

    fn two_stream_static_ready(&self) -> StoreTestResult<ReadyAndEntries> {
        let mut admission_set = self.ready.admission_set.clone();
        let mut second = admission_set.entries[0].clone();
        second.admission.stream_id = "aaron-secondary".to_string();
        second.admission.binding_generation = "8".repeat(64);
        second.admission.binding_digest = "7".repeat(64);
        second.admission.authority_pair = AuthorityPairIdentityV1 {
            current: ArtifactIdentityV1 {
                device: 11,
                inode: 101,
            },
            legacy: ArtifactIdentityV1 {
                device: 11,
                inode: 101,
            },
        };
        second.admission.admission_digest = second.admission.computed_digest()?;
        admission_set.entries.push(second);
        admission_set
            .entries
            .sort_by(|left, right| left.stream_id.cmp(&right.stream_id));
        admission_set.admission_set_digest = admission_set.computed_digest()?;
        admission_set.validate()?;

        let mut epoch = self.ready.bucket_epoch.clone();
        epoch.admission_set_digest = admission_set.admission_set_digest.clone();
        let epoch_digest = epoch.digest()?;
        let mut entries = BTreeMap::new();
        let mut stream_keys = Vec::new();
        let mut initialized_streams = BTreeMap::new();
        for admission in &admission_set.entries {
            let initialization_digest = WitnessStreamInitializationV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                bucket_epoch_digest: epoch_digest.clone(),
                admission_digest: admission.admission_digest.clone(),
                stream_id: admission.stream_id.clone(),
                witness_identity: admission.witness_identity.clone(),
                witness_key_id: admission.witness_key_id.clone(),
            }
            .digest()?;
            let mut empty = self.current.clone();
            empty.admission_digest = admission.admission_digest.clone();
            empty.bucket_epoch_digest = epoch_digest.clone();
            empty.stream_initialization_digest = initialization_digest.clone();
            empty.stream_id = admission.stream_id.clone();
            empty.session = None;
            empty.last_session_rotation = None;
            empty.current = None;
            empty.predecessor = None;
            empty.prepared = None;
            empty.genesis_abort = None;
            empty.store_generation = 0;
            empty.signature = self.base.witness.sign(&empty.signing_bytes()?);
            let stream_key = witness_stream_key(&admission.stream_id)?;
            stream_keys.push(stream_key.clone());
            initialized_streams.insert(
                stream_key,
                WitnessStreamInitializationRecordV1 {
                    schema_version: PROTOCOL_SCHEMA_VERSION,
                    stream_initialization_digest: initialization_digest,
                    empty_envelope_digest: empty.signed_envelope_digest()?,
                },
            );
            entries.insert(admission.stream_id.clone(), (1, empty));
        }
        stream_keys.sort();
        let mut manifest = self.ready.ready_manifest.clone();
        manifest.bucket_epoch_digest = epoch_digest;
        manifest.admission_set_digest = admission_set.admission_set_digest.clone();
        manifest.stream_keys = stream_keys;
        manifest.initialized_streams = initialized_streams;
        manifest.signature = self.base.witness.sign(&manifest.signing_bytes()?);
        let mut anchor = self.ready.bucket_anchor.clone();
        anchor.epoch = epoch.clone();
        anchor.ready_manifest_digest = manifest.digest()?;
        anchor.signature = self.base.witness.sign(&anchor.signing_bytes()?);
        let ready = WitnessStoreReadyResultV1::new(
            anchor.nats_stream_created_at.clone(),
            self.ready.bucket_configuration.clone(),
            epoch,
            anchor,
            admission_set,
            manifest,
            self.ready.deployment_inputs.clone(),
        )?;
        Ok((ready, entries))
    }

    fn rebind_bounds(&self, bounds: StoreBounds) -> StoreTestResult<ReadyEntriesAndEnvelope> {
        self.rebind_bounds_with_deployment(bounds, self.ready.deployment_inputs.clone())
    }

    fn rebind_bounds_with_deployment(
        &self,
        bounds: StoreBounds,
        deployment: WitnessStoreDeploymentInputsV1,
    ) -> StoreTestResult<ReadyEntriesAndEnvelope> {
        let mut admission_set = self.ready.admission_set.clone();
        let admission = &mut admission_set.entries[0];
        admission.max_state_bytes = bounds.state;
        admission.max_checkpoint_bytes = bounds.checkpoint;
        admission.max_binding_bytes = bounds.binding;
        admission.max_request_bytes = bounds.request;
        admission.max_response_bytes = bounds.response;
        admission.admission.max_retained_bytes = bounds.retained;
        admission.admission.admission_digest = admission.admission.computed_digest()?;
        admission_set.admission_set_digest = admission_set.computed_digest()?;
        admission_set.validate()?;

        let max_store = admission_set.entries[0].max_retained_bytes;
        let max_manifest = deployment.max_manifest_bytes;
        let required_bucket_bytes = 2 * (max_manifest + 65_536)
            + deployment.maximum_admitted_streams * 2 * (max_store + 65_536);
        let configuration = store_bucket_configuration(
            max_store.max(max_manifest),
            required_bucket_bytes,
            deployment.configured_replica_count,
        )?;
        let configuration_digest = configuration.digest()?;
        let mut epoch = self.ready.bucket_epoch.clone();
        epoch.bucket_configuration_digest = configuration_digest.clone();
        epoch.admission_set_digest = admission_set.admission_set_digest.clone();
        let epoch_digest = epoch.digest()?;
        let initialization_digest = WitnessStreamInitializationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            bucket_epoch_digest: epoch_digest.clone(),
            admission_digest: admission_set.entries[0].admission_digest.clone(),
            stream_id: self.stream_id.clone(),
            witness_identity: admission_set.entries[0].witness_identity.clone(),
            witness_key_id: admission_set.entries[0].witness_key_id.clone(),
        }
        .digest()?;
        let rebind = |source: &WitnessStoreEnvelopeV1| -> StoreTestResult<WitnessStoreEnvelopeV1> {
            let mut envelope = source.clone();
            envelope.admission_digest = admission_set.entries[0].admission_digest.clone();
            envelope.bucket_epoch_digest = epoch_digest.clone();
            envelope.stream_initialization_digest = initialization_digest.clone();
            envelope.signature = self.base.witness.sign(&envelope.signing_bytes()?);
            Ok(envelope)
        };
        let current = rebind(&self.current)?;
        let proposed = rebind(&self.proposed)?;
        let mut empty = rebind(&self.current)?;
        empty.session = None;
        empty.last_session_rotation = None;
        empty.current = None;
        empty.predecessor = None;
        empty.prepared = None;
        empty.genesis_abort = None;
        empty.store_generation = 0;
        empty.signature = self.base.witness.sign(&empty.signing_bytes()?);

        let stream_key = witness_stream_key(&self.stream_id)?;
        let mut manifest = self.ready.ready_manifest.clone();
        manifest.bucket_epoch_digest = epoch_digest;
        manifest.bucket_configuration_digest = configuration_digest.clone();
        manifest.admission_set_digest = admission_set.admission_set_digest.clone();
        manifest.initialized_streams.insert(
            stream_key,
            WitnessStreamInitializationRecordV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                stream_initialization_digest: initialization_digest,
                empty_envelope_digest: empty.signed_envelope_digest()?,
            },
        );
        manifest.signature = self.base.witness.sign(&manifest.signing_bytes()?);
        let mut anchor = self.ready.bucket_anchor.clone();
        anchor.epoch = epoch.clone();
        anchor.raw_stream_configuration_digest = raw_stream_configuration_digest(&configuration)?;
        anchor.ready_manifest_digest = manifest.digest()?;
        anchor.signature = self.base.witness.sign(&anchor.signing_bytes()?);
        let ready = WitnessStoreReadyResultV1::new(
            anchor.nats_stream_created_at.clone(),
            configuration,
            epoch,
            anchor,
            admission_set,
            manifest,
            deployment,
        )?;
        let entries = BTreeMap::from([(self.stream_id.clone(), (7, current))]);
        Ok((ready, entries, proposed))
    }
}

#[tokio::test]
async fn atomic_store_contract_rejects_zero_revision_and_unvalidated_transition() -> StoreTestResult
{
    let fixture = StoreFixture::new()?;
    let store = fixture.store(1_000_000)?;
    let before = store.canonical_store_bytes()?;
    assert!(matches!(
        store
            .compare_and_swap(
                &fixture.stream_id,
                0,
                &fixture.current.store_state_digest()?,
                &fixture.proposed,
            )
            .await?,
        WitnessStoreCasResultV1::Conflict {
            observed_revision: 7,
            ..
        }
    ));
    assert_eq!(store.canonical_store_bytes()?, before);

    let mut invalid = fixture.current.clone();
    invalid.store_generation += 1;
    invalid.signature = fixture.base.witness.sign(&invalid.signing_bytes()?);
    assert_eq!(
        store
            .compare_and_swap(
                &fixture.stream_id,
                7,
                &fixture.current.store_state_digest()?,
                &invalid,
            )
            .await,
        Err(WitnessStoreErrorV1::Admission),
    );
    assert_eq!(store.canonical_store_bytes()?, before);
    Ok(())
}

#[tokio::test]
async fn atomic_store_contract_confirms_revision_and_bytes() -> StoreTestResult {
    fn assert_store<T: WitnessAtomicStore>(_store: &T) {}
    let fixture = StoreFixture::new()?;
    let store = fixture.store(1_000_000)?;
    assert_store(&store);
    let result = store
        .compare_and_swap(
            &fixture.stream_id,
            7,
            &fixture.current.store_state_digest()?,
            &fixture.proposed,
        )
        .await?;
    let WitnessStoreCasResultV1::Applied {
        previous_revision,
        new_revision,
        acknowledged_value_digest,
        duplicate,
        ..
    } = result
    else {
        panic!("valid CAS did not apply")
    };
    assert_eq!((previous_revision, new_revision, duplicate), (7, 8, false));
    assert_eq!(
        acknowledged_value_digest,
        fixture.proposed.signed_envelope_digest()?
    );
    let read = store.read_entry(&fixture.stream_id).await?;
    let (_, revision, observed) = read.parts();
    assert_eq!(revision, 8);
    assert_eq!(
        observed.canonical_bytes()?,
        fixture.proposed.canonical_bytes()?
    );
    Ok(())
}

#[tokio::test]
async fn atomic_store_contract_enforces_manifest_bounds() -> StoreTestResult {
    let fixture = StoreFixture::new()?;
    let ready_json = serde_json::to_value(&fixture.ready)?;
    let object = ready_json
        .as_object()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    for forbidden in [
        "revision",
        "store_state_digest",
        "envelope",
        "validated_streams",
    ] {
        assert!(!object.contains_key(forbidden));
    }

    let mut distinct_raw = fixture.ready.clone();
    distinct_raw.bucket_anchor.raw_stream_configuration_digest = digest_domain(
        b"swarm.governance.witness-store.raw-stream-configuration.v1",
        br#"{"authoritative":"raw"}"#,
    )?;
    distinct_raw.bucket_anchor.signature = fixture
        .base
        .witness
        .sign(&distinct_raw.bucket_anchor.signing_bytes()?);
    assert!(distinct_raw.validate().is_ok());
    assert!(
        ReferenceWitnessStoreModel::new(distinct_raw, fixture.entries.clone(), 1_000_000,).is_ok()
    );

    let mut manifest_overflow = fixture.ready.clone();
    manifest_overflow.deployment_inputs.max_manifest_bytes =
        canonical_wire_bytes(&manifest_overflow.ready_manifest)?.len() as u64 - 1;
    assert!(matches!(
        manifest_overflow.validate(),
        Err(ProtocolError::Bounds { .. })
    ));

    let mut admission_overflow = fixture.ready.clone();
    admission_overflow
        .deployment_inputs
        .maximum_admitted_streams = 0;
    assert!(admission_overflow.validate().is_err());
    let mut replica_mismatch = fixture.ready.clone();
    replica_mismatch.deployment_inputs.configured_replica_count = 1;
    assert!(replica_mismatch.validate().is_err());
    assert_eq!(
        InMemoryWitnessStore::new(fixture.ready.clone(), BTreeMap::new(), 1_000_000).err(),
        Some(WitnessStoreErrorV1::Missing),
    );

    let candidate = &fixture
        .proposed
        .prepared
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .candidate;
    let state_len = candidate.state_payload.len() as u64;
    let checkpoint_len = candidate.checkpoint_payload.len() as u64;
    let binding_len = canonical_wire_bytes(&candidate.publication_binding)?.len() as u64;
    let provisional = StoreBounds {
        state: state_len,
        checkpoint: checkpoint_len,
        binding: binding_len,
        retained: fixture.ready.admission_set.entries[0].max_retained_bytes,
        request: fixture.ready.admission_set.entries[0].max_request_bytes,
        response: fixture.ready.admission_set.entries[0].max_response_bytes,
    };
    let (_, _, rebound_proposed) = fixture.rebind_bounds(provisional)?;
    let retained_len = canonical_wire_bytes(&rebound_proposed)?.len() as u64;
    let exact = StoreBounds {
        retained: retained_len,
        ..provisional
    };
    let mut one_replica_deployment = fixture.ready.deployment_inputs.clone();
    one_replica_deployment.configured_replica_count = 1;
    one_replica_deployment.maximum_admitted_streams = 5;
    let (one_replica_ready, _, _) =
        fixture.rebind_bounds_with_deployment(exact, one_replica_deployment)?;
    assert_eq!(one_replica_ready.bucket_configuration.num_replicas, 1);
    assert_eq!(
        one_replica_ready.deployment_inputs.maximum_admitted_streams,
        5,
    );
    one_replica_ready.validate()?;
    let (ready, entries, proposed) = fixture.rebind_bounds(exact)?;
    let direct = InMemoryWitnessStore::new(ready.clone(), entries.clone(), 1_000_000)?;
    let mut reference = ReferenceWitnessStoreModel::new(ready, entries, 1_000_000)?;
    let read = direct.read_entry(&fixture.stream_id).await?;
    let (_, revision, current) = read.parts();
    let digest = current.store_state_digest()?;
    assert_eq!(
        direct
            .compare_and_swap(&fixture.stream_id, revision, &digest, &proposed)
            .await,
        reference.compare_and_swap(&fixture.stream_id, revision, &digest, &proposed),
    );

    for over_limit in [
        StoreBounds {
            state: state_len.saturating_sub(1),
            ..exact
        },
        StoreBounds {
            checkpoint: checkpoint_len.saturating_sub(1),
            ..exact
        },
        StoreBounds {
            binding: binding_len.saturating_sub(1),
            ..exact
        },
        StoreBounds {
            retained: retained_len.saturating_sub(1),
            ..exact
        },
        StoreBounds { state: 1, ..exact },
    ] {
        let (ready, entries, proposed) = fixture.rebind_bounds(over_limit)?;
        let direct = InMemoryWitnessStore::new(ready.clone(), entries.clone(), 1_000_000)?;
        let mut reference = ReferenceWitnessStoreModel::new(ready, entries, 1_000_000)?;
        let digest = direct
            .read_entry(&fixture.stream_id)
            .await?
            .parts()
            .2
            .store_state_digest()?;
        assert_eq!(
            direct
                .compare_and_swap(&fixture.stream_id, 7, &digest, &proposed)
                .await,
            Err(WitnessStoreErrorV1::Bounds),
        );
        assert_eq!(
            reference.compare_and_swap(&fixture.stream_id, 7, &digest, &proposed),
            Err(WitnessStoreErrorV1::Bounds),
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum StoreScenario {
    Genesis,
    Rotation,
    Prepare,
    Commit,
    Abort,
    Read,
    Conflict,
    ExactObservation,
    ResignedContent,
    ResignedStaleSession,
    ResignedAdmission,
    ComponentLimit,
    Capacity,
    CrashBeforeCas,
    LostAfterCas,
    WrongRevisionAck,
    DuplicateAck,
    CorruptRead,
    InjectedCapacity,
}

#[tokio::test]
async fn in_memory_differential_matches_reference_for_every_operation() -> StoreTestResult {
    let scenarios = [
        ("genesis", StoreScenario::Genesis),
        ("rotation", StoreScenario::Rotation),
        ("sealed_prepare", StoreScenario::Prepare),
        ("commit", StoreScenario::Commit),
        ("abort", StoreScenario::Abort),
        ("read", StoreScenario::Read),
        ("conflict", StoreScenario::Conflict),
        (
            "exact_idempotent_observation",
            StoreScenario::ExactObservation,
        ),
        ("resigned_content", StoreScenario::ResignedContent),
        (
            "resigned_stale_session",
            StoreScenario::ResignedStaleSession,
        ),
        ("resigned_admission", StoreScenario::ResignedAdmission),
        ("component_limit", StoreScenario::ComponentLimit),
        ("capacity", StoreScenario::Capacity),
        ("crash_before_cas", StoreScenario::CrashBeforeCas),
        ("lost_after_cas", StoreScenario::LostAfterCas),
        ("wrong_revision_ack", StoreScenario::WrongRevisionAck),
        ("duplicate_ack", StoreScenario::DuplicateAck),
        ("corrupt_read", StoreScenario::CorruptRead),
        ("injected_capacity", StoreScenario::InjectedCapacity),
    ];
    assert_eq!(scenarios.len(), 19);

    for (name, scenario) in scenarios {
        let fixture = StoreFixture::new()?;
        let (entries, revision, proposed) = match scenario {
            StoreScenario::Genesis => {
                let entries = BTreeMap::from([(
                    fixture.stream_id.clone(),
                    (6, {
                        let mut empty = fixture.current.clone();
                        empty.session = None;
                        empty.last_session_rotation = None;
                        empty.current = None;
                        empty.predecessor = None;
                        empty.prepared = None;
                        empty.genesis_abort = None;
                        empty.store_generation = 0;
                        empty.signature = fixture.base.witness.sign(&empty.signing_bytes()?);
                        empty
                    }),
                )]);
                (entries, 6, None)
            }
            StoreScenario::Rotation => {
                let mut empty = fixture.current.clone();
                empty.session = None;
                empty.last_session_rotation = None;
                empty.current = None;
                empty.predecessor = None;
                empty.prepared = None;
                empty.genesis_abort = None;
                empty.store_generation = 0;
                empty.signature = fixture.base.witness.sign(&empty.signing_bytes()?);
                (
                    BTreeMap::from([(fixture.stream_id.clone(), (6, empty))]),
                    6,
                    Some(fixture.current.clone()),
                )
            }
            StoreScenario::Commit => (
                BTreeMap::from([(fixture.stream_id.clone(), (8, fixture.proposed.clone()))]),
                8,
                Some(fixture.commit_envelope()?),
            ),
            StoreScenario::Abort => (
                BTreeMap::from([(fixture.stream_id.clone(), (8, fixture.proposed.clone()))]),
                8,
                Some(fixture.abort_envelope()?),
            ),
            _ => (fixture.entries.clone(), 7, Some(fixture.proposed.clone())),
        };
        let capacity = if matches!(scenario, StoreScenario::Capacity) {
            canonical_wire_bytes(&entries)?.len()
        } else {
            1_000_000
        };
        let direct = InMemoryWitnessStore::new(fixture.ready.clone(), entries.clone(), capacity)?;
        let mut reference =
            ReferenceWitnessStoreModel::new(fixture.ready.clone(), entries, capacity)?;
        assert_eq!(
            direct.inspect_ready().await?,
            reference.inspect_ready()?,
            "{name}"
        );

        match scenario {
            StoreScenario::Genesis | StoreScenario::Read => {
                assert_eq!(
                    direct.read_entry(&fixture.stream_id).await?,
                    reference.read_entry(&fixture.stream_id)?,
                    "{name}",
                );
            }
            StoreScenario::Rotation => {
                let current = direct.read_entry(&fixture.stream_id).await?;
                let (_, _, envelope) = current.parts();
                let digest = envelope.store_state_digest()?;
                let proposed = proposed
                    .as_ref()
                    .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
                assert_eq!(
                    direct
                        .compare_and_swap(&fixture.stream_id, revision, &digest, proposed)
                        .await,
                    reference.compare_and_swap(&fixture.stream_id, revision, &digest, proposed),
                    "{name}",
                );
            }
            StoreScenario::Prepare | StoreScenario::Commit | StoreScenario::Abort => {
                let current = direct.read_entry(&fixture.stream_id).await?;
                let (_, _, envelope) = current.parts();
                let digest = envelope.store_state_digest()?;
                let proposed = proposed
                    .as_ref()
                    .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
                assert_eq!(
                    direct
                        .compare_and_swap(&fixture.stream_id, revision, &digest, proposed)
                        .await,
                    reference.compare_and_swap(&fixture.stream_id, revision, &digest, proposed),
                    "{name}",
                );
            }
            StoreScenario::Conflict => {
                assert_eq!(
                    direct
                        .compare_and_swap(&fixture.stream_id, 6, &"f".repeat(64), &fixture.proposed)
                        .await,
                    reference.compare_and_swap(
                        &fixture.stream_id,
                        6,
                        &"f".repeat(64),
                        &fixture.proposed
                    ),
                    "{name}",
                );
            }
            StoreScenario::ExactObservation => {
                let digest = fixture.current.store_state_digest()?;
                assert_eq!(
                    direct
                        .compare_and_swap(&fixture.stream_id, 7, &digest, &fixture.proposed)
                        .await,
                    reference.compare_and_swap(&fixture.stream_id, 7, &digest, &fixture.proposed),
                );
                assert_eq!(
                    direct
                        .compare_and_swap(&fixture.stream_id, 7, &digest, &fixture.proposed)
                        .await,
                    reference.compare_and_swap(&fixture.stream_id, 7, &digest, &fixture.proposed),
                    "{name}",
                );
            }
            StoreScenario::ResignedContent
            | StoreScenario::ResignedStaleSession
            | StoreScenario::ResignedAdmission
            | StoreScenario::ComponentLimit => {
                let mut mutant = fixture.proposed.clone();
                match scenario {
                    StoreScenario::ResignedContent => {
                        mutant
                            .prepared
                            .as_mut()
                            .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                            .candidate
                            .state_payload = br#"{"state":"independently-mutated"}"#.to_vec();
                    }
                    StoreScenario::ResignedStaleSession => {
                        mutant
                            .prepared
                            .as_mut()
                            .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                            .prepared
                            .session_generation += 1;
                    }
                    StoreScenario::ResignedAdmission => {
                        mutant.admission_digest = "e".repeat(64);
                    }
                    StoreScenario::ComponentLimit => {
                        mutant
                            .prepared
                            .as_mut()
                            .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                            .candidate
                            .state_byte_len = fixture.ready.admission_set.entries[0]
                            .max_state_bytes
                            .saturating_add(1);
                    }
                    _ => unreachable!(),
                }
                fixture.unchecked_resign(&mut mutant)?;
                let digest = fixture.current.store_state_digest()?;
                assert_eq!(
                    direct
                        .compare_and_swap(&fixture.stream_id, 7, &digest, &mutant)
                        .await,
                    reference.compare_and_swap(&fixture.stream_id, 7, &digest, &mutant),
                    "{name}",
                );
                assert!(
                    direct
                        .compare_and_swap(&fixture.stream_id, 7, &digest, &mutant)
                        .await
                        .is_err()
                );
            }
            StoreScenario::Capacity => {
                let digest = fixture.current.store_state_digest()?;
                assert_eq!(
                    direct
                        .compare_and_swap(&fixture.stream_id, 7, &digest, &fixture.proposed)
                        .await,
                    reference.compare_and_swap(&fixture.stream_id, 7, &digest, &fixture.proposed),
                    "{name}",
                );
            }
            StoreScenario::CrashBeforeCas => {
                direct.inject_fault(WitnessStoreFault::CrashBeforeCas)?;
                reference.inject_fault(WitnessStoreFault::CrashBeforeCas);
                let digest = fixture.current.store_state_digest()?;
                assert_eq!(
                    direct
                        .compare_and_swap(&fixture.stream_id, 7, &digest, &fixture.proposed)
                        .await,
                    reference.compare_and_swap(&fixture.stream_id, 7, &digest, &fixture.proposed),
                    "{name}",
                );
            }
            StoreScenario::LostAfterCas => {
                direct.inject_fault(WitnessStoreFault::LostAfterCas)?;
                reference.inject_fault(WitnessStoreFault::LostAfterCas);
                let digest = fixture.current.store_state_digest()?;
                assert_eq!(
                    direct
                        .compare_and_swap(&fixture.stream_id, 7, &digest, &fixture.proposed)
                        .await,
                    reference.compare_and_swap(&fixture.stream_id, 7, &digest, &fixture.proposed),
                    "{name}",
                );
                assert_eq!(
                    direct.read_entry(&fixture.stream_id).await?,
                    reference.read_entry(&fixture.stream_id)?,
                );
            }
            StoreScenario::WrongRevisionAck
            | StoreScenario::DuplicateAck
            | StoreScenario::InjectedCapacity => {
                let fault = match scenario {
                    StoreScenario::WrongRevisionAck => WitnessStoreFault::WrongRevision,
                    StoreScenario::DuplicateAck => WitnessStoreFault::DuplicateAck,
                    StoreScenario::InjectedCapacity => WitnessStoreFault::CapacityExhaustion,
                    _ => unreachable!(),
                };
                direct.inject_fault(fault)?;
                reference.inject_fault(fault);
                let digest = fixture.current.store_state_digest()?;
                assert_eq!(
                    direct
                        .compare_and_swap(&fixture.stream_id, 7, &digest, &fixture.proposed)
                        .await,
                    reference.compare_and_swap(&fixture.stream_id, 7, &digest, &fixture.proposed,),
                    "{name}",
                );
            }
            StoreScenario::CorruptRead => {
                direct.inject_fault(WitnessStoreFault::CorruptRead)?;
                reference.inject_fault(WitnessStoreFault::CorruptRead);
                assert_eq!(
                    direct.read_entry(&fixture.stream_id).await,
                    reference.read_entry(&fixture.stream_id),
                    "{name}",
                );
            }
        }
        assert_eq!(
            direct.canonical_store_bytes()?,
            reference.canonical_store_bytes()?,
            "{name}"
        );
    }

    let nested_result = std::thread::Builder::new()
        .name("phase285-plan02-nested-mutants".to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| -> StoreTestResult {
            let fixture = StoreFixture::new()?;
            let mut nested_mutants: Vec<(&str, Box<WitnessStoreEnvelopeV1>)> = Vec::new();

            {
                let mut rotation_schema = fixture.current.clone();
                rotation_schema
                    .last_session_rotation
                    .as_mut()
                    .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                    .schema_version += 1;
                fixture.unchecked_resign(&mut rotation_schema)?;
                nested_mutants.push(("rotation_schema", Box::new(rotation_schema)));
            }

            {
                let mut rotation_snapshot = fixture.current.clone();
                let receipt = rotation_snapshot
                    .last_session_rotation
                    .as_mut()
                    .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
                match receipt.response_kind {
                    WitnessSessionRotationResponseKindV1::Establish => {
                        receipt
                            .establish_snapshot
                            .as_mut()
                            .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                            .external_marker = "e".repeat(64);
                    }
                    WitnessSessionRotationResponseKindV1::Discover => {
                        receipt
                            .discovery_snapshot
                            .as_mut()
                            .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                            .schema_version += 1;
                    }
                }
                fixture.unchecked_resign(&mut rotation_snapshot)?;
                nested_mutants.push(("rotation_snapshot", Box::new(rotation_snapshot)));
            }

            {
                let mut stored_head = fixture.commit_envelope()?;
                stored_head
                    .current
                    .as_mut()
                    .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                    .head
                    .schema_version += 1;
                fixture.unchecked_resign(&mut stored_head)?;
                nested_mutants.push(("stored_head", Box::new(stored_head)));
            }

            {
                let mut prepared_record = fixture.proposed.clone();
                prepared_record
                    .prepared
                    .as_mut()
                    .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                    .prepared
                    .schema_version += 1;
                fixture.unchecked_resign(&mut prepared_record)?;
                nested_mutants.push(("prepared_record", Box::new(prepared_record)));
            }

            {
                let mut genesis_abort = fixture.abort_envelope()?;
                genesis_abort
                    .genesis_abort
                    .as_mut()
                    .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                    .schema_version += 1;
                fixture.unchecked_resign(&mut genesis_abort)?;
                nested_mutants.push(("genesis_abort", Box::new(genesis_abort)));
            }

            {
                let mut binding_digest = fixture.proposed.clone();
                binding_digest
                    .prepared
                    .as_mut()
                    .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                    .candidate
                    .publication_binding
                    .binding_digest = "e".repeat(64);
                fixture.unchecked_resign(&mut binding_digest)?;
                nested_mutants.push(("binding_digest", Box::new(binding_digest)));
            }

            {
                let mut binding_signature = fixture.proposed.clone();
                binding_signature
                    .prepared
                    .as_mut()
                    .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                    .candidate
                    .publication_binding
                    .binding_signature
                    .signature_hex = "00".repeat(64);
                fixture.unchecked_resign(&mut binding_signature)?;
                nested_mutants.push(("binding_signature", Box::new(binding_signature)));
            }

            {
                let mut binding_roles = fixture.proposed.clone();
                let roles = &mut binding_roles
                    .prepared
                    .as_mut()
                    .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                    .candidate
                    .publication_binding
                    .publication_roles;
                roles.state_canonical = roles.state_staging;
                fixture.unchecked_resign(&mut binding_roles)?;
                nested_mutants.push(("binding_roles", Box::new(binding_roles)));
            }

            for (name, mutant) in nested_mutants {
                let entries = BTreeMap::from([(fixture.stream_id.clone(), (9, *mutant))]);
                assert!(
                    InMemoryWitnessStore::new(fixture.ready.clone(), entries.clone(), 1_000_000)
                        .is_err(),
                    "production accepted malformed nested {name}",
                );
                assert!(
                    ReferenceWitnessStoreModel::new(fixture.ready.clone(), entries, 1_000_000)
                        .is_err(),
                    "reference accepted malformed nested {name}",
                );
            }
            Ok(())
        })
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?
        .join()
        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
    nested_result?;

    let source = include_str!("../src/witness_engine/store/in_memory.rs");
    let oracle = source
        .split("// REFERENCE_ORACLE_BEGIN")
        .nth(1)
        .and_then(|tail| tail.split("// REFERENCE_ORACLE_END").next())
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    assert!(reference_oracle_is_independent(oracle));
    for forbidden in REFERENCE_ORACLE_FORBIDDEN_TOKENS {
        assert!(
            !reference_oracle_is_independent(&format!("{oracle}\n{forbidden}")),
            "source guard did not kill injected token {forbidden}",
        );
    }

    let fixture = StoreFixture::new()?;
    let mut generation_mutant = fixture.proposed.clone();
    generation_mutant.store_generation += 1;
    fixture.unchecked_resign(&mut generation_mutant)?;
    let mut broken = BrokenSemanticStore::new(fixture.entries.clone());
    assert!(broken.accept_without_semantics(&fixture.stream_id, generation_mutant.clone()));
    assert_eq!(
        ReferenceWitnessStoreModel::new(fixture.ready.clone(), fixture.entries.clone(), 1_000_000)?
            .compare_and_swap(
                &fixture.stream_id,
                7,
                &fixture.current.store_state_digest()?,
                &generation_mutant,
            ),
        Err(WitnessStoreErrorV1::Admission),
    );

    let mut terminal_mutant = fixture.commit_envelope()?;
    terminal_mutant
        .current
        .as_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .head
        .last_intent_outcome = None;
    fixture.unchecked_resign(&mut terminal_mutant)?;
    let prepared_entries =
        BTreeMap::from([(fixture.stream_id.clone(), (8, fixture.proposed.clone()))]);
    let mut broken_terminal = BrokenSemanticStore::new(prepared_entries.clone());
    assert!(broken_terminal.accept_without_semantics(&fixture.stream_id, terminal_mutant.clone()));
    assert_eq!(
        ReferenceWitnessStoreModel::new(fixture.ready, prepared_entries, 1_000_000)?
            .compare_and_swap(
                &fixture.stream_id,
                8,
                &fixture.proposed.store_state_digest()?,
                &terminal_mutant,
            ),
        Err(WitnessStoreErrorV1::Admission),
    );

    let fixture = StoreFixture::new()?;
    let mut abort_mutant = fixture.abort_envelope()?;
    abort_mutant
        .genesis_abort
        .as_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .txid = "e".repeat(64);
    fixture.unchecked_resign(&mut abort_mutant)?;
    let prepared_entries =
        BTreeMap::from([(fixture.stream_id.clone(), (8, fixture.proposed.clone()))]);
    let mut broken_abort = BrokenSemanticStore::new(prepared_entries.clone());
    assert!(broken_abort.accept_without_semantics(&fixture.stream_id, abort_mutant.clone()));
    assert_eq!(
        ReferenceWitnessStoreModel::new(fixture.ready, prepared_entries, 1_000_000)?
            .compare_and_swap(
                &fixture.stream_id,
                8,
                &fixture.proposed.store_state_digest()?,
                &abort_mutant,
            ),
        Err(WitnessStoreErrorV1::Admission),
    );
    Ok(())
}

#[tokio::test]
async fn in_memory_store_preserves_bytes_after_refusal() -> StoreTestResult {
    let source = include_str!("../src/witness_engine/store/in_memory.rs");
    let oracle = source
        .split("// REFERENCE_ORACLE_BEGIN")
        .nth(1)
        .and_then(|tail| tail.split("// REFERENCE_ORACLE_END").next())
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    assert!(reference_oracle_is_independent(oracle));
    for forbidden in REFERENCE_ORACLE_FORBIDDEN_TOKENS {
        assert!(
            !reference_oracle_is_independent(&format!("{oracle}\n{forbidden}")),
            "source guard did not kill injected token {forbidden}",
        );
    }

    let fixture = StoreFixture::new()?;
    let mut corrupt_entries = fixture.entries.clone();
    corrupt_entries
        .get_mut(&fixture.stream_id)
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .1
        .signature
        .signature_hex = "00".repeat(64);
    assert_eq!(
        InMemoryWitnessStore::new(fixture.ready.clone(), corrupt_entries.clone(), 1_000_000).err(),
        Some(WitnessStoreErrorV1::Corrupt),
    );
    assert_eq!(
        ReferenceWitnessStoreModel::new(fixture.ready.clone(), corrupt_entries, 1_000_000).err(),
        Some(WitnessStoreErrorV1::Corrupt),
    );
    let mut ready_mutants = Vec::new();
    let mut corrupt_manifest = fixture.ready.clone();
    corrupt_manifest.ready_manifest.signature.signature_hex = "00".repeat(64);
    ready_mutants.push(corrupt_manifest);
    let mut corrupt_anchor = fixture.ready.clone();
    corrupt_anchor.bucket_anchor.signature.signature_hex = "00".repeat(64);
    ready_mutants.push(corrupt_anchor);
    let mut wrong_deployment = fixture.ready.clone();
    wrong_deployment.deployment_inputs.configured_replica_count = 1;
    ready_mutants.push(wrong_deployment);
    let mut wrong_configuration = fixture.ready.clone();
    wrong_configuration.bucket_configuration.allow_direct = true;
    ready_mutants.push(wrong_configuration);
    let mut invalid_timestamp = fixture.ready.clone();
    invalid_timestamp.nats_stream_created_at = "2026-02-30T00:00:00.000000000Z".to_string();
    invalid_timestamp.bucket_anchor.nats_stream_created_at =
        invalid_timestamp.nats_stream_created_at.clone();
    invalid_timestamp.bucket_anchor.signature = fixture
        .base
        .witness
        .sign(&invalid_timestamp.bucket_anchor.signing_bytes()?);
    ready_mutants.push(invalid_timestamp);
    for mutant in ready_mutants {
        assert!(
            InMemoryWitnessStore::new(mutant.clone(), fixture.entries.clone(), 1_000_000).is_err()
        );
        assert!(
            ReferenceWitnessStoreModel::new(mutant, fixture.entries.clone(), 1_000_000).is_err()
        );
    }

    let mut manifest_schema = fixture.ready.clone();
    manifest_schema.ready_manifest.schema_version += 1;
    manifest_schema.ready_manifest.signature = fixture
        .base
        .witness
        .sign(&manifest_schema.ready_manifest.signing_bytes()?);
    manifest_schema.bucket_anchor.ready_manifest_digest = digest_domain(
        WITNESS_BUCKET_MANIFEST_DOMAIN_V1,
        &canonical_wire_bytes(&manifest_schema.ready_manifest)?,
    )?;
    manifest_schema.bucket_anchor.signature = fixture
        .base
        .witness
        .sign(&manifest_schema.bucket_anchor.signing_bytes()?);

    let mut anchor_schema = fixture.ready.clone();
    anchor_schema.bucket_anchor.schema_version += 1;
    anchor_schema.bucket_anchor.signature = fixture
        .base
        .witness
        .sign(&anchor_schema.bucket_anchor.signing_bytes()?);

    let mut deployment_schema = fixture.ready.clone();
    deployment_schema.deployment_inputs.schema_version += 1;

    let mut configuration_schema = fixture.ready.clone();
    configuration_schema.bucket_configuration.schema_version += 1;
    let mut configuration_epoch = configuration_schema.bucket_epoch.clone();
    configuration_epoch.bucket_configuration_digest = digest_domain(
        b"swarm.governance.witness-bucket-configuration.v1",
        &canonical_wire_bytes(&configuration_schema.bucket_configuration)?,
    )?;
    let (configuration_schema, configuration_entries) = fixture.rebuild_ready_for_epoch(
        configuration_schema,
        configuration_epoch,
        &fixture.base.witness,
    )?;

    let mut epoch_schema = fixture.ready.bucket_epoch.clone();
    epoch_schema.schema_version += 1;
    let (epoch_schema, epoch_entries) = fixture.rebuild_ready_for_epoch(
        fixture.ready.clone(),
        epoch_schema,
        &fixture.base.witness,
    )?;

    let mut admission_schema = fixture.ready.clone();
    admission_schema.admission_set.schema_version += 1;
    let mut admission_preimage = serde_json::to_value(&admission_schema.admission_set)?;
    admission_preimage
        .as_object_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .remove("admission_set_digest");
    admission_schema.admission_set.admission_set_digest = digest_domain(
        WITNESS_ADMISSION_SET_DOMAIN_V1,
        &canonical_wire_bytes(&admission_preimage)?,
    )?;
    let mut admission_epoch = admission_schema.bucket_epoch.clone();
    admission_epoch.admission_set_digest =
        admission_schema.admission_set.admission_set_digest.clone();
    let (admission_schema, admission_entries) = fixture.rebuild_ready_for_epoch(
        admission_schema,
        admission_epoch,
        &fixture.base.witness,
    )?;

    let mut record_schema = fixture.ready.clone();
    record_schema
        .ready_manifest
        .initialized_streams
        .get_mut(&witness_stream_key(&fixture.stream_id)?)
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .schema_version += 1;
    record_schema.ready_manifest.signature = fixture
        .base
        .witness
        .sign(&record_schema.ready_manifest.signing_bytes()?);
    record_schema.bucket_anchor.ready_manifest_digest = digest_domain(
        WITNESS_BUCKET_MANIFEST_DOMAIN_V1,
        &canonical_wire_bytes(&record_schema.ready_manifest)?,
    )?;
    record_schema.bucket_anchor.signature = fixture
        .base
        .witness
        .sign(&record_schema.bucket_anchor.signing_bytes()?);

    let mut malformed_raw_digest = fixture.ready.clone();
    malformed_raw_digest
        .bucket_anchor
        .raw_stream_configuration_digest = "G".repeat(64);
    malformed_raw_digest.bucket_anchor.signature = fixture
        .base
        .witness
        .sign(&malformed_raw_digest.bucket_anchor.signing_bytes()?);

    let mut repeated_prefix = fixture.ready.clone();
    repeated_prefix.bucket_configuration.stream_name = "KV_KV_x".to_string();
    repeated_prefix.bucket_configuration.subjects = vec!["$KV.x.>".to_string()];
    let (repeated_prefix, repeated_prefix_entries) =
        fixture.rebuild_ready_for_configuration(repeated_prefix)?;

    let mut overlong_subject = fixture.ready.clone();
    overlong_subject.bucket_configuration.stream_name = format!(
        "KV_{}",
        "x".repeat(MAX_PROTOCOL_STRING_BYTES.saturating_sub(3))
    );
    overlong_subject.bucket_configuration.subjects = vec![format!(
        "$KV.{}.>",
        overlong_subject
            .bucket_configuration
            .stream_name
            .strip_prefix("KV_")
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?
    )];
    let (overlong_subject, overlong_subject_entries) =
        fixture.rebuild_ready_for_configuration(overlong_subject)?;

    let mut nul_epoch = fixture.ready.bucket_epoch.clone();
    nul_epoch.nats_account = "phase285\0account".to_string();
    let (nul_string, nul_entries) =
        fixture.rebuild_ready_for_epoch(fixture.ready.clone(), nul_epoch, &fixture.base.witness)?;

    let mut identity_epoch = fixture.ready.bucket_epoch.clone();
    identity_epoch.witness_identity = "independently-rebuilt-foreign-witness".to_string();
    let (identity_mismatch, identity_entries) = fixture.rebuild_ready_for_epoch(
        fixture.ready.clone(),
        identity_epoch,
        &fixture.base.witness,
    )?;

    let foreign_witness = Ed25519Signer::from_secret_material("phase285-ready-foreign-witness");
    let mut key_epoch = fixture.ready.bucket_epoch.clone();
    key_epoch.witness_key_id = foreign_witness.key_id().to_string();
    let (key_mismatch, key_entries) =
        fixture.rebuild_ready_for_epoch(fixture.ready.clone(), key_epoch, &foreign_witness)?;

    let mut excessive_deployment = fixture.ready.clone();
    excessive_deployment
        .deployment_inputs
        .maximum_admitted_streams = MAX_PROTOCOL_COLLECTION_ITEMS as u64 + 1;
    let max_store = excessive_deployment.admission_set.entries[0].max_retained_bytes;
    excessive_deployment.bucket_configuration.max_bytes = i64::try_from(
        2 * (excessive_deployment.deployment_inputs.max_manifest_bytes + 65_536)
            + excessive_deployment
                .deployment_inputs
                .maximum_admitted_streams
                * 2
                * (max_store + 65_536),
    )?;
    let mut excessive_epoch = excessive_deployment.bucket_epoch.clone();
    excessive_epoch.bucket_configuration_digest =
        excessive_deployment.bucket_configuration.digest()?;
    let (excessive_deployment, excessive_entries) = fixture.rebuild_ready_for_epoch(
        excessive_deployment,
        excessive_epoch,
        &fixture.base.witness,
    )?;

    for (name, mutant, entries) in [
        ("manifest-schema", manifest_schema, fixture.entries.clone()),
        ("anchor-schema", anchor_schema, fixture.entries.clone()),
        (
            "deployment-schema",
            deployment_schema,
            fixture.entries.clone(),
        ),
        (
            "configuration-schema",
            configuration_schema,
            configuration_entries,
        ),
        ("epoch-schema", epoch_schema, epoch_entries),
        ("admission-set-schema", admission_schema, admission_entries),
        (
            "manifest-record-schema",
            record_schema,
            fixture.entries.clone(),
        ),
        (
            "anchor-raw-digest-syntax",
            malformed_raw_digest,
            fixture.entries.clone(),
        ),
        (
            "configuration-repeated-prefix",
            repeated_prefix,
            repeated_prefix_entries,
        ),
        (
            "configuration-overlong-derived-subject",
            overlong_subject,
            overlong_subject_entries,
        ),
        ("epoch-nul-string", nul_string, nul_entries),
        (
            "admission-identity-epoch",
            identity_mismatch,
            identity_entries,
        ),
        ("admission-key-epoch", key_mismatch, key_entries),
        (
            "deployment-maximum",
            excessive_deployment,
            excessive_entries,
        ),
    ] {
        assert!(mutant.validate().is_err(), "production accepted {name}");
        assert!(
            ReferenceWitnessStoreModel::new(mutant, entries, usize::MAX).is_err(),
            "reference accepted {name}",
        );
    }

    let cross_stream_abort = fixture.sessionless_cross_stream_abort()?;
    assert!(cross_stream_abort.validate().is_err());
    let cross_stream_entries =
        BTreeMap::from([(fixture.stream_id.clone(), (8, cross_stream_abort))]);
    assert_eq!(
        InMemoryWitnessStore::new(
            fixture.ready.clone(),
            cross_stream_entries.clone(),
            1_000_000,
        )
        .err(),
        Some(WitnessStoreErrorV1::Admission),
    );
    assert_eq!(
        ReferenceWitnessStoreModel::new(fixture.ready.clone(), cross_stream_entries, 1_000_000)
            .err(),
        Some(WitnessStoreErrorV1::Admission),
    );
    let mut empty = fixture.current.clone();
    empty.session = None;
    empty.last_session_rotation = None;
    empty.current = None;
    empty.predecessor = None;
    empty.prepared = None;
    empty.genesis_abort = None;
    empty.store_generation = 0;
    empty.signature = fixture.base.witness.sign(&empty.signing_bytes()?);
    let empty_entries = BTreeMap::from([(fixture.stream_id.clone(), (1, empty))]);
    let mut forged_empty_digest = fixture.ready.clone();
    forged_empty_digest
        .ready_manifest
        .initialized_streams
        .get_mut(&witness_stream_key(&fixture.stream_id)?)
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .empty_envelope_digest = "f".repeat(64);
    forged_empty_digest.ready_manifest.signature = fixture
        .base
        .witness
        .sign(&forged_empty_digest.ready_manifest.signing_bytes()?);
    forged_empty_digest.bucket_anchor.ready_manifest_digest =
        forged_empty_digest.ready_manifest.digest()?;
    forged_empty_digest.bucket_anchor.signature = fixture
        .base
        .witness
        .sign(&forged_empty_digest.bucket_anchor.signing_bytes()?);
    forged_empty_digest.validate()?;
    assert_eq!(
        InMemoryWitnessStore::new(
            forged_empty_digest.clone(),
            empty_entries.clone(),
            1_000_000,
        )
        .err(),
        Some(WitnessStoreErrorV1::Corrupt),
    );
    assert_eq!(
        ReferenceWitnessStoreModel::new(forged_empty_digest, empty_entries, 1_000_000).err(),
        Some(WitnessStoreErrorV1::Corrupt),
    );
    let store = fixture.store(1_000_000)?;
    let before = store.canonical_store_bytes()?;
    for (revision, digest) in [
        (6, fixture.current.store_state_digest()?),
        (7, "f".repeat(64)),
    ] {
        assert!(matches!(
            store
                .compare_and_swap(&fixture.stream_id, revision, &digest, &fixture.proposed)
                .await?,
            WitnessStoreCasResultV1::Conflict { .. }
        ));
        assert_eq!(store.canonical_store_bytes()?, before);
    }
    store.inject_fault(WitnessStoreFault::CrashBeforeCas)?;
    assert_eq!(
        store
            .compare_and_swap(
                &fixture.stream_id,
                7,
                &fixture.current.store_state_digest()?,
                &fixture.proposed,
            )
            .await,
        Err(WitnessStoreErrorV1::Unavailable),
    );
    assert_eq!(store.canonical_store_bytes()?, before);
    Ok(())
}

#[tokio::test]
async fn in_memory_faults_return_ambiguous_without_guessing() -> StoreTestResult {
    let fixture = StoreFixture::new()?;
    let store = fixture.store(1_000_000)?;
    store.inject_fault(WitnessStoreFault::LostAfterCas)?;
    let result = store
        .compare_and_swap(
            &fixture.stream_id,
            7,
            &fixture.current.store_state_digest()?,
            &fixture.proposed,
        )
        .await?;
    assert!(matches!(
        result,
        WitnessStoreCasResultV1::Ambiguous {
            expected_previous_revision: 7,
            observed_revision: None,
            observed_value_digest: None,
            ..
        }
    ));
    let read = store.read_entry(&fixture.stream_id).await?;
    let (_, revision, envelope) = read.parts();
    assert_eq!(revision, 8);
    assert_eq!(
        envelope.canonical_bytes()?,
        fixture.proposed.canonical_bytes()?
    );
    assert!(matches!(
        store
            .compare_and_swap(
                &fixture.stream_id,
                7,
                &fixture.current.store_state_digest()?,
                &fixture.proposed,
            )
            .await?,
        WitnessStoreCasResultV1::Conflict {
            observed_revision: 8,
            ..
        }
    ));
    Ok(())
}

#[tokio::test]
async fn in_memory_capacity_exhaustion_is_pre_mutation() -> StoreTestResult {
    let fixture = StoreFixture::new()?;
    let capacity = canonical_wire_bytes(&fixture.entries)?.len();
    let store = fixture.store(capacity)?;
    let before = store.canonical_store_bytes()?;
    assert_eq!(
        store
            .compare_and_swap(
                &fixture.stream_id,
                7,
                &fixture.current.store_state_digest()?,
                &fixture.proposed,
            )
            .await,
        Err(WitnessStoreErrorV1::Bounds),
    );
    assert_eq!(store.canonical_store_bytes()?, before);
    Ok(())
}

struct BrokenSemanticStore {
    entries: BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>,
}

#[tokio::test]
async fn typed_proxy_rejects_signature_body_header_and_revision_mutations() -> StoreTestResult {
    let fixture = StoreFixture::new()?;

    let proxy = WitnessStoreProxy::new(fixture.spy_store()?, fixture.ready.clone())?;
    let mut invalid_signature_and_zero = fixture.cas_request()?;
    let WitnessStoreProxyRequestBodyV1::CompareAndSwap {
        expected_revision, ..
    } = &mut invalid_signature_and_zero.body
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch.into());
    };
    *expected_revision = 0;
    invalid_signature_and_zero.request_digest = invalid_signature_and_zero.computed_digest()?;
    invalid_signature_and_zero.signature.signature_hex = "00".repeat(64);
    assert_eq!(
        proxy
            .handle_bytes(&canonical_wire_bytes(&invalid_signature_and_zero)?)
            .await,
        Err(WitnessStoreErrorV1::Signature),
    );
    assert_eq!(proxy.store().calls(), (0, 0, 0));

    let mut resigned_zero = invalid_signature_and_zero;
    fixture.resign_request(&mut resigned_zero)?;
    assert_eq!(
        proxy
            .handle_bytes(&canonical_wire_bytes(&resigned_zero)?)
            .await,
        Err(WitnessStoreErrorV1::Admission),
    );
    assert_eq!(proxy.store().calls(), (0, 0, 0));

    let mut wrong_pair = fixture.inspect_request()?;
    wrong_pair.operation = WitnessStoreProxyOperationV1::ReadEntry;
    fixture.resign_request(&mut wrong_pair)?;
    assert_eq!(
        proxy
            .handle_bytes(&canonical_wire_bytes(&wrong_pair)?)
            .await,
        Err(WitnessStoreErrorV1::Admission),
    );
    assert_eq!(proxy.store().calls(), (0, 0, 0));

    let request = fixture.inspect_request()?;
    let mut injected = serde_json::to_value(&request)?;
    injected
        .as_object_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .insert(
            "header".to_string(),
            serde_json::json!({"KV-Operation":"PUT"}),
        );
    assert_eq!(
        proxy.handle_bytes(&canonical_wire_bytes(&injected)?).await,
        Err(WitnessStoreErrorV1::Corrupt),
    );
    assert_eq!(proxy.store().calls(), (0, 0, 0));

    let header_proxy = WitnessStoreProxy::new(HeaderStore, fixture.ready)?;
    let response = header_proxy
        .handle_bytes(&canonical_wire_bytes(&request)?)
        .await?;
    assert!(matches!(
        response.body,
        WitnessStoreProxyResponseBodyV1::Refused {
            failure_code: WitnessStoreProxyFailureCodeV1::Header,
            ..
        }
    ));
    Ok(())
}

#[tokio::test]
async fn typed_proxy_delegates_only_after_canonical_validation() -> StoreTestResult {
    let fixture = StoreFixture::new()?;
    let proxy = WitnessStoreProxy::new(fixture.spy_store()?, fixture.ready.clone())?;
    let response = proxy
        .handle_bytes(&canonical_wire_bytes(&fixture.inspect_request()?)?)
        .await?;
    let WitnessStoreProxyResponseBodyV1::Ready {
        validated_streams, ..
    } = response.body
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch.into());
    };
    assert_eq!(validated_streams.len(), 1);
    assert_eq!(validated_streams[&fixture.stream_id].revision, 7);
    assert_eq!(proxy.store().calls(), (1, 1, 0));

    let (two_ready, two_entries) = fixture.two_stream_static_ready()?;
    let ordered = OrderedReadStore {
        ready: two_ready.clone(),
        entries: two_entries,
        reads: Mutex::new(Vec::new()),
    };
    let ordered_proxy = WitnessStoreProxy::new(ordered, two_ready.clone())?;
    let mut ordered_request = fixture.inspect_request()?;
    ordered_request.admission_digest = two_ready.admission_set.entries[0].admission_digest.clone();
    ordered_request.bucket_epoch_digest = two_ready.bucket_epoch.digest()?;
    ordered_request.bucket_anchor_digest = two_ready.bucket_anchor.digest()?;
    fixture.resign_request(&mut ordered_request)?;
    let ordered_response = ordered_proxy
        .handle_bytes(&canonical_wire_bytes(&ordered_request)?)
        .await?;
    let WitnessStoreProxyResponseBodyV1::Ready {
        validated_streams, ..
    } = ordered_response.body
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch.into());
    };
    assert_eq!(validated_streams.len(), 2);
    assert_eq!(
        *ordered_proxy
            .store()
            .reads
            .lock()
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?,
        ["aaron-secondary".to_string(), "tom-primary".to_string()],
    );

    let candidate = &fixture
        .proposed
        .prepared
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .candidate;
    let base_bounds = StoreBounds {
        state: fixture.ready.admission_set.entries[0].max_state_bytes,
        checkpoint: fixture.ready.admission_set.entries[0].max_checkpoint_bytes,
        binding: canonical_wire_bytes(&candidate.publication_binding)?.len() as u64,
        retained: fixture.ready.admission_set.entries[0].max_retained_bytes,
        request: fixture.ready.admission_set.entries[0].max_request_bytes,
        response: fixture.ready.admission_set.entries[0].max_response_bytes,
    };
    let (probe_ready, probe_entries, _) = fixture.rebind_bounds(base_bounds)?;
    let probe_proxy = WitnessStoreProxy::new(
        InMemoryWitnessStore::new(probe_ready.clone(), probe_entries, 1_000_000)?,
        probe_ready.clone(),
    )?;
    let probe_response = probe_proxy
        .handle_bytes(&canonical_wire_bytes(
            &fixture.inspect_request_for(&probe_ready)?,
        )?)
        .await?;
    let exact_response_bytes = canonical_wire_bytes(&probe_response)?.len() as u64;
    for (limit, should_pass) in [
        (exact_response_bytes, true),
        (exact_response_bytes.saturating_sub(1), false),
    ] {
        let (ready, entries, _) = fixture.rebind_bounds(StoreBounds {
            response: limit,
            ..base_bounds
        })?;
        let proxy = WitnessStoreProxy::new(
            InMemoryWitnessStore::new(ready.clone(), entries, 1_000_000)?,
            ready.clone(),
        )?;
        let result = proxy
            .handle_bytes(&canonical_wire_bytes(
                &fixture.inspect_request_for(&ready)?,
            )?)
            .await;
        assert_eq!(result.is_ok(), should_pass);
        if !should_pass {
            assert_eq!(result, Err(WitnessStoreErrorV1::Bounds));
        }
    }
    let exact_request_bytes =
        canonical_wire_bytes(&fixture.inspect_request_for(&probe_ready)?)?.len() as u64;
    for (limit, should_pass) in [
        (exact_request_bytes, true),
        (exact_request_bytes.saturating_sub(1), false),
    ] {
        let (ready, entries, _) = fixture.rebind_bounds(StoreBounds {
            request: limit,
            ..base_bounds
        })?;
        let proxy = WitnessStoreProxy::new(
            InMemoryWitnessStore::new(ready.clone(), entries, 1_000_000)?,
            ready.clone(),
        )?;
        let result = proxy
            .handle_bytes(&canonical_wire_bytes(
                &fixture.inspect_request_for(&ready)?,
            )?)
            .await;
        assert_eq!(result.is_ok(), should_pass);
        if !should_pass {
            assert_eq!(result, Err(WitnessStoreErrorV1::Bounds));
        }
    }

    let read_proxy = WitnessStoreProxy::new(fixture.spy_store()?, fixture.ready.clone())?;
    let response = read_proxy
        .handle_bytes(&canonical_wire_bytes(&fixture.read_request()?)?)
        .await?;
    assert!(matches!(
        response.body,
        WitnessStoreProxyResponseBodyV1::Entry { revision: 7, .. }
    ));
    assert_eq!(read_proxy.store().calls(), (0, 1, 0));

    let foreign = ForeignReadStore {
        ready: fixture.ready.clone(),
        envelope: fixture.current.clone(),
        reads: AtomicUsize::new(0),
    };
    let foreign_proxy = WitnessStoreProxy::new(foreign, fixture.ready.clone())?;
    let refused = foreign_proxy
        .handle_bytes(&canonical_wire_bytes(&fixture.inspect_request()?)?)
        .await?;
    assert!(matches!(
        refused.body,
        WitnessStoreProxyResponseBodyV1::Refused {
            failure_code: WitnessStoreProxyFailureCodeV1::Corrupt,
            ..
        }
    ));
    assert_eq!(foreign_proxy.store().reads.load(Ordering::SeqCst), 1);

    let invalid_proxy = WitnessStoreProxy::new(fixture.spy_store()?, fixture.ready.clone())?;
    let mut invalid = fixture.current.clone();
    invalid.store_generation += 1;
    invalid.signature = fixture.base.witness.sign(&invalid.signing_bytes()?);
    let invalid_request = fixture.proxy_request(
        WitnessStoreProxyOperationV1::CompareAndSwap,
        WitnessStoreProxyRequestBodyV1::CompareAndSwap {
            stream_id: fixture.stream_id.clone(),
            expected_revision: 7,
            expected_store_state_digest: fixture.current.store_state_digest()?,
            proposed_envelope: Box::new(invalid),
        },
    )?;
    let refused = invalid_proxy
        .handle_bytes(&canonical_wire_bytes(&invalid_request)?)
        .await?;
    assert!(matches!(
        refused.body,
        WitnessStoreProxyResponseBodyV1::Refused { .. }
    ));
    assert_eq!(invalid_proxy.store().calls(), (0, 1, 0));
    Ok(())
}

#[tokio::test]
async fn typed_proxy_preserves_reference_outcomes() -> StoreTestResult {
    let fixture = StoreFixture::new()?;

    let direct = fixture.store(1_000_000)?;
    let mut reference =
        ReferenceWitnessStoreModel::new(fixture.ready.clone(), fixture.entries.clone(), 1_000_000)?;
    let proxy = WitnessStoreProxy::new(fixture.store(1_000_000)?, fixture.ready.clone())?;
    let current_digest = fixture.current.store_state_digest()?;
    let direct_result = direct
        .compare_and_swap(&fixture.stream_id, 7, &current_digest, &fixture.proposed)
        .await;
    let reference_result =
        reference.compare_and_swap(&fixture.stream_id, 7, &current_digest, &fixture.proposed);
    assert_eq!(direct_result, reference_result);
    let WitnessStoreCasResultV1::Applied {
        previous_revision,
        new_revision,
        acknowledged_value_digest,
        duplicate,
        ..
    } = direct_result?
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch.into());
    };
    let proxy_result = proxy
        .handle_bytes(&canonical_wire_bytes(&fixture.cas_request()?)?)
        .await?;
    let WitnessStoreProxyResponseBodyV1::CasApplied {
        previous_revision: proxy_previous,
        new_revision: proxy_revision,
        acknowledged_value_digest: proxy_digest,
        ..
    } = proxy_result.body
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch.into());
    };
    assert_eq!(
        (previous_revision, new_revision, acknowledged_value_digest,),
        (proxy_previous, proxy_revision, proxy_digest,),
    );
    assert!(!duplicate);
    assert_eq!(
        direct.canonical_store_bytes()?,
        reference.canonical_store_bytes()?
    );
    assert_eq!(
        direct.canonical_store_bytes()?,
        proxy.store().canonical_store_bytes()?
    );

    let conflict_direct = fixture.store(1_000_000)?;
    let mut conflict_reference =
        ReferenceWitnessStoreModel::new(fixture.ready.clone(), fixture.entries.clone(), 1_000_000)?;
    let conflict_proxy = WitnessStoreProxy::new(fixture.store(1_000_000)?, fixture.ready.clone())?;
    let direct_conflict = conflict_direct
        .compare_and_swap(&fixture.stream_id, 6, &current_digest, &fixture.proposed)
        .await;
    let reference_conflict = conflict_reference.compare_and_swap(
        &fixture.stream_id,
        6,
        &current_digest,
        &fixture.proposed,
    );
    assert_eq!(direct_conflict, reference_conflict);
    let WitnessStoreCasResultV1::Conflict {
        observed_revision,
        observed_envelope,
        ..
    } = direct_conflict?
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch.into());
    };
    let mut stale_request = fixture.cas_request()?;
    let WitnessStoreProxyRequestBodyV1::CompareAndSwap {
        expected_revision, ..
    } = &mut stale_request.body
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch.into());
    };
    *expected_revision = 6;
    fixture.resign_request(&mut stale_request)?;
    let stale_response = conflict_proxy
        .handle_bytes(&canonical_wire_bytes(&stale_request)?)
        .await?;
    let WitnessStoreProxyResponseBodyV1::Refused {
        failure_code,
        observed_revision: proxy_observed,
        observed_value_digest,
    } = stale_response.body
    else {
        return Err(ProtocolError::WitnessOutcomeMismatch.into());
    };
    assert_eq!(failure_code, WitnessStoreProxyFailureCodeV1::Conflict);
    assert_eq!(proxy_observed, Some(observed_revision));
    assert_eq!(
        observed_value_digest,
        Some(observed_envelope.store_state_digest()?),
    );
    assert_eq!(
        conflict_direct.canonical_store_bytes()?,
        conflict_reference.canonical_store_bytes()?,
    );
    assert_eq!(
        conflict_direct.canonical_store_bytes()?,
        conflict_proxy.store().canonical_store_bytes()?,
    );

    for (field, expected_error) in [
        ("epoch", WitnessStoreErrorV1::Configuration),
        ("admission", WitnessStoreErrorV1::Admission),
    ] {
        let proxy = WitnessStoreProxy::new(fixture.spy_store()?, fixture.ready.clone())?;
        let mut request = fixture.read_request()?;
        if field == "epoch" {
            request.bucket_epoch_digest = "e".repeat(64);
        } else {
            request.admission_digest = "e".repeat(64);
        }
        fixture.resign_request(&mut request)?;
        assert_eq!(
            proxy.handle_bytes(&canonical_wire_bytes(&request)?).await,
            Err(expected_error),
            "validly re-signed {field} mutant",
        );
        assert_eq!(proxy.store().calls(), (0, 0, 0));
    }

    let prepared_entries =
        BTreeMap::from([(fixture.stream_id.clone(), (8, fixture.proposed.clone()))]);
    let content_mutant = fixture.rebuilt_commit_content_mutant()?;
    assert!(content_mutant.validate().is_ok());
    let content_direct =
        InMemoryWitnessStore::new(fixture.ready.clone(), prepared_entries.clone(), 1_000_000)?;
    let mut content_reference = ReferenceWitnessStoreModel::new(
        fixture.ready.clone(),
        prepared_entries.clone(),
        1_000_000,
    )?;
    let content_proxy_store =
        InMemoryWitnessStore::new(fixture.ready.clone(), prepared_entries, 1_000_000)?;
    let content_proxy = WitnessStoreProxy::new(content_proxy_store, fixture.ready.clone())?;
    let before_content = content_direct.canonical_store_bytes()?;
    let prepared_digest = fixture.proposed.store_state_digest()?;
    assert_eq!(
        content_direct
            .compare_and_swap(&fixture.stream_id, 8, &prepared_digest, &content_mutant,)
            .await,
        Err(WitnessStoreErrorV1::Admission),
    );
    assert_eq!(
        content_reference.compare_and_swap(
            &fixture.stream_id,
            8,
            &prepared_digest,
            &content_mutant,
        ),
        Err(WitnessStoreErrorV1::Admission),
    );
    let content_request = fixture.proxy_request(
        WitnessStoreProxyOperationV1::CompareAndSwap,
        WitnessStoreProxyRequestBodyV1::CompareAndSwap {
            stream_id: fixture.stream_id.clone(),
            expected_revision: 8,
            expected_store_state_digest: prepared_digest,
            proposed_envelope: Box::new(content_mutant),
        },
    )?;
    let content_response = content_proxy
        .handle_bytes(&canonical_wire_bytes(&content_request)?)
        .await?;
    assert!(matches!(
        content_response.body,
        WitnessStoreProxyResponseBodyV1::Refused {
            failure_code: WitnessStoreProxyFailureCodeV1::Admission,
            observed_revision: Some(8),
            ..
        }
    ));
    assert_eq!(content_direct.canonical_store_bytes()?, before_content);
    assert_eq!(content_reference.canonical_store_bytes()?, before_content);
    assert_eq!(
        content_proxy.store().canonical_store_bytes()?,
        before_content
    );

    let mut mapping_mutant = fixture.proposed.clone();
    let mapping = &mut mapping_mutant
        .prepared
        .as_mut()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?
        .candidate
        .publication_mapping_after;
    mapping.state_canonical = mapping.state_staging;
    fixture.unchecked_resign(&mut mapping_mutant)?;
    let transition_mutant = fixture.commit_envelope()?;
    assert!(transition_mutant.validate().is_ok());
    for (name, mutant) in [
        ("mapping", mapping_mutant),
        ("transition", transition_mutant),
    ] {
        let direct = fixture.store(1_000_000)?;
        let mut reference = ReferenceWitnessStoreModel::new(
            fixture.ready.clone(),
            fixture.entries.clone(),
            1_000_000,
        )?;
        let proxy = WitnessStoreProxy::new(fixture.store(1_000_000)?, fixture.ready.clone())?;
        assert_eq!(
            direct
                .compare_and_swap(&fixture.stream_id, 7, &current_digest, &mutant)
                .await,
            Err(WitnessStoreErrorV1::Admission),
            "direct accepted validly re-signed {name} mutant",
        );
        assert_eq!(
            reference.compare_and_swap(&fixture.stream_id, 7, &current_digest, &mutant),
            Err(WitnessStoreErrorV1::Admission),
            "reference accepted validly re-signed {name} mutant",
        );
        let request = fixture.proxy_request(
            WitnessStoreProxyOperationV1::CompareAndSwap,
            WitnessStoreProxyRequestBodyV1::CompareAndSwap {
                stream_id: fixture.stream_id.clone(),
                expected_revision: 7,
                expected_store_state_digest: current_digest.clone(),
                proposed_envelope: Box::new(mutant),
            },
        )?;
        let response = proxy.handle_bytes(&canonical_wire_bytes(&request)?).await?;
        assert!(matches!(
            response.body,
            WitnessStoreProxyResponseBodyV1::Refused {
                failure_code: WitnessStoreProxyFailureCodeV1::Admission,
                ..
            }
        ));
        assert_eq!(
            direct.canonical_store_bytes()?,
            reference.canonical_store_bytes()?
        );
        assert_eq!(
            direct.canonical_store_bytes()?,
            proxy.store().canonical_store_bytes()?
        );
    }

    let (two_ready, two_entries) = fixture.two_stream_static_ready()?;
    for (mode, expected_failure, expected_reads) in [
        (
            ScriptedInspectMode::Missing,
            Some(WitnessStoreProxyFailureCodeV1::Missing),
            vec!["aaron-secondary".to_string()],
        ),
        (
            ScriptedInspectMode::Duplicate,
            Some(WitnessStoreProxyFailureCodeV1::Corrupt),
            vec!["aaron-secondary".to_string(), "tom-primary".to_string()],
        ),
        (
            ScriptedInspectMode::Corrupt,
            Some(WitnessStoreProxyFailureCodeV1::Corrupt),
            vec!["aaron-secondary".to_string()],
        ),
        (
            ScriptedInspectMode::CoordinatedRevision,
            None,
            vec!["aaron-secondary".to_string(), "tom-primary".to_string()],
        ),
    ] {
        let scripted = ScriptedInspectStore {
            ready: two_ready.clone(),
            entries: two_entries.clone(),
            mode,
            reads: Mutex::new(Vec::new()),
        };
        let scripted_proxy = WitnessStoreProxy::new(scripted, two_ready.clone())?;
        let response = scripted_proxy
            .handle_bytes(&canonical_wire_bytes(
                &fixture.inspect_request_for(&two_ready)?,
            )?)
            .await?;
        match (expected_failure, response.body) {
            (Some(expected), WitnessStoreProxyResponseBodyV1::Refused { failure_code, .. }) => {
                assert_eq!(failure_code, expected)
            }
            (
                None,
                WitnessStoreProxyResponseBodyV1::Ready {
                    validated_streams, ..
                },
            ) => {
                assert_eq!(validated_streams["aaron-secondary"].revision, 11);
                assert_eq!(validated_streams["tom-primary"].revision, 29);
            }
            _ => return Err(ProtocolError::WitnessOutcomeMismatch.into()),
        }
        assert_eq!(
            *scripted_proxy
                .store()
                .reads
                .lock()
                .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?,
            expected_reads,
        );
    }

    let global = GlobalRevisionStore {
        ready: fixture.ready.clone(),
        current: fixture.current.clone(),
        proposed: fixture.proposed.clone(),
        reads: AtomicUsize::new(0),
        cas: AtomicUsize::new(0),
    };
    let global_proxy = WitnessStoreProxy::new(global, fixture.ready.clone())?;
    let applied = global_proxy
        .handle_bytes(&canonical_wire_bytes(&fixture.cas_request()?)?)
        .await?;
    assert!(matches!(
        applied.body,
        WitnessStoreProxyResponseBodyV1::CasApplied {
            previous_revision: 7,
            new_revision: 19,
            ..
        }
    ));
    assert_eq!(global_proxy.store().reads.load(Ordering::SeqCst), 2);
    assert_eq!(global_proxy.store().cas.load(Ordering::SeqCst), 1);

    let error_after_cas = ErrorAfterCasStore {
        ready: fixture.ready.clone(),
        current: fixture.current.clone(),
        proposed: fixture.proposed.clone(),
        reads: AtomicUsize::new(0),
    };
    let error_proxy = WitnessStoreProxy::new(error_after_cas, fixture.ready.clone())?;
    let ambiguous = error_proxy
        .handle_bytes(&canonical_wire_bytes(&fixture.cas_request()?)?)
        .await?;
    assert!(matches!(
        ambiguous.body,
        WitnessStoreProxyResponseBodyV1::Refused {
            failure_code: WitnessStoreProxyFailureCodeV1::Ambiguous,
            observed_revision: Some(8),
            ..
        }
    ));
    assert_eq!(error_proxy.store().reads.load(Ordering::SeqCst), 2);

    for fault in [
        WitnessStoreFault::WrongRevision,
        WitnessStoreFault::DuplicateAck,
        WitnessStoreFault::LostAfterCas,
    ] {
        let proxy = WitnessStoreProxy::new(fixture.spy_store()?, fixture.ready.clone())?;
        proxy.store().inner.inject_fault(fault)?;
        let response = proxy
            .handle_bytes(&canonical_wire_bytes(&fixture.cas_request()?)?)
            .await?;
        assert!(matches!(
            response.body,
            WitnessStoreProxyResponseBodyV1::Refused {
                failure_code: WitnessStoreProxyFailureCodeV1::Ambiguous,
                ..
            }
        ));
        assert_eq!(proxy.store().cas_calls.load(Ordering::SeqCst), 1);
        assert_eq!(proxy.store().read_calls.load(Ordering::SeqCst), 2);
    }
    Ok(())
}

struct SpyStore {
    inner: InMemoryWitnessStore,
    inspect_calls: AtomicUsize,
    read_calls: AtomicUsize,
    cas_calls: AtomicUsize,
}

impl SpyStore {
    fn calls(&self) -> (usize, usize, usize) {
        (
            self.inspect_calls.load(Ordering::SeqCst),
            self.read_calls.load(Ordering::SeqCst),
            self.cas_calls.load(Ordering::SeqCst),
        )
    }
}

#[async_trait]
impl WitnessAtomicStore for SpyStore {
    async fn inspect_ready(&self) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1> {
        self.inspect_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.inspect_ready().await
    }

    async fn read_entry(
        &self,
        stream_id: &str,
    ) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.read_entry(stream_id).await
    }

    async fn compare_and_swap(
        &self,
        stream_id: &str,
        expected_revision: u64,
        expected_store_state_digest: &str,
        proposed_envelope: &WitnessStoreEnvelopeV1,
    ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1> {
        self.cas_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .compare_and_swap(
                stream_id,
                expected_revision,
                expected_store_state_digest,
                proposed_envelope,
            )
            .await
    }
}

struct HeaderStore;

#[async_trait]
impl WitnessAtomicStore for HeaderStore {
    async fn inspect_ready(&self) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1> {
        Err(WitnessStoreErrorV1::Header)
    }
    async fn read_entry(&self, _: &str) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1> {
        Err(WitnessStoreErrorV1::Header)
    }
    async fn compare_and_swap(
        &self,
        _: &str,
        _: u64,
        _: &str,
        _: &WitnessStoreEnvelopeV1,
    ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1> {
        Err(WitnessStoreErrorV1::Header)
    }
}

struct ForeignReadStore {
    ready: WitnessStoreReadyResultV1,
    envelope: WitnessStoreEnvelopeV1,
    reads: AtomicUsize,
}

struct OrderedReadStore {
    ready: WitnessStoreReadyResultV1,
    entries: BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>,
    reads: Mutex<Vec<String>>,
}

#[derive(Clone, Copy)]
enum ScriptedInspectMode {
    Missing,
    Duplicate,
    Corrupt,
    CoordinatedRevision,
}

struct ScriptedInspectStore {
    ready: WitnessStoreReadyResultV1,
    entries: StoreEntries,
    mode: ScriptedInspectMode,
    reads: Mutex<Vec<String>>,
}

#[async_trait]
impl WitnessAtomicStore for ScriptedInspectStore {
    async fn inspect_ready(&self) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1> {
        Ok(self.ready.clone())
    }

    async fn read_entry(
        &self,
        stream_id: &str,
    ) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1> {
        let mut reads = self
            .reads
            .lock()
            .map_err(|_| WitnessStoreErrorV1::Unavailable)?;
        let call = reads.len();
        reads.push(stream_id.to_string());
        if matches!(self.mode, ScriptedInspectMode::Missing) {
            return Err(WitnessStoreErrorV1::Missing);
        }
        let (mut revision, mut envelope) = self
            .entries
            .get(stream_id)
            .cloned()
            .ok_or(WitnessStoreErrorV1::Missing)?;
        let mut observed_stream = stream_id.to_string();
        match self.mode {
            ScriptedInspectMode::Missing => unreachable!(),
            ScriptedInspectMode::Duplicate if call == 1 => {
                observed_stream = self
                    .ready
                    .admission_set
                    .entries
                    .first()
                    .ok_or(WitnessStoreErrorV1::Missing)?
                    .stream_id
                    .clone();
            }
            ScriptedInspectMode::Corrupt => {
                envelope.signature.signature_hex = "00".repeat(64);
            }
            ScriptedInspectMode::CoordinatedRevision => {
                revision = if call == 0 { 11 } else { 29 };
            }
            ScriptedInspectMode::Duplicate => {}
        }
        Ok(WitnessStoreReadResultV1::Entry {
            stream_id: observed_stream,
            revision,
            envelope: Box::new(envelope),
        })
    }

    async fn compare_and_swap(
        &self,
        _: &str,
        _: u64,
        _: &str,
        _: &WitnessStoreEnvelopeV1,
    ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1> {
        panic!("scripted InspectReady control must not CAS")
    }
}

#[async_trait]
impl WitnessAtomicStore for OrderedReadStore {
    async fn inspect_ready(&self) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1> {
        Ok(self.ready.clone())
    }

    async fn read_entry(
        &self,
        stream_id: &str,
    ) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1> {
        self.reads
            .lock()
            .map_err(|_| WitnessStoreErrorV1::Unavailable)?
            .push(stream_id.to_string());
        let (revision, envelope) = self
            .entries
            .get(stream_id)
            .ok_or(WitnessStoreErrorV1::Missing)?;
        Ok(WitnessStoreReadResultV1::Entry {
            stream_id: stream_id.to_string(),
            revision: *revision,
            envelope: Box::new(envelope.clone()),
        })
    }

    async fn compare_and_swap(
        &self,
        _: &str,
        _: u64,
        _: &str,
        _: &WitnessStoreEnvelopeV1,
    ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1> {
        panic!("ordered InspectReady control must not CAS")
    }
}

#[async_trait]
impl WitnessAtomicStore for ForeignReadStore {
    async fn inspect_ready(&self) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1> {
        Ok(self.ready.clone())
    }
    async fn read_entry(&self, _: &str) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(WitnessStoreReadResultV1::Entry {
            stream_id: "foreign".to_string(),
            revision: 99,
            envelope: Box::new(self.envelope.clone()),
        })
    }
    async fn compare_and_swap(
        &self,
        _: &str,
        _: u64,
        _: &str,
        _: &WitnessStoreEnvelopeV1,
    ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1> {
        panic!("foreign-read control must not CAS")
    }
}

struct GlobalRevisionStore {
    ready: WitnessStoreReadyResultV1,
    current: WitnessStoreEnvelopeV1,
    proposed: WitnessStoreEnvelopeV1,
    reads: AtomicUsize,
    cas: AtomicUsize,
}

struct ErrorAfterCasStore {
    ready: WitnessStoreReadyResultV1,
    current: WitnessStoreEnvelopeV1,
    proposed: WitnessStoreEnvelopeV1,
    reads: AtomicUsize,
}

#[async_trait]
impl WitnessAtomicStore for ErrorAfterCasStore {
    async fn inspect_ready(&self) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1> {
        Ok(self.ready.clone())
    }

    async fn read_entry(
        &self,
        stream_id: &str,
    ) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1> {
        let call = self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(WitnessStoreReadResultV1::Entry {
            stream_id: stream_id.to_string(),
            revision: if call == 0 { 7 } else { 8 },
            envelope: Box::new(if call == 0 {
                self.current.clone()
            } else {
                self.proposed.clone()
            }),
        })
    }

    async fn compare_and_swap(
        &self,
        _: &str,
        _: u64,
        _: &str,
        _: &WitnessStoreEnvelopeV1,
    ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1> {
        Err(WitnessStoreErrorV1::Ambiguous)
    }
}

#[async_trait]
impl WitnessAtomicStore for GlobalRevisionStore {
    async fn inspect_ready(&self) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1> {
        Ok(self.ready.clone())
    }
    async fn read_entry(
        &self,
        stream_id: &str,
    ) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1> {
        let call = self.reads.fetch_add(1, Ordering::SeqCst);
        let (revision, envelope) = if call == 0 {
            (7, self.current.clone())
        } else {
            (19, self.proposed.clone())
        };
        Ok(WitnessStoreReadResultV1::Entry {
            stream_id: stream_id.to_string(),
            revision,
            envelope: Box::new(envelope),
        })
    }
    async fn compare_and_swap(
        &self,
        stream_id: &str,
        expected_revision: u64,
        _: &str,
        proposed: &WitnessStoreEnvelopeV1,
    ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1> {
        self.cas.fetch_add(1, Ordering::SeqCst);
        Ok(WitnessStoreCasResultV1::Applied {
            stream_id: stream_id.to_string(),
            expected_previous_revision: expected_revision,
            previous_revision: 7,
            new_revision: 19,
            acknowledged_value_digest: proposed
                .signed_envelope_digest()
                .map_err(|_| WitnessStoreErrorV1::Corrupt)?,
            duplicate: false,
        })
    }
}

impl BrokenSemanticStore {
    fn new(entries: BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>) -> Self {
        Self { entries }
    }

    fn accept_without_semantics(
        &mut self,
        stream_id: &str,
        proposed: WitnessStoreEnvelopeV1,
    ) -> bool {
        let Some((revision, _)) = self.entries.get(stream_id).cloned() else {
            return false;
        };
        self.entries.insert(
            stream_id.to_string(),
            (revision.saturating_add(1), proposed),
        );
        true
    }
}

fn store_bucket_configuration(
    max_value_bytes: u64,
    max_bucket_bytes: u64,
    replicas: u32,
) -> ProtocolResult<WitnessBucketConfigurationV1> {
    Ok(WitnessBucketConfigurationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        nats_server_version: "2.11.17".to_string(),
        nats_server_image_index_digest:
            "sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00".to_string(),
        stream_name: "KV_phase285_witness".to_string(),
        description: "Phase 285 external governance witness".to_string(),
        subjects: vec!["$KV.phase285_witness.>".to_string()],
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
        num_replicas: replicas,
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
            ("_nats.ver".to_string(), "2.11.17".to_string()),
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
