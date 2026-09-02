use super::*;
use crate::persistence_protocol::{
    ArtifactIdentityV1, AuthorityPairIdentityV1, PROTOCOL_SCHEMA_VERSION, RecoveryChallengeV1,
    WitnessOperationV1, WitnessSessionAuthorizationV1, WitnessSessionFenceRequestV1,
    WitnessSessionStateFenceV1, WitnessSessionV1, canonical_wire_bytes,
};
use serde::Serialize;
use swarm_crypto::{DetachedSignature, Ed25519Signer};

#[test]
fn service_operation_wire_set_is_exactly_the_nine_contract_operations()
-> crate::persistence_protocol::ProtocolResult<()> {
    let operations = [
        WitnessServiceOperationV1::Fence,
        WitnessServiceOperationV1::Establish,
        WitnessServiceOperationV1::Discover,
        WitnessServiceOperationV1::Prepare,
        WitnessServiceOperationV1::Commit,
        WitnessServiceOperationV1::Abort,
        WitnessServiceOperationV1::ReadPrepared,
        WitnessServiceOperationV1::ReadHead,
        WitnessServiceOperationV1::FetchPayload,
    ];
    let encoded = operations
        .into_iter()
        .map(|operation| serde_json::to_string(&operation))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            crate::persistence_protocol::ProtocolError::CanonicalEncoding(error.to_string())
        })?;
    assert_eq!(
        encoded,
        [
            "\"Fence\"",
            "\"Establish\"",
            "\"Discover\"",
            "\"Prepare\"",
            "\"Commit\"",
            "\"Abort\"",
            "\"ReadPrepared\"",
            "\"ReadHead\"",
            "\"FetchPayload\"",
        ]
    );
    assert!(serde_json::from_str::<WitnessServiceOperationV1>("\"Unknown\"").is_err());
    Ok(())
}

#[test]
fn session_bound_request_binds_body_digest_and_ephemeral_authorization()
-> crate::persistence_protocol::ProtocolResult<()> {
    let ephemeral = Ed25519Signer::from_secret_material("service-wire-ephemeral");
    let session = sample_session(&ephemeral);
    let txid = "8".repeat(64);
    let mut request = request(
        WitnessServiceOperationV1::Commit,
        WitnessServiceRequestBodyV1::Commit {
            session: Box::new(session.clone()),
            txid: txid.clone(),
        },
    );
    request.request_digest = request.computed_digest()?;
    request.authorization = Some(authorization(
        &ephemeral,
        &session,
        WitnessOperationV1::Commit,
        &txid,
        &request.request_digest,
    )?);
    request.validate()?;

    let digest = request.computed_digest()?;
    let mut changed_authorization = request.clone();
    let Some(authorization) = changed_authorization.authorization.as_mut() else {
        return Err(crate::persistence_protocol::ProtocolError::WitnessOutcomeMismatch);
    };
    authorization.signature.signature_hex = "00".repeat(64);
    assert_eq!(changed_authorization.computed_digest()?, digest);
    assert!(changed_authorization.validate().is_err());
    Ok(())
}

#[test]
fn operation_body_and_request_preimage_mutations_fail_closed()
-> crate::persistence_protocol::ProtocolResult<()> {
    let ephemeral = Ed25519Signer::from_secret_material("service-wire-ephemeral");
    let session = sample_session(&ephemeral);
    let txid = "8".repeat(64);
    let mut valid = request(
        WitnessServiceOperationV1::Commit,
        WitnessServiceRequestBodyV1::Commit {
            session: Box::new(session.clone()),
            txid: txid.clone(),
        },
    );
    valid.request_digest = valid.computed_digest()?;
    valid.authorization = Some(authorization(
        &ephemeral,
        &session,
        WitnessOperationV1::Commit,
        &txid,
        &valid.request_digest,
    )?);
    valid.validate()?;

    let mut wrong_operation = valid.clone();
    wrong_operation.operation = WitnessServiceOperationV1::Abort;
    assert!(wrong_operation.validate().is_err());

    let mut wrong_nonce = valid.clone();
    wrong_nonce.request_nonce = "9".repeat(64);
    assert!(wrong_nonce.validate().is_err());

    let mut wrong_admission = valid.clone();
    wrong_admission.admission_digest = "a".repeat(64);
    assert!(wrong_admission.validate().is_err());

    let mut changed_body = valid.clone();
    if let WitnessServiceRequestBodyV1::Commit { txid, .. } = &mut changed_body.body {
        *txid = "b".repeat(64);
    }
    changed_body.request_digest = changed_body.computed_digest()?;
    assert!(changed_body.validate().is_err());

    let mut missing_authorization = valid;
    missing_authorization.authorization = None;
    assert!(missing_authorization.validate().is_err());
    Ok(())
}

#[test]
fn every_non_prepare_session_operation_uses_its_exact_authorization_operation()
-> crate::persistence_protocol::ProtocolResult<()> {
    let ephemeral = Ed25519Signer::from_secret_material("service-wire-ephemeral");
    let session = sample_session(&ephemeral);
    let txid = "8".repeat(64);
    let cases = [
        (
            WitnessServiceOperationV1::Commit,
            WitnessServiceRequestBodyV1::Commit {
                session: Box::new(session.clone()),
                txid: txid.clone(),
            },
            WitnessOperationV1::Commit,
        ),
        (
            WitnessServiceOperationV1::Abort,
            WitnessServiceRequestBodyV1::Abort {
                session: Box::new(session.clone()),
                txid: txid.clone(),
            },
            WitnessOperationV1::Abort,
        ),
        (
            WitnessServiceOperationV1::ReadPrepared,
            WitnessServiceRequestBodyV1::ReadPrepared {
                session: Box::new(session.clone()),
                target_txid: txid.clone(),
            },
            WitnessOperationV1::ReadPrepared,
        ),
        (
            WitnessServiceOperationV1::ReadHead,
            WitnessServiceRequestBodyV1::ReadHead {
                session: Box::new(session.clone()),
                target_txid: txid.clone(),
            },
            WitnessOperationV1::ReadHead,
        ),
        (
            WitnessServiceOperationV1::FetchPayload,
            WitnessServiceRequestBodyV1::FetchPayload {
                session: Box::new(session.clone()),
                txid: txid.clone(),
            },
            WitnessOperationV1::FetchPayload,
        ),
    ];

    for (service_operation, body, authorization_operation) in cases {
        let mut request = request(service_operation, body);
        request.request_digest = request.computed_digest()?;
        request.authorization = Some(authorization(
            &ephemeral,
            &session,
            authorization_operation,
            &txid,
            &request.request_digest,
        )?);
        request.validate()?;

        let mut cross_operation = request;
        cross_operation.authorization = Some(authorization(
            &ephemeral,
            &session,
            WitnessOperationV1::Prepare,
            &txid,
            &cross_operation.request_digest,
        )?);
        assert!(cross_operation.validate().is_err());
    }
    Ok(())
}

#[test]
fn establish_and_discover_require_null_authorization_and_valid_challenge()
-> crate::persistence_protocol::ProtocolResult<()> {
    let governance = Ed25519Signer::from_secret_material("service-wire-governance");
    let witness = Ed25519Signer::from_secret_material("service-wire-witness");
    let ephemeral = Ed25519Signer::from_secret_material("service-wire-ephemeral");
    let challenge = sample_challenge(&governance, &witness, &ephemeral)?;

    let cases = [
        (
            WitnessServiceOperationV1::Establish,
            WitnessServiceRequestBodyV1::Establish {
                challenge: Box::new(challenge.clone()),
                expected_head: None,
            },
        ),
        (
            WitnessServiceOperationV1::Discover,
            WitnessServiceRequestBodyV1::Discover {
                challenge: Box::new(challenge),
            },
        ),
    ];
    for (operation, body) in cases {
        let mut request = request(operation, body);
        request.request_digest = request.computed_digest()?;
        request.validate()?;

        let session = sample_session(&ephemeral);
        request.authorization = Some(authorization(
            &ephemeral,
            &session,
            WitnessOperationV1::Commit,
            &"8".repeat(64),
            &request.request_digest,
        )?);
        assert!(request.validate().is_err());
    }
    Ok(())
}

#[test]
fn request_digest_is_length_delimited_domain_hash_of_only_the_contract_preimage()
-> crate::persistence_protocol::ProtocolResult<()> {
    let governance = Ed25519Signer::from_secret_material("service-wire-governance");
    let mut request = request(
        WitnessServiceOperationV1::Fence,
        WitnessServiceRequestBodyV1::Fence {
            request: Box::new(sample_fence(&governance)?),
        },
    );
    let canonical = canonical_wire_bytes(&request.preimage())?;
    let mut material = WITNESS_SERVICE_REQUEST_DOMAIN_V1.to_vec();
    material.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    material.extend_from_slice(&canonical);
    assert_eq!(
        request.computed_digest()?,
        swarm_crypto::sha256_hex(&material)
    );

    request.request_digest = request.computed_digest()?;
    let wire = request.canonical_bytes()?;
    assert_eq!(WitnessServiceRequestV1::decode(&wire)?, request);
    Ok(())
}

#[test]
fn fence_requires_null_authorization_and_validates_nested_governance_signature()
-> crate::persistence_protocol::ProtocolResult<()> {
    let governance = Ed25519Signer::from_secret_material("service-wire-governance");
    let fence = sample_fence(&governance)?;
    let mut service_request = request(
        WitnessServiceOperationV1::Fence,
        WitnessServiceRequestBodyV1::Fence {
            request: Box::new(fence.clone()),
        },
    );
    service_request.request_digest = service_request.computed_digest()?;
    service_request.validate()?;

    let ephemeral = Ed25519Signer::from_secret_material("service-wire-ephemeral");
    let session = sample_session(&ephemeral);
    service_request.authorization = Some(authorization(
        &ephemeral,
        &session,
        WitnessOperationV1::Commit,
        &"8".repeat(64),
        &service_request.request_digest,
    )?);
    assert!(service_request.validate().is_err());

    let mut changed_fence = fence;
    changed_fence.requester_nonce = "f".repeat(64);
    let mut changed = request(
        WitnessServiceOperationV1::Fence,
        WitnessServiceRequestBodyV1::Fence {
            request: Box::new(changed_fence),
        },
    );
    assert!(changed.computed_digest().is_err());
    changed.request_digest = "0".repeat(64);
    assert!(changed.validate().is_err());
    Ok(())
}

#[test]
fn canonical_decoder_rejects_unknown_request_fields()
-> crate::persistence_protocol::ProtocolResult<()> {
    let governance = Ed25519Signer::from_secret_material("service-wire-governance");
    let mut request = request(
        WitnessServiceOperationV1::Fence,
        WitnessServiceRequestBodyV1::Fence {
            request: Box::new(sample_fence(&governance)?),
        },
    );
    request.request_digest = request.computed_digest()?;
    let mut value = serde_json::to_value(&request).map_err(|error| {
        crate::persistence_protocol::ProtocolError::CanonicalEncoding(error.to_string())
    })?;
    let Some(object) = value.as_object_mut() else {
        return Err(crate::persistence_protocol::ProtocolError::WitnessOutcomeMismatch);
    };
    object.insert("subject".to_string(), serde_json::json!("raw.subject"));
    let bytes = serde_json::to_vec(&value).map_err(|error| {
        crate::persistence_protocol::ProtocolError::CanonicalEncoding(error.to_string())
    })?;
    assert!(WitnessServiceRequestV1::decode(&bytes).is_err());
    Ok(())
}

fn request(
    operation: WitnessServiceOperationV1,
    body: WitnessServiceRequestBodyV1,
) -> WitnessServiceRequestV1 {
    WitnessServiceRequestV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        operation,
        request_nonce: "6".repeat(64),
        admission_digest: "7".repeat(64),
        body,
        request_digest: "0".repeat(64),
        authorization: None,
    }
}

fn sample_session(ephemeral: &Ed25519Signer) -> WitnessSessionV1 {
    WitnessSessionV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: "tom-primary".to_string(),
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
        binding_generation: "1".repeat(64),
        binding_digest: "2".repeat(64),
        signer_key_id: "3".repeat(64),
        witness_key_id: "4".repeat(64),
        ephemeral_key_id: ephemeral.key_id().to_string(),
        witness_identity: "witness-1".to_string(),
        session_generation: 1,
        session_commitment: "5".repeat(64),
    }
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

fn authorization(
    signer: &Ed25519Signer,
    session: &WitnessSessionV1,
    operation: WitnessOperationV1,
    txid: &str,
    request_digest: &str,
) -> crate::persistence_protocol::ProtocolResult<WitnessSessionAuthorizationV1> {
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
        signature: signer.sign(&canonical_wire_bytes(&preimage)?),
    })
}

fn sample_fence(
    signer: &Ed25519Signer,
) -> crate::persistence_protocol::ProtocolResult<WitnessSessionFenceRequestV1> {
    sample_fence_for_witness(signer, &"4".repeat(64))
}

fn sample_fence_for_witness(
    signer: &Ed25519Signer,
    witness_key_id: &str,
) -> crate::persistence_protocol::ProtocolResult<WitnessSessionFenceRequestV1> {
    let authority_pair = AuthorityPairIdentityV1 {
        current: ArtifactIdentityV1 {
            device: 1,
            inode: 1,
        },
        legacy: ArtifactIdentityV1 {
            device: 1,
            inode: 1,
        },
    };
    let mut request = WitnessSessionFenceRequestV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: "tom-primary".to_string(),
        authority_pair,
        binding_generation: "1".repeat(64),
        binding_digest: "2".repeat(64),
        signer_key_id: signer.key_id().to_string(),
        witness_key_id: witness_key_id.to_string(),
        witness_identity: "witness-1".to_string(),
        requester_nonce: "5".repeat(64),
        signature: DetachedSignature {
            algorithm: "ed25519".to_string(),
            key_id: signer.key_id().to_string(),
            public_key_hex: signer.public_key_hex().to_string(),
            signature_hex: "00".repeat(64),
        },
    };
    request.signature = signer.sign(&request.signing_bytes()?);
    Ok(request)
}

fn sample_challenge(
    governance: &Ed25519Signer,
    witness: &Ed25519Signer,
    ephemeral: &Ed25519Signer,
) -> crate::persistence_protocol::ProtocolResult<RecoveryChallengeV1> {
    let fence_request = sample_fence_for_witness(governance, witness.key_id())?;
    let mut state_fence = WitnessSessionStateFenceV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        request: fence_request,
        admission_digest: "7".repeat(64),
        bucket_epoch_digest: "8".repeat(64),
        bucket_anchor_digest: "9".repeat(64),
        ready_manifest_digest: "a".repeat(64),
        store_state_digest: "b".repeat(64),
        current_session_generation: None,
        current_session_digest: None,
        current_head_digest: None,
        current_prepared_digest: None,
        witness_nonce: "c".repeat(64),
        witness_identity: "witness-1".to_string(),
        witness_key_id: witness.key_id().to_string(),
        signature: witness.sign(&[]),
    };
    state_fence.signature = witness.sign(&state_fence.signing_bytes()?);
    let mut challenge = RecoveryChallengeV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: "tom-primary".to_string(),
        authority_pair: state_fence.request.authority_pair,
        binding_generation: "1".repeat(64),
        binding_digest: "2".repeat(64),
        signer_key_id: governance.key_id().to_string(),
        witness_key_id: witness.key_id().to_string(),
        witness_identity: "witness-1".to_string(),
        state_fence,
        ephemeral_key_id: ephemeral.key_id().to_string(),
        nonce: "d".repeat(64),
        session_commitment: "e".repeat(64),
        signature: governance.sign(&[]),
    };
    challenge.signature = governance.sign(&challenge.signing_bytes()?);
    Ok(challenge)
}
