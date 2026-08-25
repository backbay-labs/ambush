// Independent service-side candidate admission and pure Prepare transition.

use crate::persistence_protocol::{
    AuthorityPairIdentityV1, CandidateV1, PROTOCOL_SCHEMA_VERSION, ProtocolError, ProtocolLimitsV1,
    ProtocolResult, PublicationRoleIdentitiesV1, VerifiedWitnessOutcomeV1, WitnessOperationV1,
    WitnessPreparedV1, WitnessSessionAuthorizationV1, WitnessSessionV1, canonical_wire_bytes,
    checked_add_size, digest_domain,
};
use crate::witness_engine::{
    WitnessStoreEnvelopeV1, WitnessStoreExpectationV1, WitnessStoredPreparedV1,
    WitnessStoreTransitionV1, validate_store_transition,
};
use serde::{Deserialize, Serialize};
use swarm_crypto::DetachedSignature;

pub const WITNESS_ADMISSION_DOMAIN_V1: &[u8] = b"swarm.governance.witness-admission.v1";

/// Deployment-authorized namespace and resource ceiling. The admission digest
/// covers every authority and limit field and is recomputed service-side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAdmissionRecordV1 {
    pub schema_version: u32,
    pub stream_id: String,
    pub signer_key_id: String,
    pub witness_identity: String,
    pub witness_key_id: String,
    pub binding_generation: String,
    pub binding_digest: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub publication_roles: PublicationRoleIdentitiesV1,
    pub limits: ProtocolLimitsV1,
    pub max_retained_bytes: u64,
    pub initial_epoch: u64,
    pub initial_sequence: u64,
    pub initial_intent_counter: u64,
    pub admission_digest: String,
}

#[derive(Serialize)]
struct WitnessAdmissionPreimageV1<'a> {
    schema_version: u32,
    stream_id: &'a str,
    signer_key_id: &'a str,
    witness_identity: &'a str,
    witness_key_id: &'a str,
    binding_generation: &'a str,
    binding_digest: &'a str,
    authority_pair: AuthorityPairIdentityV1,
    publication_roles: PublicationRoleIdentitiesV1,
    limits: ProtocolLimitsV1,
    max_retained_bytes: u64,
    initial_epoch: u64,
    initial_sequence: u64,
    initial_intent_counter: u64,
}

impl WitnessAdmissionRecordV1 {
    fn preimage(&self) -> WitnessAdmissionPreimageV1<'_> {
        WitnessAdmissionPreimageV1 {
            schema_version: self.schema_version,
            stream_id: &self.stream_id,
            signer_key_id: &self.signer_key_id,
            witness_identity: &self.witness_identity,
            witness_key_id: &self.witness_key_id,
            binding_generation: &self.binding_generation,
            binding_digest: &self.binding_digest,
            authority_pair: self.authority_pair,
            publication_roles: self.publication_roles,
            limits: self.limits,
            max_retained_bytes: self.max_retained_bytes,
            initial_epoch: self.initial_epoch,
            initial_sequence: self.initial_sequence,
            initial_intent_counter: self.initial_intent_counter,
        }
    }

    pub fn computed_digest(&self) -> ProtocolResult<String> {
        digest_domain(
            WITNESS_ADMISSION_DOMAIN_V1,
            &canonical_wire_bytes(&self.preimage())?,
        )
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_nonempty("stream_id", &self.stream_id)?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        validate_nonempty("witness_identity", &self.witness_identity)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        self.authority_pair.validate()?;
        self.publication_roles.validate()?;
        self.limits.validate()?;
        if self.max_retained_bytes == 0 || self.initial_intent_counter == 0 {
            return Err(invalid(
                "admission",
                "retention and the admitted initial intent must be nonzero",
            ));
        }
        validate_digest("admission_digest", &self.admission_digest)?;
        if self.admission_digest != self.computed_digest()? {
            return Err(ProtocolError::DigestMismatch {
                field: "admission_digest",
            });
        }
        Ok(())
    }
}

/// Non-forgeable result of complete candidate admission. It is neither
/// serializable nor cloneable and has no public constructor.
pub struct VerifiedCandidateAdmissionV1 {
    admission: WitnessAdmissionRecordV1,
    candidate: CandidateV1,
    session: WitnessSessionV1,
    prepared: WitnessPreparedV1,
    store_state_digest: String,
}

impl VerifiedCandidateAdmissionV1 {
    pub fn admission(&self) -> &WitnessAdmissionRecordV1 {
        &self.admission
    }

    pub fn candidate(&self) -> &CandidateV1 {
        &self.candidate
    }

    pub fn session(&self) -> &WitnessSessionV1 {
        &self.session
    }
}

pub struct WitnessCandidateVerifier;

impl WitnessCandidateVerifier {
    #[allow(clippy::too_many_arguments)]
    pub fn verify_prepare(
        admission: &WitnessAdmissionRecordV1,
        current_envelope: &WitnessStoreEnvelopeV1,
        session: &WitnessSessionV1,
        authorization: &WitnessSessionAuthorizationV1,
        expected_head: Option<&crate::persistence_protocol::WitnessHeadV1>,
        candidate: &CandidateV1,
        request_digest: &str,
        genesis_abort_outcome: Option<&VerifiedWitnessOutcomeV1>,
    ) -> ProtocolResult<VerifiedCandidateAdmissionV1> {
        admission.validate()?;
        validate_digest("request_digest", request_digest)?;
        session.validate()?;
        current_envelope.validate_for(store_expectation(admission, current_envelope))?;

        // Decode from complete canonical bytes instead of accepting a client
        // boolean or a previously computed digest as proof of validity.
        let candidate_bytes = canonical_wire_bytes(candidate)?;
        let decoded = CandidateV1::decode(&candidate_bytes)?;
        if &decoded != candidate {
            return Err(ProtocolError::NonCanonicalEncoding);
        }
        candidate.validate()?;

        let binding = &candidate.preimage.publication_binding;
        if candidate.preimage.stream_id != admission.stream_id
            || binding.stream_id != admission.stream_id
            || binding.signer_key_id != admission.signer_key_id
            || binding.witness_identity != admission.witness_identity
            || binding.witness_key_id != admission.witness_key_id
            || binding.generation != admission.binding_generation
            || binding.binding_digest != admission.binding_digest
            || binding.authority_pair != admission.authority_pair
            || binding.publication_roles != admission.publication_roles
            || binding.limits != admission.limits
            || current_envelope.admission_digest != admission.admission_digest
            || session.stream_id != admission.stream_id
            || session.signer_key_id != admission.signer_key_id
            || session.witness_identity != admission.witness_identity
            || session.witness_key_id != admission.witness_key_id
            || session.binding_generation != admission.binding_generation
            || session.binding_digest != admission.binding_digest
            || session.authority_pair != admission.authority_pair
            || current_envelope.session.as_ref() != Some(session)
            || expected_head != current_envelope.current.as_ref().map(|stored| &stored.head)
            || candidate.preimage.predecessor_head.as_ref() != expected_head
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }

        let prepared = match (
            current_envelope.genesis_abort.as_ref(),
            genesis_abort_outcome,
        ) {
            (None, None) => {
                if expected_head.is_none()
                    && (candidate.preimage.epoch != admission.initial_epoch
                        || candidate.preimage.sequence != admission.initial_sequence
                        || candidate.preimage.intent_counter != admission.initial_intent_counter)
                {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
                WitnessPreparedV1::from_candidate(
                    candidate,
                    expected_head.cloned(),
                    session.session_generation,
                )?
            }
            (Some(expected_abort), Some(verified_abort)) if expected_head.is_none() => {
                let prepared = WitnessPreparedV1::from_candidate_after_genesis_abort(
                    candidate,
                    verified_abort,
                    session.session_generation,
                )?;
                if prepared.genesis_abort.as_ref() != Some(expected_abort) {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
                prepared
            }
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        };

        authorization.verify_for_session_record(
            session,
            WitnessOperationV1::Prepare,
            &candidate.txid,
            request_digest,
        )?;

        enforce_retained_bound(admission, current_envelope, candidate)?;
        let store_state_digest = current_envelope.store_state_digest()?;
        Ok(VerifiedCandidateAdmissionV1 {
            admission: admission.clone(),
            candidate: candidate.clone(),
            session: session.clone(),
            prepared,
            store_state_digest,
        })
    }
}

/// Pure, unsigned one-step transition. The witness signs its exposed preimage
/// only after this value is built; `seal` then validates the exact transition.
pub struct VerifiedPrepareTransitionV1 {
    previous: WitnessStoreEnvelopeV1,
    proposed: WitnessStoreEnvelopeV1,
    admission: WitnessAdmissionRecordV1,
}

impl VerifiedPrepareTransitionV1 {
    pub fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.proposed.signing_bytes()
    }

    pub fn seal(
        self,
        witness_signature: DetachedSignature,
    ) -> ProtocolResult<WitnessStoreEnvelopeV1> {
        let proposed = self.proposed.seal_with_signature(witness_signature)?;
        let transition = validate_store_transition(
            &self.previous,
            &proposed,
            store_expectation(&self.admission, &self.previous),
        )?;
        if transition != WitnessStoreTransitionV1::Prepare {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(proposed)
    }
}

/// The service preparation seam accepts only the verifier result. A raw
/// `CandidateV1`, proposed envelope, request digest, or acknowledgement cannot
/// enter this adapter.
pub fn prepare_verified_candidate(
    current_envelope: &WitnessStoreEnvelopeV1,
    verified: VerifiedCandidateAdmissionV1,
) -> ProtocolResult<VerifiedPrepareTransitionV1> {
    current_envelope.validate_for(store_expectation(&verified.admission, current_envelope))?;
    if current_envelope.store_state_digest()? != verified.store_state_digest {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    let mut proposed = current_envelope.clone();
    proposed.prepared = Some(WitnessStoredPreparedV1 {
        candidate: verified.candidate.preimage,
        prepared: verified.prepared,
    });
    proposed.genesis_abort = None;
    proposed.store_generation = proposed
        .store_generation
        .checked_add(1)
        .ok_or(ProtocolError::Overflow {
            counter: "store_generation",
        })?;
    // The outer signature is excluded from the signing preimage and is
    // replaced by `seal`; retaining the old bytes here cannot authorize it.
    proposed.signing_bytes()?;
    Ok(VerifiedPrepareTransitionV1 {
        previous: current_envelope.clone(),
        proposed,
        admission: verified.admission,
    })
}

fn store_expectation<'a>(
    admission: &'a WitnessAdmissionRecordV1,
    envelope: &'a WitnessStoreEnvelopeV1,
) -> WitnessStoreExpectationV1<'a> {
    WitnessStoreExpectationV1 {
        admission_digest: &admission.admission_digest,
        bucket_epoch_digest: &envelope.bucket_epoch_digest,
        stream_initialization_digest: &envelope.stream_initialization_digest,
        stream_id: &admission.stream_id,
        witness_identity: &admission.witness_identity,
        witness_key_id: &admission.witness_key_id,
        authority_pair: admission.authority_pair,
        binding_generation: &admission.binding_generation,
        binding_digest: &admission.binding_digest,
        signer_key_id: &admission.signer_key_id,
    }
}

fn enforce_retained_bound(
    admission: &WitnessAdmissionRecordV1,
    envelope: &WitnessStoreEnvelopeV1,
    candidate: &CandidateV1,
) -> ProtocolResult<()> {
    let mut total = checked_add_size(
        candidate.preimage.state_byte_len,
        candidate.preimage.checkpoint_byte_len,
    )?;
    for retained in [
        envelope.current.as_ref().map(|value| &value.candidate),
        envelope.predecessor.as_ref().map(|value| &value.candidate),
        envelope.prepared.as_ref().map(|value| &value.candidate),
    ]
    .into_iter()
    .flatten()
    {
        total = checked_add_size(total, retained.state_byte_len)?;
        total = checked_add_size(total, retained.checkpoint_byte_len)?;
    }
    if total > admission.max_retained_bytes {
        return Err(ProtocolError::Bounds {
            field: "retained_payload_bytes".to_string(),
            observed: usize::try_from(total).unwrap_or(usize::MAX),
            maximum: usize::try_from(admission.max_retained_bytes).unwrap_or(usize::MAX),
        });
    }
    Ok(())
}

fn validate_nonempty(field: &'static str, value: &str) -> ProtocolResult<()> {
    if value.is_empty() || value.len() > crate::persistence_protocol::MAX_PROTOCOL_STRING_BYTES {
        return Err(invalid(field, "must be nonempty and bounded"));
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> ProtocolResult<()> {
    validate_nonempty(field, value)?;
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(invalid(
            field,
            "must be a lowercase hexadecimal SHA-256 digest",
        ));
    }
    Ok(())
}

fn invalid(field: &'static str, reason: &'static str) -> ProtocolError {
    ProtocolError::InvalidField {
        field: field.to_string(),
        reason: reason.to_string(),
    }
}
