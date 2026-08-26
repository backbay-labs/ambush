// Independent service-side candidate admission and pure Prepare transition.

use crate::persistence_protocol::{
    AuthorityPairIdentityV1, CandidateV1, GenesisPredecessorV1, PROTOCOL_SCHEMA_VERSION,
    ProtocolError, ProtocolLimitsV1, ProtocolResult, PublicationMappingV1,
    PublicationRoleIdentitiesV1, VerifiedWitnessOutcomeV1, WitnessAbortOutcomeV1,
    WitnessOperationOutcomeV1, WitnessOperationV1, WitnessOutcomeAttestationV1,
    WitnessPrepareOutcomeV1, WitnessPreparedV1, WitnessSessionAuthorizationV1, WitnessSessionV1,
    canonical_wire_bytes, checked_add_size, checked_next_intent, digest_domain,
};
use crate::witness_engine::store::WitnessAdmissionEntryV1;
use crate::witness_engine::{
    WitnessStoreEnvelopeV1, WitnessStoreExpectationV1, WitnessStoredPreparedV1,
    WitnessStoreTransitionV1, validate_store_transition,
};
use super::{
    WitnessServiceFailureCodeV1, WitnessServiceRequestBodyV1, WitnessServiceRequestV1,
};
use serde::{Deserialize, Serialize};
use swarm_crypto::{DetachedSignature, Ed25519Signer};

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

/// Closed public-Prepare classification. Only `New` carries transition authority,
/// and that value remains non-serializable with no public constructor.
pub enum WitnessPrepareVerificationV1 {
    New(Box<VerifiedCandidateAdmissionV1>),
    AlreadyPrepared(Box<VerifiedPrepareResolutionV1>),
    Conflict(Box<VerifiedPrepareResolutionV1>),
    Rejected(WitnessServiceFailureCodeV1),
}

/// The single public-service Prepare verifier. The dispatcher supplies only
/// an outer-identity-validated request plus independently authenticated store
/// state. This function alone validates the nested Prepare body, session
/// authorization, candidate signatures and transition relations.
#[allow(clippy::too_many_arguments)]
pub fn verify_public_prepare(
    admission_entry: &WitnessAdmissionEntryV1,
    expected_bucket_epoch_digest: &str,
    expected_stream_initialization_digest: &str,
    current_envelope: &WitnessStoreEnvelopeV1,
    request: &WitnessServiceRequestV1,
    witness_signer: &Ed25519Signer,
) -> WitnessPrepareVerificationV1 {
    match verify_public_prepare_inner(
        admission_entry,
        expected_bucket_epoch_digest,
        expected_stream_initialization_digest,
        current_envelope,
        request,
        witness_signer,
    ) {
        Ok(verification) => verification,
        Err(code) => WitnessPrepareVerificationV1::Rejected(code),
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_public_prepare_inner(
    admission_entry: &WitnessAdmissionEntryV1,
    expected_bucket_epoch_digest: &str,
    expected_stream_initialization_digest: &str,
    current_envelope: &WitnessStoreEnvelopeV1,
    request: &WitnessServiceRequestV1,
    witness_signer: &Ed25519Signer,
) -> Result<WitnessPrepareVerificationV1, WitnessServiceFailureCodeV1> {
    request
        .validate_public_dispatch_identity()
        .map_err(|_| WitnessServiceFailureCodeV1::InvalidSignature)?;
    admission_entry
        .validate()
        .map_err(|_| WitnessServiceFailureCodeV1::AdmissionMismatch)?;
    if request.admission_digest != admission_entry.admission_digest {
        return Err(WitnessServiceFailureCodeV1::AdmissionMismatch);
    }
    current_envelope
        .validate_for(WitnessStoreExpectationV1 {
            admission_digest: &admission_entry.admission_digest,
            bucket_epoch_digest: expected_bucket_epoch_digest,
            stream_initialization_digest: expected_stream_initialization_digest,
            stream_id: &admission_entry.stream_id,
            witness_identity: &admission_entry.witness_identity,
            witness_key_id: &admission_entry.witness_key_id,
            authority_pair: admission_entry.authority_pair,
            binding_generation: &admission_entry.binding_generation,
            binding_digest: &admission_entry.binding_digest,
            signer_key_id: &admission_entry.signer_key_id,
        })
        .map_err(|_| WitnessServiceFailureCodeV1::InvalidSignature)?;
    if witness_signer.key_id() != admission_entry.witness_key_id {
        return Err(WitnessServiceFailureCodeV1::AdmissionMismatch);
    }

    let WitnessServiceRequestBodyV1::Prepare {
        session,
        expected_head,
        candidate,
    } = &request.body
    else {
        return Err(WitnessServiceFailureCodeV1::AdmissionMismatch);
    };
    let authorization = request
        .authorization
        .as_ref()
        .ok_or(WitnessServiceFailureCodeV1::InvalidSignature)?;
    session
        .validate()
        .map_err(|_| WitnessServiceFailureCodeV1::InvalidSignature)?;

    let expected = expected_prepare_relations(
        &admission_entry.admission,
        current_envelope,
        expected_head.as_deref(),
    )?;
    let intent_matches = candidate
        .validate_for_expected_intent(expected.intent_counter)
        .map_err(classify_candidate_error)?;

    let binding = &candidate.preimage.publication_binding;
    if candidate.preimage.stream_id != admission_entry.stream_id
        || binding.stream_id != admission_entry.stream_id
        || binding.signer_key_id != admission_entry.signer_key_id
        || binding.witness_identity != admission_entry.witness_identity
        || binding.witness_key_id != admission_entry.witness_key_id
        || binding.generation != admission_entry.binding_generation
        || binding.binding_digest != admission_entry.binding_digest
        || binding.authority_pair != admission_entry.authority_pair
        || binding.publication_roles != admission_entry.publication_roles
        || binding.limits != admission_entry.limits
    {
        return Err(WitnessServiceFailureCodeV1::AdmissionMismatch);
    }

    authorization
        .verify_for_session_record(
            session,
            WitnessOperationV1::Prepare,
            &candidate.txid,
            &request.request_digest,
        )
        .map_err(|_| WitnessServiceFailureCodeV1::InvalidSignature)?;
    if current_envelope.session.as_ref() != Some(session) {
        return Err(WitnessServiceFailureCodeV1::StaleSession);
    }
    if expected_head.as_deref()
        != current_envelope.current.as_ref().map(|stored| &stored.head)
        || candidate.preimage.predecessor_head.as_ref() != expected_head.as_deref()
    {
        return Err(WitnessServiceFailureCodeV1::ExpectedHeadMismatch);
    }
    if candidate.preimage.epoch != expected.epoch
        || candidate.preimage.sequence != expected.sequence
        || candidate.preimage.predecessor_head_digest != expected.predecessor_head_digest
        || candidate.preimage.predecessor_data_head_digest != expected.predecessor_data_head_digest
        || candidate.preimage.publication_mapping_before != expected.publication_mapping
    {
        return Err(WitnessServiceFailureCodeV1::AdmissionMismatch);
    }

    enforce_selected_candidate_bounds(admission_entry, current_envelope, candidate)
        .map_err(|_| WitnessServiceFailureCodeV1::BoundsExceeded)?;
    if !intent_matches {
        return Ok(WitnessPrepareVerificationV1::Rejected(
            WitnessServiceFailureCodeV1::StaleIntent,
        ));
    }

    let stored_genesis_abort = current_envelope.genesis_abort.as_ref().or_else(|| {
        current_envelope
            .prepared
            .as_ref()
            .and_then(|stored| stored.prepared.genesis_abort.as_ref())
    });
    let verified_abort = match stored_genesis_abort {
        Some(expected_abort) => Some(
            verified_stored_genesis_abort(current_envelope, expected_abort, witness_signer)
                .map_err(|_| WitnessServiceFailureCodeV1::InvalidSignature)?,
        ),
        None => None,
    };
    let verified = WitnessCandidateVerifier::verify_prepare(
        &admission_entry.admission,
        current_envelope,
        session,
        authorization,
        expected_head.as_deref(),
        candidate,
        &request.request_digest,
        verified_abort.as_ref(),
    )
    .map_err(classify_transition_error)?;
    let Some(stored) = current_envelope.prepared.as_ref() else {
        return Ok(WitnessPrepareVerificationV1::New(Box::new(verified)));
    };
    let kind = if stored.prepared.head.txid == verified.candidate.txid
        && stored.prepared.head.candidate_digest == verified.candidate.candidate_digest
    {
        VerifiedPrepareResolutionKindV1::AlreadyPrepared
    } else {
        VerifiedPrepareResolutionKindV1::Conflict
    };
    let resolution = VerifiedPrepareResolutionV1 {
        session: verified.session,
        txid: verified.candidate.txid,
        candidate_digest: verified.candidate.candidate_digest,
        store_state_digest: verified.store_state_digest,
        kind,
    };
    Ok(match resolution.kind {
        VerifiedPrepareResolutionKindV1::AlreadyPrepared => {
            WitnessPrepareVerificationV1::AlreadyPrepared(Box::new(resolution))
        }
        VerifiedPrepareResolutionKindV1::Conflict => {
            WitnessPrepareVerificationV1::Conflict(Box::new(resolution))
        }
    })
}

struct ExpectedPrepareRelationsV1 {
    intent_counter: u64,
    epoch: u64,
    sequence: u64,
    predecessor_head_digest: String,
    predecessor_data_head_digest: String,
    publication_mapping: PublicationMappingV1,
}

fn expected_prepare_relations(
    admission: &WitnessAdmissionRecordV1,
    current: &WitnessStoreEnvelopeV1,
    expected_head: Option<&crate::persistence_protocol::WitnessHeadV1>,
) -> Result<ExpectedPrepareRelationsV1, WitnessServiceFailureCodeV1> {
    if expected_head != current.current.as_ref().map(|stored| &stored.head) {
        return Err(WitnessServiceFailureCodeV1::ExpectedHeadMismatch);
    }
    if let Some(stored) = current.prepared.as_ref() {
        if stored.prepared.predecessor_head.as_ref() != expected_head {
            return Err(WitnessServiceFailureCodeV1::AdmissionMismatch);
        }
        return Ok(ExpectedPrepareRelationsV1 {
            intent_counter: stored.candidate.intent_counter,
            epoch: stored.candidate.epoch,
            sequence: stored.candidate.sequence,
            predecessor_head_digest: stored.candidate.predecessor_head_digest.clone(),
            predecessor_data_head_digest: stored.candidate.predecessor_data_head_digest.clone(),
            publication_mapping: stored.candidate.publication_mapping_before,
        });
    }
    if let Some(head) = expected_head {
        return Ok(ExpectedPrepareRelationsV1 {
            intent_counter: checked_next_intent(head.intent_counter)
                .map_err(|_| WitnessServiceFailureCodeV1::BoundsExceeded)?,
            epoch: head.epoch,
            sequence: head
                .sequence
                .checked_add(1)
                .ok_or(WitnessServiceFailureCodeV1::BoundsExceeded)?,
            predecessor_head_digest: head
                .head_digest()
                .map_err(|_| WitnessServiceFailureCodeV1::InvalidSignature)?,
            predecessor_data_head_digest: head
                .data_head_digest()
                .map_err(|_| WitnessServiceFailureCodeV1::InvalidSignature)?,
            publication_mapping: head.publication_mapping,
        });
    }
    if current.current.is_some() {
        return Err(WitnessServiceFailureCodeV1::ExpectedHeadMismatch);
    }

    let genesis = GenesisPredecessorV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: admission.stream_id.clone(),
        binding_generation: admission.binding_generation.clone(),
        binding_digest: admission.binding_digest.clone(),
        signer_key_id: admission.signer_key_id.clone(),
        witness_key_id: admission.witness_key_id.clone(),
        authority_pair: admission.authority_pair,
        epoch: 0,
        sequence: 0,
        intent_counter: 0,
    };
    let expected_mapping = PublicationMappingV1 {
        state_canonical: admission.publication_roles.state_canonical,
        state_staging: admission.publication_roles.state_staging,
        checkpoint_canonical: admission.publication_roles.checkpoint_canonical,
        checkpoint_staging: admission.publication_roles.checkpoint_staging,
        journal_primary: admission.publication_roles.journal_primary,
        journal_secondary: admission.publication_roles.journal_secondary,
    };
    let (intent, predecessor_digest, data_digest, mapping) =
        if let Some(aborted) = current.genesis_abort.as_ref() {
            if aborted.stream_id != admission.stream_id
                || aborted.binding_generation != admission.binding_generation
                || aborted.binding_digest != admission.binding_digest
                || aborted.signer_key_id != admission.signer_key_id
                || aborted.witness_key_id != admission.witness_key_id
                || aborted.authority_pair != admission.authority_pair
                || aborted.predecessor_head_digest
                    != genesis
                        .digest()
                        .map_err(|_| WitnessServiceFailureCodeV1::AdmissionMismatch)?
                || aborted.resulting_data_head_digest
                    != genesis
                        .data_head_digest()
                        .map_err(|_| WitnessServiceFailureCodeV1::AdmissionMismatch)?
                || aborted.publication_mapping != expected_mapping
            {
                return Err(WitnessServiceFailureCodeV1::AdmissionMismatch);
            }
            (
                checked_next_intent(aborted.intent_counter)
                    .map_err(|_| WitnessServiceFailureCodeV1::BoundsExceeded)?,
                aborted.predecessor_head_digest.clone(),
                aborted.resulting_data_head_digest.clone(),
                aborted.publication_mapping,
            )
        } else {
            (
                admission.initial_intent_counter,
                genesis
                    .digest()
                    .map_err(|_| WitnessServiceFailureCodeV1::AdmissionMismatch)?,
                genesis
                    .data_head_digest()
                    .map_err(|_| WitnessServiceFailureCodeV1::AdmissionMismatch)?,
                expected_mapping,
            )
        };
    Ok(ExpectedPrepareRelationsV1 {
        intent_counter: intent,
        epoch: admission.initial_epoch,
        sequence: admission.initial_sequence,
        predecessor_head_digest: predecessor_digest,
        predecessor_data_head_digest: data_digest,
        publication_mapping: mapping,
    })
}

fn verified_stored_genesis_abort(
    current: &WitnessStoreEnvelopeV1,
    expected_abort: &crate::persistence_protocol::WitnessGenesisAbortedV1,
    witness_signer: &Ed25519Signer,
) -> ProtocolResult<VerifiedWitnessOutcomeV1> {
    let session = current
        .session
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    let outcome = WitnessOperationOutcomeV1::Abort(Box::new(
        WitnessAbortOutcomeV1::GenesisAborted(expected_abort.clone()),
    ));
    let mut attestation = WitnessOutcomeAttestationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        operation: WitnessOperationV1::Abort,
        stream_id: session.stream_id.clone(),
        binding_generation: session.binding_generation.clone(),
        binding_digest: session.binding_digest.clone(),
        signer_key_id: session.signer_key_id.clone(),
        authority_pair: session.authority_pair,
        txid: expected_abort.txid.clone(),
        candidate_digest: expected_abort.candidate_digest.clone(),
        session_generation: session.session_generation,
        session_commitment: session.session_commitment.clone(),
        witness_key_id: session.witness_key_id.clone(),
        outcome,
        signature: witness_signer.sign(&[]),
    };
    attestation.signature = witness_signer.sign(&attestation.signing_bytes()?);
    VerifiedWitnessOutcomeV1::from_authenticated_store_genesis_abort(
        attestation,
        session,
        expected_abort,
    )
}

fn enforce_selected_candidate_bounds(
    admission: &WitnessAdmissionEntryV1,
    envelope: &WitnessStoreEnvelopeV1,
    candidate: &CandidateV1,
) -> ProtocolResult<()> {
    let binding_bytes = canonical_wire_bytes(&candidate.preimage.publication_binding)?.len() as u64;
    if candidate.preimage.state_byte_len > admission.max_state_bytes
        || candidate.preimage.checkpoint_byte_len > admission.max_checkpoint_bytes
        || binding_bytes > admission.max_binding_bytes
    {
        return Err(ProtocolError::Bounds {
            field: "selected_admission_candidate".to_string(),
            observed: usize::try_from(
                candidate
                    .preimage
                    .state_byte_len
                    .max(candidate.preimage.checkpoint_byte_len)
                    .max(binding_bytes),
            )
            .unwrap_or(usize::MAX),
            maximum: usize::try_from(
                admission
                    .max_state_bytes
                    .max(admission.max_checkpoint_bytes)
                    .max(admission.max_binding_bytes),
            )
            .unwrap_or(usize::MAX),
        });
    }
    enforce_retained_bound(&admission.admission, envelope, candidate)
}

fn classify_candidate_error(error: ProtocolError) -> WitnessServiceFailureCodeV1 {
    match error {
        ProtocolError::Bounds { .. } | ProtocolError::Overflow { .. } => {
            WitnessServiceFailureCodeV1::BoundsExceeded
        }
        ProtocolError::AuthorityPairMismatch
        | ProtocolError::RoleIdentityAlias { .. }
        | ProtocolError::InvalidField { .. } => WitnessServiceFailureCodeV1::AdmissionMismatch,
        _ => WitnessServiceFailureCodeV1::InvalidSignature,
    }
}

fn classify_transition_error(error: ProtocolError) -> WitnessServiceFailureCodeV1 {
    match error {
        ProtocolError::Bounds { .. } | ProtocolError::Overflow { .. } => {
            WitnessServiceFailureCodeV1::BoundsExceeded
        }
        _ => WitnessServiceFailureCodeV1::StoreTransitionRefused,
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

#[derive(Clone, Copy)]
enum VerifiedPrepareResolutionKindV1 {
    AlreadyPrepared,
    Conflict,
}

/// Opaque result of complete Prepare verification against an authenticated
/// store that already contains a live successor. It can only be consumed
/// against the exact store-state digest that authorized its classification.
pub struct VerifiedPrepareResolutionV1 {
    session: WitnessSessionV1,
    txid: String,
    candidate_digest: String,
    store_state_digest: String,
    kind: VerifiedPrepareResolutionKindV1,
}

impl VerifiedPrepareResolutionV1 {
    pub fn into_outcome_for_store(
        self,
        current: &WitnessStoreEnvelopeV1,
    ) -> ProtocolResult<(
        WitnessSessionV1,
        String,
        String,
        WitnessPrepareOutcomeV1,
    )> {
        current.validate()?;
        if current.store_state_digest()? != self.store_state_digest {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let stored = current
            .prepared
            .as_ref()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        let same = stored.prepared.head.txid == self.txid
            && stored.prepared.head.candidate_digest == self.candidate_digest;
        let outcome = match self.kind {
            VerifiedPrepareResolutionKindV1::AlreadyPrepared if same => {
                WitnessPrepareOutcomeV1::AlreadyPrepared(stored.prepared.clone())
            }
            VerifiedPrepareResolutionKindV1::Conflict if !same => {
                WitnessPrepareOutcomeV1::Conflict
            }
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        };
        Ok((self.session, self.txid, self.candidate_digest, outcome))
    }
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

        let authenticated_genesis_abort = current_envelope.genesis_abort.as_ref().or_else(|| {
            current_envelope
                .prepared
                .as_ref()
                .and_then(|stored| stored.prepared.genesis_abort.as_ref())
        });
        let prepared = match (authenticated_genesis_abort, genesis_abort_outcome) {
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
