//! Pure authenticated witness-store state and transition model.
//!
//! This module owns no transport or storage handle. It defines the bounded
//! signed value stored for one admitted stream and the exact legal one-step
//! mutations that a later CAS adapter may accept.

use crate::persistence_protocol::{
    AuthorityPairIdentityV1, CandidatePreimageV1, MAX_PROTOCOL_RECORD_BYTES,
    MAX_PROTOCOL_STRING_BYTES, PROTOCOL_SCHEMA_VERSION, ProtocolError, ProtocolResult,
    TxidPreimageV1, WitnessAbortSummaryV1, WitnessGenesisAbortedV1, WitnessHeadV1,
    WitnessIntentOutcomeV1, WitnessPreparedV1, WitnessSessionRotationReceiptV1,
    WitnessSessionRotationResponseKindV1, WitnessSessionV1, canonical_wire_bytes,
    checked_next_sequence, decode_canonical, digest_domain,
};
use serde::{Deserialize, Serialize};
use swarm_crypto::{DetachedSignature, PublicKey, sha256_hex, verify_detached_signature};

pub const WITNESS_STORE_DOMAIN_V1: &[u8] = b"swarm.governance.witness-store.v1";
pub const WITNESS_STORE_SIGNED_DOMAIN_V1: &[u8] = b"swarm.governance.witness-store-signed.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStoredCandidateV1 {
    pub candidate: CandidatePreimageV1,
    pub head: WitnessHeadV1,
}

impl WitnessStoredCandidateV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        let candidate = self.candidate.build()?;
        self.head.validate_settled()?;

        let mut expected = WitnessHeadV1::from_candidate(&candidate)?;
        expected.intent_counter = self.head.intent_counter;
        expected.last_intent_outcome = self.head.last_intent_outcome.clone();
        if expected != self.head {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }

        match self.head.last_intent_outcome.as_ref() {
            Some(WitnessIntentOutcomeV1::Committed { .. }) => {
                if self.head != WitnessHeadV1::committed_from_candidate(&candidate)? {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            }
            Some(WitnessIntentOutcomeV1::Aborted(summary))
                if self.head.intent_counter > self.candidate.intent_counter =>
            {
                validate_retained_abort_identity(&self.candidate, &self.head, summary)?;
            }
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStoredPreparedV1 {
    pub candidate: CandidatePreimageV1,
    pub prepared: WitnessPreparedV1,
}

impl WitnessStoredPreparedV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        let candidate = self.candidate.build()?;
        self.prepared.validate()?;
        if self.prepared.head != WitnessHeadV1::from_candidate(&candidate)?
            || self.prepared.predecessor_head != self.candidate.predecessor_head
            || self.prepared.predecessor_head_digest != self.candidate.predecessor_head_digest
            || self.prepared.predecessor_data_head_digest
                != self.candidate.predecessor_data_head_digest
            || self.prepared.binding_digest != self.candidate.publication_binding.binding_digest
            || self.prepared.predecessor_publication_mapping
                != self.candidate.publication_mapping_before
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        if let Some(aborted) = &self.prepared.genesis_abort {
            // This receipt belongs to the immediately prior aborted prepare,
            // not the live prepare. `WitnessPreparedV1::validate` binds it as
            // the exact predecessor and requires the live next intent.
            validate_genesis_abort_identity(aborted)?;
            if aborted.txid == candidate.txid
                || aborted.candidate_digest == candidate.candidate_digest
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStoreEnvelopeV1 {
    pub schema_version: u32,
    pub admission_digest: String,
    pub bucket_epoch_digest: String,
    pub stream_initialization_digest: String,
    pub stream_id: String,
    pub witness_identity: String,
    pub witness_key_id: String,
    pub session: Option<WitnessSessionV1>,
    pub last_session_rotation: Option<WitnessSessionRotationReceiptV1>,
    pub current: Option<WitnessStoredCandidateV1>,
    pub predecessor: Option<WitnessStoredCandidateV1>,
    pub prepared: Option<WitnessStoredPreparedV1>,
    pub genesis_abort: Option<WitnessGenesisAbortedV1>,
    pub store_generation: u64,
    pub signature: DetachedSignature,
}

#[derive(Serialize)]
struct WitnessStoreEnvelopePreimageV1<'a> {
    schema_version: u32,
    admission_digest: &'a str,
    bucket_epoch_digest: &'a str,
    stream_initialization_digest: &'a str,
    stream_id: &'a str,
    witness_identity: &'a str,
    witness_key_id: &'a str,
    session: &'a Option<WitnessSessionV1>,
    last_session_rotation: &'a Option<WitnessSessionRotationReceiptV1>,
    current: &'a Option<WitnessStoredCandidateV1>,
    predecessor: &'a Option<WitnessStoredCandidateV1>,
    prepared: &'a Option<WitnessStoredPreparedV1>,
    genesis_abort: &'a Option<WitnessGenesisAbortedV1>,
    store_generation: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct WitnessStoreExpectationV1<'a> {
    pub admission_digest: &'a str,
    pub bucket_epoch_digest: &'a str,
    pub stream_initialization_digest: &'a str,
    pub stream_id: &'a str,
    pub witness_identity: &'a str,
    pub witness_key_id: &'a str,
    pub authority_pair: AuthorityPairIdentityV1,
    pub binding_generation: &'a str,
    pub binding_digest: &'a str,
    pub signer_key_id: &'a str,
}

impl WitnessStoreEnvelopeV1 {
    fn preimage(&self) -> WitnessStoreEnvelopePreimageV1<'_> {
        WitnessStoreEnvelopePreimageV1 {
            schema_version: self.schema_version,
            admission_digest: &self.admission_digest,
            bucket_epoch_digest: &self.bucket_epoch_digest,
            stream_initialization_digest: &self.stream_initialization_digest,
            stream_id: &self.stream_id,
            witness_identity: &self.witness_identity,
            witness_key_id: &self.witness_key_id,
            session: &self.session,
            last_session_rotation: &self.last_session_rotation,
            current: &self.current,
            predecessor: &self.predecessor,
            prepared: &self.prepared,
            genesis_abort: &self.genesis_abort,
            store_generation: self.store_generation,
        }
    }

    fn validate_contents(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_digest("admission_digest", &self.admission_digest)?;
        validate_digest("bucket_epoch_digest", &self.bucket_epoch_digest)?;
        validate_digest(
            "stream_initialization_digest",
            &self.stream_initialization_digest,
        )?;
        validate_string("stream_id", &self.stream_id)?;
        validate_string("witness_identity", &self.witness_identity)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;

        let has_runtime_state = self.session.is_some()
            || self.last_session_rotation.is_some()
            || self.current.is_some()
            || self.predecessor.is_some()
            || self.prepared.is_some()
            || self.genesis_abort.is_some();
        if (self.store_generation == 0) != !has_runtime_state {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }

        match (&self.session, &self.last_session_rotation) {
            (None, None) => {}
            (Some(session), Some(receipt)) => {
                session.validate()?;
                receipt.validate()?;
                if &receipt.session != session {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            }
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        }

        if let Some(current) = &self.current {
            current.validate()?;
        }
        if let Some(predecessor) = &self.predecessor {
            predecessor.validate()?;
        }
        if let Some(prepared) = &self.prepared {
            prepared.validate()?;
        }
        if let Some(aborted) = &self.genesis_abort {
            aborted.validate()?;
            validate_genesis_abort_identity(aborted)?;
        }

        self.validate_payload_cardinality()?;
        self.validate_namespace()?;
        canonical_wire_bytes(&self.preimage()).map(|_| ())
    }

    fn validate_payload_cardinality(&self) -> ProtocolResult<()> {
        match (&self.current, &self.predecessor) {
            (None, None) => {}
            (Some(current), None) if current.candidate.predecessor_head.is_none() => {}
            (Some(current), Some(predecessor))
                if current.candidate.predecessor_head.as_ref() == Some(&predecessor.head) => {}
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        }

        if let Some(prepared) = &self.prepared {
            let session = self
                .session
                .as_ref()
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            if prepared.prepared.session_generation != session.session_generation
                || prepared.prepared.predecessor_head
                    != self.current.as_ref().map(|current| current.head.clone())
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }

        if self.genesis_abort.is_some()
            && (self.current.is_some() || self.predecessor.is_some() || self.prepared.is_some())
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    fn validate_namespace(&self) -> ProtocolResult<()> {
        for candidate in [
            self.current.as_ref().map(|stored| &stored.candidate),
            self.predecessor.as_ref().map(|stored| &stored.candidate),
            self.prepared.as_ref().map(|stored| &stored.candidate),
        ]
        .into_iter()
        .flatten()
        {
            let binding = &candidate.publication_binding;
            if candidate.stream_id != self.stream_id
                || binding.stream_id != self.stream_id
                || binding.witness_identity != self.witness_identity
                || binding.witness_key_id != self.witness_key_id
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }

        if let Some(aborted) = &self.genesis_abort
            && (aborted.stream_id != self.stream_id
                || aborted.witness_key_id != self.witness_key_id)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }

        if let Some(session) = &self.session {
            if session.stream_id != self.stream_id
                || session.witness_identity != self.witness_identity
                || session.witness_key_id != self.witness_key_id
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
            if let Some(candidate) = self
                .current
                .as_ref()
                .map(|stored| &stored.candidate)
                .or_else(|| self.prepared.as_ref().map(|stored| &stored.candidate))
                .or_else(|| self.predecessor.as_ref().map(|stored| &stored.candidate))
            {
                let binding = &candidate.publication_binding;
                if session.authority_pair != binding.authority_pair
                    || session.binding_generation != binding.generation
                    || session.binding_digest != binding.binding_digest
                    || session.signer_key_id != binding.signer_key_id
                {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            } else if let Some(aborted) = &self.genesis_abort
                && (session.authority_pair != aborted.authority_pair
                    || session.binding_generation != aborted.binding_generation
                    || session.binding_digest != aborted.binding_digest
                    || session.signer_key_id != aborted.signer_key_id)
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate_contents()?;
        let canonical = canonical_wire_bytes(&self.preimage())?;
        domain_separated_bytes(WITNESS_STORE_SIGNED_DOMAIN_V1, &canonical)
    }

    pub fn store_state_digest(&self) -> ProtocolResult<String> {
        self.validate_contents()?;
        digest_domain(
            WITNESS_STORE_DOMAIN_V1,
            &canonical_wire_bytes(&self.preimage())?,
        )
    }

    pub fn signed_envelope_digest(&self) -> ProtocolResult<String> {
        self.validate()?;
        digest_domain(WITNESS_STORE_SIGNED_DOMAIN_V1, &canonical_wire_bytes(self)?)
    }

    pub fn seal_with_signature(mut self, signature: DetachedSignature) -> ProtocolResult<Self> {
        self.signature = signature;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        self.validate_contents()?;
        if self.signature.algorithm != "ed25519"
            || self.signature.key_id != self.witness_key_id
            || !PublicKey::from_hex(&self.signature.public_key_hex)
                .map(|key| sha256_hex(key.as_bytes()) == self.witness_key_id)
                .unwrap_or(false)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        verify_detached_signature(&self.signing_bytes()?, &self.signature)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)
    }

    pub fn validate_for(&self, expected: WitnessStoreExpectationV1<'_>) -> ProtocolResult<()> {
        self.validate()?;
        validate_digest("expected_admission_digest", expected.admission_digest)?;
        validate_digest("expected_bucket_epoch_digest", expected.bucket_epoch_digest)?;
        validate_digest(
            "expected_stream_initialization_digest",
            expected.stream_initialization_digest,
        )?;
        validate_string("expected_stream_id", expected.stream_id)?;
        validate_string("expected_witness_identity", expected.witness_identity)?;
        validate_digest("expected_witness_key_id", expected.witness_key_id)?;
        expected.authority_pair.validate()?;
        validate_digest("expected_binding_generation", expected.binding_generation)?;
        validate_digest("expected_binding_digest", expected.binding_digest)?;
        validate_digest("expected_signer_key_id", expected.signer_key_id)?;
        if self.admission_digest != expected.admission_digest
            || self.bucket_epoch_digest != expected.bucket_epoch_digest
            || self.stream_initialization_digest != expected.stream_initialization_digest
            || self.stream_id != expected.stream_id
            || self.witness_identity != expected.witness_identity
            || self.witness_key_id != expected.witness_key_id
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        self.validate_admitted_authority(expected)?;
        Ok(())
    }

    fn validate_admitted_authority(
        &self,
        expected: WitnessStoreExpectationV1<'_>,
    ) -> ProtocolResult<()> {
        for candidate in [
            self.current.as_ref().map(|stored| &stored.candidate),
            self.predecessor.as_ref().map(|stored| &stored.candidate),
            self.prepared.as_ref().map(|stored| &stored.candidate),
        ]
        .into_iter()
        .flatten()
        {
            let binding = &candidate.publication_binding;
            if binding.authority_pair != expected.authority_pair
                || binding.generation != expected.binding_generation
                || binding.binding_digest != expected.binding_digest
                || binding.signer_key_id != expected.signer_key_id
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
        if let Some(session) = &self.session
            && (session.authority_pair != expected.authority_pair
                || session.binding_generation != expected.binding_generation
                || session.binding_digest != expected.binding_digest
                || session.signer_key_id != expected.signer_key_id)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        if let Some(aborted) = &self.genesis_abort
            && (aborted.authority_pair != expected.authority_pair
                || aborted.binding_generation != expected.binding_generation
                || aborted.binding_digest != expected.binding_digest
                || aborted.signer_key_id != expected.signer_key_id)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        canonical_wire_bytes(self)
    }

    pub fn decode(bytes: &[u8]) -> ProtocolResult<Self> {
        let envelope = decode_canonical::<Self>(bytes)?;
        envelope.validate()?;
        Ok(envelope)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessStoreTransitionV1 {
    RotateSession,
    Prepare,
    Commit,
    Abort,
}

pub fn validate_store_transition(
    previous: &WitnessStoreEnvelopeV1,
    proposed: &WitnessStoreEnvelopeV1,
    expected: WitnessStoreExpectationV1<'_>,
) -> ProtocolResult<WitnessStoreTransitionV1> {
    previous.validate_for(expected)?;
    proposed.validate_for(expected)?;
    validate_immutable_namespace(previous, proposed)?;
    if proposed.store_generation
        != previous
            .store_generation
            .checked_add(1)
            .ok_or(ProtocolError::Overflow {
                counter: "store_generation",
            })?
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }

    if is_session_rotation(previous, proposed)? {
        return Ok(WitnessStoreTransitionV1::RotateSession);
    }
    if is_prepare(previous, proposed) {
        return Ok(WitnessStoreTransitionV1::Prepare);
    }
    if is_commit(previous, proposed)? {
        return Ok(WitnessStoreTransitionV1::Commit);
    }
    if is_abort(previous, proposed)? {
        return Ok(WitnessStoreTransitionV1::Abort);
    }
    Err(ProtocolError::WitnessOutcomeMismatch)
}

pub fn witness_stream_key(stream_id: &str) -> ProtocolResult<String> {
    validate_string("stream_id", stream_id)?;
    let capacity = WITNESS_STORE_DOMAIN_V1
        .len()
        .checked_add(stream_id.len())
        .ok_or(ProtocolError::Overflow {
            counter: "stream_key_size",
        })?;
    let mut material = Vec::with_capacity(capacity);
    material.extend_from_slice(WITNESS_STORE_DOMAIN_V1);
    material.extend_from_slice(stream_id.as_bytes());
    Ok(format!("s.{}", sha256_hex(&material)))
}

fn validate_immutable_namespace(
    previous: &WitnessStoreEnvelopeV1,
    proposed: &WitnessStoreEnvelopeV1,
) -> ProtocolResult<()> {
    if previous.schema_version != proposed.schema_version
        || previous.admission_digest != proposed.admission_digest
        || previous.bucket_epoch_digest != proposed.bucket_epoch_digest
        || previous.stream_initialization_digest != proposed.stream_initialization_digest
        || previous.stream_id != proposed.stream_id
        || previous.witness_identity != proposed.witness_identity
        || previous.witness_key_id != proposed.witness_key_id
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    Ok(())
}

fn is_session_rotation(
    previous: &WitnessStoreEnvelopeV1,
    proposed: &WitnessStoreEnvelopeV1,
) -> ProtocolResult<bool> {
    if previous.current != proposed.current
        || previous.predecessor != proposed.predecessor
        || previous.genesis_abort != proposed.genesis_abort
    {
        return Ok(false);
    }
    let session = match &proposed.session {
        Some(session) => session,
        None => return Ok(false),
    };
    let expected_generation = previous
        .session
        .as_ref()
        .map_or(0, |session| session.session_generation)
        .checked_add(1)
        .ok_or(ProtocolError::Overflow {
            counter: "session_generation",
        })?;
    if session.session_generation != expected_generation
        || previous.session.as_ref() == Some(session)
        || proposed.last_session_rotation == previous.last_session_rotation
    {
        return Ok(false);
    }

    match (&previous.prepared, &proposed.prepared) {
        (None, None) => {}
        (Some(old), Some(new)) => {
            let mut expected = old.clone();
            expected.prepared.session_generation = expected_generation;
            if &expected != new {
                return Ok(false);
            }
        }
        _ => return Ok(false),
    }

    validate_rotation_snapshot(proposed)?;
    Ok(true)
}

fn validate_rotation_snapshot(proposed: &WitnessStoreEnvelopeV1) -> ProtocolResult<()> {
    let receipt = proposed
        .last_session_rotation
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    match receipt.response_kind {
        WitnessSessionRotationResponseKindV1::Establish => {
            let snapshot = receipt
                .establish_snapshot
                .as_ref()
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            if proposed.prepared.is_some()
                || snapshot.committed_head
                    != proposed
                        .current
                        .as_ref()
                        .map(|current| current.head.clone())
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
        WitnessSessionRotationResponseKindV1::Discover => {
            let snapshot = receipt
                .discovery_snapshot
                .as_ref()
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            if snapshot.head
                != proposed
                    .current
                    .as_ref()
                    .map(|current| current.head.clone())
                || snapshot.prepared
                    != proposed
                        .prepared
                        .as_ref()
                        .map(|prepared| prepared.prepared.clone())
                || snapshot.genesis_abort != proposed.genesis_abort
                || Some(&snapshot.recovery_session) != proposed.session.as_ref()
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
    }
    Ok(())
}

fn is_prepare(previous: &WitnessStoreEnvelopeV1, proposed: &WitnessStoreEnvelopeV1) -> bool {
    let prepared = match (&previous.prepared, &proposed.prepared) {
        (None, Some(prepared)) => prepared,
        _ => return false,
    };
    if previous.session.is_none()
        || previous.session != proposed.session
        || previous.last_session_rotation != proposed.last_session_rotation
        || previous.current != proposed.current
        || previous.predecessor != proposed.predecessor
        || proposed.genesis_abort.is_some()
    {
        return false;
    }
    match (&previous.genesis_abort, &prepared.prepared.genesis_abort) {
        (None, None) => true,
        (Some(previous_abort), Some(prepared_abort)) => previous_abort == prepared_abort,
        _ => false,
    }
}

fn is_commit(
    previous: &WitnessStoreEnvelopeV1,
    proposed: &WitnessStoreEnvelopeV1,
) -> ProtocolResult<bool> {
    let prepared = match (&previous.prepared, &proposed.prepared) {
        (Some(prepared), None) => prepared,
        _ => return Ok(false),
    };
    if previous.session != proposed.session
        || previous.last_session_rotation != proposed.last_session_rotation
        || previous.genesis_abort.is_some()
        || proposed.genesis_abort.is_some()
        || proposed.predecessor != previous.current
    {
        return Ok(false);
    }
    let expected = WitnessStoredCandidateV1 {
        candidate: prepared.candidate.clone(),
        head: WitnessHeadV1::committed_from_candidate(&prepared.candidate.build()?)?,
    };
    Ok(proposed.current.as_ref() == Some(&expected))
}

fn is_abort(
    previous: &WitnessStoreEnvelopeV1,
    proposed: &WitnessStoreEnvelopeV1,
) -> ProtocolResult<bool> {
    let prepared = match (&previous.prepared, &proposed.prepared) {
        (Some(prepared), None) => prepared,
        _ => return Ok(false),
    };
    if previous.session != proposed.session
        || previous.last_session_rotation != proposed.last_session_rotation
        || previous.genesis_abort.is_some()
    {
        return Ok(false);
    }

    match &previous.current {
        Some(current) => {
            if proposed.predecessor != previous.predecessor || proposed.genesis_abort.is_some() {
                return Ok(false);
            }
            let mut expected_head = current.head.clone();
            expected_head.intent_counter = prepared.prepared.head.intent_counter;
            expected_head.last_intent_outcome = Some(WitnessIntentOutcomeV1::Aborted(Box::new(
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
            let expected = WitnessStoredCandidateV1 {
                candidate: current.candidate.clone(),
                head: expected_head,
            };
            Ok(proposed.current.as_ref() == Some(&expected))
        }
        None => {
            if proposed.current.is_some() || proposed.predecessor.is_some() {
                return Ok(false);
            }
            match &proposed.genesis_abort {
                Some(aborted) => Ok(aborted
                    .validate_against_prepared(&prepared.prepared)
                    .is_ok()),
                None => Ok(false),
            }
        }
    }
}

fn validate_retained_abort_identity(
    candidate: &CandidatePreimageV1,
    head: &WitnessHeadV1,
    summary: &WitnessAbortSummaryV1,
) -> ProtocolResult<()> {
    let current = candidate.build()?;
    if summary.epoch != head.epoch
        || summary.sequence != checked_next_sequence(head.sequence)?
        || summary.txid == current.txid
        || summary.candidate_digest == current.candidate_digest
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    validate_terminal_txid(
        &summary.txid,
        TxidPreimageV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: head.stream_id.clone(),
            predecessor_head_digest: summary.predecessor_head_digest.clone(),
            candidate_digest: summary.candidate_digest.clone(),
            binding_generation: summary.binding_generation.clone(),
            binding_digest: summary.binding_digest.clone(),
            authority_pair: summary.authority_pair,
            epoch: summary.epoch,
            sequence: summary.sequence,
            intent_counter: summary.intent_counter,
        },
    )?;

    if summary.intent_counter
        == candidate
            .intent_counter
            .checked_add(1)
            .ok_or(ProtocolError::Overflow {
                counter: "intent_counter",
            })?
        && summary.predecessor_head_digest
            != WitnessHeadV1::committed_from_candidate(&current)?.head_digest()?
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    Ok(())
}

fn validate_genesis_abort_identity(aborted: &WitnessGenesisAbortedV1) -> ProtocolResult<()> {
    validate_terminal_txid(
        &aborted.txid,
        TxidPreimageV1 {
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
        },
    )
}

fn validate_terminal_txid(txid: &str, preimage: TxidPreimageV1) -> ProtocolResult<()> {
    let expected = preimage.txid()?;
    if txid != expected {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    Ok(())
}

fn validate_string(field: &'static str, value: &str) -> ProtocolResult<()> {
    if value.is_empty() {
        return Err(ProtocolError::InvalidField {
            field: field.to_string(),
            reason: "must not be empty".to_string(),
        });
    }
    if value.len() > MAX_PROTOCOL_STRING_BYTES {
        return Err(ProtocolError::Bounds {
            field: field.to_string(),
            observed: value.len(),
            maximum: MAX_PROTOCOL_STRING_BYTES,
        });
    }
    if value.as_bytes().contains(&0) {
        return Err(ProtocolError::InvalidField {
            field: field.to_string(),
            reason: "must not contain NUL".to_string(),
        });
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> ProtocolResult<()> {
    validate_string(field, value)?;
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(ProtocolError::InvalidField {
            field: field.to_string(),
            reason: "must be a lowercase hexadecimal SHA-256 digest".to_string(),
        });
    }
    Ok(())
}

fn domain_separated_bytes(domain: &[u8], canonical: &[u8]) -> ProtocolResult<Vec<u8>> {
    if canonical.len() > MAX_PROTOCOL_RECORD_BYTES {
        return Err(ProtocolError::Bounds {
            field: "wire_bytes".to_string(),
            observed: canonical.len(),
            maximum: MAX_PROTOCOL_RECORD_BYTES,
        });
    }
    let length = u64::try_from(canonical.len()).map_err(|_| ProtocolError::Overflow {
        counter: "wire_size",
    })?;
    let capacity = domain
        .len()
        .checked_add(8)
        .and_then(|value| value.checked_add(canonical.len()))
        .ok_or(ProtocolError::Overflow {
            counter: "wire_size",
        })?;
    let mut material = Vec::with_capacity(capacity);
    material.extend_from_slice(domain);
    material.extend_from_slice(&length.to_be_bytes());
    material.extend_from_slice(canonical);
    Ok(material)
}

#[cfg(test)]
mod tests;
