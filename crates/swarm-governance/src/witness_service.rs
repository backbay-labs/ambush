//! Canonical public-witness service wire values.
//!
//! This module owns the closed request/response envelope and the pure
//! service-side candidate admission boundary. It deliberately owns no NATS
//! transport, store handle, or witness signing key.

use crate::persistence_protocol::{
    CandidateV1, GovernanceWitnessSession, MAX_PROTOCOL_RECORD_BYTES, MAX_PROTOCOL_STRING_BYTES,
    PROTOCOL_SCHEMA_VERSION, ProtocolError, ProtocolResult, RecoveryChallengeV1,
    WitnessDiscoveryAttestationV1, WitnessHeadV1, WitnessOperationOutcomeV1, WitnessOperationV1,
    WitnessOutcomeAttestationV1, WitnessReadAttestationV1, WitnessSessionAttestationV1,
    WitnessSessionAuthorizationV1, WitnessSessionFenceRequestV1, WitnessSessionStateFenceV1,
    WitnessSessionV1, canonical_wire_bytes, decode_canonical, digest_domain,
};
use serde::{Deserialize, Serialize};
use swarm_crypto::{DetachedSignature, PublicKey, sha256_hex, verify_detached_signature};

pub const WITNESS_SERVICE_REQUEST_DOMAIN_V1: &[u8] = b"swarm.governance.witness-service-request.v1";
pub const WITNESS_SERVICE_FAILURE_DOMAIN_V1: &[u8] = b"swarm.governance.witness-service-failure.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessServiceOperationV1 {
    Fence,
    Establish,
    Discover,
    Prepare,
    Commit,
    Abort,
    ReadPrepared,
    ReadHead,
    FetchPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessServiceRequestBodyV1 {
    Fence {
        request: Box<WitnessSessionFenceRequestV1>,
    },
    Establish {
        challenge: Box<RecoveryChallengeV1>,
        expected_head: Option<Box<WitnessHeadV1>>,
    },
    Discover {
        challenge: Box<RecoveryChallengeV1>,
    },
    Prepare {
        session: Box<WitnessSessionV1>,
        expected_head: Option<Box<WitnessHeadV1>>,
        candidate: Box<CandidateV1>,
    },
    Commit {
        session: Box<WitnessSessionV1>,
        txid: String,
    },
    Abort {
        session: Box<WitnessSessionV1>,
        txid: String,
    },
    ReadPrepared {
        session: Box<WitnessSessionV1>,
        target_txid: String,
    },
    ReadHead {
        session: Box<WitnessSessionV1>,
        target_txid: String,
    },
    FetchPayload {
        session: Box<WitnessSessionV1>,
        txid: String,
    },
}

impl WitnessServiceRequestBodyV1 {
    pub const fn operation(&self) -> WitnessServiceOperationV1 {
        match self {
            Self::Fence { .. } => WitnessServiceOperationV1::Fence,
            Self::Establish { .. } => WitnessServiceOperationV1::Establish,
            Self::Discover { .. } => WitnessServiceOperationV1::Discover,
            Self::Prepare { .. } => WitnessServiceOperationV1::Prepare,
            Self::Commit { .. } => WitnessServiceOperationV1::Commit,
            Self::Abort { .. } => WitnessServiceOperationV1::Abort,
            Self::ReadPrepared { .. } => WitnessServiceOperationV1::ReadPrepared,
            Self::ReadHead { .. } => WitnessServiceOperationV1::ReadHead,
            Self::FetchPayload { .. } => WitnessServiceOperationV1::FetchPayload,
        }
    }

    fn validate(&self) -> ProtocolResult<()> {
        match self {
            Self::Fence { request } => request.validate(),
            Self::Establish {
                challenge,
                expected_head,
            } => {
                challenge.validate()?;
                validate_expected_head_for_challenge(expected_head.as_deref(), challenge)
            }
            Self::Discover { challenge } => challenge.validate(),
            Self::Prepare {
                session,
                expected_head,
                candidate,
            } => {
                session.validate()?;
                candidate.canonical_bytes()?;
                validate_candidate_session_namespace(candidate, session)?;
                if expected_head.as_deref() != candidate.preimage.predecessor_head.as_ref() {
                    return Err(mismatch(
                        "expected_head",
                        "does not equal candidate predecessor",
                    ));
                }
                Ok(())
            }
            Self::Commit { session, txid }
            | Self::Abort { session, txid }
            | Self::FetchPayload { session, txid } => {
                session.validate()?;
                validate_digest("txid", txid)
            }
            Self::ReadPrepared {
                session,
                target_txid,
            }
            | Self::ReadHead {
                session,
                target_txid,
            } => {
                session.validate()?;
                validate_digest("target_txid", target_txid)
            }
        }
    }

    fn authorization_binding(&self) -> Option<(&WitnessSessionV1, WitnessOperationV1, &str)> {
        match self {
            Self::Fence { .. } | Self::Establish { .. } | Self::Discover { .. } => None,
            Self::Prepare {
                session, candidate, ..
            } => Some((session, WitnessOperationV1::Prepare, &candidate.txid)),
            Self::Commit { session, txid } => Some((session, WitnessOperationV1::Commit, txid)),
            Self::Abort { session, txid } => Some((session, WitnessOperationV1::Abort, txid)),
            Self::ReadPrepared {
                session,
                target_txid,
            } => Some((session, WitnessOperationV1::ReadPrepared, target_txid)),
            Self::ReadHead {
                session,
                target_txid,
            } => Some((session, WitnessOperationV1::ReadHead, target_txid)),
            Self::FetchPayload { session, txid } => {
                Some((session, WitnessOperationV1::FetchPayload, txid))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessServiceRequestV1 {
    pub schema_version: u32,
    pub operation: WitnessServiceOperationV1,
    pub request_nonce: String,
    pub admission_digest: String,
    pub body: WitnessServiceRequestBodyV1,
    pub request_digest: String,
    pub authorization: Option<WitnessSessionAuthorizationV1>,
}

#[derive(Serialize)]
struct WitnessServiceRequestPreimageV1<'a> {
    schema_version: u32,
    operation: WitnessServiceOperationV1,
    request_nonce: &'a str,
    admission_digest: &'a str,
    body: &'a WitnessServiceRequestBodyV1,
}

impl WitnessServiceRequestV1 {
    fn preimage(&self) -> WitnessServiceRequestPreimageV1<'_> {
        WitnessServiceRequestPreimageV1 {
            schema_version: self.schema_version,
            operation: self.operation,
            request_nonce: &self.request_nonce,
            admission_digest: &self.admission_digest,
            body: &self.body,
        }
    }

    fn validate_preimage(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_digest("request_nonce", &self.request_nonce)?;
        validate_digest("admission_digest", &self.admission_digest)?;
        if self.operation != self.body.operation() {
            return Err(mismatch("operation", "does not match request body"));
        }
        self.body.validate()?;
        canonical_wire_bytes(&self.preimage()).map(|_| ())
    }

    /// Compute the request identity without consulting the authorization.
    /// This is the exact digest an ephemeral session key must sign.
    pub fn computed_digest(&self) -> ProtocolResult<String> {
        self.validate_preimage()?;
        digest_domain(
            WITNESS_SERVICE_REQUEST_DOMAIN_V1,
            &canonical_wire_bytes(&self.preimage())?,
        )
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        self.validate_preimage()?;
        validate_digest("request_digest", &self.request_digest)?;
        if self.request_digest != self.computed_digest()? {
            return Err(ProtocolError::DigestMismatch {
                field: "request_digest",
            });
        }

        match (
            self.body.authorization_binding(),
            self.authorization.as_ref(),
        ) {
            (None, None) => Ok(()),
            (Some((session, operation, txid)), Some(authorization)) => authorization
                .verify_for_session_record(session, operation, txid, &self.request_digest),
            (None, Some(_)) => Err(mismatch(
                "authorization",
                "must be null for fence and session rotation",
            )),
            (Some(_), None) => Err(mismatch(
                "authorization",
                "is required for a session-bound operation",
            )),
        }
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        canonical_wire_bytes(self)
    }

    pub fn decode(bytes: &[u8]) -> ProtocolResult<Self> {
        let request = decode_canonical::<Self>(bytes)?;
        request.validate()?;
        Ok(request)
    }

    /// Decode the canonical public-service frame before consulting current
    /// store state. This deliberately validates only the outer request
    /// identity and admission routing boundary. Nested signature, bounds,
    /// session, candidate and transition failures are validated after the
    /// dispatcher authenticates the admitted stream, so they can receive a
    /// request- and store-bound signed application refusal.
    pub fn decode_for_public_dispatch(bytes: &[u8]) -> ProtocolResult<Self> {
        let request = decode_canonical::<Self>(bytes)?;
        request.validate_public_dispatch_identity()?;
        Ok(request)
    }

    /// Validate the immutable outer routing identity without treating nested
    /// application semantics as successful. This is the only request identity
    /// accepted when signing or verifying a refusal for invalid nested input.
    pub fn validate_public_dispatch_identity(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_digest("request_nonce", &self.request_nonce)?;
        validate_digest("admission_digest", &self.admission_digest)?;
        validate_digest("request_digest", &self.request_digest)?;
        if self.operation != self.body.operation() {
            return Err(mismatch("operation", "does not match request body"));
        }
        let computed = digest_domain(
            WITNESS_SERVICE_REQUEST_DOMAIN_V1,
            &canonical_wire_bytes(&self.preimage())?,
        )?;
        if self.request_digest != computed {
            return Err(ProtocolError::DigestMismatch {
                field: "request_digest",
            });
        }
        canonical_wire_bytes(self).map(|_| ())
    }
}

/// Derive the only accepted public-service nonce from one fresh 32-byte
/// entropy value. Exact retries reuse the finalized request; callers do not
/// re-run this function for a retry.
pub fn witness_service_request_nonce(entropy: [u8; 32]) -> String {
    sha256_hex(&entropy)
}

/// Request preimage frozen before session authorization is created.
///
/// Private fields prevent callers from changing the nonce, body, admission,
/// operation, or target between computing the request digest and signing it.
pub struct WitnessServiceRequestDraftV1 {
    request_nonce: String,
    admission_digest: String,
    body: WitnessServiceRequestBodyV1,
    request_digest: String,
}

impl WitnessServiceRequestDraftV1 {
    pub fn new(
        request_nonce: String,
        admission_digest: String,
        body: WitnessServiceRequestBodyV1,
    ) -> ProtocolResult<Self> {
        let request = WitnessServiceRequestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: body.operation(),
            request_nonce,
            admission_digest,
            body,
            request_digest: String::new(),
            authorization: None,
        };
        request.validate_preimage()?;
        let request_digest = request.computed_digest()?;
        Ok(Self {
            request_nonce: request.request_nonce,
            admission_digest: request.admission_digest,
            body: request.body,
            request_digest,
        })
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn finalize_without_authorization(self) -> ProtocolResult<WitnessServiceRequestV1> {
        if self.body.authorization_binding().is_some() {
            return Err(mismatch(
                "authorization",
                "session-bound operation requires finalize_with_session",
            ));
        }
        self.finish(None)
    }

    pub fn finalize_with_session(
        self,
        session: &GovernanceWitnessSession,
    ) -> ProtocolResult<WitnessServiceRequestV1> {
        let (wire_session, operation, txid) =
            self.body.authorization_binding().ok_or_else(|| {
                mismatch(
                    "authorization",
                    "fence and session rotation must not carry session authorization",
                )
            })?;
        if wire_session != session.attestation() {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let authorization = session.authorize(operation, txid, &self.request_digest)?;
        self.finish(Some(authorization))
    }

    fn finish(
        self,
        authorization: Option<WitnessSessionAuthorizationV1>,
    ) -> ProtocolResult<WitnessServiceRequestV1> {
        let request = WitnessServiceRequestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: self.body.operation(),
            request_nonce: self.request_nonce,
            admission_digest: self.admission_digest,
            body: self.body,
            request_digest: self.request_digest,
            authorization,
        };
        request.validate()?;
        Ok(request)
    }
}

fn validate_expected_head_for_challenge(
    expected_head: Option<&WitnessHeadV1>,
    challenge: &RecoveryChallengeV1,
) -> ProtocolResult<()> {
    let expected_digest = expected_head.map(WitnessHeadV1::head_digest).transpose()?;
    if expected_digest != challenge.state_fence.current_head_digest {
        return Err(mismatch(
            "expected_head",
            "does not match the signed state fence",
        ));
    }
    if let Some(head) = expected_head {
        head.validate_settled()?;
        if head.stream_id != challenge.stream_id
            || head.binding_generation != challenge.binding_generation
            || head.binding_digest != challenge.binding_digest
            || head.signer_key_id != challenge.signer_key_id
            || head.witness_key_id != challenge.witness_key_id
            || head.authority_pair != challenge.authority_pair
        {
            return Err(mismatch(
                "expected_head",
                "does not match challenge namespace",
            ));
        }
    }
    Ok(())
}

fn validate_candidate_session_namespace(
    candidate: &CandidateV1,
    session: &WitnessSessionV1,
) -> ProtocolResult<()> {
    let binding = &candidate.preimage.publication_binding;
    if candidate.preimage.stream_id != session.stream_id
        || binding.stream_id != session.stream_id
        || binding.generation != session.binding_generation
        || binding.binding_digest != session.binding_digest
        || binding.signer_key_id != session.signer_key_id
        || binding.witness_key_id != session.witness_key_id
        || binding.witness_identity != session.witness_identity
        || binding.authority_pair != session.authority_pair
    {
        return Err(mismatch(
            "candidate",
            "does not match the authorized session namespace",
        ));
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> ProtocolResult<()> {
    if value.is_empty() {
        return Err(mismatch(field, "must not be empty"));
    }
    if value.len() > MAX_PROTOCOL_STRING_BYTES {
        return Err(ProtocolError::Bounds {
            field: field.to_string(),
            observed: value.len(),
            maximum: MAX_PROTOCOL_STRING_BYTES,
        });
    }
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(mismatch(
            field,
            "must be a lowercase hexadecimal SHA-256 digest",
        ));
    }
    Ok(())
}

fn mismatch(field: &'static str, reason: &'static str) -> ProtocolError {
    ProtocolError::InvalidField {
        field: field.to_string(),
        reason: reason.to_string(),
    }
}

/// Closed application-level witness failure classes. Framing, timeout,
/// no-responder, and pre-admission overload failures remain transport errors
/// and therefore have no signed representation here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessServiceFailureCodeV1 {
    NonCanonical,
    UnsupportedVersion,
    BoundsExceeded,
    AdmissionMismatch,
    SignerMismatch,
    WitnessMismatch,
    InvalidSignature,
    StaleRotationFence,
    StaleSession,
    StaleIntent,
    ExpectedHeadMismatch,
    Conflict,
    StoreEntryMissing,
    StoreEntryCorrupt,
    StoreTransitionRefused,
    Contention,
    CapacityExhausted,
    InternalUnavailable,
}

impl WitnessServiceFailureCodeV1 {
    /// Retryability is protocol policy, never a caller-controlled bit.
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::Contention | Self::CapacityExhausted | Self::InternalUnavailable
        )
    }
}

/// Service-layer error categories that are not all representable by the
/// persistence protocol's lower-level error enum. Keeping this enum closed
/// prevents a dispatcher from converting an arbitrary error string into a
/// signed application failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessServiceProtocolFailureV1 {
    Canonical,
    Admission,
    Signature,
    Bounds,
    StaleSession,
    StaleIntent,
    Conflict,
    StoreTransition,
}

impl WitnessServiceProtocolFailureV1 {
    pub const fn failure_code(self) -> WitnessServiceFailureCodeV1 {
        match self {
            Self::Canonical => WitnessServiceFailureCodeV1::NonCanonical,
            Self::Admission => WitnessServiceFailureCodeV1::AdmissionMismatch,
            Self::Signature => WitnessServiceFailureCodeV1::InvalidSignature,
            Self::Bounds => WitnessServiceFailureCodeV1::BoundsExceeded,
            Self::StaleSession => WitnessServiceFailureCodeV1::StaleSession,
            Self::StaleIntent => WitnessServiceFailureCodeV1::StaleIntent,
            Self::Conflict => WitnessServiceFailureCodeV1::Conflict,
            Self::StoreTransition => WitnessServiceFailureCodeV1::StoreTransitionRefused,
        }
    }
}

/// Matchable failure value used before a witness signature is attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessServiceFailureV1 {
    pub failure_code: WitnessServiceFailureCodeV1,
    pub retryable: bool,
}

impl WitnessServiceFailureV1 {
    pub const fn new(failure_code: WitnessServiceFailureCodeV1) -> Self {
        Self {
            failure_code,
            retryable: failure_code.retryable(),
        }
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.retryable != self.failure_code.retryable() {
            return Err(mismatch(
                "retryable",
                "must be derived from the closed failure code",
            ));
        }
        Ok(())
    }

    pub const fn from_service_failure(error: WitnessServiceProtocolFailureV1) -> Self {
        Self::new(error.failure_code())
    }

    pub const fn from_protocol_error(error: &ProtocolError) -> Self {
        let code = match error {
            ProtocolError::UnsupportedSchema(_) => WitnessServiceFailureCodeV1::UnsupportedVersion,
            ProtocolError::CanonicalEncoding(_) | ProtocolError::NonCanonicalEncoding => {
                WitnessServiceFailureCodeV1::NonCanonical
            }
            ProtocolError::Bounds { .. } | ProtocolError::Overflow { .. } => {
                WitnessServiceFailureCodeV1::BoundsExceeded
            }
            ProtocolError::StaleIntent { .. } => WitnessServiceFailureCodeV1::StaleIntent,
            ProtocolError::WitnessOutcomeMismatch | ProtocolError::DigestMismatch { .. } => {
                WitnessServiceFailureCodeV1::InvalidSignature
            }
            ProtocolError::AuthorityPairMismatch
            | ProtocolError::RoleIdentityAlias { .. }
            | ProtocolError::InvalidField { .. } => WitnessServiceFailureCodeV1::AdmissionMismatch,
            ProtocolError::IllegalTransition { .. }
            | ProtocolError::RecoveryAmbiguous
            | ProtocolError::RecoveryFork { .. }
            | ProtocolError::InvalidEpoch { .. } => {
                WitnessServiceFailureCodeV1::StoreTransitionRefused
            }
        };
        Self::new(code)
    }
}

/// Authenticated evidence for the exact admitted stream's current store
/// state. Its fields are private so request bytes or caller booleans cannot
/// manufacture an absent-stream proof. This slice deliberately has no absence
/// constructor: it cannot exist safely before Plan 02 defines and validates
/// the complete authenticated `InspectReady` response.
///
/// ```compile_fail
/// use swarm_governance::witness_service::VerifiedWitnessStoreStateV1;
///
/// let _forged_absence = VerifiedWitnessStoreStateV1 {
///     stream_id: "stream".to_string(),
///     admission_digest: "0".repeat(64),
///     witness_identity: "witness".to_string(),
///     witness_key_id: "1".repeat(64),
///     store_state_digest: None,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWitnessStoreStateV1 {
    stream_id: String,
    admission_digest: String,
    witness_identity: String,
    witness_key_id: String,
    store_state_digest: Option<String>,
}

impl VerifiedWitnessStoreStateV1 {
    pub fn from_present(
        envelope: &crate::witness_engine::WitnessStoreEnvelopeV1,
    ) -> ProtocolResult<Self> {
        envelope.validate()?;
        Ok(Self {
            stream_id: envelope.stream_id.clone(),
            admission_digest: envelope.admission_digest.clone(),
            witness_identity: envelope.witness_identity.clone(),
            witness_key_id: envelope.witness_key_id.clone(),
            store_state_digest: Some(envelope.store_state_digest()?),
        })
    }
}

/// Signed, request-bound application rejection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessServiceFailureAttestationV1 {
    pub schema_version: u32,
    pub operation: WitnessServiceOperationV1,
    pub request_digest: String,
    pub stream_id: String,
    pub admission_digest: String,
    pub witness_identity: String,
    pub witness_key_id: String,
    pub store_state_digest: Option<String>,
    pub failure_code: WitnessServiceFailureCodeV1,
    pub retryable: bool,
    pub signature: DetachedSignature,
}

#[derive(Serialize)]
struct WitnessServiceFailurePreimageV1<'a> {
    schema_version: u32,
    operation: WitnessServiceOperationV1,
    request_digest: &'a str,
    stream_id: &'a str,
    admission_digest: &'a str,
    witness_identity: &'a str,
    witness_key_id: &'a str,
    store_state_digest: &'a Option<String>,
    failure_code: WitnessServiceFailureCodeV1,
    retryable: bool,
}

impl WitnessServiceFailureAttestationV1 {
    fn preimage(&self) -> WitnessServiceFailurePreimageV1<'_> {
        WitnessServiceFailurePreimageV1 {
            schema_version: self.schema_version,
            operation: self.operation,
            request_digest: &self.request_digest,
            stream_id: &self.stream_id,
            admission_digest: &self.admission_digest,
            witness_identity: &self.witness_identity,
            witness_key_id: &self.witness_key_id,
            store_state_digest: &self.store_state_digest,
            failure_code: self.failure_code,
            retryable: self.retryable,
        }
    }

    pub fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        let canonical = canonical_wire_bytes(&self.preimage())?;
        domain_separated_bytes(WITNESS_SERVICE_FAILURE_DOMAIN_V1, &canonical)
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_digest("request_digest", &self.request_digest)?;
        validate_digest("admission_digest", &self.admission_digest)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        if self.stream_id.is_empty() || self.witness_identity.is_empty() {
            return Err(mismatch(
                "failure_identity",
                "stream and witness identities must not be empty",
            ));
        }
        if let Some(digest) = &self.store_state_digest {
            validate_digest("store_state_digest", digest)?;
        }
        WitnessServiceFailureV1 {
            failure_code: self.failure_code,
            retryable: self.retryable,
        }
        .validate()?;
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

    fn validate_for_client_request(&self, request: &WitnessServiceRequestV1) -> ProtocolResult<()> {
        self.validate()?;
        let identity = public_request_identity(request)?;
        if self.operation != request.operation
            || self.request_digest != request.request_digest
            || self.stream_id != identity.stream_id
            || self.admission_digest != request.admission_digest
            || self.witness_identity != identity.witness_identity
            || self.witness_key_id != identity.witness_key_id
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    fn validate_for_request(
        &self,
        request: &WitnessServiceRequestV1,
        store_state: &VerifiedWitnessStoreStateV1,
    ) -> ProtocolResult<()> {
        self.validate_for_client_request(request)?;
        if self.stream_id != store_state.stream_id
            || self.admission_digest != store_state.admission_digest
            || self.witness_identity != store_state.witness_identity
            || self.witness_key_id != store_state.witness_key_id
            || self.store_state_digest != store_state.store_state_digest
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    /// Service-only signing seam: an application failure cannot be signed
    /// without an authenticated store-state value.
    pub fn sign_for_verified_store(
        request: &WitnessServiceRequestV1,
        store_state: &VerifiedWitnessStoreStateV1,
        failure: WitnessServiceFailureV1,
        witness_signer: &swarm_crypto::Ed25519Signer,
    ) -> ProtocolResult<Self> {
        request.validate_public_dispatch_identity()?;
        failure.validate()?;
        if witness_signer.key_id() != store_state.witness_key_id {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let mut attestation = Self {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            stream_id: store_state.stream_id.clone(),
            admission_digest: store_state.admission_digest.clone(),
            witness_identity: store_state.witness_identity.clone(),
            witness_key_id: store_state.witness_key_id.clone(),
            store_state_digest: store_state.store_state_digest.clone(),
            failure_code: failure.failure_code,
            retryable: failure.retryable,
            signature: witness_signer.sign(&[]),
        };
        attestation.signature = witness_signer.sign(&attestation.signing_bytes()?);
        attestation.validate_for_request(request, store_state)?;
        Ok(attestation)
    }
}

/// The only public response wire. Every success variant retains the existing
/// operation-specific witness signature; there is no generic success body or
/// signature domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// The accepted contract names six direct payload variants exactly; boxing a
// subset would change that public Rust ownership contract.
#[allow(clippy::large_enum_variant)]
pub enum WitnessServiceResponseV1 {
    Fence(WitnessSessionStateFenceV1),
    Establish(WitnessSessionAttestationV1),
    Discover(WitnessDiscoveryAttestationV1),
    Outcome(WitnessOutcomeAttestationV1),
    Read(WitnessReadAttestationV1),
    Failure(WitnessServiceFailureAttestationV1),
}

struct RequestIdentity<'a> {
    stream_id: &'a str,
    witness_identity: &'a str,
    witness_key_id: &'a str,
}

fn public_request_identity(
    request: &WitnessServiceRequestV1,
) -> ProtocolResult<RequestIdentity<'_>> {
    request.validate_public_dispatch_identity()?;
    let identity = match &request.body {
        WitnessServiceRequestBodyV1::Fence { request } => RequestIdentity {
            stream_id: &request.stream_id,
            witness_identity: &request.witness_identity,
            witness_key_id: &request.witness_key_id,
        },
        WitnessServiceRequestBodyV1::Establish { challenge, .. }
        | WitnessServiceRequestBodyV1::Discover { challenge } => RequestIdentity {
            stream_id: &challenge.stream_id,
            witness_identity: &challenge.witness_identity,
            witness_key_id: &challenge.witness_key_id,
        },
        WitnessServiceRequestBodyV1::Prepare { session, .. }
        | WitnessServiceRequestBodyV1::Commit { session, .. }
        | WitnessServiceRequestBodyV1::Abort { session, .. }
        | WitnessServiceRequestBodyV1::ReadPrepared { session, .. }
        | WitnessServiceRequestBodyV1::ReadHead { session, .. }
        | WitnessServiceRequestBodyV1::FetchPayload { session, .. } => RequestIdentity {
            stream_id: &session.stream_id,
            witness_identity: &session.witness_identity,
            witness_key_id: &session.witness_key_id,
        },
    };
    Ok(identity)
}

impl WitnessServiceResponseV1 {
    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate_nested_attestation()?;
        canonical_wire_bytes(self)
    }

    fn validate_nested_attestation(&self) -> ProtocolResult<()> {
        match self {
            Self::Fence(value) => value.validate(),
            Self::Establish(value) => value.validate(),
            Self::Discover(value) => value.validate(),
            Self::Outcome(value) => value.validate(),
            Self::Read(value) => value.validate(),
            Self::Failure(value) => value.validate(),
        }
    }

    pub fn decode_for_request(
        bytes: &[u8],
        request: &WitnessServiceRequestV1,
        store_state: Option<&VerifiedWitnessStoreStateV1>,
    ) -> ProtocolResult<Self> {
        let response = decode_canonical::<Self>(bytes)?;
        response.validate_for_request(request, store_state)?;
        Ok(response)
    }

    /// Client-safe response validation. Failure attestations remain fully
    /// signed and request-bound, but the runtime client is not required to
    /// possess the service's authenticated raw-store proof.
    pub fn decode_for_client_request(
        bytes: &[u8],
        request: &WitnessServiceRequestV1,
    ) -> ProtocolResult<Self> {
        let response = decode_canonical::<Self>(bytes)?;
        match &response {
            Self::Failure(failure) => failure.validate_for_client_request(request)?,
            _ => {
                request.validate()?;
                response.validate_for_request(request, None)?;
            }
        }
        Ok(response)
    }

    pub fn validate_for_request(
        &self,
        request: &WitnessServiceRequestV1,
        store_state: Option<&VerifiedWitnessStoreStateV1>,
    ) -> ProtocolResult<()> {
        if let Self::Failure(failure) = self {
            let proof = store_state.ok_or_else(|| {
                mismatch(
                    "store_state_proof",
                    "signed application failure requires authenticated current or absent state",
                )
            })?;
            return failure.validate_for_request(request, proof);
        }
        request.validate()?;
        match (self, &request.body) {
            (Self::Fence(response), WitnessServiceRequestBodyV1::Fence { request: fence }) => {
                response.validate()?;
                if &response.request != fence.as_ref()
                    || response.admission_digest != request.admission_digest
                {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            }
            (
                Self::Establish(response),
                WitnessServiceRequestBodyV1::Establish {
                    challenge,
                    expected_head,
                },
            ) => {
                response.validate()?;
                if &response.challenge != challenge.as_ref()
                    || response.committed_head.as_ref() != expected_head.as_deref()
                    || response.challenge.state_fence.admission_digest != request.admission_digest
                {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            }
            (Self::Discover(response), WitnessServiceRequestBodyV1::Discover { challenge }) => {
                response.validate()?;
                if &response.challenge != challenge.as_ref()
                    || response.challenge.state_fence.admission_digest != request.admission_digest
                {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            }
            (
                Self::Outcome(response),
                WitnessServiceRequestBodyV1::Prepare {
                    session, candidate, ..
                },
            ) => validate_outcome_for_session(
                response,
                session,
                WitnessOperationV1::Prepare,
                &candidate.txid,
                Some(&candidate.candidate_digest),
            )?,
            (Self::Outcome(response), WitnessServiceRequestBodyV1::Commit { session, txid }) => {
                validate_outcome_for_session(
                    response,
                    session,
                    WitnessOperationV1::Commit,
                    txid,
                    None,
                )?
            }
            (Self::Outcome(response), WitnessServiceRequestBodyV1::Abort { session, txid }) => {
                validate_outcome_for_session(
                    response,
                    session,
                    WitnessOperationV1::Abort,
                    txid,
                    None,
                )?
            }
            (
                Self::Read(response),
                WitnessServiceRequestBodyV1::ReadPrepared {
                    session,
                    target_txid,
                },
            ) => validate_read_for_session(
                response,
                session,
                WitnessOperationV1::ReadPrepared,
                target_txid,
                &request.request_digest,
            )?,
            (
                Self::Read(response),
                WitnessServiceRequestBodyV1::ReadHead {
                    session,
                    target_txid,
                },
            ) => validate_read_for_session(
                response,
                session,
                WitnessOperationV1::ReadHead,
                target_txid,
                &request.request_digest,
            )?,
            (Self::Read(response), WitnessServiceRequestBodyV1::FetchPayload { session, txid }) => {
                validate_read_for_session(
                    response,
                    session,
                    WitnessOperationV1::FetchPayload,
                    txid,
                    &request.request_digest,
                )?
            }
            (Self::Failure(_), _) => unreachable!("failure handled before success validation"),
            _ => {
                return Err(mismatch(
                    "response",
                    "variant does not match the exact request operation",
                ));
            }
        }
        Ok(())
    }
}

fn validate_outcome_for_session(
    response: &WitnessOutcomeAttestationV1,
    session: &WitnessSessionV1,
    operation: WitnessOperationV1,
    txid: &str,
    candidate_digest: Option<&str>,
) -> ProtocolResult<()> {
    response.validate()?;
    let outcome_operation = match &response.outcome {
        WitnessOperationOutcomeV1::Prepare(_) => WitnessOperationV1::Prepare,
        WitnessOperationOutcomeV1::Commit(_) => WitnessOperationV1::Commit,
        WitnessOperationOutcomeV1::Abort(_) => WitnessOperationV1::Abort,
    };
    if response.operation != operation
        || outcome_operation != operation
        || response.stream_id != session.stream_id
        || response.binding_generation != session.binding_generation
        || response.binding_digest != session.binding_digest
        || response.signer_key_id != session.signer_key_id
        || response.authority_pair != session.authority_pair
        || response.txid != txid
        || response.session_generation != session.session_generation
        || response.session_commitment != session.session_commitment
        || response.witness_key_id != session.witness_key_id
        || candidate_digest.is_some_and(|digest| response.candidate_digest != digest)
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    Ok(())
}

fn validate_read_for_session(
    response: &WitnessReadAttestationV1,
    session: &WitnessSessionV1,
    operation: WitnessOperationV1,
    target_txid: &str,
    request_digest: &str,
) -> ProtocolResult<()> {
    response.validate()?;
    if response.operation != operation
        || response.stream_id != session.stream_id
        || response.binding_generation != session.binding_generation
        || response.binding_digest != session.binding_digest
        || response.signer_key_id != session.signer_key_id
        || response.authority_pair != session.authority_pair
        || response.target_txid != target_txid
        || response.request_digest != request_digest
        || response.session_generation != session.session_generation
        || response.session_commitment != session.session_commitment
        || response.witness_key_id != session.witness_key_id
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
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

pub mod witness_candidate_verifier {
    include!("witness_candidate_verifier.rs");
}
pub use witness_candidate_verifier::{
    VerifiedCandidateAdmissionV1, VerifiedPrepareResolutionV1, VerifiedPrepareTransitionV1,
    WITNESS_ADMISSION_DOMAIN_V1, WitnessAdmissionRecordV1, WitnessCandidateVerifier,
    WitnessPrepareVerificationV1, prepare_verified_candidate, verify_public_prepare,
};

#[cfg(test)]
mod tests;
