//! Canonical public-witness service request wire values.
//!
//! This module owns only the public request envelope. It does not own
//! transport, admission, store access, candidate admission, or failure
//! attestations. Keeping those authorities out of this type prevents a valid
//! request digest from being mistaken for an accepted witness operation.

use crate::persistence_protocol::{
    CandidateV1, MAX_PROTOCOL_STRING_BYTES, PROTOCOL_SCHEMA_VERSION, ProtocolError, ProtocolResult,
    RecoveryChallengeV1, WitnessHeadV1, WitnessOperationV1, WitnessSessionAuthorizationV1,
    WitnessSessionFenceRequestV1, WitnessSessionV1, canonical_wire_bytes, decode_canonical,
    digest_domain,
};
use serde::{Deserialize, Serialize};

pub const WITNESS_SERVICE_REQUEST_DOMAIN_V1: &[u8] = b"swarm.governance.witness-service-request.v1";

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

#[cfg(test)]
mod tests;
