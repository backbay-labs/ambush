use crate::types::AgentId;
use ed25519_dalek::{Signer, SigningKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use swarm_crypto::{CryptoError, DetachedSignature, sha256_hex, verify_detached_signature};

pub const SIGNED_STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedStateStatement {
    pub schema_version: u32,
    pub state_kind: String,
    pub stream_id: String,
    pub signer_agent_id: AgentId,
    pub sequence: u64,
    pub payload_json: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedStateEnvelope<T> {
    pub statement: SignedStateStatement,
    pub signature: DetachedSignature,
    #[serde(skip)]
    _marker: PhantomData<T>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedSignedState<T> {
    pub schema_version: u32,
    pub state_kind: String,
    pub stream_id: String,
    pub signer_agent_id: AgentId,
    pub sequence: u64,
    pub payload: T,
}

#[derive(Debug, Clone, Copy)]
pub struct SignedStateExpectation<'a> {
    pub state_kind: &'a str,
    pub stream_id: &'a str,
    pub expected_signer_agent_id: Option<&'a AgentId>,
    pub accepted_sequence: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum SignedStateError {
    #[error("failed to encode signed state `{state_kind}` for stream `{stream_id}`: {source}")]
    Encode {
        state_kind: String,
        stream_id: String,
        #[source]
        source: serde_json::Error,
    },

    #[error(
        "signed state `{state_kind}` for stream `{stream_id}` failed signature verification: {source}"
    )]
    InvalidSignature {
        state_kind: String,
        stream_id: String,
        #[source]
        source: CryptoError,
    },

    #[error(
        "signed state `{state_kind}` for stream `{stream_id}` signer agent mismatch: expected `{expected}`, got `{actual}`"
    )]
    SignerMismatch {
        state_kind: String,
        stream_id: String,
        expected: String,
        actual: String,
    },

    #[error(
        "signed state kind mismatch for stream `{stream_id}`: expected `{expected}`, got `{actual}`"
    )]
    StateKindMismatch {
        stream_id: String,
        expected: String,
        actual: String,
    },

    #[error(
        "signed state stream mismatch for state kind `{state_kind}`: expected `{expected}`, got `{actual}`"
    )]
    StreamMismatch {
        state_kind: String,
        expected: String,
        actual: String,
    },

    #[error(
        "signed state replay detected for `{state_kind}` stream `{stream_id}`: accepted sequence `{accepted_sequence}`, observed `{observed_sequence}`"
    )]
    ReplayDetected {
        state_kind: String,
        stream_id: String,
        accepted_sequence: u64,
        observed_sequence: u64,
    },

    #[error(
        "failed to decode signed state payload for `{state_kind}` stream `{stream_id}`: {source}"
    )]
    DecodePayload {
        state_kind: String,
        stream_id: String,
        #[source]
        source: serde_json::Error,
    },
}

impl<T> SignedStateEnvelope<T>
where
    T: Serialize,
{
    pub fn sign(
        state_kind: impl Into<String>,
        stream_id: impl Into<String>,
        signer_agent_id: AgentId,
        sequence: u64,
        payload: T,
        signing_key: &SigningKey,
    ) -> Result<Self, SignedStateError> {
        let state_kind = state_kind.into();
        let stream_id = stream_id.into();
        let derived_agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        if signer_agent_id != derived_agent_id {
            return Err(SignedStateError::SignerMismatch {
                state_kind,
                stream_id,
                expected: signer_agent_id.to_string(),
                actual: derived_agent_id.to_string(),
            });
        }

        let statement = SignedStateStatement {
            schema_version: SIGNED_STATE_SCHEMA_VERSION,
            state_kind: state_kind.clone(),
            stream_id: stream_id.clone(),
            signer_agent_id,
            sequence,
            payload_json: serde_json::to_string(&payload).map_err(|source| {
                SignedStateError::Encode {
                    state_kind: state_kind.clone(),
                    stream_id: stream_id.clone(),
                    source,
                }
            })?,
        };
        let payload_bytes =
            serde_json::to_vec(&statement).map_err(|source| SignedStateError::Encode {
                state_kind: state_kind.clone(),
                stream_id: stream_id.clone(),
                source,
            })?;
        let signature = signing_key.sign(&payload_bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            statement,
            signature: DetachedSignature {
                algorithm: "ed25519".to_string(),
                key_id: sha256_hex(verifying_key.as_bytes()),
                public_key_hex: hex::encode(verifying_key.to_bytes()),
                signature_hex: hex::encode(signature.to_bytes()),
            },
            _marker: PhantomData,
        })
    }
}

impl<T> SignedStateEnvelope<T>
where
    T: DeserializeOwned,
{
    pub fn verify(
        &self,
        expectation: SignedStateExpectation<'_>,
    ) -> Result<VerifiedSignedState<T>, SignedStateError> {
        let statement = &self.statement;
        if statement.state_kind != expectation.state_kind {
            return Err(SignedStateError::StateKindMismatch {
                stream_id: statement.stream_id.clone(),
                expected: expectation.state_kind.to_string(),
                actual: statement.state_kind.clone(),
            });
        }
        if statement.stream_id != expectation.stream_id {
            return Err(SignedStateError::StreamMismatch {
                state_kind: statement.state_kind.clone(),
                expected: expectation.stream_id.to_string(),
                actual: statement.stream_id.clone(),
            });
        }

        let payload_bytes =
            serde_json::to_vec(statement).map_err(|source| SignedStateError::Encode {
                state_kind: statement.state_kind.clone(),
                stream_id: statement.stream_id.clone(),
                source,
            })?;
        verify_detached_signature(&payload_bytes, &self.signature).map_err(|source| {
            SignedStateError::InvalidSignature {
                state_kind: statement.state_kind.clone(),
                stream_id: statement.stream_id.clone(),
                source,
            }
        })?;

        let derived_agent_id = AgentId::from_public_key_hex(&self.signature.public_key_hex);
        if statement.signer_agent_id != derived_agent_id {
            return Err(SignedStateError::SignerMismatch {
                state_kind: statement.state_kind.clone(),
                stream_id: statement.stream_id.clone(),
                expected: derived_agent_id.to_string(),
                actual: statement.signer_agent_id.to_string(),
            });
        }
        if let Some(expected_signer_agent_id) = expectation.expected_signer_agent_id
            && statement.signer_agent_id != *expected_signer_agent_id
        {
            return Err(SignedStateError::SignerMismatch {
                state_kind: statement.state_kind.clone(),
                stream_id: statement.stream_id.clone(),
                expected: expected_signer_agent_id.to_string(),
                actual: statement.signer_agent_id.to_string(),
            });
        }
        if let Some(accepted_sequence) = expectation.accepted_sequence
            && statement.sequence < accepted_sequence
        {
            return Err(SignedStateError::ReplayDetected {
                state_kind: statement.state_kind.clone(),
                stream_id: statement.stream_id.clone(),
                accepted_sequence,
                observed_sequence: statement.sequence,
            });
        }

        let payload = serde_json::from_str(&statement.payload_json).map_err(|source| {
            SignedStateError::DecodePayload {
                state_kind: statement.state_kind.clone(),
                stream_id: statement.stream_id.clone(),
                source,
            }
        })?;

        Ok(VerifiedSignedState {
            schema_version: statement.schema_version,
            state_kind: statement.state_kind.clone(),
            stream_id: statement.stream_id.clone(),
            signer_agent_id: statement.signer_agent_id.clone(),
            sequence: statement.sequence,
            payload,
        })
    }
}

impl<T> SignedStateEnvelope<T> {
    pub fn sequence(&self) -> u64 {
        self.statement.sequence
    }

    pub fn signer_agent_id(&self) -> &AgentId {
        &self.statement.signer_agent_id
    }

    pub fn stream_id(&self) -> &str {
        &self.statement.stream_id
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{SignedStateEnvelope, SignedStateError, SignedStateExpectation};
    use crate::types::AgentId;
    use ed25519_dalek::SigningKey;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct FixtureState {
        value: u32,
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn signed_state_round_trips_with_expected_signer() {
        let signing_key = signing_key();
        let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        let envelope = SignedStateEnvelope::sign(
            "fixture",
            "stream-1",
            agent_id.clone(),
            4,
            FixtureState { value: 9 },
            &signing_key,
        )
        .unwrap();

        let statement = envelope
            .verify(SignedStateExpectation {
                state_kind: "fixture",
                stream_id: "stream-1",
                expected_signer_agent_id: Some(&agent_id),
                accepted_sequence: Some(4),
            })
            .unwrap();

        assert_eq!(statement.payload, FixtureState { value: 9 });
        assert_eq!(statement.sequence, 4);
    }

    #[test]
    fn signed_state_rejects_tampered_payload() {
        let signing_key = signing_key();
        let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        let mut envelope = SignedStateEnvelope::sign(
            "fixture",
            "stream-1",
            agent_id,
            1,
            FixtureState { value: 9 },
            &signing_key,
        )
        .unwrap();
        envelope.statement.payload_json =
            serde_json::to_string(&FixtureState { value: 10 }).unwrap();

        let error = envelope
            .verify(SignedStateExpectation {
                state_kind: "fixture",
                stream_id: "stream-1",
                expected_signer_agent_id: None,
                accepted_sequence: None,
            })
            .unwrap_err();
        assert!(matches!(error, SignedStateError::InvalidSignature { .. }));
    }

    #[test]
    fn signed_state_rejects_replayed_sequence() {
        let signing_key = signing_key();
        let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        let envelope = SignedStateEnvelope::sign(
            "fixture",
            "stream-1",
            agent_id,
            2,
            FixtureState { value: 9 },
            &signing_key,
        )
        .unwrap();

        let error = envelope
            .verify(SignedStateExpectation {
                state_kind: "fixture",
                stream_id: "stream-1",
                expected_signer_agent_id: None,
                accepted_sequence: Some(3),
            })
            .unwrap_err();
        assert!(matches!(error, SignedStateError::ReplayDetected { .. }));
    }
}
