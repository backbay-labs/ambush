//! Pure, bounded governance persistence protocol model.
//!
//! This module deliberately contains no filesystem or witness adapter code.
//! It owns the canonical wire values, identifier derivation, bounded counter
//! arithmetic, witness contract, and the local transaction state machine used
//! by the later descriptor-bound implementation slice.

use async_trait::async_trait;
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use swarm_crypto::{
    DetachedSignature, canonical_json_bytes, sha256_hex, verify_detached_signature,
};
use thiserror::Error;

pub const PROTOCOL_SCHEMA_VERSION: u32 = 1;
pub const CANDIDATE_DOMAIN_V1: &[u8] = b"swarm.governance.candidate.v1";
pub const TXID_DOMAIN_V1: &[u8] = b"swarm.governance.txid.v1";
pub const JOURNAL_RECORD_DOMAIN_V1: &[u8] = b"swarm.governance.journal-record.v1";
pub const WITNESS_HEAD_DOMAIN_V1: &[u8] = b"swarm.governance.witness-head.v1";
pub const WITNESS_DATA_HEAD_DOMAIN_V1: &[u8] = b"swarm.governance.witness-data-head.v1";
pub const WITNESS_FENCE_REQUEST_DOMAIN_V1: &[u8] = b"swarm.governance.witness-fence-request.v1";
pub const WITNESS_STATE_FENCE_DOMAIN_V1: &[u8] = b"swarm.governance.witness-state-fence.v1";
pub const WITNESS_SESSION_STATE_DOMAIN_V1: &[u8] = b"swarm.governance.witness-session-state.v1";
pub const WITNESS_PREPARED_STATE_DOMAIN_V1: &[u8] = b"swarm.governance.witness-prepared-state.v1";
pub const WITNESS_ROTATION_CHALLENGE_DOMAIN_V1: &[u8] =
    b"swarm.governance.witness-rotation-challenge.v1";
pub const WITNESS_ROTATION_RECEIPT_DOMAIN_V1: &[u8] =
    b"swarm.governance.witness-rotation-receipt.v1";
pub const WITNESS_EXTERNAL_MARKER_DOMAIN_V1: &[u8] = b"swarm.governance.witness-external-marker.v1";
pub const GENESIS_PREDECESSOR_DOMAIN_V1: &[u8] = b"swarm.governance.genesis-predecessor.v1";
pub const GENESIS_DATA_HEAD_DOMAIN_V1: &[u8] = b"swarm.governance.genesis-data-head.v1";
pub const BINDING_DOMAIN_V1: &[u8] = b"swarm.governance.publication-binding.v1";
pub const JOURNAL_ENVELOPE_DOMAIN_V1: &[u8] = b"swarm.governance.journal-envelope.v1";
pub const INTENT_ROOT_DOMAIN_V1: &[u8] = b"swarm.governance.intent-root.v1";
pub const STATE_PAYLOAD_DOMAIN_V1: &str = "swarm.governance.state.v1";
pub const CHECKPOINT_PAYLOAD_DOMAIN_V1: &str = "swarm.governance.checkpoint.v1";
pub const MAX_PROTOCOL_STRING_BYTES: usize = 4 * 1024;
pub const MAX_PROTOCOL_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PROTOCOL_RECORD_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PROTOCOL_COLLECTION_ITEMS: usize = 1_024;
pub const FIXED_CLEANUP_SLOT_COUNT: usize = 64;

#[cfg(test)]
pub(crate) const CANDIDATE_DOMAIN_V1_ALT: &[u8] = b"swarm.governance.candidate.v1.alt";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    #[error("invalid `{field}`: {reason}")]
    InvalidField { field: String, reason: String },
    #[error("`{field}` exceeds the configured bound: {observed} > {maximum}")]
    Bounds {
        field: String,
        observed: usize,
        maximum: usize,
    },
    #[error("checked arithmetic exhausted `{counter}`")]
    Overflow { counter: &'static str },
    #[error("canonical encoding failed: {0}")]
    CanonicalEncoding(String),
    #[error("wire bytes are not canonical")]
    NonCanonicalEncoding,
    #[error("digest mismatch for `{field}`")]
    DigestMismatch { field: &'static str },
    #[error("publication roles `{first}` and `{second}` alias inode identity")]
    RoleIdentityAlias {
        first: &'static str,
        second: &'static str,
    },
    #[error("authority sidecars do not share one inode identity")]
    AuthorityPairMismatch,
    #[error("illegal transaction transition from `{from:?}` to `{to:?}`")]
    IllegalTransition {
        from: TransactionPhaseV1,
        to: TransactionPhaseV1,
    },
    #[error("transaction recovery is ambiguous")]
    RecoveryAmbiguous,
    #[error("transaction recovery fork at journal generation {generation}")]
    RecoveryFork { generation: u64 },
    #[error("stale or reused intent: expected {expected}, observed {observed}")]
    StaleIntent { expected: u64, observed: u64 },
    #[error("reinitialization requires epoch {expected}, observed {observed}")]
    InvalidEpoch { expected: u64, observed: u64 },
    #[error("wire value has unsupported schema version {0}")]
    UnsupportedSchema(u32),
    #[error("durability witness outcome does not match the transaction")]
    WitnessOutcomeMismatch,
}

pub type ProtocolResult<T> = Result<T, ProtocolError>;

fn invalid(field: &'static str, reason: impl Into<String>) -> ProtocolError {
    ProtocolError::InvalidField {
        field: field.to_string(),
        reason: reason.into(),
    }
}

fn bounded_usize(value: u64) -> usize {
    if value > usize::MAX as u64 {
        usize::MAX
    } else {
        value as usize
    }
}

fn validate_string(field: &'static str, value: &str) -> ProtocolResult<()> {
    if value.is_empty() {
        return Err(invalid(field, "must not be empty"));
    }
    if value.len() > MAX_PROTOCOL_STRING_BYTES {
        return Err(ProtocolError::Bounds {
            field: field.to_string(),
            observed: value.len(),
            maximum: MAX_PROTOCOL_STRING_BYTES,
        });
    }
    if value.as_bytes().contains(&0) {
        return Err(invalid(field, "must not contain NUL"));
    }
    Ok(())
}

fn validate_string_with_limit(
    field: &'static str,
    value: &str,
    maximum: u64,
) -> ProtocolResult<()> {
    validate_string(field, value)?;
    if value.len() as u64 > maximum {
        return Err(ProtocolError::Bounds {
            field: field.to_string(),
            observed: value.len(),
            maximum: bounded_usize(maximum),
        });
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> ProtocolResult<()> {
    validate_string(field, value)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(
            field,
            "must be a lowercase hexadecimal SHA-256 digest",
        ));
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(invalid(field, "must use lowercase hexadecimal"));
    }
    Ok(())
}

fn validate_payload(field: &'static str, payload: &[u8]) -> ProtocolResult<()> {
    if payload.len() > MAX_PROTOCOL_PAYLOAD_BYTES {
        return Err(ProtocolError::Bounds {
            field: field.to_string(),
            observed: payload.len(),
            maximum: MAX_PROTOCOL_PAYLOAD_BYTES,
        });
    }
    Ok(())
}

fn validate_canonical_json_payload(field: &'static str, payload: &[u8]) -> ProtocolResult<()> {
    let value = serde_json::from_slice::<serde_json::Value>(payload)
        .map_err(|error| invalid(field, format!("invalid JSON: {error}")))?;
    if canonical_wire_bytes(&value)? != payload {
        return Err(ProtocolError::NonCanonicalEncoding);
    }
    Ok(())
}

pub fn canonical_wire_bytes<T: Serialize>(value: &T) -> ProtocolResult<Vec<u8>> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    if bytes.len() > MAX_PROTOCOL_RECORD_BYTES {
        return Err(ProtocolError::Bounds {
            field: "wire_bytes".to_string(),
            observed: bytes.len(),
            maximum: MAX_PROTOCOL_RECORD_BYTES,
        });
    }
    Ok(bytes)
}

pub fn decode_canonical<T>(bytes: &[u8]) -> ProtocolResult<T>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() > MAX_PROTOCOL_RECORD_BYTES {
        return Err(ProtocolError::Bounds {
            field: "wire_bytes".to_string(),
            observed: bytes.len(),
            maximum: MAX_PROTOCOL_RECORD_BYTES,
        });
    }
    let value = serde_json::from_slice::<T>(bytes)
        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
    if canonical_wire_bytes(&value)? != bytes {
        return Err(ProtocolError::NonCanonicalEncoding);
    }
    Ok(value)
}

/// Hash a canonical value with an explicit domain and a checked, big-endian
/// byte-length delimiter. Length delimiting prevents raw concatenation
/// ambiguity and keeps candidate and transaction identifiers non-circular.
pub fn digest_domain(domain: &[u8], canonical: &[u8]) -> ProtocolResult<String> {
    Ok(sha256_hex(&domain_separated_bytes(domain, canonical)?))
}

fn domain_separated_bytes(domain: &[u8], canonical: &[u8]) -> ProtocolResult<Vec<u8>> {
    let length = u64::try_from(canonical.len()).map_err(|_| ProtocolError::Overflow {
        counter: "wire_size",
    })?;
    let mut material = Vec::with_capacity(
        domain
            .len()
            .checked_add(8)
            .and_then(|value| value.checked_add(canonical.len()))
            .ok_or(ProtocolError::Overflow {
                counter: "wire_size",
            })?,
    );
    material.extend_from_slice(domain);
    material.extend_from_slice(&length.to_be_bytes());
    material.extend_from_slice(canonical);
    Ok(material)
}

pub fn checked_next_epoch(value: u64) -> ProtocolResult<u64> {
    value
        .checked_add(1)
        .ok_or(ProtocolError::Overflow { counter: "epoch" })
}

pub fn checked_next_sequence(value: u64) -> ProtocolResult<u64> {
    value.checked_add(1).ok_or(ProtocolError::Overflow {
        counter: "sequence",
    })
}

pub fn checked_next_intent(value: u64) -> ProtocolResult<u64> {
    value.checked_add(1).ok_or(ProtocolError::Overflow {
        counter: "intent_counter",
    })
}

pub fn checked_next_session(value: u64) -> ProtocolResult<u64> {
    value.checked_add(1).ok_or(ProtocolError::Overflow {
        counter: "session_generation",
    })
}

pub fn checked_next_journal_generation(value: u64) -> ProtocolResult<u64> {
    value.checked_add(1).ok_or(ProtocolError::Overflow {
        counter: "journal_generation",
    })
}

pub fn checked_add_size(left: u64, right: u64) -> ProtocolResult<u64> {
    left.checked_add(right)
        .ok_or(ProtocolError::Overflow { counter: "size" })
}

pub fn validate_next_intent(committed: u64, observed: u64) -> ProtocolResult<()> {
    let expected = checked_next_intent(committed)?;
    if observed != expected {
        return Err(ProtocolError::StaleIntent { expected, observed });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolLimitsV1 {
    pub max_string_bytes: u64,
    pub max_payload_bytes: u64,
    pub max_record_bytes: u64,
    pub max_collection_items: u64,
}

impl Default for ProtocolLimitsV1 {
    fn default() -> Self {
        Self {
            max_string_bytes: MAX_PROTOCOL_STRING_BYTES as u64,
            max_payload_bytes: MAX_PROTOCOL_PAYLOAD_BYTES as u64,
            max_record_bytes: MAX_PROTOCOL_RECORD_BYTES as u64,
            max_collection_items: MAX_PROTOCOL_COLLECTION_ITEMS as u64,
        }
    }
}

impl ProtocolLimitsV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        if self.max_string_bytes == 0 || self.max_string_bytes > MAX_PROTOCOL_STRING_BYTES as u64 {
            return Err(invalid(
                "max_string_bytes",
                "outside configured protocol bound",
            ));
        }
        if self.max_payload_bytes == 0 || self.max_payload_bytes > MAX_PROTOCOL_PAYLOAD_BYTES as u64
        {
            return Err(invalid(
                "max_payload_bytes",
                "outside configured protocol bound",
            ));
        }
        if self.max_record_bytes == 0
            || self.max_record_bytes > MAX_PROTOCOL_RECORD_BYTES as u64
            || self.max_record_bytes < self.max_payload_bytes
        {
            return Err(invalid(
                "max_record_bytes",
                "outside configured protocol bound",
            ));
        }
        if self.max_collection_items == 0
            || self.max_collection_items > MAX_PROTOCOL_COLLECTION_ITEMS as u64
        {
            return Err(invalid(
                "max_collection_items",
                "outside configured protocol bound",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentityV1 {
    pub device: u64,
    pub inode: u64,
}

impl ArtifactIdentityV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        if self.device == 0 || self.inode == 0 {
            return Err(invalid(
                "artifact_identity",
                "device and inode must be non-zero",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityPairIdentityV1 {
    pub current: ArtifactIdentityV1,
    pub legacy: ArtifactIdentityV1,
}

impl AuthorityPairIdentityV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        self.current.validate()?;
        self.legacy.validate()?;
        if self.current != self.legacy {
            return Err(ProtocolError::AuthorityPairMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationRoleIdentitiesV1 {
    pub state_canonical: ArtifactIdentityV1,
    pub state_staging: ArtifactIdentityV1,
    pub checkpoint_canonical: ArtifactIdentityV1,
    pub checkpoint_staging: ArtifactIdentityV1,
    pub journal_primary: ArtifactIdentityV1,
    pub journal_secondary: ArtifactIdentityV1,
}

impl PublicationRoleIdentitiesV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        validate_distinct_roles(self.identities())
    }

    fn identities(&self) -> [(&'static str, ArtifactIdentityV1); 6] {
        [
            ("state_canonical", self.state_canonical),
            ("state_staging", self.state_staging),
            ("checkpoint_canonical", self.checkpoint_canonical),
            ("checkpoint_staging", self.checkpoint_staging),
            ("journal_primary", self.journal_primary),
            ("journal_secondary", self.journal_secondary),
        ]
    }
}

fn validate_distinct_roles(roles: [(&'static str, ArtifactIdentityV1); 6]) -> ProtocolResult<()> {
    for (_, identity) in roles {
        identity.validate()?;
    }
    for (index, (first_name, first_identity)) in roles.iter().enumerate() {
        for (second_name, second_identity) in roles.iter().skip(index + 1) {
            if first_identity == second_identity {
                return Err(ProtocolError::RoleIdentityAlias {
                    first: first_name,
                    second: second_name,
                });
            }
        }
    }
    Ok(())
}

/// The binding's role identities are the immutable allowed inode pairs. A
/// mapping is the name-to-inode assignment for one publication generation;
/// exchanges therefore swap mapping values without changing the binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationMappingV1 {
    pub state_canonical: ArtifactIdentityV1,
    pub state_staging: ArtifactIdentityV1,
    pub checkpoint_canonical: ArtifactIdentityV1,
    pub checkpoint_staging: ArtifactIdentityV1,
    pub journal_primary: ArtifactIdentityV1,
    pub journal_secondary: ArtifactIdentityV1,
}

impl PublicationMappingV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        validate_distinct_roles(self.identities())
    }

    fn identities(&self) -> [(&'static str, ArtifactIdentityV1); 6] {
        [
            ("state_canonical", self.state_canonical),
            ("state_staging", self.state_staging),
            ("checkpoint_canonical", self.checkpoint_canonical),
            ("checkpoint_staging", self.checkpoint_staging),
            ("journal_primary", self.journal_primary),
            ("journal_secondary", self.journal_secondary),
        ]
    }

    pub fn validate_against(&self, allowed: &PublicationRoleIdentitiesV1) -> ProtocolResult<()> {
        self.validate()?;
        allowed.validate()?;
        let state_matches = pair_matches(
            self.state_canonical,
            self.state_staging,
            allowed.state_canonical,
            allowed.state_staging,
        );
        let checkpoint_matches = pair_matches(
            self.checkpoint_canonical,
            self.checkpoint_staging,
            allowed.checkpoint_canonical,
            allowed.checkpoint_staging,
        );
        let journal_matches = pair_matches(
            self.journal_primary,
            self.journal_secondary,
            allowed.journal_primary,
            allowed.journal_secondary,
        );
        if !(state_matches && checkpoint_matches && journal_matches) {
            return Err(invalid(
                "publication_mapping",
                "each mapping pair must be an exact permutation of its bound lane pair",
            ));
        }
        Ok(())
    }

    /// Validate the next name-to-inode assignment for one complete
    /// publication. State, checkpoint, and journal lanes each exchange their
    /// canonical/alternate names; a cross-pair or same-pair assignment is not
    /// a valid successor even when the global inode set is unchanged.
    pub fn validate_successor_of(&self, before: &Self) -> ProtocolResult<()> {
        before.validate()?;
        self.validate()?;
        let expected = Self {
            state_canonical: before.state_staging,
            state_staging: before.state_canonical,
            checkpoint_canonical: before.checkpoint_staging,
            checkpoint_staging: before.checkpoint_canonical,
            journal_primary: before.journal_primary,
            journal_secondary: before.journal_secondary,
        };
        if self != &expected {
            return Err(invalid(
                "publication_mapping",
                "successor must exchange each canonical/alternate lane pair",
            ));
        }
        Ok(())
    }
}

fn pair_matches(
    actual_first: ArtifactIdentityV1,
    actual_second: ArtifactIdentityV1,
    expected_first: ArtifactIdentityV1,
    expected_second: ArtifactIdentityV1,
) -> bool {
    BTreeSet::from([actual_first, actual_second])
        == BTreeSet::from([expected_first, expected_second])
}

fn journal_lane_is_allowed(mapping: &PublicationMappingV1, lane: ArtifactIdentityV1) -> bool {
    lane == mapping.journal_primary || lane == mapping.journal_secondary
}

fn next_journal_lane(
    mapping: &PublicationMappingV1,
    current: ArtifactIdentityV1,
) -> ProtocolResult<ArtifactIdentityV1> {
    if current == mapping.journal_primary {
        Ok(mapping.journal_secondary)
    } else if current == mapping.journal_secondary {
        Ok(mapping.journal_primary)
    } else {
        Err(invalid(
            "journal_lane",
            "record lane is not one of the bound journal lanes",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPayloadPreimageV1 {
    pub schema_version: u32,
    pub domain: String,
    pub stream_id: String,
    pub binding_generation: String,
    pub binding_digest: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub payload: Vec<u8>,
    pub byte_len: u64,
    pub digest: String,
}

impl SignedPayloadPreimageV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_string("payload_domain", &self.domain)?;
        validate_string("stream_id", &self.stream_id)?;
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        validate_payload("payload", &self.payload)?;
        validate_digest("digest", &self.digest)?;
        self.authority_pair.validate()?;
        let expected_len =
            u64::try_from(self.payload.len()).map_err(|_| ProtocolError::Overflow {
                counter: "payload_size",
            })?;
        if expected_len != self.byte_len || sha256_hex(&self.payload) != self.digest {
            return Err(ProtocolError::DigestMismatch { field: "payload" });
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        canonical_wire_bytes(self)
    }
}

struct SignedPayloadExpectation<'a> {
    field: &'static str,
    domain: &'a str,
    stream_id: &'a str,
    binding_generation: &'a str,
    binding_digest: &'a str,
    authority_pair: AuthorityPairIdentityV1,
    payload: &'a [u8],
    byte_len: u64,
    digest: &'a str,
    signer_key_id: &'a str,
    attestation: &'a DetachedSignature,
}

fn validate_signed_payload(expectation: SignedPayloadExpectation<'_>) -> ProtocolResult<()> {
    if expectation.domain.is_empty() || expectation.domain.len() > MAX_PROTOCOL_STRING_BYTES {
        return Err(invalid(expectation.field, "invalid payload signing domain"));
    }
    if expectation.attestation.algorithm != "ed25519"
        || expectation.attestation.key_id != expectation.signer_key_id
        || sha256_hex(
            &swarm_crypto::PublicKey::from_hex(&expectation.attestation.public_key_hex)
                .map_err(|_| invalid(expectation.field, "invalid payload public key"))?
                .as_bytes()[..],
        ) != expectation.signer_key_id
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    let preimage = SignedPayloadPreimageV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        domain: expectation.domain.to_string(),
        stream_id: expectation.stream_id.to_string(),
        binding_generation: expectation.binding_generation.to_string(),
        binding_digest: expectation.binding_digest.to_string(),
        authority_pair: expectation.authority_pair,
        payload: expectation.payload.to_vec(),
        byte_len: expectation.byte_len,
        digest: expectation.digest.to_string(),
    };
    let bytes = preimage.canonical_bytes()?;
    let signature = swarm_crypto::Signature::from_hex(&expectation.attestation.signature_hex)
        .map_err(|_| invalid(expectation.field, "invalid payload signature"))?;
    let mut verified = expectation.attestation.clone();
    verified.signature_hex = signature.to_hex();
    if verify_detached_signature(&bytes, &verified).is_err() {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationBindingV1 {
    pub schema_version: u32,
    pub stream_id: String,
    pub generation: String,
    pub parent_directory: ArtifactIdentityV1,
    pub pool_directory: ArtifactIdentityV1,
    pub pool_lock: ArtifactIdentityV1,
    pub binding_file: ArtifactIdentityV1,
    pub authority_pair: AuthorityPairIdentityV1,
    pub publication_roles: PublicationRoleIdentitiesV1,
    pub cleanup_slot_count: u32,
    pub cleanup_slot_names: Vec<String>,
    pub cleanup_slot_identities: Vec<ArtifactIdentityV1>,
    pub limits: ProtocolLimitsV1,
    /// The admitted governance signer for state/checkpoint payloads.
    pub signer_key_id: String,
    /// The admitted external durability-witness verification key.
    pub witness_key_id: String,
    pub witness_identity: String,
    /// Digest of the complete unsigned binding preimage.
    pub binding_digest: String,
    /// Governance signature over the complete unsigned binding preimage.
    pub binding_signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PublicationBindingPreimageV1<'a> {
    schema_version: u32,
    stream_id: &'a str,
    generation: &'a str,
    parent_directory: ArtifactIdentityV1,
    pool_directory: ArtifactIdentityV1,
    pool_lock: ArtifactIdentityV1,
    binding_file: ArtifactIdentityV1,
    authority_pair: AuthorityPairIdentityV1,
    publication_roles: PublicationRoleIdentitiesV1,
    cleanup_slot_count: u32,
    cleanup_slot_names: &'a [String],
    cleanup_slot_identities: &'a [ArtifactIdentityV1],
    limits: ProtocolLimitsV1,
    signer_key_id: &'a str,
    witness_key_id: &'a str,
    witness_identity: &'a str,
}

impl PublicationBindingV1 {
    fn unsigned_preimage(&self) -> PublicationBindingPreimageV1<'_> {
        PublicationBindingPreimageV1 {
            schema_version: self.schema_version,
            stream_id: &self.stream_id,
            generation: &self.generation,
            parent_directory: self.parent_directory,
            pool_directory: self.pool_directory,
            pool_lock: self.pool_lock,
            binding_file: self.binding_file,
            authority_pair: self.authority_pair,
            publication_roles: self.publication_roles,
            cleanup_slot_count: self.cleanup_slot_count,
            cleanup_slot_names: &self.cleanup_slot_names,
            cleanup_slot_identities: &self.cleanup_slot_identities,
            limits: self.limits,
            signer_key_id: &self.signer_key_id,
            witness_key_id: &self.witness_key_id,
            witness_identity: &self.witness_identity,
        }
    }

    /// Canonical bytes covered by the binding digest and governance signature.
    /// The digest/signature fields are intentionally excluded to avoid a
    /// circular preimage.
    pub fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        canonical_wire_bytes(&self.unsigned_preimage())
    }

    pub fn computed_digest(&self) -> ProtocolResult<String> {
        digest_domain(BINDING_DOMAIN_V1, &self.signing_bytes()?)
    }

    pub fn seal_with_signature(mut self, signature: DetachedSignature) -> ProtocolResult<Self> {
        self.binding_digest = self.computed_digest()?;
        self.binding_signature = signature;
        self.validate()?;
        Ok(self)
    }

    fn validate_unsigned(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        self.limits.validate()?;
        validate_string_with_limit("stream_id", &self.stream_id, self.limits.max_string_bytes)?;
        validate_digest("generation", &self.generation)?;
        validate_string_with_limit(
            "witness_identity",
            &self.witness_identity,
            self.limits.max_string_bytes,
        )?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        self.authority_pair.validate()?;
        self.publication_roles.validate()?;
        let slot_count =
            usize::try_from(self.cleanup_slot_count).map_err(|_| ProtocolError::Overflow {
                counter: "cleanup_slot_count",
            })?;
        if slot_count != FIXED_CLEANUP_SLOT_COUNT {
            return Err(invalid(
                "cleanup_slot_count",
                format!("must equal the fixed namespace count {FIXED_CLEANUP_SLOT_COUNT}"),
            ));
        }
        if self.cleanup_slot_names.len() != slot_count
            || self.cleanup_slot_identities.len() != slot_count
        {
            return Err(invalid(
                "cleanup_slots",
                "name and identity lists must match the fixed slot count",
            ));
        }
        if self.cleanup_slot_names.len() as u64 > self.limits.max_collection_items
            || self.cleanup_slot_identities.len() as u64 > self.limits.max_collection_items
        {
            return Err(ProtocolError::Bounds {
                field: "cleanup_slots".to_string(),
                observed: slot_count,
                maximum: bounded_usize(self.limits.max_collection_items),
            });
        }
        let mut slot_names = BTreeSet::new();
        for (index, name) in self.cleanup_slot_names.iter().enumerate() {
            validate_string_with_limit("cleanup_slot_name", name, self.limits.max_string_bytes)?;
            let expected = format!("slot-{index:02}");
            if name != &expected {
                return Err(invalid(
                    "cleanup_slot_name",
                    "must use the fixed slot-00..slot-63 namespace",
                ));
            }
            if !slot_names.insert(name) {
                return Err(invalid("cleanup_slot_name", "slot names must be unique"));
            }
        }
        for identity in &self.cleanup_slot_identities {
            identity.validate()?;
        }
        let fixed = [
            ("parent_directory", self.parent_directory),
            ("pool_directory", self.pool_directory),
            ("pool_lock", self.pool_lock),
            ("binding_file", self.binding_file),
            ("authority_current", self.authority_pair.current),
            ("state_canonical", self.publication_roles.state_canonical),
            ("state_staging", self.publication_roles.state_staging),
            (
                "checkpoint_canonical",
                self.publication_roles.checkpoint_canonical,
            ),
            (
                "checkpoint_staging",
                self.publication_roles.checkpoint_staging,
            ),
            ("journal_primary", self.publication_roles.journal_primary),
            (
                "journal_secondary",
                self.publication_roles.journal_secondary,
            ),
        ];
        let mut seen = BTreeSet::new();
        for (name, identity) in fixed {
            identity.validate()?;
            if !seen.insert(identity) {
                let first = fixed
                    .iter()
                    .find(|(_, previous)| *previous == identity)
                    .map_or(name, |(previous, _)| *previous);
                return Err(ProtocolError::RoleIdentityAlias {
                    first,
                    second: name,
                });
            }
        }
        for (index, identity) in self.cleanup_slot_identities.iter().enumerate() {
            if !seen.insert(*identity) {
                return Err(ProtocolError::RoleIdentityAlias {
                    first: "fixed_publication_role",
                    second: "cleanup_slot",
                });
            }
            if self.cleanup_slot_names[index].is_empty() {
                return Err(invalid("cleanup_slot_name", "must not be empty"));
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        self.validate_unsigned()?;
        validate_digest("binding_digest", &self.binding_digest)?;
        if self.binding_digest != self.computed_digest()? {
            return Err(ProtocolError::DigestMismatch {
                field: "binding_digest",
            });
        }
        if self.binding_signature.algorithm != "ed25519"
            || self.binding_signature.key_id != self.signer_key_id
            || !swarm_crypto::PublicKey::from_hex(&self.binding_signature.public_key_hex)
                .map(|key| sha256_hex(key.as_bytes()) == self.signer_key_id)
                .unwrap_or(false)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        verify_detached_signature(&self.signing_bytes()?, &self.binding_signature)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePreimageV1 {
    pub schema_version: u32,
    pub stream_id: String,
    /// The complete committed predecessor is part of the candidate
    /// authority preimage.  `None` is reserved for the exact genesis
    /// predecessor; it is never a digest-only wildcard.
    pub predecessor_head: Option<WitnessHeadV1>,
    pub predecessor_head_digest: String,
    pub predecessor_data_head_digest: String,
    pub state_payload: Vec<u8>,
    pub state_byte_len: u64,
    pub state_digest: String,
    pub state_attestation: DetachedSignature,
    pub checkpoint_payload: Vec<u8>,
    pub checkpoint_byte_len: u64,
    pub checkpoint_digest: String,
    pub checkpoint_attestation: DetachedSignature,
    pub publication_binding: PublicationBindingV1,
    pub publication_mapping_before: PublicationMappingV1,
    pub publication_mapping_after: PublicationMappingV1,
    pub epoch: u64,
    pub sequence: u64,
    pub intent_counter: u64,
}

impl CandidatePreimageV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        self.publication_binding.limits.validate()?;
        validate_string_with_limit(
            "stream_id",
            &self.stream_id,
            self.publication_binding.limits.max_string_bytes,
        )?;
        validate_digest("predecessor_head_digest", &self.predecessor_head_digest)?;
        validate_digest(
            "predecessor_data_head_digest",
            &self.predecessor_data_head_digest,
        )?;
        validate_payload("state_payload", &self.state_payload)?;
        validate_payload("checkpoint_payload", &self.checkpoint_payload)?;
        if self.state_payload.len() as u64 > self.publication_binding.limits.max_payload_bytes {
            return Err(ProtocolError::Bounds {
                field: "state_payload".to_string(),
                observed: self.state_payload.len(),
                maximum: bounded_usize(self.publication_binding.limits.max_payload_bytes),
            });
        }
        if self.checkpoint_payload.len() as u64 > self.publication_binding.limits.max_payload_bytes
        {
            return Err(ProtocolError::Bounds {
                field: "checkpoint_payload".to_string(),
                observed: self.checkpoint_payload.len(),
                maximum: bounded_usize(self.publication_binding.limits.max_payload_bytes),
            });
        }
        validate_canonical_json_payload("state_payload", &self.state_payload)?;
        validate_canonical_json_payload("checkpoint_payload", &self.checkpoint_payload)?;
        validate_digest("state_digest", &self.state_digest)?;
        validate_digest("checkpoint_digest", &self.checkpoint_digest)?;
        self.publication_binding.validate()?;
        validate_signed_payload(SignedPayloadExpectation {
            field: "state_attestation",
            domain: STATE_PAYLOAD_DOMAIN_V1,
            stream_id: &self.stream_id,
            binding_generation: &self.publication_binding.generation,
            binding_digest: &self.publication_binding.binding_digest,
            authority_pair: self.publication_binding.authority_pair,
            payload: &self.state_payload,
            byte_len: self.state_byte_len,
            digest: &self.state_digest,
            signer_key_id: &self.publication_binding.signer_key_id,
            attestation: &self.state_attestation,
        })?;
        validate_signed_payload(SignedPayloadExpectation {
            field: "checkpoint_attestation",
            domain: CHECKPOINT_PAYLOAD_DOMAIN_V1,
            stream_id: &self.stream_id,
            binding_generation: &self.publication_binding.generation,
            binding_digest: &self.publication_binding.binding_digest,
            authority_pair: self.publication_binding.authority_pair,
            payload: &self.checkpoint_payload,
            byte_len: self.checkpoint_byte_len,
            digest: &self.checkpoint_digest,
            signer_key_id: &self.publication_binding.signer_key_id,
            attestation: &self.checkpoint_attestation,
        })?;
        self.publication_mapping_before
            .validate_against(&self.publication_binding.publication_roles)?;
        self.publication_mapping_after
            .validate_against(&self.publication_binding.publication_roles)?;
        self.publication_mapping_after
            .validate_successor_of(&self.publication_mapping_before)?;
        if self.publication_binding.stream_id != self.stream_id {
            return Err(invalid("stream_id", "does not match publication binding"));
        }
        validate_embedded_predecessor(EmbeddedPredecessorValidation {
            predecessor: self.predecessor_head.as_ref(),
            stream_id: &self.stream_id,
            binding_generation: &self.publication_binding.generation,
            binding_digest: &self.publication_binding.binding_digest,
            signer_key_id: &self.publication_binding.signer_key_id,
            witness_key_id: &self.publication_binding.witness_key_id,
            authority_pair: self.publication_binding.authority_pair,
            publication_mapping_before: &self.publication_mapping_before,
            predecessor_head_digest: &self.predecessor_head_digest,
            predecessor_data_head_digest: &self.predecessor_data_head_digest,
            epoch: self.epoch,
            sequence: self.sequence,
            intent_counter: self.intent_counter,
        })?;
        let state_len =
            u64::try_from(self.state_payload.len()).map_err(|_| ProtocolError::Overflow {
                counter: "state_payload_size",
            })?;
        let checkpoint_len =
            u64::try_from(self.checkpoint_payload.len()).map_err(|_| ProtocolError::Overflow {
                counter: "checkpoint_payload_size",
            })?;
        if self.state_byte_len != state_len || sha256_hex(&self.state_payload) != self.state_digest
        {
            return Err(ProtocolError::DigestMismatch {
                field: "state_payload",
            });
        }
        if self.checkpoint_byte_len != checkpoint_len
            || sha256_hex(&self.checkpoint_payload) != self.checkpoint_digest
        {
            return Err(ProtocolError::DigestMismatch {
                field: "checkpoint_payload",
            });
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        let bytes = canonical_wire_bytes(self)?;
        if bytes.len() as u64 > self.publication_binding.limits.max_record_bytes {
            return Err(ProtocolError::Bounds {
                field: "candidate_preimage".to_string(),
                observed: bytes.len(),
                maximum: bounded_usize(self.publication_binding.limits.max_record_bytes),
            });
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> ProtocolResult<Self> {
        let value = decode_canonical::<Self>(bytes)?;
        value.validate()?;
        Ok(value)
    }

    pub fn candidate_digest(&self) -> ProtocolResult<String> {
        digest_domain(CANDIDATE_DOMAIN_V1, &self.canonical_bytes()?)
    }

    pub fn txid(&self, candidate_digest: &str) -> ProtocolResult<String> {
        validate_digest("candidate_digest", candidate_digest)?;
        if self.candidate_digest()? != candidate_digest {
            return Err(ProtocolError::DigestMismatch {
                field: "candidate_digest",
            });
        }
        let preimage = TxidPreimageV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: self.stream_id.clone(),
            predecessor_head_digest: self.predecessor_head_digest.clone(),
            candidate_digest: candidate_digest.to_string(),
            binding_generation: self.publication_binding.generation.clone(),
            binding_digest: self.publication_binding.binding_digest.clone(),
            authority_pair: self.publication_binding.authority_pair,
            epoch: self.epoch,
            sequence: self.sequence,
            intent_counter: self.intent_counter,
        };
        preimage.txid()
    }

    pub fn build(&self) -> ProtocolResult<CandidateV1> {
        let digest = self.candidate_digest()?;
        let txid = self.txid(&digest)?;
        Ok(CandidateV1 {
            preimage: self.clone(),
            candidate_digest: digest,
            txid,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxidPreimageV1 {
    pub schema_version: u32,
    pub stream_id: String,
    pub predecessor_head_digest: String,
    pub candidate_digest: String,
    pub binding_generation: String,
    pub binding_digest: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub epoch: u64,
    pub sequence: u64,
    pub intent_counter: u64,
}

impl TxidPreimageV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_string("stream_id", &self.stream_id)?;
        validate_digest("predecessor_head_digest", &self.predecessor_head_digest)?;
        validate_digest("candidate_digest", &self.candidate_digest)?;
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        self.authority_pair.validate()
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        canonical_wire_bytes(self)
    }

    pub fn decode(bytes: &[u8]) -> ProtocolResult<Self> {
        let value = decode_canonical::<Self>(bytes)?;
        value.validate()?;
        Ok(value)
    }

    pub fn txid(&self) -> ProtocolResult<String> {
        digest_domain(TXID_DOMAIN_V1, &self.canonical_bytes()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateV1 {
    pub preimage: CandidatePreimageV1,
    pub candidate_digest: String,
    pub txid: String,
}

/// Canonical bootstrap predecessor.  Absence is not a wildcard: it is this
/// exact digest, bound to the admitted stream, namespace generation, signer,
/// witness and authority pair at epoch/sequence/intent zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisPredecessorV1 {
    pub schema_version: u32,
    pub stream_id: String,
    pub binding_generation: String,
    pub binding_digest: String,
    pub signer_key_id: String,
    pub witness_key_id: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub epoch: u64,
    pub sequence: u64,
    pub intent_counter: u64,
}

impl GenesisPredecessorV1 {
    pub fn for_binding(binding: &PublicationBindingV1) -> Self {
        Self {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: binding.stream_id.clone(),
            binding_generation: binding.generation.clone(),
            binding_digest: binding.binding_digest.clone(),
            signer_key_id: binding.signer_key_id.clone(),
            witness_key_id: binding.witness_key_id.clone(),
            authority_pair: binding.authority_pair,
            epoch: 0,
            sequence: 0,
            intent_counter: 0,
        }
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_string("stream_id", &self.stream_id)?;
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        self.authority_pair.validate()?;
        if self.epoch != 0 || self.sequence != 0 || self.intent_counter != 0 {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        canonical_wire_bytes(self)
    }

    pub fn digest(&self) -> ProtocolResult<String> {
        digest_domain(GENESIS_PREDECESSOR_DOMAIN_V1, &self.canonical_bytes()?)
    }

    pub fn data_head_digest(&self) -> ProtocolResult<String> {
        digest_domain(GENESIS_DATA_HEAD_DOMAIN_V1, &self.canonical_bytes()?)
    }
}

struct EmbeddedPredecessorValidation<'a> {
    predecessor: Option<&'a WitnessHeadV1>,
    stream_id: &'a str,
    binding_generation: &'a str,
    binding_digest: &'a str,
    signer_key_id: &'a str,
    witness_key_id: &'a str,
    authority_pair: AuthorityPairIdentityV1,
    publication_mapping_before: &'a PublicationMappingV1,
    predecessor_head_digest: &'a str,
    predecessor_data_head_digest: &'a str,
    epoch: u64,
    sequence: u64,
    intent_counter: u64,
}

fn validate_embedded_predecessor(context: EmbeddedPredecessorValidation<'_>) -> ProtocolResult<()> {
    validate_digest("predecessor_head_digest", context.predecessor_head_digest)?;
    validate_digest(
        "predecessor_data_head_digest",
        context.predecessor_data_head_digest,
    )?;
    match context.predecessor {
        Some(predecessor) => {
            predecessor.validate_settled()?;
            if predecessor.stream_id != context.stream_id
                || predecessor.binding_generation != context.binding_generation
                || predecessor.binding_digest != context.binding_digest
                || predecessor.signer_key_id != context.signer_key_id
                || predecessor.witness_key_id != context.witness_key_id
                || predecessor.authority_pair != context.authority_pair
                || predecessor.publication_mapping != *context.publication_mapping_before
                || predecessor.head_digest()? != context.predecessor_head_digest
                || predecessor.data_head_digest()? != context.predecessor_data_head_digest
                || predecessor.epoch != context.epoch
                || context.sequence != checked_next_sequence(predecessor.sequence)?
                || context.intent_counter != checked_next_intent(predecessor.intent_counter)?
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
        None => {
            let genesis = GenesisPredecessorV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                stream_id: context.stream_id.to_string(),
                binding_generation: context.binding_generation.to_string(),
                binding_digest: context.binding_digest.to_string(),
                signer_key_id: context.signer_key_id.to_string(),
                witness_key_id: context.witness_key_id.to_string(),
                authority_pair: context.authority_pair,
                epoch: 0,
                sequence: 0,
                intent_counter: 0,
            };
            if genesis.digest()? != context.predecessor_head_digest
                || genesis.data_head_digest()? != context.predecessor_data_head_digest
                || context.epoch != 0
                || context.sequence != 0
                || context.intent_counter == 0
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
    }
    Ok(())
}

impl CandidateV1 {
    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        let bytes = canonical_wire_bytes(self)?;
        if bytes.len() > MAX_PROTOCOL_RECORD_BYTES {
            return Err(ProtocolError::Bounds {
                field: "candidate".to_string(),
                observed: bytes.len(),
                maximum: MAX_PROTOCOL_RECORD_BYTES,
            });
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> ProtocolResult<Self> {
        let value = decode_canonical::<Self>(bytes)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        let expected_candidate = self.preimage.candidate_digest()?;
        if expected_candidate != self.candidate_digest {
            return Err(ProtocolError::DigestMismatch {
                field: "candidate_digest",
            });
        }
        if self.preimage.txid(&self.candidate_digest)? != self.txid {
            return Err(ProtocolError::DigestMismatch { field: "txid" });
        }
        Ok(())
    }

    /// Authenticate the complete candidate while treating the predecessor's
    /// expected intent counter as an externally supplied relation. This seam
    /// exists only for the public Prepare verifier: it proves that every
    /// signed payload, binding, mapping, predecessor, digest, and transaction
    /// identity is valid before classifying an otherwise coherent old or
    /// skipped intent. It does not authorize a transition.
    pub(crate) fn validate_for_expected_intent(
        &self,
        expected_intent_counter: u64,
    ) -> ProtocolResult<bool> {
        let mut normalized = self.preimage.clone();
        normalized.intent_counter = expected_intent_counter;
        normalized.validate()?;

        let preimage_bytes = canonical_wire_bytes(&self.preimage)?;
        if preimage_bytes.len() as u64 > self.preimage.publication_binding.limits.max_record_bytes {
            return Err(ProtocolError::Bounds {
                field: "candidate_preimage".to_string(),
                observed: preimage_bytes.len(),
                maximum: bounded_usize(self.preimage.publication_binding.limits.max_record_bytes),
            });
        }
        let candidate_digest = digest_domain(CANDIDATE_DOMAIN_V1, &preimage_bytes)?;
        if self.candidate_digest != candidate_digest {
            return Err(ProtocolError::DigestMismatch {
                field: "candidate_digest",
            });
        }
        let txid = TxidPreimageV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: self.preimage.stream_id.clone(),
            predecessor_head_digest: self.preimage.predecessor_head_digest.clone(),
            candidate_digest,
            binding_generation: self.preimage.publication_binding.generation.clone(),
            binding_digest: self.preimage.publication_binding.binding_digest.clone(),
            authority_pair: self.preimage.publication_binding.authority_pair,
            epoch: self.preimage.epoch,
            sequence: self.preimage.sequence,
            intent_counter: self.preimage.intent_counter,
        }
        .txid()?;
        if self.txid != txid {
            return Err(ProtocolError::DigestMismatch { field: "txid" });
        }
        Ok(self.preimage.intent_counter == expected_intent_counter)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAbortSummaryV1 {
    pub txid: String,
    pub candidate_digest: String,
    pub predecessor_head_digest: String,
    pub epoch: u64,
    pub sequence: u64,
    /// The reserved intent counter consumed by this abort.  An abort does
    /// not allocate another counter after prepare: it publishes the exact
    /// counter already reserved by the prepared transaction.
    pub intent_counter: u64,
    pub binding_generation: String,
    pub binding_digest: String,
    pub signer_key_id: String,
    pub witness_key_id: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub publication_mapping: PublicationMappingV1,
    pub resulting_data_head_digest: String,
}

/// Stable committed-data identity. Intent outcome metadata is deliberately
/// excluded so an abort can advance the stream's intent head without changing
/// the data identity it preserves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WitnessDataHeadPreimageV1<'a> {
    schema_version: u32,
    stream_id: &'a str,
    epoch: u64,
    sequence: u64,
    state_digest: &'a str,
    state_byte_len: u64,
    checkpoint_digest: &'a str,
    checkpoint_byte_len: u64,
    binding_generation: &'a str,
    binding_digest: &'a str,
    authority_pair: AuthorityPairIdentityV1,
    publication_mapping: PublicationMappingV1,
}

impl WitnessAbortSummaryV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        validate_digest("txid", &self.txid)?;
        validate_digest("candidate_digest", &self.candidate_digest)?;
        validate_digest("predecessor_head_digest", &self.predecessor_head_digest)?;
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        validate_digest(
            "resulting_data_head_digest",
            &self.resulting_data_head_digest,
        )?;
        self.authority_pair.validate()?;
        self.publication_mapping.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessIntentOutcomeV1 {
    Committed {
        txid: String,
        candidate_digest: String,
        predecessor_head_digest: String,
        intent_counter: u64,
    },
    Aborted(Box<WitnessAbortSummaryV1>),
}

impl WitnessIntentOutcomeV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        match self {
            Self::Committed {
                txid,
                candidate_digest,
                predecessor_head_digest,
                intent_counter: _,
            } => {
                validate_digest("txid", txid)?;
                validate_digest("candidate_digest", candidate_digest)?;
                validate_digest("predecessor_head_digest", predecessor_head_digest)
            }
            Self::Aborted(summary) => summary.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessHeadV1 {
    pub schema_version: u32,
    pub stream_id: String,
    pub txid: String,
    pub candidate_digest: String,
    pub epoch: u64,
    pub sequence: u64,
    pub intent_counter: u64,
    pub binding_generation: String,
    pub binding_digest: String,
    pub signer_key_id: String,
    pub witness_key_id: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub state_digest: String,
    pub state_byte_len: u64,
    pub checkpoint_digest: String,
    pub checkpoint_byte_len: u64,
    pub publication_mapping: PublicationMappingV1,
    pub last_intent_outcome: Option<WitnessIntentOutcomeV1>,
}

impl WitnessHeadV1 {
    pub fn from_candidate(candidate: &CandidateV1) -> ProtocolResult<Self> {
        candidate.validate()?;
        let preimage = &candidate.preimage;
        Ok(Self {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: preimage.stream_id.clone(),
            txid: candidate.txid.clone(),
            candidate_digest: candidate.candidate_digest.clone(),
            epoch: preimage.epoch,
            sequence: preimage.sequence,
            intent_counter: preimage.intent_counter,
            binding_generation: preimage.publication_binding.generation.clone(),
            binding_digest: preimage.publication_binding.binding_digest.clone(),
            signer_key_id: preimage.publication_binding.signer_key_id.clone(),
            witness_key_id: preimage.publication_binding.witness_key_id.clone(),
            authority_pair: preimage.publication_binding.authority_pair,
            state_digest: preimage.state_digest.clone(),
            state_byte_len: preimage.state_byte_len,
            checkpoint_digest: preimage.checkpoint_digest.clone(),
            checkpoint_byte_len: preimage.checkpoint_byte_len,
            publication_mapping: preimage.publication_mapping_after,
            last_intent_outcome: None,
        })
    }

    pub fn committed_from_candidate(candidate: &CandidateV1) -> ProtocolResult<Self> {
        let mut head = Self::from_candidate(candidate)?;
        head.last_intent_outcome = Some(WitnessIntentOutcomeV1::Committed {
            txid: head.txid.clone(),
            candidate_digest: head.candidate_digest.clone(),
            predecessor_head_digest: candidate.preimage.predecessor_head_digest.clone(),
            intent_counter: head.intent_counter,
        });
        head.validate()?;
        Ok(head)
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_string("stream_id", &self.stream_id)?;
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        self.authority_pair.validate()?;
        validate_digest("txid", &self.txid)?;
        validate_digest("candidate_digest", &self.candidate_digest)?;
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        validate_digest("state_digest", &self.state_digest)?;
        validate_digest("checkpoint_digest", &self.checkpoint_digest)?;
        self.authority_pair.validate()?;
        self.publication_mapping.validate()?;
        if let Some(outcome) = &self.last_intent_outcome {
            outcome.validate()?;
            match outcome {
                WitnessIntentOutcomeV1::Committed {
                    txid,
                    candidate_digest,
                    intent_counter,
                    ..
                } if txid == &self.txid
                    && candidate_digest == &self.candidate_digest
                    && intent_counter == &self.intent_counter => {}
                WitnessIntentOutcomeV1::Aborted(summary)
                    if summary.resulting_data_head_digest == self.data_head_digest()?
                        && summary.intent_counter == self.intent_counter
                        && summary.binding_generation == self.binding_generation
                        && summary.binding_digest == self.binding_digest
                        && summary.signer_key_id == self.signer_key_id
                        && summary.witness_key_id == self.witness_key_id
                        && summary.authority_pair == self.authority_pair
                        && summary.publication_mapping == self.publication_mapping => {}
                _ => return Err(ProtocolError::WitnessOutcomeMismatch),
            }
        }
        if self.state_byte_len > MAX_PROTOCOL_PAYLOAD_BYTES as u64
            || self.checkpoint_byte_len > MAX_PROTOCOL_PAYLOAD_BYTES as u64
        {
            return Err(invalid(
                "payload_byte_len",
                "payload exceeds configured bound",
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        canonical_wire_bytes(self)
    }

    pub fn head_digest(&self) -> ProtocolResult<String> {
        digest_domain(WITNESS_HEAD_DOMAIN_V1, &self.canonical_bytes()?)
    }

    pub fn validate_settled(&self) -> ProtocolResult<()> {
        self.validate()?;
        if self.last_intent_outcome.is_none() {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    pub fn validate_prepared_successor(&self) -> ProtocolResult<()> {
        self.validate()?;
        if self.last_intent_outcome.is_some() {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    pub fn data_head_digest(&self) -> ProtocolResult<String> {
        let preimage = WitnessDataHeadPreimageV1 {
            schema_version: self.schema_version,
            stream_id: &self.stream_id,
            epoch: self.epoch,
            sequence: self.sequence,
            state_digest: &self.state_digest,
            state_byte_len: self.state_byte_len,
            checkpoint_digest: &self.checkpoint_digest,
            checkpoint_byte_len: self.checkpoint_byte_len,
            binding_generation: &self.binding_generation,
            binding_digest: &self.binding_digest,
            authority_pair: self.authority_pair,
            publication_mapping: self.publication_mapping,
        };
        digest_domain(
            WITNESS_DATA_HEAD_DOMAIN_V1,
            &canonical_wire_bytes(&preimage)?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSessionFenceRequestV1 {
    pub schema_version: u32,
    pub stream_id: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub binding_generation: String,
    pub binding_digest: String,
    pub signer_key_id: String,
    pub witness_key_id: String,
    pub witness_identity: String,
    pub requester_nonce: String,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WitnessSessionFenceRequestPreimageV1<'a> {
    schema_version: u32,
    stream_id: &'a str,
    authority_pair: AuthorityPairIdentityV1,
    binding_generation: &'a str,
    binding_digest: &'a str,
    signer_key_id: &'a str,
    witness_key_id: &'a str,
    witness_identity: &'a str,
    requester_nonce: &'a str,
}

impl WitnessSessionFenceRequestV1 {
    pub fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        let canonical = canonical_wire_bytes(&WitnessSessionFenceRequestPreimageV1 {
            schema_version: self.schema_version,
            stream_id: &self.stream_id,
            authority_pair: self.authority_pair,
            binding_generation: &self.binding_generation,
            binding_digest: &self.binding_digest,
            signer_key_id: &self.signer_key_id,
            witness_key_id: &self.witness_key_id,
            witness_identity: &self.witness_identity,
            requester_nonce: &self.requester_nonce,
        })?;
        domain_separated_bytes(WITNESS_FENCE_REQUEST_DOMAIN_V1, &canonical)
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_string("stream_id", &self.stream_id)?;
        self.authority_pair.validate()?;
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        validate_string("witness_identity", &self.witness_identity)?;
        validate_digest("requester_nonce", &self.requester_nonce)?;
        if self.signature.algorithm != "ed25519"
            || self.signature.key_id != self.signer_key_id
            || !swarm_crypto::PublicKey::from_hex(&self.signature.public_key_hex)
                .map(|key| sha256_hex(key.as_bytes()) == self.signer_key_id)
                .unwrap_or(false)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        verify_detached_signature(&self.signing_bytes()?, &self.signature)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        canonical_wire_bytes(self)
    }

    pub fn request_digest(&self) -> ProtocolResult<String> {
        digest_domain(WITNESS_FENCE_REQUEST_DOMAIN_V1, &self.canonical_bytes()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessSessionStateSnapshotV1 {
    pub admission_digest: String,
    pub bucket_epoch_digest: String,
    pub bucket_anchor_digest: String,
    pub ready_manifest_digest: String,
    pub store_state_digest: String,
    pub current_session: Option<WitnessSessionV1>,
    pub current_head: Option<WitnessHeadV1>,
    pub current_prepared: Option<WitnessPreparedV1>,
}

impl WitnessSessionStateSnapshotV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        validate_digest("admission_digest", &self.admission_digest)?;
        validate_digest("bucket_epoch_digest", &self.bucket_epoch_digest)?;
        validate_digest("bucket_anchor_digest", &self.bucket_anchor_digest)?;
        validate_digest("ready_manifest_digest", &self.ready_manifest_digest)?;
        validate_digest("store_state_digest", &self.store_state_digest)?;
        if let Some(session) = &self.current_session {
            session.validate()?;
            WitnessDiscoveryV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                head: self.current_head.clone(),
                prepared: self.current_prepared.clone(),
                genesis_abort: None,
                recovery_session: session.clone(),
            }
            .validate()?;
        } else {
            if let Some(head) = &self.current_head {
                head.validate_settled()?;
            }
            if let Some(prepared) = &self.current_prepared {
                prepared.validate()?;
                match (&self.current_head, &prepared.predecessor_head) {
                    (Some(current), Some(predecessor)) if current == predecessor => {}
                    (None, None) => {}
                    _ => return Err(ProtocolError::WitnessOutcomeMismatch),
                }
            }
        }
        Ok(())
    }

    fn current_session_generation(&self) -> Option<u64> {
        self.current_session
            .as_ref()
            .map(|session| session.session_generation)
    }

    fn current_session_digest(&self) -> ProtocolResult<Option<String>> {
        self.current_session
            .as_ref()
            .map(|session| {
                digest_domain(
                    WITNESS_SESSION_STATE_DOMAIN_V1,
                    &canonical_wire_bytes(session)?,
                )
            })
            .transpose()
    }

    fn current_head_digest(&self) -> ProtocolResult<Option<String>> {
        self.current_head
            .as_ref()
            .map(WitnessHeadV1::head_digest)
            .transpose()
    }

    fn current_prepared_digest(&self) -> ProtocolResult<Option<String>> {
        self.current_prepared
            .as_ref()
            .map(|prepared| {
                digest_domain(
                    WITNESS_PREPARED_STATE_DOMAIN_V1,
                    &canonical_wire_bytes(prepared)?,
                )
            })
            .transpose()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSessionStateFenceV1 {
    pub schema_version: u32,
    pub request: WitnessSessionFenceRequestV1,
    pub admission_digest: String,
    pub bucket_epoch_digest: String,
    pub bucket_anchor_digest: String,
    pub ready_manifest_digest: String,
    pub store_state_digest: String,
    pub current_session_generation: Option<u64>,
    pub current_session_digest: Option<String>,
    pub current_head_digest: Option<String>,
    pub current_prepared_digest: Option<String>,
    pub witness_nonce: String,
    pub witness_identity: String,
    pub witness_key_id: String,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WitnessSessionStateFencePreimageV1<'a> {
    schema_version: u32,
    request: &'a WitnessSessionFenceRequestV1,
    admission_digest: &'a str,
    bucket_epoch_digest: &'a str,
    bucket_anchor_digest: &'a str,
    ready_manifest_digest: &'a str,
    store_state_digest: &'a str,
    current_session_generation: Option<u64>,
    current_session_digest: &'a Option<String>,
    current_head_digest: &'a Option<String>,
    current_prepared_digest: &'a Option<String>,
    witness_nonce: &'a str,
    witness_identity: &'a str,
    witness_key_id: &'a str,
}

impl WitnessSessionStateFenceV1 {
    pub fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        let canonical = canonical_wire_bytes(&WitnessSessionStateFencePreimageV1 {
            schema_version: self.schema_version,
            request: &self.request,
            admission_digest: &self.admission_digest,
            bucket_epoch_digest: &self.bucket_epoch_digest,
            bucket_anchor_digest: &self.bucket_anchor_digest,
            ready_manifest_digest: &self.ready_manifest_digest,
            store_state_digest: &self.store_state_digest,
            current_session_generation: self.current_session_generation,
            current_session_digest: &self.current_session_digest,
            current_head_digest: &self.current_head_digest,
            current_prepared_digest: &self.current_prepared_digest,
            witness_nonce: &self.witness_nonce,
            witness_identity: &self.witness_identity,
            witness_key_id: &self.witness_key_id,
        })?;
        domain_separated_bytes(WITNESS_STATE_FENCE_DOMAIN_V1, &canonical)
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        self.request.validate()?;
        validate_digest("admission_digest", &self.admission_digest)?;
        validate_digest("bucket_epoch_digest", &self.bucket_epoch_digest)?;
        validate_digest("bucket_anchor_digest", &self.bucket_anchor_digest)?;
        validate_digest("ready_manifest_digest", &self.ready_manifest_digest)?;
        validate_digest("store_state_digest", &self.store_state_digest)?;
        match (
            self.current_session_generation,
            self.current_session_digest.as_deref(),
        ) {
            (None, None) => {}
            (Some(generation), Some(digest)) if generation > 0 => {
                validate_digest("current_session_digest", digest)?;
            }
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        }
        if let Some(digest) = &self.current_head_digest {
            validate_digest("current_head_digest", digest)?;
        }
        if let Some(digest) = &self.current_prepared_digest {
            validate_digest("current_prepared_digest", digest)?;
        }
        validate_digest("witness_nonce", &self.witness_nonce)?;
        validate_string("witness_identity", &self.witness_identity)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        if self.witness_nonce == self.request.requester_nonce
            || self.witness_identity != self.request.witness_identity
            || self.witness_key_id != self.request.witness_key_id
            || self.signature.algorithm != "ed25519"
            || self.signature.key_id != self.witness_key_id
            || !swarm_crypto::PublicKey::from_hex(&self.signature.public_key_hex)
                .map(|key| sha256_hex(key.as_bytes()) == self.witness_key_id)
                .unwrap_or(false)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        verify_detached_signature(&self.signing_bytes()?, &self.signature)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        canonical_wire_bytes(self)
    }

    pub fn state_fence_digest(&self) -> ProtocolResult<String> {
        digest_domain(WITNESS_STATE_FENCE_DOMAIN_V1, &self.canonical_bytes()?)
    }

    pub fn verify_for_snapshot(
        &self,
        snapshot: &WitnessSessionStateSnapshotV1,
    ) -> ProtocolResult<()> {
        self.validate()?;
        snapshot.validate()?;
        if self.admission_digest != snapshot.admission_digest
            || self.bucket_epoch_digest != snapshot.bucket_epoch_digest
            || self.bucket_anchor_digest != snapshot.bucket_anchor_digest
            || self.ready_manifest_digest != snapshot.ready_manifest_digest
            || self.store_state_digest != snapshot.store_state_digest
            || self.current_session_generation != snapshot.current_session_generation()
            || self.current_session_digest != snapshot.current_session_digest()?
            || self.current_head_digest != snapshot.current_head_digest()?
            || self.current_prepared_digest != snapshot.current_prepared_digest()?
            || snapshot.current_session.as_ref().is_some_and(|session| {
                session.stream_id != self.request.stream_id
                    || session.authority_pair != self.request.authority_pair
                    || session.binding_generation != self.request.binding_generation
                    || session.binding_digest != self.request.binding_digest
                    || session.signer_key_id != self.request.signer_key_id
                    || session.witness_key_id != self.request.witness_key_id
                    || session.witness_identity != self.request.witness_identity
            })
            || snapshot.current_head.as_ref().is_some_and(|head| {
                head.stream_id != self.request.stream_id
                    || head.authority_pair != self.request.authority_pair
                    || head.binding_generation != self.request.binding_generation
                    || head.binding_digest != self.request.binding_digest
                    || head.signer_key_id != self.request.signer_key_id
                    || head.witness_key_id != self.request.witness_key_id
            })
            || snapshot.current_prepared.as_ref().is_some_and(|prepared| {
                prepared.head.stream_id != self.request.stream_id
                    || prepared.head.authority_pair != self.request.authority_pair
                    || prepared.head.binding_generation != self.request.binding_generation
                    || prepared.head.binding_digest != self.request.binding_digest
                    || prepared.head.signer_key_id != self.request.signer_key_id
                    || prepared.head.witness_key_id != self.request.witness_key_id
            })
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    pub fn expected_session_generation(&self) -> ProtocolResult<u64> {
        checked_next_session(self.current_session_generation.unwrap_or(0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSessionV1 {
    pub schema_version: u32,
    pub stream_id: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub binding_generation: String,
    pub binding_digest: String,
    pub signer_key_id: String,
    pub witness_key_id: String,
    pub ephemeral_key_id: String,
    pub witness_identity: String,
    pub session_generation: u64,
    pub session_commitment: String,
}

impl WitnessSessionV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_string("stream_id", &self.stream_id)?;
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        validate_digest("ephemeral_key_id", &self.ephemeral_key_id)?;
        validate_string("witness_identity", &self.witness_identity)?;
        if self.session_generation == 0 {
            return Err(invalid(
                "session_generation",
                "generation zero is the absent-session baseline",
            ));
        }
        validate_digest("session_commitment", &self.session_commitment)?;
        self.authority_pair.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryChallengeV1 {
    pub schema_version: u32,
    pub stream_id: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub binding_generation: String,
    pub binding_digest: String,
    pub signer_key_id: String,
    pub witness_key_id: String,
    pub witness_identity: String,
    pub state_fence: WitnessSessionStateFenceV1,
    pub ephemeral_key_id: String,
    pub nonce: String,
    pub session_commitment: String,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RecoveryChallengePreimageV1<'a> {
    schema_version: u32,
    stream_id: &'a str,
    authority_pair: AuthorityPairIdentityV1,
    binding_generation: &'a str,
    binding_digest: &'a str,
    signer_key_id: &'a str,
    witness_key_id: &'a str,
    witness_identity: &'a str,
    state_fence: &'a WitnessSessionStateFenceV1,
    ephemeral_key_id: &'a str,
    nonce: &'a str,
    session_commitment: &'a str,
}

impl RecoveryChallengeV1 {
    pub fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        let canonical = canonical_wire_bytes(&RecoveryChallengePreimageV1 {
            schema_version: self.schema_version,
            stream_id: &self.stream_id,
            authority_pair: self.authority_pair,
            binding_generation: &self.binding_generation,
            binding_digest: &self.binding_digest,
            signer_key_id: &self.signer_key_id,
            witness_key_id: &self.witness_key_id,
            witness_identity: &self.witness_identity,
            state_fence: &self.state_fence,
            ephemeral_key_id: &self.ephemeral_key_id,
            nonce: &self.nonce,
            session_commitment: &self.session_commitment,
        })?;
        domain_separated_bytes(WITNESS_ROTATION_CHALLENGE_DOMAIN_V1, &canonical)
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_string("stream_id", &self.stream_id)?;
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        validate_string("witness_identity", &self.witness_identity)?;
        self.state_fence.validate()?;
        validate_digest("ephemeral_key_id", &self.ephemeral_key_id)?;
        validate_digest("nonce", &self.nonce)?;
        validate_digest("session_commitment", &self.session_commitment)?;
        if self.nonce == self.session_commitment
            || self.nonce == self.state_fence.witness_nonce
            || self.nonce == self.state_fence.request.requester_nonce
            || self.stream_id != self.state_fence.request.stream_id
            || self.authority_pair != self.state_fence.request.authority_pair
            || self.binding_generation != self.state_fence.request.binding_generation
            || self.binding_digest != self.state_fence.request.binding_digest
            || self.signer_key_id != self.state_fence.request.signer_key_id
            || self.witness_key_id != self.state_fence.request.witness_key_id
            || self.witness_identity != self.state_fence.request.witness_identity
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        self.authority_pair.validate()?;
        if self.signature.algorithm != "ed25519"
            || self.signature.key_id != self.signer_key_id
            || !swarm_crypto::PublicKey::from_hex(&self.signature.public_key_hex)
                .map(|key| sha256_hex(key.as_bytes()) == self.signer_key_id)
                .unwrap_or(false)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        verify_detached_signature(&self.signing_bytes()?, &self.signature)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        canonical_wire_bytes(self)
    }

    pub fn challenge_digest(&self) -> ProtocolResult<String> {
        digest_domain(
            WITNESS_ROTATION_CHALLENGE_DOMAIN_V1,
            &self.canonical_bytes()?,
        )
    }

    pub fn expected_session_generation(&self) -> ProtocolResult<u64> {
        self.state_fence.expected_session_generation()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessPreparedV1 {
    pub schema_version: u32,
    pub predecessor_head: Option<WitnessHeadV1>,
    pub head: WitnessHeadV1,
    pub predecessor_head_digest: String,
    pub predecessor_data_head_digest: String,
    pub binding_digest: String,
    pub predecessor_publication_mapping: PublicationMappingV1,
    pub session_generation: u64,
    /// The authenticated bootstrap-abort receipt authorizing a non-initial
    /// intent counter while the predecessor head is still absent.  `None`
    /// means the only valid absent-head counter is the genesis counter one.
    pub genesis_abort: Option<WitnessGenesisAbortedV1>,
}

impl WitnessPreparedV1 {
    pub fn from_candidate(
        candidate: &CandidateV1,
        predecessor_head: Option<WitnessHeadV1>,
        session_generation: u64,
    ) -> ProtocolResult<Self> {
        Self::from_candidate_internal(candidate, predecessor_head, session_generation, None)
    }

    /// Build the next bootstrap candidate only from the authenticated abort
    /// receipt that consumed the previous absent-head intent.  An arbitrary
    /// `None` predecessor is never sufficient to advance the counter.
    pub fn from_candidate_after_genesis_abort(
        candidate: &CandidateV1,
        verified: &VerifiedWitnessOutcomeV1,
        session_generation: u64,
    ) -> ProtocolResult<Self> {
        let aborted = match (verified.operation(), verified.outcome()) {
            (WitnessOperationV1::Abort, WitnessOperationOutcomeV1::Abort(outcome)) => {
                match outcome.as_ref() {
                    WitnessAbortOutcomeV1::GenesisAborted(aborted) => aborted,
                    _ => return Err(ProtocolError::WitnessOutcomeMismatch),
                }
            }
            (WitnessOperationV1::Commit, WitnessOperationOutcomeV1::Commit(outcome)) => {
                match outcome.as_ref() {
                    WitnessCommitOutcomeV1::GenesisAborted(aborted) => aborted,
                    _ => return Err(ProtocolError::WitnessOutcomeMismatch),
                }
            }
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        };
        aborted.validate()?;
        Self::from_candidate_internal(candidate, None, session_generation, Some(aborted.clone()))
    }

    fn from_candidate_internal(
        candidate: &CandidateV1,
        predecessor_head: Option<WitnessHeadV1>,
        session_generation: u64,
        genesis_abort: Option<WitnessGenesisAbortedV1>,
    ) -> ProtocolResult<Self> {
        candidate.validate()?;
        if predecessor_head.as_ref() != candidate.preimage.predecessor_head.as_ref() {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let predecessor_head = candidate.preimage.predecessor_head.clone();
        if let Some(predecessor) = predecessor_head.as_ref() {
            if genesis_abort.is_some() {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
            predecessor.validate_settled()?;
            if predecessor.head_digest()? != candidate.preimage.predecessor_head_digest
                || predecessor.data_head_digest()?
                    != candidate.preimage.predecessor_data_head_digest
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        } else {
            let genesis =
                GenesisPredecessorV1::for_binding(&candidate.preimage.publication_binding);
            let expected_intent_counter = match genesis_abort.as_ref() {
                Some(aborted) => {
                    if aborted.predecessor_head_digest != genesis.digest()?
                        || aborted.resulting_data_head_digest != genesis.data_head_digest()?
                        || aborted.stream_id != candidate.preimage.stream_id
                        || aborted.binding_generation
                            != candidate.preimage.publication_binding.generation
                        || aborted.binding_digest
                            != candidate.preimage.publication_binding.binding_digest
                        || aborted.signer_key_id
                            != candidate.preimage.publication_binding.signer_key_id
                        || aborted.witness_key_id
                            != candidate.preimage.publication_binding.witness_key_id
                        || aborted.authority_pair
                            != candidate.preimage.publication_binding.authority_pair
                        || aborted.publication_mapping
                            != candidate.preimage.publication_mapping_before
                    {
                        return Err(ProtocolError::WitnessOutcomeMismatch);
                    }
                    checked_next_intent(aborted.intent_counter)?
                }
                None => 1,
            };
            if genesis.digest()? != candidate.preimage.predecessor_head_digest
                || genesis.data_head_digest()? != candidate.preimage.predecessor_data_head_digest
                || candidate.preimage.epoch != 0
                || candidate.preimage.sequence != 0
                || candidate.preimage.intent_counter != expected_intent_counter
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
        let head = WitnessHeadV1::from_candidate(candidate)?;
        let prepared = Self {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            predecessor_head,
            head,
            predecessor_head_digest: candidate.preimage.predecessor_head_digest.clone(),
            predecessor_data_head_digest: candidate.preimage.predecessor_data_head_digest.clone(),
            binding_digest: candidate
                .preimage
                .publication_binding
                .binding_digest
                .clone(),
            predecessor_publication_mapping: candidate.preimage.publication_mapping_before,
            session_generation,
            genesis_abort,
        };
        prepared.validate()?;
        Ok(prepared)
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        if self.session_generation == 0 {
            return Err(invalid(
                "session_generation",
                "generation zero is the absent-session baseline",
            ));
        }
        self.head.validate_prepared_successor()?;
        validate_digest("predecessor_head_digest", &self.predecessor_head_digest)?;
        validate_digest(
            "predecessor_data_head_digest",
            &self.predecessor_data_head_digest,
        )?;
        validate_digest("binding_digest", &self.binding_digest)?;
        if self.binding_digest != self.head.binding_digest {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        self.predecessor_publication_mapping.validate()?;
        match &self.predecessor_head {
            Some(predecessor) => {
                if self.genesis_abort.is_some() {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
                predecessor.validate_settled()?;
                if predecessor.head_digest()? != self.predecessor_head_digest
                    || predecessor.data_head_digest()? != self.predecessor_data_head_digest
                    || self.predecessor_publication_mapping != predecessor.publication_mapping
                    || self.head.stream_id != predecessor.stream_id
                    || self.head.binding_generation != predecessor.binding_generation
                    || self.head.binding_digest != predecessor.binding_digest
                    || self.head.signer_key_id != predecessor.signer_key_id
                    || self.head.witness_key_id != predecessor.witness_key_id
                    || self.head.authority_pair != predecessor.authority_pair
                    || self.head.epoch != predecessor.epoch
                    || self.head.sequence != checked_next_sequence(predecessor.sequence)?
                    || self.head.intent_counter != checked_next_intent(predecessor.intent_counter)?
                {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            }
            None => {
                let genesis = GenesisPredecessorV1 {
                    schema_version: PROTOCOL_SCHEMA_VERSION,
                    stream_id: self.head.stream_id.clone(),
                    binding_generation: self.head.binding_generation.clone(),
                    binding_digest: self.head.binding_digest.clone(),
                    signer_key_id: self.head.signer_key_id.clone(),
                    witness_key_id: self.head.witness_key_id.clone(),
                    authority_pair: self.head.authority_pair,
                    epoch: 0,
                    sequence: 0,
                    intent_counter: 0,
                };
                if self.genesis_abort.is_some() {
                    let aborted = self
                        .genesis_abort
                        .as_ref()
                        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
                    aborted.validate()?;
                    if aborted.predecessor_head_digest != genesis.digest()?
                        || aborted.resulting_data_head_digest != self.predecessor_data_head_digest
                        || self.head.intent_counter != checked_next_intent(aborted.intent_counter)?
                        || self.head.epoch != aborted.epoch
                        || self.head.sequence != aborted.sequence
                        || self.head.stream_id != aborted.stream_id
                        || self.head.binding_generation != aborted.binding_generation
                        || self.head.binding_digest != aborted.binding_digest
                        || self.head.signer_key_id != aborted.signer_key_id
                        || self.head.witness_key_id != aborted.witness_key_id
                        || self.head.authority_pair != aborted.authority_pair
                        || self.predecessor_publication_mapping != aborted.publication_mapping
                    {
                        return Err(ProtocolError::WitnessOutcomeMismatch);
                    }
                } else if genesis.digest()? != self.predecessor_head_digest
                    || self.predecessor_data_head_digest != genesis.data_head_digest()?
                    || self.head.epoch != 0
                    || self.head.sequence != 0
                    || self.head.intent_counter != 1
                {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            }
        }
        self.head
            .publication_mapping
            .validate_successor_of(&self.predecessor_publication_mapping)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessCommittedV1 {
    pub schema_version: u32,
    pub head: WitnessHeadV1,
}

impl WitnessCommittedV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        self.head.validate_settled()?;
        match &self.head.last_intent_outcome {
            Some(WitnessIntentOutcomeV1::Committed {
                txid,
                candidate_digest,
                ..
            }) if txid == &self.head.txid && candidate_digest == &self.head.candidate_digest => {
                Ok(())
            }
            _ => Err(ProtocolError::WitnessOutcomeMismatch),
        }
    }
}

/// An authenticated bootstrap abort has no committed payload-bearing head to
/// return.  It preserves the exact genesis predecessor/data identities while
/// consuming the prepared transaction's reserved intent counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessGenesisAbortedV1 {
    pub schema_version: u32,
    pub stream_id: String,
    pub txid: String,
    pub candidate_digest: String,
    pub predecessor_head_digest: String,
    pub resulting_data_head_digest: String,
    pub epoch: u64,
    pub sequence: u64,
    pub intent_counter: u64,
    pub binding_generation: String,
    pub binding_digest: String,
    pub signer_key_id: String,
    pub witness_key_id: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub publication_mapping: PublicationMappingV1,
    pub reason: String,
}

impl WitnessGenesisAbortedV1 {
    pub fn from_prepared(prepared: &WitnessPreparedV1, reason: String) -> ProtocolResult<Self> {
        prepared.validate()?;
        if prepared.predecessor_head.is_some() {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let genesis = GenesisPredecessorV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: prepared.head.stream_id.clone(),
            binding_generation: prepared.head.binding_generation.clone(),
            binding_digest: prepared.head.binding_digest.clone(),
            signer_key_id: prepared.head.signer_key_id.clone(),
            witness_key_id: prepared.head.witness_key_id.clone(),
            authority_pair: prepared.head.authority_pair,
            epoch: 0,
            sequence: 0,
            intent_counter: 0,
        };
        if prepared.predecessor_head_digest != genesis.digest()?
            || prepared.head.epoch != 0
            || prepared.head.sequence != 0
            || prepared.head.intent_counter == 0
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let aborted = Self {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: prepared.head.stream_id.clone(),
            txid: prepared.head.txid.clone(),
            candidate_digest: prepared.head.candidate_digest.clone(),
            predecessor_head_digest: prepared.predecessor_head_digest.clone(),
            resulting_data_head_digest: genesis.data_head_digest()?,
            epoch: prepared.head.epoch,
            sequence: prepared.head.sequence,
            intent_counter: prepared.head.intent_counter,
            binding_generation: prepared.head.binding_generation.clone(),
            binding_digest: prepared.head.binding_digest.clone(),
            signer_key_id: prepared.head.signer_key_id.clone(),
            witness_key_id: prepared.head.witness_key_id.clone(),
            authority_pair: prepared.head.authority_pair,
            publication_mapping: prepared.predecessor_publication_mapping,
            reason,
        };
        aborted.validate_against_prepared(prepared)?;
        Ok(aborted)
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_string("stream_id", &self.stream_id)?;
        validate_digest("txid", &self.txid)?;
        validate_digest("candidate_digest", &self.candidate_digest)?;
        validate_digest("predecessor_head_digest", &self.predecessor_head_digest)?;
        validate_digest(
            "resulting_data_head_digest",
            &self.resulting_data_head_digest,
        )?;
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        validate_string("reason", &self.reason)?;
        self.authority_pair.validate()?;
        self.publication_mapping.validate()?;
        let genesis = GenesisPredecessorV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: self.stream_id.clone(),
            binding_generation: self.binding_generation.clone(),
            binding_digest: self.binding_digest.clone(),
            signer_key_id: self.signer_key_id.clone(),
            witness_key_id: self.witness_key_id.clone(),
            authority_pair: self.authority_pair,
            epoch: 0,
            sequence: 0,
            intent_counter: 0,
        };
        if self.epoch != 0
            || self.sequence != 0
            || self.intent_counter == 0
            || self.predecessor_head_digest != genesis.digest()?
            || self.resulting_data_head_digest != genesis.data_head_digest()?
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    pub fn validate_against_prepared(&self, prepared: &WitnessPreparedV1) -> ProtocolResult<()> {
        self.validate()?;
        prepared.validate()?;
        if prepared.predecessor_head.is_some()
            || self.stream_id != prepared.head.stream_id
            || self.txid != prepared.head.txid
            || self.candidate_digest != prepared.head.candidate_digest
            || self.predecessor_head_digest != prepared.predecessor_head_digest
            || self.resulting_data_head_digest != prepared.predecessor_data_head_digest
            || self.epoch != prepared.head.epoch
            || self.sequence != prepared.head.sequence
            || self.intent_counter != prepared.head.intent_counter
            || self.binding_generation != prepared.head.binding_generation
            || self.binding_digest != prepared.head.binding_digest
            || self.signer_key_id != prepared.head.signer_key_id
            || self.witness_key_id != prepared.head.witness_key_id
            || self.authority_pair != prepared.head.authority_pair
            || self.publication_mapping != prepared.predecessor_publication_mapping
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAbortedV1 {
    pub schema_version: u32,
    pub stream_id: String,
    pub txid: String,
    pub candidate_digest: String,
    pub predecessor_head_digest: String,
    pub epoch: u64,
    pub sequence: u64,
    pub intent_counter: u64,
    pub binding_generation: String,
    pub binding_digest: String,
    pub signer_key_id: String,
    pub witness_key_id: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub publication_mapping: PublicationMappingV1,
    pub resulting_head: WitnessHeadV1,
    pub reason: String,
}

impl WitnessAbortedV1 {
    pub fn intent_only(
        previous: &WitnessHeadV1,
        txid: String,
        candidate_digest: String,
        reason: String,
    ) -> ProtocolResult<Self> {
        // A local intent-only abort is valid only for an already committed
        // data head.  A prepared successor has a candidate-shaped head with
        // no terminal outcome and must be aborted through the authenticated
        // witness receipt, which preserves its reserved intent counter.
        previous.validate_settled()?;
        let predecessor_head_digest = previous.head_digest()?;
        let intent_counter = checked_next_intent(previous.intent_counter)?;
        let resulting_head = {
            let mut head = previous.clone();
            head.intent_counter = intent_counter;
            head.last_intent_outcome = Some(WitnessIntentOutcomeV1::Aborted(Box::new(
                WitnessAbortSummaryV1 {
                    txid: txid.clone(),
                    candidate_digest: candidate_digest.clone(),
                    predecessor_head_digest: predecessor_head_digest.clone(),
                    epoch: previous.epoch,
                    sequence: previous.sequence,
                    intent_counter,
                    binding_generation: previous.binding_generation.clone(),
                    binding_digest: previous.binding_digest.clone(),
                    signer_key_id: previous.signer_key_id.clone(),
                    witness_key_id: previous.witness_key_id.clone(),
                    authority_pair: previous.authority_pair,
                    publication_mapping: previous.publication_mapping,
                    resulting_data_head_digest: previous.data_head_digest()?,
                },
            )));
            head.validate_settled()?;
            head
        };
        let aborted = Self {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: previous.stream_id.clone(),
            txid,
            candidate_digest,
            predecessor_head_digest,
            epoch: previous.epoch,
            sequence: previous.sequence,
            intent_counter,
            binding_generation: previous.binding_generation.clone(),
            binding_digest: previous.binding_digest.clone(),
            signer_key_id: previous.signer_key_id.clone(),
            witness_key_id: previous.witness_key_id.clone(),
            authority_pair: previous.authority_pair,
            publication_mapping: previous.publication_mapping,
            resulting_head,
            reason,
        };
        aborted.validate_against_predecessor(previous)?;
        Ok(aborted)
    }

    /// Reconstruct a receipt from the authoritative current head after a
    /// lost abort response.  The head's authenticated last-outcome summary is
    /// the only source accepted here; callers cannot manufacture a receipt
    /// from a candidate-shaped head or an old transaction counter.
    pub fn from_resulting_head(
        resulting_head: &WitnessHeadV1,
        reason: String,
    ) -> ProtocolResult<Self> {
        resulting_head.validate_settled()?;
        let summary = match resulting_head.last_intent_outcome.as_ref() {
            Some(WitnessIntentOutcomeV1::Aborted(summary)) => (**summary).clone(),
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        };
        let receipt = Self {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: resulting_head.stream_id.clone(),
            txid: summary.txid,
            candidate_digest: summary.candidate_digest,
            predecessor_head_digest: summary.predecessor_head_digest,
            epoch: summary.epoch,
            sequence: summary.sequence,
            intent_counter: summary.intent_counter,
            binding_generation: summary.binding_generation,
            binding_digest: summary.binding_digest,
            signer_key_id: summary.signer_key_id,
            witness_key_id: summary.witness_key_id,
            authority_pair: summary.authority_pair,
            publication_mapping: summary.publication_mapping,
            resulting_head: resulting_head.clone(),
            reason,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_string("stream_id", &self.stream_id)?;
        validate_digest("txid", &self.txid)?;
        validate_digest("candidate_digest", &self.candidate_digest)?;
        validate_digest("predecessor_head_digest", &self.predecessor_head_digest)?;
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        validate_string("reason", &self.reason)?;
        self.authority_pair.validate()?;
        self.publication_mapping.validate()?;
        self.resulting_head.validate_settled()?;
        let expected_outcome = WitnessIntentOutcomeV1::Aborted(Box::new(WitnessAbortSummaryV1 {
            txid: self.txid.clone(),
            candidate_digest: self.candidate_digest.clone(),
            predecessor_head_digest: self.predecessor_head_digest.clone(),
            epoch: self.epoch,
            sequence: self.sequence,
            intent_counter: self.intent_counter,
            binding_generation: self.binding_generation.clone(),
            binding_digest: self.binding_digest.clone(),
            signer_key_id: self.resulting_head.signer_key_id.clone(),
            witness_key_id: self.resulting_head.witness_key_id.clone(),
            authority_pair: self.authority_pair,
            publication_mapping: self.publication_mapping,
            resulting_data_head_digest: self.resulting_head.data_head_digest()?,
        }));
        if self.resulting_head.stream_id != self.stream_id
            || self.resulting_head.intent_counter != self.intent_counter
            || self.resulting_head.binding_generation != self.binding_generation
            || self.resulting_head.binding_digest != self.binding_digest
            || self.resulting_head.signer_key_id != self.signer_key_id
            || self.resulting_head.witness_key_id != self.witness_key_id
            || self.resulting_head.authority_pair != self.authority_pair
            || self.resulting_head.publication_mapping != self.publication_mapping
            || self.resulting_head.last_intent_outcome.as_ref() != Some(&expected_outcome)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    pub fn validate_against_prepared(&self, prepared: &WitnessPreparedV1) -> ProtocolResult<()> {
        self.validate()?;
        prepared.validate()?;
        let predecessor = prepared
            .predecessor_head
            .as_ref()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        self.validate_against_predecessor(predecessor)?;
        if self.stream_id != prepared.head.stream_id
            || self.txid != prepared.head.txid
            || self.candidate_digest != prepared.head.candidate_digest
            || self.predecessor_head_digest != prepared.predecessor_head_digest
            || self.epoch != prepared.head.epoch
            || self.sequence != prepared.head.sequence
            || self.intent_counter != prepared.head.intent_counter
            || self.binding_generation != prepared.head.binding_generation
            || self.binding_digest != prepared.head.binding_digest
            || self.signer_key_id != prepared.head.signer_key_id
            || self.witness_key_id != prepared.head.witness_key_id
            || self.authority_pair != prepared.head.authority_pair
            || self.publication_mapping != prepared.predecessor_publication_mapping
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let mut expected_head = predecessor.clone();
        expected_head.intent_counter = self.intent_counter;
        expected_head.last_intent_outcome = Some(WitnessIntentOutcomeV1::Aborted(Box::new(
            WitnessAbortSummaryV1 {
                txid: self.txid.clone(),
                candidate_digest: self.candidate_digest.clone(),
                predecessor_head_digest: self.predecessor_head_digest.clone(),
                epoch: self.epoch,
                sequence: self.sequence,
                intent_counter: self.intent_counter,
                binding_generation: self.binding_generation.clone(),
                binding_digest: self.binding_digest.clone(),
                signer_key_id: self.signer_key_id.clone(),
                witness_key_id: self.witness_key_id.clone(),
                authority_pair: self.authority_pair,
                publication_mapping: self.publication_mapping,
                resulting_data_head_digest: predecessor.data_head_digest()?,
            },
        )));
        if self.resulting_head != expected_head {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    pub fn validate_against_predecessor(&self, predecessor: &WitnessHeadV1) -> ProtocolResult<()> {
        self.validate()?;
        predecessor.validate_settled()?;
        if self.stream_id != predecessor.stream_id
            || self.predecessor_head_digest != predecessor.head_digest()?
            || self.intent_counter != checked_next_intent(predecessor.intent_counter)?
            || self.binding_generation != predecessor.binding_generation
            || self.binding_digest != predecessor.binding_digest
            || self.signer_key_id != predecessor.signer_key_id
            || self.witness_key_id != predecessor.witness_key_id
            || self.authority_pair != predecessor.authority_pair
            || self.publication_mapping != predecessor.publication_mapping
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let expected_head = {
            let mut head = predecessor.clone();
            head.intent_counter = self.intent_counter;
            head.last_intent_outcome = Some(WitnessIntentOutcomeV1::Aborted(Box::new(
                WitnessAbortSummaryV1 {
                    txid: self.txid.clone(),
                    candidate_digest: self.candidate_digest.clone(),
                    predecessor_head_digest: self.predecessor_head_digest.clone(),
                    epoch: self.epoch,
                    sequence: self.sequence,
                    intent_counter: self.intent_counter,
                    binding_generation: self.binding_generation.clone(),
                    binding_digest: self.binding_digest.clone(),
                    signer_key_id: self.signer_key_id.clone(),
                    witness_key_id: self.witness_key_id.clone(),
                    authority_pair: self.authority_pair,
                    publication_mapping: self.publication_mapping,
                    resulting_data_head_digest: predecessor.data_head_digest()?,
                },
            )));
            head.validate_settled()?;
            head
        };
        if self.resulting_head != expected_head {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }
}

pub fn validate_intent_abort(
    previous: &WitnessHeadV1,
    aborted: &WitnessAbortedV1,
) -> ProtocolResult<()> {
    previous.validate_settled()?;
    if aborted.epoch != previous.epoch || aborted.sequence != previous.sequence {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    aborted.validate_against_predecessor(previous)
}

impl WitnessPrepareOutcomeV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        match self {
            Self::Prepared(value) | Self::AlreadyPrepared(value) => value.validate(),
            Self::Conflict => Ok(()),
        }
    }
}

impl WitnessCommitOutcomeV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        match self {
            Self::Committed(value) | Self::AlreadyCommitted(value) => value.validate(),
            Self::Aborted(value) => value.validate(),
            Self::GenesisAborted(value) => value.validate(),
        }
    }
}

impl WitnessAbortOutcomeV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        match self {
            Self::Aborted(value) | Self::AlreadyAborted(value) => value.validate(),
            Self::Committed(value) => value.validate(),
            Self::GenesisAborted(value) => value.validate(),
        }
    }

    pub fn validate_against_prepared(&self, prepared: &WitnessPreparedV1) -> ProtocolResult<()> {
        self.validate()?;
        prepared.validate()?;
        match self {
            Self::Aborted(value) | Self::AlreadyAborted(value) => {
                value.validate_against_prepared(prepared)
            }
            Self::Committed(value) => {
                let mut expected = prepared.head.clone();
                expected.last_intent_outcome = Some(WitnessIntentOutcomeV1::Committed {
                    txid: expected.txid.clone(),
                    candidate_digest: expected.candidate_digest.clone(),
                    predecessor_head_digest: prepared.predecessor_head_digest.clone(),
                    intent_counter: expected.intent_counter,
                });
                if value.head != expected {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
                Ok(())
            }
            Self::GenesisAborted(value) => value.validate_against_prepared(prepared),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessDiscoveryV1 {
    pub schema_version: u32,
    /// The current full witness head.  It remains present after an abort and
    /// carries the abort summary in `last_intent_outcome`; a separate stale
    /// `committed` plus `aborted` pair cannot express that authority safely.
    pub head: Option<WitnessHeadV1>,
    pub prepared: Option<WitnessPreparedV1>,
    pub genesis_abort: Option<WitnessGenesisAbortedV1>,
    pub recovery_session: WitnessSessionV1,
}

impl WitnessDiscoveryV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        if let Some(head) = &self.head {
            head.validate_settled()?;
        }
        if let Some(prepared) = &self.prepared {
            prepared.validate()?;
        }
        if let Some(aborted) = &self.genesis_abort {
            aborted.validate()?;
            if self.head.is_some() || self.prepared.is_some() {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
            if aborted.stream_id != self.recovery_session.stream_id
                || aborted.binding_generation != self.recovery_session.binding_generation
                || aborted.binding_digest != self.recovery_session.binding_digest
                || aborted.signer_key_id != self.recovery_session.signer_key_id
                || aborted.witness_key_id != self.recovery_session.witness_key_id
                || aborted.authority_pair != self.recovery_session.authority_pair
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
        self.recovery_session.validate()?;
        if let Some(head) = &self.head
            && (head.stream_id != self.recovery_session.stream_id
                || head.binding_generation != self.recovery_session.binding_generation
                || head.binding_digest != self.recovery_session.binding_digest
                || head.signer_key_id != self.recovery_session.signer_key_id
                || head.witness_key_id != self.recovery_session.witness_key_id
                || head.authority_pair != self.recovery_session.authority_pair)
        {
            return Err(invalid(
                "head",
                "current head is not bound to the recovery session",
            ));
        }
        if let Some(prepared) = &self.prepared {
            if prepared.binding_digest != self.recovery_session.binding_digest
                || prepared.head.stream_id != self.recovery_session.stream_id
                || prepared.head.binding_generation != self.recovery_session.binding_generation
                || prepared.head.binding_digest != self.recovery_session.binding_digest
                || prepared.head.signer_key_id != self.recovery_session.signer_key_id
                || prepared.head.witness_key_id != self.recovery_session.witness_key_id
                || prepared.head.authority_pair != self.recovery_session.authority_pair
            {
                return Err(invalid(
                    "prepared",
                    "head is not bound to the recovery session",
                ));
            }
            if prepared.session_generation != self.recovery_session.session_generation {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
            match (&self.head, &prepared.predecessor_head) {
                (Some(current), Some(predecessor)) => {
                    if predecessor != current
                        || prepared.predecessor_head_digest != current.head_digest()?
                    {
                        return Err(invalid(
                            "prepared",
                            "predecessor does not match the current full head",
                        ));
                    }
                    if prepared.head.txid == current.txid {
                        return Err(ProtocolError::WitnessOutcomeMismatch);
                    }
                }
                (None, None) => {}
                _ => return Err(ProtocolError::WitnessOutcomeMismatch),
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessSessionRotationResponseKindV1 {
    Establish,
    Discover,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessEstablishSnapshotV1 {
    pub schema_version: u32,
    pub committed_head: Option<WitnessHeadV1>,
    pub external_marker: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSessionRotationReceiptV1 {
    pub schema_version: u32,
    pub accepted_request_digest: String,
    pub accepted_challenge_digest: String,
    pub response_kind: WitnessSessionRotationResponseKindV1,
    pub session: WitnessSessionV1,
    pub establish_snapshot: Option<WitnessEstablishSnapshotV1>,
    pub discovery_snapshot: Option<WitnessDiscoveryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WitnessExternalMarkerPreimageV1<'a> {
    accepted_challenge_digest: &'a str,
    resulting_session_digest: &'a str,
    response_kind: WitnessSessionRotationResponseKindV1,
}

impl WitnessSessionRotationReceiptV1 {
    pub fn for_establish(
        accepted_request_digest: String,
        challenge: &RecoveryChallengeV1,
        session: WitnessSessionV1,
        committed_head: Option<WitnessHeadV1>,
    ) -> ProtocolResult<Self> {
        validate_rotated_session_for_challenge(challenge, &session)?;
        validate_fenced_response_state(challenge, committed_head.as_ref(), None)?;
        if let Some(head) = &committed_head {
            validate_established_head_for_session(head, &session)?;
        }
        let accepted_challenge_digest = challenge.challenge_digest()?;
        let external_marker = witness_external_marker(
            &accepted_challenge_digest,
            &witness_session_digest(&session)?,
        )?;
        let receipt = Self {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            accepted_request_digest,
            accepted_challenge_digest,
            response_kind: WitnessSessionRotationResponseKindV1::Establish,
            session,
            establish_snapshot: Some(WitnessEstablishSnapshotV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                committed_head,
                external_marker,
            }),
            discovery_snapshot: None,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn for_discovery(
        accepted_request_digest: String,
        challenge: &RecoveryChallengeV1,
        discovery: WitnessDiscoveryV1,
    ) -> ProtocolResult<Self> {
        discovery.validate()?;
        validate_rotated_session_for_challenge(challenge, &discovery.recovery_session)?;
        validate_fenced_response_state(
            challenge,
            discovery.head.as_ref(),
            discovery.prepared.as_ref(),
        )?;
        let receipt = Self {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            accepted_request_digest,
            accepted_challenge_digest: challenge.challenge_digest()?,
            response_kind: WitnessSessionRotationResponseKindV1::Discover,
            session: discovery.recovery_session.clone(),
            establish_snapshot: None,
            discovery_snapshot: Some(discovery),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_digest("accepted_request_digest", &self.accepted_request_digest)?;
        validate_digest("accepted_challenge_digest", &self.accepted_challenge_digest)?;
        self.session.validate()?;
        match (
            self.response_kind,
            &self.establish_snapshot,
            &self.discovery_snapshot,
        ) {
            (WitnessSessionRotationResponseKindV1::Establish, Some(snapshot), None) => {
                if snapshot.schema_version != PROTOCOL_SCHEMA_VERSION {
                    return Err(ProtocolError::UnsupportedSchema(snapshot.schema_version));
                }
                if let Some(head) = &snapshot.committed_head {
                    validate_established_head_for_session(head, &self.session)?;
                }
                validate_digest("external_marker", &snapshot.external_marker)?;
                let expected_marker = witness_external_marker(
                    &self.accepted_challenge_digest,
                    &witness_session_digest(&self.session)?,
                )?;
                if snapshot.external_marker != expected_marker {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            }
            (WitnessSessionRotationResponseKindV1::Discover, None, Some(discovery)) => {
                discovery.validate()?;
                if discovery.recovery_session != self.session {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            }
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        canonical_wire_bytes(self)
    }

    pub fn receipt_digest(&self) -> ProtocolResult<String> {
        digest_domain(WITNESS_ROTATION_RECEIPT_DOMAIN_V1, &self.canonical_bytes()?)
    }

    pub fn verify_exact_retry(
        &self,
        accepted_request_digest: &str,
        challenge: &RecoveryChallengeV1,
        response_kind: WitnessSessionRotationResponseKindV1,
    ) -> ProtocolResult<()> {
        self.validate()?;
        validate_digest("accepted_request_digest", accepted_request_digest)?;
        challenge.validate()?;
        validate_rotated_session_for_challenge(challenge, &self.session)?;
        if self.accepted_request_digest != accepted_request_digest
            || self.accepted_challenge_digest != challenge.challenge_digest()?
            || self.response_kind != response_kind
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        match (
            self.response_kind,
            &self.establish_snapshot,
            &self.discovery_snapshot,
        ) {
            (WitnessSessionRotationResponseKindV1::Establish, Some(snapshot), None) => {
                validate_fenced_response_state(challenge, snapshot.committed_head.as_ref(), None)?;
            }
            (WitnessSessionRotationResponseKindV1::Discover, None, Some(discovery)) => {
                validate_fenced_response_state(
                    challenge,
                    discovery.head.as_ref(),
                    discovery.prepared.as_ref(),
                )?;
            }
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        }
        Ok(())
    }
}

fn witness_session_digest(session: &WitnessSessionV1) -> ProtocolResult<String> {
    session.validate()?;
    digest_domain(
        WITNESS_SESSION_STATE_DOMAIN_V1,
        &canonical_wire_bytes(session)?,
    )
}

fn witness_external_marker(
    accepted_challenge_digest: &str,
    resulting_session_digest: &str,
) -> ProtocolResult<String> {
    validate_digest("accepted_challenge_digest", accepted_challenge_digest)?;
    validate_digest("resulting_session_digest", resulting_session_digest)?;
    digest_domain(
        WITNESS_EXTERNAL_MARKER_DOMAIN_V1,
        &canonical_wire_bytes(&WitnessExternalMarkerPreimageV1 {
            accepted_challenge_digest,
            resulting_session_digest,
            response_kind: WitnessSessionRotationResponseKindV1::Establish,
        })?,
    )
}

fn validate_rotated_session_for_challenge(
    challenge: &RecoveryChallengeV1,
    session: &WitnessSessionV1,
) -> ProtocolResult<()> {
    challenge.validate()?;
    session.validate()?;
    if challenge.stream_id != session.stream_id
        || challenge.authority_pair != session.authority_pair
        || challenge.binding_generation != session.binding_generation
        || challenge.binding_digest != session.binding_digest
        || challenge.signer_key_id != session.signer_key_id
        || challenge.witness_key_id != session.witness_key_id
        || challenge.witness_identity != session.witness_identity
        || challenge.ephemeral_key_id != session.ephemeral_key_id
        || challenge.session_commitment != session.session_commitment
        || challenge.expected_session_generation()? != session.session_generation
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    Ok(())
}

fn validate_established_head_for_session(
    head: &WitnessHeadV1,
    session: &WitnessSessionV1,
) -> ProtocolResult<()> {
    head.validate_settled()?;
    if head.stream_id != session.stream_id
        || head.authority_pair != session.authority_pair
        || head.binding_generation != session.binding_generation
        || head.binding_digest != session.binding_digest
        || head.signer_key_id != session.signer_key_id
        || head.witness_key_id != session.witness_key_id
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    Ok(())
}

fn validate_fenced_response_state(
    challenge: &RecoveryChallengeV1,
    head: Option<&WitnessHeadV1>,
    prepared: Option<&WitnessPreparedV1>,
) -> ProtocolResult<()> {
    challenge.validate()?;
    let head_digest = head.map(WitnessHeadV1::head_digest).transpose()?;
    let prepared_digest = prepared
        .map(|value| {
            value.validate()?;
            let mut fenced_value = value.clone();
            if let Some(current_generation) = challenge.state_fence.current_session_generation {
                if value.session_generation != checked_next_session(current_generation)? {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
                fenced_value.session_generation = current_generation;
            } else if value.session_generation != challenge.expected_session_generation()? {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
            digest_domain(
                WITNESS_PREPARED_STATE_DOMAIN_V1,
                &canonical_wire_bytes(&fenced_value)?,
            )
        })
        .transpose()?;
    if challenge.state_fence.current_head_digest != head_digest
        || challenge.state_fence.current_prepared_digest != prepared_digest
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessPrepareOutcomeV1 {
    Prepared(WitnessPreparedV1),
    AlreadyPrepared(WitnessPreparedV1),
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessCommitOutcomeV1 {
    Committed(WitnessCommittedV1),
    AlreadyCommitted(WitnessCommittedV1),
    Aborted(Box<WitnessAbortedV1>),
    GenesisAborted(Box<WitnessGenesisAbortedV1>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessAbortOutcomeV1 {
    Aborted(WitnessAbortedV1),
    AlreadyAborted(WitnessAbortedV1),
    Committed(WitnessCommittedV1),
    GenesisAborted(WitnessGenesisAbortedV1),
}

/// The local terminal record carries the exact authenticated witness receipt
/// that caused the terminal transition.  A phase value by itself is not
/// authority: deserializing or constructing a `Committed`/`Aborted` record
/// without its matching witness receipt is rejected by `validate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessTerminalOutcomeV1 {
    Committed(Box<WitnessCommittedV1>),
    Aborted(Box<WitnessAbortedV1>),
    GenesisAborted(Box<WitnessGenesisAbortedV1>),
}

impl WitnessTerminalOutcomeV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        match self {
            Self::Committed(value) => value.validate(),
            Self::Aborted(value) => value.validate(),
            Self::GenesisAborted(value) => value.validate(),
        }
    }
}

/// A signed wire response returned by an external witness transport.  This is
/// deliberately not the mutation capability: the governance crate verifies
/// the pinned witness key, challenge nonce, namespace and exact head before it
/// creates the opaque session below.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSessionAttestationV1 {
    pub schema_version: u32,
    pub challenge: RecoveryChallengeV1,
    pub session: WitnessSessionV1,
    pub committed_head: Option<WitnessHeadV1>,
    pub external_marker: String,
    pub witness_key_id: String,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WitnessSessionAttestationPreimageV1<'a> {
    schema_version: u32,
    challenge: &'a RecoveryChallengeV1,
    session: &'a WitnessSessionV1,
    committed_head: &'a Option<WitnessHeadV1>,
    external_marker: &'a str,
    witness_key_id: &'a str,
}

impl WitnessSessionAttestationV1 {
    pub fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        canonical_wire_bytes(&WitnessSessionAttestationPreimageV1 {
            schema_version: self.schema_version,
            challenge: &self.challenge,
            session: &self.session,
            committed_head: &self.committed_head,
            external_marker: &self.external_marker,
            witness_key_id: &self.witness_key_id,
        })
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        self.challenge.validate()?;
        self.session.validate()?;
        validate_fenced_response_state(&self.challenge, self.committed_head.as_ref(), None)?;
        if self.challenge.stream_id != self.session.stream_id
            || self.challenge.binding_generation != self.session.binding_generation
            || self.challenge.binding_digest != self.session.binding_digest
            || self.challenge.signer_key_id != self.session.signer_key_id
            || self.challenge.witness_key_id != self.session.witness_key_id
            || self.challenge.ephemeral_key_id != self.session.ephemeral_key_id
            || self.challenge.session_commitment != self.session.session_commitment
            || self.challenge.authority_pair != self.session.authority_pair
            || self.challenge.witness_identity != self.session.witness_identity
            || self.session.session_generation != self.challenge.expected_session_generation()?
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        if self.witness_key_id != self.session.witness_key_id {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        if let Some(head) = &self.committed_head {
            head.validate_settled()?;
            if head.stream_id != self.session.stream_id
                || head.binding_generation != self.session.binding_generation
                || head.binding_digest != self.session.binding_digest
                || head.signer_key_id != self.session.signer_key_id
                || head.witness_key_id != self.session.witness_key_id
                || head.authority_pair != self.session.authority_pair
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
        validate_digest("external_marker", &self.external_marker)?;
        let expected_external_marker = witness_external_marker(
            &self.challenge.challenge_digest()?,
            &witness_session_digest(&self.session)?,
        )?;
        if self.external_marker != expected_external_marker {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        validate_digest("witness_key_id", &self.witness_key_id)?;
        if self.signature.algorithm != "ed25519"
            || self.signature.key_id != self.witness_key_id
            || !swarm_crypto::PublicKey::from_hex(&self.signature.public_key_hex)
                .map(|key| sha256_hex(key.as_bytes()) == self.witness_key_id)
                .unwrap_or(false)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        verify_detached_signature(&self.signing_bytes()?, &self.signature)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        canonical_wire_bytes(self)
    }

    pub fn verify_for(
        &self,
        challenge: &RecoveryChallengeV1,
        expected_head: Option<&WitnessHeadV1>,
        binding: &PublicationBindingV1,
    ) -> ProtocolResult<()> {
        self.validate()?;
        challenge.validate()?;
        binding.validate()?;
        if &self.challenge != challenge
            || challenge.stream_id != binding.stream_id
            || challenge.binding_generation != binding.generation
            || challenge.binding_digest != binding.binding_digest
            || challenge.authority_pair != binding.authority_pair
            || challenge.signer_key_id != binding.signer_key_id
            || challenge.witness_key_id != binding.witness_key_id
            || challenge.witness_identity != binding.witness_identity
            || self.witness_key_id != binding.witness_key_id
            || self.session.signer_key_id != binding.signer_key_id
            || self.session.binding_digest != binding.binding_digest
            || self.session.ephemeral_key_id != challenge.ephemeral_key_id
            || self.committed_head.as_ref() != expected_head
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }
}

/// A signed discovery response.  Discovery remains a wire value until its
/// challenge and pinned witness key are verified by the governance caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessDiscoveryAttestationV1 {
    pub schema_version: u32,
    pub challenge: RecoveryChallengeV1,
    pub discovery: WitnessDiscoveryV1,
    pub witness_key_id: String,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WitnessDiscoveryAttestationPreimageV1<'a> {
    schema_version: u32,
    challenge: &'a RecoveryChallengeV1,
    discovery: &'a WitnessDiscoveryV1,
    witness_key_id: &'a str,
}

impl WitnessDiscoveryAttestationV1 {
    pub fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        canonical_wire_bytes(&WitnessDiscoveryAttestationPreimageV1 {
            schema_version: self.schema_version,
            challenge: &self.challenge,
            discovery: &self.discovery,
            witness_key_id: &self.witness_key_id,
        })
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        self.challenge.validate()?;
        self.discovery.validate()?;
        validate_fenced_response_state(
            &self.challenge,
            self.discovery.head.as_ref(),
            self.discovery.prepared.as_ref(),
        )?;
        if self.discovery.recovery_session.stream_id != self.challenge.stream_id
            || self.discovery.recovery_session.binding_generation
                != self.challenge.binding_generation
            || self.discovery.recovery_session.binding_digest != self.challenge.binding_digest
            || self.discovery.recovery_session.signer_key_id != self.challenge.signer_key_id
            || self.discovery.recovery_session.witness_key_id != self.challenge.witness_key_id
            || self.discovery.recovery_session.ephemeral_key_id != self.challenge.ephemeral_key_id
            || self.discovery.recovery_session.session_commitment
                != self.challenge.session_commitment
            || self.discovery.recovery_session.authority_pair != self.challenge.authority_pair
            || self.discovery.recovery_session.witness_identity != self.challenge.witness_identity
            || self.discovery.recovery_session.session_generation
                != self.challenge.expected_session_generation()?
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        if self.witness_key_id != self.discovery.recovery_session.witness_key_id {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        validate_digest("witness_key_id", &self.witness_key_id)?;
        if self.signature.algorithm != "ed25519"
            || self.signature.key_id != self.witness_key_id
            || !swarm_crypto::PublicKey::from_hex(&self.signature.public_key_hex)
                .map(|key| sha256_hex(key.as_bytes()) == self.witness_key_id)
                .unwrap_or(false)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        verify_detached_signature(&self.signing_bytes()?, &self.signature)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        canonical_wire_bytes(self)
    }

    pub fn verify_for(
        &self,
        challenge: &RecoveryChallengeV1,
        binding: &PublicationBindingV1,
    ) -> ProtocolResult<WitnessDiscoveryV1> {
        self.validate()?;
        challenge.validate()?;
        binding.validate()?;
        if &self.challenge != challenge
            || challenge.stream_id != binding.stream_id
            || challenge.binding_generation != binding.generation
            || challenge.binding_digest != binding.binding_digest
            || challenge.authority_pair != binding.authority_pair
            || challenge.signer_key_id != binding.signer_key_id
            || challenge.witness_key_id != binding.witness_key_id
            || challenge.witness_identity != binding.witness_identity
            || self.witness_key_id != binding.witness_key_id
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(self.discovery.clone())
    }

    /// Verify discovery into the opaque authority-bearing wrapper used by
    /// state-machine recovery.  A wire discovery value remains data only;
    /// callers must retain this wrapper and the one-time session capability
    /// returned by `GovernanceWitnessSession::from_verified_discovery`.
    pub fn verify_authority(
        &self,
        challenge: &RecoveryChallengeV1,
        binding: &PublicationBindingV1,
        expected_head: Option<&WitnessHeadV1>,
    ) -> ProtocolResult<VerifiedWitnessDiscoveryV1> {
        self.verify_for(challenge, binding)?;
        if let Some(expected_head) = expected_head
            && self.discovery.head.as_ref() != Some(expected_head)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(VerifiedWitnessDiscoveryV1 {
            attestation: self.clone(),
            discovery: self.discovery.clone(),
        })
    }
}

/// Authenticated discovery authority.  This type deliberately has no
/// public constructor and is not serializable or cloneable: replaying a
/// captured discovery envelope cannot manufacture recovery authority.
pub struct VerifiedWitnessDiscoveryV1 {
    attestation: WitnessDiscoveryAttestationV1,
    discovery: WitnessDiscoveryV1,
}

impl VerifiedWitnessDiscoveryV1 {
    pub fn attestation(&self) -> &WitnessDiscoveryAttestationV1 {
        &self.attestation
    }

    pub fn discovery(&self) -> &WitnessDiscoveryV1 {
        &self.discovery
    }
}

/// A public wire attestation is not itself authority to mutate the external
/// witness. This capability is intentionally non-Clone and non-serializable;
/// only `from_verified_attestation` can create it after signature, challenge,
/// namespace and head checks.
pub struct GovernanceWitnessSession {
    attestation: WitnessSessionV1,
    committed_head: Option<WitnessHeadV1>,
    external_marker: String,
    session_secret: SigningKey,
}

/// One-time local capability tying a signed challenge to a secret that never
/// crosses the wire.  A captured session/discovery attestation is therefore
/// insufficient to reconstruct a mutation session.
pub struct GovernanceWitnessSessionRequest {
    challenge: RecoveryChallengeV1,
    signing_key: SigningKey,
}

impl GovernanceWitnessSessionRequest {
    /// `secret` must be generated by the local caller before it signs the
    /// challenge nonce. It is retained only in this non-serializable request.
    pub fn from_secret(challenge: RecoveryChallengeV1, secret: [u8; 32]) -> ProtocolResult<Self> {
        challenge.validate()?;
        let signing_key = SigningKey::from_bytes(&secret);
        let ephemeral_key_id = sha256_hex(signing_key.verifying_key().as_bytes());
        if challenge.session_commitment != sha256_hex(&signing_key.to_bytes())
            || challenge.ephemeral_key_id != ephemeral_key_id
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(Self {
            challenge,
            signing_key,
        })
    }

    pub fn challenge(&self) -> &RecoveryChallengeV1 {
        &self.challenge
    }
}

impl GovernanceWitnessSession {
    pub fn from_verified_attestation(
        request: GovernanceWitnessSessionRequest,
        attestation: WitnessSessionAttestationV1,
        expected_head: Option<&WitnessHeadV1>,
        binding: &PublicationBindingV1,
    ) -> ProtocolResult<Self> {
        attestation.verify_for(&request.challenge, expected_head, binding)?;
        if attestation.session.session_commitment != sha256_hex(&request.signing_key.to_bytes()) {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(Self {
            attestation: attestation.session,
            committed_head: attestation.committed_head,
            external_marker: attestation.external_marker,
            session_secret: request.signing_key,
        })
    }

    /// Complete the one-time, secret-backed rotation path for discovery.
    /// The returned discovery wrapper and session are both derived from the
    /// signed wire response, the pinned binding, and the non-serializable
    /// request secret.  The wire response alone is insufficient.
    pub fn from_verified_discovery(
        request: GovernanceWitnessSessionRequest,
        attestation: WitnessDiscoveryAttestationV1,
        binding: &PublicationBindingV1,
        expected_head: Option<&WitnessHeadV1>,
    ) -> ProtocolResult<(VerifiedWitnessDiscoveryV1, Self)> {
        let verified = attestation.verify_authority(&request.challenge, binding, expected_head)?;
        let discovery = verified.discovery();
        if discovery.recovery_session.session_commitment
            != sha256_hex(&request.signing_key.to_bytes())
            || discovery.recovery_session.ephemeral_key_id
                != sha256_hex(request.signing_key.verifying_key().as_bytes())
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let external_marker = digest_domain(
            JOURNAL_ENVELOPE_DOMAIN_V1,
            &verified.attestation.signing_bytes()?,
        )?;
        let session = Self {
            attestation: discovery.recovery_session.clone(),
            committed_head: discovery.head.clone(),
            external_marker,
            session_secret: request.signing_key,
        };
        Ok((verified, session))
    }

    pub fn attestation(&self) -> &WitnessSessionV1 {
        &self.attestation
    }

    pub fn committed_head(&self) -> Option<&WitnessHeadV1> {
        self.committed_head.as_ref()
    }

    pub fn external_marker(&self) -> &str {
        &self.external_marker
    }

    fn secret_commitment(&self) -> String {
        sha256_hex(&self.session_secret.to_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessReadResponseV1 {
    Prepared(Box<Option<WitnessPreparedV1>>),
    Head(Box<Option<WitnessHeadV1>>),
    Payload(Box<Option<CandidatePreimageV1>>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessReadAttestationV1 {
    pub schema_version: u32,
    pub operation: WitnessOperationV1,
    pub stream_id: String,
    pub binding_generation: String,
    pub binding_digest: String,
    pub signer_key_id: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub target_txid: String,
    pub request_digest: String,
    pub session_generation: u64,
    pub session_commitment: String,
    pub witness_key_id: String,
    pub response: WitnessReadResponseV1,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WitnessReadAttestationPreimageV1<'a> {
    schema_version: u32,
    operation: WitnessOperationV1,
    stream_id: &'a str,
    binding_generation: &'a str,
    binding_digest: &'a str,
    signer_key_id: &'a str,
    authority_pair: AuthorityPairIdentityV1,
    target_txid: &'a str,
    request_digest: &'a str,
    session_generation: u64,
    session_commitment: &'a str,
    witness_key_id: &'a str,
    response: &'a WitnessReadResponseV1,
}

impl WitnessReadAttestationV1 {
    pub fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        canonical_wire_bytes(&WitnessReadAttestationPreimageV1 {
            schema_version: self.schema_version,
            operation: self.operation,
            stream_id: &self.stream_id,
            binding_generation: &self.binding_generation,
            binding_digest: &self.binding_digest,
            signer_key_id: &self.signer_key_id,
            authority_pair: self.authority_pair,
            target_txid: &self.target_txid,
            request_digest: &self.request_digest,
            session_generation: self.session_generation,
            session_commitment: &self.session_commitment,
            witness_key_id: &self.witness_key_id,
            response: &self.response,
        })
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_string("stream_id", &self.stream_id)?;
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        self.authority_pair.validate()?;
        validate_digest("target_txid", &self.target_txid)?;
        validate_digest("request_digest", &self.request_digest)?;
        validate_digest("session_commitment", &self.session_commitment)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        match (self.operation, &self.response) {
            (WitnessOperationV1::ReadPrepared, WitnessReadResponseV1::Prepared(value)) => {
                if let Some(prepared) = value.as_ref().as_ref() {
                    prepared.validate()?;
                    if prepared.session_generation != self.session_generation
                        || prepared.head.stream_id != self.stream_id
                        || prepared.head.binding_generation != self.binding_generation
                        || prepared.head.binding_digest != self.binding_digest
                        || prepared.head.signer_key_id != self.signer_key_id
                        || prepared.head.witness_key_id != self.witness_key_id
                        || prepared.head.authority_pair != self.authority_pair
                        || prepared.predecessor_head.as_ref().is_some_and(|head| {
                            head.stream_id != self.stream_id
                                || head.binding_generation != self.binding_generation
                                || head.binding_digest != self.binding_digest
                                || head.signer_key_id != self.signer_key_id
                                || head.witness_key_id != self.witness_key_id
                                || head.authority_pair != self.authority_pair
                        })
                    {
                        return Err(ProtocolError::WitnessOutcomeMismatch);
                    }
                }
            }
            (WitnessOperationV1::ReadHead, WitnessReadResponseV1::Head(value)) => {
                if let Some(head) = value.as_ref().as_ref() {
                    head.validate_settled()?;
                    if head.stream_id != self.stream_id
                        || head.binding_generation != self.binding_generation
                        || head.binding_digest != self.binding_digest
                        || head.signer_key_id != self.signer_key_id
                        || head.witness_key_id != self.witness_key_id
                        || head.authority_pair != self.authority_pair
                    {
                        return Err(ProtocolError::WitnessOutcomeMismatch);
                    }
                }
            }
            (WitnessOperationV1::FetchPayload, WitnessReadResponseV1::Payload(value)) => {
                if let Some(payload) = value.as_ref().as_ref() {
                    payload.validate()?;
                    let candidate_digest = payload.candidate_digest()?;
                    if payload.publication_binding.stream_id != self.stream_id
                        || payload.publication_binding.generation != self.binding_generation
                        || payload.publication_binding.binding_digest != self.binding_digest
                        || payload.publication_binding.signer_key_id != self.signer_key_id
                        || payload.publication_binding.witness_key_id != self.witness_key_id
                        || payload.publication_binding.authority_pair != self.authority_pair
                        || payload.txid(&candidate_digest)? != self.target_txid
                    {
                        return Err(ProtocolError::WitnessOutcomeMismatch);
                    }
                }
            }
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        }
        if self.signature.algorithm != "ed25519"
            || self.signature.key_id != self.witness_key_id
            || !swarm_crypto::PublicKey::from_hex(&self.signature.public_key_hex)
                .map(|key| sha256_hex(key.as_bytes()) == self.witness_key_id)
                .unwrap_or(false)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        verify_detached_signature(&self.signing_bytes()?, &self.signature)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)
    }

    pub fn verify_for(
        &self,
        session: &GovernanceWitnessSession,
        operation: WitnessOperationV1,
        target_txid: &str,
        request_digest: &str,
    ) -> ProtocolResult<WitnessReadResponseV1> {
        self.validate()?;
        validate_digest("target_txid", target_txid)?;
        validate_digest("request_digest", request_digest)?;
        if self.operation != operation
            || self.stream_id != session.attestation.stream_id
            || self.binding_generation != session.attestation.binding_generation
            || self.binding_digest != session.attestation.binding_digest
            || self.signer_key_id != session.attestation.signer_key_id
            || self.authority_pair != session.attestation.authority_pair
            || self.target_txid != target_txid
            || self.request_digest != request_digest
            || self.session_generation != session.attestation.session_generation
            || self.session_commitment != session.attestation.session_commitment
            || self.session_commitment != session.secret_commitment()
            || self.witness_key_id != session.attestation.witness_key_id
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(self.response.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessOperationV1 {
    Prepare,
    Commit,
    Abort,
    ReadPrepared,
    ReadHead,
    FetchPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessOperationOutcomeV1 {
    Prepare(Box<WitnessPrepareOutcomeV1>),
    Commit(Box<WitnessCommitOutcomeV1>),
    Abort(Box<WitnessAbortOutcomeV1>),
}

impl WitnessOperationOutcomeV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        match self {
            Self::Prepare(value) => value.validate(),
            Self::Commit(value) => value.validate(),
            Self::Abort(value) => value.validate(),
        }
    }
}

/// Every witness mutation response is itself signed and bound to the opaque
/// session commitment, operation, transaction and candidate. Plain outcome
/// values are retained as the local state-machine input only after this wire
/// envelope has been verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessOutcomeAttestationV1 {
    pub schema_version: u32,
    pub operation: WitnessOperationV1,
    pub stream_id: String,
    pub binding_generation: String,
    pub binding_digest: String,
    pub signer_key_id: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub txid: String,
    pub candidate_digest: String,
    pub session_generation: u64,
    pub session_commitment: String,
    pub witness_key_id: String,
    pub outcome: WitnessOperationOutcomeV1,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WitnessOutcomeAttestationPreimageV1<'a> {
    schema_version: u32,
    operation: WitnessOperationV1,
    stream_id: &'a str,
    binding_generation: &'a str,
    binding_digest: &'a str,
    signer_key_id: &'a str,
    authority_pair: AuthorityPairIdentityV1,
    txid: &'a str,
    candidate_digest: &'a str,
    session_generation: u64,
    session_commitment: &'a str,
    witness_key_id: &'a str,
    outcome: &'a WitnessOperationOutcomeV1,
}

impl WitnessOutcomeAttestationV1 {
    pub fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        canonical_wire_bytes(&WitnessOutcomeAttestationPreimageV1 {
            schema_version: self.schema_version,
            operation: self.operation,
            stream_id: &self.stream_id,
            binding_generation: &self.binding_generation,
            binding_digest: &self.binding_digest,
            signer_key_id: &self.signer_key_id,
            authority_pair: self.authority_pair,
            txid: &self.txid,
            candidate_digest: &self.candidate_digest,
            session_generation: self.session_generation,
            session_commitment: &self.session_commitment,
            witness_key_id: &self.witness_key_id,
            outcome: &self.outcome,
        })
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_string("stream_id", &self.stream_id)?;
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        self.authority_pair.validate()?;
        validate_digest("txid", &self.txid)?;
        validate_digest("candidate_digest", &self.candidate_digest)?;
        validate_digest("session_commitment", &self.session_commitment)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        self.outcome.validate()?;
        if let WitnessOperationOutcomeV1::Prepare(outcome) = &self.outcome {
            match outcome.as_ref() {
                WitnessPrepareOutcomeV1::Prepared(prepared)
                | WitnessPrepareOutcomeV1::AlreadyPrepared(prepared)
                    if prepared.session_generation == self.session_generation => {}
                WitnessPrepareOutcomeV1::Conflict => {}
                _ => return Err(ProtocolError::WitnessOutcomeMismatch),
            }
        }
        validate_outcome_binding(
            self.operation,
            &self.stream_id,
            &self.txid,
            &self.candidate_digest,
            &self.outcome,
        )?;
        validate_outcome_namespace(
            &self.stream_id,
            &self.binding_generation,
            &self.binding_digest,
            &self.signer_key_id,
            &self.witness_key_id,
            self.authority_pair,
            &self.outcome,
        )?;
        if self.signature.algorithm != "ed25519"
            || self.signature.key_id != self.witness_key_id
            || !swarm_crypto::PublicKey::from_hex(&self.signature.public_key_hex)
                .map(|key| sha256_hex(key.as_bytes()) == self.witness_key_id)
                .unwrap_or(false)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        verify_detached_signature(&self.signing_bytes()?, &self.signature)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)
    }

    pub fn verify_for(
        &self,
        session: &GovernanceWitnessSession,
        operation: WitnessOperationV1,
        txid: &str,
        candidate_digest: &str,
    ) -> ProtocolResult<WitnessOperationOutcomeV1> {
        self.validate()?;
        validate_digest("txid", txid)?;
        validate_digest("candidate_digest", candidate_digest)?;
        if self.operation != operation
            || self.stream_id != session.attestation.stream_id
            || self.binding_generation != session.attestation.binding_generation
            || self.binding_digest != session.attestation.binding_digest
            || self.signer_key_id != session.attestation.signer_key_id
            || self.authority_pair != session.attestation.authority_pair
            || self.txid != txid
            || self.candidate_digest != candidate_digest
            || self.session_generation != session.attestation.session_generation
            || self.session_commitment != session.attestation.session_commitment
            || self.session_commitment != session.secret_commitment()
            || self.witness_key_id != session.attestation.witness_key_id
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(self.outcome.clone())
    }
}

/// Opaque authority-bearing mutation result. Raw outcome values are never
/// accepted by transaction resolvers; this wrapper can only be created after
/// the pinned session verifies the witness signature and exact namespace.
pub struct VerifiedWitnessOutcomeV1 {
    attestation: WitnessOutcomeAttestationV1,
    outcome: WitnessOperationOutcomeV1,
}

impl VerifiedWitnessOutcomeV1 {
    pub fn from_attestation(
        attestation: WitnessOutcomeAttestationV1,
        session: &GovernanceWitnessSession,
        operation: WitnessOperationV1,
        txid: &str,
        candidate_digest: &str,
    ) -> ProtocolResult<Self> {
        let outcome = attestation.verify_for(session, operation, txid, candidate_digest)?;
        Ok(Self {
            attestation,
            outcome,
        })
    }

    /// Re-authorize an authenticated bootstrap-abort receipt for the public
    /// witness service after restart.  This is deliberately crate-private:
    /// callers cannot turn a raw receipt or boolean into transaction
    /// authority.  The public service must first authenticate the admitted
    /// store envelope, then sign this exact receipt with the pinned witness
    /// key.  The resulting value is consumed only by candidate admission.
    pub(crate) fn from_authenticated_store_genesis_abort(
        attestation: WitnessOutcomeAttestationV1,
        session: &WitnessSessionV1,
        expected_abort: &WitnessGenesisAbortedV1,
    ) -> ProtocolResult<Self> {
        session.validate()?;
        expected_abort.validate()?;
        attestation.validate()?;
        let expected_outcome = WitnessOperationOutcomeV1::Abort(Box::new(
            WitnessAbortOutcomeV1::GenesisAborted(expected_abort.clone()),
        ));
        if attestation.operation != WitnessOperationV1::Abort
            || attestation.stream_id != session.stream_id
            || attestation.binding_generation != session.binding_generation
            || attestation.binding_digest != session.binding_digest
            || attestation.signer_key_id != session.signer_key_id
            || attestation.authority_pair != session.authority_pair
            || attestation.session_generation != session.session_generation
            || attestation.session_commitment != session.session_commitment
            || attestation.witness_key_id != session.witness_key_id
            || attestation.outcome != expected_outcome
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(Self {
            attestation,
            outcome: expected_outcome,
        })
    }

    pub fn attestation(&self) -> &WitnessOutcomeAttestationV1 {
        &self.attestation
    }

    pub fn operation(&self) -> WitnessOperationV1 {
        self.attestation.operation
    }

    fn outcome(&self) -> &WitnessOperationOutcomeV1 {
        &self.outcome
    }
}

fn validate_attestation_namespace_for_record(
    attestation: &WitnessOutcomeAttestationV1,
    record: &TransactionRecordV1,
    operation: WitnessOperationV1,
) -> ProtocolResult<()> {
    attestation.validate()?;
    if attestation.operation != operation
        || attestation.stream_id != record.stream_id
        || attestation.binding_generation != record.binding_generation
        || attestation.binding_digest != record.binding_digest
        || attestation.signer_key_id != record.signer_key_id
        || attestation.witness_key_id != record.witness_key_id
        || attestation.authority_pair != record.authority_pair
        || attestation.txid != record.txid
        || attestation.candidate_digest != record.candidate_digest
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    Ok(())
}

fn validate_prepared_outcome_attestation_for_record(
    attestation: &WitnessOutcomeAttestationV1,
    record: &TransactionRecordV1,
) -> ProtocolResult<()> {
    validate_attestation_namespace_for_record(attestation, record, WitnessOperationV1::Prepare)?;
    match &attestation.outcome {
        WitnessOperationOutcomeV1::Prepare(value) => match value.as_ref() {
            WitnessPrepareOutcomeV1::Prepared(prepared)
            | WitnessPrepareOutcomeV1::AlreadyPrepared(prepared) => {
                record.validate_witness_prepared(prepared, attestation.session_generation)
            }
            WitnessPrepareOutcomeV1::Conflict => Err(ProtocolError::WitnessOutcomeMismatch),
        },
        _ => Err(ProtocolError::WitnessOutcomeMismatch),
    }
}

fn validate_outcome_attestation_for_record(
    attestation: &WitnessOutcomeAttestationV1,
    record: &TransactionRecordV1,
) -> ProtocolResult<()> {
    match (&record.phase, &attestation.outcome) {
        (
            TransactionPhaseV1::WitnessPrepared
            | TransactionPhaseV1::PayloadsStaged
            | TransactionPhaseV1::StateExchanged
            | TransactionPhaseV1::CheckpointExchanged
            | TransactionPhaseV1::ReadyForWitnessCommit
            | TransactionPhaseV1::AbortPending,
            WitnessOperationOutcomeV1::Prepare(value),
        ) => match value.as_ref() {
            WitnessPrepareOutcomeV1::Prepared(prepared)
            | WitnessPrepareOutcomeV1::AlreadyPrepared(prepared) => {
                record.validate_witness_prepared(prepared, attestation.session_generation)
            }
            WitnessPrepareOutcomeV1::Conflict => Err(ProtocolError::WitnessOutcomeMismatch),
        },
        (TransactionPhaseV1::Committed, WitnessOperationOutcomeV1::Commit(value)) => {
            match value.as_ref() {
                WitnessCommitOutcomeV1::Committed(committed)
                | WitnessCommitOutcomeV1::AlreadyCommitted(committed) => {
                    record.validate_witness_commit(committed)
                }
                WitnessCommitOutcomeV1::Aborted(_) => Err(ProtocolError::WitnessOutcomeMismatch),
                WitnessCommitOutcomeV1::GenesisAborted(_) => {
                    Err(ProtocolError::WitnessOutcomeMismatch)
                }
            }
        }
        (TransactionPhaseV1::Committed, WitnessOperationOutcomeV1::Abort(value)) => {
            match value.as_ref() {
                WitnessAbortOutcomeV1::Committed(committed) => {
                    record.validate_witness_commit(committed)
                }
                WitnessAbortOutcomeV1::Aborted(_) | WitnessAbortOutcomeV1::AlreadyAborted(_) => {
                    Err(ProtocolError::WitnessOutcomeMismatch)
                }
                WitnessAbortOutcomeV1::GenesisAborted(_) => {
                    Err(ProtocolError::WitnessOutcomeMismatch)
                }
            }
        }
        (TransactionPhaseV1::Aborted, WitnessOperationOutcomeV1::Commit(value)) => {
            match value.as_ref() {
                WitnessCommitOutcomeV1::Aborted(aborted) => record.validate_witness_abort(aborted),
                WitnessCommitOutcomeV1::Committed(_)
                | WitnessCommitOutcomeV1::AlreadyCommitted(_) => {
                    Err(ProtocolError::WitnessOutcomeMismatch)
                }
                WitnessCommitOutcomeV1::GenesisAborted(value) => {
                    record.validate_witness_genesis_abort(value)
                }
            }
        }
        (TransactionPhaseV1::Aborted, WitnessOperationOutcomeV1::Abort(value)) => {
            match value.as_ref() {
                WitnessAbortOutcomeV1::Aborted(aborted)
                | WitnessAbortOutcomeV1::AlreadyAborted(aborted) => {
                    record.validate_witness_abort(aborted)
                }
                WitnessAbortOutcomeV1::Committed(_) => Err(ProtocolError::WitnessOutcomeMismatch),
                WitnessAbortOutcomeV1::GenesisAborted(value) => {
                    record.validate_witness_genesis_abort(value)
                }
            }
        }
        _ => Err(ProtocolError::WitnessOutcomeMismatch),
    }
}

fn validate_discovery_attestation_namespace(
    attestation: &WitnessDiscoveryAttestationV1,
    record: &TransactionRecordV1,
) -> ProtocolResult<()> {
    attestation.validate()?;
    if attestation.challenge.stream_id != record.stream_id
        || attestation.challenge.binding_generation != record.binding_generation
        || attestation.challenge.binding_digest != record.binding_digest
        || attestation.challenge.signer_key_id != record.signer_key_id
        || attestation.witness_key_id != record.witness_key_id
        || attestation.challenge.authority_pair != record.authority_pair
        || attestation.discovery.recovery_session.stream_id != record.stream_id
        || attestation.discovery.recovery_session.binding_generation != record.binding_generation
        || attestation.discovery.recovery_session.binding_digest != record.binding_digest
        || attestation.discovery.recovery_session.signer_key_id != record.signer_key_id
        || attestation.discovery.recovery_session.witness_key_id != record.witness_key_id
        || attestation.discovery.recovery_session.authority_pair != record.authority_pair
        || attestation.witness_key_id != record.witness_key_id
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    Ok(())
}

fn validate_prepared_discovery_attestation_for_record(
    attestation: &WitnessDiscoveryAttestationV1,
    record: &TransactionRecordV1,
) -> ProtocolResult<()> {
    validate_discovery_attestation_namespace(attestation, record)?;
    if attestation.discovery.genesis_abort.is_some() {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    let prepared = attestation
        .discovery
        .prepared
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    record.validate_witness_prepared(
        prepared,
        attestation.discovery.recovery_session.session_generation,
    )
}

fn validate_terminal_discovery_attestation_for_record(
    attestation: &WitnessDiscoveryAttestationV1,
    record: &TransactionRecordV1,
) -> ProtocolResult<()> {
    validate_discovery_attestation_namespace(attestation, record)?;
    if attestation.discovery.prepared.is_some() {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    if let Some(genesis_abort) = &attestation.discovery.genesis_abort {
        return match (
            &record.phase,
            &record.witness_outcome,
            &attestation.discovery.head,
        ) {
            (
                TransactionPhaseV1::Aborted,
                Some(WitnessTerminalOutcomeV1::GenesisAborted(expected)),
                None,
            ) if expected.as_ref() == genesis_abort => {
                record.validate_witness_genesis_abort(genesis_abort)
            }
            _ => Err(ProtocolError::WitnessOutcomeMismatch),
        };
    }
    let head = attestation
        .discovery
        .head
        .as_ref()
        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
    match (&record.phase, &record.witness_outcome) {
        (TransactionPhaseV1::Committed, Some(WitnessTerminalOutcomeV1::Committed(committed)))
            if head == &committed.head => {}
        (TransactionPhaseV1::Aborted, Some(WitnessTerminalOutcomeV1::Aborted(aborted)))
            if head == &aborted.resulting_head => {}
        _ => return Err(ProtocolError::WitnessOutcomeMismatch),
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSessionAuthorizationV1 {
    pub schema_version: u32,
    pub operation: WitnessOperationV1,
    pub stream_id: String,
    pub binding_digest: String,
    pub txid: String,
    pub request_digest: String,
    pub session_generation: u64,
    pub session_commitment: String,
    pub ephemeral_key_id: String,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct WitnessSessionAuthorizationPreimageV1<'a> {
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

impl WitnessSessionAuthorizationV1 {
    fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        canonical_wire_bytes(&WitnessSessionAuthorizationPreimageV1 {
            schema_version: self.schema_version,
            operation: self.operation,
            stream_id: &self.stream_id,
            binding_digest: &self.binding_digest,
            txid: &self.txid,
            request_digest: &self.request_digest,
            session_generation: self.session_generation,
            session_commitment: &self.session_commitment,
            ephemeral_key_id: &self.ephemeral_key_id,
        })
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_string("stream_id", &self.stream_id)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        validate_digest("txid", &self.txid)?;
        validate_digest("request_digest", &self.request_digest)?;
        validate_digest("session_commitment", &self.session_commitment)?;
        validate_digest("ephemeral_key_id", &self.ephemeral_key_id)?;
        if self.signature.algorithm != "ed25519"
            || self.signature.key_id != self.ephemeral_key_id
            || !swarm_crypto::PublicKey::from_hex(&self.signature.public_key_hex)
                .map(|key| sha256_hex(key.as_bytes()) == self.ephemeral_key_id)
                .unwrap_or(false)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        verify_detached_signature(&self.signing_bytes()?, &self.signature)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)
    }

    pub fn verify_for_session_record(
        &self,
        session: &WitnessSessionV1,
        operation: WitnessOperationV1,
        txid: &str,
        request_digest: &str,
    ) -> ProtocolResult<()> {
        self.validate()?;
        session.validate()?;
        validate_digest("txid", txid)?;
        validate_digest("request_digest", request_digest)?;
        if self.operation != operation
            || self.stream_id != session.stream_id
            || self.binding_digest != session.binding_digest
            || self.txid != txid
            || self.request_digest != request_digest
            || self.session_generation != session.session_generation
            || self.session_commitment != session.session_commitment
            || self.ephemeral_key_id != session.ephemeral_key_id
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }
}

impl GovernanceWitnessSession {
    /// Produce the transport proof for one bounded operation. The ephemeral
    /// signing key is retained only by this capability and never serialized.
    pub fn authorize(
        &self,
        operation: WitnessOperationV1,
        txid: &str,
        request_digest: &str,
    ) -> ProtocolResult<WitnessSessionAuthorizationV1> {
        validate_digest("txid", txid)?;
        validate_digest("request_digest", request_digest)?;
        let public_key_hex = hex::encode(self.session_secret.verifying_key().to_bytes());
        let ephemeral_key_id = sha256_hex(self.session_secret.verifying_key().as_bytes());
        let mut authorization = WitnessSessionAuthorizationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation,
            stream_id: self.attestation.stream_id.clone(),
            binding_digest: self.attestation.binding_digest.clone(),
            txid: txid.to_string(),
            request_digest: request_digest.to_string(),
            session_generation: self.attestation.session_generation,
            session_commitment: self.attestation.session_commitment.clone(),
            ephemeral_key_id,
            signature: DetachedSignature {
                algorithm: "ed25519".to_string(),
                key_id: self.attestation.ephemeral_key_id.clone(),
                public_key_hex: public_key_hex.clone(),
                signature_hex: hex::encode(self.session_secret.sign(&[]).to_bytes()),
            },
        };
        let signature = self.session_secret.sign(&authorization.signing_bytes()?);
        authorization.signature = DetachedSignature {
            algorithm: "ed25519".to_string(),
            key_id: self.attestation.ephemeral_key_id.clone(),
            public_key_hex,
            signature_hex: hex::encode(signature.to_bytes()),
        };
        authorization.validate()?;
        Ok(authorization)
    }

    pub fn verify_authorization(
        &self,
        authorization: &WitnessSessionAuthorizationV1,
        operation: WitnessOperationV1,
        txid: &str,
        request_digest: &str,
    ) -> ProtocolResult<()> {
        authorization.validate()?;
        if authorization.operation != operation
            || authorization.stream_id != self.attestation.stream_id
            || authorization.binding_digest != self.attestation.binding_digest
            || authorization.txid != txid
            || authorization.request_digest != request_digest
            || authorization.session_generation != self.attestation.session_generation
            || authorization.session_commitment != self.attestation.session_commitment
            || authorization.session_commitment != self.secret_commitment()
            || authorization.ephemeral_key_id != self.attestation.ephemeral_key_id
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }
}

fn validate_outcome_binding(
    operation: WitnessOperationV1,
    stream_id: &str,
    txid: &str,
    candidate_digest: &str,
    outcome: &WitnessOperationOutcomeV1,
) -> ProtocolResult<()> {
    let (outcome_stream, outcome_txid, outcome_candidate) = match outcome {
        WitnessOperationOutcomeV1::Prepare(value) => match value.as_ref() {
            WitnessPrepareOutcomeV1::Prepared(prepared)
            | WitnessPrepareOutcomeV1::AlreadyPrepared(prepared) => (
                prepared.head.stream_id.as_str(),
                prepared.head.txid.as_str(),
                prepared.head.candidate_digest.as_str(),
            ),
            WitnessPrepareOutcomeV1::Conflict => (stream_id, txid, candidate_digest),
        },
        WitnessOperationOutcomeV1::Commit(value) => match value.as_ref() {
            WitnessCommitOutcomeV1::Committed(committed)
            | WitnessCommitOutcomeV1::AlreadyCommitted(committed) => (
                committed.head.stream_id.as_str(),
                committed.head.txid.as_str(),
                committed.head.candidate_digest.as_str(),
            ),
            WitnessCommitOutcomeV1::Aborted(aborted) => (
                aborted.stream_id.as_str(),
                aborted.txid.as_str(),
                aborted.candidate_digest.as_str(),
            ),
            WitnessCommitOutcomeV1::GenesisAborted(aborted) => (
                aborted.stream_id.as_str(),
                aborted.txid.as_str(),
                aborted.candidate_digest.as_str(),
            ),
        },
        WitnessOperationOutcomeV1::Abort(value) => match value.as_ref() {
            WitnessAbortOutcomeV1::Aborted(aborted)
            | WitnessAbortOutcomeV1::AlreadyAborted(aborted) => (
                aborted.stream_id.as_str(),
                aborted.txid.as_str(),
                aborted.candidate_digest.as_str(),
            ),
            WitnessAbortOutcomeV1::Committed(committed) => (
                committed.head.stream_id.as_str(),
                committed.head.txid.as_str(),
                committed.head.candidate_digest.as_str(),
            ),
            WitnessAbortOutcomeV1::GenesisAborted(aborted) => (
                aborted.stream_id.as_str(),
                aborted.txid.as_str(),
                aborted.candidate_digest.as_str(),
            ),
        },
    };
    let expected_operation = match outcome {
        WitnessOperationOutcomeV1::Prepare(_) => WitnessOperationV1::Prepare,
        WitnessOperationOutcomeV1::Commit(_) => WitnessOperationV1::Commit,
        WitnessOperationOutcomeV1::Abort(_) => WitnessOperationV1::Abort,
    };
    if operation != expected_operation
        || outcome_stream != stream_id
        || outcome_txid != txid
        || outcome_candidate != candidate_digest
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    Ok(())
}

fn validate_head_namespace(
    head: &WitnessHeadV1,
    stream_id: &str,
    binding_generation: &str,
    binding_digest: &str,
    signer_key_id: &str,
    witness_key_id: &str,
    authority_pair: AuthorityPairIdentityV1,
) -> ProtocolResult<()> {
    if head.stream_id != stream_id
        || head.binding_generation != binding_generation
        || head.binding_digest != binding_digest
        || head.signer_key_id != signer_key_id
        || head.witness_key_id != witness_key_id
        || head.authority_pair != authority_pair
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    Ok(())
}

fn validate_outcome_namespace(
    stream_id: &str,
    binding_generation: &str,
    binding_digest: &str,
    signer_key_id: &str,
    witness_key_id: &str,
    authority_pair: AuthorityPairIdentityV1,
    outcome: &WitnessOperationOutcomeV1,
) -> ProtocolResult<()> {
    let check_receipt = |stream: &str,
                         binding: &str,
                         digest: &str,
                         signer: &str,
                         witness: &str,
                         authority: AuthorityPairIdentityV1| {
        if stream != stream_id
            || binding != binding_generation
            || digest != binding_digest
            || signer != signer_key_id
            || witness != witness_key_id
            || authority != authority_pair
        {
            Err(ProtocolError::WitnessOutcomeMismatch)
        } else {
            Ok(())
        }
    };
    match outcome {
        WitnessOperationOutcomeV1::Prepare(value) => match value.as_ref() {
            WitnessPrepareOutcomeV1::Prepared(prepared)
            | WitnessPrepareOutcomeV1::AlreadyPrepared(prepared) => {
                if prepared.binding_digest != binding_digest {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
                validate_head_namespace(
                    &prepared.head,
                    stream_id,
                    binding_generation,
                    binding_digest,
                    signer_key_id,
                    witness_key_id,
                    authority_pair,
                )?;
                if let Some(predecessor) = &prepared.predecessor_head {
                    validate_head_namespace(
                        predecessor,
                        stream_id,
                        binding_generation,
                        binding_digest,
                        signer_key_id,
                        witness_key_id,
                        authority_pair,
                    )?;
                }
            }
            WitnessPrepareOutcomeV1::Conflict => {}
        },
        WitnessOperationOutcomeV1::Commit(value) => match value.as_ref() {
            WitnessCommitOutcomeV1::Committed(committed)
            | WitnessCommitOutcomeV1::AlreadyCommitted(committed) => {
                validate_head_namespace(
                    &committed.head,
                    stream_id,
                    binding_generation,
                    binding_digest,
                    signer_key_id,
                    witness_key_id,
                    authority_pair,
                )?;
            }
            WitnessCommitOutcomeV1::Aborted(aborted) => {
                check_receipt(
                    &aborted.stream_id,
                    &aborted.binding_generation,
                    &aborted.binding_digest,
                    &aborted.signer_key_id,
                    &aborted.witness_key_id,
                    aborted.authority_pair,
                )?;
                validate_head_namespace(
                    &aborted.resulting_head,
                    stream_id,
                    binding_generation,
                    binding_digest,
                    signer_key_id,
                    witness_key_id,
                    authority_pair,
                )?;
            }
            WitnessCommitOutcomeV1::GenesisAborted(aborted) => {
                check_receipt(
                    &aborted.stream_id,
                    &aborted.binding_generation,
                    &aborted.binding_digest,
                    &aborted.signer_key_id,
                    &aborted.witness_key_id,
                    aborted.authority_pair,
                )?;
            }
        },
        WitnessOperationOutcomeV1::Abort(value) => match value.as_ref() {
            WitnessAbortOutcomeV1::Aborted(aborted)
            | WitnessAbortOutcomeV1::AlreadyAborted(aborted) => {
                check_receipt(
                    &aborted.stream_id,
                    &aborted.binding_generation,
                    &aborted.binding_digest,
                    &aborted.signer_key_id,
                    &aborted.witness_key_id,
                    aborted.authority_pair,
                )?;
                validate_head_namespace(
                    &aborted.resulting_head,
                    stream_id,
                    binding_generation,
                    binding_digest,
                    signer_key_id,
                    witness_key_id,
                    authority_pair,
                )?;
            }
            WitnessAbortOutcomeV1::Committed(committed) => {
                validate_head_namespace(
                    &committed.head,
                    stream_id,
                    binding_generation,
                    binding_digest,
                    signer_key_id,
                    witness_key_id,
                    authority_pair,
                )?;
            }
            WitnessAbortOutcomeV1::GenesisAborted(aborted) => {
                check_receipt(
                    &aborted.stream_id,
                    &aborted.binding_generation,
                    &aborted.binding_digest,
                    &aborted.signer_key_id,
                    &aborted.witness_key_id,
                    aborted.authority_pair,
                )?;
            }
        },
    }
    Ok(())
}

#[async_trait]
pub trait GovernanceDurabilityWitness: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn issue_session_fence(
        &self,
        request: crate::witness_service::WitnessServiceRequestV1,
    ) -> Result<WitnessSessionStateFenceV1, Self::Error>;

    /// Adapters return a signed wire response.  They cannot construct the
    /// opaque mutation capability; the governance caller must pass it through
    /// `GovernanceWitnessSession::from_verified_attestation` first.
    async fn establish_session(
        &self,
        request: crate::witness_service::WitnessServiceRequestV1,
    ) -> Result<WitnessSessionAttestationV1, Self::Error>;

    async fn discover_stream(
        &self,
        request: crate::witness_service::WitnessServiceRequestV1,
    ) -> Result<WitnessDiscoveryAttestationV1, Self::Error>;

    async fn prepare_successor(
        &self,
        request: crate::witness_service::WitnessServiceRequestV1,
    ) -> Result<WitnessOutcomeAttestationV1, Self::Error>;

    async fn commit_prepared(
        &self,
        request: crate::witness_service::WitnessServiceRequestV1,
    ) -> Result<WitnessOutcomeAttestationV1, Self::Error>;

    async fn abort_prepared(
        &self,
        request: crate::witness_service::WitnessServiceRequestV1,
    ) -> Result<WitnessOutcomeAttestationV1, Self::Error>;

    /// A session-bound read cannot be authorized by a raw stream identifier.
    async fn read_prepared_for_stream(
        &self,
        request: crate::witness_service::WitnessServiceRequestV1,
    ) -> Result<WitnessReadAttestationV1, Self::Error>;

    async fn read_head(
        &self,
        request: crate::witness_service::WitnessServiceRequestV1,
    ) -> Result<WitnessReadAttestationV1, Self::Error>;

    async fn fetch_payload(
        &self,
        request: crate::witness_service::WitnessServiceRequestV1,
    ) -> Result<WitnessReadAttestationV1, Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TransactionPhaseV1 {
    Intent,
    WitnessPrepared,
    PayloadsStaged,
    StateExchanged,
    CheckpointExchanged,
    ReadyForWitnessCommit,
    AbortPending,
    Committed,
    Aborted,
}

impl TransactionPhaseV1 {
    pub fn validate_transition(self, next: Self) -> ProtocolResult<()> {
        if self.allows_transition_to(next) {
            Ok(())
        } else {
            Err(ProtocolError::IllegalTransition {
                from: self,
                to: next,
            })
        }
    }

    fn allows_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (Self::Intent, Self::WitnessPrepared | Self::AbortPending) => true,
            (Self::WitnessPrepared, Self::PayloadsStaged | Self::AbortPending) => true,
            (Self::PayloadsStaged, Self::StateExchanged | Self::AbortPending) => true,
            (Self::StateExchanged, Self::CheckpointExchanged | Self::AbortPending) => true,
            (Self::CheckpointExchanged, Self::ReadyForWitnessCommit | Self::AbortPending) => true,
            (Self::ReadyForWitnessCommit, Self::AbortPending) => true,
            (Self::AbortPending | Self::Committed | Self::Aborted, _) => false,
            _ => false,
        }
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Aborted)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionRecordV1 {
    pub schema_version: u32,
    pub stream_id: String,
    pub txid: String,
    pub candidate_digest: String,
    pub intent_root_digest: String,
    pub predecessor_head: Option<WitnessHeadV1>,
    pub predecessor_head_digest: String,
    pub expected_predecessor_data_head_digest: String,
    pub epoch: u64,
    pub sequence: u64,
    pub intent_counter: u64,
    pub binding_generation: String,
    pub binding_digest: String,
    pub signer_key_id: String,
    pub witness_key_id: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub witness_predecessor_head_digest: String,
    pub witness_prepared_head_digest: String,
    pub witness_successor_head_digest: String,
    pub journal_lane: ArtifactIdentityV1,
    pub journal_generation: u64,
    pub phase: TransactionPhaseV1,
    pub previous_record_digest: Option<String>,
    pub witness_outcome: Option<WitnessTerminalOutcomeV1>,
    pub witness_prepared_attestation: Option<WitnessOutcomeAttestationV1>,
    pub witness_outcome_attestation: Option<WitnessOutcomeAttestationV1>,
    pub witness_prepared_discovery_attestation: Option<WitnessDiscoveryAttestationV1>,
    pub witness_terminal_discovery_attestation: Option<WitnessDiscoveryAttestationV1>,
    pub publication_mapping_before: PublicationMappingV1,
    pub publication_mapping_after: PublicationMappingV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TransactionIntentRootPreimageV1<'a> {
    schema_version: u32,
    stream_id: &'a str,
    txid: &'a str,
    candidate_digest: &'a str,
    predecessor_head_digest: &'a str,
    predecessor_head: &'a Option<WitnessHeadV1>,
    expected_predecessor_data_head_digest: &'a str,
    epoch: u64,
    sequence: u64,
    intent_counter: u64,
    binding_generation: &'a str,
    binding_digest: &'a str,
    signer_key_id: &'a str,
    witness_key_id: &'a str,
    authority_pair: AuthorityPairIdentityV1,
    witness_predecessor_head_digest: &'a str,
    witness_prepared_head_digest: &'a str,
    witness_successor_head_digest: &'a str,
    journal_lane: ArtifactIdentityV1,
    publication_mapping_before: PublicationMappingV1,
    publication_mapping_after: PublicationMappingV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionIntentV1 {
    pub schema_version: u32,
    pub stream_id: String,
    pub txid: String,
    pub candidate_digest: String,
    pub intent_root_digest: String,
    pub predecessor_head: Option<WitnessHeadV1>,
    pub predecessor_head_digest: String,
    pub expected_predecessor_data_head_digest: String,
    pub epoch: u64,
    pub sequence: u64,
    pub intent_counter: u64,
    pub binding_generation: String,
    pub binding_digest: String,
    pub signer_key_id: String,
    pub witness_key_id: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub witness_predecessor_head_digest: String,
    pub witness_prepared_head_digest: String,
    pub witness_successor_head_digest: String,
    pub journal_lane: ArtifactIdentityV1,
    pub publication_mapping_before: PublicationMappingV1,
    pub publication_mapping_after: PublicationMappingV1,
}

impl TransactionIntentV1 {
    fn root_preimage(&self) -> TransactionIntentRootPreimageV1<'_> {
        TransactionIntentRootPreimageV1 {
            schema_version: self.schema_version,
            stream_id: &self.stream_id,
            txid: &self.txid,
            candidate_digest: &self.candidate_digest,
            predecessor_head_digest: &self.predecessor_head_digest,
            predecessor_head: &self.predecessor_head,
            expected_predecessor_data_head_digest: &self.expected_predecessor_data_head_digest,
            epoch: self.epoch,
            sequence: self.sequence,
            intent_counter: self.intent_counter,
            binding_generation: &self.binding_generation,
            binding_digest: &self.binding_digest,
            signer_key_id: &self.signer_key_id,
            witness_key_id: &self.witness_key_id,
            authority_pair: self.authority_pair,
            witness_predecessor_head_digest: &self.witness_predecessor_head_digest,
            witness_prepared_head_digest: &self.witness_prepared_head_digest,
            witness_successor_head_digest: &self.witness_successor_head_digest,
            journal_lane: self.journal_lane,
            publication_mapping_before: self.publication_mapping_before,
            publication_mapping_after: self.publication_mapping_after,
        }
    }

    pub fn computed_root_digest(&self) -> ProtocolResult<String> {
        digest_domain(
            INTENT_ROOT_DOMAIN_V1,
            &canonical_wire_bytes(&self.root_preimage())?,
        )
    }

    pub fn from_candidate(candidate: &CandidateV1) -> ProtocolResult<Self> {
        candidate.validate()?;
        let preimage = &candidate.preimage;
        let successor_head = WitnessHeadV1::committed_from_candidate(candidate)?;
        let prepared_head = WitnessHeadV1::from_candidate(candidate)?;
        let mut intent = Self {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: preimage.stream_id.clone(),
            txid: candidate.txid.clone(),
            candidate_digest: candidate.candidate_digest.clone(),
            intent_root_digest: "0".repeat(64),
            predecessor_head: preimage.predecessor_head.clone(),
            predecessor_head_digest: preimage.predecessor_head_digest.clone(),
            expected_predecessor_data_head_digest: preimage.predecessor_data_head_digest.clone(),
            epoch: preimage.epoch,
            sequence: preimage.sequence,
            intent_counter: preimage.intent_counter,
            binding_generation: preimage.publication_binding.generation.clone(),
            binding_digest: preimage.publication_binding.binding_digest.clone(),
            signer_key_id: preimage.publication_binding.signer_key_id.clone(),
            witness_key_id: preimage.publication_binding.witness_key_id.clone(),
            authority_pair: preimage.publication_binding.authority_pair,
            witness_predecessor_head_digest: preimage.predecessor_head_digest.clone(),
            witness_prepared_head_digest: prepared_head.head_digest()?,
            witness_successor_head_digest: successor_head.head_digest()?,
            journal_lane: preimage.publication_mapping_before.journal_primary,
            publication_mapping_before: preimage.publication_mapping_before,
            publication_mapping_after: preimage.publication_mapping_after,
        };
        intent.intent_root_digest = intent.computed_root_digest()?;
        Ok(intent)
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_string("stream_id", &self.stream_id)?;
        validate_digest("txid", &self.txid)?;
        validate_digest("candidate_digest", &self.candidate_digest)?;
        validate_digest("intent_root_digest", &self.intent_root_digest)?;
        validate_digest("predecessor_head_digest", &self.predecessor_head_digest)?;
        validate_digest(
            "expected_predecessor_data_head_digest",
            &self.expected_predecessor_data_head_digest,
        )?;
        validate_digest(
            "witness_predecessor_head_digest",
            &self.witness_predecessor_head_digest,
        )?;
        validate_digest(
            "witness_prepared_head_digest",
            &self.witness_prepared_head_digest,
        )?;
        validate_digest(
            "witness_successor_head_digest",
            &self.witness_successor_head_digest,
        )?;
        if self.witness_predecessor_head_digest != self.predecessor_head_digest {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        self.authority_pair.validate()?;
        self.journal_lane.validate()?;
        if !journal_lane_is_allowed(&self.publication_mapping_before, self.journal_lane) {
            return Err(invalid(
                "journal_lane",
                "intent lane is not one of the bound journal lanes",
            ));
        }
        self.publication_mapping_before.validate()?;
        self.publication_mapping_after.validate()?;
        self.publication_mapping_after
            .validate_successor_of(&self.publication_mapping_before)?;
        validate_embedded_predecessor(EmbeddedPredecessorValidation {
            predecessor: self.predecessor_head.as_ref(),
            stream_id: &self.stream_id,
            binding_generation: &self.binding_generation,
            binding_digest: &self.binding_digest,
            signer_key_id: &self.signer_key_id,
            witness_key_id: &self.witness_key_id,
            authority_pair: self.authority_pair,
            publication_mapping_before: &self.publication_mapping_before,
            predecessor_head_digest: &self.predecessor_head_digest,
            predecessor_data_head_digest: &self.expected_predecessor_data_head_digest,
            epoch: self.epoch,
            sequence: self.sequence,
            intent_counter: self.intent_counter,
        })?;
        if self.intent_root_digest != self.computed_root_digest()? {
            return Err(ProtocolError::DigestMismatch {
                field: "intent_root_digest",
            });
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        canonical_wire_bytes(self)
    }

    pub fn decode(bytes: &[u8]) -> ProtocolResult<Self> {
        let value = decode_canonical::<Self>(bytes)?;
        value.validate()?;
        Ok(value)
    }
}

impl TransactionRecordV1 {
    pub fn intent(input: TransactionIntentV1) -> ProtocolResult<Self> {
        input.validate()?;
        let record = Self {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: input.stream_id,
            txid: input.txid,
            candidate_digest: input.candidate_digest,
            intent_root_digest: input.intent_root_digest,
            predecessor_head: input.predecessor_head,
            predecessor_head_digest: input.predecessor_head_digest,
            expected_predecessor_data_head_digest: input.expected_predecessor_data_head_digest,
            epoch: input.epoch,
            sequence: input.sequence,
            intent_counter: input.intent_counter,
            binding_generation: input.binding_generation,
            binding_digest: input.binding_digest,
            signer_key_id: input.signer_key_id,
            witness_key_id: input.witness_key_id,
            authority_pair: input.authority_pair,
            witness_predecessor_head_digest: input.witness_predecessor_head_digest,
            witness_prepared_head_digest: input.witness_prepared_head_digest,
            witness_successor_head_digest: input.witness_successor_head_digest,
            journal_lane: input.journal_lane,
            journal_generation: 0,
            phase: TransactionPhaseV1::Intent,
            previous_record_digest: None,
            witness_outcome: None,
            witness_prepared_attestation: None,
            witness_outcome_attestation: None,
            witness_prepared_discovery_attestation: None,
            witness_terminal_discovery_attestation: None,
            publication_mapping_before: input.publication_mapping_before,
            publication_mapping_after: input.publication_mapping_after,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        validate_string("stream_id", &self.stream_id)?;
        validate_digest("txid", &self.txid)?;
        validate_digest("candidate_digest", &self.candidate_digest)?;
        validate_digest("intent_root_digest", &self.intent_root_digest)?;
        validate_embedded_predecessor(EmbeddedPredecessorValidation {
            predecessor: self.predecessor_head.as_ref(),
            stream_id: &self.stream_id,
            binding_generation: &self.binding_generation,
            binding_digest: &self.binding_digest,
            signer_key_id: &self.signer_key_id,
            witness_key_id: &self.witness_key_id,
            authority_pair: self.authority_pair,
            publication_mapping_before: &self.publication_mapping_before,
            predecessor_head_digest: &self.predecessor_head_digest,
            predecessor_data_head_digest: &self.expected_predecessor_data_head_digest,
            epoch: self.epoch,
            sequence: self.sequence,
            intent_counter: self.intent_counter,
        })?;
        validate_digest("predecessor_head_digest", &self.predecessor_head_digest)?;
        validate_digest(
            "expected_predecessor_data_head_digest",
            &self.expected_predecessor_data_head_digest,
        )?;
        validate_digest(
            "witness_predecessor_head_digest",
            &self.witness_predecessor_head_digest,
        )?;
        validate_digest(
            "witness_prepared_head_digest",
            &self.witness_prepared_head_digest,
        )?;
        validate_digest(
            "witness_successor_head_digest",
            &self.witness_successor_head_digest,
        )?;
        if self.witness_predecessor_head_digest != self.predecessor_head_digest {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        self.authority_pair.validate()?;
        self.journal_lane.validate()?;
        if !journal_lane_is_allowed(&self.publication_mapping_before, self.journal_lane) {
            return Err(invalid(
                "journal_lane",
                "record lane is not one of the bound journal lanes",
            ));
        }
        if let Some(previous) = &self.previous_record_digest {
            validate_digest("previous_record_digest", previous)?;
        }
        match self.phase {
            TransactionPhaseV1::Intent
                if self.journal_generation != 0 || self.previous_record_digest.is_some() =>
            {
                return Err(invalid(
                    "transaction_record",
                    "Intent must be the generation-zero root record",
                ));
            }
            TransactionPhaseV1::Intent => {}
            _ if self.journal_generation == 0 || self.previous_record_digest.is_none() => {
                return Err(invalid(
                    "transaction_record",
                    "non-root phase requires a predecessor-linked generation",
                ));
            }
            _ => {}
        }
        self.publication_mapping_before.validate()?;
        self.publication_mapping_after.validate()?;
        self.publication_mapping_after
            .validate_successor_of(&self.publication_mapping_before)?;
        // Every phase record carries the immutable intent root.  Rebuild the
        // root preimage from the record's immutable intent fields rather than
        // trusting a generation-local journal lane (which alternates after
        // each phase).  This is the stable anchor that lets recovery validate
        // the latest two lanes without requiring the generation-zero record
        // to remain physically present.
        let intent = TransactionIntentV1 {
            schema_version: self.schema_version,
            stream_id: self.stream_id.clone(),
            txid: self.txid.clone(),
            candidate_digest: self.candidate_digest.clone(),
            intent_root_digest: self.intent_root_digest.clone(),
            predecessor_head: self.predecessor_head.clone(),
            predecessor_head_digest: self.predecessor_head_digest.clone(),
            expected_predecessor_data_head_digest: self
                .expected_predecessor_data_head_digest
                .clone(),
            epoch: self.epoch,
            sequence: self.sequence,
            intent_counter: self.intent_counter,
            binding_generation: self.binding_generation.clone(),
            binding_digest: self.binding_digest.clone(),
            signer_key_id: self.signer_key_id.clone(),
            witness_key_id: self.witness_key_id.clone(),
            authority_pair: self.authority_pair,
            witness_predecessor_head_digest: self.witness_predecessor_head_digest.clone(),
            witness_prepared_head_digest: self.witness_prepared_head_digest.clone(),
            witness_successor_head_digest: self.witness_successor_head_digest.clone(),
            journal_lane: self.publication_mapping_before.journal_primary,
            publication_mapping_before: self.publication_mapping_before,
            publication_mapping_after: self.publication_mapping_after,
        };
        intent.validate()?;
        if self.phase.is_terminal() {
            match (&self.phase, &self.witness_outcome) {
                (
                    TransactionPhaseV1::Committed,
                    Some(WitnessTerminalOutcomeV1::Committed(value)),
                ) => self.validate_terminal_commit(value)?,
                (TransactionPhaseV1::Aborted, Some(WitnessTerminalOutcomeV1::Aborted(value))) => {
                    self.validate_terminal_abort(value)?
                }
                (
                    TransactionPhaseV1::Aborted,
                    Some(WitnessTerminalOutcomeV1::GenesisAborted(value)),
                ) => self.validate_witness_genesis_abort(value)?,
                _ => return Err(ProtocolError::WitnessOutcomeMismatch),
            }
        } else if self.witness_outcome.is_some() {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let prepared_authority_count = self.witness_prepared_attestation.is_some() as u8
            + self.witness_prepared_discovery_attestation.is_some() as u8;
        let terminal_authority_count = self.witness_outcome_attestation.is_some() as u8
            + self.witness_terminal_discovery_attestation.is_some() as u8;
        match self.phase {
            TransactionPhaseV1::Intent => {
                if self.witness_prepared_attestation.is_some()
                    || self.witness_outcome_attestation.is_some()
                    || self.witness_prepared_discovery_attestation.is_some()
                    || self.witness_terminal_discovery_attestation.is_some()
                {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            }
            TransactionPhaseV1::WitnessPrepared
            | TransactionPhaseV1::PayloadsStaged
            | TransactionPhaseV1::StateExchanged
            | TransactionPhaseV1::CheckpointExchanged
            | TransactionPhaseV1::ReadyForWitnessCommit => {
                if terminal_authority_count != 0 || prepared_authority_count != 1 {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            }
            TransactionPhaseV1::AbortPending => {
                if self.witness_outcome_attestation.is_some()
                    || self.witness_terminal_discovery_attestation.is_some()
                    || prepared_authority_count > 1
                {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            }
            TransactionPhaseV1::Committed | TransactionPhaseV1::Aborted => {
                if (self.phase == TransactionPhaseV1::Committed && prepared_authority_count != 1)
                    || terminal_authority_count != 1
                {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            }
        }
        if let Some(attestation) = &self.witness_prepared_attestation {
            validate_prepared_outcome_attestation_for_record(attestation, self)?;
        }
        if let Some(attestation) = &self.witness_outcome_attestation {
            validate_attestation_namespace_for_record(attestation, self, attestation.operation)?;
            validate_outcome_attestation_for_record(attestation, self)?;
        }
        if let Some(attestation) = &self.witness_prepared_discovery_attestation {
            validate_prepared_discovery_attestation_for_record(attestation, self)?;
        }
        if let Some(attestation) = &self.witness_terminal_discovery_attestation {
            validate_terminal_discovery_attestation_for_record(attestation, self)?;
        }
        Ok(())
    }

    pub fn record_digest(&self) -> ProtocolResult<String> {
        digest_domain(JOURNAL_RECORD_DOMAIN_V1, &self.canonical_bytes()?)
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        let bytes = canonical_wire_bytes(self)?;
        if bytes.len() > MAX_PROTOCOL_RECORD_BYTES {
            return Err(ProtocolError::Bounds {
                field: "transaction_record".to_string(),
                observed: bytes.len(),
                maximum: MAX_PROTOCOL_RECORD_BYTES,
            });
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> ProtocolResult<Self> {
        let value = decode_canonical::<Self>(bytes)?;
        value.validate()?;
        Ok(value)
    }

    pub fn transition(&self, next: TransactionPhaseV1) -> ProtocolResult<Self> {
        self.validate()?;
        if self.phase == TransactionPhaseV1::Intent && next == TransactionPhaseV1::WitnessPrepared {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        self.phase.validate_transition(next)?;
        let mut record = self.clone();
        record.phase = next;
        record.witness_outcome = None;
        record.journal_lane =
            next_journal_lane(&self.publication_mapping_before, self.journal_lane)?;
        record.journal_generation = checked_next_journal_generation(self.journal_generation)?;
        record.previous_record_digest = Some(self.record_digest()?);
        record.validate()?;
        Ok(record)
    }

    /// Persist the abort intent before calling the external witness. This is
    /// deliberately not a terminal outcome: only a verified witness receipt
    /// may produce `Aborted` after the external witness returns.
    pub fn begin_abort(&self) -> ProtocolResult<Self> {
        if matches!(
            self.phase,
            TransactionPhaseV1::AbortPending
                | TransactionPhaseV1::Committed
                | TransactionPhaseV1::Aborted
        ) {
            return Err(ProtocolError::IllegalTransition {
                from: self.phase,
                to: TransactionPhaseV1::AbortPending,
            });
        }
        self.validate()?;
        self.transition(TransactionPhaseV1::AbortPending)
    }

    /// Compatibility spelling for callers that previously requested an
    /// intent abort. It now returns the durable pending marker and cannot
    /// manufacture a local terminal `Aborted` record.
    pub fn abort_intent(&self) -> ProtocolResult<Self> {
        self.begin_abort()
    }

    /// Raw witness outcomes are intentionally not authority-bearing.  They
    /// are accepted only after `VerifiedWitnessOutcomeV1` has checked the
    /// pinned signed attestation and session capability.
    pub fn resolve_abort_outcome(&self, _outcome: &WitnessAbortOutcomeV1) -> ProtocolResult<Self> {
        Err(ProtocolError::WitnessOutcomeMismatch)
    }

    /// Raw witness outcomes are intentionally not authority-bearing.
    pub fn resolve_commit_outcome(
        &self,
        _outcome: &WitnessCommitOutcomeV1,
    ) -> ProtocolResult<Self> {
        Err(ProtocolError::WitnessOutcomeMismatch)
    }

    pub fn resolve_verified_prepare(
        &self,
        verified: &VerifiedWitnessOutcomeV1,
    ) -> ProtocolResult<Self> {
        self.require_phase(TransactionPhaseV1::Intent)?;
        if verified.operation() != WitnessOperationV1::Prepare {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let prepared = match verified.outcome() {
            WitnessOperationOutcomeV1::Prepare(value) => match value.as_ref() {
                WitnessPrepareOutcomeV1::Prepared(prepared)
                | WitnessPrepareOutcomeV1::AlreadyPrepared(prepared) => prepared,
                WitnessPrepareOutcomeV1::Conflict => {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            },
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        };
        self.validate_witness_prepared(prepared, verified.attestation().session_generation)?;
        let mut record = self.clone();
        record.phase = TransactionPhaseV1::WitnessPrepared;
        record.journal_generation = checked_next_journal_generation(self.journal_generation)?;
        record.previous_record_digest = Some(self.record_digest()?);
        record.journal_lane =
            next_journal_lane(&self.publication_mapping_before, self.journal_lane)?;
        record.witness_prepared_attestation = Some(verified.attestation().clone());
        record.witness_outcome = None;
        record.witness_outcome_attestation = None;
        record.witness_prepared_discovery_attestation = None;
        record.witness_terminal_discovery_attestation = None;
        record.validate()?;
        Ok(record)
    }

    pub fn resolve_verified_commit(
        &self,
        verified: &VerifiedWitnessOutcomeV1,
    ) -> ProtocolResult<Self> {
        if !matches!(
            self.phase,
            TransactionPhaseV1::ReadyForWitnessCommit | TransactionPhaseV1::AbortPending
        ) {
            return Err(ProtocolError::IllegalTransition {
                from: self.phase,
                to: TransactionPhaseV1::Committed,
            });
        }
        if verified.operation() != WitnessOperationV1::Commit {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        match verified.outcome() {
            WitnessOperationOutcomeV1::Commit(value) => match value.as_ref() {
                WitnessCommitOutcomeV1::Committed(value)
                | WitnessCommitOutcomeV1::AlreadyCommitted(value) => {
                    self.validate_witness_commit(value)?;
                    self.complete_terminal(
                        TransactionPhaseV1::Committed,
                        value.head.intent_counter,
                        WitnessTerminalOutcomeV1::Committed(Box::new(value.clone())),
                        Some(verified.attestation().clone()),
                        None,
                    )
                }
                WitnessCommitOutcomeV1::Aborted(value) => {
                    self.require_phase(TransactionPhaseV1::AbortPending)?;
                    self.validate_witness_abort(value)?;
                    self.complete_terminal(
                        TransactionPhaseV1::Aborted,
                        value.intent_counter,
                        WitnessTerminalOutcomeV1::Aborted(value.clone()),
                        Some(verified.attestation().clone()),
                        None,
                    )
                }
                WitnessCommitOutcomeV1::GenesisAborted(value) => {
                    self.require_phase(TransactionPhaseV1::AbortPending)?;
                    self.validate_witness_genesis_abort(value)?;
                    self.complete_terminal(
                        TransactionPhaseV1::Aborted,
                        value.intent_counter,
                        WitnessTerminalOutcomeV1::GenesisAborted(value.clone()),
                        Some(verified.attestation().clone()),
                        None,
                    )
                }
            },
            _ => Err(ProtocolError::WitnessOutcomeMismatch),
        }
    }

    pub fn resolve_verified_abort(
        &self,
        verified: &VerifiedWitnessOutcomeV1,
    ) -> ProtocolResult<Self> {
        self.require_phase(TransactionPhaseV1::AbortPending)?;
        if verified.operation() != WitnessOperationV1::Abort {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        match verified.outcome() {
            WitnessOperationOutcomeV1::Abort(value) => match value.as_ref() {
                WitnessAbortOutcomeV1::Aborted(value)
                | WitnessAbortOutcomeV1::AlreadyAborted(value) => {
                    self.validate_witness_abort(value)?;
                    self.complete_terminal(
                        TransactionPhaseV1::Aborted,
                        value.intent_counter,
                        WitnessTerminalOutcomeV1::Aborted(Box::new(value.clone())),
                        Some(verified.attestation().clone()),
                        None,
                    )
                }
                WitnessAbortOutcomeV1::Committed(value) => {
                    self.validate_witness_commit(value)?;
                    self.complete_terminal(
                        TransactionPhaseV1::Committed,
                        value.head.intent_counter,
                        WitnessTerminalOutcomeV1::Committed(Box::new(value.clone())),
                        Some(verified.attestation().clone()),
                        None,
                    )
                }
                WitnessAbortOutcomeV1::GenesisAborted(value) => {
                    self.validate_witness_genesis_abort(value)?;
                    self.complete_terminal(
                        TransactionPhaseV1::Aborted,
                        value.intent_counter,
                        WitnessTerminalOutcomeV1::GenesisAborted(Box::new(value.clone())),
                        Some(verified.attestation().clone()),
                        None,
                    )
                }
            },
            _ => Err(ProtocolError::WitnessOutcomeMismatch),
        }
    }

    /// Resolve a lost commit/abort response from session-independent witness
    /// discovery. A matching prepared record leaves the local phase pending;
    /// a matching committed/aborted receipt is the only terminal decision.
    pub fn resolve_discovery(&self, _discovery: &WitnessDiscoveryV1) -> ProtocolResult<Self> {
        Err(ProtocolError::WitnessOutcomeMismatch)
    }

    pub fn resolve_verified_discovery(
        &self,
        verified: &VerifiedWitnessDiscoveryV1,
    ) -> ProtocolResult<Self> {
        if !matches!(
            self.phase,
            TransactionPhaseV1::Intent
                | TransactionPhaseV1::ReadyForWitnessCommit
                | TransactionPhaseV1::AbortPending
        ) {
            return Err(ProtocolError::RecoveryAmbiguous);
        }
        let discovery = verified.discovery();
        discovery.validate()?;
        if let Some(genesis_abort) = &discovery.genesis_abort {
            if self.phase != TransactionPhaseV1::AbortPending {
                return Err(ProtocolError::RecoveryAmbiguous);
            }
            self.validate_witness_genesis_abort(genesis_abort)?;
            return self.complete_terminal(
                TransactionPhaseV1::Aborted,
                genesis_abort.intent_counter,
                WitnessTerminalOutcomeV1::GenesisAborted(Box::new(genesis_abort.clone())),
                None,
                Some(verified.attestation().clone()),
            );
        }
        if let Some(head) = &discovery.head {
            if self.phase == TransactionPhaseV1::Intent && discovery.prepared.is_none() {
                return Err(ProtocolError::RecoveryAmbiguous);
            }
            match head.last_intent_outcome.as_ref() {
                Some(WitnessIntentOutcomeV1::Committed { txid, .. }) if txid == &self.txid => {
                    if self.phase == TransactionPhaseV1::Intent {
                        return Err(ProtocolError::RecoveryAmbiguous);
                    }
                    let committed = WitnessCommittedV1 {
                        schema_version: PROTOCOL_SCHEMA_VERSION,
                        head: head.clone(),
                    };
                    self.validate_witness_commit(&committed)?;
                    return self.complete_terminal(
                        TransactionPhaseV1::Committed,
                        head.intent_counter,
                        WitnessTerminalOutcomeV1::Committed(Box::new(committed)),
                        None,
                        Some(verified.attestation().clone()),
                    );
                }
                Some(WitnessIntentOutcomeV1::Aborted(summary)) if summary.txid == self.txid => {
                    if self.phase != TransactionPhaseV1::AbortPending {
                        return Err(ProtocolError::RecoveryAmbiguous);
                    }
                    let aborted = WitnessAbortedV1::from_resulting_head(
                        head,
                        "discovered-abort".to_string(),
                    )?;
                    self.validate_witness_abort(&aborted)?;
                    return self.complete_terminal(
                        TransactionPhaseV1::Aborted,
                        aborted.intent_counter,
                        WitnessTerminalOutcomeV1::Aborted(Box::new(aborted)),
                        None,
                        Some(verified.attestation().clone()),
                    );
                }
                _ => {}
            }
        }
        if let Some(prepared) = &discovery.prepared {
            self.validate_witness_prepared(
                prepared,
                discovery.recovery_session.session_generation,
            )?;
            if self.phase == TransactionPhaseV1::Intent {
                let mut record = self.clone();
                record.phase = TransactionPhaseV1::WitnessPrepared;
                record.journal_generation =
                    checked_next_journal_generation(self.journal_generation)?;
                record.previous_record_digest = Some(self.record_digest()?);
                record.journal_lane =
                    next_journal_lane(&self.publication_mapping_before, self.journal_lane)?;
                record.witness_prepared_attestation = None;
                record.witness_outcome = None;
                record.witness_outcome_attestation = None;
                record.witness_prepared_discovery_attestation =
                    Some(verified.attestation().clone());
                record.witness_terminal_discovery_attestation = None;
                record.validate()?;
                return Ok(record);
            }
            return Ok(self.clone());
        }
        Err(ProtocolError::RecoveryAmbiguous)
    }

    fn require_phase(&self, phase: TransactionPhaseV1) -> ProtocolResult<()> {
        if self.phase != phase {
            return Err(ProtocolError::IllegalTransition {
                from: self.phase,
                to: phase,
            });
        }
        self.validate()
    }

    fn validate_witness_prepared(
        &self,
        prepared: &WitnessPreparedV1,
        expected_session_generation: u64,
    ) -> ProtocolResult<()> {
        prepared.validate()?;
        let head = &prepared.head;
        if prepared.session_generation != expected_session_generation
            || head.stream_id != self.stream_id
            || head.txid != self.txid
            || head.candidate_digest != self.candidate_digest
            || head.epoch != self.epoch
            || head.sequence != self.sequence
            || head.intent_counter != self.intent_counter
            || head.binding_generation != self.binding_generation
            || head.binding_digest != self.binding_digest
            || head.authority_pair != self.authority_pair
            || head.publication_mapping != self.publication_mapping_after
            || prepared.predecessor_head.as_ref() != self.predecessor_head.as_ref()
            || prepared.predecessor_head_digest != self.predecessor_head_digest
            || prepared.predecessor_data_head_digest != self.expected_predecessor_data_head_digest
            || prepared.predecessor_publication_mapping != self.publication_mapping_before
            || prepared.head.head_digest()? != self.witness_prepared_head_digest
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    fn validate_witness_commit(&self, committed: &WitnessCommittedV1) -> ProtocolResult<()> {
        committed.validate()?;
        let head = &committed.head;
        if head.stream_id != self.stream_id
            || head.txid != self.txid
            || head.candidate_digest != self.candidate_digest
            || head.epoch != self.epoch
            || head.sequence != self.sequence
            || head.intent_counter != self.intent_counter
            || head.binding_generation != self.binding_generation
            || head.binding_digest != self.binding_digest
            || head.authority_pair != self.authority_pair
            || head.publication_mapping != self.publication_mapping_after
            || head.head_digest()? != self.witness_successor_head_digest
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    fn validate_witness_abort(&self, aborted: &WitnessAbortedV1) -> ProtocolResult<()> {
        aborted.validate()?;
        let predecessor = self
            .predecessor_head
            .as_ref()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        aborted.validate_against_predecessor(predecessor)?;
        self.validate_aborted_prepared_evidence(aborted)?;
        if aborted.stream_id != self.stream_id
            || aborted.txid != self.txid
            || aborted.candidate_digest != self.candidate_digest
            || aborted.predecessor_head_digest != self.predecessor_head_digest
            || aborted.epoch != self.epoch
            || aborted.sequence != self.sequence
            || aborted.intent_counter != self.intent_counter
            || aborted.binding_generation != self.binding_generation
            || aborted.binding_digest != self.binding_digest
            || aborted.signer_key_id != self.signer_key_id
            || aborted.witness_key_id != self.witness_key_id
            || aborted.authority_pair != self.authority_pair
            || aborted.publication_mapping != self.publication_mapping_before
            || aborted.predecessor_head_digest != self.witness_predecessor_head_digest
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    fn validate_terminal_commit(&self, committed: &WitnessCommittedV1) -> ProtocolResult<()> {
        self.validate_witness_commit(committed)
    }

    fn validate_terminal_abort(&self, aborted: &WitnessAbortedV1) -> ProtocolResult<()> {
        self.validate_witness_abort(aborted)?;
        Ok(())
    }

    fn validate_aborted_prepared_evidence(&self, aborted: &WitnessAbortedV1) -> ProtocolResult<()> {
        if let Some(attestation) = &self.witness_prepared_attestation {
            match &attestation.outcome {
                WitnessOperationOutcomeV1::Prepare(outcome) => match outcome.as_ref() {
                    WitnessPrepareOutcomeV1::Prepared(prepared)
                    | WitnessPrepareOutcomeV1::AlreadyPrepared(prepared) => {
                        aborted.validate_against_prepared(prepared)?;
                    }
                    WitnessPrepareOutcomeV1::Conflict => {
                        return Err(ProtocolError::WitnessOutcomeMismatch);
                    }
                },
                _ => return Err(ProtocolError::WitnessOutcomeMismatch),
            }
        }
        if let Some(attestation) = &self.witness_prepared_discovery_attestation {
            let prepared = attestation
                .discovery
                .prepared
                .as_ref()
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            aborted.validate_against_prepared(prepared)?;
        }
        Ok(())
    }

    fn validate_witness_genesis_abort(
        &self,
        aborted: &WitnessGenesisAbortedV1,
    ) -> ProtocolResult<()> {
        aborted.validate()?;
        if self.predecessor_head.is_some()
            || aborted.stream_id != self.stream_id
            || aborted.txid != self.txid
            || aborted.candidate_digest != self.candidate_digest
            || aborted.predecessor_head_digest != self.predecessor_head_digest
            || aborted.predecessor_head_digest != self.witness_predecessor_head_digest
            || aborted.resulting_data_head_digest != self.expected_predecessor_data_head_digest
            || aborted.epoch != self.epoch
            || aborted.sequence != self.sequence
            || aborted.intent_counter != self.intent_counter
            || aborted.binding_generation != self.binding_generation
            || aborted.binding_digest != self.binding_digest
            || aborted.signer_key_id != self.signer_key_id
            || aborted.witness_key_id != self.witness_key_id
            || aborted.authority_pair != self.authority_pair
            || aborted.publication_mapping != self.publication_mapping_before
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    fn complete_terminal(
        &self,
        phase: TransactionPhaseV1,
        intent_counter: u64,
        witness_outcome: WitnessTerminalOutcomeV1,
        witness_outcome_attestation: Option<WitnessOutcomeAttestationV1>,
        terminal_discovery_attestation: Option<WitnessDiscoveryAttestationV1>,
    ) -> ProtocolResult<Self> {
        if !matches!(
            phase,
            TransactionPhaseV1::Committed | TransactionPhaseV1::Aborted
        ) {
            return Err(ProtocolError::IllegalTransition {
                from: self.phase,
                to: phase,
            });
        }
        let mut record = self.clone();
        record.phase = phase;
        record.journal_generation = checked_next_journal_generation(self.journal_generation)?;
        record.previous_record_digest = Some(self.record_digest()?);
        record.intent_counter = intent_counter;
        record.journal_lane =
            next_journal_lane(&self.publication_mapping_before, self.journal_lane)?;
        record.witness_outcome = Some(witness_outcome);
        record.witness_outcome_attestation = witness_outcome_attestation;
        record.witness_terminal_discovery_attestation = terminal_discovery_attestation;
        record.validate()?;
        Ok(record)
    }
}

/// A journal record is not authority until this envelope has been verified
/// against the admitted governance signer and exact stream/binding namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceJournalRecordV1 {
    pub schema_version: u32,
    pub stream_id: String,
    pub binding_generation: String,
    pub binding_digest: String,
    pub signer_key_id: String,
    pub authority_pair: AuthorityPairIdentityV1,
    pub journal_lane: ArtifactIdentityV1,
    pub journal_generation: u64,
    pub record_digest: String,
    pub record: TransactionRecordV1,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GovernanceJournalRecordPreimageV1<'a> {
    schema_version: u32,
    stream_id: &'a str,
    binding_generation: &'a str,
    binding_digest: &'a str,
    signer_key_id: &'a str,
    authority_pair: AuthorityPairIdentityV1,
    journal_lane: ArtifactIdentityV1,
    journal_generation: u64,
    record_digest: &'a str,
    record: &'a TransactionRecordV1,
}

impl GovernanceJournalRecordV1 {
    pub fn unsigned(record: TransactionRecordV1) -> ProtocolResult<Self> {
        record.validate()?;
        Ok(Self {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: record.stream_id.clone(),
            binding_generation: record.binding_generation.clone(),
            binding_digest: record.binding_digest.clone(),
            signer_key_id: record.signer_key_id.clone(),
            authority_pair: record.authority_pair,
            journal_lane: record.journal_lane,
            journal_generation: record.journal_generation,
            record_digest: record.record_digest()?,
            record,
            signature: DetachedSignature {
                algorithm: "ed25519".to_string(),
                key_id: String::new(),
                public_key_hex: String::new(),
                signature_hex: String::new(),
            },
        })
    }

    pub fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        canonical_wire_bytes(&GovernanceJournalRecordPreimageV1 {
            schema_version: self.schema_version,
            stream_id: &self.stream_id,
            binding_generation: &self.binding_generation,
            binding_digest: &self.binding_digest,
            signer_key_id: &self.signer_key_id,
            authority_pair: self.authority_pair,
            journal_lane: self.journal_lane,
            journal_generation: self.journal_generation,
            record_digest: &self.record_digest,
            record: &self.record,
        })
    }

    /// Structural and signature validation only.  This does not admit the
    /// record for recovery; callers must provide the current signed binding
    /// to `validate_against_binding`.
    fn validate_structure(&self) -> ProtocolResult<()> {
        if self.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedSchema(self.schema_version));
        }
        self.record.validate()?;
        validate_string("stream_id", &self.stream_id)?;
        validate_digest("binding_generation", &self.binding_generation)?;
        validate_digest("binding_digest", &self.binding_digest)?;
        validate_digest("signer_key_id", &self.signer_key_id)?;
        self.authority_pair.validate()?;
        self.journal_lane.validate()?;
        validate_digest("record_digest", &self.record_digest)?;
        if self.stream_id != self.record.stream_id
            || self.binding_generation != self.record.binding_generation
            || self.binding_digest != self.record.binding_digest
            || self.signer_key_id != self.record.signer_key_id
            || self.authority_pair != self.record.authority_pair
            || self.journal_lane != self.record.journal_lane
            || self.journal_generation != self.record.journal_generation
            || self.record_digest != self.record.record_digest()?
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        if self.signature.algorithm != "ed25519"
            || self.signature.key_id != self.signer_key_id
            || !swarm_crypto::PublicKey::from_hex(&self.signature.public_key_hex)
                .map(|key| sha256_hex(key.as_bytes()) == self.signer_key_id)
                .unwrap_or(false)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        verify_detached_signature(&self.signing_bytes()?, &self.signature)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)
    }

    pub fn validate_against_binding(&self, binding: &PublicationBindingV1) -> ProtocolResult<()> {
        binding.validate()?;
        self.validate_structure()?;
        if self.stream_id != binding.stream_id
            || self.binding_generation != binding.generation
            || self.binding_digest != binding.binding_digest
            || self.signer_key_id != binding.signer_key_id
            || self.authority_pair != binding.authority_pair
            || self.record.stream_id != binding.stream_id
            || self.record.binding_generation != binding.generation
            || self.record.binding_digest != binding.binding_digest
            || self.record.signer_key_id != binding.signer_key_id
            || self.record.witness_key_id != binding.witness_key_id
            || self.record.authority_pair != binding.authority_pair
            || self
                .record
                .publication_mapping_before
                .validate_against(&binding.publication_roles)
                .is_err()
            || self
                .record
                .publication_mapping_after
                .validate_against(&binding.publication_roles)
                .is_err()
            || ![
                binding.publication_roles.journal_primary,
                binding.publication_roles.journal_secondary,
            ]
            .contains(&self.journal_lane)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }
}

/// A journal envelope is only meaningful together with the physical fixed
/// lane from which it was observed.  The signed `journal_lane` field is a
/// claim; this wrapper carries the independently observed inode identity so a
/// valid envelope copied into the other fixed lane cannot be accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceJournalLaneObservationV1 {
    pub observed_lane: ArtifactIdentityV1,
    pub envelope: GovernanceJournalRecordV1,
}

impl GovernanceJournalLaneObservationV1 {
    fn validate_structure(&self) -> ProtocolResult<()> {
        self.observed_lane.validate()?;
        self.envelope.validate_structure()?;
        if self.observed_lane != self.envelope.journal_lane {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    pub fn validate_against_binding(&self, binding: &PublicationBindingV1) -> ProtocolResult<()> {
        self.validate_structure()?;
        self.envelope.validate_against_binding(binding)?;
        if ![
            binding.publication_roles.journal_primary,
            binding.publication_roles.journal_secondary,
        ]
        .contains(&self.observed_lane)
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }
}

pub fn validate_recovery_pair(
    first: &GovernanceJournalLaneObservationV1,
    second: &GovernanceJournalLaneObservationV1,
    binding: &PublicationBindingV1,
) -> ProtocolResult<()> {
    binding.validate()?;
    first.validate_against_binding(binding)?;
    second.validate_against_binding(binding)?;
    if first == second || first.observed_lane == second.observed_lane {
        return Err(ProtocolError::RecoveryFork {
            generation: first.envelope.journal_generation,
        });
    }
    let first_record = &first.envelope;
    let second_record = &second.envelope;
    let mapping = &first_record.record.publication_mapping_before;
    if first_record.record.publication_mapping_before
        != second_record.record.publication_mapping_before
        || first.observed_lane != first_record.journal_lane
        || second.observed_lane != second_record.journal_lane
        || ![mapping.journal_primary, mapping.journal_secondary].contains(&first.observed_lane)
        || ![mapping.journal_primary, mapping.journal_secondary].contains(&second.observed_lane)
    {
        return Err(ProtocolError::RecoveryFork {
            generation: second_record.journal_generation,
        });
    }
    let (older, newer) = if first_record.journal_generation < second_record.journal_generation {
        (first_record, second_record)
    } else {
        (second_record, first_record)
    };
    if checked_next_journal_generation(older.journal_generation)? != newer.journal_generation
        || newer.record.previous_record_digest.as_deref() != Some(older.record_digest.as_str())
        || newer.record.intent_root_digest != older.record.intent_root_digest
    {
        return Err(ProtocolError::RecoveryFork {
            generation: newer.journal_generation,
        });
    }
    let witness_terminal = matches!(
        older.record.phase,
        TransactionPhaseV1::ReadyForWitnessCommit | TransactionPhaseV1::AbortPending
    ) && matches!(
        newer.record.phase,
        TransactionPhaseV1::Committed | TransactionPhaseV1::Aborted
    );
    // Discovery can fill the journal gap between a durable Intent and the
    // first local record in two narrowly authenticated cases.  A prepared
    // discovery supplies the witness-prepared state; a genesis-abort
    // discovery supplies the terminal state when there is no committed data
    // head.  Both cases require the signed discovery attestation to be newly
    // present, and genesis abort additionally requires its exact terminal
    // outcome.  No other phase transition is widened here.
    let prepared_discovery_recovery = match (older.record.phase, newer.record.phase) {
        (TransactionPhaseV1::Intent, TransactionPhaseV1::WitnessPrepared) => {
            older
                .record
                .witness_prepared_discovery_attestation
                .is_none()
                && newer
                    .record
                    .witness_prepared_discovery_attestation
                    .is_some()
                && newer.record.witness_prepared_attestation.is_none()
        }
        _ => false,
    };
    let terminal_discovery_recovery = match (older.record.phase, newer.record.phase) {
        (TransactionPhaseV1::Intent, TransactionPhaseV1::Aborted) => {
            older
                .record
                .witness_terminal_discovery_attestation
                .is_none()
                && newer
                    .record
                    .witness_terminal_discovery_attestation
                    .is_some()
                && matches!(
                    newer.record.witness_outcome.as_ref(),
                    Some(WitnessTerminalOutcomeV1::GenesisAborted(_))
                )
        }
        _ => false,
    };
    let discovery_recovery = prepared_discovery_recovery || terminal_discovery_recovery;
    if newer.record.txid != older.record.txid
        || newer.record.stream_id != older.record.stream_id
        || newer.record.candidate_digest != older.record.candidate_digest
        || newer.record.predecessor_head_digest != older.record.predecessor_head_digest
        || newer.record.expected_predecessor_data_head_digest
            != older.record.expected_predecessor_data_head_digest
        || newer.record.epoch != older.record.epoch
        || newer.record.sequence != older.record.sequence
        || newer.record.binding_generation != older.record.binding_generation
        || newer.record.binding_digest != older.record.binding_digest
        || newer.record.signer_key_id != older.record.signer_key_id
        || newer.record.witness_key_id != older.record.witness_key_id
        || newer.record.authority_pair != older.record.authority_pair
        || newer.record.witness_predecessor_head_digest
            != older.record.witness_predecessor_head_digest
        || newer.record.witness_prepared_head_digest != older.record.witness_prepared_head_digest
        || newer.record.witness_successor_head_digest != older.record.witness_successor_head_digest
        || (newer.record.witness_prepared_attestation != older.record.witness_prepared_attestation
            && !matches!(
                (older.record.phase, newer.record.phase),
                (
                    TransactionPhaseV1::Intent,
                    TransactionPhaseV1::WitnessPrepared
                )
            ))
        || next_journal_lane(
            &older.record.publication_mapping_before,
            older.record.journal_lane,
        )? != newer.record.journal_lane
        || newer.record.publication_mapping_before != older.record.publication_mapping_before
        || newer.record.publication_mapping_after != older.record.publication_mapping_after
        || (newer.record.witness_outcome != older.record.witness_outcome
            && !matches!(
                (older.record.phase, newer.record.phase),
                (
                    TransactionPhaseV1::ReadyForWitnessCommit | TransactionPhaseV1::AbortPending,
                    TransactionPhaseV1::Committed | TransactionPhaseV1::Aborted
                )
            )
            && !discovery_recovery)
        || (newer.record.witness_prepared_discovery_attestation
            != older.record.witness_prepared_discovery_attestation
            && !prepared_discovery_recovery)
        || (newer.record.witness_terminal_discovery_attestation
            != older.record.witness_terminal_discovery_attestation
            && !witness_terminal
            && !terminal_discovery_recovery)
    {
        return Err(ProtocolError::RecoveryFork {
            generation: newer.journal_generation,
        });
    }
    if !witness_terminal
        && !discovery_recovery
        && older
            .record
            .phase
            .validate_transition(newer.record.phase)
            .is_err()
    {
        return Err(ProtocolError::RecoveryFork {
            generation: newer.journal_generation,
        });
    }
    if newer.record.intent_counter != older.record.intent_counter {
        return Err(ProtocolError::RecoveryFork {
            generation: newer.journal_generation,
        });
    }
    Ok(())
}

pub fn select_recovery_record(
    records: &[GovernanceJournalLaneObservationV1],
    binding: &PublicationBindingV1,
) -> ProtocolResult<TransactionRecordV1> {
    if records.len() != 2 {
        return Err(ProtocolError::RecoveryAmbiguous);
    }
    validate_recovery_pair(&records[0], &records[1], binding)?;
    let latest = if records[0].envelope.journal_generation > records[1].envelope.journal_generation
    {
        &records[0].envelope
    } else {
        &records[1].envelope
    };
    Ok(latest.record.clone())
}

pub fn validate_reinitialization_epoch(current: u64, next: u64) -> ProtocolResult<()> {
    let expected = checked_next_epoch(current)?;
    if next != expected {
        return Err(ProtocolError::InvalidEpoch {
            expected,
            observed: next,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
