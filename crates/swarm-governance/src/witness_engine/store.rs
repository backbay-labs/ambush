//! Typed, transport-free revision-CAS boundary for the governance witness.
//!
//! This module deliberately exposes logical stream identifiers and typed
//! results only. NATS subjects, headers, raw keys, and revision-zero creation
//! are outside the online capability.

use super::{WitnessStoreEnvelopeV1, WitnessStoreExpectationV1, validate_store_transition};
use crate::persistence_protocol::{
    MAX_PROTOCOL_COLLECTION_ITEMS, MAX_PROTOCOL_RECORD_BYTES, MAX_PROTOCOL_STRING_BYTES,
    PROTOCOL_SCHEMA_VERSION, ProtocolError, ProtocolResult, canonical_wire_bytes, decode_canonical,
    digest_domain,
};
use crate::witness_service::WitnessAdmissionRecordV1;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use swarm_crypto::{DetachedSignature, PublicKey, sha256_hex, verify_detached_signature};

pub mod in_memory;
pub mod proxy;

#[cfg(test)]
mod tests;

pub const WITNESS_ADMISSION_SET_DOMAIN_V1: &[u8] = b"swarm.governance.witness-admission-set.v1";
pub const WITNESS_ADMISSION_ENTRY_DOMAIN_V1: &[u8] = b"swarm.governance.witness-admission.v1";
pub const WITNESS_BUCKET_MANIFEST_DOMAIN_V1: &[u8] = b"swarm.governance.witness-bucket-manifest.v1";
pub const WITNESS_BUCKET_EPOCH_DOMAIN_V1: &[u8] = b"swarm.governance.witness-bucket-epoch.v1";
pub const WITNESS_BUCKET_ANCHOR_DOMAIN_V1: &[u8] = b"swarm.governance.witness-bucket-anchor.v1";
pub const WITNESS_STREAM_INITIALIZATION_DOMAIN_V1: &[u8] =
    b"swarm.governance.witness-stream-initialization.v1";
pub const WITNESS_STORE_PROXY_REQUEST_DOMAIN_V1: &[u8] =
    b"swarm.governance.witness-store-proxy-request.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAdmissionEntryV1 {
    pub schema_version: u32,
    pub admission: WitnessAdmissionRecordV1,
    pub governance_signer_public_key_hex: String,
    pub max_state_bytes: u64,
    pub max_checkpoint_bytes: u64,
    pub max_binding_bytes: u64,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub predecessor_admission_digest: Option<String>,
}

#[derive(Serialize)]
struct WitnessAdmissionEntryPreimageV1<'a> {
    schema_version: u32,
    admission: &'a WitnessAdmissionRecordV1,
    governance_signer_public_key_hex: &'a str,
    max_state_bytes: u64,
    max_checkpoint_bytes: u64,
    max_binding_bytes: u64,
    max_request_bytes: u64,
    max_response_bytes: u64,
    predecessor_admission_digest: &'a Option<String>,
}

impl WitnessAdmissionEntryV1 {
    fn preimage(&self) -> WitnessAdmissionEntryPreimageV1<'_> {
        WitnessAdmissionEntryPreimageV1 {
            schema_version: self.schema_version,
            admission: &self.admission,
            governance_signer_public_key_hex: &self.governance_signer_public_key_hex,
            max_state_bytes: self.max_state_bytes,
            max_checkpoint_bytes: self.max_checkpoint_bytes,
            max_binding_bytes: self.max_binding_bytes,
            max_request_bytes: self.max_request_bytes,
            max_response_bytes: self.max_response_bytes,
            predecessor_admission_digest: &self.predecessor_admission_digest,
        }
    }

    pub fn computed_digest(&self) -> ProtocolResult<String> {
        digest_domain(
            WITNESS_ADMISSION_ENTRY_DOMAIN_V1,
            &canonical_wire_bytes(&self.preimage())?,
        )
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        validate_schema(self.schema_version)?;
        self.admission.validate()?;
        let signer = PublicKey::from_hex(&self.governance_signer_public_key_hex)
            .map_err(|_| invalid("governance_signer_public_key_hex"))?;
        if sha256_hex(signer.as_bytes()) != self.signer_key_id {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        for (field, value) in [
            ("max_state_bytes", self.max_state_bytes),
            ("max_checkpoint_bytes", self.max_checkpoint_bytes),
            ("max_binding_bytes", self.max_binding_bytes),
            ("max_request_bytes", self.max_request_bytes),
            ("max_response_bytes", self.max_response_bytes),
        ] {
            if value == 0 || value > MAX_PROTOCOL_RECORD_BYTES as u64 {
                return Err(ProtocolError::Bounds {
                    field: field.to_string(),
                    observed: usize::try_from(value).unwrap_or(usize::MAX),
                    maximum: MAX_PROTOCOL_RECORD_BYTES,
                });
            }
        }
        if let Some(digest) = &self.predecessor_admission_digest {
            validate_digest("predecessor_admission_digest", digest)?;
            if digest == &self.admission_digest {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
        if self.max_state_bytes > self.admission.limits.max_payload_bytes
            || self.max_checkpoint_bytes > self.admission.limits.max_payload_bytes
            || self.max_binding_bytes > self.admission.limits.max_record_bytes
            || self.max_request_bytes > self.admission.limits.max_record_bytes
            || self.max_response_bytes > self.admission.limits.max_record_bytes
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    pub fn expectation<'a>(
        &'a self,
        envelope: &'a WitnessStoreEnvelopeV1,
    ) -> WitnessStoreExpectationV1<'a> {
        WitnessStoreExpectationV1 {
            admission_digest: &self.admission_digest,
            bucket_epoch_digest: &envelope.bucket_epoch_digest,
            stream_initialization_digest: &envelope.stream_initialization_digest,
            stream_id: &self.stream_id,
            witness_identity: &self.witness_identity,
            witness_key_id: &self.witness_key_id,
            authority_pair: self.authority_pair,
            binding_generation: &self.binding_generation,
            binding_digest: &self.binding_digest,
            signer_key_id: &self.signer_key_id,
        }
    }
}

impl Deref for WitnessAdmissionEntryV1 {
    type Target = WitnessAdmissionRecordV1;

    fn deref(&self) -> &Self::Target {
        &self.admission
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAdmissionSetV1 {
    pub schema_version: u32,
    pub entries: Vec<WitnessAdmissionEntryV1>,
    pub admission_set_digest: String,
}

#[derive(Serialize)]
struct WitnessAdmissionSetPreimageV1<'a> {
    schema_version: u32,
    entries: &'a [WitnessAdmissionEntryV1],
}

impl WitnessAdmissionSetV1 {
    pub fn computed_digest(&self) -> ProtocolResult<String> {
        digest_domain(
            WITNESS_ADMISSION_SET_DOMAIN_V1,
            &canonical_wire_bytes(&WitnessAdmissionSetPreimageV1 {
                schema_version: self.schema_version,
                entries: &self.entries,
            })?,
        )
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        validate_schema(self.schema_version)?;
        if self.entries.is_empty() || self.entries.len() > MAX_PROTOCOL_COLLECTION_ITEMS {
            return Err(ProtocolError::Bounds {
                field: "admission_entries".to_string(),
                observed: self.entries.len(),
                maximum: MAX_PROTOCOL_COLLECTION_ITEMS,
            });
        }
        let mut streams = BTreeSet::new();
        let mut bindings = BTreeSet::new();
        let mut previous_stream_id: Option<&str> = None;
        for entry in &self.entries {
            entry.validate()?;
            if previous_stream_id.is_some_and(|previous| previous >= entry.stream_id.as_str()) {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
            previous_stream_id = Some(&entry.stream_id);
            if !streams.insert(entry.stream_id.as_str())
                || !bindings.insert((
                    entry.authority_pair.current.device,
                    entry.authority_pair.current.inode,
                    entry.authority_pair.legacy.device,
                    entry.authority_pair.legacy.inode,
                    entry.binding_generation.as_str(),
                    entry.binding_digest.as_str(),
                ))
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
        validate_digest("admission_set_digest", &self.admission_set_digest)?;
        if self.computed_digest()? != self.admission_set_digest {
            return Err(ProtocolError::DigestMismatch {
                field: "admission_set_digest",
            });
        }
        Ok(())
    }

    pub fn entry(&self, stream_id: &str) -> Option<&WitnessAdmissionEntryV1> {
        self.entries
            .iter()
            .find(|entry| entry.stream_id == stream_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessBucketManifestPhaseV1 {
    Initializing,
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStreamInitializationRecordV1 {
    pub schema_version: u32,
    pub stream_initialization_digest: String,
    pub empty_envelope_digest: String,
}

impl WitnessStreamInitializationRecordV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        validate_schema(self.schema_version)?;
        validate_digest(
            "stream_initialization_digest",
            &self.stream_initialization_digest,
        )?;
        validate_digest("empty_envelope_digest", &self.empty_envelope_digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStreamInitializationV1 {
    pub schema_version: u32,
    pub bucket_epoch_digest: String,
    pub admission_digest: String,
    pub stream_id: String,
    pub witness_identity: String,
    pub witness_key_id: String,
}

impl WitnessStreamInitializationV1 {
    pub fn digest(&self) -> ProtocolResult<String> {
        self.validate()?;
        digest_domain(
            WITNESS_STREAM_INITIALIZATION_DOMAIN_V1,
            &canonical_wire_bytes(self)?,
        )
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        validate_schema(self.schema_version)?;
        validate_digest("bucket_epoch_digest", &self.bucket_epoch_digest)?;
        validate_digest("admission_digest", &self.admission_digest)?;
        validate_string("stream_id", &self.stream_id)?;
        validate_string("witness_identity", &self.witness_identity)?;
        validate_digest("witness_key_id", &self.witness_key_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessRetentionPolicyV1 {
    Limits,
    Interest,
    WorkQueue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessDiscardPolicyV1 {
    Old,
    New,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessStorageTypeV1 {
    File,
    Memory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessPersistenceSemanticsV1 {
    Nats21117SynchronousOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessCompressionV1 {
    Disabled,
    S2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessBucketConfigurationV1 {
    pub schema_version: u32,
    pub nats_server_version: String,
    pub nats_server_image_index_digest: String,
    pub stream_name: String,
    pub description: String,
    pub subjects: Vec<String>,
    pub retention: WitnessRetentionPolicyV1,
    pub discard: WitnessDiscardPolicyV1,
    pub discard_new_per_subject: bool,
    pub storage: WitnessStorageTypeV1,
    pub max_messages: i64,
    pub max_bytes: i64,
    pub max_messages_per_subject: i64,
    pub max_age_nanos: u64,
    pub max_consumers: i32,
    pub max_message_size: i32,
    pub num_replicas: u32,
    pub no_ack: bool,
    pub duplicate_window_nanos: u64,
    pub persistence_semantics: WitnessPersistenceSemanticsV1,
    pub persist_mode_wire_key_present: bool,
    pub sealed: bool,
    pub allow_rollup: bool,
    pub deny_delete: bool,
    pub deny_purge: bool,
    pub allow_direct: bool,
    pub mirror_direct: bool,
    pub allow_message_ttl: bool,
    pub allow_atomic_publish: bool,
    pub allow_message_schedules: bool,
    pub allow_message_counter: bool,
    pub template_owner: String,
    pub application_metadata: BTreeMap<String, String>,
    pub server_metadata: BTreeMap<String, String>,
    pub republish_present: bool,
    pub mirror_present: bool,
    pub sources_count: u64,
    pub subject_transform_present: bool,
    pub compression: WitnessCompressionV1,
    pub consumer_limits_present: bool,
    pub first_sequence: Option<u64>,
    pub placement_present: bool,
    pub pause_until: Option<String>,
    pub subject_delete_marker_ttl_nanos: Option<u64>,
}

impl WitnessBucketConfigurationV1 {
    pub fn digest(&self) -> ProtocolResult<String> {
        self.validate()?;
        digest_domain(
            b"swarm.governance.witness-bucket-configuration.v1",
            &canonical_wire_bytes(self)?,
        )
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        validate_schema(self.schema_version)?;
        for (field, value) in [
            ("nats_server_version", self.nats_server_version.as_str()),
            (
                "nats_server_image_index_digest",
                self.nats_server_image_index_digest.as_str(),
            ),
            ("stream_name", self.stream_name.as_str()),
            ("description", self.description.as_str()),
        ] {
            validate_string(field, value)?;
        }
        let bucket_name = self
            .stream_name
            .strip_prefix("KV_")
            .ok_or_else(|| invalid("stream_name"))?;
        if self.nats_server_version != "2.11.17"
            || self.nats_server_image_index_digest
                != "sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00"
            || self.description != "Phase 285 external governance witness"
            || self.subjects != [format!("$KV.{bucket_name}.>")]
            || self.subjects[0].len() > MAX_PROTOCOL_STRING_BYTES
            || self.max_bytes <= 0
            || self.max_message_size <= 0
            || i64::from(self.max_message_size) > self.max_bytes
            || self.num_replicas == 0
            || self.retention != WitnessRetentionPolicyV1::Limits
            || self.discard != WitnessDiscardPolicyV1::New
            || self.discard_new_per_subject
            || self.storage != WitnessStorageTypeV1::File
            || self.max_messages != -1
            || self.max_messages_per_subject != 1
            || self.max_age_nanos != 0
            || self.max_consumers != -1
            || self.no_ack
            || self.duplicate_window_nanos != 120_000_000_000
            || self.persistence_semantics != WitnessPersistenceSemanticsV1::Nats21117SynchronousOnly
            || self.persist_mode_wire_key_present
            || self.sealed
            || self.allow_rollup
            || !self.deny_delete
            || !self.deny_purge
            || self.allow_direct
            || self.mirror_direct
            || self.allow_message_ttl
            || self.allow_atomic_publish
            || self.allow_message_schedules
            || self.allow_message_counter
            || !self.template_owner.is_empty()
            || !self.application_metadata.is_empty()
            || self.republish_present
            || self.mirror_present
            || self.sources_count != 0
            || self.subject_transform_present
            || self.compression != WitnessCompressionV1::Disabled
            || self.consumer_limits_present
            || self.first_sequence.is_some()
            || self.placement_present
            || self.pause_until.is_some()
            || self.subject_delete_marker_ttl_nanos.is_some()
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        if self.server_metadata
            != BTreeMap::from([
                ("_nats.level".to_string(), "1".to_string()),
                ("_nats.req.level".to_string(), "0".to_string()),
                ("_nats.ver".to_string(), "2.11.17".to_string()),
            ])
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        canonical_wire_bytes(self).map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessBucketEpochV1 {
    pub schema_version: u32,
    pub bucket_generation: String,
    pub nats_account: String,
    pub stream_name: String,
    pub bucket_configuration_digest: String,
    pub admission_set_digest: String,
    pub witness_identity: String,
    pub witness_key_id: String,
}

impl WitnessBucketEpochV1 {
    pub fn digest(&self) -> ProtocolResult<String> {
        self.validate()?;
        digest_domain(WITNESS_BUCKET_EPOCH_DOMAIN_V1, &canonical_wire_bytes(self)?)
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        validate_schema(self.schema_version)?;
        validate_digest("bucket_generation", &self.bucket_generation)?;
        validate_string("nats_account", &self.nats_account)?;
        validate_string("stream_name", &self.stream_name)?;
        validate_digest(
            "bucket_configuration_digest",
            &self.bucket_configuration_digest,
        )?;
        validate_digest("admission_set_digest", &self.admission_set_digest)?;
        validate_string("witness_identity", &self.witness_identity)?;
        validate_digest("witness_key_id", &self.witness_key_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessBucketManifestV1 {
    pub schema_version: u32,
    pub bucket_epoch_digest: String,
    pub bucket_configuration_digest: String,
    pub admission_set_digest: String,
    pub stream_keys: Vec<String>,
    pub initialized_streams: BTreeMap<String, WitnessStreamInitializationRecordV1>,
    pub phase: WitnessBucketManifestPhaseV1,
    pub witness_identity: String,
    pub witness_key_id: String,
    pub signature: DetachedSignature,
}

#[derive(Serialize)]
struct WitnessBucketManifestPreimageV1<'a> {
    schema_version: u32,
    bucket_epoch_digest: &'a str,
    bucket_configuration_digest: &'a str,
    admission_set_digest: &'a str,
    stream_keys: &'a [String],
    initialized_streams: &'a BTreeMap<String, WitnessStreamInitializationRecordV1>,
    phase: WitnessBucketManifestPhaseV1,
    witness_identity: &'a str,
    witness_key_id: &'a str,
}

impl WitnessBucketManifestV1 {
    fn preimage(&self) -> WitnessBucketManifestPreimageV1<'_> {
        WitnessBucketManifestPreimageV1 {
            schema_version: self.schema_version,
            bucket_epoch_digest: &self.bucket_epoch_digest,
            bucket_configuration_digest: &self.bucket_configuration_digest,
            admission_set_digest: &self.admission_set_digest,
            stream_keys: &self.stream_keys,
            initialized_streams: &self.initialized_streams,
            phase: self.phase,
            witness_identity: &self.witness_identity,
            witness_key_id: &self.witness_key_id,
        }
    }

    pub fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        domain_separated_bytes(
            WITNESS_BUCKET_MANIFEST_DOMAIN_V1,
            &canonical_wire_bytes(&self.preimage())?,
        )
    }

    pub fn digest(&self) -> ProtocolResult<String> {
        self.validate()?;
        digest_domain(
            WITNESS_BUCKET_MANIFEST_DOMAIN_V1,
            &canonical_wire_bytes(self)?,
        )
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        validate_schema(self.schema_version)?;
        validate_digest("bucket_epoch_digest", &self.bucket_epoch_digest)?;
        validate_digest(
            "bucket_configuration_digest",
            &self.bucket_configuration_digest,
        )?;
        validate_digest("admission_set_digest", &self.admission_set_digest)?;
        validate_string("witness_identity", &self.witness_identity)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        if self.stream_keys.is_empty()
            || self.stream_keys.len() > MAX_PROTOCOL_COLLECTION_ITEMS
            || self.initialized_streams.len() > MAX_PROTOCOL_COLLECTION_ITEMS
        {
            return Err(ProtocolError::Bounds {
                field: "manifest_streams".to_string(),
                observed: self.stream_keys.len().max(self.initialized_streams.len()),
                maximum: MAX_PROTOCOL_COLLECTION_ITEMS,
            });
        }
        let mut ordered = self.stream_keys.clone();
        ordered.sort();
        ordered.dedup();
        if ordered != self.stream_keys {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        for (key, record) in &self.initialized_streams {
            validate_string("stream_key", key)?;
            record.validate()?;
        }
        validate_signature(
            &self.witness_key_id,
            &self.signing_bytes()?,
            &self.signature,
        )?;
        canonical_wire_bytes(self).map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessBucketAnchorV1 {
    pub schema_version: u32,
    pub epoch: WitnessBucketEpochV1,
    pub nats_stream_created_at: String,
    pub raw_stream_configuration_digest: String,
    pub ready_manifest_digest: String,
    pub witness_key_id: String,
    pub signature: DetachedSignature,
}

#[derive(Serialize)]
struct WitnessBucketAnchorPreimageV1<'a> {
    schema_version: u32,
    epoch: &'a WitnessBucketEpochV1,
    nats_stream_created_at: &'a str,
    raw_stream_configuration_digest: &'a str,
    ready_manifest_digest: &'a str,
    witness_key_id: &'a str,
}

impl WitnessBucketAnchorV1 {
    fn preimage(&self) -> WitnessBucketAnchorPreimageV1<'_> {
        WitnessBucketAnchorPreimageV1 {
            schema_version: self.schema_version,
            epoch: &self.epoch,
            nats_stream_created_at: &self.nats_stream_created_at,
            raw_stream_configuration_digest: &self.raw_stream_configuration_digest,
            ready_manifest_digest: &self.ready_manifest_digest,
            witness_key_id: &self.witness_key_id,
        }
    }

    pub fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        domain_separated_bytes(
            WITNESS_BUCKET_ANCHOR_DOMAIN_V1,
            &canonical_wire_bytes(&self.preimage())?,
        )
    }

    pub fn digest(&self) -> ProtocolResult<String> {
        self.validate()?;
        digest_domain(
            WITNESS_BUCKET_ANCHOR_DOMAIN_V1,
            &canonical_wire_bytes(self)?,
        )
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        validate_schema(self.schema_version)?;
        self.epoch.validate()?;
        validate_created_at(&self.nats_stream_created_at)?;
        validate_digest(
            "raw_stream_configuration_digest",
            &self.raw_stream_configuration_digest,
        )?;
        validate_digest("ready_manifest_digest", &self.ready_manifest_digest)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        if self.witness_key_id != self.epoch.witness_key_id {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        validate_signature(
            &self.witness_key_id,
            &self.signing_bytes()?,
            &self.signature,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStoreProxyValidatedEntryV1 {
    pub schema_version: u32,
    pub revision: u64,
    pub store_state_digest: String,
    pub stream_initialization_digest: String,
}

impl WitnessStoreProxyValidatedEntryV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        validate_schema(self.schema_version)?;
        if self.revision == 0 {
            return Err(invalid("revision"));
        }
        validate_digest("store_state_digest", &self.store_state_digest)?;
        validate_digest(
            "stream_initialization_digest",
            &self.stream_initialization_digest,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessStoreProxyFailureCodeV1 {
    Missing,
    Corrupt,
    Header,
    Configuration,
    Admission,
    Signature,
    Bounds,
    Conflict,
    Unavailable,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessStoreProxyOperationV1 {
    InspectReady,
    ReadEntry,
    CompareAndSwap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStoreProxyRequestV1 {
    pub schema_version: u32,
    pub operation: WitnessStoreProxyOperationV1,
    pub request_nonce: String,
    pub admission_digest: String,
    pub bucket_epoch_digest: String,
    pub bucket_anchor_digest: String,
    pub body: WitnessStoreProxyRequestBodyV1,
    pub request_digest: String,
    pub witness_key_id: String,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessStoreProxyRequestBodyV1 {
    InspectReady,
    ReadEntry {
        stream_id: String,
    },
    CompareAndSwap {
        stream_id: String,
        expected_revision: u64,
        expected_store_state_digest: String,
        proposed_envelope: Box<WitnessStoreEnvelopeV1>,
    },
}

#[derive(Serialize)]
struct WitnessStoreProxyRequestDigestPreimageV1<'a> {
    schema_version: u32,
    operation: WitnessStoreProxyOperationV1,
    request_nonce: &'a str,
    admission_digest: &'a str,
    bucket_epoch_digest: &'a str,
    bucket_anchor_digest: &'a str,
    body: &'a WitnessStoreProxyRequestBodyV1,
    witness_key_id: &'a str,
}

#[derive(Serialize)]
struct WitnessStoreProxyRequestSigningPreimageV1<'a> {
    schema_version: u32,
    operation: WitnessStoreProxyOperationV1,
    request_nonce: &'a str,
    admission_digest: &'a str,
    bucket_epoch_digest: &'a str,
    bucket_anchor_digest: &'a str,
    body: &'a WitnessStoreProxyRequestBodyV1,
    request_digest: &'a str,
    witness_key_id: &'a str,
}

impl WitnessStoreProxyRequestV1 {
    pub fn computed_digest(&self) -> ProtocolResult<String> {
        digest_domain(
            WITNESS_STORE_PROXY_REQUEST_DOMAIN_V1,
            &canonical_wire_bytes(&WitnessStoreProxyRequestDigestPreimageV1 {
                schema_version: self.schema_version,
                operation: self.operation,
                request_nonce: &self.request_nonce,
                admission_digest: &self.admission_digest,
                bucket_epoch_digest: &self.bucket_epoch_digest,
                bucket_anchor_digest: &self.bucket_anchor_digest,
                body: &self.body,
                witness_key_id: &self.witness_key_id,
            })?,
        )
    }

    pub fn signing_bytes(&self) -> ProtocolResult<Vec<u8>> {
        domain_separated_bytes(
            WITNESS_STORE_PROXY_REQUEST_DOMAIN_V1,
            &canonical_wire_bytes(&WitnessStoreProxyRequestSigningPreimageV1 {
                schema_version: self.schema_version,
                operation: self.operation,
                request_nonce: &self.request_nonce,
                admission_digest: &self.admission_digest,
                bucket_epoch_digest: &self.bucket_epoch_digest,
                bucket_anchor_digest: &self.bucket_anchor_digest,
                body: &self.body,
                request_digest: &self.request_digest,
                witness_key_id: &self.witness_key_id,
            })?,
        )
    }

    pub fn validate_structure(&self) -> ProtocolResult<()> {
        validate_schema(self.schema_version)?;
        validate_digest("request_nonce", &self.request_nonce)?;
        validate_digest("admission_digest", &self.admission_digest)?;
        validate_digest("bucket_epoch_digest", &self.bucket_epoch_digest)?;
        validate_digest("bucket_anchor_digest", &self.bucket_anchor_digest)?;
        validate_digest("request_digest", &self.request_digest)?;
        validate_digest("witness_key_id", &self.witness_key_id)?;
        let paired = matches!(
            (self.operation, &self.body),
            (
                WitnessStoreProxyOperationV1::InspectReady,
                WitnessStoreProxyRequestBodyV1::InspectReady
            ) | (
                WitnessStoreProxyOperationV1::ReadEntry,
                WitnessStoreProxyRequestBodyV1::ReadEntry { .. }
            ) | (
                WitnessStoreProxyOperationV1::CompareAndSwap,
                WitnessStoreProxyRequestBodyV1::CompareAndSwap { .. }
            )
        );
        if !paired || self.computed_digest()? != self.request_digest {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        if let WitnessStoreProxyRequestBodyV1::ReadEntry { stream_id }
        | WitnessStoreProxyRequestBodyV1::CompareAndSwap { stream_id, .. } = &self.body
        {
            validate_string("stream_id", stream_id)?;
        }
        if let WitnessStoreProxyRequestBodyV1::CompareAndSwap {
            expected_store_state_digest,
            ..
        } = &self.body
        {
            validate_digest("expected_store_state_digest", expected_store_state_digest)?;
        }
        canonical_wire_bytes(self).map(|_| ())
    }

    pub fn validate_semantics(&self) -> ProtocolResult<()> {
        if matches!(
            self.body,
            WitnessStoreProxyRequestBodyV1::CompareAndSwap {
                expected_revision: 0,
                ..
            }
        ) {
            return Err(invalid("expected_revision"));
        }
        Ok(())
    }

    pub fn validate_signature(&self) -> ProtocolResult<()> {
        validate_signature(
            &self.witness_key_id,
            &self.signing_bytes()?,
            &self.signature,
        )
    }

    pub fn decode(bytes: &[u8]) -> ProtocolResult<Self> {
        let request: Self = decode_canonical(bytes)?;
        request.validate_structure()?;
        Ok(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStoreProxyResponseV1 {
    pub schema_version: u32,
    pub operation: WitnessStoreProxyOperationV1,
    pub request_digest: String,
    pub body: WitnessStoreProxyResponseBodyV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessStoreProxyResponseBodyV1 {
    Ready {
        nats_stream_created_at: String,
        bucket_configuration_digest: String,
        ready_manifest: Box<WitnessBucketManifestV1>,
        validated_streams: BTreeMap<String, WitnessStoreProxyValidatedEntryV1>,
    },
    Entry {
        stream_id: String,
        revision: u64,
        envelope: Box<WitnessStoreEnvelopeV1>,
    },
    CasApplied {
        stream_id: String,
        previous_revision: u64,
        new_revision: u64,
        acknowledged_value_digest: String,
    },
    Conflict {
        stream_id: String,
        observed_revision: u64,
        observed_envelope: Box<WitnessStoreEnvelopeV1>,
    },
    Refused {
        failure_code: WitnessStoreProxyFailureCodeV1,
        observed_revision: Option<u64>,
        observed_value_digest: Option<String>,
    },
}

impl WitnessStoreProxyResponseV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        validate_schema(self.schema_version)?;
        validate_digest("request_digest", &self.request_digest)?;
        let paired = matches!(
            (self.operation, &self.body),
            (
                WitnessStoreProxyOperationV1::InspectReady,
                WitnessStoreProxyResponseBodyV1::Ready { .. }
                    | WitnessStoreProxyResponseBodyV1::Refused { .. }
            ) | (
                WitnessStoreProxyOperationV1::ReadEntry,
                WitnessStoreProxyResponseBodyV1::Entry { .. }
                    | WitnessStoreProxyResponseBodyV1::Refused { .. }
            ) | (
                WitnessStoreProxyOperationV1::CompareAndSwap,
                WitnessStoreProxyResponseBodyV1::CasApplied { .. }
                    | WitnessStoreProxyResponseBodyV1::Conflict { .. }
                    | WitnessStoreProxyResponseBodyV1::Refused { .. }
            )
        );
        if !paired {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        match &self.body {
            WitnessStoreProxyResponseBodyV1::Ready {
                nats_stream_created_at,
                bucket_configuration_digest,
                ready_manifest,
                validated_streams,
            } => {
                validate_created_at(nats_stream_created_at)?;
                validate_digest("bucket_configuration_digest", bucket_configuration_digest)?;
                ready_manifest.validate()?;
                if ready_manifest.bucket_configuration_digest != *bucket_configuration_digest
                    || validated_streams.is_empty()
                    || validated_streams.len() > MAX_PROTOCOL_COLLECTION_ITEMS
                {
                    return Err(ProtocolError::Bounds {
                        field: "validated_streams".to_string(),
                        observed: validated_streams.len(),
                        maximum: MAX_PROTOCOL_COLLECTION_ITEMS,
                    });
                }
                for (stream_id, entry) in validated_streams {
                    validate_string("stream_id", stream_id)?;
                    entry.validate()?;
                }
            }
            WitnessStoreProxyResponseBodyV1::Entry {
                stream_id,
                revision,
                envelope,
            } => {
                validate_string("stream_id", stream_id)?;
                if *revision == 0 || envelope.stream_id != *stream_id {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
                envelope.validate()?;
            }
            WitnessStoreProxyResponseBodyV1::CasApplied {
                stream_id,
                previous_revision,
                new_revision,
                acknowledged_value_digest,
            } => {
                validate_string("stream_id", stream_id)?;
                validate_digest("acknowledged_value_digest", acknowledged_value_digest)?;
                if *previous_revision == 0 || *new_revision <= *previous_revision {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            }
            WitnessStoreProxyResponseBodyV1::Conflict {
                stream_id,
                observed_revision,
                observed_envelope,
            } => {
                validate_string("stream_id", stream_id)?;
                if *observed_revision == 0 || observed_envelope.stream_id != *stream_id {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
                observed_envelope.validate()?;
            }
            WitnessStoreProxyResponseBodyV1::Refused {
                observed_revision,
                observed_value_digest,
                ..
            } => {
                if observed_revision == &Some(0) {
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
                if let Some(digest) = observed_value_digest {
                    validate_digest("observed_value_digest", digest)?;
                }
            }
        }
        canonical_wire_bytes(self).map(|_| ())
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        canonical_wire_bytes(self)
    }

    pub fn decode(bytes: &[u8]) -> ProtocolResult<Self> {
        let response: Self = decode_canonical(bytes)?;
        response.validate()?;
        Ok(response)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(deny_unknown_fields)]
pub enum WitnessStoreErrorV1 {
    #[error("entry missing")]
    Missing,
    #[error("entry corrupt")]
    Corrupt,
    #[error("header or framing invalid")]
    Header,
    #[error("configuration mismatch")]
    Configuration,
    #[error("admission mismatch")]
    Admission,
    #[error("signature invalid")]
    Signature,
    #[error("bound exceeded")]
    Bounds,
    #[error("compare-and-swap conflict")]
    Conflict,
    #[error("store unavailable")]
    Unavailable,
    #[error("store outcome ambiguous")]
    Ambiguous,
}

impl WitnessStoreErrorV1 {
    pub fn failure_code(self) -> WitnessStoreProxyFailureCodeV1 {
        match self {
            Self::Missing => WitnessStoreProxyFailureCodeV1::Missing,
            Self::Corrupt => WitnessStoreProxyFailureCodeV1::Corrupt,
            Self::Header => WitnessStoreProxyFailureCodeV1::Header,
            Self::Configuration => WitnessStoreProxyFailureCodeV1::Configuration,
            Self::Admission => WitnessStoreProxyFailureCodeV1::Admission,
            Self::Signature => WitnessStoreProxyFailureCodeV1::Signature,
            Self::Bounds => WitnessStoreProxyFailureCodeV1::Bounds,
            Self::Conflict => WitnessStoreProxyFailureCodeV1::Conflict,
            Self::Unavailable => WitnessStoreProxyFailureCodeV1::Unavailable,
            Self::Ambiguous => WitnessStoreProxyFailureCodeV1::Ambiguous,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStoreDeploymentInputsV1 {
    pub schema_version: u32,
    pub max_manifest_bytes: u64,
    pub maximum_admitted_streams: u64,
    pub configured_replica_count: u32,
}

impl WitnessStoreDeploymentInputsV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        validate_schema(self.schema_version)?;
        if self.max_manifest_bytes == 0
            || self.max_manifest_bytes > MAX_PROTOCOL_RECORD_BYTES as u64
            || self.maximum_admitted_streams == 0
            || self.maximum_admitted_streams > MAX_PROTOCOL_COLLECTION_ITEMS as u64
            || self.configured_replica_count == 0
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStoreReadyResultV1 {
    pub schema_version: u32,
    pub nats_stream_created_at: String,
    pub bucket_configuration: WitnessBucketConfigurationV1,
    pub bucket_epoch: WitnessBucketEpochV1,
    pub bucket_anchor: WitnessBucketAnchorV1,
    pub admission_set: WitnessAdmissionSetV1,
    pub ready_manifest: WitnessBucketManifestV1,
    pub deployment_inputs: WitnessStoreDeploymentInputsV1,
}

impl WitnessStoreReadyResultV1 {
    pub fn new(
        nats_stream_created_at: String,
        bucket_configuration: WitnessBucketConfigurationV1,
        bucket_epoch: WitnessBucketEpochV1,
        bucket_anchor: WitnessBucketAnchorV1,
        admission_set: WitnessAdmissionSetV1,
        ready_manifest: WitnessBucketManifestV1,
        deployment_inputs: WitnessStoreDeploymentInputsV1,
    ) -> Result<Self, WitnessStoreErrorV1> {
        let value = Self {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            nats_stream_created_at,
            bucket_configuration,
            bucket_epoch,
            bucket_anchor,
            admission_set,
            ready_manifest,
            deployment_inputs,
        };
        value.validate().map_err(classify_protocol_error)?;
        Ok(value)
    }

    pub fn validate(&self) -> ProtocolResult<()> {
        validate_schema(self.schema_version)?;
        validate_created_at(&self.nats_stream_created_at)?;
        self.bucket_configuration.validate()?;
        self.bucket_epoch.validate()?;
        self.bucket_anchor.validate()?;
        self.admission_set.validate()?;
        self.ready_manifest.validate()?;
        self.deployment_inputs.validate()?;

        let configuration_digest = self.bucket_configuration.digest()?;
        let epoch_digest = self.bucket_epoch.digest()?;
        let manifest_digest = self.ready_manifest.digest()?;
        if self.ready_manifest.phase != WitnessBucketManifestPhaseV1::Ready
            || configuration_digest != self.bucket_epoch.bucket_configuration_digest
            || self.bucket_epoch.stream_name != self.bucket_configuration.stream_name
            || self.admission_set.admission_set_digest != self.bucket_epoch.admission_set_digest
            || epoch_digest != self.ready_manifest.bucket_epoch_digest
            || self.bucket_anchor.epoch != self.bucket_epoch
            || self.bucket_anchor.nats_stream_created_at != self.nats_stream_created_at
            || self.bucket_anchor.ready_manifest_digest != manifest_digest
            || self.ready_manifest.bucket_configuration_digest != configuration_digest
            || self.ready_manifest.admission_set_digest != self.admission_set.admission_set_digest
            || self.ready_manifest.witness_identity != self.bucket_epoch.witness_identity
            || self.ready_manifest.witness_key_id != self.bucket_epoch.witness_key_id
            || self.admission_set.entries.iter().any(|entry| {
                entry.witness_identity != self.bucket_epoch.witness_identity
                    || entry.witness_key_id != self.bucket_epoch.witness_key_id
            })
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }

        let mut expected_keys = self
            .admission_set
            .entries
            .iter()
            .map(|entry| super::witness_stream_key(&entry.stream_id))
            .collect::<ProtocolResult<Vec<_>>>()?;
        expected_keys.sort();
        if expected_keys != self.ready_manifest.stream_keys
            || expected_keys.iter().collect::<BTreeSet<_>>()
                != self
                    .ready_manifest
                    .initialized_streams
                    .keys()
                    .collect::<BTreeSet<_>>()
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        for admission in &self.admission_set.entries {
            let initialization = WitnessStreamInitializationV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                bucket_epoch_digest: epoch_digest.clone(),
                admission_digest: admission.admission_digest.clone(),
                stream_id: admission.stream_id.clone(),
                witness_identity: admission.witness_identity.clone(),
                witness_key_id: admission.witness_key_id.clone(),
            };
            let stream_key = super::witness_stream_key(&admission.stream_id)?;
            let record = self
                .ready_manifest
                .initialized_streams
                .get(&stream_key)
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            if record.stream_initialization_digest != initialization.digest()? {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }

        let manifest_len = canonical_wire_bytes(&self.ready_manifest)?.len() as u64;
        if manifest_len > self.deployment_inputs.max_manifest_bytes {
            return Err(ProtocolError::Bounds {
                field: "ready_manifest".to_string(),
                observed: usize::try_from(manifest_len).unwrap_or(usize::MAX),
                maximum: usize::try_from(self.deployment_inputs.max_manifest_bytes)
                    .unwrap_or(usize::MAX),
            });
        }
        validate_ready_capacity(self)?;
        canonical_wire_bytes(self).map(|_| ())
    }

    pub fn entry(&self, stream_id: &str) -> Option<&WitnessAdmissionEntryV1> {
        self.admission_set.entry(stream_id)
    }

    pub fn canonical_bytes(&self) -> ProtocolResult<Vec<u8>> {
        self.validate()?;
        canonical_wire_bytes(self)
    }

    pub fn decode(bytes: &[u8]) -> ProtocolResult<Self> {
        let ready: Self = decode_canonical(bytes)?;
        ready.validate()?;
        Ok(ready)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessStoreReadResultV1 {
    Entry {
        stream_id: String,
        revision: u64,
        envelope: Box<WitnessStoreEnvelopeV1>,
    },
}

impl WitnessStoreReadResultV1 {
    pub fn parts(&self) -> (&str, u64, &WitnessStoreEnvelopeV1) {
        match self {
            Self::Entry {
                stream_id,
                revision,
                envelope,
            } => (stream_id, *revision, envelope),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WitnessStoreCasResultV1 {
    Applied {
        stream_id: String,
        expected_previous_revision: u64,
        previous_revision: u64,
        new_revision: u64,
        acknowledged_value_digest: String,
        duplicate: bool,
    },
    Conflict {
        stream_id: String,
        observed_revision: u64,
        observed_envelope: Box<WitnessStoreEnvelopeV1>,
    },
    Ambiguous {
        stream_id: String,
        expected_previous_revision: u64,
        observed_revision: Option<u64>,
        observed_value_digest: Option<String>,
    },
}

#[async_trait]
pub trait WitnessAtomicStore: Send + Sync {
    async fn inspect_ready(&self) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1>;

    async fn read_entry(
        &self,
        stream_id: &str,
    ) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1>;

    async fn compare_and_swap(
        &self,
        stream_id: &str,
        expected_revision: u64,
        expected_store_state_digest: &str,
        proposed_envelope: &WitnessStoreEnvelopeV1,
    ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1>;
}

pub fn validate_cas_transition(
    ready: &WitnessStoreReadyResultV1,
    stream_id: &str,
    expected_revision: u64,
    expected_store_state_digest: &str,
    current_revision: u64,
    current: &WitnessStoreEnvelopeV1,
    proposed: &WitnessStoreEnvelopeV1,
) -> Result<String, WitnessStoreErrorV1> {
    let current_entry = validate_read_entry(ready, stream_id, current_revision, current)?;
    if expected_revision == 0 {
        return Err(WitnessStoreErrorV1::Conflict);
    }
    let admission = ready
        .entry(stream_id)
        .ok_or(WitnessStoreErrorV1::Admission)?;
    let actual_digest = current_entry.store_state_digest;
    if current_revision != expected_revision || actual_digest != expected_store_state_digest {
        return Err(WitnessStoreErrorV1::Conflict);
    }
    proposed
        .validate_signature_before_semantics()
        .map_err(|_| WitnessStoreErrorV1::Signature)?;
    proposed
        .validate_for(admission.expectation(proposed))
        .map_err(classify_protocol_error)?;
    validate_admission_bounds(admission, proposed)?;
    validate_store_transition(current, proposed, admission.expectation(current))
        .map_err(classify_protocol_error)?;
    proposed
        .signed_envelope_digest()
        .map_err(classify_protocol_error)
}

pub fn validate_read_entry(
    ready: &WitnessStoreReadyResultV1,
    stream_id: &str,
    revision: u64,
    envelope: &WitnessStoreEnvelopeV1,
) -> Result<WitnessStoreProxyValidatedEntryV1, WitnessStoreErrorV1> {
    if revision == 0 {
        return Err(WitnessStoreErrorV1::Corrupt);
    }
    let admission = ready
        .entry(stream_id)
        .ok_or(WitnessStoreErrorV1::Admission)?;
    let epoch_digest = ready
        .bucket_epoch
        .digest()
        .map_err(classify_protocol_error)?;
    let key = super::witness_stream_key(stream_id).map_err(classify_protocol_error)?;
    let initialization = ready
        .ready_manifest
        .initialized_streams
        .get(&key)
        .ok_or(WitnessStoreErrorV1::Missing)?;
    if envelope.bucket_epoch_digest != epoch_digest
        || envelope.stream_initialization_digest != initialization.stream_initialization_digest
    {
        return Err(WitnessStoreErrorV1::Configuration);
    }
    envelope
        .validate_signature_before_semantics()
        .map_err(|_| WitnessStoreErrorV1::Corrupt)?;
    envelope
        .validate_for(admission.expectation(envelope))
        .map_err(classify_protocol_error)?;
    validate_admission_bounds(admission, envelope)?;
    if envelope.store_generation == 0
        && envelope
            .signed_envelope_digest()
            .map_err(classify_protocol_error)?
            != initialization.empty_envelope_digest
    {
        return Err(WitnessStoreErrorV1::Corrupt);
    }
    Ok(WitnessStoreProxyValidatedEntryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        revision,
        store_state_digest: envelope
            .store_state_digest()
            .map_err(classify_protocol_error)?,
        stream_initialization_digest: envelope.stream_initialization_digest.clone(),
    })
}

pub(crate) fn classify_protocol_error(error: ProtocolError) -> WitnessStoreErrorV1 {
    match error {
        ProtocolError::Bounds { .. } => WitnessStoreErrorV1::Bounds,
        ProtocolError::NonCanonicalEncoding | ProtocolError::CanonicalEncoding(_) => {
            WitnessStoreErrorV1::Corrupt
        }
        _ => WitnessStoreErrorV1::Admission,
    }
}

fn validate_schema(schema_version: u32) -> ProtocolResult<()> {
    if schema_version != PROTOCOL_SCHEMA_VERSION {
        return Err(ProtocolError::UnsupportedSchema(schema_version));
    }
    Ok(())
}

fn validate_string(field: &'static str, value: &str) -> ProtocolResult<()> {
    if value.is_empty() || value.len() > MAX_PROTOCOL_STRING_BYTES || value.as_bytes().contains(&0)
    {
        return Err(invalid(field));
    }
    Ok(())
}

fn validate_digest(field: &'static str, value: &str) -> ProtocolResult<()> {
    validate_string(field, value)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(field));
    }
    Ok(())
}

fn validate_created_at(value: &str) -> ProtocolResult<()> {
    validate_string("nats_stream_created_at", value)?;
    let bytes = value.as_bytes();
    if bytes.len() != 30
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[29] != b'Z'
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || !bytes[8..10].iter().all(u8::is_ascii_digit)
        || !bytes[11..13].iter().all(u8::is_ascii_digit)
        || !bytes[14..16].iter().all(u8::is_ascii_digit)
        || !bytes[17..19].iter().all(u8::is_ascii_digit)
        || !bytes[20..29].iter().all(u8::is_ascii_digit)
    {
        return Err(invalid("nats_stream_created_at"));
    }
    let parse = |range: std::ops::Range<usize>| -> Option<u32> {
        std::str::from_utf8(&bytes[range]).ok()?.parse().ok()
    };
    let year = parse(0..4).ok_or_else(|| invalid("nats_stream_created_at"))?;
    let month = parse(5..7).ok_or_else(|| invalid("nats_stream_created_at"))?;
    let day = parse(8..10).ok_or_else(|| invalid("nats_stream_created_at"))?;
    let hour = parse(11..13).ok_or_else(|| invalid("nats_stream_created_at"))?;
    let minute = parse(14..16).ok_or_else(|| invalid("nats_stream_created_at"))?;
    let second = parse(17..19).ok_or_else(|| invalid("nats_stream_created_at"))?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if day == 0 || day > maximum_day || hour > 23 || minute > 59 || second > 59 {
        return Err(invalid("nats_stream_created_at"));
    }
    Ok(())
}

fn validate_ready_capacity(ready: &WitnessStoreReadyResultV1) -> ProtocolResult<()> {
    const ENTRY_OVERHEAD: u64 = 65_536;
    if ready.bucket_configuration.num_replicas != ready.deployment_inputs.configured_replica_count
        || ready.admission_set.entries.len() as u64
            > ready.deployment_inputs.maximum_admitted_streams
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    let max_store = ready
        .admission_set
        .entries
        .iter()
        .map(|entry| entry.max_retained_bytes)
        .max()
        .ok_or_else(|| invalid("admission_entries"))?;
    let max_manifest = ready.deployment_inputs.max_manifest_bytes;
    let max_value = max_store.max(max_manifest);
    let streams = ready.deployment_inputs.maximum_admitted_streams;
    let required =
        2_u64
            .checked_mul(max_manifest.checked_add(ENTRY_OVERHEAD).ok_or(
                ProtocolError::Overflow {
                    counter: "required_bucket_bytes",
                },
            )?)
            .and_then(|manifest| {
                streams
                    .checked_mul(2)?
                    .checked_mul(max_store.checked_add(ENTRY_OVERHEAD)?)
                    .and_then(|entries| manifest.checked_add(entries))
            })
            .ok_or(ProtocolError::Overflow {
                counter: "required_bucket_bytes",
            })?;
    if u64::try_from(ready.bucket_configuration.max_message_size).ok() != Some(max_value)
        || u64::try_from(ready.bucket_configuration.max_bytes).ok() != Some(required)
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    Ok(())
}

pub(crate) fn validate_admission_bounds(
    admission: &WitnessAdmissionEntryV1,
    envelope: &WitnessStoreEnvelopeV1,
) -> Result<(), WitnessStoreErrorV1> {
    let retained = canonical_wire_bytes(envelope)
        .map_err(classify_protocol_error)?
        .len() as u64;
    if retained > admission.max_retained_bytes {
        return Err(WitnessStoreErrorV1::Bounds);
    }
    for candidate in [
        envelope.current.as_ref().map(|value| &value.candidate),
        envelope.predecessor.as_ref().map(|value| &value.candidate),
        envelope.prepared.as_ref().map(|value| &value.candidate),
    ]
    .into_iter()
    .flatten()
    {
        if candidate.state_payload.len() as u64 > admission.max_state_bytes
            || candidate.checkpoint_payload.len() as u64 > admission.max_checkpoint_bytes
            || canonical_wire_bytes(&candidate.publication_binding)
                .map_err(classify_protocol_error)?
                .len() as u64
                > admission.max_binding_bytes
        {
            return Err(WitnessStoreErrorV1::Bounds);
        }
    }
    Ok(())
}

fn validate_signature(
    expected_key_id: &str,
    bytes: &[u8],
    signature: &DetachedSignature,
) -> ProtocolResult<()> {
    if signature.algorithm != "ed25519"
        || signature.key_id != expected_key_id
        || !PublicKey::from_hex(&signature.public_key_hex)
            .map(|key| sha256_hex(key.as_bytes()) == expected_key_id)
            .unwrap_or(false)
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    verify_detached_signature(bytes, signature).map_err(|_| ProtocolError::WitnessOutcomeMismatch)
}

fn domain_separated_bytes(domain: &[u8], canonical: &[u8]) -> ProtocolResult<Vec<u8>> {
    let length = u64::try_from(canonical.len()).map_err(|_| ProtocolError::Overflow {
        counter: "wire_size",
    })?;
    let mut result = Vec::with_capacity(domain.len() + 8 + canonical.len());
    result.extend_from_slice(domain);
    result.extend_from_slice(&length.to_be_bytes());
    result.extend_from_slice(canonical);
    Ok(result)
}

fn invalid(field: &'static str) -> ProtocolError {
    ProtocolError::InvalidField {
        field: field.to_string(),
        reason: "invalid witness store contract value".to_string(),
    }
}
