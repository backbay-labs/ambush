//! Deterministic direct store and an implementation-independent reference model.

use super::{
    WitnessAtomicStore, WitnessStoreCasResultV1, WitnessStoreEnvelopeV1, WitnessStoreErrorV1,
    WitnessStoreReadResultV1, WitnessStoreReadyResultV1, validate_cas_transition,
    validate_read_entry,
};
use crate::persistence_protocol::canonical_wire_bytes;
use async_trait::async_trait;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessStoreFault {
    CrashBeforeCas,
    LostAfterCas,
    WrongRevision,
    DuplicateAck,
    CorruptRead,
    CapacityExhaustion,
}

#[derive(Debug)]
struct StoreState {
    entries: BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>,
    next_fault: Option<WitnessStoreFault>,
}

#[derive(Debug)]
pub struct InMemoryWitnessStore {
    ready: WitnessStoreReadyResultV1,
    capacity_bytes: usize,
    state: Mutex<StoreState>,
}

impl InMemoryWitnessStore {
    pub fn new(
        ready: WitnessStoreReadyResultV1,
        entries: BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>,
        capacity_bytes: usize,
    ) -> Result<Self, WitnessStoreErrorV1> {
        ready.validate().map_err(super::classify_protocol_error)?;
        if capacity_bytes == 0 || encoded_entries_len(&entries)? > capacity_bytes {
            return Err(WitnessStoreErrorV1::Bounds);
        }
        validate_exact_entries(&ready, &entries)?;
        Ok(Self {
            ready,
            capacity_bytes,
            state: Mutex::new(StoreState {
                entries,
                next_fault: None,
            }),
        })
    }

    pub fn inject_fault(&self, fault: WitnessStoreFault) -> Result<(), WitnessStoreErrorV1> {
        self.state
            .lock()
            .map_err(|_| WitnessStoreErrorV1::Unavailable)?
            .next_fault = Some(fault);
        Ok(())
    }

    pub fn snapshot(
        &self,
    ) -> Result<BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>, WitnessStoreErrorV1> {
        Ok(self
            .state
            .lock()
            .map_err(|_| WitnessStoreErrorV1::Unavailable)?
            .entries
            .clone())
    }

    pub fn canonical_store_bytes(&self) -> Result<Vec<u8>, WitnessStoreErrorV1> {
        canonical_wire_bytes(&self.snapshot()?).map_err(super::classify_protocol_error)
    }
}

#[async_trait]
impl WitnessAtomicStore for InMemoryWitnessStore {
    async fn inspect_ready(&self) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1> {
        self.ready
            .validate()
            .map_err(super::classify_protocol_error)?;
        let entries = self.snapshot()?;
        validate_exact_entries(&self.ready, &entries)?;
        Ok(self.ready.clone())
    }

    async fn read_entry(
        &self,
        stream_id: &str,
    ) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| WitnessStoreErrorV1::Unavailable)?;
        if state.next_fault == Some(WitnessStoreFault::CorruptRead) {
            state.next_fault = None;
            return Err(WitnessStoreErrorV1::Corrupt);
        }
        let (revision, envelope) = state
            .entries
            .get(stream_id)
            .ok_or(WitnessStoreErrorV1::Missing)?;
        validate_read_entry(&self.ready, stream_id, *revision, envelope)?;
        Ok(WitnessStoreReadResultV1::Entry {
            stream_id: stream_id.to_string(),
            revision: *revision,
            envelope: Box::new(envelope.clone()),
        })
    }

    async fn compare_and_swap(
        &self,
        stream_id: &str,
        expected_revision: u64,
        expected_store_state_digest: &str,
        proposed_envelope: &WitnessStoreEnvelopeV1,
    ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| WitnessStoreErrorV1::Unavailable)?;
        let (current_revision, current) = state
            .entries
            .get(stream_id)
            .cloned()
            .ok_or(WitnessStoreErrorV1::Missing)?;
        validate_read_entry(&self.ready, stream_id, current_revision, &current)?;
        if expected_revision == 0
            || current_revision != expected_revision
            || current
                .store_state_digest()
                .map_err(super::classify_protocol_error)?
                != expected_store_state_digest
        {
            return Ok(WitnessStoreCasResultV1::Conflict {
                stream_id: stream_id.to_string(),
                observed_revision: current_revision,
                observed_envelope: Box::new(current),
            });
        }
        let acknowledged_value_digest = validate_cas_transition(
            &self.ready,
            stream_id,
            expected_revision,
            expected_store_state_digest,
            current_revision,
            &current,
            proposed_envelope,
        )?;
        let fault = state.next_fault.take();
        if fault == Some(WitnessStoreFault::CrashBeforeCas) {
            return Err(WitnessStoreErrorV1::Unavailable);
        }
        if fault == Some(WitnessStoreFault::CapacityExhaustion) {
            return Err(WitnessStoreErrorV1::Bounds);
        }
        let new_revision = current_revision
            .checked_add(1)
            .ok_or(WitnessStoreErrorV1::Bounds)?;
        let mut candidate = state.entries.clone();
        candidate.insert(
            stream_id.to_string(),
            (new_revision, proposed_envelope.clone()),
        );
        if encoded_entries_len(&candidate)? > self.capacity_bytes {
            return Err(WitnessStoreErrorV1::Bounds);
        }
        state.entries = candidate;
        match fault {
            Some(WitnessStoreFault::LostAfterCas) => Ok(WitnessStoreCasResultV1::Ambiguous {
                stream_id: stream_id.to_string(),
                expected_previous_revision: expected_revision,
                observed_revision: None,
                observed_value_digest: None,
            }),
            Some(WitnessStoreFault::WrongRevision) => Ok(WitnessStoreCasResultV1::Applied {
                stream_id: stream_id.to_string(),
                expected_previous_revision: expected_revision,
                previous_revision: current_revision,
                new_revision: new_revision.saturating_add(1),
                acknowledged_value_digest,
                duplicate: false,
            }),
            Some(WitnessStoreFault::DuplicateAck) => Ok(WitnessStoreCasResultV1::Applied {
                stream_id: stream_id.to_string(),
                expected_previous_revision: expected_revision,
                previous_revision: current_revision,
                new_revision,
                acknowledged_value_digest,
                duplicate: true,
            }),
            _ => Ok(WitnessStoreCasResultV1::Applied {
                stream_id: stream_id.to_string(),
                expected_previous_revision: expected_revision,
                previous_revision: current_revision,
                new_revision,
                acknowledged_value_digest,
                duplicate: false,
            }),
        }
    }
}

fn validate_exact_entries(
    ready: &WitnessStoreReadyResultV1,
    entries: &BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>,
) -> Result<(), WitnessStoreErrorV1> {
    let admitted = ready
        .admission_set
        .entries
        .iter()
        .map(|entry| entry.stream_id.as_str())
        .collect::<BTreeSet<_>>();
    let present = entries.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if admitted != present {
        return Err(WitnessStoreErrorV1::Missing);
    }
    for (stream_id, (revision, envelope)) in entries {
        validate_read_entry(ready, stream_id, *revision, envelope)?;
    }
    Ok(())
}

fn encoded_entries_len(
    entries: &BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>,
) -> Result<usize, WitnessStoreErrorV1> {
    canonical_wire_bytes(entries)
        .map(|bytes| bytes.len())
        .map_err(super::classify_protocol_error)
}

// REFERENCE_ORACLE_BEGIN
mod reference_oracle {
    use super::WitnessStoreFault;
    use crate::persistence_protocol::{
        BINDING_DOMAIN_V1, CANDIDATE_DOMAIN_V1, CHECKPOINT_PAYLOAD_DOMAIN_V1,
        GENESIS_DATA_HEAD_DOMAIN_V1, GENESIS_PREDECESSOR_DOMAIN_V1, MAX_PROTOCOL_COLLECTION_ITEMS,
        MAX_PROTOCOL_RECORD_BYTES, PROTOCOL_SCHEMA_VERSION, STATE_PAYLOAD_DOMAIN_V1,
        TXID_DOMAIN_V1, WITNESS_DATA_HEAD_DOMAIN_V1, WITNESS_EXTERNAL_MARKER_DOMAIN_V1,
        WITNESS_HEAD_DOMAIN_V1, WITNESS_SESSION_STATE_DOMAIN_V1, WitnessIntentOutcomeV1,
        canonical_wire_bytes, digest_domain,
    };
    use crate::witness_engine::store::{
        WITNESS_ADMISSION_SET_DOMAIN_V1, WITNESS_BUCKET_ANCHOR_DOMAIN_V1,
        WITNESS_BUCKET_MANIFEST_DOMAIN_V1, WITNESS_STREAM_INITIALIZATION_DOMAIN_V1,
        WitnessAdmissionEntryV1, WitnessStoreCasResultV1, WitnessStoreEnvelopeV1,
        WitnessStoreErrorV1, WitnessStoreReadResultV1, WitnessStoreReadyResultV1,
    };
    use serde::Serialize;
    use serde_json::Value;
    use std::collections::{BTreeMap, BTreeSet};
    use swarm_crypto::{DetachedSignature, PublicKey, sha256_hex, verify_detached_signature};

    pub(super) struct Model {
        ready: WitnessStoreReadyResultV1,
        entries: BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>,
        capacity_bytes: usize,
        next_fault: Option<WitnessStoreFault>,
    }

    impl Model {
        pub(super) fn new(
            ready: WitnessStoreReadyResultV1,
            entries: BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>,
            capacity_bytes: usize,
        ) -> Result<Self, WitnessStoreErrorV1> {
            oracle_ready(&ready)?;
            if capacity_bytes == 0 || oracle_encoded_len(&entries)? > capacity_bytes {
                return Err(WitnessStoreErrorV1::Bounds);
            }
            oracle_exact_entries(&ready, &entries)?;
            Ok(Self {
                ready,
                entries,
                capacity_bytes,
                next_fault: None,
            })
        }

        pub(super) fn inspect_ready(
            &self,
        ) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1> {
            oracle_ready(&self.ready)?;
            oracle_exact_entries(&self.ready, &self.entries)?;
            Ok(self.ready.clone())
        }

        pub(super) fn read_entry(
            &mut self,
            stream_id: &str,
        ) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1> {
            oracle_ready(&self.ready)?;
            if self.next_fault == Some(WitnessStoreFault::CorruptRead) {
                self.next_fault = None;
                return Err(WitnessStoreErrorV1::Corrupt);
            }
            let (revision, envelope) = self
                .entries
                .get(stream_id)
                .ok_or(WitnessStoreErrorV1::Missing)?;
            oracle_entry(&self.ready, stream_id, *revision, envelope)?;
            Ok(WitnessStoreReadResultV1::Entry {
                stream_id: stream_id.to_string(),
                revision: *revision,
                envelope: Box::new(envelope.clone()),
            })
        }

        pub(super) fn inject_fault(&mut self, fault: WitnessStoreFault) {
            self.next_fault = Some(fault);
        }

        pub(super) fn compare_and_swap(
            &mut self,
            stream_id: &str,
            expected_revision: u64,
            expected_digest: &str,
            proposed: &WitnessStoreEnvelopeV1,
        ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1> {
            oracle_ready(&self.ready)?;
            let (revision, current) = self
                .entries
                .get(stream_id)
                .cloned()
                .ok_or(WitnessStoreErrorV1::Missing)?;
            let current_digest = oracle_entry(&self.ready, stream_id, revision, &current)?;
            if expected_revision == 0
                || revision != expected_revision
                || current_digest != expected_digest
            {
                return Ok(WitnessStoreCasResultV1::Conflict {
                    stream_id: stream_id.to_string(),
                    observed_revision: revision,
                    observed_envelope: Box::new(current),
                });
            }
            oracle_entry(&self.ready, stream_id, revision, proposed).map_err(|error| {
                if error == WitnessStoreErrorV1::Corrupt {
                    WitnessStoreErrorV1::Signature
                } else {
                    error
                }
            })?;
            oracle_transition(&current, proposed)?;
            let fault = self.next_fault.take();
            if fault == Some(WitnessStoreFault::CrashBeforeCas) {
                return Err(WitnessStoreErrorV1::Unavailable);
            }
            if fault == Some(WitnessStoreFault::CapacityExhaustion) {
                return Err(WitnessStoreErrorV1::Bounds);
            }
            let new_revision = revision.checked_add(1).ok_or(WitnessStoreErrorV1::Bounds)?;
            let mut candidate = self.entries.clone();
            candidate.insert(stream_id.to_string(), (new_revision, proposed.clone()));
            if oracle_encoded_len(&candidate)? > self.capacity_bytes {
                return Err(WitnessStoreErrorV1::Bounds);
            }
            self.entries = candidate;
            let value_digest = oracle_signed_digest(proposed)?;
            match fault {
                Some(WitnessStoreFault::LostAfterCas) => Ok(WitnessStoreCasResultV1::Ambiguous {
                    stream_id: stream_id.to_string(),
                    expected_previous_revision: expected_revision,
                    observed_revision: None,
                    observed_value_digest: None,
                }),
                Some(WitnessStoreFault::WrongRevision) => Ok(WitnessStoreCasResultV1::Applied {
                    stream_id: stream_id.to_string(),
                    expected_previous_revision: expected_revision,
                    previous_revision: revision,
                    new_revision: new_revision.saturating_add(1),
                    acknowledged_value_digest: value_digest,
                    duplicate: false,
                }),
                Some(WitnessStoreFault::DuplicateAck) => Ok(WitnessStoreCasResultV1::Applied {
                    stream_id: stream_id.to_string(),
                    expected_previous_revision: expected_revision,
                    previous_revision: revision,
                    new_revision,
                    acknowledged_value_digest: value_digest,
                    duplicate: true,
                }),
                _ => Ok(WitnessStoreCasResultV1::Applied {
                    stream_id: stream_id.to_string(),
                    expected_previous_revision: expected_revision,
                    previous_revision: revision,
                    new_revision,
                    acknowledged_value_digest: value_digest,
                    duplicate: false,
                }),
            }
        }

        pub(super) fn canonical_store_bytes(&self) -> Result<Vec<u8>, WitnessStoreErrorV1> {
            canonical_wire_bytes(&self.entries).map_err(|_| WitnessStoreErrorV1::Corrupt)
        }
    }

    fn oracle_ready(ready: &WitnessStoreReadyResultV1) -> Result<(), WitnessStoreErrorV1> {
        let configuration = &ready.bucket_configuration;
        let Some(bucket_name) = configuration.stream_name.strip_prefix("KV_") else {
            return Err(WitnessStoreErrorV1::Configuration);
        };
        let expected_subject = format!("$KV.{bucket_name}.>");
        if ready.schema_version != PROTOCOL_SCHEMA_VERSION
            || !oracle_timestamp(&ready.nats_stream_created_at)
            || ready.deployment_inputs.schema_version != PROTOCOL_SCHEMA_VERSION
            || ready.deployment_inputs.max_manifest_bytes == 0
            || ready.deployment_inputs.max_manifest_bytes > MAX_PROTOCOL_RECORD_BYTES as u64
            || ready.deployment_inputs.maximum_admitted_streams == 0
            || ready.deployment_inputs.maximum_admitted_streams
                > MAX_PROTOCOL_COLLECTION_ITEMS as u64
            || ready.deployment_inputs.configured_replica_count == 0
            || configuration.schema_version != PROTOCOL_SCHEMA_VERSION
            || !oracle_string(&configuration.nats_server_version)
            || !oracle_string(&configuration.nats_server_image_index_digest)
            || !oracle_string(&configuration.stream_name)
            || !oracle_string(&configuration.description)
            || configuration.nats_server_version != "2.11.17"
            || configuration.nats_server_image_index_digest
                != "sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00"
            || configuration.description != "Phase 285 external governance witness"
            || configuration.subjects != [expected_subject.clone()]
            || expected_subject.len() > crate::persistence_protocol::MAX_PROTOCOL_STRING_BYTES
            || configuration.retention
                != crate::witness_engine::store::WitnessRetentionPolicyV1::Limits
            || configuration.discard
                != crate::witness_engine::store::WitnessDiscardPolicyV1::New
            || configuration.storage
                != crate::witness_engine::store::WitnessStorageTypeV1::File
            || configuration.discard_new_per_subject
            || configuration.max_messages != -1
            || configuration.max_messages_per_subject != 1
            || configuration.max_age_nanos != 0
            || configuration.max_consumers != -1
            || configuration.max_bytes <= 0
            || configuration.max_message_size <= 0
            || i64::from(configuration.max_message_size) > configuration.max_bytes
            || configuration.no_ack
            || configuration.duplicate_window_nanos != 120_000_000_000
            || configuration.persistence_semantics
                != crate::witness_engine::store::WitnessPersistenceSemanticsV1::Nats21117SynchronousOnly
            || configuration.persist_mode_wire_key_present
            || configuration.sealed
            || configuration.allow_rollup
            || !configuration.deny_delete
            || !configuration.deny_purge
            || configuration.allow_direct
            || configuration.mirror_direct
            || configuration.allow_message_ttl
            || configuration.allow_atomic_publish
            || configuration.allow_message_schedules
            || configuration.allow_message_counter
            || !configuration.template_owner.is_empty()
            || !configuration.application_metadata.is_empty()
            || configuration.republish_present
            || configuration.mirror_present
            || configuration.sources_count != 0
            || configuration.subject_transform_present
            || configuration.compression
                != crate::witness_engine::store::WitnessCompressionV1::Disabled
            || configuration.consumer_limits_present
            || configuration.first_sequence.is_some()
            || configuration.placement_present
            || configuration.pause_until.is_some()
            || configuration.subject_delete_marker_ttl_nanos.is_some()
            || configuration.server_metadata
                != BTreeMap::from([
                    ("_nats.level".to_string(), "1".to_string()),
                    ("_nats.req.level".to_string(), "0".to_string()),
                    ("_nats.ver".to_string(), "2.11.17".to_string()),
                ])
            || configuration.num_replicas
                != ready.deployment_inputs.configured_replica_count
            || ready.admission_set.entries.is_empty()
            || ready.admission_set.schema_version != PROTOCOL_SCHEMA_VERSION
            || ready.admission_set.entries.len() > MAX_PROTOCOL_COLLECTION_ITEMS
            || ready.admission_set.entries.len() as u64
                > ready.deployment_inputs.maximum_admitted_streams
        {
            return Err(WitnessStoreErrorV1::Configuration);
        }
        let configuration_digest = oracle_digest(
            b"swarm.governance.witness-bucket-configuration.v1",
            &ready.bucket_configuration,
        )?;
        let epoch_digest = oracle_digest(
            crate::witness_engine::store::WITNESS_BUCKET_EPOCH_DOMAIN_V1,
            &ready.bucket_epoch,
        )?;
        if ready.bucket_epoch.schema_version != PROTOCOL_SCHEMA_VERSION
            || ready.bucket_epoch.bucket_configuration_digest != configuration_digest
            || ready.bucket_epoch.admission_set_digest != ready.admission_set.admission_set_digest
            || ready.bucket_epoch.stream_name != ready.bucket_configuration.stream_name
            || !oracle_digest_text(&ready.bucket_epoch.bucket_generation)
            || !oracle_string(&ready.bucket_epoch.nats_account)
            || !oracle_string(&ready.bucket_epoch.stream_name)
            || !oracle_digest_text(&ready.bucket_epoch.bucket_configuration_digest)
            || !oracle_digest_text(&ready.bucket_epoch.admission_set_digest)
            || !oracle_string(&ready.bucket_epoch.witness_identity)
            || !oracle_digest_text(&ready.bucket_epoch.witness_key_id)
        {
            return Err(WitnessStoreErrorV1::Configuration);
        }

        let mut previous = None;
        let mut stream_ids = BTreeSet::new();
        let mut bindings = BTreeSet::new();
        for entry in &ready.admission_set.entries {
            oracle_admission(entry)?;
            if previous.is_some_and(|value: &str| value >= entry.stream_id.as_str())
                || !stream_ids.insert(entry.stream_id.as_str())
                || !bindings.insert((
                    entry.authority_pair.current.device,
                    entry.authority_pair.current.inode,
                    entry.binding_generation.as_str(),
                    entry.binding_digest.as_str(),
                ))
            {
                return Err(WitnessStoreErrorV1::Admission);
            }
            previous = Some(entry.stream_id.as_str());
        }
        let admission_digest = oracle_digest_without(
            WITNESS_ADMISSION_SET_DOMAIN_V1,
            &ready.admission_set,
            &["admission_set_digest"],
        )?;
        if !oracle_digest_text(&ready.admission_set.admission_set_digest)
            || admission_digest != ready.admission_set.admission_set_digest
        {
            return Err(WitnessStoreErrorV1::Admission);
        }

        oracle_signed_object(
            WITNESS_BUCKET_MANIFEST_DOMAIN_V1,
            &ready.ready_manifest,
            &ready.ready_manifest.signature,
            &ready.ready_manifest.witness_key_id,
        )?;
        let manifest_digest =
            oracle_digest(WITNESS_BUCKET_MANIFEST_DOMAIN_V1, &ready.ready_manifest)?;
        oracle_signed_object(
            WITNESS_BUCKET_ANCHOR_DOMAIN_V1,
            &ready.bucket_anchor,
            &ready.bucket_anchor.signature,
            &ready.bucket_anchor.witness_key_id,
        )?;
        if ready.ready_manifest.schema_version != PROTOCOL_SCHEMA_VERSION
            || !oracle_digest_text(&ready.ready_manifest.bucket_epoch_digest)
            || !oracle_digest_text(&ready.ready_manifest.bucket_configuration_digest)
            || !oracle_digest_text(&ready.ready_manifest.admission_set_digest)
            || !oracle_string(&ready.ready_manifest.witness_identity)
            || !oracle_digest_text(&ready.ready_manifest.witness_key_id)
            || ready.ready_manifest.stream_keys.is_empty()
            || ready.ready_manifest.stream_keys.len() > MAX_PROTOCOL_COLLECTION_ITEMS
            || ready.ready_manifest.initialized_streams.len() > MAX_PROTOCOL_COLLECTION_ITEMS
            || ready.ready_manifest.phase
                != crate::witness_engine::store::WitnessBucketManifestPhaseV1::Ready
            || ready.ready_manifest.bucket_epoch_digest != epoch_digest
            || ready.ready_manifest.bucket_configuration_digest != configuration_digest
            || ready.ready_manifest.admission_set_digest != admission_digest
            || ready.bucket_anchor.epoch != ready.bucket_epoch
            || ready.bucket_anchor.nats_stream_created_at != ready.nats_stream_created_at
            || ready.bucket_anchor.ready_manifest_digest != manifest_digest
            || ready.ready_manifest.witness_identity != ready.bucket_epoch.witness_identity
            || ready.ready_manifest.witness_key_id != ready.bucket_epoch.witness_key_id
            || ready.admission_set.entries.iter().any(|entry| {
                entry.witness_identity != ready.bucket_epoch.witness_identity
                    || entry.witness_key_id != ready.bucket_epoch.witness_key_id
            })
            || ready.bucket_anchor.schema_version != PROTOCOL_SCHEMA_VERSION
            || !oracle_timestamp(&ready.bucket_anchor.nats_stream_created_at)
            || !oracle_digest_text(&ready.bucket_anchor.raw_stream_configuration_digest)
            || !oracle_digest_text(&ready.bucket_anchor.ready_manifest_digest)
            || !oracle_digest_text(&ready.bucket_anchor.witness_key_id)
            || ready.bucket_anchor.witness_key_id != ready.bucket_epoch.witness_key_id
        {
            return Err(WitnessStoreErrorV1::Configuration);
        }
        let mut keys = Vec::new();
        for entry in &ready.admission_set.entries {
            let key = oracle_stream_key(&entry.stream_id);
            let initialization = serde_json::json!({
                "admission_digest": entry.admission_digest,
                "bucket_epoch_digest": epoch_digest,
                "schema_version": PROTOCOL_SCHEMA_VERSION,
                "stream_id": entry.stream_id,
                "witness_identity": entry.witness_identity,
                "witness_key_id": entry.witness_key_id,
            });
            let initialization_digest =
                oracle_digest(WITNESS_STREAM_INITIALIZATION_DOMAIN_V1, &initialization)?;
            let record = ready
                .ready_manifest
                .initialized_streams
                .get(&key)
                .ok_or(WitnessStoreErrorV1::Missing)?;
            if !oracle_string(&key)
                || record.schema_version != PROTOCOL_SCHEMA_VERSION
                || !oracle_digest_text(&record.stream_initialization_digest)
                || record.stream_initialization_digest != initialization_digest
                || !oracle_digest_text(&record.empty_envelope_digest)
            {
                return Err(WitnessStoreErrorV1::Configuration);
            }
            keys.push(key);
        }
        keys.sort();
        if keys != ready.ready_manifest.stream_keys
            || keys.iter().collect::<BTreeSet<_>>()
                != ready
                    .ready_manifest
                    .initialized_streams
                    .keys()
                    .collect::<BTreeSet<_>>()
        {
            return Err(WitnessStoreErrorV1::Configuration);
        }
        if canonical_wire_bytes(&ready.ready_manifest)
            .map_err(|_| WitnessStoreErrorV1::Corrupt)?
            .len() as u64
            > ready.deployment_inputs.max_manifest_bytes
        {
            return Err(WitnessStoreErrorV1::Bounds);
        }
        let max_store = ready
            .admission_set
            .entries
            .iter()
            .map(|entry| entry.max_retained_bytes)
            .max()
            .ok_or(WitnessStoreErrorV1::Admission)?;
        let required = 2_u64
            .checked_mul(
                ready
                    .deployment_inputs
                    .max_manifest_bytes
                    .checked_add(65_536)
                    .ok_or(WitnessStoreErrorV1::Bounds)?,
            )
            .and_then(|manifest| {
                ready
                    .deployment_inputs
                    .maximum_admitted_streams
                    .checked_mul(2)?
                    .checked_mul(max_store.checked_add(65_536)?)
                    .and_then(|entries| manifest.checked_add(entries))
            })
            .ok_or(WitnessStoreErrorV1::Bounds)?;
        if u64::try_from(ready.bucket_configuration.max_message_size).ok()
            != Some(max_store.max(ready.deployment_inputs.max_manifest_bytes))
            || u64::try_from(ready.bucket_configuration.max_bytes).ok() != Some(required)
        {
            return Err(WitnessStoreErrorV1::Configuration);
        }
        Ok(())
    }

    fn oracle_admission(entry: &WitnessAdmissionEntryV1) -> Result<(), WitnessStoreErrorV1> {
        let admission_digest = oracle_digest_without(
            crate::witness_engine::store::WITNESS_ADMISSION_ENTRY_DOMAIN_V1,
            &entry.admission,
            &["admission_digest"],
        )?;
        let public = PublicKey::from_hex(&entry.governance_signer_public_key_hex)
            .map_err(|_| WitnessStoreErrorV1::Admission)?;
        let limits = entry.admission.limits;
        let roles = entry.admission.publication_roles;
        let identities = [
            roles.state_canonical,
            roles.state_staging,
            roles.checkpoint_canonical,
            roles.checkpoint_staging,
            roles.journal_primary,
            roles.journal_secondary,
        ];
        if entry.schema_version != PROTOCOL_SCHEMA_VERSION
            || entry.admission.schema_version != PROTOCOL_SCHEMA_VERSION
            || !oracle_string(&entry.stream_id)
            || !oracle_string(&entry.witness_identity)
            || entry.stream_id.len() as u64 > limits.max_string_bytes
            || entry.witness_identity.len() as u64 > limits.max_string_bytes
            || !oracle_digest_text(&entry.signer_key_id)
            || !oracle_digest_text(&entry.witness_key_id)
            || !oracle_digest_text(&entry.binding_generation)
            || !oracle_digest_text(&entry.binding_digest)
            || entry.authority_pair.current != entry.authority_pair.legacy
            || entry.authority_pair.current.device == 0
            || entry.authority_pair.current.inode == 0
            || identities
                .iter()
                .any(|identity| identity.device == 0 || identity.inode == 0)
            || identities.iter().collect::<BTreeSet<_>>().len() != identities.len()
            || limits.max_string_bytes == 0
            || limits.max_string_bytes
                > crate::persistence_protocol::MAX_PROTOCOL_STRING_BYTES as u64
            || limits.max_payload_bytes == 0
            || limits.max_payload_bytes
                > crate::persistence_protocol::MAX_PROTOCOL_PAYLOAD_BYTES as u64
            || limits.max_record_bytes < limits.max_payload_bytes
            || limits.max_record_bytes
                > crate::persistence_protocol::MAX_PROTOCOL_RECORD_BYTES as u64
            || limits.max_collection_items == 0
            || limits.max_collection_items
                > crate::persistence_protocol::MAX_PROTOCOL_COLLECTION_ITEMS as u64
            || admission_digest != entry.admission_digest
            || sha256_hex(public.as_bytes()) != entry.signer_key_id
            || entry.max_state_bytes == 0
            || entry.max_checkpoint_bytes == 0
            || entry.max_binding_bytes == 0
            || entry.max_request_bytes == 0
            || entry.max_response_bytes == 0
            || entry.max_retained_bytes == 0
            || entry.admission.initial_intent_counter == 0
            || entry.max_state_bytes > limits.max_payload_bytes
            || entry.max_checkpoint_bytes > limits.max_payload_bytes
            || entry.max_binding_bytes > limits.max_record_bytes
            || entry.max_request_bytes > limits.max_record_bytes
            || entry.max_response_bytes > limits.max_record_bytes
            || entry
                .predecessor_admission_digest
                .as_ref()
                .is_some_and(|digest| {
                    !oracle_digest_text(digest) || digest == &entry.admission_digest
                })
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        Ok(())
    }

    fn oracle_exact_entries(
        ready: &WitnessStoreReadyResultV1,
        entries: &BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>,
    ) -> Result<(), WitnessStoreErrorV1> {
        let admitted = ready
            .admission_set
            .entries
            .iter()
            .map(|entry| entry.stream_id.as_str())
            .collect::<BTreeSet<_>>();
        let present = entries.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if admitted != present {
            return Err(WitnessStoreErrorV1::Missing);
        }
        for (stream_id, (revision, envelope)) in entries {
            oracle_entry(ready, stream_id, *revision, envelope)?;
        }
        Ok(())
    }

    fn oracle_entry(
        ready: &WitnessStoreReadyResultV1,
        stream_id: &str,
        revision: u64,
        envelope: &WitnessStoreEnvelopeV1,
    ) -> Result<String, WitnessStoreErrorV1> {
        if revision == 0 {
            return Err(WitnessStoreErrorV1::Corrupt);
        }
        let admission = ready
            .admission_set
            .entries
            .iter()
            .find(|entry| entry.stream_id == stream_id)
            .ok_or(WitnessStoreErrorV1::Admission)?;
        oracle_signed_object(
            crate::witness_engine::WITNESS_STORE_SIGNED_DOMAIN_V1,
            envelope,
            &envelope.signature,
            &envelope.witness_key_id,
        )?;
        let epoch_digest = oracle_digest(
            crate::witness_engine::store::WITNESS_BUCKET_EPOCH_DOMAIN_V1,
            &ready.bucket_epoch,
        )?;
        let record = ready
            .ready_manifest
            .initialized_streams
            .get(&oracle_stream_key(stream_id))
            .ok_or(WitnessStoreErrorV1::Missing)?;
        if envelope.schema_version != PROTOCOL_SCHEMA_VERSION
            || envelope.stream_id != stream_id
            || !oracle_string(&envelope.stream_id)
            || !oracle_string(&envelope.witness_identity)
            || envelope.admission_digest != admission.admission_digest
            || envelope.bucket_epoch_digest != epoch_digest
            || envelope.stream_initialization_digest != record.stream_initialization_digest
            || envelope.witness_identity != admission.witness_identity
            || envelope.witness_key_id != admission.witness_key_id
            || (envelope.store_generation == 0)
                != !(envelope.session.is_some()
                    || envelope.last_session_rotation.is_some()
                    || envelope.current.is_some()
                    || envelope.predecessor.is_some()
                    || envelope.prepared.is_some()
                    || envelope.genesis_abort.is_some())
            || envelope
                .session
                .as_ref()
                .map(|session| &session.stream_id)
                .is_some_and(|value| value != stream_id)
            || !matches!(
                (&envelope.session, &envelope.last_session_rotation),
                (None, None) | (Some(_), Some(_))
            )
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        if let (Some(session), Some(receipt)) = (&envelope.session, &envelope.last_session_rotation)
            && (&receipt.session != session
                || oracle_session(session).is_err()
                || oracle_rotation_receipt(receipt).is_err())
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        if let Some(stored) = &envelope.current {
            oracle_stored_candidate(admission, stored)?;
        }
        if let Some(stored) = &envelope.predecessor {
            oracle_stored_candidate(admission, stored)?;
        }
        if let Some(stored) = &envelope.prepared {
            oracle_stored_prepared(admission, stored)?;
        }
        if let Some(aborted) = &envelope.genesis_abort {
            oracle_genesis_abort(aborted)?;
            if aborted.stream_id != envelope.stream_id
                || aborted.witness_key_id != envelope.witness_key_id
            {
                return Err(WitnessStoreErrorV1::Admission);
            }
        }
        match (&envelope.current, &envelope.predecessor) {
            (None, None) => {}
            (Some(current), None) if current.candidate.predecessor_head.is_none() => {}
            (Some(current), Some(predecessor))
                if current.candidate.predecessor_head.as_ref() == Some(&predecessor.head) => {}
            _ => return Err(WitnessStoreErrorV1::Admission),
        }
        if let Some(prepared) = &envelope.prepared {
            let session = envelope
                .session
                .as_ref()
                .ok_or(WitnessStoreErrorV1::Admission)?;
            if prepared.prepared.session_generation != session.session_generation
                || prepared.prepared.predecessor_head
                    != envelope
                        .current
                        .as_ref()
                        .map(|current| current.head.clone())
            {
                return Err(WitnessStoreErrorV1::Admission);
            }
        }
        if envelope.genesis_abort.is_some()
            && (envelope.current.is_some()
                || envelope.predecessor.is_some()
                || envelope.prepared.is_some())
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        for candidate in [
            envelope.current.as_ref().map(|stored| &stored.candidate),
            envelope
                .predecessor
                .as_ref()
                .map(|stored| &stored.candidate),
            envelope.prepared.as_ref().map(|stored| &stored.candidate),
        ]
        .into_iter()
        .flatten()
        {
            let binding = &candidate.publication_binding;
            if candidate.stream_id != envelope.stream_id
                || binding.stream_id != envelope.stream_id
                || binding.witness_identity != envelope.witness_identity
                || binding.witness_key_id != envelope.witness_key_id
            {
                return Err(WitnessStoreErrorV1::Admission);
            }
        }
        if let Some(session) = &envelope.session {
            if session.stream_id != envelope.stream_id
                || session.witness_identity != envelope.witness_identity
                || session.witness_key_id != envelope.witness_key_id
            {
                return Err(WitnessStoreErrorV1::Admission);
            }
            if let Some(candidate) = envelope
                .current
                .as_ref()
                .map(|stored| &stored.candidate)
                .or_else(|| envelope.prepared.as_ref().map(|stored| &stored.candidate))
                .or_else(|| {
                    envelope
                        .predecessor
                        .as_ref()
                        .map(|stored| &stored.candidate)
                })
            {
                let binding = &candidate.publication_binding;
                if session.authority_pair != binding.authority_pair
                    || session.binding_generation != binding.generation
                    || session.binding_digest != binding.binding_digest
                    || session.signer_key_id != binding.signer_key_id
                {
                    return Err(WitnessStoreErrorV1::Admission);
                }
            } else if let Some(aborted) = &envelope.genesis_abort
                && (session.authority_pair != aborted.authority_pair
                    || session.binding_generation != aborted.binding_generation
                    || session.binding_digest != aborted.binding_digest
                    || session.signer_key_id != aborted.signer_key_id)
            {
                return Err(WitnessStoreErrorV1::Admission);
            }
        }
        let retained = canonical_wire_bytes(envelope)
            .map_err(|_| WitnessStoreErrorV1::Corrupt)?
            .len() as u64;
        if retained > admission.max_retained_bytes {
            return Err(WitnessStoreErrorV1::Bounds);
        }
        let state_digest = oracle_digest_without(
            crate::witness_engine::WITNESS_STORE_DOMAIN_V1,
            envelope,
            &["signature"],
        )?;
        if envelope.store_generation == 0
            && oracle_signed_digest(envelope)? != record.empty_envelope_digest
        {
            return Err(WitnessStoreErrorV1::Corrupt);
        }
        Ok(state_digest)
    }

    fn oracle_candidate(
        admission: &WitnessAdmissionEntryV1,
        candidate: &crate::persistence_protocol::CandidatePreimageV1,
    ) -> Result<(), WitnessStoreErrorV1> {
        let binding = &candidate.publication_binding;
        if candidate.schema_version != PROTOCOL_SCHEMA_VERSION
            || !oracle_string(&candidate.stream_id)
            || candidate.stream_id.len() as u64 > binding.limits.max_string_bytes
            || candidate.stream_id != admission.stream_id
            || binding.stream_id != admission.stream_id
            || binding.signer_key_id != admission.signer_key_id
            || binding.witness_key_id != admission.witness_key_id
            || binding.witness_identity != admission.witness_identity
            || binding.generation != admission.binding_generation
            || binding.binding_digest != admission.binding_digest
            || binding.authority_pair != admission.authority_pair
            || candidate.state_payload.len() as u64 != candidate.state_byte_len
            || candidate.checkpoint_payload.len() as u64 != candidate.checkpoint_byte_len
            || sha256_hex(&candidate.state_payload) != candidate.state_digest
            || sha256_hex(&candidate.checkpoint_payload) != candidate.checkpoint_digest
            || !oracle_digest_text(&candidate.predecessor_head_digest)
            || !oracle_digest_text(&candidate.predecessor_data_head_digest)
            || !oracle_digest_text(&candidate.state_digest)
            || !oracle_digest_text(&candidate.checkpoint_digest)
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        oracle_binding(binding)?;
        oracle_mapping(&candidate.publication_mapping_before)?;
        oracle_mapping(&candidate.publication_mapping_after)?;
        if !oracle_mapping_matches_roles(
            &candidate.publication_mapping_before,
            &binding.publication_roles,
        ) || !oracle_mapping_matches_roles(
            &candidate.publication_mapping_after,
            &binding.publication_roles,
        ) || !oracle_mapping_is_successor(
            &candidate.publication_mapping_before,
            &candidate.publication_mapping_after,
        ) {
            return Err(WitnessStoreErrorV1::Admission);
        }
        for payload in [&candidate.state_payload, &candidate.checkpoint_payload] {
            let value: Value =
                serde_json::from_slice(payload).map_err(|_| WitnessStoreErrorV1::Admission)?;
            if canonical_wire_bytes(&value).map_err(|_| WitnessStoreErrorV1::Corrupt)? != *payload {
                return Err(WitnessStoreErrorV1::Admission);
            }
        }
        if candidate.state_byte_len > admission.max_state_bytes
            || candidate.checkpoint_byte_len > admission.max_checkpoint_bytes
            || candidate.state_byte_len > binding.limits.max_payload_bytes
            || candidate.checkpoint_byte_len > binding.limits.max_payload_bytes
            || canonical_wire_bytes(binding)
                .map_err(|_| WitnessStoreErrorV1::Corrupt)?
                .len() as u64
                > admission.max_binding_bytes
            || canonical_wire_bytes(candidate)
                .map_err(|_| WitnessStoreErrorV1::Corrupt)?
                .len() as u64
                > binding.limits.max_record_bytes
        {
            return Err(WitnessStoreErrorV1::Bounds);
        }
        for (domain, payload, byte_len, digest, signature) in [
            (
                STATE_PAYLOAD_DOMAIN_V1,
                &candidate.state_payload,
                candidate.state_byte_len,
                &candidate.state_digest,
                &candidate.state_attestation,
            ),
            (
                CHECKPOINT_PAYLOAD_DOMAIN_V1,
                &candidate.checkpoint_payload,
                candidate.checkpoint_byte_len,
                &candidate.checkpoint_digest,
                &candidate.checkpoint_attestation,
            ),
        ] {
            let preimage = serde_json::json!({
                "authority_pair": binding.authority_pair,
                "binding_digest": binding.binding_digest,
                "binding_generation": binding.generation,
                "byte_len": byte_len,
                "digest": digest,
                "domain": domain,
                "payload": payload,
                "schema_version": PROTOCOL_SCHEMA_VERSION,
                "stream_id": candidate.stream_id,
            });
            oracle_signed_object_raw(&preimage, signature, &binding.signer_key_id)?;
        }
        match &candidate.predecessor_head {
            Some(predecessor) => {
                oracle_head(predecessor, true)?;
                if oracle_head_digest(predecessor)? != candidate.predecessor_head_digest
                    || oracle_data_head_digest(predecessor)?
                        != candidate.predecessor_data_head_digest
                    || predecessor.stream_id != candidate.stream_id
                    || predecessor.binding_generation != binding.generation
                    || predecessor.binding_digest != binding.binding_digest
                    || predecessor.signer_key_id != binding.signer_key_id
                    || predecessor.witness_key_id != binding.witness_key_id
                    || predecessor.authority_pair != binding.authority_pair
                    || predecessor.publication_mapping != candidate.publication_mapping_before
                    || candidate.epoch != predecessor.epoch
                    || candidate.sequence
                        != predecessor
                            .sequence
                            .checked_add(1)
                            .ok_or(WitnessStoreErrorV1::Bounds)?
                    || candidate.intent_counter
                        != predecessor
                            .intent_counter
                            .checked_add(1)
                            .ok_or(WitnessStoreErrorV1::Bounds)?
                {
                    return Err(WitnessStoreErrorV1::Admission);
                }
            }
            None => {
                let (head_digest, data_digest) = oracle_genesis_digests(
                    &candidate.stream_id,
                    &binding.generation,
                    &binding.binding_digest,
                    &binding.signer_key_id,
                    &binding.witness_key_id,
                    binding.authority_pair,
                )?;
                if candidate.predecessor_head_digest != head_digest
                    || candidate.predecessor_data_head_digest != data_digest
                    || candidate.epoch != 0
                    || candidate.sequence != 0
                    || candidate.intent_counter == 0
                {
                    return Err(WitnessStoreErrorV1::Admission);
                }
            }
        }
        Ok(())
    }

    fn oracle_candidate_head_value(
        candidate: &crate::persistence_protocol::CandidatePreimageV1,
        committed: bool,
    ) -> Result<Value, WitnessStoreErrorV1> {
        let (candidate_digest, txid) = oracle_candidate_identity(candidate)?;
        let last_intent_outcome = if committed {
            serde_json::json!({
                "Committed": {
                    "candidate_digest": candidate_digest,
                    "intent_counter": candidate.intent_counter,
                    "predecessor_head_digest": candidate.predecessor_head_digest,
                    "txid": txid,
                }
            })
        } else {
            Value::Null
        };
        Ok(serde_json::json!({
            "authority_pair": candidate.publication_binding.authority_pair,
            "binding_digest": candidate.publication_binding.binding_digest,
            "binding_generation": candidate.publication_binding.generation,
            "candidate_digest": candidate_digest,
            "checkpoint_byte_len": candidate.checkpoint_byte_len,
            "checkpoint_digest": candidate.checkpoint_digest,
            "epoch": candidate.epoch,
            "intent_counter": candidate.intent_counter,
            "last_intent_outcome": last_intent_outcome,
            "publication_mapping": candidate.publication_mapping_after,
            "schema_version": PROTOCOL_SCHEMA_VERSION,
            "sequence": candidate.sequence,
            "signer_key_id": candidate.publication_binding.signer_key_id,
            "state_byte_len": candidate.state_byte_len,
            "state_digest": candidate.state_digest,
            "stream_id": candidate.stream_id,
            "txid": txid,
            "witness_key_id": candidate.publication_binding.witness_key_id,
        }))
    }

    fn oracle_stored_candidate(
        admission: &WitnessAdmissionEntryV1,
        stored: &crate::witness_engine::WitnessStoredCandidateV1,
    ) -> Result<(), WitnessStoreErrorV1> {
        oracle_candidate(admission, &stored.candidate)?;
        oracle_head(&stored.head, true)?;
        let candidate = &stored.candidate;
        let (candidate_digest, txid) = oracle_candidate_identity(candidate)?;
        let head = &stored.head;
        if head.schema_version != PROTOCOL_SCHEMA_VERSION
            || head.stream_id != candidate.stream_id
            || head.txid != txid
            || head.candidate_digest != candidate_digest
            || head.epoch != candidate.epoch
            || head.sequence != candidate.sequence
            || head.binding_generation != candidate.publication_binding.generation
            || head.binding_digest != candidate.publication_binding.binding_digest
            || head.signer_key_id != candidate.publication_binding.signer_key_id
            || head.witness_key_id != candidate.publication_binding.witness_key_id
            || head.authority_pair != candidate.publication_binding.authority_pair
            || head.state_digest != candidate.state_digest
            || head.state_byte_len != candidate.state_byte_len
            || head.checkpoint_digest != candidate.checkpoint_digest
            || head.checkpoint_byte_len != candidate.checkpoint_byte_len
            || head.publication_mapping != candidate.publication_mapping_after
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        match &head.last_intent_outcome {
            Some(WitnessIntentOutcomeV1::Committed {
                predecessor_head_digest,
                intent_counter,
                ..
            }) if head.intent_counter == candidate.intent_counter
                && intent_counter == &candidate.intent_counter
                && predecessor_head_digest == &candidate.predecessor_head_digest => {}
            Some(WitnessIntentOutcomeV1::Aborted(summary)) => {
                let next_sequence = head
                    .sequence
                    .checked_add(1)
                    .ok_or(WitnessStoreErrorV1::Bounds)?;
                let next_intent = candidate
                    .intent_counter
                    .checked_add(1)
                    .ok_or(WitnessStoreErrorV1::Bounds)?;
                if summary.epoch != head.epoch
                    || summary.sequence != next_sequence
                    || summary.txid == txid
                    || summary.candidate_digest == candidate_digest
                    || (summary.intent_counter == next_intent
                        && summary.predecessor_head_digest
                            != oracle_digest(
                                WITNESS_HEAD_DOMAIN_V1,
                                &oracle_candidate_head_value(candidate, true)?,
                            )?)
                {
                    return Err(WitnessStoreErrorV1::Admission);
                }
            }
            _ => return Err(WitnessStoreErrorV1::Admission),
        }
        Ok(())
    }

    fn oracle_stored_prepared(
        admission: &WitnessAdmissionEntryV1,
        stored: &crate::witness_engine::WitnessStoredPreparedV1,
    ) -> Result<(), WitnessStoreErrorV1> {
        oracle_candidate(admission, &stored.candidate)?;
        oracle_witness_prepared(&stored.prepared)?;
        if serde_json::to_value(&stored.prepared.head).map_err(|_| WitnessStoreErrorV1::Corrupt)?
            != oracle_candidate_head_value(&stored.candidate, false)?
            || stored.prepared.predecessor_head != stored.candidate.predecessor_head
            || stored.prepared.predecessor_head_digest != stored.candidate.predecessor_head_digest
            || stored.prepared.predecessor_data_head_digest
                != stored.candidate.predecessor_data_head_digest
            || stored.prepared.binding_digest != stored.candidate.publication_binding.binding_digest
            || stored.prepared.predecessor_publication_mapping
                != stored.candidate.publication_mapping_before
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        if let Some(aborted) = &stored.prepared.genesis_abort
            && (aborted.txid == stored.prepared.head.txid
                || aborted.candidate_digest == stored.prepared.head.candidate_digest)
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        Ok(())
    }

    fn oracle_witness_prepared(
        prepared: &crate::persistence_protocol::WitnessPreparedV1,
    ) -> Result<(), WitnessStoreErrorV1> {
        oracle_head(&prepared.head, false)?;
        oracle_mapping(&prepared.predecessor_publication_mapping)?;
        if prepared.schema_version != PROTOCOL_SCHEMA_VERSION
            || prepared.session_generation == 0
            || !oracle_digest_text(&prepared.predecessor_head_digest)
            || !oracle_digest_text(&prepared.predecessor_data_head_digest)
            || !oracle_digest_text(&prepared.binding_digest)
            || prepared.binding_digest != prepared.head.binding_digest
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        match &prepared.predecessor_head {
            Some(predecessor) => {
                oracle_head(predecessor, true)?;
                if prepared.genesis_abort.is_some()
                    || oracle_head_digest(predecessor)? != prepared.predecessor_head_digest
                    || oracle_data_head_digest(predecessor)?
                        != prepared.predecessor_data_head_digest
                    || prepared.predecessor_publication_mapping != predecessor.publication_mapping
                    || prepared.head.stream_id != predecessor.stream_id
                    || prepared.head.binding_generation != predecessor.binding_generation
                    || prepared.head.binding_digest != predecessor.binding_digest
                    || prepared.head.signer_key_id != predecessor.signer_key_id
                    || prepared.head.witness_key_id != predecessor.witness_key_id
                    || prepared.head.authority_pair != predecessor.authority_pair
                    || prepared.head.epoch != predecessor.epoch
                    || prepared.head.sequence
                        != predecessor
                            .sequence
                            .checked_add(1)
                            .ok_or(WitnessStoreErrorV1::Bounds)?
                    || prepared.head.intent_counter
                        != predecessor
                            .intent_counter
                            .checked_add(1)
                            .ok_or(WitnessStoreErrorV1::Bounds)?
                {
                    return Err(WitnessStoreErrorV1::Admission);
                }
            }
            None => {
                let (head_digest, data_digest) = oracle_genesis_digests(
                    &prepared.head.stream_id,
                    &prepared.head.binding_generation,
                    &prepared.head.binding_digest,
                    &prepared.head.signer_key_id,
                    &prepared.head.witness_key_id,
                    prepared.head.authority_pair,
                )?;
                if prepared.predecessor_head_digest != head_digest {
                    return Err(WitnessStoreErrorV1::Admission);
                }
                match &prepared.genesis_abort {
                    Some(aborted) => {
                        oracle_genesis_abort(aborted)?;
                        if aborted.resulting_data_head_digest
                            != prepared.predecessor_data_head_digest
                            || prepared.head.intent_counter
                                != aborted
                                    .intent_counter
                                    .checked_add(1)
                                    .ok_or(WitnessStoreErrorV1::Bounds)?
                            || prepared.head.epoch != aborted.epoch
                            || prepared.head.sequence != aborted.sequence
                            || prepared.head.stream_id != aborted.stream_id
                            || prepared.head.binding_generation != aborted.binding_generation
                            || prepared.head.binding_digest != aborted.binding_digest
                            || prepared.head.signer_key_id != aborted.signer_key_id
                            || prepared.head.witness_key_id != aborted.witness_key_id
                            || prepared.head.authority_pair != aborted.authority_pair
                            || prepared.predecessor_publication_mapping
                                != aborted.publication_mapping
                        {
                            return Err(WitnessStoreErrorV1::Admission);
                        }
                    }
                    None => {
                        if prepared.predecessor_data_head_digest != data_digest
                            || prepared.head.epoch != 0
                            || prepared.head.sequence != 0
                            || prepared.head.intent_counter != 1
                        {
                            return Err(WitnessStoreErrorV1::Admission);
                        }
                    }
                }
            }
        }
        if !oracle_mapping_is_successor(
            &prepared.predecessor_publication_mapping,
            &prepared.head.publication_mapping,
        ) {
            return Err(WitnessStoreErrorV1::Admission);
        }
        Ok(())
    }

    fn oracle_genesis_abort(
        aborted: &crate::persistence_protocol::WitnessGenesisAbortedV1,
    ) -> Result<(), WitnessStoreErrorV1> {
        if aborted.schema_version != PROTOCOL_SCHEMA_VERSION
            || !oracle_string(&aborted.stream_id)
            || !oracle_string(&aborted.reason)
            || aborted.epoch != 0
            || aborted.sequence != 0
            || aborted.intent_counter == 0
            || aborted.authority_pair.current != aborted.authority_pair.legacy
            || [
                &aborted.txid,
                &aborted.candidate_digest,
                &aborted.predecessor_head_digest,
                &aborted.resulting_data_head_digest,
                &aborted.binding_generation,
                &aborted.binding_digest,
                &aborted.signer_key_id,
                &aborted.witness_key_id,
            ]
            .into_iter()
            .any(|value| !oracle_digest_text(value))
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        oracle_mapping(&aborted.publication_mapping)?;
        let (head_digest, data_digest) = oracle_genesis_digests(
            &aborted.stream_id,
            &aborted.binding_generation,
            &aborted.binding_digest,
            &aborted.signer_key_id,
            &aborted.witness_key_id,
            aborted.authority_pair,
        )?;
        let transaction = serde_json::json!({
            "authority_pair": aborted.authority_pair,
            "binding_digest": aborted.binding_digest,
            "binding_generation": aborted.binding_generation,
            "candidate_digest": aborted.candidate_digest,
            "epoch": aborted.epoch,
            "intent_counter": aborted.intent_counter,
            "predecessor_head_digest": aborted.predecessor_head_digest,
            "schema_version": PROTOCOL_SCHEMA_VERSION,
            "sequence": aborted.sequence,
            "stream_id": aborted.stream_id,
        });
        if aborted.predecessor_head_digest != head_digest
            || aborted.resulting_data_head_digest != data_digest
            || oracle_digest(TXID_DOMAIN_V1, &transaction)? != aborted.txid
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        Ok(())
    }

    fn oracle_candidate_identity(
        candidate: &crate::persistence_protocol::CandidatePreimageV1,
    ) -> Result<(String, String), WitnessStoreErrorV1> {
        let candidate_digest = oracle_digest(CANDIDATE_DOMAIN_V1, candidate)?;
        let binding = &candidate.publication_binding;
        let transaction = serde_json::json!({
            "authority_pair": binding.authority_pair,
            "binding_digest": binding.binding_digest,
            "binding_generation": binding.generation,
            "candidate_digest": candidate_digest,
            "epoch": candidate.epoch,
            "intent_counter": candidate.intent_counter,
            "predecessor_head_digest": candidate.predecessor_head_digest,
            "schema_version": PROTOCOL_SCHEMA_VERSION,
            "sequence": candidate.sequence,
            "stream_id": candidate.stream_id,
        });
        let txid = oracle_digest(TXID_DOMAIN_V1, &transaction)?;
        Ok((candidate_digest, txid))
    }

    fn oracle_head(
        head: &crate::persistence_protocol::WitnessHeadV1,
        settled: bool,
    ) -> Result<(), WitnessStoreErrorV1> {
        if head.schema_version != PROTOCOL_SCHEMA_VERSION
            || !oracle_string(&head.stream_id)
            || head.authority_pair.current != head.authority_pair.legacy
            || head.authority_pair.current.device == 0
            || head.authority_pair.current.inode == 0
            || [
                &head.txid,
                &head.candidate_digest,
                &head.binding_generation,
                &head.binding_digest,
                &head.signer_key_id,
                &head.witness_key_id,
                &head.state_digest,
                &head.checkpoint_digest,
            ]
            .into_iter()
            .any(|value| !oracle_digest_text(value))
            || head.state_byte_len > crate::persistence_protocol::MAX_PROTOCOL_PAYLOAD_BYTES as u64
            || head.checkpoint_byte_len
                > crate::persistence_protocol::MAX_PROTOCOL_PAYLOAD_BYTES as u64
            || settled != head.last_intent_outcome.is_some()
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        oracle_mapping(&head.publication_mapping)?;
        match &head.last_intent_outcome {
            None => {}
            Some(WitnessIntentOutcomeV1::Committed {
                txid,
                candidate_digest,
                predecessor_head_digest,
                intent_counter,
            }) => {
                if txid != &head.txid
                    || candidate_digest != &head.candidate_digest
                    || intent_counter != &head.intent_counter
                    || !oracle_digest_text(predecessor_head_digest)
                {
                    return Err(WitnessStoreErrorV1::Admission);
                }
            }
            Some(WitnessIntentOutcomeV1::Aborted(summary)) => {
                oracle_abort_summary(summary)?;
                let transaction = serde_json::json!({
                    "authority_pair": summary.authority_pair,
                    "binding_digest": summary.binding_digest,
                    "binding_generation": summary.binding_generation,
                    "candidate_digest": summary.candidate_digest,
                    "epoch": summary.epoch,
                    "intent_counter": summary.intent_counter,
                    "predecessor_head_digest": summary.predecessor_head_digest,
                    "schema_version": PROTOCOL_SCHEMA_VERSION,
                    "sequence": summary.sequence,
                    "stream_id": head.stream_id,
                });
                if oracle_digest(TXID_DOMAIN_V1, &transaction)? != summary.txid
                    || summary.resulting_data_head_digest != oracle_data_head_digest(head)?
                    || summary.intent_counter != head.intent_counter
                    || summary.binding_generation != head.binding_generation
                    || summary.binding_digest != head.binding_digest
                    || summary.signer_key_id != head.signer_key_id
                    || summary.witness_key_id != head.witness_key_id
                    || summary.authority_pair != head.authority_pair
                    || summary.publication_mapping != head.publication_mapping
                {
                    return Err(WitnessStoreErrorV1::Admission);
                }
            }
        }
        Ok(())
    }

    fn oracle_abort_summary(
        summary: &crate::persistence_protocol::WitnessAbortSummaryV1,
    ) -> Result<(), WitnessStoreErrorV1> {
        if [
            &summary.txid,
            &summary.candidate_digest,
            &summary.predecessor_head_digest,
            &summary.binding_generation,
            &summary.binding_digest,
            &summary.signer_key_id,
            &summary.witness_key_id,
            &summary.resulting_data_head_digest,
        ]
        .into_iter()
        .any(|value| !oracle_digest_text(value))
            || summary.authority_pair.current != summary.authority_pair.legacy
            || summary.authority_pair.current.device == 0
            || summary.authority_pair.current.inode == 0
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        oracle_mapping(&summary.publication_mapping)?;
        Ok(())
    }

    fn oracle_head_digest(
        head: &crate::persistence_protocol::WitnessHeadV1,
    ) -> Result<String, WitnessStoreErrorV1> {
        oracle_digest(WITNESS_HEAD_DOMAIN_V1, head)
    }

    fn oracle_data_head_digest(
        head: &crate::persistence_protocol::WitnessHeadV1,
    ) -> Result<String, WitnessStoreErrorV1> {
        let data = serde_json::json!({
            "authority_pair": head.authority_pair,
            "binding_digest": head.binding_digest,
            "binding_generation": head.binding_generation,
            "checkpoint_byte_len": head.checkpoint_byte_len,
            "checkpoint_digest": head.checkpoint_digest,
            "epoch": head.epoch,
            "publication_mapping": head.publication_mapping,
            "schema_version": head.schema_version,
            "sequence": head.sequence,
            "state_byte_len": head.state_byte_len,
            "state_digest": head.state_digest,
            "stream_id": head.stream_id,
        });
        oracle_digest(WITNESS_DATA_HEAD_DOMAIN_V1, &data)
    }

    fn oracle_genesis_digests(
        stream_id: &str,
        binding_generation: &str,
        binding_digest: &str,
        signer_key_id: &str,
        witness_key_id: &str,
        authority_pair: crate::persistence_protocol::AuthorityPairIdentityV1,
    ) -> Result<(String, String), WitnessStoreErrorV1> {
        let genesis = serde_json::json!({
            "authority_pair": authority_pair,
            "binding_digest": binding_digest,
            "binding_generation": binding_generation,
            "epoch": 0,
            "intent_counter": 0,
            "schema_version": PROTOCOL_SCHEMA_VERSION,
            "sequence": 0,
            "signer_key_id": signer_key_id,
            "stream_id": stream_id,
            "witness_key_id": witness_key_id,
        });
        Ok((
            oracle_digest(GENESIS_PREDECESSOR_DOMAIN_V1, &genesis)?,
            oracle_digest(GENESIS_DATA_HEAD_DOMAIN_V1, &genesis)?,
        ))
    }

    fn oracle_binding(
        binding: &crate::persistence_protocol::PublicationBindingV1,
    ) -> Result<(), WitnessStoreErrorV1> {
        let limits = binding.limits;
        if binding.schema_version != PROTOCOL_SCHEMA_VERSION
            || !oracle_string(&binding.stream_id)
            || binding.stream_id.len() as u64 > limits.max_string_bytes
            || !oracle_string(&binding.witness_identity)
            || binding.witness_identity.len() as u64 > limits.max_string_bytes
            || !oracle_digest_text(&binding.generation)
            || !oracle_digest_text(&binding.signer_key_id)
            || !oracle_digest_text(&binding.witness_key_id)
            || limits.max_string_bytes == 0
            || limits.max_string_bytes
                > crate::persistence_protocol::MAX_PROTOCOL_STRING_BYTES as u64
            || limits.max_payload_bytes == 0
            || limits.max_payload_bytes
                > crate::persistence_protocol::MAX_PROTOCOL_PAYLOAD_BYTES as u64
            || limits.max_record_bytes < limits.max_payload_bytes
            || limits.max_record_bytes
                > crate::persistence_protocol::MAX_PROTOCOL_RECORD_BYTES as u64
            || limits.max_collection_items == 0
            || limits.max_collection_items
                > crate::persistence_protocol::MAX_PROTOCOL_COLLECTION_ITEMS as u64
            || binding.authority_pair.current != binding.authority_pair.legacy
            || binding.cleanup_slot_count as usize
                != crate::persistence_protocol::FIXED_CLEANUP_SLOT_COUNT
            || binding.cleanup_slot_names.len() != binding.cleanup_slot_count as usize
            || binding.cleanup_slot_identities.len() != binding.cleanup_slot_count as usize
            || binding.cleanup_slot_names.len() as u64 > limits.max_collection_items
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        let roles = binding.publication_roles;
        let mut identities = vec![
            binding.parent_directory,
            binding.pool_directory,
            binding.pool_lock,
            binding.binding_file,
            binding.authority_pair.current,
            roles.state_canonical,
            roles.state_staging,
            roles.checkpoint_canonical,
            roles.checkpoint_staging,
            roles.journal_primary,
            roles.journal_secondary,
        ];
        identities.extend(binding.cleanup_slot_identities.iter().copied());
        if identities
            .iter()
            .any(|identity| identity.device == 0 || identity.inode == 0)
            || identities.iter().collect::<BTreeSet<_>>().len() != identities.len()
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        for (index, name) in binding.cleanup_slot_names.iter().enumerate() {
            if name != &format!("slot-{index:02}") || name.len() as u64 > limits.max_string_bytes {
                return Err(WitnessStoreErrorV1::Admission);
            }
        }
        let unsigned = oracle_without(binding, &["binding_digest", "binding_signature"])?;
        if oracle_digest(BINDING_DOMAIN_V1, &unsigned)? != binding.binding_digest {
            return Err(WitnessStoreErrorV1::Admission);
        }
        oracle_signed_object_raw(
            &unsigned,
            &binding.binding_signature,
            &binding.signer_key_id,
        )
    }

    fn oracle_mapping(
        mapping: &crate::persistence_protocol::PublicationMappingV1,
    ) -> Result<(), WitnessStoreErrorV1> {
        let identities = [
            mapping.state_canonical,
            mapping.state_staging,
            mapping.checkpoint_canonical,
            mapping.checkpoint_staging,
            mapping.journal_primary,
            mapping.journal_secondary,
        ];
        if identities
            .iter()
            .any(|identity| identity.device == 0 || identity.inode == 0)
            || identities.iter().collect::<BTreeSet<_>>().len() != identities.len()
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        Ok(())
    }

    fn oracle_pair_matches<T: Ord + Copy>(left: T, right: T, first: T, second: T) -> bool {
        BTreeSet::from([left, right]) == BTreeSet::from([first, second])
    }

    fn oracle_mapping_matches_roles(
        mapping: &crate::persistence_protocol::PublicationMappingV1,
        roles: &crate::persistence_protocol::PublicationRoleIdentitiesV1,
    ) -> bool {
        oracle_pair_matches(
            mapping.state_canonical,
            mapping.state_staging,
            roles.state_canonical,
            roles.state_staging,
        ) && oracle_pair_matches(
            mapping.checkpoint_canonical,
            mapping.checkpoint_staging,
            roles.checkpoint_canonical,
            roles.checkpoint_staging,
        ) && oracle_pair_matches(
            mapping.journal_primary,
            mapping.journal_secondary,
            roles.journal_primary,
            roles.journal_secondary,
        )
    }

    fn oracle_mapping_is_successor(
        before: &crate::persistence_protocol::PublicationMappingV1,
        after: &crate::persistence_protocol::PublicationMappingV1,
    ) -> bool {
        after.state_canonical == before.state_staging
            && after.state_staging == before.state_canonical
            && after.checkpoint_canonical == before.checkpoint_staging
            && after.checkpoint_staging == before.checkpoint_canonical
            && after.journal_primary == before.journal_primary
            && after.journal_secondary == before.journal_secondary
    }

    fn oracle_session(
        session: &crate::persistence_protocol::WitnessSessionV1,
    ) -> Result<(), WitnessStoreErrorV1> {
        if session.schema_version != PROTOCOL_SCHEMA_VERSION
            || !oracle_string(&session.stream_id)
            || !oracle_string(&session.witness_identity)
            || session.session_generation == 0
            || session.authority_pair.current != session.authority_pair.legacy
            || session.authority_pair.current.device == 0
            || session.authority_pair.current.inode == 0
            || [
                &session.binding_generation,
                &session.binding_digest,
                &session.signer_key_id,
                &session.witness_key_id,
                &session.ephemeral_key_id,
                &session.session_commitment,
            ]
            .into_iter()
            .any(|value| !oracle_digest_text(value))
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        Ok(())
    }

    fn oracle_rotation_receipt(
        receipt: &crate::persistence_protocol::WitnessSessionRotationReceiptV1,
    ) -> Result<(), WitnessStoreErrorV1> {
        oracle_session(&receipt.session)?;
        if receipt.schema_version != PROTOCOL_SCHEMA_VERSION
            || !oracle_digest_text(&receipt.accepted_request_digest)
            || !oracle_digest_text(&receipt.accepted_challenge_digest)
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        match (
            receipt.response_kind,
            &receipt.establish_snapshot,
            &receipt.discovery_snapshot,
        ) {
            (
                crate::persistence_protocol::WitnessSessionRotationResponseKindV1::Establish,
                Some(snapshot),
                None,
            ) => {
                if snapshot.schema_version != PROTOCOL_SCHEMA_VERSION {
                    return Err(WitnessStoreErrorV1::Admission);
                }
                if let Some(head) = &snapshot.committed_head {
                    oracle_head(head, true)?;
                    oracle_head_matches_session(head, &receipt.session)?;
                }
                let session_digest =
                    oracle_digest(WITNESS_SESSION_STATE_DOMAIN_V1, &receipt.session)?;
                let marker = serde_json::json!({
                    "accepted_challenge_digest": receipt.accepted_challenge_digest,
                    "response_kind": "Establish",
                    "resulting_session_digest": session_digest,
                });
                if !oracle_digest_text(&snapshot.external_marker)
                    || oracle_digest(WITNESS_EXTERNAL_MARKER_DOMAIN_V1, &marker)?
                        != snapshot.external_marker
                {
                    return Err(WitnessStoreErrorV1::Admission);
                }
            }
            (
                crate::persistence_protocol::WitnessSessionRotationResponseKindV1::Discover,
                None,
                Some(discovery),
            ) => {
                oracle_discovery(discovery)?;
                if discovery.recovery_session != receipt.session {
                    return Err(WitnessStoreErrorV1::Admission);
                }
            }
            _ => return Err(WitnessStoreErrorV1::Admission),
        }
        Ok(())
    }

    fn oracle_head_matches_session(
        head: &crate::persistence_protocol::WitnessHeadV1,
        session: &crate::persistence_protocol::WitnessSessionV1,
    ) -> Result<(), WitnessStoreErrorV1> {
        if head.stream_id != session.stream_id
            || head.binding_generation != session.binding_generation
            || head.binding_digest != session.binding_digest
            || head.signer_key_id != session.signer_key_id
            || head.witness_key_id != session.witness_key_id
            || head.authority_pair != session.authority_pair
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        Ok(())
    }

    fn oracle_discovery(
        discovery: &crate::persistence_protocol::WitnessDiscoveryV1,
    ) -> Result<(), WitnessStoreErrorV1> {
        if discovery.schema_version != PROTOCOL_SCHEMA_VERSION {
            return Err(WitnessStoreErrorV1::Admission);
        }
        oracle_session(&discovery.recovery_session)?;
        if let Some(head) = &discovery.head {
            oracle_head(head, true)?;
            oracle_head_matches_session(head, &discovery.recovery_session)?;
        }
        if let Some(prepared) = &discovery.prepared {
            oracle_witness_prepared(prepared)?;
            oracle_head_matches_session(&prepared.head, &discovery.recovery_session)?;
            if prepared.session_generation != discovery.recovery_session.session_generation {
                return Err(WitnessStoreErrorV1::Admission);
            }
        }
        if let Some(aborted) = &discovery.genesis_abort {
            oracle_genesis_abort(aborted)?;
            if discovery.head.is_some()
                || discovery.prepared.is_some()
                || aborted.stream_id != discovery.recovery_session.stream_id
                || aborted.binding_generation != discovery.recovery_session.binding_generation
                || aborted.binding_digest != discovery.recovery_session.binding_digest
                || aborted.signer_key_id != discovery.recovery_session.signer_key_id
                || aborted.witness_key_id != discovery.recovery_session.witness_key_id
                || aborted.authority_pair != discovery.recovery_session.authority_pair
            {
                return Err(WitnessStoreErrorV1::Admission);
            }
        }
        if let Some(prepared) = &discovery.prepared {
            match (&discovery.head, &prepared.predecessor_head) {
                (Some(head), Some(predecessor))
                    if head == predecessor
                        && prepared.predecessor_head_digest == oracle_head_digest(head)?
                        && prepared.head.txid != head.txid => {}
                (None, None) => {}
                _ => return Err(WitnessStoreErrorV1::Admission),
            }
        }
        Ok(())
    }

    fn oracle_transition(
        current: &WitnessStoreEnvelopeV1,
        proposed: &WitnessStoreEnvelopeV1,
    ) -> Result<(), WitnessStoreErrorV1> {
        if current.schema_version != proposed.schema_version
            || current.admission_digest != proposed.admission_digest
            || current.bucket_epoch_digest != proposed.bucket_epoch_digest
            || current.stream_initialization_digest != proposed.stream_initialization_digest
            || current.stream_id != proposed.stream_id
            || current.witness_identity != proposed.witness_identity
            || current.witness_key_id != proposed.witness_key_id
            || proposed.store_generation
                != current
                    .store_generation
                    .checked_add(1)
                    .ok_or(WitnessStoreErrorV1::Bounds)?
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        let rotation = oracle_is_rotation(current, proposed)?;
        let prepare = oracle_is_prepare(current, proposed);
        let commit = oracle_is_commit(current, proposed)?;
        let abort = oracle_is_abort(current, proposed)?;
        if [rotation, prepare, commit, abort]
            .into_iter()
            .filter(|accepted| *accepted)
            .count()
            != 1
        {
            return Err(WitnessStoreErrorV1::Admission);
        }
        Ok(())
    }

    fn oracle_is_rotation(
        current: &WitnessStoreEnvelopeV1,
        proposed: &WitnessStoreEnvelopeV1,
    ) -> Result<bool, WitnessStoreErrorV1> {
        if current.current != proposed.current
            || current.predecessor != proposed.predecessor
            || current.genesis_abort != proposed.genesis_abort
        {
            return Ok(false);
        }
        let Some(session) = &proposed.session else {
            return Ok(false);
        };
        let expected_generation = current
            .session
            .as_ref()
            .map_or(0, |old| old.session_generation)
            .checked_add(1)
            .ok_or(WitnessStoreErrorV1::Bounds)?;
        if session.session_generation != expected_generation
            || current.session.as_ref() == Some(session)
            || proposed.last_session_rotation == current.last_session_rotation
        {
            return Ok(false);
        }
        match (&current.prepared, &proposed.prepared) {
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
        let receipt = proposed
            .last_session_rotation
            .as_ref()
            .ok_or(WitnessStoreErrorV1::Admission)?;
        let snapshot_matches = match receipt.response_kind {
            crate::persistence_protocol::WitnessSessionRotationResponseKindV1::Establish => {
                proposed.prepared.is_none()
                    && receipt.establish_snapshot.as_ref().is_some_and(|snapshot| {
                        snapshot.committed_head
                            == proposed.current.as_ref().map(|stored| stored.head.clone())
                    })
            }
            crate::persistence_protocol::WitnessSessionRotationResponseKindV1::Discover => {
                receipt.discovery_snapshot.as_ref().is_some_and(|snapshot| {
                    snapshot.head == proposed.current.as_ref().map(|stored| stored.head.clone())
                        && snapshot.prepared
                            == proposed
                                .prepared
                                .as_ref()
                                .map(|stored| stored.prepared.clone())
                        && snapshot.genesis_abort == proposed.genesis_abort
                        && Some(&snapshot.recovery_session) == proposed.session.as_ref()
                })
            }
        };
        Ok(snapshot_matches)
    }

    fn oracle_is_prepare(
        current: &WitnessStoreEnvelopeV1,
        proposed: &WitnessStoreEnvelopeV1,
    ) -> bool {
        let Some(prepared) = proposed
            .prepared
            .as_ref()
            .filter(|_| current.prepared.is_none())
        else {
            return false;
        };
        if current.session.is_none()
            || current.session != proposed.session
            || current.last_session_rotation != proposed.last_session_rotation
            || current.current != proposed.current
            || current.predecessor != proposed.predecessor
            || proposed.genesis_abort.is_some()
        {
            return false;
        }
        matches!(
            (&current.genesis_abort, &prepared.prepared.genesis_abort),
            (None, None) | (Some(_), Some(_))
        ) && match (&current.genesis_abort, &prepared.prepared.genesis_abort) {
            (Some(old), Some(carried)) => old == carried,
            _ => true,
        }
    }

    fn oracle_is_commit(
        current: &WitnessStoreEnvelopeV1,
        proposed: &WitnessStoreEnvelopeV1,
    ) -> Result<bool, WitnessStoreErrorV1> {
        let Some(prepared) = current.prepared.as_ref() else {
            return Ok(false);
        };
        if current.session != proposed.session
            || current.last_session_rotation != proposed.last_session_rotation
            || current.genesis_abort.is_some()
            || proposed.prepared.is_some()
            || proposed.predecessor != current.current
            || proposed.genesis_abort.is_some()
        {
            return Ok(false);
        }
        let candidate = &prepared.candidate;
        let Some(stored) = &proposed.current else {
            return Ok(false);
        };
        Ok(&stored.candidate == candidate
            && serde_json::to_value(&stored.head).map_err(|_| WitnessStoreErrorV1::Corrupt)?
                == oracle_candidate_head_value(candidate, true)?)
    }

    fn oracle_is_abort(
        current: &WitnessStoreEnvelopeV1,
        proposed: &WitnessStoreEnvelopeV1,
    ) -> Result<bool, WitnessStoreErrorV1> {
        let Some(prepared) = current.prepared.as_ref() else {
            return Ok(false);
        };
        if current.session != proposed.session
            || current.last_session_rotation != proposed.last_session_rotation
            || proposed.prepared.is_some()
            || current.genesis_abort.is_some()
        {
            return Ok(false);
        }
        match current.current.as_ref() {
            None => Ok(proposed.current.is_none()
                && proposed.predecessor.is_none()
                && proposed.genesis_abort.as_ref().is_some_and(|aborted| {
                    let expected = &prepared.prepared;
                    aborted.stream_id == expected.head.stream_id
                        && aborted.txid == expected.head.txid
                        && aborted.candidate_digest == expected.head.candidate_digest
                        && aborted.predecessor_head_digest == expected.predecessor_head_digest
                        && aborted.resulting_data_head_digest
                            == expected.predecessor_data_head_digest
                        && aborted.epoch == expected.head.epoch
                        && aborted.sequence == expected.head.sequence
                        && aborted.intent_counter == expected.head.intent_counter
                        && aborted.binding_generation == expected.head.binding_generation
                        && aborted.binding_digest == expected.head.binding_digest
                        && aborted.signer_key_id == expected.head.signer_key_id
                        && aborted.witness_key_id == expected.head.witness_key_id
                        && aborted.authority_pair == expected.head.authority_pair
                        && aborted.publication_mapping == expected.predecessor_publication_mapping
                })),
            Some(committed) => {
                let Some(stored) = &proposed.current else {
                    return Ok(false);
                };
                let Some(WitnessIntentOutcomeV1::Aborted(summary)) =
                    &stored.head.last_intent_outcome
                else {
                    return Ok(false);
                };
                let expected_summary = serde_json::json!({
                    "authority_pair": prepared.prepared.head.authority_pair,
                    "binding_digest": prepared.prepared.head.binding_digest,
                    "binding_generation": prepared.prepared.head.binding_generation,
                    "candidate_digest": prepared.prepared.head.candidate_digest,
                    "epoch": prepared.prepared.head.epoch,
                    "intent_counter": prepared.prepared.head.intent_counter,
                    "predecessor_head_digest": prepared.prepared.predecessor_head_digest,
                    "publication_mapping": prepared.prepared.predecessor_publication_mapping,
                    "resulting_data_head_digest": oracle_data_head_digest(&committed.head)?,
                    "sequence": prepared.prepared.head.sequence,
                    "signer_key_id": prepared.prepared.head.signer_key_id,
                    "txid": prepared.prepared.head.txid,
                    "witness_key_id": prepared.prepared.head.witness_key_id,
                });
                let mut expected_head = serde_json::to_value(&committed.head)
                    .map_err(|_| WitnessStoreErrorV1::Corrupt)?;
                expected_head["intent_counter"] =
                    Value::Number(prepared.prepared.head.intent_counter.into());
                expected_head["last_intent_outcome"] =
                    serde_json::json!({"Aborted": expected_summary});
                Ok(proposed.predecessor == current.predecessor
                    && proposed.genesis_abort.is_none()
                    && stored.candidate == committed.candidate
                    && serde_json::to_value(summary).map_err(|_| WitnessStoreErrorV1::Corrupt)?
                        == expected_summary
                    && serde_json::to_value(&stored.head)
                        .map_err(|_| WitnessStoreErrorV1::Corrupt)?
                        == expected_head)
            }
        }
    }

    fn oracle_stream_key(stream_id: &str) -> String {
        let mut material = crate::witness_engine::WITNESS_STORE_DOMAIN_V1.to_vec();
        material.extend_from_slice(stream_id.as_bytes());
        format!("s.{}", sha256_hex(&material))
    }

    fn oracle_digest_text(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }

    fn oracle_string(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= crate::persistence_protocol::MAX_PROTOCOL_STRING_BYTES
            && !value.as_bytes().contains(&0)
    }

    fn oracle_timestamp(value: &str) -> bool {
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
            return false;
        }
        let parse = |range: std::ops::Range<usize>| {
            std::str::from_utf8(&bytes[range]).ok()?.parse::<u32>().ok()
        };
        let Some(year) = parse(0..4) else {
            return false;
        };
        let Some(month) = parse(5..7) else {
            return false;
        };
        let Some(day) = parse(8..10) else {
            return false;
        };
        let Some(hour) = parse(11..13) else {
            return false;
        };
        let Some(minute) = parse(14..16) else {
            return false;
        };
        let Some(second) = parse(17..19) else {
            return false;
        };
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let maximum_day = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => 0,
        };
        day != 0 && day <= maximum_day && hour <= 23 && minute <= 59 && second <= 59
    }

    fn oracle_signed_digest(
        envelope: &WitnessStoreEnvelopeV1,
    ) -> Result<String, WitnessStoreErrorV1> {
        oracle_digest(
            crate::witness_engine::WITNESS_STORE_SIGNED_DOMAIN_V1,
            envelope,
        )
    }

    fn oracle_signed_object<T: Serialize>(
        domain: &[u8],
        value: &T,
        signature: &DetachedSignature,
        expected_key_id: &str,
    ) -> Result<(), WitnessStoreErrorV1> {
        let unsigned = oracle_without(value, &["signature"])?;
        let canonical =
            canonical_wire_bytes(&unsigned).map_err(|_| WitnessStoreErrorV1::Corrupt)?;
        let mut bytes = domain.to_vec();
        bytes.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&canonical);
        oracle_signature(&bytes, signature, expected_key_id)
    }

    fn oracle_signed_object_raw(
        unsigned: &Value,
        signature: &DetachedSignature,
        expected_key_id: &str,
    ) -> Result<(), WitnessStoreErrorV1> {
        let bytes = canonical_wire_bytes(unsigned).map_err(|_| WitnessStoreErrorV1::Corrupt)?;
        oracle_signature(&bytes, signature, expected_key_id)
    }

    fn oracle_signature(
        bytes: &[u8],
        signature: &DetachedSignature,
        expected_key_id: &str,
    ) -> Result<(), WitnessStoreErrorV1> {
        let public = PublicKey::from_hex(&signature.public_key_hex)
            .map_err(|_| WitnessStoreErrorV1::Corrupt)?;
        if signature.algorithm != "ed25519"
            || signature.key_id != expected_key_id
            || sha256_hex(public.as_bytes()) != expected_key_id
            || verify_detached_signature(bytes, signature).is_err()
        {
            return Err(WitnessStoreErrorV1::Corrupt);
        }
        Ok(())
    }

    fn oracle_without<T: Serialize>(
        value: &T,
        fields: &[&str],
    ) -> Result<Value, WitnessStoreErrorV1> {
        let mut value = serde_json::to_value(value).map_err(|_| WitnessStoreErrorV1::Corrupt)?;
        let object = value.as_object_mut().ok_or(WitnessStoreErrorV1::Corrupt)?;
        for field in fields {
            if object.remove(*field).is_none() {
                return Err(WitnessStoreErrorV1::Corrupt);
            }
        }
        Ok(value)
    }

    fn oracle_digest_without<T: Serialize>(
        domain: &[u8],
        value: &T,
        fields: &[&str],
    ) -> Result<String, WitnessStoreErrorV1> {
        oracle_digest(domain, &oracle_without(value, fields)?)
    }

    fn oracle_digest<T: Serialize>(
        domain: &[u8],
        value: &T,
    ) -> Result<String, WitnessStoreErrorV1> {
        let bytes = canonical_wire_bytes(value).map_err(|_| WitnessStoreErrorV1::Corrupt)?;
        digest_domain(domain, &bytes).map_err(|_| WitnessStoreErrorV1::Corrupt)
    }

    fn oracle_encoded_len<T: Serialize>(value: &T) -> Result<usize, WitnessStoreErrorV1> {
        canonical_wire_bytes(value)
            .map(|bytes| bytes.len())
            .map_err(|_| WitnessStoreErrorV1::Corrupt)
    }
}
// REFERENCE_ORACLE_END

pub struct ReferenceWitnessStoreModel(reference_oracle::Model);

impl ReferenceWitnessStoreModel {
    pub fn new(
        ready: WitnessStoreReadyResultV1,
        entries: BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>,
        capacity_bytes: usize,
    ) -> Result<Self, WitnessStoreErrorV1> {
        reference_oracle::Model::new(ready, entries, capacity_bytes).map(Self)
    }

    pub fn inspect_ready(&self) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1> {
        self.0.inspect_ready()
    }

    pub fn read_entry(
        &mut self,
        stream_id: &str,
    ) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1> {
        self.0.read_entry(stream_id)
    }

    pub fn inject_fault(&mut self, fault: WitnessStoreFault) {
        self.0.inject_fault(fault);
    }

    pub fn compare_and_swap(
        &mut self,
        stream_id: &str,
        expected_revision: u64,
        expected_store_state_digest: &str,
        proposed: &WitnessStoreEnvelopeV1,
    ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1> {
        self.0.compare_and_swap(
            stream_id,
            expected_revision,
            expected_store_state_digest,
            proposed,
        )
    }

    pub fn canonical_store_bytes(&self) -> Result<Vec<u8>, WitnessStoreErrorV1> {
        self.0.canonical_store_bytes()
    }
}
