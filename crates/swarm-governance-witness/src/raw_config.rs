use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use swarm_governance::witness_engine::store::{
    WitnessBucketAnchorV1, WitnessBucketConfigurationV1, WitnessBucketEpochV1,
    WitnessStoreDeploymentInputsV1,
};
use thiserror::Error;

use crate::nats_config::{
    DESCRIPTION, DUPLICATE_WINDOW_NANOS, NATS_IMAGE_INDEX_DIGEST, NATS_SERVER_VERSION,
    expected_server_metadata, projected_configuration,
};

const RAW_CONFIGURATION_DOMAIN: &[u8] =
    b"swarm.governance.nats-2.11.17-raw-stream-configuration.v1";
const RAW_STREAM_INFO_DOMAIN: &[u8] = b"swarm.governance.nats-2.11.17-raw-stream-info.v1";
const STREAM_INFO_RESPONSE_TYPE: &str = "io.nats.jetstream.api.v1.stream_info_response";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RawConfigurationError {
    #[error("the NATS raw stream response is not the closed 2.11.17 schema")]
    NonCanonicalRawConfiguration,
    #[error("the NATS runtime identity does not match the pinned 2.11.17 deployment")]
    WrongRuntimeIdentity,
    #[error("the projected witness configuration is invalid")]
    InvalidProjection,
    #[error("the raw inspection does not match the authenticated epoch and anchor")]
    TypedBindingMismatch,
}

pub(crate) fn relay_topology_token_is_closed(value: &str) -> bool {
    value.starts_with("relay-phase285-")
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nats21117ExpectedConfigurationV1 {
    reported_server_version: String,
    resolved_server_image_index_digest: String,
    bucket_name: String,
    required_bucket_bytes: i64,
    max_kv_value_bytes: i32,
    configured_replica_count: u32,
}

impl Nats21117ExpectedConfigurationV1 {
    #[allow(dead_code)]
    pub(crate) fn from_validated_deployment(
        configuration: &WitnessBucketConfigurationV1,
        deployment: &WitnessStoreDeploymentInputsV1,
        reported_server_version: &str,
        resolved_server_image_index_digest: &str,
    ) -> Result<Self, RawConfigurationError> {
        configuration
            .validate()
            .map_err(|_| RawConfigurationError::InvalidProjection)?;
        deployment
            .validate()
            .map_err(|_| RawConfigurationError::InvalidProjection)?;
        if reported_server_version != NATS_SERVER_VERSION
            || resolved_server_image_index_digest != NATS_IMAGE_INDEX_DIGEST
        {
            return Err(RawConfigurationError::WrongRuntimeIdentity);
        }
        if configuration.num_replicas != deployment.configured_replica_count {
            return Err(RawConfigurationError::InvalidProjection);
        }
        let bucket_name = configuration
            .stream_name
            .strip_prefix("KV_")
            .filter(|value| !value.is_empty())
            .ok_or(RawConfigurationError::InvalidProjection)?;
        let expected_projection = projected_configuration(
            bucket_name,
            configuration.max_bytes,
            configuration.max_message_size,
            deployment.configured_replica_count,
        );
        if expected_projection != *configuration {
            return Err(RawConfigurationError::InvalidProjection);
        }
        Ok(Self {
            reported_server_version: reported_server_version.to_string(),
            resolved_server_image_index_digest: resolved_server_image_index_digest.to_string(),
            bucket_name: bucket_name.to_string(),
            required_bucket_bytes: configuration.max_bytes,
            max_kv_value_bytes: configuration.max_message_size,
            configured_replica_count: deployment.configured_replica_count,
        })
    }

    #[doc(hidden)]
    pub fn phase285_conformance_fixture() -> Self {
        Self {
            reported_server_version: NATS_SERVER_VERSION.to_string(),
            resolved_server_image_index_digest: NATS_IMAGE_INDEX_DIGEST.to_string(),
            bucket_name: "phase285_witness".to_string(),
            required_bucket_bytes: 1_048_576,
            max_kv_value_bytes: 4_096,
            configured_replica_count: 1,
        }
    }

    #[doc(hidden)]
    pub fn with_wrong_server_version_for_conformance(mut self) -> Self {
        self.reported_server_version = "2.11.18".to_string();
        self
    }

    #[doc(hidden)]
    pub fn with_wrong_image_digest_for_conformance(mut self) -> Self {
        self.resolved_server_image_index_digest = "sha256:deadbeef".to_string();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nats21117RawStreamInfoV1 {
    #[serde(rename = "type")]
    response_type: String,
    total: u64,
    offset: u64,
    limit: u64,
    config: Nats21117RawConfigV1,
    created: String,
    state: Nats21117RawStreamStateV1,
    cluster: Nats21117RawClusterV1,
    ts: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nats21117RawStreamStateV1 {
    messages: u64,
    bytes: u64,
    first_seq: u64,
    first_ts: String,
    last_seq: u64,
    last_ts: String,
    consumer_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_subjects: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_deleted: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deleted: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subjects: Option<BTreeMap<String, u64>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nats21117RawClusterV1 {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raft_group: Option<String>,
    leader: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    leader_since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replicas: Option<Vec<Nats21117RawPeerV1>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nats21117RawPeerV1 {
    name: String,
    current: bool,
    active: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    offline: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lag: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nats21117RawConfigV1 {
    name: String,
    description: String,
    subjects: Vec<String>,
    retention: String,
    max_consumers: i32,
    max_msgs: i64,
    max_bytes: i64,
    max_age: u64,
    max_msgs_per_subject: i64,
    max_msg_size: i32,
    discard: String,
    storage: String,
    num_replicas: u32,
    duplicate_window: u64,
    compression: String,
    allow_direct: bool,
    mirror_direct: bool,
    sealed: bool,
    deny_delete: bool,
    deny_purge: bool,
    allow_rollup_hdrs: bool,
    consumer_limits: Nats21117EmptyConsumerLimitsV1,
    allow_msg_ttl: bool,
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nats21117EmptyConsumerLimitsV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedRawConfigurationV1 {
    raw_stream_info: Nats21117RawStreamInfoV1,
    canonical_created_at: String,
    canonical_raw_stream_info: Vec<u8>,
    raw_stream_info_digest: String,
    raw_configuration: Nats21117RawConfigV1,
    canonical_raw_configuration: Vec<u8>,
    raw_stream_configuration_digest: String,
    projected_configuration: WitnessBucketConfigurationV1,
    projected_configuration_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct Nats21117TypedSnapshotV1 {
    subjects_count: Option<u64>,
    messages: u64,
    first_sequence: u64,
    last_sequence: u64,
    created_at: String,
    canonical_raw_stream_info: Vec<u8>,
    raw_stream_info_digest: String,
    canonical_raw_configuration: Vec<u8>,
    raw_stream_configuration_digest: String,
    projected_configuration: WitnessBucketConfigurationV1,
    leader: String,
}

#[allow(dead_code)]
impl Nats21117TypedSnapshotV1 {
    pub(crate) fn subjects_count(&self) -> Option<u64> {
        self.subjects_count
    }

    pub(crate) fn messages(&self) -> u64 {
        self.messages
    }

    pub(crate) fn first_sequence(&self) -> u64 {
        self.first_sequence
    }

    pub(crate) fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    pub(crate) fn created_at(&self) -> &str {
        &self.created_at
    }

    pub(crate) fn canonical_raw_stream_info(&self) -> &[u8] {
        &self.canonical_raw_stream_info
    }

    pub(crate) fn raw_stream_info_digest(&self) -> &str {
        &self.raw_stream_info_digest
    }

    pub(crate) fn canonical_raw_configuration(&self) -> &[u8] {
        &self.canonical_raw_configuration
    }

    pub(crate) fn raw_stream_configuration_digest(&self) -> &str {
        &self.raw_stream_configuration_digest
    }

    pub(crate) fn projected_configuration(&self) -> &WitnessBucketConfigurationV1 {
        &self.projected_configuration
    }

    pub(crate) fn leader(&self) -> &str {
        &self.leader
    }
}

impl InspectedRawConfigurationV1 {
    pub fn raw_configuration(&self) -> &Nats21117RawConfigV1 {
        &self.raw_configuration
    }

    pub fn canonical_raw_configuration(&self) -> &[u8] {
        &self.canonical_raw_configuration
    }

    pub fn projected_configuration(&self) -> &WitnessBucketConfigurationV1 {
        &self.projected_configuration
    }

    pub fn canonical_raw_stream_info(&self) -> &[u8] {
        &self.canonical_raw_stream_info
    }

    pub fn raw_stream_info(&self) -> &Nats21117RawStreamInfoV1 {
        &self.raw_stream_info
    }

    pub(crate) fn canonical_created_at(&self) -> &str {
        &self.canonical_created_at
    }

    pub(crate) fn raw_stream_configuration_digest(&self) -> &str {
        &self.raw_stream_configuration_digest
    }

    #[allow(dead_code)]
    pub(crate) fn typed_snapshot(&self) -> Nats21117TypedSnapshotV1 {
        Nats21117TypedSnapshotV1 {
            subjects_count: self.raw_stream_info.state.num_subjects,
            messages: self.raw_stream_info.state.messages,
            first_sequence: self.raw_stream_info.state.first_seq,
            last_sequence: self.raw_stream_info.state.last_seq,
            created_at: self.canonical_created_at.clone(),
            canonical_raw_stream_info: self.canonical_raw_stream_info.clone(),
            raw_stream_info_digest: self.raw_stream_info_digest.clone(),
            canonical_raw_configuration: self.canonical_raw_configuration.clone(),
            raw_stream_configuration_digest: self.raw_stream_configuration_digest.clone(),
            projected_configuration: self.projected_configuration.clone(),
            leader: self.raw_stream_info.cluster.leader.clone(),
        }
    }
}

fn canonicalize_nats_created_at(value: &str) -> Result<String, RawConfigurationError> {
    let bytes = value.as_bytes();
    let (base, fraction) = if bytes.len() == 20 && bytes[19] == b'Z' {
        (&bytes[..19], &bytes[19..19])
    } else if (22..=30).contains(&bytes.len())
        && bytes[19] == b'.'
        && bytes[bytes.len() - 1] == b'Z'
    {
        (&bytes[..19], &bytes[20..bytes.len() - 1])
    } else {
        return Err(RawConfigurationError::NonCanonicalRawConfiguration);
    };
    if base[4] != b'-'
        || base[7] != b'-'
        || base[10] != b'T'
        || base[13] != b':'
        || base[16] != b':'
        || !base[..4].iter().all(u8::is_ascii_digit)
        || !base[5..7].iter().all(u8::is_ascii_digit)
        || !base[8..10].iter().all(u8::is_ascii_digit)
        || !base[11..13].iter().all(u8::is_ascii_digit)
        || !base[14..16].iter().all(u8::is_ascii_digit)
        || !base[17..19].iter().all(u8::is_ascii_digit)
        || !fraction.iter().all(u8::is_ascii_digit)
    {
        return Err(RawConfigurationError::NonCanonicalRawConfiguration);
    }
    let parse = |range: std::ops::Range<usize>| -> Option<u32> {
        std::str::from_utf8(&base[range]).ok()?.parse().ok()
    };
    let year = parse(0..4).ok_or(RawConfigurationError::NonCanonicalRawConfiguration)?;
    let month = parse(5..7).ok_or(RawConfigurationError::NonCanonicalRawConfiguration)?;
    let day = parse(8..10).ok_or(RawConfigurationError::NonCanonicalRawConfiguration)?;
    let hour = parse(11..13).ok_or(RawConfigurationError::NonCanonicalRawConfiguration)?;
    let minute = parse(14..16).ok_or(RawConfigurationError::NonCanonicalRawConfiguration)?;
    let second = parse(17..19).ok_or(RawConfigurationError::NonCanonicalRawConfiguration)?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if day == 0 || day > maximum_day || hour > 23 || minute > 59 || second > 59 {
        return Err(RawConfigurationError::NonCanonicalRawConfiguration);
    }

    let mut canonical = String::with_capacity(30);
    canonical.push_str(
        std::str::from_utf8(base)
            .map_err(|_| RawConfigurationError::NonCanonicalRawConfiguration)?,
    );
    canonical.push('.');
    canonical.push_str(
        std::str::from_utf8(fraction)
            .map_err(|_| RawConfigurationError::NonCanonicalRawConfiguration)?,
    );
    for _ in fraction.len()..9 {
        canonical.push('0');
    }
    canonical.push('Z');
    Ok(canonical)
}

impl Nats21117RawConfigV1 {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn project(
        &self,
        expected: &Nats21117ExpectedConfigurationV1,
    ) -> Result<WitnessBucketConfigurationV1, RawConfigurationError> {
        let projection = projected_configuration(
            &expected.bucket_name,
            expected.required_bucket_bytes,
            expected.max_kv_value_bytes,
            expected.configured_replica_count,
        );
        if self.name != projection.stream_name
            || self.description != DESCRIPTION
            || self.subjects != projection.subjects
            || self.retention != "limits"
            || self.max_consumers != -1
            || self.max_msgs != -1
            || self.max_bytes != expected.required_bucket_bytes
            || self.max_age != 0
            || self.max_msgs_per_subject != 1
            || self.max_msg_size != expected.max_kv_value_bytes
            || self.discard != "new"
            || self.storage != "file"
            || self.num_replicas != expected.configured_replica_count
            || self.duplicate_window != DUPLICATE_WINDOW_NANOS
            || self.compression != "none"
            || self.allow_direct
            || self.mirror_direct
            || self.sealed
            || !self.deny_delete
            || !self.deny_purge
            || self.allow_rollup_hdrs
            || self.consumer_limits != (Nats21117EmptyConsumerLimitsV1 {})
            || self.allow_msg_ttl
            || self.metadata != expected_server_metadata()
        {
            return Err(RawConfigurationError::NonCanonicalRawConfiguration);
        }
        projection
            .validate()
            .map_err(|_| RawConfigurationError::InvalidProjection)?;
        Ok(projection)
    }

    pub(crate) fn raw_digest(
        &self,
        expected: &Nats21117ExpectedConfigurationV1,
    ) -> Result<(Vec<u8>, String), RawConfigurationError> {
        self.project(expected)?;
        let canonical = serde_json::to_vec(self)
            .map_err(|_| RawConfigurationError::NonCanonicalRawConfiguration)?;
        let mut hasher = Sha256::new();
        hasher.update(RAW_CONFIGURATION_DOMAIN);
        hasher.update(
            u64::try_from(canonical.len())
                .map_err(|_| RawConfigurationError::NonCanonicalRawConfiguration)?
                .to_be_bytes(),
        );
        hasher.update(&canonical);
        Ok((canonical, hex::encode(hasher.finalize())))
    }
}

pub(crate) fn inspect_raw_stream_info_unbound(
    bytes: &[u8],
    expected: &Nats21117ExpectedConfigurationV1,
) -> Result<InspectedRawConfigurationV1, RawConfigurationError> {
    if expected.reported_server_version != NATS_SERVER_VERSION
        || expected.resolved_server_image_index_digest != NATS_IMAGE_INDEX_DIGEST
    {
        return Err(RawConfigurationError::WrongRuntimeIdentity);
    }
    let info: Nats21117RawStreamInfoV1 = serde_json::from_slice(bytes)
        .map_err(|_| RawConfigurationError::NonCanonicalRawConfiguration)?;
    let canonical_created_at = canonicalize_nats_created_at(&info.created)?;
    if info.response_type != STREAM_INFO_RESPONSE_TYPE
        || info.total != 0
        || info.offset != 0
        || info.limit != 0
        || info.cluster.leader.is_empty()
    {
        return Err(RawConfigurationError::NonCanonicalRawConfiguration);
    }
    let projected_configuration = info.config.project(expected)?;
    let projected_configuration_digest = projected_configuration
        .digest()
        .map_err(|_| RawConfigurationError::InvalidProjection)?;
    let (canonical_raw_configuration, raw_stream_configuration_digest) =
        info.config.raw_digest(expected)?;
    let canonical_raw_stream_info = serde_json::to_vec(&info)
        .map_err(|_| RawConfigurationError::NonCanonicalRawConfiguration)?;
    let mut info_hasher = Sha256::new();
    info_hasher.update(RAW_STREAM_INFO_DOMAIN);
    info_hasher.update(
        u64::try_from(canonical_raw_stream_info.len())
            .map_err(|_| RawConfigurationError::NonCanonicalRawConfiguration)?
            .to_be_bytes(),
    );
    info_hasher.update(&canonical_raw_stream_info);
    let raw_stream_info_digest = hex::encode(info_hasher.finalize());
    Ok(InspectedRawConfigurationV1 {
        raw_configuration: info.config.clone(),
        raw_stream_info: info,
        canonical_created_at,
        canonical_raw_stream_info,
        raw_stream_info_digest,
        canonical_raw_configuration,
        raw_stream_configuration_digest,
        projected_configuration,
        projected_configuration_digest,
    })
}

pub fn inspect_raw_stream_info(
    bytes: &[u8],
    expected: &Nats21117ExpectedConfigurationV1,
    epoch: &WitnessBucketEpochV1,
    anchor: &WitnessBucketAnchorV1,
) -> Result<InspectedRawConfigurationV1, RawConfigurationError> {
    epoch
        .validate()
        .map_err(|_| RawConfigurationError::TypedBindingMismatch)?;
    anchor
        .validate()
        .map_err(|_| RawConfigurationError::TypedBindingMismatch)?;
    if anchor.epoch != *epoch {
        return Err(RawConfigurationError::TypedBindingMismatch);
    }

    let inspected = inspect_raw_stream_info_unbound(bytes, expected)?;
    if inspected.projected_configuration_digest != epoch.bucket_configuration_digest
        || inspected.raw_stream_configuration_digest != anchor.raw_stream_configuration_digest
        || inspected.projected_configuration.stream_name != epoch.stream_name
        || inspected.canonical_created_at != anchor.nats_stream_created_at
    {
        return Err(RawConfigurationError::TypedBindingMismatch);
    }
    Ok(inspected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deployment(replicas: u32) -> WitnessStoreDeploymentInputsV1 {
        WitnessStoreDeploymentInputsV1 {
            schema_version: 1,
            max_manifest_bytes: 131_072,
            maximum_admitted_streams: 17,
            configured_replica_count: replicas,
        }
    }

    fn expected_dynamic() -> Result<Nats21117ExpectedConfigurationV1, RawConfigurationError> {
        let configuration = projected_configuration("dynamic_witness", 2_097_152, 8_192, 3);
        Nats21117ExpectedConfigurationV1::from_validated_deployment(
            &configuration,
            &deployment(3),
            NATS_SERVER_VERSION,
            NATS_IMAGE_INDEX_DIGEST,
        )
    }

    fn dynamic_raw_info() -> Nats21117RawStreamInfoV1 {
        Nats21117RawStreamInfoV1 {
            response_type: STREAM_INFO_RESPONSE_TYPE.to_string(),
            total: 0,
            offset: 0,
            limit: 0,
            config: Nats21117RawConfigV1 {
                name: "KV_dynamic_witness".to_string(),
                description: DESCRIPTION.to_string(),
                subjects: projected_configuration("dynamic_witness", 2_097_152, 8_192, 3).subjects,
                retention: "limits".to_string(),
                max_consumers: -1,
                max_msgs: -1,
                max_bytes: 2_097_152,
                max_age: 0,
                max_msgs_per_subject: 1,
                max_msg_size: 8_192,
                discard: "new".to_string(),
                storage: "file".to_string(),
                num_replicas: 3,
                duplicate_window: DUPLICATE_WINDOW_NANOS,
                compression: "none".to_string(),
                allow_direct: false,
                mirror_direct: false,
                sealed: false,
                deny_delete: true,
                deny_purge: true,
                allow_rollup_hdrs: false,
                consumer_limits: Nats21117EmptyConsumerLimitsV1 {},
                allow_msg_ttl: false,
                metadata: expected_server_metadata(),
            },
            created: "2026-08-25T01:02:03.000000000Z".to_string(),
            state: Nats21117RawStreamStateV1 {
                messages: 9,
                bytes: 32_768,
                first_seq: 7,
                first_ts: "2026-08-25T01:02:04.000000000Z".to_string(),
                last_seq: 19,
                last_ts: "2026-08-25T01:02:05.000000000Z".to_string(),
                consumer_count: 0,
                num_subjects: Some(2),
                num_deleted: None,
                deleted: None,
                subjects: None,
            },
            cluster: Nats21117RawClusterV1 {
                name: Some("phase285".to_string()),
                raft_group: Some("raft-1".to_string()),
                leader: "nats-a".to_string(),
                leader_since: None,
                replicas: None,
            },
            ts: "2026-08-25T01:02:06.000000000Z".to_string(),
        }
    }

    #[test]
    fn expected_configuration_derives_dynamic_validated_deployment()
    -> Result<(), RawConfigurationError> {
        let expected = expected_dynamic()?;
        assert_eq!(expected.bucket_name, "dynamic_witness");
        assert_eq!(expected.required_bucket_bytes, 2_097_152);
        assert_eq!(expected.max_kv_value_bytes, 8_192);
        assert_eq!(expected.configured_replica_count, 3);
        Ok(())
    }

    #[test]
    fn expected_configuration_rejects_invalid_or_mismatched_inputs() {
        let valid = projected_configuration("dynamic_witness", 2_097_152, 8_192, 3);
        let mut semantically_invalid = valid.clone();
        semantically_invalid.allow_direct = true;
        assert_eq!(
            Nats21117ExpectedConfigurationV1::from_validated_deployment(
                &semantically_invalid,
                &deployment(3),
                NATS_SERVER_VERSION,
                NATS_IMAGE_INDEX_DIGEST,
            ),
            Err(RawConfigurationError::InvalidProjection)
        );
        assert_eq!(
            Nats21117ExpectedConfigurationV1::from_validated_deployment(
                &valid,
                &deployment(5),
                NATS_SERVER_VERSION,
                NATS_IMAGE_INDEX_DIGEST,
            ),
            Err(RawConfigurationError::InvalidProjection)
        );
        assert_eq!(
            Nats21117ExpectedConfigurationV1::from_validated_deployment(
                &valid,
                &deployment(3),
                "2.11.18",
                NATS_IMAGE_INDEX_DIGEST,
            ),
            Err(RawConfigurationError::WrongRuntimeIdentity)
        );
        assert_eq!(
            Nats21117ExpectedConfigurationV1::from_validated_deployment(
                &valid,
                &deployment(3),
                NATS_SERVER_VERSION,
                "sha256:deadbeef",
            ),
            Err(RawConfigurationError::WrongRuntimeIdentity)
        );
    }

    #[test]
    fn typed_snapshot_maps_exact_authenticated_raw_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let raw = dynamic_raw_info();
        let canonical_config = serde_json::to_vec(&raw.config)?;
        let bytes = serde_json::to_vec(&raw)?;
        let expected = expected_dynamic()?;
        let inspected = inspect_raw_stream_info_unbound(&bytes, &expected)?;
        let snapshot = inspected.typed_snapshot();

        assert_eq!(snapshot.subjects_count(), Some(2));
        assert_eq!(snapshot.messages(), 9);
        assert_eq!(snapshot.first_sequence(), 7);
        assert_eq!(snapshot.last_sequence(), 19);
        assert_eq!(snapshot.created_at(), "2026-08-25T01:02:03.000000000Z");
        assert_eq!(snapshot.leader(), "nats-a");
        assert_eq!(snapshot.canonical_raw_configuration(), canonical_config);
        assert_eq!(snapshot.canonical_raw_stream_info(), bytes);
        assert_eq!(
            snapshot.projected_configuration(),
            &projected_configuration("dynamic_witness", 2_097_152, 8_192, 3)
        );

        let mut expected_digest = Sha256::new();
        expected_digest.update(RAW_CONFIGURATION_DOMAIN);
        expected_digest.update((canonical_config.len() as u64).to_be_bytes());
        expected_digest.update(&canonical_config);
        assert_eq!(
            snapshot.raw_stream_configuration_digest(),
            hex::encode(expected_digest.finalize())
        );

        let mut expected_info_digest = Sha256::new();
        expected_info_digest.update(RAW_STREAM_INFO_DOMAIN);
        expected_info_digest.update((bytes.len() as u64).to_be_bytes());
        expected_info_digest.update(&bytes);
        assert_eq!(
            snapshot.raw_stream_info_digest(),
            hex::encode(expected_info_digest.finalize())
        );
        assert_ne!(
            snapshot.canonical_raw_stream_info(),
            snapshot.canonical_raw_configuration()
        );
        assert_ne!(
            snapshot.raw_stream_info_digest(),
            snapshot.raw_stream_configuration_digest()
        );

        let mut explicit_zero_subject_count = raw.clone();
        explicit_zero_subject_count.state.num_subjects = Some(0);
        let explicit_zero_bytes = serde_json::to_vec(&explicit_zero_subject_count)?;
        let explicit_zero = inspect_raw_stream_info_unbound(&explicit_zero_bytes, &expected)?;
        assert_eq!(explicit_zero.typed_snapshot().subjects_count(), Some(0));

        let mut omitted_subject_count = raw;
        omitted_subject_count.state.num_subjects = None;
        let omitted_bytes = serde_json::to_vec(&omitted_subject_count)?;
        let omitted = inspect_raw_stream_info_unbound(&omitted_bytes, &expected)?;
        let omitted_count = omitted.typed_snapshot().subjects_count();
        assert_eq!(omitted_count, None);
        assert_ne!(
            explicit_zero.typed_snapshot().subjects_count(),
            omitted_count
        );
        Ok(())
    }

    #[test]
    fn typed_snapshot_canonicalizes_nats_created_without_changing_full_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let expected = expected_dynamic()?;
        let variants = [
            ("2026-08-25T01:02:03Z", "2026-08-25T01:02:03.000000000Z"),
            ("2026-08-25T01:02:03.4Z", "2026-08-25T01:02:03.400000000Z"),
            (
                "2026-08-25T01:02:03.12345678Z",
                "2026-08-25T01:02:03.123456780Z",
            ),
            (
                "2026-08-25T01:02:03.123456789Z",
                "2026-08-25T01:02:03.123456789Z",
            ),
            ("2024-02-29T23:59:59.9Z", "2024-02-29T23:59:59.900000000Z"),
        ];

        for (raw_created, canonical_created) in variants {
            let mut raw = dynamic_raw_info();
            raw.created = raw_created.to_string();
            let bytes = serde_json::to_vec(&raw)?;
            let inspected = inspect_raw_stream_info_unbound(&bytes, &expected)?;
            let snapshot = inspected.typed_snapshot();
            assert_eq!(snapshot.created_at(), canonical_created);
            assert_eq!(snapshot.canonical_raw_stream_info(), bytes);
            assert!(
                snapshot
                    .canonical_raw_stream_info()
                    .windows(raw_created.len())
                    .any(|window| window == raw_created.as_bytes()),
                "the complete evidence must retain the original NATS created spelling"
            );

            let mut expected_digest = Sha256::new();
            expected_digest.update(RAW_STREAM_INFO_DOMAIN);
            expected_digest.update((bytes.len() as u64).to_be_bytes());
            expected_digest.update(&bytes);
            assert_eq!(
                snapshot.raw_stream_info_digest(),
                hex::encode(expected_digest.finalize())
            );
        }

        let mut short = dynamic_raw_info();
        short.created = "2026-08-25T01:02:03.4Z".to_string();
        let mut padded = short.clone();
        padded.created = "2026-08-25T01:02:03.400000000Z".to_string();
        let short_bytes = serde_json::to_vec(&short)?;
        let padded_bytes = serde_json::to_vec(&padded)?;
        let short_snapshot =
            inspect_raw_stream_info_unbound(&short_bytes, &expected)?.typed_snapshot();
        let padded_snapshot =
            inspect_raw_stream_info_unbound(&padded_bytes, &expected)?.typed_snapshot();
        assert_eq!(short_snapshot.created_at(), padded_snapshot.created_at());
        assert_ne!(short_snapshot.canonical_raw_stream_info(), padded_bytes);
        assert_ne!(
            short_snapshot.raw_stream_info_digest(),
            padded_snapshot.raw_stream_info_digest(),
            "equivalent stable timestamps still have distinct complete raw evidence"
        );

        let mut changed = padded;
        changed.created = "2026-08-25T01:02:03.400000001Z".to_string();
        let changed_bytes = serde_json::to_vec(&changed)?;
        let changed_snapshot =
            inspect_raw_stream_info_unbound(&changed_bytes, &expected)?.typed_snapshot();
        assert_ne!(padded_snapshot.created_at(), changed_snapshot.created_at());
        Ok(())
    }

    #[test]
    fn typed_snapshot_rejects_non_rfc3339nano_created_forms()
    -> Result<(), Box<dyn std::error::Error>> {
        let expected = expected_dynamic()?;
        for invalid in [
            "2026-08-25T01:02:03.Z",
            "2026-08-25T01:02:03.1234567890Z",
            "2026-08-25T01:02:03.aZ",
            "2026-08-25T01:02:03.000000000z",
            "2026-08-25T01:02:03.000000000+00:00",
            "2026-13-25T01:02:03Z",
            "2026-08-00T01:02:03Z",
            "2026-02-29T01:02:03Z",
            "2024-02-30T01:02:03Z",
            "2026-08-25T24:02:03Z",
            "2026-08-25T01:60:03Z",
            "2026-08-25T01:02:60Z",
        ] {
            let mut raw = dynamic_raw_info();
            raw.created = invalid.to_string();
            let bytes = serde_json::to_vec(&raw)?;
            assert_eq!(
                inspect_raw_stream_info_unbound(&bytes, &expected),
                Err(RawConfigurationError::NonCanonicalRawConfiguration),
                "invalid created spelling survived: {invalid}"
            );
        }
        Ok(())
    }
}
