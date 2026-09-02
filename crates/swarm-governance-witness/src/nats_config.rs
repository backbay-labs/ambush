use std::collections::BTreeMap;

use swarm_governance::witness_engine::store::{
    WitnessBucketConfigurationV1, WitnessCompressionV1, WitnessDiscardPolicyV1,
    WitnessPersistenceSemanticsV1, WitnessRetentionPolicyV1, WitnessStorageTypeV1,
};

pub(crate) const NATS_SERVER_VERSION: &str = "2.11.17";
pub(crate) const NATS_IMAGE_INDEX_DIGEST: &str =
    "sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00";
pub(crate) const DESCRIPTION: &str = "Phase 285 external governance witness";
pub(crate) const DUPLICATE_WINDOW_NANOS: u64 = 120_000_000_000;

pub(crate) fn expected_server_metadata() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("_nats.level".to_string(), "1".to_string()),
        ("_nats.req.level".to_string(), "0".to_string()),
        ("_nats.ver".to_string(), NATS_SERVER_VERSION.to_string()),
    ])
}

pub(crate) fn projected_configuration(
    bucket_name: &str,
    required_bucket_bytes: i64,
    max_kv_value_bytes: i32,
    configured_replica_count: u32,
) -> WitnessBucketConfigurationV1 {
    WitnessBucketConfigurationV1 {
        schema_version: 1,
        nats_server_version: NATS_SERVER_VERSION.to_string(),
        nats_server_image_index_digest: NATS_IMAGE_INDEX_DIGEST.to_string(),
        stream_name: format!("KV_{bucket_name}"),
        description: DESCRIPTION.to_string(),
        subjects: vec![format!("$KV.{bucket_name}.>")],
        retention: WitnessRetentionPolicyV1::Limits,
        discard: WitnessDiscardPolicyV1::New,
        discard_new_per_subject: false,
        storage: WitnessStorageTypeV1::File,
        max_messages: -1,
        max_bytes: required_bucket_bytes,
        max_messages_per_subject: 1,
        max_age_nanos: 0,
        max_consumers: -1,
        max_message_size: max_kv_value_bytes,
        num_replicas: configured_replica_count,
        no_ack: false,
        duplicate_window_nanos: DUPLICATE_WINDOW_NANOS,
        persistence_semantics: WitnessPersistenceSemanticsV1::Nats21117SynchronousOnly,
        persist_mode_wire_key_present: false,
        sealed: false,
        allow_rollup: false,
        deny_delete: true,
        deny_purge: true,
        allow_direct: false,
        mirror_direct: false,
        allow_message_ttl: false,
        allow_atomic_publish: false,
        allow_message_schedules: false,
        allow_message_counter: false,
        template_owner: String::new(),
        application_metadata: BTreeMap::new(),
        server_metadata: expected_server_metadata(),
        republish_present: false,
        mirror_present: false,
        sources_count: 0,
        subject_transform_present: false,
        compression: WitnessCompressionV1::Disabled,
        consumer_limits_present: false,
        first_sequence: None,
        placement_present: false,
        pause_until: None,
        subject_delete_marker_ttl_nanos: None,
    }
}
