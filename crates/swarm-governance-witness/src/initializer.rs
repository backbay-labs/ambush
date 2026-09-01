use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use async_nats::header::{
    NATS_EXPECTED_LAST_SUBJECT_SEQUENCE, NATS_EXPECTED_STREAM, NATS_MESSAGE_ID, NATS_MESSAGE_TTL,
};
use async_nats::jetstream::response::Response;
use async_nats::jetstream::stream::{LastRawMessageErrorKind, Stream};
use async_nats::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::json;
use swarm_crypto::Ed25519Signer;
use swarm_governance::persistence_protocol::{
    MAX_PROTOCOL_STRING_BYTES, PROTOCOL_SCHEMA_VERSION, canonical_wire_bytes,
};
use swarm_governance::witness_engine::store::{
    WitnessAdmissionSetV1, WitnessBucketConfigurationV1, WitnessBucketEpochV1,
    WitnessBucketManifestPhaseV1, WitnessBucketManifestV1, WitnessStoreDeploymentInputsV1,
    WitnessStoreReadyResultV1, WitnessStreamInitializationRecordV1, WitnessStreamInitializationV1,
};
use swarm_governance::witness_engine::{WitnessStoreEnvelopeV1, witness_stream_key};
use tokio::time::{Duration, timeout};

use crate::NatsWitnessStore;
use crate::raw_config::{
    Nats21117ExpectedConfigurationV1, Nats21117RawStreamInfoV1, inspect_raw_stream_info_unbound,
};
use crate::runtime_client::{
    RoleTransportConfigV1, connect_exact_role, copy_zeroizing_utf8_secret,
};
use crate::secure_file::{StableFilePolicyV1, read_stable_file};

const MAX_INITIALIZER_CONFIG_BYTES: usize = 2_097_152;
const MAX_INITIALIZER_SECRET_BYTES: usize = 4_096;
const INITIALIZER_DEADLINE_MILLIS: u64 = 10_000;
const NATS_STREAM_NOT_FOUND_ERROR_CODE: u64 = 10_059;
const MANIFEST_KEY: &str = "__witness_bucket_manifest";
const KV_OPERATION: &str = "KV-Operation";
const KV_PUT: &str = "PUT";
const KV_ROLLUP: &str = "Nats-Rollup";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreInitializerProcessConfigV1 {
    pub nats_url: String,
    pub nats_credentials_path: String,
    pub credential_invocation_token: String,
    pub tls_ca_path: String,
    pub tls_server_name: String,
    pub witness_key_path: String,
    pub bucket_configuration: WitnessBucketConfigurationV1,
    pub bucket_epoch: WitnessBucketEpochV1,
    pub admission_set: WitnessAdmissionSetV1,
    pub deployment_inputs: WitnessStoreDeploymentInputsV1,
    pub reported_server_version: String,
    pub resolved_server_image_index_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreInitializerErrorV1 {
    #[error("witness-store initializer configuration is invalid")]
    Configuration,
    #[error("witness-store initializer authentication failed")]
    Authentication,
    #[error("witness-store initializer found an existing uninitialized store")]
    ExistingUninitializedStore,
    #[error("witness-store initializer found corrupt or conflicting durable state")]
    Corrupt,
    #[error("witness-store initializer transport is unavailable")]
    Unavailable,
    #[error("witness-store initializer publish outcome is ambiguous")]
    Ambiguous,
}

#[derive(Debug)]
struct RawEntryV1 {
    sequence: u64,
    expected_previous_revision: u64,
    payload: Vec<u8>,
}

impl StoreInitializerProcessConfigV1 {
    fn validate(&self) -> Result<Nats21117ExpectedConfigurationV1, StoreInitializerErrorV1> {
        for value in [
            self.nats_url.as_str(),
            self.nats_credentials_path.as_str(),
            self.credential_invocation_token.as_str(),
            self.tls_ca_path.as_str(),
            self.tls_server_name.as_str(),
            self.witness_key_path.as_str(),
            self.reported_server_version.as_str(),
            self.resolved_server_image_index_digest.as_str(),
        ] {
            if value.is_empty()
                || value.len() > MAX_PROTOCOL_STRING_BYTES
                || value.as_bytes().contains(&0)
            {
                return Err(StoreInitializerErrorV1::Configuration);
            }
        }
        self.bucket_configuration
            .validate()
            .map_err(|_| StoreInitializerErrorV1::Configuration)?;
        self.bucket_epoch
            .validate()
            .map_err(|_| StoreInitializerErrorV1::Configuration)?;
        self.admission_set
            .validate()
            .map_err(|_| StoreInitializerErrorV1::Configuration)?;
        self.deployment_inputs
            .validate()
            .map_err(|_| StoreInitializerErrorV1::Configuration)?;
        if self.bucket_epoch.stream_name != self.bucket_configuration.stream_name
            || self.bucket_epoch.bucket_configuration_digest
                != self
                    .bucket_configuration
                    .digest()
                    .map_err(|_| StoreInitializerErrorV1::Configuration)?
            || self.bucket_epoch.admission_set_digest != self.admission_set.admission_set_digest
            || self.admission_set.entries.len()
                > usize::try_from(self.deployment_inputs.maximum_admitted_streams)
                    .map_err(|_| StoreInitializerErrorV1::Configuration)?
            || self.admission_set.entries.iter().any(|entry| {
                entry.witness_identity != self.bucket_epoch.witness_identity
                    || entry.witness_key_id != self.bucket_epoch.witness_key_id
            })
        {
            return Err(StoreInitializerErrorV1::Configuration);
        }
        Nats21117ExpectedConfigurationV1::from_validated_deployment(
            &self.bucket_configuration,
            &self.deployment_inputs,
            &self.reported_server_version,
            &self.resolved_server_image_index_digest,
        )
        .map_err(|_| StoreInitializerErrorV1::Configuration)
    }
}

pub fn load_store_initializer_process_config(
    path: impl AsRef<Path>,
) -> Result<StoreInitializerProcessConfigV1, StoreInitializerErrorV1> {
    let bytes = read_stable_file(
        path,
        MAX_INITIALIZER_CONFIG_BYTES,
        StableFilePolicyV1::Private,
    )
    .map_err(|_| StoreInitializerErrorV1::Configuration)?;
    let config: StoreInitializerProcessConfigV1 =
        serde_json::from_slice(&bytes).map_err(|_| StoreInitializerErrorV1::Configuration)?;
    if serde_json::to_vec(&config)
        .map_err(|_| StoreInitializerErrorV1::Configuration)?
        .as_slice()
        != bytes.as_slice()
    {
        return Err(StoreInitializerErrorV1::Configuration);
    }
    config.validate()?;
    Ok(config)
}

pub async fn initialize_store(
    config: StoreInitializerProcessConfigV1,
) -> Result<WitnessStoreReadyResultV1, StoreInitializerErrorV1> {
    let expected = config.validate()?;
    let secret_bytes = read_stable_file(
        &config.witness_key_path,
        MAX_INITIALIZER_SECRET_BYTES,
        StableFilePolicyV1::Private,
    )
    .map_err(|_| StoreInitializerErrorV1::Configuration)?;
    let secret = copy_zeroizing_utf8_secret(&secret_bytes)
        .map_err(|_| StoreInitializerErrorV1::Configuration)?;
    if secret.is_empty() || secret.contains(['\r', '\n']) {
        return Err(StoreInitializerErrorV1::Configuration);
    }
    let signer = Ed25519Signer::from_secret_material(secret.as_str());
    if signer.key_id() != config.bucket_epoch.witness_key_id {
        return Err(StoreInitializerErrorV1::Configuration);
    }

    let connection = connect_exact_role(RoleTransportConfigV1 {
        nats_url: &config.nats_url,
        credentials_path: &config.nats_credentials_path,
        invocation_token: &config.credential_invocation_token,
        tls_ca_path: &config.tls_ca_path,
        tls_server_name: &config.tls_server_name,
        role: "init",
        subscription_capacity: 64,
        client_capacity: 64,
        read_buffer_capacity: 8_192,
        deadline_millis: INITIALIZER_DEADLINE_MILLIS,
    })
    .await
    .map_err(|_| StoreInitializerErrorV1::Authentication)?;
    let client = connection.client;
    let _lifecycle_events = connection.lifecycle_events;
    let context = async_nats::jetstream::new(client.clone());

    let initial_inspection = inspect_stream(&context, &config, &expected).await?;
    let (created_here, inspected) = match initial_inspection {
        Some(inspected) => (false, inspected),
        None => {
            create_stream(&context, &config).await?;
            let inspected = inspect_stream(&context, &config, &expected)
                .await?
                .ok_or(StoreInitializerErrorV1::Unavailable)?;
            (true, inspected)
        }
    };
    let stream = context
        .get_stream_no_info(&config.bucket_configuration.stream_name)
        .await
        .map_err(|_| StoreInitializerErrorV1::Unavailable)?;
    let bucket_name = config
        .bucket_configuration
        .stream_name
        .strip_prefix("KV_")
        .filter(|name| !name.is_empty())
        .ok_or(StoreInitializerErrorV1::Configuration)?;
    let manifest_subject = fixed_subject(bucket_name, MANIFEST_KEY);
    let expected_stream_keys = expected_stream_keys(&config.admission_set)?;

    let existing_manifest = read_raw_entry(&stream, &manifest_subject, &config).await?;
    if existing_manifest.is_none() && !created_here {
        return Err(StoreInitializerErrorV1::ExistingUninitializedStore);
    }
    let (mut manifest, mut manifest_revision) = match existing_manifest {
        Some(raw) => {
            let manifest: WitnessBucketManifestV1 = serde_json::from_slice(&raw.payload)
                .map_err(|_| StoreInitializerErrorV1::Corrupt)?;
            if canonical_wire_bytes(&manifest).map_err(|_| StoreInitializerErrorV1::Corrupt)?
                != raw.payload
            {
                return Err(StoreInitializerErrorV1::Corrupt);
            }
            validate_manifest_identity(&manifest, &config, &expected_stream_keys)?;
            (manifest, raw.sequence)
        }
        None => {
            let manifest = signed_manifest(
                &config,
                expected_stream_keys.clone(),
                BTreeMap::new(),
                WitnessBucketManifestPhaseV1::Initializing,
                &signer,
            )?;
            let revision = publish_put(
                &context,
                &manifest_subject,
                &config.bucket_configuration.stream_name,
                0,
                canonical_wire_bytes(&manifest)
                    .map_err(|_| StoreInitializerErrorV1::Configuration)?,
            )
            .await?;
            (manifest, revision)
        }
    };

    if manifest.phase == WitnessBucketManifestPhaseV1::Ready
        && manifest.initialized_streams.len() != expected_stream_keys.len()
    {
        return Err(StoreInitializerErrorV1::Corrupt);
    }

    for admission in &config.admission_set.entries {
        let stream_key = witness_stream_key(&admission.stream_id)
            .map_err(|_| StoreInitializerErrorV1::Configuration)?;
        let (empty, record) = empty_envelope_and_record(admission, &config.bucket_epoch, &signer)?;
        let empty_bytes = empty
            .canonical_bytes()
            .map_err(|_| StoreInitializerErrorV1::Configuration)?;
        let subject = fixed_subject(bucket_name, &stream_key);
        let current = read_raw_entry(&stream, &subject, &config).await?;
        match manifest.initialized_streams.get(&stream_key) {
            Some(existing) => {
                if existing != &record
                    || current.as_ref().is_none_or(|raw| {
                        raw.expected_previous_revision != 0 || raw.payload != empty_bytes
                    })
                {
                    return Err(StoreInitializerErrorV1::Corrupt);
                }
            }
            None => {
                if manifest.phase == WitnessBucketManifestPhaseV1::Ready {
                    return Err(StoreInitializerErrorV1::Corrupt);
                }
                match current {
                    Some(raw)
                        if raw.expected_previous_revision == 0 && raw.payload == empty_bytes => {}
                    Some(_) => return Err(StoreInitializerErrorV1::Corrupt),
                    None => {
                        publish_put(
                            &context,
                            &subject,
                            &config.bucket_configuration.stream_name,
                            0,
                            empty_bytes,
                        )
                        .await?;
                    }
                }
                manifest.initialized_streams.insert(stream_key, record);
                manifest = signed_manifest(
                    &config,
                    expected_stream_keys.clone(),
                    manifest.initialized_streams,
                    WitnessBucketManifestPhaseV1::Initializing,
                    &signer,
                )?;
                manifest_revision = publish_put(
                    &context,
                    &manifest_subject,
                    &config.bucket_configuration.stream_name,
                    manifest_revision,
                    canonical_wire_bytes(&manifest)
                        .map_err(|_| StoreInitializerErrorV1::Configuration)?,
                )
                .await?;
            }
        }
    }

    if manifest.phase == WitnessBucketManifestPhaseV1::Initializing {
        manifest = signed_manifest(
            &config,
            expected_stream_keys,
            manifest.initialized_streams,
            WitnessBucketManifestPhaseV1::Ready,
            &signer,
        )?;
        publish_put(
            &context,
            &manifest_subject,
            &config.bucket_configuration.stream_name,
            manifest_revision,
            canonical_wire_bytes(&manifest).map_err(|_| StoreInitializerErrorV1::Configuration)?,
        )
        .await?;
    }

    let mut anchor = swarm_governance::witness_engine::store::WitnessBucketAnchorV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        epoch: config.bucket_epoch.clone(),
        nats_stream_created_at: inspected.canonical_created_at().to_string(),
        raw_stream_configuration_digest: inspected.raw_stream_configuration_digest().to_string(),
        ready_manifest_digest: manifest
            .digest()
            .map_err(|_| StoreInitializerErrorV1::Configuration)?,
        witness_key_id: config.bucket_epoch.witness_key_id.clone(),
        signature: signer.sign(&[]),
    };
    anchor.signature = signer.sign(
        &anchor
            .signing_bytes()
            .map_err(|_| StoreInitializerErrorV1::Configuration)?,
    );
    let ready = WitnessStoreReadyResultV1::new(
        inspected.canonical_created_at().to_string(),
        config.bucket_configuration.clone(),
        config.bucket_epoch.clone(),
        anchor,
        config.admission_set.clone(),
        manifest,
        config.deployment_inputs.clone(),
    )
    .map_err(|_| StoreInitializerErrorV1::Configuration)?;
    NatsWitnessStore::open(
        context,
        ready.clone(),
        &config.reported_server_version,
        &config.resolved_server_image_index_digest,
    )
    .await
    .map_err(|_| StoreInitializerErrorV1::Corrupt)?;
    timeout(
        Duration::from_millis(INITIALIZER_DEADLINE_MILLIS),
        client.drain(),
    )
    .await
    .map_err(|_| StoreInitializerErrorV1::Unavailable)?
    .map_err(|_| StoreInitializerErrorV1::Unavailable)?;
    Ok(ready)
}

async fn create_stream(
    context: &async_nats::jetstream::Context,
    config: &StoreInitializerProcessConfigV1,
) -> Result<(), StoreInitializerErrorV1> {
    let projected = &config.bucket_configuration;
    let payload = json!({
        "name": projected.stream_name,
        "description": projected.description,
        "subjects": projected.subjects,
        "retention": "limits",
        "max_consumers": -1,
        "max_msgs": -1,
        "max_bytes": projected.max_bytes,
        "max_age": 0,
        "max_msgs_per_subject": 1,
        "max_msg_size": projected.max_message_size,
        "discard": "new",
        "storage": "file",
        "num_replicas": projected.num_replicas,
        "duplicate_window": projected.duplicate_window_nanos,
        "compression": "none",
        "allow_direct": false,
        "mirror_direct": false,
        "sealed": false,
        "deny_delete": true,
        "deny_purge": true,
        "allow_rollup_hdrs": false,
        "consumer_limits": {},
        "allow_msg_ttl": false,
        "metadata": projected.server_metadata,
    });
    let response: Response<serde_json::Value> = timeout(
        Duration::from_millis(INITIALIZER_DEADLINE_MILLIS),
        context.request(format!("STREAM.CREATE.{}", projected.stream_name), &payload),
    )
    .await
    .map_err(|_| StoreInitializerErrorV1::Unavailable)?
    .map_err(|_| StoreInitializerErrorV1::Unavailable)?;
    match response {
        Response::Ok(_) => Ok(()),
        Response::Err { .. } => Err(StoreInitializerErrorV1::Corrupt),
    }
}

async fn inspect_stream(
    context: &async_nats::jetstream::Context,
    config: &StoreInitializerProcessConfigV1,
    expected: &Nats21117ExpectedConfigurationV1,
) -> Result<Option<crate::raw_config::InspectedRawConfigurationV1>, StoreInitializerErrorV1> {
    let response: Response<Nats21117RawStreamInfoV1> = timeout(
        Duration::from_millis(INITIALIZER_DEADLINE_MILLIS),
        context.request(
            format!("STREAM.INFO.{}", config.bucket_configuration.stream_name),
            &json!({}),
        ),
    )
    .await
    .map_err(|_| StoreInitializerErrorV1::Unavailable)?
    .map_err(|_| StoreInitializerErrorV1::Unavailable)?;
    let info = match response {
        Response::Ok(info) => info,
        Response::Err { error } if error.error_code().0 == NATS_STREAM_NOT_FOUND_ERROR_CODE => {
            return Ok(None);
        }
        Response::Err { .. } => return Err(StoreInitializerErrorV1::Unavailable),
    };
    let bytes = serde_json::to_vec(&info).map_err(|_| StoreInitializerErrorV1::Corrupt)?;
    let inspected = inspect_raw_stream_info_unbound(&bytes, expected)
        .map_err(|_| StoreInitializerErrorV1::Corrupt)?;
    if inspected.projected_configuration() != &config.bucket_configuration
        || inspected
            .projected_configuration()
            .digest()
            .map_err(|_| StoreInitializerErrorV1::Corrupt)?
            != config.bucket_epoch.bucket_configuration_digest
    {
        return Err(StoreInitializerErrorV1::Corrupt);
    }
    Ok(Some(inspected))
}

fn expected_stream_keys(
    admission_set: &WitnessAdmissionSetV1,
) -> Result<Vec<String>, StoreInitializerErrorV1> {
    let mut keys = admission_set
        .entries
        .iter()
        .map(|entry| {
            witness_stream_key(&entry.stream_id).map_err(|_| StoreInitializerErrorV1::Configuration)
        })
        .collect::<Result<Vec<_>, _>>()?;
    keys.sort();
    if keys.iter().collect::<BTreeSet<_>>().len() != keys.len() {
        return Err(StoreInitializerErrorV1::Configuration);
    }
    Ok(keys)
}

fn signed_manifest(
    config: &StoreInitializerProcessConfigV1,
    stream_keys: Vec<String>,
    initialized_streams: BTreeMap<String, WitnessStreamInitializationRecordV1>,
    phase: WitnessBucketManifestPhaseV1,
    signer: &Ed25519Signer,
) -> Result<WitnessBucketManifestV1, StoreInitializerErrorV1> {
    let mut manifest = WitnessBucketManifestV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        bucket_epoch_digest: config
            .bucket_epoch
            .digest()
            .map_err(|_| StoreInitializerErrorV1::Configuration)?,
        bucket_configuration_digest: config.bucket_epoch.bucket_configuration_digest.clone(),
        admission_set_digest: config.admission_set.admission_set_digest.clone(),
        stream_keys,
        initialized_streams,
        phase,
        witness_identity: config.bucket_epoch.witness_identity.clone(),
        witness_key_id: config.bucket_epoch.witness_key_id.clone(),
        signature: signer.sign(&[]),
    };
    manifest.signature = signer.sign(
        &manifest
            .signing_bytes()
            .map_err(|_| StoreInitializerErrorV1::Configuration)?,
    );
    manifest
        .validate()
        .map_err(|_| StoreInitializerErrorV1::Configuration)?;
    Ok(manifest)
}

fn validate_manifest_identity(
    manifest: &WitnessBucketManifestV1,
    config: &StoreInitializerProcessConfigV1,
    expected_stream_keys: &[String],
) -> Result<(), StoreInitializerErrorV1> {
    manifest
        .validate()
        .map_err(|_| StoreInitializerErrorV1::Corrupt)?;
    if manifest.bucket_epoch_digest
        != config
            .bucket_epoch
            .digest()
            .map_err(|_| StoreInitializerErrorV1::Configuration)?
        || manifest.bucket_configuration_digest != config.bucket_epoch.bucket_configuration_digest
        || manifest.admission_set_digest != config.admission_set.admission_set_digest
        || manifest.witness_identity != config.bucket_epoch.witness_identity
        || manifest.witness_key_id != config.bucket_epoch.witness_key_id
        || manifest.stream_keys != expected_stream_keys
        || manifest
            .initialized_streams
            .keys()
            .any(|key| expected_stream_keys.binary_search(key).is_err())
    {
        return Err(StoreInitializerErrorV1::Corrupt);
    }
    Ok(())
}

fn empty_envelope_and_record(
    admission: &swarm_governance::witness_engine::store::WitnessAdmissionEntryV1,
    epoch: &WitnessBucketEpochV1,
    signer: &Ed25519Signer,
) -> Result<(WitnessStoreEnvelopeV1, WitnessStreamInitializationRecordV1), StoreInitializerErrorV1>
{
    let epoch_digest = epoch
        .digest()
        .map_err(|_| StoreInitializerErrorV1::Configuration)?;
    let initialization_digest = WitnessStreamInitializationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        bucket_epoch_digest: epoch_digest.clone(),
        admission_digest: admission.admission_digest.clone(),
        stream_id: admission.stream_id.clone(),
        witness_identity: admission.witness_identity.clone(),
        witness_key_id: admission.witness_key_id.clone(),
    }
    .digest()
    .map_err(|_| StoreInitializerErrorV1::Configuration)?;
    let mut empty = WitnessStoreEnvelopeV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        admission_digest: admission.admission_digest.clone(),
        bucket_epoch_digest: epoch_digest,
        stream_initialization_digest: initialization_digest.clone(),
        stream_id: admission.stream_id.clone(),
        witness_identity: admission.witness_identity.clone(),
        witness_key_id: admission.witness_key_id.clone(),
        session: None,
        last_session_rotation: None,
        current: None,
        predecessor: None,
        prepared: None,
        genesis_abort: None,
        store_generation: 0,
        signature: signer.sign(&[]),
    };
    empty.signature = signer.sign(
        &empty
            .signing_bytes()
            .map_err(|_| StoreInitializerErrorV1::Configuration)?,
    );
    empty
        .validate()
        .map_err(|_| StoreInitializerErrorV1::Configuration)?;
    let record = WitnessStreamInitializationRecordV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_initialization_digest: initialization_digest,
        empty_envelope_digest: empty
            .signed_envelope_digest()
            .map_err(|_| StoreInitializerErrorV1::Configuration)?,
    };
    record
        .validate()
        .map_err(|_| StoreInitializerErrorV1::Configuration)?;
    Ok((empty, record))
}

async fn read_raw_entry(
    stream: &Stream<()>,
    subject: &str,
    config: &StoreInitializerProcessConfigV1,
) -> Result<Option<RawEntryV1>, StoreInitializerErrorV1> {
    let message = match timeout(
        Duration::from_millis(INITIALIZER_DEADLINE_MILLIS),
        stream.get_last_raw_message_by_subject(subject),
    )
    .await
    .map_err(|_| StoreInitializerErrorV1::Unavailable)?
    {
        Ok(message) => message,
        Err(error) if error.kind() == LastRawMessageErrorKind::NoMessageFound => return Ok(None),
        Err(_) => return Err(StoreInitializerErrorV1::Unavailable),
    };
    if message.subject.as_ref() != subject || message.sequence == 0 || message.headers.len() != 3 {
        return Err(StoreInitializerErrorV1::Corrupt);
    }
    let operation = message.headers.get(KV_OPERATION).map(HeaderValue::as_str);
    let expected_stream = message
        .headers
        .get(NATS_EXPECTED_STREAM)
        .map(HeaderValue::as_str);
    let expected_previous_revision = message
        .headers
        .get(NATS_EXPECTED_LAST_SUBJECT_SEQUENCE)
        .map(HeaderValue::as_str)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(StoreInitializerErrorV1::Corrupt)?;
    if operation != Some(KV_PUT)
        || expected_stream != Some(config.bucket_configuration.stream_name.as_str())
        || expected_previous_revision >= message.sequence
        || message.headers.get(KV_ROLLUP).is_some()
        || message.headers.get(NATS_MESSAGE_TTL).is_some()
        || message.headers.get(NATS_MESSAGE_ID).is_some()
    {
        return Err(StoreInitializerErrorV1::Corrupt);
    }
    Ok(Some(RawEntryV1 {
        sequence: message.sequence,
        expected_previous_revision,
        payload: message.payload.to_vec(),
    }))
}

async fn publish_put(
    context: &async_nats::jetstream::Context,
    subject: &str,
    stream_name: &str,
    expected_previous_revision: u64,
    payload: Vec<u8>,
) -> Result<u64, StoreInitializerErrorV1> {
    let mut headers = HeaderMap::new();
    headers.insert(KV_OPERATION, KV_PUT);
    headers.insert(NATS_EXPECTED_STREAM, HeaderValue::from(stream_name));
    headers.insert(
        NATS_EXPECTED_LAST_SUBJECT_SEQUENCE,
        HeaderValue::from(expected_previous_revision),
    );
    let acknowledgement = timeout(Duration::from_millis(INITIALIZER_DEADLINE_MILLIS), async {
        context
            .publish_with_headers(subject.to_string(), headers, payload.into())
            .await
            .map_err(|_| StoreInitializerErrorV1::Unavailable)?
            .await
            .map_err(|_| StoreInitializerErrorV1::Ambiguous)
    })
    .await
    .map_err(|_| StoreInitializerErrorV1::Ambiguous)??;
    if acknowledgement.stream != stream_name
        || acknowledgement.duplicate
        || acknowledgement.sequence <= expected_previous_revision
    {
        return Err(StoreInitializerErrorV1::Ambiguous);
    }
    Ok(acknowledgement.sequence)
}

fn fixed_subject(bucket_name: &str, key: &str) -> String {
    format!("$KV.{bucket_name}.{key}")
}
