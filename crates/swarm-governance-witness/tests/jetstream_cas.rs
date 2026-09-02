use async_nats::header::{NATS_EXPECTED_LAST_SUBJECT_SEQUENCE, NATS_EXPECTED_STREAM};
use async_nats::jetstream::response::Response;
use async_nats::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::{env, error::Error, io};
use swarm_crypto::Ed25519Signer;
use swarm_governance::persistence_protocol::*;
use swarm_governance::witness_engine::store::{
    WitnessAdmissionEntryV1, WitnessAdmissionSetV1, WitnessAtomicStore, WitnessBucketAnchorV1,
    WitnessBucketConfigurationV1, WitnessBucketEpochV1, WitnessBucketManifestPhaseV1,
    WitnessBucketManifestV1, WitnessCompressionV1, WitnessDiscardPolicyV1,
    WitnessPersistenceSemanticsV1, WitnessRetentionPolicyV1, WitnessStorageTypeV1,
    WitnessStoreCasResultV1, WitnessStoreDeploymentInputsV1, WitnessStoreErrorV1,
    WitnessStreamInitializationRecordV1, WitnessStreamInitializationV1, validate_cas_transition,
    validate_read_entry,
};
use swarm_governance::witness_engine::{WitnessStoreEnvelopeV1, witness_stream_key};
use swarm_governance::witness_service::WitnessAdmissionRecordV1;
use swarm_governance_witness::NatsWitnessStore;
use swarm_governance_witness::raw_config::{
    Nats21117ExpectedConfigurationV1, RawConfigurationError, inspect_raw_stream_info,
};

const GOLDEN_CONFIG: &str = r#"{
  "name":"KV_phase285_witness",
  "description":"Phase 285 external governance witness",
  "subjects":["$KV.phase285_witness.>"],
  "retention":"limits",
  "max_consumers":-1,
  "max_msgs":-1,
  "max_bytes":1048576,
  "max_age":0,
  "max_msgs_per_subject":1,
  "max_msg_size":4096,
  "discard":"new",
  "storage":"file",
  "num_replicas":1,
  "duplicate_window":120000000000,
  "compression":"none",
  "allow_direct":false,
  "mirror_direct":false,
  "sealed":false,
  "deny_delete":true,
  "deny_purge":true,
  "allow_rollup_hdrs":false,
  "consumer_limits":{},
  "allow_msg_ttl":false,
  "metadata":{"_nats.level":"1","_nats.req.level":"0","_nats.ver":"2.11.17"}
}"#;

const INNER_LEDGER_PATH_ENV: &str = "PHASE285_WITNESS_INNER_LEDGER";
const INNER_LEDGER_REQUIRED_ENV: &str = "PHASE285_WITNESS_INNER_LEDGER_REQUIRED";
const INNER_LEDGER_DOMAIN: &[u8] = b"swarm.phase285.witness-inner-ledger-row.v1";

struct InnerLedger {
    case_name: &'static str,
    inner_ids: Vec<String>,
}

impl InnerLedger {
    fn new(case_name: &'static str) -> Self {
        Self {
            case_name,
            inner_ids: Vec::new(),
        }
    }

    fn passed(&mut self, inner_id: impl Into<String>) -> Result<(), io::Error> {
        let inner_id = inner_id.into();
        if inner_id.is_empty()
            || !inner_id.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
            || self.inner_ids.contains(&inner_id)
        {
            return Err(io::Error::other(
                "invalid or duplicate Phase 285 inner-ledger ID",
            ));
        }
        self.inner_ids.push(inner_id);
        Ok(())
    }

    fn finish(self) -> Result<(), io::Error> {
        let required = env::var(INNER_LEDGER_REQUIRED_ENV).as_deref() == Ok("1");
        let path = match env::var_os(INNER_LEDGER_PATH_ENV) {
            Some(path) => std::path::PathBuf::from(path),
            None if required => {
                return Err(io::Error::other(
                    "checker-required Phase 285 inner-ledger path is absent",
                ));
            }
            None => return Ok(()),
        };
        if !path.is_absolute() || path.exists() {
            return Err(io::Error::other(
                "Phase 285 inner ledger must be a fresh absolute path",
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("Phase 285 inner ledger has no parent"))?;
        if !parent.is_dir() {
            return Err(io::Error::other(
                "Phase 285 inner-ledger parent is not a directory",
            ));
        }
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        for inner_id in self.inner_ids {
            let canonical = format!(
                "{{\"case\":\"{}\",\"inner_id\":\"{}\",\"status\":\"passed\"}}",
                self.case_name, inner_id
            );
            let mut digest = Sha256::new();
            digest.update(INNER_LEDGER_DOMAIN);
            digest.update(
                u64::try_from(canonical.len())
                    .map_err(io::Error::other)?
                    .to_be_bytes(),
            );
            digest.update(canonical.as_bytes());
            writeln!(
                file,
                "{}\t{}\tpassed\t{}",
                self.case_name,
                inner_id,
                hex::encode(digest.finalize())
            )?;
        }
        file.flush()?;
        Ok(())
    }
}

fn expected() -> Nats21117ExpectedConfigurationV1 {
    Nats21117ExpectedConfigurationV1::phase285_conformance_fixture()
}

fn typed_bindings()
-> Result<(Ed25519Signer, WitnessBucketEpochV1, WitnessBucketAnchorV1), Box<dyn Error>> {
    let signer = Ed25519Signer::from_secret_material("phase285-plan03b-raw-binding");
    let epoch = WitnessBucketEpochV1 {
        schema_version: 1,
        bucket_generation: "1".repeat(64),
        nats_account: "PHASE285_EXPECTED".to_string(),
        stream_name: "KV_phase285_witness".to_string(),
        bucket_configuration_digest:
            "0e8398c6f3d43e7007ef4c073490ab655cb932ff7c78b2ad256256347a04a67b".to_string(),
        admission_set_digest: "2".repeat(64),
        witness_identity: "phase285-witness".to_string(),
        witness_key_id: signer.key_id().to_string(),
    };
    epoch.validate()?;
    let mut anchor = WitnessBucketAnchorV1 {
        schema_version: 1,
        epoch: epoch.clone(),
        nats_stream_created_at: "2026-08-25T00:00:00.000000000Z".to_string(),
        raw_stream_configuration_digest:
            "aaabfbcd39e5a19fae9f3ae03d5670e993a77900e4411d73b3911bbbefe3c224".to_string(),
        ready_manifest_digest: "3".repeat(64),
        witness_key_id: signer.key_id().to_string(),
        signature: signer.sign(&[]),
    };
    anchor.signature = signer.sign(&anchor.signing_bytes()?);
    anchor.validate()?;
    Ok((signer, epoch, anchor))
}

fn resign_anchor(
    anchor: &mut WitnessBucketAnchorV1,
    signer: &Ed25519Signer,
) -> Result<(), Box<dyn Error>> {
    anchor.signature = signer.sign(&anchor.signing_bytes()?);
    anchor.validate()?;
    Ok(())
}

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn fixture_protocol<T, E: std::fmt::Debug>(
    step: &'static str,
    result: Result<T, E>,
) -> Result<T, io::Error> {
    result.map_err(|error| io::Error::other(format!("{step}: {error:?}")))
}

const NATS_VERSION: &str = "2.11.17";
const NATS_IMAGE: &str = "sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00";
const RAW_CONFIG_DOMAIN: &[u8] = b"swarm.governance.nats-2.11.17-raw-stream-configuration.v1";
const MANIFEST_KEY: &str = "__witness_bucket_manifest";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawConfigDigestFixture {
    name: Value,
    description: Value,
    subjects: Value,
    retention: Value,
    max_consumers: Value,
    max_msgs: Value,
    max_bytes: Value,
    max_age: Value,
    max_msgs_per_subject: Value,
    max_msg_size: Value,
    discard: Value,
    storage: Value,
    num_replicas: Value,
    duplicate_window: Value,
    compression: Value,
    allow_direct: Value,
    mirror_direct: Value,
    sealed: Value,
    deny_delete: Value,
    deny_purge: Value,
    allow_rollup_hdrs: Value,
    consumer_limits: Value,
    allow_msg_ttl: Value,
    metadata: Value,
}

#[derive(Clone, Copy)]
enum InitialHeader {
    Put,
    Delete,
    Purge,
    Rollup,
    Unknown,
}

struct LiveFixture {
    context: async_nats::jetstream::Context,
    ready: swarm_governance::witness_engine::store::WitnessStoreReadyResultV1,
    stream_id: String,
    current: WitnessStoreEnvelopeV1,
    proposed: WitnessStoreEnvelopeV1,
    initial_revision: u64,
    subject: String,
}

fn info(config: Value) -> Result<Vec<u8>, serde_json::Error> {
    info_with_created(config, "2026-08-25T00:00:00.000000000Z")
}

fn info_with_created(config: Value, created: &str) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&json!({
        "type": "io.nats.jetstream.api.v1.stream_info_response",
        "total": 0,
        "offset": 0,
        "limit": 0,
        "config": config,
        "created": created,
        "state": {
            "messages": 0,
            "bytes": 0,
            "first_seq": 0,
            "first_ts": "0001-01-01T00:00:00Z",
            "last_seq": 0,
            "last_ts": "0001-01-01T00:00:00Z",
            "consumer_count": 0
        },
        "cluster": {"leader": "phase285-nats-harness"},
        "ts": "2026-08-25T00:00:00.000000000Z"
    }))
}

fn golden() -> Result<Value, serde_json::Error> {
    serde_json::from_str(GOLDEN_CONFIG)
}

fn roles() -> PublicationRoleIdentitiesV1 {
    PublicationRoleIdentitiesV1 {
        state_canonical: ArtifactIdentityV1 {
            device: 2,
            inode: 1,
        },
        state_staging: ArtifactIdentityV1 {
            device: 2,
            inode: 2,
        },
        checkpoint_canonical: ArtifactIdentityV1 {
            device: 2,
            inode: 3,
        },
        checkpoint_staging: ArtifactIdentityV1 {
            device: 2,
            inode: 4,
        },
        journal_primary: ArtifactIdentityV1 {
            device: 2,
            inode: 5,
        },
        journal_secondary: ArtifactIdentityV1 {
            device: 2,
            inode: 6,
        },
    }
}

fn binding(
    governance: &Ed25519Signer,
    witness: &Ed25519Signer,
    stream_id: &str,
) -> ProtocolResult<PublicationBindingV1> {
    let mut value = PublicationBindingV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: stream_id.to_string(),
        generation: "9".repeat(64),
        parent_directory: ArtifactIdentityV1 {
            device: 2,
            inode: 7,
        },
        pool_directory: ArtifactIdentityV1 {
            device: 2,
            inode: 8,
        },
        pool_lock: ArtifactIdentityV1 {
            device: 2,
            inode: 9,
        },
        binding_file: ArtifactIdentityV1 {
            device: 2,
            inode: 10,
        },
        authority_pair: AuthorityPairIdentityV1 {
            current: ArtifactIdentityV1 {
                device: 1,
                inode: 1,
            },
            legacy: ArtifactIdentityV1 {
                device: 1,
                inode: 1,
            },
        },
        publication_roles: roles(),
        cleanup_slot_count: FIXED_CLEANUP_SLOT_COUNT as u32,
        cleanup_slot_names: (0..FIXED_CLEANUP_SLOT_COUNT)
            .map(|index| format!("slot-{index:02}"))
            .collect(),
        cleanup_slot_identities: (11..(11 + FIXED_CLEANUP_SLOT_COUNT as u64))
            .map(|inode| ArtifactIdentityV1 { device: 2, inode })
            .collect(),
        limits: ProtocolLimitsV1::default(),
        signer_key_id: governance.key_id().to_string(),
        witness_key_id: witness.key_id().to_string(),
        witness_identity: "phase285-witness".to_string(),
        binding_digest: "0".repeat(64),
        binding_signature: governance.sign(&[]),
    };
    let signing_bytes = value.signing_bytes()?;
    value.binding_digest = value.computed_digest()?;
    value.binding_signature = governance.sign(&signing_bytes);
    value.validate()?;
    Ok(value)
}

fn session_rotation(
    governance: &Ed25519Signer,
    witness: &Ed25519Signer,
    binding: &PublicationBindingV1,
    envelope: &WitnessStoreEnvelopeV1,
) -> ProtocolResult<WitnessStoreEnvelopeV1> {
    let mut fence_request = WitnessSessionFenceRequestV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: binding.stream_id.clone(),
        authority_pair: binding.authority_pair,
        binding_generation: binding.generation.clone(),
        binding_digest: binding.binding_digest.clone(),
        signer_key_id: binding.signer_key_id.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        witness_identity: binding.witness_identity.clone(),
        requester_nonce: "3".repeat(64),
        signature: governance.sign(&[]),
    };
    fence_request.signature = governance.sign(&fence_request.signing_bytes()?);
    let mut fence = WitnessSessionStateFenceV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        request: fence_request,
        admission_digest: envelope.admission_digest.clone(),
        bucket_epoch_digest: envelope.bucket_epoch_digest.clone(),
        bucket_anchor_digest: "4".repeat(64),
        ready_manifest_digest: "5".repeat(64),
        store_state_digest: envelope.store_state_digest()?,
        current_session_generation: None,
        current_session_digest: None,
        current_head_digest: None,
        current_prepared_digest: None,
        witness_nonce: "6".repeat(64),
        witness_identity: binding.witness_identity.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        signature: witness.sign(&[]),
    };
    fence.signature = witness.sign(&fence.signing_bytes()?);
    fence.validate()?;
    let ephemeral = Ed25519Signer::from_secret_material("phase285-plan03b-ephemeral");
    let mut challenge = RecoveryChallengeV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: binding.stream_id.clone(),
        authority_pair: binding.authority_pair,
        binding_generation: binding.generation.clone(),
        binding_digest: binding.binding_digest.clone(),
        signer_key_id: binding.signer_key_id.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        witness_identity: binding.witness_identity.clone(),
        state_fence: fence.clone(),
        ephemeral_key_id: ephemeral.key_id().to_string(),
        nonce: "7".repeat(64),
        session_commitment: "8".repeat(64),
        signature: governance.sign(&[]),
    };
    challenge.signature = governance.sign(&challenge.signing_bytes()?);
    challenge.validate()?;
    let session = WitnessSessionV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: binding.stream_id.clone(),
        authority_pair: binding.authority_pair,
        binding_generation: binding.generation.clone(),
        binding_digest: binding.binding_digest.clone(),
        signer_key_id: binding.signer_key_id.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        ephemeral_key_id: ephemeral.key_id().to_string(),
        witness_identity: binding.witness_identity.clone(),
        session_generation: 1,
        session_commitment: challenge.session_commitment.clone(),
    };
    session.validate()?;
    let receipt = WitnessSessionRotationReceiptV1::for_establish(
        fence.request.request_digest()?,
        &challenge,
        session.clone(),
        None,
    )?;
    let mut proposed = envelope.clone();
    proposed.session = Some(session);
    proposed.last_session_rotation = Some(receipt);
    proposed.store_generation = 1;
    proposed.signature = witness.sign(&proposed.signing_bytes()?);
    proposed.validate()?;
    Ok(proposed)
}

fn bucket_configuration(
    bucket: &str,
    max_value_bytes: u64,
    max_bucket_bytes: u64,
) -> ProtocolResult<WitnessBucketConfigurationV1> {
    Ok(WitnessBucketConfigurationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        nats_server_version: NATS_VERSION.to_string(),
        nats_server_image_index_digest: NATS_IMAGE.to_string(),
        stream_name: format!("KV_{bucket}"),
        description: "Phase 285 external governance witness".to_string(),
        subjects: vec![format!("$KV.{bucket}.>")],
        retention: WitnessRetentionPolicyV1::Limits,
        discard: WitnessDiscardPolicyV1::New,
        discard_new_per_subject: false,
        storage: WitnessStorageTypeV1::File,
        max_messages: -1,
        max_bytes: i64::try_from(max_bucket_bytes)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?,
        max_messages_per_subject: 1,
        max_age_nanos: 0,
        max_consumers: -1,
        max_message_size: i32::try_from(max_value_bytes)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?,
        num_replicas: 1,
        no_ack: false,
        duplicate_window_nanos: 120_000_000_000,
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
        server_metadata: BTreeMap::from([
            ("_nats.level".to_string(), "1".to_string()),
            ("_nats.req.level".to_string(), "0".to_string()),
            ("_nats.ver".to_string(), NATS_VERSION.to_string()),
        ]),
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
    })
}

fn raw_configuration(bucket: &str, max_value: u64, max_bytes: u64) -> Value {
    json!({
        "name": format!("KV_{bucket}"),
        "description": "Phase 285 external governance witness",
        "subjects": [format!("$KV.{bucket}.>")],
        "retention": "limits",
        "max_consumers": -1,
        "max_msgs": -1,
        "max_bytes": max_bytes,
        "max_age": 0,
        "max_msgs_per_subject": 1,
        "max_msg_size": max_value,
        "discard": "new",
        "storage": "file",
        "num_replicas": 1,
        "duplicate_window": 120000000000_u64,
        "compression": "none",
        "allow_direct": false,
        "mirror_direct": false,
        "sealed": false,
        "deny_delete": true,
        "deny_purge": true,
        "allow_rollup_hdrs": false,
        "consumer_limits": {},
        "allow_msg_ttl": false,
        "metadata": {"_nats.level":"1","_nats.req.level":"0","_nats.ver":NATS_VERSION}
    })
}

async fn request_value(
    context: &async_nats::jetstream::Context,
    subject: String,
    payload: &Value,
) -> TestResult {
    let response: Response<Value> = context.request(subject, payload).await?;
    match response {
        Response::Ok(value) => {
            if value.is_null() {
                Err(io::Error::other("NATS returned a null response").into())
            } else {
                Ok(())
            }
        }
        Response::Err { error } => Err(io::Error::other(error.to_string()).into()),
    }
}

async fn raw_info(
    context: &async_nats::jetstream::Context,
    stream_name: &str,
) -> Result<Value, Box<dyn Error>> {
    let response: Response<Value> = context
        .request(format!("STREAM.INFO.{stream_name}"), &json!({}))
        .await?;
    match response {
        Response::Ok(value) => Ok(value),
        Response::Err { error } => Err(io::Error::other(error.to_string()).into()),
    }
}

fn raw_configuration_digest(raw_info: &Value) -> Result<String, Box<dyn Error>> {
    let config: RawConfigDigestFixture = serde_json::from_value(
        raw_info
            .get("config")
            .cloned()
            .ok_or_else(|| io::Error::other("raw info omitted config"))?,
    )?;
    let canonical = serde_json::to_vec(&config)?;
    let mut digest = Sha256::new();
    digest.update(RAW_CONFIG_DOMAIN);
    digest.update(u64::try_from(canonical.len())?.to_be_bytes());
    digest.update(canonical);
    Ok(hex::encode(digest.finalize()))
}

fn canonical_fixture_created_at(raw: &str) -> Result<String, io::Error> {
    let without_z = raw
        .strip_suffix('Z')
        .ok_or_else(|| io::Error::other("NATS created time is not UTC"))?;
    let (base, fraction) = without_z
        .split_once('.')
        .map_or((without_z, ""), |parts| parts);
    if base.len() != 19 || fraction.len() > 9 || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(io::Error::other(
            "NATS created time is not the pinned RFC3339Nano form",
        ));
    }
    Ok(format!("{base}.{fraction:0<9}Z"))
}

fn exact_put_headers(stream_name: &str, revision: u64, operation: InitialHeader) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let operation_value = match operation {
        InitialHeader::Put | InitialHeader::Rollup => "PUT",
        InitialHeader::Delete => "DEL",
        InitialHeader::Purge => "PURGE",
        InitialHeader::Unknown => "UNKNOWN",
    };
    headers.insert("KV-Operation", operation_value);
    headers.insert(NATS_EXPECTED_STREAM, HeaderValue::from(stream_name));
    headers.insert(
        NATS_EXPECTED_LAST_SUBJECT_SEQUENCE,
        HeaderValue::from(revision),
    );
    if matches!(operation, InitialHeader::Rollup) {
        headers.insert("Nats-Rollup", "sub");
    }
    headers
}

async fn publish_initial(
    context: &async_nats::jetstream::Context,
    subject: String,
    stream_name: &str,
    payload: Vec<u8>,
    operation: InitialHeader,
) -> Result<u64, Box<dyn Error>> {
    let ack = context
        .publish_with_headers(
            subject,
            exact_put_headers(stream_name, 0, operation),
            payload.into(),
        )
        .await?
        .await?;
    Ok(ack.sequence)
}

async fn live_fixture(
    bucket: &str,
    operation: InitialHeader,
) -> Result<LiveFixture, Box<dyn Error>> {
    let nats_url = env::var("NATS_URL")?;
    let server = nats_url
        .rsplit_once('@')
        .map(|(_, server)| format!("nats://{server}"))
        .ok_or_else(|| io::Error::other("NATS_URL omitted fixed harness credentials"))?;
    let client = async_nats::ConnectOptions::new()
        .user_and_password(
            "phase285_expected".to_string(),
            "phase285_expected_fixed_password".to_string(),
        )
        .connect(server)
        .await
        .map_err(|error| io::Error::other(format!("connect expected account: {error}")))?;
    let context = async_nats::jetstream::new(client);
    let stream_id = format!("stream-{bucket}");
    let governance_secret = format!("{bucket}-governance");
    let witness_secret = format!("{bucket}-witness");
    let governance = Ed25519Signer::from_secret_material(&governance_secret);
    let witness = Ed25519Signer::from_secret_material(&witness_secret);
    let binding = fixture_protocol(
        "construct publication binding",
        binding(&governance, &witness, &stream_id),
    )?;
    let max_retained_bytes = 1_000_000_u64;
    let max_manifest_bytes = 1_000_000_u64;
    let required_bucket_bytes =
        2 * (max_manifest_bytes + 65_536) + 2 * (max_retained_bytes + 65_536);
    let configuration = fixture_protocol(
        "construct bucket configuration",
        bucket_configuration(
            bucket,
            max_retained_bytes.max(max_manifest_bytes),
            required_bucket_bytes,
        ),
    )?;
    fixture_protocol("validate bucket configuration", configuration.validate())?;
    request_value(
        &context,
        format!("STREAM.CREATE.{}", configuration.stream_name),
        &raw_configuration(bucket, max_retained_bytes, required_bucket_bytes),
    )
    .await
    .map_err(|error| io::Error::other(format!("open confirmed store: {error:?}")))?;
    let server_info = raw_info(&context, &configuration.stream_name).await?;
    let raw_created_at = server_info
        .get("created")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("raw info omitted created"))?
        .to_string();
    let created_at = canonical_fixture_created_at(&raw_created_at)?;

    let mut admission = WitnessAdmissionRecordV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: binding.stream_id.clone(),
        signer_key_id: binding.signer_key_id.clone(),
        witness_identity: binding.witness_identity.clone(),
        witness_key_id: binding.witness_key_id.clone(),
        binding_generation: binding.generation.clone(),
        binding_digest: binding.binding_digest.clone(),
        authority_pair: binding.authority_pair,
        publication_roles: binding.publication_roles,
        limits: binding.limits,
        max_retained_bytes,
        initial_epoch: 0,
        initial_sequence: 0,
        initial_intent_counter: 1,
        admission_digest: "0".repeat(64),
    };
    admission.admission_digest =
        fixture_protocol("compute admission digest", admission.computed_digest())?;
    fixture_protocol("validate admission", admission.validate())?;
    let admission_entry = WitnessAdmissionEntryV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        admission: admission.clone(),
        governance_signer_public_key_hex: governance.public_key_hex().to_string(),
        max_state_bytes: admission.limits.max_payload_bytes,
        max_checkpoint_bytes: admission.limits.max_payload_bytes,
        max_binding_bytes: admission.limits.max_record_bytes,
        max_request_bytes: admission.limits.max_record_bytes,
        max_response_bytes: admission.limits.max_record_bytes,
        predecessor_admission_digest: None,
    };
    let mut admission_set = WitnessAdmissionSetV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        entries: vec![admission_entry],
        admission_set_digest: "0".repeat(64),
    };
    admission_set.admission_set_digest = fixture_protocol(
        "compute admission-set digest",
        admission_set.computed_digest(),
    )?;
    fixture_protocol("validate admission set", admission_set.validate())?;
    let configuration_digest = fixture_protocol(
        "compute bucket configuration digest",
        configuration.digest(),
    )?;
    let epoch = WitnessBucketEpochV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        bucket_generation: "a".repeat(64),
        nats_account: "PHASE285_EXPECTED".to_string(),
        stream_name: configuration.stream_name.clone(),
        bucket_configuration_digest: configuration_digest.clone(),
        admission_set_digest: admission_set.admission_set_digest.clone(),
        witness_identity: admission.witness_identity.clone(),
        witness_key_id: admission.witness_key_id.clone(),
    };
    let epoch_digest = fixture_protocol("compute bucket epoch digest", epoch.digest())?;
    let initialization_digest = WitnessStreamInitializationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        bucket_epoch_digest: epoch_digest.clone(),
        admission_digest: admission.admission_digest.clone(),
        stream_id: stream_id.clone(),
        witness_identity: admission.witness_identity.clone(),
        witness_key_id: admission.witness_key_id.clone(),
    }
    .digest()
    .map_err(|error| {
        io::Error::other(format!("compute stream initialization digest: {error:?}"))
    })?;
    let mut current = WitnessStoreEnvelopeV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        admission_digest: admission.admission_digest.clone(),
        bucket_epoch_digest: epoch_digest.clone(),
        stream_initialization_digest: initialization_digest.clone(),
        stream_id: stream_id.clone(),
        witness_identity: admission.witness_identity.clone(),
        witness_key_id: admission.witness_key_id.clone(),
        session: None,
        last_session_rotation: None,
        current: None,
        predecessor: None,
        prepared: None,
        genesis_abort: None,
        store_generation: 0,
        signature: witness.sign(&[]),
    };
    current.signature = witness.sign(&fixture_protocol(
        "encode empty envelope signing bytes",
        current.signing_bytes(),
    )?);
    fixture_protocol("validate empty envelope", current.validate())?;
    let proposed = fixture_protocol(
        "construct session rotation",
        session_rotation(&governance, &witness, &binding, &current),
    )?;
    let stream_key = fixture_protocol("derive witness stream key", witness_stream_key(&stream_id))?;
    let mut manifest = WitnessBucketManifestV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        bucket_epoch_digest: epoch_digest,
        bucket_configuration_digest: configuration_digest,
        admission_set_digest: admission_set.admission_set_digest.clone(),
        stream_keys: vec![stream_key.clone()],
        initialized_streams: BTreeMap::from([(
            stream_key.clone(),
            WitnessStreamInitializationRecordV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                stream_initialization_digest: initialization_digest,
                empty_envelope_digest: fixture_protocol(
                    "compute empty-envelope digest",
                    current.signed_envelope_digest(),
                )?,
            },
        )]),
        phase: WitnessBucketManifestPhaseV1::Ready,
        witness_identity: admission.witness_identity.clone(),
        witness_key_id: admission.witness_key_id.clone(),
        signature: witness.sign(&[]),
    };
    manifest.signature = witness.sign(&fixture_protocol(
        "encode ready-manifest signing bytes",
        manifest.signing_bytes(),
    )?);
    let mut anchor = WitnessBucketAnchorV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        epoch: epoch.clone(),
        nats_stream_created_at: created_at.clone(),
        raw_stream_configuration_digest: raw_configuration_digest(&server_info)?,
        ready_manifest_digest: fixture_protocol(
            "compute ready-manifest digest",
            manifest.digest(),
        )?,
        witness_key_id: admission.witness_key_id.clone(),
        signature: witness.sign(&[]),
    };
    anchor.signature = witness.sign(&fixture_protocol(
        "encode bucket-anchor signing bytes",
        anchor.signing_bytes(),
    )?);
    let deployment_inputs = WitnessStoreDeploymentInputsV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        max_manifest_bytes,
        maximum_admitted_streams: 1,
        configured_replica_count: 1,
    };
    let ready = fixture_protocol(
        "construct ready result",
        swarm_governance::witness_engine::store::WitnessStoreReadyResultV1::new(
            created_at,
            configuration,
            epoch,
            anchor,
            admission_set,
            manifest.clone(),
            deployment_inputs,
        ),
    )?;
    let manifest_sequence = publish_initial(
        &context,
        format!("$KV.{bucket}.{MANIFEST_KEY}"),
        &ready.bucket_configuration.stream_name,
        canonical_wire_bytes(&manifest)?,
        InitialHeader::Put,
    )
    .await?;
    assert_eq!(manifest_sequence, 1);
    let subject = format!("$KV.{bucket}.{stream_key}");
    let initial_revision = publish_initial(
        &context,
        subject.clone(),
        &ready.bucket_configuration.stream_name,
        current.canonical_bytes()?,
        operation,
    )
    .await?;
    assert_eq!(initial_revision, 2);
    Ok(LiveFixture {
        context,
        ready,
        stream_id,
        current,
        proposed,
        initial_revision,
        subject,
    })
}

#[test]
fn jetstream_cas_rejects_raw_config_unknown_field_or_persist_mode() -> TestResult {
    let mut ledger =
        InnerLedger::new("jetstream_cas_rejects_raw_config_unknown_field_or_persist_mode");
    let (signer, epoch, anchor) = typed_bindings()?;
    let accepted = inspect_raw_stream_info(&info(golden()?)?, &expected(), &epoch, &anchor)?;
    assert_eq!(
        anchor.raw_stream_configuration_digest,
        "aaabfbcd39e5a19fae9f3ae03d5670e993a77900e4411d73b3911bbbefe3c224",
        "the sealed-anchor fixture binds the exact canonical raw DTO"
    );
    ledger.passed("raw.binding.anchor_digest")?;
    assert_eq!(
        epoch.bucket_configuration_digest,
        "0e8398c6f3d43e7007ef4c073490ab655cb932ff7c78b2ad256256347a04a67b",
        "the epoch fixture binds the distinct semantic configuration"
    );
    ledger.passed("raw.binding.epoch_digest")?;
    assert_eq!(accepted.raw_configuration().name(), "KV_phase285_witness");
    ledger.passed("raw.present.name")?;
    for (created_id, equivalent_created) in [
        ("zero", "2026-08-25T00:00:00Z"),
        ("one", "2026-08-25T00:00:00.0Z"),
        ("eight", "2026-08-25T00:00:00.00000000Z"),
        ("nine", "2026-08-25T00:00:00.000000000Z"),
    ] {
        let raw = info_with_created(golden()?, equivalent_created)?;
        let equivalent = inspect_raw_stream_info(&raw, &expected(), &epoch, &anchor)?;
        assert!(
            equivalent
                .canonical_raw_stream_info()
                .windows(equivalent_created.len())
                .any(|window| window == equivalent_created.as_bytes())
        );
        ledger.passed(format!("raw.created.{created_id}"))?;
    }
    assert!(matches!(
        inspect_raw_stream_info(
            &info_with_created(golden()?, "2026-08-25T00:00:00.000000001Z")?,
            &expected(),
            &epoch,
            &anchor,
        ),
        Err(RawConfigurationError::TypedBindingMismatch)
    ));
    ledger.passed("raw.created.changed_instant")?;
    let mut expected_raw_digest = Sha256::new();
    expected_raw_digest.update(b"swarm.governance.nats-2.11.17-raw-stream-configuration.v1");
    expected_raw_digest
        .update(u64::try_from(accepted.canonical_raw_configuration().len())?.to_be_bytes());
    expected_raw_digest.update(accepted.canonical_raw_configuration());
    assert_eq!(
        anchor.raw_stream_configuration_digest,
        hex::encode(expected_raw_digest.finalize()),
        "the raw digest must include the domain and explicit length delimiter"
    );
    ledger.passed("raw.digest.length_delimiter")?;
    assert_ne!(
        anchor.raw_stream_configuration_digest, epoch.bucket_configuration_digest,
        "raw and semantic configuration digests bind distinct preimages"
    );
    ledger.passed("raw.binding.distinct_digests")?;

    let forbidden_fields = [
        ("unknown", json!(true)),
        ("persist_mode", json!("async")),
        ("persist_mode", json!("sync")),
        ("no_ack", json!(false)),
        ("discard_new_per_subject", json!(false)),
        ("template_owner", json!("")),
        ("placement", Value::Null),
        ("mirror", Value::Null),
        ("sources", json!([])),
        ("first_seq", json!(0)),
        ("subject_transform", Value::Null),
        ("republish", Value::Null),
        ("subject_delete_marker_ttl", json!(0)),
        ("allow_atomic", json!(false)),
        ("allow_msg_schedules", json!(false)),
        ("allow_msg_counter", json!(false)),
        ("pause_until", Value::Null),
    ];
    assert_eq!(forbidden_fields.len(), 17);
    for (index, (name, value)) in forbidden_fields.into_iter().enumerate() {
        let mut mutant = golden()?;
        let Value::Object(object) = &mut mutant else {
            return Err(io::Error::other("golden config is not an object").into());
        };
        object.insert(name.to_string(), value);
        assert!(matches!(
            inspect_raw_stream_info(&info(mutant)?, &expected(), &epoch, &anchor),
            Err(RawConfigurationError::NonCanonicalRawConfiguration)
        ));
        let inner_id = if name == "persist_mode" {
            if index == 1 {
                "raw.absent.persist_mode_async".to_string()
            } else {
                "raw.absent.persist_mode_sync".to_string()
            }
        } else {
            format!("raw.absent.{name}")
        };
        ledger.passed(inner_id)?;
    }

    let mut unknown_info: Value = serde_json::from_slice(&info(golden()?)?)?;
    let Value::Object(info_object) = &mut unknown_info else {
        return Err(io::Error::other("golden info is not an object").into());
    };
    info_object.insert("new_server_field".to_string(), json!(false));
    assert!(matches!(
        inspect_raw_stream_info(
            &serde_json::to_vec(&unknown_info)?,
            &expected(),
            &epoch,
            &anchor,
        ),
        Err(RawConfigurationError::NonCanonicalRawConfiguration)
    ));
    ledger.passed("raw.info.unknown_field")?;

    let wrong_version = expected().with_wrong_server_version_for_conformance();
    assert!(matches!(
        inspect_raw_stream_info(&info(golden()?)?, &wrong_version, &epoch, &anchor),
        Err(RawConfigurationError::WrongRuntimeIdentity)
    ));
    ledger.passed("raw.runtime.wrong_version")?;
    let wrong_image = expected().with_wrong_image_digest_for_conformance();
    assert!(matches!(
        inspect_raw_stream_info(&info(golden()?)?, &wrong_image, &epoch, &anchor),
        Err(RawConfigurationError::WrongRuntimeIdentity)
    ));
    ledger.passed("raw.runtime.wrong_image")?;

    let info_text = String::from_utf8(info(golden()?)?)?;
    let duplicate_name = info_text.replacen(
        r#""name":"KV_phase285_witness""#,
        r#""name":"duplicate","name":"KV_phase285_witness""#,
        1,
    );
    assert!(matches!(
        inspect_raw_stream_info(duplicate_name.as_bytes(), &expected(), &epoch, &anchor),
        Err(RawConfigurationError::NonCanonicalRawConfiguration)
    ));
    ledger.passed("raw.duplicate.name")?;

    let mut swapped_epoch = epoch.clone();
    swapped_epoch.bucket_configuration_digest = anchor.raw_stream_configuration_digest.clone();
    let mut swapped_anchor = anchor.clone();
    swapped_anchor.epoch = swapped_epoch.clone();
    swapped_anchor.raw_stream_configuration_digest = epoch.bucket_configuration_digest.clone();
    resign_anchor(&mut swapped_anchor, &signer)?;
    assert!(matches!(
        inspect_raw_stream_info(
            &info(golden()?)?,
            &expected(),
            &swapped_epoch,
            &swapped_anchor,
        ),
        Err(RawConfigurationError::TypedBindingMismatch)
    ));
    ledger.passed("binding.swapped_digest")?;

    let mut substituted_epoch = epoch.clone();
    substituted_epoch.bucket_configuration_digest = "4".repeat(64);
    let mut substituted_anchor = anchor.clone();
    substituted_anchor.epoch = substituted_epoch.clone();
    substituted_anchor.raw_stream_configuration_digest = "5".repeat(64);
    resign_anchor(&mut substituted_anchor, &signer)?;
    assert!(matches!(
        inspect_raw_stream_info(
            &info(golden()?)?,
            &expected(),
            &substituted_epoch,
            &substituted_anchor,
        ),
        Err(RawConfigurationError::TypedBindingMismatch)
    ));
    ledger.passed("binding.substituted_digest")?;

    let mut foreign_anchor_epoch = anchor.clone();
    foreign_anchor_epoch.epoch.bucket_generation = "6".repeat(64);
    resign_anchor(&mut foreign_anchor_epoch, &signer)?;
    assert!(matches!(
        inspect_raw_stream_info(
            &info(golden()?)?,
            &expected(),
            &epoch,
            &foreign_anchor_epoch,
        ),
        Err(RawConfigurationError::TypedBindingMismatch)
    ));
    ledger.passed("binding.foreign_anchor_epoch")?;

    let mut wrong_creation_time = anchor.clone();
    wrong_creation_time.nats_stream_created_at = "2026-08-25T00:00:01.000000000Z".to_string();
    resign_anchor(&mut wrong_creation_time, &signer)?;
    assert!(matches!(
        inspect_raw_stream_info(&info(golden()?)?, &expected(), &epoch, &wrong_creation_time,),
        Err(RawConfigurationError::TypedBindingMismatch)
    ));
    ledger.passed("binding.creation_time")?;

    let mut foreign_stream_epoch = epoch.clone();
    foreign_stream_epoch.stream_name = "KV_foreign_witness".to_string();
    foreign_stream_epoch.validate()?;
    let mut coherent_foreign_stream_anchor = anchor.clone();
    coherent_foreign_stream_anchor.epoch = foreign_stream_epoch.clone();
    resign_anchor(&mut coherent_foreign_stream_anchor, &signer)?;
    assert!(matches!(
        inspect_raw_stream_info(
            &info(golden()?)?,
            &expected(),
            &foreign_stream_epoch,
            &coherent_foreign_stream_anchor,
        ),
        Err(RawConfigurationError::TypedBindingMismatch)
    ));
    ledger.passed("binding.foreign_stream")?;

    let mut signature_only_mutant = anchor.clone();
    let signed_fields = signature_only_mutant.clone();
    signature_only_mutant.signature.signature_hex = "00".repeat(64);
    assert_eq!(
        signature_only_mutant.schema_version,
        signed_fields.schema_version
    );
    assert_eq!(signature_only_mutant.epoch, signed_fields.epoch);
    assert_eq!(
        signature_only_mutant.nats_stream_created_at,
        signed_fields.nats_stream_created_at
    );
    assert_eq!(
        signature_only_mutant.raw_stream_configuration_digest,
        signed_fields.raw_stream_configuration_digest
    );
    assert_eq!(
        signature_only_mutant.ready_manifest_digest,
        signed_fields.ready_manifest_digest
    );
    assert_eq!(
        signature_only_mutant.witness_key_id,
        signed_fields.witness_key_id
    );
    assert_ne!(signature_only_mutant.signature, signed_fields.signature);
    assert!(matches!(
        inspect_raw_stream_info(
            &info(golden()?)?,
            &expected(),
            &epoch,
            &signature_only_mutant,
        ),
        Err(RawConfigurationError::TypedBindingMismatch)
    ));
    ledger.passed("binding.signature")?;
    ledger.finish()?;
    Ok(())
}

#[test]
fn jetstream_cas_rejects_each_raw_config_mutation() -> TestResult {
    let mut ledger = InnerLedger::new("jetstream_cas_rejects_each_raw_config_mutation");
    let (_, epoch, anchor) = typed_bindings()?;
    let baseline = golden()?;
    let Value::Object(object) = &baseline else {
        return Err(io::Error::other("golden config is not an object").into());
    };
    assert_eq!(
        object.len(),
        24,
        "the golden binds the complete allowed key set"
    );
    ledger.passed("raw.present.cardinality")?;

    for key in object.keys() {
        let mut mutant = baseline.clone();
        let Value::Object(mutant_object) = &mut mutant else {
            return Err(io::Error::other("golden config is not an object").into());
        };
        mutant_object.remove(key);
        assert!(
            inspect_raw_stream_info(&info(mutant)?, &expected(), &epoch, &anchor).is_err(),
            "missing key {key} must fail closed"
        );
        ledger.passed(format!("raw.present.{key}"))?;
    }

    let mutations = [
        ("name", json!("KV_other")),
        ("description", json!("other")),
        ("subjects", json!(["$KV.other.>"])),
        ("retention", json!("interest")),
        ("max_consumers", json!(0)),
        ("max_msgs", json!(0)),
        ("max_bytes", json!(1048577)),
        ("max_age", json!(1)),
        ("max_msgs_per_subject", json!(2)),
        ("max_msg_size", json!(4097)),
        ("discard", json!("old")),
        ("storage", json!("memory")),
        ("num_replicas", json!(3)),
        ("duplicate_window", json!(1)),
        ("compression", json!("s2")),
        ("allow_direct", json!(true)),
        ("mirror_direct", json!(true)),
        ("sealed", json!(true)),
        ("deny_delete", json!(false)),
        ("deny_purge", json!(false)),
        ("allow_rollup_hdrs", json!(true)),
        ("consumer_limits", json!({"max_ack_pending": 1})),
        ("allow_msg_ttl", json!(true)),
        (
            "metadata",
            json!({"_nats.level":"2","_nats.req.level":"0","_nats.ver":"2.11.17"}),
        ),
    ];
    for (key, value) in mutations {
        let mut mutant = baseline.clone();
        let Value::Object(mutant_object) = &mut mutant else {
            return Err(io::Error::other("golden config is not an object").into());
        };
        mutant_object.insert(key.to_string(), value);
        assert!(
            inspect_raw_stream_info(&info(mutant)?, &expected(), &epoch, &anchor).is_err(),
            "changed field {key} must fail closed"
        );
        ledger.passed(format!("raw.semantic.{key}"))?;
    }
    ledger.finish()?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a JetStream-enabled Phase 285 NATS server and harness ledger"]
async fn jetstream_cas_rejects_wrong_revision_header_or_ack() -> TestResult {
    let mut ledger = InnerLedger::new("jetstream_cas_rejects_wrong_revision_header_or_ack");
    let fixture = live_fixture("phase285_b_wrong_revision", InitialHeader::Put).await?;
    validate_read_entry(
        &fixture.ready,
        &fixture.stream_id,
        fixture.initial_revision,
        &fixture.current,
    )?;
    ledger.passed("cas.validator.read")?;
    let store = NatsWitnessStore::open(
        fixture.context.clone(),
        fixture.ready.clone(),
        NATS_VERSION,
        NATS_IMAGE,
    )
    .await
    .map_err(|error| io::Error::other(format!("open confirmed store: {error:?}")))?;
    assert_eq!(store.inspect_ready().await?, fixture.ready);
    ledger.passed("inspect.stable_iterator_complete")?;
    let pre = store.read_entry(&fixture.stream_id).await?;
    let result = store
        .compare_and_swap(
            &fixture.stream_id,
            fixture.initial_revision + 1,
            &fixture.current.store_state_digest()?,
            &fixture.proposed,
        )
        .await
        .map_err(|error| io::Error::other(format!("confirmed CAS: {error:?}")))?;
    assert!(matches!(
        result,
        WitnessStoreCasResultV1::Conflict {
            observed_revision,
            ..
        } if observed_revision == fixture.initial_revision
    ));
    ledger.passed("cas.conflict.wrong_revision")?;
    assert_eq!(store.read_entry(&fixture.stream_id).await?, pre);
    ledger.passed("cas.refusal.wrong_revision_immutable")?;
    assert!(matches!(
        store
            .compare_and_swap(
                &fixture.stream_id,
                0,
                &fixture.current.store_state_digest()?,
                &fixture.proposed,
            )
            .await?,
        WitnessStoreCasResultV1::Conflict { observed_revision, .. }
            if observed_revision == fixture.initial_revision
    ));
    ledger.passed("cas.conflict.zero_revision")?;
    assert_eq!(store.read_entry(&fixture.stream_id).await?, pre);
    ledger.passed("cas.refusal.zero_revision_immutable")?;
    ledger.finish()?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a JetStream-enabled Phase 285 NATS server and harness ledger"]
async fn jetstream_cas_confirms_raw_sequence_and_bytes() -> TestResult {
    let mut ledger = InnerLedger::new("jetstream_cas_confirms_raw_sequence_and_bytes");
    let fixture = live_fixture("phase285_b_confirmed", InitialHeader::Put)
        .await
        .map_err(|error| io::Error::other(format!("build live fixture: {error:?}")))?;
    let expected_digest = validate_cas_transition(
        &fixture.ready,
        &fixture.stream_id,
        fixture.initial_revision,
        &fixture.current.store_state_digest()?,
        fixture.initial_revision,
        &fixture.current,
        &fixture.proposed,
    )
    .map_err(|error| io::Error::other(format!("prevalidate confirmed CAS: {error:?}")))?;
    ledger.passed("cas.validator.transition")?;
    let store = NatsWitnessStore::open(
        fixture.context.clone(),
        fixture.ready.clone(),
        NATS_VERSION,
        NATS_IMAGE,
    )
    .await
    .map_err(|error| io::Error::other(format!("open confirmed store: {error:?}")))?;
    assert_eq!(store.inspect_ready().await?, fixture.ready);
    ledger.passed("inspect.stable_iterator_complete")?;
    let applied = store
        .compare_and_swap(
            &fixture.stream_id,
            fixture.initial_revision,
            &fixture.current.store_state_digest()?,
            &fixture.proposed,
        )
        .await
        .map_err(|error| io::Error::other(format!("confirmed CAS: {error:?}")))?;
    let WitnessStoreCasResultV1::Applied {
        expected_previous_revision,
        previous_revision,
        new_revision,
        acknowledged_value_digest,
        duplicate,
        ..
    } = applied
    else {
        return Err(io::Error::other("confirmed CAS did not return Applied").into());
    };
    assert_eq!(expected_previous_revision, fixture.initial_revision);
    ledger.passed("ack.expected_previous_revision")?;
    assert_eq!(previous_revision, fixture.initial_revision);
    ledger.passed("ack.previous_revision")?;
    assert!(new_revision > previous_revision);
    ledger.passed("ack.increasing_sequence")?;
    assert_eq!(acknowledged_value_digest, expected_digest);
    ledger.passed("ack.digest")?;
    assert!(!duplicate);
    ledger.passed("ack.not_duplicate")?;
    let read = store.read_entry(&fixture.stream_id).await?;
    let (_, read_revision, read_envelope) = read.parts();
    assert_eq!(read_revision, new_revision);
    ledger.passed("read.sequence")?;
    assert_eq!(read_envelope, &fixture.proposed);
    ledger.passed("read.envelope")?;
    assert_eq!(
        read_envelope.canonical_bytes()?,
        fixture.proposed.canonical_bytes()?
    );
    ledger.passed("read.bytes")?;
    assert_eq!(
        read_envelope.signed_envelope_digest()?,
        acknowledged_value_digest
    );
    ledger.passed("read.digest")?;

    ledger.finish()?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a JetStream-enabled Phase 285 NATS server and harness ledger"]
async fn jetstream_cas_rejects_del_purge_rollup_and_direct_reads() -> TestResult {
    let mut ledger = InnerLedger::new("jetstream_cas_rejects_del_purge_rollup_and_direct_reads");
    for (bucket, operation, control_id) in [
        (
            "phase285_b_del",
            InitialHeader::Delete,
            "header.reject.delete",
        ),
        (
            "phase285_b_purge",
            InitialHeader::Purge,
            "header.reject.purge",
        ),
        (
            "phase285_b_unknown",
            InitialHeader::Unknown,
            "header.reject.unknown",
        ),
    ] {
        let fixture = live_fixture(bucket, operation)
            .await
            .map_err(|error| io::Error::other(format!("build {bucket} fixture: {error:?}")))?;
        assert!(matches!(
            NatsWitnessStore::open(fixture.context, fixture.ready, NATS_VERSION, NATS_IMAGE,).await,
            Err(WitnessStoreErrorV1::Header)
        ));
        ledger.passed(control_id)?;
    }

    let fixture = live_fixture("phase285_b_direct", InitialHeader::Put)
        .await
        .map_err(|error| io::Error::other(format!("build direct fixture: {error:?}")))?;
    let rollup = fixture
        .context
        .publish_with_headers(
            fixture.subject.clone(),
            exact_put_headers(
                &fixture.ready.bucket_configuration.stream_name,
                fixture.initial_revision,
                InitialHeader::Rollup,
            ),
            fixture.current.canonical_bytes()?.into(),
        )
        .await?
        .await;
    assert!(
        rollup.is_err(),
        "the server must reject forbidden rollup headers"
    );
    ledger.passed("header.reject.rollup")?;
    let stream = fixture
        .context
        .get_stream(&fixture.ready.bucket_configuration.stream_name)
        .await?;
    assert!(!stream.cached_info().config.allow_direct);
    ledger.passed("read.reject.direct_config")?;
    assert!(
        stream
            .direct_get_builder()
            .last_by_subject(fixture.subject.clone())
            .send()
            .await
            .is_err(),
        "the sealed stream must refuse replica-direct reads"
    );
    ledger.passed("read.reject.direct_api")?;
    NatsWitnessStore::open(fixture.context, fixture.ready, NATS_VERSION, NATS_IMAGE)
        .await
        .map_err(|error| io::Error::other(format!("open direct-read fixture: {error:?}")))?;
    ledger.passed("read.leader.open")?;
    ledger.finish()?;
    Ok(())
}
