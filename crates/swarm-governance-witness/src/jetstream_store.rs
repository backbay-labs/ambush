use std::collections::BTreeSet;
use std::sync::Mutex;

#[cfg(debug_assertions)]
use std::fs::OpenOptions;
#[cfg(debug_assertions)]
use std::io::Write;
#[cfg(debug_assertions)]
use std::path::PathBuf;

use async_nats::header::{
    NATS_EXPECTED_LAST_SUBJECT_SEQUENCE, NATS_EXPECTED_STREAM, NATS_MESSAGE_ID, NATS_MESSAGE_TTL,
};
use async_nats::jetstream::Context;
use async_nats::jetstream::response::Response;
use async_nats::jetstream::stream::{LastRawMessageErrorKind, Stream};
use async_nats::{HeaderMap, HeaderValue};
use async_trait::async_trait;
use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};
use swarm_governance::persistence_protocol::canonical_wire_bytes;
use swarm_governance::witness_engine::store::{
    WitnessAtomicStore, WitnessStoreCasResultV1, WitnessStoreErrorV1, WitnessStoreReadResultV1,
    WitnessStoreReadyResultV1, validate_cas_transition, validate_read_entry,
};
use swarm_governance::witness_engine::{WitnessStoreEnvelopeV1, witness_stream_key};

use crate::raw_config::{
    Nats21117ExpectedConfigurationV1, Nats21117RawStreamInfoV1, Nats21117TypedSnapshotV1,
    inspect_raw_stream_info,
};

const NATS_OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const READY_ENTRY_VALIDATION_CONCURRENCY: usize = 64;

const KV_OPERATION: &str = "KV-Operation";
const KV_PUT: &str = "PUT";
const KV_ROLLUP: &str = "Nats-Rollup";
const BUCKET_MANIFEST_KEY: &str = "__witness_bucket_manifest";
const RAW_STREAM_INFO_DOMAIN: &[u8] = b"swarm.governance.nats-2.11.17-raw-stream-info.v1";

#[derive(Debug)]
struct ValidatedRawEntry {
    sequence: u64,
    payload: Vec<u8>,
    expected_previous_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PostPublishAcknowledgement {
    stream: String,
    sequence: u64,
    duplicate: bool,
}

#[cfg(debug_assertions)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PostAckBarrierEvent {
    stream: String,
    sequence: u64,
    duplicate: bool,
    proposed_digest: String,
    token: String,
}

#[cfg(debug_assertions)]
#[derive(Debug)]
struct PostAckBarrierControl {
    token: String,
    acknowledgement_path: PathBuf,
    release_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PostPublishConfirmation {
    Authenticated {
        sequence: u64,
        expected_previous_revision: u64,
        payload: Vec<u8>,
        envelope_digest: String,
    },
    Failed(WitnessStoreErrorV1),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PostPublishClassificationInput {
    stream_id: String,
    configured_stream: String,
    expected_previous_revision: u64,
    current_revision: u64,
    proposed_bytes: Vec<u8>,
    proposed_digest: String,
    acknowledgement: PostPublishAcknowledgement,
    confirmation: Option<PostPublishConfirmation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostPublishClassificationCause {
    Applied,
    AckStreamMismatch,
    DuplicateAcknowledgement,
    NonIncreasingAcknowledgement,
    ConfirmationFailure(WitnessStoreErrorV1),
    ConfirmationMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PostPublishClassification {
    result: WitnessStoreCasResultV1,
    cause: PostPublishClassificationCause,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PostPublishClassificationDecision {
    NeedsConfirmation,
    Complete(PostPublishClassification),
}

fn post_publish_ack_failure(
    input: &PostPublishClassificationInput,
) -> Option<PostPublishClassificationCause> {
    if input.acknowledgement.stream != input.configured_stream {
        Some(PostPublishClassificationCause::AckStreamMismatch)
    } else if input.acknowledgement.duplicate {
        Some(PostPublishClassificationCause::DuplicateAcknowledgement)
    } else if input.acknowledgement.sequence <= input.current_revision {
        Some(PostPublishClassificationCause::NonIncreasingAcknowledgement)
    } else {
        None
    }
}

fn classify_post_publish(
    input: &PostPublishClassificationInput,
) -> PostPublishClassificationDecision {
    let ambiguous = |observed_revision, observed_value_digest| WitnessStoreCasResultV1::Ambiguous {
        stream_id: input.stream_id.clone(),
        expected_previous_revision: input.expected_previous_revision,
        observed_revision,
        observed_value_digest,
    };
    let ack_revision = Some(input.acknowledgement.sequence).filter(|revision| *revision != 0);
    if let Some(cause) = post_publish_ack_failure(input) {
        return PostPublishClassificationDecision::Complete(PostPublishClassification {
            result: ambiguous(ack_revision, None),
            cause,
        });
    }
    let Some(confirmation) = &input.confirmation else {
        return PostPublishClassificationDecision::NeedsConfirmation;
    };
    let PostPublishConfirmation::Authenticated {
        sequence,
        expected_previous_revision,
        payload,
        envelope_digest,
    } = confirmation
    else {
        let PostPublishConfirmation::Failed(error) = confirmation else {
            unreachable!();
        };
        return PostPublishClassificationDecision::Complete(PostPublishClassification {
            result: ambiguous(None, None),
            cause: PostPublishClassificationCause::ConfirmationFailure(*error),
        });
    };
    if *sequence != input.acknowledgement.sequence
        || *payload != input.proposed_bytes
        || *expected_previous_revision != input.expected_previous_revision
        || *envelope_digest != input.proposed_digest
    {
        return PostPublishClassificationDecision::Complete(PostPublishClassification {
            result: ambiguous(Some(*sequence), Some(envelope_digest.clone())),
            cause: PostPublishClassificationCause::ConfirmationMismatch,
        });
    }
    PostPublishClassificationDecision::Complete(PostPublishClassification {
        result: WitnessStoreCasResultV1::Applied {
            stream_id: input.stream_id.clone(),
            expected_previous_revision: input.expected_previous_revision,
            previous_revision: input.current_revision,
            new_revision: input.acknowledgement.sequence,
            acknowledged_value_digest: input.proposed_digest.clone(),
            duplicate: false,
        },
        cause: PostPublishClassificationCause::Applied,
    })
}

#[derive(Debug)]
pub struct NatsWitnessStore {
    context: Context,
    stream: Stream<()>,
    ready: WitnessStoreReadyResultV1,
    expected: Nats21117ExpectedConfigurationV1,
    bucket_name: String,
    inspection_evidence: Mutex<Option<InspectionEvidence>>,
    #[cfg(debug_assertions)]
    post_ack_barrier: Mutex<Option<PostAckBarrierControl>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StableReadySnapshot {
    subjects_count: u64,
    messages: u64,
    first_sequence: u64,
    last_sequence: u64,
    stream_created_at: String,
    canonical_raw_configuration: Vec<u8>,
    raw_stream_configuration_digest: String,
    projected_configuration: swarm_governance::witness_engine::store::WitnessBucketConfigurationV1,
}

impl StableReadySnapshot {
    fn from_typed(value: &Nats21117TypedSnapshotV1) -> Result<Self, WitnessStoreErrorV1> {
        Ok(Self {
            subjects_count: value
                .subjects_count()
                .ok_or(WitnessStoreErrorV1::Configuration)?,
            messages: value.messages(),
            first_sequence: value.first_sequence(),
            last_sequence: value.last_sequence(),
            stream_created_at: value.created_at().to_string(),
            canonical_raw_configuration: value.canonical_raw_configuration().to_vec(),
            raw_stream_configuration_digest: value.raw_stream_configuration_digest().to_string(),
            projected_configuration: value.projected_configuration().clone(),
        })
    }
}

#[derive(Debug)]
struct ReadySubjectAccumulator {
    advertised: u64,
    maximum: u64,
    expected: BTreeSet<String>,
    observed: BTreeSet<String>,
    yielded: u64,
}

impl ReadySubjectAccumulator {
    fn new(
        advertised: u64,
        iterator_advertised: u64,
        maximum: u64,
        expected: BTreeSet<String>,
    ) -> Result<Self, WitnessStoreErrorV1> {
        if advertised > maximum {
            return Err(WitnessStoreErrorV1::Bounds);
        }
        if u64::try_from(expected.len()).map_err(|_| WitnessStoreErrorV1::Bounds)? != advertised {
            return Err(WitnessStoreErrorV1::Missing);
        }
        if iterator_advertised != advertised {
            return Err(WitnessStoreErrorV1::Configuration);
        }
        Ok(Self {
            advertised,
            maximum,
            expected,
            observed: BTreeSet::new(),
            yielded: 0,
        })
    }

    fn observe(&mut self, subject: String, count: usize) -> Result<(), WitnessStoreErrorV1> {
        if count != 1 {
            return Err(WitnessStoreErrorV1::Corrupt);
        }
        self.yielded = self
            .yielded
            .checked_add(1)
            .ok_or(WitnessStoreErrorV1::Bounds)?;
        if self.yielded > self.maximum || self.yielded > self.advertised {
            return Err(WitnessStoreErrorV1::Bounds);
        }
        if !self.expected.contains(&subject) || !self.observed.insert(subject) {
            return Err(WitnessStoreErrorV1::Corrupt);
        }
        Ok(())
    }

    fn finish(self) -> Result<(), WitnessStoreErrorV1> {
        if self.yielded != self.advertised || self.observed != self.expected {
            return Err(WitnessStoreErrorV1::Missing);
        }
        Ok(())
    }
}

fn ready_iterator_page<T, E>(value: Result<T, E>) -> Result<T, WitnessStoreErrorV1> {
    value.map_err(|_| WitnessStoreErrorV1::Unavailable)
}

fn validate_final_ready_snapshot(
    initial: &StableReadySnapshot,
    final_snapshot: &StableReadySnapshot,
) -> Result<(), WitnessStoreErrorV1> {
    if final_snapshot != initial {
        return Err(WitnessStoreErrorV1::Configuration);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FullInfoEvidence {
    canonical_bytes: Vec<u8>,
    digest: String,
}

impl FullInfoEvidence {
    fn from_typed(value: &Nats21117TypedSnapshotV1) -> Result<Self, WitnessStoreErrorV1> {
        Self::new(
            value.canonical_raw_stream_info().to_vec(),
            value.raw_stream_info_digest().to_string(),
        )
    }

    fn new(canonical_bytes: Vec<u8>, digest: String) -> Result<Self, WitnessStoreErrorV1> {
        if canonical_bytes.is_empty() {
            return Err(WitnessStoreErrorV1::Configuration);
        }
        let mut expected = Sha256::new();
        expected.update(RAW_STREAM_INFO_DOMAIN);
        expected.update(
            u64::try_from(canonical_bytes.len())
                .map_err(|_| WitnessStoreErrorV1::Bounds)?
                .to_be_bytes(),
        );
        expected.update(&canonical_bytes);
        if hex::encode(expected.finalize()) != digest {
            return Err(WitnessStoreErrorV1::Configuration);
        }
        Ok(Self {
            canonical_bytes,
            digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InspectionEvidence {
    initial: FullInfoEvidence,
    final_snapshot: FullInfoEvidence,
}

impl InspectionEvidence {
    fn new(
        initial: Option<FullInfoEvidence>,
        final_snapshot: Option<FullInfoEvidence>,
    ) -> Result<Self, WitnessStoreErrorV1> {
        Ok(Self {
            initial: initial.ok_or(WitnessStoreErrorV1::Configuration)?,
            final_snapshot: final_snapshot.ok_or(WitnessStoreErrorV1::Configuration)?,
        })
    }
}

impl NatsWitnessStore {
    pub async fn open(
        context: Context,
        ready: WitnessStoreReadyResultV1,
        reported_server_version: &str,
        resolved_server_image_index_digest: &str,
    ) -> Result<Self, WitnessStoreErrorV1> {
        Self::open_inner(
            context,
            ready,
            reported_server_version,
            resolved_server_image_index_digest,
            #[cfg(debug_assertions)]
            None,
        )
        .await
    }

    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub async fn open_with_post_ack_barrier(
        context: Context,
        ready: WitnessStoreReadyResultV1,
        reported_server_version: &str,
        resolved_server_image_index_digest: &str,
        token: String,
        acknowledgement_path: PathBuf,
        release_path: PathBuf,
    ) -> Result<Self, WitnessStoreErrorV1> {
        if token.is_empty()
            || token.len() > 256
            || token
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || b"._-".contains(&byte)))
            || !acknowledgement_path.is_absolute()
            || !release_path.is_absolute()
            || acknowledgement_path == release_path
            || acknowledgement_path.exists()
            || release_path.exists()
        {
            return Err(WitnessStoreErrorV1::Configuration);
        }
        Self::open_inner(
            context,
            ready,
            reported_server_version,
            resolved_server_image_index_digest,
            Some(PostAckBarrierControl {
                token,
                acknowledgement_path,
                release_path,
            }),
        )
        .await
    }

    async fn open_inner(
        context: Context,
        ready: WitnessStoreReadyResultV1,
        reported_server_version: &str,
        resolved_server_image_index_digest: &str,
        #[cfg(debug_assertions)] post_ack_barrier: Option<PostAckBarrierControl>,
    ) -> Result<Self, WitnessStoreErrorV1> {
        ready
            .validate()
            .map_err(|_| WitnessStoreErrorV1::Configuration)?;
        let expected = Nats21117ExpectedConfigurationV1::from_validated_deployment(
            &ready.bucket_configuration,
            &ready.deployment_inputs,
            reported_server_version,
            resolved_server_image_index_digest,
        )
        .map_err(|_| WitnessStoreErrorV1::Configuration)?;
        let bucket_name = ready
            .bucket_configuration
            .stream_name
            .strip_prefix("KV_")
            .filter(|value| !value.is_empty())
            .ok_or(WitnessStoreErrorV1::Configuration)?
            .to_string();
        let stream = context
            .get_stream_no_info(&ready.bucket_configuration.stream_name)
            .await
            .map_err(|_| WitnessStoreErrorV1::Configuration)?;
        let store = Self {
            context,
            stream,
            ready,
            expected,
            bucket_name,
            inspection_evidence: Mutex::new(None),
            #[cfg(debug_assertions)]
            post_ack_barrier: Mutex::new(post_ack_barrier),
        };
        store.inspect_ready().await?;
        Ok(store)
    }

    #[cfg(debug_assertions)]
    async fn wait_at_post_ack_barrier(
        &self,
        acknowledgement: &PostPublishAcknowledgement,
        proposed_digest: &str,
    ) -> Result<(), WitnessStoreErrorV1> {
        let control = self
            .post_ack_barrier
            .lock()
            .map_err(|_| WitnessStoreErrorV1::Unavailable)?
            .take();
        let Some(control) = control else {
            return Ok(());
        };
        let event = PostAckBarrierEvent {
            stream: acknowledgement.stream.clone(),
            sequence: acknowledgement.sequence,
            duplicate: acknowledgement.duplicate,
            proposed_digest: proposed_digest.to_string(),
            token: control.token.clone(),
        };
        let canonical = serde_json::to_vec(&event).map_err(|_| WitnessStoreErrorV1::Corrupt)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&control.acknowledgement_path)
            .map_err(|_| WitnessStoreErrorV1::Unavailable)?;
        output
            .write_all(&canonical)
            .and_then(|()| output.write_all(b"\n"))
            .and_then(|()| output.sync_all())
            .map_err(|_| WitnessStoreErrorV1::Unavailable)?;
        drop(output);

        let expected_release = format!("{}\n", control.token);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match std::fs::read_to_string(&control.release_path) {
                Ok(value) if value == expected_release => return Ok(()),
                Ok(_) => return Err(WitnessStoreErrorV1::Corrupt),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(WitnessStoreErrorV1::Unavailable),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(WitnessStoreErrorV1::Unavailable);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    async fn closed_snapshot(&self) -> Result<Nats21117TypedSnapshotV1, WitnessStoreErrorV1> {
        let request_subject = format!(
            "STREAM.INFO.{}",
            self.ready.bucket_configuration.stream_name
        );
        let response: Response<Nats21117RawStreamInfoV1> = tokio::time::timeout(
            NATS_OPERATION_TIMEOUT,
            self.context
                .request(request_subject, &serde_json::json!({})),
        )
        .await
        .map_err(|_| WitnessStoreErrorV1::Unavailable)?
        .map_err(|_| WitnessStoreErrorV1::Unavailable)?;
        let raw = match response {
            Response::Ok(info) => info,
            Response::Err { .. } => return Err(WitnessStoreErrorV1::Unavailable),
        };
        let bytes = serde_json::to_vec(&raw).map_err(|_| WitnessStoreErrorV1::Corrupt)?;
        inspect_raw_stream_info(
            &bytes,
            &self.expected,
            &self.ready.bucket_epoch,
            &self.ready.bucket_anchor,
        )
        .map_err(|_| WitnessStoreErrorV1::Configuration)
        .map(|inspected| inspected.typed_snapshot())
    }

    fn fixed_subject(&self, stream_id: &str) -> Result<String, WitnessStoreErrorV1> {
        let stream_key =
            witness_stream_key(stream_id).map_err(|_| WitnessStoreErrorV1::Admission)?;
        if self.ready.entry(stream_id).is_none() {
            return Err(WitnessStoreErrorV1::Admission);
        }
        Ok(fixed_kv_subject(&self.bucket_name, &stream_key))
    }

    fn manifest_subject(&self) -> String {
        fixed_kv_subject(&self.bucket_name, BUCKET_MANIFEST_KEY)
    }

    fn bucket_filter(&self) -> String {
        fixed_kv_subject_filter(&self.bucket_name)
    }

    fn expected_subjects(&self) -> Result<BTreeSet<String>, WitnessStoreErrorV1> {
        let mut expected = BTreeSet::from([self.manifest_subject()]);
        for admission in &self.ready.admission_set.entries {
            if !expected.insert(self.fixed_subject(&admission.stream_id)?) {
                return Err(WitnessStoreErrorV1::Configuration);
            }
        }
        Ok(expected)
    }

    async fn read_fixed_subject(
        &self,
        expected_subject: &str,
    ) -> Result<ValidatedRawEntry, WitnessStoreErrorV1> {
        let message = tokio::time::timeout(
            NATS_OPERATION_TIMEOUT,
            self.stream
                .get_last_raw_message_by_subject(expected_subject),
        )
        .await
        .map_err(|_| WitnessStoreErrorV1::Unavailable)?
        .map_err(|error| match error.kind() {
            LastRawMessageErrorKind::NoMessageFound => WitnessStoreErrorV1::Missing,
            LastRawMessageErrorKind::InvalidSubject => WitnessStoreErrorV1::Header,
            LastRawMessageErrorKind::JetStream(_) | LastRawMessageErrorKind::Other => {
                WitnessStoreErrorV1::Unavailable
            }
        })?;
        if message.subject.as_ref() != expected_subject || message.sequence == 0 {
            return Err(WitnessStoreErrorV1::Header);
        }
        let operation = exact_header(&message.headers, KV_OPERATION)?;
        let expected_stream = exact_header(&message.headers, NATS_EXPECTED_STREAM)?;
        let expected_revision =
            exact_header(&message.headers, NATS_EXPECTED_LAST_SUBJECT_SEQUENCE)?;
        if message.headers.len() != 3
            || operation != KV_PUT
            || expected_stream != self.ready.bucket_configuration.stream_name
            || message.headers.get(KV_ROLLUP).is_some()
            || message.headers.get(NATS_MESSAGE_TTL).is_some()
            || message.headers.get(NATS_MESSAGE_ID).is_some()
        {
            return Err(WitnessStoreErrorV1::Header);
        }
        let expected_previous_revision = expected_revision
            .parse::<u64>()
            .map_err(|_| WitnessStoreErrorV1::Header)?;
        if expected_previous_revision >= message.sequence {
            return Err(WitnessStoreErrorV1::Header);
        }
        Ok(ValidatedRawEntry {
            sequence: message.sequence,
            payload: message.payload.to_vec(),
            expected_previous_revision,
        })
    }

    async fn read_validated_entry(
        &self,
        stream_id: &str,
    ) -> Result<(ValidatedRawEntry, WitnessStoreEnvelopeV1), WitnessStoreErrorV1> {
        let subject = self.fixed_subject(stream_id)?;
        let raw = self.read_fixed_subject(&subject).await?;
        let envelope = WitnessStoreEnvelopeV1::decode(&raw.payload)
            .map_err(|_| WitnessStoreErrorV1::Corrupt)?;
        validate_read_entry(&self.ready, stream_id, raw.sequence, &envelope)?;
        Ok((raw, envelope))
    }

    async fn validate_manifest_entry(&self) -> Result<(), WitnessStoreErrorV1> {
        let raw = self.read_fixed_subject(&self.manifest_subject()).await?;
        if raw.payload
            != canonical_wire_bytes(&self.ready.ready_manifest)
                .map_err(|_| WitnessStoreErrorV1::Corrupt)?
        {
            return Err(WitnessStoreErrorV1::Configuration);
        }
        Ok(())
    }

    async fn publish_cas(
        &self,
        stream_id: &str,
        expected_revision: u64,
        payload: Vec<u8>,
    ) -> Result<async_nats::jetstream::publish::PublishAck, WitnessStoreErrorV1> {
        let subject = self.fixed_subject(stream_id)?;
        let mut headers = HeaderMap::new();
        headers.insert(KV_OPERATION, KV_PUT);
        headers.insert(
            NATS_EXPECTED_STREAM,
            HeaderValue::from(self.ready.bucket_configuration.stream_name.as_str()),
        );
        headers.insert(
            NATS_EXPECTED_LAST_SUBJECT_SEQUENCE,
            HeaderValue::from(expected_revision),
        );
        let ack = tokio::time::timeout(
            NATS_OPERATION_TIMEOUT,
            self.context
                .publish_with_headers(subject, headers, payload.into()),
        )
        .await
        .map_err(|_| WitnessStoreErrorV1::Unavailable)?
        .map_err(|_| WitnessStoreErrorV1::Unavailable)?;
        tokio::time::timeout(NATS_OPERATION_TIMEOUT, ack)
            .await
            .map_err(|_| WitnessStoreErrorV1::Ambiguous)?
            .map_err(|_| WitnessStoreErrorV1::Ambiguous)
    }
}

#[async_trait]
impl WitnessAtomicStore for NatsWitnessStore {
    async fn inspect_ready(&self) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1> {
        self.ready
            .validate()
            .map_err(|_| WitnessStoreErrorV1::Configuration)?;
        let initial = self.closed_snapshot().await?;
        let initial_stable = StableReadySnapshot::from_typed(&initial)?;
        let initial_full = FullInfoEvidence::from_typed(&initial)?;
        let advertised = initial_stable.subjects_count;
        let maximum = self
            .ready
            .deployment_inputs
            .maximum_admitted_streams
            .checked_add(1)
            .ok_or(WitnessStoreErrorV1::Bounds)?;
        let expected = self.expected_subjects()?;

        let mut iterator = self
            .stream
            .info_with_subjects(self.bucket_filter())
            .await
            .map_err(|_| WitnessStoreErrorV1::Unavailable)?;
        let mut subjects = ReadySubjectAccumulator::new(
            advertised,
            iterator.info.state.subjects_count,
            maximum,
            expected,
        )?;
        while let Some((subject, count)) = ready_iterator_page(iterator.try_next().await)? {
            subjects.observe(subject, count)?;
        }
        subjects.finish()?;
        let final_snapshot = self.closed_snapshot().await?;
        let final_stable = StableReadySnapshot::from_typed(&final_snapshot)?;
        let final_full = FullInfoEvidence::from_typed(&final_snapshot)?;
        validate_final_ready_snapshot(&initial_stable, &final_stable)?;
        self.validate_manifest_entry().await?;
        let mut stream_ids = self
            .ready
            .admission_set
            .entries
            .iter()
            .map(|entry| entry.stream_id.as_str())
            .collect::<Vec<_>>();
        stream_ids.sort_unstable();
        futures_util::stream::iter(stream_ids.into_iter().map(Ok::<_, WitnessStoreErrorV1>))
            .try_for_each_concurrent(
                Some(READY_ENTRY_VALIDATION_CONCURRENCY),
                |stream_id| async move {
                    self.read_validated_entry(stream_id).await?;
                    Ok(())
                },
            )
            .await?;
        let evidence = InspectionEvidence::new(Some(initial_full), Some(final_full))?;
        *self
            .inspection_evidence
            .lock()
            .map_err(|_| WitnessStoreErrorV1::Unavailable)? = Some(evidence);
        Ok(self.ready.clone())
    }

    async fn read_entry(
        &self,
        stream_id: &str,
    ) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1> {
        let (raw, envelope) = self.read_validated_entry(stream_id).await?;
        Ok(WitnessStoreReadResultV1::Entry {
            stream_id: stream_id.to_string(),
            revision: raw.sequence,
            envelope: Box::new(envelope),
        })
    }

    async fn compare_and_swap(
        &self,
        stream_id: &str,
        expected_revision: u64,
        expected_store_state_digest: &str,
        proposed_envelope: &WitnessStoreEnvelopeV1,
    ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1> {
        let (current_raw, current) = self.read_validated_entry(stream_id).await?;
        let proposed_digest = match validate_cas_transition(
            &self.ready,
            stream_id,
            expected_revision,
            expected_store_state_digest,
            current_raw.sequence,
            &current,
            proposed_envelope,
        ) {
            Ok(digest) => digest,
            Err(WitnessStoreErrorV1::Conflict) => {
                return Ok(WitnessStoreCasResultV1::Conflict {
                    stream_id: stream_id.to_string(),
                    observed_revision: current_raw.sequence,
                    observed_envelope: Box::new(current),
                });
            }
            Err(error) => return Err(error),
        };
        let proposed_bytes = proposed_envelope
            .canonical_bytes()
            .map_err(|_| WitnessStoreErrorV1::Corrupt)?;
        let ack = self
            .publish_cas(stream_id, expected_revision, proposed_bytes.clone())
            .await?;
        let acknowledgement = PostPublishAcknowledgement {
            stream: ack.stream,
            sequence: ack.sequence,
            duplicate: ack.duplicate,
        };
        let mut classification_input = PostPublishClassificationInput {
            stream_id: stream_id.to_string(),
            configured_stream: self.ready.bucket_configuration.stream_name.clone(),
            expected_previous_revision: expected_revision,
            current_revision: current_raw.sequence,
            proposed_bytes,
            proposed_digest,
            acknowledgement,
            confirmation: None,
        };
        if post_publish_ack_failure(&classification_input).is_some() {
            let PostPublishClassificationDecision::Complete(classification) =
                classify_post_publish(&classification_input)
            else {
                unreachable!("an invalid acknowledgement must terminate classification");
            };
            return Ok(classification.result);
        }
        #[cfg(debug_assertions)]
        if let Err(error) = self
            .wait_at_post_ack_barrier(
                &classification_input.acknowledgement,
                &classification_input.proposed_digest,
            )
            .await
        {
            classification_input.confirmation = Some(PostPublishConfirmation::Failed(error));
            let PostPublishClassificationDecision::Complete(classification) =
                classify_post_publish(&classification_input)
            else {
                unreachable!("a barrier failure must terminate classification");
            };
            return Ok(classification.result);
        }
        classification_input.confirmation =
            Some(match self.read_validated_entry(stream_id).await {
                Ok((raw, envelope)) => match envelope.signed_envelope_digest() {
                    Ok(envelope_digest) => PostPublishConfirmation::Authenticated {
                        sequence: raw.sequence,
                        expected_previous_revision: raw.expected_previous_revision,
                        payload: raw.payload,
                        envelope_digest,
                    },
                    Err(_) => PostPublishConfirmation::Failed(WitnessStoreErrorV1::Corrupt),
                },
                Err(error) => PostPublishConfirmation::Failed(error),
            });
        let PostPublishClassificationDecision::Complete(classification) =
            classify_post_publish(&classification_input)
        else {
            unreachable!("a supplied confirmation must terminate classification");
        };
        Ok(classification.result)
    }
}

fn fixed_kv_subject(bucket_name: &str, stream_key: &str) -> String {
    format!("$KV.{bucket_name}.{stream_key}")
}

fn fixed_kv_subject_filter(bucket_name: &str) -> String {
    format!("$KV.{bucket_name}.>")
}

fn exact_header<K>(headers: &HeaderMap, key: K) -> Result<&str, WitnessStoreErrorV1>
where
    K: async_nats::header::IntoHeaderName + Clone,
{
    let mut values = headers.get_all(key).map(HeaderValue::as_str);
    let value = values.next().ok_or(WitnessStoreErrorV1::Header)?;
    if values.next().is_some() {
        return Err(WitnessStoreErrorV1::Header);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{File, OpenOptions};
    use std::io::Write;

    use serde::{Deserialize, Serialize};
    use swarm_crypto::{DetachedSignature, Ed25519Signer, sha256_hex};
    use swarm_governance::persistence_protocol::*;
    use swarm_governance::witness_engine::WitnessStoredCandidateV1;
    use swarm_governance::witness_engine::store::in_memory::{
        InMemoryWitnessStore, ReferenceWitnessStoreModel, WitnessStoreFault,
    };
    use swarm_governance::witness_engine::store::proxy::WitnessStoreProxy;
    use swarm_governance::witness_engine::store::{
        WitnessAdmissionEntryV1, WitnessAdmissionSetV1, WitnessBucketAnchorV1,
        WitnessBucketConfigurationV1, WitnessBucketEpochV1, WitnessBucketManifestPhaseV1,
        WitnessBucketManifestV1, WitnessCompressionV1, WitnessDiscardPolicyV1,
        WitnessPersistenceSemanticsV1, WitnessRetentionPolicyV1, WitnessStorageTypeV1,
        WitnessStoreDeploymentInputsV1, WitnessStoreProxyFailureCodeV1,
        WitnessStoreProxyOperationV1, WitnessStoreProxyRequestBodyV1, WitnessStoreProxyRequestV1,
        WitnessStoreProxyResponseBodyV1, WitnessStoreProxyResponseV1,
        WitnessStreamInitializationRecordV1, WitnessStreamInitializationV1,
    };
    use swarm_governance::witness_service::{
        WitnessAdmissionRecordV1, WitnessCandidateVerifier, prepare_verified_candidate,
    };

    const SCENARIO_LEDGER_PATH_ENV: &str = "PHASE285_WITNESS_SCENARIO_LEDGER";
    const SCENARIO_LEDGER_REQUIRED_ENV: &str = "PHASE285_WITNESS_SCENARIO_LEDGER_REQUIRED";
    const INNER_LEDGER_DOMAIN: &[u8] = b"swarm.phase285.witness-inner-ledger-row.v1";
    const SCENARIO_LEDGER_CASE: &str = "jetstream-cas-scenarios";
    const ITERATOR_LEDGER_PATH_ENV: &str = "PHASE285_WITNESS_ITERATOR_LEDGER";
    const ITERATOR_LEDGER_REQUIRED_ENV: &str = "PHASE285_WITNESS_ITERATOR_LEDGER_REQUIRED";
    const ITERATOR_LEDGER_TOKEN_ENV: &str = "PHASE285_WITNESS_ITERATOR_TOKEN";
    const ITERATOR_LEDGER_TREE_ENV: &str = "PHASE285_WITNESS_ITERATOR_TREE";
    const ITERATOR_LEDGER_CASE: &str = "jetstream-checkpoint-iterator";
    const ITERATOR_LEDGER_DOMAIN: &[u8] = b"swarm.phase285.witness-iterator-ledger-row.v1";

    struct ScenarioLedger {
        path: Option<std::path::PathBuf>,
        required: bool,
        file: Option<File>,
        emitted: BTreeSet<String>,
    }

    impl ScenarioLedger {
        fn from_environment() -> Result<Self, std::io::Error> {
            let required = std::env::var(SCENARIO_LEDGER_REQUIRED_ENV).as_deref() == Ok("1");
            let path = std::env::var_os(SCENARIO_LEDGER_PATH_ENV).map(std::path::PathBuf::from);
            if required && path.is_none() {
                return Err(std::io::Error::other(
                    "checker-required Phase 285 scenario-ledger path is absent",
                ));
            }
            if let Some(path) = &path
                && (!path.is_absolute()
                    || path.exists()
                    || !path.parent().is_some_and(|p| p.is_dir()))
            {
                return Err(std::io::Error::other(
                    "Phase 285 scenario ledger must be a fresh absolute path",
                ));
            }
            Ok(Self {
                path,
                required,
                file: None,
                emitted: BTreeSet::new(),
            })
        }

        fn passed(&mut self, inner_id: &str) -> Result<(), std::io::Error> {
            if inner_id.is_empty()
                || !inner_id.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
                })
                || !self.emitted.insert(inner_id.to_string())
            {
                return Err(std::io::Error::other(
                    "invalid or duplicate Phase 285 scenario-ledger ID",
                ));
            }
            let Some(path) = &self.path else {
                return Ok(());
            };
            if self.file.is_none() {
                self.file = Some(OpenOptions::new().write(true).create_new(true).open(path)?);
            }
            let canonical = format!(
                "{{\"case\":\"{SCENARIO_LEDGER_CASE}\",\"inner_id\":\"{inner_id}\",\"status\":\"passed\"}}"
            );
            let mut digest = Sha256::new();
            digest.update(INNER_LEDGER_DOMAIN);
            digest.update(
                u64::try_from(canonical.len())
                    .map_err(std::io::Error::other)?
                    .to_be_bytes(),
            );
            digest.update(canonical.as_bytes());
            writeln!(
                self.file.as_mut().ok_or_else(|| {
                    std::io::Error::other("Phase 285 scenario ledger was not opened")
                })?,
                "{SCENARIO_LEDGER_CASE}\t{inner_id}\tpassed\t{}",
                hex::encode(digest.finalize())
            )?;
            Ok(())
        }

        fn finish(mut self) -> Result<(), std::io::Error> {
            if self.required && self.emitted.len() != 19 {
                return Err(std::io::Error::other(format!(
                    "Phase 285 scenario ledger cardinality mismatch: {}",
                    self.emitted.len()
                )));
            }
            if let Some(file) = &mut self.file {
                file.flush()?;
            } else if self.required {
                return Err(std::io::Error::other(
                    "required Phase 285 scenario ledger was not created",
                ));
            }
            Ok(())
        }
    }

    struct IteratorContractLedger {
        file: Option<File>,
        required: bool,
        invocation_token: String,
        tree: String,
        emitted: BTreeSet<String>,
    }

    impl IteratorContractLedger {
        fn from_environment() -> Result<Self, std::io::Error> {
            let required = std::env::var(ITERATOR_LEDGER_REQUIRED_ENV).as_deref() == Ok("1");
            let path = std::env::var_os(ITERATOR_LEDGER_PATH_ENV).map(std::path::PathBuf::from);
            if required && path.is_none() {
                return Err(std::io::Error::other(
                    "checker-required Phase 285 iterator-ledger path is absent",
                ));
            }
            let token = std::env::var(ITERATOR_LEDGER_TOKEN_ENV).unwrap_or_default();
            let tree = std::env::var(ITERATOR_LEDGER_TREE_ENV).unwrap_or_default();
            if required
                && (token.is_empty()
                    || tree.len() != 40
                    || !tree.bytes().all(|byte| byte.is_ascii_hexdigit()))
            {
                return Err(std::io::Error::other(
                    "Phase 285 iterator ledger token/tree binding is absent",
                ));
            }
            if let Some(path) = &path
                && (!path.is_absolute()
                    || path.exists()
                    || !path.parent().is_some_and(|parent| parent.is_dir()))
            {
                return Err(std::io::Error::other(
                    "Phase 285 iterator ledger must be a fresh absolute path",
                ));
            }
            let file = path
                .map(|path| OpenOptions::new().write(true).create_new(true).open(path))
                .transpose()?;
            Ok(Self {
                file,
                required,
                invocation_token: token,
                tree,
                emitted: BTreeSet::new(),
            })
        }

        fn passed(&mut self, inner_id: &str) -> Result<(), std::io::Error> {
            if !self.emitted.insert(inner_id.to_string()) {
                return Err(std::io::Error::other(
                    "duplicate Phase 285 iterator-ledger ID",
                ));
            }
            let Some(file) = &mut self.file else {
                return Ok(());
            };
            let canonical = format!(
                "{{\"accepted_tree\":\"{}\",\"case\":\"{ITERATOR_LEDGER_CASE}\",\"inner_id\":\"{inner_id}\",\"invocation_token\":\"{}\",\"status\":\"passed\"}}",
                self.tree, self.invocation_token,
            );
            let mut digest = Sha256::new();
            digest.update(ITERATOR_LEDGER_DOMAIN);
            digest.update(
                u64::try_from(canonical.len())
                    .map_err(std::io::Error::other)?
                    .to_be_bytes(),
            );
            digest.update(canonical.as_bytes());
            writeln!(
                file,
                "{ITERATOR_LEDGER_CASE}\t{inner_id}\tpassed\t{}\t{}\t{}",
                self.tree,
                self.invocation_token,
                hex::encode(digest.finalize())
            )?;
            Ok(())
        }

        fn finish(mut self) -> Result<(), std::io::Error> {
            if self.required && self.emitted.len() != 6 {
                return Err(std::io::Error::other(format!(
                    "Phase 285 iterator-ledger cardinality mismatch: {}",
                    self.emitted.len()
                )));
            }
            if let Some(file) = &mut self.file {
                file.flush()?;
            } else if self.required {
                return Err(std::io::Error::other(
                    "required Phase 285 iterator ledger was not created",
                ));
            }
            Ok(())
        }
    }

    fn classifier_input() -> PostPublishClassificationInput {
        PostPublishClassificationInput {
            stream_id: "stream-phase285".to_string(),
            configured_stream: "KV_phase285".to_string(),
            expected_previous_revision: 7,
            current_revision: 7,
            proposed_bytes: br#"{"store_generation":2}"#.to_vec(),
            proposed_digest: "a".repeat(64),
            acknowledgement: PostPublishAcknowledgement {
                stream: "KV_phase285".to_string(),
                sequence: 19,
                duplicate: false,
            },
            confirmation: Some(PostPublishConfirmation::Authenticated {
                sequence: 19,
                expected_previous_revision: 7,
                payload: br#"{"store_generation":2}"#.to_vec(),
                envelope_digest: "a".repeat(64),
            }),
        }
    }

    fn complete(input: &PostPublishClassificationInput) -> PostPublishClassification {
        let PostPublishClassificationDecision::Complete(classification) =
            classify_post_publish(input)
        else {
            panic!("test input omitted a required confirmation");
        };
        classification
    }

    #[derive(Serialize)]
    struct AuthorizationPreimage<'a> {
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

    fn scenario_roles() -> PublicationRoleIdentitiesV1 {
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

    fn scenario_binding(
        governance: &Ed25519Signer,
        witness: &Ed25519Signer,
    ) -> ProtocolResult<PublicationBindingV1> {
        let mut binding = PublicationBindingV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: "phase285-differential".to_string(),
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
            publication_roles: scenario_roles(),
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
        let signing_bytes = binding.signing_bytes()?;
        binding.binding_digest = binding.computed_digest()?;
        binding.binding_signature = governance.sign(&signing_bytes);
        binding.validate()?;
        Ok(binding)
    }

    fn scenario_mapping(roles: PublicationRoleIdentitiesV1) -> PublicationMappingV1 {
        PublicationMappingV1 {
            state_canonical: roles.state_canonical,
            state_staging: roles.state_staging,
            checkpoint_canonical: roles.checkpoint_canonical,
            checkpoint_staging: roles.checkpoint_staging,
            journal_primary: roles.journal_primary,
            journal_secondary: roles.journal_secondary,
        }
    }

    fn sign_scenario_payload(
        signer: &Ed25519Signer,
        domain: &str,
        binding: &PublicationBindingV1,
        payload: Vec<u8>,
        digest: String,
    ) -> ProtocolResult<DetachedSignature> {
        let preimage = SignedPayloadPreimageV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            domain: domain.to_string(),
            stream_id: binding.stream_id.clone(),
            binding_generation: binding.generation.clone(),
            binding_digest: binding.binding_digest.clone(),
            authority_pair: binding.authority_pair,
            byte_len: payload.len() as u64,
            digest,
            payload,
        };
        Ok(signer.sign(&preimage.canonical_bytes()?))
    }

    fn scenario_candidate(
        governance: &Ed25519Signer,
        binding: &PublicationBindingV1,
    ) -> ProtocolResult<CandidateV1> {
        let before = scenario_mapping(binding.publication_roles);
        let genesis = GenesisPredecessorV1::for_binding(binding);
        let state_payload = br#"{"state":1}"#.to_vec();
        let checkpoint_payload = br#"{"checkpoint":1}"#.to_vec();
        let state_digest = sha256_hex(&state_payload);
        let checkpoint_digest = sha256_hex(&checkpoint_payload);
        CandidatePreimageV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: binding.stream_id.clone(),
            predecessor_head: None,
            predecessor_head_digest: genesis.digest()?,
            predecessor_data_head_digest: genesis.data_head_digest()?,
            state_payload: state_payload.clone(),
            state_byte_len: state_payload.len() as u64,
            state_digest: state_digest.clone(),
            state_attestation: sign_scenario_payload(
                governance,
                STATE_PAYLOAD_DOMAIN_V1,
                binding,
                state_payload,
                state_digest,
            )?,
            checkpoint_payload: checkpoint_payload.clone(),
            checkpoint_byte_len: checkpoint_payload.len() as u64,
            checkpoint_digest: checkpoint_digest.clone(),
            checkpoint_attestation: sign_scenario_payload(
                governance,
                CHECKPOINT_PAYLOAD_DOMAIN_V1,
                binding,
                checkpoint_payload,
                checkpoint_digest,
            )?,
            publication_binding: binding.clone(),
            publication_mapping_before: before,
            publication_mapping_after: PublicationMappingV1 {
                state_canonical: before.state_staging,
                state_staging: before.state_canonical,
                checkpoint_canonical: before.checkpoint_staging,
                checkpoint_staging: before.checkpoint_canonical,
                journal_primary: before.journal_primary,
                journal_secondary: before.journal_secondary,
            },
            epoch: 0,
            sequence: 0,
            intent_counter: 1,
        }
        .build()
    }

    fn scenario_authorization(
        ephemeral: &Ed25519Signer,
        session: &WitnessSessionV1,
        txid: &str,
        request_digest: &str,
    ) -> ProtocolResult<WitnessSessionAuthorizationV1> {
        let preimage = AuthorizationPreimage {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: WitnessOperationV1::Prepare,
            stream_id: &session.stream_id,
            binding_digest: &session.binding_digest,
            txid,
            request_digest,
            session_generation: session.session_generation,
            session_commitment: &session.session_commitment,
            ephemeral_key_id: &session.ephemeral_key_id,
        };
        Ok(WitnessSessionAuthorizationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: WitnessOperationV1::Prepare,
            stream_id: session.stream_id.clone(),
            binding_digest: session.binding_digest.clone(),
            txid: txid.to_string(),
            request_digest: request_digest.to_string(),
            session_generation: session.session_generation,
            session_commitment: session.session_commitment.clone(),
            ephemeral_key_id: session.ephemeral_key_id.clone(),
            signature: ephemeral.sign(&canonical_wire_bytes(&preimage)?),
        })
    }

    fn scenario_rotation(
        governance: &Ed25519Signer,
        witness: &Ed25519Signer,
        binding: &PublicationBindingV1,
        empty: &WitnessStoreEnvelopeV1,
    ) -> ProtocolResult<WitnessStoreEnvelopeV1> {
        let mut request = WitnessSessionFenceRequestV1 {
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
        request.signature = governance.sign(&request.signing_bytes()?);
        let mut fence = WitnessSessionStateFenceV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            request,
            admission_digest: empty.admission_digest.clone(),
            bucket_epoch_digest: empty.bucket_epoch_digest.clone(),
            bucket_anchor_digest: "4".repeat(64),
            ready_manifest_digest: "5".repeat(64),
            store_state_digest: empty.store_state_digest()?,
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
        let ephemeral = Ed25519Signer::from_secret_material("phase285-differential-ephemeral");
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
        let mut rotated = empty.clone();
        rotated.session = Some(session);
        rotated.last_session_rotation = Some(receipt);
        rotated.store_generation = 1;
        rotated.signature = witness.sign(&rotated.signing_bytes()?);
        rotated.validate()?;
        Ok(rotated)
    }

    fn scenario_configuration(
        max_value_bytes: u64,
        max_bucket_bytes: u64,
    ) -> ProtocolResult<WitnessBucketConfigurationV1> {
        Ok(WitnessBucketConfigurationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            nats_server_version: "2.11.17".to_string(),
            nats_server_image_index_digest:
                "sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00"
                    .to_string(),
            stream_name: "KV_phase285_differential".to_string(),
            description: "Phase 285 external governance witness".to_string(),
            subjects: vec![fixed_kv_subject_filter("phase285_differential")],
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
                ("_nats.ver".to_string(), "2.11.17".to_string()),
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

    struct SemanticFixture {
        witness: Ed25519Signer,
        stream_id: String,
        ready: WitnessStoreReadyResultV1,
        empty: WitnessStoreEnvelopeV1,
        rotated: WitnessStoreEnvelopeV1,
        prepared: WitnessStoreEnvelopeV1,
        committed: WitnessStoreEnvelopeV1,
        aborted: WitnessStoreEnvelopeV1,
    }

    impl SemanticFixture {
        fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            let governance =
                Ed25519Signer::from_secret_material("phase285-differential-governance");
            let witness = Ed25519Signer::from_secret_material("phase285-differential-witness");
            let binding = scenario_binding(&governance, &witness)?;
            let stream_id = binding.stream_id.clone();
            let max_retained_bytes = 1_000_000;
            let mut admission = WitnessAdmissionRecordV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                stream_id: stream_id.clone(),
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
            admission.admission_digest = admission.computed_digest()?;
            admission.validate()?;
            let admission_entry = WitnessAdmissionEntryV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                admission: admission.clone(),
                governance_signer_public_key_hex: governance.public_key_hex().to_string(),
                max_state_bytes: 4_096,
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
            admission_set.admission_set_digest = admission_set.computed_digest()?;
            admission_set.validate()?;
            let deployment_inputs = WitnessStoreDeploymentInputsV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                max_manifest_bytes: 1_000_000,
                maximum_admitted_streams: 1,
                configured_replica_count: 1,
            };
            let required_bucket_bytes = 2 * (deployment_inputs.max_manifest_bytes + 65_536)
                + deployment_inputs.maximum_admitted_streams * 2 * (max_retained_bytes + 65_536);
            let configuration = scenario_configuration(
                max_retained_bytes.max(deployment_inputs.max_manifest_bytes),
                required_bucket_bytes,
            )?;
            configuration.validate()?;
            let configuration_digest = configuration.digest()?;
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
            let epoch_digest = epoch.digest()?;
            let initialization_digest = WitnessStreamInitializationV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                bucket_epoch_digest: epoch_digest.clone(),
                admission_digest: admission.admission_digest.clone(),
                stream_id: stream_id.clone(),
                witness_identity: admission.witness_identity.clone(),
                witness_key_id: admission.witness_key_id.clone(),
            }
            .digest()?;
            let mut empty = WitnessStoreEnvelopeV1 {
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
            empty.signature = witness.sign(&empty.signing_bytes()?);
            empty.validate()?;
            let rotated = scenario_rotation(&governance, &witness, &binding, &empty)?;
            let candidate = scenario_candidate(&governance, &binding)?;
            let request_digest = "c".repeat(64);
            let session = rotated
                .session
                .as_ref()
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            let authorization = scenario_authorization(
                &Ed25519Signer::from_secret_material("phase285-differential-ephemeral"),
                session,
                &candidate.txid,
                &request_digest,
            )?;
            let verified = WitnessCandidateVerifier::verify_prepare(
                &admission,
                &rotated,
                session,
                &authorization,
                None,
                &candidate,
                &request_digest,
                None,
            )?;
            let transition = prepare_verified_candidate(&rotated, verified)?;
            let signature = witness.sign(&transition.signing_bytes()?);
            let prepared = transition.seal(signature)?;
            let prepared_record = prepared
                .prepared
                .as_ref()
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            let built_candidate = prepared_record.candidate.build()?;
            let mut committed = prepared.clone();
            committed.predecessor = prepared.current.clone();
            committed.current = Some(WitnessStoredCandidateV1 {
                candidate: prepared_record.candidate.clone(),
                head: WitnessHeadV1::committed_from_candidate(&built_candidate)?,
            });
            committed.prepared = None;
            committed.store_generation += 1;
            committed.signature = witness.sign(&committed.signing_bytes()?);
            committed.validate()?;
            let mut aborted = prepared.clone();
            aborted.prepared = None;
            aborted.genesis_abort = Some(WitnessGenesisAbortedV1::from_prepared(
                &prepared_record.prepared,
                "phase285-differential-abort".to_string(),
            )?);
            aborted.store_generation += 1;
            aborted.signature = witness.sign(&aborted.signing_bytes()?);
            aborted.validate()?;
            let stream_key = witness_stream_key(&stream_id)?;
            let mut manifest = WitnessBucketManifestV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                bucket_epoch_digest: epoch_digest,
                bucket_configuration_digest: configuration_digest,
                admission_set_digest: admission_set.admission_set_digest.clone(),
                stream_keys: vec![stream_key.clone()],
                initialized_streams: BTreeMap::from([(
                    stream_key,
                    WitnessStreamInitializationRecordV1 {
                        schema_version: PROTOCOL_SCHEMA_VERSION,
                        stream_initialization_digest: initialization_digest,
                        empty_envelope_digest: empty.signed_envelope_digest()?,
                    },
                )]),
                phase: WitnessBucketManifestPhaseV1::Ready,
                witness_identity: admission.witness_identity.clone(),
                witness_key_id: admission.witness_key_id.clone(),
                signature: witness.sign(&[]),
            };
            manifest.signature = witness.sign(&manifest.signing_bytes()?);
            let mut anchor = WitnessBucketAnchorV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                epoch: epoch.clone(),
                nats_stream_created_at: "2026-08-25T00:00:00.000000000Z".to_string(),
                raw_stream_configuration_digest: sha256_hex(
                    b"phase285-differential-raw-configuration",
                ),
                ready_manifest_digest: manifest.digest()?,
                witness_key_id: admission.witness_key_id.clone(),
                signature: witness.sign(&[]),
            };
            anchor.signature = witness.sign(&anchor.signing_bytes()?);
            let ready = WitnessStoreReadyResultV1::new(
                anchor.nats_stream_created_at.clone(),
                configuration,
                epoch,
                anchor,
                admission_set,
                manifest,
                deployment_inputs,
            )?;
            Ok(Self {
                witness,
                stream_id,
                ready,
                empty,
                rotated,
                prepared,
                committed,
                aborted,
            })
        }

        fn resign(&self, envelope: &mut WitnessStoreEnvelopeV1) -> ProtocolResult<()> {
            let mut value = serde_json::to_value(&*envelope)
                .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
            value
                .as_object_mut()
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                .remove("signature")
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            let canonical = canonical_wire_bytes(&value)?;
            let mut signing_bytes =
                swarm_governance::witness_engine::WITNESS_STORE_SIGNED_DOMAIN_V1.to_vec();
            signing_bytes.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
            signing_bytes.extend_from_slice(&canonical);
            envelope.signature = self.witness.sign(&signing_bytes);
            Ok(())
        }

        fn entries(
            &self,
            revision: u64,
            envelope: WitnessStoreEnvelopeV1,
        ) -> BTreeMap<String, (u64, WitnessStoreEnvelopeV1)> {
            BTreeMap::from([(self.stream_id.clone(), (revision, envelope))])
        }

        fn proxy_request(
            &self,
            operation: WitnessStoreProxyOperationV1,
            body: WitnessStoreProxyRequestBodyV1,
        ) -> ProtocolResult<WitnessStoreProxyRequestV1> {
            let mut request = WitnessStoreProxyRequestV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation,
                request_nonce: "b".repeat(64),
                admission_digest: self.ready.admission_set.entries[0].admission_digest.clone(),
                bucket_epoch_digest: self.ready.bucket_epoch.digest()?,
                bucket_anchor_digest: self.ready.bucket_anchor.digest()?,
                body,
                request_digest: "0".repeat(64),
                witness_key_id: self.witness.key_id().to_string(),
                signature: self.witness.sign(&[]),
            };
            request.request_digest = request.computed_digest()?;
            request.signature = self.witness.sign(&request.signing_bytes()?);
            Ok(request)
        }
    }

    #[test]
    fn nineteen_row_fixture_contains_all_real_transition_shapes()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fixture = SemanticFixture::new()?;
        fixture.empty.validate()?;
        fixture.rotated.validate()?;
        fixture.prepared.validate()?;
        fixture.committed.validate()?;
        fixture.aborted.validate()?;
        assert!(fixture.empty.session.is_none());
        assert!(fixture.rotated.session.is_some());
        assert!(fixture.prepared.prepared.is_some());
        assert!(fixture.committed.current.is_some());
        assert!(fixture.aborted.genesis_abort.is_some());
        Ok(())
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DifferentialScenario {
        Genesis,
        Rotation,
        SealedPrepare,
        Commit,
        Abort,
        Read,
        Conflict,
        ExactIdempotentObservation,
        ResignedContent,
        ResignedStaleSession,
        ResignedAdmission,
        ComponentLimit,
        Capacity,
        CrashBeforeCas,
        LostAfterCas,
        WrongRevisionAck,
        DuplicateAck,
        CorruptRead,
        InjectedCapacity,
    }

    const DIFFERENTIAL_SCENARIOS: [(&str, DifferentialScenario); 19] = [
        ("genesis", DifferentialScenario::Genesis),
        ("rotation", DifferentialScenario::Rotation),
        ("sealed_prepare", DifferentialScenario::SealedPrepare),
        ("commit", DifferentialScenario::Commit),
        ("abort", DifferentialScenario::Abort),
        ("read", DifferentialScenario::Read),
        ("conflict", DifferentialScenario::Conflict),
        (
            "exact_idempotent_observation",
            DifferentialScenario::ExactIdempotentObservation,
        ),
        ("resigned_content", DifferentialScenario::ResignedContent),
        (
            "resigned_stale_session",
            DifferentialScenario::ResignedStaleSession,
        ),
        (
            "resigned_admission",
            DifferentialScenario::ResignedAdmission,
        ),
        ("component_limit", DifferentialScenario::ComponentLimit),
        ("capacity", DifferentialScenario::Capacity),
        ("crash_before_cas", DifferentialScenario::CrashBeforeCas),
        ("lost_after_cas", DifferentialScenario::LostAfterCas),
        ("wrong_revision_ack", DifferentialScenario::WrongRevisionAck),
        ("duplicate_ack", DifferentialScenario::DuplicateAck),
        ("corrupt_read", DifferentialScenario::CorruptRead),
        ("injected_capacity", DifferentialScenario::InjectedCapacity),
    ];

    struct ScenarioSetup {
        entries: BTreeMap<String, (u64, WitnessStoreEnvelopeV1)>,
        expected_revision: u64,
        proposed: Option<WitnessStoreEnvelopeV1>,
        capacity: usize,
        fault: Option<WitnessStoreFault>,
        read_only: bool,
        repeat_after_apply: bool,
    }

    impl SemanticFixture {
        fn setup(
            &self,
            scenario: DifferentialScenario,
        ) -> Result<ScenarioSetup, Box<dyn std::error::Error + Send + Sync>> {
            let (revision, current, mut proposed) = match scenario {
                DifferentialScenario::Genesis => (6, self.empty.clone(), None),
                DifferentialScenario::Rotation => {
                    (6, self.empty.clone(), Some(self.rotated.clone()))
                }
                DifferentialScenario::Commit => {
                    (8, self.prepared.clone(), Some(self.committed.clone()))
                }
                DifferentialScenario::Abort => {
                    (8, self.prepared.clone(), Some(self.aborted.clone()))
                }
                _ => (7, self.rotated.clone(), Some(self.prepared.clone())),
            };
            if let Some(mutant) = proposed.as_mut() {
                match scenario {
                    DifferentialScenario::ResignedContent => {
                        mutant
                            .prepared
                            .as_mut()
                            .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                            .candidate
                            .state_payload = br#"{"state":"resigned-content"}"#.to_vec();
                        self.resign(mutant)?;
                    }
                    DifferentialScenario::ResignedStaleSession => {
                        mutant
                            .prepared
                            .as_mut()
                            .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                            .prepared
                            .session_generation += 1;
                        self.resign(mutant)?;
                    }
                    DifferentialScenario::ResignedAdmission => {
                        mutant.admission_digest = "e".repeat(64);
                        self.resign(mutant)?;
                    }
                    DifferentialScenario::ComponentLimit => {
                        let max_state_bytes = self.ready.admission_set.entries[0].max_state_bytes;
                        let state_payload = serde_json::to_vec(
                            &"x".repeat(
                                max_state_bytes
                                    .checked_sub(1)
                                    .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                                    as usize,
                            ),
                        )
                        .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
                        if state_payload.len() as u64 != max_state_bytes + 1 {
                            return Err(ProtocolError::WitnessOutcomeMismatch.into());
                        }
                        let stored = mutant
                            .prepared
                            .as_mut()
                            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
                        stored.candidate.state_payload = state_payload.clone();
                        stored.candidate.state_byte_len = state_payload.len() as u64;
                        stored.candidate.state_digest = sha256_hex(&state_payload);
                        let governance =
                            Ed25519Signer::from_secret_material("phase285-differential-governance");
                        stored.candidate.state_attestation = sign_scenario_payload(
                            &governance,
                            STATE_PAYLOAD_DOMAIN_V1,
                            &stored.candidate.publication_binding,
                            state_payload,
                            stored.candidate.state_digest.clone(),
                        )?;
                        let rebuilt = stored.candidate.build()?;
                        stored.prepared = WitnessPreparedV1::from_candidate(
                            &rebuilt,
                            rebuilt.preimage.predecessor_head.clone(),
                            stored.prepared.session_generation,
                        )?;
                        self.resign(mutant)?;
                    }
                    _ => {}
                }
            }
            let entries = self.entries(revision, current);
            let capacity = if scenario == DifferentialScenario::Capacity {
                canonical_wire_bytes(&entries)?.len()
            } else {
                1_000_000
            };
            let fault = match scenario {
                DifferentialScenario::CrashBeforeCas => Some(WitnessStoreFault::CrashBeforeCas),
                DifferentialScenario::LostAfterCas => Some(WitnessStoreFault::LostAfterCas),
                DifferentialScenario::WrongRevisionAck => Some(WitnessStoreFault::WrongRevision),
                DifferentialScenario::DuplicateAck => Some(WitnessStoreFault::DuplicateAck),
                DifferentialScenario::CorruptRead => Some(WitnessStoreFault::CorruptRead),
                DifferentialScenario::InjectedCapacity => {
                    Some(WitnessStoreFault::CapacityExhaustion)
                }
                _ => None,
            };
            Ok(ScenarioSetup {
                entries,
                expected_revision: if scenario == DifferentialScenario::Conflict {
                    revision.saturating_sub(1)
                } else {
                    revision
                },
                proposed,
                capacity,
                fault,
                read_only: matches!(
                    scenario,
                    DifferentialScenario::Genesis
                        | DifferentialScenario::Read
                        | DifferentialScenario::CorruptRead
                ),
                repeat_after_apply: scenario == DifferentialScenario::ExactIdempotentObservation,
            })
        }
    }

    #[derive(Debug)]
    struct RecordingStore {
        inner: InMemoryWitnessStore,
        last_cas: Mutex<Option<Result<WitnessStoreCasResultV1, WitnessStoreErrorV1>>>,
        reads: Mutex<Vec<Result<WitnessStoreReadResultV1, WitnessStoreErrorV1>>>,
    }

    impl RecordingStore {
        fn new(inner: InMemoryWitnessStore) -> Self {
            Self {
                inner,
                last_cas: Mutex::new(None),
                reads: Mutex::new(Vec::new()),
            }
        }

        fn take_last_cas(
            &self,
        ) -> Result<Option<Result<WitnessStoreCasResultV1, WitnessStoreErrorV1>>, WitnessStoreErrorV1>
        {
            self.last_cas
                .lock()
                .map_err(|_| WitnessStoreErrorV1::Unavailable)
                .map(|mut value| value.take())
        }

        fn canonical_store_bytes(&self) -> Result<Vec<u8>, WitnessStoreErrorV1> {
            self.inner.canonical_store_bytes()
        }

        fn take_reads(
            &self,
        ) -> Result<Vec<Result<WitnessStoreReadResultV1, WitnessStoreErrorV1>>, WitnessStoreErrorV1>
        {
            self.reads
                .lock()
                .map_err(|_| WitnessStoreErrorV1::Unavailable)
                .map(|mut reads| std::mem::take(&mut *reads))
        }
    }

    #[async_trait]
    impl WitnessAtomicStore for RecordingStore {
        async fn inspect_ready(&self) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1> {
            self.inner.inspect_ready().await
        }

        async fn read_entry(
            &self,
            stream_id: &str,
        ) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1> {
            let result = self.inner.read_entry(stream_id).await;
            self.reads
                .lock()
                .map_err(|_| WitnessStoreErrorV1::Unavailable)?
                .push(result.clone());
            result
        }

        async fn compare_and_swap(
            &self,
            stream_id: &str,
            expected_revision: u64,
            expected_store_state_digest: &str,
            proposed_envelope: &WitnessStoreEnvelopeV1,
        ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1> {
            let result = self
                .inner
                .compare_and_swap(
                    stream_id,
                    expected_revision,
                    expected_store_state_digest,
                    proposed_envelope,
                )
                .await;
            *self
                .last_cas
                .lock()
                .map_err(|_| WitnessStoreErrorV1::Unavailable)? = Some(result.clone());
            result
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum NormalizedOutcomeKind {
        Read,
        Applied,
        Conflict,
        Refused,
        Ambiguous,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum NormalizedErrorKind {
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

    impl From<WitnessStoreErrorV1> for NormalizedErrorKind {
        fn from(value: WitnessStoreErrorV1) -> Self {
            match value {
                WitnessStoreErrorV1::Missing => Self::Missing,
                WitnessStoreErrorV1::Corrupt => Self::Corrupt,
                WitnessStoreErrorV1::Header => Self::Header,
                WitnessStoreErrorV1::Configuration => Self::Configuration,
                WitnessStoreErrorV1::Admission => Self::Admission,
                WitnessStoreErrorV1::Signature => Self::Signature,
                WitnessStoreErrorV1::Bounds => Self::Bounds,
                WitnessStoreErrorV1::Conflict => Self::Conflict,
                WitnessStoreErrorV1::Unavailable => Self::Unavailable,
                WitnessStoreErrorV1::Ambiguous => Self::Ambiguous,
            }
        }
    }

    impl From<WitnessStoreProxyFailureCodeV1> for NormalizedErrorKind {
        fn from(value: WitnessStoreProxyFailureCodeV1) -> Self {
            match value {
                WitnessStoreProxyFailureCodeV1::Missing => Self::Missing,
                WitnessStoreProxyFailureCodeV1::Corrupt => Self::Corrupt,
                WitnessStoreProxyFailureCodeV1::Header => Self::Header,
                WitnessStoreProxyFailureCodeV1::Configuration => Self::Configuration,
                WitnessStoreProxyFailureCodeV1::Admission => Self::Admission,
                WitnessStoreProxyFailureCodeV1::Signature => Self::Signature,
                WitnessStoreProxyFailureCodeV1::Bounds => Self::Bounds,
                WitnessStoreProxyFailureCodeV1::Conflict => Self::Conflict,
                WitnessStoreProxyFailureCodeV1::Unavailable => Self::Unavailable,
                WitnessStoreProxyFailureCodeV1::Ambiguous => Self::Ambiguous,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum RevisionRelation {
        Less,
        Equal,
        Greater,
    }

    fn revision_relation(observed: u64, expected: u64) -> RevisionRelation {
        match observed.cmp(&expected) {
            std::cmp::Ordering::Less => RevisionRelation::Less,
            std::cmp::Ordering::Equal => RevisionRelation::Equal,
            std::cmp::Ordering::Greater => RevisionRelation::Greater,
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NormalizedConflictMetadata {
        observed_revision_relation: RevisionRelation,
        observed_envelope_bytes: Vec<u8>,
        observed_envelope_digest: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NormalizedBackendReportedObservation {
        observed_revision_relation: Option<RevisionRelation>,
        observed_value_digest: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
    enum NormalizedAuthenticatedDiagnostic {
        NotAttempted,
        Failed {
            error_kind: NormalizedErrorKind,
        },
        Authenticated {
            observed_revision_relation: RevisionRelation,
            observed_value_digest: String,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NormalizedAmbiguityMetadata {
        expected_previous_relation: RevisionRelation,
        backend_reported: NormalizedBackendReportedObservation,
        authenticated_diagnostic: NormalizedAuthenticatedDiagnostic,
        cause: NormalizedAmbiguityCause,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum NormalizedAmbiguityCause {
        AckStreamMismatch,
        DuplicateAcknowledgement,
        NonIncreasingAcknowledgement,
        ConfirmationFailure(NormalizedErrorKind),
        ConfirmationMismatch,
        StoreReported,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NormalizedRefusalBytes {
        before: Vec<u8>,
        after: Vec<u8>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NormalizedScenarioRecord {
        id: String,
        outcome: NormalizedOutcomeKind,
        error_kind: Option<NormalizedErrorKind>,
        stream_id: String,
        previous_revision_relation: Option<RevisionRelation>,
        strictly_increasing_new_revision: Option<bool>,
        acknowledged_digest: Option<String>,
        duplicate: Option<bool>,
        conflict: Option<NormalizedConflictMetadata>,
        ambiguity: Option<NormalizedAmbiguityMetadata>,
        read_envelope_bytes: Option<Vec<u8>>,
        final_envelope_bytes: Vec<u8>,
        final_envelope_digest: String,
        refusal_bytes: Option<NormalizedRefusalBytes>,
    }

    impl NormalizedScenarioRecord {
        fn validate(&self) -> Result<(), WitnessStoreErrorV1> {
            if self.id.is_empty() || self.stream_id.is_empty() {
                return Err(WitnessStoreErrorV1::Corrupt);
            }
            let final_envelope = WitnessStoreEnvelopeV1::decode(&self.final_envelope_bytes)
                .map_err(|_| WitnessStoreErrorV1::Corrupt)?;
            if final_envelope.stream_id != self.stream_id
                || final_envelope
                    .signed_envelope_digest()
                    .map_err(|_| WitnessStoreErrorV1::Corrupt)?
                    != self.final_envelope_digest
            {
                return Err(WitnessStoreErrorV1::Corrupt);
            }
            if self.outcome == NormalizedOutcomeKind::Applied
                && !(self.previous_revision_relation.is_some()
                    && self.strictly_increasing_new_revision == Some(true)
                    && self.acknowledged_digest.is_some()
                    && self.duplicate == Some(false))
            {
                return Err(WitnessStoreErrorV1::Corrupt);
            }
            if (self.outcome == NormalizedOutcomeKind::Conflict) != self.conflict.is_some()
                || (self.outcome == NormalizedOutcomeKind::Ambiguous) != self.ambiguity.is_some()
                || (matches!(
                    self.outcome,
                    NormalizedOutcomeKind::Conflict | NormalizedOutcomeKind::Refused
                ) != self.refusal_bytes.is_some())
                || (self.outcome == NormalizedOutcomeKind::Refused) != self.error_kind.is_some()
            {
                return Err(WitnessStoreErrorV1::Corrupt);
            }
            if let Some(bytes) = &self.refusal_bytes
                && bytes.before != bytes.after
            {
                return Err(WitnessStoreErrorV1::Corrupt);
            }
            if self.outcome == NormalizedOutcomeKind::Read && self.read_envelope_bytes.is_none() {
                return Err(WitnessStoreErrorV1::Corrupt);
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone)]
    enum ExecutedBackendOperation {
        Read(Result<WitnessStoreReadResultV1, WitnessStoreErrorV1>),
        Cas(Result<WitnessStoreCasResultV1, WitnessStoreErrorV1>),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ExecutedAcknowledgementEvidence {
        stream_matches: bool,
        sequence_relation: RevisionRelation,
        acknowledged_digest: String,
        duplicate: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum ExecutedDiagnosticEvidence {
        Authenticated {
            observed_revision: u64,
            observed_value_digest: String,
        },
        Failed(NormalizedErrorKind),
        NotAttempted,
    }

    #[derive(Debug, Clone)]
    enum ExecutedDiagnosticCall {
        NotAttempted,
        Attempted(Result<WitnessStoreReadResultV1, WitnessStoreErrorV1>),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct BackendAmbiguityObservation {
        observed_revision: Option<u64>,
        observed_value_digest: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    struct BackendExecutionEvidence {
        acknowledgement: Option<ExecutedAcknowledgementEvidence>,
        authenticated_diagnostic: Option<ExecutedDiagnosticEvidence>,
        ambiguity_cause: Option<NormalizedAmbiguityCause>,
        backend_reported: Option<BackendAmbiguityObservation>,
        ambiguity_response_is_diagnostic: bool,
    }

    fn read_parts(value: WitnessStoreReadResultV1) -> (String, u64, WitnessStoreEnvelopeV1) {
        let WitnessStoreReadResultV1::Entry {
            stream_id,
            revision,
            envelope,
        } = value;
        (stream_id, revision, *envelope)
    }

    fn final_entry(
        value: Result<WitnessStoreReadResultV1, WitnessStoreErrorV1>,
    ) -> Result<(u64, WitnessStoreEnvelopeV1), WitnessStoreErrorV1> {
        let (stream_id, revision, envelope) = read_parts(value?);
        if stream_id != envelope.stream_id {
            return Err(WitnessStoreErrorV1::Corrupt);
        }
        Ok((revision, envelope))
    }

    fn executed_diagnostic_from_read(
        stream_id: &str,
        diagnostic_read: &Result<WitnessStoreReadResultV1, WitnessStoreErrorV1>,
    ) -> Result<ExecutedDiagnosticEvidence, WitnessStoreErrorV1> {
        match diagnostic_read {
            Ok(WitnessStoreReadResultV1::Entry {
                stream_id: observed_stream,
                revision,
                envelope,
            }) if observed_stream == stream_id => envelope
                .signed_envelope_digest()
                .map(
                    |observed_value_digest| ExecutedDiagnosticEvidence::Authenticated {
                        observed_revision: *revision,
                        observed_value_digest,
                    },
                )
                .map_err(|_| WitnessStoreErrorV1::Corrupt),
            Ok(_) => Err(WitnessStoreErrorV1::Corrupt),
            Err(error) => Ok(ExecutedDiagnosticEvidence::Failed((*error).into())),
        }
    }

    fn executed_diagnostic_from_call(
        stream_id: &str,
        call: ExecutedDiagnosticCall,
    ) -> Result<ExecutedDiagnosticEvidence, WitnessStoreErrorV1> {
        match call {
            ExecutedDiagnosticCall::NotAttempted => Ok(ExecutedDiagnosticEvidence::NotAttempted),
            ExecutedDiagnosticCall::Attempted(result) => {
                executed_diagnostic_from_read(stream_id, &result)
            }
        }
    }

    fn execution_evidence_from_backend(
        operation: &ExecutedBackendOperation,
        stream_id: &str,
        expected_revision: u64,
        prior_revision: u64,
        proposed: Option<&WitnessStoreEnvelopeV1>,
        diagnostic_call: ExecutedDiagnosticCall,
    ) -> Result<BackendExecutionEvidence, WitnessStoreErrorV1> {
        let mut evidence = BackendExecutionEvidence::default();
        let ExecutedBackendOperation::Cas(result) = operation else {
            return Ok(evidence);
        };
        let authenticated_diagnostic =
            || executed_diagnostic_from_call(stream_id, diagnostic_call.clone());
        match result {
            Ok(WitnessStoreCasResultV1::Applied {
                stream_id: ack_stream,
                expected_previous_revision: _,
                previous_revision: _,
                new_revision,
                acknowledged_value_digest,
                duplicate,
            }) => {
                evidence.acknowledgement = Some(ExecutedAcknowledgementEvidence {
                    stream_matches: ack_stream == stream_id,
                    sequence_relation: revision_relation(*new_revision, prior_revision),
                    acknowledged_digest: acknowledged_value_digest.clone(),
                    duplicate: *duplicate,
                });
                if ack_stream != stream_id {
                    evidence.authenticated_diagnostic =
                        Some(ExecutedDiagnosticEvidence::NotAttempted);
                    evidence.ambiguity_cause = Some(NormalizedAmbiguityCause::AckStreamMismatch);
                } else if *duplicate {
                    evidence.authenticated_diagnostic =
                        Some(ExecutedDiagnosticEvidence::NotAttempted);
                    evidence.ambiguity_cause =
                        Some(NormalizedAmbiguityCause::DuplicateAcknowledgement);
                } else if *new_revision <= prior_revision {
                    evidence.authenticated_diagnostic =
                        Some(ExecutedDiagnosticEvidence::NotAttempted);
                    evidence.ambiguity_cause =
                        Some(NormalizedAmbiguityCause::NonIncreasingAcknowledgement);
                } else {
                    let diagnostic = authenticated_diagnostic()?;
                    let confirmed = matches!(
                        (&diagnostic, proposed),
                        (
                            ExecutedDiagnosticEvidence::Authenticated {
                                observed_revision,
                                observed_value_digest,
                            },
                            Some(proposed),
                        ) if observed_revision == new_revision
                            && observed_value_digest == acknowledged_value_digest
                            && proposed.signed_envelope_digest().ok()
                                == Some(observed_value_digest.clone())
                    );
                    evidence.authenticated_diagnostic = Some(diagnostic);
                    if !confirmed {
                        evidence.ambiguity_cause =
                            Some(NormalizedAmbiguityCause::ConfirmationMismatch);
                    }
                }
                if evidence.ambiguity_cause.is_some() {
                    evidence.backend_reported = Some(BackendAmbiguityObservation {
                        observed_revision: Some(*new_revision),
                        observed_value_digest: Some(acknowledged_value_digest.clone()),
                    });
                }
            }
            Ok(WitnessStoreCasResultV1::Ambiguous {
                expected_previous_revision,
                observed_revision,
                observed_value_digest,
                ..
            }) => {
                evidence.authenticated_diagnostic = Some(authenticated_diagnostic()?);
                evidence.ambiguity_cause = Some(NormalizedAmbiguityCause::ConfirmationFailure(
                    NormalizedErrorKind::Ambiguous,
                ));
                evidence.backend_reported = Some(BackendAmbiguityObservation {
                    observed_revision: *observed_revision,
                    observed_value_digest: observed_value_digest.clone(),
                });
                if *expected_previous_revision != expected_revision {
                    return Err(WitnessStoreErrorV1::Corrupt);
                }
                if observed_revision == &Some(0)
                    || observed_value_digest
                        .as_ref()
                        .is_some_and(|digest| digest.len() != 64)
                {
                    return Err(WitnessStoreErrorV1::Corrupt);
                }
            }
            Ok(WitnessStoreCasResultV1::Conflict { .. }) | Err(_) => {}
        }
        Ok(evidence)
    }

    fn operation_attempts_diagnostic(
        operation: &ExecutedBackendOperation,
        stream_id: &str,
        prior_revision: u64,
    ) -> bool {
        match operation {
            ExecutedBackendOperation::Cas(Ok(WitnessStoreCasResultV1::Applied {
                stream_id: ack_stream,
                new_revision,
                duplicate,
                ..
            })) => ack_stream == stream_id && !duplicate && *new_revision > prior_revision,
            ExecutedBackendOperation::Cas(Ok(WitnessStoreCasResultV1::Ambiguous { .. })) => true,
            _ => false,
        }
    }

    struct NormalizationContext<'a> {
        id: &'a str,
        stream_id: &'a str,
        expected_revision: u64,
        prior_revision: u64,
        prior: &'a WitnessStoreEnvelopeV1,
        proposed: Option<&'a WitnessStoreEnvelopeV1>,
    }

    fn validate_execution_evidence(
        _operation: &ExecutedBackendOperation,
        evidence: &BackendExecutionEvidence,
    ) -> Result<(), WitnessStoreErrorV1> {
        if evidence.ambiguity_cause.is_some()
            && (evidence.backend_reported.is_none() || evidence.authenticated_diagnostic.is_none())
        {
            return Err(WitnessStoreErrorV1::Corrupt);
        }
        Ok(())
    }

    fn normalize_backend_record(
        context: NormalizationContext<'_>,
        operation: ExecutedBackendOperation,
        execution_evidence: BackendExecutionEvidence,
        final_read: Result<WitnessStoreReadResultV1, WitnessStoreErrorV1>,
    ) -> Result<NormalizedScenarioRecord, WitnessStoreErrorV1> {
        validate_execution_evidence(&operation, &execution_evidence)?;
        let (final_revision, final_envelope) = final_entry(final_read)?;
        let final_envelope_bytes = final_envelope
            .canonical_bytes()
            .map_err(|_| WitnessStoreErrorV1::Corrupt)?;
        let final_envelope_digest = final_envelope
            .signed_envelope_digest()
            .map_err(|_| WitnessStoreErrorV1::Corrupt)?;
        let before = context
            .prior
            .canonical_bytes()
            .map_err(|_| WitnessStoreErrorV1::Corrupt)?;
        let normalize_ambiguity_observations = |backend: BackendAmbiguityObservation,
                                                diagnostic: ExecutedDiagnosticEvidence|
         -> Result<
            (
                NormalizedBackendReportedObservation,
                NormalizedAuthenticatedDiagnostic,
            ),
            WitnessStoreErrorV1,
        > {
            let backend_reported = NormalizedBackendReportedObservation {
                observed_revision_relation: backend
                    .observed_revision
                    .map(|revision| revision_relation(revision, context.expected_revision)),
                observed_value_digest: backend.observed_value_digest,
            };
            let authenticated_diagnostic = match diagnostic {
                ExecutedDiagnosticEvidence::NotAttempted => {
                    NormalizedAuthenticatedDiagnostic::NotAttempted
                }
                ExecutedDiagnosticEvidence::Failed(error_kind) => {
                    NormalizedAuthenticatedDiagnostic::Failed { error_kind }
                }
                ExecutedDiagnosticEvidence::Authenticated {
                    observed_revision,
                    observed_value_digest,
                } => {
                    if observed_revision != final_revision
                        || observed_value_digest != final_envelope_digest
                    {
                        return Err(WitnessStoreErrorV1::Corrupt);
                    }
                    NormalizedAuthenticatedDiagnostic::Authenticated {
                        observed_revision_relation: revision_relation(
                            observed_revision,
                            context.expected_revision,
                        ),
                        observed_value_digest,
                    }
                }
            };
            Ok((backend_reported, authenticated_diagnostic))
        };
        let mut record = NormalizedScenarioRecord {
            id: context.id.to_string(),
            outcome: NormalizedOutcomeKind::Refused,
            error_kind: None,
            stream_id: context.stream_id.to_string(),
            previous_revision_relation: None,
            strictly_increasing_new_revision: None,
            acknowledged_digest: None,
            duplicate: None,
            conflict: None,
            ambiguity: None,
            read_envelope_bytes: Some(before.clone()),
            final_envelope_bytes: final_envelope_bytes.clone(),
            final_envelope_digest: final_envelope_digest.clone(),
            refusal_bytes: None,
        };
        if let Some(acknowledgement) = &execution_evidence.acknowledgement {
            if !acknowledgement.stream_matches {
                record.outcome = NormalizedOutcomeKind::Ambiguous;
            }
            record.previous_revision_relation = Some(RevisionRelation::Equal);
            record.strictly_increasing_new_revision =
                Some(acknowledgement.sequence_relation == RevisionRelation::Greater);
            record.acknowledged_digest = Some(acknowledgement.acknowledged_digest.clone());
            record.duplicate = Some(acknowledgement.duplicate);
        }
        match operation {
            ExecutedBackendOperation::Read(result) => match result {
                Ok(entry) => {
                    let (observed_stream, _, envelope) = read_parts(entry);
                    if observed_stream != context.stream_id || envelope != final_envelope {
                        return Err(WitnessStoreErrorV1::Corrupt);
                    }
                    record.outcome = NormalizedOutcomeKind::Read;
                    record.read_envelope_bytes = Some(
                        envelope
                            .canonical_bytes()
                            .map_err(|_| WitnessStoreErrorV1::Corrupt)?,
                    );
                }
                Err(error) => {
                    record.error_kind = Some(error.into());
                    record.refusal_bytes = Some(NormalizedRefusalBytes {
                        before,
                        after: final_envelope_bytes,
                    });
                    record.read_envelope_bytes = None;
                }
            },
            ExecutedBackendOperation::Cas(result) => match result {
                Ok(WitnessStoreCasResultV1::Applied {
                    stream_id: observed_stream,
                    expected_previous_revision,
                    previous_revision,
                    new_revision,
                    acknowledged_value_digest,
                    duplicate,
                }) => {
                    let proposed = context.proposed.ok_or(WitnessStoreErrorV1::Corrupt)?;
                    let proposed_bytes = proposed
                        .canonical_bytes()
                        .map_err(|_| WitnessStoreErrorV1::Corrupt)?;
                    let proposed_digest = proposed
                        .signed_envelope_digest()
                        .map_err(|_| WitnessStoreErrorV1::Corrupt)?;
                    record.previous_revision_relation = Some(revision_relation(
                        previous_revision,
                        context.expected_revision,
                    ));
                    record.strictly_increasing_new_revision =
                        Some(new_revision > previous_revision);
                    record.acknowledged_digest = Some(acknowledged_value_digest.clone());
                    record.duplicate = Some(duplicate);
                    let valid = observed_stream == context.stream_id
                        && expected_previous_revision == context.expected_revision
                        && previous_revision == context.prior_revision
                        && new_revision > context.prior_revision
                        && !duplicate
                        && acknowledged_value_digest == proposed_digest
                        && final_revision == new_revision
                        && final_envelope_bytes == proposed_bytes;
                    if valid {
                        record.outcome = NormalizedOutcomeKind::Applied;
                    } else {
                        let backend = execution_evidence
                            .backend_reported
                            .ok_or(WitnessStoreErrorV1::Corrupt)?;
                        let diagnostic = execution_evidence
                            .authenticated_diagnostic
                            .ok_or(WitnessStoreErrorV1::Corrupt)?;
                        let (backend_reported, authenticated_diagnostic) =
                            normalize_ambiguity_observations(backend, diagnostic)?;
                        record.outcome = NormalizedOutcomeKind::Ambiguous;
                        record.ambiguity = Some(NormalizedAmbiguityMetadata {
                            expected_previous_relation: revision_relation(
                                expected_previous_revision,
                                context.expected_revision,
                            ),
                            backend_reported,
                            authenticated_diagnostic,
                            cause: execution_evidence
                                .ambiguity_cause
                                .ok_or(WitnessStoreErrorV1::Corrupt)?,
                        });
                    }
                }
                Ok(WitnessStoreCasResultV1::Conflict {
                    stream_id: observed_stream,
                    observed_revision,
                    observed_envelope,
                }) => {
                    if observed_stream != context.stream_id || *observed_envelope != final_envelope
                    {
                        return Err(WitnessStoreErrorV1::Corrupt);
                    }
                    let conflict_bytes = observed_envelope
                        .canonical_bytes()
                        .map_err(|_| WitnessStoreErrorV1::Corrupt)?;
                    record.outcome = NormalizedOutcomeKind::Conflict;
                    record.error_kind = None;
                    record.conflict = Some(NormalizedConflictMetadata {
                        observed_revision_relation: revision_relation(
                            observed_revision,
                            context.expected_revision,
                        ),
                        observed_envelope_bytes: conflict_bytes,
                        observed_envelope_digest: observed_envelope
                            .signed_envelope_digest()
                            .map_err(|_| WitnessStoreErrorV1::Corrupt)?,
                    });
                    record.refusal_bytes = Some(NormalizedRefusalBytes {
                        before,
                        after: final_envelope_bytes,
                    });
                }
                Ok(WitnessStoreCasResultV1::Ambiguous {
                    stream_id: observed_stream,
                    expected_previous_revision,
                    observed_revision: diagnostic_revision,
                    observed_value_digest: diagnostic_digest,
                }) => {
                    if observed_stream != context.stream_id {
                        return Err(WitnessStoreErrorV1::Corrupt);
                    }
                    let backend = execution_evidence
                        .backend_reported
                        .ok_or(WitnessStoreErrorV1::Corrupt)?;
                    let diagnostic = execution_evidence
                        .authenticated_diagnostic
                        .ok_or(WitnessStoreErrorV1::Corrupt)?;
                    let response_pair = (diagnostic_revision, diagnostic_digest.clone());
                    if execution_evidence.ambiguity_response_is_diagnostic {
                        let expected_pair = match &diagnostic {
                            ExecutedDiagnosticEvidence::Authenticated {
                                observed_revision,
                                observed_value_digest,
                            } => (
                                Some(*observed_revision),
                                Some(observed_value_digest.clone()),
                            ),
                            ExecutedDiagnosticEvidence::Failed(_)
                            | ExecutedDiagnosticEvidence::NotAttempted => (None, None),
                        };
                        if response_pair != expected_pair {
                            return Err(WitnessStoreErrorV1::Corrupt);
                        }
                    } else if response_pair
                        != (
                            backend.observed_revision,
                            backend.observed_value_digest.clone(),
                        )
                    {
                        return Err(WitnessStoreErrorV1::Corrupt);
                    }
                    let (backend_reported, authenticated_diagnostic) =
                        normalize_ambiguity_observations(backend, diagnostic)?;
                    record.outcome = NormalizedOutcomeKind::Ambiguous;
                    record.ambiguity = Some(NormalizedAmbiguityMetadata {
                        expected_previous_relation: revision_relation(
                            expected_previous_revision,
                            context.expected_revision,
                        ),
                        backend_reported,
                        authenticated_diagnostic,
                        cause: execution_evidence
                            .ambiguity_cause
                            .ok_or(WitnessStoreErrorV1::Corrupt)?,
                    });
                }
                Err(error) => {
                    record.error_kind = Some(error.into());
                    record.refusal_bytes = Some(NormalizedRefusalBytes {
                        before,
                        after: final_envelope_bytes,
                    });
                }
            },
        }
        record.validate()?;
        Ok(record)
    }

    fn failure_to_store_error(value: WitnessStoreProxyFailureCodeV1) -> WitnessStoreErrorV1 {
        match value {
            WitnessStoreProxyFailureCodeV1::Missing => WitnessStoreErrorV1::Missing,
            WitnessStoreProxyFailureCodeV1::Corrupt => WitnessStoreErrorV1::Corrupt,
            WitnessStoreProxyFailureCodeV1::Header => WitnessStoreErrorV1::Header,
            WitnessStoreProxyFailureCodeV1::Configuration => WitnessStoreErrorV1::Configuration,
            WitnessStoreProxyFailureCodeV1::Admission => WitnessStoreErrorV1::Admission,
            WitnessStoreProxyFailureCodeV1::Signature => WitnessStoreErrorV1::Signature,
            WitnessStoreProxyFailureCodeV1::Bounds => WitnessStoreErrorV1::Bounds,
            WitnessStoreProxyFailureCodeV1::Conflict => WitnessStoreErrorV1::Conflict,
            WitnessStoreProxyFailureCodeV1::Unavailable => WitnessStoreErrorV1::Unavailable,
            WitnessStoreProxyFailureCodeV1::Ambiguous => WitnessStoreErrorV1::Ambiguous,
        }
    }

    fn proxy_response_to_backend(
        read_only: bool,
        stream_id: &str,
        expected_revision: u64,
        final_revision: u64,
        final_envelope: &WitnessStoreEnvelopeV1,
        response: Result<WitnessStoreProxyResponseV1, WitnessStoreErrorV1>,
        recorded_cas: Option<Result<WitnessStoreCasResultV1, WitnessStoreErrorV1>>,
    ) -> ExecutedBackendOperation {
        let response = match response {
            Ok(response) => response.body,
            Err(error) => {
                return if read_only {
                    ExecutedBackendOperation::Read(Err(error))
                } else {
                    ExecutedBackendOperation::Cas(Err(error))
                };
            }
        };
        match response {
            WitnessStoreProxyResponseBodyV1::Entry {
                stream_id,
                revision,
                envelope,
            } => ExecutedBackendOperation::Read(Ok(WitnessStoreReadResultV1::Entry {
                stream_id,
                revision,
                envelope,
            })),
            WitnessStoreProxyResponseBodyV1::CasApplied {
                stream_id,
                previous_revision,
                new_revision,
                acknowledged_value_digest,
            } => {
                let projected = WitnessStoreCasResultV1::Applied {
                    stream_id,
                    expected_previous_revision: expected_revision,
                    previous_revision,
                    new_revision,
                    acknowledged_value_digest,
                    duplicate: false,
                };
                if recorded_cas.as_ref() != Some(&Ok(projected.clone())) {
                    ExecutedBackendOperation::Cas(Err(WitnessStoreErrorV1::Corrupt))
                } else {
                    ExecutedBackendOperation::Cas(Ok(projected))
                }
            }
            WitnessStoreProxyResponseBodyV1::Conflict {
                stream_id,
                observed_revision,
                observed_envelope,
            } => ExecutedBackendOperation::Cas(Ok(WitnessStoreCasResultV1::Conflict {
                stream_id,
                observed_revision,
                observed_envelope,
            })),
            WitnessStoreProxyResponseBodyV1::Refused {
                failure_code,
                observed_revision,
                observed_value_digest,
            } => match failure_code {
                WitnessStoreProxyFailureCodeV1::Conflict => {
                    match final_envelope.store_state_digest() {
                        Ok(final_digest)
                            if observed_revision == Some(final_revision)
                                && observed_value_digest.as_deref()
                                    == Some(final_digest.as_str()) =>
                        {
                            ExecutedBackendOperation::Cas(Ok(WitnessStoreCasResultV1::Conflict {
                                stream_id: stream_id.to_string(),
                                observed_revision: final_revision,
                                observed_envelope: Box::new(final_envelope.clone()),
                            }))
                        }
                        _ => ExecutedBackendOperation::Cas(Err(WitnessStoreErrorV1::Corrupt)),
                    }
                }
                WitnessStoreProxyFailureCodeV1::Ambiguous => {
                    ExecutedBackendOperation::Cas(Ok(WitnessStoreCasResultV1::Ambiguous {
                        stream_id: stream_id.to_string(),
                        expected_previous_revision: expected_revision,
                        observed_revision,
                        observed_value_digest,
                    }))
                }
                error => {
                    let error = failure_to_store_error(error);
                    if read_only {
                        ExecutedBackendOperation::Read(Err(error))
                    } else {
                        ExecutedBackendOperation::Cas(Err(error))
                    }
                }
            },
            WitnessStoreProxyResponseBodyV1::Ready { .. } => {
                if read_only {
                    ExecutedBackendOperation::Read(Err(WitnessStoreErrorV1::Corrupt))
                } else {
                    ExecutedBackendOperation::Cas(Err(WitnessStoreErrorV1::Corrupt))
                }
            }
        }
    }

    fn proxy_authenticated_diagnostic(
        operation: &ExecutedBackendOperation,
    ) -> Result<Option<ExecutedDiagnosticEvidence>, WitnessStoreErrorV1> {
        let ExecutedBackendOperation::Cas(Ok(WitnessStoreCasResultV1::Ambiguous {
            observed_revision,
            observed_value_digest,
            ..
        })) = operation
        else {
            return Ok(None);
        };
        match (observed_revision, observed_value_digest) {
            (Some(revision), Some(digest)) => Ok(Some(ExecutedDiagnosticEvidence::Authenticated {
                observed_revision: *revision,
                observed_value_digest: digest.clone(),
            })),
            (None, None) => Ok(Some(ExecutedDiagnosticEvidence::Failed(
                NormalizedErrorKind::Ambiguous,
            ))),
            _ => Err(WitnessStoreErrorV1::Corrupt),
        }
    }

    async fn direct_record(
        fixture: &SemanticFixture,
        id: &str,
        scenario: DifferentialScenario,
    ) -> Result<(NormalizedScenarioRecord, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        let setup = fixture.setup(scenario)?;
        let (mut prior_revision, mut prior) = setup
            .entries
            .get(&fixture.stream_id)
            .cloned()
            .ok_or(WitnessStoreErrorV1::Missing)?;
        let store =
            InMemoryWitnessStore::new(fixture.ready.clone(), setup.entries, setup.capacity)?;
        if let Some(fault) = setup.fault {
            store.inject_fault(fault)?;
        }
        let mut repeat_evidence = None;
        let operation = if setup.read_only {
            ExecutedBackendOperation::Read(store.read_entry(&fixture.stream_id).await)
        } else {
            let proposed = setup
                .proposed
                .as_ref()
                .ok_or(WitnessStoreErrorV1::Corrupt)?;
            let digest = prior.store_state_digest()?;
            if setup.repeat_after_apply {
                let first = store
                    .compare_and_swap(
                        &fixture.stream_id,
                        setup.expected_revision,
                        &digest,
                        proposed,
                    )
                    .await;
                let first_operation = ExecutedBackendOperation::Cas(first.clone());
                let first_diagnostic = if operation_attempts_diagnostic(
                    &first_operation,
                    &fixture.stream_id,
                    prior_revision,
                ) {
                    ExecutedDiagnosticCall::Attempted(store.read_entry(&fixture.stream_id).await)
                } else {
                    ExecutedDiagnosticCall::NotAttempted
                };
                repeat_evidence = Some(execution_evidence_from_backend(
                    &first_operation,
                    &fixture.stream_id,
                    setup.expected_revision,
                    prior_revision,
                    setup.proposed.as_ref(),
                    first_diagnostic,
                )?);
                first?;
                let first_read = store.read_entry(&fixture.stream_id).await;
                (prior_revision, prior) = final_entry(first_read)?;
            }
            ExecutedBackendOperation::Cas(
                store
                    .compare_and_swap(
                        &fixture.stream_id,
                        setup.expected_revision,
                        &digest,
                        proposed,
                    )
                    .await,
            )
        };
        let diagnostic_call =
            if operation_attempts_diagnostic(&operation, &fixture.stream_id, prior_revision) {
                ExecutedDiagnosticCall::Attempted(store.read_entry(&fixture.stream_id).await)
            } else {
                ExecutedDiagnosticCall::NotAttempted
            };
        let final_read = store.read_entry(&fixture.stream_id).await;
        let mut execution_evidence = execution_evidence_from_backend(
            &operation,
            &fixture.stream_id,
            setup.expected_revision,
            prior_revision,
            setup.proposed.as_ref(),
            diagnostic_call,
        )?;
        if execution_evidence.acknowledgement.is_none()
            && let Some(first) = repeat_evidence
        {
            execution_evidence = first;
        }
        let record = normalize_backend_record(
            NormalizationContext {
                id,
                stream_id: &fixture.stream_id,
                expected_revision: setup.expected_revision,
                prior_revision,
                prior: &prior,
                proposed: setup.proposed.as_ref(),
            },
            operation,
            execution_evidence,
            final_read,
        )?;
        Ok((record, store.canonical_store_bytes()?))
    }

    fn reference_record(
        fixture: &SemanticFixture,
        id: &str,
        scenario: DifferentialScenario,
    ) -> Result<(NormalizedScenarioRecord, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        let setup = fixture.setup(scenario)?;
        let (mut prior_revision, mut prior) = setup
            .entries
            .get(&fixture.stream_id)
            .cloned()
            .ok_or(WitnessStoreErrorV1::Missing)?;
        let mut store =
            ReferenceWitnessStoreModel::new(fixture.ready.clone(), setup.entries, setup.capacity)?;
        if let Some(fault) = setup.fault {
            store.inject_fault(fault);
        }
        let mut repeat_evidence = None;
        let operation = if setup.read_only {
            ExecutedBackendOperation::Read(store.read_entry(&fixture.stream_id))
        } else {
            let proposed = setup
                .proposed
                .as_ref()
                .ok_or(WitnessStoreErrorV1::Corrupt)?;
            let digest = prior.store_state_digest()?;
            if setup.repeat_after_apply {
                let first = store.compare_and_swap(
                    &fixture.stream_id,
                    setup.expected_revision,
                    &digest,
                    proposed,
                );
                let first_operation = ExecutedBackendOperation::Cas(first.clone());
                let first_diagnostic = if operation_attempts_diagnostic(
                    &first_operation,
                    &fixture.stream_id,
                    prior_revision,
                ) {
                    ExecutedDiagnosticCall::Attempted(store.read_entry(&fixture.stream_id))
                } else {
                    ExecutedDiagnosticCall::NotAttempted
                };
                repeat_evidence = Some(execution_evidence_from_backend(
                    &first_operation,
                    &fixture.stream_id,
                    setup.expected_revision,
                    prior_revision,
                    setup.proposed.as_ref(),
                    first_diagnostic,
                )?);
                first?;
                let first_read = store.read_entry(&fixture.stream_id);
                (prior_revision, prior) = final_entry(first_read)?;
            }
            ExecutedBackendOperation::Cas(store.compare_and_swap(
                &fixture.stream_id,
                setup.expected_revision,
                &digest,
                proposed,
            ))
        };
        let diagnostic_call =
            if operation_attempts_diagnostic(&operation, &fixture.stream_id, prior_revision) {
                ExecutedDiagnosticCall::Attempted(store.read_entry(&fixture.stream_id))
            } else {
                ExecutedDiagnosticCall::NotAttempted
            };
        let final_read = store.read_entry(&fixture.stream_id);
        let mut execution_evidence = execution_evidence_from_backend(
            &operation,
            &fixture.stream_id,
            setup.expected_revision,
            prior_revision,
            setup.proposed.as_ref(),
            diagnostic_call,
        )?;
        if execution_evidence.acknowledgement.is_none()
            && let Some(first) = repeat_evidence
        {
            execution_evidence = first;
        }
        let record = normalize_backend_record(
            NormalizationContext {
                id,
                stream_id: &fixture.stream_id,
                expected_revision: setup.expected_revision,
                prior_revision,
                prior: &prior,
                proposed: setup.proposed.as_ref(),
            },
            operation,
            execution_evidence,
            final_read,
        )?;
        Ok((record, store.canonical_store_bytes()?))
    }

    async fn proxy_record(
        fixture: &SemanticFixture,
        id: &str,
        scenario: DifferentialScenario,
    ) -> Result<(NormalizedScenarioRecord, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        let setup = fixture.setup(scenario)?;
        let (mut prior_revision, mut prior) = setup
            .entries
            .get(&fixture.stream_id)
            .cloned()
            .ok_or(WitnessStoreErrorV1::Missing)?;
        let inner =
            InMemoryWitnessStore::new(fixture.ready.clone(), setup.entries, setup.capacity)?;
        if let Some(fault) = setup.fault {
            inner.inject_fault(fault)?;
        }
        let proxy = WitnessStoreProxy::new(RecordingStore::new(inner), fixture.ready.clone())?;
        let request = if setup.read_only {
            fixture.proxy_request(
                WitnessStoreProxyOperationV1::ReadEntry,
                WitnessStoreProxyRequestBodyV1::ReadEntry {
                    stream_id: fixture.stream_id.clone(),
                },
            )?
        } else {
            let proposed = setup
                .proposed
                .as_ref()
                .ok_or(WitnessStoreErrorV1::Corrupt)?;
            fixture.proxy_request(
                WitnessStoreProxyOperationV1::CompareAndSwap,
                WitnessStoreProxyRequestBodyV1::CompareAndSwap {
                    stream_id: fixture.stream_id.clone(),
                    expected_revision: setup.expected_revision,
                    expected_store_state_digest: prior.store_state_digest()?,
                    proposed_envelope: Box::new(proposed.clone()),
                },
            )?
        };
        let mut repeat_evidence = None;
        if setup.repeat_after_apply {
            let first_response = proxy.handle_bytes(&canonical_wire_bytes(&request)?).await?;
            if !matches!(
                first_response.body,
                WitnessStoreProxyResponseBodyV1::CasApplied { .. }
            ) {
                return Err(WitnessStoreErrorV1::Corrupt.into());
            }
            let first_response_reads = proxy.store().take_reads()?;
            let first = proxy
                .store()
                .take_last_cas()?
                .ok_or(WitnessStoreErrorV1::Corrupt)?;
            let first_operation = ExecutedBackendOperation::Cas(first);
            let first_diagnostic = if operation_attempts_diagnostic(
                &first_operation,
                &fixture.stream_id,
                prior_revision,
            ) {
                ExecutedDiagnosticCall::Attempted(
                    first_response_reads
                        .last()
                        .cloned()
                        .ok_or(WitnessStoreErrorV1::Corrupt)?,
                )
            } else {
                ExecutedDiagnosticCall::NotAttempted
            };
            let first_read = proxy.store().read_entry(&fixture.stream_id).await;
            repeat_evidence = Some(execution_evidence_from_backend(
                &first_operation,
                &fixture.stream_id,
                setup.expected_revision,
                prior_revision,
                setup.proposed.as_ref(),
                first_diagnostic,
            )?);
            (prior_revision, prior) = final_entry(first_read)?;
            proxy.store().take_reads()?;
        }
        let response = proxy.handle_bytes(&canonical_wire_bytes(&request)?).await;
        let response_reads = proxy.store().take_reads()?;
        let recorded_cas = proxy.store().take_last_cas()?;
        let final_read = proxy.store().read_entry(&fixture.stream_id).await;
        let (final_revision, final_envelope) = final_entry(final_read.clone())?;
        let operation = proxy_response_to_backend(
            setup.read_only,
            &fixture.stream_id,
            setup.expected_revision,
            final_revision,
            &final_envelope,
            response,
            recorded_cas.clone(),
        );
        let captured_backend = recorded_cas
            .map(ExecutedBackendOperation::Cas)
            .unwrap_or_else(|| operation.clone());
        let diagnostic_attempted =
            operation_attempts_diagnostic(&captured_backend, &fixture.stream_id, prior_revision);
        let diagnostic_call = if diagnostic_attempted {
            ExecutedDiagnosticCall::Attempted(
                response_reads
                    .last()
                    .cloned()
                    .ok_or(WitnessStoreErrorV1::Corrupt)?,
            )
        } else {
            ExecutedDiagnosticCall::NotAttempted
        };
        let mut execution_evidence = execution_evidence_from_backend(
            &captured_backend,
            &fixture.stream_id,
            setup.expected_revision,
            prior_revision,
            setup.proposed.as_ref(),
            diagnostic_call,
        )?;
        if proxy_authenticated_diagnostic(&operation)?.is_some() && diagnostic_attempted {
            execution_evidence.ambiguity_response_is_diagnostic = true;
        }
        if execution_evidence.acknowledgement.is_none()
            && let Some(first) = repeat_evidence
        {
            execution_evidence = first;
        }
        let record = normalize_backend_record(
            NormalizationContext {
                id,
                stream_id: &fixture.stream_id,
                expected_revision: setup.expected_revision,
                prior_revision,
                prior: &prior,
                proposed: setup.proposed.as_ref(),
            },
            operation,
            execution_evidence,
            final_read,
        )?;
        Ok((record, proxy.store().canonical_store_bytes()?))
    }

    fn classifier_execution_evidence(
        input: &PostPublishClassificationInput,
        classification: &PostPublishClassification,
        backend_reported: Option<BackendAmbiguityObservation>,
        diagnostic_call: ExecutedDiagnosticCall,
    ) -> Result<BackendExecutionEvidence, WitnessStoreErrorV1> {
        let cause = match classification.cause {
            PostPublishClassificationCause::Applied => None,
            PostPublishClassificationCause::AckStreamMismatch => {
                Some(NormalizedAmbiguityCause::AckStreamMismatch)
            }
            PostPublishClassificationCause::DuplicateAcknowledgement => {
                Some(NormalizedAmbiguityCause::DuplicateAcknowledgement)
            }
            PostPublishClassificationCause::NonIncreasingAcknowledgement => {
                Some(NormalizedAmbiguityCause::NonIncreasingAcknowledgement)
            }
            PostPublishClassificationCause::ConfirmationFailure(error) => {
                Some(NormalizedAmbiguityCause::ConfirmationFailure(error.into()))
            }
            PostPublishClassificationCause::ConfirmationMismatch => {
                Some(NormalizedAmbiguityCause::ConfirmationMismatch)
            }
        };
        Ok(BackendExecutionEvidence {
            acknowledgement: Some(ExecutedAcknowledgementEvidence {
                stream_matches: input.acknowledgement.stream == input.configured_stream,
                sequence_relation: revision_relation(
                    input.acknowledgement.sequence,
                    input.current_revision,
                ),
                acknowledged_digest: input.proposed_digest.clone(),
                duplicate: input.acknowledgement.duplicate,
            }),
            authenticated_diagnostic: Some(executed_diagnostic_from_call(
                &input.stream_id,
                diagnostic_call,
            )?),
            ambiguity_cause: cause,
            backend_reported,
            ambiguity_response_is_diagnostic: true,
        })
    }

    async fn execute_jetstream_classifier(
        fixture: &SemanticFixture,
        setup: &ScenarioSetup,
        prior_revision: u64,
        prior: &WitnessStoreEnvelopeV1,
    ) -> Result<
        (
            ExecutedBackendOperation,
            BackendExecutionEvidence,
            u64,
            WitnessStoreEnvelopeV1,
        ),
        WitnessStoreErrorV1,
    > {
        let store = InMemoryWitnessStore::new(
            fixture.ready.clone(),
            fixture.entries(prior_revision, prior.clone()),
            setup.capacity,
        )?;
        if let Some(fault) = setup.fault {
            store.inject_fault(fault)?;
        }
        let captured_operation = if setup.read_only {
            ExecutedBackendOperation::Read(store.read_entry(&fixture.stream_id).await)
        } else {
            let proposed = setup
                .proposed
                .as_ref()
                .ok_or(WitnessStoreErrorV1::Corrupt)?;
            ExecutedBackendOperation::Cas(
                store
                    .compare_and_swap(
                        &fixture.stream_id,
                        setup.expected_revision,
                        &prior
                            .store_state_digest()
                            .map_err(|_| WitnessStoreErrorV1::Corrupt)?,
                        proposed,
                    )
                    .await,
            )
        };
        let diagnostic_call = if operation_attempts_diagnostic(
            &captured_operation,
            &fixture.stream_id,
            prior_revision,
        ) {
            ExecutedDiagnosticCall::Attempted(store.read_entry(&fixture.stream_id).await)
        } else {
            ExecutedDiagnosticCall::NotAttempted
        };
        let final_read = store.read_entry(&fixture.stream_id).await;
        let (final_revision, final_envelope) = final_entry(final_read)?;
        let captured_evidence = execution_evidence_from_backend(
            &captured_operation,
            &fixture.stream_id,
            setup.expected_revision,
            prior_revision,
            setup.proposed.as_ref(),
            diagnostic_call.clone(),
        )?;
        let Some(proposed) = setup.proposed.as_ref() else {
            return Ok((
                captured_operation,
                captured_evidence,
                final_revision,
                final_envelope,
            ));
        };
        let acknowledgement = match &captured_operation {
            ExecutedBackendOperation::Cas(Ok(WitnessStoreCasResultV1::Applied {
                stream_id,
                new_revision,
                duplicate,
                ..
            })) => Some(PostPublishAcknowledgement {
                stream: if stream_id == &fixture.stream_id {
                    fixture.ready.bucket_configuration.stream_name.clone()
                } else {
                    stream_id.clone()
                },
                sequence: *new_revision,
                duplicate: *duplicate,
            }),
            _ => None,
        };
        let Some(acknowledgement) = acknowledgement else {
            return Ok((
                captured_operation,
                captured_evidence,
                final_revision,
                final_envelope,
            ));
        };
        let mut input = PostPublishClassificationInput {
            stream_id: fixture.stream_id.clone(),
            configured_stream: fixture.ready.bucket_configuration.stream_name.clone(),
            expected_previous_revision: setup.expected_revision,
            current_revision: prior_revision,
            proposed_bytes: proposed
                .canonical_bytes()
                .map_err(|_| WitnessStoreErrorV1::Corrupt)?,
            proposed_digest: proposed
                .signed_envelope_digest()
                .map_err(|_| WitnessStoreErrorV1::Corrupt)?,
            acknowledgement,
            confirmation: None,
        };
        let classification = match classify_post_publish(&input) {
            PostPublishClassificationDecision::Complete(classification) => classification,
            PostPublishClassificationDecision::NeedsConfirmation => {
                input.confirmation = Some(match &diagnostic_call {
                    ExecutedDiagnosticCall::Attempted(Ok(read)) => {
                        let (confirmed_stream, sequence, envelope) = read_parts(read.clone());
                        if confirmed_stream != fixture.stream_id {
                            return Err(WitnessStoreErrorV1::Corrupt);
                        }
                        PostPublishConfirmation::Authenticated {
                            sequence,
                            expected_previous_revision: setup.expected_revision,
                            payload: envelope
                                .canonical_bytes()
                                .map_err(|_| WitnessStoreErrorV1::Corrupt)?,
                            envelope_digest: envelope
                                .signed_envelope_digest()
                                .map_err(|_| WitnessStoreErrorV1::Corrupt)?,
                        }
                    }
                    ExecutedDiagnosticCall::Attempted(Err(error)) => {
                        PostPublishConfirmation::Failed(*error)
                    }
                    ExecutedDiagnosticCall::NotAttempted => {
                        return Err(WitnessStoreErrorV1::Corrupt);
                    }
                });
                let PostPublishClassificationDecision::Complete(classification) =
                    classify_post_publish(&input)
                else {
                    return Err(WitnessStoreErrorV1::Corrupt);
                };
                classification
            }
        };
        let projected_result = match &classification.result {
            WitnessStoreCasResultV1::Ambiguous {
                stream_id,
                expected_previous_revision,
                ..
            } => {
                let (observed_revision, observed_value_digest) =
                    match &captured_evidence.authenticated_diagnostic {
                        Some(ExecutedDiagnosticEvidence::Authenticated {
                            observed_revision,
                            observed_value_digest,
                        }) => (
                            Some(*observed_revision),
                            Some(observed_value_digest.clone()),
                        ),
                        Some(
                            ExecutedDiagnosticEvidence::Failed(_)
                            | ExecutedDiagnosticEvidence::NotAttempted,
                        ) => (None, None),
                        None => return Err(WitnessStoreErrorV1::Corrupt),
                    };
                WitnessStoreCasResultV1::Ambiguous {
                    stream_id: stream_id.clone(),
                    expected_previous_revision: *expected_previous_revision,
                    observed_revision,
                    observed_value_digest,
                }
            }
            result => result.clone(),
        };
        let evidence = classifier_execution_evidence(
            &input,
            &classification,
            captured_evidence.backend_reported,
            diagnostic_call,
        )?;
        Ok((
            ExecutedBackendOperation::Cas(Ok(projected_result)),
            evidence,
            final_revision,
            final_envelope,
        ))
    }

    async fn jetstream_projection_record(
        fixture: &SemanticFixture,
        id: &str,
        scenario: DifferentialScenario,
    ) -> Result<(NormalizedScenarioRecord, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        let setup = fixture.setup(scenario)?;
        let (mut prior_revision, mut prior) = setup
            .entries
            .get(&fixture.stream_id)
            .cloned()
            .ok_or(WitnessStoreErrorV1::Missing)?;
        let (mut operation, mut evidence, mut final_revision, mut final_envelope) =
            execute_jetstream_classifier(fixture, &setup, prior_revision, &prior).await?;
        if setup.repeat_after_apply {
            let first_evidence = evidence;
            prior_revision = final_revision;
            prior = final_envelope.clone();
            (operation, evidence, final_revision, final_envelope) =
                execute_jetstream_classifier(fixture, &setup, prior_revision, &prior).await?;
            if evidence.acknowledgement.is_none() {
                evidence = first_evidence;
            }
        }
        let final_read = Ok(WitnessStoreReadResultV1::Entry {
            stream_id: fixture.stream_id.clone(),
            revision: final_revision,
            envelope: Box::new(final_envelope.clone()),
        });
        let record = normalize_backend_record(
            NormalizationContext {
                id,
                stream_id: &fixture.stream_id,
                expected_revision: setup.expected_revision,
                prior_revision,
                prior: &prior,
                proposed: setup.proposed.as_ref(),
            },
            operation,
            evidence,
            final_read,
        )?;
        let terminal = canonical_wire_bytes(&fixture.entries(final_revision, final_envelope))?;
        Ok((record, terminal))
    }

    const NORMALIZED_RECORD_FIELDS: [&str; 14] = [
        "acknowledged_digest",
        "ambiguity",
        "conflict",
        "duplicate",
        "error_kind",
        "final_envelope_bytes",
        "final_envelope_digest",
        "id",
        "outcome",
        "previous_revision_relation",
        "read_envelope_bytes",
        "refusal_bytes",
        "stream_id",
        "strictly_increasing_new_revision",
    ];

    fn validate_record_inventory(value: &serde_json::Value) -> Result<(), WitnessStoreErrorV1> {
        let object = value.as_object().ok_or(WitnessStoreErrorV1::Corrupt)?;
        let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        let expected = NORMALIZED_RECORD_FIELDS.to_vec();
        if keys != expected {
            return Err(WitnessStoreErrorV1::Corrupt);
        }
        if let Some(conflict) = object
            .get("conflict")
            .and_then(serde_json::Value::as_object)
        {
            let mut fields = conflict.keys().map(String::as_str).collect::<Vec<_>>();
            fields.sort_unstable();
            if fields
                != [
                    "observed_envelope_bytes",
                    "observed_envelope_digest",
                    "observed_revision_relation",
                ]
            {
                return Err(WitnessStoreErrorV1::Corrupt);
            }
        }
        if let Some(ambiguity) = object
            .get("ambiguity")
            .and_then(serde_json::Value::as_object)
        {
            let mut fields = ambiguity.keys().map(String::as_str).collect::<Vec<_>>();
            fields.sort_unstable();
            if fields
                != [
                    "authenticated_diagnostic",
                    "backend_reported",
                    "cause",
                    "expected_previous_relation",
                ]
            {
                return Err(WitnessStoreErrorV1::Corrupt);
            }
            let backend = ambiguity
                .get("backend_reported")
                .and_then(serde_json::Value::as_object)
                .ok_or(WitnessStoreErrorV1::Corrupt)?;
            let mut backend_fields = backend.keys().map(String::as_str).collect::<Vec<_>>();
            backend_fields.sort_unstable();
            if backend_fields != ["observed_revision_relation", "observed_value_digest"] {
                return Err(WitnessStoreErrorV1::Corrupt);
            }
            let diagnostic = ambiguity
                .get("authenticated_diagnostic")
                .and_then(serde_json::Value::as_object)
                .ok_or(WitnessStoreErrorV1::Corrupt)?;
            let status = diagnostic
                .get("status")
                .and_then(serde_json::Value::as_str)
                .ok_or(WitnessStoreErrorV1::Corrupt)?;
            let mut diagnostic_fields = diagnostic.keys().map(String::as_str).collect::<Vec<_>>();
            diagnostic_fields.sort_unstable();
            let expected_fields: &[&str] = match status {
                "not_attempted" => &["status"],
                "failed" => &["error_kind", "status"],
                "authenticated" => &[
                    "observed_revision_relation",
                    "observed_value_digest",
                    "status",
                ],
                _ => return Err(WitnessStoreErrorV1::Corrupt),
            };
            if diagnostic_fields != expected_fields {
                return Err(WitnessStoreErrorV1::Corrupt);
            }
        }
        if let Some(refusal) = object
            .get("refusal_bytes")
            .and_then(serde_json::Value::as_object)
        {
            let mut fields = refusal.keys().map(String::as_str).collect::<Vec<_>>();
            fields.sort_unstable();
            if fields != ["after", "before"] {
                return Err(WitnessStoreErrorV1::Corrupt);
            }
        }
        Ok(())
    }

    fn decode_record(
        value: serde_json::Value,
    ) -> Result<NormalizedScenarioRecord, WitnessStoreErrorV1> {
        validate_record_inventory(&value)?;
        let record: NormalizedScenarioRecord =
            serde_json::from_value(value).map_err(|_| WitnessStoreErrorV1::Corrupt)?;
        record.validate()?;
        Ok(record)
    }

    fn frozen_scenario_expectation(
        fixture: &SemanticFixture,
        id: &str,
        scenario: DifferentialScenario,
    ) -> Result<(NormalizedScenarioRecord, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        let setup = fixture.setup(scenario)?;
        let (initial_revision, initial) = setup
            .entries
            .get(&fixture.stream_id)
            .cloned()
            .ok_or(WitnessStoreErrorV1::Missing)?;
        let post_cas = matches!(
            scenario,
            DifferentialScenario::Rotation
                | DifferentialScenario::SealedPrepare
                | DifferentialScenario::Commit
                | DifferentialScenario::Abort
                | DifferentialScenario::ExactIdempotentObservation
                | DifferentialScenario::LostAfterCas
                | DifferentialScenario::WrongRevisionAck
                | DifferentialScenario::DuplicateAck
        );
        let final_envelope = if post_cas {
            setup.proposed.clone().ok_or(WitnessStoreErrorV1::Corrupt)?
        } else {
            initial.clone()
        };
        let final_revision = initial_revision + u64::from(post_cas);
        let final_bytes = canonical_wire_bytes(&final_envelope)?;
        let initial_bytes = canonical_wire_bytes(&initial)?;
        let final_digest = final_envelope.signed_envelope_digest()?;
        let acknowledged = matches!(
            scenario,
            DifferentialScenario::Rotation
                | DifferentialScenario::SealedPrepare
                | DifferentialScenario::Commit
                | DifferentialScenario::Abort
                | DifferentialScenario::ExactIdempotentObservation
                | DifferentialScenario::WrongRevisionAck
                | DifferentialScenario::DuplicateAck
        );
        let proposed_digest = if acknowledged {
            Some(
                setup
                    .proposed
                    .as_ref()
                    .ok_or(WitnessStoreErrorV1::Corrupt)?
                    .signed_envelope_digest()?,
            )
        } else {
            None
        };
        let (outcome, error_kind) = match scenario {
            DifferentialScenario::Genesis | DifferentialScenario::Read => {
                (NormalizedOutcomeKind::Read, None)
            }
            DifferentialScenario::Rotation
            | DifferentialScenario::SealedPrepare
            | DifferentialScenario::Commit
            | DifferentialScenario::Abort => (NormalizedOutcomeKind::Applied, None),
            DifferentialScenario::Conflict | DifferentialScenario::ExactIdempotentObservation => {
                (NormalizedOutcomeKind::Conflict, None)
            }
            DifferentialScenario::CorruptRead => (
                NormalizedOutcomeKind::Refused,
                Some(NormalizedErrorKind::Corrupt),
            ),
            DifferentialScenario::ResignedContent
            | DifferentialScenario::ResignedStaleSession
            | DifferentialScenario::ResignedAdmission => (
                NormalizedOutcomeKind::Refused,
                Some(NormalizedErrorKind::Admission),
            ),
            DifferentialScenario::ComponentLimit
            | DifferentialScenario::Capacity
            | DifferentialScenario::InjectedCapacity => (
                NormalizedOutcomeKind::Refused,
                Some(NormalizedErrorKind::Bounds),
            ),
            DifferentialScenario::CrashBeforeCas => (
                NormalizedOutcomeKind::Refused,
                Some(NormalizedErrorKind::Unavailable),
            ),
            DifferentialScenario::LostAfterCas
            | DifferentialScenario::WrongRevisionAck
            | DifferentialScenario::DuplicateAck => (NormalizedOutcomeKind::Ambiguous, None),
        };
        let conflict = matches!(
            scenario,
            DifferentialScenario::Conflict | DifferentialScenario::ExactIdempotentObservation
        )
        .then(|| NormalizedConflictMetadata {
            observed_revision_relation: RevisionRelation::Greater,
            observed_envelope_bytes: final_bytes.clone(),
            observed_envelope_digest: final_digest.clone(),
        });
        let ambiguity = match scenario {
            DifferentialScenario::LostAfterCas => Some(NormalizedAmbiguityMetadata {
                expected_previous_relation: RevisionRelation::Equal,
                backend_reported: NormalizedBackendReportedObservation {
                    observed_revision_relation: None,
                    observed_value_digest: None,
                },
                authenticated_diagnostic: NormalizedAuthenticatedDiagnostic::Authenticated {
                    observed_revision_relation: RevisionRelation::Greater,
                    observed_value_digest: final_digest.clone(),
                },
                cause: NormalizedAmbiguityCause::ConfirmationFailure(
                    NormalizedErrorKind::Ambiguous,
                ),
            }),
            DifferentialScenario::WrongRevisionAck => Some(NormalizedAmbiguityMetadata {
                expected_previous_relation: RevisionRelation::Equal,
                backend_reported: NormalizedBackendReportedObservation {
                    observed_revision_relation: Some(RevisionRelation::Greater),
                    observed_value_digest: proposed_digest.clone(),
                },
                authenticated_diagnostic: NormalizedAuthenticatedDiagnostic::Authenticated {
                    observed_revision_relation: RevisionRelation::Greater,
                    observed_value_digest: final_digest.clone(),
                },
                cause: NormalizedAmbiguityCause::ConfirmationMismatch,
            }),
            DifferentialScenario::DuplicateAck => Some(NormalizedAmbiguityMetadata {
                expected_previous_relation: RevisionRelation::Equal,
                backend_reported: NormalizedBackendReportedObservation {
                    observed_revision_relation: Some(RevisionRelation::Greater),
                    observed_value_digest: proposed_digest.clone(),
                },
                authenticated_diagnostic: NormalizedAuthenticatedDiagnostic::NotAttempted,
                cause: NormalizedAmbiguityCause::DuplicateAcknowledgement,
            }),
            _ => None,
        };
        let refusal = matches!(
            outcome,
            NormalizedOutcomeKind::Conflict | NormalizedOutcomeKind::Refused
        )
        .then(|| NormalizedRefusalBytes {
            before: final_bytes.clone(),
            after: final_bytes.clone(),
        });
        let record = NormalizedScenarioRecord {
            id: id.to_string(),
            outcome,
            error_kind,
            stream_id: fixture.stream_id.clone(),
            previous_revision_relation: acknowledged.then_some(RevisionRelation::Equal),
            strictly_increasing_new_revision: acknowledged.then_some(true),
            acknowledged_digest: if acknowledged {
                Some(proposed_digest.ok_or(WitnessStoreErrorV1::Corrupt)?)
            } else {
                None
            },
            duplicate: acknowledged.then_some(scenario == DifferentialScenario::DuplicateAck),
            conflict,
            ambiguity,
            read_envelope_bytes: if scenario == DifferentialScenario::CorruptRead {
                None
            } else {
                Some(
                    if scenario == DifferentialScenario::ExactIdempotentObservation {
                        final_bytes.clone()
                    } else {
                        initial_bytes
                    },
                )
            },
            final_envelope_bytes: final_bytes,
            final_envelope_digest: final_digest,
            refusal_bytes: refusal,
        };
        let mut terminal = setup.entries;
        terminal.insert(fixture.stream_id.clone(), (final_revision, final_envelope));
        Ok((record, canonical_wire_bytes(&terminal)?))
    }

    fn evaluate_frozen_scenario(
        fixture: &SemanticFixture,
        id: &str,
        scenario: DifferentialScenario,
        record: &NormalizedScenarioRecord,
        terminal: &[u8],
    ) -> Result<(), WitnessStoreErrorV1> {
        let (expected, expected_terminal) = frozen_scenario_expectation(fixture, id, scenario)
            .map_err(|_| WitnessStoreErrorV1::Corrupt)?;
        if record != &expected || terminal != expected_terminal {
            return Err(WitnessStoreErrorV1::Corrupt);
        }
        Ok(())
    }

    #[test]
    fn proxy_cas_applied_is_normalized_from_the_public_response()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fixture = SemanticFixture::new()?;
        let response = WitnessStoreProxyResponseV1 {
            schema_version: 1,
            operation: WitnessStoreProxyOperationV1::CompareAndSwap,
            request_digest: "1".repeat(64),
            body: WitnessStoreProxyResponseBodyV1::CasApplied {
                stream_id: "stream-phase285".to_string(),
                previous_revision: 7,
                new_revision: 19,
                acknowledged_value_digest: "a".repeat(64),
            },
        };
        let recorded = WitnessStoreCasResultV1::Applied {
            stream_id: "stream-phase285".to_string(),
            expected_previous_revision: 7,
            previous_revision: 7,
            new_revision: 19,
            acknowledged_value_digest: "a".repeat(64),
            duplicate: false,
        };
        assert!(matches!(
            proxy_response_to_backend(
                false,
                "stream-phase285",
                7,
                19,
                &fixture.prepared,
                Ok(response.clone()),
                Some(Ok(recorded.clone())),
            ),
            ExecutedBackendOperation::Cas(Ok(WitnessStoreCasResultV1::Applied {
                previous_revision: 7,
                new_revision: 19,
                ..
            }))
        ));
        let mutants = [
            WitnessStoreProxyResponseBodyV1::CasApplied {
                stream_id: "foreign".to_string(),
                previous_revision: 7,
                new_revision: 19,
                acknowledged_value_digest: "a".repeat(64),
            },
            WitnessStoreProxyResponseBodyV1::CasApplied {
                stream_id: "stream-phase285".to_string(),
                previous_revision: 6,
                new_revision: 19,
                acknowledged_value_digest: "a".repeat(64),
            },
            WitnessStoreProxyResponseBodyV1::CasApplied {
                stream_id: "stream-phase285".to_string(),
                previous_revision: 7,
                new_revision: 20,
                acknowledged_value_digest: "a".repeat(64),
            },
            WitnessStoreProxyResponseBodyV1::CasApplied {
                stream_id: "stream-phase285".to_string(),
                previous_revision: 7,
                new_revision: 19,
                acknowledged_value_digest: "b".repeat(64),
            },
        ];
        for body in mutants {
            let mut mutant = response.clone();
            mutant.body = body;
            assert!(matches!(
                proxy_response_to_backend(
                    false,
                    "stream-phase285",
                    7,
                    19,
                    &fixture.prepared,
                    Ok(mutant),
                    Some(Ok(recorded.clone())),
                ),
                ExecutedBackendOperation::Cas(Err(WitnessStoreErrorV1::Corrupt))
            ));
        }
        Ok(())
    }

    #[test]
    fn proxy_conflict_requires_complete_public_response_evidence()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fixture = SemanticFixture::new()?;
        let final_revision = 19;
        let final_digest = fixture.prepared.store_state_digest()?;
        let response = WitnessStoreProxyResponseV1 {
            schema_version: 1,
            operation: WitnessStoreProxyOperationV1::CompareAndSwap,
            request_digest: "1".repeat(64),
            body: WitnessStoreProxyResponseBodyV1::Refused {
                failure_code: WitnessStoreProxyFailureCodeV1::Conflict,
                observed_revision: Some(final_revision),
                observed_value_digest: Some(final_digest.clone()),
            },
        };

        assert!(matches!(
            proxy_response_to_backend(
                false,
                &fixture.stream_id,
                7,
                final_revision,
                &fixture.prepared,
                Ok(response.clone()),
                None,
            ),
            ExecutedBackendOperation::Cas(Ok(WitnessStoreCasResultV1::Conflict {
                observed_revision: 19,
                ..
            }))
        ));

        let mutants = [
            (None, Some(final_digest.clone())),
            (Some(final_revision - 1), Some(final_digest.clone())),
            (Some(final_revision), None),
            (Some(final_revision), Some("0".repeat(64))),
        ];
        for (observed_revision, observed_value_digest) in mutants {
            let mut mutant = response.clone();
            mutant.body = WitnessStoreProxyResponseBodyV1::Refused {
                failure_code: WitnessStoreProxyFailureCodeV1::Conflict,
                observed_revision,
                observed_value_digest,
            };
            assert!(matches!(
                proxy_response_to_backend(
                    false,
                    &fixture.stream_id,
                    7,
                    final_revision,
                    &fixture.prepared,
                    Ok(mutant),
                    None,
                ),
                ExecutedBackendOperation::Cas(Err(WitnessStoreErrorV1::Corrupt))
            ));
        }
        Ok(())
    }

    #[test]
    fn ambiguity_observations_change_only_with_their_actual_inputs()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fixture = SemanticFixture::new()?;
        let prior_revision = 7;
        let proposed = fixture.prepared.clone();
        let proposed_digest = proposed.signed_envelope_digest()?;
        let diagnostic = Ok(WitnessStoreReadResultV1::Entry {
            stream_id: fixture.stream_id.clone(),
            revision: 8,
            envelope: Box::new(proposed.clone()),
        });
        let operation = |new_revision: u64, digest: String| {
            ExecutedBackendOperation::Cas(Ok(WitnessStoreCasResultV1::Applied {
                stream_id: fixture.stream_id.clone(),
                expected_previous_revision: prior_revision,
                previous_revision: prior_revision,
                new_revision,
                acknowledged_value_digest: digest,
                duplicate: false,
            }))
        };
        let first = execution_evidence_from_backend(
            &operation(9, proposed_digest.clone()),
            &fixture.stream_id,
            prior_revision,
            prior_revision,
            Some(&proposed),
            ExecutedDiagnosticCall::Attempted(diagnostic.clone()),
        )?;
        let changed_backend = execution_evidence_from_backend(
            &operation(10, "b".repeat(64)),
            &fixture.stream_id,
            prior_revision,
            prior_revision,
            Some(&proposed),
            ExecutedDiagnosticCall::Attempted(diagnostic),
        )?;
        assert_eq!(
            first.backend_reported,
            Some(BackendAmbiguityObservation {
                observed_revision: Some(9),
                observed_value_digest: Some(proposed_digest.clone()),
            })
        );
        assert_eq!(
            changed_backend.backend_reported,
            Some(BackendAmbiguityObservation {
                observed_revision: Some(10),
                observed_value_digest: Some("b".repeat(64)),
            })
        );
        assert_eq!(
            first.authenticated_diagnostic,
            changed_backend.authenticated_diagnostic
        );
        assert_eq!(
            first.authenticated_diagnostic,
            Some(ExecutedDiagnosticEvidence::Authenticated {
                observed_revision: 8,
                observed_value_digest: proposed_digest.clone(),
            })
        );

        let failed_diagnostic = execution_evidence_from_backend(
            &operation(9, proposed_digest),
            &fixture.stream_id,
            prior_revision,
            prior_revision,
            Some(&proposed),
            ExecutedDiagnosticCall::Attempted(Err(WitnessStoreErrorV1::Unavailable)),
        )?;
        assert_eq!(first.backend_reported, failed_diagnostic.backend_reported);
        assert_eq!(
            failed_diagnostic.authenticated_diagnostic,
            Some(ExecutedDiagnosticEvidence::Failed(
                NormalizedErrorKind::Unavailable
            ))
        );

        let input = classifier_input();
        let mut no_call = input.clone();
        no_call.acknowledgement.duplicate = true;
        no_call.confirmation = None;
        let PostPublishClassificationDecision::Complete(classification) =
            classify_post_publish(&no_call)
        else {
            return Err(WitnessStoreErrorV1::Corrupt.into());
        };
        let no_call_evidence = classifier_execution_evidence(
            &no_call,
            &classification,
            Some(BackendAmbiguityObservation {
                observed_revision: Some(19),
                observed_value_digest: Some("a".repeat(64)),
            }),
            ExecutedDiagnosticCall::NotAttempted,
        )?;
        assert_eq!(
            no_call_evidence.authenticated_diagnostic,
            Some(ExecutedDiagnosticEvidence::NotAttempted)
        );
        let proxy_ambiguity = |observed_revision, observed_value_digest| {
            ExecutedBackendOperation::Cas(Ok(WitnessStoreCasResultV1::Ambiguous {
                stream_id: fixture.stream_id.clone(),
                expected_previous_revision: 7,
                observed_revision,
                observed_value_digest,
            }))
        };
        assert_eq!(
            proxy_authenticated_diagnostic(&proxy_ambiguity(Some(8), Some("a".repeat(64)))),
            Ok(Some(ExecutedDiagnosticEvidence::Authenticated {
                observed_revision: 8,
                observed_value_digest: "a".repeat(64),
            }))
        );
        assert_eq!(
            proxy_authenticated_diagnostic(&proxy_ambiguity(None, None)),
            Ok(Some(ExecutedDiagnosticEvidence::Failed(
                NormalizedErrorKind::Ambiguous
            )))
        );
        assert_eq!(
            proxy_authenticated_diagnostic(&proxy_ambiguity(Some(8), None)),
            Err(WitnessStoreErrorV1::Corrupt)
        );
        assert_eq!(
            proxy_authenticated_diagnostic(&proxy_ambiguity(None, Some("a".repeat(64)))),
            Err(WitnessStoreErrorV1::Corrupt)
        );
        Ok(())
    }

    #[test]
    fn nineteen_non_lossy_records_match_every_projection_and_kill_mutants()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let result = std::thread::Builder::new()
            .name("phase285-jetstream-nineteen-row-differential".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(async {
                    let fixture = SemanticFixture::new()?;
                    let mut scenario_ledger = ScenarioLedger::from_environment()?;
                    let mut records = Vec::new();
                    for (id, scenario) in DIFFERENTIAL_SCENARIOS {
                        let (direct, direct_terminal) =
                            direct_record(&fixture, id, scenario).await?;
                        let (reference, reference_terminal) =
                            reference_record(&fixture, id, scenario)?;
                        let (proxy, proxy_terminal) = proxy_record(&fixture, id, scenario).await?;
                        let (jetstream, jetstream_terminal) =
                            jetstream_projection_record(&fixture, id, scenario).await?;
                        assert_eq!(direct, reference, "direct/reference {id}");
                        assert_eq!(direct, proxy, "direct/proxy {id}");
                        assert_eq!(direct, jetstream, "direct/JetStream {id}");
                        assert_eq!(direct_terminal, reference_terminal, "terminal {id}");
                        assert_eq!(direct_terminal, proxy_terminal, "proxy terminal {id}");
                        assert_eq!(direct_terminal, jetstream_terminal, "NATS terminal {id}");
                        let (expected, expected_terminal) =
                            frozen_scenario_expectation(&fixture, id, scenario)?;
                        assert_eq!(direct, expected, "frozen record {id}");
                        assert_eq!(direct_terminal, expected_terminal, "frozen terminal {id}");
                        direct.validate()?;
                        let encoded = serde_json::to_value(&direct)?;
                        assert_eq!(decode_record(encoded)?, direct);
                        records.push(direct);
                    }
                    assert_eq!(records.len(), 19);
                    let ids = records
                        .iter()
                        .map(|record| record.id.as_str())
                        .collect::<Vec<_>>();
                    assert_eq!(
                        ids,
                        DIFFERENTIAL_SCENARIOS
                            .iter()
                            .map(|(id, _)| *id)
                            .collect::<Vec<_>>()
                    );
                    for (index, record) in records.iter().enumerate() {
                        let (id, scenario) = DIFFERENTIAL_SCENARIOS[index];
                        let terminal = frozen_scenario_expectation(&fixture, id, scenario)?.1;
                        let rejects = |mutant: &NormalizedScenarioRecord, terminal: &[u8]| {
                            assert_eq!(
                                evaluate_frozen_scenario(&fixture, id, scenario, mutant, terminal,),
                                Err(WitnessStoreErrorV1::Corrupt),
                                "frozen evaluator accepted mutant for {id}"
                            );
                        };
                        if let Some(actual) = record.previous_revision_relation {
                            for relation in [
                                RevisionRelation::Less,
                                RevisionRelation::Equal,
                                RevisionRelation::Greater,
                            ] {
                                if relation != actual {
                                    let mut mutant = record.clone();
                                    mutant.previous_revision_relation = Some(relation);
                                    rejects(&mutant, &terminal);
                                }
                            }
                        }
                        if record.acknowledged_digest.is_some() {
                            let mut mutant = record.clone();
                            mutant.acknowledged_digest = Some("0".repeat(64));
                            rejects(&mutant, &terminal);
                        }
                        if let Some(conflict) = &record.conflict {
                            for relation in [
                                RevisionRelation::Less,
                                RevisionRelation::Equal,
                                RevisionRelation::Greater,
                            ] {
                                if relation != conflict.observed_revision_relation {
                                    let mut mutant = record.clone();
                                    mutant
                                        .conflict
                                        .as_mut()
                                        .ok_or(WitnessStoreErrorV1::Corrupt)?
                                        .observed_revision_relation = relation;
                                    rejects(&mutant, &terminal);
                                }
                            }
                            let mut mutant = record.clone();
                            mutant
                                .conflict
                                .as_mut()
                                .ok_or(WitnessStoreErrorV1::Corrupt)?
                                .observed_envelope_digest = "0".repeat(64);
                            rejects(&mutant, &terminal);
                        }
                        if let Some(ambiguity) = &record.ambiguity {
                            for relation in [
                                None,
                                Some(RevisionRelation::Less),
                                Some(RevisionRelation::Equal),
                                Some(RevisionRelation::Greater),
                            ] {
                                if relation != ambiguity.backend_reported.observed_revision_relation
                                {
                                    let mut mutant = record.clone();
                                    mutant
                                        .ambiguity
                                        .as_mut()
                                        .ok_or(WitnessStoreErrorV1::Corrupt)?
                                        .backend_reported
                                        .observed_revision_relation = relation;
                                    rejects(&mutant, &terminal);
                                }
                            }
                            let mut mutant = record.clone();
                            mutant
                                .ambiguity
                                .as_mut()
                                .ok_or(WitnessStoreErrorV1::Corrupt)?
                                .backend_reported
                                .observed_value_digest = Some("0".repeat(64));
                            rejects(&mutant, &terminal);
                            let mut mutant = record.clone();
                            mutant
                                .ambiguity
                                .as_mut()
                                .ok_or(WitnessStoreErrorV1::Corrupt)?
                                .cause = NormalizedAmbiguityCause::StoreReported;
                            rejects(&mutant, &terminal);
                        }
                        if record.refusal_bytes.is_some() {
                            let mut mutant = record.clone();
                            mutant.refusal_bytes = None;
                            rejects(&mutant, &terminal);
                        }
                        let mut mutant = record.clone();
                        mutant.final_envelope_digest = "0".repeat(64);
                        rejects(&mutant, &terminal);
                        let mut terminal_mutant = terminal.clone();
                        terminal_mutant.push(0);
                        rejects(record, &terminal_mutant);
                        scenario_ledger.passed(id)?;
                    }

                    let baseline = serde_json::to_value(&records[0])?;
                    for field in NORMALIZED_RECORD_FIELDS {
                        let mut removed = baseline.clone();
                        removed
                            .as_object_mut()
                            .ok_or(WitnessStoreErrorV1::Corrupt)?
                            .remove(field);
                        assert_eq!(decode_record(removed), Err(WitnessStoreErrorV1::Corrupt));
                    }
                    let (applied_index, applied) = records
                        .iter()
                        .enumerate()
                        .find(|(_, record)| record.outcome == NormalizedOutcomeKind::Applied)
                        .ok_or(WitnessStoreErrorV1::Corrupt)?;
                    let mut relation_constant = applied.clone();
                    relation_constant.previous_revision_relation = Some(RevisionRelation::Less);
                    assert_eq!(
                        evaluate_frozen_scenario(
                            &fixture,
                            DIFFERENTIAL_SCENARIOS[applied_index].0,
                            DIFFERENTIAL_SCENARIOS[applied_index].1,
                            &relation_constant,
                            &frozen_scenario_expectation(
                                &fixture,
                                DIFFERENTIAL_SCENARIOS[applied_index].0,
                                DIFFERENTIAL_SCENARIOS[applied_index].1,
                            )?
                            .1,
                        ),
                        Err(WitnessStoreErrorV1::Corrupt)
                    );
                    let conflict = records
                        .iter()
                        .find(|record| record.conflict.is_some())
                        .ok_or(WitnessStoreErrorV1::Corrupt)?;
                    for field in [
                        "observed_revision_relation",
                        "observed_envelope_bytes",
                        "observed_envelope_digest",
                    ] {
                        let mut removed = serde_json::to_value(conflict)?;
                        removed
                            .get_mut("conflict")
                            .and_then(serde_json::Value::as_object_mut)
                            .ok_or(WitnessStoreErrorV1::Corrupt)?
                            .remove(field);
                        assert_eq!(decode_record(removed), Err(WitnessStoreErrorV1::Corrupt));
                    }
                    let mut substituted_metadata = conflict.clone();
                    substituted_metadata
                        .conflict
                        .as_mut()
                        .ok_or(WitnessStoreErrorV1::Corrupt)?
                        .observed_envelope_digest = "0".repeat(64);
                    assert!(!records.contains(&substituted_metadata));
                    let refused = records
                        .iter()
                        .find(|record| record.refusal_bytes.is_some())
                        .ok_or(WitnessStoreErrorV1::Corrupt)?;
                    let mut elided = refused.clone();
                    elided.refusal_bytes = None;
                    assert_eq!(elided.validate(), Err(WitnessStoreErrorV1::Corrupt));
                    for field in ["before", "after"] {
                        let mut removed = serde_json::to_value(refused)?;
                        removed
                            .get_mut("refusal_bytes")
                            .and_then(serde_json::Value::as_object_mut)
                            .ok_or(WitnessStoreErrorV1::Corrupt)?
                            .remove(field);
                        assert_eq!(decode_record(removed), Err(WitnessStoreErrorV1::Corrupt));
                    }
                    let ambiguous = records
                        .iter()
                        .find(|record| record.ambiguity.is_some())
                        .ok_or(WitnessStoreErrorV1::Corrupt)?;
                    for field in [
                        "expected_previous_relation",
                        "backend_reported",
                        "authenticated_diagnostic",
                        "cause",
                    ] {
                        let mut removed = serde_json::to_value(ambiguous)?;
                        removed
                            .get_mut("ambiguity")
                            .and_then(serde_json::Value::as_object_mut)
                            .ok_or(WitnessStoreErrorV1::Corrupt)?
                            .remove(field);
                        assert_eq!(decode_record(removed), Err(WitnessStoreErrorV1::Corrupt));
                    }
                    let (lost_index, lost) = records
                        .iter()
                        .enumerate()
                        .find(|(_, record)| record.id == "lost_after_cas")
                        .ok_or(WitnessStoreErrorV1::Corrupt)?;
                    let lost_terminal = frozen_scenario_expectation(
                        &fixture,
                        DIFFERENTIAL_SCENARIOS[lost_index].0,
                        DIFFERENTIAL_SCENARIOS[lost_index].1,
                    )?
                    .1;
                    for (object, fields) in [
                        (
                            "backend_reported",
                            &["observed_revision_relation", "observed_value_digest"][..],
                        ),
                        (
                            "authenticated_diagnostic",
                            &[
                                "observed_revision_relation",
                                "observed_value_digest",
                                "status",
                            ][..],
                        ),
                    ] {
                        for field in fields {
                            let mut removed = serde_json::to_value(lost)?;
                            removed
                                .get_mut("ambiguity")
                                .and_then(|value| value.get_mut(object))
                                .and_then(serde_json::Value::as_object_mut)
                                .ok_or(WitnessStoreErrorV1::Corrupt)?
                                .remove(*field);
                            assert_eq!(decode_record(removed), Err(WitnessStoreErrorV1::Corrupt));
                        }
                    }
                    for (status, extra_field) in [
                        ("not_attempted", Some("observed_value_digest")),
                        ("failed", Some("observed_revision_relation")),
                        ("unknown", None),
                    ] {
                        let mut invalid = serde_json::to_value(lost)?;
                        let diagnostic = invalid
                            .get_mut("ambiguity")
                            .and_then(|value| value.get_mut("authenticated_diagnostic"))
                            .and_then(serde_json::Value::as_object_mut)
                            .ok_or(WitnessStoreErrorV1::Corrupt)?;
                        diagnostic.insert("status".to_string(), status.into());
                        if let Some(field) = extra_field {
                            diagnostic.insert(field.to_string(), "0".repeat(64).into());
                        }
                        assert_eq!(decode_record(invalid), Err(WitnessStoreErrorV1::Corrupt));
                    }
                    let mut diagnostic_into_backend = lost.clone();
                    let diagnostic = match diagnostic_into_backend
                        .ambiguity
                        .as_ref()
                        .ok_or(WitnessStoreErrorV1::Corrupt)?
                        .authenticated_diagnostic
                        .clone()
                    {
                        NormalizedAuthenticatedDiagnostic::Authenticated {
                            observed_revision_relation,
                            observed_value_digest,
                        } => (
                            Some(observed_revision_relation),
                            Some(observed_value_digest),
                        ),
                        _ => return Err(WitnessStoreErrorV1::Corrupt.into()),
                    };
                    let ambiguity = diagnostic_into_backend
                        .ambiguity
                        .as_mut()
                        .ok_or(WitnessStoreErrorV1::Corrupt)?;
                    ambiguity.backend_reported = NormalizedBackendReportedObservation {
                        observed_revision_relation: diagnostic.0,
                        observed_value_digest: diagnostic.1,
                    };
                    assert_eq!(
                        evaluate_frozen_scenario(
                            &fixture,
                            DIFFERENTIAL_SCENARIOS[lost_index].0,
                            DIFFERENTIAL_SCENARIOS[lost_index].1,
                            &diagnostic_into_backend,
                            &lost_terminal,
                        ),
                        Err(WitnessStoreErrorV1::Corrupt)
                    );
                    let mut backend_into_diagnostic = lost.clone();
                    backend_into_diagnostic
                        .ambiguity
                        .as_mut()
                        .ok_or(WitnessStoreErrorV1::Corrupt)?
                        .authenticated_diagnostic = NormalizedAuthenticatedDiagnostic::NotAttempted;
                    assert_eq!(
                        evaluate_frozen_scenario(
                            &fixture,
                            DIFFERENTIAL_SCENARIOS[lost_index].0,
                            DIFFERENTIAL_SCENARIOS[lost_index].1,
                            &backend_into_diagnostic,
                            &lost_terminal,
                        ),
                        Err(WitnessStoreErrorV1::Corrupt)
                    );
                    let mut digest_mutant = applied.clone();
                    digest_mutant.acknowledged_digest = Some("0".repeat(64));
                    assert_eq!(
                        evaluate_frozen_scenario(
                            &fixture,
                            DIFFERENTIAL_SCENARIOS[applied_index].0,
                            DIFFERENTIAL_SCENARIOS[applied_index].1,
                            &digest_mutant,
                            &frozen_scenario_expectation(
                                &fixture,
                                DIFFERENTIAL_SCENARIOS[applied_index].0,
                                DIFFERENTIAL_SCENARIOS[applied_index].1,
                            )?
                            .1,
                        ),
                        Err(WitnessStoreErrorV1::Corrupt)
                    );
                    scenario_ledger.finish()?;
                    Ok(())
                })
            })?
            .join()
            .map_err(|_| WitnessStoreErrorV1::Corrupt)?;
        result?;
        Ok(())
    }

    #[test]
    fn post_publish_classifier_is_fail_closed_and_mutation_sensitive() {
        let mut pending_confirmation = classifier_input();
        pending_confirmation.confirmation = None;
        assert_eq!(
            classify_post_publish(&pending_confirmation),
            PostPublishClassificationDecision::NeedsConfirmation,
            "only a structurally valid acknowledgement may trigger the leader confirmation read"
        );
        let applied = complete(&classifier_input());
        assert!(matches!(
            applied.result,
            WitnessStoreCasResultV1::Applied {
                previous_revision: 7,
                new_revision: 19,
                duplicate: false,
                ..
            }
        ));

        let mut wrong_stream = classifier_input();
        wrong_stream.acknowledgement.stream = "KV_foreign".to_string();
        wrong_stream.confirmation = None;
        let wrong_stream = complete(&wrong_stream);
        assert!(matches!(
            wrong_stream.result,
            WitnessStoreCasResultV1::Ambiguous {
                observed_revision: Some(19),
                observed_value_digest: None,
                ..
            }
        ));
        assert_eq!(
            wrong_stream.cause,
            PostPublishClassificationCause::AckStreamMismatch
        );

        let mut duplicate = classifier_input();
        duplicate.acknowledgement.duplicate = true;
        duplicate.confirmation = None;
        let duplicate = complete(&duplicate);
        assert!(matches!(
            duplicate.result,
            WitnessStoreCasResultV1::Ambiguous { .. }
        ));
        assert_eq!(
            duplicate.cause,
            PostPublishClassificationCause::DuplicateAcknowledgement
        );

        let mut non_increasing = classifier_input();
        non_increasing.acknowledgement.sequence = 7;
        non_increasing.confirmation = None;
        let non_increasing = complete(&non_increasing);
        assert!(matches!(
            non_increasing.result,
            WitnessStoreCasResultV1::Ambiguous {
                observed_revision: Some(7),
                observed_value_digest: None,
                ..
            }
        ));
        assert_eq!(
            non_increasing.cause,
            PostPublishClassificationCause::NonIncreasingAcknowledgement
        );
        for (sequence, observed_revision) in [(0, None), (6, Some(6))] {
            let mut lower = classifier_input();
            lower.acknowledgement.sequence = sequence;
            lower.confirmation = None;
            let lower = complete(&lower);
            assert_eq!(
                lower.cause,
                PostPublishClassificationCause::NonIncreasingAcknowledgement
            );
            assert!(matches!(
                lower.result,
                WitnessStoreCasResultV1::Ambiguous {
                    observed_revision: actual,
                    observed_value_digest: None,
                    ..
                } if actual == observed_revision
            ));
        }

        let mut lost = classifier_input();
        lost.confirmation = Some(PostPublishConfirmation::Failed(
            WitnessStoreErrorV1::Unavailable,
        ));
        let lost = complete(&lost);
        assert!(matches!(
            lost.result,
            WitnessStoreCasResultV1::Ambiguous {
                observed_revision: None,
                observed_value_digest: None,
                ..
            }
        ));
        assert_eq!(
            lost.cause,
            PostPublishClassificationCause::ConfirmationFailure(WitnessStoreErrorV1::Unavailable)
        );
        let mut corrupt_confirmation = classifier_input();
        corrupt_confirmation.confirmation = Some(PostPublishConfirmation::Failed(
            WitnessStoreErrorV1::Corrupt,
        ));
        assert_eq!(
            complete(&corrupt_confirmation).cause,
            PostPublishClassificationCause::ConfirmationFailure(WitnessStoreErrorV1::Corrupt),
            "confirmation corruption must remain distinct from transport unavailability"
        );

        let mut confirmation_mutants = Vec::new();
        let mut wrong_sequence = classifier_input();
        wrong_sequence.confirmation = Some(PostPublishConfirmation::Authenticated {
            sequence: 20,
            expected_previous_revision: 7,
            payload: br#"{"store_generation":2}"#.to_vec(),
            envelope_digest: "a".repeat(64),
        });
        confirmation_mutants.push(wrong_sequence);
        let mut wrong_previous = classifier_input();
        wrong_previous.confirmation = Some(PostPublishConfirmation::Authenticated {
            sequence: 19,
            expected_previous_revision: 8,
            payload: br#"{"store_generation":2}"#.to_vec(),
            envelope_digest: "a".repeat(64),
        });
        confirmation_mutants.push(wrong_previous);
        let mut wrong_payload = classifier_input();
        wrong_payload.confirmation = Some(PostPublishConfirmation::Authenticated {
            sequence: 19,
            expected_previous_revision: 7,
            payload: br#"{"store_generation":3}"#.to_vec(),
            envelope_digest: "a".repeat(64),
        });
        confirmation_mutants.push(wrong_payload);
        let mut wrong_digest = classifier_input();
        wrong_digest.confirmation = Some(PostPublishConfirmation::Authenticated {
            sequence: 19,
            expected_previous_revision: 7,
            payload: br#"{"store_generation":2}"#.to_vec(),
            envelope_digest: "b".repeat(64),
        });
        confirmation_mutants.push(wrong_digest);
        assert_eq!(confirmation_mutants.len(), 4);
        for mutant in confirmation_mutants {
            let classification = complete(&mutant);
            assert_eq!(
                classification.cause,
                PostPublishClassificationCause::ConfirmationMismatch
            );
            assert!(matches!(
                classification.result,
                WitnessStoreCasResultV1::Ambiguous { .. }
            ));
        }
    }

    fn stable() -> StableReadySnapshot {
        StableReadySnapshot {
            subjects_count: 2,
            messages: 2,
            first_sequence: 1,
            last_sequence: 2,
            stream_created_at: "2026-08-25T12:00:00.000000000Z".to_string(),
            canonical_raw_configuration: br#"{"name":"KV_phase285"}"#.to_vec(),
            raw_stream_configuration_digest: "1".repeat(64),
            projected_configuration: crate::nats_config::projected_configuration(
                "phase285", 4_262_144, 1_000_000, 1,
            ),
        }
    }

    fn iterator_subjects() -> BTreeSet<String> {
        [
            iterator_subject("__witness_bucket_manifest"),
            iterator_subject("stream-a"),
        ]
        .into_iter()
        .collect()
    }

    fn iterator_subject(suffix: &str) -> String {
        ["$", "KV", ".phase285.", suffix].concat()
    }

    #[test]
    fn inspect_ready_iterator_page_and_final_snapshot_contract_kills_mutants()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut ledger = IteratorContractLedger::from_environment()?;

        assert!(matches!(
            ReadySubjectAccumulator::new(3, 3, 2, iterator_subjects()),
            Err(WitnessStoreErrorV1::Bounds)
        ));
        assert!(matches!(
            ReadySubjectAccumulator::new(1, 1, 2, iterator_subjects()),
            Err(WitnessStoreErrorV1::Missing)
        ));
        assert!(matches!(
            ReadySubjectAccumulator::new(2, 1, 2, iterator_subjects()),
            Err(WitnessStoreErrorV1::Configuration)
        ));
        ledger.passed("iterator.understated_advertised")?;

        let mut short = ReadySubjectAccumulator::new(2, 2, 2, iterator_subjects())?;
        short.observe(iterator_subject("__witness_bucket_manifest"), 1)?;
        assert_eq!(short.finish(), Err(WitnessStoreErrorV1::Missing));
        assert_eq!(
            ReadySubjectAccumulator::new(2, 2, 2, iterator_subjects())?
                .observe(iterator_subject("__witness_bucket_manifest"), 2,),
            Err(WitnessStoreErrorV1::Corrupt)
        );
        ledger.passed("iterator.short_iterator")?;
        assert_eq!(
            ready_iterator_page::<Option<(String, u64)>, _>(Err("page unavailable")),
            Err(WitnessStoreErrorV1::Unavailable)
        );
        ledger.passed("iterator.pagination_error")?;

        let mut duplicate = ReadySubjectAccumulator::new(2, 2, 2, iterator_subjects())?;
        duplicate.observe(iterator_subject("__witness_bucket_manifest"), 1)?;
        assert_eq!(
            duplicate.observe(iterator_subject("__witness_bucket_manifest"), 1),
            Err(WitnessStoreErrorV1::Corrupt)
        );
        let mut wildcard = ReadySubjectAccumulator::new(2, 2, 2, iterator_subjects())?;
        assert_eq!(
            wildcard.observe(iterator_subject("*"), 1),
            Err(WitnessStoreErrorV1::Corrupt)
        );
        ledger.passed("iterator.cross_page_duplicate_or_wildcard")?;

        let mut overflow = ReadySubjectAccumulator::new(2, 2, 2, iterator_subjects())?;
        overflow.observe(iterator_subject("__witness_bucket_manifest"), 1)?;
        overflow.observe(iterator_subject("stream-a"), 1)?;
        assert_eq!(
            overflow.observe(iterator_subject("extra"), 1),
            Err(WitnessStoreErrorV1::Bounds)
        );
        let mut checked_overflow = ReadySubjectAccumulator::new(2, 2, 2, iterator_subjects())?;
        checked_overflow.yielded = u64::MAX;
        assert_eq!(
            checked_overflow.observe(iterator_subject("stream-a"), 1),
            Err(WitnessStoreErrorV1::Bounds)
        );
        ledger.passed("iterator.cumulative_overflow")?;

        let baseline = stable();
        assert_eq!(validate_final_ready_snapshot(&baseline, &baseline), Ok(()));
        let final_mutants = [
            StableReadySnapshot {
                subjects_count: 3,
                ..baseline.clone()
            },
            StableReadySnapshot {
                messages: 3,
                ..baseline.clone()
            },
            StableReadySnapshot {
                first_sequence: 2,
                ..baseline.clone()
            },
            StableReadySnapshot {
                last_sequence: 3,
                ..baseline.clone()
            },
            StableReadySnapshot {
                stream_created_at: "2026-08-25T12:00:01.000000000Z".to_string(),
                ..baseline.clone()
            },
            StableReadySnapshot {
                canonical_raw_configuration: b"changed".to_vec(),
                ..baseline.clone()
            },
            StableReadySnapshot {
                raw_stream_configuration_digest: "2".repeat(64),
                ..baseline.clone()
            },
            StableReadySnapshot {
                projected_configuration: crate::nats_config::projected_configuration(
                    "other", 4_262_144, 1_000_000, 1,
                ),
                ..baseline.clone()
            },
        ];
        for mutant in final_mutants {
            assert_eq!(
                validate_final_ready_snapshot(&baseline, &mutant),
                Err(WitnessStoreErrorV1::Configuration)
            );
        }
        ledger.passed("iterator.final_closed_snapshot")?;
        ledger.finish()?;
        Ok(())
    }

    fn full(bytes: &[u8]) -> Result<FullInfoEvidence, WitnessStoreErrorV1> {
        let mut digest = Sha256::new();
        digest.update(RAW_STREAM_INFO_DOMAIN);
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
        FullInfoEvidence::new(bytes.to_vec(), hex::encode(digest.finalize()))
    }

    #[test]
    fn stable_projection_compares_every_normative_field() {
        let baseline = stable();
        let mutants = [
            StableReadySnapshot {
                subjects_count: 3,
                ..baseline.clone()
            },
            StableReadySnapshot {
                messages: 3,
                ..baseline.clone()
            },
            StableReadySnapshot {
                first_sequence: 2,
                ..baseline.clone()
            },
            StableReadySnapshot {
                last_sequence: 3,
                ..baseline.clone()
            },
            StableReadySnapshot {
                stream_created_at: "2026-08-25T12:00:01.000000000Z".to_string(),
                ..baseline.clone()
            },
            StableReadySnapshot {
                canonical_raw_configuration: b"changed".to_vec(),
                ..baseline.clone()
            },
            StableReadySnapshot {
                raw_stream_configuration_digest: "2".repeat(64),
                ..baseline.clone()
            },
            StableReadySnapshot {
                projected_configuration: crate::nats_config::projected_configuration(
                    "other", 4_262_144, 1_000_000, 1,
                ),
                ..baseline.clone()
            },
        ];
        assert_eq!(mutants.len(), 8);
        for mutant in mutants {
            assert_ne!(mutant, baseline);
        }
    }

    #[test]
    fn full_responses_remain_distinct_complete_evidence() -> Result<(), WitnessStoreErrorV1> {
        let initial = full(br#"{"ts":"2026-08-25T12:00:00.000000000Z"}"#)?;
        let final_snapshot = full(br#"{"ts":"2026-08-25T12:00:01.000000000Z"}"#)?;
        assert_ne!(initial, final_snapshot);
        let evidence =
            InspectionEvidence::new(Some(initial.clone()), Some(final_snapshot.clone()))?;
        assert_eq!(evidence.initial, initial);
        assert_eq!(evidence.final_snapshot, final_snapshot);
        assert_eq!(
            stable(),
            stable(),
            "full-response inequality is not a stability failure"
        );
        assert_eq!(
            InspectionEvidence::new(None, Some(final_snapshot.clone())),
            Err(WitnessStoreErrorV1::Configuration)
        );
        assert_eq!(
            InspectionEvidence::new(Some(initial.clone()), None),
            Err(WitnessStoreErrorV1::Configuration)
        );
        assert_eq!(
            FullInfoEvidence::new(br#"{"ts":"normalized"}"#.to_vec(), initial.digest.clone(),),
            Err(WitnessStoreErrorV1::Configuration),
            "normalizing or excluding ts without recomputing the full response digest must fail",
        );
        Ok(())
    }
}
