use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::future::Future;
use swarm_governance::persistence_protocol::{
    MAX_PROTOCOL_RECORD_BYTES, MAX_PROTOCOL_STRING_BYTES, ProtocolError, ProtocolResult,
};
use swarm_governance::witness_engine::store::WitnessAdmissionSetV1;
use swarm_governance::witness_engine::store::WitnessStoreReadyResultV1;
use swarm_governance::witness_service::WitnessServiceOperationV1;
use tokio::time::{Duration, Instant, timeout_at};

pub(crate) const STORE_HANDLER_DEADLINE_MILLIS: u64 = 2_000;
pub(crate) const STORE_RESPONSE_GRANT_MILLIS: u64 = 3_000;
pub(crate) const PUBLIC_HANDLER_DEADLINE_MILLIS: u64 = 10_000;
pub(crate) const PUBLIC_RESPONSE_GRANT_MILLIS: u64 = 12_000;
pub(crate) const STORE_HANDLER_RESERVE_MILLIS: u64 =
    STORE_RESPONSE_GRANT_MILLIS - STORE_HANDLER_DEADLINE_MILLIS;
pub(crate) const PUBLIC_PRIVATE_RESERVE_MILLIS: u64 =
    PUBLIC_HANDLER_DEADLINE_MILLIS - 3 * STORE_RESPONSE_GRANT_MILLIS;
pub(crate) const PUBLIC_HANDLER_RESERVE_MILLIS: u64 =
    PUBLIC_RESPONSE_GRANT_MILLIS - PUBLIC_HANDLER_DEADLINE_MILLIS;
pub(crate) const RESPONSE_GRANT_MAXIMUM: usize = 1;

const _: () = assert!(STORE_HANDLER_DEADLINE_MILLIS == 2_000);
const _: () = assert!(STORE_RESPONSE_GRANT_MILLIS == 3_000);
const _: () = assert!(PUBLIC_HANDLER_DEADLINE_MILLIS == 10_000);
const _: () = assert!(PUBLIC_RESPONSE_GRANT_MILLIS == 12_000);
const _: () = assert!(STORE_HANDLER_RESERVE_MILLIS == 1_000);
const _: () = assert!(PUBLIC_PRIVATE_RESERVE_MILLIS == 1_000);
const _: () = assert!(PUBLIC_HANDLER_RESERVE_MILLIS == 2_000);
const _: () = assert!(RESPONSE_GRANT_MAXIMUM == 1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WorkerKindV1 {
    Private,
    Public,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SubscriberAdmissionReceiptV1 {
    pub(crate) worker: WorkerKindV1,
    pub(crate) subject: String,
    pub(crate) payload_sha256: String,
    pub(crate) reply: String,
    pub(crate) deadline_millis: u64,
}

pub(crate) trait SubscriberAdmissionObserverV1: Send + Sync {
    fn accepted(&self, receipt: SubscriberAdmissionReceiptV1);
}

#[derive(Debug, Default)]
pub(crate) struct NoopSubscriberAdmissionObserverV1;

impl SubscriberAdmissionObserverV1 for NoopSubscriberAdmissionObserverV1 {
    fn accepted(&self, _receipt: SubscriberAdmissionReceiptV1) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub(crate) enum WorkerTransitionEventV1 {
    Dequeued {
        worker: WorkerKindV1,
    },
    PostPreflight {
        worker: WorkerKindV1,
    },
    ProxyStoreBegin {
        worker: WorkerKindV1,
        operation: &'static str,
        cas_attempted: bool,
    },
    ProxyStoreEnd {
        worker: WorkerKindV1,
        operation: &'static str,
        succeeded: bool,
        cas_applied: bool,
    },
    #[cfg(test)]
    CasAppliedObservation {
        worker: WorkerKindV1,
    },
    ResponseEnqueueAttempt {
        worker: WorkerKindV1,
        accepted: bool,
    },
    PublishAttempt {
        worker: WorkerKindV1,
        published: bool,
    },
    OutcomeUnknown,
}

pub(crate) trait WorkerTransitionObserverV1: Send + Sync {
    fn observe(&self, event: WorkerTransitionEventV1);
}

#[derive(Debug, Default)]
pub(crate) struct NoopWorkerTransitionObserverV1;

impl WorkerTransitionObserverV1 for NoopWorkerTransitionObserverV1 {
    fn observe(&self, _event: WorkerTransitionEventV1) {}
}

#[async_trait]
pub(crate) trait WorkerPublisherV1: Send + Sync {
    async fn publish(&self, reply: async_nats::Subject, payload: Vec<u8>) -> bool;
}

#[derive(Clone)]
pub(crate) struct NatsWorkerPublisherV1(pub(crate) async_nats::Client);

#[async_trait]
impl WorkerPublisherV1 for NatsWorkerPublisherV1 {
    async fn publish(&self, reply: async_nats::Subject, payload: Vec<u8>) -> bool {
        self.0.publish(reply, payload.into()).await.is_ok()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReceiptDeadlineV1 {
    at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReceiptExpiredV1;

#[derive(Clone, Copy)]
pub(crate) struct WorkerTransitionV1<'a> {
    worker: WorkerKindV1,
    deadline: ReceiptDeadlineV1,
    observer: &'a dyn WorkerTransitionObserverV1,
}

impl<'a> WorkerTransitionV1<'a> {
    pub(crate) fn new(
        worker: WorkerKindV1,
        deadline: ReceiptDeadlineV1,
        observer: &'a dyn WorkerTransitionObserverV1,
    ) -> Self {
        Self {
            worker,
            deadline,
            observer,
        }
    }

    pub(crate) fn dequeued(self) -> Result<(), ReceiptExpiredV1> {
        self.observer.observe(WorkerTransitionEventV1::Dequeued {
            worker: self.worker,
        });
        self.deadline.ensure_open()
    }

    pub(crate) fn post_preflight(self) {
        self.observer
            .observe(WorkerTransitionEventV1::PostPreflight {
                worker: self.worker,
            });
    }

    pub(crate) async fn proxy_store<T, F, C>(
        self,
        operation: &'static str,
        cas_attempted: bool,
        future: F,
        classify: C,
    ) -> Result<T, ReceiptExpiredV1>
    where
        F: Future<Output = T>,
        C: FnOnce(&T) -> (bool, bool),
    {
        self.deadline.ensure_open()?;
        self.observer
            .observe(WorkerTransitionEventV1::ProxyStoreBegin {
                worker: self.worker,
                operation,
                cas_attempted,
            });
        let output = self.deadline.run(future).await?;
        let (succeeded, cas_applied) = classify(&output);
        self.observer
            .observe(WorkerTransitionEventV1::ProxyStoreEnd {
                worker: self.worker,
                operation,
                succeeded,
                cas_applied,
            });
        Ok(output)
    }

    pub(crate) fn response_enqueue(self) -> Result<(), ReceiptExpiredV1> {
        let accepted = self.deadline.ensure_open().is_ok();
        self.observer
            .observe(WorkerTransitionEventV1::ResponseEnqueueAttempt {
                worker: self.worker,
                accepted,
            });
        accepted.then_some(()).ok_or(ReceiptExpiredV1)
    }

    pub(crate) async fn publish<P: WorkerPublisherV1>(
        self,
        publisher: &P,
        reply: async_nats::Subject,
        payload: Vec<u8>,
    ) -> bool {
        let published = self
            .deadline
            .run(publisher.publish(reply, payload))
            .await
            .is_ok_and(|published| published);
        self.observer
            .observe(WorkerTransitionEventV1::PublishAttempt {
                worker: self.worker,
                published,
            });
        published
    }

    pub(crate) fn outcome_unknown(self) {
        self.observer
            .observe(WorkerTransitionEventV1::OutcomeUnknown);
    }

    pub(crate) fn ensure_open(self) -> Result<(), ReceiptExpiredV1> {
        self.deadline.ensure_open()
    }
}

pub(crate) async fn run_observed_worker_message<'a, P, H, F, E>(
    worker: WorkerKindV1,
    deadline: ReceiptDeadlineV1,
    observer: &'a dyn WorkerTransitionObserverV1,
    publisher: &P,
    reply: async_nats::Subject,
    handler: H,
) where
    P: WorkerPublisherV1,
    H: FnOnce(WorkerTransitionV1<'a>) -> F,
    F: Future<Output = Result<Vec<u8>, E>>,
{
    let transition = WorkerTransitionV1::new(worker, deadline, observer);
    if transition.dequeued().is_err() {
        return;
    }
    let Ok(bytes) = handler(transition).await else {
        return;
    };
    // Preserve a scheduling boundary between completed handler work and the
    // response enqueue. The deadline remains receipt-anchored; a task that
    // consumed the remainder of its budget while completing may not enqueue a
    // stale response merely because both operations happened in one poll.
    tokio::task::yield_now().await;
    if transition.response_enqueue().is_err() {
        return;
    }
    transition.publish(publisher, reply, bytes).await;
}

impl ReceiptDeadlineV1 {
    pub(crate) fn private() -> Self {
        Self::from_now(STORE_HANDLER_DEADLINE_MILLIS)
    }

    pub(crate) fn public() -> Self {
        Self::from_now(PUBLIC_HANDLER_DEADLINE_MILLIS)
    }

    pub(crate) fn from_now(millis: u64) -> Self {
        Self {
            at: Instant::now() + Duration::from_millis(millis),
        }
    }

    pub(crate) fn ensure_open(self) -> Result<(), ReceiptExpiredV1> {
        (Instant::now() < self.at)
            .then_some(())
            .ok_or(ReceiptExpiredV1)
    }

    pub(crate) async fn run<F: Future>(self, future: F) -> Result<F::Output, ReceiptExpiredV1> {
        self.ensure_open()?;
        timeout_at(self.at, future)
            .await
            .map_err(|_| ReceiptExpiredV1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicWitnessServiceConfigV1 {
    pub nats_url: String,
    pub nats_credentials_path: String,
    pub tls_ca_path: String,
    pub tls_server_name: String,
    pub witness_key_path: String,
    pub witness_identity: String,
    pub witness_key_id: String,
    pub bucket_name: String,
    pub bucket_configuration_digest: String,
    pub bucket_epoch_digest: String,
    pub bucket_anchor_digest: String,
    pub admission_set_digest: String,
    pub ready_manifest_digest: String,
    pub admission_set: WitnessAdmissionSetV1,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub ingress_queue_capacity: usize,
    pub max_in_flight: usize,
    pub request_deadline_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreProxyServiceConfigV1 {
    pub nats_url: String,
    pub nats_credentials_path: String,
    pub credential_invocation_token: String,
    pub stream_name: String,
    pub tls_ca_path: String,
    pub tls_server_name: String,
    pub pinned_witness_public_key_hex: String,
    pub witness_key_id: String,
    pub bucket_epoch_digest: String,
    pub bucket_anchor_digest: String,
    pub admission_set_digest: String,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub ingress_queue_capacity: usize,
    pub max_in_flight: usize,
    pub subscription_capacity: usize,
    pub client_capacity: usize,
    pub read_buffer_capacity: u16,
    pub request_deadline_millis: u64,
}

impl StoreProxyServiceConfigV1 {
    pub(crate) fn validate_transport(&self) -> ProtocolResult<()> {
        for (field, value) in [
            ("nats_url", self.nats_url.as_str()),
            ("nats_credentials_path", self.nats_credentials_path.as_str()),
            (
                "credential_invocation_token",
                self.credential_invocation_token.as_str(),
            ),
            ("stream_name", self.stream_name.as_str()),
            ("tls_ca_path", self.tls_ca_path.as_str()),
            ("tls_server_name", self.tls_server_name.as_str()),
            (
                "pinned_witness_public_key_hex",
                self.pinned_witness_public_key_hex.as_str(),
            ),
            ("witness_key_id", self.witness_key_id.as_str()),
            ("bucket_epoch_digest", self.bucket_epoch_digest.as_str()),
            ("bucket_anchor_digest", self.bucket_anchor_digest.as_str()),
            ("admission_set_digest", self.admission_set_digest.as_str()),
        ] {
            if value.is_empty() || value.len() > MAX_PROTOCOL_STRING_BYTES {
                return Err(invalid(field, "must be nonempty and bounded"));
            }
        }
        if !self.nats_url.starts_with("tls://") || self.nats_url.contains("skip_verify") {
            return Err(invalid("nats_url", "must use verified tls://"));
        }
        for (field, value) in [
            ("max_request_bytes", self.max_request_bytes),
            ("max_response_bytes", self.max_response_bytes),
            ("ingress_queue_capacity", self.ingress_queue_capacity),
            ("max_in_flight", self.max_in_flight),
            ("subscription_capacity", self.subscription_capacity),
            ("client_capacity", self.client_capacity),
            (
                "read_buffer_capacity",
                usize::from(self.read_buffer_capacity),
            ),
        ] {
            if value == 0 || value > MAX_PROTOCOL_RECORD_BYTES {
                return Err(ProtocolError::Bounds {
                    field: field.to_string(),
                    observed: value,
                    maximum: MAX_PROTOCOL_RECORD_BYTES,
                });
            }
        }
        if self.max_in_flight > self.ingress_queue_capacity || self.request_deadline_millis == 0 {
            return Err(invalid(
                "store_proxy_limits",
                "transport capacities and deadline must be bounded",
            ));
        }
        Ok(())
    }

    pub fn validate_for_ready(&self, ready: &WitnessStoreReadyResultV1) -> ProtocolResult<()> {
        use swarm_crypto::{PublicKey, sha256_hex};

        self.validate_transport()?;
        let public_key = PublicKey::from_hex(&self.pinned_witness_public_key_hex)
            .map_err(|_| invalid("pinned_witness_public_key_hex", "invalid Ed25519 key"))?;
        if sha256_hex(public_key.as_bytes()) != self.witness_key_id {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        ready.validate()?;
        if ready.bucket_epoch.digest()? != self.bucket_epoch_digest
            || ready.bucket_anchor.digest()? != self.bucket_anchor_digest
            || ready.admission_set.admission_set_digest != self.admission_set_digest
            || ready.bucket_configuration.stream_name != self.stream_name
            || ready.bucket_epoch.witness_key_id != self.witness_key_id
            || ready.admission_set.entries.iter().any(|entry| {
                entry.witness_key_id != self.witness_key_id
                    || entry.witness_identity != ready.bucket_epoch.witness_identity
            })
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        if self.max_in_flight > self.ingress_queue_capacity
            || ready.admission_set.entries.iter().any(|entry| {
                entry.max_request_bytes > self.max_request_bytes as u64
                    || entry.max_response_bytes > self.max_response_bytes as u64
            })
        {
            return Err(invalid(
                "store_proxy_limits",
                "admission bounds must fit nonzero service limits",
            ));
        }
        Ok(())
    }
}

impl PublicWitnessServiceConfigV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        for (field, value) in [
            ("nats_url", self.nats_url.as_str()),
            ("nats_credentials_path", self.nats_credentials_path.as_str()),
            ("tls_ca_path", self.tls_ca_path.as_str()),
            ("tls_server_name", self.tls_server_name.as_str()),
            ("witness_key_path", self.witness_key_path.as_str()),
            ("witness_identity", self.witness_identity.as_str()),
            ("witness_key_id", self.witness_key_id.as_str()),
            ("bucket_name", self.bucket_name.as_str()),
            (
                "bucket_configuration_digest",
                self.bucket_configuration_digest.as_str(),
            ),
            ("bucket_epoch_digest", self.bucket_epoch_digest.as_str()),
            ("bucket_anchor_digest", self.bucket_anchor_digest.as_str()),
            ("admission_set_digest", self.admission_set_digest.as_str()),
            ("ready_manifest_digest", self.ready_manifest_digest.as_str()),
        ] {
            if value.is_empty() || value.len() > MAX_PROTOCOL_STRING_BYTES {
                return Err(invalid(field, "must be nonempty and bounded"));
            }
        }
        if !self.nats_url.starts_with("tls://") {
            return Err(invalid("nats_url", "must use tls://"));
        }
        for (field, digest) in [
            ("witness_key_id", self.witness_key_id.as_str()),
            (
                "bucket_configuration_digest",
                self.bucket_configuration_digest.as_str(),
            ),
            ("bucket_epoch_digest", self.bucket_epoch_digest.as_str()),
            ("bucket_anchor_digest", self.bucket_anchor_digest.as_str()),
            ("admission_set_digest", self.admission_set_digest.as_str()),
            ("ready_manifest_digest", self.ready_manifest_digest.as_str()),
        ] {
            if digest.len() != 64
                || digest
                    .bytes()
                    .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
            {
                return Err(invalid(field, "must be a lowercase SHA-256 digest"));
            }
        }
        self.admission_set.validate()?;
        if self.admission_set.admission_set_digest != self.admission_set_digest {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        for admission in &self.admission_set.entries {
            if admission.witness_identity != self.witness_identity
                || admission.witness_key_id != self.witness_key_id
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
        for (field, value) in [
            ("max_request_bytes", self.max_request_bytes),
            ("max_response_bytes", self.max_response_bytes),
            ("ingress_queue_capacity", self.ingress_queue_capacity),
            ("max_in_flight", self.max_in_flight),
        ] {
            if value == 0 || value > MAX_PROTOCOL_RECORD_BYTES {
                return Err(ProtocolError::Bounds {
                    field: field.to_string(),
                    observed: value,
                    maximum: MAX_PROTOCOL_RECORD_BYTES,
                });
            }
        }
        if self.max_in_flight > self.ingress_queue_capacity || self.request_deadline_millis == 0 {
            return Err(invalid(
                "service_limits",
                "max-in-flight must fit the queue and deadline must be nonzero",
            ));
        }
        Ok(())
    }

    pub const fn subject_for(operation: WitnessServiceOperationV1) -> &'static str {
        match operation {
            WitnessServiceOperationV1::Fence => "swarm.governance.witness.v1.fence",
            WitnessServiceOperationV1::Establish => "swarm.governance.witness.v1.establish",
            WitnessServiceOperationV1::Discover => "swarm.governance.witness.v1.discover",
            WitnessServiceOperationV1::Prepare => "swarm.governance.witness.v1.prepare",
            WitnessServiceOperationV1::Commit => "swarm.governance.witness.v1.commit",
            WitnessServiceOperationV1::Abort => "swarm.governance.witness.v1.abort",
            WitnessServiceOperationV1::ReadPrepared => "swarm.governance.witness.v1.read_prepared",
            WitnessServiceOperationV1::ReadHead => "swarm.governance.witness.v1.read_head",
            WitnessServiceOperationV1::FetchPayload => "swarm.governance.witness.v1.fetch_payload",
        }
    }
}

fn invalid(field: &'static str, reason: &'static str) -> ProtocolError {
    ProtocolError::InvalidField {
        field: field.to_string(),
        reason: reason.to_string(),
    }
}
