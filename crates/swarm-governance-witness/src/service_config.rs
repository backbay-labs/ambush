use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::future::Future;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use swarm_governance::persistence_protocol::{
    MAX_PROTOCOL_RECORD_BYTES, MAX_PROTOCOL_STRING_BYTES, ProtocolError, ProtocolResult,
};
use swarm_governance::witness_engine::store::WitnessAdmissionSetV1;
use swarm_governance::witness_engine::store::WitnessStoreReadyResultV1;
use swarm_governance::witness_service::WitnessServiceOperationV1;
#[cfg(test)]
use tokio::sync::{Notify, watch};
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

pub const fn store_response_grant_millis() -> u64 {
    STORE_RESPONSE_GRANT_MILLIS
}

pub const fn public_response_grant_millis() -> u64 {
    PUBLIC_RESPONSE_GRANT_MILLIS
}

pub const fn response_grant_maximum() -> usize {
    RESPONSE_GRANT_MAXIMUM
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct SubscriberPollGateV1 {
    subject: &'static str,
    reached: Arc<AtomicBool>,
    reached_notify: Arc<Notify>,
    release: watch::Receiver<bool>,
}

#[cfg(test)]
pub(crate) struct SubscriberPollGateControlV1 {
    reached: Arc<AtomicBool>,
    reached_notify: Arc<Notify>,
    release: watch::Sender<bool>,
}

#[cfg(test)]
impl SubscriberPollGateV1 {
    pub(crate) fn new(
        subject: &'static str,
    ) -> (SubscriberPollGateV1, SubscriberPollGateControlV1) {
        let reached = Arc::new(AtomicBool::new(false));
        let reached_notify = Arc::new(Notify::new());
        let (release, release_receiver) = watch::channel(false);
        (
            Self {
                subject,
                reached: reached.clone(),
                reached_notify: reached_notify.clone(),
                release: release_receiver,
            },
            SubscriberPollGateControlV1 {
                reached,
                reached_notify,
                release,
            },
        )
    }

    pub(crate) async fn before_first_poll(&mut self, subject: &'static str) {
        if self.subject != subject {
            return;
        }
        self.reached.store(true, Ordering::SeqCst);
        self.reached_notify.notify_waiters();
        while !*self.release.borrow() {
            if self.release.changed().await.is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
impl SubscriberPollGateControlV1 {
    pub(crate) async fn wait_reached(&self) {
        loop {
            // Register before inspecting the predicate. `notify_waiters` does
            // not retain a permit, so checking first can lose the transition
            // between the load and `notified().await`.
            let notified = self.reached_notify.notified();
            if self.reached.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn release(&self) {
        let _ = self.release.send(true);
    }
}

const _: () = assert!(STORE_HANDLER_DEADLINE_MILLIS == 2_000);
const _: () = assert!(STORE_RESPONSE_GRANT_MILLIS == 3_000);
const _: () = assert!(PUBLIC_HANDLER_DEADLINE_MILLIS == 10_000);
const _: () = assert!(PUBLIC_RESPONSE_GRANT_MILLIS == 12_000);
const _: () = assert!(STORE_HANDLER_RESERVE_MILLIS == 1_000);
const _: () = assert!(PUBLIC_PRIVATE_RESERVE_MILLIS == 1_000);
const _: () = assert!(PUBLIC_HANDLER_RESERVE_MILLIS == 2_000);
const _: () = assert!(RESPONSE_GRANT_MAXIMUM == 1);

pub const MAX_SERVICE_WORKERS: usize = 64;
pub const MAX_SERVICE_CHANNEL_ENTRIES: usize = 1_024;
pub const MAX_SERVICE_BUFFERED_BYTES: usize = 512 * 1024 * 1024;
const BUFFER_FRAME_OVERHEAD_BYTES: usize = 1_024;

#[allow(clippy::too_many_arguments)]
pub fn checked_service_buffer_budget(
    max_request_bytes: usize,
    max_response_bytes: usize,
    ingress_capacity: usize,
    subscription_capacity: usize,
    client_capacity: usize,
    worker_count: usize,
    read_buffer_bytes: usize,
) -> ProtocolResult<usize> {
    if max_request_bytes == 0
        || max_response_bytes == 0
        || ingress_capacity == 0
        || subscription_capacity == 0
        || client_capacity == 0
        || worker_count == 0
        || worker_count > MAX_SERVICE_WORKERS
        || ingress_capacity > MAX_SERVICE_CHANNEL_ENTRIES
        || subscription_capacity > MAX_SERVICE_CHANNEL_ENTRIES
        || client_capacity > MAX_SERVICE_CHANNEL_ENTRIES
        || worker_count > ingress_capacity
        || read_buffer_bytes == 0
    {
        return Err(invalid(
            "service_operational_bounds",
            "worker and channel counts must fit closed operational ceilings",
        ));
    }
    let request_frame = max_request_bytes
        .checked_add(BUFFER_FRAME_OVERHEAD_BYTES)
        .ok_or_else(|| invalid("service_buffer_budget", "request frame overflow"))?;
    let response_frame = max_response_bytes
        .checked_add(BUFFER_FRAME_OVERHEAD_BYTES)
        .ok_or_else(|| invalid("service_buffer_budget", "response frame overflow"))?;
    // Shared Bytes payload ownership is counted once in the client-command
    // component. Ingress/subscription frames and each worker's in-flight
    // request/response are distinct owned buffers.
    let components = [
        ingress_capacity.checked_mul(request_frame),
        subscription_capacity.checked_mul(request_frame),
        client_capacity.checked_mul(request_frame.max(response_frame)),
        worker_count.checked_mul(
            request_frame
                .checked_add(response_frame)
                .ok_or_else(|| invalid("service_buffer_budget", "worker frame overflow"))?,
        ),
        Some(read_buffer_bytes),
    ];
    let mut total = 0usize;
    for component in components {
        total = total
            .checked_add(
                component.ok_or_else(|| invalid("service_buffer_budget", "capacity overflow"))?,
            )
            .ok_or_else(|| invalid("service_buffer_budget", "aggregate overflow"))?;
    }
    if total > MAX_SERVICE_BUFFERED_BYTES {
        return Err(ProtocolError::Bounds {
            field: "service_buffer_budget".to_string(),
            observed: total,
            maximum: MAX_SERVICE_BUFFERED_BYTES,
        });
    }
    Ok(total)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeWitnessClientConfigV1 {
    pub nats_url: String,
    pub nats_credentials_path: String,
    pub credential_invocation_token: String,
    pub tls_ca_path: String,
    pub tls_server_name: String,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub subscription_capacity: usize,
    pub client_capacity: usize,
    pub read_buffer_capacity: u16,
    pub request_deadline_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicWitnessProcessConfigV1 {
    pub service: PublicWitnessServiceConfigV1,
    pub credential_invocation_token: String,
    pub subscription_capacity: usize,
    pub client_capacity: usize,
    pub read_buffer_capacity: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreProxyProcessConfigV1 {
    pub service: StoreProxyServiceConfigV1,
    pub ready: WitnessStoreReadyResultV1,
    pub reported_server_version: String,
    pub resolved_server_image_index_digest: String,
}

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
    #[cfg(test)]
    pub(crate) payload: Vec<u8>,
    #[cfg(test)]
    pub(crate) deadline_identity: u64,
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
    #[cfg(test)]
    ReceiptDeadlineIdentity {
        worker: WorkerKindV1,
        identity: u64,
    },
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
    ResponseDeadlineCheck {
        worker: WorkerKindV1,
        open: bool,
    },
    #[serde(rename = "response_enqueue_attempt")]
    ResponseEnqueueAttempt {
        worker: WorkerKindV1,
        enqueued: bool,
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

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResponsePreEnqueueCaptureV1 {
    pub(crate) worker: WorkerKindV1,
    pub(crate) reply: String,
    pub(crate) payload: Vec<u8>,
}

#[cfg(test)]
pub(crate) trait ResponsePreEnqueueObserverV1: Send + Sync {
    fn observe(&self, capture: ResponsePreEnqueueCaptureV1);
}

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct NoopResponsePreEnqueueObserverV1;

#[cfg(test)]
impl ResponsePreEnqueueObserverV1 for NoopResponsePreEnqueueObserverV1 {
    fn observe(&self, _capture: ResponsePreEnqueueCaptureV1) {}
}

#[derive(Clone)]
pub(crate) struct NatsWorkerPublisherV1 {
    client: async_nats::Client,
    #[cfg(test)]
    worker: WorkerKindV1,
    #[cfg(test)]
    observer: Arc<dyn ResponsePreEnqueueObserverV1>,
}

impl NatsWorkerPublisherV1 {
    #[cfg(not(test))]
    pub(crate) fn new(client: async_nats::Client) -> Self {
        Self { client }
    }

    #[cfg(test)]
    pub(crate) fn observed(
        client: async_nats::Client,
        worker: WorkerKindV1,
        observer: Arc<dyn ResponsePreEnqueueObserverV1>,
    ) -> Self {
        Self {
            client,
            worker,
            observer,
        }
    }
}

#[async_trait]
impl WorkerPublisherV1 for NatsWorkerPublisherV1 {
    async fn publish(&self, reply: async_nats::Subject, payload: Vec<u8>) -> bool {
        #[cfg(test)]
        self.observer.observe(ResponsePreEnqueueCaptureV1 {
            worker: self.worker,
            reply: reply.to_string(),
            payload: payload.clone(),
        });
        self.client.publish(reply, payload.into()).await.is_ok()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReceiptDeadlineV1 {
    at: Instant,
    #[cfg(test)]
    identity: u64,
}

#[cfg(test)]
static NEXT_RECEIPT_DEADLINE_IDENTITY: AtomicU64 = AtomicU64::new(0);

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
        #[cfg(test)]
        observer.observe(WorkerTransitionEventV1::ReceiptDeadlineIdentity {
            worker,
            identity: deadline.identity,
        });
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

    pub(crate) fn response_deadline_check(self) -> Result<(), ReceiptExpiredV1> {
        let open = self.deadline.ensure_open().is_ok();
        self.observer
            .observe(WorkerTransitionEventV1::ResponseDeadlineCheck {
                worker: self.worker,
                open,
            });
        open.then_some(()).ok_or(ReceiptExpiredV1)
    }

    pub(crate) async fn publish<P: WorkerPublisherV1>(
        self,
        publisher: &P,
        reply: async_nats::Subject,
        payload: Vec<u8>,
    ) -> bool {
        let enqueued = self
            .deadline
            .run(publisher.publish(reply, payload))
            .await
            .is_ok_and(|enqueued| enqueued);
        self.observer
            .observe(WorkerTransitionEventV1::ResponseEnqueueAttempt {
                worker: self.worker,
                enqueued,
            });
        enqueued
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
    if transition.response_deadline_check().is_err() {
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
            #[cfg(test)]
            identity: NEXT_RECEIPT_DEADLINE_IDENTITY.fetch_add(1, Ordering::SeqCst) + 1,
        }
    }

    #[cfg(test)]
    pub(crate) fn identity_for_test(self) -> u64 {
        self.identity
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

#[cfg(test)]
mod response_enqueue_schema_tests {
    use super::*;

    #[test]
    fn local_enqueue_is_never_serialized_as_publication() {
        let event = WorkerTransitionEventV1::ResponseEnqueueAttempt {
            worker: WorkerKindV1::Public,
            enqueued: true,
        };
        let Ok(encoded) = serde_json::to_string(&event) else {
            panic!("response enqueue serialization failed");
        };
        assert_eq!(
            encoded,
            r#"{"event":"response_enqueue_attempt","worker":"public","enqueued":true}"#
        );
        assert!(!encoded.contains("publish"));
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
            ("read_buffer_capacity", self.read_buffer_capacity.into()),
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
        checked_service_buffer_budget(
            self.max_request_bytes,
            self.max_response_bytes,
            self.ingress_queue_capacity,
            self.subscription_capacity,
            self.client_capacity,
            self.max_in_flight,
            usize::from(self.read_buffer_capacity),
        )?;
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
        if self.max_in_flight > self.ingress_queue_capacity
            || self.max_in_flight > MAX_SERVICE_WORKERS
            || self.ingress_queue_capacity > MAX_SERVICE_CHANNEL_ENTRIES
            || self.request_deadline_millis == 0
        {
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

impl RuntimeWitnessClientConfigV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        for (field, value) in [
            ("nats_url", self.nats_url.as_str()),
            ("nats_credentials_path", self.nats_credentials_path.as_str()),
            (
                "credential_invocation_token",
                self.credential_invocation_token.as_str(),
            ),
            ("tls_ca_path", self.tls_ca_path.as_str()),
            ("tls_server_name", self.tls_server_name.as_str()),
        ] {
            if value.is_empty() || value.len() > MAX_PROTOCOL_STRING_BYTES {
                return Err(invalid(field, "must be nonempty and bounded"));
            }
        }
        let authority = self
            .nats_url
            .strip_prefix("tls://")
            .and_then(|value| value.rsplit_once(':').map(|(host, _)| host));
        if authority != Some(self.tls_server_name.as_str())
            || [
                self.max_request_bytes,
                self.max_response_bytes,
                self.subscription_capacity,
                self.client_capacity,
                usize::from(self.read_buffer_capacity),
            ]
            .into_iter()
            .any(|value| value == 0 || value > MAX_PROTOCOL_RECORD_BYTES)
            || self.request_deadline_millis != PUBLIC_RESPONSE_GRANT_MILLIS
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        checked_service_buffer_budget(
            self.max_request_bytes,
            self.max_response_bytes,
            1,
            self.subscription_capacity,
            self.client_capacity,
            1,
            usize::from(self.read_buffer_capacity),
        )?;
        Ok(())
    }
}

impl PublicWitnessProcessConfigV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        self.service.validate()?;
        validate_process_transport(
            &self.service.nats_url,
            &self.service.nats_credentials_path,
            &self.credential_invocation_token,
            &self.service.tls_ca_path,
            &self.service.tls_server_name,
            self.subscription_capacity,
            self.client_capacity,
            self.read_buffer_capacity,
        )?;
        checked_service_buffer_budget(
            self.service.max_request_bytes,
            self.service.max_response_bytes,
            self.service.ingress_queue_capacity,
            self.subscription_capacity,
            self.client_capacity,
            self.service.max_in_flight,
            usize::from(self.read_buffer_capacity),
        )?;
        Ok(())
    }
}

impl StoreProxyProcessConfigV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        self.service.validate_for_ready(&self.ready)?;
        for (field, value) in [
            (
                "reported_server_version",
                self.reported_server_version.as_str(),
            ),
            (
                "resolved_server_image_index_digest",
                self.resolved_server_image_index_digest.as_str(),
            ),
        ] {
            if value.is_empty() || value.len() > MAX_PROTOCOL_STRING_BYTES {
                return Err(invalid(field, "must be nonempty and bounded"));
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_process_transport(
    nats_url: &str,
    credentials_path: &str,
    invocation_token: &str,
    tls_ca_path: &str,
    tls_server_name: &str,
    subscription_capacity: usize,
    client_capacity: usize,
    read_buffer_capacity: u16,
) -> ProtocolResult<()> {
    for (field, value) in [
        ("nats_url", nats_url),
        ("nats_credentials_path", credentials_path),
        ("credential_invocation_token", invocation_token),
        ("tls_ca_path", tls_ca_path),
        ("tls_server_name", tls_server_name),
    ] {
        if value.is_empty() || value.len() > MAX_PROTOCOL_STRING_BYTES {
            return Err(invalid(field, "must be nonempty and bounded"));
        }
    }
    let host = nats_url
        .strip_prefix("tls://")
        .and_then(|authority| authority.rsplit_once(':').map(|(host, _)| host));
    if host != Some(tls_server_name)
        || [
            subscription_capacity,
            client_capacity,
            usize::from(read_buffer_capacity),
        ]
        .into_iter()
        .any(|value| value == 0 || value > MAX_PROTOCOL_RECORD_BYTES)
        || subscription_capacity > MAX_SERVICE_CHANNEL_ENTRIES
        || client_capacity > MAX_SERVICE_CHANNEL_ENTRIES
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    Ok(())
}

fn invalid(field: &'static str, reason: &'static str) -> ProtocolError {
    ProtocolError::InvalidField {
        field: field.to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod operational_bound_tests {
    use super::*;

    #[test]
    fn operational_counts_and_aggregate_budget_are_closed() {
        assert!(checked_service_buffer_budget(4_096, 4_096, 64, 64, 64, 64, 4_096).is_ok());
        for (ingress, subscriptions, clients, workers) in [
            (1_025, 1, 1, 1),
            (1, 1_025, 1, 1),
            (1, 1, 1_025, 1),
            (65, 1, 1, 65),
        ] {
            assert!(
                checked_service_buffer_budget(
                    4_096,
                    4_096,
                    ingress,
                    subscriptions,
                    clients,
                    workers,
                    4_096,
                )
                .is_err()
            );
        }
        assert!(
            checked_service_buffer_budget(1_048_576, 1_048_576, 1_024, 1_024, 1_024, 64, 65_535,)
                .is_err()
        );
        assert!(checked_service_buffer_budget(usize::MAX, 1, 1, 1, 1, 1, 1).is_err());
    }
}
