use async_trait::async_trait;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use swarm_governance::persistence_protocol::{PROTOCOL_SCHEMA_VERSION, canonical_wire_bytes};
use swarm_governance::witness_engine::store::proxy::WitnessStoreProxy;
use swarm_governance::witness_engine::store::{
    WitnessAtomicStore, WitnessStoreErrorV1, WitnessStoreProxyFailureCodeV1,
    WitnessStoreProxyOperationV1, WitnessStoreProxyRequestV1, WitnessStoreProxyResponseBodyV1,
    WitnessStoreProxyResponseV1, WitnessStoreReadyResultV1,
};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, timeout};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::runtime_client::{
    cancel_and_join_owned_tasks, service_event_is_terminal, wait_for_owned_task_failure,
};
use crate::secure_file::{StableFilePolicyV1, read_stable_file, read_stable_tls_client_config};
use crate::service_config::{
    NatsWorkerPublisherV1, NoopSubscriberAdmissionObserverV1, NoopWorkerTransitionObserverV1,
    ReceiptDeadlineV1, STORE_HANDLER_DEADLINE_MILLIS, STORE_RESPONSE_GRANT_MILLIS,
    SubscriberAdmissionObserverV1, SubscriberAdmissionReceiptV1, WorkerKindV1, WorkerPublisherV1,
    WorkerTransitionObserverV1, WorkerTransitionV1, run_observed_worker_message,
};
#[cfg(test)]
use crate::service_config::{ResponsePreEnqueueObserverV1, SubscriberPollGateV1};
use crate::{
    PublicWitnessProxyTransportErrorV1, PublicWitnessStoreProxyClient, StoreProxyServiceConfigV1,
};

const PRIVATE_STORE_QUEUE_GROUP: &str = "swarm-governance-witness-store-v1";
const PRIVATE_STORE_SUBJECTS: [&str; 3] = [
    "swarm.governance.witness.store.v1.inspect_ready",
    "swarm.governance.witness.store.v1.read_entry",
    "swarm.governance.witness.store.v1.compare_and_swap",
];

pub const fn store_proxy_subjects() -> &'static [&'static str; 3] {
    &PRIVATE_STORE_SUBJECTS
}

fn subject_for(operation: WitnessStoreProxyOperationV1) -> &'static str {
    match operation {
        WitnessStoreProxyOperationV1::InspectReady => PRIVATE_STORE_SUBJECTS[0],
        WitnessStoreProxyOperationV1::ReadEntry => PRIVATE_STORE_SUBJECTS[1],
        WitnessStoreProxyOperationV1::CompareAndSwap => PRIVATE_STORE_SUBJECTS[2],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreProxyServiceErrorV1 {
    #[error("private proxy request is invalid")]
    Invalid,
    #[error("private proxy request exceeds its configured bound")]
    Bounds,
    #[error("private proxy is unavailable")]
    Unavailable,
    #[error("private proxy request timed out")]
    Timeout,
}

/// The sole online owner of a raw atomic-store handle. Its public input is the
/// closed proxy DTO; subjects, KV keys, headers, and raw operations are never
/// accepted from callers.
pub struct StoreProxyService<S> {
    proxy: WitnessStoreProxy<S>,
    config: StoreProxyServiceConfigV1,
    ready: WitnessStoreReadyResultV1,
    ready_binding: StoreProxyReadyBindingV1,
    subscriber_admission_observer: Arc<dyn SubscriberAdmissionObserverV1>,
    worker_observer: Arc<dyn WorkerTransitionObserverV1>,
    #[cfg(test)]
    subscriber_poll_gate: Option<SubscriberPollGateV1>,
    #[cfg(test)]
    response_pre_enqueue_observer: Arc<dyn ResponsePreEnqueueObserverV1>,
}

#[derive(Clone)]
struct StoreProxyReadyBindingV1([u8; 32]);

impl StoreProxyReadyBindingV1 {
    fn validated(
        config: &StoreProxyServiceConfigV1,
        ready: &WitnessStoreReadyResultV1,
    ) -> Result<Self, StoreProxyServiceErrorV1> {
        config
            .validate_for_ready(ready)
            .map_err(|_| StoreProxyServiceErrorV1::Invalid)?;
        let canonical = canonical_wire_bytes(&(config, ready))
            .map_err(|_| StoreProxyServiceErrorV1::Invalid)?;
        let mut preimage = b"swarm.phase285.store-proxy-ready-binding.v1".to_vec();
        preimage.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
        preimage.extend_from_slice(&canonical);
        let digest = Sha256::digest(preimage);
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        Ok(Self(bytes))
    }

    fn constant_time_matches(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
    }
}

struct SelectedProxyRequestV1 {
    request: WitnessStoreProxyRequestV1,
    max_response_bytes: usize,
}

impl<S: WitnessAtomicStore> StoreProxyService<S> {
    pub fn new(
        config: StoreProxyServiceConfigV1,
        ready: WitnessStoreReadyResultV1,
        store: S,
    ) -> Result<Self, StoreProxyServiceErrorV1> {
        let ready_binding = StoreProxyReadyBindingV1::validated(&config, &ready)?;
        let proxy = WitnessStoreProxy::new(store, ready.clone())
            .map_err(|_| StoreProxyServiceErrorV1::Invalid)?;
        Ok(Self {
            proxy,
            config,
            ready,
            ready_binding,
            subscriber_admission_observer: Arc::new(NoopSubscriberAdmissionObserverV1),
            worker_observer: Arc::new(NoopWorkerTransitionObserverV1),
            #[cfg(test)]
            subscriber_poll_gate: None,
            #[cfg(test)]
            response_pre_enqueue_observer: Arc::new(
                crate::service_config::NoopResponsePreEnqueueObserverV1,
            ),
        })
    }

    #[cfg(test)]
    pub(crate) fn observe_subscriber_admissions_for_test(
        &mut self,
        observer: Arc<dyn SubscriberAdmissionObserverV1>,
    ) {
        self.subscriber_admission_observer = observer;
    }

    #[cfg(test)]
    pub(crate) fn observe_worker_transitions_for_test(
        &mut self,
        observer: Arc<dyn WorkerTransitionObserverV1>,
    ) {
        self.worker_observer = observer;
    }

    #[cfg(test)]
    pub(crate) fn hold_first_subscription_poll_for_test(&mut self, gate: SubscriberPollGateV1) {
        self.subscriber_poll_gate = Some(gate);
    }

    #[cfg(test)]
    pub(crate) fn observe_response_pre_enqueue_for_test(
        &mut self,
        observer: Arc<dyn ResponsePreEnqueueObserverV1>,
    ) {
        self.response_pre_enqueue_observer = observer;
    }

    pub async fn handle_subject_bytes(
        &self,
        subject: &str,
        raw: &[u8],
    ) -> Result<Vec<u8>, StoreProxyServiceErrorV1> {
        self.handle_subject_bytes_before(
            subject,
            raw,
            ReceiptDeadlineV1::private(),
            &NoopWorkerTransitionObserverV1,
        )
        .await
    }

    pub(crate) async fn handle_subject_bytes_before(
        &self,
        subject: &str,
        raw: &[u8],
        receipt_deadline: ReceiptDeadlineV1,
        observer: &dyn WorkerTransitionObserverV1,
    ) -> Result<Vec<u8>, StoreProxyServiceErrorV1> {
        if receipt_deadline.ensure_open().is_err() {
            return Err(StoreProxyServiceErrorV1::Timeout);
        }
        if raw.len() > self.config.max_request_bytes {
            return Err(StoreProxyServiceErrorV1::Bounds);
        }
        let selected = self.preflight(subject, raw)?;
        let transition = WorkerTransitionV1::new(WorkerKindV1::Private, receipt_deadline, observer);
        transition.post_preflight();
        tokio::task::yield_now().await;
        let operation = operation_label(selected.request.operation);
        let cas_attempted =
            selected.request.operation == WitnessStoreProxyOperationV1::CompareAndSwap;
        let response = transition
            .proxy_store(
                operation,
                cas_attempted,
                self.proxy.handle_bytes(raw),
                |response| {
                    let succeeded = response.is_ok();
                    let cas_applied = response.as_ref().is_ok_and(|response| {
                        matches!(
                            &response.body,
                            WitnessStoreProxyResponseBodyV1::CasApplied { .. }
                        )
                    });
                    (succeeded, cas_applied)
                },
            )
            .await
            .map_err(|_| StoreProxyServiceErrorV1::Timeout)?;
        let response = response.map_err(map_store_error)?;
        if transition.ensure_open().is_err() {
            return Err(StoreProxyServiceErrorV1::Timeout);
        }
        let bytes = response
            .canonical_bytes()
            .map_err(|_| StoreProxyServiceErrorV1::Invalid)?;
        if bytes.len() > selected.max_response_bytes {
            return Err(StoreProxyServiceErrorV1::Bounds);
        }
        Ok(bytes)
    }

    fn preflight(
        &self,
        subject: &str,
        raw: &[u8],
    ) -> Result<SelectedProxyRequestV1, StoreProxyServiceErrorV1> {
        let request = WitnessStoreProxyRequestV1::decode(raw)
            .map_err(|_| StoreProxyServiceErrorV1::Invalid)?;
        if subject != subject_for(request.operation)
            || request.signature.public_key_hex != self.config.pinned_witness_public_key_hex
            || request.witness_key_id != self.config.witness_key_id
            || request.bucket_epoch_digest != self.config.bucket_epoch_digest
            || request.bucket_anchor_digest != self.config.bucket_anchor_digest
            || request.admission_digest.is_empty()
        {
            return Err(StoreProxyServiceErrorV1::Invalid);
        }
        request
            .validate_signature()
            .map_err(|_| StoreProxyServiceErrorV1::Invalid)?;
        let admission = match &request.body {
            swarm_governance::witness_engine::store::WitnessStoreProxyRequestBodyV1::InspectReady => self
                .ready
                .admission_set
                .entries
                .iter()
                .find(|entry| entry.admission_digest == request.admission_digest),
            swarm_governance::witness_engine::store::WitnessStoreProxyRequestBodyV1::ReadEntry { stream_id }
            | swarm_governance::witness_engine::store::WitnessStoreProxyRequestBodyV1::CompareAndSwap { stream_id, .. } => {
                self.ready.entry(stream_id)
            }
        }
        .ok_or(StoreProxyServiceErrorV1::Invalid)?;
        if request.admission_digest != admission.admission_digest
            || raw.len() as u64 > admission.max_request_bytes
        {
            return Err(StoreProxyServiceErrorV1::Bounds);
        }
        let selected_response_bytes = usize::try_from(admission.max_response_bytes)
            .map_err(|_| StoreProxyServiceErrorV1::Bounds)?;
        Ok(SelectedProxyRequestV1 {
            request,
            max_response_bytes: self.config.max_response_bytes.min(selected_response_bytes),
        })
    }

    fn overload_response(&self, subject: &str, raw: &[u8]) -> Option<Vec<u8>> {
        let selected = self.preflight(subject, raw).ok()?;
        let request = selected.request;
        let response = WitnessStoreProxyResponseV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: request.operation,
            request_digest: request.request_digest,
            body: WitnessStoreProxyResponseBodyV1::Refused {
                failure_code: WitnessStoreProxyFailureCodeV1::Unavailable,
                observed_revision: None,
                observed_value_digest: None,
            },
        };
        let bytes = response.canonical_bytes().ok()?;
        (bytes.len() <= selected.max_response_bytes).then_some(bytes)
    }
}

const fn operation_label(operation: WitnessStoreProxyOperationV1) -> &'static str {
    match operation {
        WitnessStoreProxyOperationV1::InspectReady => "inspect_ready",
        WitnessStoreProxyOperationV1::ReadEntry => "read_entry",
        WitnessStoreProxyOperationV1::CompareAndSwap => "compare_and_swap",
    }
}

fn map_store_error(error: WitnessStoreErrorV1) -> StoreProxyServiceErrorV1 {
    match error {
        WitnessStoreErrorV1::Bounds => StoreProxyServiceErrorV1::Bounds,
        WitnessStoreErrorV1::Unavailable | WitnessStoreErrorV1::Ambiguous => {
            StoreProxyServiceErrorV1::Unavailable
        }
        _ => StoreProxyServiceErrorV1::Invalid,
    }
}

pub(crate) struct PrivateIngressMessage {
    pub(crate) subject: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) reply: async_nats::Subject,
    pub(crate) receipt_deadline: ReceiptDeadlineV1,
}

pub(crate) async fn run_private_worker_message<S: WitnessAtomicStore, P: WorkerPublisherV1>(
    service: &StoreProxyService<S>,
    message: PrivateIngressMessage,
    observer: &dyn WorkerTransitionObserverV1,
    publisher: &P,
) {
    run_observed_worker_message(
        WorkerKindV1::Private,
        message.receipt_deadline,
        observer,
        publisher,
        message.reply,
        |_| {
            service.handle_subject_bytes_before(
                &message.subject,
                &message.payload,
                message.receipt_deadline,
                observer,
            )
        },
    )
    .await;
}

pub(crate) async fn receive_and_run_private_worker_message<
    S: WitnessAtomicStore,
    P: WorkerPublisherV1,
>(
    receiver: &Mutex<mpsc::Receiver<PrivateIngressMessage>>,
    service: &StoreProxyService<S>,
    observer: &dyn WorkerTransitionObserverV1,
    publisher: &P,
) -> bool {
    let message = {
        let mut guard = receiver.lock().await;
        guard.recv().await
    };
    let Some(message) = message else {
        return false;
    };
    run_private_worker_message(service, message, observer, publisher).await;
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreProxyRunnerErrorV1 {
    #[error("private proxy transport configuration failed")]
    Configuration,
    #[error("private proxy transport authentication failed")]
    Authentication,
    #[error("private proxy subscription setup failed")]
    Subscription,
    #[error("private proxy task exited unexpectedly")]
    TaskExit,
    #[error("private proxy shutdown failed")]
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct StoreRoleCredentialFileV1 {
    schema_version: u32,
    role: String,
    username: String,
    password: String,
    invocation_token: String,
}

/// Opaque proof that the private runner established the configured TLS session
/// using a credential file explicitly scoped to the online store role.
pub struct StoreRoleConnectionV1 {
    client: async_nats::Client,
    ready_binding: StoreProxyReadyBindingV1,
    lifecycle_events: Option<mpsc::Receiver<async_nats::Event>>,
}

impl StoreRoleConnectionV1 {
    pub async fn connect(
        config: &StoreProxyServiceConfigV1,
        ready: &WitnessStoreReadyResultV1,
    ) -> Result<Self, StoreProxyRunnerErrorV1> {
        Self::connect_with_event_observer(config, ready, None).await
    }

    #[cfg(test)]
    pub(crate) async fn connect_observed_for_test(
        config: &StoreProxyServiceConfigV1,
        ready: &WitnessStoreReadyResultV1,
    ) -> Result<(Self, mpsc::UnboundedReceiver<async_nats::Event>), StoreProxyRunnerErrorV1> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let connection = Self::connect_with_event_observer(config, ready, Some(sender)).await?;
        Ok((connection, receiver))
    }

    async fn connect_with_event_observer(
        config: &StoreProxyServiceConfigV1,
        ready: &WitnessStoreReadyResultV1,
        event_observer: Option<mpsc::UnboundedSender<async_nats::Event>>,
    ) -> Result<Self, StoreProxyRunnerErrorV1> {
        let ready_binding = StoreProxyReadyBindingV1::validated(config, ready)
            .map_err(|_| StoreProxyRunnerErrorV1::Configuration)?;
        let authority =
            tls_authority(&config.nats_url).ok_or(StoreProxyRunnerErrorV1::Configuration)?;
        if authority != config.tls_server_name {
            return Err(StoreProxyRunnerErrorV1::Configuration);
        }
        let tls_client_config = read_stable_tls_client_config(&config.tls_ca_path, 1_048_576)
            .map_err(|_| StoreProxyRunnerErrorV1::Configuration)?;
        let raw = read_stable_file(
            &config.nats_credentials_path,
            4_096,
            StableFilePolicyV1::Private,
        )
        .map_err(|_| StoreProxyRunnerErrorV1::Configuration)?;
        let credentials: StoreRoleCredentialFileV1 =
            serde_json::from_slice(&raw).map_err(|_| StoreProxyRunnerErrorV1::Configuration)?;
        let canonical = Zeroizing::new(
            serde_json::to_vec(&credentials).map_err(|_| StoreProxyRunnerErrorV1::Configuration)?,
        );
        if canonical.as_slice() != raw.as_slice()
            || credentials.schema_version != PROTOCOL_SCHEMA_VERSION
            || credentials.role != "witness-store"
            || credentials.invocation_token != config.credential_invocation_token
            || credentials.username.is_empty()
            || credentials.password.is_empty()
        {
            return Err(StoreProxyRunnerErrorV1::Configuration);
        }
        let username = Zeroizing::new(credentials.username.clone());
        let password = Zeroizing::new(credentials.password.clone());
        let (lifecycle_sender, lifecycle_events) = mpsc::channel(1_024);
        let options = async_nats::ConnectOptions::with_user_and_password(
            username.to_string(),
            password.to_string(),
        )
        .require_tls(true)
        .tls_client_config(tls_client_config)
        .subscription_capacity(config.subscription_capacity)
        .client_capacity(config.client_capacity)
        .read_buffer_capacity(config.read_buffer_capacity)
        .connection_timeout(Duration::from_millis(config.request_deadline_millis))
        .request_timeout(Some(Duration::from_millis(config.request_deadline_millis)))
        .max_reconnects(Some(1))
        .event_callback(move |event| {
            let observer = event_observer.clone();
            let lifecycle_sender = lifecycle_sender.clone();
            async move {
                let _ = lifecycle_sender.send(event.clone()).await;
                if let Some(observer) = observer {
                    let _ = observer.send(event);
                }
            }
        });
        let client = timeout(
            Duration::from_millis(config.request_deadline_millis),
            options.connect(&config.nats_url),
        )
        .await
        .map_err(|_| StoreProxyRunnerErrorV1::Authentication)?
        .map_err(|_| StoreProxyRunnerErrorV1::Authentication)?;
        timeout(
            Duration::from_millis(config.request_deadline_millis),
            client.flush(),
        )
        .await
        .map_err(|_| StoreProxyRunnerErrorV1::Authentication)?
        .map_err(|_| StoreProxyRunnerErrorV1::Authentication)?;
        Ok(Self {
            client,
            ready_binding,
            lifecycle_events: Some(lifecycle_events),
        })
    }

    #[cfg(test)]
    pub(crate) fn server_client_id_for_test(&self) -> u64 {
        self.client.server_info().client_id
    }

    #[cfg(test)]
    pub(crate) fn client_for_test(&self) -> async_nats::Client {
        self.client.clone()
    }
}

fn tls_authority(url: &str) -> Option<&str> {
    let authority = url.strip_prefix("tls://")?;
    if authority.contains('@') || authority.contains('/') || authority.contains('?') {
        return None;
    }
    authority.rsplit_once(':').map(|(host, _)| host)
}

pub struct StoreProxyServiceRunner<S> {
    tasks: Vec<tokio::task::JoinHandle<()>>,
    client: Option<async_nats::Client>,
    ready: Arc<AtomicBool>,
    stop_result: Option<Result<(), StoreProxyRunnerErrorV1>>,
    _service: std::marker::PhantomData<S>,
}

impl<S: WitnessAtomicStore + 'static> StoreProxyServiceRunner<S> {
    pub async fn start(
        connection: StoreRoleConnectionV1,
        service: StoreProxyService<S>,
    ) -> Result<Self, StoreProxyRunnerErrorV1> {
        Self::start_inner(connection, service).await
    }

    async fn start_inner(
        connection: StoreRoleConnectionV1,
        service: StoreProxyService<S>,
    ) -> Result<Self, StoreProxyRunnerErrorV1> {
        if !connection
            .ready_binding
            .constant_time_matches(&service.ready_binding)
        {
            return Err(StoreProxyRunnerErrorV1::Configuration);
        }
        let client = connection.client;
        let mut lifecycle_events = connection
            .lifecycle_events
            .ok_or(StoreProxyRunnerErrorV1::Configuration)?;
        timeout(
            Duration::from_millis(service.config.request_deadline_millis),
            async_nats::jetstream::new(client.clone()).get_stream(&service.config.stream_name),
        )
        .await
        .map_err(|_| StoreProxyRunnerErrorV1::Authentication)?
        .map_err(|_| StoreProxyRunnerErrorV1::Authentication)?;
        let inspect = client
            .queue_subscribe(
                PRIVATE_STORE_SUBJECTS[0],
                PRIVATE_STORE_QUEUE_GROUP.to_string(),
            )
            .await
            .map_err(|_| StoreProxyRunnerErrorV1::Subscription)?;
        let read = client
            .queue_subscribe(
                PRIVATE_STORE_SUBJECTS[1],
                PRIVATE_STORE_QUEUE_GROUP.to_string(),
            )
            .await
            .map_err(|_| StoreProxyRunnerErrorV1::Subscription)?;
        let cas = client
            .queue_subscribe(
                PRIVATE_STORE_SUBJECTS[2],
                PRIVATE_STORE_QUEUE_GROUP.to_string(),
            )
            .await
            .map_err(|_| StoreProxyRunnerErrorV1::Subscription)?;
        client
            .flush()
            .await
            .map_err(|_| StoreProxyRunnerErrorV1::Subscription)?;
        let capacity = service.config.ingress_queue_capacity;
        let worker_count = service.config.max_in_flight;
        let max_request_bytes = service.config.max_request_bytes;
        let admission_observer = service.subscriber_admission_observer.clone();
        let observer = service.worker_observer.clone();
        #[cfg(test)]
        let subscriber_poll_gate = service.subscriber_poll_gate.clone();
        let service = Arc::new(service);
        let (sender, receiver) = mpsc::channel(capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut tasks = Vec::with_capacity(3 + worker_count);
        for (subject, subscriber) in [
            (PRIVATE_STORE_SUBJECTS[0], inspect),
            (PRIVATE_STORE_SUBJECTS[1], read),
            (PRIVATE_STORE_SUBJECTS[2], cas),
        ] {
            let sender = sender.clone();
            let client = client.clone();
            let service = service.clone();
            let admission_observer = admission_observer.clone();
            #[cfg(test)]
            let mut subscriber_poll_gate = subscriber_poll_gate.clone();
            tasks.push(tokio::spawn(async move {
                let mut subscriber = subscriber;
                #[cfg(test)]
                if let Some(gate) = subscriber_poll_gate.as_mut() {
                    gate.before_first_poll(subject).await;
                }
                while let Some(message) = subscriber.next().await {
                    if let Some(Err((reply, payload))) = admit_private_subscription_message(
                        subject,
                        message,
                        &sender,
                        admission_observer.as_ref(),
                        max_request_bytes,
                    ) && let Some(bytes) = service.overload_response(subject, &payload)
                    {
                        let _ = client.publish(reply, bytes.into()).await;
                    }
                }
            }));
        }
        drop(sender);
        #[cfg(not(test))]
        let publisher = Arc::new(NatsWorkerPublisherV1::new(client.clone()));
        #[cfg(test)]
        let publisher = Arc::new(NatsWorkerPublisherV1::observed(
            client.clone(),
            WorkerKindV1::Private,
            service.response_pre_enqueue_observer.clone(),
        ));
        for _ in 0..worker_count {
            let receiver = receiver.clone();
            let service = service.clone();
            let observer = observer.clone();
            let publisher = publisher.clone();
            tasks.push(tokio::spawn(async move {
                while receive_and_run_private_worker_message(
                    receiver.as_ref(),
                    service.as_ref(),
                    observer.as_ref(),
                    publisher.as_ref(),
                )
                .await
                {}
            }));
        }
        tasks.push(tokio::spawn(async move {
            while let Some(event) = lifecycle_events.recv().await {
                if service_event_is_terminal(&event) {
                    return;
                }
            }
        }));
        Ok(Self {
            tasks,
            client: Some(client),
            ready: Arc::new(AtomicBool::new(true)),
            stop_result: None,
            _service: std::marker::PhantomData,
        })
    }

    pub async fn wait_for_failure(&mut self) -> Result<(), StoreProxyRunnerErrorV1> {
        if self.tasks.is_empty() {
            self.ready.store(false, Ordering::SeqCst);
            return Err(StoreProxyRunnerErrorV1::TaskExit);
        }
        wait_for_owned_task_failure(&mut self.tasks).await;
        self.ready.store(false, Ordering::SeqCst);
        Err(StoreProxyRunnerErrorV1::TaskExit)
    }

    pub async fn stop_and_wait(
        &mut self,
        deadline: tokio::time::Duration,
    ) -> Result<(), StoreProxyRunnerErrorV1> {
        if let Some(result) = self.stop_result {
            return result;
        }
        // Fail closed if this future is cancelled. A later call reports the
        // same terminal shutdown failure and never starts a second drain.
        self.stop_result = Some(Err(StoreProxyRunnerErrorV1::Shutdown));
        self.ready.store(false, Ordering::SeqCst);
        let client = &self.client;
        let result = match tokio::time::timeout(deadline, async {
            let task_result = cancel_and_join_owned_tasks(&mut self.tasks).await;
            let drain_result = async {
                if let Some(client) = client.as_ref() {
                    client
                        .drain()
                        .await
                        .map_err(|_| StoreProxyRunnerErrorV1::Shutdown)?;
                }
                Ok(())
            }
            .await;
            if task_result.is_err() {
                Err(StoreProxyRunnerErrorV1::TaskExit)
            } else {
                drain_result
            }
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(StoreProxyRunnerErrorV1::Shutdown),
        };
        self.client.take();
        self.stop_result = Some(result);
        result
    }
}

pub(crate) fn admit_private_subscription_message(
    expected_subject: &'static str,
    message: async_nats::Message,
    ingress: &mpsc::Sender<PrivateIngressMessage>,
    admission_observer: &dyn SubscriberAdmissionObserverV1,
    max_request_bytes: usize,
) -> Option<Result<(), (async_nats::Subject, Vec<u8>)>> {
    if message.subject.as_str() != expected_subject {
        return None;
    }
    if message.payload.len() > max_request_bytes {
        return None;
    }
    let reply = message.reply?;
    if !bounded_inbox(&reply) {
        return None;
    }
    let receipt_deadline = ReceiptDeadlineV1::private();
    let payload = message.payload.to_vec();
    let receipt = SubscriberAdmissionReceiptV1 {
        worker: WorkerKindV1::Private,
        subject: expected_subject.to_string(),
        payload_sha256: swarm_crypto::sha256_hex(&payload),
        #[cfg(test)]
        payload: payload.clone(),
        #[cfg(test)]
        deadline_identity: receipt_deadline.identity_for_test(),
        reply: reply.to_string(),
        deadline_millis: STORE_HANDLER_DEADLINE_MILLIS,
    };
    let ingress_message = PrivateIngressMessage {
        subject: expected_subject.to_string(),
        payload: payload.clone(),
        reply: reply.clone(),
        receipt_deadline,
    };
    if ingress.try_send(ingress_message).is_err() {
        return Some(Err((reply, payload)));
    }
    admission_observer.accepted(receipt);
    Some(Ok(()))
}

impl<S> Drop for StoreProxyServiceRunner<S> {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn bounded_inbox(subject: &async_nats::Subject) -> bool {
    let value = subject.as_str();
    (value.starts_with("_INBOX.") || value.starts_with("_R_."))
        && value.len() <= 512
        && !value.contains('*')
        && !value.contains('>')
}

pub fn private_store_ingress_overload_control() -> bool {
    let (sender, _receiver) = mpsc::channel::<u8>(1);
    sender.try_send(1).is_ok() && sender.try_send(2).is_err()
}

#[derive(Clone)]
pub struct NatsPublicWitnessStoreProxyClient {
    client: async_nats::Client,
    max_request_bytes: usize,
    max_response_bytes: usize,
}

fn map_store_request_error(
    kind: async_nats::RequestErrorKind,
) -> PublicWitnessProxyTransportErrorV1 {
    match kind {
        async_nats::RequestErrorKind::TimedOut | async_nats::RequestErrorKind::Other => {
            PublicWitnessProxyTransportErrorV1::OutcomeUnknown
        }
        async_nats::RequestErrorKind::NoResponders => {
            PublicWitnessProxyTransportErrorV1::Unavailable
        }
        async_nats::RequestErrorKind::InvalidSubject => PublicWitnessProxyTransportErrorV1::Framing,
    }
}

impl NatsPublicWitnessStoreProxyClient {
    pub fn new(
        client: async_nats::Client,
        max_request_bytes: usize,
        max_response_bytes: usize,
        request_deadline_millis: u64,
    ) -> Result<Self, PublicWitnessProxyTransportErrorV1> {
        if max_request_bytes == 0 || max_response_bytes == 0 {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        validate_store_proxy_client_deadline(request_deadline_millis)?;
        Ok(Self {
            client,
            max_request_bytes,
            max_response_bytes,
        })
    }

    async fn request(
        &self,
        request: WitnessStoreProxyRequestV1,
        operation: WitnessStoreProxyOperationV1,
    ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
        self.request_on_subject(request, operation, subject_for(operation))
            .await
    }

    async fn request_on_subject(
        &self,
        request: WitnessStoreProxyRequestV1,
        operation: WitnessStoreProxyOperationV1,
        subject: &str,
    ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
        if request.operation != operation {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        let request_digest = request.request_digest.clone();
        let bytes = canonical_wire_bytes(&request)
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        self.request_bytes_on_subject(bytes, operation, subject, &request_digest)
            .await
    }

    async fn request_bytes_on_subject(
        &self,
        request_bytes: Vec<u8>,
        operation: WitnessStoreProxyOperationV1,
        subject: &str,
        request_digest: &str,
    ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
        if request_bytes.len() > self.max_request_bytes {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        let message = timeout(
            Duration::from_millis(STORE_RESPONSE_GRANT_MILLIS),
            self.client
                .request(subject.to_string(), request_bytes.into()),
        )
        .await
        .map_err(|_| PublicWitnessProxyTransportErrorV1::OutcomeUnknown)?
        .map_err(|error| map_store_request_error(error.kind()))?;
        if message.payload.len() > self.max_response_bytes {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        let response = WitnessStoreProxyResponseV1::decode(&message.payload)
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        if response.operation != operation || response.request_digest != request_digest {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        Ok(response)
    }

    #[cfg(test)]
    pub(crate) async fn request_on_subject_for_test(
        &self,
        request: WitnessStoreProxyRequestV1,
        operation: WitnessStoreProxyOperationV1,
        subject: &str,
    ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
        self.request_on_subject(request, operation, subject).await
    }

    #[cfg(test)]
    pub(crate) async fn replay_canonical_request_for_test(
        &self,
        request_bytes: &[u8],
        operation: WitnessStoreProxyOperationV1,
    ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
        let request = WitnessStoreProxyRequestV1::decode(request_bytes)
            .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
        if request.operation != operation {
            return Err(PublicWitnessProxyTransportErrorV1::Framing);
        }
        let request_digest = request.request_digest;
        self.request_bytes_on_subject(
            request_bytes.to_vec(),
            operation,
            subject_for(operation),
            &request_digest,
        )
        .await
    }
}

pub(crate) fn validate_store_proxy_client_deadline(
    request_deadline_millis: u64,
) -> Result<(), PublicWitnessProxyTransportErrorV1> {
    if request_deadline_millis != STORE_RESPONSE_GRANT_MILLIS {
        return Err(PublicWitnessProxyTransportErrorV1::Framing);
    }
    Ok(())
}

#[async_trait]
impl PublicWitnessStoreProxyClient for NatsPublicWitnessStoreProxyClient {
    async fn inspect_ready(
        &self,
        request: WitnessStoreProxyRequestV1,
    ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
        self.request(request, WitnessStoreProxyOperationV1::InspectReady)
            .await
    }

    async fn read_entry(
        &self,
        request: WitnessStoreProxyRequestV1,
    ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
        self.request(request, WitnessStoreProxyOperationV1::ReadEntry)
            .await
    }

    async fn compare_and_swap(
        &self,
        request: WitnessStoreProxyRequestV1,
    ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
        self.request(request, WitnessStoreProxyOperationV1::CompareAndSwap)
            .await
    }
}
