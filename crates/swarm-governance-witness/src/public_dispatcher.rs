use async_trait::async_trait;
use futures_util::StreamExt;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use swarm_crypto::{DetachedSignature, Ed25519Signer, sha256_hex};
use swarm_governance::persistence_protocol::{
    MAX_PROTOCOL_STRING_BYTES, PROTOCOL_SCHEMA_VERSION, ProtocolError, ProtocolResult,
    RecoveryChallengeV1, WITNESS_PREPARED_STATE_DOMAIN_V1, WITNESS_SESSION_STATE_DOMAIN_V1,
    WitnessAbortOutcomeV1, WitnessAbortedV1, WitnessCommitOutcomeV1, WitnessCommittedV1,
    WitnessDiscoveryAttestationV1, WitnessDiscoveryV1, WitnessGenesisAbortedV1,
    WitnessOperationOutcomeV1, WitnessOperationV1, WitnessOutcomeAttestationV1,
    WitnessPrepareOutcomeV1, WitnessReadAttestationV1, WitnessReadResponseV1,
    WitnessSessionAttestationV1, WitnessSessionRotationReceiptV1,
    WitnessSessionRotationResponseKindV1, WitnessSessionStateFenceV1, WitnessSessionV1,
    canonical_wire_bytes, digest_domain,
};
use swarm_governance::witness_engine::store::{
    WitnessAdmissionEntryV1, WitnessBucketManifestPhaseV1, WitnessStoreProxyFailureCodeV1,
    WitnessStoreProxyOperationV1, WitnessStoreProxyRequestBodyV1, WitnessStoreProxyRequestV1,
    WitnessStoreProxyResponseBodyV1, WitnessStoreProxyResponseV1, WitnessStreamInitializationV1,
};
use swarm_governance::witness_engine::{
    WitnessStoreEnvelopeV1, WitnessStoreExpectationV1, WitnessStoreTransitionV1,
    WitnessStoredCandidateV1, validate_store_transition, witness_stream_key,
};
use swarm_governance::witness_service::{
    VerifiedPrepareResolutionV1, VerifiedWitnessStoreStateV1, WitnessPrepareVerificationV1,
    WitnessServiceFailureAttestationV1, WitnessServiceFailureCodeV1, WitnessServiceFailureV1,
    WitnessServiceOperationV1, WitnessServiceRequestBodyV1, WitnessServiceRequestV1,
    WitnessServiceResponseV1, prepare_verified_candidate, verify_public_prepare,
};
use tokio::sync::{Mutex, Semaphore, mpsc};

use crate::PublicWitnessServiceConfigV1;
use crate::service_config::{
    NatsWorkerPublisherV1, NoopSubscriberAdmissionObserverV1, NoopWorkerTransitionObserverV1,
    PUBLIC_HANDLER_DEADLINE_MILLIS, ReceiptDeadlineV1, SubscriberAdmissionObserverV1,
    SubscriberAdmissionReceiptV1, WorkerKindV1, WorkerPublisherV1, WorkerTransitionEventV1,
    WorkerTransitionObserverV1, WorkerTransitionV1, run_observed_worker_message,
};
#[cfg(test)]
use crate::service_config::{ResponsePreEnqueueObserverV1, SubscriberPollGateV1};

tokio::task_local! {
    static ACTIVE_CAS_ATTEMPTED: Arc<AtomicBool>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PublicWitnessProxyTransportErrorV1 {
    #[error("proxy framing failure")]
    Framing,
    #[error("proxy timeout")]
    Timeout,
    #[error("proxy unavailable")]
    Unavailable,
    #[error("proxy mutation outcome is unknown")]
    OutcomeUnknown,
}

#[async_trait]
pub trait PublicWitnessStoreProxyClient: Send + Sync {
    async fn inspect_ready(
        &self,
        request: WitnessStoreProxyRequestV1,
    ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1>;

    async fn read_entry(
        &self,
        request: WitnessStoreProxyRequestV1,
    ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1>;

    async fn compare_and_swap(
        &self,
        request: WitnessStoreProxyRequestV1,
    ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1>;
}

#[derive(Debug, thiserror::Error)]
pub enum PublicWitnessDispatchErrorV1 {
    #[error("public witness request is invalid")]
    Invalid,
    #[error("public witness ingress is overloaded")]
    Overloaded,
    #[error("public witness proxy unavailable")]
    Unavailable,
    #[error("public witness request timed out")]
    Timeout,
    #[error("public witness response exceeds configured bound")]
    ResponseBounds,
    #[error("public witness mutation outcome is unknown")]
    OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicWitnessDispatchMappingV1 {
    pub method: &'static str,
    pub operation: WitnessServiceOperationV1,
    pub subject: &'static str,
    pub response_variant: &'static str,
    pub session_authorization: bool,
}

const DISPATCHER_MAPPING: [PublicWitnessDispatchMappingV1; 9] = [
    mapping(
        "issue_session_fence",
        WitnessServiceOperationV1::Fence,
        "Fence",
        false,
    ),
    mapping(
        "establish_session",
        WitnessServiceOperationV1::Establish,
        "Establish",
        false,
    ),
    mapping(
        "discover_stream",
        WitnessServiceOperationV1::Discover,
        "Discover",
        false,
    ),
    mapping(
        "prepare_successor",
        WitnessServiceOperationV1::Prepare,
        "Outcome",
        true,
    ),
    mapping(
        "commit_prepared",
        WitnessServiceOperationV1::Commit,
        "Outcome",
        true,
    ),
    mapping(
        "abort_prepared",
        WitnessServiceOperationV1::Abort,
        "Outcome",
        true,
    ),
    mapping(
        "read_prepared_for_stream",
        WitnessServiceOperationV1::ReadPrepared,
        "Read",
        true,
    ),
    mapping(
        "read_head",
        WitnessServiceOperationV1::ReadHead,
        "Read",
        true,
    ),
    mapping(
        "fetch_payload",
        WitnessServiceOperationV1::FetchPayload,
        "Read",
        true,
    ),
];

const fn mapping(
    method: &'static str,
    operation: WitnessServiceOperationV1,
    response_variant: &'static str,
    session_authorization: bool,
) -> PublicWitnessDispatchMappingV1 {
    PublicWitnessDispatchMappingV1 {
        method,
        operation,
        subject: PublicWitnessServiceConfigV1::subject_for(operation),
        response_variant,
        session_authorization,
    }
}

pub const fn dispatcher_mapping() -> &'static [PublicWitnessDispatchMappingV1; 9] {
    &DISPATCHER_MAPPING
}

const PUBLIC_WITNESS_QUEUE_GROUP: &str = "swarm-governance-witness-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PublicWitnessRunnerErrorV1 {
    #[error("public witness subscription setup failed")]
    Subscription,
}

pub(crate) struct PublicIngressMessage {
    pub(crate) subject: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) reply: async_nats::Subject,
    pub(crate) receipt_deadline: ReceiptDeadlineV1,
}

pub(crate) async fn run_public_worker_message<
    C: PublicWitnessStoreProxyClient,
    P: WorkerPublisherV1,
>(
    dispatcher: &PublicWitnessDispatcher<C>,
    message: PublicIngressMessage,
    observer: &dyn WorkerTransitionObserverV1,
    publisher: &P,
) {
    run_observed_worker_message(
        WorkerKindV1::Public,
        message.receipt_deadline,
        observer,
        publisher,
        message.reply,
        |_| {
            dispatcher.dispatch_before(&message.subject, &message.payload, message.receipt_deadline)
        },
    )
    .await;
}

pub(crate) async fn receive_and_run_public_worker_message<
    C: PublicWitnessStoreProxyClient,
    P: WorkerPublisherV1,
>(
    receiver: &Mutex<mpsc::Receiver<PublicIngressMessage>>,
    dispatcher: &PublicWitnessDispatcher<C>,
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
    run_public_worker_message(dispatcher, message, observer, publisher).await;
    true
}

/// Running public NATS service. The only subscriptions and queue group are
/// compiled into this module; callers cannot supply subjects, wildcards,
/// queue names, or raw JetStream operations. Reply subjects come from the
/// authenticated NATS transport message, never from the request payload.
pub struct PublicWitnessServiceRunner<C> {
    tasks: Vec<tokio::task::JoinHandle<()>>,
    _proxy: PhantomData<C>,
}

impl<C: PublicWitnessStoreProxyClient + 'static> PublicWitnessServiceRunner<C> {
    pub async fn start(
        client: async_nats::Client,
        dispatcher: PublicWitnessDispatcher<C>,
    ) -> Result<Self, PublicWitnessRunnerErrorV1> {
        Self::start_inner(client, dispatcher).await
    }

    async fn start_inner(
        client: async_nats::Client,
        dispatcher: PublicWitnessDispatcher<C>,
    ) -> Result<Self, PublicWitnessRunnerErrorV1> {
        let admission_observer = dispatcher.subscriber_admission_observer.clone();
        #[cfg(test)]
        let subscriber_poll_gate = dispatcher.subscriber_poll_gate.clone();
        let queue = PUBLIC_WITNESS_QUEUE_GROUP.to_string();
        let fence = client
            .queue_subscribe("swarm.governance.witness.v1.fence", queue.clone())
            .await
            .map_err(|_| PublicWitnessRunnerErrorV1::Subscription)?;
        let establish = client
            .queue_subscribe("swarm.governance.witness.v1.establish", queue.clone())
            .await
            .map_err(|_| PublicWitnessRunnerErrorV1::Subscription)?;
        let discover = client
            .queue_subscribe("swarm.governance.witness.v1.discover", queue.clone())
            .await
            .map_err(|_| PublicWitnessRunnerErrorV1::Subscription)?;
        let prepare = client
            .queue_subscribe("swarm.governance.witness.v1.prepare", queue.clone())
            .await
            .map_err(|_| PublicWitnessRunnerErrorV1::Subscription)?;
        let commit = client
            .queue_subscribe("swarm.governance.witness.v1.commit", queue.clone())
            .await
            .map_err(|_| PublicWitnessRunnerErrorV1::Subscription)?;
        let abort = client
            .queue_subscribe("swarm.governance.witness.v1.abort", queue.clone())
            .await
            .map_err(|_| PublicWitnessRunnerErrorV1::Subscription)?;
        let read_prepared = client
            .queue_subscribe("swarm.governance.witness.v1.read_prepared", queue.clone())
            .await
            .map_err(|_| PublicWitnessRunnerErrorV1::Subscription)?;
        let read_head = client
            .queue_subscribe("swarm.governance.witness.v1.read_head", queue.clone())
            .await
            .map_err(|_| PublicWitnessRunnerErrorV1::Subscription)?;
        let fetch_payload = client
            .queue_subscribe("swarm.governance.witness.v1.fetch_payload", queue)
            .await
            .map_err(|_| PublicWitnessRunnerErrorV1::Subscription)?;
        client
            .flush()
            .await
            .map_err(|_| PublicWitnessRunnerErrorV1::Subscription)?;

        let capacity = dispatcher.config.ingress_queue_capacity;
        let worker_count = dispatcher.config.max_in_flight;
        let observer = dispatcher.worker_observer.clone();
        let dispatcher = Arc::new(dispatcher);
        let (sender, receiver) = mpsc::channel(capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut tasks = Vec::with_capacity(9 + worker_count);
        for (subject, subscriber) in [
            ("swarm.governance.witness.v1.fence", fence),
            ("swarm.governance.witness.v1.establish", establish),
            ("swarm.governance.witness.v1.discover", discover),
            ("swarm.governance.witness.v1.prepare", prepare),
            ("swarm.governance.witness.v1.commit", commit),
            ("swarm.governance.witness.v1.abort", abort),
            ("swarm.governance.witness.v1.read_prepared", read_prepared),
            ("swarm.governance.witness.v1.read_head", read_head),
            ("swarm.governance.witness.v1.fetch_payload", fetch_payload),
        ] {
            tasks.push(spawn_public_subscription(
                subject,
                subscriber,
                sender.clone(),
                admission_observer.clone(),
                #[cfg(test)]
                subscriber_poll_gate.clone(),
            ));
        }
        drop(sender);
        #[cfg(not(test))]
        let publisher = Arc::new(NatsWorkerPublisherV1::new(client.clone()));
        #[cfg(test)]
        let publisher = Arc::new(NatsWorkerPublisherV1::observed(
            client.clone(),
            WorkerKindV1::Public,
            dispatcher.response_pre_enqueue_observer.clone(),
        ));
        for _ in 0..worker_count {
            let receiver = receiver.clone();
            let dispatcher = dispatcher.clone();
            let observer = observer.clone();
            let publisher = publisher.clone();
            tasks.push(tokio::spawn(async move {
                while receive_and_run_public_worker_message(
                    receiver.as_ref(),
                    dispatcher.as_ref(),
                    observer.as_ref(),
                    publisher.as_ref(),
                )
                .await
                {}
            }));
        }
        Ok(Self {
            tasks,
            _proxy: PhantomData,
        })
    }
}

impl<C> Drop for PublicWitnessServiceRunner<C> {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn spawn_public_subscription(
    expected_subject: &'static str,
    mut subscriber: async_nats::Subscriber,
    ingress: mpsc::Sender<PublicIngressMessage>,
    admission_observer: Arc<dyn SubscriberAdmissionObserverV1>,
    #[cfg(test)] mut subscriber_poll_gate: Option<SubscriberPollGateV1>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        #[cfg(test)]
        if let Some(gate) = subscriber_poll_gate.as_mut() {
            gate.before_first_poll(expected_subject).await;
        }
        while let Some(message) = subscriber.next().await {
            if !admit_public_subscription_message(
                expected_subject,
                message,
                &ingress,
                admission_observer.as_ref(),
            ) {
                // The bounded queue refusal happens synchronously here,
                // before a worker task, dispatcher, or store call can begin.
                continue;
            }
        }
    })
}

pub(crate) fn admit_public_subscription_message(
    expected_subject: &'static str,
    message: async_nats::Message,
    ingress: &mpsc::Sender<PublicIngressMessage>,
    admission_observer: &dyn SubscriberAdmissionObserverV1,
) -> bool {
    let receipt_deadline = ReceiptDeadlineV1::public();
    if message.subject.as_str() != expected_subject {
        return false;
    }
    let Some(reply) = message.reply else {
        return false;
    };
    if !is_bounded_inbox_reply(&reply) {
        return false;
    }
    let payload = message.payload.to_vec();
    let receipt = SubscriberAdmissionReceiptV1 {
        worker: WorkerKindV1::Public,
        subject: expected_subject.to_string(),
        payload_sha256: sha256_hex(&payload),
        #[cfg(test)]
        payload: payload.clone(),
        #[cfg(test)]
        deadline_identity: receipt_deadline.identity_for_test(),
        reply: reply.to_string(),
        deadline_millis: PUBLIC_HANDLER_DEADLINE_MILLIS,
    };
    let ingress_message = PublicIngressMessage {
        subject: expected_subject.to_string(),
        payload,
        reply,
        receipt_deadline,
    };
    if !try_enqueue_public_message(ingress, ingress_message) {
        return false;
    }
    admission_observer.accepted(receipt);
    true
}

fn try_enqueue_public_message(
    ingress: &mpsc::Sender<PublicIngressMessage>,
    message: PublicIngressMessage,
) -> bool {
    ingress.try_send(message).is_ok()
}

fn is_bounded_inbox_reply(reply: &async_nats::Subject) -> bool {
    let value = reply.as_str();
    (value.starts_with("_INBOX.") || value.starts_with("_R_."))
        && value.len() <= MAX_PROTOCOL_STRING_BYTES
        && !value.contains(['*', '>'])
}

/// Closed conformance probe for the exact production bounded-ingress helper.
/// It accepts no subjects, messages, reply routes, clients, or capacities.
#[doc(hidden)]
pub fn public_witness_ingress_overload_control() -> bool {
    let (sender, _receiver) = mpsc::channel(1);
    let message = || PublicIngressMessage {
        subject: PublicWitnessServiceConfigV1::subject_for(WitnessServiceOperationV1::Fence)
            .to_string(),
        payload: vec![1],
        reply: "_INBOX.phase285".into(),
        receipt_deadline: ReceiptDeadlineV1::public(),
    };
    try_enqueue_public_message(&sender, message())
        && !try_enqueue_public_message(&sender, message())
}

pub struct PublicWitnessDispatcher<C> {
    config: PublicWitnessServiceConfigV1,
    signer: Ed25519Signer,
    proxy: C,
    in_flight: Semaphore,
    worker_observer: Arc<dyn WorkerTransitionObserverV1>,
    subscriber_admission_observer: Arc<dyn SubscriberAdmissionObserverV1>,
    #[cfg(test)]
    subscriber_poll_gate: Option<SubscriberPollGateV1>,
    #[cfg(test)]
    response_pre_enqueue_observer: Arc<dyn ResponsePreEnqueueObserverV1>,
}

impl<C: PublicWitnessStoreProxyClient> PublicWitnessDispatcher<C> {
    pub async fn new(
        config: PublicWitnessServiceConfigV1,
        signer: Ed25519Signer,
        proxy: C,
    ) -> Result<Self, PublicWitnessDispatchErrorV1> {
        config.validate().map_err(invalid)?;
        if signer.key_id() != config.witness_key_id {
            return Err(PublicWitnessDispatchErrorV1::Invalid);
        }
        let max_in_flight = config.max_in_flight;
        let dispatcher = Self {
            config,
            signer,
            proxy,
            in_flight: Semaphore::new(max_in_flight),
            worker_observer: Arc::new(NoopWorkerTransitionObserverV1),
            subscriber_admission_observer: Arc::new(NoopSubscriberAdmissionObserverV1),
            #[cfg(test)]
            subscriber_poll_gate: None,
            #[cfg(test)]
            response_pre_enqueue_observer: Arc::new(
                crate::service_config::NoopResponsePreEnqueueObserverV1,
            ),
        };
        dispatcher.validate_startup_ready().await?;
        Ok(dispatcher)
    }

    #[cfg(test)]
    pub(crate) fn observe_worker_transitions_for_test(
        &mut self,
        observer: Arc<dyn WorkerTransitionObserverV1>,
    ) {
        self.worker_observer = observer;
    }

    #[cfg(test)]
    pub(crate) fn observe_subscriber_admissions_for_test(
        &mut self,
        observer: Arc<dyn SubscriberAdmissionObserverV1>,
    ) {
        self.subscriber_admission_observer = observer;
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

    async fn validate_startup_ready(&self) -> Result<(), PublicWitnessDispatchErrorV1> {
        let startup_digest = digest_domain(
            b"swarm.governance.witness-public-startup.v1",
            &canonical_wire_bytes(&self.config).map_err(invalid)?,
        )
        .map_err(invalid)?;
        let inspect_admission = self
            .config
            .admission_set
            .entries
            .first()
            .ok_or(PublicWitnessDispatchErrorV1::Invalid)?;
        let request = self
            .proxy_request_for_digest(
                &startup_digest,
                "startup-ready",
                inspect_admission,
                WitnessStoreProxyRequestBodyV1::InspectReady,
            )
            .map_err(invalid)?;
        let expected_digest = request.request_digest.clone();
        let response = self.proxy.inspect_ready(request).await.map_err(transport)?;
        response.validate().map_err(invalid)?;
        if response.operation != WitnessStoreProxyOperationV1::InspectReady
            || response.request_digest != expected_digest
        {
            return Err(PublicWitnessDispatchErrorV1::Invalid);
        }
        let WitnessStoreProxyResponseBodyV1::Ready {
            bucket_configuration_digest,
            ready_manifest,
            validated_streams,
            ..
        } = response.body
        else {
            return Err(PublicWitnessDispatchErrorV1::Invalid);
        };
        let mut expected_stream_keys = self
            .config
            .admission_set
            .entries
            .iter()
            .map(|entry| witness_stream_key(&entry.stream_id))
            .collect::<ProtocolResult<Vec<_>>>()
            .map_err(invalid)?;
        expected_stream_keys.sort();
        if validated_streams.len() != self.config.admission_set.entries.len()
            || bucket_configuration_digest != self.config.bucket_configuration_digest
            || ready_manifest.digest().map_err(invalid)? != self.config.ready_manifest_digest
            || ready_manifest.bucket_epoch_digest != self.config.bucket_epoch_digest
            || ready_manifest.bucket_configuration_digest != self.config.bucket_configuration_digest
            || ready_manifest.admission_set_digest != self.config.admission_set_digest
            || ready_manifest.phase != WitnessBucketManifestPhaseV1::Ready
            || ready_manifest.witness_identity != self.config.witness_identity
            || ready_manifest.witness_key_id != self.config.witness_key_id
            || ready_manifest.stream_keys != expected_stream_keys
            || ready_manifest.initialized_streams.len() != self.config.admission_set.entries.len()
        {
            return Err(PublicWitnessDispatchErrorV1::Invalid);
        }
        for admission in &self.config.admission_set.entries {
            let stream_key = witness_stream_key(&admission.stream_id).map_err(invalid)?;
            let initialization_digest = self
                .stream_initialization_digest(admission)
                .map_err(invalid)?;
            let summary = validated_streams
                .get(&admission.stream_id)
                .ok_or(PublicWitnessDispatchErrorV1::Invalid)?;
            if ready_manifest
                .initialized_streams
                .get(&stream_key)
                .is_none_or(|record| record.stream_initialization_digest != initialization_digest)
                || summary.stream_initialization_digest != initialization_digest
            {
                return Err(PublicWitnessDispatchErrorV1::Invalid);
            }
            let current = self
                .read_authenticated_for_digest(&startup_digest, "startup-entry", admission)
                .await?;
            validate_selected_entry_bounds(admission, &current.envelope).map_err(invalid)?;
            if summary.revision != current.revision
                || summary.store_state_digest
                    != current.envelope.store_state_digest().map_err(invalid)?
            {
                return Err(PublicWitnessDispatchErrorV1::Invalid);
            }
        }
        Ok(())
    }

    pub async fn dispatch(
        &self,
        subject: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, PublicWitnessDispatchErrorV1> {
        self.dispatch_before(subject, payload, ReceiptDeadlineV1::public())
            .await
    }

    async fn dispatch_before(
        &self,
        subject: &str,
        payload: &[u8],
        receipt_deadline: ReceiptDeadlineV1,
    ) -> Result<Vec<u8>, PublicWitnessDispatchErrorV1> {
        if receipt_deadline.ensure_open().is_err() {
            return Err(PublicWitnessDispatchErrorV1::Timeout);
        }
        if payload.len() > self.config.max_request_bytes {
            return Err(PublicWitnessDispatchErrorV1::Invalid);
        }
        let request =
            WitnessServiceRequestV1::decode_for_public_dispatch(payload).map_err(invalid)?;
        if subject != PublicWitnessServiceConfigV1::subject_for(request.operation) {
            return Err(PublicWitnessDispatchErrorV1::Invalid);
        }
        let selected = self.selected_admission(&request)?;
        if payload.len()
            > self.config.max_request_bytes.min(
                usize::try_from(selected.max_request_bytes)
                    .map_err(|_| PublicWitnessDispatchErrorV1::Invalid)?,
            )
        {
            return Err(PublicWitnessDispatchErrorV1::Invalid);
        }
        let selected_max_response = usize::try_from(selected.max_response_bytes)
            .map_err(|_| PublicWitnessDispatchErrorV1::Invalid)?;
        let _permit = self
            .in_flight
            .try_acquire()
            .map_err(|_| PublicWitnessDispatchErrorV1::Overloaded)?;
        let transition = WorkerTransitionV1::new(
            WorkerKindV1::Public,
            receipt_deadline,
            self.worker_observer.as_ref(),
        );
        transition.post_preflight();
        tokio::task::yield_now().await;
        if transition.ensure_open().is_err() {
            return Err(PublicWitnessDispatchErrorV1::Timeout);
        }
        let cas_attempted = Arc::new(AtomicBool::new(false));
        let execution =
            ACTIVE_CAS_ATTEMPTED.scope(cas_attempted.clone(), self.execute(request.clone()));
        let response = match receipt_deadline.run(execution).await {
            Ok(Err(PublicWitnessDispatchErrorV1::OutcomeUnknown)) => {
                transition.outcome_unknown();
                return Err(PublicWitnessDispatchErrorV1::OutcomeUnknown);
            }
            Ok(result) => result?,
            Err(_) if cas_attempted.load(Ordering::SeqCst) => {
                transition.outcome_unknown();
                return Err(PublicWitnessDispatchErrorV1::OutcomeUnknown);
            }
            Err(_) => return Err(PublicWitnessDispatchErrorV1::Timeout),
        };
        if transition.ensure_open().is_err() {
            return Err(if cas_attempted.load(Ordering::SeqCst) {
                transition.outcome_unknown();
                PublicWitnessDispatchErrorV1::OutcomeUnknown
            } else {
                PublicWitnessDispatchErrorV1::Timeout
            });
        }
        let bytes = response.canonical_bytes().map_err(invalid)?;
        if bytes.len() > self.config.max_response_bytes.min(selected_max_response) {
            return Err(PublicWitnessDispatchErrorV1::ResponseBounds);
        }
        WitnessServiceResponseV1::decode_for_client_request(&bytes, &request).map_err(invalid)?;
        Ok(bytes)
    }

    async fn execute(
        &self,
        request: WitnessServiceRequestV1,
    ) -> Result<WitnessServiceResponseV1, PublicWitnessDispatchErrorV1> {
        let admission = self.selected_admission(&request)?;
        let current = self.read_authenticated(&request, "initial").await?;
        if validate_selected_entry_bounds(admission, &current.envelope).is_err() {
            return self
                .sign_failure(
                    &request,
                    &current,
                    WitnessServiceFailureCodeV1::BoundsExceeded,
                )
                .map_err(invalid);
        }
        if !matches!(request.body, WitnessServiceRequestBodyV1::Prepare { .. }) {
            if let Err(error) = request.validate() {
                let code = WitnessServiceFailureV1::from_protocol_error(&error).failure_code;
                return self.sign_failure(&request, &current, code).map_err(invalid);
            }
            if request_session(&request)
                .is_some_and(|session| current.envelope.session.as_ref() != Some(session))
            {
                return self
                    .sign_failure(
                        &request,
                        &current,
                        WitnessServiceFailureCodeV1::StaleSession,
                    )
                    .map_err(invalid);
            }
        }
        match &request.body {
            WitnessServiceRequestBodyV1::Fence { request: fence } => {
                let completion = UnsignedPublicWitnessSuccessV1::Fence(Box::new(
                    self.build_fence(fence.as_ref(), &current.envelope, &request.request_digest)
                        .map_err(invalid)?,
                ));
                VerifiedPublicWitnessCompletionV1::success(completion, &request, &current)
                    .map_err(invalid)?
                    .sign_for_request(&request, &self.signer)
                    .map_err(invalid)
            }
            WitnessServiceRequestBodyV1::Prepare {
                session, candidate, ..
            } => {
                let stream_initialization_digest = self
                    .stream_initialization_digest(admission)
                    .map_err(invalid)?;
                let verified = match verify_public_prepare(
                    admission,
                    &self.config.bucket_epoch_digest,
                    &stream_initialization_digest,
                    &current.envelope,
                    &request,
                    &self.signer,
                ) {
                    WitnessPrepareVerificationV1::New(verified) => verified,
                    WitnessPrepareVerificationV1::AlreadyPrepared(resolution)
                    | WitnessPrepareVerificationV1::Conflict(resolution) => {
                        return self.sign_prepare_resolution(&request, &current, *resolution);
                    }
                    WitnessPrepareVerificationV1::Rejected(code) => {
                        return self.sign_failure(&request, &current, code).map_err(invalid);
                    }
                };
                let transition = match prepare_verified_candidate(&current.envelope, *verified) {
                    Ok(transition) => transition,
                    Err(ProtocolError::Bounds { .. } | ProtocolError::Overflow { .. }) => {
                        return self
                            .sign_failure(
                                &request,
                                &current,
                                WitnessServiceFailureCodeV1::BoundsExceeded,
                            )
                            .map_err(invalid);
                    }
                    Err(_) => {
                        return self
                            .sign_failure(
                                &request,
                                &current,
                                WitnessServiceFailureCodeV1::StoreTransitionRefused,
                            )
                            .map_err(invalid);
                    }
                };
                let signing_bytes = transition.signing_bytes().map_err(invalid)?;
                let proposed = transition
                    .seal(self.signer.sign(&signing_bytes))
                    .map_err(invalid)?;
                let confirmed = match self.apply_and_confirm(&request, &current, proposed).await? {
                    MutationStoreResult::Confirmed(confirmed) => *confirmed,
                    MutationStoreResult::Failure(response) => return Ok(*response),
                    MutationStoreResult::ObservedConflict(observed) => {
                        return match verify_public_prepare(
                            admission,
                            &self.config.bucket_epoch_digest,
                            &stream_initialization_digest,
                            &observed.envelope,
                            &request,
                            &self.signer,
                        ) {
                            WitnessPrepareVerificationV1::AlreadyPrepared(resolution)
                            | WitnessPrepareVerificationV1::Conflict(resolution) => {
                                self.sign_prepare_resolution(&request, &observed, *resolution)
                            }
                            WitnessPrepareVerificationV1::Rejected(code) => self
                                .sign_failure(&request, &observed, code)
                                .map_err(invalid),
                            WitnessPrepareVerificationV1::New(_) => self
                                .sign_failure(
                                    &request,
                                    &observed,
                                    WitnessServiceFailureCodeV1::Conflict,
                                )
                                .map_err(invalid),
                        };
                    }
                };
                let prepared = confirmed
                    .envelope
                    .prepared
                    .as_ref()
                    .ok_or_else(|| invalid(()))?
                    .prepared
                    .clone();
                let completion = UnsignedPublicWitnessSuccessV1::Outcome(unsigned_prepare_outcome(
                    session,
                    candidate,
                    prepared,
                    &self.signer,
                ));
                VerifiedPublicWitnessCompletionV1::success(completion, &request, &confirmed)
                    .map_err(invalid)?
                    .sign_for_request(&request, &self.signer)
                    .map_err(invalid)
            }
            WitnessServiceRequestBodyV1::Establish {
                challenge,
                expected_head,
            } => {
                self.handle_establish(&request, &current, challenge, expected_head.as_deref())
                    .await
            }
            WitnessServiceRequestBodyV1::Discover { challenge } => {
                self.handle_discover(&request, &current, challenge).await
            }
            WitnessServiceRequestBodyV1::Commit { session, txid } => {
                self.handle_commit(&request, &current, session, txid).await
            }
            WitnessServiceRequestBodyV1::Abort { session, txid } => {
                self.handle_abort(&request, &current, session, txid).await
            }
            WitnessServiceRequestBodyV1::ReadPrepared {
                session,
                target_txid,
            } => self.sign_read(
                &request,
                &current,
                session,
                WitnessOperationV1::ReadPrepared,
                target_txid,
                WitnessReadResponseV1::Prepared(Box::new(
                    current.envelope.prepared.as_ref().and_then(|stored| {
                        (stored.prepared.head.txid == *target_txid).then(|| stored.prepared.clone())
                    }),
                )),
            ),
            WitnessServiceRequestBodyV1::ReadHead {
                session,
                target_txid,
            } => self.sign_read(
                &request,
                &current,
                session,
                WitnessOperationV1::ReadHead,
                target_txid,
                WitnessReadResponseV1::Head(Box::new(current.envelope.current.as_ref().and_then(
                    |stored| (stored.head.txid == *target_txid).then(|| stored.head.clone()),
                ))),
            ),
            WitnessServiceRequestBodyV1::FetchPayload { session, txid } => {
                let payload = [
                    current
                        .envelope
                        .current
                        .as_ref()
                        .map(|stored| &stored.candidate),
                    current
                        .envelope
                        .predecessor
                        .as_ref()
                        .map(|stored| &stored.candidate),
                    current
                        .envelope
                        .prepared
                        .as_ref()
                        .map(|stored| &stored.candidate),
                ]
                .into_iter()
                .flatten()
                .find(|candidate| {
                    candidate
                        .candidate_digest()
                        .and_then(|digest| candidate.txid(&digest))
                        .is_ok_and(|candidate_txid| candidate_txid == *txid)
                })
                .cloned();
                self.sign_read(
                    &request,
                    &current,
                    session,
                    WitnessOperationV1::FetchPayload,
                    txid,
                    WitnessReadResponseV1::Payload(Box::new(payload)),
                )
            }
        }
    }

    /// Selects one deployment admission and checks the complete immutable
    /// namespace carried by the operation before any permit, handler, or store
    /// call can be reached.
    fn selected_admission(
        &self,
        request: &WitnessServiceRequestV1,
    ) -> Result<&WitnessAdmissionEntryV1, PublicWitnessDispatchErrorV1> {
        let (
            stream_id,
            authority_pair,
            binding_generation,
            binding_digest,
            signer_key_id,
            witness_key_id,
            witness_identity,
        ) = match &request.body {
            WitnessServiceRequestBodyV1::Fence { request } => (
                request.stream_id.as_str(),
                request.authority_pair,
                request.binding_generation.as_str(),
                request.binding_digest.as_str(),
                request.signer_key_id.as_str(),
                request.witness_key_id.as_str(),
                request.witness_identity.as_str(),
            ),
            WitnessServiceRequestBodyV1::Establish { challenge, .. }
            | WitnessServiceRequestBodyV1::Discover { challenge } => {
                let fenced = &challenge.state_fence.request;
                if challenge.stream_id != fenced.stream_id
                    || challenge.authority_pair != fenced.authority_pair
                    || challenge.binding_generation != fenced.binding_generation
                    || challenge.binding_digest != fenced.binding_digest
                    || challenge.signer_key_id != fenced.signer_key_id
                    || challenge.witness_key_id != fenced.witness_key_id
                    || challenge.witness_identity != fenced.witness_identity
                    || challenge.state_fence.admission_digest != request.admission_digest
                    || challenge.state_fence.bucket_epoch_digest != self.config.bucket_epoch_digest
                    || challenge.state_fence.bucket_anchor_digest
                        != self.config.bucket_anchor_digest
                    || challenge.state_fence.ready_manifest_digest
                        != self.config.ready_manifest_digest
                    || challenge.state_fence.witness_identity != challenge.witness_identity
                    || challenge.state_fence.witness_key_id != challenge.witness_key_id
                {
                    return Err(PublicWitnessDispatchErrorV1::Invalid);
                }
                (
                    challenge.stream_id.as_str(),
                    challenge.authority_pair,
                    challenge.binding_generation.as_str(),
                    challenge.binding_digest.as_str(),
                    challenge.signer_key_id.as_str(),
                    challenge.witness_key_id.as_str(),
                    challenge.witness_identity.as_str(),
                )
            }
            WitnessServiceRequestBodyV1::Prepare { session, .. }
            | WitnessServiceRequestBodyV1::Commit { session, .. }
            | WitnessServiceRequestBodyV1::Abort { session, .. }
            | WitnessServiceRequestBodyV1::ReadPrepared { session, .. }
            | WitnessServiceRequestBodyV1::ReadHead { session, .. }
            | WitnessServiceRequestBodyV1::FetchPayload { session, .. } => (
                session.stream_id.as_str(),
                session.authority_pair,
                session.binding_generation.as_str(),
                session.binding_digest.as_str(),
                session.signer_key_id.as_str(),
                session.witness_key_id.as_str(),
                session.witness_identity.as_str(),
            ),
        };
        let admission = self
            .config
            .admission_set
            .entry(stream_id)
            .ok_or(PublicWitnessDispatchErrorV1::Invalid)?;
        if request.admission_digest != admission.admission_digest
            || stream_id != admission.stream_id
            || signer_key_id != admission.signer_key_id
            || witness_identity != admission.witness_identity
            || witness_key_id != admission.witness_key_id
            || binding_generation != admission.binding_generation
            || binding_digest != admission.binding_digest
            || authority_pair != admission.authority_pair
        {
            return Err(PublicWitnessDispatchErrorV1::Invalid);
        }
        Ok(admission)
    }

    async fn handle_establish(
        &self,
        request: &WitnessServiceRequestV1,
        current: &AuthenticatedStoreEntry,
        challenge: &RecoveryChallengeV1,
        expected_head: Option<&swarm_governance::persistence_protocol::WitnessHeadV1>,
    ) -> Result<WitnessServiceResponseV1, PublicWitnessDispatchErrorV1> {
        if let Some(receipt) = &current.envelope.last_session_rotation
            && receipt
                .verify_exact_retry(
                    &request.request_digest,
                    challenge,
                    WitnessSessionRotationResponseKindV1::Establish,
                )
                .is_ok()
        {
            return self.sign_establish_completion(request, current, challenge, receipt);
        }
        if self
            .validate_challenge_freshness(current, challenge)
            .is_err()
        {
            return self
                .sign_failure(
                    request,
                    current,
                    WitnessServiceFailureCodeV1::StaleRotationFence,
                )
                .map_err(invalid);
        }
        let session = match rotated_session(&current.envelope, challenge) {
            Ok(session) => session,
            Err(error) => {
                return self
                    .sign_failure(request, current, failure_code_for_protocol(&error))
                    .map_err(invalid);
            }
        };
        let receipt = match WitnessSessionRotationReceiptV1::for_establish(
            request.request_digest.clone(),
            challenge,
            session.clone(),
            expected_head.cloned(),
        ) {
            Ok(receipt) => receipt,
            Err(_) => {
                return self
                    .sign_failure(
                        request,
                        current,
                        WitnessServiceFailureCodeV1::ExpectedHeadMismatch,
                    )
                    .map_err(invalid);
            }
        };
        let proposed = match self.seal_rotation(current, session, receipt) {
            Ok(proposed) => proposed,
            Err(error) => {
                return self
                    .sign_failure(request, current, failure_code_for_protocol(&error))
                    .map_err(invalid);
            }
        };
        let confirmed = match self.apply_and_confirm(request, current, proposed).await? {
            MutationStoreResult::Confirmed(value) => *value,
            MutationStoreResult::Failure(value) => return Ok(*value),
            MutationStoreResult::ObservedConflict(observed) => {
                if let Some(receipt) = &observed.envelope.last_session_rotation
                    && receipt
                        .verify_exact_retry(
                            &request.request_digest,
                            challenge,
                            WitnessSessionRotationResponseKindV1::Establish,
                        )
                        .is_ok()
                {
                    return self.sign_establish_completion(request, &observed, challenge, receipt);
                }
                return self
                    .sign_failure(request, &observed, WitnessServiceFailureCodeV1::Conflict)
                    .map_err(invalid);
            }
        };
        let receipt = confirmed
            .envelope
            .last_session_rotation
            .as_ref()
            .ok_or_else(|| invalid(()))?;
        self.sign_establish_completion(request, &confirmed, challenge, receipt)
    }

    fn sign_establish_completion(
        &self,
        request: &WitnessServiceRequestV1,
        current: &AuthenticatedStoreEntry,
        challenge: &RecoveryChallengeV1,
        receipt: &WitnessSessionRotationReceiptV1,
    ) -> Result<WitnessServiceResponseV1, PublicWitnessDispatchErrorV1> {
        let snapshot = receipt
            .establish_snapshot
            .as_ref()
            .ok_or_else(|| invalid(()))?;
        let unsigned = WitnessSessionAttestationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            challenge: challenge.clone(),
            session: receipt.session.clone(),
            committed_head: snapshot.committed_head.clone(),
            external_marker: snapshot.external_marker.clone(),
            witness_key_id: self.config.witness_key_id.clone(),
            signature: placeholder_signature(&self.signer),
        };
        VerifiedPublicWitnessCompletionV1::success(
            UnsignedPublicWitnessSuccessV1::Establish(Box::new(unsigned)),
            request,
            current,
        )
        .map_err(invalid)?
        .sign_for_request(request, &self.signer)
        .map_err(invalid)
    }

    async fn handle_discover(
        &self,
        request: &WitnessServiceRequestV1,
        current: &AuthenticatedStoreEntry,
        challenge: &RecoveryChallengeV1,
    ) -> Result<WitnessServiceResponseV1, PublicWitnessDispatchErrorV1> {
        if let Some(receipt) = &current.envelope.last_session_rotation
            && receipt
                .verify_exact_retry(
                    &request.request_digest,
                    challenge,
                    WitnessSessionRotationResponseKindV1::Discover,
                )
                .is_ok()
        {
            return self.sign_discovery_completion(request, current, challenge, receipt);
        }
        if self
            .validate_challenge_freshness(current, challenge)
            .is_err()
        {
            return self
                .sign_failure(
                    request,
                    current,
                    WitnessServiceFailureCodeV1::StaleRotationFence,
                )
                .map_err(invalid);
        }
        let session = match rotated_session(&current.envelope, challenge) {
            Ok(session) => session,
            Err(error) => {
                return self
                    .sign_failure(request, current, failure_code_for_protocol(&error))
                    .map_err(invalid);
            }
        };
        let discovery = WitnessDiscoveryV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            head: current
                .envelope
                .current
                .as_ref()
                .map(|stored| stored.head.clone()),
            prepared: current
                .envelope
                .prepared
                .as_ref()
                .map(|stored| stored.prepared.clone()),
            genesis_abort: current.envelope.genesis_abort.clone(),
            recovery_session: session.clone(),
        };
        let receipt = match WitnessSessionRotationReceiptV1::for_discovery(
            request.request_digest.clone(),
            challenge,
            discovery,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                return self
                    .sign_failure(request, current, failure_code_for_protocol(&error))
                    .map_err(invalid);
            }
        };
        let proposed = match self.seal_rotation(current, session, receipt) {
            Ok(proposed) => proposed,
            Err(error) => {
                return self
                    .sign_failure(request, current, failure_code_for_protocol(&error))
                    .map_err(invalid);
            }
        };
        let confirmed = match self.apply_and_confirm(request, current, proposed).await? {
            MutationStoreResult::Confirmed(value) => *value,
            MutationStoreResult::Failure(value) => return Ok(*value),
            MutationStoreResult::ObservedConflict(observed) => {
                if let Some(receipt) = &observed.envelope.last_session_rotation
                    && receipt
                        .verify_exact_retry(
                            &request.request_digest,
                            challenge,
                            WitnessSessionRotationResponseKindV1::Discover,
                        )
                        .is_ok()
                {
                    return self.sign_discovery_completion(request, &observed, challenge, receipt);
                }
                return self
                    .sign_failure(request, &observed, WitnessServiceFailureCodeV1::Conflict)
                    .map_err(invalid);
            }
        };
        let receipt = confirmed
            .envelope
            .last_session_rotation
            .as_ref()
            .ok_or_else(|| invalid(()))?;
        self.sign_discovery_completion(request, &confirmed, challenge, receipt)
    }

    fn sign_discovery_completion(
        &self,
        request: &WitnessServiceRequestV1,
        current: &AuthenticatedStoreEntry,
        challenge: &RecoveryChallengeV1,
        receipt: &WitnessSessionRotationReceiptV1,
    ) -> Result<WitnessServiceResponseV1, PublicWitnessDispatchErrorV1> {
        let discovery = receipt
            .discovery_snapshot
            .as_ref()
            .ok_or_else(|| invalid(()))?
            .clone();
        let unsigned = WitnessDiscoveryAttestationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            challenge: challenge.clone(),
            discovery,
            witness_key_id: self.config.witness_key_id.clone(),
            signature: placeholder_signature(&self.signer),
        };
        VerifiedPublicWitnessCompletionV1::success(
            UnsignedPublicWitnessSuccessV1::Discover(Box::new(unsigned)),
            request,
            current,
        )
        .map_err(invalid)?
        .sign_for_request(request, &self.signer)
        .map_err(invalid)
    }

    fn seal_rotation(
        &self,
        current: &AuthenticatedStoreEntry,
        session: WitnessSessionV1,
        receipt: WitnessSessionRotationReceiptV1,
    ) -> ProtocolResult<WitnessStoreEnvelopeV1> {
        let mut proposed = current.envelope.clone();
        if let Some(prepared) = &mut proposed.prepared {
            prepared.prepared.session_generation = session.session_generation;
        }
        proposed.session = Some(session);
        proposed.last_session_rotation = Some(receipt);
        proposed.store_generation =
            proposed
                .store_generation
                .checked_add(1)
                .ok_or(ProtocolError::Overflow {
                    counter: "store_generation",
                })?;
        proposed.signature = self.signer.sign(&proposed.signing_bytes()?);
        self.validate_transition(current, &proposed, WitnessStoreTransitionV1::RotateSession)?;
        Ok(proposed)
    }

    fn validate_challenge_freshness(
        &self,
        current: &AuthenticatedStoreEntry,
        challenge: &RecoveryChallengeV1,
    ) -> ProtocolResult<()> {
        challenge.validate()?;
        let admission = self
            .config
            .admission_set
            .entry(&challenge.stream_id)
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        let current_session_digest = current
            .envelope
            .session
            .as_ref()
            .map(|session| {
                digest_domain(
                    WITNESS_SESSION_STATE_DOMAIN_V1,
                    &canonical_wire_bytes(session)?,
                )
            })
            .transpose()?;
        if challenge.state_fence.admission_digest != admission.admission_digest
            || challenge.state_fence.bucket_epoch_digest != self.config.bucket_epoch_digest
            || challenge.state_fence.bucket_anchor_digest != self.config.bucket_anchor_digest
            || challenge.state_fence.ready_manifest_digest != self.config.ready_manifest_digest
            || challenge.state_fence.store_state_digest != current.envelope.store_state_digest()?
            || challenge.state_fence.current_session_generation
                != current
                    .envelope
                    .session
                    .as_ref()
                    .map(|session| session.session_generation)
            || challenge.state_fence.current_session_digest != current_session_digest
            || challenge.witness_identity != self.config.witness_identity
            || challenge.witness_key_id != self.config.witness_key_id
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    async fn handle_commit(
        &self,
        request: &WitnessServiceRequestV1,
        current: &AuthenticatedStoreEntry,
        session: &WitnessSessionV1,
        txid: &str,
    ) -> Result<WitnessServiceResponseV1, PublicWitnessDispatchErrorV1> {
        if current.envelope.prepared.is_none() {
            if let Some((candidate_digest, outcome)) =
                commit_winner(&current.envelope, txid).map_err(invalid)?
            {
                return self.sign_outcome(
                    request,
                    current,
                    session,
                    txid,
                    &candidate_digest,
                    WitnessOperationOutcomeV1::Commit(Box::new(outcome)),
                );
            }
            return self
                .sign_failure(request, current, WitnessServiceFailureCodeV1::StaleIntent)
                .map_err(invalid);
        }
        let prepared = current
            .envelope
            .prepared
            .as_ref()
            .ok_or_else(|| invalid(()))?;
        if prepared.prepared.head.txid != txid {
            return self
                .sign_failure(request, current, WitnessServiceFailureCodeV1::StaleIntent)
                .map_err(invalid);
        }
        let candidate = prepared.candidate.clone().build().map_err(invalid)?;
        let committed_head =
            swarm_governance::persistence_protocol::WitnessHeadV1::committed_from_candidate(
                &candidate,
            )
            .map_err(invalid)?;
        let committed = WitnessCommittedV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            head: committed_head.clone(),
        };
        let mut proposed = current.envelope.clone();
        proposed.predecessor = current.envelope.current.clone();
        proposed.current = Some(WitnessStoredCandidateV1 {
            candidate: prepared.candidate.clone(),
            head: committed_head,
        });
        proposed.prepared = None;
        proposed.store_generation = proposed
            .store_generation
            .checked_add(1)
            .ok_or(ProtocolError::Overflow {
                counter: "store_generation",
            })
            .map_err(invalid)?;
        proposed.signature = self
            .signer
            .sign(&proposed.signing_bytes().map_err(invalid)?);
        self.validate_transition(current, &proposed, WitnessStoreTransitionV1::Commit)
            .map_err(invalid)?;
        let confirmed = match self.apply_and_confirm(request, current, proposed).await? {
            MutationStoreResult::Confirmed(value) => *value,
            MutationStoreResult::Failure(value) => return Ok(*value),
            MutationStoreResult::ObservedConflict(observed) => {
                if let Some((candidate_digest, outcome)) =
                    commit_winner(&observed.envelope, txid).map_err(invalid)?
                {
                    return self.sign_outcome(
                        request,
                        &observed,
                        session,
                        txid,
                        &candidate_digest,
                        WitnessOperationOutcomeV1::Commit(Box::new(outcome)),
                    );
                }
                return self
                    .sign_failure(request, &observed, WitnessServiceFailureCodeV1::Conflict)
                    .map_err(invalid);
            }
        };
        let candidate_digest = committed.head.candidate_digest.clone();
        self.sign_outcome(
            request,
            &confirmed,
            session,
            txid,
            &candidate_digest,
            WitnessOperationOutcomeV1::Commit(Box::new(WitnessCommitOutcomeV1::Committed(
                committed,
            ))),
        )
    }

    async fn handle_abort(
        &self,
        request: &WitnessServiceRequestV1,
        current: &AuthenticatedStoreEntry,
        session: &WitnessSessionV1,
        txid: &str,
    ) -> Result<WitnessServiceResponseV1, PublicWitnessDispatchErrorV1> {
        if current.envelope.prepared.is_none() {
            if let Some((candidate_digest, outcome)) =
                abort_winner(&current.envelope, txid).map_err(invalid)?
            {
                return self.sign_outcome(
                    request,
                    current,
                    session,
                    txid,
                    &candidate_digest,
                    WitnessOperationOutcomeV1::Abort(Box::new(outcome)),
                );
            }
            return self
                .sign_failure(request, current, WitnessServiceFailureCodeV1::StaleIntent)
                .map_err(invalid);
        }
        let prepared = current
            .envelope
            .prepared
            .as_ref()
            .ok_or_else(|| invalid(()))?;
        if prepared.prepared.head.txid != txid {
            return self
                .sign_failure(request, current, WitnessServiceFailureCodeV1::StaleIntent)
                .map_err(invalid);
        }
        let (outcome, candidate_digest, proposed) = if let Some(stored) = &current.envelope.current
        {
            let aborted = WitnessAbortedV1::intent_only(
                &stored.head,
                txid.to_string(),
                prepared.prepared.head.candidate_digest.clone(),
                "phase285-public-abort".to_string(),
            )
            .map_err(invalid)?;
            let mut proposed = current.envelope.clone();
            let mut resulting = stored.clone();
            resulting.head = aborted.resulting_head.clone();
            proposed.current = Some(resulting);
            proposed.prepared = None;
            (
                WitnessAbortOutcomeV1::Aborted(aborted.clone()),
                aborted.candidate_digest,
                proposed,
            )
        } else {
            let aborted = WitnessGenesisAbortedV1::from_prepared(
                &prepared.prepared,
                "phase285-public-abort".to_string(),
            )
            .map_err(invalid)?;
            let mut proposed = current.envelope.clone();
            proposed.prepared = None;
            proposed.genesis_abort = Some(aborted.clone());
            (
                WitnessAbortOutcomeV1::GenesisAborted(aborted.clone()),
                aborted.candidate_digest,
                proposed,
            )
        };
        let mut proposed = proposed;
        proposed.store_generation = proposed
            .store_generation
            .checked_add(1)
            .ok_or(ProtocolError::Overflow {
                counter: "store_generation",
            })
            .map_err(invalid)?;
        proposed.signature = self
            .signer
            .sign(&proposed.signing_bytes().map_err(invalid)?);
        self.validate_transition(current, &proposed, WitnessStoreTransitionV1::Abort)
            .map_err(invalid)?;
        let confirmed = match self.apply_and_confirm(request, current, proposed).await? {
            MutationStoreResult::Confirmed(value) => *value,
            MutationStoreResult::Failure(value) => return Ok(*value),
            MutationStoreResult::ObservedConflict(observed) => {
                if let Some((candidate_digest, outcome)) =
                    abort_winner(&observed.envelope, txid).map_err(invalid)?
                {
                    return self.sign_outcome(
                        request,
                        &observed,
                        session,
                        txid,
                        &candidate_digest,
                        WitnessOperationOutcomeV1::Abort(Box::new(outcome)),
                    );
                }
                return self
                    .sign_failure(request, &observed, WitnessServiceFailureCodeV1::Conflict)
                    .map_err(invalid);
            }
        };
        self.sign_outcome(
            request,
            &confirmed,
            session,
            txid,
            &candidate_digest,
            WitnessOperationOutcomeV1::Abort(Box::new(outcome)),
        )
    }

    fn sign_outcome(
        &self,
        request: &WitnessServiceRequestV1,
        current: &AuthenticatedStoreEntry,
        session: &WitnessSessionV1,
        txid: &str,
        candidate_digest: &str,
        outcome: WitnessOperationOutcomeV1,
    ) -> Result<WitnessServiceResponseV1, PublicWitnessDispatchErrorV1> {
        let unsigned = WitnessOutcomeAttestationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: match outcome {
                WitnessOperationOutcomeV1::Prepare(_) => WitnessOperationV1::Prepare,
                WitnessOperationOutcomeV1::Commit(_) => WitnessOperationV1::Commit,
                WitnessOperationOutcomeV1::Abort(_) => WitnessOperationV1::Abort,
            },
            stream_id: session.stream_id.clone(),
            binding_generation: session.binding_generation.clone(),
            binding_digest: session.binding_digest.clone(),
            signer_key_id: session.signer_key_id.clone(),
            authority_pair: session.authority_pair,
            txid: txid.to_string(),
            candidate_digest: candidate_digest.to_string(),
            session_generation: session.session_generation,
            session_commitment: session.session_commitment.clone(),
            witness_key_id: session.witness_key_id.clone(),
            outcome,
            signature: placeholder_signature(&self.signer),
        };
        VerifiedPublicWitnessCompletionV1::success(
            UnsignedPublicWitnessSuccessV1::Outcome(unsigned),
            request,
            current,
        )
        .map_err(invalid)?
        .sign_for_request(request, &self.signer)
        .map_err(invalid)
    }

    fn sign_prepare_resolution(
        &self,
        request: &WitnessServiceRequestV1,
        current: &AuthenticatedStoreEntry,
        resolution: VerifiedPrepareResolutionV1,
    ) -> Result<WitnessServiceResponseV1, PublicWitnessDispatchErrorV1> {
        let (session, txid, candidate_digest, outcome) = resolution
            .into_outcome_for_store(&current.envelope)
            .map_err(invalid)?;
        self.sign_outcome(
            request,
            current,
            &session,
            &txid,
            &candidate_digest,
            WitnessOperationOutcomeV1::Prepare(Box::new(outcome)),
        )
    }

    fn validate_transition(
        &self,
        current: &AuthenticatedStoreEntry,
        proposed: &WitnessStoreEnvelopeV1,
        expected: WitnessStoreTransitionV1,
    ) -> ProtocolResult<()> {
        let admission = self
            .config
            .admission_set
            .entry(&current.envelope.stream_id)
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        let stream_initialization_digest = self.stream_initialization_digest(admission)?;
        let observed = validate_store_transition(
            &current.envelope,
            proposed,
            WitnessStoreExpectationV1 {
                admission_digest: &admission.admission_digest,
                bucket_epoch_digest: &self.config.bucket_epoch_digest,
                stream_initialization_digest: &stream_initialization_digest,
                stream_id: &admission.stream_id,
                witness_identity: &admission.witness_identity,
                witness_key_id: &admission.witness_key_id,
                authority_pair: admission.authority_pair,
                binding_generation: &admission.binding_generation,
                binding_digest: &admission.binding_digest,
                signer_key_id: &admission.signer_key_id,
            },
        )?;
        if observed != expected {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(())
    }

    fn sign_read(
        &self,
        request: &WitnessServiceRequestV1,
        current: &AuthenticatedStoreEntry,
        session: &swarm_governance::persistence_protocol::WitnessSessionV1,
        operation: WitnessOperationV1,
        target_txid: &str,
        response: WitnessReadResponseV1,
    ) -> Result<WitnessServiceResponseV1, PublicWitnessDispatchErrorV1> {
        let unsigned = WitnessReadAttestationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation,
            stream_id: session.stream_id.clone(),
            binding_generation: session.binding_generation.clone(),
            binding_digest: session.binding_digest.clone(),
            signer_key_id: session.signer_key_id.clone(),
            authority_pair: session.authority_pair,
            target_txid: target_txid.to_string(),
            request_digest: request.request_digest.clone(),
            session_generation: session.session_generation,
            session_commitment: session.session_commitment.clone(),
            witness_key_id: session.witness_key_id.clone(),
            response,
            signature: placeholder_signature(&self.signer),
        };
        VerifiedPublicWitnessCompletionV1::success(
            UnsignedPublicWitnessSuccessV1::Read(unsigned),
            request,
            current,
        )
        .map_err(invalid)?
        .sign_for_request(request, &self.signer)
        .map_err(invalid)
    }

    fn sign_failure(
        &self,
        request: &WitnessServiceRequestV1,
        current: &AuthenticatedStoreEntry,
        code: WitnessServiceFailureCodeV1,
    ) -> ProtocolResult<WitnessServiceResponseV1> {
        Ok(WitnessServiceResponseV1::Failure(
            WitnessServiceFailureAttestationV1::sign_for_verified_store(
                request,
                &current.verified,
                WitnessServiceFailureV1::new(code),
                &self.signer,
            )?,
        ))
    }

    async fn read_authenticated(
        &self,
        service_request: &WitnessServiceRequestV1,
        label: &str,
    ) -> Result<AuthenticatedStoreEntry, PublicWitnessDispatchErrorV1> {
        let admission = self.selected_admission(service_request)?;
        self.read_authenticated_for_digest(&service_request.request_digest, label, admission)
            .await
    }

    async fn read_authenticated_for_digest(
        &self,
        request_identity_digest: &str,
        label: &str,
        admission: &WitnessAdmissionEntryV1,
    ) -> Result<AuthenticatedStoreEntry, PublicWitnessDispatchErrorV1> {
        let request = self
            .proxy_request_for_digest(
                request_identity_digest,
                label,
                admission,
                WitnessStoreProxyRequestBodyV1::ReadEntry {
                    stream_id: admission.stream_id.clone(),
                },
            )
            .map_err(invalid)?;
        let expected_digest = request.request_digest.clone();
        self.worker_observer
            .observe(WorkerTransitionEventV1::ProxyStoreBegin {
                worker: WorkerKindV1::Public,
                operation: "read_entry",
                cas_attempted: false,
            });
        let response = self.proxy.read_entry(request).await;
        self.worker_observer
            .observe(WorkerTransitionEventV1::ProxyStoreEnd {
                worker: WorkerKindV1::Public,
                operation: "read_entry",
                succeeded: response.is_ok(),
                cas_applied: false,
            });
        let response = response.map_err(transport)?;
        response.validate().map_err(invalid)?;
        if response.operation != WitnessStoreProxyOperationV1::ReadEntry
            || response.request_digest != expected_digest
        {
            return Err(PublicWitnessDispatchErrorV1::Invalid);
        }
        let WitnessStoreProxyResponseBodyV1::Entry {
            stream_id,
            revision,
            envelope,
        } = response.body
        else {
            return Err(PublicWitnessDispatchErrorV1::Invalid);
        };
        if stream_id != admission.stream_id || revision == 0 {
            return Err(PublicWitnessDispatchErrorV1::Invalid);
        }
        let initialization_digest = self
            .stream_initialization_digest(admission)
            .map_err(invalid)?;
        AuthenticatedStoreEntry::new(
            revision,
            *envelope,
            &self.config,
            admission,
            &initialization_digest,
        )
        .map_err(invalid)
    }

    async fn apply_and_confirm(
        &self,
        service_request: &WitnessServiceRequestV1,
        current: &AuthenticatedStoreEntry,
        proposed: WitnessStoreEnvelopeV1,
    ) -> Result<MutationStoreResult, PublicWitnessDispatchErrorV1> {
        let admission = self.selected_admission(service_request)?;
        let initialization_digest = self
            .stream_initialization_digest(admission)
            .map_err(invalid)?;
        proposed
            .validate_for(WitnessStoreExpectationV1 {
                admission_digest: &admission.admission_digest,
                bucket_epoch_digest: &self.config.bucket_epoch_digest,
                stream_initialization_digest: &initialization_digest,
                stream_id: &admission.stream_id,
                witness_identity: &admission.witness_identity,
                witness_key_id: &admission.witness_key_id,
                authority_pair: admission.authority_pair,
                binding_generation: &admission.binding_generation,
                binding_digest: &admission.binding_digest,
                signer_key_id: &admission.signer_key_id,
            })
            .map_err(invalid)?;
        if validate_selected_entry_bounds(admission, &proposed).is_err() {
            return Ok(MutationStoreResult::Failure(Box::new(
                self.sign_failure(
                    service_request,
                    current,
                    WitnessServiceFailureCodeV1::BoundsExceeded,
                )
                .map_err(invalid)?,
            )));
        }
        let proposed_digest = proposed.signed_envelope_digest().map_err(invalid)?;
        let request = self
            .proxy_request(
                service_request,
                "cas",
                admission,
                WitnessStoreProxyRequestBodyV1::CompareAndSwap {
                    stream_id: admission.stream_id.clone(),
                    expected_revision: current.revision,
                    expected_store_state_digest: current
                        .envelope
                        .store_state_digest()
                        .map_err(invalid)?,
                    proposed_envelope: Box::new(proposed.clone()),
                },
            )
            .map_err(invalid)?;
        let expected_digest = request.request_digest.clone();
        let _ = ACTIVE_CAS_ATTEMPTED.try_with(|attempted| attempted.store(true, Ordering::SeqCst));
        self.worker_observer
            .observe(WorkerTransitionEventV1::ProxyStoreBegin {
                worker: WorkerKindV1::Public,
                operation: "compare_and_swap",
                cas_attempted: true,
            });
        let response = self.proxy.compare_and_swap(request).await;
        let cas_applied = response.as_ref().is_ok_and(|response| {
            matches!(
                &response.body,
                WitnessStoreProxyResponseBodyV1::CasApplied { .. }
            )
        });
        self.worker_observer
            .observe(WorkerTransitionEventV1::ProxyStoreEnd {
                worker: WorkerKindV1::Public,
                operation: "compare_and_swap",
                succeeded: response.is_ok(),
                cas_applied,
            });
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                // A diagnostic read can retain evidence for a later fenced
                // resolver, but transport loss after an attempted CAS never
                // authorizes success, deterministic refusal, or retry.
                let _diagnostic = self
                    .confirm_proposed(service_request, current, &proposed, None)
                    .await;
                let _ = error;
                return Err(PublicWitnessDispatchErrorV1::OutcomeUnknown);
            }
        };
        response
            .validate()
            .map_err(|_| PublicWitnessDispatchErrorV1::OutcomeUnknown)?;
        if response.operation != WitnessStoreProxyOperationV1::CompareAndSwap
            || response.request_digest != expected_digest
        {
            return Err(PublicWitnessDispatchErrorV1::OutcomeUnknown);
        }
        match response.body {
            WitnessStoreProxyResponseBodyV1::CasApplied {
                stream_id,
                previous_revision,
                new_revision,
                acknowledged_value_digest,
            } if stream_id == admission.stream_id
                && previous_revision == current.revision
                && new_revision > previous_revision
                && acknowledged_value_digest == proposed_digest =>
            {
                let confirmed = self
                    .confirm_proposed(service_request, current, &proposed, Some(new_revision))
                    .await?;
                Ok(MutationStoreResult::Confirmed(Box::new(confirmed)))
            }
            WitnessStoreProxyResponseBodyV1::Conflict {
                stream_id,
                observed_revision,
                observed_envelope,
            } if stream_id == admission.stream_id && observed_revision > 0 => {
                let observed = AuthenticatedStoreEntry::new(
                    observed_revision,
                    *observed_envelope,
                    &self.config,
                    admission,
                    &self
                        .stream_initialization_digest(admission)
                        .map_err(invalid)?,
                )
                .map_err(|_| PublicWitnessDispatchErrorV1::OutcomeUnknown)?;
                if validate_selected_entry_bounds(admission, &observed.envelope).is_err() {
                    return Ok(MutationStoreResult::Failure(Box::new(
                        self.sign_failure(
                            service_request,
                            &observed,
                            WitnessServiceFailureCodeV1::BoundsExceeded,
                        )
                        .map_err(invalid)?,
                    )));
                }
                Ok(MutationStoreResult::ObservedConflict(Box::new(observed)))
            }
            WitnessStoreProxyResponseBodyV1::Refused {
                failure_code,
                observed_revision,
                observed_value_digest,
            } if observed_revision == Some(current.revision)
                && observed_value_digest
                    == Some(current.envelope.signed_envelope_digest().map_err(invalid)?) =>
            {
                Ok(MutationStoreResult::Failure(Box::new(
                    self.sign_failure(service_request, current, map_proxy_failure(failure_code))
                        .map_err(invalid)?,
                )))
            }
            _ => Err(PublicWitnessDispatchErrorV1::OutcomeUnknown),
        }
    }

    async fn confirm_proposed(
        &self,
        service_request: &WitnessServiceRequestV1,
        current: &AuthenticatedStoreEntry,
        proposed: &WitnessStoreEnvelopeV1,
        expected_revision: Option<u64>,
    ) -> Result<AuthenticatedStoreEntry, PublicWitnessDispatchErrorV1> {
        let confirmed = self
            .read_authenticated(service_request, "confirm")
            .await
            .map_err(|_| PublicWitnessDispatchErrorV1::OutcomeUnknown)?;
        let admission = self.selected_admission(service_request)?;
        if validate_selected_entry_bounds(admission, &confirmed.envelope).is_err() {
            return Err(PublicWitnessDispatchErrorV1::OutcomeUnknown);
        }
        let proposed_bytes = proposed.canonical_bytes().map_err(invalid)?;
        let proposed_signed_digest = proposed.signed_envelope_digest().map_err(invalid)?;
        let proposed_store_digest = proposed.store_state_digest().map_err(invalid)?;
        if confirmed.revision <= current.revision
            || expected_revision.is_some_and(|revision| confirmed.revision != revision)
            || confirmed.envelope.canonical_bytes().map_err(invalid)? != proposed_bytes
            || confirmed
                .envelope
                .signed_envelope_digest()
                .map_err(invalid)?
                != proposed_signed_digest
            || confirmed.envelope.store_state_digest().map_err(invalid)? != proposed_store_digest
        {
            return Err(PublicWitnessDispatchErrorV1::OutcomeUnknown);
        }
        Ok(confirmed)
    }

    fn proxy_request(
        &self,
        service_request: &WitnessServiceRequestV1,
        label: &str,
        admission: &WitnessAdmissionEntryV1,
        body: WitnessStoreProxyRequestBodyV1,
    ) -> ProtocolResult<WitnessStoreProxyRequestV1> {
        self.proxy_request_for_digest(&service_request.request_digest, label, admission, body)
    }

    fn proxy_request_for_digest(
        &self,
        request_identity_digest: &str,
        label: &str,
        admission: &WitnessAdmissionEntryV1,
        body: WitnessStoreProxyRequestBodyV1,
    ) -> ProtocolResult<WitnessStoreProxyRequestV1> {
        let request_nonce = digest_domain(
            b"swarm.governance.witness-public-proxy-nonce.v1",
            &canonical_wire_bytes(&(request_identity_digest, label))?,
        )?;
        let operation = match body {
            WitnessStoreProxyRequestBodyV1::InspectReady => {
                WitnessStoreProxyOperationV1::InspectReady
            }
            WitnessStoreProxyRequestBodyV1::ReadEntry { .. } => {
                WitnessStoreProxyOperationV1::ReadEntry
            }
            WitnessStoreProxyRequestBodyV1::CompareAndSwap { .. } => {
                WitnessStoreProxyOperationV1::CompareAndSwap
            }
        };
        let mut request = WitnessStoreProxyRequestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation,
            request_nonce,
            admission_digest: admission.admission_digest.clone(),
            bucket_epoch_digest: self.config.bucket_epoch_digest.clone(),
            bucket_anchor_digest: self.config.bucket_anchor_digest.clone(),
            body,
            request_digest: String::new(),
            witness_key_id: self.config.witness_key_id.clone(),
            signature: placeholder_signature(&self.signer),
        };
        request.request_digest = request.computed_digest()?;
        request.signature = self.signer.sign(&request.signing_bytes()?);
        request.validate_structure()?;
        request.validate_semantics()?;
        request.validate_signature()?;
        Ok(request)
    }

    fn stream_initialization_digest(
        &self,
        admission: &WitnessAdmissionEntryV1,
    ) -> ProtocolResult<String> {
        WitnessStreamInitializationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            bucket_epoch_digest: self.config.bucket_epoch_digest.clone(),
            admission_digest: admission.admission_digest.clone(),
            stream_id: admission.stream_id.clone(),
            witness_identity: admission.witness_identity.clone(),
            witness_key_id: admission.witness_key_id.clone(),
        }
        .digest()
    }

    fn build_fence(
        &self,
        fence: &swarm_governance::persistence_protocol::WitnessSessionFenceRequestV1,
        envelope: &WitnessStoreEnvelopeV1,
        request_digest: &str,
    ) -> ProtocolResult<WitnessSessionStateFenceV1> {
        let admission = self
            .config
            .admission_set
            .entry(&fence.stream_id)
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        let current_session_digest = envelope
            .session
            .as_ref()
            .map(|session| {
                digest_domain(
                    WITNESS_SESSION_STATE_DOMAIN_V1,
                    &canonical_wire_bytes(session)?,
                )
            })
            .transpose()?;
        let current_head_digest = envelope
            .current
            .as_ref()
            .map(|current| current.head.head_digest())
            .transpose()?;
        let current_prepared_digest = envelope
            .prepared
            .as_ref()
            .map(|prepared| {
                digest_domain(
                    WITNESS_PREPARED_STATE_DOMAIN_V1,
                    &canonical_wire_bytes(&prepared.prepared)?,
                )
            })
            .transpose()?;
        Ok(WitnessSessionStateFenceV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            request: fence.clone(),
            admission_digest: admission.admission_digest.clone(),
            bucket_epoch_digest: self.config.bucket_epoch_digest.clone(),
            bucket_anchor_digest: self.config.bucket_anchor_digest.clone(),
            ready_manifest_digest: self.config.ready_manifest_digest.clone(),
            store_state_digest: envelope.store_state_digest()?,
            current_session_generation: envelope
                .session
                .as_ref()
                .map(|session| session.session_generation),
            current_session_digest,
            current_head_digest,
            current_prepared_digest,
            witness_nonce: digest_domain(
                b"swarm.governance.witness-public-fence-nonce.v1",
                request_digest.as_bytes(),
            )?,
            witness_identity: self.config.witness_identity.clone(),
            witness_key_id: self.config.witness_key_id.clone(),
            signature: placeholder_signature(&self.signer),
        })
    }
}

struct AuthenticatedStoreEntry {
    revision: u64,
    envelope: WitnessStoreEnvelopeV1,
    verified: VerifiedWitnessStoreStateV1,
}

enum MutationStoreResult {
    Confirmed(Box<AuthenticatedStoreEntry>),
    Failure(Box<WitnessServiceResponseV1>),
    ObservedConflict(Box<AuthenticatedStoreEntry>),
}

impl AuthenticatedStoreEntry {
    fn new(
        revision: u64,
        envelope: WitnessStoreEnvelopeV1,
        config: &PublicWitnessServiceConfigV1,
        admission: &WitnessAdmissionEntryV1,
        initialization_digest: &str,
    ) -> ProtocolResult<Self> {
        envelope.validate_for(WitnessStoreExpectationV1 {
            admission_digest: &admission.admission_digest,
            bucket_epoch_digest: &config.bucket_epoch_digest,
            stream_initialization_digest: initialization_digest,
            stream_id: &admission.stream_id,
            witness_identity: &admission.witness_identity,
            witness_key_id: &admission.witness_key_id,
            authority_pair: admission.authority_pair,
            binding_generation: &admission.binding_generation,
            binding_digest: &admission.binding_digest,
            signer_key_id: &admission.signer_key_id,
        })?;
        let verified = VerifiedWitnessStoreStateV1::from_present(&envelope)?;
        Ok(Self {
            revision,
            envelope,
            verified,
        })
    }
}

enum UnsignedPublicWitnessSuccessV1 {
    Fence(Box<WitnessSessionStateFenceV1>),
    Establish(Box<WitnessSessionAttestationV1>),
    Discover(Box<WitnessDiscoveryAttestationV1>),
    Outcome(WitnessOutcomeAttestationV1),
    Read(WitnessReadAttestationV1),
}

struct VerifiedPublicWitnessCompletionV1 {
    success: UnsignedPublicWitnessSuccessV1,
}

impl VerifiedPublicWitnessCompletionV1 {
    fn success(
        success: UnsignedPublicWitnessSuccessV1,
        request: &WitnessServiceRequestV1,
        current: &AuthenticatedStoreEntry,
    ) -> ProtocolResult<Self> {
        if current.envelope.stream_id != config_stream_id(request)? {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        // Nested validation is deliberately deferred until the terminal
        // signature replaces the untrusted placeholder.
        Ok(Self { success })
    }

    fn sign_for_request(
        mut self,
        request: &WitnessServiceRequestV1,
        signer: &Ed25519Signer,
    ) -> ProtocolResult<WitnessServiceResponseV1> {
        let response = match &mut self.success {
            UnsignedPublicWitnessSuccessV1::Fence(value) => {
                value.signature = signer.sign(&value.signing_bytes()?);
                WitnessServiceResponseV1::Fence(value.as_ref().clone())
            }
            UnsignedPublicWitnessSuccessV1::Establish(value) => {
                value.signature = signer.sign(&value.signing_bytes()?);
                WitnessServiceResponseV1::Establish(value.as_ref().clone())
            }
            UnsignedPublicWitnessSuccessV1::Discover(value) => {
                value.signature = signer.sign(&value.signing_bytes()?);
                WitnessServiceResponseV1::Discover(value.as_ref().clone())
            }
            UnsignedPublicWitnessSuccessV1::Outcome(value) => {
                value.signature = signer.sign(&value.signing_bytes()?);
                WitnessServiceResponseV1::Outcome(value.clone())
            }
            UnsignedPublicWitnessSuccessV1::Read(value) => {
                value.signature = signer.sign(&value.signing_bytes()?);
                WitnessServiceResponseV1::Read(value.clone())
            }
        };
        response.validate_for_request(request, None)?;
        Ok(response)
    }
}

fn request_session(request: &WitnessServiceRequestV1) -> Option<&WitnessSessionV1> {
    match &request.body {
        WitnessServiceRequestBodyV1::Prepare { session, .. }
        | WitnessServiceRequestBodyV1::Commit { session, .. }
        | WitnessServiceRequestBodyV1::Abort { session, .. }
        | WitnessServiceRequestBodyV1::ReadPrepared { session, .. }
        | WitnessServiceRequestBodyV1::ReadHead { session, .. }
        | WitnessServiceRequestBodyV1::FetchPayload { session, .. } => Some(session),
        WitnessServiceRequestBodyV1::Fence { .. }
        | WitnessServiceRequestBodyV1::Establish { .. }
        | WitnessServiceRequestBodyV1::Discover { .. } => None,
    }
}

fn commit_winner(
    envelope: &WitnessStoreEnvelopeV1,
    txid: &str,
) -> ProtocolResult<Option<(String, WitnessCommitOutcomeV1)>> {
    if let Some(genesis) = &envelope.genesis_abort
        && genesis.txid == txid
    {
        return Ok(Some((
            genesis.candidate_digest.clone(),
            WitnessCommitOutcomeV1::GenesisAborted(Box::new(genesis.clone())),
        )));
    }
    let Some(stored) = envelope.current.as_ref() else {
        return Ok(None);
    };
    match stored.head.last_intent_outcome.as_ref() {
        Some(swarm_governance::persistence_protocol::WitnessIntentOutcomeV1::Committed {
            txid: winning_txid,
            candidate_digest,
            ..
        }) if winning_txid == txid => {
            let committed = WitnessCommittedV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                head: stored.head.clone(),
            };
            committed.validate()?;
            Ok(Some((
                candidate_digest.clone(),
                WitnessCommitOutcomeV1::AlreadyCommitted(committed),
            )))
        }
        Some(swarm_governance::persistence_protocol::WitnessIntentOutcomeV1::Aborted(summary))
            if summary.txid == txid =>
        {
            let aborted = WitnessAbortedV1::from_resulting_head(
                &stored.head,
                "phase285-public-commit-observed-abort".to_string(),
            )?;
            Ok(Some((
                aborted.candidate_digest.clone(),
                WitnessCommitOutcomeV1::Aborted(Box::new(aborted)),
            )))
        }
        _ => Ok(None),
    }
}

fn abort_winner(
    envelope: &WitnessStoreEnvelopeV1,
    txid: &str,
) -> ProtocolResult<Option<(String, WitnessAbortOutcomeV1)>> {
    if let Some(genesis) = &envelope.genesis_abort
        && genesis.txid == txid
    {
        return Ok(Some((
            genesis.candidate_digest.clone(),
            WitnessAbortOutcomeV1::GenesisAborted(genesis.clone()),
        )));
    }
    let Some(stored) = envelope.current.as_ref() else {
        return Ok(None);
    };
    match stored.head.last_intent_outcome.as_ref() {
        Some(swarm_governance::persistence_protocol::WitnessIntentOutcomeV1::Committed {
            txid: winning_txid,
            candidate_digest,
            ..
        }) if winning_txid == txid => {
            let committed = WitnessCommittedV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                head: stored.head.clone(),
            };
            committed.validate()?;
            Ok(Some((
                candidate_digest.clone(),
                WitnessAbortOutcomeV1::Committed(committed),
            )))
        }
        Some(swarm_governance::persistence_protocol::WitnessIntentOutcomeV1::Aborted(summary))
            if summary.txid == txid =>
        {
            let aborted = WitnessAbortedV1::from_resulting_head(
                &stored.head,
                "phase285-public-abort-retry".to_string(),
            )?;
            Ok(Some((
                aborted.candidate_digest.clone(),
                WitnessAbortOutcomeV1::AlreadyAborted(aborted),
            )))
        }
        _ => Ok(None),
    }
}

fn rotated_session(
    current: &WitnessStoreEnvelopeV1,
    challenge: &RecoveryChallengeV1,
) -> ProtocolResult<WitnessSessionV1> {
    challenge.validate()?;
    let current_generation = current
        .session
        .as_ref()
        .map_or(0, |session| session.session_generation);
    if challenge.state_fence.current_session_generation
        != current
            .session
            .as_ref()
            .map(|session| session.session_generation)
    {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    let session_generation = current_generation
        .checked_add(1)
        .ok_or(ProtocolError::Overflow {
            counter: "session_generation",
        })?;
    if challenge.expected_session_generation()? != session_generation {
        return Err(ProtocolError::WitnessOutcomeMismatch);
    }
    let session = WitnessSessionV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        stream_id: challenge.stream_id.clone(),
        authority_pair: challenge.authority_pair,
        binding_generation: challenge.binding_generation.clone(),
        binding_digest: challenge.binding_digest.clone(),
        signer_key_id: challenge.signer_key_id.clone(),
        witness_key_id: challenge.witness_key_id.clone(),
        ephemeral_key_id: challenge.ephemeral_key_id.clone(),
        witness_identity: challenge.witness_identity.clone(),
        session_generation,
        session_commitment: challenge.session_commitment.clone(),
    };
    session.validate()?;
    Ok(session)
}

fn config_stream_id(request: &WitnessServiceRequestV1) -> ProtocolResult<&str> {
    match &request.body {
        WitnessServiceRequestBodyV1::Fence { request } => Ok(&request.stream_id),
        WitnessServiceRequestBodyV1::Establish { challenge, .. }
        | WitnessServiceRequestBodyV1::Discover { challenge } => Ok(&challenge.stream_id),
        WitnessServiceRequestBodyV1::Prepare { session, .. }
        | WitnessServiceRequestBodyV1::Commit { session, .. }
        | WitnessServiceRequestBodyV1::Abort { session, .. }
        | WitnessServiceRequestBodyV1::ReadPrepared { session, .. }
        | WitnessServiceRequestBodyV1::ReadHead { session, .. }
        | WitnessServiceRequestBodyV1::FetchPayload { session, .. } => Ok(&session.stream_id),
    }
}

fn unsigned_prepare_outcome(
    session: &swarm_governance::persistence_protocol::WitnessSessionV1,
    candidate: &swarm_governance::persistence_protocol::CandidateV1,
    prepared: swarm_governance::persistence_protocol::WitnessPreparedV1,
    signer: &Ed25519Signer,
) -> WitnessOutcomeAttestationV1 {
    WitnessOutcomeAttestationV1 {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        operation: WitnessOperationV1::Prepare,
        stream_id: session.stream_id.clone(),
        binding_generation: session.binding_generation.clone(),
        binding_digest: session.binding_digest.clone(),
        signer_key_id: session.signer_key_id.clone(),
        authority_pair: session.authority_pair,
        txid: candidate.txid.clone(),
        candidate_digest: candidate.candidate_digest.clone(),
        session_generation: session.session_generation,
        session_commitment: session.session_commitment.clone(),
        witness_key_id: session.witness_key_id.clone(),
        outcome: WitnessOperationOutcomeV1::Prepare(Box::new(WitnessPrepareOutcomeV1::Prepared(
            prepared,
        ))),
        signature: placeholder_signature(signer),
    }
}

fn placeholder_signature(signer: &Ed25519Signer) -> DetachedSignature {
    DetachedSignature {
        algorithm: "ed25519".to_string(),
        key_id: signer.key_id().to_string(),
        public_key_hex: signer.public_key_hex().to_string(),
        signature_hex: "0".repeat(128),
    }
}

fn failure_code_for_protocol(error: &ProtocolError) -> WitnessServiceFailureCodeV1 {
    WitnessServiceFailureV1::from_protocol_error(error).failure_code
}

fn validate_selected_entry_bounds(
    admission: &WitnessAdmissionEntryV1,
    envelope: &WitnessStoreEnvelopeV1,
) -> ProtocolResult<()> {
    let retained_wire = canonical_wire_bytes(envelope)?.len() as u64;
    let mut retained_payload = 0_u64;
    for candidate in [
        envelope.current.as_ref().map(|value| &value.candidate),
        envelope.predecessor.as_ref().map(|value| &value.candidate),
        envelope.prepared.as_ref().map(|value| &value.candidate),
    ]
    .into_iter()
    .flatten()
    {
        let binding_bytes = canonical_wire_bytes(&candidate.publication_binding)?.len() as u64;
        if candidate.state_payload.len() as u64 > admission.max_state_bytes
            || candidate.checkpoint_payload.len() as u64 > admission.max_checkpoint_bytes
            || binding_bytes > admission.max_binding_bytes
        {
            return Err(ProtocolError::Bounds {
                field: "selected_admission_candidate".to_string(),
                observed: usize::try_from(
                    (candidate.state_payload.len() as u64)
                        .max(candidate.checkpoint_payload.len() as u64)
                        .max(binding_bytes),
                )
                .unwrap_or(usize::MAX),
                maximum: usize::try_from(
                    admission
                        .max_state_bytes
                        .max(admission.max_checkpoint_bytes)
                        .max(admission.max_binding_bytes),
                )
                .unwrap_or(usize::MAX),
            });
        }
        retained_payload = retained_payload
            .checked_add(candidate.state_payload.len() as u64)
            .and_then(|value| value.checked_add(candidate.checkpoint_payload.len() as u64))
            .ok_or(ProtocolError::Overflow {
                counter: "selected_admission_retained_payload",
            })?;
    }
    if retained_wire > admission.max_retained_bytes
        || retained_payload > admission.max_retained_bytes
    {
        return Err(ProtocolError::Bounds {
            field: "selected_admission_retained".to_string(),
            observed: usize::try_from(retained_wire.max(retained_payload)).unwrap_or(usize::MAX),
            maximum: usize::try_from(admission.max_retained_bytes).unwrap_or(usize::MAX),
        });
    }
    Ok(())
}

fn map_proxy_failure(code: WitnessStoreProxyFailureCodeV1) -> WitnessServiceFailureCodeV1 {
    match code {
        WitnessStoreProxyFailureCodeV1::Missing => WitnessServiceFailureCodeV1::StoreEntryMissing,
        WitnessStoreProxyFailureCodeV1::Corrupt | WitnessStoreProxyFailureCodeV1::Header => {
            WitnessServiceFailureCodeV1::StoreEntryCorrupt
        }
        WitnessStoreProxyFailureCodeV1::Configuration
        | WitnessStoreProxyFailureCodeV1::Admission => {
            WitnessServiceFailureCodeV1::AdmissionMismatch
        }
        WitnessStoreProxyFailureCodeV1::Signature => WitnessServiceFailureCodeV1::InvalidSignature,
        WitnessStoreProxyFailureCodeV1::Bounds => WitnessServiceFailureCodeV1::BoundsExceeded,
        WitnessStoreProxyFailureCodeV1::Conflict => WitnessServiceFailureCodeV1::Conflict,
        WitnessStoreProxyFailureCodeV1::Unavailable | WitnessStoreProxyFailureCodeV1::Ambiguous => {
            WitnessServiceFailureCodeV1::InternalUnavailable
        }
    }
}

fn invalid<T>(_: T) -> PublicWitnessDispatchErrorV1 {
    PublicWitnessDispatchErrorV1::Invalid
}

fn transport(error: PublicWitnessProxyTransportErrorV1) -> PublicWitnessDispatchErrorV1 {
    match error {
        PublicWitnessProxyTransportErrorV1::Framing => PublicWitnessDispatchErrorV1::Invalid,
        PublicWitnessProxyTransportErrorV1::Timeout => PublicWitnessDispatchErrorV1::OutcomeUnknown,
        PublicWitnessProxyTransportErrorV1::OutcomeUnknown => {
            PublicWitnessDispatchErrorV1::OutcomeUnknown
        }
        PublicWitnessProxyTransportErrorV1::Unavailable => {
            PublicWitnessDispatchErrorV1::Unavailable
        }
    }
}

#[cfg(test)]
pub(crate) fn classify_proxy_transport_for_test(
    error: PublicWitnessProxyTransportErrorV1,
) -> PublicWitnessDispatchErrorV1 {
    transport(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_ingress_refuses_before_worker_or_store_access() {
        assert!(public_witness_ingress_overload_control());
        assert!(is_bounded_inbox_reply(&"_INBOX.phase285".into()));
        assert!(!is_bounded_inbox_reply(&"client.chosen.reply".into()));
    }

    #[test]
    fn post_command_proxy_timeout_is_outcome_unknown() {
        assert!(matches!(
            classify_proxy_transport_for_test(PublicWitnessProxyTransportErrorV1::Timeout),
            PublicWitnessDispatchErrorV1::OutcomeUnknown
        ));
    }
}
