#![forbid(unsafe_code)]

//! Downstream transport boundary for the authenticated governance witness.

mod jetstream_store;
mod nats_config;
mod public_dispatcher;
pub mod raw_config;
mod runtime_client;
mod service_config;
mod store_proxy_service;

pub use jetstream_store::NatsWitnessStore;
pub use public_dispatcher::{
    PublicWitnessDispatchErrorV1, PublicWitnessDispatchMappingV1, PublicWitnessDispatcher,
    PublicWitnessProxyTransportErrorV1, PublicWitnessRunnerErrorV1, PublicWitnessServiceRunner,
    PublicWitnessStoreProxyClient, dispatcher_mapping, public_witness_ingress_overload_control,
};
pub use runtime_client::{RuntimeWitnessClient, RuntimeWitnessClientErrorV1};
pub use service_config::{
    PublicWitnessServiceConfigV1, RuntimeWitnessClientConfigV1, StoreProxyServiceConfigV1,
};
pub use store_proxy_service::{
    NatsPublicWitnessStoreProxyClient, StoreProxyRunnerErrorV1, StoreProxyService,
    StoreProxyServiceErrorV1, StoreProxyServiceRunner, StoreRoleConnectionV1,
    private_store_ingress_overload_control, store_proxy_subjects,
};

#[cfg(test)]
mod deadline_state_machine_tests {
    use super::public_dispatcher::{
        PublicIngressMessage, admit_public_subscription_message,
        receive_and_run_public_worker_message, run_public_worker_message,
    };
    use super::service_config::{
        PUBLIC_HANDLER_DEADLINE_MILLIS, PUBLIC_HANDLER_RESERVE_MILLIS,
        PUBLIC_PRIVATE_RESERVE_MILLIS, PUBLIC_RESPONSE_GRANT_MILLIS, RESPONSE_GRANT_MAXIMUM,
        ReceiptDeadlineV1, STORE_HANDLER_DEADLINE_MILLIS, STORE_HANDLER_RESERVE_MILLIS,
        STORE_RESPONSE_GRANT_MILLIS, SubscriberAdmissionObserverV1, SubscriberAdmissionReceiptV1,
        WorkerKindV1, WorkerPublisherV1, WorkerTransitionEventV1, WorkerTransitionObserverV1,
        WorkerTransitionV1,
    };
    use super::store_proxy_service::{
        PrivateIngressMessage, admit_private_subscription_message,
        receive_and_run_private_worker_message, run_private_worker_message, store_proxy_subjects,
    };
    use super::{
        NatsPublicWitnessStoreProxyClient, PublicWitnessDispatchErrorV1, PublicWitnessDispatcher,
        PublicWitnessProxyTransportErrorV1, PublicWitnessServiceConfigV1,
        PublicWitnessServiceRunner, PublicWitnessStoreProxyClient, RuntimeWitnessClient,
        RuntimeWitnessClientConfigV1, StoreProxyService, StoreProxyServiceConfigV1,
        StoreProxyServiceErrorV1, StoreProxyServiceRunner, StoreRoleConnectionV1,
    };
    use async_trait::async_trait;
    use futures_util::StreamExt;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Instant as MonotonicInstant;
    use swarm_crypto::{Ed25519Signer, sha256_hex};
    use swarm_governance::persistence_protocol::*;
    use swarm_governance::witness_engine::store::{
        WitnessAdmissionEntryV1, WitnessAdmissionSetV1, WitnessAtomicStore, WitnessBucketAnchorV1,
        WitnessBucketConfigurationV1, WitnessBucketEpochV1, WitnessBucketManifestPhaseV1,
        WitnessBucketManifestV1, WitnessCompressionV1, WitnessDiscardPolicyV1,
        WitnessPersistenceSemanticsV1, WitnessRetentionPolicyV1, WitnessStorageTypeV1,
        WitnessStoreCasResultV1, WitnessStoreDeploymentInputsV1, WitnessStoreErrorV1,
        WitnessStoreProxyOperationV1, WitnessStoreProxyRequestBodyV1, WitnessStoreProxyRequestV1,
        WitnessStoreProxyResponseV1, WitnessStoreReadResultV1, WitnessStoreReadyResultV1,
        WitnessStreamInitializationRecordV1, WitnessStreamInitializationV1,
        in_memory::InMemoryWitnessStore,
    };
    use swarm_governance::witness_engine::{WitnessStoreEnvelopeV1, witness_stream_key};
    use swarm_governance::witness_service::{
        WitnessAdmissionRecordV1, WitnessServiceOperationV1, WitnessServiceRequestBodyV1,
        WitnessServiceRequestV1, WitnessServiceResponseV1,
    };
    use tokio::sync::{Mutex as TokioMutex, Notify, mpsc};
    use tokio::time::{Duration, advance, sleep};

    const LEDGER_PATH_ENV: &str = "PHASE285_DEADLINE_LEDGER";
    const LEDGER_REQUIRED_ENV: &str = "PHASE285_DEADLINE_LEDGER_REQUIRED";
    const TREE_ENV: &str = "PHASE285_DEADLINE_TREE";
    const TOKEN_ENV: &str = "PHASE285_DEADLINE_INVOCATION_TOKEN";
    const CASE_ENV: &str = "PHASE285_DEADLINE_CASE";

    fn must<T, E: std::fmt::Debug>(result: Result<T, E>, label: &str) -> T {
        result.unwrap_or_else(|error| panic!("{label}: {error:?}"))
    }

    fn must_some<T>(value: Option<T>, label: &str) -> T {
        value.unwrap_or_else(|| panic!("{label}"))
    }

    #[derive(Default)]
    struct RecordingWorkerTransitionObserverV1 {
        events: Mutex<Vec<WorkerTransitionEventV1>>,
        gate: Mutex<Option<(DeadlineGateV1, Arc<Notify>)>>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DeadlineGateV1 {
        PrivatePostPreflight,
        PrivateStoreEnd,
        PublicProxyEnd,
    }

    impl RecordingWorkerTransitionObserverV1 {
        fn clear(&self) {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
            *self
                .gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }

        fn arm(&self, gate: DeadlineGateV1) -> Arc<Notify> {
            let notify = Arc::new(Notify::new());
            *self
                .gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((gate, notify.clone()));
            notify
        }

        fn reduce(&self) -> DeadlineEvidenceV1 {
            let events = self
                .events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut queue_dequeues = 0;
            let mut preflights = 0;
            let mut store_calls = 0;
            let mut private_proxy_calls = 0;
            let mut cas_attempted = 0;
            let mut cas_applied = 0;
            let mut retries = 0;
            let mut publications = 0;
            let mut outcome_unknown = false;
            for event in events.iter() {
                match event {
                    WorkerTransitionEventV1::Dequeued { .. } => queue_dequeues += 1,
                    WorkerTransitionEventV1::PostPreflight { .. } => preflights += 1,
                    WorkerTransitionEventV1::ProxyStoreBegin {
                        worker,
                        cas_attempted: attempted,
                        ..
                    } => {
                        match worker {
                            WorkerKindV1::Private => store_calls += 1,
                            WorkerKindV1::Public => private_proxy_calls += 1,
                        }
                        if *attempted {
                            if cas_attempted > 0 {
                                retries += 1;
                            }
                            cas_attempted += 1;
                        }
                    }
                    WorkerTransitionEventV1::ProxyStoreEnd { .. } => {}
                    WorkerTransitionEventV1::CasAppliedObservation { .. } => cas_applied += 1,
                    WorkerTransitionEventV1::PublishAttempt { published, .. } => {
                        publications += u64::from(*published);
                    }
                    WorkerTransitionEventV1::OutcomeUnknown => outcome_unknown = true,
                    WorkerTransitionEventV1::ResponseEnqueueAttempt { .. } => {}
                }
            }
            DeadlineEvidenceV1 {
                ordered_trace: events.clone(),
                queue_dequeues,
                preflights,
                store_calls,
                private_proxy_calls,
                cas_attempted,
                cas_applied,
                retries,
                publications,
                outcome_unknown,
            }
        }

        fn reduce_authenticated(
            &self,
            facts: &RecordingStoreFactsV1,
            publisher: &RecordingPublisherV1,
            worker: WorkerKindV1,
        ) -> DeadlineEvidenceV1 {
            let evidence = self.reduce();
            let reads = facts.reads.load(Ordering::SeqCst) as u64;
            let cas_attempted = facts.cas_attempted.load(Ordering::SeqCst) as u64;
            let cas_applied = facts.cas_applied.load(Ordering::SeqCst) as u64;
            assert_eq!(
                evidence.publications,
                publisher.publications.load(Ordering::SeqCst) as u64,
                "publisher event diverged from recording publisher"
            );
            assert_eq!(
                evidence.cas_attempted, cas_attempted,
                "CAS event diverged from recording WitnessAtomicStore"
            );
            assert_eq!(
                evidence.cas_applied, cas_applied,
                "CAS-applied event diverged from recording WitnessAtomicStore: trace={:?}",
                evidence.ordered_trace
            );
            if worker == WorkerKindV1::Private {
                assert_eq!(
                    evidence.store_calls,
                    reads + cas_attempted,
                    "private store event diverged from recording WitnessAtomicStore"
                );
            }
            evidence
        }
    }

    impl WorkerTransitionObserverV1 for RecordingWorkerTransitionObserverV1 {
        fn observe(&self, event: WorkerTransitionEventV1) {
            let should_release = self
                .gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .is_some_and(|(gate, _)| {
                    matches!(
                        (gate, &event),
                        (
                            DeadlineGateV1::PrivatePostPreflight,
                            WorkerTransitionEventV1::PostPreflight {
                                worker: WorkerKindV1::Private
                            }
                        ) | (
                            DeadlineGateV1::PrivateStoreEnd,
                            WorkerTransitionEventV1::ProxyStoreEnd {
                                worker: WorkerKindV1::Private,
                                ..
                            }
                        ) | (
                            DeadlineGateV1::PublicProxyEnd,
                            WorkerTransitionEventV1::ProxyStoreEnd {
                                worker: WorkerKindV1::Public,
                                ..
                            }
                        )
                    )
                });
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(event);
            if should_release
                && let Some((_, notify)) = self
                    .gate
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
            {
                notify.notify_one();
            }
        }
    }

    struct RecordingSubscriberAdmissionObserverV1 {
        sender: mpsc::Sender<SubscriberAdmissionReceiptV1>,
    }

    impl SubscriberAdmissionObserverV1 for RecordingSubscriberAdmissionObserverV1 {
        fn accepted(&self, receipt: SubscriberAdmissionReceiptV1) {
            let _ = self.sender.try_send(receipt);
        }
    }

    struct RecordingPublisherV1 {
        delay_millis: u64,
        publications: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl WorkerPublisherV1 for RecordingPublisherV1 {
        async fn publish(&self, _reply: async_nats::Subject, _payload: Vec<u8>) -> bool {
            sleep(Duration::from_millis(self.delay_millis)).await;
            self.publications.fetch_add(1, Ordering::SeqCst);
            true
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct DeadlineEvidenceV1 {
        ordered_trace: Vec<WorkerTransitionEventV1>,
        queue_dequeues: u64,
        preflights: u64,
        store_calls: u64,
        private_proxy_calls: u64,
        cas_attempted: u64,
        cas_applied: u64,
        retries: u64,
        publications: u64,
        outcome_unknown: bool,
    }

    #[derive(Default)]
    struct RecordingStoreFactsV1 {
        reads: AtomicUsize,
        cas_attempted: AtomicUsize,
        cas_applied: AtomicUsize,
        inspect_ready: AtomicUsize,
        records: Mutex<Vec<StoreObservationV1>>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct StoreObservationV1 {
        operation: &'static str,
        stream_id: Option<String>,
        input_canonical_hex: String,
        input_sha256: String,
        result_canonical_hex: String,
        result_sha256: String,
        revision: Option<u64>,
        store_generation: Option<u64>,
        store_state_digest: Option<String>,
        cas_attempted: bool,
        cas_applied: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct ProxyObservationV1 {
        operation: WitnessStoreProxyOperationV1,
        subject: String,
        request_nonce: String,
        request_digest: String,
        request_canonical_hex: String,
        request_sha256: String,
        response_canonical_hex: String,
        response_sha256: String,
        stream_id: Option<String>,
        revision: Option<u64>,
        store_generation: Option<u64>,
        store_state_digest: Option<String>,
        request_at_nanos: u64,
        response_at_nanos: u64,
    }

    struct ObservationClockV1 {
        origin: MonotonicInstant,
    }

    impl ObservationClockV1 {
        fn new() -> Self {
            Self {
                origin: MonotonicInstant::now(),
            }
        }

        fn now(&self) -> u64 {
            must(
                u64::try_from(self.origin.elapsed().as_nanos()),
                "observation timestamp overflow",
            )
        }
    }

    #[derive(Clone)]
    struct RecordingNatsProxyV1 {
        inner: NatsPublicWitnessStoreProxyClient,
        records: Arc<Mutex<Vec<ProxyObservationV1>>>,
        clock: Arc<ObservationClockV1>,
    }

    impl RecordingNatsProxyV1 {
        async fn call(
            &self,
            request: WitnessStoreProxyRequestV1,
            operation: WitnessStoreProxyOperationV1,
        ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
            let request_bytes = canonical_wire_bytes(&request)
                .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
            let request_at_nanos = self.clock.now();
            let request_nonce = request.request_nonce.clone();
            let request_digest = request.request_digest.clone();
            let response = match operation {
                WitnessStoreProxyOperationV1::InspectReady => {
                    self.inner.inspect_ready(request).await?
                }
                WitnessStoreProxyOperationV1::ReadEntry => self.inner.read_entry(request).await?,
                WitnessStoreProxyOperationV1::CompareAndSwap => {
                    self.inner.compare_and_swap(request).await?
                }
            };
            let response_bytes = canonical_wire_bytes(&response)
                .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
            let response_at_nanos = self.clock.now();
            let (stream_id, revision, store_generation, store_state_digest) =
                match &response.body {
                    swarm_governance::witness_engine::store::WitnessStoreProxyResponseBodyV1::Entry {
                        stream_id,
                        revision,
                        envelope,
                    } => (
                        Some(stream_id.clone()),
                        Some(*revision),
                        Some(envelope.store_generation),
                        envelope.store_state_digest().ok(),
                    ),
                    swarm_governance::witness_engine::store::WitnessStoreProxyResponseBodyV1::CasApplied {
                        stream_id,
                        new_revision,
                        ..
                    } => (Some(stream_id.clone()), Some(*new_revision), None, None),
                    _ => (None, None, None, None),
                };
            self.records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(ProxyObservationV1 {
                    operation,
                    subject: match operation {
                        WitnessStoreProxyOperationV1::InspectReady => store_proxy_subjects()[0],
                        WitnessStoreProxyOperationV1::ReadEntry => store_proxy_subjects()[1],
                        WitnessStoreProxyOperationV1::CompareAndSwap => store_proxy_subjects()[2],
                    }
                    .to_string(),
                    request_nonce,
                    request_digest,
                    request_canonical_hex: hex::encode(&request_bytes),
                    request_sha256: sha256_hex(&request_bytes),
                    response_canonical_hex: hex::encode(&response_bytes),
                    response_sha256: sha256_hex(&response_bytes),
                    stream_id,
                    revision,
                    store_generation,
                    store_state_digest,
                    request_at_nanos,
                    response_at_nanos,
                });
            Ok(response)
        }
    }

    #[async_trait]
    impl PublicWitnessStoreProxyClient for RecordingNatsProxyV1 {
        async fn inspect_ready(
            &self,
            request: WitnessStoreProxyRequestV1,
        ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
            self.call(request, WitnessStoreProxyOperationV1::InspectReady)
                .await
        }

        async fn read_entry(
            &self,
            request: WitnessStoreProxyRequestV1,
        ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
            self.call(request, WitnessStoreProxyOperationV1::ReadEntry)
                .await
        }

        async fn compare_and_swap(
            &self,
            request: WitnessStoreProxyRequestV1,
        ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
            self.call(request, WitnessStoreProxyOperationV1::CompareAndSwap)
                .await
        }
    }

    struct DeadlineRecordingStoreV1 {
        inner: InMemoryWitnessStore,
        facts: Arc<RecordingStoreFactsV1>,
        mode: Arc<AtomicU8>,
        observer: Arc<RecordingWorkerTransitionObserverV1>,
        block_next_read: Arc<AtomicBool>,
        read_entered: Arc<Notify>,
        read_release: Arc<(Mutex<bool>, Condvar)>,
    }

    #[async_trait]
    impl WitnessAtomicStore for DeadlineRecordingStoreV1 {
        async fn inspect_ready(&self) -> Result<WitnessStoreReadyResultV1, WitnessStoreErrorV1> {
            self.facts.inspect_ready.fetch_add(1, Ordering::SeqCst);
            let result = self.inner.inspect_ready().await;
            if let Ok(ready) = &result {
                let result_bytes = must(
                    canonical_wire_bytes(ready),
                    "store InspectReady observation serialization",
                );
                self.facts
                    .records
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(StoreObservationV1 {
                        operation: "inspect_ready",
                        stream_id: None,
                        input_canonical_hex: hex::encode(b"inspect_ready"),
                        input_sha256: sha256_hex(b"inspect_ready"),
                        result_canonical_hex: hex::encode(&result_bytes),
                        result_sha256: sha256_hex(&result_bytes),
                        revision: None,
                        store_generation: None,
                        store_state_digest: None,
                        cas_attempted: false,
                        cas_applied: false,
                    });
            }
            result
        }

        async fn read_entry(
            &self,
            stream_id: &str,
        ) -> Result<WitnessStoreReadResultV1, WitnessStoreErrorV1> {
            self.facts.reads.fetch_add(1, Ordering::SeqCst);
            if self.block_next_read.swap(false, Ordering::SeqCst) {
                self.read_entered.notify_one();
                let (released, condition) = self.read_release.as_ref();
                let mut released = released
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while !*released {
                    released = condition
                        .wait(released)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                *released = false;
            }
            let mode = self.mode.load(Ordering::SeqCst);
            if mode == 1 {
                sleep(Duration::from_millis(STORE_HANDLER_DEADLINE_MILLIS - 500)).await;
            } else if mode == 3 || (mode == 2 && self.facts.cas_applied.load(Ordering::SeqCst) == 1)
            {
                sleep(Duration::from_millis(STORE_HANDLER_DEADLINE_MILLIS + 1)).await;
            }
            let result = self.inner.read_entry(stream_id).await;
            if let Ok(read) = &result {
                let (_, revision, envelope) = read.parts();
                let input_bytes = must(
                    canonical_wire_bytes(&stream_id),
                    "store ReadEntry input observation serialization",
                );
                let result_bytes = must(
                    canonical_wire_bytes(read),
                    "store ReadEntry result observation serialization",
                );
                self.facts
                    .records
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(StoreObservationV1 {
                        operation: "read_entry",
                        stream_id: Some(stream_id.to_string()),
                        input_canonical_hex: hex::encode(&input_bytes),
                        input_sha256: sha256_hex(&input_bytes),
                        result_canonical_hex: hex::encode(&result_bytes),
                        result_sha256: sha256_hex(&result_bytes),
                        revision: Some(revision),
                        store_generation: Some(envelope.store_generation),
                        store_state_digest: envelope.store_state_digest().ok(),
                        cas_attempted: false,
                        cas_applied: false,
                    });
            }
            result
        }

        async fn compare_and_swap(
            &self,
            stream_id: &str,
            expected_revision: u64,
            expected_store_state_digest: &str,
            proposed_envelope: &WitnessStoreEnvelopeV1,
        ) -> Result<WitnessStoreCasResultV1, WitnessStoreErrorV1> {
            self.facts.cas_attempted.fetch_add(1, Ordering::SeqCst);
            let result = self
                .inner
                .compare_and_swap(
                    stream_id,
                    expected_revision,
                    expected_store_state_digest,
                    proposed_envelope,
                )
                .await?;
            if matches!(result, WitnessStoreCasResultV1::Applied { .. }) {
                self.facts.cas_applied.fetch_add(1, Ordering::SeqCst);
                self.observer
                    .observe(WorkerTransitionEventV1::CasAppliedObservation {
                        worker: WorkerKindV1::Private,
                    });
            }
            let input_bytes = must(
                canonical_wire_bytes(&(
                    stream_id,
                    expected_revision,
                    expected_store_state_digest,
                    proposed_envelope,
                )),
                "store CAS input observation serialization",
            );
            let result_bytes = must(
                canonical_wire_bytes(&result),
                "store CAS result observation serialization",
            );
            self.facts
                .records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(StoreObservationV1 {
                    operation: "compare_and_swap",
                    stream_id: Some(stream_id.to_string()),
                    input_canonical_hex: hex::encode(&input_bytes),
                    input_sha256: sha256_hex(&input_bytes),
                    result_canonical_hex: hex::encode(&result_bytes),
                    result_sha256: sha256_hex(&result_bytes),
                    revision: match &result {
                        WitnessStoreCasResultV1::Applied { new_revision, .. } => {
                            Some(*new_revision)
                        }
                        WitnessStoreCasResultV1::Conflict {
                            observed_revision, ..
                        } => Some(*observed_revision),
                        WitnessStoreCasResultV1::Ambiguous {
                            observed_revision, ..
                        } => *observed_revision,
                    },
                    store_generation: Some(proposed_envelope.store_generation),
                    store_state_digest: proposed_envelope.store_state_digest().ok(),
                    cas_attempted: true,
                    cas_applied: matches!(result, WitnessStoreCasResultV1::Applied { .. }),
                });
            Ok(result)
        }
    }

    #[derive(Clone)]
    struct DeadlineServiceProxyV1 {
        service: Arc<StoreProxyService<DeadlineRecordingStoreV1>>,
    }

    impl DeadlineServiceProxyV1 {
        async fn round_trip(
            &self,
            request: WitnessStoreProxyRequestV1,
        ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
            let operation = request.operation;
            let index = match operation {
                WitnessStoreProxyOperationV1::InspectReady => 0,
                WitnessStoreProxyOperationV1::ReadEntry => 1,
                WitnessStoreProxyOperationV1::CompareAndSwap => 2,
            };
            let raw = canonical_wire_bytes(&request)
                .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)?;
            let response = self
                .service
                .handle_subject_bytes(store_proxy_subjects()[index], &raw)
                .await
                .map_err(map_proxy_error)?;
            WitnessStoreProxyResponseV1::decode(&response)
                .map_err(|_| PublicWitnessProxyTransportErrorV1::Framing)
        }
    }

    #[async_trait]
    impl PublicWitnessStoreProxyClient for DeadlineServiceProxyV1 {
        async fn inspect_ready(
            &self,
            request: WitnessStoreProxyRequestV1,
        ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
            self.round_trip(request).await
        }

        async fn read_entry(
            &self,
            request: WitnessStoreProxyRequestV1,
        ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
            self.round_trip(request).await
        }

        async fn compare_and_swap(
            &self,
            request: WitnessStoreProxyRequestV1,
        ) -> Result<WitnessStoreProxyResponseV1, PublicWitnessProxyTransportErrorV1> {
            self.round_trip(request).await
        }
    }

    fn map_proxy_error(error: StoreProxyServiceErrorV1) -> PublicWitnessProxyTransportErrorV1 {
        match error {
            StoreProxyServiceErrorV1::Invalid | StoreProxyServiceErrorV1::Bounds => {
                PublicWitnessProxyTransportErrorV1::Framing
            }
            StoreProxyServiceErrorV1::Timeout => PublicWitnessProxyTransportErrorV1::Timeout,
            StoreProxyServiceErrorV1::Unavailable => {
                PublicWitnessProxyTransportErrorV1::Unavailable
            }
        }
    }

    #[derive(Debug, Clone, Copy, Serialize)]
    struct DeadlineTopologyV1 {
        private_handler_millis: u64,
        private_response_grant_millis: u64,
        public_handler_millis: u64,
        public_response_grant_millis: u64,
        private_handler_reserve_millis: u64,
        public_private_reserve_millis: u64,
        public_handler_reserve_millis: u64,
        response_grant_maximum: usize,
    }

    #[derive(Debug, Serialize)]
    struct DeadlineLedgerRowV1<'a> {
        schema_version: u8,
        tree: &'a str,
        invocation_token: &'a str,
        case: &'a str,
        inner_id: &'a str,
        status: &'static str,
        live_nats_grants_proved: bool,
        evidence: DeadlineEvidenceV1,
    }

    #[derive(Debug, Serialize)]
    struct DeadlineBudgetReceiptV1<'a> {
        schema_version: u8,
        tree: &'a str,
        invocation_token: &'a str,
        case: &'a str,
        inner_id: &'static str,
        status: &'static str,
        live_nats_grants_proved: bool,
        topology: DeadlineTopologyV1,
    }

    struct AuthenticatedDeadlineFixtureV1 {
        governance: Ed25519Signer,
        witness: Ed25519Signer,
        ephemeral: Ed25519Signer,
        binding: PublicationBindingV1,
        admission: WitnessAdmissionRecordV1,
        ready: WitnessStoreReadyResultV1,
        challenge: RecoveryChallengeV1,
        service: Arc<StoreProxyService<DeadlineRecordingStoreV1>>,
        facts: Arc<RecordingStoreFactsV1>,
        mode: Arc<AtomicU8>,
        public_config: PublicWitnessServiceConfigV1,
        block_next_read: Arc<AtomicBool>,
        read_entered: Arc<Notify>,
        read_release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl AuthenticatedDeadlineFixtureV1 {
        fn new(observer: Arc<RecordingWorkerTransitionObserverV1>) -> ProtocolResult<Self> {
            let governance = Ed25519Signer::from_secret_material("phase285-a1-governance");
            let witness = Ed25519Signer::from_secret_material("phase285-a1-witness");
            let ephemeral = Ed25519Signer::from_secret_material("phase285-a1-ephemeral");
            let binding = fixture_stage("binding", deadline_binding(&governance, &witness))?;
            let admission = fixture_stage("admission", deadline_admission(&binding))?;
            let bucket_epoch_digest = "1".repeat(64);
            let stream_initialization_digest = WitnessStreamInitializationV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                bucket_epoch_digest: bucket_epoch_digest.clone(),
                admission_digest: admission.admission_digest.clone(),
                stream_id: admission.stream_id.clone(),
                witness_identity: admission.witness_identity.clone(),
                witness_key_id: admission.witness_key_id.clone(),
            }
            .digest()?;
            let mut empty = WitnessStoreEnvelopeV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                admission_digest: admission.admission_digest.clone(),
                bucket_epoch_digest,
                stream_initialization_digest,
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
                signature: witness.sign(&[]),
            };
            empty.signature = witness.sign(&empty.signing_bytes()?);
            empty.validate()?;

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
            admission_entry.validate()?;
            let mut admission_set = WitnessAdmissionSetV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                entries: vec![admission_entry],
                admission_set_digest: "0".repeat(64),
            };
            admission_set.admission_set_digest = admission_set.computed_digest()?;
            admission_set.validate()?;
            let (ready, empty) = fixture_stage(
                "ready",
                deadline_ready(&witness, admission_set.clone(), empty),
            )?;
            let anchor_digest = ready.bucket_anchor.digest()?;
            let ready_manifest_digest = ready.ready_manifest.digest()?;
            let challenge = fixture_stage(
                "challenge",
                deadline_challenge(
                    &governance,
                    &witness,
                    &ephemeral,
                    &binding,
                    &admission,
                    &empty,
                    &anchor_digest,
                    &ready_manifest_digest,
                ),
            )?;
            let facts = Arc::new(RecordingStoreFactsV1::default());
            let mode = Arc::new(AtomicU8::new(0));
            let block_next_read = Arc::new(AtomicBool::new(false));
            let read_entered = Arc::new(Notify::new());
            let read_release = Arc::new((Mutex::new(false), Condvar::new()));
            let inner = InMemoryWitnessStore::new(
                ready.clone(),
                BTreeMap::from([(admission.stream_id.clone(), (7, empty.clone()))]),
                2_000_000,
            )
            .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?;
            let store = DeadlineRecordingStoreV1 {
                inner,
                facts: facts.clone(),
                mode: mode.clone(),
                observer,
                block_next_read: block_next_read.clone(),
                read_entered: read_entered.clone(),
                read_release: read_release.clone(),
            };
            let service_config = deadline_store_config(&witness, &ready)?;
            let service = Arc::new(
                StoreProxyService::new(service_config, ready.clone(), store)
                    .map_err(|error| ProtocolError::CanonicalEncoding(error.to_string()))?,
            );
            let public_config = PublicWitnessServiceConfigV1 {
                nats_url: "tls://127.0.0.1:4222".to_string(),
                nats_credentials_path: "/conf/runtime.creds".to_string(),
                tls_ca_path: "/conf/ca.pem".to_string(),
                tls_server_name: "nats.phase285.test".to_string(),
                witness_key_path: "/conf/witness.key".to_string(),
                witness_identity: admission.witness_identity.clone(),
                witness_key_id: witness.key_id().to_string(),
                bucket_name: "phase285".to_string(),
                bucket_configuration_digest: ready.bucket_configuration.digest()?,
                bucket_epoch_digest: ready.bucket_epoch.digest()?,
                bucket_anchor_digest: anchor_digest,
                admission_set_digest: admission_set.admission_set_digest.clone(),
                ready_manifest_digest,
                admission_set,
                max_request_bytes: 1_048_576,
                max_response_bytes: 1_048_576,
                ingress_queue_capacity: 1,
                max_in_flight: 1,
                request_deadline_millis: 1_000,
            };
            public_config.validate()?;
            Ok(Self {
                governance,
                witness,
                ephemeral,
                binding,
                admission,
                ready,
                challenge,
                service,
                facts,
                mode,
                public_config,
                block_next_read,
                read_entered,
                read_release,
            })
        }

        async fn dispatcher(
            &self,
            observer: Arc<RecordingWorkerTransitionObserverV1>,
        ) -> Result<PublicWitnessDispatcher<DeadlineServiceProxyV1>, PublicWitnessDispatchErrorV1>
        {
            let proxy = DeadlineServiceProxyV1 {
                service: self.service.clone(),
            };
            let mut dispatcher = PublicWitnessDispatcher::new(
                self.public_config.clone(),
                self.witness.clone(),
                proxy,
            )
            .await?;
            dispatcher.observe_worker_transitions_for_test(observer);
            self.reset_facts();
            Ok(dispatcher)
        }

        fn reset_facts(&self) {
            self.facts.reads.store(0, Ordering::SeqCst);
            self.facts.cas_attempted.store(0, Ordering::SeqCst);
            self.facts.cas_applied.store(0, Ordering::SeqCst);
            self.facts.inspect_ready.store(0, Ordering::SeqCst);
            self.facts
                .records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
            self.mode.store(0, Ordering::SeqCst);
        }

        fn signed_read_request(&self) -> ProtocolResult<WitnessStoreProxyRequestV1> {
            let mut request = WitnessStoreProxyRequestV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation: WitnessStoreProxyOperationV1::ReadEntry,
                request_nonce: "b".repeat(64),
                admission_digest: self.admission.admission_digest.clone(),
                bucket_epoch_digest: self.ready.bucket_epoch.digest()?,
                bucket_anchor_digest: self.ready.bucket_anchor.digest()?,
                body: WitnessStoreProxyRequestBodyV1::ReadEntry {
                    stream_id: self.admission.stream_id.clone(),
                },
                request_digest: String::new(),
                witness_key_id: self.witness.key_id().to_string(),
                signature: self.witness.sign(&[]),
            };
            request.request_digest = request.computed_digest()?;
            request.signature = self.witness.sign(&request.signing_bytes()?);
            request.validate_structure()?;
            request.validate_semantics()?;
            request.validate_signature()?;
            Ok(request)
        }

        fn fence_request(&self) -> ProtocolResult<WitnessServiceRequestV1> {
            let fence = self.challenge.state_fence.request.clone();
            finalized_deadline_request(
                WitnessServiceOperationV1::Fence,
                self.admission.admission_digest.clone(),
                WitnessServiceRequestBodyV1::Fence {
                    request: Box::new(fence),
                },
            )
        }

        fn establish_request(&self) -> ProtocolResult<WitnessServiceRequestV1> {
            finalized_deadline_request(
                WitnessServiceOperationV1::Establish,
                self.admission.admission_digest.clone(),
                WitnessServiceRequestBodyV1::Establish {
                    challenge: Box::new(self.challenge.clone()),
                    expected_head: None,
                },
            )
        }

        fn read_head_request(
            ephemeral: &Ed25519Signer,
            admission: &WitnessAdmissionRecordV1,
            session: WitnessSessionV1,
            target_txid: String,
        ) -> ProtocolResult<WitnessServiceRequestV1> {
            let mut request = WitnessServiceRequestV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation: WitnessServiceOperationV1::ReadHead,
                request_nonce: "d".repeat(64),
                admission_digest: admission.admission_digest.clone(),
                body: WitnessServiceRequestBodyV1::ReadHead {
                    session: Box::new(session.clone()),
                    target_txid: target_txid.clone(),
                },
                request_digest: String::new(),
                authorization: None,
            };
            request.request_digest = request.computed_digest()?;
            #[derive(Serialize)]
            struct AuthorizationPreimageV1<'a> {
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
            let preimage = AuthorizationPreimageV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation: WitnessOperationV1::ReadHead,
                stream_id: &session.stream_id,
                binding_digest: &session.binding_digest,
                txid: &target_txid,
                request_digest: &request.request_digest,
                session_generation: session.session_generation,
                session_commitment: &session.session_commitment,
                ephemeral_key_id: &session.ephemeral_key_id,
            };
            let authorization_bytes = canonical_wire_bytes(&preimage)?;
            request.authorization = Some(WitnessSessionAuthorizationV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation: WitnessOperationV1::ReadHead,
                stream_id: session.stream_id.clone(),
                binding_digest: session.binding_digest.clone(),
                txid: target_txid.clone(),
                request_digest: request.request_digest.clone(),
                session_generation: session.session_generation,
                session_commitment: session.session_commitment.clone(),
                ephemeral_key_id: session.ephemeral_key_id.clone(),
                signature: ephemeral.sign(&authorization_bytes),
            });
            request.validate()?;
            Ok(request)
        }

        fn candidate(&self) -> ProtocolResult<CandidateV1> {
            let before = PublicationMappingV1 {
                state_canonical: self.binding.publication_roles.state_canonical,
                state_staging: self.binding.publication_roles.state_staging,
                checkpoint_canonical: self.binding.publication_roles.checkpoint_canonical,
                checkpoint_staging: self.binding.publication_roles.checkpoint_staging,
                journal_primary: self.binding.publication_roles.journal_primary,
                journal_secondary: self.binding.publication_roles.journal_secondary,
            };
            let state_payload = br#"{"state":1}"#.to_vec();
            let checkpoint_payload = br#"{"checkpoint":1}"#.to_vec();
            let state_digest = sha256_hex(&state_payload);
            let checkpoint_digest = sha256_hex(&checkpoint_payload);
            let genesis = GenesisPredecessorV1::for_binding(&self.binding);
            CandidatePreimageV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                stream_id: self.binding.stream_id.clone(),
                predecessor_head: None,
                predecessor_head_digest: genesis.digest()?,
                predecessor_data_head_digest: genesis.data_head_digest()?,
                state_payload: state_payload.clone(),
                state_byte_len: state_payload.len() as u64,
                state_digest: state_digest.clone(),
                state_attestation: self.sign_payload(
                    STATE_PAYLOAD_DOMAIN_V1,
                    state_payload,
                    state_digest,
                )?,
                checkpoint_payload: checkpoint_payload.clone(),
                checkpoint_byte_len: checkpoint_payload.len() as u64,
                checkpoint_digest: checkpoint_digest.clone(),
                checkpoint_attestation: self.sign_payload(
                    CHECKPOINT_PAYLOAD_DOMAIN_V1,
                    checkpoint_payload,
                    checkpoint_digest,
                )?,
                publication_binding: self.binding.clone(),
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

        fn sign_payload(
            &self,
            domain: &str,
            payload: Vec<u8>,
            digest: String,
        ) -> ProtocolResult<swarm_crypto::DetachedSignature> {
            let preimage = SignedPayloadPreimageV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                domain: domain.to_string(),
                stream_id: self.binding.stream_id.clone(),
                binding_generation: self.binding.generation.clone(),
                binding_digest: self.binding.binding_digest.clone(),
                authority_pair: self.binding.authority_pair,
                byte_len: payload.len() as u64,
                digest,
                payload,
            };
            Ok(self.governance.sign(&preimage.canonical_bytes()?))
        }

        fn mutation_request(
            ephemeral: &Ed25519Signer,
            admission: &WitnessAdmissionRecordV1,
            operation: WitnessServiceOperationV1,
            witness_operation: WitnessOperationV1,
            session: &WitnessSessionV1,
            txid: &str,
            body: WitnessServiceRequestBodyV1,
        ) -> ProtocolResult<WitnessServiceRequestV1> {
            let mut request = WitnessServiceRequestV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation,
                request_nonce: "e".repeat(64),
                admission_digest: admission.admission_digest.clone(),
                body,
                request_digest: "0".repeat(64),
                authorization: None,
            };
            request.request_digest = request.computed_digest()?;
            #[derive(Serialize)]
            struct AuthorizationPreimageV1<'a> {
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
            let preimage = AuthorizationPreimageV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation: witness_operation,
                stream_id: &session.stream_id,
                binding_digest: &session.binding_digest,
                txid,
                request_digest: &request.request_digest,
                session_generation: session.session_generation,
                session_commitment: &session.session_commitment,
                ephemeral_key_id: &session.ephemeral_key_id,
            };
            request.authorization = Some(WitnessSessionAuthorizationV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                operation: witness_operation,
                stream_id: session.stream_id.clone(),
                binding_digest: session.binding_digest.clone(),
                txid: txid.to_string(),
                request_digest: request.request_digest.clone(),
                session_generation: session.session_generation,
                session_commitment: session.session_commitment.clone(),
                ephemeral_key_id: session.ephemeral_key_id.clone(),
                signature: ephemeral.sign(&canonical_wire_bytes(&preimage)?),
            });
            request.validate()?;
            Ok(request)
        }
    }

    fn fixture_stage<T>(field: &str, result: ProtocolResult<T>) -> ProtocolResult<T> {
        result.map_err(|error| ProtocolError::InvalidField {
            field: format!("deadline_fixture_{field}"),
            reason: error.to_string(),
        })
    }

    fn finalized_deadline_request(
        operation: WitnessServiceOperationV1,
        admission_digest: String,
        body: WitnessServiceRequestBodyV1,
    ) -> ProtocolResult<WitnessServiceRequestV1> {
        let mut request = WitnessServiceRequestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation,
            request_nonce: "a".repeat(64),
            admission_digest,
            body,
            request_digest: "0".repeat(64),
            authorization: None,
        };
        request.request_digest = request.computed_digest()?;
        request.validate()?;
        Ok(request)
    }

    fn deadline_binding(
        governance: &Ed25519Signer,
        witness: &Ed25519Signer,
    ) -> ProtocolResult<PublicationBindingV1> {
        let roles = PublicationRoleIdentitiesV1 {
            state_canonical: deadline_artifact(1),
            state_staging: deadline_artifact(2),
            checkpoint_canonical: deadline_artifact(3),
            checkpoint_staging: deadline_artifact(4),
            journal_primary: deadline_artifact(5),
            journal_secondary: deadline_artifact(6),
        };
        let mut binding = PublicationBindingV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: "tom-primary".to_string(),
            generation: "9".repeat(64),
            parent_directory: deadline_artifact(7),
            pool_directory: deadline_artifact(8),
            pool_lock: deadline_artifact(9),
            binding_file: deadline_artifact(10),
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
            publication_roles: roles,
            cleanup_slot_count: FIXED_CLEANUP_SLOT_COUNT as u32,
            cleanup_slot_names: (0..FIXED_CLEANUP_SLOT_COUNT)
                .map(|index| format!("slot-{index:02}"))
                .collect(),
            cleanup_slot_identities: (11..(11 + FIXED_CLEANUP_SLOT_COUNT as u64))
                .map(deadline_artifact)
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

    const fn deadline_artifact(inode: u64) -> ArtifactIdentityV1 {
        ArtifactIdentityV1 { device: 2, inode }
    }

    fn deadline_admission(
        binding: &PublicationBindingV1,
    ) -> ProtocolResult<WitnessAdmissionRecordV1> {
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
            max_retained_bytes: 1_000_000,
            initial_epoch: 0,
            initial_sequence: 0,
            initial_intent_counter: 1,
            admission_digest: "0".repeat(64),
        };
        admission.admission_digest = admission.computed_digest()?;
        admission.validate()?;
        Ok(admission)
    }

    fn deadline_ready(
        witness: &Ed25519Signer,
        admission_set: WitnessAdmissionSetV1,
        mut envelope: WitnessStoreEnvelopeV1,
    ) -> ProtocolResult<(WitnessStoreReadyResultV1, WitnessStoreEnvelopeV1)> {
        let max_value_bytes = 1_000_000_u64;
        let max_manifest_bytes = 1_000_000_u64;
        let required_bucket_bytes = 2 * (max_manifest_bytes + 65_536)
            + admission_set.entries.len() as u64 * 2 * (max_value_bytes + 65_536);
        let configuration = WitnessBucketConfigurationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            nats_server_version: "2.11.17".to_string(),
            nats_server_image_index_digest:
                "sha256:e4bf19f15fd3218814a4e3c9e0064e1334bd8aa20d5984b9f1a0afd084f8cc00"
                    .to_string(),
            stream_name: "KV_phase285_service".to_string(),
            description: "Phase 285 external governance witness".to_string(),
            subjects: vec!["$KV.phase285_service.>".to_string()],
            retention: WitnessRetentionPolicyV1::Limits,
            discard: WitnessDiscardPolicyV1::New,
            discard_new_per_subject: false,
            storage: WitnessStorageTypeV1::File,
            max_messages: -1,
            max_bytes: i64::try_from(required_bucket_bytes)
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
        };
        fixture_stage("configuration", configuration.validate())?;
        let configuration_digest = configuration.digest()?;
        let epoch = WitnessBucketEpochV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            bucket_generation: "c".repeat(64),
            nats_account: "witness-store".to_string(),
            stream_name: configuration.stream_name.clone(),
            bucket_configuration_digest: configuration_digest.clone(),
            admission_set_digest: admission_set.admission_set_digest.clone(),
            witness_identity: envelope.witness_identity.clone(),
            witness_key_id: envelope.witness_key_id.clone(),
        };
        envelope.bucket_epoch_digest = epoch.digest()?;
        envelope.stream_initialization_digest = WitnessStreamInitializationV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            bucket_epoch_digest: envelope.bucket_epoch_digest.clone(),
            admission_digest: envelope.admission_digest.clone(),
            stream_id: envelope.stream_id.clone(),
            witness_identity: envelope.witness_identity.clone(),
            witness_key_id: envelope.witness_key_id.clone(),
        }
        .digest()?;
        envelope.signature = witness.sign(&envelope.signing_bytes()?);
        fixture_stage("ready_envelope", envelope.validate())?;
        let stream_key = witness_stream_key(&envelope.stream_id)?;
        let mut initialized_streams = BTreeMap::new();
        initialized_streams.insert(
            stream_key.clone(),
            WitnessStreamInitializationRecordV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                stream_initialization_digest: envelope.stream_initialization_digest.clone(),
                empty_envelope_digest: envelope.signed_envelope_digest()?,
            },
        );
        let mut manifest = WitnessBucketManifestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            bucket_epoch_digest: envelope.bucket_epoch_digest.clone(),
            bucket_configuration_digest: configuration_digest,
            admission_set_digest: admission_set.admission_set_digest.clone(),
            stream_keys: vec![stream_key],
            initialized_streams,
            phase: WitnessBucketManifestPhaseV1::Ready,
            witness_identity: envelope.witness_identity.clone(),
            witness_key_id: envelope.witness_key_id.clone(),
            signature: witness.sign(&[]),
        };
        manifest.signature = witness.sign(&manifest.signing_bytes()?);
        fixture_stage("manifest", manifest.validate())?;
        let mut anchor = WitnessBucketAnchorV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            epoch: epoch.clone(),
            nats_stream_created_at: "2026-08-25T00:00:00.000000000Z".to_string(),
            raw_stream_configuration_digest: sha256_hex(b"phase285-a1-raw-configuration"),
            ready_manifest_digest: manifest.digest()?,
            witness_key_id: witness.key_id().to_string(),
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
            WitnessStoreDeploymentInputsV1 {
                schema_version: PROTOCOL_SCHEMA_VERSION,
                max_manifest_bytes,
                maximum_admitted_streams: 1,
                configured_replica_count: 1,
            },
        )
        .map_err(|error| ProtocolError::InvalidField {
            field: "deadline_fixture_ready_result".to_string(),
            reason: error.to_string(),
        })?;
        Ok((ready, envelope))
    }

    #[allow(clippy::too_many_arguments)]
    fn deadline_challenge(
        governance: &Ed25519Signer,
        witness: &Ed25519Signer,
        ephemeral: &Ed25519Signer,
        binding: &PublicationBindingV1,
        admission: &WitnessAdmissionRecordV1,
        envelope: &WitnessStoreEnvelopeV1,
        anchor_digest: &str,
        ready_manifest_digest: &str,
    ) -> ProtocolResult<RecoveryChallengeV1> {
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
            admission_digest: admission.admission_digest.clone(),
            bucket_epoch_digest: envelope.bucket_epoch_digest.clone(),
            bucket_anchor_digest: anchor_digest.to_string(),
            ready_manifest_digest: ready_manifest_digest.to_string(),
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
        let mut challenge = RecoveryChallengeV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            stream_id: binding.stream_id.clone(),
            authority_pair: binding.authority_pair,
            binding_generation: binding.generation.clone(),
            binding_digest: binding.binding_digest.clone(),
            signer_key_id: binding.signer_key_id.clone(),
            witness_key_id: binding.witness_key_id.clone(),
            witness_identity: binding.witness_identity.clone(),
            state_fence: fence,
            ephemeral_key_id: ephemeral.key_id().to_string(),
            nonce: "7".repeat(64),
            session_commitment: "8".repeat(64),
            signature: governance.sign(&[]),
        };
        challenge.signature = governance.sign(&challenge.signing_bytes()?);
        challenge.validate()?;
        Ok(challenge)
    }

    fn deadline_store_config(
        witness: &Ed25519Signer,
        ready: &WitnessStoreReadyResultV1,
    ) -> ProtocolResult<StoreProxyServiceConfigV1> {
        Ok(StoreProxyServiceConfigV1 {
            nats_url: std::env::var("SWARM_NATS_STORE_TLS_URL")
                .unwrap_or_else(|_| "tls://nats.phase285.test:4222".to_string()),
            nats_credentials_path: std::env::var("SWARM_NATS_STORE_CREDENTIAL_PATH")
                .unwrap_or_else(|_| "/run/phase285/store.credentials.json".to_string()),
            credential_invocation_token: std::env::var("SWARM_NATS_TLS_CREDENTIAL_TOKEN")
                .unwrap_or_else(|_| "b".repeat(64)),
            stream_name: ready.bucket_configuration.stream_name.clone(),
            tls_ca_path: std::env::var("SWARM_NATS_TLS_CA_PATH")
                .unwrap_or_else(|_| "/run/phase285/ca.pem".to_string()),
            tls_server_name: std::env::var("SWARM_NATS_TLS_SERVER_NAME")
                .unwrap_or_else(|_| "nats.phase285.test".to_string()),
            pinned_witness_public_key_hex: witness.public_key_hex().to_string(),
            witness_key_id: witness.key_id().to_string(),
            bucket_epoch_digest: ready.bucket_epoch.digest()?,
            bucket_anchor_digest: ready.bucket_anchor.digest()?,
            admission_set_digest: ready.admission_set.admission_set_digest.clone(),
            max_request_bytes: MAX_PROTOCOL_RECORD_BYTES,
            max_response_bytes: MAX_PROTOCOL_RECORD_BYTES,
            ingress_queue_capacity: 1,
            max_in_flight: 1,
            subscription_capacity: 8,
            client_capacity: 8,
            read_buffer_capacity: 4_096,
            request_deadline_millis: 1_000,
        })
    }

    async fn run_private_queue_expired(
        fixture: &AuthenticatedDeadlineFixtureV1,
        observer: &RecordingWorkerTransitionObserverV1,
        queued_millis: u64,
    ) -> ProtocolResult<()> {
        let (sender, receiver) = mpsc::channel(1);
        let request = fixture.signed_read_request()?;
        let payload = canonical_wire_bytes(&request)?;
        let (receipt_sender, mut receipt_receiver) = mpsc::channel(1);
        let admission_observer = RecordingSubscriberAdmissionObserverV1 {
            sender: receipt_sender,
        };
        let message = async_nats::Message {
            subject: store_proxy_subjects()[1].into(),
            reply: Some("_INBOX.phase285-private-queue-deadline".into()),
            payload: payload.clone().into(),
            headers: None,
            status: None,
            description: None,
            length: payload.len(),
        };
        assert!(
            matches!(
                admit_private_subscription_message(
                    store_proxy_subjects()[1],
                    message,
                    &sender,
                    &admission_observer,
                ),
                Some(Ok(()))
            ),
            "private raw subscription message was not admitted"
        );
        assert!(
            receipt_receiver.try_recv().is_ok(),
            "private admission receipt absent"
        );
        advance(Duration::from_millis(queued_millis)).await;
        let receiver = TokioMutex::new(receiver);
        let publisher = RecordingPublisherV1 {
            delay_millis: 0,
            publications: Arc::new(AtomicUsize::new(0)),
        };
        assert!(
            receive_and_run_private_worker_message(
                &receiver,
                fixture.service.as_ref(),
                observer,
                &publisher,
            )
            .await,
            "private typed ingress was not received"
        );
        Ok(())
    }

    async fn run_public_queue_expired(
        fixture: &AuthenticatedDeadlineFixtureV1,
        dispatcher: &PublicWitnessDispatcher<DeadlineServiceProxyV1>,
        observer: &RecordingWorkerTransitionObserverV1,
        queued_millis: u64,
    ) -> ProtocolResult<()> {
        let (sender, receiver) = mpsc::channel(1);
        let request = fixture.fence_request()?;
        let subject = PublicWitnessServiceConfigV1::subject_for(request.operation);
        let payload = request.canonical_bytes()?;
        let (receipt_sender, mut receipt_receiver) = mpsc::channel(1);
        let admission_observer = RecordingSubscriberAdmissionObserverV1 {
            sender: receipt_sender,
        };
        let message = async_nats::Message {
            subject: subject.into(),
            reply: Some("_INBOX.phase285-public-queue-deadline".into()),
            payload: payload.clone().into(),
            headers: None,
            status: None,
            description: None,
            length: payload.len(),
        };
        assert!(
            admit_public_subscription_message(subject, message, &sender, &admission_observer,),
            "public raw subscription message was not admitted"
        );
        assert!(
            receipt_receiver.try_recv().is_ok(),
            "public admission receipt absent"
        );
        advance(Duration::from_millis(queued_millis)).await;
        let receiver = TokioMutex::new(receiver);
        let publisher = RecordingPublisherV1 {
            delay_millis: 0,
            publications: Arc::new(AtomicUsize::new(0)),
        };
        assert!(
            receive_and_run_public_worker_message(&receiver, dispatcher, observer, &publisher,)
                .await,
            "public typed ingress was not received"
        );
        Ok(())
    }

    async fn run_private_read(
        fixture: &AuthenticatedDeadlineFixtureV1,
        observer: &RecordingWorkerTransitionObserverV1,
        deadline: ReceiptDeadlineV1,
        publisher: &RecordingPublisherV1,
    ) -> ProtocolResult<()> {
        let request = fixture.signed_read_request()?;
        run_private_worker_message(
            fixture.service.as_ref(),
            PrivateIngressMessage {
                subject: store_proxy_subjects()[1].to_string(),
                payload: canonical_wire_bytes(&request)?,
                reply: "_INBOX.phase285-private-deadline".into(),
                receipt_deadline: deadline,
            },
            observer,
            publisher,
        )
        .await;
        Ok(())
    }

    async fn run_public_request(
        dispatcher: &PublicWitnessDispatcher<DeadlineServiceProxyV1>,
        request: &WitnessServiceRequestV1,
        observer: &RecordingWorkerTransitionObserverV1,
        deadline: ReceiptDeadlineV1,
        publisher: &RecordingPublisherV1,
    ) -> ProtocolResult<()> {
        run_public_worker_message(
            dispatcher,
            PublicIngressMessage {
                subject: PublicWitnessServiceConfigV1::subject_for(request.operation).to_string(),
                payload: request.canonical_bytes()?,
                reply: "_INBOX.phase285-public-deadline".into(),
                receipt_deadline: deadline,
            },
            observer,
            publisher,
        )
        .await;
        Ok(())
    }

    fn ledger_context() -> Option<(PathBuf, String, String, String)> {
        let required = std::env::var_os(LEDGER_REQUIRED_ENV).is_some();
        let path = std::env::var_os(LEDGER_PATH_ENV).map(PathBuf::from);
        let tree = std::env::var(TREE_ENV).ok();
        let token = std::env::var(TOKEN_ENV).ok();
        let case = std::env::var(CASE_ENV).ok();
        if path.is_none() && tree.is_none() && token.is_none() && case.is_none() && !required {
            return None;
        }
        let Some(path) = path else {
            panic!("deadline ledger path absent");
        };
        assert!(path.is_absolute(), "deadline ledger path must be absolute");
        let Some(tree) = tree else {
            panic!("deadline tree absent");
        };
        let Some(token) = token else {
            panic!("deadline invocation token absent");
        };
        let Some(case) = case else {
            panic!("deadline case absent");
        };
        assert!(
            [tree.as_str(), token.as_str(), case.as_str()]
                .into_iter()
                .all(|value| !value.is_empty() && value.len() <= 256),
            "deadline ledger identity is not closed and bounded"
        );
        Some((path, tree, token, case))
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HarnessCredentialV1 {
        schema_version: u32,
        role: String,
        username: String,
        password: String,
        invocation_token: String,
    }

    async fn connect_deadline_role(
        path_variable: &str,
        expected_role: &str,
    ) -> ProtocolResult<async_nats::Client> {
        let path =
            std::env::var(path_variable).map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        let raw = std::fs::read(path).map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        let credential: HarnessCredentialV1 =
            serde_json::from_slice(&raw).map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        let token = std::env::var("SWARM_NATS_TLS_CREDENTIAL_TOKEN")
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        if credential.schema_version != PROTOCOL_SCHEMA_VERSION
            || credential.role != expected_role
            || credential.invocation_token != token
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let url = std::env::var("SWARM_NATS_STORE_TLS_URL")
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        let ca = std::env::var("SWARM_NATS_TLS_CA_PATH")
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        async_nats::ConnectOptions::with_user_and_password(credential.username, credential.password)
            .require_tls(true)
            .add_root_certificates(ca.into())
            .connect(url)
            .await
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)
    }

    async fn initialize_deadline_stream() -> ProtocolResult<()> {
        let client = connect_deadline_role("SWARM_NATS_INIT_CREDENTIAL_PATH", "init").await?;
        let context = async_nats::jetstream::new(client);
        match context.get_stream("KV_phase285_service").await {
            Ok(_) => Ok(()),
            Err(_) => context
                .create_stream(async_nats::jetstream::stream::Config {
                    name: "KV_phase285_service".to_string(),
                    subjects: vec!["$KV.phase285_service.>".to_string()],
                    max_messages_per_subject: 1,
                    ..Default::default()
                })
                .await
                .map(|_| ())
                .map_err(|_| ProtocolError::WitnessOutcomeMismatch),
        }
    }

    async fn publish_deadline_request(
        client: &async_nats::Client,
        subject: &str,
        payload: Vec<u8>,
    ) -> ProtocolResult<(async_nats::Subscriber, async_nats::Subject)> {
        let reply = client.new_inbox();
        let subscriber = client
            .subscribe(reply.clone())
            .await
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        client
            .publish_with_reply(subject.to_string(), reply.clone(), payload.into())
            .await
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        client
            .flush()
            .await
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        Ok((subscriber, reply.into()))
    }

    #[derive(Serialize)]
    struct SubscriberCallsiteReceiptV1<'a> {
        schema_version: u8,
        tree: &'a str,
        invocation_token: &'a str,
        case: &'a str,
        private: &'a SubscriberAdmissionReceiptV1,
        public: &'a SubscriberAdmissionReceiptV1,
        private_backend_calls: usize,
        public_backend_calls: usize,
        private_second_publications: usize,
        public_second_publications: usize,
    }

    fn write_subscriber_callsite_receipt(
        private: &SubscriberAdmissionReceiptV1,
        public: &SubscriberAdmissionReceiptV1,
        private_backend_calls: usize,
        public_backend_calls: usize,
    ) {
        let Some(path) = std::env::var_os("PHASE285_DEADLINE_CALLSITE_RECEIPT") else {
            return;
        };
        let tree = must(std::env::var(TREE_ENV), "deadline callsite tree absent");
        let token = must(std::env::var(TOKEN_ENV), "deadline callsite token absent");
        let case = must(std::env::var(CASE_ENV), "deadline callsite case absent");
        let row = SubscriberCallsiteReceiptV1 {
            schema_version: 1,
            tree: &tree,
            invocation_token: &token,
            case: &case,
            private,
            public,
            private_backend_calls,
            public_backend_calls,
            private_second_publications: 0,
            public_second_publications: 0,
        };
        let bytes = must(canonical_wire_bytes(&row), "subscriber callsite receipt");
        let mut file = must(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(PathBuf::from(path)),
            "deadline callsite receipt reuse",
        );
        must(file.write_all(&bytes), "deadline callsite receipt write");
        must(file.write_all(b"\n"), "deadline callsite receipt frame");
        must(file.sync_all(), "deadline callsite receipt sync");
    }

    fn write_deadline_budget_receipt(topology: DeadlineTopologyV1) {
        let Some(path) = std::env::var_os("PHASE285_DEADLINE_BUDGET_RECEIPT") else {
            return;
        };
        let tree = must(std::env::var(TREE_ENV), "deadline budget tree absent");
        let token = must(std::env::var(TOKEN_ENV), "deadline budget token absent");
        let case = must(std::env::var(CASE_ENV), "deadline budget case absent");
        let row = DeadlineBudgetReceiptV1 {
            schema_version: 1,
            tree: &tree,
            invocation_token: &token,
            case: &case,
            inner_id: "deadline_budget_constructor_exact",
            status: "passed",
            live_nats_grants_proved: false,
            topology,
        };
        let bytes = must(canonical_wire_bytes(&row), "deadline budget receipt");
        let mut file = must(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(PathBuf::from(path)),
            "deadline budget receipt reuse",
        );
        must(file.write_all(&bytes), "deadline budget receipt write");
        must(file.write_all(b"\n"), "deadline budget receipt frame");
        must(file.sync_all(), "deadline budget receipt sync");
    }

    #[test]
    fn subscriber_callsite_is_receipt_anchored_and_mutation_sensitive() {
        let thread = must(
            std::thread::Builder::new()
                .name("phase285-a1-subscriber-callsite".to_string())
                .stack_size(64 * 1024 * 1024)
                .spawn(|| {
                    let runtime = must(
                        tokio::runtime::Builder::new_multi_thread()
                            .worker_threads(4)
                            .thread_stack_size(64 * 1024 * 1024)
                            .enable_all()
                            .build(),
                        "subscriber runtime",
                    );
                    runtime.block_on(Box::pin(run_subscriber_callsite()));
                }),
            "subscriber thread",
        );
        must(thread.join(), "subscriber thread panicked");
    }

    async fn run_subscriber_callsite() {
        must(
            initialize_deadline_stream().await,
            "deadline subscriber stream initialization",
        );

        let worker_observer = Arc::new(RecordingWorkerTransitionObserverV1::default());
        let mut private_fixture = must(
            AuthenticatedDeadlineFixtureV1::new(worker_observer.clone()),
            "private fixture",
        );
        let (private_receipt_tx, mut private_receipt_rx) = mpsc::channel(1);
        must_some(
            Arc::get_mut(&mut private_fixture.service),
            "private service must be uniquely owned",
        )
        .observe_subscriber_admissions_for_test(Arc::new(
            RecordingSubscriberAdmissionObserverV1 {
                sender: private_receipt_tx,
            },
        ));
        let private_config = must(
            deadline_store_config(&private_fixture.witness, &private_fixture.ready),
            "private config",
        );
        let private_connection = must(
            StoreRoleConnectionV1::connect(&private_config, &private_fixture.ready).await,
            "private role connection",
        );
        let private_request = must(private_fixture.signed_read_request(), "private request");
        let private_payload = must(canonical_wire_bytes(&private_request), "private payload");
        let private_service = must_some(
            Arc::try_unwrap(private_fixture.service).ok(),
            "private service ownership",
        );
        let _private_runner = must(
            StoreProxyServiceRunner::start(private_connection, private_service).await,
            "shipping private start",
        );
        let witness_client = must(
            connect_deadline_role("SWARM_NATS_WITNESS_CREDENTIAL_PATH", "witness").await,
            "witness client",
        );
        private_fixture
            .block_next_read
            .store(true, Ordering::SeqCst);
        let (mut private_first_response, _) = must(
            publish_deadline_request(
                &witness_client,
                store_proxy_subjects()[1],
                private_payload.clone(),
            )
            .await,
            "private request one",
        );
        must(
            tokio::time::timeout(
                Duration::from_secs(2),
                private_fixture.read_entered.notified(),
            )
            .await,
            "private request one did not enter store",
        );
        let _private_first_receipt =
            must_some(private_receipt_rx.recv().await, "private receipt one");
        let (mut private_second_response, _) = must(
            publish_deadline_request(&witness_client, store_proxy_subjects()[1], private_payload)
                .await,
            "private request two",
        );
        let private_second_receipt = must_some(
            must(
                tokio::time::timeout(Duration::from_secs(2), private_receipt_rx.recv()).await,
                "private receipt two timeout",
            ),
            "private receipt two absent",
        );
        tokio::time::sleep(Duration::from_millis(STORE_HANDLER_DEADLINE_MILLIS + 500)).await;
        {
            let (released, condition) = private_fixture.read_release.as_ref();
            *released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            condition.notify_all();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(500), private_first_response.next())
                .await
                .is_err(),
            "deadline_r24_private_late_first_publication"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(150), private_second_response.next())
                .await
                .is_err(),
            "deadline_r24_private_second_publication"
        );
        assert_eq!(
            private_fixture.facts.reads.load(Ordering::SeqCst),
            1,
            "deadline_r24_private_start_delegation_bypassed"
        );

        let public_fixture = must(
            AuthenticatedDeadlineFixtureV1::new(worker_observer),
            "public fixture",
        );
        let (public_receipt_tx, mut public_receipt_rx) = mpsc::channel(1);
        let mut dispatcher = must(
            public_fixture
                .dispatcher(Arc::new(RecordingWorkerTransitionObserverV1::default()))
                .await,
            "public dispatcher",
        );
        dispatcher.observe_subscriber_admissions_for_test(Arc::new(
            RecordingSubscriberAdmissionObserverV1 {
                sender: public_receipt_tx,
            },
        ));
        public_fixture.block_next_read.store(true, Ordering::SeqCst);
        let witness_public_client = must(
            connect_deadline_role("SWARM_NATS_WITNESS_CREDENTIAL_PATH", "witness").await,
            "public witness client",
        );
        let _public_runner = must(
            PublicWitnessServiceRunner::start(witness_public_client, dispatcher).await,
            "shipping public start",
        );
        let runtime_client = must(
            connect_deadline_role("SWARM_NATS_RUNTIME_CREDENTIAL_PATH", "runtime").await,
            "runtime client",
        );
        let public_request = must(public_fixture.fence_request(), "public request");
        let public_payload = must(public_request.canonical_bytes(), "public payload");
        let public_subject = PublicWitnessServiceConfigV1::subject_for(public_request.operation);
        let (mut public_first_response, _) = must(
            publish_deadline_request(&runtime_client, public_subject, public_payload.clone()).await,
            "public request one",
        );
        let _public_first_receipt = must_some(
            must(
                tokio::time::timeout(Duration::from_secs(2), public_receipt_rx.recv()).await,
                "public receipt one timeout",
            ),
            "public receipt one absent",
        );
        must(
            tokio::time::timeout(
                Duration::from_secs(2),
                public_fixture.read_entered.notified(),
            )
            .await,
            "public request one did not enter proxy",
        );
        let (mut public_second_response, _) = must(
            publish_deadline_request(&runtime_client, public_subject, public_payload).await,
            "public request two",
        );
        let public_second_receipt = must_some(
            must(
                tokio::time::timeout(Duration::from_secs(2), public_receipt_rx.recv()).await,
                "public receipt two timeout",
            ),
            "public receipt two absent",
        );
        tokio::time::sleep(Duration::from_millis(PUBLIC_HANDLER_DEADLINE_MILLIS + 500)).await;
        {
            let (released, condition) = public_fixture.read_release.as_ref();
            *released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            condition.notify_all();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(500), public_first_response.next())
                .await
                .is_err(),
            "deadline_r24_public_late_first_publication"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(150), public_second_response.next())
                .await
                .is_err(),
            "deadline_r24_public_second_publication"
        );
        assert_eq!(
            public_fixture.facts.reads.load(Ordering::SeqCst),
            1,
            "deadline_r24_public_start_delegation_bypassed"
        );

        write_subscriber_callsite_receipt(
            &private_second_receipt,
            &public_second_receipt,
            private_fixture.facts.reads.load(Ordering::SeqCst),
            public_fixture.facts.reads.load(Ordering::SeqCst),
        );
    }

    #[test]
    fn deadline_state_machine_is_receipt_anchored_and_mutation_sensitive() {
        let thread = must(
            std::thread::Builder::new()
                .name("phase285-a1-deadline-state-machine".to_string())
                .stack_size(64 * 1024 * 1024)
                .spawn(|| {
                    let runtime = must(
                        tokio::runtime::Builder::new_current_thread()
                            .enable_time()
                            .build(),
                        "deadline runtime",
                    );
                    runtime.block_on(Box::pin(run_deadline_state_machine()));
                }),
            "deadline thread",
        );
        must(thread.join(), "deadline thread panicked");
    }

    async fn run_deadline_state_machine() {
        tokio::time::pause();
        let observer = Arc::new(RecordingWorkerTransitionObserverV1::default());
        let mut rows: Vec<(&str, DeadlineEvidenceV1, Option<DeadlineTopologyV1>)> =
            Vec::with_capacity(8);

        let fixture = must(
            AuthenticatedDeadlineFixtureV1::new(observer.clone()),
            "authenticated fixture",
        );
        must(
            run_private_queue_expired(&fixture, &observer, STORE_HANDLER_DEADLINE_MILLIS).await,
            "private queue expiry",
        );
        assert_eq!(
            fixture.facts.reads.load(Ordering::SeqCst),
            0,
            "deadline_r20_private_queue_expired deadline_r20_worker_budget_substitution deadline_r20_private_queue_expired_behavior"
        );
        rows.push(("private_queue_expired", observer.reduce(), None));
        observer.clear();

        let fixture = must(
            AuthenticatedDeadlineFixtureV1::new(observer.clone()),
            "authenticated fixture",
        );
        let publisher = RecordingPublisherV1 {
            delay_millis: 0,
            publications: Arc::new(AtomicUsize::new(0)),
        };
        let gate = observer.arm(DeadlineGateV1::PrivatePostPreflight);
        let expiry = tokio::spawn(async move {
            gate.notified().await;
            advance(Duration::from_millis(STORE_HANDLER_DEADLINE_MILLIS)).await;
        });
        must(
            run_private_read(
                &fixture,
                &observer,
                ReceiptDeadlineV1::private(),
                &publisher,
            )
            .await,
            "private preflight request",
        );
        must(expiry.await, "private preflight expiry");
        assert_eq!(
            fixture.facts.reads.load(Ordering::SeqCst),
            0,
            "deadline_r20_worker_budget_substitution"
        );
        assert_eq!(
            publisher.publications.load(Ordering::SeqCst),
            0,
            "deadline_r20_worker_budget_substitution"
        );
        rows.push((
            "private_preflight_expired",
            observer.reduce_authenticated(&fixture.facts, &publisher, WorkerKindV1::Private),
            None,
        ));
        observer.clear();

        let fixture = must(
            AuthenticatedDeadlineFixtureV1::new(observer.clone()),
            "authenticated fixture",
        );
        fixture.mode.store(1, Ordering::SeqCst);
        let publisher = RecordingPublisherV1 {
            delay_millis: 0,
            publications: Arc::new(AtomicUsize::new(0)),
        };
        let gate = observer.arm(DeadlineGateV1::PrivatePostPreflight);
        let elapsed_before_store = tokio::spawn(async move {
            gate.notified().await;
            advance(Duration::from_millis(1_000)).await;
        });
        must(
            run_private_read(
                &fixture,
                &observer,
                ReceiptDeadlineV1::private(),
                &publisher,
            )
            .await,
            "private store deadline request",
        );
        must(elapsed_before_store.await, "private store elapsed budget");
        assert_eq!(fixture.facts.reads.load(Ordering::SeqCst), 1);
        assert_eq!(publisher.publications.load(Ordering::SeqCst), 0);
        rows.push((
            "private_store_crosses_deadline",
            observer.reduce_authenticated(&fixture.facts, &publisher, WorkerKindV1::Private),
            None,
        ));
        observer.clear();

        let fixture = must(
            AuthenticatedDeadlineFixtureV1::new(observer.clone()),
            "authenticated fixture",
        );
        let publisher = RecordingPublisherV1 {
            delay_millis: 0,
            publications: Arc::new(AtomicUsize::new(0)),
        };
        let gate = observer.arm(DeadlineGateV1::PrivateStoreEnd);
        let expiry = tokio::spawn(async move {
            gate.notified().await;
            advance(Duration::from_millis(STORE_HANDLER_DEADLINE_MILLIS)).await;
        });
        must(
            run_private_read(
                &fixture,
                &observer,
                ReceiptDeadlineV1::private(),
                &publisher,
            )
            .await,
            "private enqueue deadline request",
        );
        must(expiry.await, "private enqueue expiry");
        assert_eq!(fixture.facts.reads.load(Ordering::SeqCst), 1);
        assert_eq!(publisher.publications.load(Ordering::SeqCst), 0);
        rows.push((
            "private_response_enqueue_expired",
            observer.reduce_authenticated(&fixture.facts, &publisher, WorkerKindV1::Private),
            None,
        ));
        observer.clear();

        let fixture = must(
            AuthenticatedDeadlineFixtureV1::new(observer.clone()),
            "authenticated fixture",
        );
        let dispatcher = must(
            fixture.dispatcher(observer.clone()).await,
            "authenticated dispatcher",
        );
        observer.clear();
        must(
            run_public_queue_expired(
                &fixture,
                &dispatcher,
                &observer,
                PUBLIC_HANDLER_DEADLINE_MILLIS,
            )
            .await,
            "public queue expiry",
        );
        rows.push(("public_queue_expired", observer.reduce(), None));
        observer.clear();

        let fixture = must(
            AuthenticatedDeadlineFixtureV1::new(observer.clone()),
            "authenticated fixture",
        );
        let dispatcher = must(
            fixture.dispatcher(observer.clone()).await,
            "authenticated dispatcher",
        );
        observer.clear();
        fixture.mode.store(3, Ordering::SeqCst);
        let publisher = RecordingPublisherV1 {
            delay_millis: 0,
            publications: Arc::new(AtomicUsize::new(0)),
        };
        let request = must(fixture.fence_request(), "fence request");
        must(
            run_public_request(
                &dispatcher,
                &request,
                &observer,
                ReceiptDeadlineV1::public(),
                &publisher,
            )
            .await,
            "public exchange deadline request",
        );
        assert_eq!(fixture.facts.reads.load(Ordering::SeqCst), 1);
        assert_eq!(publisher.publications.load(Ordering::SeqCst), 0);
        rows.push((
            "public_private_exchange_crosses_deadline",
            observer.reduce_authenticated(&fixture.facts, &publisher, WorkerKindV1::Public),
            None,
        ));
        observer.clear();

        let fixture = must(
            AuthenticatedDeadlineFixtureV1::new(observer.clone()),
            "authenticated fixture",
        );
        let dispatcher = must(
            fixture.dispatcher(observer.clone()).await,
            "authenticated dispatcher",
        );
        observer.clear();
        let publisher = RecordingPublisherV1 {
            delay_millis: 0,
            publications: Arc::new(AtomicUsize::new(0)),
        };
        let gate = observer.arm(DeadlineGateV1::PublicProxyEnd);
        let expiry = tokio::spawn(async move {
            gate.notified().await;
            advance(Duration::from_millis(PUBLIC_HANDLER_DEADLINE_MILLIS)).await;
        });
        let request = must(fixture.fence_request(), "fence request");
        must(
            run_public_request(
                &dispatcher,
                &request,
                &observer,
                ReceiptDeadlineV1::public(),
                &publisher,
            )
            .await,
            "public enqueue deadline request",
        );
        must(expiry.await, "public enqueue expiry");
        assert_eq!(fixture.facts.reads.load(Ordering::SeqCst), 1);
        assert_eq!(publisher.publications.load(Ordering::SeqCst), 0);
        rows.push((
            "public_response_enqueue_expired",
            observer.reduce_authenticated(&fixture.facts, &publisher, WorkerKindV1::Public),
            None,
        ));
        observer.clear();

        let fixture = must(
            AuthenticatedDeadlineFixtureV1::new(observer.clone()),
            "authenticated fixture",
        );
        let dispatcher = must(
            fixture.dispatcher(observer.clone()).await,
            "authenticated dispatcher",
        );
        observer.clear();
        fixture.mode.store(2, Ordering::SeqCst);
        let publisher = RecordingPublisherV1 {
            delay_millis: 0,
            publications: Arc::new(AtomicUsize::new(0)),
        };
        let request = must(fixture.establish_request(), "establish request");
        must(
            run_public_request(
                &dispatcher,
                &request,
                &observer,
                ReceiptDeadlineV1::public(),
                &publisher,
            )
            .await,
            "post-CAS deadline request",
        );
        assert_eq!(
            fixture.facts.reads.load(Ordering::SeqCst),
            4,
            "deadline_r20_post_cas_exact_store_trace"
        );
        assert_eq!(fixture.facts.cas_attempted.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.facts.cas_applied.load(Ordering::SeqCst), 1);
        assert_eq!(publisher.publications.load(Ordering::SeqCst), 0);
        rows.push((
            "post_cas_timeout_outcome_unknown",
            observer.reduce_authenticated(&fixture.facts, &publisher, WorkerKindV1::Public),
            None,
        ));
        observer.clear();

        let topology = DeadlineTopologyV1 {
            private_handler_millis: STORE_HANDLER_DEADLINE_MILLIS,
            private_response_grant_millis: STORE_RESPONSE_GRANT_MILLIS,
            public_handler_millis: PUBLIC_HANDLER_DEADLINE_MILLIS,
            public_response_grant_millis: PUBLIC_RESPONSE_GRANT_MILLIS,
            private_handler_reserve_millis: STORE_HANDLER_RESERVE_MILLIS,
            public_private_reserve_millis: PUBLIC_PRIVATE_RESERVE_MILLIS,
            public_handler_reserve_millis: PUBLIC_HANDLER_RESERVE_MILLIS,
            response_grant_maximum: RESPONSE_GRANT_MAXIMUM,
        };
        assert_eq!(
            (
                topology.private_handler_millis,
                topology.private_response_grant_millis,
                topology.public_handler_millis,
                topology.public_response_grant_millis,
                topology.private_handler_reserve_millis,
                topology.public_private_reserve_millis,
                topology.public_handler_reserve_millis,
                topology.response_grant_maximum,
            ),
            (2_000, 3_000, 10_000, 12_000, 1_000, 1_000, 2_000, 1)
        );
        write_deadline_budget_receipt(topology);

        let expected = [
            ("private_queue_expired", (1, 0, 0, 0, 0, 0, 0, 0, false)),
            ("private_preflight_expired", (1, 1, 0, 0, 0, 0, 0, 0, false)),
            (
                "private_store_crosses_deadline",
                (1, 1, 1, 0, 0, 0, 0, 0, false),
            ),
            (
                "private_response_enqueue_expired",
                (1, 1, 1, 0, 0, 0, 0, 0, false),
            ),
            ("public_queue_expired", (1, 0, 0, 0, 0, 0, 0, 0, false)),
            (
                "public_private_exchange_crosses_deadline",
                (1, 1, 0, 1, 0, 0, 0, 0, false),
            ),
            (
                "public_response_enqueue_expired",
                (1, 1, 0, 1, 0, 0, 0, 0, false),
            ),
            (
                "post_cas_timeout_outcome_unknown",
                (1, 1, 0, 3, 1, 1, 0, 0, true),
            ),
        ];
        let expected_traces = [
            vec![WorkerTransitionEventV1::Dequeued {
                worker: WorkerKindV1::Private,
            }],
            vec![
                WorkerTransitionEventV1::Dequeued {
                    worker: WorkerKindV1::Private,
                },
                WorkerTransitionEventV1::PostPreflight {
                    worker: WorkerKindV1::Private,
                },
            ],
            vec![
                WorkerTransitionEventV1::Dequeued {
                    worker: WorkerKindV1::Private,
                },
                WorkerTransitionEventV1::PostPreflight {
                    worker: WorkerKindV1::Private,
                },
                WorkerTransitionEventV1::ProxyStoreBegin {
                    worker: WorkerKindV1::Private,
                    operation: "read_entry",
                    cas_attempted: false,
                },
            ],
            vec![
                WorkerTransitionEventV1::Dequeued {
                    worker: WorkerKindV1::Private,
                },
                WorkerTransitionEventV1::PostPreflight {
                    worker: WorkerKindV1::Private,
                },
                WorkerTransitionEventV1::ProxyStoreBegin {
                    worker: WorkerKindV1::Private,
                    operation: "read_entry",
                    cas_attempted: false,
                },
                WorkerTransitionEventV1::ProxyStoreEnd {
                    worker: WorkerKindV1::Private,
                    operation: "read_entry",
                    succeeded: true,
                    cas_applied: false,
                },
                WorkerTransitionEventV1::ResponseEnqueueAttempt {
                    worker: WorkerKindV1::Private,
                    accepted: false,
                },
            ],
            vec![WorkerTransitionEventV1::Dequeued {
                worker: WorkerKindV1::Public,
            }],
            vec![
                WorkerTransitionEventV1::Dequeued {
                    worker: WorkerKindV1::Public,
                },
                WorkerTransitionEventV1::PostPreflight {
                    worker: WorkerKindV1::Public,
                },
                WorkerTransitionEventV1::ProxyStoreBegin {
                    worker: WorkerKindV1::Public,
                    operation: "read_entry",
                    cas_attempted: false,
                },
                WorkerTransitionEventV1::ProxyStoreEnd {
                    worker: WorkerKindV1::Public,
                    operation: "read_entry",
                    succeeded: false,
                    cas_applied: false,
                },
            ],
            vec![
                WorkerTransitionEventV1::Dequeued {
                    worker: WorkerKindV1::Public,
                },
                WorkerTransitionEventV1::PostPreflight {
                    worker: WorkerKindV1::Public,
                },
                WorkerTransitionEventV1::ProxyStoreBegin {
                    worker: WorkerKindV1::Public,
                    operation: "read_entry",
                    cas_attempted: false,
                },
                WorkerTransitionEventV1::ProxyStoreEnd {
                    worker: WorkerKindV1::Public,
                    operation: "read_entry",
                    succeeded: true,
                    cas_applied: false,
                },
                WorkerTransitionEventV1::ResponseEnqueueAttempt {
                    worker: WorkerKindV1::Public,
                    accepted: false,
                },
            ],
            vec![
                WorkerTransitionEventV1::Dequeued {
                    worker: WorkerKindV1::Public,
                },
                WorkerTransitionEventV1::PostPreflight {
                    worker: WorkerKindV1::Public,
                },
                WorkerTransitionEventV1::ProxyStoreBegin {
                    worker: WorkerKindV1::Public,
                    operation: "read_entry",
                    cas_attempted: false,
                },
                WorkerTransitionEventV1::ProxyStoreEnd {
                    worker: WorkerKindV1::Public,
                    operation: "read_entry",
                    succeeded: true,
                    cas_applied: false,
                },
                WorkerTransitionEventV1::ProxyStoreBegin {
                    worker: WorkerKindV1::Public,
                    operation: "compare_and_swap",
                    cas_attempted: true,
                },
                WorkerTransitionEventV1::CasAppliedObservation {
                    worker: WorkerKindV1::Private,
                },
                WorkerTransitionEventV1::ProxyStoreEnd {
                    worker: WorkerKindV1::Public,
                    operation: "compare_and_swap",
                    succeeded: false,
                    cas_applied: false,
                },
                WorkerTransitionEventV1::ProxyStoreBegin {
                    worker: WorkerKindV1::Public,
                    operation: "read_entry",
                    cas_attempted: false,
                },
                WorkerTransitionEventV1::ProxyStoreEnd {
                    worker: WorkerKindV1::Public,
                    operation: "read_entry",
                    succeeded: false,
                    cas_applied: false,
                },
                WorkerTransitionEventV1::OutcomeUnknown,
            ],
        ];
        assert_eq!(rows.len(), expected.len());
        let mut distinct_traces = std::collections::BTreeSet::new();
        for (index, ((inner_id, evidence, _), (expected_id, expected_counts))) in
            rows.iter().zip(expected).enumerate()
        {
            assert_eq!(*inner_id, expected_id, "deadline_r20_ordered_inventory");
            assert_eq!(
                (
                    evidence.queue_dequeues,
                    evidence.preflights,
                    evidence.store_calls,
                    evidence.private_proxy_calls,
                    evidence.cas_attempted,
                    evidence.cas_applied,
                    evidence.retries,
                    evidence.publications,
                    evidence.outcome_unknown,
                ),
                expected_counts,
                "deadline_r20_{expected_id}_behavior"
            );
            assert_eq!(
                evidence.ordered_trace, expected_traces[index],
                "deadline_r20_{expected_id}_ordered_trace"
            );
            assert!(
                !evidence.ordered_trace.is_empty(),
                "deadline_r20_{expected_id}_trace_absent"
            );
            let encoded = must(
                canonical_wire_bytes(&evidence.ordered_trace),
                "deadline trace canonicalization",
            );
            assert!(
                distinct_traces.insert(encoded),
                "deadline_r20_pairwise_trace_duplicate_{expected_id}"
            );
        }
        assert_eq!(
            distinct_traces.len(),
            8,
            "deadline_r20_distinct_trace_count"
        );

        observer.clear();
        let fixture = must(
            AuthenticatedDeadlineFixtureV1::new(observer.clone()),
            "authenticated preflight fixture",
        );
        let request = must(fixture.signed_read_request(), "preflight request");
        let raw = must(canonical_wire_bytes(&request), "preflight request bytes");
        let expired = ReceiptDeadlineV1::private();
        advance(Duration::from_millis(STORE_HANDLER_DEADLINE_MILLIS)).await;
        let result = fixture
            .service
            .handle_subject_bytes_before(
                store_proxy_subjects()[1],
                &raw,
                expired,
                observer.as_ref(),
            )
            .await;
        assert_eq!(
            result,
            Err(StoreProxyServiceErrorV1::Timeout),
            "deadline_r20_preflight_check_deleted"
        );
        assert!(
            observer.reduce().ordered_trace.is_empty(),
            "deadline_r20_preflight_check_deleted"
        );
        assert_eq!(
            fixture.facts.reads.load(Ordering::SeqCst),
            0,
            "deadline_r20_preflight_check_deleted"
        );

        if let Some((path, tree, token, case)) = ledger_context() {
            let opened = OpenOptions::new().write(true).create_new(true).open(path);
            assert!(opened.is_ok(), "deadline ledger was not fresh");
            let Ok(mut file) = opened else {
                return;
            };
            for (inner_id, evidence, _) in rows {
                let encoded = canonical_wire_bytes(&DeadlineLedgerRowV1 {
                    schema_version: 1,
                    tree: &tree,
                    invocation_token: &token,
                    case: &case,
                    inner_id,
                    status: "passed",
                    live_nats_grants_proved: false,
                    evidence,
                });
                assert!(encoded.is_ok(), "deadline ledger row was not canonical");
                let Ok(bytes) = encoded else {
                    return;
                };
                assert!(
                    file.write_all(&bytes).is_ok(),
                    "deadline ledger row write failed"
                );
                assert!(
                    file.write_all(b"\n").is_ok(),
                    "deadline ledger newline failed"
                );
            }
            assert!(
                file.sync_all().is_ok(),
                "deadline ledger durable write failed"
            );
        }

        let publisher = RecordingPublisherV1 {
            delay_millis: 0,
            publications: Arc::new(AtomicUsize::new(0)),
        };
        let transition = WorkerTransitionV1::new(
            WorkerKindV1::Private,
            ReceiptDeadlineV1::private(),
            observer.as_ref(),
        );
        assert!(
            transition
                .publish(&publisher, "_INBOX.phase285-deadline".into(), Vec::new())
                .await
        );
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct ConnectionObservationV1 {
        runner_role: &'static str,
        account: String,
        authenticated_user: String,
        server_client_id: u64,
        server_evidence_canonical_hex: String,
        server_evidence_sha256: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ServerConnectionAuthorityV1 {
        account: String,
        authenticated_user: String,
        server_client_id: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct PublisherObservationV1 {
        ordinal: usize,
        worker: WorkerKindV1,
        published: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct TimestampedPublicAdmissionV1 {
        subject: String,
        payload_sha256: String,
        reply_subject: String,
        deadline_millis: u64,
        received_at_nanos: u64,
    }

    struct RecordingPublicAdmissionObserverV1 {
        clock: Arc<ObservationClockV1>,
        records: Mutex<Vec<TimestampedPublicAdmissionV1>>,
    }

    impl SubscriberAdmissionObserverV1 for RecordingPublicAdmissionObserverV1 {
        fn accepted(&self, receipt: SubscriberAdmissionReceiptV1) {
            self.records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(TimestampedPublicAdmissionV1 {
                    subject: receipt.subject,
                    payload_sha256: receipt.payload_sha256,
                    reply_subject: receipt.reply,
                    deadline_millis: receipt.deadline_millis,
                    received_at_nanos: self.clock.now(),
                });
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct CompletePublisherObservationV1 {
        reply_subject: String,
        response_canonical_hex: String,
        response_sha256: String,
        request_received_at_nanos: u64,
        response_received_at_nanos: u64,
    }

    #[derive(Debug, Serialize)]
    struct ObservationCountsV1 {
        worker_events: usize,
        proxy_exchanges: usize,
        private_exchanges: usize,
        store_operations: usize,
        publisher_attempts: usize,
        connections: usize,
        cas_attempted: usize,
        cas_applied: usize,
    }

    #[derive(Debug, Serialize)]
    struct ObservationDigestsV1 {
        request_sha256: String,
        response_sha256: String,
        worker_events_sha256: String,
        proxy_exchanges_sha256: String,
        private_exchanges_sha256: String,
        store_operations_sha256: String,
        publisher_attempts_sha256: String,
        public_admission_sha256: String,
        publisher_sha256: String,
        connections_sha256: String,
        connection_client_ids_sha256: String,
    }

    #[derive(Debug, Serialize)]
    struct ObservationLedgerV1<'a> {
        schema_version: u8,
        tree: &'a str,
        invocation_token: &'a str,
        case: &'a str,
        status: &'static str,
        operation: WitnessServiceOperationV1,
        public_subject: &'static str,
        request_nonce: String,
        request_digest: String,
        request_canonical_hex: String,
        response_canonical_hex: String,
        selected_store_revision: u64,
        selected_store_generation: u64,
        selected_store_state_digest: String,
        selected_envelope_digest: String,
        selected_head_txid: String,
        worker_events: Vec<WorkerTransitionEventV1>,
        proxy_exchanges: Vec<ProxyObservationV1>,
        private_exchanges: Vec<ProxyObservationV1>,
        store_operations: Vec<StoreObservationV1>,
        publisher_attempts: Vec<PublisherObservationV1>,
        public_admission: TimestampedPublicAdmissionV1,
        publisher: CompletePublisherObservationV1,
        connections: Vec<ConnectionObservationV1>,
        connection_client_ids: Vec<u64>,
        counts: ObservationCountsV1,
        digests: ObservationDigestsV1,
    }

    fn observation_identity() -> Option<(PathBuf, String, String, String)> {
        let required = std::env::var_os("PHASE285_OBSERVATION_LEDGER_REQUIRED").is_some();
        let path = std::env::var("PHASE285_OBSERVATION_LEDGER").ok();
        let tree = std::env::var("PHASE285_OBSERVATION_TREE").ok();
        let token = std::env::var("PHASE285_OBSERVATION_INVOCATION_TOKEN").ok();
        let case = std::env::var("PHASE285_OBSERVATION_CASE").ok();
        if !required && path.is_none() && tree.is_none() && token.is_none() && case.is_none() {
            return None;
        }
        let path = PathBuf::from(must_some(path, "observation ledger path absent"));
        assert!(
            path.is_absolute(),
            "observation ledger path must be absolute"
        );
        let tree = must_some(tree, "observation tree absent");
        let token = must_some(token, "observation invocation token absent");
        let case = must_some(case, "observation case absent");
        assert!(
            [tree.as_str(), token.as_str(), case.as_str()]
                .into_iter()
                .all(|value| !value.is_empty() && value.len() <= 256),
            "observation identity is not closed and bounded"
        );
        Some((path, tree, token, case))
    }

    fn credential_user(path_variable: &str, role: &str) -> String {
        let path = must(
            std::env::var(path_variable),
            "observation credential path absent",
        );
        let raw = must(std::fs::read(path), "observation credential unreadable");
        let credential: HarnessCredentialV1 = must(
            serde_json::from_slice(&raw),
            "observation credential invalid",
        );
        assert_eq!(
            credential.role, role,
            "observation credential role mismatch"
        );
        credential.username
    }

    fn server_connection_observation(
        runner_role: &'static str,
        expected_account: &str,
        credential_path_variable: &str,
        credential_role: &str,
        server_client_id: u64,
    ) -> ConnectionObservationV1 {
        assert!(server_client_id > 0, "observation server client ID absent");
        let monitor_url = must(
            std::env::var("SWARM_NATS_TLS_HTTP_URL"),
            "observation monitor URL absent",
        );
        let output = must(
            std::process::Command::new("curl")
                .args([
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "2",
                    &format!("{monitor_url}/connz?auth=1&subs=0"),
                ])
                .output(),
            "observation monitor request",
        );
        assert!(
            output.status.success(),
            "observation monitor refused request"
        );
        assert!(
            !output.stdout.is_empty() && output.stdout.len() <= MAX_PROTOCOL_RECORD_BYTES,
            "observation monitor response is not bounded"
        );
        let response: serde_json::Value = must(
            serde_json::from_slice(&output.stdout),
            "observation monitor response invalid",
        );
        let connections = must_some(
            response
                .get("connections")
                .and_then(serde_json::Value::as_array),
            "observation monitor connections absent",
        );
        let record = must_some(
            connections.iter().find(|record| {
                record.get("cid").and_then(serde_json::Value::as_u64) == Some(server_client_id)
            }),
            "observation server connection absent",
        );
        let authority = ServerConnectionAuthorityV1 {
            account: must_some(
                record.get("account").and_then(serde_json::Value::as_str),
                "observation server account absent",
            )
            .to_string(),
            authenticated_user: must_some(
                record
                    .get("authorized_user")
                    .and_then(serde_json::Value::as_str),
                "observation server authenticated user absent",
            )
            .to_string(),
            server_client_id,
        };
        assert_eq!(
            authority.account, expected_account,
            "observation server account differs"
        );
        assert_eq!(
            authority.authenticated_user,
            credential_user(credential_path_variable, credential_role),
            "observation server user is not credential-bound"
        );
        let canonical = must(
            canonical_wire_bytes(&authority),
            "observation server evidence serialization",
        );
        ConnectionObservationV1 {
            runner_role,
            account: authority.account,
            authenticated_user: authority.authenticated_user,
            server_client_id,
            server_evidence_canonical_hex: hex::encode(&canonical),
            server_evidence_sha256: sha256_hex(&canonical),
        }
    }

    fn runtime_observation_config() -> RuntimeWitnessClientConfigV1 {
        RuntimeWitnessClientConfigV1 {
            nats_url: must(
                std::env::var("SWARM_NATS_STORE_TLS_URL"),
                "runtime NATS URL absent",
            ),
            nats_credentials_path: must(
                std::env::var("SWARM_NATS_RUNTIME_CREDENTIAL_PATH"),
                "runtime credential path absent",
            ),
            credential_invocation_token: must(
                std::env::var("SWARM_NATS_TLS_CREDENTIAL_TOKEN"),
                "runtime credential token absent",
            ),
            tls_ca_path: must(
                std::env::var("SWARM_NATS_TLS_CA_PATH"),
                "runtime CA path absent",
            ),
            tls_server_name: must(
                std::env::var("SWARM_NATS_TLS_SERVER_NAME"),
                "runtime TLS server name absent",
            ),
            max_request_bytes: MAX_PROTOCOL_RECORD_BYTES,
            max_response_bytes: MAX_PROTOCOL_RECORD_BYTES,
            subscription_capacity: 8,
            client_capacity: 8,
            read_buffer_capacity: 4_096,
            request_deadline_millis: PUBLIC_RESPONSE_GRANT_MILLIS,
        }
    }

    pub(super) fn run_worker_observation_test() {
        let thread = must(
            std::thread::Builder::new()
                .name("phase285-a2a-worker-observations".to_string())
                .stack_size(64 * 1024 * 1024)
                .spawn(|| {
                    let runtime = must(
                        tokio::runtime::Builder::new_multi_thread()
                            .worker_threads(4)
                            .thread_stack_size(64 * 1024 * 1024)
                            .enable_all()
                            .build(),
                        "observation runtime",
                    );
                    runtime.block_on(Box::pin(run_worker_observation_test_async()));
                }),
            "observation thread",
        );
        must(thread.join(), "observation thread panicked");
    }

    async fn run_worker_observation_test_async() -> Vec<u8> {
        must(
            initialize_deadline_stream().await,
            "observation stream initialization",
        );
        let observer = Arc::new(RecordingWorkerTransitionObserverV1::default());
        let mut fixture = must(
            AuthenticatedDeadlineFixtureV1::new(observer.clone()),
            "observation fixture",
        );
        must_some(
            Arc::get_mut(&mut fixture.service),
            "observation private service ownership",
        )
        .observe_worker_transitions_for_test(observer.clone());
        let store_config = must(
            deadline_store_config(&fixture.witness, &fixture.ready),
            "observation store config",
        );
        let store_connection = must(
            StoreRoleConnectionV1::connect(&store_config, &fixture.ready).await,
            "observation store connection",
        );
        let store_client_id = store_connection.server_client_id_for_test();
        let establish_request = must(fixture.establish_request(), "observation establish request");
        let public_config = fixture.public_config.clone();
        let witness_signer = fixture.witness.clone();
        let evidence_signer = fixture.witness.clone();
        let _ = &evidence_signer;
        let ephemeral_signer = fixture.ephemeral.clone();
        let admission = fixture.admission.clone();
        let candidate = must(fixture.candidate(), "observation candidate");
        let facts = fixture.facts.clone();
        let mode = fixture.mode.clone();
        let store_service = must_some(
            Arc::try_unwrap(fixture.service).ok(),
            "observation private service still shared",
        );
        let _store_runner = must(
            StoreProxyServiceRunner::start(store_connection, store_service).await,
            "observation shipping private start",
        );

        let witness_client = must(
            connect_deadline_role("SWARM_NATS_WITNESS_CREDENTIAL_PATH", "witness").await,
            "observation witness connection",
        );
        let witness_client_id = witness_client.server_info().client_id;
        let observation_clock = Arc::new(ObservationClockV1::new());
        let proxy_records = Arc::new(Mutex::new(Vec::new()));
        let proxy = RecordingNatsProxyV1 {
            inner: must(
                NatsPublicWitnessStoreProxyClient::new(
                    witness_client.clone(),
                    MAX_PROTOCOL_RECORD_BYTES,
                    MAX_PROTOCOL_RECORD_BYTES,
                    STORE_RESPONSE_GRANT_MILLIS,
                ),
                "observation NATS proxy",
            ),
            records: proxy_records.clone(),
            clock: observation_clock.clone(),
        };
        let mut dispatcher = must(
            PublicWitnessDispatcher::new(public_config, witness_signer, proxy).await,
            "observation dispatcher startup",
        );
        let startup_private_exchanges = proxy_records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            startup_private_exchanges.len(),
            2,
            "observation startup private exchange count"
        );
        let public_admissions = Arc::new(RecordingPublicAdmissionObserverV1 {
            clock: observation_clock.clone(),
            records: Mutex::new(Vec::new()),
        });
        dispatcher.observe_worker_transitions_for_test(observer.clone());
        dispatcher.observe_subscriber_admissions_for_test(public_admissions.clone());
        let _public_runner = must(
            PublicWitnessServiceRunner::start(witness_client, dispatcher).await,
            "observation shipping public start",
        );

        let runtime_client = must(
            RuntimeWitnessClient::connect(runtime_observation_config()).await,
            "observation runtime connection",
        );
        let session = must(
            runtime_client.establish_session(establish_request).await,
            "observation establish response",
        )
        .session;
        let prepare_request = must(
            AuthenticatedDeadlineFixtureV1::mutation_request(
                &ephemeral_signer,
                &admission,
                WitnessServiceOperationV1::Prepare,
                WitnessOperationV1::Prepare,
                &session,
                &candidate.txid,
                WitnessServiceRequestBodyV1::Prepare {
                    session: Box::new(session.clone()),
                    expected_head: None,
                    candidate: Box::new(candidate.clone()),
                },
            ),
            "observation Prepare request",
        );
        let prepared = must(
            runtime_client.prepare_successor(prepare_request).await,
            "observation Prepare response",
        );
        must(prepared.validate(), "observation Prepare attestation");
        let commit_request = must(
            AuthenticatedDeadlineFixtureV1::mutation_request(
                &ephemeral_signer,
                &admission,
                WitnessServiceOperationV1::Commit,
                WitnessOperationV1::Commit,
                &session,
                &candidate.txid,
                WitnessServiceRequestBodyV1::Commit {
                    session: Box::new(session.clone()),
                    txid: candidate.txid.clone(),
                },
            ),
            "observation Commit request",
        );
        let committed = must(
            runtime_client.commit_prepared(commit_request).await,
            "observation Commit response",
        );
        must(committed.validate(), "observation Commit attestation");

        observer.clear();
        facts.reads.store(0, Ordering::SeqCst);
        facts.cas_attempted.store(0, Ordering::SeqCst);
        facts.cas_applied.store(0, Ordering::SeqCst);
        facts.inspect_ready.store(0, Ordering::SeqCst);
        facts
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        mode.store(0, Ordering::SeqCst);
        proxy_records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        public_admissions
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        let request = must(
            AuthenticatedDeadlineFixtureV1::read_head_request(
                &ephemeral_signer,
                &admission,
                session,
                candidate.txid,
            ),
            "observation ReadHead request",
        );
        let response = must(
            runtime_client.read_head(request.clone()).await,
            "observation ReadHead response",
        );
        let response_received_at_nanos = observation_clock.now();
        must(response.validate(), "observation ReadHead attestation");
        assert_eq!(response.request_digest, request.request_digest);
        assert_eq!(response.operation, WitnessOperationV1::ReadHead);

        let worker_events = observer
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let proxy_exchanges = proxy_records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut private_exchanges = startup_private_exchanges;
        private_exchanges.extend(proxy_exchanges.clone());
        assert_eq!(
            private_exchanges.len(),
            3,
            "observation complete private exchange count"
        );
        let public_admissions = public_admissions
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            public_admissions.len(),
            1,
            "observation public admission count"
        );
        let public_admission = public_admissions[0].clone();
        let store_operations = facts
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let publisher_attempts: Vec<_> = worker_events
            .iter()
            .enumerate()
            .filter_map(|(ordinal, event)| match event {
                WorkerTransitionEventV1::PublishAttempt { worker, published } => {
                    Some(PublisherObservationV1 {
                        ordinal,
                        worker: *worker,
                        published: *published,
                    })
                }
                _ => None,
            })
            .collect();
        let runtime_client_id = runtime_client.connection_client_id();
        let connection_client_ids = vec![runtime_client_id, witness_client_id, store_client_id];
        let connections = vec![
            server_connection_observation(
                "runtime-client",
                "PHASE285_RUNTIME",
                "SWARM_NATS_RUNTIME_CREDENTIAL_PATH",
                "runtime",
                runtime_client_id,
            ),
            server_connection_observation(
                "public-witness",
                "PHASE285_WITNESS",
                "SWARM_NATS_WITNESS_CREDENTIAL_PATH",
                "witness",
                witness_client_id,
            ),
            server_connection_observation(
                "private-store",
                "PHASE285_WITNESS_STORE",
                "SWARM_NATS_STORE_CREDENTIAL_PATH",
                "witness-store",
                store_client_id,
            ),
        ];
        assert_eq!(
            connections[0].authenticated_user,
            runtime_client.authenticated_user(),
            "observation runtime connection is not credential-bound"
        );
        assert!(connections.iter().all(|record| record.server_client_id > 0));
        assert_eq!(
            connections
                .iter()
                .map(|record| record.server_client_id)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            connections.len(),
            "observation connection identities are not fresh and distinct"
        );
        assert_eq!(proxy_exchanges.len(), 1, "observation proxy count");
        assert_eq!(store_operations.len(), 1, "observation store count");
        assert_eq!(publisher_attempts.len(), 2, "observation publisher count");
        assert!(publisher_attempts.iter().all(|record| record.published));
        assert_eq!(
            proxy_exchanges[0].operation,
            WitnessStoreProxyOperationV1::ReadEntry
        );
        assert_eq!(proxy_exchanges[0].stream_id.as_deref(), Some("tom-primary"));
        assert_eq!(store_operations[0].operation, "read_entry");
        assert_eq!(
            store_operations[0].stream_id.as_deref(),
            Some("tom-primary")
        );
        assert_eq!(facts.cas_attempted.load(Ordering::SeqCst), 0);
        assert_eq!(facts.cas_applied.load(Ordering::SeqCst), 0);
        assert_eq!(
            proxy_exchanges[0].store_generation,
            store_operations[0].store_generation
        );
        assert_eq!(
            proxy_exchanges[0].store_state_digest,
            store_operations[0].store_state_digest
        );

        let store_result_bytes = must(
            hex::decode(&store_operations[0].result_canonical_hex),
            "observation store result hex",
        );
        let store_result: WitnessStoreReadResultV1 = must(
            serde_json::from_slice(&store_result_bytes),
            "observation store result decode",
        );
        assert_eq!(
            must(
                canonical_wire_bytes(&store_result),
                "observation decoded store result serialization",
            ),
            store_result_bytes,
            "observation store result is not canonical"
        );
        let (selected_store_stream, selected_store_revision, selected_envelope) =
            store_result.parts();
        let proxy_response_bytes = must(
            hex::decode(&proxy_exchanges[0].response_canonical_hex),
            "observation proxy response hex",
        );
        let proxy_response = must(
            WitnessStoreProxyResponseV1::decode(&proxy_response_bytes),
            "observation proxy response decode",
        );
        let (proxy_stream, proxy_revision, proxy_envelope) = match &proxy_response.body {
            swarm_governance::witness_engine::store::WitnessStoreProxyResponseBodyV1::Entry {
                stream_id,
                revision,
                envelope,
            } => (stream_id.as_str(), *revision, envelope.as_ref()),
            _ => panic!("observation proxy response is not Entry"),
        };
        assert_eq!(
            proxy_stream, selected_store_stream,
            "observation proxy/store stream"
        );
        assert_eq!(
            proxy_revision, selected_store_revision,
            "observation proxy/store revision"
        );
        assert_eq!(
            proxy_envelope, selected_envelope,
            "observation proxy/store envelope"
        );
        let selected_current = must_some(
            selected_envelope.current.as_ref(),
            "observation selected current state absent",
        );
        let selected_head = &selected_current.head;
        let public_head = match &response.response {
            WitnessReadResponseV1::Head(head) => must_some(
                head.as_ref().as_ref(),
                "observation public ReadHead is absent",
            ),
            _ => panic!("observation public response is not ReadHead"),
        };
        assert_eq!(
            public_head, selected_head,
            "observation public head differs from authenticated store head"
        );
        let requested_txid = match &request.body {
            WitnessServiceRequestBodyV1::ReadHead { target_txid, .. } => target_txid,
            _ => panic!("observation request is not ReadHead"),
        };
        assert_eq!(
            response.target_txid, selected_head.txid,
            "observation response target differs from selected head"
        );
        assert_eq!(
            requested_txid, &selected_head.txid,
            "observation request target differs from selected head"
        );

        let request_bytes = must(request.canonical_bytes(), "observation request bytes");
        let response_bytes = must(
            WitnessServiceResponseV1::Read(response.clone()).canonical_bytes(),
            "observation response bytes",
        );
        assert_eq!(
            public_admission.subject,
            PublicWitnessServiceConfigV1::subject_for(request.operation),
            "observation publisher subject differs"
        );
        assert_eq!(
            public_admission.payload_sha256,
            sha256_hex(&request_bytes),
            "observation publisher request bytes differ"
        );
        assert_eq!(
            public_admission.deadline_millis, PUBLIC_HANDLER_DEADLINE_MILLIS,
            "observation publisher deadline differs"
        );
        let publisher = CompletePublisherObservationV1 {
            reply_subject: public_admission.reply_subject.clone(),
            response_canonical_hex: hex::encode(&response_bytes),
            response_sha256: sha256_hex(&response_bytes),
            request_received_at_nanos: public_admission.received_at_nanos,
            response_received_at_nanos,
        };
        let worker_bytes = must(
            canonical_wire_bytes(&worker_events),
            "observation worker bytes",
        );
        let proxy_bytes = must(
            canonical_wire_bytes(&proxy_exchanges),
            "observation proxy bytes",
        );
        let private_exchange_bytes = must(
            canonical_wire_bytes(&private_exchanges),
            "observation private exchange bytes",
        );
        let store_bytes = must(
            canonical_wire_bytes(&store_operations),
            "observation store bytes",
        );
        let publisher_bytes = must(
            canonical_wire_bytes(&publisher_attempts),
            "observation publisher bytes",
        );
        let complete_publisher_bytes = must(
            canonical_wire_bytes(&publisher),
            "observation complete publisher bytes",
        );
        let public_admission_bytes = must(
            canonical_wire_bytes(&public_admission),
            "observation public admission bytes",
        );
        let connection_bytes = must(
            canonical_wire_bytes(&connections),
            "observation connection bytes",
        );
        let connection_client_id_bytes = must(
            canonical_wire_bytes(&connection_client_ids),
            "observation connection client-id bytes",
        );
        let counts = ObservationCountsV1 {
            worker_events: worker_events.len(),
            proxy_exchanges: proxy_exchanges.len(),
            private_exchanges: private_exchanges.len(),
            store_operations: store_operations.len(),
            publisher_attempts: publisher_attempts.len(),
            connections: connections.len(),
            cas_attempted: facts.cas_attempted.load(Ordering::SeqCst),
            cas_applied: facts.cas_applied.load(Ordering::SeqCst),
        };
        let selected_store_generation = selected_envelope.store_generation;
        let selected_store_state_digest = must(
            selected_envelope.store_state_digest(),
            "observation selected store digest",
        );
        let selected_envelope_digest = must(
            selected_envelope.signed_envelope_digest(),
            "observation selected envelope digest",
        );
        let digests = ObservationDigestsV1 {
            request_sha256: sha256_hex(&request_bytes),
            response_sha256: sha256_hex(&response_bytes),
            worker_events_sha256: sha256_hex(&worker_bytes),
            proxy_exchanges_sha256: sha256_hex(&proxy_bytes),
            private_exchanges_sha256: sha256_hex(&private_exchange_bytes),
            store_operations_sha256: sha256_hex(&store_bytes),
            publisher_attempts_sha256: sha256_hex(&publisher_bytes),
            public_admission_sha256: sha256_hex(&public_admission_bytes),
            publisher_sha256: sha256_hex(&complete_publisher_bytes),
            connections_sha256: sha256_hex(&connection_bytes),
            connection_client_ids_sha256: sha256_hex(&connection_client_id_bytes),
        };
        let identity = observation_identity();
        let complete_identity = if identity.is_none()
            && std::env::var_os("PHASE285_COMPLETE_RECEIPT_LEDGER_PATH").is_some()
        {
            Some((
                must(
                    std::env::var("PHASE285_SERVICE_CHECKPOINT_TREE"),
                    "complete receipt tree absent",
                ),
                must(
                    std::env::var("PHASE285_COMPLETE_RECEIPT_INVOCATION_TOKEN"),
                    "complete receipt invocation token absent",
                ),
                "service_checkpoint_complete_receipt".to_string(),
            ))
        } else {
            None
        };
        let (tree, token, case) = identity
            .as_ref()
            .map(|(_, tree, token, case)| (tree.as_str(), token.as_str(), case.as_str()))
            .or_else(|| {
                complete_identity
                    .as_ref()
                    .map(|(tree, token, case)| (tree.as_str(), token.as_str(), case.as_str()))
            })
            .unwrap_or((
                "direct-a2b1-tree",
                "direct-a2b1-invocation",
                "service_checkpoint_complete_receipt",
            ));
        let row = ObservationLedgerV1 {
            schema_version: 1,
            tree,
            invocation_token: token,
            case,
            status: "passed",
            operation: request.operation,
            public_subject: PublicWitnessServiceConfigV1::subject_for(request.operation),
            request_nonce: request.request_nonce.clone(),
            request_digest: request.request_digest.clone(),
            request_canonical_hex: hex::encode(request_bytes),
            response_canonical_hex: hex::encode(response_bytes),
            selected_store_revision,
            selected_store_generation,
            selected_store_state_digest,
            selected_envelope_digest,
            selected_head_txid: selected_head.txid.clone(),
            worker_events,
            proxy_exchanges,
            private_exchanges,
            store_operations,
            publisher_attempts,
            public_admission,
            publisher,
            connections,
            connection_client_ids,
            counts,
            digests,
        };
        let bytes = must(
            canonical_wire_bytes(&row),
            "observation ledger canonical bytes",
        );
        if let Some((path, _, _, _)) = identity {
            let mut file = must(
                OpenOptions::new().write(true).create_new(true).open(path),
                "observation ledger is not fresh",
            );
            must(file.write_all(&bytes), "observation ledger write");
            must(file.write_all(b"\n"), "observation ledger frame");
            must(file.sync_all(), "observation ledger sync");
        }
        bytes
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct LedgerBoundCompleteReceiptV1 {
        schema_version: u8,
        observation_ledger_canonical_hex: String,
        observation_ledger_sha256: String,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum CompleteReceiptDispositionV1 {
        Forward,
        Suppress,
    }

    fn ledger_field<'a>(
        value: &'a serde_json::Value,
        name: &str,
        reason: &'static str,
    ) -> Result<&'a serde_json::Value, &'static str> {
        value.get(name).ok_or(reason)
    }

    fn ledger_string<'a>(
        value: &'a serde_json::Value,
        name: &str,
        reason: &'static str,
    ) -> Result<&'a str, &'static str> {
        ledger_field(value, name, reason)?.as_str().ok_or(reason)
    }

    fn ledger_u64(
        value: &serde_json::Value,
        name: &str,
        reason: &'static str,
    ) -> Result<u64, &'static str> {
        ledger_field(value, name, reason)?.as_u64().ok_or(reason)
    }

    fn ledger_hex(
        value: &serde_json::Value,
        name: &str,
        reason: &'static str,
    ) -> Result<Vec<u8>, &'static str> {
        hex::decode(ledger_string(value, name, reason)?).map_err(|_| reason)
    }

    fn ledger_digest_matches(
        value: &serde_json::Value,
        bytes_name: &str,
        digest_name: &str,
        reason: &'static str,
    ) -> Result<Vec<u8>, &'static str> {
        let bytes = ledger_hex(value, bytes_name, reason)?;
        if sha256_hex(&bytes) != ledger_string(value, digest_name, reason)? {
            return Err(reason);
        }
        Ok(bytes)
    }

    fn canonical_value_bytes(
        value: &serde_json::Value,
        reason: &'static str,
    ) -> Result<Vec<u8>, &'static str> {
        canonical_wire_bytes(value).map_err(|_| reason)
    }

    fn validate_complete_worker_events(events: &[serde_json::Value]) -> Result<(), &'static str> {
        let expected = [
            ("dequeued", "public", None),
            ("post_preflight", "public", None),
            ("proxy_store_begin", "public", Some("read_entry")),
            ("dequeued", "private", None),
            ("post_preflight", "private", None),
            ("proxy_store_begin", "private", Some("read_entry")),
            ("proxy_store_end", "private", Some("read_entry")),
            ("response_enqueue_attempt", "private", None),
            ("publish_attempt", "private", None),
            ("proxy_store_end", "public", Some("read_entry")),
            ("response_enqueue_attempt", "public", None),
            ("publish_attempt", "public", None),
        ];
        if events.len() != expected.len() {
            return Err("worker_operation");
        }
        for (event, (kind, worker, operation)) in events.iter().zip(expected) {
            if ledger_string(event, "event", "worker_operation")? != kind
                || ledger_string(event, "worker", "worker_operation")? != worker
                || operation.is_some_and(|operation| {
                    ledger_string(event, "operation", "worker_operation") != Ok(operation)
                })
            {
                return Err("worker_operation");
            }
        }
        for index in [2_usize, 5] {
            if ledger_field(&events[index], "cas_attempted", "worker_cas")?.as_bool() != Some(false)
            {
                return Err("worker_cas");
            }
        }
        for index in [6_usize, 9] {
            if ledger_field(&events[index], "cas_applied", "worker_cas")?.as_bool() != Some(false) {
                return Err("worker_cas");
            }
            if ledger_field(&events[index], "succeeded", "worker_operation")?.as_bool()
                != Some(true)
            {
                return Err("worker_operation");
            }
        }
        for index in [7_usize, 10] {
            if ledger_field(&events[index], "accepted", "worker_operation")?.as_bool() != Some(true)
            {
                return Err("worker_operation");
            }
        }
        for index in [8_usize, 11] {
            if ledger_field(&events[index], "published", "worker_operation")?.as_bool()
                != Some(true)
            {
                return Err("worker_operation");
            }
        }
        Ok(())
    }

    fn validate_complete_publisher_attempts(
        attempts: &[serde_json::Value],
        events: &[serde_json::Value],
    ) -> Result<(), &'static str> {
        let expected = [(8_u64, "private"), (11_u64, "public")];
        if attempts.len() != expected.len() {
            return Err("publisher_fabrication");
        }
        for (attempt, (ordinal, worker)) in attempts.iter().zip(expected) {
            let ordinal_index = usize::try_from(ordinal).map_err(|_| "publisher_fabrication")?;
            let event = events.get(ordinal_index).ok_or("publisher_fabrication")?;
            if ledger_u64(attempt, "ordinal", "publisher_fabrication")? != ordinal
                || ledger_string(attempt, "worker", "publisher_fabrication")? != worker
                || ledger_field(attempt, "published", "publisher_fabrication")?.as_bool()
                    != Some(true)
                || ledger_string(event, "event", "publisher_fabrication")? != "publish_attempt"
                || ledger_string(event, "worker", "publisher_fabrication")? != worker
                || ledger_field(event, "published", "publisher_fabrication")?.as_bool()
                    != Some(true)
            {
                return Err("publisher_fabrication");
            }
        }
        Ok(())
    }

    fn validate_complete_connections(
        connections: &[serde_json::Value],
    ) -> Result<(), &'static str> {
        let expected = [
            ("runtime-client", "PHASE285_RUNTIME", "phase285_foreign"),
            ("public-witness", "PHASE285_WITNESS", "phase285_witness"),
            (
                "private-store",
                "PHASE285_WITNESS_STORE",
                "phase285_witness_store",
            ),
        ];
        if connections.len() != expected.len() {
            return Err("connection_identity");
        }
        let mut client_ids = std::collections::BTreeSet::new();
        for (connection, (role, account, user)) in connections.iter().zip(expected) {
            let client_id = ledger_u64(connection, "server_client_id", "connection_identity")?;
            if client_id == 0
                || !client_ids.insert(client_id)
                || ledger_string(connection, "runner_role", "connection_identity")? != role
                || ledger_string(connection, "account", "connection_identity")? != account
                || ledger_string(connection, "authenticated_user", "connection_identity")? != user
            {
                return Err("connection_identity");
            }
            let evidence = ledger_digest_matches(
                connection,
                "server_evidence_canonical_hex",
                "server_evidence_sha256",
                "connection_identity",
            )?;
            let authority: ServerConnectionAuthorityV1 =
                serde_json::from_slice(&evidence).map_err(|_| "connection_identity")?;
            if canonical_wire_bytes(&authority).map_err(|_| "connection_identity")? != evidence
                || authority.account != account
                || authority.authenticated_user != user
                || authority.server_client_id != client_id
            {
                return Err("connection_identity");
            }
        }
        Ok(())
    }

    fn validate_complete_receipt(
        receipt: &LedgerBoundCompleteReceiptV1,
        expected_tree: &str,
        expected_invocation_token: &str,
        expected_case: &str,
    ) -> Result<(), &'static str> {
        if receipt.schema_version != 1 {
            return Err("receipt_schema");
        }
        let ledger = hex::decode(&receipt.observation_ledger_canonical_hex)
            .map_err(|_| "ledger_canonical")?;
        if sha256_hex(&ledger) != receipt.observation_ledger_sha256 {
            return Err("ledger_digest");
        }
        let row: serde_json::Value =
            serde_json::from_slice(&ledger).map_err(|_| "ledger_canonical")?;
        if canonical_value_bytes(&row, "ledger_canonical")? != ledger
            || ledger_u64(&row, "schema_version", "ledger_identity")? != 1
            || ledger_string(&row, "status", "ledger_identity")? != "passed"
            || ledger_string(&row, "operation", "public_request")? != "ReadHead"
            || ledger_string(&row, "public_subject", "public_request")?
                != "swarm.governance.witness.v1.read_head"
        {
            return Err("ledger_identity");
        }
        if ledger_string(&row, "tree", "current_invocation")? != expected_tree
            || ledger_string(&row, "invocation_token", "current_invocation")?
                != expected_invocation_token
            || ledger_string(&row, "case", "current_invocation")? != expected_case
        {
            return Err("current_invocation");
        }

        let request_bytes = ledger_hex(&row, "request_canonical_hex", "public_request")?;
        let request =
            WitnessServiceRequestV1::decode(&request_bytes).map_err(|_| "public_request")?;
        if request.canonical_bytes().map_err(|_| "public_request")? != request_bytes
            || request.operation != WitnessServiceOperationV1::ReadHead
            || request.request_nonce != ledger_string(&row, "request_nonce", "public_request")?
            || request.request_digest != ledger_string(&row, "request_digest", "public_request")?
        {
            return Err("public_request");
        }
        let response_bytes = ledger_hex(&row, "response_canonical_hex", "public_response")?;
        let response =
            WitnessServiceResponseV1::decode_for_client_request(&response_bytes, &request)
                .map_err(|_| "public_response")?;

        let events = ledger_field(&row, "worker_events", "worker_operation")?
            .as_array()
            .ok_or("worker_operation")?;
        validate_complete_worker_events(events)?;

        let private = ledger_field(&row, "private_exchanges", "private_exchange")?
            .as_array()
            .ok_or("private_exchange")?;
        let expected_operations = [
            WitnessStoreProxyOperationV1::InspectReady,
            WitnessStoreProxyOperationV1::ReadEntry,
            WitnessStoreProxyOperationV1::ReadEntry,
        ];
        if private.len() != expected_operations.len() {
            return Err("private_exchange");
        }
        let mut previous_response_at = 0;
        let mut final_private_response = None;
        for (exchange, expected_operation) in private.iter().zip(expected_operations) {
            let request_bytes = ledger_digest_matches(
                exchange,
                "request_canonical_hex",
                "request_sha256",
                "private_request_digest",
            )?;
            let response_bytes = ledger_digest_matches(
                exchange,
                "response_canonical_hex",
                "response_sha256",
                "private_response_digest",
            )?;
            let private_request = WitnessStoreProxyRequestV1::decode(&request_bytes)
                .map_err(|_| "private_request_digest")?;
            private_request
                .validate_semantics()
                .and_then(|()| private_request.validate_signature())
                .map_err(|_| "private_request_digest")?;
            let private_response = WitnessStoreProxyResponseV1::decode(&response_bytes)
                .map_err(|_| "private_response_digest")?;
            if private_request.operation != expected_operation
                || private_response.operation != expected_operation
                || private_response.request_digest != private_request.request_digest
                || ledger_string(exchange, "request_nonce", "private_exchange")?
                    != private_request.request_nonce
                || ledger_string(exchange, "request_digest", "private_exchange")?
                    != private_request.request_digest
            {
                return Err("private_exchange");
            }
            let request_at = ledger_u64(exchange, "request_at_nanos", "causal_timestamps")?;
            let response_at = ledger_u64(exchange, "response_at_nanos", "causal_timestamps")?;
            if request_at < previous_response_at || response_at < request_at {
                return Err("causal_timestamps");
            }
            previous_response_at = response_at;
            final_private_response = Some(private_response);
        }

        let proxy = ledger_field(&row, "proxy_exchanges", "proxy_cross_copy")?
            .as_array()
            .ok_or("proxy_cross_copy")?;
        if proxy.len() != 1
            || canonical_value_bytes(&proxy[0], "proxy_cross_copy")?
                != canonical_value_bytes(&private[2], "proxy_cross_copy")?
        {
            return Err("proxy_cross_copy");
        }

        let publisher_attempts = ledger_field(&row, "publisher_attempts", "publisher_fabrication")?
            .as_array()
            .ok_or("publisher_fabrication")?;
        validate_complete_publisher_attempts(publisher_attempts, events)?;

        let store = ledger_field(&row, "store_operations", "store_result_digest")?
            .as_array()
            .ok_or("store_result_digest")?;
        if store.len() != 1
            || ledger_string(&store[0], "operation", "store_result_digest")? != "read_entry"
            || ledger_field(&store[0], "cas_attempted", "worker_cas")?.as_bool() != Some(false)
            || ledger_field(&store[0], "cas_applied", "worker_cas")?.as_bool() != Some(false)
        {
            return Err("store_result_digest");
        }
        let store_input = ledger_digest_matches(
            &store[0],
            "input_canonical_hex",
            "input_sha256",
            "store_input_digest",
        )?;
        let stream: String =
            serde_json::from_slice(&store_input).map_err(|_| "store_input_digest")?;
        if stream != "tom-primary"
            || canonical_wire_bytes(&stream).map_err(|_| "store_input_digest")? != store_input
        {
            return Err("store_input_digest");
        }
        let store_result_bytes = ledger_digest_matches(
            &store[0],
            "result_canonical_hex",
            "result_sha256",
            "store_result_digest",
        )?;
        let store_result: WitnessStoreReadResultV1 =
            serde_json::from_slice(&store_result_bytes).map_err(|_| "store_result_digest")?;
        if canonical_wire_bytes(&store_result).map_err(|_| "store_result_digest")?
            != store_result_bytes
        {
            return Err("store_result_digest");
        }
        let (store_stream, store_revision, store_envelope) = store_result.parts();
        if store_stream != stream
            || ledger_string(&store[0], "stream_id", "store_result_digest")? != store_stream
            || ledger_u64(&store[0], "revision", "store_result_digest")? != store_revision
            || ledger_u64(&store[0], "store_generation", "store_result_digest")?
                != store_envelope.store_generation
            || ledger_string(&store[0], "store_state_digest", "store_result_digest")?
                != store_envelope
                    .store_state_digest()
                    .map_err(|_| "store_result_digest")?
        {
            return Err("store_result_digest");
        }
        let final_private_response = final_private_response.ok_or("private_store_entry")?;
        match final_private_response.body {
            swarm_governance::witness_engine::store::WitnessStoreProxyResponseBodyV1::Entry {
                stream_id,
                revision,
                envelope,
            } if stream_id == store_stream
                && revision == store_revision
                && envelope.as_ref() == store_envelope => {}
            _ => return Err("private_store_entry"),
        }

        if ledger_u64(&row, "selected_store_revision", "store_result_digest")? != store_revision
            || ledger_u64(&row, "selected_store_generation", "store_result_digest")?
                != store_envelope.store_generation
            || ledger_string(&row, "selected_store_state_digest", "store_result_digest")?
                != store_envelope
                    .store_state_digest()
                    .map_err(|_| "store_result_digest")?
            || ledger_string(&row, "selected_envelope_digest", "store_result_digest")?
                != store_envelope
                    .signed_envelope_digest()
                    .map_err(|_| "store_result_digest")?
        {
            return Err("store_result_digest");
        }
        let selected_head = &store_envelope
            .current
            .as_ref()
            .ok_or("public_store_head")?
            .head;
        let WitnessServiceResponseV1::Read(read) = response else {
            return Err("public_store_head");
        };
        let WitnessReadResponseV1::Head(head) = &read.response else {
            return Err("public_store_head");
        };
        if head.as_ref().as_ref() != Some(selected_head)
            || read.target_txid != selected_head.txid
            || ledger_string(&row, "selected_head_txid", "public_store_head")? != selected_head.txid
        {
            return Err("public_store_head");
        }
        let WitnessServiceRequestBodyV1::ReadHead { target_txid, .. } = &request.body else {
            return Err("public_store_head");
        };
        if target_txid != &selected_head.txid {
            return Err("public_store_head");
        }

        let publisher = ledger_field(&row, "publisher", "publisher_reply_subject")?;
        let admission = ledger_field(&row, "public_admission", "publisher_reply_subject")?;
        let reply = ledger_string(publisher, "reply_subject", "publisher_reply_subject")?;
        if reply.len() > 512
            || !(reply.starts_with("_INBOX.") || reply.starts_with("_R_."))
            || reply.contains('*')
            || reply.contains('>')
        {
            return Err("publisher_reply_subject");
        }
        if ledger_string(admission, "reply_subject", "publisher_reply_subject")? != reply
            || ledger_string(admission, "subject", "publisher_reply_subject")?
                != "swarm.governance.witness.v1.read_head"
            || ledger_string(admission, "payload_sha256", "publisher_reply_subject")?
                != sha256_hex(&request_bytes)
            || ledger_u64(admission, "deadline_millis", "publisher_reply_subject")?
                != PUBLIC_HANDLER_DEADLINE_MILLIS
        {
            return Err("publisher_reply_subject");
        }
        let publisher_response = ledger_digest_matches(
            publisher,
            "response_canonical_hex",
            "response_sha256",
            "publisher_response",
        )?;
        if publisher_response != response_bytes {
            return Err("publisher_response");
        }
        let request_received =
            ledger_u64(publisher, "request_received_at_nanos", "causal_timestamps")?;
        if ledger_u64(admission, "received_at_nanos", "causal_timestamps")? != request_received {
            return Err("causal_timestamps");
        }
        let response_received =
            ledger_u64(publisher, "response_received_at_nanos", "causal_timestamps")?;
        let final_private = private.last().ok_or("causal_timestamps")?;
        if ledger_u64(final_private, "request_at_nanos", "causal_timestamps")? < request_received
            || ledger_u64(final_private, "response_at_nanos", "causal_timestamps")?
                > response_received
            || response_received < request_received
        {
            return Err("causal_timestamps");
        }

        let connections = ledger_field(&row, "connections", "connection_identity")?
            .as_array()
            .ok_or("connection_identity")?;
        validate_complete_connections(connections)?;
        let connection_client_ids =
            ledger_field(&row, "connection_client_ids", "connection_identity")?
                .as_array()
                .ok_or("connection_identity")?;
        if connection_client_ids.len() != connections.len()
            || connection_client_ids
                .iter()
                .zip(connections)
                .any(|(client_id, connection)| {
                    client_id.as_u64()
                        != connection
                            .get("server_client_id")
                            .and_then(serde_json::Value::as_u64)
                })
        {
            return Err("connection_identity");
        }

        let counts = ledger_field(&row, "counts", "ledger_counts")?;
        for (name, expected) in [
            ("worker_events", events.len()),
            (
                "proxy_exchanges",
                ledger_field(&row, "proxy_exchanges", "ledger_counts")?
                    .as_array()
                    .ok_or("ledger_counts")?
                    .len(),
            ),
            ("private_exchanges", private.len()),
            ("store_operations", store.len()),
            (
                "publisher_attempts",
                ledger_field(&row, "publisher_attempts", "ledger_counts")?
                    .as_array()
                    .ok_or("ledger_counts")?
                    .len(),
            ),
            ("connections", connections.len()),
        ] {
            if ledger_u64(counts, name, "ledger_counts")? != expected as u64 {
                return Err("ledger_counts");
            }
        }
        if ledger_u64(counts, "cas_attempted", "worker_cas")? != 0
            || ledger_u64(counts, "cas_applied", "worker_cas")? != 0
        {
            return Err("worker_cas");
        }

        let digests = ledger_field(&row, "digests", "ledger_digests")?;
        for (name, value) in [
            (
                "worker_events_sha256",
                ledger_field(&row, "worker_events", "ledger_digests")?,
            ),
            (
                "proxy_exchanges_sha256",
                ledger_field(&row, "proxy_exchanges", "ledger_digests")?,
            ),
            (
                "private_exchanges_sha256",
                ledger_field(&row, "private_exchanges", "ledger_digests")?,
            ),
            (
                "store_operations_sha256",
                ledger_field(&row, "store_operations", "ledger_digests")?,
            ),
            (
                "publisher_attempts_sha256",
                ledger_field(&row, "publisher_attempts", "ledger_digests")?,
            ),
            ("publisher_sha256", publisher),
            ("public_admission_sha256", admission),
            (
                "connections_sha256",
                ledger_field(&row, "connections", "ledger_digests")?,
            ),
            (
                "connection_client_ids_sha256",
                ledger_field(&row, "connection_client_ids", "ledger_digests")?,
            ),
        ] {
            if sha256_hex(&canonical_value_bytes(value, "ledger_digests")?)
                != ledger_string(digests, name, "ledger_digests")?
            {
                return Err("ledger_digests");
            }
        }
        if sha256_hex(&request_bytes) != ledger_string(digests, "request_sha256", "ledger_digests")?
            || sha256_hex(&response_bytes)
                != ledger_string(digests, "response_sha256", "ledger_digests")?
        {
            return Err("ledger_digests");
        }
        Ok(())
    }

    fn complete_receipt_disposition(
        receipt: Option<LedgerBoundCompleteReceiptV1>,
        sender: Option<&mpsc::Sender<LedgerBoundCompleteReceiptV1>>,
        expected_tree: &str,
        expected_invocation_token: &str,
        expected_case: &str,
    ) -> CompleteReceiptDispositionV1 {
        let Some(receipt) = receipt else {
            return CompleteReceiptDispositionV1::Forward;
        };
        if validate_complete_receipt(
            &receipt,
            expected_tree,
            expected_invocation_token,
            expected_case,
        )
        .is_err()
        {
            return CompleteReceiptDispositionV1::Forward;
        }
        let Some(sender) = sender else {
            return CompleteReceiptDispositionV1::Forward;
        };
        if sender.max_capacity() != 1 {
            return CompleteReceiptDispositionV1::Forward;
        }
        match sender.try_send(receipt) {
            Ok(()) => CompleteReceiptDispositionV1::Suppress,
            Err(_) => CompleteReceiptDispositionV1::Forward,
        }
    }

    fn complete_receipt_file_path(variable: &str) -> PathBuf {
        assert!(
            matches!(
                variable,
                "PHASE285_COMPLETE_RECEIPT_LEDGER_PATH" | "PHASE285_COMPLETE_RECEIPT_PATH"
            ),
            "complete receipt path selector is not closed"
        );
        let path = PathBuf::from(must(
            std::env::var(variable),
            "checker-owned complete receipt artifact path absent",
        ));
        assert!(
            path.is_absolute(),
            "complete receipt artifact path is relative"
        );
        path
    }

    fn persist_and_reopen(variable: &str, bytes: &[u8]) -> Vec<u8> {
        use std::os::unix::fs::OpenOptionsExt;

        let path = complete_receipt_file_path(variable);
        let mut file = must(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path),
            "complete receipt evidence is not fresh",
        );
        must(file.write_all(bytes), "complete receipt evidence write");
        must(file.write_all(b"\n"), "complete receipt evidence frame");
        must(file.sync_all(), "complete receipt evidence sync");
        drop(file);
        let framed = must(std::fs::read(&path), "complete receipt evidence reopen");
        assert_eq!(
            framed.last(),
            Some(&b'\n'),
            "complete receipt evidence frame absent"
        );
        assert_eq!(
            framed[..framed.len() - 1],
            *bytes,
            "complete receipt reopened bytes differ"
        );
        bytes.to_vec()
    }

    fn complete_receipt_from_ledger_value(
        value: &serde_json::Value,
    ) -> LedgerBoundCompleteReceiptV1 {
        let bytes = must(
            canonical_wire_bytes(value),
            "coherent complete receipt ledger bytes",
        );
        LedgerBoundCompleteReceiptV1 {
            schema_version: 1,
            observation_ledger_sha256: sha256_hex(&bytes),
            observation_ledger_canonical_hex: hex::encode(bytes),
        }
    }

    fn refresh_ledger_array_digest(
        value: &mut serde_json::Value,
        array_name: &str,
        digest_name: &str,
    ) {
        let bytes = must(
            canonical_wire_bytes(must_some(value.get(array_name), "coherent array absent")),
            "coherent array bytes",
        );
        must_some(
            value
                .get_mut("digests")
                .and_then(serde_json::Value::as_object_mut),
            "coherent ledger digests absent",
        )
        .insert(
            digest_name.to_string(),
            serde_json::Value::String(sha256_hex(&bytes)),
        );
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct TopologyOwnerPairV1 {
        account: String,
        principal: String,
    }

    fn topology_bounded_read(variable: &str, maximum: u64) -> Vec<u8> {
        let allowed = [
            "PHASE285_TOPOLOGY_CONFIG_PATH",
            "PHASE285_TOPOLOGY_PROBE_CONFIG_PATH",
            "PHASE285_TOPOLOGY_RUNTIME_CREDENTIAL_PATH",
            "PHASE285_TOPOLOGY_WITNESS_CREDENTIAL_PATH",
            "PHASE285_TOPOLOGY_STORE_CREDENTIAL_PATH",
            "PHASE285_TOPOLOGY_INIT_CREDENTIAL_PATH",
        ];
        assert!(
            allowed.contains(&variable),
            "topology input selector is not closed"
        );
        let path = PathBuf::from(must(std::env::var(variable), "topology input path absent"));
        assert!(path.is_absolute(), "topology input path is relative");
        let before = must(std::fs::symlink_metadata(&path), "topology input metadata");
        assert!(
            before.file_type().is_file(),
            "topology input is not regular"
        );
        assert!(
            !before.file_type().is_symlink(),
            "topology input is symlink"
        );
        assert!(
            (1..=maximum).contains(&before.len()),
            "topology input bound"
        );
        let bytes = must(std::fs::read(&path), "topology input read");
        let after = must(std::fs::symlink_metadata(&path), "topology input recheck");
        assert_eq!(
            (before.dev(), before.ino(), before.mode(), before.len()),
            (after.dev(), after.ino(), after.mode(), after.len()),
            "topology input identity"
        );
        assert_eq!(
            u64::try_from(bytes.len()).ok(),
            Some(before.len()),
            "topology input length"
        );
        bytes
    }

    fn topology_parse_pairs(bytes: &[u8]) -> Vec<TopologyOwnerPairV1> {
        let source = must(std::str::from_utf8(bytes), "topology config utf8");
        let mut current_account: Option<String> = None;
        let mut accounts = Vec::new();
        let mut pairs = Vec::new();
        for line in source.lines() {
            if line.starts_with("  ") && !line.starts_with("    ") && line.ends_with(" {") {
                let account = line.trim().trim_end_matches(" {").to_string();
                assert!(!account.is_empty(), "topology account is empty");
                accounts.push(account.clone());
                current_account = Some(account);
            } else if let Some(rest) = line.trim().strip_prefix("user: \"") {
                let principal = rest.split('"').next().unwrap_or_default();
                assert!(!principal.is_empty(), "topology principal is empty");
                pairs.push(TopologyOwnerPairV1 {
                    account: must_some(current_account.clone(), "topology principal owner absent"),
                    principal: principal.to_string(),
                });
            }
        }
        accounts.dedup();
        assert_eq!(accounts.len(), 3, "topology account cardinality");
        assert_eq!(pairs.len(), 4, "topology principal cardinality");
        pairs
    }

    fn topology_credential_user(variable: &str, expected_role: &str) -> String {
        let bytes = topology_bounded_read(variable, 4_096);
        let value: serde_json::Value =
            must(serde_json::from_slice(&bytes), "topology credential json");
        assert_eq!(
            ledger_string(&value, "role", "topology credential"),
            Ok(expected_role)
        );
        must(
            ledger_string(&value, "username", "topology credential"),
            "topology credential username",
        )
        .to_string()
    }

    fn topology_projection_path(variable: &str) -> PathBuf {
        let allowed = [
            "PHASE285_TOPOLOGY_RUST_CANONICAL_PROJECTION_PATH",
            "PHASE285_TOPOLOGY_RUST_PROBE_PROJECTION_PATH",
        ];
        assert!(
            allowed.contains(&variable),
            "topology projection selector is not closed"
        );
        let path = PathBuf::from(must(
            std::env::var(variable),
            "topology projection path absent",
        ));
        assert!(path.is_absolute(), "topology projection path is relative");
        path
    }

    fn topology_write_projection(variable: &str, value: &serde_json::Value) {
        let bytes = must(canonical_wire_bytes(value), "topology projection canonical");
        assert!(
            (1..=16_384).contains(&bytes.len()),
            "topology projection bound"
        );
        let path = topology_projection_path(variable);
        let mut file = must(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path),
            "topology projection freshness",
        );
        must(file.write_all(&bytes), "topology projection write");
        must(file.write_all(b"\n"), "topology projection frame");
        must(file.sync_all(), "topology projection fsync");
        drop(file);
        let metadata = must(
            std::fs::symlink_metadata(&path),
            "topology projection metadata",
        );
        assert!(
            metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
            "topology projection type"
        );
        assert_eq!(metadata.mode() & 0o777, 0o600, "topology projection mode");
        assert!(
            (1..=16_384).contains(&metadata.len()),
            "topology projection framed bound"
        );
        let reopened = must(std::fs::read(&path), "topology projection reopen");
        assert_eq!(
            reopened,
            [bytes.as_slice(), b"\n"].concat(),
            "topology projection reopen bytes"
        );
    }

    fn run_topology_projection_test() {
        let canonical = topology_bounded_read("PHASE285_TOPOLOGY_CONFIG_PATH", 262_144);
        let probe = topology_bounded_read("PHASE285_TOPOLOGY_PROBE_CONFIG_PATH", 262_144);
        let canonical_pairs = topology_parse_pairs(&canonical);
        let probe_pairs = topology_parse_pairs(&probe);
        let credential_users = [
            topology_credential_user("PHASE285_TOPOLOGY_RUNTIME_CREDENTIAL_PATH", "runtime"),
            topology_credential_user("PHASE285_TOPOLOGY_WITNESS_CREDENTIAL_PATH", "witness"),
            topology_credential_user("PHASE285_TOPOLOGY_STORE_CREDENTIAL_PATH", "witness-store"),
            topology_credential_user("PHASE285_TOPOLOGY_INIT_CREDENTIAL_PATH", "init"),
        ];
        assert_eq!(
            canonical_pairs
                .iter()
                .map(|pair| pair.principal.as_str())
                .collect::<Vec<_>>(),
            credential_users
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            "topology credential binding"
        );
        let tree = must(
            std::env::var("PHASE285_SERVICE_CHECKPOINT_TREE"),
            "topology tree absent",
        );
        let token = must(
            std::env::var("PHASE285_TOPOLOGY_INVOCATION_TOKEN"),
            "topology token absent",
        );
        let canonical_digest = sha256_hex(&canonical);
        let probe_digest = sha256_hex(&probe);
        for (variable, input_kind, pairs) in [
            (
                "PHASE285_TOPOLOGY_RUST_CANONICAL_PROJECTION_PATH",
                "canonical",
                canonical_pairs,
            ),
            (
                "PHASE285_TOPOLOGY_RUST_PROBE_PROJECTION_PATH",
                "probe",
                probe_pairs,
            ),
        ] {
            topology_write_projection(
                variable,
                &serde_json::json!({
                    "canonical_config_sha256": canonical_digest,
                    "case": "service_checkpoint_topology_owner_blocks",
                    "input_kind": input_kind,
                    "invocation_token": token,
                    "pairs": pairs,
                    "probe_config_sha256": probe_digest,
                    "schema_version": 1,
                    "tree": tree,
                }),
            );
        }
        println!("topology_rust_projection canonical=1 probe=1 accounts=3 principals=4 passed=1");
    }

    pub(super) fn run_complete_receipt_suppression_test() {
        let thread = must(
            std::thread::Builder::new()
                .name("phase285-a2b1-complete-receipt".to_string())
                .stack_size(64 * 1024 * 1024)
                .spawn(|| {
                    let runtime = must(
                        tokio::runtime::Builder::new_multi_thread()
                            .worker_threads(4)
                            .thread_stack_size(64 * 1024 * 1024)
                            .enable_all()
                            .build(),
                        "complete receipt runtime",
                    );
                    runtime.block_on(Box::pin(run_complete_receipt_suppression_test_async()));
                }),
            "complete receipt thread",
        );
        must(thread.join(), "complete receipt thread panicked");
    }

    async fn run_complete_receipt_suppression_test_async() {
        let expected_tree = must(
            std::env::var("PHASE285_SERVICE_CHECKPOINT_TREE"),
            "complete receipt tree absent",
        );
        let expected_invocation_token = must(
            std::env::var("PHASE285_COMPLETE_RECEIPT_INVOCATION_TOKEN"),
            "complete receipt invocation token absent",
        );
        let expected_case = "service_checkpoint_complete_receipt";
        let produced_ledger = run_worker_observation_test_async().await;
        let reopened_ledger =
            persist_and_reopen("PHASE285_COMPLETE_RECEIPT_LEDGER_PATH", &produced_ledger);
        let receipt = LedgerBoundCompleteReceiptV1 {
            schema_version: 1,
            observation_ledger_sha256: sha256_hex(&reopened_ledger),
            observation_ledger_canonical_hex: hex::encode(&reopened_ledger),
        };
        must(
            validate_complete_receipt(
                &receipt,
                &expected_tree,
                &expected_invocation_token,
                expected_case,
            ),
            "complete receipt validation",
        );
        let receipt_bytes = must(
            canonical_wire_bytes(&receipt),
            "complete receipt serialization",
        );
        let reopened_receipt = persist_and_reopen("PHASE285_COMPLETE_RECEIPT_PATH", &receipt_bytes);
        let receipt: LedgerBoundCompleteReceiptV1 = must(
            serde_json::from_slice(&reopened_receipt),
            "complete receipt reopen decode",
        );
        assert_eq!(
            must(
                canonical_wire_bytes(&receipt),
                "complete receipt reopen serialization",
            ),
            reopened_receipt,
            "complete receipt reopened canonical bytes differ"
        );

        let (capacity_one_sender, mut capacity_one_receiver) = mpsc::channel(1);
        assert_eq!(
            complete_receipt_disposition(
                Some(receipt.clone()),
                Some(&capacity_one_sender),
                &expected_tree,
                &expected_invocation_token,
                expected_case,
            ),
            CompleteReceiptDispositionV1::Suppress,
            "complete capacity-one reservation must suppress"
        );
        assert_eq!(
            must(capacity_one_receiver.try_recv(), "complete receipt absent"),
            receipt
        );
        let (cross_invocation_sender, mut cross_invocation_receiver) = mpsc::channel(1);
        let different_invocation = format!("{expected_invocation_token}-different");
        assert_eq!(
            complete_receipt_disposition(
                Some(receipt.clone()),
                Some(&cross_invocation_sender),
                &expected_tree,
                &different_invocation,
                expected_case,
            ),
            CompleteReceiptDispositionV1::Forward,
            "cross invocation complete receipt suppressed"
        );
        assert!(
            cross_invocation_receiver.try_recv().is_err(),
            "cross invocation receiver was not empty"
        );
        assert_eq!(
            complete_receipt_disposition(
                Some(receipt.clone()),
                None,
                &expected_tree,
                &expected_invocation_token,
                expected_case,
            ),
            CompleteReceiptDispositionV1::Forward,
            "zero-capacity receipt must forward"
        );
        let (capacity_two_sender, mut capacity_two_receiver) = mpsc::channel(2);
        assert_eq!(
            complete_receipt_disposition(
                Some(receipt.clone()),
                Some(&capacity_two_sender),
                &expected_tree,
                &expected_invocation_token,
                expected_case,
            ),
            CompleteReceiptDispositionV1::Forward,
            "capacity-two receipt must forward"
        );
        assert!(capacity_two_receiver.try_recv().is_err());
        must(
            capacity_two_sender.try_send(receipt.clone()),
            "capacity-two partial occupancy",
        );
        assert_eq!(
            complete_receipt_disposition(
                Some(receipt.clone()),
                Some(&capacity_two_sender),
                &expected_tree,
                &expected_invocation_token,
                expected_case,
            ),
            CompleteReceiptDispositionV1::Forward,
            "partially occupied capacity-two receipt must forward"
        );
        assert_eq!(
            must(capacity_two_receiver.try_recv(), "occupied receipt absent"),
            receipt
        );
        let (full_sender, mut full_receiver) = mpsc::channel(1);
        must(full_sender.try_send(receipt.clone()), "full receipt setup");
        assert_eq!(
            complete_receipt_disposition(
                Some(receipt.clone()),
                Some(&full_sender),
                &expected_tree,
                &expected_invocation_token,
                expected_case,
            ),
            CompleteReceiptDispositionV1::Forward,
            "full capacity-one receipt must forward"
        );
        assert_eq!(
            must(full_receiver.try_recv(), "full receipt missing"),
            receipt
        );
        let (closed_sender, closed_receiver) = mpsc::channel(1);
        drop(closed_receiver);
        assert_eq!(
            complete_receipt_disposition(
                Some(receipt.clone()),
                Some(&closed_sender),
                &expected_tree,
                &expected_invocation_token,
                expected_case,
            ),
            CompleteReceiptDispositionV1::Forward,
            "closed capacity-one receipt must forward"
        );

        let mut missing = receipt.clone();
        missing.observation_ledger_canonical_hex.clear();
        let mut invalid = receipt.clone();
        invalid.observation_ledger_sha256 = "0".repeat(64);
        let mut partial_value: serde_json::Value = must(
            serde_json::from_slice(&reopened_ledger),
            "partial ledger decode",
        );
        must_some(
            partial_value
                .get_mut("private_exchanges")
                .and_then(serde_json::Value::as_array_mut),
            "partial private exchanges",
        )
        .pop();
        let partial_bytes = must(canonical_wire_bytes(&partial_value), "partial ledger bytes");
        let partial = LedgerBoundCompleteReceiptV1 {
            schema_version: 1,
            observation_ledger_sha256: sha256_hex(&partial_bytes),
            observation_ledger_canonical_hex: hex::encode(partial_bytes),
        };
        let mut proxy_cross_copy_value: serde_json::Value = must(
            serde_json::from_slice(&reopened_ledger),
            "proxy cross-copy ledger decode",
        );
        let substitute_proxy = must_some(
            proxy_cross_copy_value
                .get("private_exchanges")
                .and_then(serde_json::Value::as_array)
                .and_then(|rows| rows.get(1)),
            "proxy cross-copy substitute absent",
        )
        .clone();
        must_some(
            proxy_cross_copy_value
                .get_mut("proxy_exchanges")
                .and_then(serde_json::Value::as_array_mut)
                .and_then(|rows| rows.get_mut(0)),
            "proxy cross-copy target absent",
        )
        .clone_from(&substitute_proxy);
        refresh_ledger_array_digest(
            &mut proxy_cross_copy_value,
            "proxy_exchanges",
            "proxy_exchanges_sha256",
        );
        let proxy_cross_copy = complete_receipt_from_ledger_value(&proxy_cross_copy_value);

        let mut publisher_fabrication_value: serde_json::Value = must(
            serde_json::from_slice(&reopened_ledger),
            "publisher fabrication ledger decode",
        );
        must_some(
            publisher_fabrication_value
                .get_mut("publisher_attempts")
                .and_then(serde_json::Value::as_array_mut)
                .and_then(|rows| rows.get_mut(0))
                .and_then(serde_json::Value::as_object_mut),
            "publisher fabrication target absent",
        )
        .insert("ordinal".to_string(), serde_json::Value::from(9_u64));
        refresh_ledger_array_digest(
            &mut publisher_fabrication_value,
            "publisher_attempts",
            "publisher_attempts_sha256",
        );
        let publisher_fabrication =
            complete_receipt_from_ledger_value(&publisher_fabrication_value);
        for (label, candidate) in [
            ("missing", missing),
            ("invalid", invalid),
            ("partial", partial),
            ("proxy cross-copy", proxy_cross_copy),
            ("publisher fabrication", publisher_fabrication),
        ] {
            let (sender, mut receiver) = mpsc::channel(1);
            assert_eq!(
                complete_receipt_disposition(
                    Some(candidate),
                    Some(&sender),
                    &expected_tree,
                    &expected_invocation_token,
                    expected_case,
                ),
                CompleteReceiptDispositionV1::Forward,
                "{label} complete receipt suppressed"
            );
            assert!(receiver.try_recv().is_err());
        }
        println!(
            "complete_receipt_ledger rows=1 private=3 proxy=1 publisher=2 worker=12 current_invocation=bound capacity=0,1,2,2-partial full=forward closed=forward passed=1"
        );
        if std::env::var_os("PHASE285_TOPOLOGY_CONFIG_PATH").is_some() {
            run_topology_projection_test();
        }
    }
}

#[cfg(test)]
mod service_checkpoint_observation_tests {
    #[test]
    fn worker_observations_are_real_and_reconciled() {
        assert!(
            std::env::var_os("SWARM_NATS_STORE_TLS_URL").is_some(),
            "normal NATS harness is required"
        );
        super::deadline_state_machine_tests::run_worker_observation_test();
    }
}

#[cfg(test)]
mod service_checkpoint_relay_tests {
    #[test]
    fn complete_receipt_authority_and_grants_are_observed() {
        assert!(
            std::env::var_os("SWARM_NATS_STORE_TLS_URL").is_some(),
            "normal NATS harness is required"
        );
        super::deadline_state_machine_tests::run_complete_receipt_suppression_test();
    }
}
