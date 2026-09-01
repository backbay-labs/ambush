#![forbid(unsafe_code)]

//! Downstream transport boundary for the authenticated governance witness.

mod initializer;
mod jetstream_store;
mod nats_config;
mod public_dispatcher;
pub mod raw_config;
mod runtime_client;
mod secure_file;
mod service_config;
mod store_proxy_service;

pub use initializer::{
    StoreInitializerErrorV1, StoreInitializerProcessConfigV1, initialize_store,
    load_store_initializer_process_config,
};
pub use jetstream_store::NatsWitnessStore;
pub use public_dispatcher::{
    PublicWitnessDispatchErrorV1, PublicWitnessDispatchMappingV1, PublicWitnessDispatcher,
    PublicWitnessProxyTransportErrorV1, PublicWitnessRunnerErrorV1, PublicWitnessServiceRunner,
    PublicWitnessStoreProxyClient, dispatcher_mapping, public_witness_ingress_overload_control,
};
pub use runtime_client::{
    RuntimeWitnessClient, RuntimeWitnessClientErrorV1, WitnessProcessErrorV1,
    load_public_witness_process_config, load_store_proxy_process_config,
    run_public_witness_process, run_store_proxy_process,
};
pub use service_config::{
    PublicWitnessProcessConfigV1, PublicWitnessServiceConfigV1, RuntimeWitnessClientConfigV1,
    StoreProxyProcessConfigV1, StoreProxyServiceConfigV1, public_response_grant_millis,
    response_grant_maximum, store_response_grant_millis,
};
pub use store_proxy_service::{
    NatsPublicWitnessStoreProxyClient, StoreProxyRunnerErrorV1, StoreProxyService,
    StoreProxyServiceErrorV1, StoreProxyServiceRunner, StoreRoleConnectionV1,
    private_store_ingress_overload_control, store_proxy_subjects,
};

#[cfg(test)]
mod deadline_state_machine_tests {
    use super::public_dispatcher::{
        PublicIngressMessage, admit_public_subscription_message, classify_proxy_transport_for_test,
        receive_and_run_public_worker_message, run_public_worker_message,
    };
    use super::runtime_client::RuntimeRequestObservationV1;
    use super::service_config::{
        PUBLIC_HANDLER_DEADLINE_MILLIS, PUBLIC_HANDLER_RESERVE_MILLIS,
        PUBLIC_PRIVATE_RESERVE_MILLIS, PUBLIC_RESPONSE_GRANT_MILLIS, RESPONSE_GRANT_MAXIMUM,
        ReceiptDeadlineV1, ResponsePreEnqueueCaptureV1, ResponsePreEnqueueObserverV1,
        STORE_HANDLER_DEADLINE_MILLIS, STORE_HANDLER_RESERVE_MILLIS, STORE_RESPONSE_GRANT_MILLIS,
        SubscriberAdmissionObserverV1, SubscriberAdmissionReceiptV1, SubscriberPollGateV1,
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
        RuntimeWitnessClientConfigV1, RuntimeWitnessClientErrorV1, StoreProxyService,
        StoreProxyServiceConfigV1, StoreProxyServiceErrorV1, StoreProxyServiceRunner,
        StoreRoleConnectionV1,
    };
    use async_trait::async_trait;
    use futures_util::StreamExt;
    use serde::{Deserialize, Serialize};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Instant as MonotonicInstant;
    use swarm_crypto::{Ed25519Signer, sha256_hex};
    use swarm_governance::persistence_protocol::*;
    use swarm_governance::witness_engine::store::{
        WitnessAdmissionEntryV1, WitnessAdmissionSetV1, WitnessAtomicStore, WitnessBucketAnchorV1,
        WitnessBucketEpochV1, WitnessBucketManifestPhaseV1, WitnessBucketManifestV1,
        WitnessStoreCasResultV1, WitnessStoreDeploymentInputsV1, WitnessStoreErrorV1,
        WitnessStoreProxyFailureCodeV1, WitnessStoreProxyOperationV1,
        WitnessStoreProxyRequestBodyV1, WitnessStoreProxyRequestV1,
        WitnessStoreProxyResponseBodyV1, WitnessStoreProxyResponseV1, WitnessStoreReadResultV1,
        WitnessStoreReadyResultV1, WitnessStreamInitializationRecordV1,
        WitnessStreamInitializationV1, in_memory::InMemoryWitnessStore,
    };
    use swarm_governance::witness_engine::{WitnessStoreEnvelopeV1, witness_stream_key};
    use swarm_governance::witness_service::{
        WitnessAdmissionRecordV1, WitnessServiceOperationV1, WitnessServiceRequestBodyV1,
        WitnessServiceRequestV1, WitnessServiceResponseV1,
    };
    use tokio::sync::{Mutex as TokioMutex, Notify, mpsc, oneshot};
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

    fn must_err<T, E>(result: Result<T, E>, label: &str) -> E {
        match result {
            Ok(_) => panic!("{label}"),
            Err(error) => error,
        }
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
        fn sequence(&self) -> u64 {
            must(
                u64::try_from(
                    self.events
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .len(),
                ),
                "worker-transition sequence overflow",
            )
        }

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
            let mut response_enqueues = 0;
            let mut outcome_unknown = false;
            for event in events.iter() {
                match event {
                    WorkerTransitionEventV1::ReceiptDeadlineIdentity { .. } => {}
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
                    WorkerTransitionEventV1::ResponseEnqueueAttempt { enqueued, .. } => {
                        response_enqueues += u64::from(*enqueued);
                    }
                    WorkerTransitionEventV1::OutcomeUnknown => outcome_unknown = true,
                    WorkerTransitionEventV1::ResponseDeadlineCheck { .. } => {}
                }
            }
            DeadlineEvidenceV1 {
                ordered_trace: events
                    .iter()
                    .filter(|event| {
                        !matches!(
                            event,
                            WorkerTransitionEventV1::ReceiptDeadlineIdentity { .. }
                        )
                    })
                    .cloned()
                    .collect(),
                queue_dequeues,
                preflights,
                store_calls,
                private_proxy_calls,
                cas_attempted,
                cas_applied,
                retries,
                response_enqueues,
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
                evidence.response_enqueues,
                publisher.response_enqueues.load(Ordering::SeqCst) as u64,
                "response-enqueue event diverged from recording publisher"
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
        response_enqueues: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl WorkerPublisherV1 for RecordingPublisherV1 {
        async fn publish(&self, _reply: async_nats::Subject, _payload: Vec<u8>) -> bool {
            sleep(Duration::from_millis(self.delay_millis)).await;
            self.response_enqueues.fetch_add(1, Ordering::SeqCst);
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
        response_enqueues: u64,
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

    fn verified_cas_evidence(
        records: &[StoreObservationV1],
    ) -> Result<(usize, usize), &'static str> {
        let mut attempted = 0;
        let mut applied = 0;
        for record in records
            .iter()
            .filter(|record| record.operation == "compare_and_swap")
        {
            attempted += 1;
            let bytes =
                hex::decode(&record.result_canonical_hex).map_err(|_| "store CAS result hex")?;
            if sha256_hex(&bytes) != record.result_sha256 {
                return Err("store CAS result digest");
            }
            let result: WitnessStoreCasResultV1 =
                serde_json::from_slice(&bytes).map_err(|_| "store CAS result decode")?;
            if canonical_wire_bytes(&result).map_err(|_| "store CAS result canonical")? != bytes {
                return Err("store CAS result canonical");
            }
            let result_applied = matches!(result, WitnessStoreCasResultV1::Applied { .. });
            if record.cas_applied != result_applied {
                return Err("store CAS evidence disagrees with authoritative result");
            }
            applied += usize::from(result_applied);
        }
        Ok((attempted, applied))
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

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct ProxyRequestObservationV1 {
        operation: WitnessStoreProxyOperationV1,
        request_digest: String,
        request_canonical_hex: String,
        request_sha256: String,
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
        request_records: Arc<Mutex<Vec<ProxyRequestObservationV1>>>,
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
            self.request_records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(ProxyRequestObservationV1 {
                    operation,
                    request_digest: request_digest.clone(),
                    request_canonical_hex: hex::encode(&request_bytes),
                    request_sha256: sha256_hex(&request_bytes),
                });
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
        let configuration = super::nats_config::projected_configuration(
            "phase285_service",
            i64::try_from(required_bucket_bytes)
                .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?,
            i32::try_from(max_value_bytes).map_err(|_| ProtocolError::WitnessOutcomeMismatch)?,
            1,
        );
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
            current_session_generation: envelope
                .session
                .as_ref()
                .map(|session| session.session_generation),
            current_session_digest: envelope
                .session
                .as_ref()
                .map(|session| {
                    digest_domain(
                        WITNESS_SESSION_STATE_DOMAIN_V1,
                        &canonical_wire_bytes(session)?,
                    )
                })
                .transpose()?,
            current_head_digest: envelope
                .current
                .as_ref()
                .map(|stored| stored.head.head_digest())
                .transpose()?,
            current_prepared_digest: envelope
                .prepared
                .as_ref()
                .map(|stored| {
                    digest_domain(
                        WITNESS_PREPARED_STATE_DOMAIN_V1,
                        &canonical_wire_bytes(&stored.prepared)?,
                    )
                })
                .transpose()?,
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
                    MAX_PROTOCOL_RECORD_BYTES,
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
            response_enqueues: Arc::new(AtomicUsize::new(0)),
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
            admit_public_subscription_message(
                subject,
                message,
                &sender,
                &admission_observer,
                MAX_PROTOCOL_RECORD_BYTES,
            ),
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
            response_enqueues: Arc::new(AtomicUsize::new(0)),
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

    async fn private_deadline_request_route() -> ProtocolResult<(async_nats::Client, String)> {
        if std::env::var_os("SWARM_NATS_RELAY_CREDENTIAL_PATH").is_some() {
            return Ok((
                connect_deadline_role("SWARM_NATS_RELAY_CREDENTIAL_PATH", "relay").await?,
                "swarm.governance.witness.relay.forward.store.v1.read_entry".to_string(),
            ));
        }
        Ok((
            connect_deadline_role("SWARM_NATS_WITNESS_CREDENTIAL_PATH", "witness").await?,
            store_proxy_subjects()[1].to_string(),
        ))
    }

    async fn public_deadline_request_route(
        ordinary_subject: &str,
    ) -> ProtocolResult<(async_nats::Client, String)> {
        if std::env::var_os("SWARM_NATS_RELAY_CREDENTIAL_PATH").is_some() {
            let suffix = ordinary_subject
                .strip_prefix("swarm.governance.witness.v1.")
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            return Ok((
                connect_deadline_role("SWARM_NATS_RELAY_CREDENTIAL_PATH", "relay").await?,
                format!("swarm.governance.witness.relay.forward.v1.{suffix}"),
            ));
        }
        Ok((
            connect_deadline_role("SWARM_NATS_RUNTIME_CREDENTIAL_PATH", "runtime").await?,
            ordinary_subject.to_string(),
        ))
    }

    async fn initialize_deadline_stream() -> ProtocolResult<()> {
        let client = connect_deadline_role("SWARM_NATS_INIT_CREDENTIAL_PATH", "init").await?;
        let context = async_nats::jetstream::new(client);
        match context.get_stream("KV_phase285_service").await {
            Ok(_) => Ok(()),
            Err(_) => context
                .create_stream(async_nats::jetstream::stream::Config {
                    name: "KV_phase285_service".to_string(),
                    subjects: super::nats_config::projected_configuration(
                        "phase285_service",
                        1,
                        1,
                        1,
                    )
                    .subjects,
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
        private_second_responses: usize,
        public_second_responses: usize,
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
            private_second_responses: 0,
            public_second_responses: 0,
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
    fn oversized_subscription_payloads_are_rejected_before_typed_ingress() {
        const LIMIT: usize = 4;
        let payload = vec![0_u8; LIMIT + 1];

        let (public_sender, mut public_receiver) = mpsc::channel(1);
        let (public_receipt_sender, mut public_receipt_receiver) = mpsc::channel(1);
        let public_observer = RecordingSubscriberAdmissionObserverV1 {
            sender: public_receipt_sender,
        };
        let public_subject = "swarm.governance.witness.v1.fence";
        let public_message = async_nats::Message {
            subject: public_subject.into(),
            reply: Some("_INBOX.phase285-public-oversized".into()),
            payload: payload.clone().into(),
            headers: None,
            status: None,
            description: None,
            length: payload.len(),
        };
        assert!(!admit_public_subscription_message(
            public_subject,
            public_message,
            &public_sender,
            &public_observer,
            LIMIT,
        ));
        assert!(public_receiver.try_recv().is_err());
        assert!(public_receipt_receiver.try_recv().is_err());

        let (private_sender, mut private_receiver) = mpsc::channel(1);
        let (private_receipt_sender, mut private_receipt_receiver) = mpsc::channel(1);
        let private_observer = RecordingSubscriberAdmissionObserverV1 {
            sender: private_receipt_sender,
        };
        let private_subject = store_proxy_subjects()[1];
        let private_message = async_nats::Message {
            subject: private_subject.into(),
            reply: Some("_INBOX.phase285-private-oversized".into()),
            payload: payload.clone().into(),
            headers: None,
            status: None,
            description: None,
            length: payload.len(),
        };
        assert!(
            admit_private_subscription_message(
                private_subject,
                private_message,
                &private_sender,
                &private_observer,
                LIMIT,
            )
            .is_none()
        );
        assert!(private_receiver.try_recv().is_err());
        assert!(private_receipt_receiver.try_recv().is_err());
    }

    #[test]
    #[ignore = "requires the authenticated Phase 285 NATS topology and credential artifacts"]
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
        let (private_requester, private_subject) = must(
            private_deadline_request_route().await,
            "private deadline request route",
        );
        private_fixture
            .block_next_read
            .store(true, Ordering::SeqCst);
        let (mut private_first_response, _) = must(
            publish_deadline_request(
                &private_requester,
                &private_subject,
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
            publish_deadline_request(&private_requester, &private_subject, private_payload).await,
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
            "deadline_r24_private_late_first_response"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(150), private_second_response.next())
                .await
                .is_err(),
            "deadline_r24_private_second_response"
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
        let public_request = must(public_fixture.fence_request(), "public request");
        let public_payload = must(public_request.canonical_bytes(), "public payload");
        let public_subject = PublicWitnessServiceConfigV1::subject_for(public_request.operation);
        let (public_requester, public_request_subject) = must(
            public_deadline_request_route(public_subject).await,
            "public deadline request route",
        );
        let (mut public_first_response, _) = must(
            publish_deadline_request(
                &public_requester,
                &public_request_subject,
                public_payload.clone(),
            )
            .await,
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
            publish_deadline_request(&public_requester, &public_request_subject, public_payload)
                .await,
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
            "deadline_r24_public_late_first_response"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(150), public_second_response.next())
                .await
                .is_err(),
            "deadline_r24_public_second_response"
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
            response_enqueues: Arc::new(AtomicUsize::new(0)),
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
            publisher.response_enqueues.load(Ordering::SeqCst),
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
            response_enqueues: Arc::new(AtomicUsize::new(0)),
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
        assert_eq!(publisher.response_enqueues.load(Ordering::SeqCst), 0);
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
            response_enqueues: Arc::new(AtomicUsize::new(0)),
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
        assert_eq!(publisher.response_enqueues.load(Ordering::SeqCst), 0);
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
            response_enqueues: Arc::new(AtomicUsize::new(0)),
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
        assert_eq!(publisher.response_enqueues.load(Ordering::SeqCst), 0);
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
            response_enqueues: Arc::new(AtomicUsize::new(0)),
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
        assert_eq!(publisher.response_enqueues.load(Ordering::SeqCst), 0);
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
            response_enqueues: Arc::new(AtomicUsize::new(0)),
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
        assert_eq!(publisher.response_enqueues.load(Ordering::SeqCst), 0);
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
                (1, 1, 0, 1, 0, 0, 0, 0, true),
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
                WorkerTransitionEventV1::ResponseDeadlineCheck {
                    worker: WorkerKindV1::Private,
                    open: false,
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
                WorkerTransitionEventV1::OutcomeUnknown,
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
                WorkerTransitionEventV1::ResponseDeadlineCheck {
                    worker: WorkerKindV1::Public,
                    open: false,
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
                    evidence.response_enqueues,
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
            response_enqueues: Arc::new(AtomicUsize::new(0)),
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
    struct ResponseEnqueueObservationV1 {
        ordinal: usize,
        worker: WorkerKindV1,
        enqueued: bool,
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
        response_enqueue_attempts: usize,
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
        response_enqueue_attempts_sha256: String,
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
        response_enqueue_attempts: Vec<ResponseEnqueueObservationV1>,
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

    const OBSERVATION_EXACT_RETRY_ATTEMPTS: usize = 5;
    const OBSERVATION_EXACT_RETRY_DELAY: Duration = Duration::from_millis(25);

    fn server_connection_observation(
        runner_role: &'static str,
        expected_account: &str,
        credential_path_variable: &str,
        credential_role: &str,
        server_client_id: u64,
    ) -> ConnectionObservationV1 {
        assert!(server_client_id > 0, "observation server client ID absent");
        let response = must(relay_connz(), "observation monitor request");
        let connections = must(
            relay_connz_records(&response),
            "observation monitor snapshot incomplete",
        );
        let record = must_some(
            must(
                relay_record_for_client_id(connections, server_client_id),
                "observation server connection ambiguous",
            ),
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

    struct HeldPublicRelayResponseV1 {
        request_bytes: Vec<u8>,
        response_bytes: Vec<u8>,
        decision: oneshot::Sender<bool>,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RelaySubscriptionOmissionV1 {
        None,
        Public,
        Private,
    }

    struct LiveRelayLegsV1 {
        public_client: async_nats::Client,
        private_client: async_nats::Client,
        public_client_id: u64,
        private_client_id: u64,
        public_subscription_count: usize,
        private_subscription_count: usize,
        held_response: mpsc::Receiver<HeldPublicRelayResponseV1>,
        tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct RelayTeardownEvidenceV1 {
        tasks_joined: usize,
        old_identities_absent: usize,
        clients_drained: usize,
        public_client_drained: bool,
        private_client_drained: bool,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct RelayReadinessEvidenceV1 {
        new_identities_present: usize,
        public_subscriptions: usize,
        private_subscriptions: usize,
        wildcard_subscriptions: usize,
    }

    fn public_relay_subjects() -> Vec<String> {
        [
            WitnessServiceOperationV1::Fence,
            WitnessServiceOperationV1::Establish,
            WitnessServiceOperationV1::Discover,
            WitnessServiceOperationV1::Prepare,
            WitnessServiceOperationV1::Commit,
            WitnessServiceOperationV1::Abort,
            WitnessServiceOperationV1::ReadPrepared,
            WitnessServiceOperationV1::ReadHead,
            WitnessServiceOperationV1::FetchPayload,
        ]
        .into_iter()
        .map(|operation| {
            let ordinary = PublicWitnessServiceConfigV1::subject_for(operation);
            let suffix = ordinary
                .strip_prefix("swarm.governance.witness.v1.")
                .unwrap_or_else(|| panic!("relay public subject prefix differs"));
            format!("swarm.governance.witness.relay.v1.{suffix}")
        })
        .collect()
    }

    fn private_relay_subjects() -> Vec<String> {
        store_proxy_subjects()
            .iter()
            .map(|ordinary| {
                let suffix = ordinary
                    .strip_prefix("swarm.governance.witness.store.v1.")
                    .unwrap_or_else(|| panic!("relay private subject prefix differs"));
                format!("swarm.governance.witness.relay.store.v1.{suffix}")
            })
            .collect()
    }

    fn exact_public_relay_subjects() -> BTreeSet<String> {
        BTreeSet::from([
            "swarm.governance.witness.relay.v1.fence".to_string(),
            "swarm.governance.witness.relay.v1.establish".to_string(),
            "swarm.governance.witness.relay.v1.discover".to_string(),
            "swarm.governance.witness.relay.v1.prepare".to_string(),
            "swarm.governance.witness.relay.v1.commit".to_string(),
            "swarm.governance.witness.relay.v1.abort".to_string(),
            "swarm.governance.witness.relay.v1.read_prepared".to_string(),
            "swarm.governance.witness.relay.v1.read_head".to_string(),
            "swarm.governance.witness.relay.v1.fetch_payload".to_string(),
        ])
    }

    fn exact_private_relay_subjects() -> BTreeSet<String> {
        BTreeSet::from([
            "swarm.governance.witness.relay.store.v1.inspect_ready".to_string(),
            "swarm.governance.witness.relay.store.v1.read_entry".to_string(),
            "swarm.governance.witness.relay.store.v1.compare_and_swap".to_string(),
        ])
    }

    fn relay_curl_path() -> ProtocolResult<PathBuf> {
        let raw = std::env::var("PHASE285_CONNZ_CURL_BIN")
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        let path = PathBuf::from(raw);
        if !path.is_absolute() {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.mode() & 0o111 == 0
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let canonical =
            std::fs::canonicalize(&path).map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        if canonical != path {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(path)
    }

    fn read_relay_command_pipe<R: Read>(
        mut reader: R,
        limit: usize,
        overflow: std::sync::mpsc::Sender<()>,
    ) -> std::io::Result<(Vec<u8>, bool)> {
        let mut captured = Vec::with_capacity(limit.min(8_192));
        let mut total = 0_usize;
        let mut exceeded = false;
        let mut chunk = [0_u8; 8_192];
        loop {
            let read = reader.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            total = total.checked_add(read).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "relay pipe length overflow",
                )
            })?;
            if total > limit {
                if !exceeded {
                    exceeded = true;
                    let _ = overflow.send(());
                }
            } else {
                captured.extend_from_slice(&chunk[..read]);
            }
        }
        Ok((captured, exceeded))
    }

    fn relay_connz() -> ProtocolResult<serde_json::Value> {
        let monitor_url = std::env::var("SWARM_NATS_TLS_HTTP_URL")
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        let maximum = MAX_PROTOCOL_RECORD_BYTES.to_string();
        let mut child = std::process::Command::new(relay_curl_path()?)
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "2",
                "--max-filesize",
                &maximum,
                &format!("{monitor_url}/connz?auth=1&subs=1"),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProtocolError::WitnessOutcomeMismatch);
        };
        let (overflow_tx, overflow_rx) = std::sync::mpsc::channel();
        let stderr_overflow_tx = overflow_tx.clone();
        let stdout_reader = std::thread::spawn(move || {
            read_relay_command_pipe(stdout, MAX_PROTOCOL_RECORD_BYTES, overflow_tx)
        });
        let stderr_reader = std::thread::spawn(move || {
            read_relay_command_pipe(stderr, MAX_PROTOCOL_RECORD_BYTES, stderr_overflow_tx)
        });
        let deadline = MonotonicInstant::now() + Duration::from_secs(3);
        let mut overflowed = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ProtocolError::WitnessOutcomeMismatch);
                }
            }
            if overflow_rx.recv_timeout(Duration::from_millis(10)).is_ok()
                || MonotonicInstant::now() >= deadline
            {
                overflowed = true;
                let _ = child.kill();
                break child
                    .wait()
                    .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
            }
        };
        let (stdout, stdout_exceeded) = stdout_reader
            .join()
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        let (_stderr, stderr_exceeded) = stderr_reader
            .join()
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        if overflowed
            || stdout_exceeded
            || stderr_exceeded
            || !status.success()
            || stdout.is_empty()
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        serde_json::from_slice(&stdout).map_err(|_| ProtocolError::WitnessOutcomeMismatch)
    }

    fn relay_connz_records(value: &serde_json::Value) -> ProtocolResult<&Vec<serde_json::Value>> {
        let records = value
            .get("connections")
            .and_then(serde_json::Value::as_array)
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        let offset = value
            .get("offset")
            .and_then(serde_json::Value::as_u64)
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        let total = value
            .get("total")
            .and_then(serde_json::Value::as_u64)
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        let limit = value
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        let num_connections = value
            .get("num_connections")
            .and_then(serde_json::Value::as_u64)
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        let observed =
            u64::try_from(records.len()).map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        if offset != 0 || total != num_connections || num_connections != observed || limit < total {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let mut client_ids = BTreeSet::new();
        for record in records {
            let client_id = record
                .get("cid")
                .and_then(serde_json::Value::as_u64)
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            if client_id == 0 || !client_ids.insert(client_id) {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
        Ok(records)
    }

    fn relay_record_for_client_id(
        records: &[serde_json::Value],
        client_id: u64,
    ) -> ProtocolResult<Option<&serde_json::Value>> {
        if client_id == 0 {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let mut matches = records.iter().filter(|record| {
            record.get("cid").and_then(serde_json::Value::as_u64) == Some(client_id)
        });
        let record = matches.next();
        if matches.next().is_some() {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(record)
    }

    fn relay_record_subjects(record: &serde_json::Value) -> ProtocolResult<BTreeSet<String>> {
        let declared = record
            .get("subscriptions")
            .and_then(serde_json::Value::as_u64)
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        let values = match record
            .get("subscriptions_list")
            .and_then(serde_json::Value::as_array)
        {
            Some(values) => values.as_slice(),
            None if declared == 0 => &[],
            None => return Err(ProtocolError::WitnessOutcomeMismatch),
        };
        let mut subjects = BTreeSet::new();
        for value in values {
            let subject = value
                .as_str()
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?
                .to_string();
            if !subjects.insert(subject) {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
        }
        if u64::try_from(subjects.len()).ok() != Some(declared) {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        Ok(subjects)
    }

    fn relay_subject_sets_are_exact(
        public_subjects: &BTreeSet<String>,
        private_subjects: &BTreeSet<String>,
        expected_public: &BTreeSet<String>,
        expected_private: &BTreeSet<String>,
    ) -> bool {
        public_subjects == expected_public && private_subjects == expected_private
    }

    async fn await_relay_subject_sets(
        public_client_id: u64,
        private_client_id: u64,
        expected_public: &BTreeSet<String>,
        expected_private: &BTreeSet<String>,
    ) -> ProtocolResult<RelayReadinessEvidenceV1> {
        let expected_user = credential_user("SWARM_NATS_RELAY_CREDENTIAL_PATH", "relay");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let connz = relay_connz()?;
            let records = relay_connz_records(&connz)?;
            if let (Some(public_record), Some(private_record)) = (
                relay_record_for_client_id(records, public_client_id)?,
                relay_record_for_client_id(records, private_client_id)?,
            ) {
                let authority_is_exact =
                    [public_record, private_record].into_iter().all(|record| {
                        record.get("account").and_then(serde_json::Value::as_str)
                            == Some("PHASE285_RELAY")
                            && record
                                .get("authorized_user")
                                .and_then(serde_json::Value::as_str)
                                == Some(expected_user.as_str())
                    });
                let public_subjects = relay_record_subjects(public_record)?;
                let private_subjects = relay_record_subjects(private_record)?;
                if authority_is_exact
                    && relay_subject_sets_are_exact(
                        &public_subjects,
                        &private_subjects,
                        expected_public,
                        expected_private,
                    )
                {
                    let wildcard_subscriptions = public_subjects
                        .iter()
                        .chain(private_subjects.iter())
                        .filter(|subject| subject.contains('*') || subject.contains('>'))
                        .count();
                    if wildcard_subscriptions != 0 {
                        return Err(ProtocolError::WitnessOutcomeMismatch);
                    }
                    return Ok(RelayReadinessEvidenceV1 {
                        new_identities_present: 2,
                        public_subscriptions: public_subjects.len(),
                        private_subscriptions: private_subjects.len(),
                        wildcard_subscriptions,
                    });
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn await_relay_identities_absent(
        public_client_id: u64,
        private_client_id: u64,
    ) -> ProtocolResult<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let connz = relay_connz()?;
            let records = relay_connz_records(&connz)?;
            let old_present = relay_record_for_client_id(records, public_client_id)?.is_some()
                || relay_record_for_client_id(records, private_client_id)?.is_some();
            if !old_present {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    type RelayPrivateReleaseControlV1 = (oneshot::Sender<(u64, u64)>, oneshot::Receiver<()>);

    impl LiveRelayLegsV1 {
        async fn start(hold_first_read_head: bool) -> ProtocolResult<Self> {
            Self::start_selective(hold_first_read_head, RelaySubscriptionOmissionV1::None).await
        }

        async fn start_selective(
            hold_first_read_head: bool,
            omission: RelaySubscriptionOmissionV1,
        ) -> ProtocolResult<Self> {
            Self::start_selective_with_private_release(hold_first_read_head, omission, None).await
        }

        async fn start_after_private_release(
            hold_first_read_head: bool,
            private_gate_reached: oneshot::Sender<(u64, u64)>,
            private_release: oneshot::Receiver<()>,
        ) -> ProtocolResult<Self> {
            Self::start_selective_with_private_release(
                hold_first_read_head,
                RelaySubscriptionOmissionV1::None,
                Some((private_gate_reached, private_release)),
            )
            .await
        }

        #[allow(dead_code)]
        async fn start_with_zero_sleep_control(
            hold_first_read_head: bool,
            private_gate_reached: oneshot::Sender<(u64, u64)>,
            private_release: oneshot::Receiver<()>,
        ) -> ProtocolResult<Self> {
            drop(private_release);
            tokio::time::sleep(Duration::ZERO).await;
            let legs = Self::start(hold_first_read_head).await?;
            private_gate_reached
                .send((legs.public_client_id, legs.private_client_id))
                .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
            Ok(legs)
        }

        async fn start_selective_with_private_release(
            hold_first_read_head: bool,
            omission: RelaySubscriptionOmissionV1,
            private_release: Option<RelayPrivateReleaseControlV1>,
        ) -> ProtocolResult<Self> {
            let public_client =
                connect_deadline_role("SWARM_NATS_RELAY_CREDENTIAL_PATH", "relay").await?;
            let private_client =
                connect_deadline_role("SWARM_NATS_RELAY_CREDENTIAL_PATH", "relay").await?;
            let public_client_id = public_client.server_info().client_id;
            let private_client_id = private_client.server_info().client_id;
            if public_client_id == 0
                || private_client_id == 0
                || public_client_id == private_client_id
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
            let (held_sender, held_response) = mpsc::channel(1);
            let held_once = Arc::new(AtomicBool::new(false));
            let mut public_subscriptions = Vec::new();
            let mut public_subscription_count = 0;
            if omission != RelaySubscriptionOmissionV1::Public {
                for (operation, routed) in [
                    WitnessServiceOperationV1::Fence,
                    WitnessServiceOperationV1::Establish,
                    WitnessServiceOperationV1::Discover,
                    WitnessServiceOperationV1::Prepare,
                    WitnessServiceOperationV1::Commit,
                    WitnessServiceOperationV1::Abort,
                    WitnessServiceOperationV1::ReadPrepared,
                    WitnessServiceOperationV1::ReadHead,
                    WitnessServiceOperationV1::FetchPayload,
                ]
                .into_iter()
                .zip(public_relay_subjects())
                {
                    let suffix = routed
                        .strip_prefix("swarm.governance.witness.relay.v1.")
                        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
                    let forward = format!("swarm.governance.witness.relay.forward.v1.{suffix}");
                    let subscriber = public_client
                        .subscribe(routed)
                        .await
                        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
                    public_subscription_count += 1;
                    public_subscriptions.push((operation, forward, subscriber));
                }
            }
            let mut private_subscriptions = Vec::new();
            let mut private_subscription_count = 0;
            if omission != RelaySubscriptionOmissionV1::Private {
                if let Some((gate_reached, release)) = private_release {
                    public_client
                        .flush()
                        .await
                        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
                    private_client
                        .flush()
                        .await
                        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
                    gate_reached
                        .send((public_client_id, private_client_id))
                        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
                    release
                        .await
                        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
                }
                for (index, routed) in private_relay_subjects().into_iter().enumerate() {
                    let suffix = routed
                        .strip_prefix("swarm.governance.witness.relay.store.v1.")
                        .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
                    let forward =
                        format!("swarm.governance.witness.relay.forward.store.v1.{suffix}");
                    let subscriber = private_client
                        .subscribe(routed)
                        .await
                        .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
                    private_subscription_count += 1;
                    private_subscriptions.push((index, forward, subscriber));
                }
            }
            public_client
                .flush()
                .await
                .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
            private_client
                .flush()
                .await
                .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
            let mut tasks = Vec::new();
            for (operation, forward, mut subscriber) in public_subscriptions {
                let client = public_client.clone();
                let held_sender = held_sender.clone();
                let held_once = held_once.clone();
                tasks.push(tokio::spawn(async move {
                    while let Some(message) = subscriber.next().await {
                        let Some(reply) = message.reply.clone() else {
                            continue;
                        };
                        let request_bytes = message.payload.to_vec();
                        let Ok(response) = client.request(forward.clone(), message.payload).await
                        else {
                            continue;
                        };
                        let response_bytes = response.payload.to_vec();
                        let should_hold = hold_first_read_head
                            && operation == WitnessServiceOperationV1::ReadHead
                            && !held_once.swap(true, Ordering::SeqCst);
                        if should_hold {
                            let (decision, decision_receiver) = oneshot::channel();
                            if held_sender
                                .send(HeldPublicRelayResponseV1 {
                                    request_bytes,
                                    response_bytes: response_bytes.clone(),
                                    decision,
                                })
                                .await
                                .is_err()
                            {
                                continue;
                            }
                            if !matches!(decision_receiver.await, Ok(true)) {
                                continue;
                            }
                        }
                        if client.publish(reply, response_bytes.into()).await.is_ok() {
                            let _ = client.flush().await;
                        }
                    }
                }));
            }
            for (index, forward, mut subscriber) in private_subscriptions {
                let client = private_client.clone();
                tasks.push(tokio::spawn(async move {
                    while let Some(message) = subscriber.next().await {
                        let Some(reply) = message.reply.clone() else {
                            continue;
                        };
                        let Ok(response) = client.request(forward.clone(), message.payload).await
                        else {
                            continue;
                        };
                        if client.publish(reply, response.payload).await.is_ok() {
                            let _ = client.flush().await;
                        }
                    }
                    let _ = index;
                }));
            }
            Ok(Self {
                public_client,
                private_client,
                public_client_id,
                private_client_id,
                public_subscription_count,
                private_subscription_count,
                held_response,
                tasks,
            })
        }

        async fn stop_and_confirm(mut self) -> ProtocolResult<RelayTeardownEvidenceV1> {
            let task_inventory_valid = self.tasks.len() == 12;
            for task in &self.tasks {
                task.abort();
            }
            let shutdown_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut tasks_joined = 0_usize;
            let mut task_joins_valid = true;
            while let Some(mut task) = self.tasks.pop() {
                match tokio::time::timeout_at(shutdown_deadline, &mut task).await {
                    Ok(Err(error)) if error.is_cancelled() => match tasks_joined.checked_add(1) {
                        Some(count) => tasks_joined = count,
                        None => task_joins_valid = false,
                    },
                    Ok(Ok(())) | Ok(Err(_)) | Err(_) => task_joins_valid = false,
                }
            }
            let mut clients_drained = 0_usize;
            let public_client_drained = matches!(
                tokio::time::timeout_at(shutdown_deadline, self.public_client.drain()).await,
                Ok(Ok(()))
            );
            if public_client_drained {
                clients_drained += 1;
            }
            let private_client_drained = matches!(
                tokio::time::timeout_at(shutdown_deadline, self.private_client.drain()).await,
                Ok(Ok(()))
            );
            if private_client_drained {
                clients_drained += 1;
            }
            let identities_absent =
                await_relay_identities_absent(self.public_client_id, self.private_client_id)
                    .await
                    .is_ok();
            let evidence = RelayTeardownEvidenceV1 {
                tasks_joined,
                old_identities_absent: usize::from(identities_absent) * 2,
                clients_drained,
                public_client_drained,
                private_client_drained,
            };
            if task_inventory_valid
                && task_joins_valid
                && tasks_joined == 12
                && clients_drained == 2
                && identities_absent
            {
                Ok(evidence)
            } else {
                Err(ProtocolError::WitnessOutcomeMismatch)
            }
        }

        #[allow(dead_code)]
        async fn abort_only_for_control(mut self) -> ProtocolResult<RelayTeardownEvidenceV1> {
            if self.tasks.len() != 12 {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
            for task in &self.tasks {
                task.abort();
            }
            let connz = relay_connz()?;
            let records = relay_connz_records(&connz)?;
            let mut old_identities_present = 0_usize;
            for client_id in [self.public_client_id, self.private_client_id] {
                if relay_record_for_client_id(records, client_id)?.is_some() {
                    old_identities_present += 1;
                }
            }
            if old_identities_present != 2 {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
            self.tasks.clear();
            Ok(RelayTeardownEvidenceV1 {
                tasks_joined: 0,
                old_identities_absent: 0,
                clients_drained: 0,
                public_client_drained: false,
                private_client_drained: false,
            })
        }

        async fn confirm_ready(
            &self,
            old_public_client_id: u64,
            old_private_client_id: u64,
        ) -> ProtocolResult<RelayReadinessEvidenceV1> {
            if self.public_client_id == 0
                || self.private_client_id == 0
                || self.public_client_id == self.private_client_id
                || [self.public_client_id, self.private_client_id]
                    .into_iter()
                    .any(|current| {
                        current == old_public_client_id || current == old_private_client_id
                    })
            {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
            let expected_public = exact_public_relay_subjects();
            let expected_private = exact_private_relay_subjects();
            if expected_public.len() != 9 || expected_private.len() != 3 {
                return Err(ProtocolError::WitnessOutcomeMismatch);
            }
            await_relay_subject_sets(
                self.public_client_id,
                self.private_client_id,
                &expected_public,
                &expected_private,
            )
            .await
        }
    }

    async fn connect_grant_role(
        path_variable: &str,
        expected_role: &str,
    ) -> ProtocolResult<(
        async_nats::Client,
        mpsc::UnboundedReceiver<async_nats::Event>,
    )> {
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
        let (events_sender, events_receiver) = mpsc::unbounded_channel();
        let options = async_nats::ConnectOptions::with_user_and_password(
            credential.username,
            credential.password,
        )
        .require_tls(true)
        .add_root_certificates(ca.into())
        .event_callback(move |event| {
            let sender = events_sender.clone();
            async move {
                let _ = sender.send(event);
            }
        });
        let client = options
            .connect(url)
            .await
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        Ok((client, events_receiver))
    }

    async fn next_grant_request(
        requester: &async_nats::Client,
        responder: &mut async_nats::Subscriber,
        subject: &str,
    ) -> ProtocolResult<(async_nats::Message, async_nats::Subscriber, String)> {
        let reply = requester.new_inbox();
        let replies = requester
            .subscribe(reply.clone())
            .await
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        requester
            .publish_with_reply(
                subject.to_string(),
                reply.clone(),
                b"grant-probe".to_vec().into(),
            )
            .await
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        requester
            .flush()
            .await
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        let request = tokio::time::timeout(Duration::from_secs(2), responder.next())
            .await
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        Ok((request, replies, reply))
    }

    async fn permission_event(
        events: &mut mpsc::UnboundedReceiver<async_nats::Event>,
        reply: &str,
    ) -> ProtocolResult<String> {
        loop {
            let text = next_publish_permission_violation(events).await?;
            if text.contains(reply) {
                return Ok(text);
            }
        }
    }

    async fn next_publish_permission_violation(
        events: &mut mpsc::UnboundedReceiver<async_nats::Event>,
    ) -> ProtocolResult<String> {
        let deadline = MonotonicInstant::now() + std::time::Duration::from_secs(2);
        loop {
            let remaining = deadline
                .checked_duration_since(MonotonicInstant::now())
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            let event = tokio::time::timeout(remaining, events.recv())
                .await
                .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            let text = event.to_string();
            if text.contains("Permissions Violation for Publish to") {
                return Ok(text);
            }
        }
    }

    async fn targeted_admission_receipt(
        receipts: &mut mpsc::Receiver<SubscriberAdmissionReceiptV1>,
        worker: WorkerKindV1,
        subject: &str,
    ) -> ProtocolResult<SubscriberAdmissionReceiptV1> {
        let deadline = MonotonicInstant::now() + std::time::Duration::from_secs(2);
        loop {
            let remaining = deadline
                .checked_duration_since(MonotonicInstant::now())
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            let receipt = tokio::time::timeout(remaining, receipts.recv())
                .await
                .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            if receipt.worker == worker && receipt.subject == subject {
                return Ok(receipt);
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct ResponseCaptureReceiptV1 {
        invocation_token: String,
        physical_case: String,
        capture_id: u64,
        worker: WorkerKindV1,
        reply: String,
        payload_len: usize,
        payload_sha256: String,
        preceding_worker_transition_sequence: u64,
    }

    #[derive(Debug, Clone)]
    struct RecordedResponseCaptureV1 {
        receipt: ResponseCaptureReceiptV1,
        payload: Vec<u8>,
    }

    struct RecordingResponsePreEnqueueObserverV1 {
        sender: mpsc::UnboundedSender<RecordedResponseCaptureV1>,
        next_capture_id: AtomicU64,
        transitions: Arc<RecordingWorkerTransitionObserverV1>,
        invocation_token: String,
        physical_case: String,
    }

    impl ResponsePreEnqueueObserverV1 for RecordingResponsePreEnqueueObserverV1 {
        fn observe(&self, capture: ResponsePreEnqueueCaptureV1) {
            let capture_id = self.next_capture_id.fetch_add(1, Ordering::SeqCst) + 1;
            let receipt = ResponseCaptureReceiptV1 {
                invocation_token: self.invocation_token.clone(),
                physical_case: self.physical_case.clone(),
                capture_id,
                worker: capture.worker,
                reply: capture.reply,
                payload_len: capture.payload.len(),
                payload_sha256: sha256_hex(&capture.payload),
                preceding_worker_transition_sequence: self.transitions.sequence(),
            };
            let _ = self.sender.send(RecordedResponseCaptureV1 {
                receipt,
                payload: capture.payload,
            });
        }
    }

    async fn targeted_response_capture(
        captures: &mut mpsc::UnboundedReceiver<RecordedResponseCaptureV1>,
        worker: WorkerKindV1,
        reply: &str,
    ) -> ProtocolResult<RecordedResponseCaptureV1> {
        let deadline = MonotonicInstant::now() + std::time::Duration::from_secs(3);
        loop {
            let remaining = deadline
                .checked_duration_since(MonotonicInstant::now())
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            let capture = tokio::time::timeout(remaining, captures.recv())
                .await
                .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?
                .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
            if capture.receipt.worker == worker && capture.receipt.reply == reply {
                return Ok(capture);
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct RequesterChildTerminalReceiptV1 {
        invocation_token: String,
        physical_case: String,
        child_task_id: String,
        response_variant: &'static str,
        response_sha256: String,
        child_sequence: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct RequesterParentJoinReceiptV1 {
        invocation_token: String,
        physical_case: String,
        child_task_id: String,
        child_record_sha256: String,
        returned_response_sha256: String,
        parent_sequence: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    enum RequesterJoinLedgerRowV1 {
        Child(RequesterChildTerminalReceiptV1),
        Parent(RequesterParentJoinReceiptV1),
    }

    #[derive(Default)]
    struct RequesterJoinLedgerV1 {
        next_sequence: AtomicU64,
        rows: Mutex<Vec<RequesterJoinLedgerRowV1>>,
    }

    impl RequesterJoinLedgerV1 {
        fn record_child(
            &self,
            invocation_token: &str,
            physical_case: &str,
            child_task_id: &str,
            response: &WitnessServiceResponseV1,
            response_bytes: &[u8],
        ) -> RequesterChildTerminalReceiptV1 {
            assert!(
                matches!(response, WitnessServiceResponseV1::Establish(_)),
                "requester child terminal response variant differs"
            );
            let receipt = RequesterChildTerminalReceiptV1 {
                invocation_token: invocation_token.to_string(),
                physical_case: physical_case.to_string(),
                child_task_id: child_task_id.to_string(),
                response_variant: "establish",
                response_sha256: sha256_hex(response_bytes),
                child_sequence: self.next_sequence.fetch_add(1, Ordering::SeqCst) + 1,
            };
            self.rows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(RequesterJoinLedgerRowV1::Child(receipt.clone()));
            receipt
        }

        fn record_parent(
            &self,
            invocation_token: &str,
            physical_case: &str,
            child_task_id: &str,
            child: &RequesterChildTerminalReceiptV1,
            returned_response_bytes: &[u8],
        ) -> RequesterParentJoinReceiptV1 {
            let child_record_sha256 = sha256_hex(&must(
                canonical_wire_bytes(child),
                "requester child terminal receipt bytes",
            ));
            let returned_response_sha256 = sha256_hex(returned_response_bytes);
            let child_is_recorded = self
                .rows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .any(|row| row == &RequesterJoinLedgerRowV1::Child(child.clone()));
            assert!(child_is_recorded, "requester child terminal record absent");
            assert_eq!(child.invocation_token, invocation_token);
            assert_eq!(child.physical_case, physical_case);
            assert_eq!(child.child_task_id, child_task_id);
            assert_eq!(child.response_sha256, returned_response_sha256);
            let receipt = RequesterParentJoinReceiptV1 {
                invocation_token: invocation_token.to_string(),
                physical_case: physical_case.to_string(),
                child_task_id: child_task_id.to_string(),
                child_record_sha256,
                returned_response_sha256,
                parent_sequence: self.next_sequence.fetch_add(1, Ordering::SeqCst) + 1,
            };
            assert!(receipt.parent_sequence > child.child_sequence);
            self.rows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(RequesterJoinLedgerRowV1::Parent(receipt.clone()));
            receipt
        }

        fn contains_parent(&self, receipt: &RequesterParentJoinReceiptV1) -> bool {
            self.rows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .any(|row| row == &RequesterJoinLedgerRowV1::Parent(receipt.clone()))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct PublicRecoveryOperandReceiptV1 {
        left_kind: &'static str,
        left_capture_id: u64,
        left_sha256: String,
        right_kind: &'static str,
        right_sha256: String,
        equal: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct PrivateCasJoinReceiptV1 {
        capture_id: u64,
        capture_sha256: String,
        cas_request_digest: String,
        cas_request_sha256: String,
        store_result_sha256: String,
        proposed_envelope_sha256: String,
        proposed_envelope_digest: String,
        final_read_sha256: String,
        rotation_receipt_sha256: String,
        outer_attestation_sha256: String,
        new_revision: u64,
    }

    struct PrivateCasJoinContextV1<'a> {
        public_request: &'a WitnessServiceRequestV1,
        challenge: &'a RecoveryChallengeV1,
        binding: &'a PublicationBindingV1,
        outer_response: &'a WitnessServiceResponseV1,
    }

    fn validate_private_cas_join(
        capture: &RecordedResponseCaptureV1,
        proxy_records: &[ProxyRequestObservationV1],
        store_records: &[StoreObservationV1],
        final_read: &WitnessStoreProxyResponseV1,
        context: PrivateCasJoinContextV1<'_>,
    ) -> ProtocolResult<PrivateCasJoinReceiptV1> {
        let PrivateCasJoinContextV1 {
            public_request,
            challenge,
            binding,
            outer_response,
        } = context;
        if capture.receipt.worker != WorkerKindV1::Private
            || capture.receipt.payload_len != capture.payload.len()
            || capture.receipt.payload_sha256 != sha256_hex(&capture.payload)
            || capture.receipt.capture_id == 0
            || capture.receipt.preceding_worker_transition_sequence == 0
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let private_response = WitnessStoreProxyResponseV1::decode(&capture.payload)?;
        private_response.validate()?;
        let (
            response_stream_id,
            response_previous_revision,
            response_new_revision,
            response_acknowledged_digest,
        ) = match &private_response.body {
            WitnessStoreProxyResponseBodyV1::CasApplied {
                stream_id,
                previous_revision,
                new_revision,
                acknowledged_value_digest,
            } => (
                stream_id,
                *previous_revision,
                *new_revision,
                acknowledged_value_digest,
            ),
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        };
        if private_response.operation != WitnessStoreProxyOperationV1::CompareAndSwap {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let proxy_record = proxy_records
            .iter()
            .find(|record| {
                record.operation == WitnessStoreProxyOperationV1::CompareAndSwap
                    && record.request_digest == private_response.request_digest
            })
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        let cas_request_bytes = hex::decode(&proxy_record.request_canonical_hex)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        if sha256_hex(&cas_request_bytes) != proxy_record.request_sha256 {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let cas_request = WitnessStoreProxyRequestV1::decode(&cas_request_bytes)?;
        cas_request.validate_structure()?;
        cas_request.validate_semantics()?;
        cas_request.validate_signature()?;
        if cas_request.request_digest != private_response.request_digest {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let (request_stream_id, expected_revision, proposed_envelope) = match &cas_request.body {
            WitnessStoreProxyRequestBodyV1::CompareAndSwap {
                stream_id,
                expected_revision,
                proposed_envelope,
                ..
            } => (stream_id, *expected_revision, proposed_envelope.as_ref()),
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        };
        let proposed_envelope_bytes = canonical_wire_bytes(proposed_envelope)?;
        let proposed_envelope_digest = proposed_envelope.signed_envelope_digest()?;
        if response_stream_id != request_stream_id
            || response_previous_revision != expected_revision
            || response_new_revision <= response_previous_revision
            || response_acknowledged_digest != &proposed_envelope_digest
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let store_record = store_records
            .iter()
            .find(|record| {
                record.operation == "compare_and_swap"
                    && record.cas_applied
                    && record.stream_id.as_deref() == Some(request_stream_id)
            })
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        let store_input = hex::decode(&store_record.input_canonical_hex)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        if sha256_hex(&store_input) != store_record.input_sha256 {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let (store_stream_id, store_expected_revision, _store_expected_digest, store_proposed): (
            String,
            u64,
            String,
            WitnessStoreEnvelopeV1,
        ) = serde_json::from_slice(&store_input)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        if store_stream_id != *request_stream_id
            || store_expected_revision != expected_revision
            || canonical_wire_bytes(&store_proposed)? != proposed_envelope_bytes
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let store_result_bytes = hex::decode(&store_record.result_canonical_hex)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        if sha256_hex(&store_result_bytes) != store_record.result_sha256 {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let store_result: WitnessStoreCasResultV1 = serde_json::from_slice(&store_result_bytes)
            .map_err(|_| ProtocolError::WitnessOutcomeMismatch)?;
        match store_result {
            WitnessStoreCasResultV1::Applied {
                stream_id,
                expected_previous_revision,
                previous_revision,
                new_revision,
                acknowledged_value_digest,
                ..
            } if stream_id == *request_stream_id
                && expected_previous_revision == expected_revision
                && previous_revision == response_previous_revision
                && new_revision == response_new_revision
                && acknowledged_value_digest == proposed_envelope_digest => {}
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        }
        let final_read_bytes = final_read.canonical_bytes()?;
        let final_envelope = match &final_read.body {
            WitnessStoreProxyResponseBodyV1::Entry {
                stream_id,
                revision,
                envelope,
            } if stream_id == request_stream_id && *revision == response_new_revision => {
                envelope.as_ref()
            }
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        };
        if canonical_wire_bytes(final_envelope)? != proposed_envelope_bytes {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        final_envelope.validate()?;
        let rotation = final_envelope
            .last_session_rotation
            .as_ref()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        rotation.validate()?;
        let establish_snapshot = rotation
            .establish_snapshot
            .as_ref()
            .ok_or(ProtocolError::WitnessOutcomeMismatch)?;
        if rotation.accepted_request_digest != public_request.request_digest
            || rotation.accepted_challenge_digest != challenge.challenge_digest()?
            || rotation.response_kind != WitnessSessionRotationResponseKindV1::Establish
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let attestation = match outer_response {
            WitnessServiceResponseV1::Establish(attestation) => attestation,
            _ => return Err(ProtocolError::WitnessOutcomeMismatch),
        };
        attestation.validate()?;
        attestation.verify_for(
            challenge,
            establish_snapshot.committed_head.as_ref(),
            binding,
        )?;
        if attestation.challenge != *challenge
            || attestation.session != rotation.session
            || attestation.committed_head != establish_snapshot.committed_head
            || attestation.external_marker != establish_snapshot.external_marker
            || attestation.witness_key_id != final_envelope.witness_key_id
        {
            return Err(ProtocolError::WitnessOutcomeMismatch);
        }
        let rotation_bytes = canonical_wire_bytes(rotation)?;
        let attestation_bytes = attestation.canonical_bytes()?;
        Ok(PrivateCasJoinReceiptV1 {
            capture_id: capture.receipt.capture_id,
            capture_sha256: capture.receipt.payload_sha256.clone(),
            cas_request_digest: cas_request.request_digest,
            cas_request_sha256: sha256_hex(&cas_request_bytes),
            store_result_sha256: sha256_hex(&store_result_bytes),
            proposed_envelope_sha256: sha256_hex(&proposed_envelope_bytes),
            proposed_envelope_digest,
            final_read_sha256: sha256_hex(&final_read_bytes),
            rotation_receipt_sha256: sha256_hex(&rotation_bytes),
            outer_attestation_sha256: sha256_hex(&attestation_bytes),
            new_revision: response_new_revision,
        })
    }

    struct GrantCaseV1 {
        label: &'static str,
        responder_path: &'static str,
        responder_role: &'static str,
        responder_account: &'static str,
        requester_path: &'static str,
        requester_role: &'static str,
        requester_account: &'static str,
        requester_subject: String,
        responder_subject: String,
        grant_millis: u64,
        accepted_delay_millis: u64,
        rejected_delay_millis: u64,
    }

    async fn run_grant_case(case: GrantCaseV1) -> serde_json::Value {
        let (responder, mut events) = must(
            connect_grant_role(case.responder_path, case.responder_role).await,
            "grant responder connection",
        );
        let requester = must(
            connect_deadline_role(case.requester_path, case.requester_role).await,
            "grant requester connection",
        );
        let responder_client_id = responder.server_info().client_id;
        let requester_client_id = requester.server_info().client_id;
        let mut incoming = must(
            responder.subscribe(case.responder_subject.clone()).await,
            "grant responder subscription",
        );
        must(responder.flush().await, "grant responder flush");
        let (accepted, mut accepted_replies, accepted_reply) = must(
            next_grant_request(&requester, &mut incoming, &case.requester_subject).await,
            "grant accepted request",
        );
        let accepted_origin = MonotonicInstant::now();
        sleep(Duration::from_millis(case.accepted_delay_millis)).await;
        let response_subject = must_some(accepted.reply.clone(), "grant accepted reply absent");
        let first_response_enqueue_started_at_micros =
            u64::try_from(accepted_origin.elapsed().as_micros())
                .unwrap_or_else(|_| panic!("grant first response-enqueue timestamp overflow"));
        must(
            responder
                .publish(response_subject.clone(), b"accepted".to_vec().into())
                .await,
            "grant first publish",
        );
        let second_response_enqueue_started_at_micros =
            u64::try_from(accepted_origin.elapsed().as_micros())
                .unwrap_or_else(|_| panic!("grant second response-enqueue timestamp overflow"));
        must(
            responder
                .publish(response_subject.clone(), b"duplicate".to_vec().into())
                .await,
            "grant duplicate publish",
        );
        must(responder.flush().await, "grant duplicate flush");
        let first_response = must(
            tokio::time::timeout(Duration::from_secs(2), accepted_replies.next()).await,
            "grant first response deadline",
        );
        assert_eq!(
            must_some(first_response, "grant first response absent").payload,
            b"accepted".as_slice(),
            "grant first response bytes differ"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), accepted_replies.next())
                .await
                .is_err(),
            "grant requester received more than one response"
        );
        let maximum_rejection = must(
            permission_event(&mut events, response_subject.as_str()).await,
            "grant maximum permission event",
        );
        assert!(
            second_response_enqueue_started_at_micros >= first_response_enqueue_started_at_micros
                && second_response_enqueue_started_at_micros
                    - first_response_enqueue_started_at_micros
                    < 50_000,
            "grant response-enqueue-start delta differs"
        );
        assert!(
            second_response_enqueue_started_at_micros < case.grant_millis * 1_000,
            "grant duplicate response enqueue did not start strictly pre-expiry"
        );

        let (expired, mut expired_replies, _) = must(
            next_grant_request(&requester, &mut incoming, &case.requester_subject).await,
            "grant expiry request",
        );
        let expired_reply = must_some(expired.reply.clone(), "grant expiry reply absent");
        sleep(Duration::from_millis(case.rejected_delay_millis)).await;
        must(
            responder
                .publish(expired_reply.clone(), b"expired".to_vec().into())
                .await,
            "grant expired publish",
        );
        must(responder.flush().await, "grant expired flush");
        let expiry_rejection = must(
            permission_event(&mut events, expired_reply.as_str()).await,
            "grant expiry permission event",
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), expired_replies.next())
                .await
                .is_err(),
            "expired grant produced a response"
        );

        let (delayed, mut delayed_replies, _) = must(
            next_grant_request(&requester, &mut incoming, &case.requester_subject).await,
            "grant delayed control request",
        );
        let delayed_reply = must_some(delayed.reply.clone(), "grant delayed reply absent");
        let delayed_origin = MonotonicInstant::now();
        must(
            responder
                .publish(delayed_reply.clone(), b"delayed-first".to_vec().into())
                .await,
            "grant delayed first publish",
        );
        sleep(Duration::from_millis(60)).await;
        let delayed_second_response_enqueue_started_at_micros =
            u64::try_from(delayed_origin.elapsed().as_micros())
                .unwrap_or_else(|_| panic!("grant delayed response-enqueue timestamp overflow"));
        must(
            responder
                .publish(delayed_reply.clone(), b"delayed-second".to_vec().into())
                .await,
            "grant delayed second publish",
        );
        must(responder.flush().await, "grant delayed flush");
        let delayed_first = must(
            tokio::time::timeout(Duration::from_secs(2), delayed_replies.next()).await,
            "grant delayed response deadline",
        );
        assert_eq!(
            must_some(delayed_first, "grant delayed response absent").payload,
            b"delayed-first".as_slice(),
            "grant delayed response bytes differ"
        );
        let delayed_rejection = must(
            permission_event(&mut events, delayed_reply.as_str()).await,
            "grant delayed permission event",
        );
        assert!(
            delayed_second_response_enqueue_started_at_micros >= 50_000,
            "grant delayed-first-response control did not cross 50ms"
        );

        let responder_connection = server_connection_observation(
            case.label,
            case.responder_account,
            case.responder_path,
            case.responder_role,
            responder_client_id,
        );
        let requester_connection = server_connection_observation(
            "grant-requester",
            case.requester_account,
            case.requester_path,
            case.requester_role,
            requester_client_id,
        );
        serde_json::json!({
            "label": case.label,
            "grant_millis": case.grant_millis,
            "accepted_delay_millis": case.accepted_delay_millis,
            "rejected_delay_millis": case.rejected_delay_millis,
            "first_response_enqueue_started_at_micros": first_response_enqueue_started_at_micros,
            "second_response_enqueue_started_at_micros": second_response_enqueue_started_at_micros,
            "second_response_enqueue_start_delta_micros": second_response_enqueue_started_at_micros - first_response_enqueue_started_at_micros,
            "response_grant_expires_at_micros": case.grant_millis * 1_000,
            "requester_response_count": 1,
            "maximum_rejection": maximum_rejection,
            "expiry_rejection": expiry_rejection,
            "delayed_control_rejection": delayed_rejection,
            "delayed_control_enqueue_start_delta_micros": delayed_second_response_enqueue_started_at_micros,
            "responder_connection": responder_connection,
            "requester_connection": requester_connection,
            "requester_subject": case.requester_subject,
            "responder_subject": case.responder_subject,
            "accepted_reply": accepted_reply.to_string(),
        })
    }

    async fn run_response_grants_are_live_and_exact() {
        let relay = std::env::var_os("PHASE285_RELAY_TOPOLOGY_TOKEN").is_some();
        let public = GrantCaseV1 {
            label: "public",
            responder_path: if relay {
                "SWARM_NATS_RELAY_CREDENTIAL_PATH"
            } else {
                "SWARM_NATS_WITNESS_CREDENTIAL_PATH"
            },
            responder_role: if relay { "relay" } else { "witness" },
            responder_account: if relay {
                "PHASE285_RELAY"
            } else {
                "PHASE285_WITNESS"
            },
            requester_path: "SWARM_NATS_RUNTIME_CREDENTIAL_PATH",
            requester_role: "runtime",
            requester_account: "PHASE285_RUNTIME",
            requester_subject: "swarm.governance.witness.v1.fence".to_string(),
            responder_subject: if relay {
                "swarm.governance.witness.relay.v1.fence".to_string()
            } else {
                "swarm.governance.witness.v1.fence".to_string()
            },
            grant_millis: 12_000,
            accepted_delay_millis: 10_500,
            rejected_delay_millis: 12_500,
        };
        let private = GrantCaseV1 {
            label: "private",
            responder_path: "SWARM_NATS_STORE_CREDENTIAL_PATH",
            responder_role: "witness-store",
            responder_account: "PHASE285_WITNESS_STORE",
            requester_path: if relay {
                "SWARM_NATS_RELAY_CREDENTIAL_PATH"
            } else {
                "SWARM_NATS_WITNESS_CREDENTIAL_PATH"
            },
            requester_role: if relay { "relay" } else { "witness" },
            requester_account: if relay {
                "PHASE285_RELAY"
            } else {
                "PHASE285_WITNESS"
            },
            requester_subject: if relay {
                "swarm.governance.witness.relay.forward.store.v1.inspect_ready".to_string()
            } else {
                "swarm.governance.witness.store.v1.inspect_ready".to_string()
            },
            responder_subject: "swarm.governance.witness.store.v1.inspect_ready".to_string(),
            grant_millis: 3_000,
            accepted_delay_millis: 2_500,
            rejected_delay_millis: 3_500,
        };
        let (public_row, private_row) =
            tokio::join!(run_grant_case(public), run_grant_case(private));
        if let Ok(path) = std::env::var("PHASE285_GRANT_LEDGER") {
            let tree = must(
                std::env::var("PHASE285_SERVICE_CHECKPOINT_TREE")
                    .or_else(|_| std::env::var("PHASE285_CHECKPOINT_TREE")),
                "grant tree absent",
            );
            let token = std::env::var("PHASE285_RELAY_TOPOLOGY_TOKEN")
                .unwrap_or_else(|_| format!("normal-{}", tree));
            let ledger = serde_json::json!({
                "schema_version": 1,
                "tree": tree,
                "invocation_token": token,
                "case": "service_checkpoint_response_grants",
                "mode": if relay { "relay" } else { "normal" },
                "rows": [private_row, public_row],
            });
            let bytes = must(canonical_wire_bytes(&ledger), "grant ledger serialization");
            let mut file = must(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path),
                "grant ledger freshness",
            );
            must(file.write_all(&bytes), "grant ledger write");
            must(file.write_all(b"\n"), "grant ledger frame");
            must(file.sync_all(), "grant ledger sync");
        }
        println!(
            "response_grants mode={} rows=2 max_one=2 pre_expiry=2 expiry_refusal=2 delayed_control=2 server_bound=4 passed=1",
            if relay { "relay" } else { "normal" }
        );
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

    async fn observation_prepare_with_exact_retry(
        client: &RuntimeWitnessClient,
        request: WitnessServiceRequestV1,
    ) -> Result<WitnessOutcomeAttestationV1, RuntimeWitnessClientErrorV1> {
        for attempt in 0..OBSERVATION_EXACT_RETRY_ATTEMPTS {
            match client.prepare_successor(request.clone()).await {
                Err(RuntimeWitnessClientErrorV1::OutcomeUnknown)
                    if attempt + 1 < OBSERVATION_EXACT_RETRY_ATTEMPTS =>
                {
                    // The protocol recognizes an identical already-prepared
                    // request. Retry only the exact signed bytes after an
                    // ambiguous transport outcome; never rebuild authority,
                    // nonce, session, or candidate state.
                    tokio::time::sleep(OBSERVATION_EXACT_RETRY_DELAY).await;
                }
                result => return result,
            }
        }
        unreachable!("bounded observation Prepare retry loop must return")
    }

    async fn observation_commit_with_exact_retry(
        client: &RuntimeWitnessClient,
        request: WitnessServiceRequestV1,
        reconciliation_request: WitnessServiceRequestV1,
        expected_txid: &str,
    ) -> Result<Option<WitnessOutcomeAttestationV1>, RuntimeWitnessClientErrorV1> {
        for attempt in 0..OBSERVATION_EXACT_RETRY_ATTEMPTS {
            match client.commit_prepared(request.clone()).await {
                Ok(attestation) => return Ok(Some(attestation)),
                Err(RuntimeWitnessClientErrorV1::OutcomeUnknown) => {
                    // A commit timeout is ambiguous: retrying the exact signed
                    // bytes is safe, but the committed winner may already be
                    // durable while every outcome response misses its grant.
                    // Reconcile through an independently signed ReadHead before
                    // another mutation attempt. Only the authenticated exact
                    // candidate head resolves the ambiguity as success.
                    match client.read_head(reconciliation_request.clone()).await {
                        Ok(read) => {
                            read.validate()
                                .map_err(|_| RuntimeWitnessClientErrorV1::InvalidResponse)?;
                            if read.request_digest != reconciliation_request.request_digest
                                || read.target_txid != expected_txid
                            {
                                return Err(RuntimeWitnessClientErrorV1::InvalidResponse);
                            }
                            match &read.response {
                                WitnessReadResponseV1::Head(head)
                                    if head
                                        .as_ref()
                                        .as_ref()
                                        .is_some_and(|head| head.txid == expected_txid) =>
                                {
                                    return Ok(None);
                                }
                                WitnessReadResponseV1::Head(head)
                                    if head.as_ref().as_ref().is_none()
                                        && attempt + 1 < OBSERVATION_EXACT_RETRY_ATTEMPTS => {}
                                WitnessReadResponseV1::Head(_) => {
                                    return Err(RuntimeWitnessClientErrorV1::InvalidResponse);
                                }
                                _ => return Err(RuntimeWitnessClientErrorV1::InvalidResponse),
                            }
                        }
                        Err(RuntimeWitnessClientErrorV1::OutcomeUnknown)
                            if attempt + 1 < OBSERVATION_EXACT_RETRY_ATTEMPTS => {}
                        Err(error) => return Err(error),
                    }
                    if attempt + 1 < OBSERVATION_EXACT_RETRY_ATTEMPTS {
                        tokio::time::sleep(OBSERVATION_EXACT_RETRY_DELAY).await;
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(RuntimeWitnessClientErrorV1::OutcomeUnknown)
    }

    async fn run_worker_observation_test_async() -> Vec<u8> {
        must(
            initialize_deadline_stream().await,
            "observation stream initialization",
        );
        let relay_enabled = std::env::var_os("PHASE285_RELAY_TOPOLOGY_TOKEN").is_some();
        let mut relay_legs = if relay_enabled {
            Some(must(
                LiveRelayLegsV1::start(true).await,
                "relay legs startup",
            ))
        } else {
            None
        };
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
            request_records: Arc::new(Mutex::new(Vec::new())),
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

        let runtime_client = Arc::new(must(
            RuntimeWitnessClient::connect(runtime_observation_config()).await,
            "observation runtime connection",
        ));
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
            observation_prepare_with_exact_retry(&runtime_client, prepare_request).await,
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
        let commit_reconciliation_request = must(
            AuthenticatedDeadlineFixtureV1::read_head_request(
                &ephemeral_signer,
                &admission,
                session.clone(),
                candidate.txid.clone(),
            ),
            "observation Commit reconciliation request",
        );
        let committed = must(
            observation_commit_with_exact_retry(
                &runtime_client,
                commit_request,
                commit_reconciliation_request,
                &candidate.txid,
            )
            .await,
            "observation Commit response",
        );
        if let Some(committed) = committed {
            must(committed.validate(), "observation Commit attestation");
        }

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
        let request_bytes = must(request.canonical_bytes(), "observation request bytes");
        let relay_origin = Arc::new(MonotonicInstant::now());
        let first_request_started_at_micros = Arc::new(AtomicU64::new(0));
        let mut held_relay_response = None;
        let mut first_request_task = None;
        let response = if let Some(relay) = relay_legs.as_mut() {
            let client = runtime_client.clone();
            let spawned_request_bytes = request_bytes.clone();
            let request_subject = PublicWitnessServiceConfigV1::subject_for(request.operation);
            let origin = relay_origin.clone();
            let request_started = first_request_started_at_micros.clone();
            first_request_task = Some(tokio::spawn(async move {
                let observed = u64::try_from(origin.elapsed().as_micros())
                    .unwrap_or_else(|_| panic!("relay first-request timestamp overflow"));
                request_started.store(observed, Ordering::SeqCst);
                client
                    .observe_transport_message_for_test(
                        request_subject,
                        spawned_request_bytes,
                        Duration::from_millis(PUBLIC_RESPONSE_GRANT_MILLIS),
                    )
                    .await
            }));
            let held = must(
                tokio::time::timeout(
                    Duration::from_millis(PUBLIC_HANDLER_DEADLINE_MILLIS),
                    relay.held_response.recv(),
                )
                .await,
                "relay held response deadline",
            );
            let held = must_some(held, "relay held response absent");
            assert_eq!(
                held.request_bytes, request_bytes,
                "relay held request differs"
            );
            let decoded = must(
                WitnessServiceResponseV1::decode_for_client_request(&held.response_bytes, &request),
                "relay held response decode",
            );
            held_relay_response = Some(held);
            match decoded {
                WitnessServiceResponseV1::Read(value) => value,
                _ => panic!("relay held response kind differs"),
            }
        } else {
            must(
                runtime_client.read_head(request.clone()).await,
                "observation ReadHead response",
            )
        };
        let response_received_at_nanos = observation_clock.now();
        must(response.validate(), "observation ReadHead attestation");
        assert_eq!(response.request_digest, request.request_digest);
        assert_eq!(response.operation, WitnessOperationV1::ReadHead);

        let worker_events = observer
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|event| {
                !matches!(
                    event,
                    WorkerTransitionEventV1::ReceiptDeadlineIdentity { .. }
                )
            })
            .cloned()
            .collect::<Vec<_>>();
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
        let response_enqueue_attempts: Vec<_> = worker_events
            .iter()
            .enumerate()
            .filter_map(|(ordinal, event)| match event {
                WorkerTransitionEventV1::ResponseEnqueueAttempt { worker, enqueued } => {
                    Some(ResponseEnqueueObservationV1 {
                        ordinal,
                        worker: *worker,
                        enqueued: *enqueued,
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
        assert_eq!(
            response_enqueue_attempts.len(),
            2,
            "observation response enqueue count"
        );
        assert!(
            response_enqueue_attempts
                .iter()
                .all(|record| record.enqueued)
        );
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
        let response_enqueue_bytes = must(
            canonical_wire_bytes(&response_enqueue_attempts),
            "observation response enqueue bytes",
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
            response_enqueue_attempts: response_enqueue_attempts.len(),
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
            response_enqueue_attempts_sha256: sha256_hex(&response_enqueue_bytes),
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
        } else if identity.is_none() && relay_enabled {
            Some((
                must(
                    std::env::var("PHASE285_SERVICE_CHECKPOINT_TREE")
                        .or_else(|_| std::env::var("PHASE285_CHECKPOINT_TREE")),
                    "relay tree absent",
                ),
                must(
                    std::env::var("PHASE285_RELAY_TOPOLOGY_TOKEN"),
                    "relay invocation token absent",
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
            request_canonical_hex: hex::encode(&request_bytes),
            response_canonical_hex: hex::encode(&response_bytes),
            selected_store_revision,
            selected_store_generation,
            selected_store_state_digest,
            selected_envelope_digest,
            selected_head_txid: selected_head.txid.clone(),
            worker_events,
            proxy_exchanges,
            private_exchanges,
            store_operations,
            response_enqueue_attempts,
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
        if relay_enabled {
            let expected_tree = must(
                std::env::var("PHASE285_SERVICE_CHECKPOINT_TREE")
                    .or_else(|_| std::env::var("PHASE285_CHECKPOINT_TREE")),
                "relay tree absent",
            );
            let expected_token = must(
                std::env::var("PHASE285_RELAY_TOPOLOGY_TOKEN"),
                "relay invocation token absent",
            );
            // The observation route writes its own independently bound ledger,
            // but the relay-completion receipt belongs to the relay invocation.
            // Rebind only those outer identity fields before validating and
            // reserving the receipt; every request, response, store, publisher,
            // and connection relation remains byte-for-byte identical.
            let mut receipt_ledger: serde_json::Value = must(
                serde_json::from_slice(&bytes),
                "relay complete receipt ledger decode",
            );
            let receipt_identity = must_some(
                receipt_ledger.as_object_mut(),
                "relay complete receipt ledger object",
            );
            receipt_identity.insert(
                "tree".to_string(),
                serde_json::Value::String(expected_tree.clone()),
            );
            receipt_identity.insert(
                "invocation_token".to_string(),
                serde_json::Value::String(expected_token.clone()),
            );
            receipt_identity.insert(
                "case".to_string(),
                serde_json::Value::String("service_checkpoint_complete_receipt".to_string()),
            );
            let receipt_ledger_bytes = must(
                canonical_wire_bytes(&receipt_ledger),
                "relay complete receipt ledger serialization",
            );
            let receipt = LedgerBoundCompleteReceiptV1 {
                schema_version: 1,
                observation_ledger_canonical_hex: hex::encode(&receipt_ledger_bytes),
                observation_ledger_sha256: sha256_hex(&receipt_ledger_bytes),
            };
            let (receipt_sender, mut receipt_receiver) = mpsc::channel(1);
            assert_eq!(
                complete_receipt_disposition(
                    Some(receipt.clone()),
                    Some(&receipt_sender),
                    &expected_tree,
                    &expected_token,
                    "service_checkpoint_complete_receipt",
                ),
                CompleteReceiptDispositionV1::Suppress,
                "live relay complete receipt did not reserve before loss"
            );
            assert_eq!(
                must(receipt_receiver.try_recv(), "live relay receipt absent"),
                receipt,
            );
            let held = must_some(held_relay_response.take(), "live relay response absent");
            assert_eq!(
                held.response_bytes, response_bytes,
                "live relay response bytes"
            );
            assert!(
                held.decision.send(false).is_ok(),
                "live relay suppression decision was not delivered"
            );
            must(
                runtime_client.drain_for_test().await,
                "accepted relay requester drain",
            );
            let first = must_some(first_request_task.take(), "live relay request task absent");
            let first = must(first.await, "live relay request task panicked");
            let (post_accept_kind_text, post_accept_shipping_text) = match &first {
                Err((
                    RuntimeRequestObservationV1::Other,
                    RuntimeWitnessClientErrorV1::OutcomeUnknown,
                )) => ("other", "outcome_unknown"),
                Err((
                    RuntimeRequestObservationV1::NoResponders,
                    RuntimeWitnessClientErrorV1::Unavailable,
                )) => ("no_responders", "unavailable"),
                Err((
                    RuntimeRequestObservationV1::TimedOut,
                    RuntimeWitnessClientErrorV1::OutcomeUnknown,
                )) => ("timed_out", "outcome_unknown"),
                Err((
                    RuntimeRequestObservationV1::InvalidSubject,
                    RuntimeWitnessClientErrorV1::Configuration,
                )) => ("invalid_subject", "configuration"),
                Err(_) => ("other_error", "other_error"),
                Ok(_) => ("response", "response"),
            };
            println!(
                "relay_recreation_observation case=post_accept kind={post_accept_kind_text} shipping={post_accept_shipping_text} persisted=1"
            );
            assert!(
                matches!(
                    &first,
                    Err((
                        RuntimeRequestObservationV1::Other,
                        RuntimeWitnessClientErrorV1::OutcomeUnknown
                    ))
                ),
                "other_kind"
            );
            let post_accept_kind = match &first {
                Err((kind, _)) => *kind,
                Ok(_) => panic!("live relay accepted loss returned a response"),
            };
            assert!(
                !post_accept_kind.is_replay_response(),
                "other_accepted_as_replay"
            );
            let first_legs = must_some(relay_legs.take(), "live relay legs absent");
            let first_public_client_id = first_legs.public_client_id;
            let first_private_client_id = first_legs.private_client_id;
            let first_public_connection = server_connection_observation(
                "public-relay-first",
                "PHASE285_RELAY",
                "SWARM_NATS_RELAY_CREDENTIAL_PATH",
                "relay",
                first_public_client_id,
            );
            let first_private_connection = server_connection_observation(
                "private-relay-first",
                "PHASE285_RELAY",
                "SWARM_NATS_RELAY_CREDENTIAL_PATH",
                "relay",
                first_private_client_id,
            );
            let teardown = must(
                first_legs.stop_and_confirm().await,
                "old_relay_identity_present",
            );
            assert_eq!(
                teardown.old_identities_absent, 2,
                "old_relay_identity_present"
            );
            assert_eq!(teardown.tasks_joined, 12, "relay_task_join_cardinality");
            assert!(
                teardown.public_client_drained,
                "old_public_relay_identity_present"
            );
            assert!(
                teardown.private_client_drained,
                "old_private_relay_identity_present"
            );
            let (startup_failure_gate_sender, startup_failure_gate_receiver) = oneshot::channel();
            let (startup_failure_release_sender, startup_failure_release_receiver) =
                oneshot::channel();
            let startup_failure = tokio::spawn(LiveRelayLegsV1::start_after_private_release(
                false,
                startup_failure_gate_sender,
                startup_failure_release_receiver,
            ));
            let (failed_public_client_id, failed_private_client_id) = must(
                must(
                    tokio::time::timeout(Duration::from_secs(5), startup_failure_gate_receiver)
                        .await,
                    "relay startup-failure gate deadline",
                ),
                "relay startup-failure gate closed",
            );
            drop(startup_failure_release_sender);
            let startup_failure = must(
                tokio::time::timeout(Duration::from_secs(5), startup_failure).await,
                "relay startup-failure task deadline",
            );
            assert!(
                matches!(
                    startup_failure,
                    Ok(Err(ProtocolError::WitnessOutcomeMismatch))
                ),
                "relay_startup_failure_not_rejected"
            );
            must(
                await_relay_identities_absent(failed_public_client_id, failed_private_client_id)
                    .await,
                "relay_startup_failure_residue",
            );
            println!(
                "relay_recreation_startup_failure public_tasks_spawned=0 private_tasks_spawned=0 identities_absent=2 passed=1"
            );
            let replay_client = Arc::new(must(
                RuntimeWitnessClient::connect(runtime_observation_config()).await,
                "relay replay runtime connection",
            ));
            let no_responders = replay_client
                .observe_transport_for_test(
                    PublicWitnessServiceConfigV1::subject_for(request.operation),
                    request_bytes.clone(),
                    Duration::from_secs(2),
                )
                .await;
            let (no_responders_kind_text, no_responders_shipping_text) = match &no_responders {
                Err((
                    RuntimeRequestObservationV1::NoResponders,
                    RuntimeWitnessClientErrorV1::Unavailable,
                )) => ("no_responders", "unavailable"),
                Err((
                    RuntimeRequestObservationV1::Other,
                    RuntimeWitnessClientErrorV1::OutcomeUnknown,
                )) => ("other", "outcome_unknown"),
                Err((
                    RuntimeRequestObservationV1::TimedOut,
                    RuntimeWitnessClientErrorV1::OutcomeUnknown,
                )) => ("timed_out", "outcome_unknown"),
                Err((
                    RuntimeRequestObservationV1::InvalidSubject,
                    RuntimeWitnessClientErrorV1::Configuration,
                )) => ("invalid_subject", "configuration"),
                Err(_) => ("other_error", "other_error"),
                Ok(_) => ("response", "response"),
            };
            println!(
                "relay_recreation_observation case=no_responders kind={no_responders_kind_text} shipping={no_responders_shipping_text} persisted=1"
            );
            assert!(
                matches!(
                    &no_responders,
                    Err((
                        RuntimeRequestObservationV1::NoResponders,
                        RuntimeWitnessClientErrorV1::Unavailable
                    ))
                ),
                "no_responders_kind"
            );
            let no_responders_kind = match &no_responders {
                Err((kind, _)) => *kind,
                Ok(_) => panic!("relay absence unexpectedly returned a response"),
            };
            assert!(
                !no_responders_kind.is_replay_response(),
                "no_responders_accepted_as_replay"
            );
            let (private_gate_reached_sender, private_gate_reached_receiver) = oneshot::channel();
            let (private_release_sender, private_release_receiver) = oneshot::channel();
            let replay_start = tokio::spawn(LiveRelayLegsV1::start_after_private_release(
                false,
                private_gate_reached_sender,
                private_release_receiver,
            ));
            let (pending_public_client_id, pending_private_client_id) = must(
                must(
                    tokio::time::timeout(Duration::from_secs(5), private_gate_reached_receiver)
                        .await,
                    "relay private readiness gate deadline",
                ),
                "relay private readiness gate closed",
            );
            assert!(
                !replay_start.is_finished(),
                "delayed_readiness_completed_early"
            );
            let expected_pending_public = exact_public_relay_subjects();
            let expected_pending_private = BTreeSet::new();
            let pending_readiness = must(
                await_relay_subject_sets(
                    pending_public_client_id,
                    pending_private_client_id,
                    &expected_pending_public,
                    &expected_pending_private,
                )
                .await,
                "delayed_readiness_completed_early",
            );
            assert_eq!(
                pending_readiness.public_subscriptions, 9,
                "public_subscription_set"
            );
            assert_eq!(
                pending_readiness.private_subscriptions, 0,
                "private_subscription_set"
            );
            assert!(
                private_release_sender.send(()).is_ok(),
                "relay private readiness release failed"
            );
            let replay_legs = must(
                must(
                    tokio::time::timeout(Duration::from_secs(5), replay_start).await,
                    "replay relay startup deadline",
                ),
                "replay relay startup task",
            );
            let replay_legs = must(replay_legs, "replay relay legs startup");
            let replay_public_client_id = replay_legs.public_client_id;
            let replay_private_client_id = replay_legs.private_client_id;
            let readiness = must(
                replay_legs
                    .confirm_ready(first_public_client_id, first_private_client_id)
                    .await,
                "relay replacement readiness",
            );
            assert!(
                replay_legs
                    .confirm_ready(replay_public_client_id, first_private_client_id)
                    .await
                    .is_err(),
                "relay_identity_reuse_accepted"
            );
            let exact_public = exact_public_relay_subjects();
            let exact_private = exact_private_relay_subjects();
            let mut missing_public = exact_public.clone();
            assert!(missing_public.pop_first().is_some());
            assert!(
                !relay_subject_sets_are_exact(
                    &exact_public,
                    &exact_private,
                    &missing_public,
                    &exact_private,
                ),
                "public_subscription_set"
            );
            let mut missing_private = exact_private.clone();
            assert!(missing_private.pop_first().is_some());
            assert!(
                !relay_subject_sets_are_exact(
                    &exact_public,
                    &exact_private,
                    &exact_public,
                    &missing_private,
                ),
                "private_subscription_set"
            );
            let replay_request_started_at_micros = AtomicU64::new(0);
            let replay = must(
                replay_client
                    .read_head_with_request_start_observation(
                        request.clone(),
                        relay_origin.as_ref(),
                        &replay_request_started_at_micros,
                    )
                    .await,
                "live relay replay response",
            );
            let replay_kind = RuntimeRequestObservationV1::Response;
            assert!(
                replay_kind.is_replay_response(),
                "relay replay predicate refused response"
            );
            must(replay.validate(), "live relay replay attestation");
            assert_eq!(replay, response, "live relay replay response differs");
            let first_request_started = first_request_started_at_micros.load(Ordering::SeqCst);
            let replay_request_started = replay_request_started_at_micros.load(Ordering::SeqCst);
            assert!(
                first_request_started > 0 && replay_request_started > first_request_started,
                "live relay request-start order differs"
            );
            let relay_connections = vec![
                first_public_connection,
                first_private_connection,
                server_connection_observation(
                    "public-relay-replay",
                    "PHASE285_RELAY",
                    "SWARM_NATS_RELAY_CREDENTIAL_PATH",
                    "relay",
                    replay_public_client_id,
                ),
                server_connection_observation(
                    "private-relay-replay",
                    "PHASE285_RELAY",
                    "SWARM_NATS_RELAY_CREDENTIAL_PATH",
                    "relay",
                    replay_private_client_id,
                ),
            ];
            if let Ok(path) = std::env::var("PHASE285_RELAY_LEDGER") {
                let relay_value = serde_json::json!({
                    "schema_version": 1,
                    "tree": expected_tree,
                    "invocation_token": expected_token,
                    "case": "service_checkpoint_relay_positive",
                    "operation": "ReadHead",
                    "request_canonical_hex": hex::encode(&request_bytes),
                    "request_sha256": sha256_hex(&request_bytes),
                    "response_canonical_hex": hex::encode(&response_bytes),
                    "response_sha256": sha256_hex(&response_bytes),
                    "complete_receipt_canonical_hex": hex::encode(must(canonical_wire_bytes(&receipt), "relay receipt bytes")),
                    "complete_receipt_sha256": sha256_hex(&must(canonical_wire_bytes(&receipt), "relay receipt digest bytes")),
                    "first_request_started_at_micros": first_request_started,
                    "replay_request_started_at_micros": replay_request_started,
                    "relay_connections": relay_connections,
                    "relay_connection_client_ids": [first_public_client_id, first_private_client_id, replay_public_client_id, replay_private_client_id],
                    "post_accept_other_outcome_unknown": true,
                    "no_responders_unavailable": true,
                    "replay_forwarded": true,
                });
                let relay_bytes = must(
                    canonical_wire_bytes(&relay_value),
                    "relay ledger serialization",
                );
                let mut file = must(
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path),
                    "relay ledger freshness",
                );
                must(file.write_all(&relay_bytes), "relay ledger write");
                must(file.write_all(b"\n"), "relay ledger frame");
                must(file.sync_all(), "relay ledger sync");
            }
            must(
                replay_legs.stop_and_confirm().await,
                "replay relay quiescent teardown",
            );
            println!(
                "relay_recreation_errors no_responders=1 no_responders_unavailable=1 post_accept_other=1 post_accept_other_outcome_unknown=1 rejected_as_replay=2 passed=1"
            );
            println!(
                "relay_recreation_teardown tasks_joined={} old_absent={} drained={} passed=1",
                teardown.tasks_joined, teardown.old_identities_absent, teardown.clients_drained,
            );
            println!(
                "relay_recreation_readiness delayed_pending=1 new_present={} public_subscriptions={} private_subscriptions={} wildcard={} passed=1",
                readiness.new_identities_present,
                readiness.public_subscriptions,
                readiness.private_subscriptions,
                readiness.wildcard_subscriptions,
            );
            println!("relay_replay_request_outcome kind=response passed=1");
            println!(
                "relay_positive public_legs=2 private_legs=2 complete_receipt=1 outcome_unknown=1 replay=1 typed_read_head=1 passed=1"
            );
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
            ("response_deadline_check", "private", None),
            ("response_enqueue_attempt", "private", None),
            ("proxy_store_end", "public", Some("read_entry")),
            ("response_deadline_check", "public", None),
            ("response_enqueue_attempt", "public", None),
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
            if ledger_field(&events[index], "open", "worker_operation")?.as_bool() != Some(true) {
                return Err("worker_operation");
            }
        }
        for index in [8_usize, 11] {
            if ledger_field(&events[index], "enqueued", "worker_operation")?.as_bool() != Some(true)
            {
                return Err("worker_operation");
            }
        }
        Ok(())
    }

    fn validate_complete_response_enqueue_attempts(
        attempts: &[serde_json::Value],
        events: &[serde_json::Value],
    ) -> Result<(), &'static str> {
        let expected = [(8_u64, "private"), (11_u64, "public")];
        if attempts.len() != expected.len() {
            return Err("response_enqueue_fabrication");
        }
        for (attempt, (ordinal, worker)) in attempts.iter().zip(expected) {
            let ordinal_index =
                usize::try_from(ordinal).map_err(|_| "response_enqueue_fabrication")?;
            let event = events
                .get(ordinal_index)
                .ok_or("response_enqueue_fabrication")?;
            if ledger_u64(attempt, "ordinal", "response_enqueue_fabrication")? != ordinal
                || ledger_string(attempt, "worker", "response_enqueue_fabrication")? != worker
                || ledger_field(attempt, "enqueued", "response_enqueue_fabrication")?.as_bool()
                    != Some(true)
                || ledger_string(event, "event", "response_enqueue_fabrication")?
                    != "response_enqueue_attempt"
                || ledger_string(event, "worker", "response_enqueue_fabrication")? != worker
                || ledger_field(event, "enqueued", "response_enqueue_fabrication")?.as_bool()
                    != Some(true)
            {
                return Err("response_enqueue_fabrication");
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

        let response_enqueue_attempts = ledger_field(
            &row,
            "response_enqueue_attempts",
            "response_enqueue_fabrication",
        )?
        .as_array()
        .ok_or("response_enqueue_fabrication")?;
        validate_complete_response_enqueue_attempts(response_enqueue_attempts, events)?;

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
                "response_enqueue_attempts",
                ledger_field(&row, "response_enqueue_attempts", "ledger_counts")?
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
                "response_enqueue_attempts_sha256",
                ledger_field(&row, "response_enqueue_attempts", "ledger_digests")?,
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

    fn require_complete_receipt_artifact_paths_fresh() {
        for variable in [
            "PHASE285_COMPLETE_RECEIPT_LEDGER_PATH",
            "PHASE285_COMPLETE_RECEIPT_PATH",
        ] {
            let path = complete_receipt_file_path(variable);
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => panic!("complete receipt evidence is not fresh: {variable}"),
                Err(error) => {
                    panic!(
                        "complete receipt evidence freshness preflight failed: {variable}: {error:?}"
                    )
                }
            }
        }
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
            "SWARM_NATS_RELAY_CREDENTIAL_PATH",
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

    fn topology_parse_pairs(bytes: &[u8], relay_expected: bool) -> Vec<TopologyOwnerPairV1> {
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
        let expected_accounts = if relay_expected { 4 } else { 3 };
        let expected_principals = if relay_expected { 5 } else { 4 };
        assert_eq!(
            accounts.len(),
            expected_accounts,
            "topology account cardinality"
        );
        assert_eq!(
            pairs.len(),
            expected_principals,
            "topology principal cardinality"
        );
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
        let relay_expected = std::env::var_os("PHASE285_RELAY_TOPOLOGY_TOKEN").is_some();
        let canonical_pairs = topology_parse_pairs(&canonical, relay_expected);
        let probe_pairs = topology_parse_pairs(&probe, relay_expected);
        let mut credential_users = vec![
            topology_credential_user("PHASE285_TOPOLOGY_RUNTIME_CREDENTIAL_PATH", "runtime"),
            topology_credential_user("PHASE285_TOPOLOGY_WITNESS_CREDENTIAL_PATH", "witness"),
        ];
        if relay_expected {
            credential_users.push(topology_credential_user(
                "SWARM_NATS_RELAY_CREDENTIAL_PATH",
                "relay",
            ));
        }
        credential_users.extend([
            topology_credential_user("PHASE285_TOPOLOGY_STORE_CREDENTIAL_PATH", "witness-store"),
            topology_credential_user("PHASE285_TOPOLOGY_INIT_CREDENTIAL_PATH", "init"),
        ]);
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
        println!(
            "topology_rust_projection canonical=1 probe=1 accounts={} principals={} relay={} passed=1",
            if relay_expected { 4 } else { 3 },
            if relay_expected { 5 } else { 4 },
            usize::from(relay_expected)
        );
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
                    if std::env::var_os("PHASE285_GRANT_ONLY").is_some() {
                        runtime.block_on(Box::pin(run_response_grants_are_live_and_exact()));
                    } else {
                        if std::env::var_os("PHASE285_RELAY_TOPOLOGY_TOKEN").is_some()
                            && std::env::var_os("PHASE285_GRANT_LEDGER").is_some()
                        {
                            runtime.block_on(Box::pin(run_response_grants_are_live_and_exact()));
                        }
                        runtime.block_on(Box::pin(run_complete_receipt_suppression_test_async()));
                    }
                }),
            "complete receipt thread",
        );
        must(thread.join(), "complete receipt thread panicked");
    }

    async fn run_complete_receipt_suppression_test_async() {
        if std::env::var_os("PHASE285_RELAY_TOPOLOGY_TOKEN").is_some()
            && std::env::var_os("PHASE285_COMPLETE_RECEIPT_LEDGER_PATH").is_none()
        {
            let _ = run_worker_observation_test_async().await;
            return;
        }
        let expected_tree = must(
            std::env::var("PHASE285_SERVICE_CHECKPOINT_TREE"),
            "complete receipt tree absent",
        );
        let expected_invocation_token = must(
            std::env::var("PHASE285_COMPLETE_RECEIPT_INVOCATION_TOKEN"),
            "complete receipt invocation token absent",
        );
        let expected_case = "service_checkpoint_complete_receipt";
        require_complete_receipt_artifact_paths_fresh();
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

        let mut response_enqueue_fabrication_value: serde_json::Value = must(
            serde_json::from_slice(&reopened_ledger),
            "response enqueue fabrication ledger decode",
        );
        must_some(
            response_enqueue_fabrication_value
                .get_mut("response_enqueue_attempts")
                .and_then(serde_json::Value::as_array_mut)
                .and_then(|rows| rows.get_mut(0))
                .and_then(serde_json::Value::as_object_mut),
            "response enqueue fabrication target absent",
        )
        .insert("ordinal".to_string(), serde_json::Value::from(9_u64));
        refresh_ledger_array_digest(
            &mut response_enqueue_fabrication_value,
            "response_enqueue_attempts",
            "response_enqueue_attempts_sha256",
        );
        let response_enqueue_fabrication =
            complete_receipt_from_ledger_value(&response_enqueue_fabrication_value);
        for (label, candidate) in [
            ("missing", missing),
            ("invalid", invalid),
            ("partial", partial),
            ("proxy cross-copy", proxy_cross_copy),
            ("response enqueue fabrication", response_enqueue_fabrication),
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
        if std::env::var_os("PHASE285_TOPOLOGY_RUST_CANONICAL_PROJECTION_PATH").is_some() {
            run_topology_projection_test();
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TransportRouteReadinessDispositionV1 {
        Retry,
        Terminal,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TransportRouteReadinessModeV1 {
        Condition,
        FixedSleepFabricated,
    }

    fn transport_route_readiness_mode(
        fixed_sleep_fabricated: bool,
    ) -> TransportRouteReadinessModeV1 {
        if fixed_sleep_fabricated {
            TransportRouteReadinessModeV1::FixedSleepFabricated
        } else {
            TransportRouteReadinessModeV1::Condition
        }
    }

    fn classify_transport_route_readiness(
        observation: &RuntimeRequestObservationV1,
        error: &RuntimeWitnessClientErrorV1,
    ) -> TransportRouteReadinessDispositionV1 {
        match (observation, error) {
            (
                RuntimeRequestObservationV1::NoResponders,
                RuntimeWitnessClientErrorV1::Unavailable,
            ) => TransportRouteReadinessDispositionV1::Retry,
            (RuntimeRequestObservationV1::Other, RuntimeWitnessClientErrorV1::OutcomeUnknown) => {
                TransportRouteReadinessDispositionV1::Terminal
            }
            (
                RuntimeRequestObservationV1::TimedOut,
                RuntimeWitnessClientErrorV1::OutcomeUnknown,
            ) => TransportRouteReadinessDispositionV1::Terminal,
            _ => TransportRouteReadinessDispositionV1::Terminal,
        }
    }

    #[derive(Clone, Debug)]
    struct TransportRouteReadinessEvidenceV1 {
        attempts: u64,
        no_responders: u64,
        expected_request: Vec<u8>,
        observed_request: Vec<u8>,
        relay_routed_reply_subject: String,
        requester_local_reply_subject: String,
        expected_response: Vec<u8>,
        requester_response: Vec<u8>,
        relay_observations: u64,
        requester_responses: u64,
        joined: bool,
        outer_started_at: tokio::time::Instant,
        outer_deadline_at: tokio::time::Instant,
        completed_at: tokio::time::Instant,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TransportRouteReadinessReceiptV1 {
        attempts: u64,
        no_responders: u64,
        request_sha256: String,
        relay_routed_reply_subject_sha256: String,
        requester_local_reply_subject_sha256: String,
        response_sha256: String,
        relay_observations: u64,
        requester_responses: u64,
        joined: bool,
        outer_budget: Duration,
        completion_offset: Duration,
    }

    fn transport_route_readiness_receipt(
        evidence: &TransportRouteReadinessEvidenceV1,
    ) -> TransportRouteReadinessReceiptV1 {
        TransportRouteReadinessReceiptV1 {
            attempts: evidence.attempts,
            no_responders: evidence.no_responders,
            request_sha256: sha256_hex(&evidence.observed_request),
            relay_routed_reply_subject_sha256: sha256_hex(
                evidence.relay_routed_reply_subject.as_bytes(),
            ),
            requester_local_reply_subject_sha256: sha256_hex(
                evidence.requester_local_reply_subject.as_bytes(),
            ),
            response_sha256: sha256_hex(&evidence.requester_response),
            relay_observations: evidence.relay_observations,
            requester_responses: evidence.requester_responses,
            joined: evidence.joined,
            outer_budget: evidence
                .outer_deadline_at
                .checked_duration_since(evidence.outer_started_at)
                .unwrap_or(Duration::ZERO),
            completion_offset: evidence
                .completed_at
                .checked_duration_since(evidence.outer_started_at)
                .unwrap_or(Duration::ZERO),
        }
    }

    fn readiness_reply_subject_in_namespace(subject: &str, prefix: &str) -> bool {
        !subject.is_empty()
            && subject.len() <= 512
            && subject.starts_with(prefix)
            && !subject.contains(['*', '>'])
    }

    fn validate_transport_route_readiness(
        evidence: &TransportRouteReadinessEvidenceV1,
        receipt: &TransportRouteReadinessReceiptV1,
    ) -> Result<(), &'static str> {
        if evidence.relay_observations != 1
            || evidence.requester_responses != 1
            || !evidence.joined
            || evidence.expected_request.is_empty()
            || evidence.expected_response.is_empty()
        {
            return Err("readiness[condition-required]");
        }
        if evidence.outer_deadline_at
            != evidence
                .outer_started_at
                .checked_add(Duration::from_secs(5))
                .ok_or("readiness[condition-required]")?
        {
            return Err("readiness[condition-required]");
        }
        let completion_offset = evidence
            .completed_at
            .checked_duration_since(evidence.outer_started_at)
            .ok_or("readiness[completed-within-deadline]")?;
        if evidence.completed_at >= evidence.outer_deadline_at {
            return Err("readiness[completed-within-deadline]");
        }
        if evidence.attempts == 0 || evidence.attempts != evidence.no_responders.saturating_add(1) {
            return Err("readiness[receipt-recomputed]");
        }
        if evidence.expected_request != evidence.observed_request {
            return Err("readiness[request-bytes-correlated]");
        }
        if !readiness_reply_subject_in_namespace(&evidence.relay_routed_reply_subject, "_R_.")
            || !readiness_reply_subject_in_namespace(
                &evidence.requester_local_reply_subject,
                "_INBOX.",
            )
            || evidence.relay_routed_reply_subject == evidence.requester_local_reply_subject
        {
            return Err("readiness[reply-route-transformed]");
        }
        if evidence.expected_response != evidence.requester_response {
            return Err("readiness[response-bytes-correlated]");
        }
        if receipt.outer_budget != Duration::from_secs(5)
            || receipt.completion_offset != completion_offset
        {
            return Err("readiness[receipt-recomputed]");
        }
        if &transport_route_readiness_receipt(evidence) != receipt {
            return Err("readiness[receipt-recomputed]");
        }
        Ok(())
    }

    fn require_transport_route_readiness_rejection(
        evidence: &TransportRouteReadinessEvidenceV1,
        receipt: &TransportRouteReadinessReceiptV1,
        expected: &'static str,
    ) {
        match validate_transport_route_readiness(evidence, receipt) {
            Err(actual) if actual == expected => {}
            Ok(()) => panic!("{expected}"),
            Err(actual) => panic!(
                "readiness[unexpected-validation-error]: expected={expected} actual={actual}"
            ),
        }
    }

    fn prove_transport_route_readiness_validator(
        evidence: &TransportRouteReadinessEvidenceV1,
        receipt: &TransportRouteReadinessReceiptV1,
    ) {
        if let Err(error) = validate_transport_route_readiness(evidence, receipt) {
            panic!("{error}");
        }

        let mut hostile = evidence.clone();
        hostile.observed_request.push(0);
        require_transport_route_readiness_rejection(
            &hostile,
            &transport_route_readiness_receipt(&hostile),
            "readiness[request-bytes-correlated]",
        );

        let mut hostile = evidence.clone();
        hostile.relay_routed_reply_subject = "_INBOX.wrong-relay-namespace".to_string();
        require_transport_route_readiness_rejection(
            &hostile,
            &transport_route_readiness_receipt(&hostile),
            "readiness[reply-route-transformed]",
        );

        let mut hostile = evidence.clone();
        hostile.requester_local_reply_subject = "_R_.wrong-requester-namespace".to_string();
        require_transport_route_readiness_rejection(
            &hostile,
            &transport_route_readiness_receipt(&hostile),
            "readiness[reply-route-transformed]",
        );

        let mut hostile = evidence.clone();
        hostile.relay_routed_reply_subject = "_R_.wildcard.*".to_string();
        require_transport_route_readiness_rejection(
            &hostile,
            &transport_route_readiness_receipt(&hostile),
            "readiness[reply-route-transformed]",
        );

        let mut hostile = evidence.clone();
        hostile.relay_routed_reply_subject = format!("_R_.{}", "x".repeat(512));
        require_transport_route_readiness_rejection(
            &hostile,
            &transport_route_readiness_receipt(&hostile),
            "readiness[reply-route-transformed]",
        );

        let mut hostile = evidence.clone();
        hostile.requester_local_reply_subject = hostile.relay_routed_reply_subject.clone();
        require_transport_route_readiness_rejection(
            &hostile,
            &transport_route_readiness_receipt(&hostile),
            "readiness[reply-route-transformed]",
        );

        let mut hostile = evidence.clone();
        hostile.requester_response.push(0);
        require_transport_route_readiness_rejection(
            &hostile,
            &transport_route_readiness_receipt(&hostile),
            "readiness[response-bytes-correlated]",
        );

        let mut hostile = receipt.clone();
        hostile.attempts = hostile.attempts.saturating_add(1);
        require_transport_route_readiness_rejection(
            evidence,
            &hostile,
            "readiness[receipt-recomputed]",
        );

        let mut hostile = evidence.clone();
        hostile.relay_observations = 0;
        require_transport_route_readiness_rejection(
            &hostile,
            &transport_route_readiness_receipt(&hostile),
            "readiness[condition-required]",
        );

        let mut hostile = evidence.clone();
        hostile.attempts = hostile.attempts.saturating_add(1);
        require_transport_route_readiness_rejection(
            &hostile,
            &transport_route_readiness_receipt(&hostile),
            "readiness[receipt-recomputed]",
        );

        let mut hostile = evidence.clone();
        hostile.completed_at = hostile.outer_deadline_at;
        require_transport_route_readiness_rejection(
            &hostile,
            &transport_route_readiness_receipt(&hostile),
            "readiness[completed-within-deadline]",
        );
    }

    pub(super) fn run_transport_other_test() {
        let thread = must(
            std::thread::Builder::new()
                .name("phase285-r1a-transport-other".to_string())
                .stack_size(32 * 1024 * 1024)
                .spawn(|| {
                    let runtime = must(
                        tokio::runtime::Builder::new_multi_thread()
                            .worker_threads(2)
                            .thread_stack_size(32 * 1024 * 1024)
                            .enable_all()
                            .build(),
                        "transport Other runtime",
                    );
                    runtime.block_on(run_transport_other_test_async());
                }),
            "transport Other thread",
        );
        must(thread.join(), "transport Other thread panicked");
    }

    async fn run_transport_other_test_async() {
        let relay_token = must(
            std::env::var("PHASE285_RELAY_TOPOLOGY_TOKEN"),
            "transport Other relay topology token absent",
        );
        assert!(
            !relay_token.is_empty(),
            "transport Other relay topology token empty"
        );
        let relay = must(
            connect_deadline_role("SWARM_NATS_RELAY_CREDENTIAL_PATH", "relay").await,
            "transport Other relay connection",
        );
        let subject = PublicWitnessServiceConfigV1::subject_for(WitnessServiceOperationV1::Fence);
        let responder_subject = "swarm.governance.witness.relay.v1.fence";
        assert_eq!(
            responder_subject,
            format!(
                "swarm.governance.witness.relay.v1.{}",
                must_some(
                    subject.rsplit('.').next(),
                    "transport Other operation suffix"
                )
            ),
            "transport[relay-routed-responder]",
        );
        let requester = Arc::new(must(
            RuntimeWitnessClient::connect(runtime_observation_config()).await,
            "transport requester connection",
        ));
        let no_responders = requester
            .observe_transport_for_test(
                subject,
                b"phase285-r1a-no-responders".to_vec(),
                Duration::from_secs(2),
            )
            .await;
        assert!(
            matches!(
                &no_responders,
                Err((
                    RuntimeRequestObservationV1::NoResponders,
                    RuntimeWitnessClientErrorV1::Unavailable
                ))
            ),
            "transport[no-responders-unavailable]"
        );
        let (no_responder_observation, no_responder_error) = match &no_responders {
            Err((observation, error)) => (observation, error),
            Ok(_) => panic!("readiness[no-responders-not-ready]"),
        };
        if classify_transport_route_readiness(no_responder_observation, no_responder_error)
            != TransportRouteReadinessDispositionV1::Retry
        {
            panic!("readiness[no-responders-not-ready]");
        }
        assert!(matches!(
            requester
                .observe_transport_for_test(
                    "invalid subject",
                    b"phase285-r1a-invalid-subject".to_vec(),
                    Duration::from_secs(2),
                )
                .await,
            Err((
                RuntimeRequestObservationV1::InvalidSubject,
                RuntimeWitnessClientErrorV1::Configuration
            ))
        ));
        let readiness_outer_started = tokio::time::Instant::now();
        let readiness_outer_deadline = readiness_outer_started + Duration::from_secs(5);
        let mut responder = match tokio::time::timeout_at(
            readiness_outer_deadline,
            relay.subscribe(responder_subject.to_string()),
        )
        .await
        {
            Ok(Ok(responder)) => responder,
            Ok(Err(_)) | Err(_) => panic!("readiness[condition-required]"),
        };
        match tokio::time::timeout_at(readiness_outer_deadline, relay.flush()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => panic!("readiness[condition-required]"),
        }

        let mut readiness_attempts = 0_u64;
        let mut readiness_no_responders = 0_u64;
        let readiness_mode = transport_route_readiness_mode(false);
        enum TransportRouteReadinessProbeOutcomeV1 {
            RetryJoined,
            SuccessJoined {
                observed: async_nats::Message,
                requester_response: Box<async_nats::Message>,
                completed_at: tokio::time::Instant,
            },
            TerminalJoined(String),
            TerminalPending(String),
        }
        async fn terminate_after_requester_cleanup(
            mut requester_task: tokio::task::JoinHandle<
                Result<
                    async_nats::Message,
                    (RuntimeRequestObservationV1, RuntimeWitnessClientErrorV1),
                >,
            >,
            reason: String,
        ) -> ! {
            requester_task.abort();
            match tokio::time::timeout(Duration::from_millis(250), &mut requester_task).await {
                Ok(_joined_result) => panic!("{reason}"),
                Err(_) => std::process::abort(),
            }
        }
        let readiness_evidence = match readiness_mode {
            TransportRouteReadinessModeV1::Condition => loop {
                let probe_started_at = tokio::time::Instant::now();
                let probe_deadline = probe_started_at
                    .checked_add(Duration::from_millis(250))
                    .unwrap_or(readiness_outer_deadline)
                    .min(readiness_outer_deadline);
                let probe_budget = probe_deadline
                    .checked_duration_since(probe_started_at)
                    .unwrap_or_else(|| panic!("readiness[condition-required]"));
                assert!(!probe_budget.is_zero(), "readiness[condition-required]");
                readiness_attempts = readiness_attempts
                    .checked_add(1)
                    .unwrap_or_else(|| panic!("readiness[receipt-recomputed]"));
                let expected_request =
                    format!("phase285-r1a-route-ready:{relay_token}:{readiness_attempts}")
                        .into_bytes();
                let expected_response =
                    format!("phase285-r1a-route-ready-ok:{relay_token}:{readiness_attempts}")
                        .into_bytes();
                let mut requester_task = {
                    let requester = requester.clone();
                    let request = expected_request.clone();
                    tokio::spawn(async move {
                        requester
                            .observe_transport_message_for_test(subject, request, probe_budget)
                            .await
                    })
                };
                let relay_next = responder.next();
                tokio::pin!(relay_next);
                let probe_timeout = tokio::time::sleep_until(probe_deadline);
                tokio::pin!(probe_timeout);

                let probe_outcome = tokio::select! {
                    requester_result = &mut requester_task => {
                        match requester_result {
                            Ok(Err((observation, error)))
                                if classify_transport_route_readiness(&observation, &error)
                                    == TransportRouteReadinessDispositionV1::Retry =>
                            {
                                TransportRouteReadinessProbeOutcomeV1::RetryJoined
                            }
                            Ok(Err((observation, error))) => {
                                TransportRouteReadinessProbeOutcomeV1::TerminalJoined(format!(
                                    "readiness[condition-required]: terminal before relay observation: {observation:?}/{error:?}"
                                ))
                            }
                            Ok(Ok(_)) => TransportRouteReadinessProbeOutcomeV1::TerminalJoined(
                                "readiness[condition-required]: response without relay observation".to_string(),
                            ),
                            Err(error) => TransportRouteReadinessProbeOutcomeV1::TerminalJoined(
                                format!("readiness[condition-required]: requester join failed: {error:?}"),
                            ),
                        }
                    }
                    relay_result = &mut relay_next => 'relay: {
                        let observed = match relay_result {
                            Some(observed) => observed,
                            None => break 'relay TransportRouteReadinessProbeOutcomeV1::TerminalPending(
                                "readiness[condition-required]: relay subscription closed".to_string(),
                            ),
                        };
                        if observed.payload.as_ref() != expected_request.as_slice() {
                            break 'relay TransportRouteReadinessProbeOutcomeV1::TerminalPending(
                                "readiness[request-bytes-correlated]".to_string(),
                            );
                        }
                        let observed_reply = match observed.reply.clone() {
                            Some(reply) if !reply.as_str().is_empty() => reply,
                            _ => break 'relay TransportRouteReadinessProbeOutcomeV1::TerminalPending(
                                "readiness[reply-route-transformed]".to_string(),
                            ),
                        };
                        match tokio::time::timeout_at(
                            probe_deadline,
                            relay.publish(
                                observed_reply.clone(),
                                expected_response.clone().into(),
                            ),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                break 'relay TransportRouteReadinessProbeOutcomeV1::TerminalPending(
                                    format!("readiness[condition-required]: response enqueue failed: {error:?}"),
                                );
                            }
                            Err(error) => {
                                break 'relay TransportRouteReadinessProbeOutcomeV1::TerminalPending(
                                    format!("readiness[condition-required]: response enqueue deadline: {error:?}"),
                                );
                            }
                        }
                        match tokio::time::timeout_at(probe_deadline, relay.flush()).await {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                break 'relay TransportRouteReadinessProbeOutcomeV1::TerminalPending(
                                    format!("readiness[condition-required]: response flush failed: {error:?}"),
                                );
                            }
                            Err(error) => {
                                break 'relay TransportRouteReadinessProbeOutcomeV1::TerminalPending(
                                    format!("readiness[condition-required]: response flush deadline: {error:?}"),
                                );
                            }
                        }
                        match tokio::time::timeout_at(probe_deadline, &mut requester_task).await {
                            Ok(Ok(Ok(requester_response))) => {
                                if requester_response.payload.as_ref() != expected_response.as_slice() {
                                    break 'relay TransportRouteReadinessProbeOutcomeV1::TerminalJoined(
                                        "readiness[response-bytes-correlated]".to_string(),
                                    );
                                }
                                let completed_at = tokio::time::Instant::now();
                                if completed_at >= readiness_outer_deadline {
                                    break 'relay TransportRouteReadinessProbeOutcomeV1::TerminalJoined(
                                        "readiness[completed-within-deadline]".to_string(),
                                    );
                                }
                                TransportRouteReadinessProbeOutcomeV1::SuccessJoined {
                                    observed,
                                    requester_response: Box::new(requester_response),
                                    completed_at,
                                }
                            }
                            Ok(Ok(Err((observation, error)))) => {
                                TransportRouteReadinessProbeOutcomeV1::TerminalJoined(format!(
                                    "readiness[condition-required]: requester transport failed after relay observation: {observation:?}/{error:?}"
                                ))
                            }
                            Ok(Err(error)) => TransportRouteReadinessProbeOutcomeV1::TerminalJoined(
                                format!("readiness[condition-required]: requester join failed after relay observation: {error:?}"),
                            ),
                            Err(error) => TransportRouteReadinessProbeOutcomeV1::TerminalPending(
                                format!("readiness[condition-required]: requester join deadline: {error:?}"),
                            ),
                        }
                    },
                    () = &mut probe_timeout => TransportRouteReadinessProbeOutcomeV1::TerminalPending(
                        "readiness[condition-required]: probe deadline elapsed".to_string(),
                    ),
                };

                match probe_outcome {
                    TransportRouteReadinessProbeOutcomeV1::RetryJoined => {
                        match futures_util::FutureExt::now_or_never(relay_next.as_mut()) {
                            None => {}
                            Some(Some(_)) => panic!(
                                "readiness[condition-required]: relay observed a request classified as no responders"
                            ),
                            Some(None) => panic!(
                                "readiness[condition-required]: relay subscription closed after no responders"
                            ),
                        }
                        readiness_no_responders = readiness_no_responders
                            .checked_add(1)
                            .unwrap_or_else(|| panic!("readiness[receipt-recomputed]"));
                        continue;
                    }
                    TransportRouteReadinessProbeOutcomeV1::SuccessJoined {
                        observed,
                        requester_response,
                        completed_at,
                    } => {
                        break TransportRouteReadinessEvidenceV1 {
                            attempts: readiness_attempts,
                            no_responders: readiness_no_responders,
                            expected_request,
                            observed_request: observed.payload.to_vec(),
                            relay_routed_reply_subject: observed
                                .reply
                                .as_ref()
                                .unwrap_or_else(|| panic!("readiness[reply-route-transformed]"))
                                .to_string(),
                            requester_local_reply_subject: requester_response.subject.to_string(),
                            expected_response,
                            requester_response: requester_response.payload.to_vec(),
                            relay_observations: 1,
                            requester_responses: 1,
                            joined: true,
                            outer_started_at: readiness_outer_started,
                            outer_deadline_at: readiness_outer_deadline,
                            completed_at,
                        };
                    }
                    TransportRouteReadinessProbeOutcomeV1::TerminalJoined(reason) => {
                        panic!("{reason}");
                    }
                    TransportRouteReadinessProbeOutcomeV1::TerminalPending(reason) => {
                        terminate_after_requester_cleanup(requester_task, reason).await;
                    }
                }
            },
            TransportRouteReadinessModeV1::FixedSleepFabricated => {
                tokio::time::sleep(Duration::from_millis(1)).await;
                TransportRouteReadinessEvidenceV1 {
                    attempts: 1,
                    no_responders: 0,
                    expected_request: b"phase285-r1a-fabricated-readiness".to_vec(),
                    observed_request: b"phase285-r1a-fabricated-readiness".to_vec(),
                    relay_routed_reply_subject: "_R_.phase285.fabricated".to_string(),
                    requester_local_reply_subject: "_INBOX.phase285.fabricated".to_string(),
                    expected_response: b"phase285-r1a-fabricated-response".to_vec(),
                    requester_response: b"phase285-r1a-fabricated-response".to_vec(),
                    relay_observations: 0,
                    requester_responses: 0,
                    joined: false,
                    outer_started_at: readiness_outer_started,
                    outer_deadline_at: readiness_outer_deadline,
                    completed_at: tokio::time::Instant::now(),
                }
            }
        };
        let readiness_receipt = transport_route_readiness_receipt(&readiness_evidence);
        prove_transport_route_readiness_validator(&readiness_evidence, &readiness_receipt);
        println!(
            "transport_route_readiness attempts={} no_responders={} relay_observations=1 requester_responses=1 request_correlated=1 reply_route_transformed=1 response_correlated=1 joined=1 outer_deadline_millis=5000 per_probe_deadline_millis=250 passed=1",
            readiness_receipt.attempts, readiness_receipt.no_responders,
        );

        let response_task = {
            let requester = requester.clone();
            tokio::spawn(async move {
                requester
                    .observe_transport_for_test(
                        subject,
                        b"phase285-r1a-response".to_vec(),
                        Duration::from_secs(2),
                    )
                    .await
            })
        };
        let response_request = must_some(
            must(
                tokio::time::timeout(Duration::from_secs(5), responder.next()).await,
                "transport response request absent",
            ),
            "transport response subscription closed",
        );
        must(
            relay
                .publish(
                    must_some(response_request.reply, "transport response reply absent"),
                    b"phase285-r1a-response-ok".to_vec().into(),
                )
                .await,
            "transport response enqueue",
        );
        assert!(matches!(
            must(
                must(
                    tokio::time::timeout(Duration::from_secs(2), response_task).await,
                    "transport response task timeout",
                ),
                "transport response task panicked",
            ),
            Ok(RuntimeRequestObservationV1::Response)
        ));

        let timeout_task = {
            let requester = requester.clone();
            tokio::spawn(async move {
                requester
                    .observe_transport_for_test(
                        subject,
                        b"phase285-r1a-timeout".to_vec(),
                        Duration::from_millis(150),
                    )
                    .await
            })
        };
        let timed_request = must_some(
            must(
                tokio::time::timeout(Duration::from_secs(2), responder.next()).await,
                "transport timed request absent",
            ),
            "transport timed subscription closed",
        );
        assert_eq!(timed_request.payload.as_ref(), b"phase285-r1a-timeout");
        let timed = must(
            must(
                tokio::time::timeout(Duration::from_secs(2), timeout_task).await,
                "transport timed task timeout",
            ),
            "transport timed task panicked",
        );
        assert!(matches!(
            &timed,
            Err((
                RuntimeRequestObservationV1::TimedOut,
                RuntimeWitnessClientErrorV1::OutcomeUnknown
            ))
        ));
        let (timed_observation, timed_error) = match &timed {
            Err((observation, error)) => (observation, error),
            Ok(_) => panic!("readiness[timed-out-terminal]"),
        };
        if classify_transport_route_readiness(timed_observation, timed_error)
            != TransportRouteReadinessDispositionV1::Terminal
        {
            panic!("readiness[timed-out-terminal]");
        }

        let exact_request = b"phase285-r1a-post-command-other".to_vec();
        let request_task = {
            let requester = requester.clone();
            let request = exact_request.clone();
            tokio::spawn(async move {
                requester
                    .observe_transport_for_test(subject, request, Duration::from_secs(10))
                    .await
            })
        };
        let observed = must_some(
            must(
                tokio::time::timeout(Duration::from_secs(2), responder.next()).await,
                "transport Other request was not responder-observed",
            ),
            "transport Other responder subscription closed",
        );
        assert_eq!(
            observed.payload.as_ref(),
            exact_request.as_slice(),
            "transport Other responder observed different request bytes"
        );
        assert!(
            observed.reply.is_some(),
            "transport Other reply subject absent"
        );
        must(
            requester.drain_for_test().await,
            "transport Other requester drain",
        );
        let post_command = must(
            tokio::time::timeout(Duration::from_secs(2), request_task).await,
            "transport Other request did not resolve after drain",
        );
        let post_command = must(post_command, "transport Other request task panicked");
        assert!(
            matches!(
                &post_command,
                Err((
                    RuntimeRequestObservationV1::Other,
                    RuntimeWitnessClientErrorV1::OutcomeUnknown
                ))
            ),
            "transport[post-command-other-outcome-unknown]"
        );
        let (post_command_observation, post_command_error) = match &post_command {
            Err((observation, error)) => (observation, error),
            Ok(_) => panic!("readiness[other-terminal]"),
        };
        if classify_transport_route_readiness(post_command_observation, post_command_error)
            != TransportRouteReadinessDispositionV1::Terminal
        {
            panic!("readiness[other-terminal]");
        }

        let pre_send = Arc::new(must(
            RuntimeWitnessClient::connect(runtime_observation_config()).await,
            "transport pre-send requester connection",
        ));
        must(
            pre_send.drain_for_test().await,
            "transport pre-send requester drain",
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        let pre_send_result = pre_send
            .observe_transport_for_test(
                subject,
                b"phase285-r1a-pre-send-other".to_vec(),
                Duration::from_secs(2),
            )
            .await;
        assert!(
            matches!(
                &pre_send_result,
                Err((
                    RuntimeRequestObservationV1::Other,
                    RuntimeWitnessClientErrorV1::OutcomeUnknown
                ))
            ),
            "pre-send drain control was not typed Other/OutcomeUnknown"
        );
        let (pre_send_observation, pre_send_error) = match &pre_send_result {
            Err((observation, error)) => (observation, error),
            Ok(_) => panic!("readiness[other-terminal]"),
        };
        assert_eq!(
            classify_transport_route_readiness(pre_send_observation, pre_send_error),
            TransportRouteReadinessDispositionV1::Terminal,
            "readiness[other-terminal]"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(250), responder.next())
                .await
                .is_err(),
            "pre-send drain control reached the authenticated responder"
        );
        run_private_transport_classification_test(&relay).await;
        println!(
            "transport_semantics response=1 timed_out=1 no_responders=1 invalid_subject=1 post_command_other=1 shipping_other=outcome_unknown responder_observed=1 pre_send_other=1 pre_send_observed=0 relay_routed_responder=1 private_invalid_subject_invalid=1 private_malformed_invalid=1 private_operation_mismatch_invalid=1 private_digest_mismatch_invalid=1 passed=1"
        );
    }

    fn private_transport_probe_request() -> WitnessStoreProxyRequestV1 {
        let signer = Ed25519Signer::from_secret_material("phase285-r1a-private-transport-probe");
        let mut request = WitnessStoreProxyRequestV1 {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            operation: WitnessStoreProxyOperationV1::InspectReady,
            request_nonce: sha256_hex(b"phase285-r1a-private-transport-nonce"),
            admission_digest: sha256_hex(b"phase285-r1a-private-transport-admission"),
            bucket_epoch_digest: sha256_hex(b"phase285-r1a-private-transport-epoch"),
            bucket_anchor_digest: sha256_hex(b"phase285-r1a-private-transport-anchor"),
            body: WitnessStoreProxyRequestBodyV1::InspectReady,
            request_digest: String::new(),
            witness_key_id: signer.key_id().to_string(),
            signature: signer.sign(&[]),
        };
        request.request_digest = must(
            request.computed_digest(),
            "private transport probe request digest",
        );
        request.signature = signer.sign(&must(
            request.signing_bytes(),
            "private transport probe request signing bytes",
        ));
        request
    }

    async fn run_private_transport_classification_test(relay: &async_nats::Client) {
        let mut responder = must(
            relay
                .subscribe("swarm.governance.witness.relay.store.v1.inspect_ready")
                .await,
            "private transport relay responder subscription",
        );
        must(
            relay.flush().await,
            "private transport relay responder flush",
        );
        let witness = must(
            connect_deadline_role("SWARM_NATS_WITNESS_CREDENTIAL_PATH", "witness").await,
            "private transport witness connection",
        );
        let proxy = must(
            NatsPublicWitnessStoreProxyClient::new(
                witness,
                MAX_PROTOCOL_RECORD_BYTES,
                MAX_PROTOCOL_RECORD_BYTES,
                STORE_RESPONSE_GRANT_MILLIS,
            ),
            "private transport proxy",
        );
        let request = private_transport_probe_request();
        let invalid_subject = must_err(
            proxy
                .request_on_subject_for_test(
                    request.clone(),
                    WitnessStoreProxyOperationV1::InspectReady,
                    "invalid subject",
                )
                .await,
            "private InvalidSubject unexpectedly succeeded",
        );
        assert!(
            matches!(invalid_subject, PublicWitnessProxyTransportErrorV1::Framing),
            "private[invalid-subject-invalid]",
        );
        assert!(
            matches!(
                classify_proxy_transport_for_test(invalid_subject),
                PublicWitnessDispatchErrorV1::Invalid
            ),
            "private[framing-invalid]"
        );

        for (label, response) in [
            ("malformed", None),
            (
                "operation",
                Some(WitnessStoreProxyResponseV1 {
                    schema_version: PROTOCOL_SCHEMA_VERSION,
                    operation: WitnessStoreProxyOperationV1::ReadEntry,
                    request_digest: request.request_digest.clone(),
                    body: WitnessStoreProxyResponseBodyV1::Refused {
                        failure_code: WitnessStoreProxyFailureCodeV1::Configuration,
                        observed_revision: None,
                        observed_value_digest: None,
                    },
                }),
            ),
            (
                "digest",
                Some(WitnessStoreProxyResponseV1 {
                    schema_version: PROTOCOL_SCHEMA_VERSION,
                    operation: WitnessStoreProxyOperationV1::InspectReady,
                    request_digest: "f".repeat(64),
                    body: WitnessStoreProxyResponseBodyV1::Refused {
                        failure_code: WitnessStoreProxyFailureCodeV1::Configuration,
                        observed_revision: None,
                        observed_value_digest: None,
                    },
                }),
            ),
        ] {
            let intended = match label {
                "malformed" => "private[malformed-response-invalid]",
                "operation" => "private[operation-mismatch-invalid]",
                "digest" => "private[request-digest-mismatch-invalid]",
                _ => unreachable!(),
            };
            let task = {
                let proxy = proxy.clone();
                let request = request.clone();
                tokio::spawn(async move { proxy.inspect_ready(request).await })
            };
            let observed = must_some(
                must(
                    tokio::time::timeout(Duration::from_secs(2), responder.next()).await,
                    "private transport request absent",
                ),
                "private transport relay subscription closed",
            );
            let reply = must_some(observed.reply, "private transport reply absent");
            let bytes = match response {
                Some(response) => must(
                    response.canonical_bytes(),
                    "private transport response bytes",
                ),
                None => b"phase285-r1a-malformed-private-response".to_vec(),
            };
            must(
                relay.publish(reply, bytes.into()).await,
                "private transport response enqueue",
            );
            must(
                relay.flush().await,
                "private transport response enqueue flush",
            );
            let error = match must(task.await, "private transport request task panicked") {
                Err(error) => error,
                Ok(_) => panic!("{intended}"),
            };
            assert!(
                matches!(error, PublicWitnessProxyTransportErrorV1::Framing)
                    && matches!(
                        classify_proxy_transport_for_test(error),
                        PublicWitnessDispatchErrorV1::Invalid
                    ),
                "{intended}",
            );
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum GrantExpiryLegV1 {
        Public,
        Private,
    }

    #[derive(Clone, Copy, Debug)]
    enum GrantRecoveryModeV1 {
        Held,
        NoHold,
    }

    fn grant_physical_case(leg: GrantExpiryLegV1, mode: GrantRecoveryModeV1) -> &'static str {
        match (leg, mode) {
            (GrantExpiryLegV1::Public, GrantRecoveryModeV1::Held) => "held-public",
            (GrantExpiryLegV1::Private, GrantRecoveryModeV1::Held) => "held-private",
            (GrantExpiryLegV1::Public, GrantRecoveryModeV1::NoHold) => "no-hold-public",
            (GrantExpiryLegV1::Private, GrantRecoveryModeV1::NoHold) => "no-hold-private",
        }
    }

    pub(super) fn run_response_grant_recovery_test() {
        let thread = must(
            std::thread::Builder::new()
                .name("phase285-r1a-response-grant-recovery".to_string())
                .stack_size(64 * 1024 * 1024)
                .spawn(|| {
                    let runtime = must(
                        tokio::runtime::Builder::new_multi_thread()
                            .worker_threads(4)
                            .thread_stack_size(64 * 1024 * 1024)
                            .enable_all()
                            .build(),
                        "response grant recovery runtime",
                    );
                    runtime.block_on(async {
                        must(
                            initialize_deadline_stream().await,
                            "response grant stream initialization",
                        );
                        match std::env::var("PHASE285_R1A_GRANT_CASE").as_deref() {
                            Ok("held-public") => {
                                run_response_grant_recovery_leg(
                                    GrantExpiryLegV1::Public,
                                    GrantRecoveryModeV1::Held,
                                )
                                .await
                            }
                            Ok("held-private") => {
                                run_response_grant_recovery_leg(
                                    GrantExpiryLegV1::Private,
                                    GrantRecoveryModeV1::Held,
                                )
                                .await
                            }
                            Ok("no-hold-public") => {
                                run_response_grant_recovery_leg(
                                    GrantExpiryLegV1::Public,
                                    GrantRecoveryModeV1::NoHold,
                                )
                                .await
                            }
                            Ok("no-hold-private") => {
                                run_response_grant_recovery_leg(
                                    GrantExpiryLegV1::Private,
                                    GrantRecoveryModeV1::NoHold,
                                )
                                .await
                            }
                            Err(std::env::VarError::NotPresent) => {
                                for (leg, mode) in [
                                    (GrantExpiryLegV1::Public, GrantRecoveryModeV1::Held),
                                    (GrantExpiryLegV1::Private, GrantRecoveryModeV1::Held),
                                    (GrantExpiryLegV1::Public, GrantRecoveryModeV1::NoHold),
                                    (GrantExpiryLegV1::Private, GrantRecoveryModeV1::NoHold),
                                ] {
                                    run_response_grant_recovery_leg(leg, mode).await;
                                }
                            }
                            _ => panic!("response grant physical case selector is invalid"),
                        }
                    });
                }),
            "response grant recovery thread",
        );
        must(thread.join(), "response grant recovery thread panicked");
    }

    async fn run_response_grant_recovery_leg(leg: GrantExpiryLegV1, mode: GrantRecoveryModeV1) {
        let relay_token = must(
            std::env::var("PHASE285_RELAY_TOPOLOGY_TOKEN"),
            "response grant relay topology token absent",
        );
        assert!(
            !relay_token.is_empty(),
            "response grant relay topology token empty"
        );
        let physical_case = grant_physical_case(leg, mode);
        let relay_legs = must(
            LiveRelayLegsV1::start(false).await,
            "response grant relay legs startup",
        );
        if relay_legs.public_subscription_count != 9 {
            panic!("relay[public-route-ready]");
        }
        if relay_legs.private_subscription_count != 3 {
            panic!("relay[private-route-ready]");
        }
        let relay_legs = Some(relay_legs);
        let observer = Arc::new(RecordingWorkerTransitionObserverV1::default());
        let mut fixture = must(
            AuthenticatedDeadlineFixtureV1::new(observer.clone()),
            "response grant fixture",
        );
        let (private_admission_tx, mut private_admission_rx) = mpsc::channel(16);
        let (public_admission_tx, mut public_admission_rx) = mpsc::channel(16);
        let (capture_tx, mut capture_rx) = mpsc::unbounded_channel();
        let capture_observer = Arc::new(RecordingResponsePreEnqueueObserverV1 {
            sender: capture_tx,
            next_capture_id: AtomicU64::new(0),
            transitions: observer.clone(),
            invocation_token: relay_token.clone(),
            physical_case: physical_case.to_string(),
        });
        let requester_ledger = Arc::new(RequesterJoinLedgerV1::default());
        let (private_gate, private_control) = SubscriberPollGateV1::new(store_proxy_subjects()[2]);
        if matches!(
            (leg, mode),
            (GrantExpiryLegV1::Private, GrantRecoveryModeV1::Held)
        ) {
            must_some(
                Arc::get_mut(&mut fixture.service),
                "response grant private service ownership",
            )
            .hold_first_subscription_poll_for_test(private_gate);
        }
        must_some(
            Arc::get_mut(&mut fixture.service),
            "response grant private observer ownership",
        )
        .observe_worker_transitions_for_test(observer.clone());
        must_some(
            Arc::get_mut(&mut fixture.service),
            "response grant private admission observer ownership",
        )
        .observe_subscriber_admissions_for_test(Arc::new(
            RecordingSubscriberAdmissionObserverV1 {
                sender: private_admission_tx,
            },
        ));
        must_some(
            Arc::get_mut(&mut fixture.service),
            "response grant private capture ownership",
        )
        .observe_response_pre_enqueue_for_test(capture_observer.clone());
        let store_config = must(
            deadline_store_config(&fixture.witness, &fixture.ready),
            "response grant store config",
        );
        let (store_connection, mut store_events) = must(
            StoreRoleConnectionV1::connect_observed_for_test(&store_config, &fixture.ready).await,
            "response grant store connection",
        );
        let store_event_probe = store_connection.client_for_test();
        let request = must(fixture.establish_request(), "response grant request");
        let final_read_request = must(
            fixture.signed_read_request(),
            "response grant final read request",
        );
        let store_service = must_some(
            Arc::try_unwrap(fixture.service).ok(),
            "response grant private service still shared",
        );
        let store_runner = must(
            StoreProxyServiceRunner::start(store_connection, store_service).await,
            "response grant private runner",
        );

        let (witness_client, mut witness_events) = must(
            connect_grant_role("SWARM_NATS_WITNESS_CREDENTIAL_PATH", "witness").await,
            "response grant witness client",
        );
        let proxy = must(
            NatsPublicWitnessStoreProxyClient::new(
                witness_client.clone(),
                MAX_PROTOCOL_RECORD_BYTES,
                MAX_PROTOCOL_RECORD_BYTES,
                STORE_RESPONSE_GRANT_MILLIS,
            ),
            "response grant NATS proxy",
        );
        let stale_cas_proxy = proxy.clone();
        let proxy_records = Arc::new(Mutex::new(Vec::new()));
        let proxy_request_records = Arc::new(Mutex::new(Vec::new()));
        let recording_proxy = RecordingNatsProxyV1 {
            inner: proxy,
            records: proxy_records.clone(),
            request_records: proxy_request_records.clone(),
            clock: Arc::new(ObservationClockV1::new()),
        };
        let mut dispatcher = must(
            PublicWitnessDispatcher::new(
                fixture.public_config.clone(),
                fixture.witness.clone(),
                recording_proxy,
            )
            .await,
            "response grant dispatcher",
        );
        dispatcher.observe_worker_transitions_for_test(observer.clone());
        dispatcher.observe_subscriber_admissions_for_test(Arc::new(
            RecordingSubscriberAdmissionObserverV1 {
                sender: public_admission_tx,
            },
        ));
        let (public_gate, public_control) = SubscriberPollGateV1::new(
            PublicWitnessServiceConfigV1::subject_for(WitnessServiceOperationV1::Establish),
        );
        dispatcher.observe_response_pre_enqueue_for_test(capture_observer);
        if matches!(
            (leg, mode),
            (GrantExpiryLegV1::Public, GrantRecoveryModeV1::Held)
        ) {
            dispatcher.hold_first_subscription_poll_for_test(public_gate);
        }
        let witness_event_probe = witness_client.clone();
        let public_runner = must(
            PublicWitnessServiceRunner::start(witness_client, dispatcher).await,
            "response grant public runner",
        );
        let runtime_client = Arc::new(must(
            RuntimeWitnessClient::connect(runtime_observation_config()).await,
            "response grant runtime client",
        ));
        let child_task_id = format!("phase285-r1a-{physical_case}-requester-1");
        let first = {
            let client = runtime_client.clone();
            let request = request.clone();
            let requester_ledger = requester_ledger.clone();
            let invocation_token = relay_token.clone();
            let physical_case = physical_case.to_string();
            let child_task_id = child_task_id.clone();
            tokio::spawn(async move {
                let (response, response_bytes) =
                    client.observe_response_bytes_for_test(&request).await?;
                let child_receipt = requester_ledger.record_child(
                    &invocation_token,
                    &physical_case,
                    &child_task_id,
                    &response,
                    &response_bytes,
                );
                Ok::<_, RuntimeWitnessClientErrorV1>((response, response_bytes, child_receipt))
            })
        };
        let (control, grant_millis) = match leg {
            GrantExpiryLegV1::Public => (&public_control, PUBLIC_RESPONSE_GRANT_MILLIS),
            GrantExpiryLegV1::Private => (&private_control, STORE_RESPONSE_GRANT_MILLIS),
        };
        if matches!(mode, GrantRecoveryModeV1::NoHold) {
            let public_receipt = must(
                targeted_admission_receipt(
                    &mut public_admission_rx,
                    WorkerKindV1::Public,
                    PublicWitnessServiceConfigV1::subject_for(WitnessServiceOperationV1::Establish),
                )
                .await,
                "no-hold response grant public admission receipt",
            );
            let private_receipt = if matches!(leg, GrantExpiryLegV1::Private) {
                Some(must(
                    targeted_admission_receipt(
                        &mut private_admission_rx,
                        WorkerKindV1::Private,
                        store_proxy_subjects()[2],
                    )
                    .await,
                    "no-hold private CAS admission receipt",
                ))
            } else {
                None
            };
            let first = must(
                tokio::time::timeout(
                    Duration::from_millis(PUBLIC_RESPONSE_GRANT_MILLIS + 2_000),
                    first,
                )
                .await,
                "no-hold response grant request timeout",
            );
            let (response, response_bytes, child_receipt) = must(
                must(first, "no-hold response grant request task panicked"),
                "no-hold response grant requester response",
            );
            assert!(
                matches!(response, WitnessServiceResponseV1::Establish(_)),
                "no-hold response grant returned the wrong response variant: {leg:?}",
            );
            let private_capture = if let Some(receipt) = private_receipt.as_ref() {
                Some(must(
                    targeted_response_capture(
                        &mut capture_rx,
                        WorkerKindV1::Private,
                        &receipt.reply,
                    )
                    .await,
                    "no-hold private response capture",
                ))
            } else {
                None
            };
            let public_capture = must(
                targeted_response_capture(
                    &mut capture_rx,
                    WorkerKindV1::Public,
                    &public_receipt.reply,
                )
                .await,
                "no-hold response grant first payload capture",
            );
            assert_eq!(public_capture.receipt.invocation_token, relay_token);
            assert_eq!(public_capture.receipt.physical_case, physical_case);
            let parent_receipt = requester_ledger.record_parent(
                &relay_token,
                physical_case,
                &child_task_id,
                &child_receipt,
                &response_bytes,
            );
            let parent_join_bound = requester_ledger.contains_parent(&parent_receipt)
                && parent_receipt.parent_sequence > child_receipt.child_sequence
                && parent_receipt.returned_response_sha256 == sha256_hex(&response_bytes);
            match leg {
                GrantExpiryLegV1::Public => {
                    assert!(parent_join_bound, "no-hold[public-parent-join-consumed]")
                }
                GrantExpiryLegV1::Private => {
                    assert!(parent_join_bound, "no-hold[private-parent-join-consumed]")
                }
            }
            let (verified_attempts, verified_applied) = {
                let records = fixture
                    .facts
                    .records
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                must(
                    verified_cas_evidence(&records),
                    "no-hold canonical store CAS evidence",
                )
            };
            assert_eq!((verified_attempts, verified_applied), (1, 1));
            let parent_join_digest = sha256_hex(&must(
                canonical_wire_bytes(&parent_receipt),
                "no-hold parent join receipt bytes",
            ));
            let case_fields = match leg {
                GrantExpiryLegV1::Public => {
                    assert_eq!(
                        public_capture.payload, response_bytes,
                        "capture[public-first-payload-real]",
                    );
                    "public_capture_delivered_identical=1"
                }
                GrantExpiryLegV1::Private => {
                    let private_capture =
                        must_some(private_capture.as_ref(), "no-hold private capture absent");
                    let final_read = must(
                        stale_cas_proxy.read_entry(final_read_request.clone()).await,
                        "no-hold private final authenticated ReadEntry",
                    );
                    let proxy_request_records = proxy_request_records
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    let store_records = fixture
                        .facts
                        .records
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    let join = must(
                        validate_private_cas_join(
                            private_capture,
                            &proxy_request_records,
                            &store_records,
                            &final_read,
                            PrivateCasJoinContextV1 {
                                public_request: &request,
                                challenge: &fixture.challenge,
                                binding: &fixture.binding,
                                outer_response: &response,
                            },
                        ),
                        "no-hold private CAS/store/rotation/attestation join",
                    );
                    assert_eq!(join.capture_id, private_capture.receipt.capture_id);
                    "private_cas_applied_bound=1 stored_envelope_bound=1 rotation_receipt_bound=1 outer_attestation_bound=1 cross_layer_bytes_compared=0"
                }
            };
            drop(public_runner);
            drop(store_runner);
            must(
                must_some(relay_legs, "response grant relay legs absent")
                    .stop_and_confirm()
                    .await,
                "response grant relay teardown",
            );
            println!(
                "response_grant_recovery leg={leg:?} mode=NoHold physical_case={physical_case} grant_millis={grant_millis} relay_path=1 first_payload_captured=1 {case_fields} parent_join_digest={parent_join_digest} terminal_attempts=1 terminal_applied=1 additional_cas_applied=0 no_hold_reply=1 passed=1"
            );
            return;
        }
        if tokio::time::timeout(Duration::from_secs(2), control.wait_reached())
            .await
            .is_err()
        {
            panic!(
                "{}",
                match (relay_legs.is_some(), leg) {
                    (false, GrantExpiryLegV1::Public) => "relay[public-route-ready]",
                    (false, GrantExpiryLegV1::Private) => "relay[private-route-ready]",
                    (true, GrantExpiryLegV1::Public) => "grant[public-pre-poll-gate-reached]",
                    (true, GrantExpiryLegV1::Private) => "grant[private-pre-poll-gate-reached]",
                },
            );
        }
        let unrelated_reply = match leg {
            GrantExpiryLegV1::Public => "_R_.phase285.r1a.unrelated.public",
            GrantExpiryLegV1::Private => "_R_.phase285.r1a.unrelated.private",
        };
        let event_probe = match leg {
            GrantExpiryLegV1::Public => &witness_event_probe,
            GrantExpiryLegV1::Private => &store_event_probe,
        };
        must(
            event_probe
                .publish(
                    unrelated_reply,
                    b"unrelated-refusal-control".to_vec().into(),
                )
                .await,
            "response grant unrelated refusal enqueue",
        );
        must(
            event_probe.flush().await,
            "response grant unrelated refusal flush",
        );
        tokio::time::sleep(Duration::from_millis(grant_millis + 250)).await;
        control.release();
        let targeted_receipt = must(
            match leg {
                GrantExpiryLegV1::Public => {
                    targeted_admission_receipt(
                        &mut public_admission_rx,
                        WorkerKindV1::Public,
                        PublicWitnessServiceConfigV1::subject_for(
                            WitnessServiceOperationV1::Establish,
                        ),
                    )
                    .await
                }
                GrantExpiryLegV1::Private => {
                    targeted_admission_receipt(
                        &mut private_admission_rx,
                        WorkerKindV1::Private,
                        store_proxy_subjects()[2],
                    )
                    .await
                }
            },
            "response grant targeted admission receipt",
        );
        let first = must(
            tokio::time::timeout(
                Duration::from_millis(PUBLIC_RESPONSE_GRANT_MILLIS + 2_000),
                first,
            )
            .await,
            "response grant first request timeout",
        );
        let first = must(first, "response grant first request task panicked");
        assert!(
            matches!(first, Err(RuntimeWitnessClientErrorV1::OutcomeUnknown)),
            "expired response grant was not requester-observed OutcomeUnknown: {leg:?}"
        );
        let permission_violation = must(
            match leg {
                GrantExpiryLegV1::Public => {
                    permission_event(&mut witness_events, &targeted_receipt.reply).await
                }
                GrantExpiryLegV1::Private => {
                    permission_event(&mut store_events, &targeted_receipt.reply).await
                }
            },
            "expired response grant lacked broker-authoritative late-publish refusal",
        );
        assert!(
            permission_violation.contains("Permissions Violation for Publish to")
                && permission_violation.contains(&targeted_receipt.reply)
                && !permission_violation.contains(unrelated_reply),
            "grant[targeted-public-refusal]"
        );
        let first_capture = must(
            targeted_response_capture(
                &mut capture_rx,
                match leg {
                    GrantExpiryLegV1::Public => WorkerKindV1::Public,
                    GrantExpiryLegV1::Private => WorkerKindV1::Private,
                },
                &targeted_receipt.reply,
            )
            .await,
            "expired response grant first payload capture",
        );
        assert_eq!(first_capture.receipt.invocation_token, relay_token);
        assert_eq!(first_capture.receipt.physical_case, physical_case);
        assert!(
            observer
                .events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .any(|event| matches!(
                    event,
                    WorkerTransitionEventV1::ReceiptDeadlineIdentity { worker, identity }
                        if *worker == match leg {
                            GrantExpiryLegV1::Public => WorkerKindV1::Public,
                            GrantExpiryLegV1::Private => WorkerKindV1::Private,
                        } && *identity == targeted_receipt.deadline_identity
                )),
            "deadline[admission-anchor-preserved]",
        );
        let initial_private_admission = if matches!(leg, GrantExpiryLegV1::Private) {
            let _initial_public_receipt = must(
                targeted_admission_receipt(
                    &mut public_admission_rx,
                    WorkerKindV1::Public,
                    PublicWitnessServiceConfigV1::subject_for(WitnessServiceOperationV1::Establish),
                )
                .await,
                "held-private initial public admission receipt",
            );
            targeted_receipt.clone()
        } else {
            must(
                targeted_admission_receipt(
                    &mut private_admission_rx,
                    WorkerKindV1::Private,
                    store_proxy_subjects()[2],
                )
                .await,
                "held-public initial private CAS admission receipt",
            )
        };
        assert_eq!(
            initial_private_admission.subject,
            store_proxy_subjects()[2],
            "recovery[captured-private-cas-subject]",
        );
        assert_eq!(
            initial_private_admission.payload_sha256,
            sha256_hex(&initial_private_admission.payload),
            "recovery[captured-private-cas-digest]",
        );
        let captured_private_request = must(
            WitnessStoreProxyRequestV1::decode(&initial_private_admission.payload),
            "captured signed private CAS decode",
        );
        must(
            captured_private_request.validate_semantics(),
            "captured signed private CAS semantics",
        );
        must(
            captured_private_request.validate_signature(),
            "captured signed private CAS signature",
        );
        assert_eq!(
            must(
                canonical_wire_bytes(&captured_private_request),
                "captured signed private CAS canonical bytes",
            ),
            initial_private_admission.payload,
            "recovery[captured-private-cas-canonical]",
        );
        assert_eq!(
            captured_private_request.operation,
            WitnessStoreProxyOperationV1::CompareAndSwap,
            "recovery[captured-private-cas-operation]",
        );
        must(
            tokio::time::timeout(Duration::from_secs(3), async {
                while fixture.facts.cas_applied.load(Ordering::SeqCst) != 1 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await,
            "expired response grant did not apply exactly one CAS",
        );
        let (pre_recovery_attempts, pre_recovery_applied) = {
            let records = fixture
                .facts
                .records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            must(
                verified_cas_evidence(&records),
                "response grant pre-recovery CAS evidence",
            )
        };
        assert_eq!((pre_recovery_attempts, pre_recovery_applied), (1, 1));

        let (replay_one, replay_one_bytes) = must(
            runtime_client
                .observe_response_bytes_for_test(&request)
                .await,
            "response grant first exact replay",
        );
        assert!(
            matches!(replay_one, WitnessServiceResponseV1::Establish(_)),
            "response grant replay returned the wrong response variant: {leg:?}",
        );
        let replay_one_admission = must(
            targeted_admission_receipt(
                &mut public_admission_rx,
                WorkerKindV1::Public,
                PublicWitnessServiceConfigV1::subject_for(WitnessServiceOperationV1::Establish),
            )
            .await,
            "response grant recovery-one public admission receipt",
        );
        let replay_one_capture = must(
            targeted_response_capture(
                &mut capture_rx,
                WorkerKindV1::Public,
                &replay_one_admission.reply,
            )
            .await,
            "response grant recovery-one public capture",
        );
        assert_eq!(replay_one_capture.payload, replay_one_bytes);
        let (replay_two, replay_two_bytes) = must(
            runtime_client
                .observe_response_bytes_for_test(&request)
                .await,
            "response grant second exact replay",
        );
        assert!(
            matches!(replay_two, WitnessServiceResponseV1::Establish(_)),
            "response grant second replay returned the wrong response variant: {leg:?}",
        );
        let replay_two_admission = must(
            targeted_admission_receipt(
                &mut public_admission_rx,
                WorkerKindV1::Public,
                PublicWitnessServiceConfigV1::subject_for(WitnessServiceOperationV1::Establish),
            )
            .await,
            "response grant recovery-two public admission receipt",
        );
        let replay_two_capture = must(
            targeted_response_capture(
                &mut capture_rx,
                WorkerKindV1::Public,
                &replay_two_admission.reply,
            )
            .await,
            "response grant recovery-two public capture",
        );
        assert_eq!(replay_two_capture.payload, replay_two_bytes);
        assert!(
            replay_two_capture.receipt.capture_id > replay_one_capture.receipt.capture_id,
            "response capture IDs are not strictly monotonic"
        );
        assert_eq!(
            replay_one_bytes, replay_two_bytes,
            "response grant authenticated public replays differ",
        );
        let (post_recovery_attempts, post_recovery_applied) = {
            let records = fixture
                .facts
                .records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            must(
                verified_cas_evidence(&records),
                "response grant post-recovery CAS evidence",
            )
        };
        assert_eq!((post_recovery_attempts, post_recovery_applied), (1, 1));
        assert_eq!(
            (
                post_recovery_attempts - pre_recovery_attempts,
                post_recovery_applied - pre_recovery_applied,
            ),
            (0, 0),
            "response grant recovery added a CAS attempt or application",
        );
        let final_read = must(
            stale_cas_proxy.read_entry(final_read_request.clone()).await,
            "held response final authenticated ReadEntry",
        );
        let final_envelope = match &final_read.body {
            WitnessStoreProxyResponseBodyV1::Entry { envelope, .. } => envelope.as_ref(),
            _ => panic!("held response final ReadEntry returned the wrong body"),
        };
        let mut operand_receipt_digest = None;
        let mut private_join_receipt_digest = None;
        if matches!(leg, GrantExpiryLegV1::Public) {
            let public_evidence_capture = &first_capture;
            assert!(
                public_evidence_capture.receipt.worker == WorkerKindV1::Public
                    && public_evidence_capture.receipt.reply == targeted_receipt.reply
                    && public_evidence_capture.receipt.payload_len
                        == public_evidence_capture.payload.len()
                    && public_evidence_capture.receipt.payload_sha256
                        == sha256_hex(&public_evidence_capture.payload)
                    && public_evidence_capture.receipt.capture_id
                        < replay_one_capture.receipt.capture_id
                    && public_evidence_capture
                        .receipt
                        .preceding_worker_transition_sequence
                        > 0,
                "capture[public-first-payload-real]",
            );
            let operand_receipt = PublicRecoveryOperandReceiptV1 {
                left_kind: "public_pre_enqueue_capture",
                left_capture_id: first_capture.receipt.capture_id,
                left_sha256: first_capture.receipt.payload_sha256.clone(),
                right_kind: "runtime_recovery_1",
                right_sha256: sha256_hex(&replay_one_bytes),
                equal: first_capture.payload == replay_one_bytes,
            };
            assert!(
                operand_receipt.left_kind == "public_pre_enqueue_capture"
                    && operand_receipt.left_capture_id == first_capture.receipt.capture_id
                    && operand_receipt.left_sha256 == sha256_hex(&first_capture.payload)
                    && operand_receipt.right_kind == "runtime_recovery_1"
                    && operand_receipt.right_sha256 == sha256_hex(&replay_one_bytes)
                    && operand_receipt.equal,
                "recovery[public-lost-replay-operands]",
            );
            operand_receipt_digest = Some(sha256_hex(&must(
                canonical_wire_bytes(&operand_receipt),
                "public recovery operand receipt bytes",
            )));
        } else {
            let private_evidence_capture = &first_capture;
            assert!(
                private_evidence_capture.receipt.worker == WorkerKindV1::Private
                    && private_evidence_capture.receipt.reply == targeted_receipt.reply
                    && private_evidence_capture.receipt.payload_len
                        == private_evidence_capture.payload.len()
                    && private_evidence_capture.receipt.payload_sha256
                        == sha256_hex(&private_evidence_capture.payload)
                    && private_evidence_capture.receipt.capture_id
                        < replay_one_capture.receipt.capture_id
                    && private_evidence_capture
                        .receipt
                        .preceding_worker_transition_sequence
                        > 0,
                "capture[private-first-payload-real]",
            );
            assert_ne!(
                first_capture.payload, replay_one_bytes,
                "recovery[cross-layer-bytes-differ]",
            );
            let proxy_request_records = proxy_request_records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let store_records = fixture
                .facts
                .records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let private_join = must(
                validate_private_cas_join(
                    &first_capture,
                    &proxy_request_records,
                    &store_records,
                    &final_read,
                    PrivateCasJoinContextV1 {
                        public_request: &request,
                        challenge: &fixture.challenge,
                        binding: &fixture.binding,
                        outer_response: &replay_one,
                    },
                ),
                "held-private CAS/store/rotation/attestation join",
            );
            let hostile_cross_wired_capture = RecordedResponseCaptureV1 {
                receipt: first_capture.receipt.clone(),
                payload: replay_one_capture.payload.clone(),
            };
            assert!(
                validate_private_cas_join(
                    &hostile_cross_wired_capture,
                    &proxy_request_records,
                    &store_records,
                    &final_read,
                    PrivateCasJoinContextV1 {
                        public_request: &request,
                        challenge: &fixture.challenge,
                        binding: &fixture.binding,
                        outer_response: &replay_one,
                    },
                )
                .is_err(),
                "recovery[private-cas-binding-required]",
            );
            private_join_receipt_digest = Some(sha256_hex(&must(
                canonical_wire_bytes(&private_join),
                "private CAS join receipt bytes",
            )));
        }
        let initial_private_response = if matches!(leg, GrantExpiryLegV1::Private) {
            must(
                WitnessStoreProxyResponseV1::decode(&first_capture.payload),
                "held-private initial CasApplied capture decode",
            )
        } else {
            let records = proxy_records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let record = must_some(
                records.iter().find(|record| {
                    record.operation == WitnessStoreProxyOperationV1::CompareAndSwap
                        && record.request_sha256 == initial_private_admission.payload_sha256
                }),
                "held-public initial private CAS proxy response absent",
            );
            let bytes = must(
                hex::decode(&record.response_canonical_hex),
                "held-public initial private CAS proxy response hex",
            );
            assert_eq!(sha256_hex(&bytes), record.response_sha256);
            must(
                WitnessStoreProxyResponseV1::decode(&bytes),
                "held-public initial private CAS proxy response decode",
            )
        };
        must(
            initial_private_response.validate(),
            "initial private CasApplied response validation",
        );
        assert_eq!(
            initial_private_response.request_digest, captured_private_request.request_digest,
            "recovery[initial-private-request-digest]",
        );
        let initial_new_revision = match &initial_private_response.body {
            WitnessStoreProxyResponseBodyV1::CasApplied { new_revision, .. } => *new_revision,
            _ => panic!("initial private response was not CasApplied"),
        };
        let final_revision = match &final_read.body {
            WitnessStoreProxyResponseBodyV1::Entry { revision, .. } => *revision,
            _ => unreachable!(),
        };
        assert_eq!(initial_new_revision, final_revision);
        let final_store_state_digest = must(
            final_envelope.store_state_digest(),
            "held final envelope store-state digest",
        );
        let atomic_records_before_stale: Vec<_> = fixture
            .facts
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|record| record.operation == "compare_and_swap")
            .cloned()
            .collect();
        let atomic_records_digest_before_stale = sha256_hex(&must(
            canonical_wire_bytes(&atomic_records_before_stale),
            "pre-stale atomic record bytes",
        ));
        assert_eq!(atomic_records_before_stale.len(), 1);
        let stale_response = must(
            stale_cas_proxy
                .replay_canonical_request_for_test(
                    &initial_private_admission.payload,
                    WitnessStoreProxyOperationV1::CompareAndSwap,
                )
                .await,
            "exact captured signed private CAS replay",
        );
        let stale_private_admission = must(
            targeted_admission_receipt(
                &mut private_admission_rx,
                WorkerKindV1::Private,
                store_proxy_subjects()[2],
            )
            .await,
            "response grant stale private CAS admission",
        );
        assert_eq!(
            stale_private_admission.payload, initial_private_admission.payload,
            "recovery[stale-private-exact-request-bytes]",
        );
        assert_eq!(
            stale_private_admission.payload_sha256, initial_private_admission.payload_sha256,
            "recovery[stale-private-exact-request-digest]",
        );
        let stale_capture = must(
            targeted_response_capture(
                &mut capture_rx,
                WorkerKindV1::Private,
                &stale_private_admission.reply,
            )
            .await,
            "response grant stale private CAS capture",
        );
        must(
            stale_response.validate(),
            "response grant stale private response",
        );
        assert!(
            matches!(
                &stale_response.body,
                WitnessStoreProxyResponseBodyV1::Refused {
                    failure_code: WitnessStoreProxyFailureCodeV1::Conflict,
                    observed_revision: Some(observed_revision),
                    observed_value_digest: Some(observed_value_digest),
                } if *observed_revision == initial_new_revision
                    && *observed_revision == final_revision
                    && observed_value_digest == &final_store_state_digest
            ),
            "recovery[stale-private-conflict]"
        );
        assert_eq!(
            stale_capture.payload,
            must(
                canonical_wire_bytes(&stale_response),
                "response grant stale response canonical bytes",
            ),
            "recovery[stale-private-captured-response]",
        );
        assert_eq!(
            stale_response.request_digest, captured_private_request.request_digest,
            "recovery[stale-private-request-bound]",
        );
        let atomic_records_after_stale: Vec<_> = fixture
            .facts
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|record| record.operation == "compare_and_swap")
            .cloned()
            .collect();
        let atomic_records_digest_after_stale = sha256_hex(&must(
            canonical_wire_bytes(&atomic_records_after_stale),
            "post-stale atomic record bytes",
        ));
        assert_eq!(
            atomic_records_after_stale.len(),
            atomic_records_before_stale.len(),
            "recovery[stale-private-no-second-cas-record]",
        );
        assert_eq!(
            atomic_records_digest_after_stale, atomic_records_digest_before_stale,
            "recovery[stale-private-atomic-record-unchanged]",
        );
        let (verified_attempts, verified_applied) = {
            let records = fixture
                .facts
                .records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            must(
                verified_cas_evidence(&records),
                "response grant canonical store CAS evidence",
            )
        };
        assert_eq!(
            (
                verified_attempts - post_recovery_attempts,
                verified_applied - post_recovery_applied,
            ),
            (0, 0),
            "recovery[stale-private-atomic-delta]",
        );
        assert_eq!(verified_attempts, 1, "response grant CAS attempt authority");
        assert_eq!(verified_applied, 1, "response grant CAS applied authority");
        assert_eq!(
            fixture.facts.cas_attempted.load(Ordering::SeqCst),
            verified_attempts,
            "response grant CAS-attempt counter disagrees with canonical store results"
        );
        assert_eq!(
            fixture.facts.cas_applied.load(Ordering::SeqCst),
            verified_applied,
            "response grant CAS counter disagrees with canonical store results"
        );
        {
            let observed_events = observer
                .events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                observed_events.iter().any(|event| matches!(
                    event,
                    WorkerTransitionEventV1::ResponseEnqueueAttempt { enqueued: true, .. }
                )),
                "response grant processing never reached the truthful local enqueue seam: {leg:?}"
            );
            let event_bytes = must(
                canonical_wire_bytes(&*observed_events),
                "response grant event bytes",
            );
            let event_text = must(
                std::str::from_utf8(&event_bytes),
                "response grant event text",
            );
            assert!(
                event_text.contains("\"event\":\"response_enqueue_attempt\"")
                    && event_text.contains("\"enqueued\":true")
                    && !event_text.contains("response_delivery_success")
                    && !event_text.contains("publish_attempt")
                    && !event_text.contains("\"published\":true"),
                "evidence[enqueue-not-publication]"
            );
        }
        drop(public_runner);
        drop(store_runner);
        must(
            must_some(relay_legs, "response grant relay legs absent")
                .stop_and_confirm()
                .await,
            "response grant relay teardown",
        );
        let case_fields = match leg {
            GrantExpiryLegV1::Public => format!(
                "public_lost_replay_bytes_identical=1 operand_receipt_digest={}",
                must_some(
                    operand_receipt_digest.as_deref(),
                    "held-public operand receipt digest absent",
                )
            ),
            GrantExpiryLegV1::Private => format!(
                "private_cas_applied_bound=1 stored_envelope_bound=1 rotation_receipt_bound=1 public_replays_identical=1 cross_layer_bytes_compared=0 private_join_receipt_digest={}",
                must_some(
                    private_join_receipt_digest.as_deref(),
                    "held-private join receipt digest absent",
                )
            ),
        };
        println!(
            "response_grant_recovery leg={leg:?} mode=Held physical_case={physical_case} grant_millis={grant_millis} held_past_grant=1 relay_path=1 first_payload_captured=1 outcome_unknown=1 broker_late_publish_refused=1 exact_reply_bound=1 unrelated_refusal_rejected=1 {case_fields} pre_recovery_attempts=1 pre_recovery_applied=1 post_recovery_attempts=1 post_recovery_applied=1 recovery_delta_attempts=0 recovery_delta_applied=0 stale_service_atomic_delta_attempts=0 stale_service_atomic_delta_applied=0 stale_service_refused_conflict=1 atomic_record_digest_before={atomic_records_digest_before_stale} atomic_record_digest_after={atomic_records_digest_after_stale} terminal_attempts=1 terminal_applied=1 additional_cas_applied=0 no_hold_reply=0 passed=1"
        );
    }
}

#[cfg(test)]
mod service_checkpoint_observation_tests {
    #[test]
    #[ignore = "requires the authenticated Phase 285 NATS topology and observation artifacts"]
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
    #[ignore = "requires the authenticated Phase 285 relay topology and receipt artifacts"]
    fn complete_receipt_authority_and_grants_are_observed() {
        assert!(
            std::env::var_os("SWARM_NATS_STORE_TLS_URL").is_some(),
            "normal NATS harness is required"
        );
        super::deadline_state_machine_tests::run_complete_receipt_suppression_test();
    }
}

#[cfg(test)]
mod service_checkpoint_transport_semantics_tests {
    #[test]
    #[ignore = "requires the authenticated Phase 285 relay topology and transport evidence"]
    fn post_command_other_is_distinct_from_pre_send_drain() {
        assert!(
            std::env::var_os("SWARM_NATS_STORE_TLS_URL").is_some(),
            "normal NATS harness is required"
        );
        super::deadline_state_machine_tests::run_transport_other_test();
    }

    #[test]
    #[ignore = "requires the authenticated Phase 285 relay topology and response-grant evidence"]
    fn public_and_private_expired_response_grants_recover_exactly_once() {
        assert!(
            std::env::var_os("SWARM_NATS_STORE_TLS_URL").is_some(),
            "normal NATS harness is required"
        );
        super::deadline_state_machine_tests::run_response_grant_recovery_test();
    }
}
